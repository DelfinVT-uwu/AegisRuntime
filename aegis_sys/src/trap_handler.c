/*
 * trap_handler.c — Trap Layer de AegisRuntime (C23).
 *
 * Responsabilidad: ser el punto de entrada que el KERNEL invoca cuando un hilo
 * del proceso falla (SIGSEGV/SIGFPE/SIGILL/SIGBUS). Todo lo que ocurre aquí
 * corre en la alt-stack, con el hilo congelado a medio camino de un crash.
 *
 * [SEC] Este archivo es la frontera de confianza del motor. El código que se
 * ejecuta aquí es async-signal-safe: solo memcpy/write/_exit, acceso a memoria
 * pre-asignada y llamada al fast-path de Rust. Cualquier malloc, lock o printf
 * introducido aquí convierte Aegis en un parásito que empeora el crash que
 * promete curar.
 */

#define _GNU_SOURCE
#include <signal.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>

#include "aegis_api.h"
#include "aegis_maps.h"

/* ------------------------------------------------------------------ *
 *  Resolución del núcleo Rust (dlsym cacheado)                        *
 * ------------------------------------------------------------------ */

typedef int (*aegis_heal_fn)(const aegis_frame_in_t *, aegis_frame_out_t *);

/* [WHY] No llamamos a dlsym() dentro del handler: no es async-signal-safe y
 * un crash pudo corromper el heap donde dlopen cachea sus estructuras. El
 * símbolo se resuelve UNA vez durante aegis_boot() (hilo principal, sin
 * riesgo) y se cachea. Si aegis_core no está preload-eada, este puntero es
 * NULL y el handler degrada a re-lanzamiento limpio de la señal. */
static aegis_heal_fn g_heal = NULL;

/* ------------------------------------------------------------------ *
 *  Ventana segura de lectura del código en RIP                        *
 * ------------------------------------------------------------------ */

/* [API] patch_id que registra "no pudimos ni leer la instrucción". */
#define AEGIS_PATCH_ID_NO_CODE 9

/* [API] patch_id: el motor pidió escribir un divisor en RAM pero la página no
 * es escribible. Se degrada a SKIP en vez de abortar: el proceso vive, aunque
 * el resultado aritmético sea indefinido (que es exactamente lo que habría
 * dado el hardware sin nosotros). Un abort aquí sería peor que el crash. */
#define AEGIS_PATCH_ID_MEM_RO   11

/* [API] patch_id: `mem_size` con un valor que no es 1/2/4/8. Se ignora el
 * parche. Es el fallo de una ABI desalineada Rust↔C, y tratarlo como "no hay
 * parche" es lo que evita escribir un número arbitrario de bytes. */
#define AEGIS_PATCH_ID_MEM_BAD  12

/* Aplica el parche de memoria pedido por el motor (curar un divisor que vive
 * en RAM, p. ej. `idivq -0x20(%rbp)`), devolviendo el patch_id DEFINITIVO:
 * el que se telemetrea, no el que pidió Rust.
 *
 * [POR QUÉ ESTA ES LA OPERACIÓN MÁS PELIGROSA DEL RUNTIME]
 * Un registro mal elegido se nota: la siguiente instrucción usa basura y el
 * programa falla ruidosamente. Una DIRECCIÓN mal elegida corrompe un dato que
 * la app quizá no vuelve a leer nunca, así que el síntoma aparece minutos
 * después, en otro módulo, y con la culpa puesta en Aegis. Por eso, en orden:
 *
 *   1. `mem_size` debe ser 1/2/4/8. Cualquier otro valor = ABI rota; no se
 *      escribe nada.
 *   2. La dirección debe caer en una página ESCRIBIBLE según /proc/self/maps.
 *      Sin esta comprobación, escribir en un hole mapping (PROT_NONE) provoca
 *      un SEGFAULT DENTRO del handler, y eso es irrecuperable.
 *   3. La escritura es de exactamente `mem_size` bytes, no de 8. Escribir 8
 *      cuando la instrucción lee 4 (`div dword ptr`) pisaría el campo
 *      contiguo de la app con basura creada por el runtime de rescate.
 *
 * [NOTE] La lectura previa del divisor NO se hace aquí: no hace falta. El
 * kernel ya lo leyó (por eso hubo #DE), así que la página existe y es
 * legible; y el valor a escribir es la constante 1 que decidió Rust.
 */
static uint32_t aegis_apply_mem_patch(const aegis_frame_out_t *out, uint32_t patch_id)
{
    uint32_t n = out->mem_size;

    if (n != 1 && n != 2 && n != 4 && n != 8)
        return (out->mem_size == 0) ? patch_id : AEGIS_PATCH_ID_MEM_BAD;

    if (!aegis_addr_writable((uintptr_t)out->mem_addr))
        return AEGIS_PATCH_ID_MEM_RO;

    /* [SEC] Escritura directa por puntero: `memcpy` es async-signal-safe y
     * compila a la misma instrucción de stores. No se usa ninguna función de
     * libc que pueda tomar locks. */
    switch (n) {
    case 1: {
        uint8_t  v = (uint8_t)out->mem_val;
        memcpy((void *)(uintptr_t)out->mem_addr, &v, 1);
        break;
    }
    case 2: {
        uint16_t v = (uint16_t)out->mem_val;
        memcpy((void *)(uintptr_t)out->mem_addr, &v, 2);
        break;
    }
    case 4: {
        uint32_t v = (uint32_t)out->mem_val;
        memcpy((void *)(uintptr_t)out->mem_addr, &v, 4);
        break;
    }
    default: {
        uint64_t v = out->mem_val;
        memcpy((void *)(uintptr_t)out->mem_addr, &v, 8);
        break;
    }
    }
    return patch_id;
}

/* Devuelve a la disposición por defecto y relanza la señal, para que el
 * kernel mate el proceso como lo habría hecho sin el runtime. */
static void aegis_default_and_raise(int sig, int saved_errno)
{
    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    (void)sigaction(sig, &dfl, NULL);
    errno = saved_errno;
    raise(sig);
    _exit(128 + sig);   /* inalcanzable si raise() funcionó */
}

/* ------------------------------------------------------------------ *
 *  Configuración                                                      *
 * ------------------------------------------------------------------ */

static atomic_uint g_max_retries = 5;   /* límite anti-bucle por firma       */
static uint64_t    g_window_ns   = 1000000000ULL; /* ventana de 1 segundo    */
static int         g_log_fd      = 2;   /* stderr por defecto                */

int aegis_init(const aegis_config_t *cfg)
{
    /* aegis_init() es idempotente: con LD_PRELOAD el constructor llama a
     * aegis_boot(); con SDK nativo el usuario puede llamar a aegis_init()
     * después. Ambas rutas terminan aquí sin estado duplicado. */
    if (cfg) {
        if (cfg->max_patch_retries) g_max_retries = cfg->max_patch_retries;
        if (cfg->retry_window_ns)   g_window_ns   = cfg->retry_window_ns;
        if (cfg->log_fd >= 0)       g_log_fd      = cfg->log_fd;
    }
    return 0;
}

/* ------------------------------------------------------------------ *
 *  Telemetría mínima (C-side): línea JSON sin printf                   *
 * ------------------------------------------------------------------ */

/* [WHY] snprintf()/fprintf() no están en la lista async-signal-safe de
 * POSIX: internamente toman locks de FILE* que un hilo roto pudo dejar
 * tomados. Escribimos la línea a mano: prefijos fijos + valores en hex.
 * Suficiente para forense, sin violar la frontera de seguridad. */
#define LOG_BUF_CAP 256
static char g_log_buf[LOG_BUF_CAP];

static void append_hex(char **p, char *end, uint64_t v)
{
    static const char hexd[] = "0123456789abcdef";
    char tmp[16];
    int  n = 0;
    do { tmp[n++] = hexd[v & 0xf]; v >>= 4; } while (v && n < 16);
    while (n > 0 && *p < end - 2) { *(*p)++ = tmp[--n]; }
}

static void aegis_log_trap(int sig, uint64_t rip, uint64_t fault,
                           unsigned action, uint32_t patch_id)
{
    char *p = g_log_buf;
    char *end = g_log_buf + LOG_BUF_CAP;
    static const char pre[]  = "[aegis] trap sig=";
    static const char m0[]   = " rip=";
    static const char m1[]   = " fault=";
    static const char m2[]   = " action=";
    static const char m3[]   = " rule=";
    static const char nl[]   = "\n";

    memcpy(p, pre, sizeof(pre) - 1); p += sizeof(pre) - 1;
    append_hex(&p, end, (uint64_t)sig);
    memcpy(p, m0, sizeof(m0) - 1);   p += sizeof(m0) - 1;
    append_hex(&p, end, rip);
    memcpy(p, m1, sizeof(m1) - 1);   p += sizeof(m1) - 1;
    append_hex(&p, end, fault);
    memcpy(p, m2, sizeof(m2) - 1);   p += sizeof(m2) - 1;
    append_hex(&p, end, action);
    memcpy(p, m3, sizeof(m3) - 1);   p += sizeof(m3) - 1;
    append_hex(&p, end, patch_id);
    memcpy(p, nl, sizeof(nl) - 1);   p += sizeof(nl) - 1;

    (void)!write(g_log_fd, g_log_buf, (size_t)(p - g_log_buf));
}

/* ------------------------------------------------------------------ *
 *  El handler                                                         *
 * ------------------------------------------------------------------ */

/* [WARN] volatile: el kernel construye ucontext_t en la pila normal del hilo
 * y puede reutilizarla tras sigreturn; el compilador tiene prohibido cachear
 * el puntero en registros a través de la llamada a Rust. */
static void aegis_trap_handler(int sig, siginfo_t *si, void *ucontext_ptr)
{
    int saved_errno = errno;   /* regla de oro de todo handler de señal      */
    ucontext_t *uc = (ucontext_t *)ucontext_ptr;

    /* 1) Instantánea plana del hilo roto -------------------------------- */
    aegis_frame_in_t in;
    memset(&in, 0, sizeof(in));
    in.sig     = sig;
    in.si_code  = si->si_code;
    in.rip      = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
    /* [EXPL] si_addr solo existe para SIGSEGV/SIGBUS (y para SIGILL es la
     * dirección de la instrucción). Para el resto, no hay dirección útil. */
    in.fault_addr = (sig == SIGSEGV || sig == SIGBUS)
                    ? (uint64_t)si->si_addr : 0;
    memcpy(in.gregs, uc->uc_mcontext.gregs, sizeof(in.gregs));

    aegis_frame_out_t out;
    memset(&out, 0, sizeof(out));

    aegis_action_t action = AEGIS_ACTION_NONE;

    /* [BUG-CRITICO] Copiar el codigo de RIP de forma SEGURA antes de que Rust
     * lo toque. El motor antes hacia `from_raw_parts(rip, 15)` por su cuenta,
     * y eso rompia dos cosas:
     *   1) Si RIP no era legible (fallo de FETCH sobre PROT_NONE, salto a
     *      direccion basura) el handler se colgaba dentro de si mismo y el
     *      kernel mataba el proceso sin log ni telemetria.
     *   2) Exigir 15 bytes legibles descartaba la curacion de instrucciones
     *      validas que caben enteras pero no tienen 15 bytes libres hasta el
     *      final de su pagina (caso real: tests/demos/idiv_overflow.c).
     *
     * Ahora copiamos el PREFIJO LEGIBLE y le damos su longitud exacta a Rust,
     * que ya sabe fallar cerrado ante un buffer truncado.
     *
     * La lectura va AQUI, en C, porque es donde el peligro es real: Rust no
     * vuelve a tocar memoria del proceso, solo analiza bytes ya copiados.
     */
    size_t got = aegis_read_code_prefix(in.rip, in.code, AEGIS_CODE_MAX);
    in.code_len = (uint8_t)got;
    if (got == 0) {
        /* Ni un byte legible en RIP: no hay instruccion que decodificar ni a
         * lo que saltar. Abortamos por la via limpia: log + re-lanzado. */
        aegis_log_trap(sig, in.rip, in.fault_addr,
                       (unsigned)AEGIS_ACTION_ABORT, AEGIS_PATCH_ID_NO_CODE);
        aegis_default_and_raise(sig, saved_errno);
        return;
    }

    /* 2) Delegar la decisión al núcleo Rust (si está presente) ---------- */
    uint32_t patch_id = 0;
    if (g_heal != NULL && g_heal(&in, &out) == 0) {
        action   = (aegis_action_t)out.action;
        patch_id = out.patch_id;

        /* 3) Aplicar mutaciones pedidas sobre el contexto real ----------- */
        for (int i = 0; i < AEGIS_NGREG; i++) {
            if (out.gregs_mask & (1ULL << i))
                uc->uc_mcontext.gregs[i] = (greg_t)out.gregs[i];
        }

        if (action == AEGIS_ACTION_PATCH_MEM) {
            /* [API] Parche de RAM + RE-EJECUCIÓN de la misma instrucción.
             * No movemos RIP: después de escribir el divisor correcto,
             * `idivq -0x20(%rbp)` se repite y ahora se divide por 1, que es lo
             * que la app pretendía hacer. Esto es lo que diferencia Aegis de
             * Wireshark/DynamoRIO: aquellos ABANDONAN la instrucción (longjmp
             * a un punto seguro); Aegis la REPARA y deja que la app decida
             * con su propia semántica. El cociente que obtiene la app es el
             * que habría obtenido con `b = 1`, no un cero inventado. */
            patch_id = aegis_apply_mem_patch(&out, patch_id);
        } else if (action == AEGIS_ACTION_SKIP || action == AEGIS_ACTION_PATCH) {
            uc->uc_mcontext.gregs[REG_RIP] = (greg_t)out.new_rip;
        }
    }

    aegis_log_trap(sig, in.rip, in.fault_addr, (unsigned)action, patch_id);

    /* 4) Si no hay remedio o el motor pidió abortar: re-lanzar la señal
     *    con la disposición por defecto para que el kernel mate el proceso
     *    como habría hecho sin nosotros. --------------------------------- */
    if (action == AEGIS_ACTION_NONE || action == AEGIS_ACTION_ABORT) {
        aegis_default_and_raise(sig, saved_errno);
        return;
    }

    errno = saved_errno;
}

/* ------------------------------------------------------------------ *
 *  Arranque (constructor LD_PRELOAD / SDK)                            *
 * ------------------------------------------------------------------ */

extern int aegis_mman_init(void);   /* mman_utils.c: reserva sin heap */

/* [WHY] __attribute__((constructor)) es lo que permite el Modo A
 * (LD_PRELOAD): el cargador dinámico ejecuta esto en cuanto mapea la .so,
 * ANTES de main() del binario objetivo, sin tocar una sola línea suya. */
static void aegis_boot(void) __attribute__((constructor));
static void aegis_boot(void)
{
    /* Orden estricto: memoria → símbolo Rust → señales.
     *
     * [BUG-GUARDADO] `aegis_maps_init()` va ANTES que nada porque el handler
     * consulta la tabla para decidir si puede leer RIP. Con la tabla vacía la
     * primera consulta forzaría un refresco diferido en pleno handler, que
     * funciona pero es justo el camino lento que queremos evitar. */
    if (aegis_mman_init() != 0)
        return;

    aegis_maps_init();

    /* [WHY] POSIX obliga a que dlsym() devuelva `void *`, y convertir `void *` a
     * un puntero-a-función está prohibido por ISO C (-Wpedantic avisa). La
     * unión intermedia es la forma que el estándar SÍ garantiza: leer un
     * miembro distinto del último escrito es UB en general, pero POSIX exige
     * esta conversión en dlsym(), así que es una excepción con respaldo
     * normativo. La alternativa `*(void **)(&g_heal) = dlsym(...)` sería
     * UB por strict aliasing sin ninguna norma detrás. */
    union { void *obj; aegis_heal_fn fn; } sym;
    sym.obj = dlsym(RTLD_DEFAULT, "aegis_analyze_and_heal");
    g_heal = sym.fn;
    /* [NOTE] Si aegis_core.so no está en LD_PRELOAD, g_heal queda NULL y el
     * motor corre en modo observador (log + re-lanzamiento). Es un modo de
     * degradación deliberado, no un error: permite desplegar el trap layer
     * antes de que exista el cerebro. */

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = aegis_trap_handler;
    sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    /* [EXPL] SA_ONSTACK + sigaltstack (hecho en mman_init): si el crash fue
     * un stack overflow, la pila normal ya no tiene espacio ni para entrar
     * al handler; sin pila alternativa el kernel entrega SIGSEGV doble. */
    (void)sigaction(SIGSEGV, &sa, NULL);
    (void)sigaction(SIGFPE,  &sa, NULL);
    (void)sigaction(SIGILL,  &sa, NULL);
    (void)sigaction(SIGBUS,  &sa, NULL);
}