/*
 * mman_utils.c — Gestor de memoria pre-asignada de AegisRuntime.
 *
 * Responsabilidad: reservar TODA la memoria que el motor necesitará dentro de
 * un signal handler ANTES de que pueda ocurrir cualquier fault.
 *
 * [WHY] Un crash pudo corromper el heap de glibc (por ejemplo, un double-free
 * o un overflow en una arena). Si el handler llamara a malloc()/free() en ese
 * momento, reentraría en las mismas estructuras corruptas → deadlock o doble
 * fault. La solución no es "tener cuidado": es NO depender del heap jamás,
 * reservando zonas privadas con mmap() en el arranque (fuera del handler).
 */

#define _GNU_SOURCE         /* MAP_ANONYMOUS + la rama __USE_MISC de signal.h */
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>   /* write() y _exit(): únicas salidas async-signal-safe */

#include "aegis_api.h"
#include "aegis_mman.h"

/* ------------------------------------------------------------------ *
 *  Mapa de memoria del motor (documentado en docs/ARCHITECTURE.md §5) *
 * ------------------------------------------------------------------ */

/* [PERF] La shadow page se reserva aunque la Fase 2 aún no la use: su coste es
 * una sola syscall y evita tener que arriesgar un mmap() dentro de un handler
 * cuando la primera deref nula aparezca en producción. */
#define AEGIS_ALT_STACK_SIZE   (64 * 1024)   /* pila alternativa del handler   */
#define AEGIS_SHADOW_PAGE_SIZE (4  * 1024)   /* página de ceros anti-deref-nula */
#define AEGIS_CODE_CAVE_SIZE   (1  * 1024 * 1024) /* trampolines JIT (Fase 2)  */
#define AEGIS_TELEMETRY_SIZE   (64 * 1024)   /* ring buffer de eventos         */

/* [BUG] Este archivo declaraba `static uint8_t *g_shadow_page_base` y luego
 * asignaba a `g_shadow_page`, que solo existe como `extern` en aegis_mman.h.
 * El resultado era un símbolo sin definición: la .so cargaba pero cualquier
 * acceso a él fallaba en tiempo de enlace dinámico ("symbol lookup error:
 * undefined symbol: g_shadow_page") y las 4 demos morían al arrancar, no al
 * fallar. Se unifica en UN solo símbolo, el declarado en el header. */
uint8_t *g_shadow_page = (uint8_t *) NULL;
static uint8_t *g_code_cave   = NULL;
static uint8_t *g_alt_stack   = NULL;
/* [BUG] El tipo correcto es `stack_t`, NO `sigaltstack_t`. glibc eliminó el
 * typedef `sigaltstack_t` (solo queda en el kernel, en asm/signal.h): la API
 * POSIX usa `stack_t` directamente, declarado por signal.h bajo __USE_MISC /
 * __USE_XOPEN_EXTENDED — de ahí el `_GNU_SOURCE` de arriba. Con `sigaltstack_t`
 * el archivo no compilaba, y este motor nunca se llegó a enlazar. */
static stack_t g_alt_sigstack;    /* copia para inspección (asserts)          */

/* ------------------------------------------------------------------ *
 *  helpers internos                                                    *
 * ------------------------------------------------------------------ */

uint8_t *aegis_mman_shadow_base(void) { return g_shadow_page; }
size_t    aegis_mman_shadow_size(void) { return AEGIS_SHADOW_PAGE_SIZE; }

/* ------------------------------------------------------------------ *
 *  API pública (segura para llamar desde el constructor)              *
 * ------------------------------------------------------------------ */

/* Reserva una zona anónima privada. Si falla en el arranque, no hay remedio:
 * un motor sin memoria no puede prometer resiliencia, así que abortamos con
 * mensaje en stderr (es constructor: todavía no hay nada que proteger).
 *
 * [WHY] abort() y no un return con error: el llamador es el constructor del
 * runtime. Devolver NULL dejaría al proceso *sin* alt-stack ni shadow page y
 * el handler intentaría ejecutarse sobre una pila que quizá no existe,
 * fallando por segunda vez. Fallar ruidoso aquí es lo correcto.
 *
 * [NOTE] `write()` + `_exit()` en vez de `fprintf`: incluso en el constructor
 * preferimos la ruta async-signal-safe por si alguien llega a llamarlo desde un
 * contexto donde el heap no es de fiar. */
static void *aegis_mmap_zone(size_t size, int prot)
{
    void *p = mmap(NULL, size, prot,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED) {
        static const char msg[] =
            "aegis: mmap fallo en el arranque; el runtime no puede garantizar "
            "resiliencia sin su memoria pre-asignada.\n";
        (void)write(2, msg, sizeof(msg) - 1);
        _exit(127);   /* mismo código que un binario no encontrado: "no arrancar" */
    }
    return p;
}

int aegis_mman_init(void)
{
    /* [WARN] Orden importa: la alt-stack debe existir antes de registrar
     * señales (trap_handler.c), porque sigaction con SA_ONSTACK exige que
     * sigaltstack() ya haya sido llamada. Por eso aegis_mman_init() corre
     * primero en el constructor. */
    g_alt_stack = (uint8_t *) aegis_mmap_zone(AEGIS_ALT_STACK_SIZE,
                                  PROT_READ | PROT_WRITE);

    g_shadow_page = (uint8_t *) aegis_mmap_zone(AEGIS_SHADOW_PAGE_SIZE,
                                    PROT_READ | PROT_WRITE);
    /* [NOTE] La página ya nace toda a ceros por MAP_ANONYMOUS; no hace falta
     * memset. Esa propiedad es la que hace "segura" la redirección en Fase 2. */

    g_code_cave = (uint8_t *) aegis_mmap_zone(AEGIS_CODE_CAVE_SIZE,
                                  PROT_READ | PROT_WRITE | PROT_EXEC);
    /* [SEC] RWX permanente es comodidad de Fase 1; la Fase 2 alternará a
     * W^X con mprotect() (ver aegis_mman_set_rwx) para no dejar páginas que
     * un exploit podría ejecutar después de escribirlas. */

    memset(&g_alt_sigstack, 0, sizeof(g_alt_sigstack));
    g_alt_sigstack.ss_sp    = g_alt_stack;
    g_alt_sigstack.ss_size  = AEGIS_ALT_STACK_SIZE;
    /* SS_DISABLE no: queremos la pila ACTIVA desde ya. Si la segunda llamada
     * falla (sigaltstack ya configurada por el host), la ignoramos: en ese
     * caso el host ya garantiza una pila alternativa o el kernel usará la
     * pila normal y avisará con SIGSEGV doble. */
    (void)sigaltstack(&g_alt_sigstack, NULL);

    return 0;
}

/* ------------------------------------------------------------------ *
 *  Accesores para el trap handler (siempre sin alocar)                *
 * ------------------------------------------------------------------ */

uint8_t *aegis_code_cave(void)     { return g_code_cave; }
size_t   aegis_code_cave_size(void){ return AEGIS_CODE_CAVE_SIZE; }

/* ------------------------------------------------------------------ *
 *  Fase 2: alternancia W^X sobre la code cave                          *
 * ------------------------------------------------------------------ */

/* [WHY] Escribir y ejecutar la misma página es el patrón que los exploits
 * abusan (W^X violation). El runtime legítimo necesita ambas fases, pero
 * nunca simultáneas: se escribe con RW y se ejecuta con R-X. El costo de la
 * syscall (~1µs) solo se paga al aplicar un parche, no en régimen normal. */
int aegis_mman_set_rwx(int executable)
{
    int prot = executable
        ? PROT_READ | PROT_EXEC
        : PROT_READ | PROT_WRITE;
    return mprotect(g_code_cave, AEGIS_CODE_CAVE_SIZE, prot);
}

/* printf prohibido dentro del handler: no usar. */