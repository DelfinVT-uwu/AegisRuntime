/*
 * aegis_api.h — C-ABI pública de AegisRuntime.
 *
 * Responsabilidad: definir el CONTRATO entre aegis_sys (C23, lo que invoca el
 * kernel) y aegis_core (Rust, quien decide la mitigación). Cualquier cambio aquí
 * rompe ambos lados a la vez; por eso el contrato es un par de structs planos
 * #[repr(C)] y no una estructura dependiente del layout de glibc.
 *
 * [WARN] Este header se compila en C23 Y se replica a mano en Rust (lib.rs).
 *        Mantener ambas copias idénticas:
 *        size check:  _Static_assert en C-usuario + assert en Rust.
 */
#ifndef AEGIS_API_H
#define AEGIS_API_H

#include <stdint.h>
#include <stddef.h>   /* offsetof, usado en los _Static_assert */

#ifdef __cplusplus
extern "C" {
#endif

/* NGREG = 23 registros GPR del gregset_t de glibc/x86-64 (sys/ucontext.h).
 * Copiamos el array completo con memcpy: el orden concreto lo define
 * _GNU_SOURCE en el .c, no este header. */
#define AEGIS_NGREG 23

/* Longitud máxima de una instrucción x86-64 (15 bytes: prefijos + opcode +
 * ModRM + SIB + displacement + inmediato). Es el tamaño de la ventana que el
 * decodificador necesita y también el del campo `code` de frame_in. */
#define AEGIS_CODE_MAX 15

/* ---------------------------------------------------------------- *
 *  Acciones de mitigación que Rust puede pedirle a C                *
 * ---------------------------------------------------------------- */
typedef enum aegis_action {
    AEGIS_ACTION_NONE     = 0, /* sin remedio aplicable (aún): re-lanzar señal */
    AEGIS_ACTION_REEXEC   = 1, /* ajustar registros y RE-EJECUTAR la instrucción */
    AEGIS_ACTION_SKIP     = 2, /* saltar la instrucción (RIP += len)            */
    AEGIS_ACTION_PATCH    = 3, /* parche JIT aplicado en code cave (fase 2)     */
    AEGIS_ACTION_ABORT    = 4, /* firma recurrente: core dump controlado        */
    /* [API] Escribir en la memoria de la víctima (`mem_addr`) y RE-EJECUTAR
     * la misma instrucción. Es lo que cura `idivq -0x20(%rbp)`: el divisor
     * está en el stack spilled, no en un registro, así que no hay registro que
     * parchear y saltar la instrucción dejaría el resultado sin calcular.
     *
     * El 5 lo comparte con `Action::PatchMem` en engine.rs. Renumerar cualquiera
     * de los dos rompe la curación EN SILENCIO: el `switch` de C no cae en la
     * rama de escritura, el proceso se "cura" sin cambiar nada y la telemetría
     * sigue diciendo rule=10. Por eso el número vive en un enum compartido y no
     * en dos literales. */
    AEGIS_ACTION_PATCH_MEM = 5,
} aegis_action_t;

/* ---------------------------------------------------------------- *
 *  frame_in: instantánea del hilo roto (va de C → Rust)            *
 * ---------------------------------------------------------------- */
typedef struct aegis_frame_in {
    int32_t    sig;          /* señal: SIGSEGV/SIGFPE/SIGILL/SIGBUS          */
    /* [API] siginfo.si_code: SUB-tipo del fallo. Ocupa el padding de
     * alineación que ya existía entre `sig` y `fault_addr`, así que el
     * tamaño del struct (208 B) y los offsets de fault_addr/rip/gregs NO
     * cambian — es una ampliación ABI-gratis.
     *
     * [WHY] Hace falta porque SIGFPE es una señal ambigua: `FPE_ZERODIVISE`
     * y `FPE_INTOVF` llegan como el MISMO SIGFPE. Sin este campo el motor
     * fuerza el divisor a 1 para ambos, y esa cura es FALSA para el
     * desbordamiento (ver decide_fpe en engine.rs y tests/demos/idiv_overflow.c). */
    int32_t    si_code;      /* subtipo: FPE_* / SEGV_MAPERR / SEGV_ACCERR...  */
    uint64_t   fault_addr;   /* siginfo.si_addr: dirección que disparó el trap */
    uint64_t   rip;          /* puntero de instrucción en el momento del fallo */
    uint64_t   gregs[AEGIS_NGREG]; /* copia plana de uc_mcontext.gregs[]      */
    /* [API] COPIA SEGURA de los bytes de la instrucción en RIP.
     *
     * [WHY] El motor NO debe leer memoria por su cuenta. Antes lo hacía con
     * `slice::from_raw_parts(rip, 15)`, lo que rompía dos cosas:
     *   1) Si RIP no era legible (fallo de FETCH sobre una página PROT_NONE,
     *      salto a dirección basura) el handler se colgaba dentro de sí mismo
     *      y el kernel mataba el proceso sin log. Ver `aegis_try_read_code`.
     *   2) Una ventana fija de 15 bytes descarta la curación de cualquier
     *      instrucción a menos de 15 bytes del final de su página, aunque la
     *      instrucción ENTERA quepa (que es el caso normal).
     *
     * La capa C copia el PREFIJO LEGIBLE (hasta 15 bytes, o hasta donde acabe
     * la página) y Rust decodifica SOLO sobre esa copia. `code_len` puede ser
     * menor que la longitud real de la instrucción si el resto estaba
     * truncado; en ese caso el decodificador debe fallar cerrado en vez de
     * adivinar (ver `protected_against_truncation` en fastpath.rs).
     *
     * Esto también deja a Rust sin NINGÚN `unsafe` de acceso a memoria, que
     * es exactamente donde no queremos estar dentro de un signal handler. */
    uint8_t    code[AEGIS_CODE_MAX]; /* hasta 15 bytes (x86-64), ya copiados  */
    uint8_t    code_len;     /* bytes válidos en `code` (0..=15)              */
    uint8_t    reserved[7];  /* relleno explícito a 8 para tamaño estable     */
} aegis_frame_in_t;

/* ---------------------------------------------------------------- *
 *  Layout: si esto no cuadra, el C y Rust se pisan el uno al otro.  *
 *  Espejo exacto de los `const _: () = { assert!(...) }` de        *
 *  aegis_core/src/lib.rs.                                            *
 * ---------------------------------------------------------------- */
_Static_assert(sizeof(aegis_frame_in_t) == 232,
               "frame_in: C y Rust deben coincidir (4+4+8+8+184+15+1+7 -> 232)");
_Static_assert(offsetof(aegis_frame_in_t, si_code) == 4, "frame_in.si_code");
_Static_assert(offsetof(aegis_frame_in_t, fault_addr) == 8, "frame_in.fault_addr");
_Static_assert(offsetof(aegis_frame_in_t, rip) == 16, "frame_in.rip");
_Static_assert(offsetof(aegis_frame_in_t, gregs) == 24, "frame_in.gregs");
_Static_assert(offsetof(aegis_frame_in_t, code) == 208, "frame_in.code");
_Static_assert(offsetof(aegis_frame_in_t, code_len) == 223, "frame_in.code_len");

/* ---------------------------------------------------------------- *
 *  frame_out: mutaciones pedidas por Rust (va de Rust → C)         *
 * ---------------------------------------------------------------- */
typedef struct aegis_frame_out {
    uint32_t   action;       /* aegis_action_t                                */
    uint32_t   patch_id;     /* id del parche/regla aplicada (telemetría)     */
    uint64_t   new_rip;      /* relevante solo si action == SKIP o PATCH      */
    uint64_t   gregs_mask;   /* bit i = sobrescribir gregs[i] del contexto    */
    uint64_t   gregs[AEGIS_NGREG]; /* nuevos valores (aplicados según mask)  */
    /* [API] Parche de MEMORIA: la cura del divisor cuando el DIV/IDIV
     * opera sobre un operando en RAM (`idivq -0x20(%rbp)`), que es la forma
     * que emite GCC para `a / b` con variables locales spilled. Hasta ahora
     * ese caso caía en patch_id 2 = "skip", que NO cura nada: salta la
     * instrucción y el resultado es basura silenciosa.
     *
     * [WHY] El motor NO calcula aquí la dirección efectiva por su cuenta ni la
     * escribe. Fija `mem_addr` (que ya ha resuelto leyendo los gregs, que sí
     * tiene) y C hace la escritura, porque ESCRIBIR en la memoria de un
     * proceso roto es la operación más peligrosa del runtime: si la dirección
     * está mal calculada, corrompe algo que funcionaba. Mantener el acto en C
     * —donde ya está la lectura segura de /proc/self/maps— permite validar
     * que la página es escribible ANTES de escribir.
     *
     * `mem_size` (1/2/4/8) es el tamaño del divisor en bytes, que depende del
     * operando (`div r/m8` vs `idivq r/m64`). Escribir 8 bytes cuando la
     * instrucción solo lee 4 pisaría el campo contiguo de la app.
     *
     * Se añaden AL FINAL a propósito: los offsets de los campos previos no
     * cambian, así que un motor Rust antiguo sigue hablando con este header.
     */
    uint64_t   mem_addr;     /* dirección efectiva a parchear (0 = no aplica)  */
    uint64_t   mem_val;      /* valor a escribir (1 para el divisor)           */
    uint32_t   mem_size;     /* 0 = no aplica; si no, 1, 2, 4 u 8              */
    uint32_t   reserved2;    /* relleno explícito a 8 para tamaño estable     */
} aegis_frame_out_t;

_Static_assert(sizeof(aegis_frame_out_t) == 232, "frame_out");
_Static_assert(offsetof(aegis_frame_out_t, gregs) == 24, "frame_out.gregs");
_Static_assert(offsetof(aegis_frame_out_t, mem_addr) == 208, "frame_out.mem_addr");
_Static_assert(offsetof(aegis_frame_out_t, mem_size) == 224, "frame_out.mem_size");

/* ---------------------------------------------------------------- *
 *  Configuración de arranque (Modo B: SDK nativo)                  *
 * ---------------------------------------------------------------- */
typedef struct aegis_config {
    uint32_t   max_patch_retries; /* límite de re-parcheos por firma (def: 5) */
    uint64_t   retry_window_ns;   /* ventana temporal del contador   (def: 1s) */
    int        enable_shadow_memory; /* Fase 2+: reservar shadow page (def: 1)*/
    int        log_fd;             /* fd para telemetría (def: 2 = stderr)    */
} aegis_config_t;

/* ---------------------------------------------------------------- *
 *  API pública                                                      *
 * ---------------------------------------------------------------- */

/* Inicializa el motor. Idempotente y seguro de llamar varias veces.
 * En Modo A (LD_PRELOAD) lo invoca automáticamente el constructor. */
int aegis_init(const aegis_config_t *cfg);

/* Núcleo exportado por aegis_core (Rust). Decide la mitigación a partir del
 * snapshot del hilo roto. NO es async-signal-safe por defecto en general, pero
 * la implementación fast-path está escrita para no alocar ni bloquear:
 * por eso el contrato es plano y sin punteros al heap. */
int aegis_analyze_and_heal(const aegis_frame_in_t *frame_in,
                           aegis_frame_out_t      *frame_out);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_API_H */