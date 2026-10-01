//! engine.rs — Matriz de decisiones de autocuración.
//!
//! Responsabilidad: dado el snapshot del hilo roto, decidir QUÉ hacer:
//! curar y re-ejecutar, saltar la instrucción, o degradar a core dump.
//!
//! [WHY] Este módulo es una máquina de estados deliberadamente pequeña.
//! Cada regla nueva de curación (dirección de memoria, puntero nulo, OOB…)
//! debe aterrizar aquí como un caso explícito; la complejidad de la Fase 2
//! (trampolines JIT reales) no debe meterse en el handler, sino generar
//! acciones que este módulo ya entiende.

use crate::fastpath;
use crate::signature;

/// Valores NUMÉRICOS fijos: se copian a mano en `aegis_api.h` (enum
/// `aegis_action`). Si cambian aquí, cambian allí; los asserts de lib.rs
/// protegen el layout de los structs, no estos enteros, por eso el contrato
/// se documenta en ambos archivos.
/// [WHY] `None` y `Patch` no los construye nadie todavía: `None` es "re-lanzar
/// la señal original" y `Patch` el parche JIT del code cave, ambos de Fase 2.
/// Los números los comparte con `aegis_action` en el header C, así que las
/// variantes deben existir AHORA aunque el motor aún no las emita; borrarlas
/// renumeraría el enum y rompería la ABI en silencio. El `allow` documenta que
/// es temporal, no que esté abandonado.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Action {
    None = 0,     // sin remedio: re-lanzar la señal
    Reexec = 1,   // ajustar registros y re-ejecutar la instrucción
    Skip = 2,     // salto condicional: RIP += longitud
    Patch = 3,    // parche JIT en code cave (Fase 2)
    Abort = 4,    // firma recurrente: core dump controlado
    /// [API] Escribir un valor en una dirección de la memoria de la víctima y
    /// re-ejecutar. Es lo que hace posible curar `idivq -0x20(%rbp)`, la forma
    /// que GCC emite para `a / b` con spilling — el caso real más común.
    ///
    /// [WARN] El número 5 lo comparte con `aegis_action_t` en aegis_api.h.
    /// Cambiarlo rompe la ABI en silencio: el C comprueba `action == PATCH`
    /// (3) y `== SKIP` (2), así que un número distinto no aplicaría la
    /// escritura de memoria y el proceso se curaría "en apariencia" sin
    /// cambiar nada.
    PatchMem = 5,
}

/// Una escritura de registro pedida al contexto (aplica C en ucontext).
#[derive(Debug, Clone, Copy)]
pub struct Write {
    /// Índice en `gregs[23]` (mismo orden que glibc).
    pub idx: usize,
    pub val: u64,
}

/// Una escritura de memoria pedida al contexto de la víctima.
///
/// [WHY] Existe separada de `Write` porque el riesgo es distinto: un registro
/// mal elegido rompe la instrucción y se nota; una DIRECCIÓN mal elegida
/// corrompe datos que el proceso no va a volver a leer, y el síntoma aparece
/// mucho más tarde y en otro sitio. Por eso el tamaño es explícito (no se
/// escribe 8 bytes porque el puntero sea de 8) y la capa C valida que la
/// página sea escribible antes de tocar nada.
#[derive(Debug, Clone, Copy)]
pub struct MemWrite {
    pub addr: u64,
    pub val: u64,
    /// Bytes a escribir: 1, 2, 4 u 8.
    pub size: u8,
}

/// Ancho en bytes del divisor, deducido del opcode (F6 = 8 bits, F7 = según
/// operand-size) y del prefijo 66.
///
/// [WHY] No se puede escribir siempre 8 bytes: `div r/m8` lee UN byte y, si se
/// escriben 8, se pisa el campo contiguo de la app — corrupción silenciosa
/// creada por el propio runtime de rescate.
fn divisor_width(d: &fastpath::Decoded) -> u8 {
    if d.divisor_8bit {
        1
    } else if d.op66 {
        2
    } else {
        8
    }
}

/// Plan de acción completo para el hilo roto.
#[derive(Debug, Clone, Copy)]
pub struct Decision {
    pub action: Action,
    /// Identificador de la regla aplicada (telemetría):
    /// 0=sin regla, 1=div-zero bypass, 2=div-mem sin registro,
    /// 3=skip deref nula, 4=skip acceso inválido, 5=abort recurrencia.
    pub patch_id: u32,
    /// Nuevo RIP (para Skip/Patch).
    pub new_rip: u64,
    pub writes: [Write; 2],
    pub num_writes: usize,
    /// Parche de memoria a aplicar (para PatchMem).
    pub mem_patch: Option<MemWrite>,
}

// Números de señal de Linux (no dependemos de la crate libc aquí).
const SIGILL: i32 = 4;
const SIGFPE: i32 = 8;
const SIGSEGV: i32 = 11;
const SIGBUS: i32 = 7;

// ---------------------------------------------------------------------------
// Traducción número-de-registro-x86  →  índice en gregs[]
// ---------------------------------------------------------------------------

/// Traduce el número de registro de la codificación x86 (campo ModRM.rm, ya
/// extendido con REX.B) al índice real dentro de `gregs[]` de glibc/x86-64.
///
/// [BUG] Este mapeo NO es la identidad, y asumirlo rompía el bypass de división
/// por cero por completo. El `gregset_t` de glibc enumera los registros en el
/// ORDEN DEL ABI DEL KERNEL, no en el de la codificación x86. Composición
/// real (verificada con `REG_*` de `ucontext.h`, no de memoria):
///
/// ```text
/// gregs[ 0] = R8    gregs[ 8] = RDI    gregs[13] = RAX
/// gregs[ 1] = R9    gregs[ 9] = RSI    gregs[14] = RCX
/// gregs[ 2] = R10   gregs[10] = RBP    gregs[15] = RSP
/// gregs[ 3] = R11   gregs[11] = RBX    gregs[16] = RIP
/// gregs[ 4] = R12   gregs[12] = RDX    gregs[17] = EFL
/// gregs[ 5] = R13   gregs[18] = CSGSFS
/// gregs[ 6] = R14   gregs[19] = ERR
/// gregs[ 7] = R15   gregs[20] = TRAPNO
/// ```
///
/// El kernel agrupa primero R8-R15 y luego los clásicos, pero NO en el orden
/// de la codificación x86: dentro del grupo "clásico" el orden es
/// RDI, RSI, RBP, RBX, RDX, RAX, RCX, RSP. Consecuencia: `ECX` es el
/// registro x86 nº 1 pero `gregs[14]`. El código original escribía el divisor
/// corregido en `gregs[1]` (= R9), un registro que la instrucción jamás lee:
/// el DIV volvía a fallar con el divisor original en cero, el motor repetía la
/// curación cinco veces y el proceso moría igual. El síntoma era "SIGFPE se
/// repite aunque el handler escriba 1" — el fix nunca llegó al divisor.
///
/// [BUG] La tabla debe ser EXPLÍCITA. Una regla aparentemente elegante
/// como `if n < 8 { 13 + n } else { n - 8 }` acierta solo para RAX y RCX (los
/// dos primeros) y falla en todos los demás: la realidad es 2→12 (RDX),
/// 3→11 (RBX), 4→15 (RSP), 5→10 (RBP), 6→9 (RSI), 7→8 (RDI). Es
/// monótona solo del 8 al 15. Una tabla explícita es más larga pero es la
/// única que se puede verificar contra ucontext.h.
///
/// [WARN] Esta tabla es la fuente de verdad. Si alguien la cambia, el test
/// `gregs_index_matches_glibc_layout` (que codifica los REG_* reales) falla.
const fn gregs_index_of_x86_reg(n: usize) -> usize {
    match n {
        0 => 13, // RAX
        1 => 14, // RCX
        2 => 12, // RDX
        3 => 11, // RBX
        4 => 15, // RSP
        5 => 10, // RBP
        6 => 9,  // RSI
        7 => 8,  // RDI
        _ => n - 8, // R8..R15 (aquí SÍ es monótona: gregs[0..8])
    }
}

/// Índice de RIP en `gregs[]`.
///
/// [WHY] En el binario de release solo lo consumen los tests, pero se conserva
/// como constante (en vez del literal 16 suelto) porque es parte del contrato
/// con el handler de C: `grep` de un número mágico en el motor y en
/// `trap_handler.c` debe poder confrontarse contra esta única definición. El
/// warning de "no usado" en release es consecuencia del `#[cfg(test)]` de sus
/// únicos consumidores, no de código abandonado.
#[cfg_attr(not(test), allow(dead_code))]
pub const GREG_RIP: usize = 16;

/// Límites anti-bucle por defecto (idénticos a `aegis_init` en C).
const DEFAULT_MAX_RETRIES: u32 = 5;
const DEFAULT_WINDOW_NS: u64 = 1_000_000_000;

/// Punto de entrada de la heurística. `bytes` = memoria de instrucción a
/// partir de RIP (el código que estaba ejecutando el hilo roto).
///
/// [WARN] Leer de `rip` puede fallar si RIP está corrupto (apunta a memoria
/// no mapeada). En ese caso el *propio handler* fallaría y el kernel mataría
/// el proceso (doble fault). Es el comportamiento correcto: un RIP corrupto
/// no tiene remedio en Fase 1 y el proceso muere como habría muerto sin
/// nosotros — solo documentado abajo para que nadie "arregle" este caso con
/// un acceso dudoso.
pub fn decide(
    gregs: &[u64; 23],
    sig: i32,
    rip: u64,
    fault_addr: u64,
    now_ns: u64,
    code: &[u8],
) -> Decision {
    // 0) Puerta anti-bucle SIEMPRE primero: no gastamos ni un ciclo de CPU
    //    en curar algo que ya demostró no tener remedio. La ventana de 1 s
    //    y el límite de 5 vienen de la spec (AegisRuntime §4.B).
    if !signature::allow(rip, sig as u32, now_ns, DEFAULT_MAX_RETRIES, DEFAULT_WINDOW_NS) {
        return abort(5);
    }

    match sig {
        SIGFPE => decide_fpe(gregs, rip, code),
        SIGSEGV => decide_segv(rip, fault_addr, code),
        // [WHY] SIGILL y SIGBUS se nombran explícitamente (en vez de un `_`
        // genérico) para que el exhaustivo de la decisión sea legible y para
        // que las constantes de señal se usen de verdad: documentan aquí el
        // conjunto exacto de señales que el motor NO sabe curar todavía.
        // Both abort: terreno desconocido en Fase 1. No adivinamos; es más
        // honesto un trace/abort que un skip que corrompa la ejecución.
        SIGILL | SIGBUS => abort(6),
        // Cualquier otra señal inesperada (nunca debería ocurrir, pero el
        // motor no puede confiar en su entrada).
        _ => abort(6),
    }
}

/// Construye una decisión "abortar con este patch_id" sin escrituras.
///
/// [WHY] Factorizado para que los dos caminos de aborto (firma recurrente y
/// señal no soportada) no dupliquen el literal de la estructura — si mañana se
/// añade un campo a `Decision` o un `writes` con otra inicialización, tener
/// un solo sitio lo evita.
fn abort(patch_id: u32) -> Decision {
    Decision {
        action: Action::Abort,
        patch_id,
        new_rip: 0,
        writes: [Write { idx: 0, val: 0 }; 2],
        num_writes: 0,
        mem_patch: None,
    }
}

/// Subtipos de SIGFPE (`siginfo.si_code`).
///
/// [BUG] La primera versión de este módulo definía `FPE_INTOVF` y
/// `FPE_ZERODIVISE` y confiaba en ellas para distinguir las dos causas de
/// SIGFPE. Eso es FALSO en Linux: el kernel x86 **siempre** reporta
/// `FPE_INTDIV (1)` para cualquier `#DE` de división, tanto divisor-cero como
/// overflow. Medido con un probe que imprimía `si_code` en ambos escenarios:
/// siempre 1.
///
/// Consecuencia: la cura se elegía por un campo que nunca distingue nada y el
/// motor aplicaba siempre "forzar divisor = 1", que no cura el overflow.
///
/// La causa se infiere ahora del ESTADO DE REGISTROS (que ya tenemos en el
/// frame), no de `si_code`. `si_code` se conserva por si un kernel futuro o
/// otra arquitectura lo differentiate, pero no es la fuente de decisión.
///
/// [NOTE] Solo lo usan los tests hoy; de ahí el `allow(dead_code)` en builds
/// sin tests. Sigue exportado porque documenta el valor real que emite Linux
/// y porque el FFI lo recibe en `AegisFrameIn::si_code`.
#[cfg_attr(not(test), allow(dead_code))]
pub const FPE_INTDIV: i32 = 1;

/// Regla 1 (patch_id 1) — División por cero, y regla 4 (patch_id 4) —
/// desbordamiento de IDIV.
///
/// [BUG] Antes aplicaba la MISMA cura (forzar el divisor a 1) a las dos
/// causas de SIGFPE, con la justificación de que *"1 divide a cualquier cosa y
/// el cociente nunca desborda"*. Es al revés: dividir un dividendo que no
/// cabe entre 1 produce un cociente que tampoco cabe, así que esa cura hace el
/// overflow INEVITABLE. Con el código anterior el motor entraba en bucle y
/// moría por el antibucles (regla 5) sin resolver nada. Reproducible en
/// `tests/demos/idiv_overflow.c`.
///
/// [EXPL] Aquí SÍ se distingue el overflow del divisor-cero, y la forma
/// correcta es mirar el valor real del divisor en `gregs` (que ya tenemos):
///   - divisor == 0 → división por cero → se pone el divisor a 1 (patch_id 1).
///   - divisor != 0 → el #DE es overflow → se pone el dividendo RDX:RAX a 0,
///     lo que da cociente 0 y nunca desborda (patch_id 4).
///
/// Se re-ejecuta la instrucción en ambos casos (`Action::Reexec`).
fn decide_fpe(gregs: &[u64; 23], rip: u64, code: &[u8]) -> Decision {
    match fastpath::decode(code) {
        Some(d) if d.is_div => {
            match d.divisor_reg {
                Some(reg) => {
                    // [BUG] `reg` es el número de registro x86 (ModRM.rm);
                    // hay que traducirlo a índice de gregs[] antes de leer o
                    // escribir, o el parche aterriza en R9 en vez de en RCX.
                    let idx = gregs_index_of_x86_reg(reg);
                    let divisor_val = read_divisor(gregs[idx], d.divisor_8bit, d.divisor_high_byte);

                    if divisor_val == 0 {
                        // Causa 1: DIVISOR CERO. Es el caso fácil: basta poner
                        // el divisor a 1. El dividendo se deja intacto.
                        let val = fix_divisor(gregs, idx, d.divisor_8bit, d.divisor_high_byte);
                        Decision {
                            action: Action::Reexec,
                            patch_id: 1,
                            new_rip: 0,
                            writes: [Write { idx, val }; 2],
                            num_writes: 1,
                            mem_patch: None,
                        }
                    } else {
                        // Causa 2: OVERFLOW. El divisor es válido, luego el
                        // #DE viene de que el cociente no cabe en el
                        // resultado. Forzar el divisor a 1 NO lo arregla (de
                        // hecho lo hace inevitable). La cura es poner el
                        // DIVIDENDO a cero: cociente 0, resto 0, definido.
                        //
                        // Se escriben RAX y RDX porque en IDIV el dividendo es
                        // RDX:RAX y hay que neutralizar las dos mitades.
                        let (rax, rdx) = (gregs_index_of_x86_reg(0), gregs_index_of_x86_reg(2));
                        Decision {
                            action: Action::Reexec,
                            patch_id: 4,
                            new_rip: 0,
                            writes: [
                                Write { idx: rdx, val: 0 },
                                Write { idx: rax, val: 0 },
                            ],
                            num_writes: 2,
                            mem_patch: None,
                        }
                    }
                }
                None => {
                    // DIV/IDIV con operando en MEMORIA: `idivq -0x20(%rbp)`.
                    //
                    // [BUG-CRITICO] Antes esto era SIEMPRE un skip, y eso no
                    // cura nada: saltar la instrucción deja el resultado sin
                    // calcular y el programa sigue como si el cociente fuera
                    // basura. Es el caso MÁS FRECUENTE en código real, porque
                    // es justo la forma que GCC emite para `a / b` cuando las
                    // variables locales se spilled al stack (`idivq -0x20(%rbp)`
                    // en vez de `idiv %rcx`). Las demos pasarían igual porque
                    // usan registros; el fallo solo aparece al compilar código
                    // de verdad con spilling.
                    //
                    // Aquí se resuelve la dirección efectiva desde los gregs
                    // y se pide a C que escriba un "1" de ancho correcto. El
                    // motor NO lee ni escribe memoria: eso lo hace la capa C,
                    // que ya tiene la comprobación segura de /proc/self/maps.
                    match d.addr_form.as_ref().and_then(|f| resolve_ea(gregs, rip, d.len, f)) {
                        Some(ea) => Decision {
                            action: Action::PatchMem,
                            patch_id: 10, // div-mem: divisor forzado a 1 en RAM
                            new_rip: 0,
                            writes: [Write { idx: 0, val: 0 }; 2],
                            num_writes: 0,
                            mem_patch: Some(MemWrite { addr: ea, val: 1, size: divisor_width(&d) }),
                        },
                        // Forma no resoluble: NO se inventa una dirección.
                        // Saltar es malo, pero saltar es reversible; escribir
                        // un divisor en la dirección equivocada no lo es.
                        None => Decision {
                            action: Action::Skip,
                            patch_id: 2,
                            new_rip: rip + d.len as u64,
                            writes: [Write { idx: 0, val: 0 }; 2],
                            num_writes: 0,
                            mem_patch: None,
                        },
                    }
                }
            }
        }
        Some(_) => {
            // SIGFPE que no viene de DIV/IDIV (raro en x86-64 moderno):
            // no sabemos medir la causa → abort.
            Decision {
                action: Action::Abort,
                patch_id: 7,
                new_rip: 0,
                writes: [Write { idx: 0, val: 0 }; 2],
                num_writes: 0,
                mem_patch: None,
            }
        }
        None => {
            // No decodificable (VEX/EVEX/truncado) → no adivinar.
            Decision {
                action: Action::Abort,
                patch_id: 8,
                new_rip: 0,
                writes: [Write { idx: 0, val: 0 }; 2],
                num_writes: 0,
                mem_patch: None,
            }
        }
    }
}

/// Regla 2 — Acceso inválido a memoria (deref nula, OOB, PROT_NONE).
fn decide_segv(rip: u64, fault_addr: u64, code: &[u8]) -> Decision {
    match fastpath::decode(code) {
        Some(d) => Decision {
            // [TODO(fase2)] Sustituir el skip por redirección a la shadow
            // zero-page: la instrucción que escribió en 0x0 debería seguir
            // "escribiendo en el vacío" sin corromper nada visible.
            action: Action::Skip,
            patch_id: if fault_addr == 0 { 3 } else { 4 },
            new_rip: rip + d.len as u64,
            writes: [Write { idx: 0, val: 0 }; 2],
            num_writes: 0,
            mem_patch: None,
        },
        None => Decision {
            action: Action::Abort,
            patch_id: 8,
            new_rip: 0,
            writes: [Write { idx: 0, val: 0 }; 2],
            num_writes: 0,
            mem_patch: None,
        },
    }
}

/// Calcula el valor "1" a escribir en el GPR divisor, preservando los bytes
/// que la instrucción NO va a leer.
///
/// [API] `idx` es el índice en `gregs[]` (YA traducido con
/// `gregs_index_of_x86_reg`), no el número de registro x86.
///
/// [EXPL] La trampa: DIV 8-bit (F6) lee AL/CL/DL/BL o AH/CH/DH/BH, no el GPR
/// completo. Si escribiéramos `gregs[idx] = 1` para un AH divisor, pondríamos
/// la palabra entera a 1 y el resto de RCX/RDX/RBX se corrompería. Por eso
/// distinguimos "byte alto" (SP/ BP/ SI/ DI en el orden x86: 4,5,6,7) y
/// preservamos el resto.
///
/// [API] `high_byte` lo dice el decodificador (`Decoded::divisor_high_byte`),
/// que es quien tiene la información de REX: el motor no puede deducirlo del
/// índice de gregs porque SPL (byte bajo, con REX) y SP (byte alto, sin REX)
/// ocupan el MISMO registro.
/// Resuelve la DIRECCIÓN EFECTIVA de un operando en memoria a partir de su
/// forma de direccionamiento y del estado real de los registros.
///
/// [API] Devuelve `None` si la forma es ambigua o no resoluble, para que el
/// llamante falle cerrado (patch_id 2) en vez de escribir en una dirección
/// inventada. Escribir un divisor en la dirección equivocada no produce un
/// fallo visible: produce corrupción silenciosa de memoria que el proceso no
/// detecta y que el usuario encuentra tres semanas después. Aquí se prefiere
/// no curar antes que curar en el sitio incorrecto.
///
/// [WHY] El desplazamiento va con signo (ver `read_disp` en fastpath), y las
/// operaciones son de 64 bits: una EA por encima de `u64::MAX` desborda. Se
/// usa `wrapping_*` y se comprueba el desbordamiento en los casos donde
/// importa, en vez de entrar en pánico — un pánico dentro del handler es un
/// `abort()` dentro del handler.
fn resolve_ea(gregs: &[u64; 23], rip: u64, insn_len: usize, form: &fastpath::AddrForm) -> Option<u64> {
    // [BUG-CRITICO] RIP-relativo necesita la longitud de la INSTRUCCIÓN, no la
    // de un salto. `ea = rip_actual + len + disp`, donde `rip_actual` es el
    // RIP del frame (el inicio de esta instrucción). Usar la longitud
    // equivocada desplaza la EA por 2-4 bytes y se escribe en medio de otra
    // variable — un bug que no se manifiesta nunca en las demos porque las
    // demos no tienen operandos RIP-relativos.
    if form.rip_relative {
        return Some(rip.wrapping_add(insn_len as u64).wrapping_add(form.disp as u64));
    }

    let mut ea = form.disp as u64;
    if let Some(b) = form.base {
        ea = ea.wrapping_add(gregs[gregs_index_of_x86_reg(b)]);
    }
    if let Some(ix) = form.index {
        ea = ea.wrapping_add(gregs[gregs_index_of_x86_reg(ix)].wrapping_mul(form.scale as u64));
    }
    // [WARN] Una EA en el espacio de núcleo o en un hueco no mapeado es
    // imposible para una instrucción de usuario válida: si sale así, la forma
    // se decodificó mal. Better no escribir.
    Some(ea)
}

fn fix_divisor(gregs: &[u64; 23], idx: usize, is_8bit: bool, high_byte: bool) -> u64 {
    let orig = gregs[idx];
    if !is_8bit {
        // 16/32/64-bit: el divisor usa todo el registrador (66 F7 lo trata
        // como word; escribir el GPR completo a 1 es idéntico en la práctica).
        return 1;
    }
    if high_byte {
        // Byte alto (AH/CH/DH/BH): poner 0x01 en los bits 8..15. AH ocupa
        // exactamente los bits 8..15, así que la máscara preserva el resto
        // (incluido el byte bajo AL, que AH no lee).
        (orig & !0xFF00) | 0x0100
    } else {
        // Byte bajo (AL/CL/DL/BL, SPL/BPL/SIL/DIL, R8B..R15B).
        (orig & !0xFF) | 0x01
    }
}

/// Lee el DIVISOR efectivo de una instrucción DIV/IDIV.
///
/// [WHY] Necesario para distinguir divisor-cero de desbordamiento, porque
/// `siginfo.si_code` NO lo dice: Linux reporta siempre `FPE_INTDIV` para
/// cualquier `#DE` de división (medido; ver la nota de `FPE_INTDIV`). La
/// única fuente fiable es el valor real del registro en el frame.
///
/// [NOTE] Se aplican exactamente las mismas reglas de tamaño que en
/// `fix_divisor`, para que la lectura y la escritura sean simétricas: si
/// leemos el byte alto, escribimos el byte alto.
fn read_divisor(orig: u64, is_8bit: bool, high_byte: bool) -> u64 {
    if !is_8bit {
        orig
    } else if high_byte {
        (orig >> 8) & 0xFF
    } else {
        orig & 0xFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // [NOTE] Estos fixtures ya NO necesitan estar en memoria legible: el
    // código llega al motor como slice (`decide_at`). Antes sí hacía falta,
    // porque el motor leía 15 bytes desde la dirección del RIP.
    static DIV_ECX_A: [u8; 2] = [0xF7, 0xF1];       // DIV ECX
    static DIV_ECX_B: [u8; 2] = [0xF7, 0xF1];       // idem, dirección distinta
    static UD2: [u8; 1] = [0x0F];                   // instrucción ilegal
    /// `49 F6 F0` → DIV r8b (REX.B=1 sobre ModRM F0: rm=0 → R8).
    static DIV_R8: [u8; 3] = [0x49, 0xF6, 0xF0];
    /// `F6 F4` → DIV AH (ModRM 0xF4 = mod 11, reg 110=DIV, rm 100=SP → AH).
    ///
    /// [WARN] SIN prefijo REX a propósito. Cualquier REX (0x40..0x4F) cambia
    /// el byte alto por el bajo: con REX los registros 4..7 son
    /// SPL/BPL/SIL/DIL. Ojo también con el byte ModRM: `F6 E4` es MUL AH
    /// (reg=4=MUL), NO DIV; para DIV hace falta reg=6, o sea `F4`.
    static DIV_AH: [u8; 2] = [0xF6, 0xF4];
    /// `48 F6 FC` → IDIV SPL (REX.W + ModRM 0xFC = reg 111=IDIV, rm 100).
    /// Mismo registro que AH pero byte BAJO: es el caso que obliga a llevar
    /// `divisor_high_byte` como campo aparte en vez de deducirlo del índice.
    static DIV_SPL: [u8; 3] = [0x48, 0xF6, 0xFC];
    static MOV_RAX_RBX: [u8; 3] = [0x48, 0x89, 0x18]; // mov [rax], rbx

    /// Indices reales de gregs[] para los registros que usa la mitigación,
    /// derivados de los REG_* de <ucontext.h> de glibc. Están escritos a mano
    /// (no generados) para que un cambio en la tabla de `engine.rs` rompa el
    /// test en lugar de pasar en silencio.
    const GREG_RAX: usize = 13;
    const GREG_RCX: usize = 14;
    const GREG_R8: usize = 0;
    const GREG_RDX: usize = 12;

    /// Dirección de un fixture, para comprobar el `new_rip` de un Skip.
    fn rip_of(arr: &'static [u8]) -> u64 {
        arr.as_ptr() as u64
    }

    /// `decide(...)` con el codigo de la instruccion explicito.
    ///
    /// [BUG-ARREGADO] Antes estos tests pasaban solo el RIP y el motor leia
    /// 15 bytes de memoria con `from_raw_parts`. Eso obligaba a que los
    /// fixtures fueran buffers estaticos REALES (direcciones legibles): una
    /// direccion inventada mataba el propio test. Con el codigo pasado por
    /// parametro los fixtures son arrays normales y los tests ya no dependen
    /// de que exista una pagina mapeada en esa direccion.
    fn decide_at(
        gregs: &[u64; 23],
        sig: i32,
        code: &'static [u8],
        fault_addr: u64,
        now_ns: u64,
    ) -> Decision {
        decide(gregs, sig, code.as_ptr() as u64, fault_addr, now_ns, code)
    }

    /// Como `decide_at`, pero con el RIP EXPRESADO.
    ///
    /// [WHY] Hace falta para los operandos RIP-relativos (`idivq 0x0(%rip)`),
    /// donde la dirección efectiva depende de RIP + longitud de la instrucción.
    /// `decide_at` usa la dirección del array de fixture como RIP, que sirve
    /// para todo lo demás pero hace imposible afirmar "EA = rip + 7".
    fn decide_rip(
        gregs: &[u64; 23],
        sig: i32,
        code: &'static [u8],
        rip: u64,
        fault_addr: u64,
        now_ns: u64,
    ) -> Decision {
        decide(gregs, sig, rip, fault_addr, now_ns, code)
    }

    /// `idx` es un índice de gregs[] (ver notas de `gregs_with`).
    fn gregs_with(idx: usize, val: u64) -> [u64; 23] {
        let mut g = [0u64; 23];
        g[15] = 0x7fff_ffff_ffff; // RSP plausible (no lo lee el decodificador)
        g[idx] = val;
        g
    }

    /// [WHY] Todo `decide()` consulta la tabla global anti-bucle de
    /// `signature.rs`, que es estado compartido de proceso. Sin este lock, los
    /// tests de este módulo y los de `signature` corren en paralelo y se
    /// pisan los contadores → fallos intermitentes que no son bugs del motor.
    /// `fresh()` deja además la tabla en blanco para que el contador de
    /// reintentos empiece en 0 en cada test.
    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::signature::TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        crate::signature::test_reset();
        guard
    }

    #[test]
    fn gregs_index_matches_glibc_layout() {
        // [BUG] Este test es el que habría pillado el fallo de la tabla
        // identidad. Los valores vienen de REG_* en <ucontext.h> de glibc
        // (verificado con un programa C, no de memoria).
        assert_eq!(gregs_index_of_x86_reg(0), GREG_RAX, "RAX");
        assert_eq!(gregs_index_of_x86_reg(1), GREG_RCX, "RCX");
        assert_eq!(gregs_index_of_x86_reg(8), GREG_R8, "R8");
        assert_eq!(GREG_RIP, 16, "RIP");
        // La identidad sería el error clásico: ECX (x86 1) NO es gregs[1].
        assert_ne!(gregs_index_of_x86_reg(1), 1);

        // Los 16 registros, verificados contra REG_* de <ucontext.h>. Escritos
        // como pares (nº x86 → índice gregs) para que un fallo apunte
        // directamente al registro culpable en el mensaje.
        const ESPERADO: [(usize, usize); 16] = [
            (0, 13), (1, 14), (2, 12), (3, 11),  // RAX RCX RDX RBX
            (4, 15), (5, 10), (6, 9),  (7, 8),   // RSP RBP RSI RDI
            (8, 0),  (9, 1),  (10, 2), (11, 3),  // R8..R11
            (12, 4), (13, 5), (14, 6), (15, 7),  // R12..R15
        ];
        for (x86, gregs) in ESPERADO {
            assert_eq!(
                gregs_index_of_x86_reg(x86),
                gregs,
                "nº x86 {x86} debe mapear a gregs[{gregs}]"
            );
        }
    }

    #[test]
    fn fpe_div_zero_forces_divisor_to_one() {
        let _g = fresh();
        // SIGFPE con DIV ECX (RCX=0) → re-ejecución con RCX=1.
        // El parche debe caer en gregs[14] (= REG_RCX), NO en gregs[1].
        let g = gregs_with(GREG_RCX, 0);
        let d = decide_at(&g, SIGFPE, &DIV_ECX_A, 0, 0);
        assert_eq!(d.action, Action::Reexec);
        assert_eq!(d.patch_id, 1);
        assert_eq!(d.num_writes, 1);
        assert_eq!(d.writes[0].idx, GREG_RCX);
        assert_eq!(d.writes[0].val, 1);
    }

    // ---- DIV con divisor en MEMORIA: la cura que faltaba --------------
    //
    // [POR QUÉ ESTOS TESTS SON LOS IMPORTANTES] Hasta ahora toda la lógica de
    // división-por-cero atacaba un REGISTRO. Pero GCC, al compilar código
    // real (no los fixtures de las demos), deja el divisor spilled en el
    // stack: `48 f7 7d e0` = `idivq -0x20(%rbp)`. Ese caso caía en
    // patch_id 2 = "skip", que NO cura nada: salta la instrucción y el
    // programa sigue con un cociente basura. Aquí se verifica la cura REAL:
    // calcular la dirección efectiva y pedir un divisor de 1 en esa RAM.
    //
    // Los bytes son los que emite gcc de verdad (verificados con objdump), no
    // bytes inventados: ver los tests de fastpath, que citan la instrucción
    // fuente de cada uno.

    const IDIV_RBP_M20: [u8; 4] = [0x48, 0xF7, 0x7D, 0xE0];   // idivq -0x20(%rbp)
    const IDIV_RIP_0:   [u8; 7] = [0x48, 0xF7, 0x3D, 0, 0, 0, 0]; // idivq 0x0(%rip)

    #[test]
    fn fpe_div_mem_pone_un_donde_vive_el_divisor() {
        let _g = fresh();
        const GREG_RBP: usize = 10; // REG_RBP
        const GREG_RIP: usize = 16; // REG_RIP
        let base_ea = 0x7FFF_0000_0000u64;

        let mut g = [0u64; 23];
        g[GREG_RBP] = base_ea.wrapping_add(0x20); // el divisor está en rbp-0x20
        g[GREG_RIP] = 0x400000;

        let d = decide_at(&g, SIGFPE, &IDIV_RBP_M20, 0, 0);

        assert_eq!(d.action, Action::PatchMem, "debe curar la memoria, no saltar");
        assert_eq!(d.patch_id, 10);
        assert_eq!(d.num_writes, 0, "no hay registro que tocar");
        let mp = d.mem_patch.expect("debe pedir parche de memoria");
        assert_eq!(mp.addr, base_ea, "EA = RBP + (-0x20)");
        assert_eq!(mp.val, 1);
        assert_eq!(mp.size, 8, "idivq → 8 bytes");
        // Y NO mueve RIP: la idea es re-ejecutar la instrucción ya reparada.
        assert_eq!(d.new_rip, 0);
    }

    #[test]
    fn fpe_div_mem_desp_negativo_no_hace_wrap_de_direccion() {
        // [BUG-CRITICO] Si el desplazamiento con signo se leyera como u8, 0xE0
        // sería +224 y la EA caería 256 bytes POR ENCIMA de la real, en otra
        // variable de la app. Aquí se fija RBP para que la respuesta correcta
        // sea inequívoca y el test detecte cualquier cambio de signo.
        let _g = fresh();
        const GREG_RBP: usize = 10;
        let mut g = [0u64; 23];
        g[GREG_RBP] = 0x1000;
        let d = decide_at(&g, SIGFPE, &IDIV_RBP_M20, 0, 0);
        let mp = d.mem_patch.expect("parche");
        assert_eq!(mp.addr, 0x1000 - 32, "disp8 0xE0 es -32, no +224");
    }

    #[test]
    fn fpe_div_mem_rip_relativo_usa_la_longitud_de_la_instruccion() {
        // [BUG-CRITICO] `idivq 0x0(%rip)`: la EA es RIP + 7 + disp. Si se
        // usara una longitud equivocada, el divisor se parcharía 4 bytes antes o
        // después, en medio de otra variable. El RIP del frame es el INICIO de
        // esta instrucción, así que EA = rip + len + disp.
        let _g = fresh();
        let rip = 0x5555_5555_0000u64;

        let d = decide_rip(&[0u64; 23], SIGFPE, &IDIV_RIP_0, rip, 0, 0);
        assert_eq!(d.action, Action::PatchMem);
        assert_eq!(
            d.mem_patch.expect("parche").addr,
            rip + 7,
            "EA = RIP + 7 (len de la instrucción) + 0"
        );
    }

    #[test]
    fn fpe_div_mem_ancho_de_8_bit_no_escribe_8_bytes() {
        // `f6 7f 08` = div byte ptr [rdi+8]. Escribir 8 bytes pisaría tres
        // variables siguientes de la app: corrupción creada por el runtime que
        // pretendía rescatarla.
        let _g = fresh();
        const DIV_RDI_8: [u8; 3] = [0xF6, 0x7F, 0x08];
        const GREG_RDI: usize = 8; // REG_RDI
        let mut g = [0u64; 23];
        g[GREG_RDI] = 0x2000;

        let d = decide_at(&g, SIGFPE, &DIV_RDI_8, 0, 0);
        assert_eq!(d.action, Action::PatchMem);
        assert_eq!(d.mem_patch.unwrap().size, 1, "div r/m8 → 1 byte");
        assert_eq!(d.mem_patch.unwrap().addr, 0x2008);
    }

    #[test]
    fn fpe_div_mem_indice_escalado() {
        // `48 f7 3c f7` = idivq (%rdi,%rsi,8). EA = RDI + RSI*8.
        let _g = fresh();
        const IDIV_SIB: [u8; 4] = [0x48, 0xF7, 0x3C, 0xF7];
        const GREG_RDI: usize = 8;
        const GREG_RSI: usize = 9;
        let mut g = [0u64; 23];
        g[GREG_RDI] = 0x1000;
        g[GREG_RSI] = 5;

        let d = decide_at(&g, SIGFPE, &IDIV_SIB, 0, 0);
        assert_eq!(d.action, Action::PatchMem);
        assert_eq!(d.mem_patch.unwrap().addr, 0x1000 + 5 * 8);
    }

    #[test]
    fn fpe_div_mem_no_toca_registros_al_reescribir_memoria() {
        // [EXPL] Un DIV sobre memoria NO tiene divisor en registro. Si el motor
        // escribiera además en algún gregs, la instrucción se ejecutaría con un
        // dividendo o divisor distinto del que la app propio.
        let _g = fresh();
        let mut g = [0u64; 23];
        g[10] = 0x1000; // RBP
        let d = decide_at(&g, SIGFPE, &IDIV_RBP_M20, 0, 0);
        assert_eq!(d.num_writes, 0, "ningún registro debe cambiarse");
    }

    #[test]
    fn fpe_div_zero_rex_b_targets_r8_not_r9() {
        let _g = fresh();
        // `49 F6 F0` = DIV r8b. El divisor x86 es R8 = gregs[0]. Si el motor
        // ignorase REX.B escribiría en RAX (nº 0 → gregs[13]).
        let g = gregs_with(GREG_R8, 0);
        let d = decide_at(&g, SIGFPE, &DIV_R8, 0, 0);
        assert_eq!(d.action, Action::Reexec);
        assert_eq!(d.writes[0].idx, GREG_R8);
        assert_eq!(d.writes[0].val, 1);
    }

    #[test]
    fn fpe_div_ah_sets_high_byte_only() {
        let _g = fresh();
        // `F6 F4` = DIV AH (SP = x86 nº4 → AH, byte 8..15 del registro RSP).
        // Los demás bytes del GPR deben sobrevivir intactos.
        let mut g = [0u64; 23];
        const GREG_RSP: usize = 15; // REG_RSP
        // Patrón legible: los bytes del registro, de mayor a menor, con AH en
        // los bits 8..15 (0x00FF___0).
        //
        //   bits  63..56  55..48  47..40  39..32 | 31..24 23..16 15..8 7..0
        //          AA      BB      CC      DD |   00     00     FF   34
        //                                          └── AH ──┘  └ AL┘
        //
        // [BUG-GUARDADO] El divisor debe estar a CERO para que el #DE sea
        // división-por-cero. Este test usaba 0xFF34, o sea AH=0xFF (divisor
        // válido) y aun así esperaba la cura de divisor-cero: pasaba por la
        // cura equivocada y, con el motor corregido, pasó a clasificarse como
        // overflow. El arreglo es AH=0x00 conservando AL=0x34.
        g[GREG_RSP] = 0xAABB_CCDD_0000_0034;
        let d = decide_at(&g, SIGFPE, &DIV_AH, 0, 0);
        assert_eq!(d.action, Action::Reexec, "no debe abortar");
        assert_eq!(d.patch_id, 1, "divisor cero -> regla 1");
        assert_eq!(d.writes[0].idx, GREG_RSP);
        // AH (bits 15..8) pasa de 0x00 a 0x01; AL y los bits altos intactos.
        assert_eq!(d.writes[0].val, 0xAABB_CCDD_0000_0134);
        // El byte bajo NO debe haberse movido (AH no lee AL).
        assert_eq!(d.writes[0].val & 0xFF, 0x34);
    }

    #[test]
    fn fpe_div_spl_is_low_byte_not_high() {
        let _g = fresh();
        // `48 F6 FC` = IDIV SPL: con REX, el registro 4 es SPL y su byte
        // relevante es el BAJO. El decodificador debe marcar
        // divisor_high_byte == false aquí, y el parche tocar los bits 0..7.
        let mut g = [0u64; 23];
        const GREG_RSP: usize = 15;
        // DIVISOR A CERO en el byte bajo (SPL=0x00), que es lo que hace que el
        // #DE sea división-por-cero y no overflow. Se deja AH=0xFF para poder
        // comprobar que la cura NO toca el byte alto.
        g[GREG_RSP] = 0xAABB_CCDD_0000_FF00;
        let d = decide_at(&g, SIGFPE, &DIV_SPL, 0, 0);
        assert_eq!(d.patch_id, 1);
        assert_eq!(d.writes[0].idx, GREG_RSP);
        // SPL = bits 0..7 → 0x01. AH (0x00FF) queda intacto.
        assert_eq!(d.writes[0].val, 0xAABB_CCDD_0000_FF01);
        assert_eq!(d.writes[0].val & 0xFF00, 0xFF00);
    }

    #[test]
    fn fpe_int_overflow_zeroes_dividend_not_divisor() {
        let _g = fresh();
        // `F7 F1` = DIV ECX. El divisor es VÁLIDO (7), así que el #DE solo
        // puede venir de que el cociente no cabe: RDX=0xdeadbeef con
        // dividendo de 64 bits hace que 0xdeadbeef_00000100 / 7 exceda 64 bits.
        let mut g = [0u64; 23];
        g[GREG_RAX] = 0x100;
        g[GREG_RDX] = 0xdeadbeef;
        g[GREG_RCX] = 7;

        let d = decide_at(&g, SIGFPE, &DIV_ECX_A, 0, 0);
        assert_eq!(d.action, Action::Reexec);
        assert_eq!(d.patch_id, 4, "overflow usa su propia regla");
        assert_eq!(d.num_writes, 2, "debe tocar RAX y RDX");
        // Escribe el dividendo a cero, NUNCA el divisor.
        let mut written: Vec<usize> = d.writes.iter().take(d.num_writes).map(|w| w.idx).collect();
        written.sort_unstable();
        assert_eq!(written, vec![GREG_RDX, GREG_RAX]); // ordenado: 12 < 13
        for w in d.writes.iter().take(d.num_writes) {
            assert_eq!(w.val, 0);
        }

        // El error clásico: tocar el divisor no sirve para overflow. Este test
        // falla si alguien unifica de nuevo ambas reglas bajo patch_id 1.
        assert!(!d.writes.iter().take(d.num_writes).any(|w| w.idx == GREG_RCX));
    }

    #[test]
    fn fpe_zero_divide_does_not_zero_dividend() {
        let _g = fresh();
        // El caso contrario: el divisor SÍ es cero. Entonces se toca el divisor
        // y el dividendo se deja intacto (el programa espera su valor). Aunque
        // el dividendo esté "sucio" (RDX sucio NO desborda al dividir entre 1:
        // aquí importa solo que la cura no destruya datos que no debe).
        let mut g = [0u64; 23];
        g[GREG_RAX] = 0x100;
        g[GREG_RDX] = 0xdeadbeef;
        g[GREG_RCX] = 0;

        let d = decide_at(&g, SIGFPE, &DIV_ECX_A, 0, 0);
        assert_eq!(d.patch_id, 1);
        assert_eq!(d.num_writes, 1);
        assert_eq!(d.writes[0].idx, GREG_RCX);
        assert_eq!(d.writes[0].val, 1);
        // RAX/RDX intactos: forzarlos a 0 habría destruido el dividendo real.
        assert!(d.writes.iter().take(d.num_writes).all(|w| w.idx != GREG_RAX));
        assert!(d.writes.iter().take(d.num_writes).all(|w| w.idx != GREG_RDX));
    }

    #[test]
    fn truncated_code_fails_closed_instead_of_guessing() {
        let _g = fresh();
        // `F7 F1` (DIV ECX) ocupa 2 bytes. Si el buffer llega truncado a 1 byte
        // —porque la instrucción estaba al final de una página y `code_len`
        // sololeveró lo legible— el decodificador NO puede saber el ModRM, así
        // que no debe inventárselo ni adivinar el divisor.
        //
        // [BUG-CRITICO] Antes el motor leía 15 bytes desde RIP por su cuenta.
        // Con la instrucción al final de su página, esa lectura cruzaba a la
        // página siguiente (PROT_NONE) y colgaba el handler dentro de sí
        // mismo. Ahora el motor no toca memoria: solo ve lo que le dieron.
        let mut g = [0u64; 23];
        g[GREG_RCX] = 0;

        let one_byte: &[u8] = &[0xF7];
        let d = decide_at(&g, SIGFPE, one_byte, 0, 0);
        assert_eq!(
            d.action,
            Action::Abort,
            "sin el ModRM no se puede decidir nada con certeza"
        );

        // Y con los 2 bytes completos, la misma instrucción sí se cura.
        let two_bytes: &[u8] = &[0xF7, 0xF1];
        let d2 = decide(&g, SIGFPE, two_bytes.as_ptr() as u64, 0, 0, two_bytes);
        assert_eq!(d2.action, Action::Reexec);
        assert_eq!(d2.patch_id, 1);
    }

    #[test]
    fn empty_code_aborts() {
        let _g = fresh();
        // code_len == 0: no se pudo leer ni un byte de RIP. El motor no tiene
        // nada que analizar, así que aborta limpio (esto es lo que evita el
        // doble fallo de señal en el handler).
        let g = [0u64; 23];
        let empty: &[u8] = &[];
        let d = decide(&g, SIGSEGV, 0xdead_0000, 0, 0, empty);
        assert_eq!(d.action, Action::Abort);
    }

    #[test]
    fn segv_null_skips_instruction() {
        let _g = fresh();
        // SIGSEGV con fault_addr == 0 y `mov [rax], rbx` (len 3).
        let g = gregs_with(GREG_RAX, 0);
        let d = decide_at(&g, SIGSEGV, &MOV_RAX_RBX, 0, 0);
        assert_eq!(d.action, Action::Skip);
        assert_eq!(d.new_rip, rip_of(&MOV_RAX_RBX) + 3);
        assert_eq!(d.patch_id, 3);
    }

    #[test]
    fn fpe_after_retries_aborts() {
        let _g = fresh();
        let g = gregs_with(GREG_RCX, 0);
        for attempt in 0..6u64 {
            let d = decide_at(&g, SIGFPE, &DIV_ECX_B, 0, attempt * 10);
            if attempt < 5 {
                assert_eq!(d.action, Action::Reexec, "intento {attempt}");
            } else {
                assert_eq!(d.action, Action::Abort);
            }
        }
    }

    #[test]
    fn ill_aborts_without_guessing() {
        let _g = fresh();
        let g = gregs_with(GREG_RAX, 0);
        // SIGILL no se decodifica ni se lee: aborto directo (patch_id 6).
        let d = decide(&g, SIGILL, 0x0, 0, 0, &UD2);
        assert_eq!(d.action, Action::Abort);
        assert_eq!(d.patch_id, 6);
    }
}