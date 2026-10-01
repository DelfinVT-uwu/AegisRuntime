//! fastpath.rs — Decodificador de instrucciones x86-64 (fast-path).
//!
//! Responsabilidad: dado el byte-stream que empieza en `RIP`, decir con qué
//! longitud continúa la ejecución y si la instrucción es un `DIV`/`IDIV` con
//! divisor en registro (el único caso que Fase 1 sabe curar sin memoria).
//!
//! [WHY] Este módulo está escrito para compilar en `#![no_std]`: cero
//! alocación, cero locks, solo slices y aritmética. Corre dentro del signal
//! handler, donde un fallo del *motor* sería tan letal como el fallo del
//! programa que prometemos curar. Por eso no hay `Vec`, `String` ni `format!`
//! aquí. (La prueba es su uso: los tests usan std; el fast-path no.)
//!
//! [TODO(fase2)] En Fase 2 este módulo se sustituye por un wrapper sobre
//! Zydis para cubrir VEX/EVEX y semántica completa de operandos de memoria.
//! El motivo de mantener un decodificador propio en Fase 1 es que la
//! integración FFI con Zydis es trabajo, mientras que el bypass de
//! división por cero solo necesita: longitud + `DIV`/`IDIV` + índice del
//! registro divisor. Aquello que no sabemos decodificar → devolvemos `None`
//! y la heurística aborta en vez de adivinar (ver `engine.rs`).

/// Longitud máxima de una instrucción x86-64 (imposición del propio ISA,
/// no una elección nuestra: el decodificador de la CPU descarta más de 15).
pub const MAX_INSN_LEN: usize = 15;

/// Información mínima que la heurística necesita para decidir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// Longitud total de la instrucción en bytes.
    pub len: usize,
    /// `true` si es `DIV`/`IDIV` (grupo 3, ModRM.reg == 6|7).
    pub is_div: bool,
    /// Índice del GPR divisor (0=RAX..15=R15) si ModRM.mod == 3 (operando
    /// en registro). `None` para operando en memoria: curarlo requiere
    /// resolver la dirección efectiva, cosa que Fase 1 no hace.
    pub divisor_reg: Option<usize>,
    /// `true` si el divisor es de 8 bits (F6: AH/AL/CL...). Determina cómo
    /// se escribe el "1" sin romper los bytes altos del GPR.
    pub divisor_8bit: bool,
    /// `true` si el divisor es un byte ALTO (AH/CH/DH/BH). Solo puede ser
    /// `true` si `divisor_8bit`.
    ///
    /// [BUG] Faltaba esta distinción y hacía imposible curar `DIV AH`
    /// sin corromper el registro: el motor solo sabía "8 bits" y escribía el
    /// byte bajo, dejando AH en cero → el DIV volvía a fallar. Y escribir el
    /// GPR entero a 1 habría destruido los bytes altos que el programa espera.
    ///
    /// [EXPL] Un byte alto exige que NO haya REX: con cualquier prefijo REX,
    /// los registros 4..7 pasan a ser SPL/BPL/SIL/DIL (byte bajo). Por eso el
    /// campo se calcula con el flag `saw_rex`, no solo con el número de reg.
    pub divisor_high_byte: bool,
    /// `true` si `IDIV` (firmado); solo informativo para telemetría.
    pub signed: bool,
    /// FORMA de direccionamiento del operando de memoria, cuando el DIV/IDIV
    /// no opera sobre un registro.
    ///
    /// [WHY] Esto NO es la dirección efectiva, y la distinción es deliberada.
    /// La EA final depende de los VALORES de los registros, que son estado
    /// del hilo roto; el decodificador solo ve bytes. Por eso `fastpath`
    /// devuelve la forma (base + index·scale + disp) y quien tiene los
    /// `gregs` —`engine.rs`— la resuelve. Mantener el decodificador libre de
    /// "qué vale RCX ahora mismo" es lo que permite testearlo con arrays
    /// estáticos (ver los tests de este módulo).
    ///
    /// Antes de esto, un `div [mem]` caía en `patch_id 2` = skip: no se
    /// curaba nada y el programa continuaba con un resultado basura. Es la
    /// forma que emite GCC para `a / b` con spilling de variables locales,
    /// o sea **el caso más común de división por cero en código real
    /// compilado**, no un caso exótico.
    pub addr_form: Option<AddrForm>,
    /// `true` si había prefijo 0x66 (operando de 16 bits). Necesario para
    /// saber el ANCHO del divisor en RAM (`div word ptr` son 2 bytes): sin
    /// esto se escribirían 8 y se pisaría el campo contiguo de la app.
    pub op66: bool,
}

/// Forma de direccionamiento x86-64 de un operando en memoria.
///
/// [WARN] `base`/`index` son números de registro del ABI x86 (0=RAX..15=R15),
/// NO índices de `gregs[]`. Convertirlos con la tabla de `engine.rs`;plets
/// confundirlos es el bug nº4 de ARCHITECTURE.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrForm {
    /// Registro base, si lo hay (`None` = sin base, p. ej. `[disp32]`).
    pub base: Option<usize>,
    /// Registro índice, si lo hay.
    pub index: Option<usize>,
    /// Escala del índice: 1, 2, 4 u 8.
    pub scale: u8,
    /// Desplazamiento con signo.
    pub disp: i64,
    /// `true` si el operando es RIP+disp32 (ModRM.mod=00, rm=101, sin SIB).
    ///
    /// [WHY] Es un caso aparte porque NO hay ningún registro: la EA es
    /// `RIP_actual + longitud_instrucción + disp`, y "RIP_actual" hay que
    /// tomarlo del frame, no de aquí. Confundirlo con "base = RIP" y luego
    /// buscar RIP en `gregs` funcionaría por casualidad (RIP ES gregs[16]),
    /// pero ocultaría que la EA depende también de la longitud de la
    /// instrucción, que es justo lo que este decodificador calcula.
    pub rip_relative: bool,
}

// ---------------------------------------------------------------------------
// Tablas de forma: por cada opcode, ¿hay ModRM y qué inmediato le sigue?
// ---------------------------------------------------------------------------

/// Clase de inmediato tras opcode (+ModRM). Se traduce a bytes según prefijos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Imm {
    None,
    I8,       // 1 byte
    I16,      // 2 bytes
    I32,      // 4 bytes
    Enter,    // enter imm16,imm8 → 3 bytes de inmediato (4 total con opcode)
    I32or64,  // 4 si !REX.W, 8 si REX.W (mov r64, imm64)
    I16or32,  // 2 si prefijo 66, 4 si no
    Moffs,    // desplazamiento absoluto: 4 si 67 (addr32), 8 si no
    F6,       // grupo3 /0: imm8 solo si ModRM.reg == 0 (TEST)
    F7,       // grupo3 /0: imm16or32 solo si ModRM.reg == 0 (TEST)
}

/// Especificación de un opcode de 1 byte en modo 64-bit.
///
/// [EXPL] Esta función es la "tabla" de decodificación: en vez de una matriz
/// de 256 entradas (ilegible), expresamos rangos. La regla x86 de oro: los
/// opcodes de ALU (00-3F), la mayoría de grupos (80-8F, C0-C7, D0-DF, F6-F7,
/// FE-FF) llevan ModRM; los de flujo (E8-EB, 70-7F), push/pop/mov de
/// registro (50-5F, B0-BF) y los de pila no lo llevan.
fn one_byte(op: u8) -> Option<(bool, Imm)> {
    Some(match op {
        0x00..=0x3F => (true, Imm::None),          // ALU r/m, r / r, r/m
        0x50..=0x5F => (false, Imm::None),         // push/pop reg
        0x60 | 0x61 => (false, Imm::None),         // pusha/popa (inválido 64-bit)
        0x63        => (true, Imm::None),          // movsxd r64, r/m32
        0x68        => (false, Imm::I32),          // push imm32
        0x69        => (true, Imm::I32),           // imul r, r/m, imm32
        0x6A        => (false, Imm::I8),           // push imm8
        0x6B        => (true, Imm::I8),            // imul r, r/m, imm8
        0x6C..=0x6F => (false, Imm::None),         // ins/outs
        0x70..=0x7F => (false, Imm::I8),           // Jcc rel8
        0x80        => (true, Imm::I8),            // grupo1 /0-7, imm8
        0x81        => (true, Imm::I16or32),       // grupo1, imm16/32
        0x82        => (true, Imm::I8),            // alias de 0x80
        0x83        => (true, Imm::I8),            // grupo1 /0-7, imm8 sign-ext
        0x84..=0x8F => (true, Imm::None),          // test/xchg/mov r/m
        0x90..=0x97 => (false, Imm::None),         // xchg eax,r (0x90=nop)
        0x98 | 0x99 => (false, Imm::None),         // cbw/cwde/cdqe, cwd/cdq/cqo
        0x9A        => return None,                // call far (inválido 64-bit):
                                                   // mejor abortar que medir mal
        0x9B..=0x9F => (false, Imm::None),         // wait/pushf/popf/sahf/lahf
        0xA0..=0xA3 => (false, Imm::Moffs),        // mov rax, moffs
        0xA4..=0xA7 => (false, Imm::None),         // movs/cmps
        0xA8        => (false, Imm::I8),           // test al, imm8
        0xA9        => (false, Imm::I16or32),      // test eax/rax, imm32
        0xAA..=0xAF => (false, Imm::None),         // stos/lods/scas
        0xB0..=0xB7 => (false, Imm::I8),           // mov r8, imm8
        0xB8..=0xBF => (false, Imm::I32or64),      // mov r32/64, imm
        0xC0 | 0xC1 => (true, Imm::I8),            // grupo2 rot/shift, imm8
        0xC2        => (false, Imm::I16),          // ret imm16
        0xC3        => (false, Imm::None),         // ret
        0xC6        => (true, Imm::I8),            // mov r/m8, imm8
        0xC7        => (true, Imm::I16or32),       // mov r/m, imm16/32
        0xC8        => (false, Imm::Enter),        // enter imm16,imm8 (4 B total)
        0xC9        => (false, Imm::None),         // leave
        0xCA        => (false, Imm::I16),          // retf imm16
        0xCB | 0xCC => (false, Imm::None),         // retf / int3
        0xCD        => (false, Imm::I8),           // int imm8
        0xCE | 0xCF => (false, Imm::None),         // into / iret
        0xD0..=0xD3 => (true, Imm::None),          // grupo2 por 1 o CL
        0xD4 | 0xD5 => (false, Imm::I8),           // aam/aad imm8 (inv. 64-bit)
        0xD6 | 0xD7 => (false, Imm::None),         // salc / xlat
        0xD8..=0xDF => (true, Imm::None),          // x87 coprocesador
        0xE0..=0xE3 => (false, Imm::I8),           // loop/jcxz rel8
        0xE4..=0xE7 => (false, Imm::I8),           // in/out imm8
        0xE8 | 0xE9 => (false, Imm::I32),          // call/jmp rel32
        0xEB        => (false, Imm::I8),           // jmp rel8
        0xEC..=0xEF => (false, Imm::None),         // in/out dx
        0xF4 | 0xF5 => (false, Imm::None),         // hlt / cmc
        0xF6        => (true, Imm::F6),            // grupo3: TEST div idiv
        0xF7        => (true, Imm::F7),            // grupo3: TEST div idiv
        0xF8..=0xFD => (false, Imm::None),         // stc/clc/sti/cli/cld/std
        0xFE | 0xFF => (true, Imm::None),          // grupo4/5 (inc, call, jmp)
        // 0x62 (EVEX), 0xC4/0xC5 (VEX) y el resto: no decodificables aquí.
        _ => return None,
    })
}

/// Opcodes de 2 bytes (`0F xx`). Misma idea que `one_byte`, con la salvedad
/// de que 0x38/0x3A abren el mapa de 3 bytes.
fn two_byte(op: u8) -> Option<(bool, Imm)> {
    Some(match op {
        0x00..=0x03 => (true, Imm::None),      // sldt/str/lldt/ltr + grupo16
        0x05..=0x09 => (false, Imm::None),     // syscall/clts/sysret/invd/wbinvd
        0x0B        => (false, Imm::None),     // ud2
        0x0E | 0x0F => (true, Imm::None),      // femms / 3DNow
        0x10..=0x1F => (true, Imm::None),      // SSE movups.. + prefetch
        0x20..=0x2F => (true, Imm::None),      // mov cr/dr + movaps...
        0x30..=0x37 => (false, Imm::None),     // wrmsr/rdtsc/rdmsr/rdpmc/sysenter
        0x40..=0x4F => (true, Imm::None),      // cmovcc
        0x50..=0x76 => (true, Imm::None),      // SSE/MMX
        0x77        => (false, Imm::None),     // emms
        0x78..=0x7F => (true, Imm::None),      // SSE
        0x80..=0x8F => (false, Imm::I32),      // Jcc rel32 ¡sin ModRM!
        0x90..=0x9F => (true, Imm::None),      // setcc
        0xA0..=0xA2 => (false, Imm::None),     // push/pop fs, cpuid
        0xA3        => (true, Imm::None),      // bt
        0xA4        => (true, Imm::I8),        // shld r/m, r, imm8
        0xA5        => (true, Imm::None),      // shld r/m, r, cl
        0xA8 | 0xA9 => (false, Imm::None),     // push/pop gs
        0xAA        => (false, Imm::None),     // rsm
        0xAB        => (true, Imm::None),      // bts
        0xAC        => (true, Imm::I8),        // shrd r/m, r, imm8
        0xAD        => (true, Imm::None),      // shrd r/m, r, cl
        0xAE        => (true, Imm::None),      // grupo15: fxsave/ldmxcsr...
        0xAF        => (true, Imm::None),      // imul r, r/m
        0xB0..=0xB5 => (true, Imm::None),      // cmpxchg/lss/btr/lfs/lgs
        0xB6 | 0xB7 => (true, Imm::None),      // movzx
        0xB8 | 0xB9 => (true, Imm::None),      // popcnt / ud1
        0xBA        => (true, Imm::I8),        // grupo8 bt/bts/btr/btc, imm8
        0xBB..=0xBF => (true, Imm::None),      // btc/bsf/bsr/movsx
        0xC0 | 0xC1 => (true, Imm::None),      // xadd
        0xC2        => (true, Imm::I8),        // cmpps, imm8
        0xC3        => (true, Imm::None),      // movnti
        0xC4        => (true, Imm::I8),        // pinsrw, imm8
        0xC5        => (true, Imm::I8),        // pextrw, imm8
        0xC6        => (true, Imm::I8),        // shufps, imm8
        0xC7        => (true, Imm::None),      // grupo9: cmpxchg8b/rdrand
        0xC8..=0xCF => (false, Imm::None),     // bswap
        0xD0..=0xFF => (true, Imm::None),      // SSE2/3/4 + misc
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Prefijos que el bucle consume ANTES del opcode.
// ---------------------------------------------------------------------------

#[inline]
fn is_legacy_prefix(b: u8) -> bool {
    matches!(b, 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65)
}

/// Decodifica la instrucción que comienza en `bytes[0]`.
///
/// Devuelve `None` si el stream no es decodificable con seguridad (VEX/EVEX,
/// opcodes reservados, longitud > 15). Es una decisión deliberada: ver
/// comentario de cabecera del módulo.
pub fn decode(bytes: &[u8]) -> Option<Decoded> {
    let mut i = 0usize;
    let mut rex_w = false;
    let mut rex_b = false;
    let mut rex_x = false;
    let mut saw_rex = false; // ¿apareció ALGÚN prefijo REX? (ver divisor_high_byte)
    let mut op66 = false; // prefijo de tamaño de operando 0x66
    let mut op67 = false; // prefijo de tamaño de dirección 0x67

    // --- 1) Prefijos --------------------------------------------------
    // [EXPL] Los prefijos pueden repetirse y aparecer en cualquier orden;
    // REX debe ser el último para tener efecto, pero aceptamos cualquier
    // orden y simplemente recordamos los bits (len no depende del orden).
    while i < bytes.len() && i < MAX_INSN_LEN {
        let b = bytes[i];
        if is_legacy_prefix(b) {
            i += 1;
        } else if b == 0x66 {
            op66 = true;
            i += 1;
        } else if b == 0x67 {
            op67 = true;
            i += 1;
        } else if (0x40..=0x4F).contains(&b) {
            rex_w |= b & 0x08 != 0;
            rex_b |= b & 0x01 != 0;
            rex_x |= b & 0x02 != 0;
            saw_rex = true;
            i += 1;
        } else {
            break;
        }
    }

    if i >= bytes.len() {
        return None;
    }

    // --- 2) Opcode (1, 2 o 3 bytes) ------------------------------------
    let has_modrm;
    let mut imm_kind;
    let mut is_div = false;
    let mut signed = false;
    let mut op_f6 = false; // opcode F6: divisor de 8 bits (ver abajo)

    if bytes[i] == 0x0F {
        i += 1;
        if i >= bytes.len() {
            return None;
        }
        let op2 = bytes[i];
        i += 1;
        if op2 == 0x38 || op2 == 0x3A {
            // [EXPL] Mapa de 3 bytes: 0F 38/3A. Todos los miembros llevan
            // ModRM; 0F 3A además un imm8 (son SSE4.1 de "shape").
            if i >= bytes.len() {
                return None;
            }
            i += 1; // tercer byte del opcode
            has_modrm = true;
            imm_kind = if op2 == 0x3A { Imm::I8 } else { Imm::None };
        } else {
            let (m, im) = two_byte(op2)?;
            has_modrm = m;
            imm_kind = im;
        }
    } else {
        let op = bytes[i];
        let (m, im) = one_byte(op)?;
        has_modrm = m;
        imm_kind = im;
        // Grupo 3 (F6/F7): el sub-opcode vive en ModRM.reg, así que hay que
        // ASOMAR al ModRM para decidir el inmediato... pero sin consumirlo.
        //
        // [BUG] Aquí el código hacía `i += 1` antes de leer ModRM y después
        // otro `i += 1` al final del bloque: el byte ModRM se contaba DOS
        // veces, y el paso 3 lo releía desde la posición equivocada. Resultado
        // neto: `decode([0xF7, 0xF1])` devolvía None (índice 2 fuera de rango)
        // y TODO el bypass de división por cero era inalcanzable.
        if op == 0xF6 || op == 0xF7 {
            op_f6 = op == 0xF6;
            // Asomada pura: el avance del cursor lo hace el `i += 1` de aquí
            // abajo y, después, el paso 3. `get` en vez de indexar para que un
            // stream truncado (`[0xF7]`) devuelva None en vez de panic.
            let &mrm = bytes.get(i + 1)?;
            let reg = (mrm >> 3) & 7;
            if reg == 6 || reg == 7 {
                is_div = true;
                signed = reg == 7;
            }
            // [BUG] El `imm_kind` de la tabla para F6/F7 es `Imm::F6`/`Imm::F7`
            // (que significan "inmediato SI reg==0", es decir TEST). La
            // corrección solo se aplicaba en el caso reg==0; para DIV/IDIV
            // (reg 6/7) el inmediato fantasma se colaba en el cálculo de
            // longitud, añadiendo 4 bytes a la instrucción. DIV no lleva
            // inmediato NUNCA: hay que anularlo explícitamente.
            imm_kind = match reg {
                0 => if op == 0xF7 { Imm::F7 } else { Imm::F6 }, // TEST r/m, imm
                _ => Imm::None, // MUL/IMUL/NEG/NOT/DIV/IDIV: sin inmediato
            };
        }
        i += 1; /* opcode ya contado */
    }
    // notar: en la rama 0F, i apunta tras el último byte de opcode.

    // --- 3) ModRM + SIB + desplazamiento --------------------------------
    let mut divisor_reg: Option<usize> = None;
    let mut divisor_high_byte = false;
    let mut addr_form: Option<AddrForm> = None;
    if has_modrm {
        if i >= bytes.len() {
            return None;
        }
        let m = bytes[i];
        let mod_ = m >> 6;
        let rm = m & 7;
        i += 1;

        // [EXPL] Las reglas de direccionamiento x86-64, que son la parte más
        // fácil de desteñir de este decodificador porque son SEIS casos:
        //
        //   mod=3                    → operando en REGISTRO (rm, extendido REX.B)
        //   mod≠3, rm=4              → hay byte SIB: base e índice salen de él
        //   mod≠3, rm=5              → SIN SIB, la base es RBP/R13 (NO un
        //                              displacement absoluto: en 64 bits
        //                              mod=0,rm=5 es RIP+disp32)
        //   mod≠3, rm∉{4,5}        → SIN SIB, la base es el GPR rm
        //   mod=0, SIB.base=5       → sin base, disp32 absoluto
        //   mod=0, rm=5, sin SIB    → RIP+disp32 (salvo prefijo 67)
        //
        // [BUG-CRITICO] El caso `mod≠3, rm=5` es el que produce `idivq -0x20(%rbp)`,
        // la instrucción que emite GCC para `a / b` cuando las variables
        // locales se spilled al stack — o sea la división-por-cero MÁS FRECUENTE
        // en código real compilado. Una versión anterior de este decodificador
        // solo rellenaba `base` cuando leía un byte SIB, así que en esa forma
        // devolvía `base: None` y la EA calculada era `disp` pelado (= -32), es
        // decir 0xFFFFFFFFFFFFFFE0. El motor escribía ahí el divisor corregido,
        // no dividía por 1, y el proceso volvía a fallar en el mismo RIP hasta
        // que la tabla anti-bucle lo mataba. La cura "funcionaba" y no curaba
        // nada: el peor tipo de bug, porque la telemetría decía rule=10.
        let mut base: Option<usize> = None;
        let mut index: Option<usize> = None;
        let mut scale: u8 = 1;
        // [BUG-CRITICO] Hay DOS formas distintas de "mod=00 sin base registro",
        // y confundirlas rompe la longitud de la instrucción:
        //   rm=4 + SIB.base=101  → `idivq 0x44332211`      (disp32 absoluto)
        //   rm=5 sin SIB          → `idivq 0x0(%rip)`      (RIP-relativo)
        // Ambas consumen 4 bytes de disp32, así que el cursor avanza igual; lo
        // que cambia es si la EA depende de RIP o es una constante. La bandera
        // distingue cuál era, y se lee `rip_relative` del caso NO-SIB.
        let mut rip_rel = false;

        if mod_ != 3 {
            let has_sib = rm == 4;
            if has_sib {
                if i >= bytes.len() { return None; }
                let sib = bytes[i];
                i += 1;
                scale = 1u8 << ((sib >> 6) & 3);
                // [EXPL] índice 0b100 (RSP, sin REX.X) significa "sin índice",
                // no "el índice es RSP". Confundirlo suma RSP al EA.
                let idx = (sib >> 3) & 7;
                if idx != 4 {
                    index = Some(if rex_x { idx as usize + 8 } else { idx as usize });
                }
                let sib_b = sib & 7;
                // base=101 con mod=00 significa "sin base": disp32 absoluto.
                if sib_b == 5 && mod_ == 0 {
                    base = None;
                } else {
                    base = Some(if rex_b { sib_b as usize + 8 } else { sib_b as usize });
                }
            } else if rm == 5 && mod_ == 0 {
                // RIP+disp32 (o disp32 absoluto si hay prefijo 67).
                rip_rel = !op67;
            } else {
                // [BUG-CRITICO] rm≠4 (sin SIB) y no es el caso RIP-relativo:
                // la base ES el GPR rm, extendido con REX.B. Este es el `rbp`
                // de `idivq -0x20(%rbp)`, la forma más FRECUENTE en código real.
                base = Some(if rex_b { rm as usize + 8 } else { rm as usize });
            }
        }

        match mod_ {
            0 => {
                if base.is_none() {
                    // disp32 absoluto (con SIB) o RIP+disp32 (sin SIB).
                    let disp = read_disp(bytes, i, 4)? as i32 as i64;
                    i = add_disp(i, 4, bytes)?;
                    addr_form = Some(AddrForm {
                        base: None, index, scale, disp, rip_relative: rip_rel,
                    });
                } else if is_div {
                    addr_form = Some(AddrForm {
                        base, index, scale, disp: 0, rip_relative: false,
                    });
                }
            }
            1 | 2 => {
                let n = if mod_ == 1 { 1 } else { 4 };
                let disp = read_disp(bytes, i, n)? as i32 as i64;
                i = add_disp(i, n, bytes)?;
                if is_div {
                    addr_form = Some(AddrForm {
                        base, index, scale, disp, rip_relative: false,
                    });
                }
            }
            _ => {
                // mod == 3: operando en registro. Si es DIV/IDIV, el
                // divisor vive en el GPR rm (extendido por REX.B).
                //
                // [BUG] La extensión de REX.B es `rm + 8`, NO `rm | 1`.
                // Los bits de rm (0..7) y el de REX.B (8) son disjuntos: 8 es
                // el bit 3, y 0..7 nunca lo tienen. Con `|` el resultado es
                // idéntico a `rm` para rm<4 (0|1=1, 1|1=1, 2|1=3, 3|1=3) y
                // para rm>=4 (4|1=5, 5|1=5…) — es decir, NUNCA daba 8..15:
                // `DIV r8` se curaba como si fuera RCX/RDX/RBX/RSI. Peor: el
                // bug mapeaba rm=0 (r8) a 1 (rcx) y rm=2 (r10) a 3 (rbx),
                // parcheando un registro que la instrucción no lee.
                if is_div {
                    let n = if rex_b { rm as usize + 8 } else { rm as usize };
                    divisor_reg = Some(n);
                    // [EXPL] AH/CH/DH/BH = registros x86 4..7 en modo de byte
                    // ALTO, pero solo si NO hay REX. Con REX, 4..7 son
                    // SPL/BPL/SIL/DIL (byte bajo) — `48 F6 E4` es MUL SPL.
                    divisor_high_byte = op_f6 && !saw_rex && matches!(n, 4..=7);
                }
            }
        }
        // Nota: los flags de la instrucción no nos interesan; solo len.
    }

    // --- 4) Inmediato ---------------------------------------------------
    let imm_len = match imm_kind {
        Imm::None => 0,
        Imm::I8 => 1,
        Imm::I16 => 2,
        Imm::I32 => 4,
        Imm::Enter => 3, // imm16 + imm8 de enter
        Imm::I32or64 => if rex_w { 8 } else { 4 },
        Imm::I16or32 | Imm::F7 => if op66 { 2 } else { 4 },
        Imm::F6 => 1,
        Imm::Moffs => if op67 { 4 } else { 8 },
    };
    i += imm_len;

    if i > MAX_INSN_LEN || i > bytes.len() {
        return None; // stream truncado o longitud imposible
    }

    Some(Decoded {
        len: i,
        is_div,
        divisor_reg,
        divisor_8bit: is_div && op_f6,
        divisor_high_byte,
        signed,
        addr_form,
        op66,
    })
}

/// Lee un desplazamiento de `n` bytes (1 o 4) como entero con signo.
///
/// [WHY] El desplazamiento de ModRM/SIB es CON signo: `[rbp-0x20]` codifica
/// -0x20, y leerlo como `u8` daría 0xE0, es decir, una dirección ~224 bytes
/// más alta de la correcta. Escribir un "1" en esa dirección sería un
/// borrado de memoria en un sitio que no tiene nada que ver — el peor tipo de
/// bug posible en un runtime que sedefine por no empeorar el crash. Los tests
/// `div_mem_disp8_negativo` y `div_mem_disp32_negativo` cubren exactamente esto.
fn read_disp(bytes: &[u8], i: usize, n: usize) -> Option<u64> {
    let end = i.checked_add(n)?;
    if end > bytes.len() || end > MAX_INSN_LEN {
        return None;
    }
    match n {
        1 => Some(bytes[i] as i8 as i64 as u64),
        4 => Some(i32::from_le_bytes([bytes[i], bytes[i+1], bytes[i+2], bytes[i+3]]) as i64 as u64),
        _ => None,
    }
}

#[inline]
fn add_disp(i: usize, n: usize, bytes: &[u8]) -> Option<usize> {
    let j = i.checked_add(n)?;
    if j > bytes.len() || j > MAX_INSN_LEN {
        None
    } else {
        Some(j)
    }
}

// ---------------------------------------------------------------------------
// Tests del decodificador (el fast-path es lo único que aquí usa std).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn d(b: &[u8]) -> Decoded {
        decode(b).expect("debe decodificar")
    }

    #[test]
    fn div_by_zero_ecx() {
        // DIV ECX  (64-bit dividendo RDX:RAX / ECX)
        let x = d(&[0xF7, 0xF1]);
        assert_eq!(x.len, 2);
        assert!(x.is_div);
        assert_eq!(x.divisor_reg, Some(1)); // ECX
        assert!(!x.signed);                 // DIV, no IDIV
    }

    #[test]
    fn idiv_rcx_con_rexw() {
        // IDIV RCX  → 48 F7 F9
        let x = d(&[0x48, 0xF7, 0xF9]);
        assert_eq!(x.len, 3);
        assert!(x.is_div);
        assert!(x.signed);
        assert_eq!(x.divisor_reg, Some(1));
    }

    #[test]
    fn div_16bit_con_66() {
        // 66 F7 F1 → DIV r/m16, CX
        let x = d(&[0x66, 0xF7, 0xF1]);
        assert_eq!(x.len, 3);
        assert!(x.is_div);
        assert_eq!(x.divisor_reg, Some(1));
    }

    #[test]
    fn div_cl_8bit() {
        // F6 F1 → DIV CL (8-bit)
        let x = d(&[0xF6, 0xF1]);
        assert_eq!(x.len, 2);
        assert!(x.is_div);
        assert_eq!(x.divisor_reg, Some(1)); // CL
    }

    #[test]
    fn div_memoria_no_curar() {
        // F7 76 00 → DIV dword ptr [rsi+0] (mod=01, rm=6, disp8)
        let x = d(&[0xF7, 0x76, 0x00]);
        assert!(x.is_div);
        assert_eq!(x.divisor_reg, None); // memoria: se cura vía addr_form
        assert_eq!(x.len, 3);
        // [API] Y ahora además sabemos DÓNDE está: base=RSI(6), disp=0.
        // Antes esto era un skip sin más información.
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: Some(6), index: None, scale: 1, disp: 0, rip_relative: false })
        );
    }

    // ---- Formas de direccionamiento del divisor en RAM -------------------
    //
    // [POR QUÉ ESTOS TESTS USAN BYTES DE OBJDUMP Y NO DE LIBRO] Una versión
    // anterior de esta suite pasó años con bytes escritos a mano que GCC nunca
    // emite (por ejemplo `48 F7 04 8E` para SIB indexado, donde el campo `reg`
    // del ModRM es 000 = TEST, no 111 = IDIV: esa instrucción no es una
    // división en absoluto). Los tests PASABAN porque assertan el resultado del
    // propio decodificador, y el decodificador estaba tan equivocado como los
    // bytes. Un test que valida la lógica contra bytes inventados mide la
    // coherencia interna, no la correctitud frente al hardware.
    //
    // Los bytes de abajo están verificados contra `gcc -O1/-O2` (ver el
    // comentario de cada uno con la línea de C que los produce).

    #[test]
    fn div_mem_rbp_disp8_negativo() {
        // `return MEM(a) / MEM(b);` a -O0 spilled al stack:
        //   48 f7 7d e0   idivq  -0x20(%rbp)
        // ModRM=0x7d ⇒ mod=01, reg=111 (IDIV), rm=101 (RBP, SIN byte SIB).
        let x = d(&[0x48, 0xF7, 0x7D, 0xE0]);
        assert_eq!(x.len, 4);
        assert!(x.is_div);
        assert!(!x.divisor_8bit);
        // [BUG-CRITICO] rm=5 con mod!=0 significa base=rbp, NO displacement
        // absoluto. Una versión anterior devolvía base=None y calculaba la EA
        // como 0xFFFFFFFFFFFFFFE0: escribía el divisor corregido en el
        // espacio de núcleo, el #DE se repetía y el proceso moría por la
        // tabla anti-bucle. La telemetría decía "rule=10, curado" mientras
        // la app seguía sin funcionar.
        assert_eq!(
            x.addr_form,
            Some(AddrForm {
                base: Some(5),          // RBP
                index: None,
                scale: 1,
                disp: -32,               // 0xE0 leído como i8 CON SIGNO
                rip_relative: false,
            })
        );
    }

    #[test]
    fn div_mem_r13_disp8() {
        // 49 f7 7d f0 → idivq -0x10(%r13). REX.B (bit 0 de 0x49) extiende
        // rm=101 (5) a R13. Sin extender, el motor parchearía RBP.
        let x = d(&[0x49, 0xF7, 0x7D, 0xF0]);
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: Some(13), index: None, scale: 1, disp: -16, rip_relative: false })
        );
    }

    #[test]
    fn div_mem_disp32() {
        // 48 f7 bd 00 f0 ff ff → idivq -0x1000(%rbp)  (mod=10 → disp32)
        let x = d(&[0x48, 0xF7, 0xBD, 0x00, 0xF0, 0xFF, 0xFF]);
        assert_eq!(x.len, 7);
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: Some(5), index: None, scale: 1, disp: -4096, rip_relative: false })
        );
    }

    #[test]
    fn div_mem_sib_indexado() {
        // `return v[0] / v[i];` con arrays volatile a -O1:
        //   48 f7 3c f7   idivq  (%rdi,%rsi,8)
        // SIB=0xf7 ⇒ scale=11(×8), index=110 (RSI), base=111 (RDI).
        let x = d(&[0x48, 0xF7, 0x3C, 0xF7]);
        assert_eq!(x.len, 4);
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: Some(7), index: Some(6), scale: 8, disp: 0, rip_relative: false })
        );
    }

    #[test]
    fn div_mem_sib_sin_indice() {
        // 48 f7 3f → idivq (%rdi). ModRM=0x3f ⇒ mod=00, rm=111, SIN SIB:
        // la base es el GPR rm. (Contrastar con el caso SIB de abajo, donde el
        // índice 0b100 significa "sin índice".)
        let x = d(&[0x48, 0xF7, 0x3F]);
        assert_eq!(x.len, 3);
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: Some(7), index: None, scale: 1, disp: 0, rip_relative: false })
        );
    }

    #[test]
    fn div_mem_sib_index_rsp_es_sin_indice() {
        // 48 f7 3c 24 → idivq (%rsp) (gas/masm). ModRM=0x3c ⇒ mod=00, rm=100 → SIB.
        // SIB=0x24 ⇒ scale=00(×1), index=100 (SIN índice), base=100 (RSP).
        // index=0b100 significa SIN índice; tomarlo como "índice = RSP" sumaría
        // RSP a la EA dos veces y escribiría 8 bytes en el sitio equivocado del
        // stack — que en un crash es indistinguible de corrupción de memoria.
        let x = d(&[0x48, 0xF7, 0x3C, 0x24]);
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: Some(4), index: None, scale: 1, disp: 0, rip_relative: false })
        );
    }

    #[test]
    fn div_mem_sin_base_disp32_absoluto() {
        // 48 f7 3c 25 11 22 33 44 → idivq 0x44332211 (objdump de gas)
        // ModRM=0x3c rm=100 → SIB. SIB=0x25 ⇒ scale=00, index=100 (sin índice),
        // base=101 con mod=00 ⇒ sin base + disp32 absoluto.
        let x = d(&[0x48, 0xF7, 0x3C, 0x25, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(x.len, 8);
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: None, index: None, scale: 1, disp: 0x44332211, rip_relative: false })
        );
    }

    #[test]
    fn div_mem_rip_relativo() {
        // `return 1000000 / glob;` con `volatile long glob` a -O1:
        //   48 f7 3d 00 00 00 00   idivq  0x0(%rip)
        // ModRM=0x3d ⇒ mod=00, rm=101, SIN SIB ⇒ RIP+disp32 en 64 bits.
        // [BUG-CRITICO] La EA depende de RIP + LONGITUD DE LA INSTRUCCIÓN.
        // Usar la longitud de otra cosa desplaza la EA 2-4 bytes y el divisor
        // parcheado cae en medio de otra variable.
        let x = d(&[0x48, 0xF7, 0x3D, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(x.len, 7);
        let f = x.addr_form.expect("mod=00 rm=101 sin SIB debe dar forma");
        assert!(f.rip_relative, "rm=5 con mod=00 en 64 bits es RIP-relativo");
        assert_eq!(f.base, None);
        assert_eq!(f.index, None);
        assert_eq!(f.disp, 0);
    }

    #[test]
    fn div_mem_16bits_marca_op66() {
        // El prefijo 66 no debe alterar la forma, pero sí el ANCHO del divisor
        // (2 bytes), que es lo que impide a la capa C escribir 8 bytes sobre un
        // campo de 2 y pisar la variable contigua de la app.
        let x = d(&[0x66, 0x48, 0xF7, 0x7D, 0xE0]);
        assert!(x.op66);
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: Some(5), index: None, scale: 1, disp: -32, rip_relative: false })
        );
    }

    #[test]
    fn div_reg_no_tiene_addr_form() {
        // Un DIV sobre registro NO tiene forma de direccionamiento: no hay
        // memoria que parchear. Si se llenara, el motor podría intentar
        // escribir un divisor en la dirección que fuera.
        let x = d(&[0x48, 0xF7, 0xF9]); // idiv rcx  (48 f7 f9, de objdump)
        assert!(x.is_div);
        assert_eq!(x.divisor_reg, Some(1));
        assert!(x.addr_form.is_none());
    }

    #[test]
    fn div_16bit_operand_size_conserva_forma() {
        // 66 f7 7f 08 → DIV word ptr [rdi+8]: op66 sin REX.W ⇒ ancho de 2 bytes.
        let x = d(&[0x66, 0xF7, 0x7F, 0x08]);
        assert!(x.op66);
        assert!(!x.divisor_8bit, "F7 con 66 es de 16 bits, no de 8");
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: Some(7), index: None, scale: 1, disp: 8, rip_relative: false })
        );
    }

    #[test]
    fn div_8bit_operando_memoria_marca_8bit() {
        // f6 7f 08 → DIV byte ptr [rdi+8]: F6 ⇒ ancho de 1 byte. La capa C
        // tiene que escribir 1 byte, no 8, o corrompe la app que intentaba
        // rescatar.
        let x = d(&[0xF6, 0x7F, 0x08]);
        assert!(x.divisor_8bit);
        assert_eq!(
            x.addr_form,
            Some(AddrForm { base: Some(7), index: None, scale: 1, disp: 8, rip_relative: false })
        );
    }

    #[test]
    fn call_rel32() {
        assert_eq!(d(&[0xE8, 0, 0, 0, 0]).len, 5);
    }

    #[test]
    fn jcc_rel8() {
        assert_eq!(d(&[0x75, 0x01]).len, 2);
    }

    #[test]
    fn add_rax_inm8() {
        // 48 83 C0 01 → add rax, 1
        assert_eq!(d(&[0x48, 0x83, 0xC0, 0x01]).len, 4);
    }

    #[test]
    fn mov_rax_rip_rel() {
        // 48 8B 05 <disp32> → mov rax, [rip+disp32]
        let x = d(&[0x48, 0x8B, 0x05, 0, 0, 0, 0]);
        assert_eq!(x.len, 7);
        assert!(!x.is_div);
    }

    #[test]
    fn mov_rax_sib() {
        // 48 8B 04 B8 → mov rax, [rax+rdi*4]  (mod=00 rm=100→sib)
        assert_eq!(d(&[0x48, 0x8B, 0x04, 0xB8]).len, 4);
    }

    #[test]
    fn syscall_y_ud2() {
        assert_eq!(d(&[0x0F, 0x05]).len, 2);
        assert_eq!(d(&[0x0F, 0x0B]).len, 2);
        assert!(!d(&[0x0F, 0x0B]).is_div);
    }

    #[test]
    fn jcc_rel32_dos_bytes() {
        assert_eq!(d(&[0x0F, 0x85, 0, 0, 0, 0]).len, 6);
    }

    #[test]
    fn mov_r64_inm64() {
        // 48 B8 <imm64> → mov rax, imm64  → 10 bytes
        assert_eq!(d(&[0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0]).len, 10);
    }

    #[test]
    fn vectores_rechazados() {
        assert!(decode(&[0xC5, 0xF8, 0x77]).is_none());  // VEX
        assert!(decode(&[0xC4, 0xE2, 0x7D, 0x18]).is_none()); // VEX
        assert!(decode(&[0x62]).is_none());              // EVEX
    }

    #[test]
    fn prefijos_repetidos() {
        // 66 66 48 F7 F1 — prefijos redundantes son legales
        let x = d(&[0x66, 0x66, 0x48, 0xF7, 0xF1]);
        assert_eq!(x.len, 5);
        assert!(x.is_div);
    }

    #[test]
    fn protected_against_truncation() {
        assert!(decode(&[0xE8, 0x00]).is_none());          // call falta imm
        assert!(decode(&[0xF7]).is_none());                // falta ModRM
        assert!(decode(&[]).is_none());
    }
}