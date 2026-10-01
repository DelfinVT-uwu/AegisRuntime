//! aegis_core — Núcleo heurístico de AegisRuntime (cdylib, C-ABI).
//!
//! Responsabilidad: exponer `aegis_analyze_and_heal`, la única función que
//! el trap layer de C (aegis_sys) conoce. Recibe un snapshot plano del hilo
//! roto y devuelve el plan de curación. Todo el "cerebro" (decodificación,
//! heurística, firma, telemetría) vive en los módulos de abajo.
//!
//! [WHY] La razón de que `aegis_sys` no pase el `ucontext_t` crudo sino este
//! snapshot: `ucontext_t` es dependiente de glibc y de arquitectura, y
//! reinterpretarlo desde Rust sin la crate `libc` es frágil. Un par de
//! structs `#[repr(C)]` planos es lo único que ambos lados pueden
//! _verificar_ en compilación (asserts de tamaño abajo).

mod engine;
mod fastpath;
mod signature;
mod telemetry;

use core::mem;

// ---------------------------------------------------------------------------
// Espejo de aegis_api.h (aegis_sys/include). ¡MANTENER SÍNCRONO!
// ---------------------------------------------------------------------------

/// Número de GPR copiados del `gregset_t` de glibc (NGREG = 23).
pub const AEGIS_NGREG: usize = 23;

/// Longitud máxima de una instrucción x86-64 (prefijo + opcode + ModRM + SIB +
/// displacement + inmediato). Espejo de `AEGIS_CODE_MAX` en aegis_api.h.
pub const AEGIS_CODE_MAX: usize = 15;

/// `aegis_frame_in_t` — instantánea del hilo roto (C → Rust).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AegisFrameIn {
    pub sig: i32,
    /// [API] `siginfo.si_code`, el subtipo del fallo.
    ///
    /// [BUG] La primera versión lo ignoraba, y luego se intentó usar para
    /// distinguir `FPE_ZERODIVISE` de `FPE_INTOVF`. Medido en esta máquina:
    /// **Linux x86 reporta siempre `FPE_INTDIV` (1)** para cualquier `#DE` de
    /// división, así que no sirve para eso. Se conserva porque es telemetría
    /// útil (y en SIGSEGV sí distingue `SEGV_MAPERR` de `SEGV_ACCERR`, que
    /// Fase 2 necesita), pero la causa del #DE se infiere de los REGISTROS.
    pub si_code: i32,
    pub fault_addr: u64,
    pub rip: u64,
    pub gregs: [u64; AEGIS_NGREG],
    /// [API] Copia SEGURA de la instrucción, hecha en C (`aegis_read_code_prefix`).
    ///
    /// [BUG-CRITICO] El motor antes leía la instrucción él mismo con
    /// `slice::from_raw_parts(rip, 15)`. Eso era un `unsafe` dentro de un
    /// signal handler que podía matar al proceso: si RIP no era legible
    /// (fallo de FETCH sobre PROT_NONE, salto a dirección basura) la lectura
    /// colgaba el handler DENTRO de sí mismo y el kernel lo mataba sin log.
    ///
    /// Ahora la C copia solo el prefijo legible y Rust nunca toca memoria del
    /// proceso: solo analiza estos bytes. Bonus: `code_len` puede ser menor que
    /// 15 si la instrucción está al final de su página, y el decodificador
    /// falla cerrado en vez de leer de una página que no existe.
    pub code: [u8; AEGIS_CODE_MAX],
    /// Bytes válidos en `code` (0..=15). Si es < longitud real de la
    /// instrucción, el buffer está truncado y `decode` debe fallar cerrado.
    pub code_len: u8,
    pub reserved: [u8; 7],
}

/// `aegis_frame_out_t` — plan de curación (Rust → C).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AegisFrameOut {
    pub action: u32,
    pub patch_id: u32,
    pub new_rip: u64,
    pub gregs_mask: u64,
    pub gregs: [u64; AEGIS_NGREG],
    /// Dirección efectiva a parchear en la memoria de la víctima.
    ///
    /// [BUG-CRITICO] Rust NO lee ni escribe esta dirección: solo la CALCULA a
    /// partir de los `gregs` que ya tiene en el frame (que es una copia, no
    /// acceso a memoria). El acto de escribir lo hace la capa C, que comprueba
    /// antes que la página sea escribible con la tabla de `/proc/self/maps`.
    /// Ese reparto es el que hace que este módulo siga sin un solo `unsafe`
    /// de acceso a memoria, que es donde no queremos estar en un handler.
    pub mem_addr: u64,
    /// Valor a escribir en `mem_addr` (1 para el divisor cero).
    pub mem_val: u64,
    /// Bytes a escribir (0 = no aplica; si no, 1, 2, 4 u 8).
    pub mem_size: u32,
    pub reserved2: u32,
}

// [WARN] Estos asserts convierten un desajuste de layout en un error de
// compilación, no en corrupción de memoria en producción. El C de al lado
// usa `_Static_assert` con los mismos números (ver aegis_api.h).
const _: () = {
    assert!(mem::size_of::<AegisFrameIn>() == 232);   // 4+4+8+8+184+15+1+7=231 -> 232 (align 8)
    assert!(mem::align_of::<AegisFrameIn>() == 8);
    assert!(mem::size_of::<AegisFrameOut>() == 232);  // +24 de campos de parche de memoria
    assert!(mem::align_of::<AegisFrameOut>() == 8);
    assert!(mem::offset_of!(AegisFrameIn, gregs) == 24);
    assert!(mem::offset_of!(AegisFrameOut, gregs) == 24);
    // Cada campo nuevo DEBE caer donde C espera. Si alguien mueve alguno, el C
    // lee basura: peor que un error de compilación, porque corrompe en
    // producción y solo con un binario que linkea bien.
    assert!(mem::offset_of!(AegisFrameIn, si_code) == 4);
    assert!(mem::offset_of!(AegisFrameIn, fault_addr) == 8);
    assert!(mem::offset_of!(AegisFrameIn, rip) == 16);
    assert!(mem::offset_of!(AegisFrameIn, code) == 208);
    assert!(mem::offset_of!(AegisFrameIn, code_len) == 223);
    // Parche de memoria: estos offsets son un contrato con trap_handler.c.
    // Si se mueven, C escribe el divisor en un sitio arbitrario.
    assert!(mem::offset_of!(AegisFrameOut, mem_addr) == 208);
    assert!(mem::offset_of!(AegisFrameOut, mem_size) == 224);
};

impl Default for AegisFrameOut {
    fn default() -> Self {
        AegisFrameOut {
            action: 0,
            patch_id: 0,
            new_rip: 0,
            gregs_mask: 0,
            gregs: [0; AEGIS_NGREG],
            mem_addr: 0,
            mem_val: 0,
            mem_size: 0,
            reserved2: 0,
        }
    }
}

/// Marca de tiempo para telemetría sin dependencias externas.
///
/// [NOTE] `SystemTime::now()` usa `clock_gettime` vía vDSO: ~20 ns, sin
/// locks, y es seguro en la práctica dentro de un handler. En una build
/// `no_std` estricta se sustituiría por un contador de ticks (TODO fase 3).
fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// FFI exportado (el único símbolo que aegis_sys resuelve con dlsym)
// ---------------------------------------------------------------------------

/// Punto de entrada de la heurística. `frame_in`/`frame_out` se pasan como
/// punteros planos (nada de alocación). Devuelve 0 en éxito; -1 si un
/// puntero es NULL (defensa contra un error de llamada de C, no esperado).
///
/// # Safety
///
/// `frame_in` debe apuntar a un `AegisFrameIn` válido (alineado, legible,
/// exactamente `size_of::<AegisFrameIn>()` bytes) y `frame_out` a un
/// `AegisFrameOut` writable de ese tamaño, ambos provistos por el handler de
/// señales de `aegis_sys` (pila del alt-stack reservada en `aegis_mman_init`).
/// La función desreferencia ambos punteros sin comprobación de rango más allá
/// del NULL-check.
///
/// Es `unsafe` (y no un error de clippy que se silencia) porque REALMENTE
/// desreferencia punteros del llamante: marcarlo `unsafe` obliga a que el
/// contrato quede explícito en la firma en lugar de asumido implícitamente. El
/// lado C la invoca vía `dlsym` desde el handler, donde la validez del frame es
/// una garantía de diseño (no del usuario), y en Rust los tests la llaman
/// dentro de `unsafe { }`.
///
/// Async-signal-safety: el camino caliente no aloca, no toma locks y no
/// hace I/O. El único uso "estándar" es `SystemTime` (vDSO, ver arriba).
#[no_mangle]
pub unsafe extern "C" fn aegis_analyze_and_heal(
    frame_in: *const AegisFrameIn,
    frame_out: *mut AegisFrameOut,
) -> i32 {
    if frame_in.is_null() || frame_out.is_null() {
        return -1;
    }
    let fin = unsafe { &*frame_in };
    let fout = unsafe { &mut *frame_out };
    *fout = AegisFrameOut::default();

    // [BUG-CRITICO] El slice se recorta a `code_len`: son los bytes que la
    // capa C comprobó como legibles uno a uno. Si `code_len` es menor que 15
    // (RIP al final de una página) el decodificador verá un buffer truncado y
    // fallará cerrado, en vez de leer una página que no existe.
    let code: &[u8] = &fin.code[..(fin.code_len as usize).min(AEGIS_CODE_MAX)];

    // [EXPL] El engine decide sobre los gregs reales (para el fix del
    // divisor necesita el valor ORIGINAL del registro, p. ej. para
    // preservar los bytes altos en DIV 8-bit).
    let decision = engine::decide(
        &fin.gregs,
        fin.sig,
        fin.rip,
        fin.fault_addr,
        now_ns(),
        code,
    );

    // Materializar el plan en el frame de salida: acción + escrituras.
    fout.action = decision.action as u32;
    fout.patch_id = decision.patch_id;
    match decision.action {
        engine::Action::Skip | engine::Action::Patch => fout.new_rip = decision.new_rip,
        _ => {}
    }
    for w in decision.writes.iter().take(decision.num_writes) {
        fout.gregs_mask |= 1u64 << w.idx;
        fout.gregs[w.idx] = w.val;
    }
    // Parche de memoria (divisor en RAM). Se materializa como DIRECCIÓN +
    // VALOR + TAMAÑO, y C decide si la página es escribible antes de
    // escribir. `mem_size == 0` es el "no aplica" explícito: si la dirección
    // fuera 0 y C no mirara el tamaño, creería que hay un parche en la
    // página nula, que no existe.
    if let Some(mp) = decision.mem_patch {
        fout.mem_addr = mp.addr;
        fout.mem_val = mp.val;
        fout.mem_size = mp.size as u32;
    }

    // Telemetría: la copia más barata posible del evento.
    telemetry::push(telemetry::Event {
        ts_ns: now_ns(),
        sig: fin.sig as u32,
        action: decision.action as u32,
        patch_id: decision.patch_id,
        rip: fin.rip,
        fault_addr: fin.fault_addr,
    });

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fastpath;

    #[test]
    fn layout_matches_api_header() {
        // Valores documentados en aegis_api.h; si esto truena, el C romperá
        // memoria en producción — no es un test cosmético.
        assert_eq!(mem::size_of::<AegisFrameIn>(), 232);
        assert_eq!(mem::offset_of!(AegisFrameIn, rip), 16);
        assert_eq!(mem::offset_of!(AegisFrameIn, gregs), 24);
        // Campos de la copia segura del código: si se mueven, C y Rust
        // intercambian basura y el motor decodifica sobre un buffer que no
        // contiene la instrucción.
        assert_eq!(mem::offset_of!(AegisFrameIn, code), 208);
        assert_eq!(mem::offset_of!(AegisFrameIn, code_len), 223);
        // [API] frame_out creció a 232 al añadir el parche de memoria. Los
        // offsets de los campos previos NO cambian (los nuevos van al final),
        // así que este assert sobre `gregs` sigue valiendo tal cual — que es
        // justo la propiedad que hace el cambio retrocompatible.
        assert_eq!(mem::size_of::<AegisFrameOut>(), 232);
        assert_eq!(mem::offset_of!(AegisFrameOut, gregs), 24);
        assert_eq!(mem::offset_of!(AegisFrameOut, mem_addr), 208);
        assert_eq!(mem::offset_of!(AegisFrameOut, mem_size), 224);
    }

    #[test]
    fn heal_div_zero_returns_reexec_plan() {
        // [WHY] Este test entra por la FFI pública, que llama a engine::decide
        // y por tanto consume un reintento de la tabla global anti-bucle. Sin
        // tomar el lock compartido podría heredar el conteo de otro test y
        // devolver Abort en lugar de Reexec.
        let _g = signature::TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        signature::test_reset();

        static CODE: [u8; 2] = [0xF7, 0xF1]; // DIV ECX
        let mut gregs = [0u64; AEGIS_NGREG];
        // [BUG] Índice real de RCX en gregs[] (REG_RCX = 14), no 1: gregs[0]
        // es R8. Escribir en gregs[1] parcheaba R9 y el DIV volvía a fallar.
        const GREG_RCX: usize = 14;
        gregs[GREG_RCX] = 0; // ECX = 0 → fallo

        let fin = AegisFrameIn {
            sig: 8, // SIGFPE
            si_code: engine::FPE_INTDIV,
            fault_addr: 0,
            rip: CODE.as_ptr() as u64,
            gregs,
            code: [0; AEGIS_CODE_MAX],
            code_len: CODE.len() as u8,
            reserved: [0; 7],
        };
        // Rellenamos `code` con la instrucción real: la capa C hace esta
        // copia de forma segura y Rust solo analiza lo que le llega.
        let mut fin = fin;
        fin.code[..CODE.len()].copy_from_slice(&CODE);
        let mut fout = AegisFrameOut::default();

        // SAFETY: `fin` y `fout` son locals válidos, alineados y del tamaño
        // exacto que exige el contrato de la FFI.
        let rc = unsafe { aegis_analyze_and_heal(&fin as *const _, &mut fout as *mut _) };
        assert_eq!(rc, 0);
        assert_eq!(fout.action, engine::Action::Reexec as u32);
        // La máscara debe marcar gregs[14], el índice que el handler de C
        // interpretará como REG_RCX. Además, el índice de RIP (16) es parte
        // del contrato y debe coincidir con lo que espera el handler.
        assert_eq!(engine::GREG_RIP, 16);
        assert_eq!(fout.gregs_mask & (1 << GREG_RCX), 1 << GREG_RCX);
        assert_eq!(fout.gregs[GREG_RCX], 1);
        assert_eq!(fout.patch_id, 1);
    }

    #[test]
    fn null_pointers_rejected() {
        // SAFETY: punteros NULL; la función los rechaza ANTES de desreferenciar.
        let rc = unsafe { aegis_analyze_and_heal(core::ptr::null(), core::ptr::null_mut()) };
        assert_eq!(rc, -1);
    }

    #[test]
    fn decoder_fastpath_is_consistent() {
        // El decodificador debe reconocer el DIV del test de arriba.
        let d = fastpath::decode(&[0xF7, 0xF1]).unwrap();
        assert_eq!(d.len, 2);
        assert!(d.is_div);
    }
}