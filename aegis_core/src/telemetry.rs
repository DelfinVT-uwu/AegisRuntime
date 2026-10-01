//! telemetry.rs — Registro lock-free de eventos (Ring Buffer).
//!
//! Responsabilidad: guardar una traza compacta de cada trap/heal para
//! auditoría post-mortem, sin bloquear ni alocar dentro del handler.
//!
//! [WHY] Escribir a disco/syslog *dentro* del handler es caro y no
//! async-signal-safe. En su lugar, el handler hace una copia barata a un
//! buffer circular en RAM y un drenador externo (Fase 3: hilo de flusher o
//! eBPF) la vuelca en calma. Mientras no exista el drenador, el ring retiene
//! los últimos N eventos en memoria — suficiente para un `gdb`/`crash` dump
//! posterior y para los tests.
//!
//! [WARN] El diseño es SPSC best-effort: solo los handlers escriben (un
//! productor lógico por hilo) y el futuro flusher lee. Una lectura mientras
//! un hilo escribe puede ver un evento a medias; para Fase 1 es aceptable y
//! documentado — el drenador de Fase 3 introducirá una secuencia + checksum
//! por slot.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Un evento forense mínimo.
///
/// [WHY] `#[allow(dead_code)]` en los campos: los escribe `push()` pero
/// dentro del crate nadie los LEE todavía, porque el drenador (flusher) que
/// exportará estas trazas a disco es trabajo de Fase 3. Son datos, no código
/// muerto: si desaparecieran, el ring no cumpliría su propósito. El warning
/// se silencia aquí de forma explícita para que no ensucie cada build; cuando
/// exista el flusher, este `allow` se puede quitar y el warning debe volver a
/// dar si alguien rompe el contrato.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub ts_ns: u64,
    pub sig: u32,
    pub action: u32,
    pub patch_id: u32,
    pub rip: u64,
    pub fault_addr: u64,
}

const CAPACITY: usize = 256;

const EMPTY: Event = Event {
    ts_ns: 0,
    sig: 0,
    action: 0,
    patch_id: 0,
    rip: 0,
    fault_addr: 0,
};

/// [PERF] 256 × 40 B = 10 KB durante todo el ciclo de vida del proceso.
/// Deliberadamente pequeño: la telemetría no debe competir con la caché del
/// programa curado (el sobrecoste en régimen normal debe ser 0%).
// [WHY] `static mut` + unsafe es deliberado: el productor ES el handler (un
// solo hilo lógico por fault) y el ring es un array plano de 10 KB; una
// celda `UnsafeCell` por slot duplicaría la complejidad sin cambiar la
// semántica. La disciplina se protege con comentario en vez de con el
// type-system porque el type-system no admite este patrón sin boilerplate.
static mut RING: [Event; CAPACITY] = [EMPTY; CAPACITY];

/// Índice del próximo slot (crece monótonamente; se envuelve al escribir).
static HEAD: AtomicUsize = AtomicUsize::new(0);
/// Total de eventos desde el arranque (nunca se envuelve).
static TOTAL: AtomicU64 = AtomicU64::new(0);

/// Registra un evento (llamado SOLO desde el handler).
pub fn push(ev: Event) {
    let idx = HEAD.fetch_add(1, Ordering::Relaxed) % CAPACITY;
    // [EXPL] Relajado es correcto: el productor es el propio hilo y el lector
    // (flusher) no existe todavía; el uso de Release/acquire se introducirá
    // con el checksum de Fase 3.
    unsafe {
        RING[idx] = ev;
    }
    TOTAL.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn test_reset() {
    HEAD.store(0, Ordering::Relaxed);
    TOTAL.store(0, Ordering::Relaxed);
    // Limpiar el ring evita que eventos antiguos aparezcan.
    unsafe {
        RING = [EMPTY; CAPACITY];
    }
}

/// Número total de eventos registrados (diagnóstico / tests).
#[allow(dead_code)]
pub fn total_events() -> u64 {
    TOTAL.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_wraps_and_keeps_total() {
        // [BUG] El ring y `TOTAL` son globales. La FFI (`aegis_analyze_and_heal`)
        // hace `push()` y `cargo test` corre tests en paralelo: el contador
        // podía crecer entre el `load` inicial y los `push()` o entre tests.
        // Además, el test original comparaba con un valor absoluto. El fix es:
        // aislar con mutex (o, al menos, resetear) y comparar con 0 relativo.
        let _g = crate::signature::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        test_reset();
        let n = CAPACITY + 10;
        for i in 0..n {
            push(Event {
                ts_ns: i as u64,
                sig: 11,
                action: 2,
                patch_id: 3,
                rip: 0x400000 + i as u64,
                fault_addr: 0,
            });
        }
        assert_eq!(total_events(), n as u64, "cada push() debe sumar exactamente 1");
    }
}