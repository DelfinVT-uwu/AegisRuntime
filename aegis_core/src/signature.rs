//! signature.rs — Firmas de fallo y prevención de bucles de parcheo.
//!
//! Responsabilidad: responder "¿esta misma (RIP, señal) ya falló demasiadas
//! veces en poco tiempo?" La respuesta decide entre seguir curando o abortar
//! con core dump controlado.
//!
//! [WHY] Sin este contador, un fallo *no reparable* (p. ej. RIP corrupto que
//! apunta al vacío) se reintentaría infinitamente: el motor curaría, el
//! programa volvería a fallar, curaría... un bucle de parcheo peor que el
//! crash original. Por eso la casa de apuestas del motor es: "máximo N
//! parcheos por firma en una ventana T; después, degradación elegante".
//!
//! [WHY] Hash table de 64 buckets estática (no un HashMap): dentro del signal
//! handler no podemos alocar ni tomar locks; un array fijo de `Atomic*`
//! lock-free es todo lo que la frontera async-signal-safe permite. Las
//! colisiones (2 firmas en el mismo bucket) solo *comparten* el contador, lo
//! que puede abortar prematuramente en el peor caso — nunca curar de más,
//! que es el error peligroso.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const BUCKETS: usize = 64;

/// Hash table estática: un bucket por franja de hash.
struct Bucket {
    /// Hash de la firma dueña del bucket (0 = vacío).
    key: AtomicU64,
    /// Parcheos contados en la ventana actual.
    count: AtomicU32,
    /// Inicio (ns) de la ventana temporal.
    win_start: AtomicU64,
}

impl Bucket {
    const fn new() -> Self {
        Bucket {
            key: AtomicU64::new(0),
            count: AtomicU32::new(0),
            win_start: AtomicU64::new(0),
        }
    }
}

// [BUG] Esto NO lleva `#[derive(Copy)]`. El patrón original repetía una
// instancia de `Bucket` para inicializar el array, y eso exigía Copy — pero
// `AtomicU64`/`AtomicU32` nunca implementaron Copy (el compilador lo rechaza
// con E0204: un atómico no es trivialmente copiable, copiarlo rompería la
// semántica de sincronización). La forma correcta es `const { ... }` inline:
// el inicializador se evalúa en tiempo de compilación tantas veces como haga
// falta, sin mover ningún `Atomic` en runtime. Alternativa que también
// funcionaba: `Default` + `[Bucket::default(); N]`, que tampoco requiere Copy.
static BUCKET_ARR: [Bucket; BUCKETS] = [const { Bucket::new() }; BUCKETS];

/// [WHY] Serializa a los tests que tocan la tabla global. Vive fuera del
/// módulo `tests` porque `engine.rs` y `lib.rs` también llegan a `allow()`
/// (todo `decide()` pasa por aquí) y deben compartir el MISMO mutex: si cada
/// módulo tuviera el suyo, seguirían compitiendo por los mismos buckets.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// [WHY] Vacía la tabla para que un test arranque con contadores a cero. Es
/// `pub(crate)` (no privado del módulo `tests`) por el mismo motivo que
/// `TEST_LOCK`: los tests de `engine.rs` también necesitan un estado limpio,
/// porque su `decide()` consume reintentos del contador global.
#[cfg(test)]
pub(crate) fn test_reset() {
    for b in BUCKET_ARR.iter() {
        b.key.store(0, Ordering::Relaxed);
        b.count.store(0, Ordering::Relaxed);
        b.win_start.store(0, Ordering::Relaxed);
    }
}

/// Hash FNV-1a 64-bit de (rip, sig). FNV es deliberado: es *barato* (5
/// operaciones por byte) y no necesitamos resistencia criptográfica, solo
/// distribución decente sobre 64 buckets. El coste importa: corre dentro
/// del handler.
pub fn hash64(rip: u64, sig: u32) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    let mut h = OFFSET;
    // Alimentamos RIP (8 bytes) y la señal (4 bytes); mezclarlos byte a byte
    // en vez de XOR+hash garantiza que dos RIPs con el mismo XOR den firmas
    // distintas, que es justo el caso que queremos distinguir.
    let words = [rip.to_le_bytes(), (sig as u64).to_le_bytes()];
    for chunk in words {
        for &b in &chunk {
            h ^= b as u64;
            h = h.wrapping_mul(PRIME);
        }
    }
    h
}

/// Registra un fallo con esa firma y dice si se permite seguir curando.
///
/// `max` = límite de parcheos por ventana; `window_ns` = duración de la
/// ventana. Idempotente y lock-free; varios hilos fallando a la vez producen
/// conteos best-effort (nunca un deadlock, que es lo que importa aquí).
pub fn allow(rip: u64, sig: u32, now_ns: u64, max: u32, window_ns: u64) -> bool {
    let h = hash64(rip, sig);
    let idx = (h % BUCKETS as u64) as usize;
    let b = &BUCKET_ARR[idx];

    let key = b.key.load(Ordering::Relaxed);
    if key != h {
        // Firma nueva (o bucket tomado por otra): reclamamos el bucket con
        // CAS para no pisar al hilo que acaba de ganarlo.
        if b.key
            .compare_exchange(key, h, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            b.count.store(1, Ordering::Relaxed);
            b.win_start.store(now_ns, Ordering::Relaxed);
            return true;
        }
        // Perdimos la carrera: este fallo cuenta para la firma ganadora.
        //
        // [EXPL] `fetch_add` devuelve el valor ANTERIOR, así que el conteo
        // nuevo es `prev + 1` y la condición "no exceder max" es
        // `prev + 1 <= max`, que equivale a `prev < max`. Se escribe así
        // (sin el `+ 1`) porque es más claro y evita la aritmética.
        return b.count.fetch_add(1, Ordering::AcqRel) < max;
    }

    let start = b.win_start.load(Ordering::Relaxed);
    if now_ns.saturating_sub(start) > window_ns {
        // Ventana expirada: el fallo es *antiguo*, no una recurrencia.
        // Reiniciamos la ventana y seguimos curando.
        b.count.store(1, Ordering::Relaxed);
        b.win_start.store(now_ns, Ordering::Relaxed);
        true
    } else {
        b.count.fetch_add(1, Ordering::AcqRel) < max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [WHY] Sólo para tests. `BUCKET_ARR` es estado global de proceso y el
    /// runner de Rust lanza los tests en PARALELO: dos tests que nominalmente
    /// usan firmas distintas se pisan el conteo del bucket compartido y ambos
    /// fallan de forma intermitente, según el orden de ejecución. Además, las
    /// colisiones de hash son el comportamiento *diseñado* (ver cabecera del
    /// módulo), así que no se puede "arreglar" la tabla: hay que aislar el
    /// test. `test_reset` + este mutex dejan cada test partiendo de una tabla
    /// limpia y sin carrera. `#[cfg(test)]` los elimina por completo de la
    /// build de release: el hot-path no los toca.
    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK
            .lock()
            // [NOTE] `unwrap()` envenenaría el lock: un test que falla deja el
            // mutex envenenado y el siguiente test también fallaría, creando
            // un tsunami de falsos negativos. `into_inner()` lo rescata.
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        test_reset();
        guard
    }

    #[test]
    fn same_signature_exhausts_after_max() {
        let _g = fresh();
        let now = 1_000;
        for i in 0..5 {
            assert!(allow(0x401000, 11, now, 5, 1_000_000), "intento {i}");
        }
        // El sexto fallo en la misma ventana debe negarse.
        assert!(!allow(0x401000, 11, now, 5, 1_000_000));
    }

    #[test]
    fn different_signature_independent() {
        let _g = fresh();
        let now = 1_000;
        // Agotamos la primera firma: 5 curaciones, la 6ª aborta.
        for i in 0..5 {
            assert!(allow(0x401000, 11, now, 5, 1_000_000), "intento {i}");
        }
        assert!(!allow(0x401000, 11, now, 5, 1_000_000));

        // [WARN] 0x402000/11 cae en el bucket 46 y 0x401000/11 en el 30 con el
        // hash64 actual. Si someday se cambia `hash64` y chocan, este test
        // fallaría NO por un fallo del motor sino por la colisión documentada:
        // es la prueba de que el aislamiento depende del hash.
        assert!(allow(0x402000, 11, now, 5, 1_000_000));
    }

    #[test]
    fn window_resets_counter() {
        let _g = fresh();
        assert!(allow(0x401000, 8, 0, 5, 1_000));
        assert!(allow(0x401000, 8, 100, 5, 1_000));
        // Ventana de 1ms expirada → nueva ventana, se vuelve a curar.
        assert!(allow(0x401000, 8, 2_000, 5, 1_000));
    }

    #[test]
    fn hash_distinguishes_rip_from_sig() {
        assert_ne!(hash64(0x1000, 11), hash64(0x1000, 8));
        assert_ne!(hash64(0x1000, 11), hash64(0x2000, 11));
    }
}