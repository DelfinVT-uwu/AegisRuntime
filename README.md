# AegisRuntime

**Runtime de resiliencia que cura fallos de CPU en procesos reales, sin recompilarlos.**

Cuando un programa recibe un `SIGFPE` (división por cero) o un `SIGSEGV` (acceso
inválido a memoria), normalmente el kernel lo mata y se acabó: core dump, pérdida
de datos, downtime. AegisRuntime se inyecta en el proceso mediante `LD_PRELOAD`,
intercepta la señal **antes** de que el kernel mate nada, diagnostica la causa, la
**repara** y reanuda la ejecución.

```
$ ./aegis run ./mi_programa 100 0
total=100                          # el programa sigue y da un resultado útil

  ── informe ────────────────────────────────────
    curados  : 1 evento(s)
    ────────────────────────────────────────────
    SIGFPE   action=patchmem rule=div-mem: divisor forzado a 1 en RAM + re-ejecucion
```

Sin Aegis, ese mismo programa moría con `rc=136` (128 + 8 = SIGFPE).

---

## ¿En qué se diferencia?

| Herramienta | Qué hace ante un fallo |
|---|---|
| **Wireshark** (`epan/except.c`) | `siglongjmp`: **abandona** la instrucción que falló |
| **DynamoRIO** (`dr_register_exception_event`) | **abandona** la instrucción que falló |
| **AegisRuntime** | **repara** el estado y **re-ejecuta** la instrucción |

Las herramientas existentes hacen que el programa *sobreviva* saltándose el error.
Aegis lo hace **calculando el resultado correcto**: si divides por cero, reescribe
el divisor y te da el cociente real. En `100 / 0` devuelve `100`, no un cero
inventado ni un salto silencioso.

---

## Cómo funciona

Cada lenguaje está donde el peligro es real. La regla: **donde hay lógica hay
seguridad de memoria** (Rust), y **donde el kernel te llama hay C mínimo**.

| Capa | Lenguaje | Responsabilidad |
|---|---|---|
| `aegis_injector` | **Nim** | CLI: lanza el proceso, recoge la telemetría. No decide curas. |
| `aegis_sys` | **C23 + ASM** | Handler de señal, `ucontext_t`, validación de memoria. Lo que invoca el kernel. |
| `aegis_core` | **Rust `no_std`** | Decodifica la instrucción, decide la acción, firma anti-bucle. |

### El flujo de una curación

```
Fallo de CPU → kernel → sigaltstack → aegis_trap_handler (C23)
   │
   ├─ 1. Copia gregs[] (23×u64) + RIP + los BYTES de la instrucción → frame_in
   ├─ 2. dlsym cacheado → aegis_analyze_and_heal(&in, &out)   [Rust]
   │        ├─ fastpath: decodifica la instrucción en RIP (x86-64)
   │        ├─ engine:   decide la acción (parche / saltar / abortar)
   │        ├─ signature: hash de (RIP, señal) → contador anti-bucle
   │        └─ telemetry: ring buffer lock-free
   ├─ 3. C VALIDA y APLICA las mutaciones (nunca Rust directamente)
   └─ 4. return → sigreturn → la instrucción se re-ejecuta con el estado reparado
```

### Las tres ideas del diseño

**1. El motor no toca memoria. Ni la desreferencia, ni la lee.**
C copia el prefijo legible de la instrucción (hasta 15 bytes, o hasta donde acabe
la página) y Rust decodifica **sobre esa copia**. Así Rust no tiene un solo `unsafe`
de acceso a memoria, que es exactamente donde no queremos estar dentro de un
handler de señal. Antes de esto el motor hacía `slice::from_raw_parts(rip, 15)` y se
colgaba solo si RIP no era legible.

**2. Separar "calcular la dirección" de "escribir en ella".**
Rust devuelve un `MemWrite { addr, val, size }`: Rust **calcula** la dirección,
C la **valida** (tamaño ∈ {1,2,4,8}, página escribible según `/proc/self/maps`) y
**escribe** exactamente ese tamaño. Nadie desreferencia por su cuenta: si la
dirección no es resoluble, degrada a `skip` en vez de inventarla — **fallo cerrado**.

**3. Cero decisiones duplicadas.**
El inyector en Nim no reimplementa la heurística: hay una sola fuente de verdad
(el motor en Rust). Añadir una regla no obliga a tocar tres sitios.

### La cura `PatchMem`: el divisor vive en RAM

Este es el caso difícil y el más frecuente en software compilado a `-O2`. GCC
optimiza el divisor a un **stack spill**, así que la instrucción que falla es algo
como `idivq -0x8(%rsp)` — el divisor **no está en ningún registro**, sino en
memoria. No hay registro que parchear.

Aegis entonces:
1. Decodifica el ModRM y el SIB para resolver la **dirección efectiva** del divisor
   (`base + index×scale + disp`, RIP-relativo, `rbp+disp8`, …).
2. Comprueba que la dirección es válida y escribible.
3. Escribe `1` en esa posición de memoria.
4. **Re-ejecuta** la misma instrucción → el cociente sale correcto.

```
idiv REAL en offset 0x11f1  ->  48 f7 7c 24 f8   idivq  -0x8(%rsp)
dirección efectiva del divisor = 0x7fffffffe390
valor del divisor EN MEMORIA  = 0   <-- cero => #DE
```

### Seguridad

- **Fallo cerrado.** Si algo no cuadra, Aegis no improvisa: devuelve `skip` o deja
  morir al proceso. Nunca inventa una dirección ni un valor.
- **Anti-bucle.** Si la misma `(RIP, señal)` falla muchas veces en 1 segundo, aborta
  con core dump controlado en vez de parchear en bucle infinito.
- **Sin `malloc` en el handler.** Toda la memoria (alt-stack, shadow page, code
  cave, ring de telemetría) se reserva en el constructor con `mmap`, antes del
  primer trap.
- **No desactiva ASLR ni elude Yama.** Son decisiones de seguridad del proceso
  objetivo; toolkits que las sortean no tienen nada que enseñar aquí.

---

## Compilar

Requisitos: **gcc/clang** (C23), **cargo**, **nim**, y opcionalmente Capstone.

```bash
make all       # las dos .so (esto es el producto)
make demos     # binarios de prueba, que fallan A PROPÓSITO
make cli       # el binario `aegis` (Nim)
make test      # suite de tests
```

Las demos están separadas de `all` a propósito: son programas que abortan con core
dump por diseño, y no tiene sentido que `make` los construya por defecto.

## Uso

```bash
# ejecutar un programa bajo Aegis
./build/bin/aegis run ./mi_programa argumentos...

# como `run`, pero devuelve error (rc=1) si NO hubo ninguna cura.
# útil en CI: "este test debe lanzar SIGFPE y ser curado".
./build/bin/aegis heal ./mi_programa

# engancharse a un proceso ya vivo y observar sus traps (solo lectura)
./build/bin/aegis attach <pid>
```

También funciona con `LD_PRELOAD` directo, **precargando las dos bibliotecas**
(el motor sin la otra no cura: son dos bibliotecas, no una):

```bash
LD_PRELOAD=build/lib/libaegis_sys.so:build/lib/libaegis_core.so ./mi_programa
```

---

## Verificación

El requisito de diseño era: **probar con programas reales del sistema, no con
programas inventados para que fallen.** Un programa escrito por nosotros ya sabe
dónde está su `idiv`, así que no demuestra nada.

**No-interferencia** — binarios reales del sistema, salida idéntica bit a bit
(hash SHA-256 de la salida con y sin Aegis):

```
IGUAL   df          IGUAL   awk         IGUAL   python3
IGUAL   sort        IGUAL   objdump     IGUAL   readelf
IGUAL   iconv       IGUAL   nm          IGUAL   file
IGUAL   sqlite3     IGUAL   sha256sum
```

**Curación real** — un programa compilado a `-O2` (como el software de producción),
con el divisor spilled en el stack:

| | Sin Aegis | Con Aegis |
|---|---|---|
| Código de salida | `136` (SIGFPE) | `0` |
| Resultado | proceso muerto | `total=100` |

Y el resultado numérico es el correcto, no un número fijo:
`76543 / 0 → 76543` (con el divisor reparado a 1, el cociente es el dividendo).
Cuando el divisor es válido no se toca nada: `100 / 5 → 20`.

**Resultado negativo honesto.** Se intentó encontrar fallos naturales haciendo
fuzzing (3000 rondas de mutación) sobre parsers reales (`djpeg`, `ffprobe`,
`ImageMagick`, `objdump`, `readelf`, `xz`, `7z`) con archivos del sistema
degradados. **0 crashes**: los binarios de 2025–26 están endurecidos contra
entrada malformada trivial. Se documenta porque el resultado negativo es
información, y porque confirma que el arnés de prueba funcionaba.

---

## Estructura

```
├── Makefile
├── aegis_injector/aegis_injector.nim   # CLI (Nim): run / attach
├── aegis_sys/                         # C23 + ASM: handler de señal
│   ├── include/aegis_api.h            # contrato FFI (+ asserts de layout)
│   └── src/{trap_handler,addrspace,mman_utils,capdisasm}.c
├── aegis_core/src/*.rs                # Rust no_std: fastpath, engine, signature
├── tests/demos/*.c                    # binarios con fallos intencionales
├── scripts/{run_demos,bench_overhead}.sh
└── docs/ARCHITECTURE.md               # decisiones y bitácora de deuda técnica
```

`docs/ARCHITECTURE.md` tiene el detalle completo: por qué cada lenguaje está donde
está, el contrato FFI, y una bitácora de los **bugs que se encontraron y
corrigieron** (incluidos los que estaban en el código antes de que llegara a
compilar).

## Rendimiento

Medido sobre sqlite3, bash, python3 y git (mediana, `scripts/bench_overhead.sh`):

- **Arranque** (procesos mínimos): +0.5–0.6 ms fijos.
- **Estado estable** (workloads de cientos de ms): **+0.02% a +3.5%**, típico 1%.

## Estado

Fase 1 (núcleo) completa y verificada end-to-end. La fase 2 (parche JIT con
trampolines y shadow page) está preparada en la estructura pero inactiva.

## Advertencia

Esto es una herramienta de diagnóstico y resiliencia. Repara fallos para que
puedas inspeccionar el estado del proceso; **no** convierte un programa con
memoria corrupta en uno correcto. Usar `PatchMem` cambia el resultado del cálculo:
para una app de producción es una decisión, no un efecto gratis.

## Licencia

MIT.