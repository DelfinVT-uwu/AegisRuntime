# AegisRuntime — Arquitectura

**Estado:** Fase 1 (Core Engine) — verificada end-to-end. 37 tests unitarios y
4 demos reales (div-zero, null-deref, idiv-overflow, page-edge) pasan de forma
reproducible desde un árbol limpio (`make clean && make test`).

> **Nota de honestidad (2026-09-30):** hasta esa fecha el motor **no había
> compilado nunca**, pese a que este documento ya declaraba la Fase 1 como
> completada. Los fallos encontrados al ponerlo a construir eran graves
> (ver §8). La mitigación de div-zero nunca había llegado a ejecutarse sobre
> un proceso real: el parche aterrizaba en el registro equivocado.

## 1. Propósito

Runtime de resiliencia autónoma para procesos nativos (C/C++/Rust/Go/Fortran).
Intercepta fallos de hardware/memoria a nivel de OS (`SIGSEGV`, `SIGFPE`,
`SIGILL`, `SIGBUS`) **antes** de que el kernel mate el proceso, diagnostica la
causa en microsegundos, aplica un parche/ajuste de contexto y reanuda la
ejecución sin downtime. Funciona vía `LD_PRELOAD` o inyección con `ptrace`
(fase 4), sin recompilar el binario objetivo.

## 2. Stack políglota (por qué cada lenguaje en su sitio)

| Capa            | Lenguaje | Responsabilidad |
|-----------------|----------|-----------------|
| `aegis_sys`     | C23 + ASM x86-64 | ABI C, registro de señales, `sigaltstack`, parseo de `ucontext_t`, memoria con `mmap`. Lo que el kernel invoca. |
| `aegis_core`    | Rust     | Decodificación de instrucción (fast-path `no_std`), heurística de mitigación, firma anti-bucle, telemetría. Donde hay lógica = donde hay seguridad de memoria. |
| `aegis_injector`| Nim      | CLI (`start`/`attach`/`monitor`), orquestación, inyección `ptrace` (fase 4). |

**Decisión clave:** el manejador de C NO pasa el `ucontext_t` crudo a Rust.
C construye un *snapshot* plano `aegis_frame_in_t` (registros GPR + RIP + fault
addr) y Rust devuelve mutaciones en `aegis_frame_out_t`. Razones:

1. `ucontext_t` de glibc es un layout privado y de arquitectura; reinterpretarlo
   desde Rust sin la crate `libc` es frágil y rompe al cambiar de libc/arch.
2. Un struct plano `#[repr(C)]` es barato de copiar y verificar (`_Static_assert`
   en C y `assert` de tamaño en Rust).
3. El contrato FFI queda explícito y auditable (ver `aegis_api.h`).

## 3. Flujo de intercepción (Fase 1)

```
[ CPU fault ] → kernel → sigaltstack → aegis_trap_handler (C23)
   │
   ├─ 1. memcpy de gregs[] (23×u64) → frame_in
   ├─ 2. dlsym cacheado → aegis_analyze_and_heal(&frame_in, &frame_out)  [Rust]
   │        ├─ fastpath: decode longitud de instrucción en RIP (x86-64)
   │        ├─ signature: hash64(RIP ⊕ sig) → contador anti-bucle
   │        ├─ engine: decide acción (div-zero bypass / skip / abort)
   │        └─ telemetry: push a ring buffer lock-free
   ├─ 3. aplicar mutaciones de frame_out al ucontext real
   └─ 4. return → sigreturn → la instrucción se re-ejecuta o se salta
```

## 4. Mitigaciones implementadas (Fase 1)

- **División por cero (`SIGFPE`):** decodifica el `DIV/IDIV` en RIP, detecta el
  registro divisor vía ModRM, lo fuerza a `1` en el snapshot → re-ejecución
  segura (cociente = dividendo).
- **Null/Object-OOB (`SIGSEGV`):** *skip* de la instrucción que falló
  (RIP += longitud). Fase 2 reemplaza el skip por redirección a *Shadow
  Zero-Page*.
- **Firma repetida:** si la misma `(RIP, señal)` falla > `MAX_PATCH_COUNT`
  veces en una ventana de 1 s, el motor aborta con core dump controlado en vez
  de entrar en bucle de parcheo.

## 5. Memoria pre-asignada (regla de no-interferencia)

| Zona | Tamaño | Permisos | Uso |
|------|--------|----------|-----|
| Alt-Stack | 64 KB | RW | Ejecutar el handler si el crash fue stack overflow |
| Shadow Zero-Page | 4 KB | RW | Fase 2+: destino de derefs nulas |
| JIT Code Cave | 1 MB | RW (W^X alternado) | Fase 2+: trampolines `0xE9` |
| Ring telemetría | 64 KB | RW | Eventos lock-free |

Todo se reserva en `aegis_boot()` (constructor) con `mmap(MAP_PRIVATE |
MAP_ANONYMOUS)`. **Nunca** `malloc/free` dentro del handler.

## 6. Estructura del repositorio

```
├── Makefile               # orquesta todo (targets: sys, core, injector, demos, demo, docs, clean)
├── docs/
│   ├── ARCHITECTURE.md    # este archivo
│   ├── STYLE_GUIDE.md     # contrato de comentarios (lo consume docgen)
│   └── generated/         # salida de docgen (HTML + PDF)
├── tools/docgen/          # automatizador: comentarios → HTML + PDF
├── aegis_sys/include/aegis_api.h      # C-ABI pública (+ _Static_assert de layout)
├── aegis_sys/include/aegis_maps.h     # API de consulta del espacio de direcciones
├── aegis_sys/src/trap_handler.c       # handler de señales + ucontext
├── aegis_sys/src/mman_utils.c         # mmap pre-asignado (alt-stack, shadow, code cave)
├── aegis_sys/src/addrspace.c          # /proc/self/maps → lectura SEGURA de RIP
├── aegis_sys/src/trampolines.S        # stubs JIT (fase 2, patrón listo)
├── aegis_core/src/lib.rs              # FFI export (C-ABI)
├── aegis_core/src/fastpath.rs         # decodificador x86-64 (no_std-clean)
├── aegis_core/src/engine.rs           # matriz de decisiones + anti-bucle
├── aegis_core/src/signature.rs        # hash de firma 64-bit
├── aegis_core/src/telemetry.rs        # ring buffer lock-free
├── aegis_injector/                    # [NIM] CLI (fase 4, esqueleto)
├── tests/demos/                       # binarios con fallos intencionales
│   ├── divzero.c          # SIGFPE: DIV por cero
│   ├── null_deref.c       # SIGSEGV: store a NULL
│   ├── idiv_overflow.c    # SIGFPE: cociente que no cabe (NO divisor cero)
│   └── page_edge.c        # SIGFPE al borde de página + guard page detrás
└── scripts/run_demos.sh               # control vs. runtime por demo
```

## 7. Hoja de ruta

- **Fase 1 ✅** intercepción + decode + div-zero bypass + skip + telemetría.
  Verificada end-to-end sobre binarios reales (`make test`).
- **Fase 2** shadow memory re-dirección (deref nula → shadow page), trampolines
  JIT con `mprotect` W^X, detección OOB vía `/proc/self/maps`, Zydis real.
- **Fase 3** empaquetado `libaegis_runtime.so` combinada, syslog/eBPF, suite de
  benchmarks de latencia.
- **Fase 4** injector Nim con `ptrace` para attach a procesos vivos.

## 8. Deuda técnica corregida (2026-09-30)

Todo lo siguiente estaba escrito, documentado y marcado como "Fase 1 ✅", pero
**nunca se había compilado ni ejecutado**. Salió a la luz al intentar construir
el proyecto:

| # | Componente | Fallo | Efecto |
|---|-----------|-------|--------|
| 1 | `signature.rs` | `#[derive(Copy)]` sobre un struct con `AtomicU64` (E0204) | **El crate no compilaba.** Nada de Rust era funcional. |
| 2 | `fastpath.rs` | El byte ModRM se contaba dos veces en la rama `F6/F7` | `decode()` devolvía `None` para **todo** DIV/IDIV. La regla 1 era inalcanzable. |
| 3 | `fastpath.rs` | Inmediato fantasma `Imm::F7` (4 B) en DIV/IDIV | Longitudes de instrucción infladas 4 bytes → `RIP += len` saltaba a mitad de otra instrucción. |
| 4 | `engine.rs` | Índice de registro asumido como identidad | **El parche iba al registro equivocado.** `gregs[0]` es R8, no RAX; RCX es `gregs[14]`, no `gregs[1]`. Se curaba R9 mientras el DIV volvía a fallar con divisor 0. Tras 5 reintentos, core dump. |
| 5 | `fastpath.rs` | REX.B implementado como `rm \| 1` en vez de `rm + 8` | `DIV r8` se curaba como RCX/RDX/RBX/RSI. Nunca producía el rango 8..15. |
| 6 | `fastpath.rs` | Sin distinción byte-alto / byte-bajo en divisores de 8 bits | `DIV AH` imposible de curar: o se parcheaba AL (ineficaz) o se destruía el registro entero. |
| 7 | `mman_utils.c` | `sigaltstack_t` no existe en glibc | **El archivo no compilaba.** El tipo POSIX es `stack_t`. |
| 8 | `engine.rs` | Chequeo de "byte alto" por rango de índice de `gregs` | Confundía SPL (byte bajo, con REX) con AH (byte alto, sin REX). |
| 9 | tests | Tests de `signature` compartían un bucket global y se pisaban entre hilos | Fallos intermitentes dependientes del orden de ejecución. |
| 10 | tests | `different_signature_independent` llamaba `allow()` 10 veces con `max=5` | El test era imposible de pasar por construcción: el 6º intento debe fallar. |
| 11 | `telemetry.rs` | Afirmaba un total absoluto en vez de un delta | Fallaba según qué test hubiera corrido antes en el mismo proceso. |

### El error de fondo (nº 4)

Es el que más merece recordarse, porque **ningún test lo detectaba**: los
tests usaban `gregs[1]` para representar ECX, coherentes con el código
equivocado. Para romper el círculo hizo falta compilar un programa en C que
imprimiera los valores de `REG_*` de `<ucontext.h>` y confrontarlos con la
tabla del motor:

```c
printf("gregs[%2d] = %s (REG_%s = %d)\n", i, ...);
/* gregs[ 0] = R8   gregs[13] = RAX
   gregs[ 1] = R9   gregs[14] = RCX   ... */
```

Un test que use la misma suposición que el código no puede detectar el error;
solo puede detectarlo uno derivado de una fuente externa. Por eso ahora
`gregs_index_matches_glibc_layout` codifica los 16 valores **verificados contra
`ucontext.h`**, escritos a mano para que un cambio en la tabla rompa la
aserción.

## 9. Deuda técnica corregida (2026-09-30, segunda ronda)

Estos tres aparecieron al auditar el código ya funcionando, y los tres
requirieron **medir el sistema real** en vez de fiarse de la documentación:

| # | Componente | Fallo | Efecto |
|---|-----------|-------|--------|
| 12 | `engine.rs` | "Forzar el divisor a 1 cura también el overflow" | **La cura era lo contrario de lo que se creía.** Dividir un dividendo que no cabe entre 1 da un cociente que tampoco cabe: la cura volvía el overflow *inevitable*. El motor entraba en bucle y moría por el antibucles sin resolver nada. |
| 13 | `engine.rs` | Se confiaba en `siginfo.si_code` para distinguir `#DE` de divisor-cero vs. overflow | **Linux x86 nunca lo distingue**: emite siempre `FPE_INTDIV` (1) para cualquier división. Un probe que imprimía `si_code` en ambos escenarios devolvió 1 en los dos. La causa se infiere ahora del **valor real del divisor** en los registros. |
| 14 | `engine.rs` | `slice::from_raw_parts(rip, 15)` — lectura ciega de memoria del proceso | **El runtime mataba al proceso desde dentro del handler.** Si RIP no era legible (fallo de *fetch* sobre `PROT_NONE`, salto a dirección basura) la lectura colgaba el handler en sí mismo, y el kernel forzaba `SIG_DFL`: muerte sin log, sin telemetría y sin abort controlado. Además exigía 15 bytes legibles, descartando la curación de toda instrucción a menos de 15 bytes del final de su página. |

### El error de fondo (nº 14): por qué los tests no lo detectaban

Todos los tests usaban `rip_of(&ARRAY)`, es decir, **la dirección de un array
estático real y legible**. El motor leía 15 bytes de ahí y todo pasaba. El
test nunca ejercitaba el caso que mata: RIP no legible.

La lección es la inversa de la del nº 4. Un test cuyo fixture depende de la
misma suposición que el código no puede detectar el error; hace falta un
fixture que *contraiga* la suposición. Aquí se resolvió moviendo la lectura
fuera del motor:

- `aegis_sys/src/addrspace.c` mantiene un índice de `/proc/self/maps`
  (buffers estáticos, solo `open`/`read`/`close`: async-signal-safe) y expone
  `aegis_read_code_prefix()`, que copia **el prefijo legible** de la
  instrucción, byte a byte, parándose en el primero no legible.
- El código viaja al motor en `aegis_frame_in_t::code[15]` + `code_len`.
- `engine::decide()` recibe `code: &[u8]` y ya **no toca memoria del proceso**:
  no queda ni un `unsafe` en `engine.rs`.

Efectos secundarios favorables:

| Antes | Ahora |
|---|---|
| Exigía 15 bytes legibles;DIV al final de página no se curaba | Se cura con 2 bytes legibles + los que haya (`page_edge.c`) |
| Sin instruction ⇒ el motor aún intentaba leer ⇒ doble fallo | Sin instrucción ⇒ `patch_id 9` + log + re-lanzado limpio |
| Fixtures de test debían estar en memoria real mapeada | Fixtures son arrays normales: `decide_at(&g, SIGFPE, &[0xF7, 0xF1], ...)` |

Lo que **no** se usa, y por qué (medido en esta máquina):

- `process_vm_readv(getpid(), …)`: sería la solución ideal (devuelve `EFAULT`
  en vez de fallar), pero aquí devuelve el conteo de bytes correcto **y no
  copia nada**. Un falso positivo de "puedo leer" reintroduciría el bug.
- `mincore` / `msync`: devuelven éxito sobre una página `PROT_NONE`. Solo
  informan de *residencia*, no de protección.

### El error de fondo (nº 12/13): documentar no es verificar

La justificación original — *"1 divide a cualquier cosa y el cociente nunca
desborda"* — era plausible, estaba escrita con calmly y nadie la contrastó con
el silicio. `tests/demos/idiv_overflow.c` la refuta en cuatro líneas, y las
constantes `FPE_ZERODIVISE`/`FPE_INTOVF` inventadas a partir de esa
justificación eran **constantes documentadas pero nunca observadas**. Un probe
de 20 líneas que imprime `si_code` fue más informativo que la documentación de
`asm-generic/siginfo.h`, que da a entender que se distinguen.

Corolario aplicado: `FPE_INTDIV` se documenta explícitamente como el valor que
Linux emite **de verdad**, y la decisión se toma desde los registros, que sí
son observables.

### Prevenir la repetición

- `scripts/run_demos.sh` ejecuta cada demo **dos veces**: sin el runtime
  (control, debe morir con señal) y con él (debe salir con 0). Un "OK" sin el
  control contrario no demuestra que el motor hizo nada.
- `make test` encadena unitarios + integración.
- Los bytes de cada instrucción de test se han **verificado con `objdump`**
  (`48 F6 E4` es `MUL SPL`, no `DIV AH`; `F6 E4` es `MUL AH`, no `DIV AH`).
  Escribir el test "a ojo" fue la fuente de dos de los fallos.
- `sys` enlaza con **lista explícita** de objetos y `-Wl,--no-undefined`
  (§10), de modo que un símbolo o un `.c` ausente se ven al compilar.

## 10. Deuda técnica corregida (2026-10-01)

Al retomar el árbol, `make test` fallaba en las 4 demos. Los dos fallos eran
**enlazado**, no de lógica: el motor estaba correcto y nunca llegó a ejecutar.

| # | Componente | Fallo | Efecto |
|---|-----------|-------|--------|
| 15 | `mman_utils.c` | `aegis_mmap_zone` declarada `static` sin cuerpo | El alt-stack, la shadow page y el code cave nunca se reservaban. El warning del compilador lo decía (`se usa pero nunca se define`) y estaba ahí desde antes. |
| 16 | `mman_utils.c` | Asignaba a `g_shadow_page`, definido como `static g_shadow_page_base`; `g_shadow_page` solo existía como `extern` en el header | Símbolo sin definición. Todas las demos morían con `exit=127` (`symbol lookup error`) **al arrancar**, no al fallar: el runtime no se cargaba. |
| 17 | `Makefile` | El target `sys` no compilaba `addrspace.c`; el glob `obj/*.o` enmascaraba la ausencia | Tras `make clean`, `aegis_maps_init` quedaba sin definir y las 4 demos volvían a caer. El bug nº16 era **disfrazado** por un `addrspace.o` viejo que sobrevivía en `build/`. |

### El error de fondo (nº 17): un build verde sobre un árbol sucio

Este es el más instructivo, porque **el mismo `make` daba verde y rojo según el
historial del directorio**. La secuencia fue:

1. `make` → verde. Las demos pasaban.
2. `make clean && make test` → las 4 demos fallaban con
   `undefined symbol: aegis_maps_init`.

El paso 1 no demonstraba nada: `build/obj/` contenía un `addrspace.o` de una
compilación anterior en la que el `.c` sí estaba en la lista. El glob
`$(BUILD)/obj/*.o` lo recogía y el enlazador, que por defecto acepta
referencias sin resolver, no tenía nada que objetar. El fallo solo se hacía
visible al borrar la caché —justo lo que nadie hace cuando "ya funciona".

Corolario doble:

- **`ld -shared` no es un verificador.** Por defecto aplaza los símbolos sin
  resolver a la carga, así que una `.so` con referencias rotas parece
  correcta. `-Wl,--no-undefined` convierte ese fallo invisible en un error de
  compilación.
- **Un artefacto que nadie ha pedido en este turno no se puede usar como
  evidencia.** La lección de los errores nº 4 y nº 14 era "verificar contra
  una fuente externa"; aquí la fuente externa era el árbol limpio.

Mitigación aplicada: `SYS_OBJ` es una lista explícita (los cinco `.o`, con el
nombre escrito a mano) en vez de un glob, y el enlace usa `--no-undefined`.
Añadir un `.c` a `SYS_SRC` sin añadir su `.o` a `SYS_OBJ` ahora es un error de
enlace, no un misterio en ejecución.

### Nota sobre el código Capstone (`capdisasm.c`)

`capdisasm.c` compila y se enlaza, pero **`aegis_capstone_init()` no lo llama
nadie**: no está en el constructor de `trap_handler.c` ni hay ninguna llamada
a `aegis_cap_disasm()` en todo el árbol. Es infraestructura de Fase 2
preparada pero no conectada; el motor sigue usando el decodificador propio de
`fastpath.rs`. Se deja así a propósito y documentado, para que no se lea como
una functionality perdida: hoy es inerte y no está en el camino de curate,
pero su presencia en la `.so` significa que **la biblioteca Capstone está
cargada en cada proceso preloadeado** (por `-lcapstone`) sin que nada la use.
Recortar eso, o conectarlo de verdad, es trabajo de Fase 2.

---

## §11. La cura del divisor en memoria (`PatchMem`) — 2026-10-01

### El fallo que existía

El motor solo sabía curar `SIGFPE` cuando el divisor estaba en un **registro**:
escribía un `1` en el `greg` correspondiente y re-ejecutaba la instrucción
(`patch_id 1`).

Esa no es la forma que GCC emite al compilar código real. Cuando las variables
locales se spilled al stack —es decir, siempre que el divisor viene de un
argumento, de un array o de un buffer— el ensamblado es:

```
48 f7 7d e0     idivq  -0x20(%rbp)     ← -O0, variables en el stack
48 f7 3f        idivq  (%rdi)          ← -O1/-O2, argumento en memoria
48 f7 3c f7     idivq  (%rdi,%rsi,8)   ← -O1/-O2, elemento de array
48 f7 3d ...    idivq  0x0(%rip)       ← -O1, global
```

Verificado con `objdump` sobre binarios compilados, no asumido. En esas cuatro
formas **no hay ningún registro que parchear**: el divisor vive en la memoria de
la víctima.

Lo que ocurría entonces era `patch_id 2` = "div-mem: skip". Y aquí está el
problema de fondo: **skip no cura nada**. Salta la instrucción, el proceso
sigue vivo, el supervisor ve exit=0, y el resultado aritmético es basura
silenciosa. Para un runtime que promete "el proceso no muere", eso es peor que
dejarlo morir: un proceso que devuelve datos incorrectos durante horas es un
incidente de producción más caro que un crash.

### Lo que se ha hecho

Nueva acción `PatchMem` (`action 5`), repartida en el punto correcto de la
frontera de confianza:

| Capa | Qué hace | Por qué aquí |
|---|---|---|
| `fastpath.rs` | Decodifica la **forma** de direccionamiento: `base`, `index`, `scale`, `disp`, `rip_relative` | Solo ve bytes. No conoce valores de registro, y eso es lo que lo hace testeable con arrays estáticos. |
| `engine.rs` | **Resuelve** la EA con los `gregs` del frame y decide | Es lo único que tiene los valores. Sigue sin tocar memoria. |
| `lib.rs` | Serializa a `mem_addr`, `mem_val`, `mem_size` en `frame_out` | Transporta la decisión, no la ejecuta. |
| `trap_handler.c` | **Valida y escribe**, con `memcpy` de ancho exacto | Es la frontera de confianza. Aquí ya existe la tabla de `/proc/self/maps`. |

El reparto es deliberado: Rust *calcula* direcciones pero nunca las desreferencia.
C *escribe* pero nunca *decide*. Ninguno de los dos tiene la operación
peligrosa por completo.

### Las tres validaciones que hacen esto seguro

Escribir en la memoria de un proceso roto es **la operación más peligrosa del
runtime**. Un registro mal elegido rompe la instrucción y se nota; una
dirección mal elegida corrompe un dato que la app quizá no vuelve a leer nunca,
y el síntoma aparece minutos después en otro módulo con la culpa puesta en
Aegis. Por eso, en orden, y con fallo cerrado en cada paso:

1. **`mem_size` ∈ {1,2,4,8}** — si no, no se escribe nada. Es la defensa contra
   una ABI desalineada Rust↔C: un `mem_size` corrupto no puede convertirse en
   un número arbitrario de bytes escritos.
2. **La página debe ser escribible** (`aegis_addr_writable()`, nueva consulta en
   `addrspace.c`, que ya tenía la de lectura). Sin esto, escribir en un *hole
   mapping* provocaría un `SIGSEGV` **dentro del handler**, que es
   irrecuperable.
3. **Se escriben exactamente `mem_size` bytes**, no 8. `div r/m8` lee un byte;
   escribir 8 pisaría tres variables siguientes de la app.

Y cuando la EA no es resoluble, el motor **degrada a `skip`** en vez de inventar
una dirección: saltar es malo, pero saltar es reversible.

### Bugs encontrados al implementar esto

Tres, y los tres eran del mismo tipo — código que parecía correcto porque el
test afirmaba lo que el código hacía:

**1. `rm == 5` con `mod != 0` significa base = RBP, no displacement absoluto.**
La primera versión solo rellenaba `base` cuando leía un byte SIB. Pero
`idivq -0x20(%rbp)` **no tiene SIB**: ModRM = `0x7d` (mod=01, rm=101) y el `rm`
es directamente el registro base. El motor devolvía `base: None`, calculaba la
EA como `disp` pelado (`0xFFFFFFFFFFFFFFE0`), escribía el divisor corregido en
el espacio de núcleo, el `#DE` se repetía y el proceso moría por la tabla
anti-bucle. La telemetría decía `rule=10` — "curado" — mientras la app no
funcionaba. **El peor tipo de bug: la cura que no cura y lo reporta como
cura.**

**2. Los tests usaban bytes que GCC nunca emite.** Escribí la suite de
direccionamiento a mano y pasó. Los bytes eran incorrectos: en
`48 F7 04 8E` el campo `reg` del ModRM es `000` = **TEST**, no `111` = IDIV.
Esa instrucción no es una división en absoluto. Los tests PASABAN porque
assertan el resultado del propio decodificador, y el decodificador estaba tan
equivocado como los bytes: medían coherencia interna, no correctitud frente al
hardware.

Mitigación: **todos los bytes de la suite de direccionamiento salen ahora de
`objdump`** (sobre binarios que GCC compila, y sobre `as`/`objdump` para las
formas que el compilador no genera solo). El comentario de cada test cita la
línea de C que produce esos bytes. Es la diferencia entre un test que verifica
el decodificador y un test que verifica que el decodificador coincide con el
procesador.

**3. Hay dos "mod=00 sin base" distintos.** `rm=4` con `SIB.base=101` es
`idivq 0x44332211` (disp32 absoluto); `rm=5` sin SIB es `idivq 0x0(%rip)`
(RIP-relativo). Ambos consumen 4 bytes, así que la longitud salía bien, pero la
EA se calculaba mal en uno de los dos. Ahora hay una bandera explícita que
distingue los casos en vez de deducirlos de la ausencia de base.

Además: `read_disp` lee el desplazamiento **con signo**. `0xE0` es `-32`, y
leerlo como `u8` daría una dirección 256 bytes más alta — es decir, un borrado
de memoria en un sitio sin relación. Hay tests dedicados a los dos anchos de
desplazamiento negativo (`disp8` y `disp32`).

### ABI

`aegis_frame_out_t` crece de 208 a 232 bytes. Los campos nuevos (`mem_addr`,
`mem_val`, `mem_size`, `reserved2`) van **al final**, así que los offsets de todo
lo existente no cambian: un motor Rust antiguo sigue hablando con este header.
Hay `_Static_assert` en C y `assert_eq!(offset_of!(...))` en Rust para los dos
lados, porque si se mueven los campos C escribe el divisor en un sitio
arbitrario y nada en el build lo detecta.

`AEGIS_ACTION_PATCH_MEM = 5` **comparte número** con `Action::PatchMem = 5` en
Rust. Renumerar cualquiera de los dos rompe la curación **en silencio**: el
`switch` de C no cae en la rama de escritura, el proceso se cura sin cambiar
nada, y la telemetría sigue diciendo `rule=10`.

### Verificación

- 55 tests unitarios Rust (antes 37). Los nuevos cubren: las 8 formas de
  direccionamiento de `fastpath`, y en `engine` la EA con `rbp+disp8`,
  `disp32`, RIP-relativo, SIB indexado, ancho de 8 bits, y que **no** se toca
  ningún registro al curar por memoria.
- Nueva demo `tests/demos/divmem`, y `scripts/run_demos.sh` ahora comprueba
  **qué regla se aplicó**, no solo que el proceso sobreviva. Es la diferencia
  entre verificar una cura y verificar que el proceso no se muriera.
- Programa real (no fixture): un `divide()` de aplicación compilado a -O2 que
  emite `idivq -0x8(%rsp)`; sin Aegis `rc=136` (`SIGFPE`), con Aegis
  `total=100` y `rc=0`.

---

## §12. `aegis_injector/` — la CLI en Nim

### Por qué Nim y no más C

El reparto de lenguajes no es arbitrario, y el criterio es **dónde está el
peligro**:

| Componente | Lenguaje | Motivo |
|---|---|---|
| `trap_handler.c`, `addrspace.c`, `mman_utils.c` | C23 + ASM | Frontera de confianza. Corre en un signal handler con el hilo a medio camino de un crash. Aquí la ausencia de alocaciones, locks y stdio **no es una preferencia de estilo: es una corrección**. |
| `aegis_core` | Rust `no_std` | Lógica de decisión verificable, sin UB en el acceso a memoria, tipos que impiden el fallo silencioso. |
| `aegis_injector` | **Nim** | Orquestación: parsear argv, hablar con `ptrace`, formatear informes, responder al operador. |

El criterio: **en el camino de curación, lo que es fácil de equivocar es la
gestión de memoria manual sobre procesos ajenos.** Es exactamente el tipo de bug que se
ha acumulado en la capa de trapping. Nim da GC, `string` seguras y `seq` a
cambio de nada que el supervisor necesite evitar — y esa componente corre **una
vez por proceso hijo**, nunca dentro de un handler.

Por eso el inyector **no duplica ninguna heurística de curación**: esa lógica
vive en `aegis_core` y está verificada con 55 tests. Dos fuentes de verdad que
divergen son exactamente los fallos nº4 y nº12 de este documento.

### Los tres modos

```
aegis run    <cmd> [args]   ejecuta con LD_PRELOAD y muestra la telemetría
aegis heal   <cmd> [args]   como `run`, pero exit=0 solo si curó y terminó bien (CI)
aegis attach <pid>          observa (sin reparar) un proceso existente
```

`heal` es el modo pensado para CI: distingue "el proceso sobrevivió" de "el
runtime lo salvó". Un `aegis heal` que devuelve 0 es evidencia; un `LD_PRELOAD`
a mano que devuelve 0 no lo es.

`attach` es deliberadamente **read-mostly**: observa traps vía `ptrace` sin
modificar el contexto del proceso ajeno. Curar el proceso de otro es una
decisión de política —¿y si la corrupción es intencional?— que un supervisor no
tiene derecho a tomar por su cuenta.

### Detalles de implementación que parecían menores y no lo son

- **Las rutas se resuelven desde el binario, no desde el CWD.** Un supervisor
  lanza el inyector desde `/` o desde `cron`. Con rutas relativas al CWD,
  `aegis heal /usr/bin/mi_app` fallaría con "falta libaegis_sys.so" en el 99%
  de los despliegues reales.
- **La clasificación de "curado" no es `action in 1..3`.** `patchmem` (5) es la
  cura más fuerte de todas y clasificarla como fatal haría que `heal` fallara
  justo cuando el motor funciona mejor. La lista se escribe explícita.
- **No se desactiva ASLR.** Es una defensa de seguridad del proceso objetivo;
  desactivarla para "facilitar" la observación sería un empeoramiento silencioso
  que el operador no pidió. Si quiere direcciones estables, que use `setarch -R`
  él mismo, de forma explícita.
- **El entorno se copia a un `StringTableRef`**, no a una `seq[string]`: Nim
  2.x exige la tabla, y el `LD_PRELOAD` propio sustituye a cualquier previo
  (el constructor de Aegis debe registrar los handlers antes que nadie más).