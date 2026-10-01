# Guía de Estilo de Comentarios — AegisRuntime

> **Regla de oro:** el código dice *qué* hace; el comentario dice *por qué*
> lo hace así, y qué contexto o restricción obligó a hacerlo así.
> Si un comentario solo parafrasea la línea siguiente, sobra.

Esta guía es el **contrato** que consume `tools/docgen` (el generador HTML/PDF).
Por eso cada comentario debe ser auto-contenido: el automatizador lo extrae y lo
presenta fuera del archivo, junto a la línea de código que ancla.

---

## 1. Idiomas y sintaxis de comentario

| Lenguaje            | Comentario de línea   | Comentario de bloque        |
|---------------------|-----------------------|-----------------------------|
| C / C23 (`.c/.h`)   | `// ...`              | `/* ... */`                 |
| Rust (`.rs`)        | `// ...` / `/// ...`  | `/* ... */`                 |
| Ensamblador (`.S`)  | `# ...` / `// ...`    | `/* ... */` (GAS x86-64)    |
| Nim (`.nim`)        | `# ...`               | `#[ ... ]#`                 |
| Python (`.py`)      | `# ...`               | `""" ... """`               |
| Make / Shell        | `# ...`               | —                           |

Idioma del contenido: **español** (equipo), preservando términos técnicos en
inglés que no tienen traducción estándar (`signal handler`, `trampoline`,
`ucontext`, `mmap`...).

---

## 2. El comentario correcto

### Qué debe explicar (el PORQUÉ)

1. **Restricciones impuestas por el entorno**: "aquí no podemos llamar a
   `malloc` porque…", "esto debe ser *async-signal-safe* porque…".
2. **Decisiones de diseño** y alternativas descartadas, con su motivo.
3. **Complejidad algorítmica** que no salta a la vista leyendo el código.
4. **Bugs corregidos / deudas pendientes** (con marcador, ver §3).
5. **Razones de portabilidad o ABI** frágil (offsets, orden de registros…).

### Qué NO debe hacer (el QUÉ)

- ❌ Traducir la línea: `// incrementa el contador` sobre `i++`.
- ❌ Repetir el nombre de la función o de la variable.
- ❌ Comentar qué hace una librería estándar ya conocida.

---

## 3. Marcadores estructurados (los lee docgen y los colorea)

Colocarlos **al inicio** del comentario, en mayúsculas, seguidos de `:`.

| Marcador  | Uso                                                                 |
|-----------|---------------------------------------------------------------------|
| `[WHY]`   | Decisión contraintuitiva o que un lector razonablemente tacharía.   |
| `[NOTE]`  | Información contextual que explica el entorno o el flujo.           |
| `[WARN]`  | Peligro conocido, invariante frágil, requisito no obvio.            |
| `[TODO]`  | Trabajo pendiente. Formato: `TODO(autor): qué falta y por qué`.     |
| `[FIXME]` | Código que se sabe incorrecto/incompleto y la cirugía necesaria.    |
| `[BUG]`   | Corrección documentada: qué fallaba, por qué, y qué se hizo.        |
| `[PERF]`  | Trade-off de rendimiento deliberado.                                |
| `[SEC]`   | Consideración de seguridad del propio motor.                        |
| `[EXPL]`  | Explicación de un algoritmo o flujo no trivial.                     |
| `[API]`   | Contrato de la interfaz pública (C-ABI / FFI).                      |

Sin marcador = explicación general de decisión o contexto (misma prioridad que
`[EXPL]`, pero sin etiqueta visual).

### Ejemplos

```c
// [WHY] No resolvemos el símbolo de aegis_core en el constructor con dlsym
// en el *primer* fault: dlsym() no es async-signal-safe y el crash pudo
// corromper el heap. Por eso se resuelve durante aegis_boot() y se cachea.
```

```c
// [FIXME] El decodificador aún no soporta prefijos VEX/EVEX (opcodes 0xC4/0xC5/0x62).
// Cuando aparezcan en RIP, la heurística aborta en vez de adivinar una longitud:
// saltar con una longitud errónea corrompería el flujo silenciosamente.
```

---

## 4. Estructura de archivo recomendada

1. **Cabecera de archivo**: propósito del archivo + responsabilidad en el motor
   (2‑4 líneas, sin divagar).
2. **Secciones**: separadores `// ====== Nombre ======` (docgen los detecta y
   genera un índice de navegación).
3. **Comentario antes del bloque que explica**, nunca dentro si puede evitarse.
4. Los comentarios "trailing" (misma línea) solo para notas cortísimas.

---

## 5. Reglas de mantenimiento

- El docgen se regenera con `make docs`; **todo comentario nuevo aparece solo**.
- Si cambia el código, actualiza el comentario en el mismo commit
  ("documentación evoluciona a la par del código").
- Nunca dupliques documentación: lo que ya está en `docs/ARCHITECTURE.md` no se
  repite en el código; el comentario enlaza el *porqué local*, no la visión global.