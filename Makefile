# =============================================================================
# Makefile — AegisRuntime
#
# Orquesta el build de las tres capas (C23, Rust, ASM) y las demos.
#
# [BUG-GUARDADO] `sys` NO enlaza con `build/obj/*.o` sino con la lista
# explícita SYS_OBJ, y usa -Wl,--no-undefined. Un glob más un enlazador
# tolerante convertían un `.c` sin compilar en un fallo que solo aparecía al
# PRELOADAR la .so (undefined symbol en runtime), y de paso permitían que un
# .o huérfano de una versión anterior siguiera enlazado para siempre. Ver
# §10 de docs/ARCHITECTURE.md.
#
# [WHY] `all` NO compila las demos. Las .so son el producto; las demos son
# fixtures de prueba — programas que fallan A PROPÓSITO. Meterlas en el
# objetivo por defecto haría que `make` construyera binarios que abortan con
# core dump, que es exactamente lo que un usuario espera que no pase.
#
# [NOTE] No es que el runtime "contamine" a las demos al compilarlas:
# LD_PRELOAD se aplica al EJECUTARLAS, no al construirlas. El aislamiento es
# de proceso, y por eso `scripts/run_demos.sh` lanza cada demo dos veces —sin
# y con el runtime— para que el resultado signifique algo.
# =============================================================================

CC      ?= gcc
RUSTC   ?= cargo
# [WHY] -std=c2x y no -std=c23: gcc 13+/clang lo nombran distinto según la
# versión. c2x es el nombre estable que ambos aceptan desde 2020.
CSTD    ?= -std=c2x
CFLAGS  ?= -O2 -g -Wall -Wextra -Wpedantic -fPIC
ASFLAGS ?= -g
# [WARN] NO añadimos -ffast-math ni -O3 aquí: -O3 puede reordenar divisiones y
# el divisor cero ni siquiera se materializa, ruining las demos de SIGFPE.
OPT     ?= -O0

BUILD   := build
BIN     := $(BUILD)/bin
LIB     := $(BUILD)/lib

SYS_SRC := aegis_sys/src/trap_handler.c aegis_sys/src/mman_utils.c \
           aegis_sys/src/addrspace.c aegis_sys/src/capdisasm.c
ASM_SRC := aegis_sys/src/trampolines.S
INC     := -Iaegis_sys/include

SYS_LIB := $(LIB)/libaegis_sys.so
CORE_LIB:= $(LIB)/libaegis_core.so

# [BUG-CRITICO] La .so se enlaza con una lista EXPLÍCITA de objetos, no con
# `$(BUILD)/obj/*.o`. El glob tenía dos fallos encadenados:
#   1) Si un .c de SYS_SRC no estuviera en el target `sys`, el glob lo
#      enmascaraba: la .so|linkaba sin él y el fallo solo aparecía en
#      EJECUCIÓN ("symbol lookup error: undefined symbol: aegis_maps_init").
#   2) Al revés, un .o HUÉRFANO de una versión anterior se enlazaba para
#      siempre, así que un bug añadido y luego "arreglado" en el .c podía
#      seguir presente en los binarios. Lo nº1 era el caso real: faltaba
#      addrspace.c (aegis_maps_init) y `make` nunca lo_velocityó.
SYS_OBJ := $(BUILD)/obj/trap_handler.o $(BUILD)/obj/mman_utils.o \
           $(BUILD)/obj/addrspace.o    $(BUILD)/obj/capdisasm.o \
           $(BUILD)/obj/trampolines.o

# [WHY] --no-undefined: por defecto, `ld -shared` ACEPTA referencias sin
# resolver y las aplaza al momento de cargar. Ese es exactamente el modo de
# fallo que acabamos de tener: un .so "correcto" según el enlazador que
# revienta en cada proceso que lo preloadea. Con este flag, un símbolo
# faltante rompe el BUILD, que es donde puede verse.
LDFLAGS_SYS := -shared -Wl,--no-undefined

# Demos: nombres autoexplicativos del fallo que provocan.
# `DEMO_BIN` se deriva del wildcard de tests/demos/*.c, así que añadir una demo
# no requiere tocar nada aquí: basta con dejar el .c en el directorio.
DEMO_SRC:= $(wildcard tests/demos/*.c)
DEMO_BIN:= $(patsubst tests/demos/%.c,$(BIN)/%,$(DEMO_SRC))

.PHONY: all core sys demos test demo cli clean help
.DEFAULT_GOAL := all

# -----------------------------------------------------------------------------
# all: las dos .so (lo mínimo para LD_PRELOAD)
# -----------------------------------------------------------------------------
all: core sys

core:
	@mkdir -p $(LIB)
	$(RUSTC) build --release --manifest-path aegis_core/Cargo.toml
	cp aegis_core/target/release/libaegis_core.so $(CORE_LIB)

sys: core
	@mkdir -p $(LIB) $(BUILD)/obj
	$(CC) $(CSTD) $(CFLAGS) $(INC) -c aegis_sys/src/trap_handler.c \
		-o $(BUILD)/obj/trap_handler.o
	$(CC) $(CSTD) $(CFLAGS) $(INC) -c aegis_sys/src/mman_utils.c \
		-o $(BUILD)/obj/mman_utils.o
	$(CC) $(CSTD) $(CFLAGS) $(INC) -c aegis_sys/src/addrspace.c \
		-o $(BUILD)/obj/addrspace.o
	$(CC) $(CSTD) $(CFLAGS) $(INC) $(shell pkg-config --cflags capstone 2>/dev/null) -c aegis_sys/src/capdisasm.c \
		-o $(BUILD)/obj/capdisasm.o
	$(CC) $(ASFLAGS) -c aegis_sys/src/trampolines.S \
		-o $(BUILD)/obj/trampolines.o
	# [BUG-GUARDADO] `-lcapstone` estaba aquí. Como `aegis_capstone_init()` no lo
	# llama nadie, eso mapeaba libcapstone.so.5 (7.4 MB) y pagaba ~1.4 ms de
	# ARRANQUE en cada proceso preloadeado, por un componente que no se usa.
	# Medido: ver `scripts/bench_overhead.sh`. Capstone se carga ahora con
	# dlopen() perezosamente desde capdisasm.c, la primera vez que se use.
	$(CC) $(LDFLAGS_SYS) -o $(SYS_LIB) $(SYS_OBJ) -ldl
	@echo "→ $(SYS_LIB)"

# -----------------------------------------------------------------------------
# demos: binarios que fallan a propósito
#
# [WHY] $(OPT)=-O0 por defecto. A -O2 el compilador puede constante-propagar
# 100/0 y emitir un UD2 o un `div` con inmediato, cambiando el escenario.
#
# [BUG-GUARDADO] Esa regla tiene una EXCEPCIÓN: `divmem` debe compilarse a
# -O1, no a -O0. A -O0 GCC copia la variable del stack a un registro y emite
# `idiv %rcx` — o sea, el caso de REGISTRO, idéntico a `divzero`, y la demo
# no probaría lo que dice probar. A -O1 emite `idivq 0x8(%rsp)`, que es el
# divisor EN MEMORIA: el caso real que motiva la cura. Una demo que no ejercita
# su propio escenario es peor que no tenerla, porque da cobertura verde de algo
# que nadie midió. El nivel de optimización por demo se declara aquí, no se
# escribe "a ojo" en el recipe, para que cambiar OPT global no la rompa en
# silencio.
#
# Verificado con objdump sobre el binario construido, no asumido:
#   -O0 → 117c: idiv  %rcx        (registro: NO es lo que queremos)
#   -O1 → 1174: idivq 0x8(%rsp)   (memoria: sí lo es)
# -----------------------------------------------------------------------------
DIVER_OPT := -O0
DIVEROPT_divmem := -O1

demos: $(DEMO_BIN)

$(BIN)/%: tests/demos/%.c
	@mkdir -p $(BIN)
	$(CC) $(or $(DIVEROPT_$*),$(DIVER_OPT)) -g $(CSTD) -Wall -Wextra -o $@ $<

demo: all demos
	@./scripts/run_demos.sh

# -----------------------------------------------------------------------------
# test: unitarios de Rust + integración real end-to-end
#
# [BUG] Declaraba solo `core` como dependencia, pero run_demos.sh necesita las
# TRES cosas: las dos .so (para LD_PRELOAD) y los binarios de demo. Con
# `make test` sobre un árbol recién clonado fallaba con "Falta
# build/bin/divzero" en lugar de construirlas. Depender de `all demos` hace
# que el objetivo sea autosuficiente: nunca más depende del orden ni de un
# `make demos` previo que nadie recuerda.
# -----------------------------------------------------------------------------
test: all demos
	$(RUSTC) test --manifest-path aegis_core/Cargo.toml
	./scripts/run_demos.sh

# -----------------------------------------------------------------------------
# cli: la herramienta de producción (aegis_injector/, Nim).
#
# [BUG-GUARDADO] Este target NO estaba, y `build/bin/aegis` era un binario que
# aparecía por casualidad cuando alguien compilaba el .nim a mano. Peor: el
# target `demos` es un patrón `$(BIN)/%: tests/demos/%.c`, así que el binario de
# la CLI y el de las demos comparten el directorio sin declararse. Si `make test`
# hubiera arrastrado el CLI, no se sabría qué versión se validó.
#
# [NOTE] `make test` NO depende de `cli` a propósito: los tests validan el motor
# (Rust + C), que es lo que se despliega en producción. La CLI es una capa de
# orquestación encima, con su propia comprobación (`make cli && build/bin/aegis
# --help`). Couplarlas haría que un error de compilación de Nim —una herramienta
# opcional— pudiera tumbar la validación del motor, que es la que importa.
# -----------------------------------------------------------------------------
NIM       ?= nim
AEGIS_CLI := $(BIN)/aegis

cli: all
	@mkdir -p $(BIN)
	$(NIM) c -d:release --hints:off -o:$(AEGIS_CLI) aegis_injector/aegis_injector.nim
	@echo "→ $(AEGIS_CLI)"

clean:
	rm -rf $(BUILD)
	$(RUSTC) clean --manifest-path aegis_core/Cargo.toml

help:
	@echo "make           → core + sys (las .so)"
	@echo "make test      → unitarios Rust + demos end-to-end"
	@echo "make demo      → solo la demo end-to-end"
	@echo "make cli       → compila la CLI en Nim (build/bin/aegis)"
	@echo "make clean     → limpia build/"