#!/usr/bin/env bash
# =============================================================================
# run_demos.sh — Verificación end-to-end de AegisRuntime.
#
# Demuestra el bucle completo sobre procesos REALES: cada demo se ejecuta dos
# veces —sin el runtime (control, debe morir) y con él (debe sobrevivir)— y el
# script compara. Comparar es lo que da valor: un "OK" sin el control
# contrario no demuestra que el motor hizo nada.
#
# [WHY] Cada salida se acota a N líneas. Una demo que entra en bucle de
# parcheo produciría cientos de líneas y llenaría el terminal; el corte es
# también una detección de fallo (si se activa el `timeout`, no hay curación
# efectiva).
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/build/bin"
SYS="$ROOT/build/lib/libaegis_sys.so"
CORE="$ROOT/build/lib/libaegis_core.so"
MAX_LINES=6
TIMEOUT=15

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'

# [BUG-GUARDADO] Solo comprobaba `divzero`. Si faltaba cualquiera de las otras
# demos, el script las daba por buenas sin haberlas ejecutado nunca: un "4/4
# demos curadas" habría sido mentira. Ahora se verifica que estén las cuatro.
for required in divzero divmem null_deref idiv_overflow page_edge; do
    [[ -x "$BIN/$required" ]] || { echo "Falta $BIN/$required (make demos)"; exit 1; }
done
[[ -f "$SYS" ]] || { echo "Falta $SYS (make sys)"; exit 1; }
[[ -f "$CORE" ]] || { echo "Falta $CORE (make core)"; exit 1; }

pass=0; fail=0

run() { timeout "$TIMEOUT" "$@" 2>&1; }

# -----------------------------------------------------------------------------
# check <nombre> <binario> <código_muerte_esperado_sin_aegis>
#
# Contrato: sin aegis el proceso muere por la señal (código >= 128), con aegis
# termina con 0. Si alguno de los dos lados no se cumple, la demo FALLA.
# -----------------------------------------------------------------------------
check() {
    local name="$1" bin="$2" expect_death="$3"

    echo
    echo "── $name ─────────────────────────────────────────"

    local ctl rc_ctl
    ctl="$(run "$bin")"; rc_ctl=$?
    echo "${DIM}sin aegis:${RST} exit=$rc_ctl"
    (( rc_ctl >= 128 )) \
        && echo "${DIM}  $(echo "$ctl" | head -2)${RST}"

    # El control DEBE morir: si sobrevive, la demo no reproduce el fallo que
    # dice reproducir y el resultado de aegis no significaría nada.
    if (( rc_ctl < expect_death )); then
        echo "${RED}✗ el control NO murió (exit=$rc_ctl): la demo no provoca el fallo${RST}"
        (( fail++ )); return
    fi

    local aeg rc_aeg
    aeg="$(run env LD_PRELOAD="$SYS:$CORE" "$bin")"; rc_aeg=$?

    # [BUG-GUARDADO] Vivir NO es curar. Un `skip` deja el proceso en pie con el
    # acumulador sin calcular, así que un exit=0 sin más pruebas es exactamente
    # el falso positivo que este runtime podría vender. Aquí se compara el
    # código de la regla de curación en la telemetría con el valor esperado.
    local expect_rule="${4:-}"
    if [[ -n "$expect_rule" ]]; then
        if grep -q "rule=$expect_rule" <<<"$aeg"; then
            echo "${GRN}✓ con aegis: exit=0 (proceso curado, rule=$expect_rule)${RST}"
            echo "$aeg" | head -"$MAX_LINES" | sed 's/^/  /'
            (( pass++ ))
        else
            echo "${RED}✗ con aegis: exit=0 pero la cura NO fue la esperada (rule=$expect_rule)${RST}"
            echo "$aeg" | head -"$MAX_LINES" | sed 's/^/  /'
            (( fail++ ))
        fi
        return
    fi

    if (( rc_aeg == 0 )); then
        echo "${GRN}✓ con aegis: exit=0 (proceso curado)${RST}"
        echo "$aeg" | head -"$MAX_LINES" | sed 's/^/  /'
        (( pass++ ))
    else
        echo "${RED}✗ con aegis: exit=$rc_aeg (el motor no pudo curar)${RST}"
        echo "$aeg" | head -"$MAX_LINES" | sed 's/^/  /'
        (( fail++ ))
    fi
}

echo "AegisRuntime — verificación end-to-end"
echo "  sys : $SYS"
echo "  core: $CORE"

check "div-zero: SIGFPE, DIV por cero"      "$BIN/divzero"    136
# El divisor en MEMORIA (`idivq -0x20(%rbp)`): el caso que GCC emite de verdad
# al compilar código con spilling, y que hasta ahora solo se "curaba" saltando
# la instrucción. Se verifica además el VALOR impreso, no solo que el proceso
# sobreviva: un skip habría producido un cociente distinto.
# El `rule` se compara en HEX porque la telemetría se emite en hex (append_hex
# en trap_handler.c, por async-signal-safety). patch_id 10 = "divisor forzado a
# 1 en RAM" se escribe "a". La comprobación existe para distinguir una cura
# REAL de un skip que deja el proceso vivo con basura: ambos darían exit=0.
check "div-mem: SIGFPE, divisor spilled en RAM" "$BIN/divmem" 136 a
check "null-deref: SIGSEGV, escritura a NULL" "$BIN/null_deref" 139
# Overflow de cociente: comprueba que la cura del divisor NO se aplica por
# extensión automática. Antes esta demo moría por el antibucles (regla 5).
check "idiv-overflow: SIGFPE, cociente que no cabe" "$BIN/idiv_overflow" 136
# DIV pegado al final de su página, con guard page detrás. Regresión del
# doble fallo en el handler: la lectura de código tenía que ser segura.
check "page-edge: SIGFPE al borde de página"  "$BIN/page_edge"   136

echo
echo "════════════════════════════════════════════"
if (( fail == 0 )); then
    echo "${GRN}${pass}/${pass} demos curadas${RST}"
else
    echo "${YEL}$pass curadas, $fail fallidas${RST}"
fi
echo "════════════════════════════════════════════"
exit $(( fail > 0 ))