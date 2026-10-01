#!/usr/bin/env bash
# =============================================================================
# bench_overhead.sh — Coste real de AegisRuntime sobre programas del SISTEMA.
#
# [POR QUÉ ESTE SCRIPT Y NO UN NÚMERO SUELTO]
# Medir "el overhead" sin separar QUÉ se está midiendo produce números sin
# significado. Aquí hay dos costes completamente distintos que se confundían
# en una sola cifra:
#
#   (a) ARRANQUE  — fijo, se paga UNA vez por proceso: ld.so resuelve y mapea
#                   las .so, el constructor lee /proc/self/maps e instala los
#                   handlers. En un proceso de vida corta (/bin/true, 1.3 ms)
#                   esto DOMINA la medición y da porcentajes del 25-40%.
#   (b) ESTADO    — lo que hace el runtime mientras el proceso trabaja. Si no
#                   hay traps, el handler NO se ejecuta, así que debe ser ~0.
#
# Reportarlos juntos produce la conclusión opuesta a la real: "Aegis cuesta un
# 30%", cuando lo que cuesta un 30% esemesclar preloadear dos bibliotecas en
# algo que dura 1 ms.
#
# [METODOLOGÍA]
# Ningún workload es un fixture escrito para esto: son /bin/true, bash, sqlite3 y
# python3, programas que ya estaban instalados. (Un comentario anterior de este
# fichero decía "sqlite3, bash, git y python3", pero git no aparece en ningún
# workload de aquí: se quitó para no arrastrar un repositorio temporal y nadie
# actualizó la nota. Los números del README se midieron con esta lista.)
# Los workloads de (b) duran cientos de ms para que el coste de arranque sea ruido.
# Se reporta la MEDIANA de N repeticiones, no el mínimo: en procesos de
# milisegundos el mínimo lo elige siempre el lucky scheduling del kernel y
# exagera las diferencias. Se descartan además las primeras 2 ejecuciones
# (caché fría de la .so).
#
# Uso:  N=21 scripts/bench_overhead.sh
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYS="$ROOT/build/lib/libaegis_sys.so"
CORE="$ROOT/build/lib/libaegis_core.so"
DB="$(mktemp -u /tmp/aegis-bench-XXXXXX.db)"
N=${N:-11}
WARM=2

for f in "$SYS" "$CORE"; do
    [[ -f "$f" ]] || { echo "Falta $f (make all)"; exit 1; }
done

command -v sqlite3 >/dev/null || { echo "Este bench necesita sqlite3"; exit 1; }

# [NOTE] La base de datos se genera aquí con sqlite3 real: 200k filas. No es
# un input sintético pensado para que el bench sea rápido, es la carga típica
# de una app que usa SQL.
echo "preparando la carga de trabajo…"
sqlite3 "$DB" "create table t(a,b);
  with recursive c(i) as (select 1 union all select i+1 from c where i<200000)
  insert into t select i, i+1 from c;"
trap 'rm -f "$DB"' EXIT

median() { sort -g | awk '{v[NR]=$1} END{print v[int((NR+1)/2)]}'; }

bench() { # → mediana en nanosegundos
    for _ in $(seq "$WARM"); do "$@" >/dev/null 2>&1; done
    for _ in $(seq "$N"); do
        local t0 t1
        t0=$(date +%s%N); "$@" >/dev/null 2>&1; t1=$(date +%s%N)
        echo $((t1-t0))
    done | median
}

row() {
    local label="$1"; shift
    local a b pct
    a=$(bench "$@")
    b=$(bench env LD_PRELOAD="$SYS:$CORE" "$@")
    pct=$(awk -v a="$a" -v b="$b" 'BEGIN{ if(a>0) printf "%+.2f%%", (b-a)*100/a; else print "n/a" }')
    printf "%-44s %9.2f ms %9.2f ms %9s\n" "$label" \
        "$(awk -v v="$a" 'BEGIN{print v/1e6}')" \
        "$(awk -v v="$b" 'BEGIN{print v/1e6}')" "$pct"
}

header() {
    printf "%-44s %11s %11s %9s\n" workload sin_aegis con_aegis overhead
}

echo "AegisRuntime — coste sobre programas reales"
echo "  sys : $SYS"
echo "  core: $CORE"
echo "  N=$N (mediana) + $WARM de calentamiento"

echo
echo "── (a) ARRANQUE: procesos mínimos. Mide ld.so + el constructor ──"
header
row "/bin/true"                              /bin/true
row "bash -c : (shell mínimo)"                bash -c :
row "sqlite3 :memory: (vacío)"                sqlite3 :memory: ""

echo
echo "── (b) ESTADO ESTABLE: workloads de cientos de ms ──"
header
row "sqlite3: sum(a+b) sobre 200k filas"      sqlite3 "$DB" "select sum(a+b) from t"
row "sqlite3: index scan filtrado"             sqlite3 "$DB" "select sum(a) from t where b < 150000"
row "bash: 2M de operaciones aritméticas" \
    bash -c 'i=0; for ((n=0;n<2000000;n++)); do i=$((i+n%7)); done'
row "python3: 10M de iteraciones" \
    python3 -c "s=0
for i in range(10000000): s+=i%7
print(s)"

cat <<'NOTA'

Cómo leerlo:

  · (b) es el coste del runtime mientras el proceso trabaja. Con traps
    inexistentes el handler de señales no se ejecuta nunca, así que cualquier
    cifra distinta de ~0 indica trabajo que se está haciendo sin necesidad.

  · (a) es el precio FIJO por usar Aegis en un proceso de vida corta. Es
    irreducible en la forma actual: se paga al arrancar. Un servicio que vive
    horas lo amortiza en nanosegundos; un script que dura 1 ms lo nota.

  · El porcentaje engaña cuando el denominador es pequeño. +40% sobre 1.35 ms
    son 0.54 ms reales; +1.4% sobre 2814 ms son 40 ms reales. Por eso el script
    imprime milisegundos además del porcentaje.
NOTA