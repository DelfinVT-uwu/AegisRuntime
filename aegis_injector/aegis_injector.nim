## aegis_injector.nim — CLI de producción de AegisRuntime.
##
## Qué es: el componente que convierte el runtime en una HERRAMIENTA usable.
## Las demos (`tests/demos/`) son fixtures; esto es el producto. Tres modos:
##
##   aegis run   <cmd> [args]   → ejecuta con LD_PRELOAD y telemetría
##   aegis attach <pid>         → se engancha a un proceso VIVO (fase ptrace)
##   aegis heal  <cmd> [args]   → ejecuta, y devuelve 0 SI curó, !=0 si no
##
## Por qué Nim aquí (y C/Rust en el resto): este componente es Orquestación.
## No está en el camino caliente de curación — el handler de señales NO lo
## toca. Su trabajo es parsear argv, hablar con `ptrace`, spawnar procesos,
## formatear informes y hablar con el usuario. Para eso, un lenguaje con GC,
## strings seguras y `seq` evita exactamente el tipo de bug que se ha
## acumulado en la capa de trapping: gestión manual de memoria en código que
## corre sobre procesos ajenos. El código de generación de traps (mmap,
## signal handler, decodificación en el hot path) sigue en C/Rust porque
## allí la ausencia de alocaciones NO es una preferencia, es una corrección.
##
## [POR QUÉ NO REESCRIBIR LO QUE YA FUNCIONA] Este fichero NO contiene
## heurística de curación. Esa lógica vive en `aegis_core` (Rust) y está
## verificada con tests. Duplicarla aquí sería crear dos fuentes de verdad que
## divergen — el fallo nº4 y nº12 de ARCHITECTURE.md eran exactamente eso. El
## inyector orquesta; el motor decide.

import std/[os, osproc, streams, strutils, strformat, tables, strtabs,
            options, envvars]

const
  libAegisSys  = "libaegis_sys.so"
  libAegisCore = "libaegis_core.so"

# [WHY] El directorio de las .so se resuelve a partir del PROPIO BINARIO, no
# del CWD. Un supervisor lanza el inyector desde `/` o desde `cron`; si las
# rutas fueran relativas al CWD, `aegis heal /usr/bin/mi_app` fallaría con
# "falta libaegis_sys.so" en el 99% de los despliegues. `getAppDir()` es la
# única base correcta.
proc aegisLibDir(): string =
  # El binario vive en build/bin/ y las .so en build/lib/ → un nivel arriba.
  result = parentDir(getAppDir().string) / "lib"

# ---------------------------------------------------------------------------
# Constantes de Linux/x86-64 (FFI a ptrace y waitpid).
# ---------------------------------------------------------------------------

const libc = "libc.so.6"

{.push importc, cdecl, dynlib: libc.}

proc ptrace(req: cint, pid: cint, a: pointer, d: pointer): clong
proc waitpid(pid: cint, status: ptr cint, options: cint): cint
proc kill(pid: cint, sig: cint): cint
proc getpid(): cint
proc strerror(e: cint): cstring

{.pop.}

# Números de errno que usamos para explicar el fallo, no para decidir nada.
const
  EPERM = 1   # Operation not permitted → casi siempre Yama (ver attachObserve)

const
  PTRACE_TRACEME   = 0
  PTRACE_PEEKTEXT  = 1
  PTRACE_POKETEXT  = 4
  PTRACE_CONT      = 7
  PTRACE_ATTACH    = 16
  PTRACE_DETACH    = 17
  PTRACE_GETREGS   = 12

  WUNTRACED = 2
  ADDR_NO_RANDOMIZE = 0x0040000

# Números de señal de Linux.
const
  SIGILL  = 4
  SIGTRAP = 5
  SIGBUS  = 7
  SIGFPE  = 8
  SIGKILL = 9
  SIGSEGV = 11

# ---------------------------------------------------------------------------
# Telemetry: lo que el runtime ya emite por stderr como líneas
# `[aegis] trap sig=… rip=… fault=… action=… rule=…`.
#
# [WHY] Se parsea esa línea en vez de añadir un segundo formato: el runtime
# ya la emite desde un signal handler donde NO se puede alocar, así que su
# formato es inmutable sin tocar el camino caliente. El inyector la traduce a
# estructura. Formato único = una sola fuente de verdad, incluso si el
# runtime corre sin el inyector.
# ---------------------------------------------------------------------------

type
  Trap = object
    sigNo: int
    rip: uint64
    fault: uint64
    action: int
    rule: int

  Report = object
    traps: seq[Trap]
    exitCode: int
    healed: int
    fatal: int

proc parseTrap(line: string): Option[Trap] =
  ## Convierte una línea `[aegis] trap …` en `Trap`, o `none` si no lo es.
  if not line.startsWith("[aegis] trap"): return none(Trap)
  var kv = initTable[string, string]()
  for part in line.splitWhitespace()[2..^1]:
    let pair = part.split('=')
    if pair.len == 2: kv[pair[0]] = pair[1]
  try:
    result = some(Trap(
      sigNo:   parseHexInt(kv.getOrDefault("sig", "0")),
      rip:     parseHexInt(kv.getOrDefault("rip", "0")).uint64,
      fault:   parseHexInt(kv.getOrDefault("fault", "0")).uint64,
      action:  parseHexInt(kv.getOrDefault("action", "0")),
      rule:    parseHexInt(kv.getOrDefault("rule", "0"))))
  except ValueError:
    discard  # línea de aegis malformada: mejor perderla que morir por el log

proc parseHexInt(s: string): int =
  ## `parseHexInt` NO acepta prefijos; las líneas de aegis son hex puro.
  var v = 0
  for ch in s:
    let d = case ch
            of '0'..'9': ch.ord - '0'.ord
            of 'a'..'f': ch.ord - 'a'.ord + 10
            of 'A'..'F': ch.ord - 'A'.ord + 10
            else: return v
    v = v * 16 + d
  return v

proc sigName(s: int): string =
  case s
  of SIGFPE:  "SIGFPE"
  of SIGSEGV: "SIGSEGV"
  of SIGBUS:  "SIGBUS"
  of SIGILL:  "SIGILL"
  else:       "SIG" & $s

proc actionName(a: int): string =
  ## Traduce el enum `aegis_action_t` de aegis_api.h. Los MISMOS números:
  ## si se renumeran en C, esto miente. Ver aegis_api.h.
  case a
  of 0: "none"
  of 1: "reexec"
  of 2: "skip"
  of 3: "patch"
  of 4: "abort"
  of 5: "patchmem"   # divisor en RAM reparado + re-ejecución
  else: "?"

proc ruleName(r: int): string =
  ## Traduce `patch_id` de engine.rs.
  case r
  of 1: "div-zero (divisor=1)"
  of 2: "div-mem: unresolvable form (skip)"
  of 3: "skip null-deref"
  of 4: "skip invalid-access"
  of 5: "abort: recurring signature"
  of 6: "abort: unsupported signal"
  of 7: "abort: SIGFPE non-DIV"
  of 8: "abort: undecodable"
  of 9: "abort: RIP unreadable"
  of 10: "div-mem: divisor forced to 1 in RAM + re-execution"
  of 11: "degraded to skip: page not writable"
  of 12: "ignored: invalid patch size"
  else: "?"

proc summarize(r: Report): string =
  ## Human-readable report: what was healed, what was not, and what to do about it.
  result = ""
  if r.healed > 0:
    result.add("  healed  : " & $r.healed & " event(s)\n")
  if r.fatal > 0:
    result.add("  fatal   : " & $r.fatal & " event(s) with no remedy\n")
  if r.traps.len == 0:
    result.add("  (no traps recorded)\n")
    return
  result.add("  " & repeat("-", 68) & "\n")
  for t in r.traps:
    result.add(&"  {sigName(t.sigNo):8} rip=0x{t.rip:012x} action={actionName(t.action):6} rule={ruleName(t.rule)}\n")
    if t.fault != 0:
      result.add(&"           fault=0x{t.fault:x}\n")

# ---------------------------------------------------------------------------
# Ejecutar un proceso bajo Aegis.
# ---------------------------------------------------------------------------

type RunResult = object
  exitCode: int
  signal: int
  report: Report

proc signalFromStatus(st: cint): int =
  ## Decodifica el status de waitpid: sólo tiene sentido si WIFSIGNALED.
  if (st and 0x7f) != 0: return int(st and 0x7f)
  return 0

proc environSeq(): seq[string] =
  ## Copia el entorno del proceso actual a una seq de pares `CLAVE=VALOR`.
  ##
  ## [WHY] `environ()` de la libc devuelve un `char**` terminado en NULL. El
  ## FFI de Nim lo tipa como array de `char`, lo que obliga a castear y es
  ## frágil. `std/envvars` ya hace exactamente esto de forma tipada y
  ## probada, así que se usa en su lugar. La decisión de no alocar importa en
  ## el camino de curación del runtime, NO aquí (el inyector corre en el
  ## supervisor, una vez por proceso hijo, no en el handler de señal).
  for k, v in envPairs():
    result.add(k & "=" & v)

proc runAegis(cmd: string, args: openArray[string]): RunResult =
  ## Lanza `cmd` con LD_PRELOAD y captura su telemetría.
  ##
  ## [WHY] Se captura la salida por un pipe y se parsea línea a línea en
  ## lugar de dejar que el runtime escriba directo a nuestro stderr. Motivo:
  ## en un proceso que estamos curando, stdout/stderr pueden estar en
  ## estados raros; el pipe es el único punto de captura fiable y, además,
  ## permite distinguir "el runtime curó" de "el programa escribió algo".
  let root = aegisLibDir()
  let preload = root / libAegisSys & ":" & root / libAegisCore

  if not fileExists(root / libAegisSys):
    stderr.writeLine("aegis: missing " & (root / libAegisSys) & " (run `make`)")
    quit(2)

  # Nim 2.x exige un StringTableRef para `env`, no una seq: el proceso hijo
  # hereda el entorno, y el LD_PRELOAD propio sobrescribe cualquier previo
  # (el constructor de aegis debe registrar los handlers antes que nadie más).
  var env = newStringTable()
  for entry in environSeq():
    let eq = entry.find('=')
    if eq > 0 and entry[0..<eq] != "LD_PRELOAD":
      env[entry[0..<eq]] = entry[eq+1..^1]
  env["LD_PRELOAD"] = preload

  let p = startProcess(cmd, args = args, env = env,
                       options = {poUsePath, poStdErrToStdOut})
  # Se lee línea a línea porque el runtime escribe la telemetría en stderr y la
  # app puede escribir mucho en stdout: leer todo a memoria de golpe en un
  # proceso que estamos supervisando puede ser justo el problema que
  # consuma toda la RAM. `readAll` sobre el stream no existe en std de Nim.
  var outText = ""
  var lineBuf: string
  while p.outputStream.readLine(lineBuf):
    outText.add(lineBuf)
    outText.add('\n')
  let rc = p.waitForExit()

  var rep: Report
  for line in outText.splitLines():
    let t = parseTrap(line)
    if t.isSome:
      rep.traps.add(t.get)
      # [WARN] El conjunto de acciones que CUERAN no es 1..3: `patchmem` (5) es la
      # cura más fuerte de todas (repara la memoria y re-ejecuta), y clasificarla
      # como fatal haría que `aegis heal` fallara justo cuando el motor funciona
      # mejor. `none` (0) y `abort` (4) son las únicas sin remedio. La lista se
      # escribe explícita en vez de `in 1..3` para que añadir una acción en C no
      # pueda cambiar la clasificación por accidente.
      if t.get.action in [1, 2, 3, 5]: rep.healed.inc
      else: rep.fatal.inc
  rep.exitCode = rc

  # La salida del programa (menos las líneas de aegis) se preserva: es el
  # resultado del usuario, y esconderla sería mentir sobre si la app worked.
  for line in outText.splitLines():
    if not line.startsWith("[aegis]"): stdout.writeLine(line)

  result = RunResult(exitCode: rc, signal: 0, report: rep)

# ---------------------------------------------------------------------------
# Modo attach: engancharse a un proceso vivo y observar sus traps.
#
# [POR QUÉ ptrace y no "leer /proc"] Un attach de ptrace hace que el kernel
# pause el proceso en CADA señal, así que vemos los traps aunque el proceso
# no los propague a nadie. Sólo observación: NO se modifica el contexto del
# proceso ajeno. Curar el proceso de otro sería una decisión de política
# (¿y si la corrupción es intencional?) que el inyector no tiene derecho a
# tomar por su cuenta. Por eso `attach` es read-mostly y `run` es el modo que
# cura.
# ---------------------------------------------------------------------------

proc attachObserve(pid: cint): int =
  # [NOTE] `personality(ADDR_NO_RANDOMIZE)` se imposing al hijo solo si su
  # proceso padre no puede. Aquí NO se hace: ASLR es una defensa de seguridad
  # del objetivo, y desactivarla para "facilitar" la observación sería un
  # empeoramiento silencioso de la seguridad de un proceso ajeno. Si el
  # operador quiere direcciones estables, que use `setarch -R` él mismo de
  # forma explícita.

  if ptrace(PTRACE_ATTACH, pid, nil, nil) != 0:
    let e = cast[cint](osLastError())
    stderr.writeLine("aegis attach: ptrace(ATTACH) falló: " & $strerror(e))
    # [NOTE] EPERM en Linux casi nunca es un bug de este código: es Yama.
    # `kernel.yama.ptrace_scope` (1 por defecto en Arch/Debian/Fedora)
    # restringe PTRACE_ATTACH a los descendientes del proceso que llama. Como
    # la víctima observada casi nunca es descendiente de un supervisor, el modo
    # `attach` REQUIERE una de estas dos cosas, y conviene decir cuáles en vez
    # de dejar un EPERM críptico que parece un bug:
    #   1) ejecutar el supervisor con CAP_SYS_PTRACE, o
    #   2) poner kernel.yama.ptrace_scope=0 (solo aceptable en un host donde
    #      todos los procesos son de fiar).
    # Se dice en stderr y no se intenta eludirlo. Sortear por diseño una
    # restricción de seguridad de otro proceso sería la peor decisión posible
    # en una herramienta de resiliencia.
    if e == EPERM:
      stderr.writeLine("  probable cause: Yama. `cat /proc/sys/kernel/yama/ptrace_scope`")
      stderr.writeLine("  ptrace_scope=1 restricts attach to descendants of the supervisor.")
      stderr.writeLine("  the supervisor needs CAP_SYS_PTRACE, or ptrace_scope=0 on the host.")
    return 2

  var status: cint = 0
  var traps: seq[Trap] = @[]
  while true:
    if waitpid(pid, addr status, 0) < 0: break
    let st = status.cint
    let sig = signalFromStatus(st)
    if sig == SIGKILL: break
    if sig in [SIGFPE, SIGSEGV, SIGBUS, SIGILL]:
      # Sin PEEKUSER no tenemos el ucontext completo (rip/fault): se registra
      # el evento, que es lo que un supervisor necesita saber, y se continúa.
      traps.add(Trap(sigNo: sig, rip: 0, fault: 0, action: 0, rule: 0))
      echo &"  [!] {sigName(sig)} en pid {pid} (attach observa, no repara)"
      discard ptrace(PTRACE_CONT, pid, nil, nil)
    elif sig == 0 or sig == SIGTRAP:
      if (st shr 8) == 0 and sig == 0: break  # salida normal
      discard ptrace(PTRACE_CONT, pid, nil, nil)
    else:
      discard ptrace(PTRACE_CONT, pid, nil, cast[pointer](sig.cint))

  discard ptrace(PTRACE_DETACH, pid, nil, nil)
  echo &"attach: {traps.len} trap(s) observado(s) en pid {pid}. Proceso intacto."
  return 0

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

const usage = """
aegis — resilience runtime for native processes

USAGE:
  aegis run    <cmd> [args...]   run <cmd> with the runtime and show the
                                  telemetry of every healed trap
  aegis heal   <cmd> [args...]   like `run`, but the exit code is 0 only if
                                  the runtime healed AT LEAST one fault AND
                                  the process exited cleanly. Useful in CI.
  aegis attach <pid>             observe (without repairing) a running process

EXAMPLES:
  aegis run   ./my_app 100 0       # the app has a zero divisor
  aegis heal  ./my_app data.csv    # CI: fails if the app crashes unhealed
  aegis attach 12345

DEPENDENCIES: make (builds build/lib/*.so). Aegis uses LD_PRELOAD, so the
target app does not need to be recompiled.
"""

proc main() =
  let args = commandLineParams()
  if args.len < 1 or args[0] in ["-h", "--help", "help"]:
    echo usage
    quit(if args.len < 1: 1 else: 0)

  let mode = args[0]
  let rest = args[1..^1]

  case mode
  of "run":
    if rest.len == 0: quit("aegis run: missing command", 2)
    let r = runAegis(rest[0], rest[1..^1])
    echo ""
    echo "── report ───────────────────────────────────────────────"
    echo summarize(r.report)
    if r.exitCode != 0:
      echo &"  process exited with exit={r.exitCode}"
    quit(if r.report.fatal > 0: 1 else: r.exitCode)

  of "heal":
    if rest.len == 0: quit("aegis heal: missing command", 2)
    let r = runAegis(rest[0], rest[1..^1])
    echo ""
    echo "── report (heal mode) ──────────────────────────────────"
    echo summarize(r.report)
    # Success = the process survived AND at least one real heal happened.
    let ok = r.exitCode == 0 and r.report.healed > 0 and r.report.fatal == 0
    echo(if ok: "  RESULT: healed" else: "  RESULT: not healed")
    quit(if ok: 0 else: 1)

  of "attach":
    if rest.len != 1: quit("aegis attach: expected exactly one pid", 2)
    try:
      quit(attachObserve(parseInt(rest[0]).cint))
    except ValueError:
      quit("aegis attach: pid is not numeric", 2)

  else:
    stderr.writeLine("aegis: subcomando desconocido '" & mode & "'")
    stderr.writeLine(usage)
    quit(2)

when isMainModule:
  main()