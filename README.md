# AegisRuntime

**A resilience runtime that heals CPU faults in real processes, without recompiling them.**

When a program receives a `SIGFPE` (division by zero) or a `SIGSEGV` (invalid memory
access), the kernel normally kills it and that's that: core dump, lost data, downtime.
AegisRuntime is injected into the process via `LD_PRELOAD`, intercepts the signal
**before** the kernel kills anything, diagnoses the cause, **repairs** it, and
resumes execution.

```console
$ ./build/bin/divmem; echo "exit=$?"
Floating point exception (core dumped)
exit=136                      # 128 + 8 = SIGFPE

$ ./build/bin/aegis run ./build/bin/divmem
resultado = 200

── report ───────────────────────────────────────────────
  healed  : 1 event(s)
  --------------------------------------------------------------------
  SIGFPE   rip=0x55cd11d3b174 action=patchmem rule=div-mem: divisor forced to 1 in RAM + re-execution
```

That is `tests/demos/divmem.c`, included in the repo: `200 / 0` where the divisor
lives in a `volatile` array, so it is compiled as a memory operand
(`idivq 0x8(%rdi)`) rather than a register. Without Aegis it dies with `rc=136`;
with Aegis it returns `200` (the divisor is repaired to 1, so the quotient is the
dividend). Try it yourself after `make demos`.

---

## What makes it different

| Tool | What it does on a fault |
|---|---|
| **Wireshark** (`epan/except.c`) | `siglongjmp`: **abandons** the faulting instruction |
| **DynamoRIO** (`dr_register_exception_event`) | **abandons** the faulting instruction |
| **AegisRuntime** | **repairs** the state and **re-executes** the instruction |

Existing tools keep the program *alive* by stepping over the error. Aegis does it by
**computing the correct result**: if you divide by zero, it rewrites the divisor and
gives you the real quotient. For `100 / 0` it returns `100` — not an invented zero
and not a silent skip.

---

## How it works

Each language lives where the danger is. The rule: **where there is logic there is
memory safety** (Rust), and **where the kernel calls you there is minimal C**.

| Layer | Language | Responsibility |
|---|---|---|
| `aegis_injector` | **Nim** | CLI: launches the process, collects telemetry. Decides no cures. |
| `aegis_sys` | **C23 + ASM** | Signal handler, `ucontext_t`, memory validation. What the kernel invokes. |
| `aegis_core` | **Rust `no_std`** | Decodes the instruction, decides the action, anti-loop signature. |

### The flow of a heal

```
CPU fault → kernel → sigaltstack → aegis_trap_handler (C23)
   │
   ├─ 1. Copy gregs[] (23×u64) + RIP + the instruction BYTES → frame_in
   ├─ 2. cached dlsym → aegis_analyze_and_heal(&in, &out)   [Rust]
   │        ├─ fastpath: decode the instruction at RIP (x86-64)
   │        ├─ engine:   decide the action (patch / skip / abort)
   │        ├─ signature: hash of (RIP, signal) → anti-loop counter
   │        └─ telemetry: lock-free ring buffer
   ├─ 3. C VALIDATES and APPLIES the mutations (never Rust directly)
   └─ 4. return → sigreturn → the instruction re-executes with repaired state
```

### The three design ideas

**1. The engine never touches memory. It neither dereferences nor reads it.**
C copies the legible prefix of the instruction (up to 15 bytes, or up to the end of
the page) and Rust decodes **on that copy**. So the decoding and decision logic —
`fastpath.rs`, `engine.rs`, `signature.rs` — contain **zero** `unsafe` and zero
pointer dereferences. The only `unsafe` in the crate is the FFI boundary itself
(converting the caller's raw pointers into references) and the tests, which is
exactly where a compiler should force you to state the contract.
Before this, the engine did `slice::from_raw_parts(rip, 15)` and would hang by
itself when RIP was unreadable — a signal handler deadlocking inside itself.

**2. Separating "compute the address" from "write to it".**
Rust returns a `MemWrite { addr, val, size }`: Rust **computes** the address, C
**validates** it (size ∈ {1,2,4,8}, writable page according to `/proc/self/maps`) and
**writes** exactly that size. Nobody dereferences on their own: if the address is not
resolvable, it degrades to `skip` rather than inventing one — **fail closed**.

**3. Zero duplicated decisions.**
The Nim injector does not reimplement the heuristic: there is a single source of truth
(the Rust engine). Adding a rule means touching one place, not three.

### The `PatchMem` cure: the divisor lives in RAM

This is the hard case and the most common one in software compiled at `-O2`. GCC
spills the operands to the stack, so the instruction that faults is something like
`idivq 0x8(%rsp)` — the divisor **is not in any register**, it is in memory.
There is no register to patch.

Aegis then:
1. Decodes the ModRM and SIB byte to resolve the divisor's **effective address**
   (`base + index×scale + disp`, RIP-relative, `rbp+disp8`, …).
2. Checks that the address is valid and writable.
3. Writes `1` at that memory location.
4. **Re-executes** the same instruction → the quotient comes out correct.

```console
$ objdump -d build/bin/divmem | grep -B2 idiv
    116e:	48 8b 04 24          	mov    (%rsp),%rax     # dividend: also spilled
    1172:	48 99                	cqto                   # sign-extend RAX -> RDX:RAX
    1174:	48 f7 7c 24 08       	idivq  0x8(%rsp)       # divisor: an ADDRESS, not a register
```

Note the operand: `0x8(%rsp)`. Both operands are in memory, and there is no
register anywhere to patch — that is exactly why a register-only cure is not
enough.

### Safety

- **Fail closed.** If anything doesn't add up, Aegis does not improvise: it returns
  `skip` or lets the process die. It never invents an address or a value.
- **Anti-loop.** If the same `(RIP, signal)` faults many times within 1 second, it
  aborts with a controlled core dump instead of patching in an infinite loop.
- **No `malloc` in the handler.** All memory (alt-stack, shadow page, code cave,
  telemetry ring) is reserved in the constructor with `mmap`, before the first trap.
- **Does not disable ASLR or evade Yama.** Those are the target process's own
  security decisions; toolkits that bypass them have nothing to teach here.

---

## Building

Requirements: **gcc/clang** (C23), **cargo**, **nim**, and optionally Capstone.

```bash
make all       # the two .so files (this is the product)
make demos     # test binaries, which fail ON PURPOSE
make cli       # the `aegis` binary (Nim)
make test      # test suite
```

The demos are kept out of `all` deliberately: they are programs that core-dump by
design, and it makes no sense for `make` to build them by default.

## Usage

```bash
# run a program under Aegis
./build/bin/aegis run ./my_program args...

# like `run`, but exits with an error (rc=1) if NO heal happened.
# useful in CI: "this test must raise SIGFPE and be healed".
./build/bin/aegis heal ./my_program

# attach to an already-running process and observe its traps (read-only)
./build/bin/aegis attach <pid>
```

It also works with plain `LD_PRELOAD`, **preloading both libraries** (the engine
heals nothing without the other — these are two libraries, not one):

```bash
LD_PRELOAD=build/lib/libaegis_sys.so:build/lib/libaegis_core.so ./my_program
```

---

## Verification

The design requirement was: **test against real system programs, not programs
invented to fail.** A program we wrote ourselves already knows where its `idiv` is, so
it proves nothing.

**Non-interference** — real system binaries, bit-for-bit identical output (SHA-256 of
the output with and without Aegis):

```
MATCH   df          MATCH   awk         MATCH   python3
MATCH   sort        MATCH   objdump     MATCH   readelf
MATCH   iconv       MATCH   nm          MATCH   file
MATCH   sqlite3     MATCH   sha256sum
```

**Real healing** — a program compiled at `-O2` (like production software), with the
divisor spilled onto the stack:

| | Without Aegis | With Aegis |
|---|---|---|
| Exit code | `136` (SIGFPE) | `0` |
| Result | process dead | `resultado = 200` |

And the numeric result is correct, not a fixed number: `200 / 0 → 200` (with the
divisor repaired to 1, the quotient is the dividend). This is the check that matters:
if the engine merely *skipped* the instruction, the process would also survive but
`resultado` would be garbage — healed in appearance, broken in reality.

**An honest negative result.** We tried to find natural faults by fuzzing against
real parsers — `djpeg`, `ffprobe`, `ImageMagick`, `objdump`, `readelf`, `xz`, `7z` —
using degraded system files. **0 crashes** in 3000 mutation rounds: 2025–26 binaries
are hardened against trivially malformed input.

This is reproducible — the harness is in the repo:

```bash
python3 scripts/fuzz_real_parsers.py 3000
```

It is documented because a negative result is information, and because the harness
having found nothing is itself the check that it worked. If it reports crashes on
your machine, that is real data about your versions of those binaries.

---

## Layout

```
├── Makefile
├── aegis_injector/aegis_injector.nim   # CLI (Nim): run / heal / attach
├── aegis_sys/                         # C23 + ASM: signal handler
│   ├── include/aegis_api.h            # FFI contract (+ layout asserts)
│   └── src/{trap_handler,addrspace,mman_utils,capdisasm}.c
├── aegis_core/src/*.rs                # Rust no_std: fastpath, engine, signature
├── tests/demos/*.c                    # binaries with intentional faults
├── scripts/run_demos.sh               # control vs. runtime, per demo
├── scripts/bench_overhead.sh          # startup + steady-state overhead
└── scripts/fuzz_real_parsers.py       # hunts natural faults in real parsers
```

`docs/ARCHITECTURE.md` has the full detail: why each language is where it is, the FFI
contract, and a log of the **bugs that were found and fixed** (including the ones that
were in the code before it ever compiled).

## Performance

Measured with `scripts/bench_overhead.sh` (median of 9 runs + 2 warmup), on real
installed binaries — no fixture is used here either:

**Startup** — the fixed price of paying `ld.so` plus Aegis' constructor:

| Workload | Without | With | Overhead |
|---|---|---|---|
| `/bin/true` | 1.31 ms | 2.01 ms | **+0.70 ms** |
| `bash -c :` | 2.05 ms | 2.62 ms | **+0.57 ms** |
| `sqlite3 :memory:` (empty) | 2.06 ms | 2.59 ms | **+0.53 ms** |

**Steady state** — the runtime while the process actually works. With no traps the
signal handler never runs, so this is pure overhead:

| Workload | Without | With | Overhead |
|---|---|---|---|
| `bash`: 2M arithmetic ops | 2820 ms | 2839 ms | +18.7 ms (**+0.66%**) |
| `python3`: 10M iterations | 537 ms | 541 ms | +4.4 ms (**+0.81%**) |

Two caveats, stated plainly:

- Percentages lie when the denominator is small. On the short sqlite3 workloads the
  numbers swing between −4% and +28% run to run, because ~10 ms is too little time to
  measure against. The milliseconds, not the percentage, are the real measurement.
- Startup overhead is **irreducible in the current design**: it is paid on every
  process start. A service running for hours amortizes it to nothing; a 1 ms script
  notices it. That is a property of preloading, not a tuning bug.

## Status

Phase 1 (core) complete and verified end-to-end. Phase 2 (JIT patching with
trampolines and shadow page) is present in the structure but inactive.

## Warning

This is a diagnostic and resilience tool. It repairs faults so you can inspect the
process state; it does **not** turn a program with corrupted memory into a correct
one. Using `PatchMem` changes the result of the computation: for a production app
that is a decision, not a free side effect.

## License

MIT.

## Contributing & Issues

If you find a bug, please [open an issue](https://github.com/DelfinVT-uwu/AegisRuntime/issues)
and include:

- The exact command you ran
- The output (with `AEGIS_LOG=1` if relevant)
- Your OS/architecture, compiler versions (`gcc --version`, `cargo --version`, `nim --version`)
- A minimal reproducer if possible

Suggestions are welcome. Pull requests are accepted if they keep the safety
guarantees (fail-closed) and don't introduce `unsafe` outside the FFI boundary.
For design changes, it's best to start with an issue first.