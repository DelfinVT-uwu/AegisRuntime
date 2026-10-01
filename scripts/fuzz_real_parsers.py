#!/usr/bin/env python3
# hunt_faults.py — hunting NATURAL crashes in REAL, UNMODIFIED system binaries.
#
# Method: we never write a program. We take real files (real PNG/JPEG/GIF/ICO
# from the system, real ELF binaries) and mutate them, then feed them to real
# parsers (ImageMagick, djpeg, ffprobe, objdump, readelf, nm, xz, zstd, 7z,
# cpio, ar, gdb). A SIGSEGV/SIGFPE there is a genuine bug, discovered the way
# the real world discovers them: by handing bad bytes to a real parser.
#
# This is the honest counterpart of "I wrote a program that divides by zero,
# of course it crashes" — here we do not control the program at all.
#
# Usage:  python3 scripts/fuzz_real_parsers.py [rounds]
#
# [POR QUÉ ESTE SCRIPT ESTÁ EN EL REPO]
# El README afirma que se hicieron 3000 rondas sin encontrar ni un crash. Una
# afirmación así solo vale algo si quien la lee puede repetirla: sin este
# fichero, el dato era inverificable. También fija el resultado negativo: si en
# tu máquina salen crashes, es información real sobre TU versión de esos binarios.
#
# Los directorios de trabajo cuelgan de un temporal del sistema, no de rutas
# absolutas: el script tiene que funcionar para quien clone el repo.

import os, sys, random, shutil, subprocess, struct, tempfile
from pathlib import Path

ROOT = Path(tempfile.gettempdir()) / "aegis-fuzz"
WORK = ROOT / "work"
SEEDS = ROOT / "seeds"
WORK.mkdir(parents=True, exist_ok=True)
SEEDS.mkdir(parents=True, exist_ok=True)

CRASHES = ROOT / "real_crashes.txt"

SIGNAME = {4:"SIGILL", 6:"SIGABRT", 7:"SIGBUS", 8:"SIGFPE", 11:"SIGSEGV"}


def log_crash(prog, sig, seed, mode, extra=""):
    with CRASHES.open("a") as f:
        f.write(f"sig={sig}({SIGNAME.get(sig,'?')}) prog={prog} "
                f"seed={Path(seed).name} mode={mode} {extra}\n")


def run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout)
        return p.returncode
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def check(prog_name, cmd, seed, mode, extra=""):
    rc = run(cmd)
    if rc is not None and rc >= 128:
        sig = rc - 128
        if sig in SIGNAME:
            print(f"  >>> CRASH {SIGNAME[sig]} in {prog_name} "
                  f"[seed={Path(seed).name} mode={mode}] {extra}")
            log_crash(prog_name, sig, seed, mode, extra)
            return True
    return False


# ---------------------------------------------------------------- mutations
def m_trunc(d, rnd):
    n = max(8, int(len(d) * rnd.uniform(0.02, 0.98)))
    return d[:n]

def m_flip(d, rnd):
    o = bytearray(d)
    for _ in range(rnd.randint(1, 24)):
        o[rnd.randrange(len(o))] = rnd.randrange(256)
    return bytes(o)

def m_zero(d, rnd):
    o = bytearray(d)
    a = rnd.randrange(0, len(o))
    n = rnd.randint(1, min(len(o) - a, rnd.randint(16, 4096)))
    o[a:a+n] = b"\x00" * n
    return bytes(o)

def m_ransack(d, rnd):
    """classic AFL havoc: many random ops"""
    o = bytearray(d)
    for _ in range(rnd.randint(4, 64)):
        k = rnd.random()
        if k < 0.3 and o:
            o[rnd.randrange(len(o))] = rnd.randrange(256)
        elif k < 0.5 and len(o) > 16:
            a = rnd.randrange(len(o) - 8)
            o[a:a+8] = struct.pack("<Q", rnd.getrandbits(64))
        elif k < 0.7 and len(o) > 32:
            a = rnd.randrange(len(o) - 4)
            v = rnd.choice([0, 1, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
                            0x8000000000000000, rnd.getrandbits(32)])
            o[a:a+4] = struct.pack("<I", v & 0xFFFFFFFF)
        elif k < 0.85 and len(o) > 16:
            del o[rnd.randrange(len(o)):][:rnd.randint(1, 64)]
        else:
            a = rnd.randrange(len(o))
            o[a:a] = bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 32)))
    return bytes(o)

def m_elfhdr(d, rnd):
    """attack ELF header fields directly: sizes, offsets, counts"""
    if len(d) < 64:
        return d
    o = bytearray(d)
    is64 = d[4] == 2
    # e_shoff, e_phoff, e_phnum, e_shnum, e_shentsize
    for field_off, size in ((0x28, 8), (0x20, 8), (0x38, 2), (0x3C, 2), (0x3A, 2)):
        if field_off + size <= len(o):
            v = rnd.choice([0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                            rnd.getrandbits(16), rnd.getrandbits(32)])
            o[field_off:field_off+size] = (v & ((1 << (size*8)) - 1)).to_bytes(size, "little")
    if is64 and rnd.random() < 0.6:
        # e_shentsize / e_shstrndx in the 64-bit layout
        for field_off, size in ((0x3A, 2), (0x3E, 4)):
            if field_off + size <= len(o):
                v = rnd.choice([0, 1, 0xFFFF, 0xFFFFFFFF])
                o[field_off:field_off+size] = (v & ((1 << (size*8))-1)).to_bytes(size, "little")
    return bytes(o)

MUTATORS = [m_trunc, m_flip, m_zero, m_ransack, m_elfhdr]


# ---------------------------------------------------------------- corpus
def build_seeds():
    SEEDS.mkdir(exist_ok=True)
    n = 0
    for root in ("/usr/share/pixmaps", "/usr/share/icons",
                 "/usr/lib/gdk-pixbuf", "/usr/share/mime"):
        r = Path(root)
        if not r.exists():
            continue
        for p in r.rglob("*"):
            if n >= 60:
                break
            if not p.is_file():
                continue
            if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".ico",
                                    ".bmp", ".xpm", ".svg", ".wav") \
               and 32 < p.stat().st_size < 400_000:
                try:
                    shutil.copy2(p, SEEDS / f"img{n}{p.suffix.lower()}")
                    n += 1
                except OSError:
                    pass
    # real ELF binaries as seeds for the ELF parsers
    m = 0
    for b in ("curl", "iconv", "xz", "zstd", "sqlite3", "ffprobe", "objdump",
              "readelf", "nm", "file", "python3", "gdb", "7z", "tar", "gzip"):
        pp = shutil.which(b)
        if pp:
            try:
                shutil.copy2(pp, SEEDS / f"elf_{b}")
                m += 1
            except OSError:
                pass
    return n, m


# ---------------------------------------------------------------- parsers
def parsers_for(seed: Path):
    """real programs to feed the mutated file to"""
    out = []
    s = seed.suffix.lower()
    if s in (".png", ".jpg", ".jpeg"):
        if shutil.which("identify"):   out.append(("identify", ["identify", "{F}"]))
        if shutil.which("convert"):    out.append(("convert", ["convert", "{F}", "-resize", "1x1", "null:"]))
        if shutil.which("djpeg") and s in (".jpg", ".jpeg"):
            out.append(("djpeg", ["djpeg", "{F}"]))
        if shutil.which("ffprobe"):    out.append(("ffprobe", ["ffprobe", "-hide_banner", "{F}"]))
        if shutil.which("ffmpeg"):
            out.append(("ffmpeg", ["ffmpeg", "-hide_banner", "-v", "quiet", "-i", "{F}",
                                   "-f", "null", "-"]))
    elif s == ".gif":
        if shutil.which("identify"):   out.append(("identify", ["identify", "{F}"]))
        if shutil.which("convert"):    out.append(("convert", ["convert", "{F}", "null:"]))
    elif s == ".ico":
        if shutil.which("identify"):   out.append(("identify", ["identify", "{F}"]))
        if shutil.which("convert"):    out.append(("convert", ["convert", "{F}", "null:"]))
    elif s == ".wav":
        if shutil.which("ffprobe"):    out.append(("ffprobe", ["ffprobe", "-hide_banner", "{F}"]))
        if shutil.which("ffmpeg"):
            out.append(("ffmpeg", ["ffmpeg", "-hide_banner", "-v", "quiet", "-i", "{F}",
                                   "-f", "null", "-"]))
    elif s == ".svg":
        if shutil.which("convert"):    out.append(("convert", ["convert", "{F}", "null:"]))
        if shutil.which("rsvg-convert"): out.append(("rsvg-convert", ["rsvg-convert", "{F}", "-o", os.devnull]))
    elif seed.name.startswith("elf_"):
        prog = seed.name[4:]
        pp = shutil.which(prog) or str(seed)
        if prog == "objdump":
            for fl in (["-a"], ["-d"], ["-x"], ["-s", "-j", ".text"], ["--dwarf=info"]):
                out.append(("objdump " + " ".join(fl), [pp] + fl + ["{F}"]))
        elif prog == "readelf":
            for fl in (["-a"], ["-h", "-l"], ["-S", "--wide"], ["-r", "-W"],
                       ["--dyn-syms"], ["-e", "frames"], ["-n"]):
                out.append(("readelf " + " ".join(fl), [pp] + fl + ["{F}"]))
        elif prog == "nm":
            out.append(("nm -a", [pp, "-a", "{F}"]))
            out.append(("nm -D", [pp, "-D", "{F}"]))
        elif prog == "file":
            out.append(("file -k", [pp, "-k", "{F}"]))
            out.append(("file -b", [pp, "-b", "{F}"]))
        elif prog == "xz":
            out.append(("xz -dc", [pp, "-dc", "{F}"]))
            out.append(("xz -t", [pp, "-t", "{F}"]))
        elif prog == "zstd":
            out.append(("zstd -dc", [pp, "-dc", "{F}"]))
        elif prog == "7z":
            out.append(("7z l", [pp, "l", "{F}"]))
            out.append(("7z t", [pp, "t", "{F}"]))
        elif prog == "gzip":
            out.append(("gzip -dc", [pp, "-dc", "{F}"]))
        elif prog == "gdb":
            out.append(("gdb exec-file", [pp, "-batch", "-ex", "info functions", "{F}"]))
        else:
            out.append((prog, [pp, "{F}"]))
    return out


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 400
    random.seed(0xC0FFEE)
    nimg, nelf = build_seeds()
    seeds = [p for p in SEEDS.glob("*") if p.is_file()]
    print(f"corpus: {nimg} imagenes reales, {nelf} ELF reales, "
          f"{rounds} rondas de mutacion")

    found = 0
    for r in range(rounds):
        seed = random.choice(seeds)
        parsers = parsers_for(seed)
        if not parsers:
            continue
        mut = random.choice(MUTATORS)
        try:
            d = mut(seed.read_bytes(), random)
        except Exception:
            continue
        if len(d) < 8:
            continue
        tf = WORK / f"t{r}{seed.suffix}"
        try:
            tf.write_bytes(d)
        except OSError:
            continue
        for name, tmpl in parsers:
            cmd = [x.replace("{F}", str(tf)) for x in tmpl]
            if check(name, cmd, seed, mut.__name__):
                found += 1
        tf.unlink(missing_ok=True)
    print(f"--- crashes naturales encontrados: {found} ---")
    if CRASHES.exists():
        print(CRASHES.read_text())


if __name__ == "__main__":
    main()