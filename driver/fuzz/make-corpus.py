#!/usr/bin/env python3
"""Seed inputs for the fuzz targets, from the private data in captures/.

Writes captures/fuzz/TARGET/ (git-ignored: the seeds hold session data and fingerprint scans):
  commands  the command files
  records   recorded server transfers (selector 0 and 1), ServerHellos (2), signed patches
            against the recorded flash block (3)
  frames    the start of decrypted swipe streams
  assemble  scan lines of normal and rejected swipes

Usage: make-corpus.py
"""
import glob
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAPTURES = ROOT / "captures"
OUT = CAPTURES / "fuzz"


def load_wire(path):
    """(direction, endpoint, bytes) per transfer of a wire log (as research/session/decrypt.py)."""
    out = []
    for line in open(path):
        w = line.split()
        if len(w) > 5 and w[1] in ("OUT", "IN") and w[5].startswith("data="):
            out.append((w[1], w[2].split("=")[1], bytes.fromhex(w[5][5:])))
    return out


LINE = 264


def write(target, name, data):
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)


def commands():
    for p in (CAPTURES / "vfs495-commands.bin", CAPTURES / "recipe" / "built.bin"):
        if p.exists():
            write("commands", p.stem, p.read_bytes())


def records():
    for vec in sorted(glob.glob(str(CAPTURES / "test-vectors" / "*.vec"))):
        name = Path(vec).stem
        ins = [bytes.fromhex(l.split()[1]) for l in open(vec) if l.startswith("in ")]
        if ins:
            write("records", f"{name}.finish", b"\x01" + ins[0])
            for k, t in enumerate(ins[1:6]):
                write("records", f"{name}.open{k}", b"\x00" + t)
    for log in sorted(glob.glob(str(CAPTURES / "wire.*.log")))[:3]:
        sh = next((d for dr, ep, d in load_wire(log) if dr == "IN" and ep == "01" and d[:1] == b"\x16"), None)
        if sh:
            write("records", f"{Path(log).stem}.serverhello", b"\x02" + sh)
    built, flash = CAPTURES / "recipe" / "built.bin", CAPTURES / "test-vectors" / "nocal.flash"
    if built.exists() and flash.exists():
        b, f = built.read_bytes(), flash.read_bytes()
        n, pos, k = int.from_bytes(b[8:12], "little"), 12, 0
        for _ in range(n):
            flags, ln = b[pos + 1], int.from_bytes(b[pos + 8:pos + 12], "little")
            payload = b[pos + 12:pos + 12 + ln]
            pos += 12 + ln
            if flags & 1:
                # the flash half: the end of the block, where the signature cache sits
                write("records", f"patch{k}", b"\x03" + payload + f[-len(payload):])
                k += 1


def frames():
    for p in sorted(glob.glob(str(CAPTURES / "*.dec")))[:6]:
        write("frames", Path(p).stem, Path(p).read_bytes()[:64 * 1024])


def assemble():
    picks = sorted(glob.glob(str(CAPTURES / "diag" / "*.lines.raw"))) + \
        sorted(glob.glob(str(CAPTURES / "ctool" / "rest.*.lines.raw")))
    for p in picks:
        raw, data, pos = Path(p).read_bytes(), bytearray(), 0
        while pos + 2 + LINE <= len(raw) and len(data) < 1500 * LINE:
            data += raw[pos + 2:pos + 2 + LINE]
            pos += 2 + LINE
        write("assemble", Path(p).name.replace(".lines.raw", ""), bytes(data))


def main():
    for f in (commands, records, frames, assemble):
        f()
    for d in sorted(OUT.iterdir()):
        print(f"{d.name}: {len(list(d.iterdir()))} seeds")


if __name__ == "__main__":
    main()
