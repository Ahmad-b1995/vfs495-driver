#!/usr/bin/env python3
"""Build the driver's command file from HP's driver package and the recipe.

  build-commands.py HP_SOURCE OUT.bin [--signatures flash|rsa]

HP_SOURCE is HP's SoftPaq sp84530.tar (download it from hp_package.SOFTPAQ_URL), the RPM in
it, or the validity-sensor program; all are checked against known checksums. No recording
of HP's tool and no sensor are needed.

Signed firmware patches: by default each is stored as its flash label (u32 id, u8 version,
"PS", ff) followed by the patch as HP ships it, RSA-signed, with flag 1 set. The driver sends
it the way HP's tool does, with the RSA signature replaced by the HMAC the sensor keeps in
its flash under that label, or RSA-signed when the flash has no such entry (the sensor
accepts both). With --signatures rsa the patches are always sent RSA-signed.

Format of the output: see driver/tools/make-commands.py (VFS495C2); flags bit 0 marks a
patch whose signature comes from flash.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from hp_package import PackageError, find_patch, load_program, patch_table  # noqa: E402

MAGIC = b"VFS495C2"
PHASES = {"pre": 0, "hello": 1, "setup": 2, "rearm": 3, "arm": 4, "descramble": 5, "close": 6}
FLAG_FLASH_SIGNATURE = 1
NO_KEY = 0xFFFF
LINE_WIDTH = 264


def flash_label(pid, version):
    return struct.pack("<IB", pid, version) + b"PS\xff"


def build_payload(parts, program, table, signatures):
    out, flags = bytearray(), 0
    for p in parts:
        if "hex" in p:
            out += bytes.fromhex(p["hex"])
        elif "zero" in p:
            out += bytes(p["zero"])
        elif "hp" in p:
            off, n = p["hp"]
            out += program[off:off + n]
        elif "patch" in p:
            pid, version, size = p["patch"]
            data = find_patch(table, pid, version, size, p["sha256"])
            if p["signature"] == "flash" and signatures == "flash":
                if out != b"\x06":
                    raise PackageError("a signed patch must follow the 06 command byte")
                out[:0] = flash_label(pid, version)      # label | 06 | RSA-signed patch
                flags |= FLAG_FLASH_SIGNATURE
            out += data
        else:
            raise PackageError(f"unknown recipe part {p}")
    return bytes(out), flags


def descramble_table(runs):
    table = [None] * LINE_WIDTH
    for lo, hi, to_lo, to_hi in runs:
        step = 1 if to_hi >= to_lo else -1
        for k, i in enumerate(range(lo, hi + 1)):
            table[i] = to_lo + step * k
    if sorted(table) != list(range(LINE_WIDTH)):
        raise PackageError("descramble runs do not form a permutation")
    return struct.pack(f"<{LINE_WIDTH}H", *table)


def build(recipe, program, signatures="flash"):
    table = patch_table(program)
    entries = []
    for c in recipe["commands"]:
        phase = PHASES[c["phase"]]
        if "descramble" in c:
            payload, flags = descramble_table(c["descramble"]), 0
        else:
            payload, flags = build_payload(c["parts"], program, table, signatures)
        entries.append(struct.pack("<BBHII", phase, flags, c.get("key_offset", NO_KEY), c.get("data_len", 0),
                                   len(payload)) + payload)
    return MAGIC + struct.pack("<I", len(entries)) + b"".join(entries)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("source")
    ap.add_argument("out")
    ap.add_argument("--signatures", choices=("flash", "rsa"), default="flash")
    ap.add_argument("--recipe", default=str(HERE / "vfs495-recipe.json"))
    a = ap.parse_args()
    try:
        blob = build(json.loads(Path(a.recipe).read_text()), load_program(a.source), a.signatures)
    except (PackageError, OSError, KeyError) as e:
        sys.exit(f"build-commands: {e}")
    Path(a.out).write_bytes(blob)
    print(f"wrote {a.out}: {len(blob)} bytes ({a.signatures} signatures)")


if __name__ == "__main__":
    main()
