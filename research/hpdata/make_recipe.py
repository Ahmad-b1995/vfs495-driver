"""Derive the command recipe from a command file recorded on this machine and HP's package.

The recipe (driver/recipe/vfs495-recipe.json) rebuilds the command file from HP's download
without any recording: every command is a list of parts that are either small literals
(protocol framing, command bytes, TLV headers), zero runs, byte ranges of HP's
validity-sensor program, or HP patches named by their id and version in HP's patch table.
It contains no HP data. driver/recipe/build-commands.py turns it into a command file.

Per-session values are dropped: the ClientHello random, and the arming command's key field
(the driver fills bytes 0-95 of every arming with fresh random data).

Usage: python3 make_recipe.py captures/vfs495-commands.bin HP/validity-sensor OUT.json
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "driver" / "recipe"))
from hp_package import BASE, patch_table  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from map_commands import PHASES  # noqa: E402

MIN_ZERO = 8     # zero runs at least this long become "zero" parts
MIN_HP = 32      # HP byte ranges at least this long, with MIN_CONTENT non-zero bytes, become
MIN_CONTENT = 16  # "hp" parts; shorter matches are coincidences in protocol parameters
KEY_FIELD_RANDOM = 96
OMIT = {9: "HP's 512 KB flash read: 540 ms, its data is not used; swipes are unchanged without it",
        **{i: "HP's second patch reload and calibration capture before arming: 60 ms, not needed for arming"
           for i in range(15, 20)}}


def load(path):
    b = Path(path).read_bytes()
    n, pos, out = struct.unpack_from("<I", b, 8)[0], 12, []
    for _ in range(n):
        ph, flags, ko, dl, ln = struct.unpack_from("<BBHII", b, pos)
        out.append({"phase": PHASES[ph], "key_offset": ko, "data_len": dl, "payload": bytearray(b[pos + 12:pos + 12 + ln])})
        pos += 12 + ln
    return out


def longest_hp(payload, p, hp):
    seed = bytes(payload[p:p + MIN_HP])
    if len(seed) < MIN_HP or not any(seed):
        return 0, -1
    best, i = (0, -1), hp.find(seed)
    while i >= 0:
        n = MIN_HP
        while p + n < len(payload) and i + n < len(hp) and payload[p + n] == hp[i + n]:
            n += 1
        best = max(best, (n, i))
        i = hp.find(seed, i + 1)
    return best


def segment(payload, hp):
    parts, lit, p = [], bytearray(), 0

    def flush():
        if lit:
            parts.append({"hex": lit.hex()})
            lit.clear()

    while p < len(payload):
        z = 0
        while p + z < len(payload) and payload[p + z] == 0:
            z += 1
        if z >= MIN_ZERO:
            flush()
            parts.append({"zero": z})
            p += z
            continue
        n, off = longest_hp(payload, p, hp)
        if n and sum(1 for x in payload[p:p + n] if x) >= MIN_CONTENT:
            flush()
            parts.append({"hp": [off, n]})
            p += n
            continue
        lit.append(payload[p])
        p += 1
    flush()
    return parts


def patch_parts(payload, table):
    """A patch command (06 + patch) as a reference to HP's patch table."""
    patch = bytes(payload[1:])
    for e in table:
        ref = {"patch": [e["id"], e["version"], len(e["data"])],
               "sha256": hashlib.sha256(e["data"]).hexdigest()[:16]}
        if patch == e["data"]:
            return [{"hex": "06"}, {**ref, "signature": "rsa"}]
        if patch[:4] == b"\x02\x00\x20\x00" and patch[36:] == e["data"][260:]:
            return [{"hex": "06"}, {**ref, "signature": "flash"}]
    return None


def descramble_runs(payload):
    t = struct.unpack(f"<{len(payload) // 2}H", payload)
    runs, s = [], 0
    for i in range(1, len(t) + 1):
        if i == len(t) or abs(t[i] - t[i - 1]) != 1 or (i > s + 1 and t[i] - t[i - 1] != t[s + 1] - t[s]):
            runs.append([s, i - 1, t[s], t[i - 1]])
            s = i
    return runs


def main():
    cmds = load(sys.argv[1])
    hp = Path(sys.argv[2]).read_bytes()
    table = patch_table(hp)
    out = []
    for c in cmds:
        p = c["payload"]
        entry = {"phase": c["phase"]}
        if c["data_len"]:
            entry["data_len"] = c["data_len"]
        if c["phase"] == "descramble":
            entry["descramble"] = descramble_runs(p)
            out.append(entry)
            continue
        if c["phase"] == "hello":
            p[3 + 11:3 + 43] = bytes(32)                     # ClientHello random
        if c["key_offset"] != 0xFFFF:
            entry["key_offset"] = c["key_offset"]
            p[c["key_offset"]:c["key_offset"] + KEY_FIELD_RANDOM] = bytes(KEY_FIELD_RANDOM)
        entry["parts"] = (p[:1] == b"\x06" and patch_parts(p, table)) or segment(p, hp)
        out.append(entry)
    # measured on the sensor (research/session/speed-test.sh): HP's steps the driver skips
    for i, reason in OMIT.items():
        out[i]["omit"] = reason
    recipe = {
        "format": 1,
        "comment": "Rebuilds the VFS495 command file from HP's SoftPaq sp84530 (driver/recipe/build-commands.py). "
                   "Contains no HP data: parts are literals, zero runs, byte ranges of HP's validity-sensor, "
                   "or HP patches by table id and version.",
        "commands": out,
    }
    Path(sys.argv[3]).write_text(json.dumps(recipe, indent=1) + "\n")
    kinds = {}
    for e in out:
        for part in e.get("parts", []):
            k = next(iter(part))
            kinds[k] = kinds.get(k, 0) + 1
    lit = sum(len(pt["hex"]) // 2 for e in out for pt in e.get("parts", []) if "hex" in pt)
    print(f"{len(out)} commands; parts: {kinds}; literal bytes: {lit}")


if __name__ == "__main__":
    main()
