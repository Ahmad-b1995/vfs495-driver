"""Map each command of the driver's command file onto HP's files.

Covers every payload with the longest byte runs that also occur in HP's program or firmware
images (runs of at least MIN_RUN bytes); what remains are bytes HP computes or that come from
this sensor. Prints, per command, how many bytes were found and where the rest sits.

Usage: python3 map_commands.py captures/vfs495-commands.bin HPFILE [HPFILE ...]
"""
import struct
import sys
from pathlib import Path

MIN_RUN = 12
PHASES = ["pre", "hello", "setup", "rearm", "arm", "descramble", "close"]


def load_commands(path):
    b = Path(path).read_bytes()
    assert b[:8] == b"VFS495C2"
    n, pos, out = struct.unpack_from("<I", b, 8)[0], 12, []
    for _ in range(n):
        ph, _, ko, dl, ln = struct.unpack_from("<BBHII", b, pos)
        out.append((PHASES[ph], ko, dl, b[pos + 12:pos + 12 + ln]))
        pos += 12 + ln
    return out


def longest_at(p, payload, hay):
    """Longest run of payload starting at p that occurs in hay: (length, offset)."""
    seed = payload[p:p + MIN_RUN]
    if len(seed) < MIN_RUN:
        return 0, -1
    best, i = (0, -1), hay.find(seed)
    while i >= 0:
        n = MIN_RUN
        while p + n < len(payload) and i + n < len(hay) and payload[p + n] == hay[i + n]:
            n += 1
        best = max(best, (n, i))
        i = hay.find(seed, i + 1)
    return best


def cover(payload, files):
    segs, p = [], 0
    while p < len(payload):
        cands = [(longest_at(p, payload, data) + (name,)) for name, data in files]
        n, off, name = max(cands)
        if n:
            segs.append(("hp", name, off, n))
            p += n
        else:
            if segs and segs[-1][0] == "lit":
                segs[-1] = ("lit", segs[-1][1] + payload[p:p + 1])
            else:
                segs.append(("lit", payload[p:p + 1]))
            p += 1
    return segs


def main():
    cmds = load_commands(sys.argv[1])
    files = [(Path(f).name, Path(f).read_bytes()) for f in sys.argv[2:]]
    total = found = 0
    for k, (phase, ko, dl, payload) in enumerate(cmds):
        if phase == "descramble":
            continue
        segs = cover(payload, files)
        hp = sum(s[3] for s in segs if s[0] == "hp")
        total += len(payload)
        found += hp
        lits = [s[1] for s in segs if s[0] == "lit"]
        print(f"#{k:2d} {phase:6s} cmd {payload[0]:02x} {len(payload):5d} B: {hp:5d} in HP files, "
              f"{len(payload) - hp:4d} other in {len(lits)} pieces"
              + (f"  key@{ko}" if ko != 0xFFFF else ""))
        p = 0
        for s in segs:
            if s[0] == "lit":
                print(f"      @{p:5d} +{len(s[1]):3d}: {s[1][:40].hex()}{'..' if len(s[1]) > 40 else ''}")
                p += len(s[1])
            else:
                p += s[3]
    print(f"\n{found} of {total} bytes found in HP's files ({100 * found / total:.1f}%)")


if __name__ == "__main__":
    main()
