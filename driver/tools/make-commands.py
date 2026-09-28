#!/usr/bin/env python3
"""Generate the driver's command data file from a decrypted recording of this sensor.

The driver replays the uncalibrated session recorded from HP's tool on this machine. This
writes the commands it needs, in order, to a small binary file the driver loads at startup.
The file is specific to this sensor and stays local (captures/ is git-ignored).

Format (little-endian):
  magic "VFS495C2", u32 entry count, then per entry:
  u8 phase, u8 reserved, u16 key offset, u32 data length, u32 length, payload
    phase: 0 pre-session (plaintext), 1 ClientHello template, 2 setup, 3 re-arm, 4 arm,
           5 column descramble table (264 u16: out[table[i]] = pixel[i]),
           6 close (sent after the final abort, before close_notify)
    key offset: offset of the 64-byte image-key field in the payload, 0xFFFF if none
    data length: bytes the sensor sends on endpoint 0x82 after this command. The driver
      reads exactly this much: the sensor sends these blocks in whole 64-byte packets with
      no terminating short packet, so a read of unknown length only ends by timing out.
Setup and re-arm commands get their image-key field zeroed; the driver fills the arming
command's field with a fresh key and IV for every capture.

The descramble table is read from the upstream clone (../vfs495-linux/driver/
vfs495_descramble.inc), so HP-derived data stays in this local file only.

Usage: make-commands.py RECORDING.decrypted.json OUT.bin
"""
import json
import re
import struct
import sys
from pathlib import Path

DESCRAMBLE_INC = Path(__file__).resolve().parents[3] / "vfs495-linux" / "driver" / "vfs495_descramble.inc"
LINE_WIDTH = 264

MAGIC = b"VFS495C2"
PRE, HELLO, SETUP, REARM, ARM, DESCRAMBLE, CLOSE = range(7)
NO_KEY = 0xFFFF
CMD_FINGER_STATE = b"\x17"
CMD_ABORT = b"\x04"


def key_offset(payload):
    """Offset of the value of the type 0x0006 field in a configuration command, if any."""
    if payload[:1] != b"\x02":
        return NO_KEY
    i = 5
    while i + 4 <= len(payload):
        t = int.from_bytes(payload[i:i + 2], "little")
        n = int.from_bytes(payload[i + 2:i + 4], "little")
        if t == 0x0006 and n >= 64:
            return i + 4
        i += 4 + n
    return NO_KEY


def commands(transcript):
    """(phase-less) list of (kind, payload, data length) from the recording, up to the first poll."""
    out = []
    for k, e in enumerate(transcript):
        if e["dir"] != "OUT" or "plain" not in e:
            continue
        payload = bytes.fromhex(e["plain"])
        data = 0
        for later in transcript[k + 1:]:
            if later["dir"] == "OUT":
                break
            if later["ep"] == "02":
                data += later["len"]
        out.append((e["kind"], payload, data))
        if e["kind"] == "appdata" and payload == CMD_FINGER_STATE:
            break
    return out


def closing(transcript):
    """Commands HP sends after its final abort: unload the session patch and reload the one
    that was active before the handshake. Without them the next session's first patch load
    fails and the sensor resets itself."""
    outs = [bytes.fromhex(e["plain"]) for e in transcript
            if e["dir"] == "OUT" and e["kind"] == "appdata" and "plain" in e]
    last_abort = max(i for i, p in enumerate(outs) if p == CMD_ABORT)
    return [(p, 0) for p in outs[last_abort + 1:]]


def plan(transcript):
    cmds = commands(transcript)
    pre = [(p, d) for k, p, d in cmds if k == "plain" and p[:1] != b"\x11"]
    hello = next(p for k, p, d in cmds if k == "plain" and p[:1] == b"\x11")
    session = [(p, d) for k, p, d in cmds if k == "appdata" and p != CMD_FINGER_STATE]
    arm = len(session) - 1
    payloads = [p for p, _ in session]
    rearm = max(i for i in range(arm - 1) if payloads[i][:1] == b"\x1a" and payloads[i + 1][:1] == b"\x06"
                and payloads[i + 2][:1] == b"\x02")
    entries = [(PRE, p, d) for p, d in pre]
    entries.append((HELLO, hello, 0))
    entries += [(SETUP, p, d) for p, d in session[:arm]]
    entries += [(REARM, p, d) for p, d in session[rearm:arm]]
    entries.append((ARM, session[arm][0], session[arm][1]))
    entries += [(CLOSE, p, d) for p, d in closing(transcript)]
    entries.append((DESCRAMBLE, descramble_table(), 0))
    return entries


def descramble_table():
    src = DESCRAMBLE_INC.read_text()
    perm = [int(v) for v in re.findall(r"\d+", src[src.index("{") + 1:src.rindex("}")])]
    assert sorted(perm) == list(range(LINE_WIDTH)), "descramble table is not a permutation"
    return struct.pack(f"<{LINE_WIDTH}H", *perm)


def pack(entries):
    out = [MAGIC, struct.pack("<I", len(entries))]
    for phase, payload, data in entries:
        off = key_offset(payload) if phase in (SETUP, REARM, ARM) else NO_KEY
        if off != NO_KEY:
            payload = payload[:off] + bytes(64) + payload[off + 64:]
        out.append(struct.pack("<BBHII", phase, 0, off, data, len(payload)) + payload)
    return b"".join(out)


def main():
    entries = plan(json.load(open(sys.argv[1])))
    blob = pack(entries)
    open(sys.argv[2], "wb").write(blob)
    names = ["pre-session", "hello", "setup", "re-arm", "arm", "descramble", "close"]
    counts = {n: sum(1 for p, _, _ in entries if names[p] == n) for n in names}
    print(f"wrote {sys.argv[2]}: {len(entries)} commands {counts}, {len(blob)} bytes")


if __name__ == "__main__":
    main()
