#!/usr/bin/env python3
"""Extract test vectors for vfs495-test from recordings of HP's tool.

For each session (captures/session.NAME.jsonl + captures/wire.NAME.log) writes
captures/test-vectors/NAME.vec, a text file of hex fields, one per line:

  premaster P / client_random R / server_random R / master M / keyblock K
  handshake H          ClientHello .. ClientKeyExchange handshake messages, for Finished
  finished F           the 36-byte client Finished HP computed
  out TYPE PLAIN WIRE  a client record: its plaintext and the record HP sent (header included)
  in TRANSFER          a server transfer on the command endpoint, records as received; the
                       first one starts with ChangeCipherSpec and the server Finished

For a recording with a swipe (arming command followed by an image stream) it also writes
NAME.stream (the encrypted stream as received) and NAME.key (image key and IV, 48 bytes), and
NAME.flash, the pre-session flash block (RSA key, cached patch signatures).

These files hold session secrets and fingerprint data: they stay in the git-ignored captures/.

Usage: make-vectors.py NAME [NAME ...]      e.g. make-vectors.py nocal run4 swipe1
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "research" / "session"))
from decrypt import Direction, load_wire, records  # noqa: E402

CAPTURES = ROOT / "captures"
OUT = CAPTURES / "test-vectors"


def record_bytes(rtype, payload):
    return bytes([rtype, 3, 0]) + len(payload).to_bytes(2, "big") + payload


def tlv_key(plain):
    """The 48-byte image key and IV from an arming command's type 0x0006 field."""
    i = 5
    while i + 4 <= len(plain):
        t = int.from_bytes(plain[i:i + 2], "little")
        n = int.from_bytes(plain[i + 2:i + 4], "little")
        if t == 0x0006 and n >= 64:
            return plain[i + 4:i + 4 + 48]
        i += 4 + n
    return None


def vectors(name):
    events = [json.loads(l) for l in open(CAPTURES / f"session.{name}.jsonl")]
    pm = next(e for e in events if e["kind"] == "premaster")
    keys = next(e for e in events if e["kind"] == "keys")
    fin = next(e for e in events if e["kind"] == "finished")
    hs = "".join(e["data"] for e in events if e["kind"] == "hs_update")
    kb = bytes.fromhex(keys["keyblock"])
    client = Direction(kb[0:20], kb[40:72], kb[104:120])

    lines = [f"premaster {pm['premaster']}", f"client_random {pm['rand_0x38']}",
             f"server_random {pm['rand_0x40']}", f"master {keys['master']}", f"keyblock {keys['keyblock']}",
             f"handshake {hs}", f"finished {fin['out'][8:]}"]
    in_session, arm_key, stream, polling, swipe = False, None, bytearray(), False, None
    wire = load_wire(CAPTURES / f"wire.{name}.log")
    flash = next((data for d, ep, data in wire if d == "IN" and ep == "02" and len(data) == 4096), None)
    for d, ep, data in wire:
        if d == "OUT" and data[:3] == b"\x11\x54\x01":
            rtype, ct = records(data[3:])[2]
            plain, ok = client.open(rtype, ct)
            assert ok, "client Finished MAC"
            lines.append(f"out {rtype:02x} {plain.hex()} {record_bytes(rtype, ct).hex()}")
            in_session = True
        elif not in_session or ep not in ("01", "02"):
            continue
        elif d == "IN" and ep == "01":
            lines.append(f"in {data.hex()}")
        elif d == "OUT" and data[:1] in (b"\x17", b"\x15"):
            for rtype, ct in records(data):
                plain, ok = client.open(rtype, ct)
                assert ok, "client record MAC"
                lines.append(f"out {rtype:02x} {plain.hex()} {record_bytes(rtype, ct).hex()}")
                if plain[:1] == b"\x02" and tlv_key(plain) and any(tlv_key(plain)):
                    arm_key, stream, polling = tlv_key(plain), bytearray(), False
                elif plain == b"\x17":
                    polling = True
                elif plain == b"\x04":
                    polling = False
                    if stream and not swipe:
                        swipe = (arm_key, bytes(stream))   # the first complete swipe
        elif d == "IN" and ep == "02" and polling and arm_key:
            stream += data
    OUT.mkdir(exist_ok=True)
    (OUT / f"{name}.vec").write_text("\n".join(lines) + "\n")
    if flash:
        (OUT / f"{name}.flash").write_bytes(flash)
    msg = f"{name}: {sum(l.startswith('out') for l in lines)} client records, " \
          f"{sum(l.startswith('in') for l in lines)} server transfers"
    if swipe:
        (OUT / f"{name}.key").write_bytes(swipe[0])
        (OUT / f"{name}.stream").write_bytes(swipe[1])
        msg += f", swipe stream {len(swipe[1])} bytes"
    print(msg)


if __name__ == "__main__":
    for n in sys.argv[1:] or sys.exit(__doc__):
        vectors(n)
