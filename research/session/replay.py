"""Replay a recorded HP session with the open client (no HP code involved).

Pre-session commands and in-session commands come from a decrypted recording
(see decrypt.py). The sensor key is read from the sensor's flash during the replay.

Usage: python3 replay.py captures/wire.NAME.decrypted.json OUTNAME [--field6 keep|zero|random]
                         [--repeat-capture N]

--field6 replaces the 64 varying bytes of every type-0x0006 field in configuration commands,
to test whether the sensor checks them. --repeat-capture re-runs the final capture block N more
times in the same session. Data-endpoint output goes to captures/replay.OUTNAME.*.
"""
import argparse
import json
import secrets
import time
from pathlib import Path

from vfs495 import FLASH_KEY_OFFSET, ROOT, Vfs495


def tlv_fields(payload, start=5):
    """Yield (type, value_offset, length) for a configuration command's TLV list."""
    i = start
    while i + 4 <= len(payload):
        t = int.from_bytes(payload[i:i + 2], "little")
        n = int.from_bytes(payload[i + 2:i + 4], "little")
        yield t, i + 4, n
        i += 4 + n


def patch_field6(payload, mode):
    if mode == "keep" or payload[:1] != b"\x02":
        return payload, False
    p = bytearray(payload)
    changed = False
    for t, off, n in tlv_fields(payload):
        if t == 0x0006 and n >= 64:
            p[off:off + 64] = bytes(64) if mode == "zero" else secrets.token_bytes(64)
            changed = True
    return bytes(p), changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript")
    ap.add_argument("outname")
    ap.add_argument("--field6", choices=("keep", "zero", "random"), default="keep")
    ap.add_argument("--repeat-capture", type=int, default=0,
                    help="afterwards, re-run the final capture block (from the 1a before the capture command) N times")
    args = ap.parse_args()

    tr = json.load(open(args.transcript))
    out_dir = ROOT / "captures"
    s = Vfs495()
    try:
        # plaintext phase: replay recorded commands up to the ClientHello
        flash_block = None
        for idx, e in enumerate(tr):
            if e["dir"] != "OUT":
                continue
            p = bytes.fromhex(e["plain"])
            if p[:1] == b"\x11":
                client_hello = p
                break
            r = s.cmd_plain(p)
            data = s.read_data(timeout=500) if p[0] == 0x1F else b""
            if len(data) == 4096:
                flash_block = data
            print(f"plain {p[0]:02x} len {len(p):4d} -> status {r[:2].hex()} data {len(data)}")
        modulus = flash_block[FLASH_KEY_OFFSET:FLASH_KEY_OFFSET + 256]
        extra = s.handshake(modulus, client_hello)
        print(f"handshake ok; key read from flash; unsolicited record {extra.hex()[:16]}..")

        # in-session phase
        entries = [e for e in tr[idx:] if e.get("kind") in ("appdata",) or e["ep"] == "02"]
        n_cmd = 0
        for j, e in enumerate(entries):
            if e["dir"] != "OUT":
                continue
            payload, changed = patch_field6(bytes.fromhex(e["plain"]), args.field6)
            reply = s.cmd(payload)
            status = reply[:2][::-1].hex()
            # the recorded reply comes first; data follows before the next command, if any
            following = []
            for later in entries[j + 1:]:
                if later["dir"] == "OUT":
                    break
                following.append(later)
            expect_data = any(x["ep"] == "02" for x in following)
            data = s.read_data() if expect_data else b""
            if data:
                (out_dir / f"replay.{args.outname}.cmd{n_cmd:02d}.bin").write_bytes(data)
            recorded = next((x for x in tr if x["i"] == e["i"] + 1), {})
            rec_status = bytes.fromhex(recorded.get("plain", "0000"))[:2][::-1].hex()
            flag = "" if status == rec_status else f"   <-- HP got {rec_status}"
            print(f"cmd {n_cmd:2d} {payload[0]:02x} len {len(payload):5d}{' (field6 ' + args.field6 + ')' if changed else ''}"
                  f" -> status {status} reply +{len(reply) - 2}B data {len(data)}{flag}")
            n_cmd += 1
        sent = [bytes.fromhex(e["plain"]) for e in entries if e["dir"] == "OUT"]
        cap = max(i for i, p in enumerate(sent) if p[:1] == b"\x02")
        block = sent[max(i for i in range(cap) if sent[i][:1] == b"\x1a"):]
        for rep in range(args.repeat_capture):
            t0, got = time.monotonic(), 0
            for p in block:
                payload, _ = patch_field6(p, args.field6)
                reply = s.cmd(payload)
                if reply[:2] != b"\x00\x00":
                    print(f"repeat {rep}: cmd {p[0]:02x} -> status {reply[:2][::-1].hex()}")
                if p[:1] == b"\x02":
                    got = len(s.read_data())
            print(f"repeat {rep}: capture block of {len(block)} commands -> {got} bytes in {time.monotonic() - t0:.2f}s")
        print("goodbye:", s.goodbye().hex())
    finally:
        s.close()


if __name__ == "__main__":
    main()
