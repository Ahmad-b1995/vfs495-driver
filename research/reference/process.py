"""Turn HP reference recordings into matched pairs for the image-quality work.

For each captures/ref/NAME.K recording: decrypt the session, take the image key from the arming
command, decrypt and descramble the swipe stream, and save HP's assembled image next to it.
Outputs captures/refset/NAME.K.lines.raw (upstream line format) and NAME.K.hp.pgm.

Usage: python3 process.py NAME
"""
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "research" / "session"))
sys.path.insert(0, str(ROOT / "research" / "image"))
from decode import WIDTH, frames, load_perm  # noqa: E402
from decrypt import load_wire  # noqa: E402
from replay import tlv_fields  # noqa: E402

CMD_FINGER_STATE = "17"


def swipe_stream(transcript, wire):
    polls = [e for e in transcript if e["dir"] == "OUT" and e.get("plain") == CMD_FINGER_STATE]
    if not polls:
        return None, None
    cmds = [e for e in transcript if e["dir"] == "OUT" and e.get("kind") == "appdata"]
    arm = bytes.fromhex(cmds[cmds.index(polls[0]) - 1]["plain"])
    f6 = next(arm[o:o + n] for t, o, n in tlv_fields(arm) if t == 0x0006)
    last = polls[-1]["i"]
    nxt = next(e["i"] for e in transcript if e["i"] > last and e["dir"] == "OUT")
    stream = b"".join(wire[e["i"]][2] for e in transcript if last < e["i"] < nxt and e["ep"] == "02")
    return stream, f6


def main():
    name = sys.argv[1]
    ref, out = ROOT / "captures" / "ref", ROOT / "captures" / "refset"
    out.mkdir(exist_ok=True)
    perm = load_perm()
    for session in sorted(ref.glob(f"{name}.*.session.jsonl")):
        base = session.name[: -len(".session.jsonl")]
        wire_path = ref / f"{base}.wire.log"
        subprocess.run([sys.executable, str(ROOT / "research" / "session" / "decrypt.py"), str(session), str(wire_path)],
                       check=True, stdout=subprocess.DEVNULL)
        transcript = json.load(open(wire_path.with_suffix(".decrypted.json")))
        stream, f6 = swipe_stream(transcript, load_wire(wire_path))
        asms = sorted(ref.glob(f"{base}.asm.*"))
        if not stream or not asms:
            print(f"{base}: skipped (stream {len(stream or b'')} bytes, {len(asms)} assembled images)")
            continue
        usable = len(stream) - len(stream) % 16
        pt = Cipher(algorithms.AES(f6[:32]), modes.CBC(f6[32:48])).decryptor().update(stream[:usable])
        raw, _, skipped = frames(pt)
        lines = np.empty_like(raw)
        lines[:, perm] = raw
        with open(out / f"{base}.lines.raw", "wb") as f:
            for row in lines:
                f.write(WIDTH.to_bytes(2, "little") + row.tobytes())
        d = asms[-1].read_bytes()
        w, h = int.from_bytes(d[:4], "little"), int.from_bytes(d[4:8], "little")
        with open(out / f"{base}.hp.pgm", "wb") as f:
            f.write(f"P5\n{w} {h}\n255\n".encode() + d[8:8 + w * h])
        print(f"{base}: {len(lines)} lines ({skipped} stray bytes), HP image {w}x{h} ({len(asms)} built)")


if __name__ == "__main__":
    main()
