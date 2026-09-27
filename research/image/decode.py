"""Decode a decrypted VFS495 swipe stream into descrambled scan lines.

The stream is a sequence of 272-byte frames: `01 fe <seq u16 LE> <4 bytes>` then 264 pixels in
sensor column order. Pixels are descrambled with the upstream table
(../vfs495-linux/driver/vfs495_descramble.inc, out[perm[i]] = pixel[i]).

Writes OUT.lines.raw (upstream format: repeated [u16 len][264 bytes], usable with
../vfs495-linux/tools/reconstruct.py) and OUT.overview.png (all lines, main 200 columns).

Usage: python3 decode.py STREAM.dec OUT
"""
import re
import sys
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
FRAME, HEADER, WIDTH, MAIN_COLS = 272, 8, 264, 200


def load_perm():
    src = (ROOT.parent / "vfs495-linux" / "driver" / "vfs495_descramble.inc").read_text()
    body = src[src.index("{") + 1:src.rindex("}")]
    perm = [int(v) for v in re.findall(r"\d+", body)]
    assert sorted(perm) == list(range(WIDTH)), "descramble table is not a permutation"
    return np.array(perm)


def frames(stream):
    lines, seqs, skipped = [], [], 0
    i = 0
    while i + FRAME <= len(stream):
        if stream[i] == 0x01 and stream[i + 1] == 0xFE:
            seqs.append(int.from_bytes(stream[i + 2:i + 4], "little"))
            lines.append(np.frombuffer(stream[i + HEADER:i + FRAME], np.uint8))
            i += FRAME
        else:
            i += 1
            skipped += 1
    return np.array(lines), seqs, skipped


def main():
    stream = open(sys.argv[1], "rb").read()
    out = sys.argv[2]
    raw, seqs, skipped = frames(stream)
    gaps = sum(1 for a, b in zip(seqs, seqs[1:]) if (b - a) & 0xFFFF != 1)
    print(f"{len(raw)} frames, {skipped} bytes outside frames, {gaps} sequence gaps")

    perm = load_perm()
    lines = np.empty_like(raw)
    lines[:, perm] = raw

    with open(out + ".lines.raw", "wb") as f:
        for row in lines:
            f.write(WIDTH.to_bytes(2, "little") + row.tobytes())

    main_img = lines[:, :MAIN_COLS].astype(np.float32)
    main_img -= main_img.mean(0, keepdims=True)
    lo, hi = np.percentile(main_img, [1, 99])
    view = np.clip((main_img - lo) / (hi - lo) * 255, 0, 255).astype(np.uint8)
    Image.fromarray(view, "L").save(out + ".overview.png")
    print(f"wrote {out}.lines.raw and {out}.overview.png {view.shape}")


if __name__ == "__main__":
    main()
