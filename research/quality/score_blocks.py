"""Score many fingerprint images pairwise without tripping libfprint's thermal protection.

`vfs495-match` runs libfprint's matcher in one process, and after a few hundred operations
libfprint disables the device "to prevent overheating", which loses scores. This splits the
images into blocks of about 5 and runs every pair of blocks as its own process (about 10 images,
90 pairs each), so every pair is scored in a fresh process.

The finger of an image is the part of its file name before the first dot
(e.g. rindex.hp3.pgm -> rindex). fprintd accepts a score of 40 or more.

Usage: python3 score_blocks.py [--json OUT.json] IMG.pgm [IMG.pgm ...]
--json saves every score as {"enrolled|verified": score}.
"""
import collections
import itertools
import json
import re
import statistics
import subprocess
import sys
from pathlib import Path

THRESHOLD = 40
BLOCK = 5
LINE = re.compile(r"enroll (\S+)\s+verify (\S+)\s+(-?\d+)/\d+")


def finger(name):
    return name.split(".")[0]


def main():
    args = sys.argv[1:]
    json_out = None
    if args[:1] == ["--json"]:
        json_out, args = args[1], args[2:]
    images = args
    blocks = [images[i:i + BLOCK] for i in range(0, len(images), BLOCK)]
    runs = list(itertools.combinations(range(len(blocks)), 2)) if len(blocks) > 1 else [(0, 0)]
    scores = {}
    for n, (a, b) in enumerate(runs, 1):
        batch = blocks[a] + (blocks[b] if b != a else [])
        out = subprocess.run(["vfs495-match", *batch], capture_output=True, text=True, timeout=1800)
        errors = out.stderr.count("overheating")
        got = 0
        for x, y, v in LINE.findall(out.stdout):
            v = int(v)
            if v >= 0:                      # -1 means the verification itself failed
                scores[(x, y)] = v
                got += 1
        print(f"run {n}/{len(runs)}: {len(batch)} images, {got} scores" + (f", {errors} overheating errors" if errors else ""),
              flush=True)

    names = [Path(p).name for p in images]
    expected = [(x, y) for x in names for y in names if x != y]
    missing = [p for p in expected if p not in scores]
    print(f"\nscored {len(expected) - len(missing)} of {len(expected)} pairs")
    groups = collections.defaultdict(list)
    for (x, y), v in scores.items():
        groups["same finger: " + finger(x) if finger(x) == finger(y) else "different fingers"].append(v)
    for k, v in sorted(groups.items()):
        hits = sum(s >= THRESHOLD for s in v)
        print(f"{k:28s} {len(v):4d} pairs, {hits:4d} match ({100 * hits / len(v):3.0f}%), "
              f"median {statistics.median(v):5.1f}, min {min(v)}, max {max(v)}")
    worst = sorted(((v, x, y) for (x, y), v in scores.items() if finger(x) != finger(y)), reverse=True)[:3]
    if worst:
        print("highest different-finger scores:", worst)
    if missing:
        print("missing pairs:", missing[:10], "..." if len(missing) > 10 else "")
    if json_out:
        json.dump({f"{x}|{y}": v for (x, y), v in scores.items()}, open(json_out, "w"), indent=0)


if __name__ == "__main__":
    main()
