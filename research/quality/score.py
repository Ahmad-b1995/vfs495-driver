"""Score a set of fingerprint images pairwise with libfprint's matcher (the one fprintd uses).

Runs the installed `vfs495-match` (vfs495-fprint package): each image is enrolled on its own and
verified against every other image. Prints the score matrix and a summary. fprintd accepts a
score of 40 or more.

Usage: python3 score.py LABEL IMG.pgm [IMG.pgm ...]
       python3 score.py LABEL --genuine A.pgm ... --impostor B.pgm ...
With --impostor, images from the two groups are also scored against each other; those pairs
should never match.
"""
import re
import statistics
import subprocess
import sys
from pathlib import Path

THRESHOLD = 40
LINE = re.compile(r"enroll (\S+)\s+verify (\S+)\s+(-?\d+)/\d+")


def run_matcher(images):
    out = subprocess.run(["vfs495-match", *images], capture_output=True, text=True, timeout=3600).stdout
    return {(a, b): int(s) for a, b, s in LINE.findall(out)}


def summarize(label, scores, pairs):
    vals = [scores[p] for p in pairs if p in scores]
    if not vals:
        return f"{label}: no pairs"
    hits = sum(v >= THRESHOLD for v in vals)
    return (f"{label}: {len(vals)} pairs, {hits} match ({100 * hits / len(vals):.0f}%), "
            f"median {statistics.median(vals):.0f}, min {min(vals)}, max {max(vals)}")


def main():
    args = sys.argv[1:]
    label = args.pop(0)
    genuine, impostor = [], []
    if "--genuine" in args:
        g, i = args.index("--genuine"), args.index("--impostor") if "--impostor" in args else len(args)
        genuine, impostor = args[g + 1:i], args[i + 1:]
    else:
        genuine = args
    names = {str(Path(p).name): p for p in genuine + impostor}
    scores = run_matcher(genuine + impostor)
    g_names = [Path(p).name for p in genuine]
    i_names = [Path(p).name for p in impostor]

    width = max(len(n) for n in names)
    print(f"{'enrolled \\ verified':<{width}} " + " ".join(f"{k:>4}" for k in range(1, len(names) + 1)))
    order = g_names + i_names
    for a in order:
        row = [scores.get((a, b), -1) if a != b else None for b in order]
        print(f"{a:<{width}} " + " ".join("   ." if v is None else f"{v:4d}" for v in row))
    print()
    same = [(a, b) for a in g_names for b in g_names if a != b]
    print(summarize(f"[{label}] same finger", scores, same))
    if i_names:
        same_i = [(a, b) for a in i_names for b in i_names if a != b]
        cross = [(a, b) for a in order for b in order if (a in g_names) != (b in g_names)]
        print(summarize(f"[{label}] other finger, same finger", scores, same_i))
        print(summarize(f"[{label}] different fingers (must not match)", scores, cross))


if __name__ == "__main__":
    main()
