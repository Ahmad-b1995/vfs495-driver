"""Stitch VFS495 swipe scan lines into a fingerprint image using the sensor's two sensing lines.

Each 264-pixel line holds the main sensing line (columns 0-199) and a shorter auxiliary line
(columns 200-263, inverted polarity) that sits ahead of the main line in the swipe direction and
sees roughly main columns 68..131. A ridge reaches the main line `lag` lines after the aux line,
so the finger moves D / lag pixels per line, where D is the distance between the two lines.

Pipeline: find the finger region, estimate the lag per line by correlating the aux line with
later main lines (search over lag and a small horizontal offset for drift), smooth it, fill gaps
where no confident lag exists (entry, exit, pauses), place each main line at its cumulative
position and resample to evenly spaced rows.

Usage: python3 assemble.py OUT_DIR LINES.raw [...] [--d D]
Writes OUT_DIR/<name>.pgm (200 wide, ridges dark).
"""
import argparse
from pathlib import Path

import numpy as np
from scipy.ndimage import gaussian_filter, median_filter, uniform_filter1d

MAIN, AUX_START, AUX_W = 200, 200, 64
MAX_LAG, WINDOW = 250, 24
MIN_TRUSTED_LAG, MAX_TRUSTED_LAG = 8, 245   # outside this, matches are crosstalk or search-edge artifacts
RUN_GAP = 120                               # trusted readings closer than this belong to one swipe
D_DEFAULT = 8.0   # aux-to-main line distance in pixels, calibrated against HP's assembled images
C0_RANGE = range(58, 80)


def load(path):
    d = open(path, "rb").read()
    rows, i = [], 0
    while i + 2 <= len(d):
        n = int.from_bytes(d[i:i + 2], "little")
        rows.append(np.frombuffer(d[i + 2:i + 2 + n], np.uint8))
        i += 2 + n
    return np.array(rows, dtype=np.float32)


def bad_columns(x, z=6.0):
    """Columns whose response differs strongly from their neighbours (dead or hot pixels)."""
    col_std = x.std(0)
    ref = median_filter(col_std, size=7, mode="nearest")
    dev = np.abs(col_std - ref) / (np.median(np.abs(col_std - ref)) * 1.4826 + 1e-6)
    # a healthy column also tracks its neighbours over time
    nb = np.zeros(x.shape[1])
    for c in range(1, x.shape[1] - 1):
        a, b = x[:, c] - x[:, c].mean(), (x[:, c - 1] + x[:, c + 1]) / 2
        b = b - b.mean()
        nb[c] = (a * b).sum() / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-6)
    nb[0], nb[-1] = nb[1], nb[-2]
    return np.where((dev > z) | (nb < np.median(nb) - 0.6))[0]


def repair_columns(x, bad):
    """Replace bad columns by interpolating from the nearest good ones, row by row."""
    if len(bad) == 0:
        return x
    x = x.copy()
    good = np.setdiff1d(np.arange(x.shape[1]), bad)
    for r in range(x.shape[0]):
        x[r, bad] = np.interp(bad, good, x[r, good])
    return x


def highpass(x):
    x = x - x.mean(0)                      # fixed per-column pattern (sensor gain)
    return x - uniform_filter1d(x, 9, axis=1)


def unit_rows(x):
    x = x - x.mean(1, keepdims=True)
    return x / (np.linalg.norm(x, axis=1, keepdims=True) + 1e-6)


def finger_region(main_hp):
    energy = gaussian_filter(np.abs(main_hp).mean(1), 15)
    base = np.median(energy[-len(energy) // 4:]) if len(energy) > 400 else energy.min()
    on = np.where(energy > base + 0.12 * (energy.max() - base))[0]
    return (on.min(), on.max() + 1) if len(on) else (0, len(energy))


def estimate_lag(lines, window=WINDOW):
    """Per-line lag (in lines) between aux and main, with a confidence in [0, 1]."""
    aux = unit_rows(-highpass(lines[:, AUX_START:AUX_START + AUX_W]))
    hp = highpass(lines[:, :MAIN])
    n = len(lines)
    best = np.full(n, -1.0, np.float32)
    lag = np.zeros(n, np.int32)
    for c0 in C0_RANGE:
        m = unit_rows(hp[:, c0:c0 + AUX_W])
        for tau in range(1, MAX_LAG + 1):
            p = np.full(n, -1.0, np.float32)
            p[:n - tau] = (aux[:n - tau] * m[tau:]).sum(1)
            c = uniform_filter1d(p, window)
            better = c > best
            best[better], lag[better] = c[better], tau
    return lag, best


def stationary(main_hp, k=20, thr=0.8):
    """True where a line nearly repeats the line k earlier: the finger is not moving."""
    u = unit_rows(main_hp)
    sim = np.ones(len(u), np.float32)
    sim[k:] = (u[k:] * u[:-k]).sum(1)
    return uniform_filter1d(sim, 15) > thr


def positions(lag, conf, still, lo, hi, d, conf_min=0.3):
    """Returns (first, last, y): the span of lines that form the print and their positions.

    A lag is trusted when it is confident, physically plausible, the finger is moving, and it
    points at a main line where the finger is also moving (while the finger rests, every aux
    line matches the same frozen main line and produces a fake, steadily shrinking lag). The
    print is the longest run of trusted lags. Between trusted lags the lag is interpolated.
    Before the first and after the last trusted lag, the main line can only see the finger for
    about one lag's worth of lines, so the print is extended by that much at each end.
    """
    n = len(lag)
    t = np.arange(n)
    target = np.clip(t + lag, 0, n - 1)
    trusted = ((conf >= conf_min) & ~still & ~still[target]
               & (lag >= MIN_TRUSTED_LAG) & (lag <= MAX_TRUSTED_LAG))
    trusted[:lo] = trusted[hi:] = False
    ok = np.where(trusted)[0]
    if len(ok) < 10:
        raise ValueError("no usable motion estimate in this swipe")
    # longest run of trusted readings, allowing gaps shorter than RUN_GAP
    breaks = np.where(np.diff(ok) > RUN_GAP)[0]
    starts = np.concatenate([[0], breaks + 1])
    ends = np.concatenate([breaks, [len(ok) - 1]])
    best = int(np.argmax(ends - starts))
    ok = ok[starts[best]:ends[best] + 1]
    smooth = median_filter(lag[ok].astype(np.float32), size=61, mode="nearest")
    first = max(lo, int(ok[0] - smooth[0]))
    last = min(hi, int(ok[-1] + smooth[-1]) + 1)
    idx = np.arange(first, last)
    filled = np.interp(idx, ok, smooth)
    speed = d / filled
    speed[still[first:last]] = 0.0   # finger resting: no advance
    return first, last, np.concatenate([[0.0], np.cumsum(speed)[:-1]])


def resample(main_hp, y):
    """Evenly spaced rows from lines at positions y.

    Every line is added to its nearest output row, so rows the finger crossed slowly average
    several lines. Rows no line landed on (fast motion) are interpolated from their neighbours."""
    rows = int(np.floor(y[-1] + 0.5)) + 1
    bins = np.clip(np.floor(y + 0.5).astype(int), 0, rows - 1)
    acc = np.zeros((rows, main_hp.shape[1]), np.float64)
    cnt = np.zeros(rows)
    np.add.at(acc, bins, main_hp)
    np.add.at(cnt, bins, 1)
    filled = cnt > 0
    out = np.zeros_like(acc)
    out[filled] = acc[filled] / cnt[filled, None]
    r = np.arange(rows)
    for c in range(out.shape[1]):
        out[~filled, c] = np.interp(r[~filled], r[filled], out[filled, c])
    return out.astype(np.float32)


def to_u8(img):
    """Global contrast stretch only."""
    lo, hi = np.percentile(img, [1, 99])
    return np.clip((img - lo) / (hi - lo) * 255, 0, 255).astype(np.uint8)


def ridge_period(img, axis):
    """Dominant ridge period (pixels) along an axis, from the averaged power spectrum."""
    x = img - img.mean()
    spec = np.abs(np.fft.rfft(x, axis=axis)) ** 2
    spec = spec.mean(axis=1 - axis)
    n = x.shape[axis]
    freqs = np.fft.rfftfreq(n)
    band = (freqs > 1 / 25) & (freqs < 1 / 5)
    return 1 / freqs[band][np.argmax(spec[band])]


def assemble(lines, d=D_DEFAULT, window=WINDOW, conf_min=0.3):
    main = lines[:, :MAIN]
    bad = bad_columns(highpass(main))
    hp = highpass(repair_columns(main, bad))
    lo, hi = finger_region(hp)
    gain = hp[lo:hi].std(0)
    hp = hp / (gain / np.median(gain) + 1e-3)       # equalise column gain inside the finger area
    lag, conf = estimate_lag(lines, window)
    still = stationary(hp)
    first, last, y = positions(lag, conf, still, lo, hi, d, conf_min)
    # Output from near-raw pixels: the matcher does its own enhancement, and spatial filtering
    # lowers match rates. Only per-column offset and gain are corrected, from the print area.
    raw = repair_columns(main, bad)[first:last]
    raw = raw - np.median(raw, axis=0)
    spread = np.median(np.abs(raw), axis=0) + 1e-3
    img = resample(raw / (spread / np.median(spread)), y)
    return img, {"lines": (int(first), int(last)), "rows": img.shape[0], "bad": bad.tolist(),
                 "median_lag": float(np.median(lag[lo:hi][conf[lo:hi] >= 0.3])) if (conf[lo:hi] >= 0.3).any() else None,
                 "confident": float((conf[lo:hi] >= 0.3).mean()),
                 "still": float(still[lo:hi].mean())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("lines", nargs="+")
    ap.add_argument("--d", type=float, default=D_DEFAULT, help="aux-to-main line distance in pixels")
    ap.add_argument("--window", type=int, default=WINDOW, help="lines per lag-correlation window")
    ap.add_argument("--conf", type=float, default=0.3, help="minimum correlation to trust a lag")
    args = ap.parse_args()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for path in args.lines:
        lines = load(path)
        name = Path(path).name.replace(".lines.raw", "")
        d = args.d
        try:
            img, info = assemble(lines, d, args.window, args.conf)
        except ValueError as e:
            print(f"{name}: {e}")
            continue
        u8 = to_u8(img)
        with open(out / f"{name}.pgm", "wb") as f:
            f.write(f"P5\n{u8.shape[1]} {u8.shape[0]}\n255\n".encode() + u8.tobytes())
        print(f"{name}: D={d:.2f} finger lines {info['lines']}, median lag {info['median_lag']}, "
              f"confident {100 * info['confident']:.0f}%, still {100 * info['still']:.0f}% -> {info['rows']} rows")


if __name__ == "__main__":
    main()
