"""Capture swipes with the open client only: arm the sensor with our own image key, wait for a
finger, decrypt and decode the stream.

The setup and arming commands come from a decrypted HP getprintwait recording (the index of
the arming command is found automatically: the last configuration command before the first
finger-state poll). Our own AES key and IV go into the arming command's type 0x0006 field.

Usage: python3 capture.py captures/wire.NAME.decrypted.json OUTNAME [--count N] [--timeout S]
Writes captures/OUTNAME.HHMMSS.K.dec (decrypted stream) and .overview.png per swipe.
"""
import argparse
import json
import secrets
import sys
import time
from pathlib import Path

import numpy as np
import usb.core
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

from replay import tlv_fields
from vfs495 import FLASH_KEY_OFFSET, ROOT, Vfs495

sys.path.insert(0, str(ROOT / "research" / "image"))
from decode import MAIN_COLS, frames, load_perm  # noqa: E402

CMD_FINGER_STATE, CMD_ABORT = 0x17, 0x04


def set_field6(payload, value):
    p = bytearray(payload)
    for t, off, n in tlv_fields(payload):
        if t == 0x0006 and n >= 64:
            p[off:off + 64] = value
    return bytes(p)


def load_plan(path):
    """Commands from a recording, each with whether the sensor sent data after it."""
    tr = json.load(open(path))
    plain, session = [], []
    for k, e in enumerate(tr):
        if e["dir"] != "OUT" or "plain" not in e:
            continue
        p = bytes.fromhex(e["plain"])
        data = False
        for later in tr[k + 1:]:
            if later["dir"] == "OUT":
                break
            data = data or later["ep"] == "02"
        if e["kind"] == "plain" and p[:1] != b"\x11":
            plain.append((p, data))
        elif e["kind"] == "plain":
            client_hello = p
        elif e["kind"] == "appdata":
            session.append((p, data))
    cmds = [p for p, _ in session]
    first_poll = cmds.index(bytes([CMD_FINGER_STATE]))
    arm = first_poll - 1
    # re-arm block: from the unload (1a) that precedes the calibration before arming
    rearm = max(i for i in range(arm - 1) if cmds[i][:1] == b"\x1a" and cmds[i + 1][:1] == b"\x06"
                and cmds[i + 2][:1] == b"\x02")
    return plain, client_hello, session[:arm], session[rearm:arm], cmds[arm]


def read_until_quiet(s, gap, limit):
    """Read the data endpoint until it stays silent for `gap` seconds or `limit` seconds pass.

    Swipe streams can contain short transfers mid-stream, so a short read is not an end marker."""
    chunks, t_end = [], time.monotonic() + limit
    last, max_gap, short = time.monotonic(), 0.0, 0
    while time.monotonic() < t_end:
        try:
            chunk = bytes(s.dev.read(0x82, 16384, int(gap * 1000)))
        except usb.core.USBTimeoutError:
            break
        now = time.monotonic()
        max_gap, last = max(max_gap, now - last), now
        short += len(chunk) < 16384
        chunks.append(chunk)
    read_until_quiet.stats = f"{len(chunks)} transfers, {short} short, max gap {max_gap * 1000:.0f} ms"
    return b"".join(chunks)


def wait_for_swipe(s, timeout, gap=0.3, limit=10):
    """Poll finger state; once the sensor streams, collect the stream. Returns (stream, state)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = s.cmd(bytes([CMD_FINGER_STATE]))
        if state[:2] != b"\x00\x00":
            raise RuntimeError(f"finger-state poll failed: {state.hex()}")
        # byte 0 after the status becomes 02 when the sensor starts a capture. Also probe the data
        # endpoint: never send another command while the sensor might be streaming.
        try:
            first = bytes(s.dev.read(0x82, 16384, 40))
        except usb.core.USBTimeoutError:
            first = b""
        if first or state[2] != 0:
            return first + read_until_quiet(s, gap, limit), state
        time.sleep(0.01)
    return b"", None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript")
    ap.add_argument("outname")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=30)
    args = ap.parse_args()

    plain, client_hello, setup, rearm, arm = load_plan(args.transcript)
    perm = load_perm()
    stamp = time.strftime("%H%M%S")
    out = ROOT / "captures"
    s = Vfs495()
    try:
        flash = None
        for p, expects_data in plain:
            r = s.cmd_plain(p)
            data = s.read_data(timeout=500) if expects_data else b""
            if len(data) == 4096:
                flash = data
        s.handshake(flash[FLASH_KEY_OFFSET:FLASH_KEY_OFFSET + 256], client_hello)
        t0 = time.monotonic()
        for p, expects_data in setup:
            r = s.cmd(set_field6(p, bytes(64)))
            if r[:2] != b"\x00\x00":
                raise RuntimeError(f"setup cmd {p[0]:02x} -> {r[:2][::-1].hex()}")
            if expects_data:
                s.read_data(timeout=300)
        print(f"session ready in {time.monotonic() - t0:.2f}s (setup {len(setup)} commands, re-arm {len(rearm)})")

        for k in range(args.count):
            if k:
                t1 = time.monotonic()
                for p, expects_data in rearm:
                    r = s.cmd(set_field6(p, bytes(64)))
                    if r[:2] != b"\x00\x00":
                        raise RuntimeError(f"re-arm cmd {p[0]:02x} -> {r[:2][::-1].hex()}")
                    if expects_data:
                        s.read_data(timeout=300)
                print(f"re-armed in {time.monotonic() - t1:.2f}s")
            key, iv = secrets.token_bytes(32), secrets.token_bytes(16)
            r = s.cmd(set_field6(arm, key + iv + secrets.token_bytes(16)))
            if r[:2] != b"\x00\x00":
                raise RuntimeError(f"arm -> {r[:2][::-1].hex()}")
            print(f"[{k + 1}/{args.count}] armed: swipe now")
            t_arm = time.monotonic()
            stream, state = wait_for_swipe(s, args.timeout)
            t_abort = time.monotonic()
            abort, tail = s.cmd_draining(bytes([CMD_ABORT]))
            print(f"   abort replied after {time.monotonic() - t_abort:.2f}s ({len(tail)} bytes drained)")
            if not stream:
                print(f"   no swipe within {args.timeout:.0f}s (abort -> {abort[:2][::-1].hex()})")
                continue
            usable = len(stream) - len(stream) % 16
            pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(stream[:usable])
            raw, seqs, skipped = frames(pt)
            lines = np.empty_like(raw)
            lines[:, perm] = raw
            name = f"{args.outname}.{stamp}.{k + 1}"
            (out / f"{name}.dec").write_bytes(pt)
            img = lines[:, :MAIN_COLS].astype(np.float32)
            img -= img.mean(0, keepdims=True)
            lo, hi = np.percentile(img, [1, 99])
            view = np.clip((img - lo) / (hi - lo) * 255, 0, 255).astype(np.uint8)
            Image.fromarray(view, "L").save(out / f"{name}.overview.png")
            print(f"   got {len(stream)} bytes {time.monotonic() - t_arm:.2f}s after arming; state {state.hex() if state else None};"
                  f" {len(lines)} frames ({read_until_quiet.stats}), {skipped} stray bytes; abort -> {abort[:2][::-1].hex()}; saved {name}")
        print("goodbye:", s.goodbye().hex())
    finally:
        s.close()


if __name__ == "__main__":
    main()
