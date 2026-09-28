#!/usr/bin/env python3
"""Exercise the VFS495 libfprint driver through libfprint itself, without installing it.

Loads the TOD module from the build directory (FP_TOD_DRIVERS_DIR) and the command file from
captures/ (VFS495_COMMANDS), unless those are already set.

Usage:
  fp-test.py list                     show the devices libfprint sees
  fp-test.py open                     open and close the sensor (setup, handshake, close)
  fp-test.py capture N OUT_PREFIX [T] capture N swipes, writing OUT_PREFIX.K.pgm; cancel a
                                      swipe after T seconds (as fprintd does on timeout)
  fp-test.py enroll PRINT.bin         enroll a finger (several swipes), save the print
  fp-test.py verify PRINT.bin [N]     verify N times against a saved print
"""
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("FP_TOD_DRIVERS_DIR", str(ROOT / "build" / "driver"))
os.environ.setdefault("VFS495_COMMANDS", str(ROOT / "captures" / "vfs495-commands.bin"))

import gi  # noqa: E402

gi.require_version("FPrint", "2.0")
from gi.repository import FPrint, Gio, GLib  # noqa: E402


def say(msg):
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


# One context for the whole run, as fprintd keeps it: it owns the USB context the devices use.
CTX = None


def device():
    global CTX
    CTX = FPrint.Context()
    CTX.enumerate()
    devs = [d for d in CTX.get_devices() if d.get_driver() == "vfs495"]
    if not devs:
        sys.exit("no vfs495 device (is the module built, and the sensor free?)")
    return devs[0]


def retry_text(error):
    if error and error.domain == "fp - device - retry-quark":
        return f"retry: {FPrint.DeviceRetry(error.code).value_nick}"
    return str(error) if error else ""


def cmd_list():
    ctx = FPrint.Context()
    ctx.enumerate()
    for d in ctx.get_devices():
        print(d.get_driver(), d.get_device_id(), d.get_name(), d.get_scan_type().value_nick)


def cmd_open():
    d = device()
    t = time.monotonic()
    d.open_sync()
    say(f"opened in {time.monotonic() - t:.2f} s")
    d.close_sync()
    say("closed")


def cancel_after(seconds):
    """A cancellable that fires after `seconds` (None: never)."""
    c = Gio.Cancellable()
    if seconds:
        t = threading.Timer(seconds, c.cancel)
        t.daemon = True
        t.start()
    return c


def cmd_capture(n, prefix, timeout=None):
    d = device()
    d.open_sync()
    try:
        for k in range(1, n + 1):
            say(f"[{k}/{n}] swipe now")
            try:
                img = d.capture_sync(True, cancel_after(timeout))
            except GLib.Error as e:
                say(f"   {retry_text(e)}")
                continue
            w, h = img.get_width(), img.get_height()
            data = img.get_data()
            path = f"{prefix}.{k}.pgm"
            with open(path, "wb") as f:
                f.write(f"P5\n{w} {h}\n255\n".encode() + bytes(data))
            say(f"   {w}x{h}, {len(img.get_minutiae())} minutiae -> {path}")
    finally:
        d.close_sync()


def cmd_enroll(path):
    d = device()
    d.open_sync()
    try:
        template = FPrint.Print.new(d)
        template.set_finger(FPrint.Finger.RIGHT_INDEX)
        stages = d.get_nr_enroll_stages()
        say(f"enrolling: {stages} good swipes needed; swipe now")

        def progress(dev, stage, prt, user_data, error):
            if error:
                say(f"   {retry_text(error)}; swipe again")
            else:
                say(f"   stage {stage}/{stages} done" + ("; swipe again" if stage < stages else ""))

        enrolled = d.enroll_sync(template, None, progress, None)
        Path(path).write_bytes(enrolled.serialize())
        say(f"enrolled -> {path}")
    finally:
        d.close_sync()


def cmd_verify(path, n):
    d = device()
    d.open_sync()
    try:
        enrolled = FPrint.Print.deserialize(Path(path).read_bytes())
        results = []
        for k in range(1, n + 1):
            say(f"[{k}/{n}] swipe now")
            try:
                match, prt = d.verify_sync(enrolled)
                results.append(match)
                say(f"   {'MATCH' if match else 'no match'}")
            except GLib.Error as e:
                say(f"   {retry_text(e)}")
        say(f"{sum(results)} of {len(results)} swipes matched")
    finally:
        d.close_sync()


def main():
    a = sys.argv[1:]
    if a[:1] == ["list"]:
        cmd_list()
    elif a[:1] == ["open"]:
        cmd_open()
    elif a[:1] == ["capture"] and len(a) in (3, 4):
        cmd_capture(int(a[1]), a[2], float(a[3]) if len(a) == 4 else None)
    elif a[:1] == ["enroll"] and len(a) == 2:
        cmd_enroll(a[1])
    elif a[:1] == ["verify"] and len(a) in (2, 3):
        cmd_verify(a[1], int(a[2]) if len(a) == 3 else 5)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
