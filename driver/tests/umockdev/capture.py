#!/usr/bin/env python3
"""One capture through libfprint, the image written as PGM (record.sh and replay.sh).

Usage: capture.py OUT.pgm
"""
import sys

import gi

gi.require_version("FPrint", "2.0")
from gi.repository import FPrint  # noqa: E402

ctx = FPrint.Context()
devices = [d for d in ctx.get_devices() if d.get_driver() == "vfs495"]
if not devices:
    sys.exit("no VFS495 reader found")
dev = devices[0]
dev.open_sync()
print("swipe your finger", file=sys.stderr)
image = dev.capture_sync(True)
dev.close_sync()
w, h = image.get_width(), image.get_height()
with open(sys.argv[1], "wb") as f:
    f.write(b"P5\n%d %d\n255\n" % (w, h) + bytes(image.get_data()))
print(f"captured {w}x{h}", file=sys.stderr)
