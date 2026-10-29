#!/usr/bin/python3
"""vfs495-check: can fprintd use the VFS495 reader?

Checks that the reader is on USB, that the driver module is installed, and that libfprint
loads the module and finds the reader, the way fprintd does. Needs no root and does not
open the reader. The package runs it after every libfprint upgrade.

  vfs495-check            report, exit 0 if usable, 1 if not
  vfs495-check --quiet    only report problems
"""
import ctypes
import glob
import os
import subprocess
import sys

VID, PID = "138a", "003f"
MODULE_NAME = "libfprint-tod-vfs495.so"
FIX = "rebuild and reinstall the driver: cd @SOURCE_DIR@ && sudo driver/tools/install-driver.sh"


def reader_on_usb():
    for d in glob.glob("/sys/bus/usb/devices/*"):
        try:
            if open(f"{d}/idVendor").read().strip() == VID and open(f"{d}/idProduct").read().strip() == PID:
                return True
        except OSError:
            pass
    return False


def module_path():
    dirs = [os.environ["FP_TOD_DRIVERS_DIR"]] if os.environ.get("FP_TOD_DRIVERS_DIR") else \
        [f"{libdir}/libfprint-2/tod-1" for libdir in ("/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib")]
    for d in dirs:
        p = f"{d}/{MODULE_NAME}"
        if os.path.exists(p):
            return p
    return None


def enumerate_child():
    """Runs in a child process: libfprint's drivers as fprintd sees them, one per line."""
    fp = ctypes.CDLL("libfprint-2.so.2", mode=ctypes.RTLD_GLOBAL)
    fp.fp_context_new.restype = ctypes.c_void_p
    fp.fp_context_enumerate.argtypes = [ctypes.c_void_p]
    fp.fp_context_get_devices.restype = ctypes.c_void_p
    fp.fp_context_get_devices.argtypes = [ctypes.c_void_p]
    fp.fp_device_get_driver.restype = ctypes.c_char_p
    fp.fp_device_get_driver.argtypes = [ctypes.c_void_p]

    class GPtrArray(ctypes.Structure):
        _fields_ = [("pdata", ctypes.POINTER(ctypes.c_void_p)), ("len", ctypes.c_uint)]

    ctx = fp.fp_context_new()
    fp.fp_context_enumerate(ctx)
    arr = GPtrArray.from_address(fp.fp_context_get_devices(ctx))
    for i in range(arr.len):
        print(fp.fp_device_get_driver(arr.pdata[i]).decode(), flush=True)
    os._exit(0)   # skip teardown: nothing to clean up in a throwaway process


def libfprint_drivers():
    env = {**os.environ, "G_MESSAGES_DEBUG": "libfprint-tod"}
    try:
        r = subprocess.run([sys.executable, __file__, "--enumerate"], capture_output=True, text=True, env=env,
                           timeout=30)
    except subprocess.TimeoutExpired:
        return [], "libfprint did not finish enumerating within 30 s"
    notes = [l.split(": ", 2)[-1] for l in r.stderr.splitlines()
             if "Impossible to load" in l or "symbol" in l or "doesn't expose" in l or "CRITICAL" in l]
    if r.returncode != 0 and not notes:
        notes = [l for l in r.stderr.splitlines() if l.strip()][-1:] or [f"exit status {r.returncode}"]
    return r.stdout.split(), "; ".join(notes)


def main():
    if "--enumerate" in sys.argv:
        enumerate_child()
    quiet = "--quiet" in sys.argv
    problems = []
    if not reader_on_usb():
        problems.append("the VFS495 reader (138a:003f) is not on USB")
    module = module_path()
    if not module:
        problems.append(f"{MODULE_NAME} is not installed")
    elif reader_on_usb():
        drivers, notes = libfprint_drivers()
        if "vfs495" not in drivers:
            problems.append("libfprint does not load the driver" + (f" ({notes})" if notes else ""))
    if problems:
        print("vfs495-check: fingerprint login is not available:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        if module or not reader_on_usb():
            print(f"  To fix: {FIX}", file=sys.stderr)
        return 1
    if not quiet:
        print(f"vfs495-check: ok (reader on USB, {module} loaded by libfprint)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
