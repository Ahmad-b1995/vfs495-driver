# gdb python: log every command HP's validity-sensor sends (scsSensorSend*_V4) with its call
# chain, plus calls to functions that look up, convert or calibrate configuration programs.
# Only logs; never changes behaviour. Appends JSON lines to $TRACE_OUT.
import json
import os

import gdb

OUT = os.environ["TRACE_OUT"]
BUILDERS = [
    "scsFalconConvertPrintConfig", "scsFalconFindPrintConfig", "scsFalconFindWoeConfig",
    "scsSensorFindPrintConfiguration", "scsSensorFindWoeConfiguration", "scsSensorGetDefaultPrintConfiguration",
    "scsSensorClonePrintConfiguration", "scsSensorSetPrintParamBlobToPrintConfig",
    "scsSensorSetUint32DataToPrintConfig", "scsSensorGetUint32DataFromPrintConfig",
    "scsFalconCalWoe", "scsSensorFalconWOESetup", "_scsSensorFalconWOESetup", "scsSensorFalconCalGetWoeSetupEx",
    "scsSensorGetWoeThreshold", "scsSensorSetWoeThreshold", "scsSensorGetWoeThresholdDelta",
    "scsSensorSetWoeThresholdDelta", "scsSensorCalibrate", "scsSensorFalconCalibrate", "idsSensorSetPrintConfig",
]
seq = {"n": 0}


def log(kind, **kw):
    seq["n"] += 1
    with open(OUT, "a") as f:
        f.write(json.dumps({"seq": seq["n"], "kind": kind, **kw}) + "\n")


def chain(depth=10):
    names, f = [], gdb.selected_frame().older()
    while f is not None and len(names) < depth:
        names.append(f.name() or hex(f.pc()))
        f = f.older()
    return names


def regs():
    fr = gdb.selected_frame()
    return {r: hex(int(fr.read_register(r)) & 0xFFFFFFFFFFFFFFFF) for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")}


class Logged(gdb.Breakpoint):
    def __init__(self, name, kind):
        super().__init__(name, internal=True)
        self.fn, self.kind = name, kind

    def stop(self):
        log(self.kind, fn=self.fn, callers=chain(), args=regs())
        return False


names = [l.split()[-1] for l in gdb.execute("info functions ^scsSensorSend.*_V4$", to_string=True).splitlines()
         if l.strip().endswith("_V4")]
for n in sorted(set(names)):
    Logged(n, "send")
for n in BUILDERS:
    try:
        Logged(n, "builder")
    except gdb.error:
        pass
gdb.execute("run")
gdb.execute("quit")
