# gdb python: record one HP swipe as a reference. Installs the session breakpoints from
# ../handshake/dump_session.py (keys for decrypting the traffic) plus a breakpoint that saves
# HP's motion-compensated assembled image at IRqualityDetermination (0x4689b0, address and
# layout from saifulmd0/vfs495-linux runtime/harvest_assembled.py).
# Writes <u32 w><u32 h><pixels> to $REF_ASM_OUT.N for each assembled image HP builds.
import os

import gdb

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ["HS_NO_RUN"] = "1"
gdb.execute(f"source {HERE}/../handshake/dump_session.py")

# Distinct name: this runs in the same namespace as dump_session.py, which uses OUT.
ASM_OUT = os.environ["REF_ASM_OUT"]
hits = {"n": 0}


class Assembled(gdb.Breakpoint):
    def stop(self):
        inf = gdb.selected_inferior()
        ctx = int(gdb.selected_frame().read_register("rdi")) & 0xFFFFFFFFFFFFFFFF
        try:
            img = int.from_bytes(inf.read_memory(ctx + 0xA8, 8), "little")
            if not img:
                return False
            w = int.from_bytes(inf.read_memory(img - 0x44, 4), "little")
            h = int.from_bytes(inf.read_memory(img - 0x48, 4), "little")
            if not (0 < w <= 5000 and 0 < h <= 20000 and w * h <= 4_000_000):
                return False
            px = bytes(inf.read_memory(img, w * h))
        except gdb.MemoryError:
            return False
        hits["n"] += 1
        with open(f"{ASM_OUT}.{hits['n']}", "wb") as f:
            f.write(w.to_bytes(4, "little") + h.to_bytes(4, "little") + px)
        return False


Assembled("*0x4689b0")
gdb.execute("run")
gdb.execute("quit")
