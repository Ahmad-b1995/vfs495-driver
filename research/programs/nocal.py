# gdb python: run HP's session with calibration disabled, on top of the session recorder.
# HP reads "calibrationEnable" with palGetPersistentDataLongValue(path, name, default, out);
# the persistent store is empty, so the default (RDX) is what HP gets. Setting it to 0 makes
# scsSensorFalconCalibrate skip calibration and use scsFalconCalSetDefaults.
import os

import gdb

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ["HS_NO_RUN"] = "1"
gdb.execute(f"source {HERE}/../handshake/dump_session.py")


class CalibrationOff(gdb.Breakpoint):
    def stop(self):
        frame = gdb.selected_frame()
        name_ptr = int(frame.read_register("rsi")) & 0xFFFFFFFFFFFFFFFF
        name = gdb.selected_inferior().read_memory(name_ptr, 64).tobytes().split(b"\0")[0]
        if name == b"calibrationEnable":
            gdb.execute("set $rdx = 0")
            print("vfs495: calibrationEnable default forced to 0")
        return False


CalibrationOff("palGetPersistentDataLongValue")
gdb.execute("run")
gdb.execute("quit")
