# gdb python: record one HP handshake end to end (validity-sensor 4.5-136 addresses,
# taken from saifulmd0/vfs495-linux runtime/dump_*.py). Appends JSON events to $HS_OUT.
import gdb, os, json

OUT = os.environ["HS_OUT"]
seq = {"n": 0}


def ev(kind, **kw):
    seq["n"] += 1
    with open(OUT, "a") as f:
        f.write(json.dumps({"seq": seq["n"], "kind": kind, **kw}) + "\n")


def reg(name):
    return int(gdb.selected_frame().read_register(name)) & 0xFFFFFFFFFFFFFFFF


def mem(addr, n):
    return bytes(gdb.selected_inferior().read_memory(addr, n))


def ptr(addr):
    return int.from_bytes(mem(addr, 8), "little")


class RsaKey(gdb.Breakpoint):  # key setup: bits=RDI, exp*=RSI, mod*=RDX
    def stop(self):
        ev("rsakey", bits=reg("rdi") & 0xFFFFFFFF, exp=mem(reg("rsi"), 4).hex(),
           modulus=mem(reg("rdx"), 256).hex())
        return False


class HsUpdate(gdb.Breakpoint):  # handshake hash update: data=RSI, len=RDX
    def stop(self):
        n = reg("rdx") & 0xFFFFFFFF
        if 0 < n <= 4096:
            ev("hs_update", data=mem(reg("rsi"), n).hex())
        else:
            ev("hs_update_skipped", n=n)
        return False


class MasterGen(gdb.Breakpoint):  # scsSSLMasterSecretGenerate(ctx=RDI, premaster=RSI)
    def stop(self):
        ctx = reg("rdi")
        ev("premaster", premaster=mem(reg("rsi"), 48).hex(),
           rand_0x38=mem(ptr(ctx + 0x38), 32).hex(), rand_0x40=mem(ptr(ctx + 0x40), 32).hex())
        return False


class RsaEnc(gdb.Breakpoint):  # scsSSLRsaPublicEncrypt(ctx=RDI): master + keyblock filled
    def stop(self):
        ctx = reg("rdi")
        ev("keys", master=mem(ctx + 8, 48).hex(), keyblock=mem(ctx + 0x48, 136).hex())
        return False


class FinishedWrite(gdb.Breakpoint):  # scsSSLFinishedWrite(ctx=RDI, out=RSI)
    def stop(self):
        ctx, out = reg("rdi"), reg("rsi")
        master = mem(ctx + 8, 48).hex()

        class Done(gdb.FinishBreakpoint):
            def __init__(s):
                super().__init__(internal=True)

            def stop(s):
                ev("finished", master=master, out=mem(out, 40).hex())
                return False

        Done()
        return False



class RsaOp(gdb.Breakpoint):  # palRsaPublicKeyOperation: input block=RSI (per runtime/dump_em3.py)
    def stop(self):
        ev("rsa_op", em=mem(reg("rsi"), 256).hex(), rdi=hex(reg("rdi")), rdx=hex(reg("rdx")), rcx=hex(reg("rcx")))
        return False

RsaOp("*0x52b770")
RsaKey("*0x51fac0")
HsUpdate("*0x5132b0")
MasterGen("*0x5139c0")
RsaEnc("*0x5161c0")
FinishedWrite("*0x513920")
if os.environ.get("HS_NO_RUN") != "1":  # set by scripts that add breakpoints before running
    gdb.execute("run")
    gdb.execute("quit")
