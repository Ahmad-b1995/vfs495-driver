# gdb python: log how HP computes the HMAC-SHA256 that replaces each patch's RSA signature.
# Records hmac_sha256_init/update/final calls and scsReplaseRSASignatureByHMAC entries
# (symbols from the unstripped validity-sensor 4.5-136). Appends JSON events to $HS_OUT.
import gdb, os, json

OUT = os.environ["HS_OUT"]


def ev(kind, **kw):
    with open(OUT, "a") as f:
        f.write(json.dumps({"kind": kind, **kw}) + "\n")


def reg(name):
    return int(gdb.selected_frame().read_register(name)) & 0xFFFFFFFFFFFFFFFF


def mem(addr, n):
    return bytes(gdb.selected_inferior().read_memory(addr, n))


def caller():
    f = gdb.selected_frame().older()
    return f.name() if f is not None else None


class Init(gdb.Breakpoint):  # hmac_sha256_init(ctx, key, keylen)
    def stop(self):
        n = reg("rdx") & 0xFFFFFFFF
        ev("hmac_init", ctx=hex(reg("rdi")), keylen=n, key=mem(reg("rsi"), min(n, 256)).hex(), caller=caller())
        return False


class Update(gdb.Breakpoint):  # hmac_sha256_update(ctx, data, len)
    def stop(self):
        n = reg("rdx") & 0xFFFFFFFF
        ev("hmac_update", ctx=hex(reg("rdi")), len=n, data=mem(reg("rsi"), min(n, 8192)).hex())
        return False


class Final(gdb.Breakpoint):  # hmac_sha256_final(ctx, out)
    def stop(self):
        ctx, out = reg("rdi"), reg("rsi")

        class Done(gdb.FinishBreakpoint):
            def __init__(s):
                super().__init__(internal=True)

            def stop(s):
                ev("hmac_final", ctx=hex(ctx), mac=mem(out, 32).hex())
                return False

        Done()
        return False


class Replace(gdb.Breakpoint):
    def stop(self):
        ev("replace_sig", rdi=hex(reg("rdi")), rsi=hex(reg("rsi")), rdx=hex(reg("rdx")), rcx=hex(reg("rcx")),
           caller=caller())
        return False


Init("hmac_sha256_init")
Update("hmac_sha256_update")
Final("hmac_sha256_final")
Replace("scsReplaseRSASignatureByHMAC")
gdb.execute("run")
gdb.execute("quit")
