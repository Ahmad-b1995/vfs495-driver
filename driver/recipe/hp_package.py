"""Read HP's VFS495 Linux driver package (SoftPaq sp84530) without external tools.

sp84530.tar holds an RPM whose payload is a compressed cpio archive; the recipe needs
usr/sbin/validity-sensor from it. Everything is checked against known checksums, so a
different HP build is refused instead of producing wrong commands.
"""
import gzip
import hashlib
import io
import lzma
import struct
import tarfile
from pathlib import Path

SOFTPAQ_URL = "https://ftp.hp.com/pub/softpaq/sp84501-85000/sp84530.tar"
SOFTPAQ_MD5 = "9877c69c4f4b57a00f9e4afbcd9baacc"
RPM_NAME = "SP84530/Validity-Sensor-Setup-4.5-136.0.x86_64.rpm"
PROGRAM = "usr/sbin/validity-sensor"
PROGRAM_SHA256 = "089322826391fad7735407c28c986cf016ce5817637589235273ab7bde20d353"
BASE = 0x400000    # validity-sensor is not position independent


class PackageError(Exception):
    pass


def _rpm_payload(rpm):
    """The decompressed cpio payload of an RPM."""
    if rpm[:4] != b"\xed\xab\xee\xdb":
        raise PackageError("not an RPM")
    pos = 96                                     # lead
    for pad in (True, False):                    # signature header (8-aligned), then header
        if rpm[pos:pos + 3] != b"\x8e\xad\xe8":
            raise PackageError("bad RPM header")
        nindex, hsize = struct.unpack_from(">II", rpm, pos + 8)
        pos += 16 + 16 * nindex + hsize
        if pad:
            pos = (pos + 7) & ~7
    payload = rpm[pos:]
    if payload[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(payload)
    if payload[:2] == b"\x1f\x8b":
        return gzip.decompress(payload)
    return lzma.decompress(payload, format=lzma.FORMAT_ALONE)


def _cpio_file(cpio, name):
    """One file from a cpio archive in newc format."""
    pos = 0
    while pos + 110 <= len(cpio):
        hdr = cpio[pos:pos + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            raise PackageError("unexpected cpio format")
        size = int(hdr[54:62], 16)
        nlen = int(hdr[94:102], 16)
        fname = cpio[pos + 110:pos + 110 + nlen - 1].decode()
        start = (pos + 110 + nlen + 3) & ~3
        if fname == "TRAILER!!!":
            break
        if fname.lstrip("./") == name:
            return cpio[start:start + size]
        pos = (start + size + 3) & ~3
    raise PackageError(f"{name} not in the package")


def load_program(path):
    """validity-sensor from sp84530.tar, the RPM inside it, or the program itself."""
    data = Path(path).read_bytes()
    if data[:4] == b"\x7fELF":
        program = data
    else:
        if data[:4] != b"\xed\xab\xee\xdb":
            if hashlib.md5(data).hexdigest() != SOFTPAQ_MD5:
                raise PackageError(f"{path} is not HP's SoftPaq sp84530 (MD5 mismatch)")
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                data = tar.extractfile(RPM_NAME).read()
        program = _cpio_file(_rpm_payload(data), PROGRAM)
    if hashlib.sha256(program).hexdigest() != PROGRAM_SHA256:
        raise PackageError("validity-sensor is not version 4.5-136 as shipped by HP")
    return program


def patch_table(program):
    """HP's firmware patches: entries of 0x60 bytes with version at +0x20, id at +0x2c, size at
    +0x44 and a pointer at +0x48 to the patch (02 00, signature length u16, signature, body)."""
    out = []
    for e in range(0, len(program) - 0x60, 8):
        ptr = struct.unpack_from("<Q", program, e + 0x48)[0]
        if not BASE <= ptr < BASE + len(program):
            continue
        size = struct.unpack_from("<H", program, e + 0x44)[0]
        d = program[ptr - BASE:ptr - BASE + size]
        if size > 260 and d[:2] == b"\x02\x00" and struct.unpack_from("<H", d, 2)[0] == 0x100:
            out.append({"id": struct.unpack_from("<I", program, e + 0x2c)[0], "version": program[e + 0x20],
                        "data": d, "entry": e})
    return out


def find_patch(table, pid, version, size, sha256_prefix):
    """The patch with this id, version and size (ids and versions alone repeat across lists)."""
    for e in table:
        if (e["id"], e["version"], len(e["data"])) == (pid, version, size):
            if not hashlib.sha256(e["data"]).hexdigest().startswith(sha256_prefix):
                raise PackageError(f"patch {pid:#x} v{version} differs from the expected one")
            return e["data"]
    raise PackageError(f"patch {pid:#x} v{version} ({size} bytes) not in HP's patch table")

