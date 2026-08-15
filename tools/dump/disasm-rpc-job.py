"""Offline disasm RpcDispatch / RpcJob neighborhood in FIFA17.exe."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct

exe = Path(r"C:\Users\Mineg\Desktop\serveur fifa 17\FIFA 17\FIFA17.exe")
data = exe.read_bytes()


def pe_map(buf):
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", buf, coff + 2)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", buf, opt)[0]
    assert magic == 0x20B
    image_base = struct.unpack_from("<Q", buf, opt + 24)[0]
    sec_off = opt + struct.unpack_from("<H", buf, coff + 16)[0]
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        va, rsz, raw, vsz = struct.unpack_from("<IIII", buf, o + 8)[0:4]
        # correct unpack
        vsz, va, rsz, raw = struct.unpack_from("<IIII", buf, o + 8)
        secs.append((va, rsz, raw, vsz))
    return image_base, secs


def rva_to_off(rva, secs):
    for va, rsz, raw, vsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None


image_base, secs = pe_map(data)
md = Cs(CS_ARCH_X86, CS_MODE_64)


def disasm_rva(rva, size=0x200, label=""):
    off = rva_to_off(rva, secs)
    if off is None:
        print(f"NOMAP {label} {rva:#x}")
        return []
    blob = data[off : off + size]
    print(f"\n=== {label} RVA {rva:#x} VA {image_base + rva:#x} ===")
    calls = []
    for insn in md.disasm(blob, image_base + rva):
        print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic == "call":
            calls.append((insn.address - image_base, insn.op_str))
        if insn.address >= image_base + rva + size - 0x10:
            break
    print("CALL_RVAS:", [(f"{c:#x}", t) for c, t in calls])
    return calls


for rva, lab, sz in [
    (0x6DB5A60, "RpcDispatch", 0x200),
    (0x6DB5660, "RpcJob_send", 0x220),
    (0x6DB57D0, "near_0x6db57d0", 0x120),
    (0x6DB5900, "near_0x6db5900", 0x160),
]:
    disasm_rva(rva, sz, lab)
