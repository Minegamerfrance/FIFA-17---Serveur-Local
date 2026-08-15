"""Disasm PreAuth callback registration region + Heat2 strings."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
import json

base14 = 0x1460ed000
data14 = Path("rx-0014.bin").read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_64)
ranges = {
    r["file"]: (int(r["base"], 16), r["size"])
    for r in json.loads(Path("rx-meta.json").read_text())["ranges"]
}


def load(va, n):
    for f, (b, s) in ranges.items():
        if b <= va < b + s:
            return Path(f).read_bytes()[va - b : va - b + n]
    return None


def s_at(va):
    d = load(va, 96)
    if not d:
        return None
    try:
        return d.split(b"\x00", 1)[0].decode("ascii")
    except Exception:
        return None


va = 0x146E1E2E0
blob = data14[va - base14 : va - base14 + 0x200]
print("===== register/callback region =====")
for insn in md.disasm(blob, va):
    ann = ""
    raw = bytes(insn.bytes)
    if (
        insn.mnemonic == "lea"
        and "rip" in insn.op_str
        and len(raw) >= 7
        and raw[0] in (0x48, 0x4C)
    ):
        dest = insn.address + len(raw) + struct.unpack_from("<i", raw, 3)[0]
        s = s_at(dest)
        if s and s.isprintable() and len(s) > 2:
            ann = f'  ; ->{dest:#x} "{s}"'
        else:
            ann = f"  ; ->{dest:#x} rva={dest - 0x140000000:#x}"
    print(f"{insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}{ann}")
    if insn.address >= 0x146E1E420:
        break

for v in [0x14354B5F0, 0x143883138]:
    print(hex(v), repr(s_at(v)))

print("\n===== Heat2 / decode error strings =====")
needles = [
    b"[Heat2Decoder]",
    b"[Heat2Encoder]",
    b"Heat2Decoder::",
    b"Type contains unknown member",
    b"Map key value is not equal",
]
for f, (b, _s) in ranges.items():
    blob = Path(f).read_bytes()
    for n in needles:
        idx = 0
        c = 0
        while c < 6:
            i = blob.find(n, idx)
            if i < 0:
                break
            end = blob.find(b"\x00", i)
            s = blob[i : end if end > i else i + 80]
            try:
                print(f"{b + i:#x}: {s.decode('ascii', 'replace')}")
            except Exception:
                pass
            idx = i + 1
            c += 1
