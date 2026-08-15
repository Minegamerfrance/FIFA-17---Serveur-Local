"""Disasm PreAuthResponse visit/decode @ 0x146df24e0 and member table @ 0x144873d20."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
import json

ranges = {
    r["file"]: (int(r["base"], 16), r["size"])
    for r in json.loads(Path("rx-meta.json").read_text())["ranges"]
}
md = Cs(CS_ARCH_X86, CS_MODE_64)


def load(va, n):
    for f, (b, s) in ranges.items():
        if b <= va < b + s:
            return Path(f).read_bytes()[va - b : va - b + n]
    return None


def s_at(va):
    d = load(va, 64)
    if not d:
        return None
    try:
        return d.split(b"\x00", 1)[0].decode("ascii")
    except Exception:
        return None


def dis(va, n=0x300, title=""):
    data = load(va, n)
    print(f"\n===== {title or hex(va)} RVA={va-0x140000000:#x} =====")
    for insn in md.disasm(data, va):
        ann = ""
        raw = bytes(insn.bytes)
        if (
            insn.mnemonic == "lea"
            and "rip" in insn.op_str
            and len(raw) >= 7
            and raw[0] in (0x48, 0x4C)
            and raw[1] == 0x8D
        ):
            dest = insn.address + len(raw) + struct.unpack_from("<i", raw, 3)[0]
            s = s_at(dest)
            ann = f"  ; ->{dest:#x}" + (f' "{s}"' if s and s.isprintable() and 2 < len(s) < 40 else "")
        print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}{ann}")
        if insn.mnemonic == "ret":
            break


# Member table at 0x144873d20 — typically array of {tag, type, offset, ...}
print("=== member table qwords @ 0x144873d20 ===")
tab = load(0x144873D20, 0x200)
for i in range(0, 0x200, 8):
    q = struct.unpack_from("<Q", tab, i)[0]
    s = s_at(q) if 0x140000000 < q < 0x150000000 else None
    extra = f" '{s}'" if s else ""
    print(f"  {0x144873D20 + i:#x}: {q:#018x}{extra}")

dis(0x146DF24E0, 0x280, "PreAuthResponse_visit")
dis(0x146DF2420, 0x180, "PreAuthRequest_visit")

# Also dump factory/vtable at 0x144873d20 - maybe it's a pointer to registration fn
# Look at 0x146df24e0 callers
FN = 0x146DF24E0
print("\n=== E8 callers of visit ===")
for f, (b, s) in ranges.items():
    blob = Path(f).read_bytes()
    for i in range(len(blob) - 5):
        if blob[i] != 0xE8:
            continue
        dest = b + i + 5 + struct.unpack_from("<i", blob, i + 1)[0]
        if dest == FN:
            print(f"  {b + i:#x}")
