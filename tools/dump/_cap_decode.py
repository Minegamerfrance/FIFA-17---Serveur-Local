"""Disasm PreAuthResponse decode/ctor 0x146df37a0 — field visits."""
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
    d = load(va, 80)
    if not d:
        return None
    try:
        t = d.split(b"\x00", 1)[0].decode("ascii")
        return t if t.isprintable() else None
    except Exception:
        return None


def dis(va, n=0x600):
    data = load(va, n)
    print(f"===== decode @{va:#x} RVA={va-0x140000000:#x} =====")
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
            ann = f"  ; ->{dest:#x}" + (f' "{s}"' if s and 1 < len(s) < 48 else "")
        # annotate tag immediates that look like TDF tags (often in edx/r8d)
        print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}{ann}")
        if insn.mnemonic == "ret":
            break


# size constants
print("size PreAuthResponse:", hex((0xC346A20F + 0x3CB96039) & 0xFFFFFFFF))
print("size PreAuthRequest:", hex((0xC34FA20F + 0x3CB05F49) & 0xFFFFFFFF))

dis(0x146DF37A0, 0x700)

# Also look at member name table at 0x144875600 area — '0xb' might be tag count
print("\n=== scan for 4-char field name cstrings near PreAuthResponse ===")
# Search ASRC as standalone near 0x143895xxx
base = 0x14354B000
blob = Path("rx-0006.bin").read_bytes()
region_va = 0x143890000
off = region_va - base
chunk = blob[off : off + 0x8000]
i = 0
while i < len(chunk) - 5:
    if all(65 <= chunk[i + k] <= 90 for k in range(4)) and chunk[i + 4] == 0:
        # 4-letter uppercase tag
        tag = chunk[i : i + 4].decode()
        if tag in (
            "ANON",
            "ASRC",
            "CIDS",
            "CNGN",
            "CONF",
            "INST",
            "MINR",
            "NASP",
            "PILD",
            "PLAT",
            "PTAG",
            "QOSS",
            "RSRC",
            "SVER",
            "CDAT",
            "CINF",
            "FCCR",
            "LADD",
            "BWPS",
            "LTPS",
            "SVID",
            "LNP",
        ):
            print(f"  {region_va + i:#x}: {tag}")
    i += 1
