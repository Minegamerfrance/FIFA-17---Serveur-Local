"""Xref Heat2Decoder string + find decode entry; also member visit helpers."""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
import json

ranges = {
    r["file"]: (int(r["base"], 16), r["size"])
    for r in json.loads(Path("rx-meta.json").read_text())["ranges"]
}
md = Cs(CS_ARCH_X86, CS_MODE_64)
H2 = 0x143884730  # Heat2Decoder
UNK = 0x143AC0C98  # [XmlDecoder].readValue: Type contains unknown member.
# Note: Heat2 may share XmlDecoder path or have own

print("=== RIP-rel to Heat2Decoder / unknown-member ===")
for label, tva in [("Heat2Decoder", H2), ("XmlUnkMember", UNK), ("JsonUnk", 0x143AC0A71)]:
    for f in ["rx-0013.bin", "rx-0014.bin", "rx-0015.bin", "rx-0016.bin"]:
        b, sz = ranges[f]
        data = Path(f).read_bytes()
        hits = []
        for i in range(len(data) - 7):
            if data[i] in (0x48, 0x4C) and data[i + 1] == 0x8D and (data[i + 2] & 0xC7) == 0x05:
                dest = b + i + 7 + struct.unpack_from("<i", data, i + 3)[0]
                if dest == tva:
                    hits.append(b + i)
        if hits:
            print(f"  {label} {f}: {[hex(h) for h in hits[:12]]} n={len(hits)}")

# Disasm around first Heat2Decoder LEA and first XmlUnk LEA
def dis_around(va, back=0x40, n=0x120):
    for f, (b, s) in ranges.items():
        if b <= va < b + s:
            data = Path(f).read_bytes()
            start = va - back
            blob = data[start - b : start - b + n]
            print(f"\n===== around {va:#x} =====")
            for insn in md.disasm(blob, start):
                print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}")
            return


# Will fill after we know hits — try common decode RVAs from prior research
# Also: search for call pattern that decodes reply — 0x146df4ff0 was used in apply for CONF copy
print("\n=== disasm 0x146df4ff0 (struct copy used on CONF?) ===")
for f, (b, s) in ranges.items():
    if b <= 0x146DF4FF0 < b + s:
        data = Path(f).read_bytes()
        blob = data[0x146DF4FF0 - b : 0x146DF4FF0 - b + 0x100]
        for insn in md.disasm(blob, 0x146DF4FF0):
            print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}")
            if insn.mnemonic == "ret":
                break

# Find registration of members — look at 0x146df61xx init that set size 0xe
print("\n=== PreAuthResponse type init full (from earlier site) better start ===")
# find real prologue before 0x146df6171
va = 0x146DF6100
for f, (b, s) in ranges.items():
    if b <= va < b + s:
        data = Path(f).read_bytes()
        blob = data[va - b : va - b + 0x100]
        for insn in md.disasm(blob, va):
            raw = bytes(insn.bytes)
            ann = ""
            if insn.mnemonic == "lea" and "rip" in insn.op_str and len(raw) >= 7:
                dest = insn.address + len(raw) + struct.unpack_from("<i", raw, 3)[0]
                ann = f"  ; {dest:#x}"
            print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}{ann}")
            if insn.address > 0x146DF61F0:
                break
