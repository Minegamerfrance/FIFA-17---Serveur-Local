from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pathlib import Path
import struct

md = Cs(CS_ARCH_X86, CS_MODE_64)
blob = Path("rx-0014.bin").read_bytes()
base = 0x1460ED000

print("=== rbp refs in FrameUnpack ===")
for insn in md.disasm(blob[0x146DB8070 - base : 0x146DB8750 - base], 0x146DB8070):
    if "rbp" in insn.op_str and (
        "0x70" in insn.op_str
        or "0x58" in insn.op_str
        or "0x3c" in insn.op_str
        or "0x40" in insn.op_str
        or "0x28" in insn.op_str
    ):
        print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}")

print("\n=== scan encodings for [rbp-0x70] ===")
off = 0x146DB8070 - base
end = 0x146DB8750 - base
for i in range(off, end - 4):
    if blob[i] == 0x8B and blob[i + 1] == 0x45 and blob[i + 2] == 0x90:
        print(f"  mov eax,[rbp-0x70] @{base + i:#x}")
    if blob[i] == 0x89 and blob[i + 1] == 0x45 and blob[i + 2] == 0x90:
        print(f"  mov [rbp-0x70],eax @{base + i:#x}")
    if blob[i] == 0xC7 and blob[i + 1] == 0x45 and blob[i + 2] == 0x90:
        val = struct.unpack_from("<i", blob, i + 3)[0]
        print(f"  mov [rbp-0x70],imm @{base + i:#x} val={val:#x}")
    # mov dword ptr [rbp-0x70], r8d etc with REX
    if blob[i] == 0x44 and blob[i + 1] == 0x89 and blob[i + 2] == 0x45 and blob[i + 3] == 0x90:
        print(f"  mov [rbp-0x70],r8d @{base + i:#x}")

# Disasm 0x146dd5170 briefly - what does decoder store?
print("\n=== decoder ctor-like 0x146dd5170 prologue ===")
# may be in same file
va = 0x146DD5170
if base <= va < base + len(blob):
    for insn in md.disasm(blob[va - base : va - base + 0x80], va):
        print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}")
        if insn.mnemonic == "ret":
            break

# Compare FramePack header layout by simulating field positions from disasm
print("\n=== Confirm FramePack writes vs FrameUnpack reads ===")
print("FramePack ALT (b2c/d1c gate fail path still packs same body):")
print("  [0:3]=sizeBE, [4:5]=0 then maybe enc-len, [6:7]=component,")
print("  [8:9]=command?, [a:b]=error?, [c]=msgNum0, [d]=type|opts, [e:f]=0")
print("FrameUnpack RPC path:")
print("  size=[0:3], component=[6:7], command=[8:9],")
print("  msgNum24BE=[a:c], type=( [d]>>5 ), opts=( [d]&0x1f )")
print("  error=dword [rbp-0x70] (decoder/stack), NOT raw header u16")
