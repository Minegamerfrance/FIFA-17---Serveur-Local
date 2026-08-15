"""Deep analysis of PreAuth apply fn @ 0x146e1cf10 and callers."""
from pathlib import Path
import json
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

meta = json.loads(Path("rx-meta.json").read_text(encoding="utf-8"))
ranges = {r["file"]: (int(r["base"], 16), r["size"]) for r in meta["ranges"]}
md = Cs(CS_ARCH_X86, CS_MODE_64)

def load_va(va, n):
    for file, (base, size) in ranges.items():
        if base <= va < base + size:
            data = Path(file).read_bytes()
            return data[va - base : va - base + n]
    return None

def disasm(va, n=0x400):
    data = load_va(va, n)
    lines = []
    for insn in md.disasm(data, va):
        lines.append((insn.address, insn.mnemonic, insn.op_str, insn.bytes))
    return lines

def resolve_lea_str(insn_addr, op_str):
    # lea reg, [rip +/- disp]
    if "rip" not in op_str:
        return None
    # parse from bytes better
    return None

FN = 0x146e1cf10
lines = disasm(FN, 0x550)
print(f"===== full fn @{FN:#x} RVA={FN-0x140000000:#x} =====")
for addr, mnem, ops, raw in lines:
    annot = ""
    # annotate rip-relative LEAs that land on strings
    if mnem == "lea" and "rip" in ops and len(raw) >= 7:
        # 48 8D xx disp32
        if raw[0] in (0x48, 0x4C) and raw[1] == 0x8D:
            disp = struct.unpack_from("<i", raw, 3)[0]
            dest = addr + len(raw) + disp
            sdata = load_va(dest, 64)
            if sdata:
                try:
                    s = sdata.split(b"\x00", 1)[0].decode("ascii")
                    if s.isprintable() and len(s) >= 3:
                        annot = f"  ; \"{s}\""
                except Exception:
                    pass
            annot = annot or f"  ; ->{dest:#x}"
    if mnem == "call":
        annot = f"  ; call"
    print(f"  {addr:#x}: {mnem:8s} {ops}{annot}")
    if mnem == "ret":
        break

# Find CALL sites to FN via E8 rel32 in rx-0014/15
print("\n===== callers of 0x146e1cf10 =====")
target = FN
for file in ["rx-0014.bin", "rx-0015.bin", "rx-0013.bin"]:
    base, size = ranges[file]
    data = Path(file).read_bytes()
    for i in range(len(data) - 5):
        if data[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", data, i + 1)[0]
        dest = base + i + 5 + rel
        if dest == target:
            print(f"  call @{base+i:#x} RVA={base+i-0x140000000:#x}")

# Also find references to PreAuthResponse typeinfo slot 0x144875610 via LEA
print("\n===== LEA to PreAuthResponse typeinfo 0x144875610 =====")
TI = 0x144875610
for file in ["rx-0013.bin", "rx-0014.bin", "rx-0015.bin", "rx-0016.bin", "rx-0006.bin"]:
    if file not in ranges:
        continue
    base, size = ranges[file]
    data = Path(file).read_bytes()
    for i in range(len(data) - 7):
        if data[i] in (0x48, 0x4C) and data[i+1] == 0x8D and (data[i+2] & 0xC7) == 0x05:
            dest = base + i + 7 + struct.unpack_from("<i", data, i + 3)[0]
            if dest == TI:
                print(f"  {file} @{base+i:#x}")

# Search for component 9 command 7 reply handler patterns near Util
# Look at strings: "preAuth" usage context - who LEAs it
print("\n===== disasm around preAuth lea with better fn start =====")
# find push rbx / sub rsp near 0x146df7257 going back properly
va = 0x146df7257
data = load_va(va - 0x200, 0x280)
# find last '48 89 5c' or '40 55' or '48 83 ec'
best = None
for i in range(len(data) - 4):
    abs_a = va - 0x200 + i
    if data[i:i+4] == b"\x48\x89\x5c" or data[i:i+3] == b"\x48\x83\xec" or data[i:i+2] == b"\x40\x55":
        if abs_a < va:
            best = abs_a
print(f"best prologue near preAuth: {best:#x}" if best else "none")
if best:
    for addr, mnem, ops, raw in disasm(best, 0x200):
        annot = ""
        if mnem == "lea" and "rip" in ops and len(raw) >= 7 and raw[0] in (0x48, 0x4C):
            dest = addr + len(raw) + struct.unpack_from("<i", raw, 3)[0]
            sdata = load_va(dest, 48)
            if sdata:
                try:
                    s = sdata.split(b"\x00", 1)[0].decode("ascii")
                    if s.isprintable() and 3 <= len(s) < 48:
                        annot = f'  ; "{s}"'
                except Exception:
                    pass
        print(f"  {addr:#x}: {mnem:8s} {ops}{annot}")
        if mnem == "ret" and addr > va:
            break
