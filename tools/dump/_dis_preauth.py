"""Disassemble around PreAuth string refs; find fn starts; xrefs to typeinfo ptrs."""
from pathlib import Path
import json
import struct

meta = json.loads(Path("rx-meta.json").read_text(encoding="utf-8"))
ranges = {r["file"]: (int(r["base"], 16), r["size"]) for r in meta["ranges"]}

def load_va(va, n):
    for file, (base, size) in ranges.items():
        if base <= va < base + size:
            data = Path(file).read_bytes()
            off = va - base
            return data[off : off + n], base, file
    return None, None, None

def find_fn_start(va, max_back=0x800):
    """Heuristic: look backward for common prologue / int3 padding / CC CC."""
    chunk, base, file = load_va(va - max_back, max_back + 16)
    if chunk is None:
        return None
    # search for 40 55 / 48 89 5C / 48 83 EC / CC CC pattern ending near va
    best = None
    for i in range(len(chunk) - 1, -1, -1):
        abs_va = (va - max_back) + i
        # after int3s
        if chunk[i] == 0xCC and i + 1 < len(chunk) and chunk[i + 1] != 0xCC:
            # next insn might be fn start
            cand = abs_va + 1
            if cand <= va:
                best = cand
                break
        # push rbp / sub rsp
        if chunk[i:i+2] in (b"\x40\x55", b"\x55\x48") or chunk[i:i+3] == b"\x48\x83\xec" or chunk[i:i+4] == b"\x48\x89\x5c":
            if abs_va <= va and (best is None or abs_va > best - 0x40):
                # prefer closest reasonable
                if va - abs_va < 0x600:
                    best = abs_va
                    # don't break — keep scanning for closer? actually want closest from below
    # better: walk back from va finding last CC-padding boundary
    for i in range(len(chunk) - 1, max(0, len(chunk) - max_back), -1):
        if chunk[i] == 0xCC:
            # find end of CC run
            j = i
            while j > 0 and chunk[j - 1] == 0xCC:
                j -= 1
            # start after CCs
            end = i
            while end + 1 < len(chunk) and chunk[end + 1] == 0xCC:
                end += 1
            start = end + 1
            cand = (va - max_back) + start
            if cand <= va and va - cand < 0x1000:
                return cand
    return best

SITES = [
    ("PreAuthResponse_s", 0x146df61bd),
    ("preAuth", 0x146df7257),
    ("UtilComponent", 0x146df7370),
    ("pingPeriod", 0x146e1d0a5),
    ("connIdleTimeout", 0x146e1d139),
    ("cem_ea_id", 0x14722c240),
]

print("=== sites + fn starts + hex dump ===")
for label, va in SITES:
    fn = find_fn_start(va)
    rva = va - 0x140000000
    fn_rva = (fn - 0x140000000) if fn else None
    fn_s = f"{fn:#x}" if fn else "None"
    fnr_s = f"{fn_rva:#x}" if fn_rva else "None"
    print(f"\n{label} @{va:#x} RVA={rva:#x} fn≈{fn_s} fnRVA={fnr_s}")
    start = fn if fn else (va - 0x20)
    data, _, _ = load_va(start, 0xC0)
    if data:
        print(f"  dump@{start:#x}: {data[:96].hex()}")

# Decode typeinfo / RTTI around PreAuthResponse ptr slot
print("\n=== PreAuthResponse typeinfo neighborhood ===")
for slot in [0x144875610, 0x144875628, 0x1448755c0]:
    data, _, _ = load_va(slot - 0x20, 0x60)
    print(f"slot {slot:#x}:")
    for i in range(0, 0x60, 8):
        q = struct.unpack_from("<Q", data, i)[0]
        print(f"  {slot-0x20+i:#x}: {q:#018x}")

# Xrefs TO pointer slots (LEA/MOV rip-rel to slot address)
SLOTS = {
    "PreAuthResponse_ti": 0x144875610,
    "PreAuthResponse_s_ti": 0x144875628,
    "PreAuthRequest_ti": 0x1448755c0,
    "cem_ea_id_ptr": 0x144323840,
}
print("\n=== RIP-rel to typeinfo slots (rx-0013..16) ===")
for file in ["rx-0013.bin", "rx-0014.bin", "rx-0015.bin", "rx-0016.bin"]:
    base, size = ranges[file]
    data = Path(file).read_bytes()
    for i in range(len(data) - 7):
        if data[i] in (0x48, 0x4C) and data[i + 1] in (0x8D, 0x8B) and (data[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", data, i + 3)[0]
            dest = base + i + 7 + disp
            for label, tva in SLOTS.items():
                if dest == tva:
                    print(f"  {label} @{base+i:#x} RVA={(base+i)-0x140000000:#x}")

# Also search lea to PreAuthResponse string itself (not _s)
print("\n=== re-scan PreAuthResponse (0x1438952E5) all bins with MOV/LEA ===")
TARGET = 0x1438952E5
for file, (base, size) in ranges.items():
    data = Path(file).read_bytes()
    hits = []
    for i in range(len(data) - 7):
        if data[i] in (0x48, 0x4C) and data[i + 1] in (0x8D, 0x8B) and (data[i + 2] & 0xC7) == 0x05:
            dest = base + i + 7 + struct.unpack_from("<i", data, i + 3)[0]
            if dest == TARGET:
                hits.append(base + i)
        # also 8D 0D / 8D 15 without REX
        elif data[i] == 0x8D and (data[i + 1] & 0xC7) == 0x05:
            dest = base + i + 6 + struct.unpack_from("<i", data, i + 2)[0]
            if dest == TARGET:
                hits.append(base + i)
    if hits:
        print(f"  {file}: {[hex(h) for h in hits]}")
