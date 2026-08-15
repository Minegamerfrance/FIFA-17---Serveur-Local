"""Capstone disasm around PreAuth string sites + member registration."""
from pathlib import Path
import json
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

meta = json.loads(Path("rx-meta.json").read_text(encoding="utf-8"))
ranges = {r["file"]: (int(r["base"], 16), r["size"]) for r in meta["ranges"]}
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

def load_va(va, n):
    for file, (base, size) in ranges.items():
        if base <= va < base + size:
            data = Path(file).read_bytes()
            off = va - base
            return data[off : off + n], file
    return None, None

def disasm(va, n=0x200, title=""):
    data, _ = load_va(va, n)
    if not data:
        print(f"MISS {va:#x}")
        return
    print(f"\n===== {title or hex(va)} =====")
    for insn in md.disasm(data, va):
        print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}")

def find_cc_start(va, max_back=0x1000):
    data, _ = load_va(va - max_back, max_back)
    if not data:
        return None
    # walk back for CC run then first non-CC
    for i in range(len(data) - 1, -1, -1):
        if data[i] == 0xCC:
            j = i
            while j + 1 < len(data) and data[j + 1] == 0xCC:
                j += 1
            start = (va - max_back) + j + 1
            if start <= va:
                return start
    return None

# Sites from xref
sites = {
    "PreAuthResponse_s_lea": 0x146df61bd,
    "preAuth_lea": 0x146df7257,
    "UtilComponent_lea": 0x146df7370,
    "pingPeriod_lea": 0x146e1d0a5,
    "connIdleTimeout_lea": 0x146e1d139,
}

for name, va in sites.items():
    fn = find_cc_start(va)
    fn_s = f"{fn:#x}" if fn else "None"
    print(f"{name} @{va:#x} fn_start~{fn_s} RVA={(fn or va)-0x140000000:#x}")

# Disassemble full functions
for name, va in [
    ("fn_PreAuthResponse_s", find_cc_start(0x146df61bd) or 0x146df6100),
    ("fn_preAuth", find_cc_start(0x146df7257) or 0x146df7200),
    ("fn_pingPeriod", find_cc_start(0x146e1d0a5) or 0x146e1d000),
]:
    disasm(va, 0x280, name)

# Search TDF field name strings near PreAuth in rdata (rx-0006)
print("\n===== field-ish strings near PreAuthResponse in rx-0006 =====")
base6 = 0x14354b000
data6 = Path("rx-0006.bin").read_bytes()
# PreAuthResponse at 0x1438952E5 → off = 0x1438952E5 - 0x14354b000
off = 0x1438952E5 - base6
region = data6[off - 0x400 : off + 0x800]
# extract printable cstrings
i = 0
while i < len(region):
    if 32 <= region[i] < 127:
        j = i
        while j < len(region) and 32 <= region[j] < 127:
            j += 1
        s = region[i:j].decode("ascii")
        if len(s) >= 3:
            print(f"  {base6 + (off - 0x400) + i:#x}: {s}")
        i = j + 1
    else:
        i += 1

# Search ASRC / NASP / CIDS as standalone cstrings in dump
print("\n===== ASRC/NASP/CIDS/SVER/INST/CONF/ANON string VAs =====")
needles = [b"ASRC\x00", b"NASP\x00", b"CIDS\x00", b"SVER\x00", b"INST\x00",
           b"CONF\x00", b"ANON\x00", b"QOSS\x00", b"RSRC\x00", b"MINR\x00",
           b"CNGN\x00", b"PILD\x00", b"PLAT\x00", b"PTAG\x00", b"pingPeriod\x00"]
for file, (base, size) in ranges.items():
    blob = Path(file).read_bytes()
    for n in needles:
        idx = 0
        found = []
        while True:
            i = blob.find(n, idx)
            if i < 0:
                break
            found.append(base + i)
            idx = i + 1
            if len(found) >= 3:
                break
        if found:
            print(f"  {n[:-1].decode()}: {[hex(x) for x in found]} ({file})")
