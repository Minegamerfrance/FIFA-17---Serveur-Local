"""Statically find TDF member pointer tables in FIFA17.exe for Redirector types."""
from __future__ import annotations

import struct
from pathlib import Path

data = Path(r"C:\Users\Mineg\Desktop\serveur fifa 17\FIFA 17\FIFA17.exe").read_bytes()
pe = struct.unpack_from("<I", data, 0x3C)[0]
image_base = struct.unpack_from("<Q", data, pe + 0x18 + 0x18)[0]
num_sec = struct.unpack_from("<H", data, pe + 6)[0]
opt_size = struct.unpack_from("<H", data, pe + 0x14)[0]
sec_off = pe + 0x18 + opt_size
sections = []
for i in range(num_sec):
    s = sec_off + i * 40
    name = data[s : s + 8].split(b"\0", 1)[0].decode("latin1")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
    sections.append((name, va, vsize, rawptr, rawsize))


def file_to_va(fo: int) -> int | None:
    for _n, va, vsize, rawptr, rawsize in sections:
        if rawsize and rawptr <= fo < rawptr + rawsize:
            return image_base + va + (fo - rawptr)
    return None


def va_to_file(va: int) -> int | None:
    rva = va - image_base
    for _n, sva, vsize, rawptr, rawsize in sections:
        if rawsize and sva <= rva < sva + rawsize:
            return rawptr + (rva - sva)
    return None


def find_nt(s: bytes) -> int:
    return data.find(s + b"\0")


# Exact member / type strings we care about
names = [
    b"ServerInstanceRequest",
    b"ServerInstanceInfo",
    b"ServerAddressInfo",
    b"ServerAddress",
    b"hostname",
    b"secure",
    b"defaultDnsAddress",
    b"messages",
    b"name",
    b"trialServiceName",
    b"connectionProfile",
    b"clientName",
    b"blazeSDKVersion",
    b"ipPairAddress",
    b"externalAddress",
    b"hostName",
    b"xboxServerAddress",
]

print("image_base", hex(image_base))
vas: dict[str, int] = {}
for n in names:
    # prefer redirector-region hits for ambiguous names
    fo = -1
    start = 0
    cands = []
    while True:
        j = data.find(n + b"\0", start)
        if j < 0:
            break
        cands.append(j)
        start = j + 1
    if not cands:
        print(f"MISSING {n}")
        continue
    # pick candidate in 0x36f000-0x379000 when possible
    pick = None
    for c in cands:
        if 0x36F000 <= c <= 0x379000:
            pick = c
            break
    if pick is None:
        pick = cands[0]
    va = file_to_va(pick)
    vas[n.decode()] = va or 0
    print(f"{n.decode():24} file={hex(pick)} va={hex(va) if va else None} n={len(cands)}")


def find_abs_refs(va: int, limit: int = 30) -> list[int]:
    needle = struct.pack("<Q", va)
    out = []
    start = 0
    while len(out) < limit:
        j = data.find(needle, start)
        if j < 0:
            break
        out.append(j)
        start = j + 1
    return out


print("\n=== abs64 refs (may be empty if reloc/pack) ===")
for n, va in vas.items():
    if not va:
        continue
    refs = find_abs_refs(va)
    print(f"{n}: {len(refs)} refs {[hex(r) for r in refs[:8]]}")

# Search for clusters: consecutive pointers to known member names (member tables)
print("\n=== search member-table clusters (stride scan in .srdata/.data1) ===")
# Build set of interesting VAs
interesting = {va: name for name, va in vas.items() if va}

# Scan pointer-aligned qwords in file ranges that exist on disk
scan_ranges = []
for name, va, vsize, rawptr, rawsize in sections:
    if rawsize >= 0x1000 and name in (".srdata", ".data1", ".data", ".rdata"):
        scan_ranges.append((name, rawptr, rawptr + rawsize))

for sname, lo, hi in scan_ranges:
    print(f"scan {sname} {hex(lo)}-{hex(hi)}")
    # sliding window of 8 qwords
    i = lo
    # align
    i = (i + 7) & ~7
    found_clusters = 0
    while i + 64 < hi and found_clusters < 40:
        names_hit = []
        for k in range(8):
            q = struct.unpack_from("<Q", data, i + k * 8)[0]
            if q in interesting:
                names_hit.append(interesting[q])
        if len(names_hit) >= 2:
            print(f"  cluster @{hex(i)}: {names_hit}")
            found_clusters += 1
            i += 64
            continue
        i += 8

# Specifically: list strings in order from ServerInstanceRequest field registration
# by dumping all cstrings between ServerInstanceRequest and next type block already done.
# Infer ServerInstanceInfo members as those appearing in docs: address?, secure, name, defaultDnsAddress
print("\n=== Request wire tags (CAPTURED — ground truth) ===")
print(
    "blazesdkversion, blazesdkbuilddate, clientname, clienttype, clientplatform,"
    " clientskuid, clientversion, dirtysdkversion, environment, clientlocale,"
    " name, platform, connectionprofile, istrial"
)
print("=> Heat2 XML = lowercased camelCase member names from TDF registration")
