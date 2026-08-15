"""Find TDF member tables pointing at ServerInstanceInfo-related strings."""
from __future__ import annotations

import struct
from pathlib import Path

data = Path(r"C:\Users\Mineg\Desktop\serveur fifa 17\FIFA 17\FIFA17.exe").read_bytes()

pe_off = struct.unpack_from("<I", data, 0x3C)[0]
image_base = struct.unpack_from("<Q", data, pe_off + 0x18 + 0x18)[0]
num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
opt_size = struct.unpack_from("<H", data, pe_off + 0x14)[0]
sec_off = pe_off + 0x18 + opt_size
sections: list[tuple[str, int, int, int, int]] = []
for i in range(num_sections):
    s = sec_off + i * 40
    name = data[s : s + 8].split(b"\0", 1)[0].decode("latin1")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
    sections.append((name, va, vsize, rawptr, rawsize))


def file_to_va(file_off: int) -> int | None:
    for _name, va, vsize, rawptr, rawsize in sections:
        span = max(rawsize, vsize)
        if rawsize and rawptr <= file_off < rawptr + rawsize:
            return image_base + va + (file_off - rawptr)
    return None


def va_to_file(va: int) -> int | None:
    rva = va - image_base
    for _name, sva, vsize, rawptr, rawsize in sections:
        if rawsize and sva <= rva < sva + rawsize:
            return rawptr + (rva - sva)
        if sva <= rva < sva + vsize and rawsize:
            return rawptr + (rva - sva)
    return None


def find_nt(s: bytes) -> int:
    return data.find(s + b"\0")


targets = {
    "ServerInstanceInfo": find_nt(b"ServerInstanceInfo"),
    "ServerInstanceRequest": find_nt(b"ServerInstanceRequest"),
    "defaultDnsAddress": find_nt(b"defaultDnsAddress"),
    "secure": find_nt(b"secure"),  # may hit wrong one
    "ipPairAddress": find_nt(b"ipPairAddress"),
    "externalAddress": find_nt(b"externalAddress"),
    "hostName": find_nt(b"hostName"),
    "hostname": find_nt(b"hostname"),
    "messages": find_nt(b"messages"),
    "trialServiceName": find_nt(b"trialServiceName"),
}

# Prefer redirector-region secure @ 0x3784ac
targets["secure"] = 0x3784AC
targets["messages"] = 0x3784A0

print("string VAs:")
string_vas: dict[str, int] = {}
for k, fo in targets.items():
    if fo < 0:
        print(f"  {k}: MISSING")
        continue
    va = file_to_va(fo)
    string_vas[k] = va or 0
    print(f"  {k}: file={hex(fo)} va={hex(va) if va else None}")

# Search for absolute pointers to these VAs in writable/code-ish sections
print("\npointer refs (abs64):")
for k, va in string_vas.items():
    if not va:
        continue
    needle = struct.pack("<Q", va)
    refs = []
    start = 0
    while len(refs) < 12:
        j = data.find(needle, start)
        if j < 0:
            break
        refs.append(j)
        start = j + 1
    print(f"  {k}: {[hex(r) for r in refs]}")

# Also try image-relative / RVA32 in .data
print("\npointer refs (rva32 aligned):")
for k, va in string_vas.items():
    if not va:
        continue
    rva = va - image_base
    needle = struct.pack("<I", rva)
    refs = []
    start = 0
    while len(refs) < 30:
        j = data.find(needle, start)
        if j < 0:
            break
        if j % 8 == 0:
            refs.append(j)
        start = j + 1
    print(f"  {k}: n={len(refs)} sample={[hex(r) for r in refs[:8]]}")

# Dump nearby strings around trialServiceName / messages / secure — likely ServerInstanceInfo members in registration order
print("\n=== field pool around messages/secure (likely ServerInstanceInfo) ===")
fo = 0x378480
chunk = data[fo : fo + 0x80]
cur = bytearray()
off = 0
for i, b in enumerate(chunk):
    if 32 <= b < 127:
        if not cur:
            off = fo + i
        cur.append(b)
    else:
        if len(cur) >= 2:
            print(f"  {hex(off)}: {cur.decode()}")
        cur = bytearray()
