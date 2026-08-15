"""Extract NetworkAddress / ServerInstanceInfo field layout from FIFA17.exe."""
from pathlib import Path

data = Path(r"C:\Users\Mineg\Desktop\serveur fifa 17\FIFA 17\FIFA17.exe").read_bytes()


def dump_strings(lo: int, hi: int) -> None:
    chunk = data[lo:hi]
    cur = bytearray()
    off = 0
    for i, b in enumerate(chunk):
        if 32 <= b < 127:
            if not cur:
                off = lo + i
            cur.append(b)
        else:
            if len(cur) >= 2:
                print(f"  {hex(off)}: {cur.decode()}")
            cur = bytearray()


def find_nt(needle: bytes, region: tuple[int, int] | None = None) -> list[int]:
    lo, hi = region if region else (0, len(data))
    blob = data[lo:hi]
    out: list[int] = []
    start = 0
    while True:
        j = blob.find(needle, start)
        if j < 0:
            break
        abs_off = lo + j
        # null-terminated-ish: next byte 0 or non-alpha
        end = abs_off + len(needle)
        if end < len(data) and data[end] == 0:
            out.append(abs_off)
        start = j + 1
    return out


print("=== NetworkAddress region strings 0x36f880-0x370120 ===")
dump_strings(0x36F880, 0x370120)

print("\n=== null-terminated port/ip/host ===")
for n in [b"port", b"ip", b"host", b"hostName", b"hostname", b"name", b"address"]:
    hits = find_nt(n, (0x36F800, 0x370200))
    print(n, [hex(h) for h in hits[:10]])

print("\n=== Redirector field pool name/secure/messages ===")
for n in [b"name", b"secure", b"messages", b"defaultDnsAddress", b"trialServiceName", b"serviceName"]:
    hits = find_nt(n, (0x378180, 0x378560))
    print(n, [hex(h) for h in hits])

# Look for Tdf registration: often pattern is pointer to name string followed by type info
# Search for relative offsets / absolute pointers to ServerInstanceInfo string
target = 0x377C80  # "ServerInstanceInfo"
print(f"\n=== pointer refs to ServerInstanceInfo string @ {hex(target)} ===")
# PE is likely 64-bit; image base often 0x140000000
# Also try file-offset as RVA - need PE parse

import struct

# Parse PE to get image base and section mapping
pe_off = struct.unpack_from("<I", data, 0x3C)[0]
print("PE", hex(pe_off), data[pe_off : pe_off + 4])
magic = struct.unpack_from("<H", data, pe_off + 0x18)[0]
print("magic", hex(magic))
if magic == 0x20B:  # PE32+
    image_base = struct.unpack_from("<Q", data, pe_off + 0x18 + 0x18)[0]
    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 0x14)[0]
    sec_off = pe_off + 0x18 + opt_size
    print("image_base", hex(image_base), "sections", num_sections)
    sections = []
    for i in range(num_sections):
        s = sec_off + i * 40
        name = data[s : s + 8].split(b"\0", 1)[0].decode("latin1")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        sections.append((name, va, vsize, rawptr, rawsize))
        print(f"  {name}: VA={hex(va)} VS={hex(vsize)} raw={hex(rawptr)}")

    def file_to_va(file_off: int) -> int | None:
        for name, va, vsize, rawptr, rawsize in sections:
            if rawptr <= file_off < rawptr + max(rawsize, vsize):
                return image_base + va + (file_off - rawptr)
        return None

    def va_to_file(va: int) -> int | None:
        rva = va - image_base
        for name, sva, vsize, rawptr, rawsize in sections:
            if sva <= rva < sva + max(vsize, rawsize):
                return rawptr + (rva - sva)
        return None

    va = file_to_va(target)
    print("ServerInstanceInfo VA", hex(va) if va else None)

    if va:
        # search for absolute 64-bit pointer to this VA in the file
        needle = struct.pack("<Q", va)
        refs = []
        start = 0
        while len(refs) < 20:
            j = data.find(needle, start)
            if j < 0:
                break
            refs.append(j)
            start = j + 1
        print("abs ptr refs file offs", [hex(r) for r in refs])

        # also search 32-bit RVA
        rva = va - image_base
        needle32 = struct.pack("<I", rva)
        refs32 = []
        start = 0
        while len(refs32) < 20:
            j = data.find(needle32, start)
            if j < 0:
                break
            # filter: must look like pointer table (aligned)
            if j % 4 == 0:
                refs32.append(j)
            start = j + 1
        print("rva32 refs (aligned sample)", [hex(r) for r in refs32[:15]])
