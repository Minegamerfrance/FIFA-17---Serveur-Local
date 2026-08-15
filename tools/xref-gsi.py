"""Static PE xrefs to getServerInstanceHttp / RedirectorComponent in FIFA17.exe."""
from __future__ import annotations

import struct
from pathlib import Path

EXE = Path(r"C:\Users\Mineg\Desktop\serveur fifa 17\FIFA 17\FIFA17.exe")
data = EXE.read_bytes()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
assert magic == 0x20B, hex(magic)
image_base = struct.unpack_from("<Q", data, e_lfanew + 0x18 + 24)[0]
num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
sec_off = e_lfanew + 24 + opt_size
sections: list[dict] = []
for i in range(num_sections):
    o = sec_off + i * 40
    name = data[o : o + 8].split(b"\0", 1)[0].decode("latin1")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
    chars = struct.unpack_from("<I", data, o + 36)[0]
    sections.append(
        dict(name=name, va=va, vsize=vsize, rawptr=rawptr, rawsize=rawsize, chars=chars)
    )

print(f"image_base={hex(image_base)} sections={len(sections)}")
for s in sections:
    print(
        f"  {s['name']:8} VA={hex(s['va']):10} raw={hex(s['rawptr']):10} "
        f"size={hex(s['rawsize'])} chars={hex(s['chars'])}"
    )


def off_to_rva(off: int) -> int | None:
    for s in sections:
        if s["rawptr"] <= off < s["rawptr"] + s["rawsize"]:
            return s["va"] + (off - s["rawptr"])
    return None


def rva_to_off(rva: int) -> int | None:
    for s in sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["rawptr"] + (rva - s["va"])
    return None


needles = [
    b"getServerInstanceHttp\0",
    b"getServerInstance\0",
    b"ServerInstanceInfo\0",
    b"RedirectorComponent\0",
    b"serverinstanceinfo\0",
    b"INTERNAL_IPPORT\0",
    b"X-BLAZE-ERRORCODE\0",
]

string_rvas: dict[str, tuple[int, int, int]] = {}
for n in needles:
    off = data.find(n)
    label = n.rstrip(b"\0").decode()
    if off < 0:
        off = data.find(n.rstrip(b"\0"))
    if off < 0:
        print("MISS", label)
        continue
    rva = off_to_rva(off)
    if rva is None:
        print(f"STR {label} off={hex(off)} NO RVA")
        continue
    va = image_base + rva
    string_rvas[label] = (off, rva, va)
    print(f"STR {label!r} off={hex(off)} rva={hex(rva)} va={hex(va)}")

exec_secs = [s for s in sections if s["chars"] & 0x20000000]
print("exec sections:", [s["name"] for s in exec_secs])


def scan_abs_ptr(target_va: int, label: str, limit: int = 40) -> list[tuple[int, int]]:
    pat = struct.pack("<Q", target_va)
    hits: list[tuple[int, int]] = []
    start = 0
    while len(hits) < limit:
        i = data.find(pat, start)
        if i < 0:
            break
        rva = off_to_rva(i)
        if rva is not None:
            hits.append((i, rva))
        start = i + 1
    print(f"ABS {label}: {len(hits)} hits")
    for off, rva in hits[:20]:
        print(f"  file={hex(off)} rva={hex(rva)} va={hex(image_base + rva)}")
    return hits


def scan_lea_rip(target_rva: int, label: str, limit: int = 50) -> list[int]:
    hits: list[int] = []
    for s in exec_secs:
        chunk = memoryview(data)[s["rawptr"] : s["rawptr"] + s["rawsize"]]
        for i in range(len(chunk) - 7):
            b0 = chunk[i]
            if b0 not in (0x48, 0x4C):
                continue
            if chunk[i + 1] != 0x8D:
                continue
            modrm = chunk[i + 2]
            if (modrm & 0xC7) != 0x05:
                continue
            disp = struct.unpack_from("<i", chunk, i + 3)[0]
            instr_rva = s["va"] + i
            if instr_rva + 7 + disp == target_rva:
                hits.append(instr_rva)
                if len(hits) >= limit:
                    break
        if len(hits) >= limit:
            break
    print(f"LEA {label}: {len(hits)} hits")
    for r in hits[:25]:
        print(f"  lea @{hex(image_base + r)} rva={hex(r)}")
    return hits


def scan_lea_rip_all_sections(target_rva: int, label: str, limit: int = 50) -> list[int]:
    """Also scan non-exec (packed .xtextA etc. may not have IMAGE_SCN_MEM_EXECUTE)."""
    hits: list[int] = []
    for s in sections:
        if s["rawsize"] < 16:
            continue
        # skip huge raw if not likely code — still scan .text* / .xtext*
        if not any(x in s["name"].lower() for x in ("text", "code", "xtext")):
            continue
        chunk = memoryview(data)[s["rawptr"] : s["rawptr"] + s["rawsize"]]
        for i in range(len(chunk) - 7):
            b0 = chunk[i]
            if b0 not in (0x48, 0x4C):
                continue
            if chunk[i + 1] != 0x8D:
                continue
            modrm = chunk[i + 2]
            if (modrm & 0xC7) != 0x05:
                continue
            disp = struct.unpack_from("<i", chunk, i + 3)[0]
            instr_rva = s["va"] + i
            if instr_rva + 7 + disp == target_rva:
                hits.append(instr_rva)
                if len(hits) >= limit:
                    break
        if len(hits) >= limit:
            break
    print(f"LEA-alltext {label}: {len(hits)} hits")
    for r in hits[:25]:
        print(f"  lea @{hex(image_base + r)} rva={hex(r)}")
    return hits


def find_fn_start(rva: int) -> int:
    off = rva_to_off(rva)
    if off is None:
        return rva
    for b in range(0x300):
        p = off - b
        if p < 0:
            break
        v = data[p]
        if v == 0xCC and b > 4:
            return off_to_rva(p + 1) or rva
        if v == 0x40 and data[p + 1] == 0x55:
            return off_to_rva(p) or rva
        if v == 0x55 and data[p + 1] == 0x48:
            return off_to_rva(p) or rva
        # common: 48 89 5C 24 / 48 83 EC
        if v == 0x48 and data[p + 1] == 0x89 and b > 8:
            # weak heuristic — keep going for better prologues
            pass
    return rva


def dump_bytes(rva: int, n: int = 32) -> str:
    off = rva_to_off(rva)
    if off is None:
        return "?"
    return " ".join(f"{b:02x}" for b in data[off : off + n])


all_leas: dict[str, list[int]] = {}
for name, (off, rva, va) in string_rvas.items():
    scan_abs_ptr(va, name)
    leas = scan_lea_rip(rva, name)
    if not leas:
        leas = scan_lea_rip_all_sections(rva, name)
    all_leas[name] = leas

print("\n=== candidate functions (LEA → fn start) ===")
seen: set[int] = set()
for name, leas in all_leas.items():
    for lea in leas[:10]:
        fn = find_fn_start(lea)
        if fn in seen:
            continue
        seen.add(fn)
        print(
            f"{name}: lea={hex(image_base + lea)} fn={hex(image_base + fn)} "
            f"rva_fn={hex(fn)} bytes={dump_bytes(fn, 16)}"
        )

# Write hook list for Frida
out = Path(__file__).with_name("xref-gsi-hooks.txt")
lines = []
for name, leas in all_leas.items():
    for lea in leas:
        fn = find_fn_start(lea)
        lines.append(f"{name}\tlea={hex(image_base + lea)}\tfn={hex(image_base + fn)}\trva={hex(fn)}")
out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
print(f"\nwrote {out} ({len(lines)} lines)")
