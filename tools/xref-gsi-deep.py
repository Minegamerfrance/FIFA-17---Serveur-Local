"""Deeper static refs: .data LEA + 32-bit RVA dwords (FIFA17 packed)."""
from __future__ import annotations

import struct
from pathlib import Path

EXE = Path(r"C:\Users\Mineg\Desktop\serveur fifa 17\FIFA 17\FIFA17.exe")
OUT = Path(__file__).with_name("xref-gsi-hooks.txt")
data = EXE.read_bytes()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
image_base = struct.unpack_from("<Q", data, e_lfanew + 0x18 + 24)[0]
num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
sec_off = e_lfanew + 24 + opt_size
sections = []
for i in range(num_sections):
    o = sec_off + i * 40
    name = data[o : o + 8].split(b"\0", 1)[0].decode("latin1")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
    chars = struct.unpack_from("<I", data, o + 36)[0]
    sections.append(
        dict(name=name, va=va, vsize=vsize, rawptr=rawptr, rawsize=rawsize, chars=chars)
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


TARGETS = {
    "getServerInstanceHttp": 0x38919C0,
    "RedirectorComponent": 0x3891978,
    "ServerInstanceInfo": 0x389166B,
    "INTERNAL_IPPORT": 0x3891468,
    "X-BLAZE-ERRORCODE": 0x3882298,
    "getServerInstance": 0x388E983,
}


def scan_lea_in_section(sec: dict, target_rva: int, limit: int = 40) -> list[int]:
    hits: list[int] = []
    raw = memoryview(data)[sec["rawptr"] : sec["rawptr"] + sec["rawsize"]]
    # LEA r64,[rip+disp]: (48|4C|49|4D) 8D xx(/r with mod=00 rm=101)
    for i in range(len(raw) - 7):
        if raw[i + 1] != 0x8D:
            continue
        if raw[i] not in (0x48, 0x4C, 0x49, 0x4D):
            continue
        if (raw[i + 2] & 0xC7) != 0x05:
            continue
        disp = struct.unpack_from("<i", raw, i + 3)[0]
        instr_rva = sec["va"] + i
        if instr_rva + 7 + disp == target_rva:
            hits.append(instr_rva)
            if len(hits) >= limit:
                break
    return hits


def scan_mov_rip_load(sec: dict, target_rva: int, limit: int = 20) -> list[int]:
    """48 8B 05 disp32 = mov rax,[rip+disp] where [addr] holds ptr — skip.
    Also 48 8D already covered. Try 8D 05 (32-bit lea) targeting low 32 of VA."""
    hits: list[int] = []
    raw = memoryview(data)[sec["rawptr"] : sec["rawptr"] + sec["rawsize"]]
    target_va32 = (image_base + target_rva) & 0xFFFFFFFF
    for i in range(len(raw) - 6):
        # lea reg32, [rip+disp] — 8D 05 / 8D 0D / 8D 15 / 8D 1D / 8D 2D / 8D 35 / 8D 3D
        if raw[i] == 0x8D and (raw[i + 1] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", raw, i + 2)[0]
            instr_rva = sec["va"] + i
            if (instr_rva + 6 + disp) == target_rva:
                hits.append(instr_rva)
        # mov reg, imm32 of VA low — rare
        if raw[i] in (0xB8, 0xB9, 0xBA, 0xBB, 0xB9) and i + 5 < len(raw):
            imm = struct.unpack_from("<I", raw, i + 1)[0]
            if imm == target_rva or imm == target_va32:
                hits.append(sec["va"] + i)
        if len(hits) >= limit:
            break
    return hits


def scan_dword_rva(target_rva: int, label: str, limit: int = 40) -> list[tuple[int, int]]:
    pat = struct.pack("<I", target_rva)
    hits: list[tuple[int, int]] = []
    start = 0
    while len(hits) < limit:
        i = data.find(pat, start)
        if i < 0:
            break
        rva = off_to_rva(i)
        if rva is not None:
            # skip the string itself and nearby string pool
            if abs(rva - target_rva) > 8:
                hits.append((i, rva))
        start = i + 1
    print(f"DWORD RVA {label} ({hex(target_rva)}): {len(hits)} hits")
    for off, rva in hits[:15]:
        print(f"  @{hex(image_base + rva)} file={hex(off)}")
    return hits


# Prefer scanning .data + .xtext + .code (where ProtoSSL RVAs live ~0x612xxxx)
prefer = [s for s in sections if s["name"] in (".data", ".xtext", ".code", ".srdata", ".data1")]
print("scan sections:", [(s["name"], hex(s["va"]), hex(s["rawsize"])) for s in prefer])

lines: list[str] = []
for name, trva in TARGETS.items():
    print(f"\n=== {name} rva={hex(trva)} ===")
    scan_dword_rva(trva, name)
    for sec in prefer:
        leas = scan_lea_in_section(sec, trva)
        if leas:
            print(f"  LEA in {sec['name']}: {len(leas)}")
            for r in leas:
                print(f"    {hex(image_base + r)}")
                lines.append(f"{name}\tlea\t{hex(image_base + r)}\trva={hex(r)}\tsec={sec['name']}")
        movs = scan_mov_rip_load(sec, trva)
        # filter only real hits (mov scan is noisy) — only print if lea-style matched target
        movs = [m for m in movs if True]
        # Only keep if we used the lea32 path that matched target_rva exactly — already filtered
        if movs:
            # re-check: only those that are lea32 to target (from function logic)
            real = []
            raw = memoryview(data)[sec["rawptr"] : sec["rawptr"] + sec["rawsize"]]
            for r in movs:
                off = r - sec["va"]
                if off < 0 or off + 6 > len(raw):
                    continue
                if raw[off] == 0x8D and (raw[off + 1] & 0xC7) == 0x05:
                    disp = struct.unpack_from("<i", raw, off + 2)[0]
                    if r + 6 + disp == trva:
                        real.append(r)
            if real:
                print(f"  LEA32 in {sec['name']}: {len(real)}")
                for r in real:
                    print(f"    {hex(image_base + r)}")
                    lines.append(f"{name}\tlea32\t{hex(image_base + r)}\trva={hex(r)}\tsec={sec['name']}")

# Known runtime code band from Frida SSL: 0x6120000–0x6140000 inside .data
band_va = 0x6100000
band_off = rva_to_off(band_va)
print(f"\nProtoSSL band file_off={hex(band_off) if band_off else None}")
if band_off:
    # search only ±8MB around band for LEAs to GSI
    for name, trva in TARGETS.items():
        sec = next(s for s in sections if s["name"] == ".data")
        # local window
        win_lo = max(sec["rawptr"], band_off - 0x800000)
        win_hi = min(sec["rawptr"] + sec["rawsize"], band_off + 0x800000)
        raw = memoryview(data)[win_lo:win_hi]
        hits = []
        for i in range(len(raw) - 7):
            if raw[i + 1] != 0x8D or raw[i] not in (0x48, 0x4C, 0x49, 0x4D):
                continue
            if (raw[i + 2] & 0xC7) != 0x05:
                continue
            disp = struct.unpack_from("<i", raw, i + 3)[0]
            instr_rva = sec["va"] + (win_lo - sec["rawptr"]) + i
            if instr_rva + 7 + disp == trva:
                hits.append(instr_rva)
        print(f"BAND LEA {name}: {len(hits)}")
        for r in hits[:10]:
            print(f"  {hex(image_base + r)}")
            lines.append(f"{name}\tband-lea\t{hex(image_base + r)}\trva={hex(r)}")

OUT.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
print(f"\nwrote {OUT} lines={len(lines)}")
