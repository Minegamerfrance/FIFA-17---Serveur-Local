"""Fast static LEA/dword xref hunt in packed FIFA17.exe (.data holds code)."""
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
    sections.append(dict(name=name, va=va, vsize=vsize, rawptr=rawptr, rawsize=rawsize))


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
}

# rip-relative LEA r64 encodings: REX + 8D + ModRM(mod=00,rm=101)
MODRMS = bytes([0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D])
REXES = bytes([0x48, 0x4C, 0x49, 0x4D])


def find_lea64(blob: bytes, blob_rva_base: int, target_rva: int) -> list[int]:
    hits: list[int] = []
    for rex in REXES:
        for modrm in MODRMS:
            pat = bytes([rex, 0x8D, modrm])
            start = 0
            while True:
                i = blob.find(pat, start)
                if i < 0:
                    break
                if i + 7 <= len(blob):
                    disp = struct.unpack_from("<i", blob, i + 3)[0]
                    instr_rva = blob_rva_base + i
                    if instr_rva + 7 + disp == target_rva:
                        hits.append(instr_rva)
                start = i + 1
    return hits


def find_lea32(blob: bytes, blob_rva_base: int, target_rva: int) -> list[int]:
    hits: list[int] = []
    for modrm in MODRMS:
        pat = bytes([0x8D, modrm])
        start = 0
        while True:
            i = blob.find(pat, start)
            if i < 0:
                break
            # skip if previous byte is REX (already counted as lea64)
            if i > 0 and blob[i - 1] in REXES:
                start = i + 1
                continue
            if i + 6 <= len(blob):
                disp = struct.unpack_from("<i", blob, i + 2)[0]
                instr_rva = blob_rva_base + i
                if instr_rva + 6 + disp == target_rva:
                    hits.append(instr_rva)
            start = i + 1
    return hits


def find_fn_start(rva: int) -> int:
    off = rva_to_off(rva)
    if off is None:
        return rva
    for b in range(1, 0x400):
        p = off - b
        if p < 0:
            break
        # int3 padding
        if data[p] == 0xCC and b > 4 and data[p + 1] != 0xCC:
            return off_to_rva(p + 1) or rva
        # push rbp / mov rbp,rsp variants
        if data[p] == 0x40 and data[p + 1] == 0x55:
            return off_to_rva(p) or rva
        if data[p] == 0x55 and data[p + 1] == 0x48 and data[p + 2] == 0x8B:
            return off_to_rva(p) or rva
        if data[p] == 0x48 and data[p + 1] == 0x83 and data[p + 2] == 0xEC:
            return off_to_rva(p) or rva
        if data[p] == 0x48 and data[p + 1] == 0x89 and data[p + 2] == 0x5C:
            return off_to_rva(p) or rva
    return rva


# Scan whole file via sections with raw data
scan_secs = [s for s in sections if s["rawsize"] >= 0x1000]
print("scanning", [s["name"] for s in scan_secs])

lines: list[str] = []
for name, trva in TARGETS.items():
    print(f"\n=== {name} {hex(trva)} ===")
    # dword RVA refs
    pat = struct.pack("<I", trva)
    dhits = []
    start = 0
    while len(dhits) < 50:
        i = data.find(pat, start)
        if i < 0:
            break
        r = off_to_rva(i)
        if r is not None and abs(r - trva) > 16:
            dhits.append(r)
        start = i + 1
    print(f"  dword RVA hits={len(dhits)}")
    for r in dhits[:12]:
        print(f"    {hex(image_base + r)}")
        lines.append(f"{name}\tdword\t{hex(image_base + r)}\trva={hex(r)}")

    lea_all: list[int] = []
    for s in scan_secs:
        blob = data[s["rawptr"] : s["rawptr"] + s["rawsize"]]
        lea_all.extend(find_lea64(blob, s["va"], trva))
        lea_all.extend(find_lea32(blob, s["va"], trva))
    lea_all = sorted(set(lea_all))
    print(f"  LEA hits={len(lea_all)}")
    for r in lea_all[:20]:
        fn = find_fn_start(r)
        print(f"    lea={hex(image_base + r)} fn={hex(image_base + fn)}")
        lines.append(
            f"{name}\tlea\t{hex(image_base + r)}\tfn={hex(image_base + fn)}\trva_fn={hex(fn)}"
        )

OUT.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
print(f"\nwrote {OUT} n={len(lines)}")
