"""Find RIP-relative LEA/MOV references to PreAuthResponse / PreAuthRequest strings."""
from pathlib import Path
import json
import struct

meta = json.loads(Path("rx-meta.json").read_text(encoding="utf-8"))
ranges = meta["ranges"]

TARGETS = {
    "PreAuthResponse": 0x1438952E5,
    "PreAuthResponse_short": 0x1438952F8,
    "PreAuthRequest": 0x1438952B5,
    "preAuth_cmd": 0x143895930,
    "UtilComponent": 0x143895858,
    "cem_ea_id": 0x14388B148,  # 0x14354b000+0x33a148
    "pingPeriod": 0x1438A0A30,  # 0x14354b000+0x355a30
}

# Fix cem_ea and pingPeriod
TARGETS["cem_ea_id"] = 0x14354B000 + 0x33A148
TARGETS["pingPeriod"] = 0x14354B000 + 0x355A30
TARGETS["UtilComponent"] = 0x14354B000 + 0x34A858


def file_for_va(va: int):
    for r in ranges:
        base = int(r["base"], 16)
        size = r["size"]
        if base <= va < base + size:
            return r["file"], base, va - base
    return None, None, None


def scan_code_for_imm32(target_va: int, label: str):
    """Scan all ranges for little-endian u32 == target_va (absolute) or RIP-rel candidates."""
    hits = []
    for r in ranges:
        base = int(r["base"], 16)
        data = Path(r["file"]).read_bytes()
        needle = struct.pack("<I", target_va & 0xFFFFFFFF)
        # Also high part for absolute MOV in x64 rare
        idx = 0
        while True:
            i = data.find(needle, idx)
            if i < 0:
                break
            va = base + i
            # classify: if previous bytes look like lea/mov rip-relative
            # lea r64, [rip+disp32] = 48 8D xx disp32  OR 4C 8D / 8D
            prev = data[max(0, i - 7) : i]
            kind = "imm32"
            # rip-rel: disp32 at i means instruction ends at i+4, rip=i+4+base
            rip = va + 4
            # If this is a disp32 for rip-rel, the target would be rip+disp == target
            # So when we find absolute VA as imm, it might be a pointer slot in .rdata
            # For rip-rel we search differently below
            hits.append((va, kind, prev.hex()))
            idx = i + 1
            if len(hits) > 40:
                break
    print(f"\n=== absolute imm32 refs to {label} {target_va:#x}: {len(hits)} ===")
    for va, kind, prev in hits[:15]:
        print(f"  {va:#x} prev={prev}")


def scan_rip_rel(target_va: int, label: str):
    """For each code byte position, check if lea/mov rip+disp points to target."""
    # Pattern: 48 8D 0D/15/1D/05/2D/35/3D disp32  (lea rcx/rdx/rbx/rax/rbp/rsi/rdi)
    # Also 4C 8D ... for r8+
    # And 8D 0D without rex
    found = []
    for r in ranges:
        base = int(r["base"], 16)
        data = Path(r["file"]).read_bytes()
        # Only scan likely code ranges (high addresses / rwx)
        for i in range(0, len(data) - 7):
            b0, b1, b2 = data[i], data[i + 1], data[i + 2]
            disp_off = None
            # REX.W lea
            if b0 in (0x48, 0x4C) and b1 == 0x8D and (b2 & 0xC7) == 0x05:
                # ModRM: mod=00, rm=101 => rip-relative; reg in bits 3-5
                disp_off = i + 3
            elif b0 == 0x8D and (b1 & 0xC7) == 0x05:
                disp_off = i + 2
            # lea with 67 prefix skip
            # MOV r64, [rip+disp] : 48 8B 0D etc
            elif b0 in (0x48, 0x4C) and b1 == 0x8B and (b2 & 0xC7) == 0x05:
                disp_off = i + 3
            # LEA without REX already handled
            # push/call not
            if disp_off is None:
                continue
            disp = struct.unpack_from("<i", data, disp_off)[0]
            rip = base + disp_off + 4
            if rip + disp == target_va:
                found.append(base + i)
                if len(found) >= 20:
                    break
        if len(found) >= 20:
            break
    print(f"\n=== RIP-rel xrefs to {label} {target_va:#x}: {len(found)} ===")
    for va in found:
        print(f"  insn@{va:#x}")


for label, va in TARGETS.items():
    scan_code_for_imm32(va, label)
    scan_rip_rel(va, label)
