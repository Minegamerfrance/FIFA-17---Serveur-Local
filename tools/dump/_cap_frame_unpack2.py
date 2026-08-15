"""Scan for Blaze header UNPACK: movzx-byte + shl 8 + or, with offs 0..15."""
from __future__ import annotations

import re
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

ROOT = Path(__file__).resolve().parent
blob = (ROOT / "rx-0014.bin").read_bytes()
base = 0x1460ED000
MODULE = 0x140000000
md = Cs(CS_ARCH_X86, CS_MODE_64)

DISP_RE = re.compile(r"\[\s*([a-z0-9]+)\s*(?:\+\s*(0x[0-9a-f]+|\d+))?\s*\]", re.I)


def find_func_start(va: int, max_back: int = 0x600) -> int:
    off = va - base
    for back in range(0, max_back):
        p = off - back
        if p < 0:
            break
        if blob[p : p + 5] == b"\x48\x89\x5c\x24\x08":
            return base + p
        if blob[p : p + 4] == b"\x48\x89\x5c\x24":
            return base + p
        # int3 padding then code
        if back > 8 and blob[p] == 0xCC and blob[p + 1] != 0xCC:
            # next instr after int3s
            q = p + 1
            while q < len(blob) and blob[q] == 0xCC:
                q += 1
            if base + q <= va:
                return base + q
    return va


def parse_disps(op_str: str):
    out = []
    for m in DISP_RE.finditer(op_str):
        reg = m.group(1).lower()
        disp = m.group(2)
        d = 0
        if disp:
            d = int(disp, 16) if disp.startswith("0x") or disp.startswith("0X") else int(disp)
        out.append((reg, d))
    return out


def scan_region(start: int, end: int):
    """Find shl-8 sites with nearby byte loads from buffer offsets 0..0x10."""
    off0 = start - base
    off1 = end - base
    hits = []
    i = off0
    while i < off1 - 4:
        # shl ax,8 = 66 c1 e0..e7 08 ; shl eax/r32,8 = c1 e0..e7 08 ; shl r8w etc
        matched = None
        if blob[i] == 0x66 and blob[i + 1] == 0xC1 and blob[i + 3] == 0x08 and (blob[i + 2] & 0xF8) == 0xE0:
            matched = i
            sz = 4
        elif blob[i] == 0xC1 and blob[i + 2] == 0x08 and (blob[i + 1] & 0xF8) == 0xE0:
            matched = i
            sz = 3
        elif blob[i] in (0x41, 0x44, 0x45) and blob[i + 1] == 0xC1 and blob[i + 3] == 0x08 and (blob[i + 2] & 0xF8) == 0xE0:
            # REX + shl r32, 8
            matched = i
            sz = 4
        elif blob[i] == 0x66 and blob[i + 1] in (0x41, 0x44, 0x45) and blob[i + 2] == 0xC1 and blob[i + 4] == 0x08:
            matched = i
            sz = 5
        if matched is None:
            i += 1
            continue

        va = base + matched
        win_lo = max(off0, matched - 0x50)
        win_hi = min(off1, matched + 0x60)
        data = blob[win_lo:win_hi]
        start_va = base + win_lo
        offs = set()
        regs = set()
        has_or = False
        movzx_byte = 0
        for insn in md.disasm(data, start_va):
            if insn.mnemonic in ("or", "or"):
                has_or = True
            if insn.mnemonic == "movzx" and "byte ptr" in insn.op_str:
                movzx_byte += 1
            if "byte ptr" in insn.op_str or "word ptr" in insn.op_str:
                for reg, d in parse_disps(insn.op_str):
                    if d <= 0x20:
                        offs.add(d)
                        regs.add(reg)
        score = 0
        if movzx_byte >= 2:
            score += 2
        if has_or:
            score += 1
        if 0 in offs:
            score += 2
        if offs & {4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF}:
            score += len(offs & set(range(0, 0x11)))
        if score >= 5:
            hits.append((va, score, sorted(offs), sorted(regs), movzx_byte))
        i = matched + sz

    # cluster
    hits.sort()
    out = []
    for h in hits:
        if out and h[0] - out[-1][0] < 0x18:
            # keep higher score
            if h[1] > out[-1][1]:
                out[-1] = h
            continue
        out.append(h)
    return out


def dis(va, n=0x200):
    data = blob[va - base : va - base + n]
    print(f"===== @{va:#x} RVA={va - MODULE:#x} =====")
    for insn in md.disasm(data, va):
        print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}")
        if insn.mnemonic == "ret" and insn.address > va + 0x40:
            break


def main():
    # Broad Fire2 / Blaze region in rx-0014: 0x146daa000 .. 0x146e50000
    regions = [
        (0x146DAA000, 0x146E50000, "Fire2/Blaze core"),
        (0x146DB0000, 0x146DC0000, "near FramePack"),
    ]
    all_hits = []
    for a, b, name in regions:
        hits = scan_region(a, b)
        print(f"=== {name} {a:#x}-{b:#x}: {len(hits)} hits ===")
        for va, score, offs, regs, mz in hits:
            fn = find_func_start(va)
            print(
                f"  @{va:#x} RVA={va-MODULE:#x} score={score} offs={offs} regs={regs} mz={mz} fn~{fn:#x}/{fn-MODULE:#x}"
            )
            all_hits.append((fn, va, score, offs))

    # Unique fns sorted by score
    by_fn = {}
    for fn, va, score, offs in all_hits:
        by_fn.setdefault(fn, []).append((score, va, offs))
    ranked = sorted(by_fn.items(), key=lambda kv: -max(x[0] for x in kv[1]))
    print("\n=== Top unique functions ===")
    for fn, lst in ranked[:25]:
        best = max(lst, key=lambda x: x[0])
        print(f"  fn {fn:#x} RVA={fn-MODULE:#x} best_score={best[0]} hit@{best[1]:#x} offs={best[2]}")

    print("\n=== Disasm top candidates (excluding FramePack itself) ===")
    shown = 0
    for fn, lst in ranked:
        if fn == 0x146DBBA60:
            continue
        best = max(lst, key=lambda x: x[0])
        if best[0] < 6:
            continue
        # Prefer functions that touch both size(0) and mid-header
        offs = set(best[2])
        if not (0 in offs and offs & {4, 5, 6, 7, 8, 9}):
            continue
        print(f"\n# candidate score={best[0]} offs={sorted(offs)}")
        dis(fn, 0x280)
        shown += 1
        if shown >= 8:
            break

    # Also search for cmp *, 0x10 near movups xmm (copy 16-byte header)
    print("\n=== movups xmmword near Fire2 (16-byte header copies) ===")
    a, b = 0x146DAA000 - base, 0x146E50000 - base
    count = 0
    i = a
    while i < b - 3 and count < 40:
        # movups xmm, [mem] = 0F 10  or 41 0F 10
        if blob[i : i + 2] == b"\x0f\x10" or (
            blob[i] in (0x41, 0x44, 0x45) and blob[i + 1 : i + 3] == b"\x0f\x10"
        ):
            va = base + i
            # check nearby for 0x10 immediates / header field stores
            win = blob[max(a, i - 0x20) : min(b, i + 0x40)]
            # disasm short
            data = blob[i : i + 8]
            for insn in md.disasm(blob[max(0, i - 8) : i + 0x30], base + max(0, i - 8)):
                if "xmmword" in insn.op_str or insn.mnemonic == "movups":
                    if any(x in insn.op_str for x in ("+ 0x", "+ 0xb", "+ 0xc", "rsp", "rbx", "rsi", "rdi", "rcx", "rdx")):
                        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
                        count += 1
                        break
            i += 3
            continue
        i += 1


if __name__ == "__main__":
    main()
