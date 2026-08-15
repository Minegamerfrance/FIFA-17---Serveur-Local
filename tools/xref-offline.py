"""
Offline LEA / MOV-imm64 / qword xref hunt on dumped FIFA17 r-x images.

Usage (from repo root):
  python tools/xref-offline.py
  python tools/xref-offline.py --string getServerInstanceHttp

Reads:
  tools/dump/rx-meta.json
  tools/dump/strings-map.json
  tools/dump/rx-*.bin

Writes:
  tools/dump/xref-hits.txt
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

DUMP = Path(__file__).resolve().parent / "dump"
META = DUMP / "rx-meta.json"
STRINGS = DUMP / "strings-map.json"
OUT = DUMP / "xref-hits.txt"

REXES = {0x48, 0x4C, 0x49, 0x4D}
MODRMS = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}


def parse_va(s: str) -> int:
    return int(s, 16) if isinstance(s, str) else int(s)


def find_lea64(blob: bytes, base_va: int, target_va: int, limit: int = 32) -> list[int]:
    hits: list[int] = []
    n = len(blob)
    i = 0
    while i + 7 < n and len(hits) < limit:
        b0 = blob[i]
        if b0 in REXES and blob[i + 1] == 0x8D and blob[i + 2] in MODRMS:
            disp = struct.unpack_from("<i", blob, i + 3)[0]
            instr_va = base_va + i
            if instr_va + 7 + disp == target_va:
                hits.append(instr_va)
                i += 7
                continue
        i += 1
    return hits


def find_mov_imm64(blob: bytes, base_va: int, target_va: int, limit: int = 16) -> list[int]:
    """48 B8/B9/... imm64 — absolute VA load."""
    hits: list[int] = []
    pat = struct.pack("<Q", target_va)
    start = 0
    while len(hits) < limit:
        i = blob.find(pat, start)
        if i < 0:
            break
        # check for REX.W MOV r64, imm64: 48 B8+reg
        if i >= 2 and blob[i - 2] == 0x48 and 0xB8 <= blob[i - 1] <= 0xBF:
            hits.append(base_va + i - 2)
        start = i + 1
    return hits


def find_qword_ptr(blob: bytes, base_va: int, target_va: int, limit: int = 32) -> list[int]:
    hits: list[int] = []
    pat = struct.pack("<Q", target_va)
    start = 0
    while len(hits) < limit:
        i = blob.find(pat, start)
        if i < 0:
            break
        hits.append(base_va + i)
        start = i + 1
    return hits


def guess_fn_start(blob: bytes, base_va: int, hit_va: int) -> int:
    off = hit_va - base_va
    for b in range(1, min(0x400, off + 1)):
        p = off - b
        if blob[p] == 0xCC and b > 4:
            return base_va + p + 1
        if p + 2 < len(blob):
            if blob[p] == 0x40 and blob[p + 1] == 0x55:
                return base_va + p
            if blob[p] == 0x55 and blob[p + 1] == 0x48:
                return base_va + p
            if blob[p] == 0x48 and blob[p + 1] == 0x83 and blob[p + 2] == 0xEC:
                return base_va + p
            if blob[p] == 0x48 and blob[p + 1] == 0x89 and blob[p + 2] == 0x5C:
                return base_va + p
    return hit_va


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--string", action="append", default=[], help="Only these string names")
    args = ap.parse_args()

    if not META.exists() or not STRINGS.exists():
        print(f"Missing dump files under {DUMP} — run tools\\run-dump-rx.ps1 first")
        return 1

    meta = json.loads(META.read_text(encoding="utf-8"))
    smap = json.loads(STRINGS.read_text(encoding="utf-8"))
    want = set(args.string) if args.string else set(smap.get("strings", {}).keys())

    lines: list[str] = []
    lines.append(f"# xref-offline {meta.get('dumpedAt')}")
    lines.append(f"# ranges={len(meta.get('ranges', []))} bytes={meta.get('totalBytes')}")
    lines.append("")

    for name, addrs in smap.get("strings", {}).items():
        if name not in want:
            continue
        if not addrs:
            lines.append(f"## {name}\nMISS (no string VA in dump map)\n")
            continue
        target_va = parse_va(addrs[0])
        lines.append(f"## {name}")
        lines.append(f"string_va={hex(target_va)}")

        total_lea = total_mov = total_q = 0
        for r in meta.get("ranges", []):
            path = DUMP / r["file"]
            if not path.exists():
                continue
            base_va = parse_va(r["base"])
            blob = path.read_bytes()
            leas = find_lea64(blob, base_va, target_va)
            movs = find_mov_imm64(blob, base_va, target_va)
            qs = find_qword_ptr(blob, base_va, target_va)
            total_lea += len(leas)
            total_mov += len(movs)
            total_q += len(qs)
            for va in leas:
                fn = guess_fn_start(blob, base_va, va)
                lines.append(
                    f"  LEA  @{hex(va)} fn≈{hex(fn)} file={r['file']} +0x{va - base_va:x}"
                )
            for va in movs:
                fn = guess_fn_start(blob, base_va, va)
                lines.append(
                    f"  MOV  @{hex(va)} fn≈{hex(fn)} file={r['file']} +0x{va - base_va:x}"
                )
            for va in qs[:8]:
                lines.append(f"  QWORD @{hex(va)} file={r['file']} +0x{va - base_va:x}")

        lines.append(
            f"  SUMMARY lea={total_lea} mov_imm64={total_mov} qword={total_q}"
        )
        lines.append("")
        print(f"{name}: lea={total_lea} mov={total_mov} qword={total_q}")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
