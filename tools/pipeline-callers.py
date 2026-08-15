"""
Offline call-graph for Redirector → Fire2 pipeline.

Finds call/jmp sites to Fire2Connection_ctor / ServiceResolver / redir_err_mapper,
disassembles preceding branches, writes tools/dump/pipeline-callers.txt.

Usage (repo root):
  python tools/pipeline-callers.py
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_GRP_JUMP, X86_GRP_CALL

DUMP = Path(__file__).resolve().parent / "dump"
META = DUMP / "rx-meta.json"
TARGETS = DUMP / "TARGETS.json"
OUT = DUMP / "pipeline-callers.txt"

# Explicit pipeline anchors (may refine ServiceResolver to true fn entry).
DEFAULT_ANCHORS = {
    "Fire2Connection_ctor": 0x146DAAEE0,
    "ServiceResolver_a": 0x146DBAA47,
    "ServiceResolver_b": 0x1486B4561,
    "redir_err_mapper": 0x146DEE6F0,
    "BlazeHub_site": 0x146DAA9B0,
}


def load_ranges():
    meta = json.loads(META.read_text(encoding="utf-8"))
    ranges = []
    for r in meta["ranges"]:
        path = DUMP / r["file"]
        if not path.exists():
            continue
        ranges.append((int(r["base"], 16), path.read_bytes(), r["file"]))
    return ranges


def blob_at(ranges, va: int):
    for base, blob, fn in ranges:
        if base <= va < base + len(blob):
            return blob, base, fn
    return None, None, None


def find_calls_jmps(ranges, target: int, limit: int = 64):
    """E8 call rel32 / E9 jmp rel32 / EB short jmp to target."""
    hits = []
    for base, blob, fn in ranges:
        n = len(blob)
        i = 0
        while i + 5 <= n and len(hits) < limit:
            b = blob[i]
            if b == 0xE8 or b == 0xE9:
                rel = struct.unpack_from("<i", blob, i + 1)[0]
                dest = base + i + 5 + rel
                if dest == target:
                    hits.append(
                        {
                            "va": base + i,
                            "kind": "call" if b == 0xE8 else "jmp",
                            "file": fn,
                            "size": 5,
                        }
                    )
                    i += 5
                    continue
            elif b == 0xEB:
                rel = struct.unpack_from("<b", blob, i + 1)[0]
                dest = base + i + 2 + rel
                if dest == target:
                    hits.append(
                        {
                            "va": base + i,
                            "kind": "jmp8",
                            "file": fn,
                            "size": 2,
                        }
                    )
                    i += 2
                    continue
            i += 1
    return hits


def guess_fn_start(blob: bytes, base: int, hit_va: int) -> int:
    off = hit_va - base
    for b in range(1, min(0x800, off + 1)):
        p = off - b
        if blob[p] == 0xCC and b > 4:
            return base + p + 1
        if p + 3 < len(blob):
            if blob[p] == 0x40 and blob[p + 1] == 0x55:
                return base + p
            if blob[p] == 0x55 and blob[p + 1] == 0x48:
                return base + p
            if blob[p : p + 3] == b"\x48\x83\xec":
                return base + p
            if blob[p : p + 3] == b"\x48\x89\x5c":
                return base + p
            if blob[p : p + 4] == b"\x48\x8b\xc4":
                return base + p
    return hit_va


def disasm_window(ranges, va: int, before: int = 0x60, after: int = 0x10):
    blob, base, fn = blob_at(ranges, va)
    if blob is None:
        return [], None, None
    off = va - base
    start = max(0, off - before)
    end = min(len(blob), off + after)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(blob[start:end], base + start))
    return insns, base, fn


def collect_branches(insns, call_va: int):
    """Insns before call that look like conditions."""
    out = []
    for insn in insns:
        if insn.address >= call_va:
            break
        # keep recent cmp/test/jcc
        is_jcc = insn.group(X86_GRP_JUMP) and insn.mnemonic not in ("jmp", "call")
        if insn.mnemonic in ("cmp", "test", "and", "or", "xor") or is_jcc:
            out.append(f"{insn.address:x}: {insn.mnemonic}\t{insn.op_str}")
    return out[-12:]


def resolve_true_entries(ranges, anchors: dict[str, int]) -> dict[str, int]:
    """If LEA site is mid-fn, snap ServiceResolver to guessed fn start."""
    resolved = dict(anchors)
    for name in ("ServiceResolver_a", "ServiceResolver_b", "BlazeHub_site"):
        va = anchors.get(name)
        if not va:
            continue
        blob, base, _ = blob_at(ranges, va)
        if blob is None:
            continue
        resolved[name + "_fn"] = guess_fn_start(blob, base, va)
    # Fire2 already at ctor prologue
    return resolved


def main() -> int:
    if not META.exists():
        print(f"Missing {META}")
        return 1

    ranges = load_ranges()
    anchors = dict(DEFAULT_ANCHORS)
    if TARGETS.exists():
        tj = json.loads(TARGETS.read_text(encoding="utf-8"))
        for name, info in tj.get("targets", {}).items():
            if name in anchors or name in (
                "Fire2Connection_ctor",
                "ServiceResolver_a",
                "ServiceResolver_b",
                "redirector_error_mapper",
            ):
                key = "redir_err_mapper" if name == "redirector_error_mapper" else name
                if key in DEFAULT_ANCHORS or name in DEFAULT_ANCHORS:
                    anchors[key if key in DEFAULT_ANCHORS else name] = int(info["va"], 16)

    resolved = resolve_true_entries(ranges, anchors)

    lines: list[str] = []
    lines.append("# pipeline-callers — Redirector → Fire2 decision map")
    lines.append(f"# ranges={len(ranges)}")
    lines.append("")
    lines.append("## Anchors")
    for k, v in resolved.items():
        lines.append(f"  {k} = {hex(v)}")
    lines.append("")

    # Search both LEA sites and guessed fn entries for ServiceResolver
    search_targets: list[tuple[str, int]] = [
        ("Fire2Connection_ctor", anchors["Fire2Connection_ctor"]),
        ("ServiceResolver_a_lea", anchors["ServiceResolver_a"]),
        ("ServiceResolver_b_lea", anchors["ServiceResolver_b"]),
        ("redir_err_mapper", anchors["redir_err_mapper"]),
        ("BlazeHub_site", anchors["BlazeHub_site"]),
    ]
    if "ServiceResolver_a_fn" in resolved:
        search_targets.append(("ServiceResolver_a_fn", resolved["ServiceResolver_a_fn"]))
    if "ServiceResolver_b_fn" in resolved:
        search_targets.append(("ServiceResolver_b_fn", resolved["ServiceResolver_b_fn"]))

    all_fire2_callers: list[int] = []

    for name, target in search_targets:
        lines.append(f"## {name}  target={hex(target)}")
        hits = find_calls_jmps(ranges, target, limit=80)
        lines.append(f"  direct_call_jmp_sites={len(hits)}")
        if not hits:
            lines.append("  (none — may be via vtable / jmp table / register call)")
            lines.append("")
            continue

        for h in hits:
            if name.startswith("Fire2"):
                all_fire2_callers.append(h["va"])
            blob, base, _ = blob_at(ranges, h["va"])
            fn_start = guess_fn_start(blob, base, h["va"]) if blob is not None else h["va"]
            insns, _, _ = disasm_window(ranges, h["va"], before=0x70, after=0x8)
            branches = collect_branches(insns, h["va"])
            lines.append(
                f"  {h['kind']} @{hex(h['va'])}  caller_fn≈{hex(fn_start)}  file={h['file']}"
            )
            for b in branches:
                lines.append(f"    | {b}")
            # show the call line
            for insn in insns:
                if insn.address == h["va"]:
                    lines.append(f"    * {insn.address:x}: {insn.mnemonic}\t{insn.op_str}")
                    break
        lines.append("")

    # Cross-link: do any Fire2 callers also call ServiceResolver nearby?
    lines.append("## Summary")
    lines.append(f"  Fire2 direct callers: {len(all_fire2_callers)}")
    for va in all_fire2_callers:
        lines.append(f"    - {hex(va)}")
    lines.append("")
    lines.append(
        "## Next probe classification (HOOK_XREFS UT session)\n"
        "  redir_err_mapper fire     → client error path\n"
        "  ServiceResolver no Fire2  → skip between resolve and ctor\n"
        "  Fire2 no BLAZE_CONNECT    → connect path after ctor\n"
        "  nothing after XML         → callback/parse never enters resolve\n"
    )

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    # also print short summary
    for name, target in search_targets:
        hits = find_calls_jmps(ranges, target, limit=80)
        print(f"{name}: {len(hits)} call/jmp sites")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
