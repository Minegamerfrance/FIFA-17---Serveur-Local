"""Find Blaze header unpack (symmetric to FramePack @ 0x146dbba60)."""
from __future__ import annotations

import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

ROOT = Path(__file__).resolve().parent
ranges = {
    r["file"]: (int(r["base"], 16), r["size"])
    for r in json.loads((ROOT / "rx-meta.json").read_text())["ranges"]
}
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

FRAME_PACK = 0x146DBBA60
MODULE = 0x140000000


def load(va: int, n: int) -> bytes | None:
    for f, (b, s) in ranges.items():
        if b <= va < b + s:
            return (ROOT / f).read_bytes()[va - b : va - b + n]
    return None


def file_for(va: int) -> tuple[Path, int, int] | None:
    for f, (b, s) in ranges.items():
        if b <= va < b + s:
            return ROOT / f, b, s
    return None


def dis(va: int, n: int = 0x200, stop_ret: bool = True):
    data = load(va, n)
    if not data:
        print(f"  !! no data @{va:#x}")
        return
    for insn in md.disasm(data, va):
        print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}")
        if stop_ret and insn.mnemonic == "ret" and insn.address > va + 0x20:
            break


def find_xrefs_to(target: int, scan_vas: list[tuple[int, int]]):
    """Scan for E8/E9 rel32 and RIP-relative LEA to target."""
    hits = []
    for start, size in scan_vas:
        info = file_for(start)
        if not info:
            continue
        path, b, _ = info
        blob = path.read_bytes()
        off0 = start - b
        chunk = blob[off0 : off0 + size]
        for i in range(len(chunk) - 5):
            op = chunk[i]
            if op in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", chunk, i + 1)[0]
                dest = start + i + 5 + rel
                if dest == target:
                    hits.append(("call/jmp", start + i, dest))
            # ff 15 / ff 25 rip-relative — skip
        # also scan mov/lea rip for absolute ptr slots pointing at target? rare for code
    return hits


def scan_header_unpack_patterns(file: str, base: int, blob: bytes, window: int = 0x80):
    """
    Heuristic: sites that assemble BE u16/u32 from consecutive byte loads
    with shl 8 / or — classic FramePack inverse.

    Look for clusters that touch offsets +0..+15 relative to a base register.
    """
    # Pattern A: movzx eax, byte ptr [reg]; shl ax/eax, 8; movzx ecx, byte ptr [reg+1]; or
    # Pattern B: reads of [reg+4],[reg+5] and [reg+6],[reg+7] nearby (classic vs fifa)
    hits = []
    # Find "shl ax/eax/r?x, 8" followed soon by or involving another movzx byte
    for i in range(0, len(blob) - 16, 1):
        # shl r16/r32, 8  encodings: 66 c1 e0 08 (ax), c1 e0 08 (eax), etc.
        b0, b1, b2, b3 = blob[i], blob[i + 1], blob[i + 2], blob[i + 3]
        is_shl8 = False
        if b0 == 0xC1 and b2 == 0x08 and (b1 & 0xF8) == 0xE0:  # shl r32, 8
            is_shl8 = True
        elif b0 == 0x66 and b1 == 0xC1 and b3 == 0x08 and (b2 & 0xF8) == 0xE0:
            is_shl8 = True
        if not is_shl8:
            continue
        va = base + i
        # look back/forward for movzx byte and or
        lo = max(0, i - 0x30)
        hi = min(len(blob), i + 0x40)
        region = blob[lo:hi]
        # count movzx r32, byte (0FB6) in window
        movzx_byte = region.count(b"\x0f\xb6")
        or_count = sum(1 for j in range(len(region)) if region[j] == 0x09 or region[j] == 0x0B)
        if movzx_byte < 2:
            continue
        # prefer sites that also reference small displacements 0..0xf in nearby mem ops
        # Capstone a short window
        data = blob[max(0, i - 0x40) : min(len(blob), i + 0x80)]
        start_va = base + max(0, i - 0x40)
        offs_seen = set()
        regs_base = set()
        for insn in md.disasm(data, start_va):
            ops = insn.op_str
            if "byte ptr" in ops or "word ptr" in ops or "dword ptr" in ops:
                # crude: +0xN
                for part in ops.replace("[", " ").replace("]", " ").replace(",", " ").split():
                    if part.startswith("+") and part[1:].startswith("0x"):
                        try:
                            d = int(part[1:], 16)
                            if d <= 0x20:
                                offs_seen.add(d)
                        except ValueError:
                            pass
                    elif part.startswith("+") and part[1:].isdigit():
                        d = int(part[1:])
                        if d <= 0x20:
                            offs_seen.add(d)
        # interesting if touches size (0) and header fields (4..15)
        if 0 in offs_seen and offs_seen & {4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF}:
            hits.append((va, sorted(offs_seen), movzx_byte))
    # dedupe by clustering within 0x20
    hits.sort()
    clustered = []
    for va, offs, mz in hits:
        if clustered and va - clustered[-1][0] < 0x20:
            continue
        clustered.append((va, offs, mz))
    return clustered


def scan_add_0x10_cursor(file: str, base: int, blob: bytes):
    """Sites that do add qword ptr [reg+disp], 0x10 near header work (cursor advance by 16)."""
    # encoding: 48 83 80/81/82... XX 10  or 48 83 40/41.. 10
    hits = []
    for i in range(len(blob) - 5):
        if blob[i] == 0x48 and blob[i + 1] == 0x83:
            # add qword ptr [reg+disp8], imm8
            modrm = blob[i + 2]
            if (modrm & 0xC0) == 0x40 and blob[i + 4] == 0x10 and (modrm & 0x38) == 0x00:
                # /0 = add
                hits.append(base + i)
            elif (modrm & 0xC0) == 0x80 and i + 7 < len(blob) and blob[i + 7] == 0x10 and (modrm & 0x38) == 0x00:
                hits.append(base + i)
    return hits


def find_func_start(va: int, max_back: int = 0x400) -> int:
    """Walk back to likely prologue: mov [rsp+8],rbx / push rbx / sub rsp."""
    data = load(va - max_back, max_back + 16)
    if not data:
        return va
    base_va = va - max_back
    # look for common MSVC prologues ending just before va
    best = va
    for i in range(len(data) - 8, -1, -1):
        chunk = data[i : i + 16]
        # 48 89 5c 24 08 = mov [rsp+8], rbx
        if chunk[:5] == b"\x48\x89\x5c\x24\x08":
            best = base_va + i
            break
        # 40 53 / 48 83 ec / 55 48 8b ec etc — push rbx; sub rsp
        if chunk[0:2] in (b"\x40\x53", b"\x48\x53") and chunk[2:5] in (
            b"\x48\x83\xec",
            b"\x48\x81\xec",
        ):
            best = base_va + i
            break
        if chunk[0] == 0x48 and chunk[1] == 0x89 and chunk[2] == 0x5C and chunk[3] == 0x24:
            best = base_va + i
            break
    return best


def search_strings_near_blaze():
    needles = [
        b"Frame",
        b"frame",
        b"Blaze",
        b"Packet",
        b"packet",
        b"Fire2",
        b"RpcRequest",
        b"component",
        b"msgType",
        b"MsgType",
        b"decode",
        b"Decode",
        b"incoming",
        b"Incoming",
        b"header",
        b"Header",
        b"Payload",
        b"payload",
        b"ERR_TIMEOUT",
        b"NOT_CONNECTED",
        b"Fire Frame",
        b"FireFrame",
        b"processPacket",
        b"ProcessPacket",
        b"handlePacket",
        b"onPacket",
        b"receive",
        b"Receive",
    ]
    # search in data-ish ranges: rx-0006 (strings mixed), and nearby
    found = []
    for f, (b, s) in ranges.items():
        if not f.startswith("rx-"):
            continue
        # only scan smaller / known string-heavy early ranges + mid
        if f not in (
            "rx-0003.bin",
            "rx-0006.bin",
            "rx-0007.bin",
            "rx-0008.bin",
            "rx-0014.bin",
        ):
            continue
        blob = (ROOT / f).read_bytes()
        for n in needles:
            start = 0
            while True:
                j = blob.find(n, start)
                if j < 0:
                    break
                # extract cstring
                end = blob.find(b"\x00", j)
                raw = blob[j : min(end if end > 0 else j + 64, j + 96)]
                try:
                    s2 = raw.decode("ascii", errors="ignore")
                except Exception:
                    s2 = repr(raw)
                if s2.isprintable() or all(32 <= c < 127 or c == 0 for c in raw[:40]):
                    found.append((b + j, s2[:80], f))
                start = j + 1
                if start - j > 0 and len(found) > 500:
                    break
    return found


def main():
    print("=== FramePack xrefs in rx-0014 ===")
    f14, b14, s14 = file_for(0x1460ED000)
    blob14 = f14.read_bytes()
    xrefs = []
    for i in range(len(blob14) - 5):
        if blob14[i] in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", blob14, i + 1)[0]
            dest = b14 + i + 5 + rel
            if dest == FRAME_PACK:
                xrefs.append((b14 + i, "e8" if blob14[i] == 0xE8 else "e9"))
    print(f"  xrefs to FramePack: {len(xrefs)}")
    for va, k in xrefs[:40]:
        print(f"    {va:#x} ({k})  RVA={va-MODULE:#x}")

    print("\n=== Heuristic header unpack clusters in rx-0014 (near Fire2 0x146db*) ===")
    # focus on Fire2 region 0x146da0000 .. 0x146e20000
    region_start = 0x146DA0000
    region_end = 0x146E30000
    off_a = region_start - b14
    off_b = region_end - b14
    clusters = scan_header_unpack_patterns("rx-0014.bin", region_start, blob14[off_a:off_b])
    # adjust VAs — scan_header used base=region_start on sliced blob, good
    print(f"  clusters: {len(clusters)}")
    for va, offs, mz in clusters[:60]:
        fn = find_func_start(va)
        print(f"  hit @{va:#x} RVA={va-MODULE:#x} offs={offs} movzx={mz} fn~{fn:#x} rva={fn-MODULE:#x}")

    print("\n=== add [reg+disp], 0x10 near FramePack (±0x8000) ===")
    near = blob14[(FRAME_PACK - 0x8000 - b14) : (FRAME_PACK + 0x8000 - b14)]
    near_base = FRAME_PACK - 0x8000
    adds = scan_add_0x10_cursor("rx-0014.bin", near_base, near)
    for va in adds:
        if abs(va - FRAME_PACK) < 0x3000:
            print(f"  {va:#x} RVA={va-MODULE:#x}  delta={va-FRAME_PACK:+#x}")

    print("\n=== Disasm candidate functions with both +4 and +6 byte reads ===")
    # Re-scan with stricter: within same 0x100 bytes, movzx byte [x+4] and [x+6] OR [x+0] size assemble
    candidates = []
    for va, offs, mz in clusters:
        if {0, 4, 6}.issubset(set(offs)) or ({0, 4, 5, 6, 7} & set(offs) == {0, 4, 5, 6, 7}):
            candidates.append(va)
        elif 0 in offs and 4 in offs and (6 in offs or 8 in offs):
            candidates.append(va)
    # also pick top by offset richness
    rich = sorted(clusters, key=lambda t: -len(t[1]))[:15]
    print("richest offset sets:")
    for va, offs, mz in rich:
        print(f"  {va:#x} offs={offs}")

    # Disasm unique function starts for top candidates
    seen_fn = set()
    for va, offs, mz in rich + [(c, [], 0) for c in candidates]:
        fn = find_func_start(va)
        if fn in seen_fn:
            continue
        seen_fn.add(fn)
        print(f"\n----- candidate fn @{fn:#x} RVA={fn-MODULE:#x} (hit near {va:#x}) -----")
        dis(fn, 0x180)

    print("\n=== String search (frame/packet/blaze related) ===")
    strs = search_strings_near_blaze()
    # filter interesting
    keys = (
        "Frame",
        "Packet",
        "Fire2",
        "Rpc",
        "header",
        "Header",
        "decode",
        "Decode",
        "incoming",
        "Receive",
        "component",
        "MsgType",
        "msgType",
        "NOT_CONNECTED",
        "TIMEOUT",
        "Blaze",
        "payload",
        "Payload",
    )
    shown = 0
    for va, s, f in strs:
        if any(k in s for k in keys):
            print(f"  {va:#x} [{f}] {s!r}")
            shown += 1
            if shown > 80:
                break


if __name__ == "__main__":
    main()
