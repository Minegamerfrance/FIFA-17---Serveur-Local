from __future__ import annotations

import argparse
from pathlib import Path
import struct

import capstone
import pefile


KEYS = (b"pfyc/user/club", b"assetId", b"clubId", b"teamId")


def file_offset_to_rva(pe: pefile.PE, offset: int) -> int:
    for section in pe.sections:
        start = int(section.PointerToRawData)
        end = start + int(section.SizeOfRawData)
        if start <= offset < end:
            return int(section.VirtualAddress) + offset - start
    raise ValueError(f"file offset 0x{offset:x} is outside mapped sections")


def main() -> int:
    parser = argparse.ArgumentParser(description="Find RIP-relative xrefs to FIFA 17 POW club strings")
    parser.add_argument("dll", type=Path)
    parser.add_argument("--around-rva", type=lambda value: int(value, 0), default=None)
    parser.add_argument("--exact", action="store_true", help="start disassembly exactly at --around-rva")
    args = parser.parse_args()

    data = args.dll.read_bytes()
    pe = pefile.PE(str(args.dll), fast_load=False)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    text = next(
        (section for section in pe.sections if section.Name.rstrip(b"\0") == b".text"),
        None,
    )
    if text is None and args.around_rva is not None:
        text = next(
            section for section in pe.sections
            if int(section.VirtualAddress) <= args.around_rva
            < int(section.VirtualAddress) + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        )
    if text is None:
        raise RuntimeError("no code section found")
    text_rva = int(text.VirtualAddress)
    text_data = text.get_data()

    targets: dict[int, str] = {}
    for key in KEYS:
        start = 0
        while True:
            offset = data.find(key + b"\0", start)
            if offset < 0:
                break
            rva = file_offset_to_rva(pe, offset)
            targets[image_base + rva] = key.decode("ascii")
            print(f"STRING key={key.decode()} file=0x{offset:x} rva=0x{rva:x} va=0x{image_base+rva:x}")
            start = offset + 1

    table_targets: dict[int, str] = {}
    for target, key in sorted(targets.items()):
        rva = target - image_base
        for label, needle in (
            ("VA64", struct.pack("<Q", target)),
            ("RVA32", struct.pack("<I", rva)),
        ):
            start = 0
            while True:
                offset = data.find(needle, start)
                if offset < 0:
                    break
                try:
                    ref_rva = file_offset_to_rva(pe, offset)
                except ValueError:
                    start = offset + 1
                    continue
                print(f"TABLE_REF key={key} kind={label} file=0x{offset:x} rva=0x{ref_rva:x}")
                table_targets[image_base + ref_rva] = key
                start = offset + 1

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    # FIFA17.exe stores executable code in an unusually large `.data` section.
    # Avoid decoding that whole section when only a local window was requested.
    instructions = [] if args.around_rva is not None and len(text_data) > 0x2000000 else list(md.disasm(text_data, image_base + text_rva))
    if args.around_rva is not None:
        window_rva = args.around_rva if args.exact else max(text_rva, args.around_rva - 0x180)
        window_data = pe.get_data(window_rva, 0x300)
        window_instructions = list(md.disasm(window_data, image_base + window_rva))
        print(f"DISASM around_rva=0x{args.around_rva:x}")
        for insn in window_instructions:
            marker = "=>" if insn.address <= image_base + args.around_rva < insn.address + insn.size else "  "
            print(f"{marker} 0x{insn.address-image_base:08x}  {insn.mnemonic:<8} {insn.op_str}")
    hits: list[tuple[int, str, str, int]] = []
    for insn in instructions:
        for operand in insn.operands:
            if operand.type == capstone.x86.X86_OP_IMM and operand.imm in targets:
                key = targets[operand.imm]
                hits.append((insn.address, insn.mnemonic, insn.op_str, operand.imm))
                print(
                    f"XREF_IMM key={key} rva=0x{insn.address-image_base:x} "
                    f"insn={insn.mnemonic} {insn.op_str}"
                )
        for operand in insn.operands:
            if operand.type != capstone.x86.X86_OP_MEM:
                continue
            mem = operand.mem
            if mem.base != capstone.x86.X86_REG_RIP:
                continue
            target = insn.address + insn.size + mem.disp
            key = targets.get(target)
            if key:
                hits.append((insn.address, insn.mnemonic, insn.op_str, target))
                print(
                    f"XREF key={key} rva=0x{insn.address-image_base:x} "
                    f"insn={insn.mnemonic} {insn.op_str}"
                )
            table_key = table_targets.get(target)
            if table_key:
                hits.append((insn.address, insn.mnemonic, insn.op_str, target))
                print(
                    f"TABLE_XREF key={table_key} table_rva=0x{target-image_base:x} "
                    f"code_rva=0x{insn.address-image_base:x} insn={insn.mnemonic} {insn.op_str}"
                )

    print(f"SUMMARY strings={len(targets)} xrefs={len(hits)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
