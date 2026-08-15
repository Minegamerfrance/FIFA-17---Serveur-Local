"""Targeted disassembly for the native post-Ping access violation."""
from pathlib import Path
import json
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


HERE = Path(__file__).resolve().parent
BASE = 0x140000000
RANGES = {
    item["file"]: (int(item["base"], 16), int(item["size"]))
    for item in json.loads((HERE / "rx-meta.json").read_text(encoding="utf-8"))[
        "ranges"
    ]
}
MD = Cs(CS_ARCH_X86, CS_MODE_64)


def load(va: int, size: int) -> bytes:
    for filename, (base, range_size) in RANGES.items():
        if base <= va < base + range_size:
            available = min(size, base + range_size - va)
            data = (HERE / filename).read_bytes()
            return data[va - base : va - base + available]
    raise ValueError(f"address not dumped: {va:#x}")


def disassemble(title: str, start: int, size: int) -> None:
    print(f"\n===== {title} start={start:#x} rva={start - BASE:#x} =====")
    for insn in MD.disasm(load(start, size), start):
        suffix = ""
        raw = bytes(insn.bytes)
        if insn.mnemonic in ("call", "jmp") and len(raw) == 5 and raw[0] in (
            0xE8,
            0xE9,
        ):
            target = insn.address + 5 + struct.unpack_from("<i", raw, 1)[0]
            suffix = f" ; target={target:#x} rva={target - BASE:#x}"
        print(f"{insn.address:#x}: {insn.mnemonic:9s} {insn.op_str}{suffix}")


disassemble("crashing helper", 0x1461638A0, 0x60)
disassemble("second crashing helper", 0x146163190, 0xB0)
disassemble("ServiceResolver cleanup called after Ping", 0x146DF0360, 0x180)
disassemble("Fire2 post-Ping cleanup call site", 0x146DB7420, 0x60)
for caller in (
    0x145374DCE,
    0x145374E57,
    0x145375161,
    0x145376327,
    0x14537646E,
    0x1453764B1,
    0x1453764D3,
    0x145376501,
    0x145376558,
):
    disassemble(f"caller {caller:#x}", caller - 0x30, 0x70)
