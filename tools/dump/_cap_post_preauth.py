"""Disassemble the native hand-off immediately after Blaze PreAuth."""
from pathlib import Path
import json
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


HERE = Path(__file__).resolve().parent
MODULE_BASE = 0x140000000
RANGES = {
    item["file"]: (int(item["base"], 16), int(item["size"]))
    for item in json.loads((HERE / "rx-meta.json").read_text(encoding="utf-8"))["ranges"]
}

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def load(va: int, size: int) -> bytes:
    for filename, (base, range_size) in RANGES.items():
        if base <= va < base + range_size:
            available = min(size, base + range_size - va)
            return (HERE / filename).read_bytes()[va - base : va - base + available]
    raise ValueError(f"address not dumped: {va:#x}")


def ascii_at(va: int) -> str | None:
    try:
        raw = load(va, 128).split(b"\0", 1)[0]
        text = raw.decode("ascii")
        if 2 < len(text) < 128 and text.isprintable():
            return text
    except (ValueError, UnicodeDecodeError):
        pass
    return None


def annotations(insn) -> list[str]:
    result: list[str] = []
    raw = bytes(insn.bytes)

    if insn.mnemonic in ("call", "jmp") and len(raw) == 5 and raw[0] in (0xE8, 0xE9):
        target = insn.address + 5 + struct.unpack_from("<i", raw, 1)[0]
        result.append(f"target={target:#x} rva={target - MODULE_BASE:#x}")

    for operand in insn.operands:
        if operand.type == 3 and insn.reg_name(operand.mem.base) == "rip":
            target = insn.address + insn.size + operand.mem.disp
            text = ascii_at(target)
            note = f"rip={target:#x}"
            if text:
                note += f' "{text}"'
            result.append(note)

    return result


def disassemble(title: str, start: int, size: int, stop_on_ret: bool = False) -> None:
    print(f"\n===== {title} {start:#x} RVA={start - MODULE_BASE:#x} =====")
    for insn in md.disasm(load(start, size), start):
        note = annotations(insn)
        suffix = f"  ; {' | '.join(note)}" if note else ""
        print(f"{insn.address:#x}: {insn.mnemonic:9s} {insn.op_str}{suffix}")
        if stop_on_ret and insn.mnemonic == "ret":
            break


def dump_qwords(title: str, start: int, size: int) -> None:
    print(f"\n===== {title} {start:#x} =====")
    data = load(start, size)
    for offset in range(0, len(data) - 7, 8):
        value = struct.unpack_from("<Q", data, offset)[0]
        text = ascii_at(value) if MODULE_BASE <= value < 0x150000000 else None
        suffix = f' "{text}"' if text else ""
        print(f"{start + offset:#x}: {value:#018x}{suffix}")


def find_disp32(title: str, displacement: int) -> None:
    pattern = struct.pack("<I", displacement)
    print(f"\n===== {title} disp={displacement:#x} =====")
    for filename, (base, _range_size) in RANGES.items():
        data = (HERE / filename).read_bytes()
        offset = 0
        while True:
            offset = data.find(pattern, offset)
            if offset < 0:
                break
            va = base + offset
            if 0x146D00000 <= va < 0x146F00000:
                decoded = set()
                for back in range(1, 13):
                    start = va - back
                    for insn in md.disasm(load(start, 20), start, count=1):
                        raw = bytes(insn.bytes)
                        if pattern in raw and insn.address <= va < insn.address + insn.size:
                            decoded.add(
                                f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}"
                            )
                detail = " | ".join(sorted(decoded)) if decoded else "(instruction unresolved)"
                print(f"{va:#x} ({filename}) {detail}")
            offset += 1


def find_rel32_xrefs(title: str, target: int) -> None:
    print(f"\n===== {title} target={target:#x} =====")
    hits: list[int] = []
    for filename, (base, _range_size) in RANGES.items():
        data = (HERE / filename).read_bytes()
        for opcode in (0xE8, 0xE9):
            offset = 0
            while True:
                offset = data.find(bytes((opcode,)), offset)
                if offset < 0:
                    break
                if offset + 5 <= len(data):
                    displacement = struct.unpack_from("<i", data, offset + 1)[0]
                    source = base + offset
                    if source + 5 + displacement == target:
                        hits.append(source)
                offset += 1
    for source in sorted(set(hits)):
        print(f"{source:#x}: rel32 -> {target:#x}")
    if not hits:
        print("(no rel32 xrefs; likely virtual/indirect target)")


def find_qword_refs(title: str, target: int) -> None:
    print(f"\n===== {title} qword={target:#x} =====")
    pattern = struct.pack("<Q", target)
    hits: list[int] = []
    for filename, (base, _range_size) in RANGES.items():
        data = (HERE / filename).read_bytes()
        offset = 0
        while True:
            offset = data.find(pattern, offset)
            if offset < 0:
                break
            hits.append(base + offset)
            offset += 1
    for address in sorted(set(hits)):
        print(f"{address:#x}: qword -> {target:#x}")
    if not hits:
        print("(no qword refs in dumped ranges)")


disassemble("PreAuth Apply tail", 0x146E1D170, 0xD0)
disassemble("PreAuth post hand-off", 0x146E1E460, 0xB0, stop_on_ret=True)
disassemble("Util/2 Ping completion callback", 0x146E1D290, 0xD0)
disassemble("PingResponse TDF visit", 0x146DF21C0, 0xC0, stop_on_ret=True)
disassemble("PingResponse TDF visit body", 0x146DF21E0, 0x100, stop_on_ret=True)
disassemble("Ping success finalizer", 0x146E1CAC0, 0x1A0, stop_on_ret=True)
disassemble("Ping success setup", 0x146E19920, 0x100, stop_on_ret=True)
disassemble("Per-listener callback after first successful Ping", 0x146FCF789, 0x180)
disassemble("First Ping listener virtual target", 0x146DB73E0, 0x100, stop_on_ret=True)
disassemble("Common Ping listener virtual target", 0x1465734F0, 0x80, stop_on_ret=True)
disassemble("Native crash function around RVA 0x61638b5", 0x146163780, 0x280)
disassemble("Native crash function exact entry candidate A", 0x146163830, 0x100)
disassemble("Native crash function exact entry candidate B", 0x146163880, 0x120)
disassemble("Native crash instruction window", 0x1461638A0, 0x80)
find_rel32_xrefs("Direct callers of native crash region", 0x146163880)
find_rel32_xrefs("Direct callers of exact crashing helper", 0x1461638B0)
find_qword_refs("Function-pointer references to crashing helper", 0x1461638B0)
for crash_caller in (
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
    disassemble(
        f"Caller window for crash helper at {crash_caller:#x}",
        crash_caller - 0x50,
        0xB0,
    )
disassemble("Fire2 +0xc58 initializer region", 0x146DB6B40, 0x120)
disassemble("Blaze object +0xc58 assignment A", 0x146DAAB70, 0xA0)
disassemble("Blaze object +0xc58 assignment B", 0x146DAC270, 0x90)
disassemble("RpcJob-related callee", 0x146E1D360, 0x180, stop_on_ret=True)
disassemble("post helper A", 0x146DB4CE0, 0xA0, stop_on_ret=True)
disassemble("post helper B", 0x146DB4D80, 0xA0, stop_on_ret=True)
disassemble("post helper C", 0x146DB4E70, 0xA0, stop_on_ret=True)
dump_qwords("Util type descriptors before PreAuthRequest", 0x1448754C0, 0xF0)
dump_qwords("PingResponse member descriptor", 0x144874380, 0x60)
dump_qwords("PingResponse object vtable", 0x143894298, 0xA0)
find_disp32("References near BlazeSDK object+0xc58", 0xC58)
