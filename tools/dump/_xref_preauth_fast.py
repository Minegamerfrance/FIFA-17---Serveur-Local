"""Fast xref: pointer slots + LEA rip-rel in blaze code ranges only."""
from pathlib import Path
import json
import struct

meta = json.loads(Path("rx-meta.json").read_text(encoding="utf-8"))
ranges = {r["file"]: (int(r["base"], 16), r["size"]) for r in meta["ranges"]}

TARGETS = {
    "PreAuthResponse": 0x1438952E5,
    "PreAuthResponse_s": 0x1438952F8,
    "PreAuthRequest": 0x1438952B5,
    "preAuth": 0x143895930,
    "cem_ea_id": 0x14354B000 + 0x33A148,
    "pingPeriod": 0x14354B000 + 0x355A30,
    "UtilComponent": 0x14354B000 + 0x34A858,
    "connIdleTimeout": 0x14354B000 + 0x355A58,
}


def load(file):
    base, _ = ranges[file]
    return base, Path(file).read_bytes()


# 1) pointer slots (qword = VA)
print("=== pointer slots (qword) ===")
ptr_slots = {k: [] for k in TARGETS}
for file, (base, size) in ranges.items():
    data = Path(file).read_bytes()
    for label, tva in TARGETS.items():
        needle = struct.pack("<Q", tva)
        idx = 0
        while True:
            i = data.find(needle, idx)
            if i < 0:
                break
            # align?
            ptr_slots[label].append(base + i)
            idx = i + 1
for label, slots in ptr_slots.items():
    if slots:
        print(f"  {label}: {[hex(s) for s in slots[:12]]} (n={len(slots)})")

# 2) RIP-rel LEA/MOV in code bins that cover Blaze (~0x146–0x147)
CODE_FILES = ["rx-0013.bin", "rx-0014.bin", "rx-0015.bin", "rx-0016.bin"]
print("\n=== RIP-rel LEA/MOV to targets (code bins) ===")
for file in CODE_FILES:
    base, data = load(file)
    print(f"-- {file} base={base:#x} --")
    for i in range(len(data) - 7):
        b0 = data[i]
        # 48/4C 8D /r with rip-rel, or 48/4C 8B /r rip-rel
        if b0 in (0x48, 0x4C) and data[i + 1] in (0x8D, 0x8B) and (data[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", data, i + 3)[0]
            rip = base + i + 7
            dest = rip + disp
            for label, tva in TARGETS.items():
                if dest == tva:
                    print(f"  {label} insn@{base+i:#x} dest={dest:#x}")
        elif b0 == 0x8D and (data[i + 1] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", data, i + 2)[0]
            rip = base + i + 6
            dest = rip + disp
            for label, tva in TARGETS.items():
                if dest == tva:
                    print(f"  {label} insn@{base+i:#x} dest={dest:#x}")

# 3) Also search for component/command dispatch constants: util=9 cmd=7 as immediates near each other
print("\n=== nearby imm16 0x0009 and 0x0007 patterns in rx-0014 (sample) ===")
base, data = load("rx-0014.bin")
# look for cmp/mov with 9 then nearby 7 — limited
count = 0
for i in range(0, len(data) - 16):
    # cmp r16/32/64, imm8 9? too noisy
    # mov edx, 9 ; mov r8d, 7  common for RpcRequest
    if data[i : i + 5] == b"\xba\x09\x00\x00\x00":  # mov edx, 9
        window = data[i : i + 24]
        if b"\x07\x00\x00\x00" in window or b"\xb8\x07\x00\x00\x00" in window or b"\xb9\x07\x00\x00\x00" in window:
            print(f"  mov edx,9 @{base+i:#x} win={window.hex()}")
            count += 1
            if count >= 15:
                break
print(f"  shown {count}")
