"""Find full decoder format strings and PreAuthResponse member name table."""
from pathlib import Path
import json
import struct

ranges = {
    r["file"]: (int(r["base"], 16), r["size"])
    for r in json.loads(Path("rx-meta.json").read_text())["ranges"]
}

needles = [
    b"Type contains unknown member",
    b"Map key value is not equal",
    b"XmlDecoder",
    b"Heat2Decoder",
    b"JsonDecoder",
    b"pingPeriod",
    b"connIdleTimeout",
    b"defaultRequestTimeout",
    b"autoReconnectEnabled",
    b"maxReconnectAttempts",
    b"Blaze::Util::PreAuthResponse",
]


def cstring_at(blob, i):
    # walk back to start
    s = i
    while s > 0 and blob[s - 1] >= 32 and blob[s - 1] < 127:
        s -= 1
    e = i
    while e < len(blob) and blob[e] != 0 and e - s < 200:
        e += 1
    try:
        return blob[s:e].decode("ascii")
    except Exception:
        return None


for f, (b, _sz) in ranges.items():
    blob = Path(f).read_bytes()
    for n in needles:
        idx = 0
        c = 0
        while c < 8:
            i = blob.find(n, idx)
            if i < 0:
                break
            s = cstring_at(blob, i)
            print(f"{b + i:#x} ({f}): {s!r}")
            idx = i + 1
            c += 1

# Member registration near PreAuthResponse typeinfo 0x144875610
print("\n=== near typeinfo 0x144875610 ===")
# find which file
for f, (b, sz) in ranges.items():
    if b <= 0x144875610 < b + sz:
        blob = Path(f).read_bytes()
        off = 0x144875610 - b
        # dump 0x100 before/after as qwords + try strings
        for i in range(off - 0x80, off + 0x100, 8):
            q = struct.unpack_from("<Q", blob, i)[0]
            s = None
            if 0x140000000 < q < 0x150000000:
                s = None
                for f2, (b2, sz2) in ranges.items():
                    if b2 <= q < b2 + sz2:
                        s = cstring_at(Path(f2).read_bytes(), q - b2)
                        break
            print(f"  {b + i:#x}: {q:#018x} {s!r}" if s else f"  {b + i:#x}: {q:#018x}")
