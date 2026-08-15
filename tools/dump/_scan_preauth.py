from pathlib import Path
import json

meta = json.loads(Path("rx-meta.json").read_text(encoding="utf-8"))
# meta may be list or dict of regions
print("meta type", type(meta))
if isinstance(meta, dict):
    print(list(meta.keys())[:20])
    regions = meta.get("regions") or meta.get("maps") or meta
else:
    regions = meta
print("regions sample", str(regions)[:500])

needles = [
    b"ASRC", b"NASP", b"CIDS", b"QOSS", b"PreAuth", b"preAuth", b"PRE_AUTH",
    b"postAuth", b"PostAuth", b"cem_ea", b"pingPeriod", b"connIdleTimeout",
    b"SVER", b"MINR", b"BlazeSDK", b"UtilComponent", b"fetchClientConfig",
    b"GetTelemetryServer", b"ERR_AUTHENTICATION", b"LOGIN_",
]

root = Path(".")
# Prefer data sections (rx-0006 was used as data before)
bins = sorted(root.glob("rx-*.bin"))

# Build VA map from meta if possible
def find_region(file_offset_hint=None):
    return None

for p in bins:
    data = p.read_bytes()
    found_any = False
    for n in needles:
        hits = []
        idx = 0
        while len(hits) < 5:
            i = data.find(n, idx)
            if i < 0:
                break
            hits.append(i)
            idx = i + 1
        if hits:
            if not found_any:
                print(f"\n=== {p.name} size={len(data)} ===")
                found_any = True
            print(f"  {n!r} hits={data.count(n)} first={[hex(h) for h in hits]}")
            for h in hits[:2]:
                ctx = data[max(0, h - 8) : h + len(n) + 24]
                print(f"    @{h:#x} {ctx!r}")
