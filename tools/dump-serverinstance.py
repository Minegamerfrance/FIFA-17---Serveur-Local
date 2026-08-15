"""Dump ServerInstanceInfo / redirector-related strings from FIFA17.exe."""
from pathlib import Path

exe = Path(r"C:\Users\Mineg\Desktop\serveur fifa 17\FIFA 17\FIFA17.exe")
data = exe.read_bytes()
print(f"size={len(data):,}")

needles = [
    b"ServerInstanceInfo",
    b"getServerInstance",
    b"serverinstancereply",
    b"ServerInstanceRequest",
    b"Heat2",
    b"Fire2",
    b"ippair",
    b"hostnameaddress",
    b"xboxclientaddress",
    b"IpPairAddress",
    b"HostnameAddress",
    b"NetworkAddress",
    b"standardSecure_v4",
    b"connectionprofile",
    b"ProtoHttp",
    b"defaultdnsaddress",
    b"DefaultDnsAddress",
]


def find_all(needle: bytes, limit: int = 12) -> list[int]:
    idxs: list[int] = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        idxs.append(i)
        start = i + 1
        if len(idxs) >= limit:
            break
    return idxs


for n in needles:
    idxs = find_all(n)
    print(f"{n.decode('latin1', 'replace')}: n={len(idxs)} offs={[hex(i) for i in idxs]}")


def dump_strings_around(key: bytes, before: int = 0x600, after: int = 0xA00) -> None:
    pos = data.find(key)
    if pos < 0:
        print(f"MISSING {key!r}")
        return
    print(f"\n=== context around {key.decode()} @ {hex(pos)} ===")
    lo = max(0, pos - before)
    hi = min(len(data), pos + after)
    chunk = data[lo:hi]
    strings: list[tuple[int, str]] = []
    cur = bytearray()
    cur_off = 0
    for i, b in enumerate(chunk):
        if 32 <= b < 127:
            if not cur:
                cur_off = lo + i
            cur.append(b)
        else:
            if len(cur) >= 4:
                strings.append((cur_off, cur.decode("ascii")))
            cur = bytearray()
    if len(cur) >= 4:
        strings.append((cur_off, cur.decode("ascii")))
    for off, s in strings:
        print(f"  {hex(off)}: {s}")


dump_strings_around(b"ServerInstanceInfo")
dump_strings_around(b"getServerInstance", before=0x200, after=0x400)

# Wide scan: any *address* / *instance* ascii near redirector keywords
print("\n=== global interesting substrings ===")
interesting = re_pat = (
    b"Instance",
    b"Address",
    b"ippair",
    b"hostname",
    b"secure",
    b"redirect",
    b"Redirector",
)
# Only dump unique lowercased hits containing address/instance near ServerInstanceInfo region
pos = data.find(b"ServerInstanceInfo")
region = data[max(0, pos - 0x5000) : min(len(data), pos + 0x5000)]
hits = set()
cur = bytearray()
base = max(0, pos - 0x5000)
cur_off = 0
for i, b in enumerate(region):
    if 32 <= b < 127:
        if not cur:
            cur_off = base + i
        cur.append(b)
    else:
        if len(cur) >= 6:
            s = cur.decode("ascii")
            sl = s.lower()
            if any(
                k in sl
                for k in (
                    "instance",
                    "address",
                    "ippair",
                    "hostname",
                    "secure",
                    "redirect",
                    "dns",
                    "blaze",
                    "heat",
                    "fire",
                    "proto",
                )
            ):
                hits.add((cur_off, s))
        cur = bytearray()
for off, s in sorted(hits):
    print(f"  {hex(off)}: {s}")
