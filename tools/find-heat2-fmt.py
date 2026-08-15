from pathlib import Path

data = Path(r"C:\Users\Mineg\Desktop\serveur fifa 17\FIFA 17\FIFA17.exe").read_bytes()
needles = [
    b" val=",
    b'val="',
    b"valu",
    b"tdfclass",
    b"tdfid",
    b"<%s",
    b"%s val",
    b"UNION",
    b"unset",
]
for n in needles:
    hits = []
    start = 0
    while len(hits) < 6:
        j = data.find(n, start)
        if j < 0:
            break
        hits.append(j)
        start = j + 1
    print(repr(n.decode("latin1", "replace")), [hex(h) for h in hits])
    for h in hits[:2]:
        chunk = bytes(b if 32 <= b < 127 else 46 for b in data[h : h + 70])
        print(" ", chunk.decode("ascii", "replace"))
