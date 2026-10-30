"""Find pairs of distinct single characters that os.path.normcase maps to the
same key but NTFS stores as two different names (the _EntryWalk cache key)."""
import os, sys, tempfile, collections
groups = collections.defaultdict(list)
for cp in range(0x20, 0x10000):
    if 0xD800 <= cp <= 0xDFFF: continue
    ch = chr(cp)
    if ch in '<>:"/\|?*': continue
    groups[os.path.normcase(ch)].append(ch)
pairs = [(k, v) for k, v in groups.items() if len(v) > 1]
print("normcase groups with >1 member:", len(pairs))
base = tempfile.mkdtemp(prefix="r2nc_", dir=sys.argv[1])
distinct = []
for key, members in pairs:
    d = os.path.join(base, "g%04x" % ord(key[0]))
    os.mkdir(d)
    made = []
    for m in members:
        try:
            fd = os.open(os.path.join(d, "n" + m), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd); made.append(m)
        except FileExistsError:
            pass
        except OSError:
            pass
    if len(made) > 1:
        distinct.append([hex(ord(m)) for m in made])
print("pairs NTFS keeps distinct but normcase merges:", len(distinct))
for row in distinct[:40]:
    print("  ", row)
import shutil; shutil.rmtree(base)
