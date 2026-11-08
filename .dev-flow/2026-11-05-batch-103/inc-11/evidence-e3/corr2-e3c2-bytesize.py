"""Inc 11 E3 correction round 2 (batch-103), runner only: on the 35 tracked A2L files at e07fb00, how many tags have no
length but an enriched byte_size (the layout's element size, a2l.py:2890)? Those are the tags whose enriched size
E3S-18's ruling ("no length -> no byte_size") removes. Counts only, by section and kind; no file text, no tag name.

    python -I e3c2-bytesize.py <repo>
"""
import collections, pathlib, subprocess, sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo))
from s19_app.tui.a2l import parse_a2l_file, enrich_a2l_tags_with_values  # noqa: E402

files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True,
                       check=True).stdout.split()
print("tracked files", len(files))
tot = 0
hit = collections.Counter()
per_file = collections.Counter()
for rel in files:
    data = parse_a2l_file(repo / rel)
    for t in enrich_a2l_tags_with_values(data, {}):
        tot += 1
        if t.get("length") is None and t.get("byte_size") is not None:
            key = (t.get("section") or "?", t.get("char_type") or "-")
            hit[key] += 1
            per_file[rel.rsplit("/", 1)[-1]] += 1
print("tags", tot)
print("length None with an enriched byte_size:", sum(hit.values()))
for k, v in sorted(hit.items()):
    print("  ", k, v)
print("files holding them:", len(per_file), "| per file:", sorted(per_file.values(), reverse=True))
