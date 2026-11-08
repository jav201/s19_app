"""apply_edits.py <file> <edits.py>: targeted replacements, each old text exactly once; CRLF kept (edits use \\n)."""
import runpy
import sys

path, spec = sys.argv[1], sys.argv[2]
EDITS = runpy.run_path(spec)["EDITS"]
with open(path, encoding="utf-8", newline="") as fh:
    s = fh.read()
crlf = "\r\n" in s
for old, new in EDITS:
    if crlf:
        old, new = old.replace("\n", "\r\n"), new.replace("\n", "\r\n")
    c = s.count(old)
    if c != 1:
        raise SystemExit(f"count {c} for: {old[:100]!r}")
    s = s.replace(old, new)
with open(path, "w", encoding="utf-8", newline="") as fh:
    fh.write(s)
print("applied", len(EDITS), "to", path)
