"""Inc 2 E3 architect probe 2 (batch-103): masked enum objects in the tracked A2L files (pure parse only).

Usage: python i2e3a-probe2.py <clone root> <out dir>
"""
import subprocess
import sys
from pathlib import Path


def walk(sections):
    for s in sections:
        yield s
        yield from walk(s.get("children") or [])


def main(argv):
    clone = Path(argv[1])
    sys.path.insert(0, str(clone))
    import s19_app
    print("s19_app.__file__ =", s19_app.__file__)
    from s19_app.tui import a2l
    files = subprocess.run(["git", "-C", str(clone), "ls-files", "*.a2l"], capture_output=True,
                           text=True, check=True).stdout.split()
    total, addressed, per_file = 0, 0, {}
    for rel in files:
        data = a2l.parse_a2l_file(clone / rel)
        meth = {}
        for s in walk(data["sections"]):
            if s.get("name") == "COMPU_METHOD":
                tok = a2l._flatten_body_tokens([s.get("meta", "")] + (s.get("lines") or []))
                if tok:
                    meth.setdefault(tok[0], tok)
        for t in data["tags"]:
            if t.get("bit_org") is None:
                continue
            tok = meth.get(str(t.get("conversion") or ""))
            if tok and len(tok) > 2 and tok[2] == "TAB_VERB":
                total += 1
                if t.get("address") is not None:
                    addressed += 1
                    per_file[rel] = per_file.get(rel, 0) + 1
    print("[Q1 masked TAB_VERB objects: total / with an address / per file]", (total, addressed, per_file))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
