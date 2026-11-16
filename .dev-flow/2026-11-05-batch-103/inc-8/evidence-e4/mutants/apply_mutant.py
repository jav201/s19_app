"""apply_mutant.py <tree-root> <key> | --check <tree-root>: apply one mutation of mutants.py to a tree copy.

The edits are exact-string replacements; each ``old`` must occur exactly once (else exit 3).
Files are read and written as bytes (LF kept). ``--check`` verifies every key on a scratch
copy of each touched file in memory and writes nothing.
"""
import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutants import M  # noqa: E402


def edits_for(root, key):
    out = {}
    for path, old, new in M[key][1]:
        full = os.path.join(root, path)
        data = out.get(path)
        if data is None:
            with open(full, "rb") as handle:
                data = handle.read().decode("utf-8")
        if data.count(old) != 1:
            raise SystemExit(f"{key}: {path}: old string occurs {data.count(old)} times")
        out[path] = data.replace(old, new)
    return out


def main(argv):
    if argv[1] == "--check":
        bad = 0
        for key in M:
            try:
                edits_for(argv[2], key)
            except SystemExit as exc:
                print("BAD", exc)
                bad += 1
        print(f"checked {len(M)} keys, {bad} bad")
        return 1 if bad else 0
    root, key = argv[1], argv[2]
    for path, data in edits_for(root, key).items():
        with open(os.path.join(root, path), "wb") as handle:
            handle.write(data.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
