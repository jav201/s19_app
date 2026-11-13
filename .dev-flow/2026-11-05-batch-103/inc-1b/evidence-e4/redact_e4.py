from pathlib import Path
import hashlib
import os
import sys

ROOT = Path(__file__).resolve().parent
# The literal account, host and path tokens are not kept in this public repo.
# S19_REDACT_FILE names a local file with one `<needle>\t<replacement>` pair per
# line, in the order they apply (longest needles first).
_token_file = os.environ.get("S19_REDACT_FILE")
if not _token_file:
    sys.exit("redact_e4: set S19_REDACT_FILE to the local token file")
REPLACEMENTS = [
    tuple(part.encode("utf-8") for part in line.split("\t", 1))
    for line in Path(_token_file).read_text(encoding="utf-8").splitlines()
    if "\t" in line
]

for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or path == Path(__file__):
        continue
    data = path.read_bytes()
    if b"\x00" in data:
        continue
    original = data
    counts = []
    for index, (needle, replacement) in enumerate(REPLACEMENTS, 1):
        count = data.count(needle)
        if count:
            data = data.replace(needle, replacement)
        counts.append(count)
    if data != original:
        path.write_bytes(data)
    if any(counts):
        print(f"{path.relative_to(ROOT).as_posix()}: " + ",".join(map(str, counts)))

for directory in sorted(path for path in ROOT.iterdir() if path.is_dir()):
    lines = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name.startswith("SHA256SUMS"):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    if lines:
        (directory / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
