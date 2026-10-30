"""Apply one single-occurrence reviewer mutation; the literal two-character
sequence backslash-n in OLD / NEW stands for the file's own line ending."""
import hashlib
import sys
from pathlib import Path

path, old, new = Path(sys.argv[1]), sys.argv[2].encode(), sys.argv[3].encode()
data = path.read_bytes()
nl = b"\r\n" if b"\r\n" in data else b"\n"
marker = bytes([92, 110])  # backslash, n
old, new = old.replace(marker, nl), new.replace(marker, nl)
assert data.count(old) == 1, data.count(old)
before = hashlib.sha256(data).hexdigest()[:16]
data = data.replace(old, new)
path.write_bytes(data)
print(f"# mutant: {path}\n#   old: {old!r}\n#   new: {new!r}\n#   sha256[:16] before {before} after {hashlib.sha256(data).hexdigest()[:16]}")
