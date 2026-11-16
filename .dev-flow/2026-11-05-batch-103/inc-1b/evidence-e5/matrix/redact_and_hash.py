from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REDACTOR_PATH = ROOT.parent / "redact_e5.py"

spec = importlib.util.spec_from_file_location("e5_redaction", REDACTOR_PATH)
if spec is None or spec.loader is None:
    raise ImportError(f"cannot load {REDACTOR_PATH}")
redactor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redactor)
redactor.redact_tree(ROOT, write=True)

lines = []
for path in sorted(ROOT.iterdir()):
    if not path.is_file() or path.name == "SHA256SUMS.txt":
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {path.name}")
(ROOT / "SHA256SUMS.txt").write_bytes(
    ("\n".join(lines) + "\n").encode("utf-8")
)
