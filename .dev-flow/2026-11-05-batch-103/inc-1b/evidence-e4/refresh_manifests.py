from pathlib import Path
import hashlib
import re

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = Path(__file__).resolve().parent

for manifest in sorted(EVIDENCE.rglob("SHA256SUMS*")):
    if not manifest.is_file():
        continue
    output = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^[0-9a-f]{64}\s+(.+)$", line)
        if not match:
            if line.strip():
                output.append(line)
            else:
                output.append("")
            continue
        name = match.group(1)
        if name.endswith(" (unmodified base)"):
            output.append(line)
            continue
        prefix = "*" if name.startswith("*") else ""
        relative = name[1:] if prefix else name
        target = ROOT / relative
        if not target.is_file():
            target = manifest.parent / relative
        if not target.is_file():
            raise FileNotFoundError(f"{manifest}: {relative}")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        output.append(f"{digest}  {prefix}{relative}")
    manifest.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(manifest.relative_to(ROOT).as_posix())
