from pathlib import Path
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
OUT = Path(os.environ.get("B103_FULL_SUITE_OUT", "/tmp/b103-full-suite"))
OUT.mkdir(parents=True, exist_ok=True)
CHUNKS = 8

files = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "tests").glob("test_*.py"))
if not files:
    raise SystemExit("no test files found")
size = (len(files) + CHUNKS - 1) // CHUNKS
chunks = [files[index:index + size] for index in range(0, len(files), size)]
summary = []
for number, chunk in enumerate(chunks, 1):
    log = OUT / f"chunk-{number:02d}.txt"
    code = (
        "import sys; sys.path.insert(0, '.'); import s19_app; "
        "print(s19_app.__file__, flush=True); import pytest; "
        f"raise SystemExit(pytest.main(['-q', '-p', 'no:cacheprovider', *{chunk!r}]))"
    )
    started = time.monotonic()
    with log.open("wb") as stream:
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", code],
            cwd=ROOT,
            env=os.environ,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
    item = {
        "chunk": number,
        "tests_files": len(chunk),
        "returncode": completed.returncode,
        "seconds": round(time.monotonic() - started, 2),
        "log": log.name,
    }
    summary.append(item)
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(item), flush=True)
raise SystemExit(0 if all(item["returncode"] == 0 for item in summary) else 1)
