import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_ACTIVE = os.environ.get("SKIP_ACTIVE")
ACCOUNT = "javier" + "gr"
USER = "jjg" + "h8"
PYTHON = "/home/" + ACCOUNT + "/miniconda3/envs/s19ci/bin/python"
REPLACEMENTS = (
    ("C:\\Users\\" + USER, "<user-profile>"),
    ("C:/Users/" + USER, "<user-profile>"),
    (PYTHON, "<runner-python>"),
    ("/home/" + ACCOUNT, "<runner-home>"),
    ("pytest-of-" + ACCOUNT, "pytest-of-<account>"),
    ("192.168.1." + "67", "<runner>"),
    (ACCOUNT, "<account>"),
    (USER, "<user>"),
)

changed = []
for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or (SKIP_ACTIVE and path.name == SKIP_ACTIVE):
        continue
    data = path.read_bytes()
    if b"\x00" in data:
        continue
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        continue
    counts = []
    for old, new in REPLACEMENTS:
        count = text.count(old)
        if count:
            text = text.replace(old, new)
            counts.append((new, count))
    text, count = re.subn(r"pytest-of-[A-Za-z0-9_.-]+", "pytest-of-<account>", text)
    if count:
        counts.append(("pytest-of-<account>", count))
    if counts:
        path.write_bytes(text.encode("utf-8"))
        changed.append((path.relative_to(ROOT).as_posix(), counts))

for name, counts in changed:
    print(name, sum(count for _, count in counts), counts)
print(f"files_changed={len(changed)} replacements={sum(count for _, counts in changed for _, count in counts)}")
