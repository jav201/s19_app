import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import s19_app.tui.a2l_definition as model
from s19_app.tui.a2l import parse_a2l_file

path = next(Path("examples").rglob("software_a.a2l"))
data = parse_a2l_file(path)
names = [tag["name"] for tag in data["tags"]]
original = model._entry_overlaps
calls = 0


def wrapped(*args):
    global calls
    calls += 1
    return original(*args)


model._entry_overlaps = wrapped
results = []
for index, name in enumerate(names, 1):
    calls = 0
    definition = model.describe_definition(name, data)
    results.append((calls, index, name, definition.address, definition.byte_length, definition.byte_order, definition.shared_with))
for result in sorted(results, reverse=True)[:20]:
    print(result)
