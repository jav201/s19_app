import cProfile
import pstats
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.a2l_definition import describe_definitions

path = Path("examples/case_01_from_source/software_a.a2l")
if not path.exists():
    path = next(Path("examples").rglob("software_a.a2l"))
data = parse_a2l_file(path)
names = [tag["name"] for tag in data["tags"]]
print("NAMES", len(names))
profile = cProfile.Profile()
profile.enable()
describe_definitions(names, data)
profile.disable()
pstats.Stats(profile).sort_stats("cumulative").print_stats(35)
