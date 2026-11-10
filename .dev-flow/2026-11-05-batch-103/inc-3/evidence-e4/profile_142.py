import cProfile
import pstats
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, ".")

from s19_app.tui.a2l_definition import describe_definitions
from tests.test_b103_a2l_definition_arrays_fix_cap import _cap_fixture

root = Path(tempfile.mkdtemp())
a2l, names = _cap_fixture(root)
profile = cProfile.Profile()
profile.enable()
describe_definitions(names, a2l)
profile.disable()
pstats.Stats(profile).sort_stats("cumulative").print_stats(35)
