from pathlib import Path
import hashlib
import os
import subprocess
import sys

TREE = Path("/tmp/b103-e5-11-mutB-rtx/tree")
TARGET = TREE / "s19_app/tui/a2l_definition.py"
PYTHON = "/home/javiergr/miniconda3/envs/s19ci/bin/python"
NODE = "tests/test_b103_a2l_reader_coverage.py::test_cov_read_54_tab_verb_near_keyword_is_not_enum"
ANCHOR = 'conversion_type == "TAB_VERB"'
REPLACEMENT = 'conversion_type.startswith("TAB_VERB")'

sys.path.insert(0, str(TREE))
import s19_app

print(s19_app.__file__, flush=True)
original = TARGET.read_bytes()
original_hash = hashlib.sha256(original).hexdigest()
source = original.decode("utf-8")
assert source.count(ANCHOR) == 2


def run(label):
    code = (
        "import sys; sys.path.insert(0, "
        + repr(str(TREE))
        + "); import s19_app; print(s19_app.__file__, flush=True); "
        + "import pytest; raise SystemExit(pytest.main([\"-q\", \"-p\", \"no:cacheprovider\", "
        + repr(NODE)
        + "]))"
    )
    env = os.environ.copy()
    env.update(
        HOME="/tmp/b103-e5-11-mutB-rtx/zq_iso_user",
        XDG_CONFIG_HOME="/tmp/b103-e5-11-mutB-rtx/zq_iso_user/config",
        XDG_CACHE_HOME="/tmp/b103-e5-11-mutB-rtx/zq_iso_user/cache",
        XDG_DATA_HOME="/tmp/b103-e5-11-mutB-rtx/zq_iso_user/data",
        LOCALAPPDATA="/tmp/b103-e5-11-mutB-rtx/zq_iso_user/local",
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONIOENCODING="utf-8",
    )
    completed = subprocess.run(
        [PYTHON, "-I", "-B", "-c", code], cwd=TREE, env=env, stdin=subprocess.DEVNULL
    )
    print(f"{label}_EXIT={completed.returncode}", flush=True)
    return completed.returncode


try:
    TARGET.write_text(source.replace(ANCHOR, REPLACEMENT), encoding="utf-8")
    mutant_rc = run("MUTANT")
    assert mutant_rc != 0, "P17 exactness mutant SURVIVED"
finally:
    TARGET.write_bytes(original)
    assert hashlib.sha256(TARGET.read_bytes()).hexdigest() == original_hash

restored_rc = run("RESTORED")
assert restored_rc == 0
print("P17_EXACTNESS_MUTANT_KILLED_AND_BASELINE_RESTORED")
