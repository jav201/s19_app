"""X10 diagnosis of TC-B100-59 open-project save: the status lines the save produced (tree vs base)."""
import os
import pathlib
import tempfile

import tests.test_b100_save_image as m

seen = []
orig = m._status_text


def spy(app):
    text = orig(app)
    if not seen or seen[-1] != text:
        seen.append(text)
    return text


m._status_text = spy
try:
    m._open_project_session(pathlib.Path(tempfile.mkdtemp(dir=os.environ["TMPDIR"])), patch=False)
    print("RESULT ok")
except Exception as exc:  # noqa: BLE001
    print("RESULT", type(exc).__name__, exc)
for line in seen[-6:]:
    print("STATUS", line[:300])
