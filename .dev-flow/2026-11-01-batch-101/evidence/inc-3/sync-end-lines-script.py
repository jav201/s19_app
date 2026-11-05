"""batch-101 Inc 3 E3 corrective (finding F8): the lines a data-file load paints when the open
project's folder is gone, on the tree it runs in.

P2 (image only, case_01 firmware.s19) is opened through the shipped handler; then its folder is
either deleted (``deleted``) or replaced by a regular file (``file``); then one load from outside
the work area: other.s19 (case_01), other.hex (tests/fixtures/synth/synth_hex_basic.hex) or
other.mac (case_01 firmware.mac). Prints the lines painted since the load, whether the app exited,
and whether the project folder's path exists afterwards (``lexists``) and is a folder.
Usage: python sync-end-lines-script.py <tmp root>
"""
import asyncio, os, shutil, sys, tempfile
from pathlib import Path

sys.path.insert(0, os.getcwd())
from tests import test_b100_workers as w
from tests.support import b100_projects as projects

ROOT = Path(os.getcwd())
SOURCES = {
    "s19": ROOT / "examples" / "case_01_basic_valid" / "firmware.s19",
    "hex": ROOT / "tests" / "fixtures" / "synth" / "synth_hex_basic.hex",
    "mac": ROOT / "examples" / "case_01_basic_valid" / "firmware.mac",
}


def one(tmp: Path, kind: str, state: str) -> None:
    base = tmp / "app"
    w.trio(w.W(base) / "P2", names=("firmware.s19",))
    src = tmp / "src" / f"other.{kind}"
    src.parent.mkdir(parents=True)
    shutil.copyfile(SOURCES[kind], src)
    folder = w.W(base) / "P2"

    async def scenario(app, pilot, log):
        await w.open_trio_project(app, pilot, "P2")
        shutil.rmtree(folder)
        if state == "file":
            folder.write_bytes(b"")
        mark = len(log.messages)
        app.load_from_path(src)
        exited = await w.ended_or_exited(app, "file_load")
        return exited, log.since(mark)

    exited, lines = w.run(base, scenario)
    print(f"[{kind}/{state}] exited={exited} lexists={os.path.lexists(folder)} isdir={folder.is_dir()}")
    for line in lines:
        print(f"    {line}")


import s19_app
print("s19_app from", s19_app.__file__)
for kind in ("s19", "hex", "mac"):
    for state in ("deleted", "file"):
        one(Path(tempfile.mkdtemp(dir=sys.argv[1])), kind, state)
