"""Inc-6 PC-10 follow-up probe: how often does a snapshot cell's status bar
paint ``(none)`` instead of the A2L name (``snap.a2l``) right after the
snapshot harness's ``run_before`` — on a given tree?

Usage: python context_race_probe.py <tree root> [cell id] [runs]
Prints, per run, the context cell text and the pauses it took to show the
A2L name (bounded at 20).
"""
import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT))
CELL = sys.argv[2] if len(sys.argv) > 2 else "mac-compact-120x30"
RUNS = int(sys.argv[3]) if len(sys.argv) > 3 else 8

from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests import test_tui_snapshot as snap  # noqa: E402


class _Factory:
    def mktemp(self, name, numbered=True):
        return Path(tempfile.mkdtemp(prefix=name))


triple = snap.public_triple._get_wrapped_function()(_Factory())
param = next(p for p in snap._ALL_SNAPSHOT_CELLS if p.id == CELL)
screen, density, size_key = param.values


async def once():
    width, height = snap._SIZES[size_key]
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=(width, height)) as pilot:
        await snap._snapshot_run_before(screen, density, triple)(pilot)
        await pilot.pause()
        first = str(app.query_one("#status_context").render())
        n = 0
        while "snap.a2l" not in str(app.query_one("#status_context").render()) and n < 20:
            await pilot.pause()
            n += 1
        return first.strip(), n


async def main():
    print("tree", ROOT, "cell", CELL)
    for _ in range(RUNS):
        print(*(await once()), flush=True)


asyncio.run(main())
