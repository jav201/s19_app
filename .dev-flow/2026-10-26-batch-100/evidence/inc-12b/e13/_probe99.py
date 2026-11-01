"""Probe: run qz-quit exactly like the selftest (chdir to base) at a size."""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))

import tools.e13.run as runner  # noqa: E402

cols = int(sys.argv[1])
rows = int(sys.argv[2])
base = Path(tempfile.mkdtemp(prefix="probeqz_")).resolve()
base.mkdir(parents=True, exist_ok=True)
os.chdir(base)
app = runner.build_app(base, "qz-quit", False)
print("app built", flush=True)


async def _once() -> None:
    async with app.run_test(size=(cols, rows)) as pilot:
        print("mounted", flush=True)
        await asyncio.wait_for(app.e13_ready.wait(), timeout=30)
        await pilot.pause()
        print("ready; screen:", type(app.screen).__name__, flush=True)
        print("status_text:", str(app.query_one("#status_text").render()), flush=True)


try:
    asyncio.run(_once())
except Exception as exc:  # noqa: BLE001
    print("EXC:", type(exc).__name__, exc, flush=True)
print("DONE", flush=True)
