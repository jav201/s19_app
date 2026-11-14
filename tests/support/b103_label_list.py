"""Shared fixtures and helpers of the Inc 7 label-list tests (batch-103).

Used by ``tests/test_b103_label_list.py`` (G-T-L), ``tests/test_b103_a2l_list_view.py``
(G-T-V) and ``tests/test_b103_a2l_list_at.py`` (G-T-AT). Expected values come from the
shipped parser (I-5) and the shipped matcher (I-3) or from the app's own text-mode cell
builder; the only typed data are the list text of the approved G2 scene and invented
hostile names. Nothing here reads or writes the OS clipboard.
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.a2l_parameter_picker import parse_parameter_list
from tests.support.b100_workers import settle_workers
from tests.support.timing import wait_until

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

SEED = 20260001
G2L_TEXT = (
    "VALUE_0002\nCURVE_0001, MAP_0003\nMEASUREMENT_0005\nVALUE_0042, CURVE_0017\nMAP_0024\n"
    "MAP_0001\nMEASUREMENT_0012, VALUE_0002\nCURVE_0071\nVALUE_0118\n"
)
G2L_NAMES = parse_parameter_list(G2L_TEXT)
G2L_JOINED = ", ".join(G2L_NAMES)
HOST_NAME = "A[red]\x1bB\x00\x85"
HOST_SHOWN = "A[red]�B��"


def build_case08(folder: Path) -> Path:
    """Case 08 (seed 20260001, 1.0 MB): 462 A2L tags, written under ``folder``."""
    gen.generate(folder, SEED, 1.0)
    return folder


def case_tags(case: Path) -> list:
    """The parsed A2L tags of case 08 (dicts with ``name``, ``section`` ...)."""
    return list(parse_a2l_file(case / "firmware.a2l").get("tags", []))


def case_names(case: Path) -> list:
    return [str(t.get("name") or "") for t in case_tags(case)]


def plain(value: Any) -> str:
    """The plain text of a cell, a Text or a Static's content."""
    return getattr(value, "plain", None) if hasattr(value, "plain") else str(value)


def static_text(widget: Any) -> str:
    """The plain text a Static or Label paints (never its markup)."""
    return plain(widget.render())


async def settle(pilot, n: int = 6) -> None:
    for _ in range(n):
        await pilot.pause()


async def flush(app, pilot) -> None:
    """Let the 0.15 s filter debounce run, then every worker and its hand-over."""
    await pilot.pause(0.3)
    await settle_workers(pilot)


async def open_a2l(app, pilot, case: Path, *, image: bool = True) -> None:
    """Load case 08 (image first when ``image``) and show the A2L Explorer."""
    if image:
        app.load_selected_file(case / "firmware.s19")
        await wait_until(pilot, lambda: app.current_file is not None, "image load")
    app.load_a2l_from_path(case / "firmware.a2l")
    await settle_workers(pilot)
    await settle(pilot)
    app.action_show_screen("a2l")
    await settle(pilot)


def run_a2l(tmp_path: Path, case: Path, scenario: Callable, *, size=(118, 54), image=True,
            load=True, setup: Callable | None = None):
    """Run ``await scenario(app, pilot)`` in a fresh app that shows case 08's explorer."""
    from s19_app.tui.app import S19TuiApp

    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        if setup is not None:
            setup(app)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            if load:
                await open_a2l(app, pilot, case, image=image)
            else:
                app.action_show_screen("a2l")
                await settle(pilot)
            return await scenario(app, pilot)

    return asyncio.run(drive())


def table_rows(app) -> list:
    from textual.widgets import DataTable

    table = app.query_one("#a2l_tags_list", DataTable)
    return [[plain(c) for c in table.get_row_at(i)] for i in range(table.row_count)]


def table_labels(app) -> list:
    from textual.widgets import DataTable

    return [plain(c.label) for c in app.query_one("#a2l_tags_list", DataTable).ordered_columns]


def tag_by_name(app) -> dict:
    return {t.get("name"): t for t in app._a2l_enriched_tags}


def text_cells(app, tag: dict) -> dict:
    """The text-mode cells of ``tag`` keyed by the shipped column label."""
    labels = [
        "Address", "Length", "Tag", "Source", "Raw", "Physical", "InMem", "Region",
        "Limits", "Unit", "Bits", "Endian", "Virt", "Func", "Access", "Dtype",
    ]
    return dict(zip(labels, [plain(c) for c in app._build_a2l_table_cells(tag, None)]))


async def set_filter(app, pilot, text: str) -> None:
    """Set the filter box value as a paste route would and let the viewer refresh."""
    from textual.widgets import Input

    box = app.query_one("#a2l_tags_filter_input", Input)
    box.value = text
    await flush(app, pilot)


class Hold:
    """A seam that blocks the worker thread in ``real`` until the test opens its gate."""

    def __init__(self, real: Callable, *, fail: BaseException | None = None, block=True,
                 fail_times: int | None = None) -> None:
        self.real, self.fail, self.block, self.fail_times = real, fail, block, fail_times
        self.gate, self.entered = threading.Event(), threading.Event()
        self.calls: list = []
        self.threads: list = []

    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        self.threads.append(threading.get_ident())
        self.entered.set()
        if self.block:
            self.gate.wait(30)
        if self.fail is not None and (self.fail_times is None or len(self.calls) <= self.fail_times):
            raise self.fail
        return self.real(*args, **kwargs)


def patch_seam(monkeypatch, name: str, stand_in: Callable) -> None:
    """Replace ``build_label_index`` / ``rank`` where the list module or the matcher holds it."""
    import s19_app.tui.a2l_label_list as mod
    import s19_app.tui.services.label_match as lm

    monkeypatch.setattr(mod, name, stand_in, raising=False)
    monkeypatch.setattr(lm, name, stand_in)


def real_seam(name: str) -> Callable:
    import s19_app.tui.services.label_match as lm

    return getattr(lm, name)


def capture_workers(app, monkeypatch) -> list:
    """Spy on ``app.run_worker``: every call is kept as ``(kwargs, worker)``."""
    seen: list = []
    original = app.run_worker

    def spy(work, *args, **kwargs):
        worker = original(work, *args, **kwargs)
        seen.append((kwargs, worker))
        return worker

    monkeypatch.setattr(app, "run_worker", spy)
    return seen


async def release_after_close(holds: list, pause: float = 0.6) -> None:
    """Open every gate after the app closed, then give the worker tail time to end."""
    for hold in holds:
        hold.gate.set()
    await asyncio.sleep(pause)


def worker_errors(seen: list) -> list:
    """The unhandled errors of the captured workers (a missing guard leaves one)."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not all(w.is_finished for _, w in seen):
        time.sleep(0.05)
    return [w.error for _, w in seen if w.error is not None]


# ---------------------------------------------------------------------------
# An independent oracle of the summary lines (no product code)
# ---------------------------------------------------------------------------


def oracle_rows(names: list, tag_names: set, hidden: set = frozenset()) -> list:
    """``(pos, name, status, first_pos)`` per pasted name, from the definitions alone."""
    first: dict = {}
    rows: list = []
    for pos, name in enumerate(names, 1):
        if name in first:
            rows.append((pos, name, "duplicate", first[name]))
            continue
        first[name] = pos
        status = "missing" if name not in tag_names else ("hidden" if name in hidden else "found")
        rows.append((pos, name, status, None))
    return rows


def oracle_counts(rows: list) -> str:
    n = len(rows)
    count = lambda s: sum(1 for r in rows if r[2] == s)
    dup = count("duplicate")
    line = (f"{n} pasted  ·  ● {count('found') + count('hidden')} found  ·  "
            f"✗ {count('missing')} missing  ·  = {dup} duplicate{'' if dup == 1 else 's'}")
    return line + (f"  ·  ◐ {count('hidden')} hidden by mode" if count("hidden") else "")


def oracle_ribbon(rows: list, budget: int) -> str:
    glyph = {"found": "●", "missing": "✗", "duplicate": "=", "hidden": "◐"}
    marks = [glyph[r[2]] for r in rows]
    if 2 * len(marks) <= budget:
        return "".join(m + " " for m in marks)
    return "".join(marks[:budget]) + f" +{len(marks) - budget}"


def oracle_missing(rows: list) -> str:
    def part(items, fmt):
        shown = " · ".join(fmt(r) for r in items[:20])
        return ("▸ " + shown + (f" +{len(items) - 20}" if len(items) > 20 else "")) if items else ""

    miss = [r for r in rows if r[2] == "missing"]
    dups = [r for r in rows if r[2] == "duplicate"]
    return (f"Missing {len(miss)} " + part(miss, lambda r: f"#{r[0]} {r[1]}")
            + f"    Duplicates {len(dups)} " + part(dups, lambda r: f"#{r[0]} {r[1]} (= #{r[3]})"))
