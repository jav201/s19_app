# Inc-003 gate probe for batch 2026-10-12-batch-94 — the rail 11->12 landing.
# Sibling of the PDR probe (evidence/pdr_rail_key_probe.py); where the PDR
# probe measured the CANDIDATE scheme by patching the class, this probe
# verifies the SHIPPED tree with ZERO patching: the 12-entry RAIL_ENTRIES_B94,
# the `]` Binding, the #screen_flow_execution container, and the routing.
#
# What is measured here (the R-1 closure's landing gate, design-proposal §4):
#   (a) SHIPPED CENSUS — the app composes 12 rail entries in the declared
#       order; SCREEN_CONTAINER_IDS / _FIND_GOTO_INPUTS carry flow_execution;
#       the `]` binding resolves to show_screen('flow_execution') with
#       show=False (footer chrome unchanged, C-13).
#   (b) REACHABILITY — `]` mounts #screen_flow_execution and moves the rail
#       marker, at 120x30 AND at 80x24; the ten digit bindings still resolve
#       (regression: `8` still mounts the Flow Builder).
#   (c) RAIL CHROME at 80x24 — 12 entries render inside the 21-row chrome
#       budget (24 - top 2 - footer 1, HLR-002's threshold; the C-3 arm).
#   (d) ZERO COLLISIONS — a logging watch on the "textual" logger fails the
#       probe if Textual emits any binding collision/conflict/duplicate
#       warning while the 12-entry rail + the new screen mount and run.
#
# Throwaway evidence tooling; not part of the suite.
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import textual
from textual.keys import KEY_TO_UNICODE_NAME

from s19_app.tui.app import RAIL_ENTRIES_B94, S19TuiApp
from s19_app.tui.rail import Rail, RailItem

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "ok" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""), flush=True)
    if not cond:
        FAILURES.append(name)


class CollisionWatch(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        text = record.getMessage().lower()
        if any(w in text for w in ("bind", "collision", "conflict", "duplicate")):
            self.records.append(record.getMessage())


def visible(app: S19TuiApp, widget_id: str) -> bool:
    return "hidden" not in app.query_one(f"#{widget_id}").classes


async def drive(app: S19TuiApp, pilot, size: tuple[int, int]) -> None:
    print(f"=== run_test {size[0]}x{size[1]} — shipped-tree reachability", flush=True)
    items = list(app.query(RailItem))
    order = [it.entry.key for it in items]
    check(
        "the app composes the 12 shipped rail entries",
        order == [e.key for e in RAIL_ENTRIES_B94],
        f"order={order}",
    )
    check(
        "order: flow_execution after flow (the R-1 landing)",
        order.index("flow_execution") == order.index("flow") + 1,
    )
    if size == (80, 24):
        rail = app.query_one(Rail)
        check(
            "C-3 rail-chrome arm: 12 entries inside the 21-row budget at 80x24",
            rail.region.height <= 21 and len(order) == 12,
            f"rail renders {rail.region.height} rows for {len(order)} entries",
        )

    active = app.active_bindings
    check(
        "right_square_bracket resolves to show_screen('flow_execution')",
        active.get("right_square_bracket") is not None
        and active["right_square_bracket"].binding.action
        == "show_screen('flow_execution')",
    )
    check(
        "the `]` binding is show=False (footer chrome unchanged, C-13)",
        active["right_square_bracket"].binding.show is False,
    )
    check(
        "ten digit bindings intact",
        all(
            active.get(d) is not None
            and active[d].binding.action.startswith("show_screen")
            for d in "1234567890"
        ),
    )

    await pilot.press("8")
    for _ in range(3):
        await pilot.pause()
    check("'8' still mounts the Flow Builder (regression)", visible(app, "screen_flow"))

    await pilot.press("right_square_bracket")
    for _ in range(3):
        await pilot.pause()
    check("']' mounts #screen_flow_execution", visible(app, "screen_flow_execution"))
    check(
        "the Flow Builder is hidden after ']'",
        not visible(app, "screen_flow"),
    )
    check(
        "the rail marker follows ']'",
        app.query_one(Rail).active_key == "flow_execution",
    )


async def main() -> None:
    print(f"textual {textual.__version__}", flush=True)
    watch = CollisionWatch()
    logging.getLogger("textual").addHandler(watch)

    print("=== static census — the shipped 12-entry rail", flush=True)
    keys = [entry.key for entry in RAIL_ENTRIES_B94]
    check("RAIL_ENTRIES_B94 declares 12", len(RAIL_ENTRIES_B94) == 12, f"keys={keys}")
    check(
        "duplicate screen keys rejected",
        len(set(S19TuiApp.SCREEN_CONTAINER_IDS)) == 12
        and len(keys) == len(set(keys)),
    )
    check(
        "SCREEN_CONTAINER_IDS carries flow_execution",
        S19TuiApp.SCREEN_CONTAINER_IDS.get("flow_execution")
        == "screen_flow_execution",
    )
    check(
        "_FIND_GOTO_INPUTS owns an explicit decision for flow_execution",
        "flow_execution" in S19TuiApp._FIND_GOTO_INPUTS
        and S19TuiApp._FIND_GOTO_INPUTS["flow_execution"] is None,
    )
    print("  terminal-side canonicalization (textual.keys):", flush=True)
    print(
        f"    KEY_TO_UNICODE_NAME[']'] = {KEY_TO_UNICODE_NAME.get('right_square_bracket')!r}",
        flush=True,
    )

    for size in ((120, 30), (80, 24)):
        app = S19TuiApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await drive(app, pilot, size)

    check(
        "no Textual binding collision/conflict/duplicate warning",
        not watch.records,
        f"captured={watch.records!r}",
    )

    print("", flush=True)
    if FAILURES:
        print(f"PROBE: FAIL ({len(FAILURES)}): {FAILURES}", flush=True)
        sys.exit(1)
    print(
        "PROBE: PASS — the shipped rail lands 12 entries; `]` routes; "
        "80x24 chrome holds; zero collisions",
        flush=True,
    )


asyncio.run(main())
