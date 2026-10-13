# PDR probe for batch 2026-10-12-batch-94 risk R-1 — the rail 10->12 key binding.
# Closes the OPEN key-binding question (HLR-002 rationale, contract 6.3 R-1,
# ARQ R11) with executed evidence instead of argument.
#
# Candidate scheme under test (the PDR's proposal):
#     equals_sign   ("=")  -> show_screen('check_editor')   (Check Editor)
#     right_square_bracket ("]") -> show_screen('flow_execution') (Flow Execution)
#
# What is measured here:
#   (a) STATIC CENSUS — every key occupied in S19TuiApp.BINDINGS today
#       (app.py:1334-1388); the two candidates and the rejected classes
#       (f1/f2, shift-digit !/@) must be absent.
#   (b) RUNTIME RESOLUTION — Textual 8.x active_bindings with the scheme
#       applied: the two candidate keys resolve to the proposed actions; a
#       logging handler on the "textual" logger fails the probe if Textual
#       emits any binding collision/conflict/duplicate warning while the
#       12-entry rail + two stub screens mount and run.
#   (c) REACHABILITY — a headless pilot (App.run_test, the p1_pilot_probe.py /
#       batch-93 inc001_render_check.py idiom) mounts 12 rail entries and two
#       stub screen containers; pressing "6"/"="/"]"/"0" mounts the expected
#       screen and moves the rail active marker, at 120x30 AND at 80x24.
#   (d) DISCOVERABILITY — the `?` help panel's source of truth
#       (app.active_bindings) lists the two new bindings; the Footer render
#       (show=True only) gains no new hint row (C-13).
#
# The scheme is applied by patching S19TuiApp class attributes for the probe
# run (the real change is the same shape: two BINDINGS rows + two
# SCREEN_CONTAINER_IDS rows + two _FIND_GOTO_INPUTS rows); patching the class
# in place also keeps Textual's css_path resolution on the real module.
#
# NOT measurable here, recorded as the rejection reason instead: real-terminal
# delivery of F-keys — run_test injects key events in-process; the terminal
# never delivers them, so an F-key swallow hazard cannot be disproven headlessly.
#
# Throwaway evidence tooling; not part of the suite.
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import textual
from textual.binding import Binding
from textual.containers import Container
from textual.keys import KEY_TO_UNICODE_NAME
from textual.widgets import Label

from s19_app.tui.app import S19TuiApp
from s19_app.tui.rail import RAIL_ENTRIES, Rail, RailEntry, RailItem

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "ok" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""), flush=True)
    if not cond:
        FAILURES.append(name)


def binding_keys(bindings) -> list[str]:
    keys = []
    for b in bindings:
        key = b.key if isinstance(b, Binding) else b[0]
        keys.extend(k.strip() for k in key.split(","))
    return keys


# The 12-entry rail per LLR-002.1: existing order preserved; Check Editor
# after Patch Editor; Flow Execution after Flow Builder. The two glyphs are
# PROBE-PLACEHOLDER glyphs (the production glyph census is Phase-3 chrome work);
# what the probe measures is entry count, order, keys, and routing.
EXTENDED_RAIL: tuple[RailEntry, ...] = (
    RAIL_ENTRIES[:6]
    + (RailEntry("check_editor", "✔", "V", "Check Editor"),)
    + RAIL_ENTRIES[6:8]
    + (RailEntry("flow_execution", "▶", ">", "Flow Execution"),)
    + RAIL_ENTRIES[8:]
)

PATCHED = False


def apply_scheme() -> None:
    """Apply the candidate scheme to the S19TuiApp class for the probe run."""
    global PATCHED
    S19TuiApp.BINDINGS = [
        *S19TuiApp.BINDINGS,
        Binding("equals_sign", "show_screen('check_editor')", "Check Editor",
                show=False),
        Binding("right_square_bracket", "show_screen('flow_execution')",
                "Flow Execution", show=False),
    ]
    S19TuiApp.SCREEN_CONTAINER_IDS = {
        **S19TuiApp.SCREEN_CONTAINER_IDS,
        "check_editor": "screen_check_editor",
        "flow_execution": "screen_flow_execution",
    }
    S19TuiApp._FIND_GOTO_INPUTS = {
        **S19TuiApp._FIND_GOTO_INPUTS,
        "check_editor": None,
        "flow_execution": None,
    }
    # Textual freezes the processed binding table at class-creation time
    # (DOMNode.__init_subclass__ -> _merge_bindings); recompute it so the
    # patched BINDINGS list is what the app actually resolves.
    S19TuiApp._merged_bindings = S19TuiApp._merge_bindings()
    PATCHED = True


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
    print(f"=== run_test {size[0]}x{size[1]} — reachability", flush=True)
    # 12-entry rail mounted (rebuilt inside the real #rail_slot)
    rail = app.query_one(Rail)
    await rail.remove()
    slot = app.query_one("#rail_slot")
    await slot.mount(Rail(entries=EXTENDED_RAIL, active="workspace"))
    body = app.query_one("#workspace_body")
    await body.mount(
        Container(Label("Check Editor (probe stub)", classes="db-screen-title"),
                  id="screen_check_editor", classes="db-screen hidden"),
        Container(Label("Flow Execution (probe stub)", classes="db-screen-title"),
                  id="screen_flow_execution", classes="db-screen hidden"),
    )
    for _ in range(4):
        await pilot.pause()

    items = app.query(RailItem)
    order = [it.entry.key for it in items]
    check("rail mounts 12 entries", len(order) == 12, f"order={order}")
    check(
        "order: check_editor after patch, flow_execution after flow",
        order.index("check_editor") == order.index("patch") + 1
        and order.index("flow_execution") == order.index("flow") + 1,
    )

    # runtime binding resolution — the mapping the `?` help panel renders
    active = app.active_bindings
    check("equals_sign resolves to show_screen('check_editor')",
          active.get("equals_sign") is not None
          and active["equals_sign"].binding.action == "show_screen('check_editor')")
    check("right_square_bracket resolves to show_screen('flow_execution')",
          active.get("right_square_bracket") is not None
          and active["right_square_bracket"].binding.action == "show_screen('flow_execution')")
    check("ten digit bindings intact",
          all(active.get(d) is not None and active[d].binding.action.startswith("show_screen")
              for d in "1234567890"))

    # key reachability on the shipped routing path
    await pilot.press("6")
    for _ in range(3):
        await pilot.pause()
    check("key '6' mounts Patch Editor", visible(app, "screen_patch"))

    await pilot.press("equals_sign")
    for _ in range(3):
        await pilot.pause()
    check("'=' mounts #screen_check_editor", visible(app, "screen_check_editor"))
    check("'=' hides the Patch Editor", not visible(app, "screen_patch"))
    check("rail marker follows '='", app.query_one(Rail).active_key == "check_editor")

    await pilot.press("right_square_bracket")
    for _ in range(3):
        await pilot.pause()
    check("']' mounts #screen_flow_execution",
          visible(app, "screen_flow_execution"))
    check("'=' screen hidden after ']'",
          not visible(app, "screen_check_editor"))
    check("rail marker follows ']'",
          app.query_one(Rail).active_key == "flow_execution")

    await pilot.press("0")
    for _ in range(3):
        await pilot.pause()
    check("key '0' still mounts CRC Designer (regression)",
          visible(app, "screen_crc_designer"))


async def main() -> None:
    print(f"textual {textual.__version__}", flush=True)
    watch = CollisionWatch()
    logging.getLogger("textual").addHandler(watch)

    print("=== static census — occupied keys (S19TuiApp.BINDINGS, app.py:1334-1388)",
          flush=True)
    occupied = binding_keys(S19TuiApp.BINDINGS)
    print(f"  occupied ({len(occupied)}): {' '.join(sorted(occupied))}", flush=True)
    for cand, why in (("equals_sign", "chosen"), ("right_square_bracket", "chosen"),
                      ("f1", "rejected class"), ("f2", "rejected class"),
                      ("exclamation_mark", "rejected class"),
                      ("at_sign", "rejected class")):
        check(f"{cand} ({why}) not occupied", cand not in occupied)
    print("  terminal-side canonicalization (textual.keys):", flush=True)
    for name in ("equals_sign", "right_square_bracket", "f1"):
        print(f"    KEY_TO_UNICODE_NAME[{name!r}] = {KEY_TO_UNICODE_NAME.get(name)!r}",
              flush=True)

    apply_scheme()

    for size in ((120, 30), (80, 24)):
        app = S19TuiApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await drive(app, pilot, size)

    print("=== chrome — footer stays uncrowded (C-13), help-panel source lists new apps",
          flush=True)
    app = S19TuiApp()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        # The Footer renders show=True bindings only; the headless Footer
        # composes no FooterKey rows, so assert the rule at its source: the
        # two new bindings are show=False and no show=True binding is theirs.
        active = app.active_bindings
        shown = {key: ab.binding.description for key, ab in active.items()
                 if ab.binding.show}
        check("new bindings are show=False (footer renders show=True only)",
              active["equals_sign"].binding.show is False
              and active["right_square_bracket"].binding.show is False)
        check("no show=True binding names the new surfaces",
              "Check Editor" not in shown.values()
              and "Flow Execution" not in shown.values(),
              f"show=True set: {sorted(shown.values())}")
        app.action_show_help_panel()
        for _ in range(3):
            await pilot.pause()
        active = app.active_bindings
        check("help-panel source lists Check Editor binding",
              active.get("equals_sign") is not None
              and "Check Editor" in active["equals_sign"].binding.description)
        check("help-panel source lists Flow Execution binding",
              active.get("right_square_bracket") is not None
              and "Flow Execution" in active["right_square_bracket"].binding.description)
        app.action_show_help_panel()  # the app's override is an on/off toggle
        for _ in range(3):
            await pilot.pause()

    check("no Textual binding collision/conflict/duplicate warning",
          not watch.records, f"captured={watch.records!r}")

    print("", flush=True)
    if FAILURES:
        print(f"PROBE: FAIL ({len(FAILURES)}): {FAILURES}", flush=True)
        sys.exit(1)
    print("PROBE: PASS — '=' / ']' scheme: no collision, reachable, discoverable",
          flush=True)


asyncio.run(main())
