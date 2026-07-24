"""FB-P1 (batch-53) flow.json persistence — UI pilot tests (Inc-3).

Black-box ATs driving the SHIPPED FlowBuilderPanel surface through the REAL
buttons + modals via ``app.run_test`` + ``asyncio.run`` (the test_flow_builder_
render idiom), asserting on PAINTED widget state read back through
``render().plain`` / ``.spans`` / ``.region`` (C-32 painted-result, C-17
markup-safety):

- AT-002 / TC-011 — name-strip dirty ``●`` → saved ``✓`` glyph (glyph-primary,
  C-10), read off the painted strip line, through the real Save button + modal.
- AT-003 / TC-012/013 — SaveFlowScreen overwrite notice; LoadFlowScreen lists
  the saved flow stems.
- AT-004 (list arm) — a flow copied into ``flows/`` appears in the Load list
  (the filedialog→copy step itself is service-covered by AT-P1-10, C-12, which
  cannot run headless).
- AT-006 / AMD-2 — a loaded report-bearing flow renders a ``REPORT`` row (the
  ``_flow_block_label`` report arm is non-vacuous).
- AT-006 / TC-016 — quarantine card PAINTED ``sev-error`` on a rejected load,
  one line per finding, hostile ref rendered literally (no injected span), and
  the current flow left UNCHANGED (C-32 / C-17 / LLR-003.5).
- TC-018 — no-project Save/Load renders the error card (mirrors Run).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.widgets import Button, Input, ListView, Static

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ConfirmDiscardScreen, SaveFlowScreen
from s19_app.tui.services.flow_model import Flow, ReportBlock, SourceBlock
from s19_app.tui.services.flow_persistence_service import save_flow_json

_HOSTILE_REF = "[bold red]evil\x1b[31m[/]x[link=file:///etc/passwd]"


def _make_project(tmp_path: Path, name: str = "proj") -> Path:
    """A real ``<tmp>/.s19tool/workarea/<name>/`` project dir (workarea-contained)."""
    project = tmp_path / ".s19tool" / "workarea" / name
    project.mkdir(parents=True, exist_ok=True)
    return project


def _painted(widget: Static) -> str:
    """The widget's PAINTED plain text (C-32 — not a pre-layout attribute)."""
    return widget.render().plain


# --------------------------------------------------------------------------- #
# AT-002 / TC-011 — name strip glyph dirty ● → saved ✓ (painted, C-32/C-10)
# --------------------------------------------------------------------------- #

def test_at002_name_strip_glyph_dirty_then_saved(tmp_path: Path) -> None:
    project = _make_project(tmp_path)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            strip = app.query_one("#flow_name_strip", Static)
            states: list = []
            # (i) initial: saved ✓, visible (region painted).
            states.append(
                (_painted(strip), strip.region.area, set(strip.classes))
            )
            # (ii) add a block -> dirty ●.
            app.query_one("#flow_ref", Input).value = "prg.s19"
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            states.append((_painted(strip), strip.region.area, set(strip.classes)))
            # (iii) Save through the REAL button + modal -> saved ✓ + file on disk.
            app.query_one("#flow_save", Button).press()
            await pilot.pause()
            app.screen.query_one("#flow_save_name", Input).value = "nightly"
            app.screen.query_one("#flow_save_ok", Button).press()
            await pilot.pause()
            await pilot.pause()
            states.append((_painted(strip), strip.region.area, set(strip.classes)))
            saved_exists = (project / "flows" / "nightly.json").exists()
            return states, saved_exists

    states, saved_exists = asyncio.run(_drive())
    initial, dirty, saved = states
    # (i) saved on entry, glyph is the primary cue and the strip is painted.
    assert "✓" in initial[0] and initial[1] > 0
    assert "sev-neutral" in initial[2]
    # (ii) dirty after add — glyph flips ●, colour is the secondary cue.
    assert "●" in dirty[0]
    assert "sev-warning" in dirty[2]
    # (iii) saved after Save — glyph back to ✓, name adopted, file written.
    assert "✓" in saved[0]
    assert "nightly" in saved[0]
    assert "sev-neutral" in saved[2]
    assert saved_exists


# --------------------------------------------------------------------------- #
# AT-003 / TC-012 — SaveFlowScreen overwrite notice (live)
# --------------------------------------------------------------------------- #

def test_at003_save_overwrite_notice_fires_on_existing_name(tmp_path: Path) -> None:
    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.push_screen(SaveFlowScreen("nightly", existing=["nightly", "release"]))
            await pilot.pause()
            notice = app.screen.query_one("#flow_overwrite_notice", Static)
            on_existing = _painted(notice)
            app.screen.query_one("#flow_save_name", Input).value = "brand_new"
            await pilot.pause()
            on_new = _painted(notice)
            return on_existing, on_new

    on_existing, on_new = asyncio.run(_drive())
    assert "overwrites existing" in on_existing
    assert on_new.strip() == ""


# --------------------------------------------------------------------------- #
# AT-003 / TC-013 + AT-004 (list arm) — LoadFlowScreen lists saved stems
# --------------------------------------------------------------------------- #

def test_at003_load_screen_lists_saved_flow_stems(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    save_flow_json(Flow(name="a", blocks=[SourceBlock("prg.s19")]), "release", project)
    save_flow_json(Flow(name="b", blocks=[SourceBlock("prg.s19")]), "nightly", project)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            app.query_one("#flow_load", Button).press()
            await pilot.pause()
            rows = [
                item.query_one(Static).render().plain
                for item in app.screen.query("#flow_list ListItem")
            ]
            return rows

    rows = asyncio.run(_drive())
    assert set(rows) == {"nightly", "release"}


# --------------------------------------------------------------------------- #
# AT-006 / AMD-2 — a loaded report-bearing flow renders a REPORT row
# --------------------------------------------------------------------------- #

def test_at006_report_bearing_flow_shows_report_row(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    save_flow_json(
        Flow(name="withrep", blocks=[SourceBlock("prg.s19"), ReportBlock()]),
        "withrep",
        project,
    )

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            app.query_one("#flow_load", Button).press()
            await pilot.pause()
            # highlight the "withrep" row and Load it.
            app.screen.query_one("#flow_list", ListView).index = 0
            app.screen.query_one("#flow_load_ok", Button).press()
            await pilot.pause()
            await pilot.pause()
            return app.query_one("#flow_blocks", Static).render().plain

    blocks_text = asyncio.run(_drive())
    assert "REPORT" in blocks_text


# --------------------------------------------------------------------------- #
# AT-006 / TC-016 — quarantine card PAINTED sev-error; current flow UNCHANGED
# --------------------------------------------------------------------------- #

def test_at006_quarantine_card_painted_and_flow_unchanged(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    # A hostile flow.json: the unknown-kind value IS a markup payload, so the
    # FLOW-UNKNOWN-KIND finding message echoes it — the card is the markup sink.
    hostile = {
        "schema_version": 1,
        "name": "vendor",
        "blocks": [{"kind": _HOSTILE_REF}],
    }
    flows_dir = project / "flows"
    flows_dir.mkdir(parents=True, exist_ok=True)
    (flows_dir / "vendor.json").write_text(json.dumps(hostile), encoding="utf-8")

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            # Build a current flow so we can prove it survives the rejection.
            app.query_one("#flow_ref", Input).value = "keep.s19"
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            blocks_before = app.query_one("#flow_blocks", Static).render().plain
            # Open Load, pick the hostile file, Load it.
            app.query_one("#flow_load", Button).press()
            await pilot.pause()
            app.screen.query_one("#flow_list", ListView).index = 0
            app.screen.query_one("#flow_load_ok", Button).press()
            await pilot.pause()
            await pilot.pause()
            cards = list(app.query("#flow_result .flow-quarantine"))
            card = cards[0] if cards else None
            lines = [
                s.render().plain
                for s in app.query("#flow_result .flow-quarantine-line")
            ]
            head = app.query_one("#flow_result .flow-quarantine-head", Static)
            spans = [list(s.render().spans) for s in app.query(
                "#flow_result .flow-quarantine-line"
            )]
            blocks_after = app.query_one("#flow_blocks", Static).render().plain
            strip = _painted(app.query_one("#flow_name_strip", Static))
            return {
                "has_card": card is not None,
                "card_classes": set(card.classes) if card else set(),
                "card_area": card.region.area if card else 0,
                "head": head.render().plain,
                "lines": lines,
                "spans": spans,
                "blocks_before": blocks_before,
                "blocks_after": blocks_after,
                "strip": strip,
            }

    r = asyncio.run(_drive())
    # (i) card present, classed sev-error, VISIBLE (region painted, C-32).
    assert r["has_card"]
    assert "sev-error" in r["card_classes"]
    assert r["card_area"] > 0
    # (ii) header names the rejected file + finding count.
    assert "LOAD REJECTED" in r["head"] and "vendor" in r["head"]
    # (iii) at least one finding line; the hostile markup tokens render LITERALLY
    # (the `{kind!r}` repr keeps the brackets) and inject NO span — the C-17
    # discriminator is "literal text AND spans == []", crash-only is insufficient.
    assert len(r["lines"]) >= 1
    joined = "\n".join(r["lines"])
    assert "[bold red]" in joined and "[link=file:" in joined
    assert all(span == [] for span in r["spans"])
    # (iv) the current flow is UNTOUCHED (blocks + name strip preserved).
    assert r["blocks_after"] == r["blocks_before"]
    assert "keep.s19" in r["blocks_after"]
    assert "●" in r["strip"]  # still dirty (unchanged), never flipped by the reject


# --------------------------------------------------------------------------- #
# TC-018 — no-project Save/Load renders the error card (mirrors Run)
# --------------------------------------------------------------------------- #

def test_tc018_no_project_save_and_load_render_error_card(tmp_path: Path) -> None:
    async def _drive(button_id: str):
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.current_project_dir = None
            app.current_project = None
            await pilot.press("8")
            await pilot.pause()
            app.query_one(f"#{button_id}", Button).press()
            await pilot.pause()
            banners = [
                s.render().plain for s in app.query("#flow_result .flow-banner")
            ]
            return banners

    for button_id in ("flow_save", "flow_load"):
        banners = asyncio.run(_drive(button_id))
        assert any("FAILED" in b for b in banners), button_id


# --------------------------------------------------------------------------- #
# Inc-4 · AT-005 / AT-P1-18 — dirty-guard confirm-discard on Load-over-dirty
# --------------------------------------------------------------------------- #

def test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces(tmp_path: Path) -> None:
    """OQ-3 / LLR-003.6 / AMD-8: loading over a DIRTY flow prompts a
    confirm-discard modal. Cancel keeps the current blocks verbatim (the
    counterfactual — a Cancel that still called set_blocks would replace them and
    go RED); Discard proceeds; a subsequent CLEAN load shows no modal."""
    project = _make_project(tmp_path)
    save_flow_json(Flow(name="o", blocks=[SourceBlock("other.s19")]), "other", project)

    async def _load_other(app, pilot):
        app.query_one("#flow_load", Button).press()
        await pilot.pause()
        app.screen.query_one("#flow_list", ListView).index = 0
        app.screen.query_one("#flow_load_ok", Button).press()
        await pilot.pause()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            # Make the flow dirty.
            app.query_one("#flow_ref", Input).value = "keep.s19"
            app.query_one("#flow_add", Button).press()
            await pilot.pause()

            # (a) dirty + Load -> confirm modal shown; Cancel -> blocks kept.
            await _load_other(app, pilot)
            modal_on_cancel = any(
                isinstance(s, ConfirmDiscardScreen) for s in app.screen_stack
            )
            app.screen.query_one("#flow_discard_cancel", Button).press()
            await pilot.pause()
            blocks_after_cancel = app.query_one("#flow_blocks", Static).render().plain

            # (b) dirty + Load -> Discard -> blocks replaced with the loaded flow.
            await _load_other(app, pilot)
            app.screen.query_one("#flow_discard_ok", Button).press()
            await pilot.pause()
            await pilot.pause()
            blocks_after_discard = app.query_one("#flow_blocks", Static).render().plain
            strip_after_discard = _painted(app.query_one("#flow_name_strip", Static))

            # (c) clean + Load -> NO modal (loads directly).
            await _load_other(app, pilot)
            modal_on_clean = any(
                isinstance(s, ConfirmDiscardScreen) for s in app.screen_stack
            )
            return {
                "modal_on_cancel": modal_on_cancel,
                "blocks_after_cancel": blocks_after_cancel,
                "blocks_after_discard": blocks_after_discard,
                "strip_after_discard": strip_after_discard,
                "modal_on_clean": modal_on_clean,
            }

    r = asyncio.run(_drive())
    # (a) modal appeared; Cancel kept the dirty blocks verbatim (no set_blocks).
    assert r["modal_on_cancel"]
    assert "keep.s19" in r["blocks_after_cancel"]
    assert "other.s19" not in r["blocks_after_cancel"]
    # (b) Discard replaced the blocks and cleared dirty (✓).
    assert "other.s19" in r["blocks_after_discard"]
    assert "keep.s19" not in r["blocks_after_discard"]
    assert "✓" in r["strip_after_discard"]
    # (c) a clean load shows no confirm modal.
    assert not r["modal_on_clean"]
