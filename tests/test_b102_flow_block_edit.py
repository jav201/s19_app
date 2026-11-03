"""TC-B102-FB-01..06 — batch-102 Inc 6 — Flow Builder: editar y borrar bloques
individualmente (tester E4).

Pins the Inc-6 slice designed in
``.dev-flow/2026-11-03-batch-102/inc-6/{01-requirements.md,02-test-cases.md,codewire-graph.md,prototype.md}``
plus the mandatory Inc-6 addenda of
``.dev-flow/2026-11-03-batch-102/design/E3-rulings-inc6.md``:

* TC-B102-FB-01 — Edit opens an initialized modal for each of the 8 block
  kinds; title names the ledger number + kind and the kind-specific fields
  carry the block's current values verbatim (R-B102-FB-001).
* TC-B102-FB-02 — Save replaces ONLY the selected block on the three routes
  (SOURCE / A2B / External step); the other blocks stay dataclass-equal to
  their originals, pipeline/ribbon repaint and the dirty flag sets
  (R-B102-FB-002). Funnel and clipboard survive the replacement.
* TC-B102-FB-03 — an invalid edit (A2B binding pointing downstream, external
  step with an empty log) is refused INSIDE the modal: the original chain and
  the dirty state are untouched by the failed save (R-B102-FB-003).
* TC-B102-FB-04 — Remove, confirmed, deletes exactly the picked index (first,
  then middle, then last of a 3-block chain); variables and clipboard survive;
  dirty sets; Cancel starts focused and ``escape`` cancels without a trace
  (R-B102-FB-004 + ruling 8).
* TC-B102-FB-05 — empty / non-numeric / out-of-range picks for BOTH actions
  paint the exact notice ``Edit/Remove needs a block # between 1 and <N>.``
  and neither open a modal nor mutate the chain (R-B102-FB-005 + ruling 1:
  empty is invalid for Edit/Remove; Copy's empty=last arm keeps working —
  pinned green-on-base by the r1 regression test).
* TC-B102-FB-06 — hostile block fields render as literal text in the edit
  modal and its refusal: zero markup spans, zero control bytes, and the
  sentinel is never logged (R-B102-FB-006 + rulings 7/10).

E3-rulings addenda:

* ruling 2 (merge, unexposed fields) — saving an edit preserves the wire
  fields the modal does not expose: ``file_type`` / ``a2l_ref`` on SOURCE and
  ``fmt`` on WRITE-OUT.
* ruling 4 (explicit containment base) — with no project loaded the modal
  still opens but Save refuses in-modal; nothing is persisted for a later
  failure and the chain stays clean.
* ruling 5 (defensive parsing) — the shared resolver parses the pick with
  ``try/except ValueError`` + range: ``'²'`` (``str.isdigit()`` is True but
  ``int()`` raises) and a 4,301-digit integer both refuse with the exact
  notice, never a crash; an AST pin forbids an ``isdigit()`` guard.
* ruling 6 (A2B round-trip) — the modal shows bindings 1-based as ``#n`` and
  saves the canonical wire form (0-based ``{source, ref}``); an unchanged
  save round-trips to an equal block and leaves the flow clean (ruling 9).
* ruling 9 (honest dirty) — TC-02 pins dirty on a changed save, the r6
  round-trip and the r9 test pin NO dirty flag when the candidate equals the
  original.
* ruling 11 (censuses/containment) — ``#flow_clip_row`` keeps
  ``#flow_pick``/Copy/Paste/Edit/Remove + the status on ONE row inside the
  panel at 80x24 and 118x54 (the focus/group census update lives in
  ``tests/test_b97_flow_builder.py``: KEY_GROUPS + TC-B97-47, ruling-sanctioned
   RED like the Inc-4 census idiom).

RED-phase discipline: every symbol the increment adds (the ``#flow_edit`` /
``#flow_remove`` chips, ``FlowBlockEditScreen``, ``ConfirmQuestionScreen``'s
question, the ``_selected_block`` resolver) is reached lazily through the
shipped UI — a ``need()`` assertion, a bounded screen poll or an AST walk — so
this module still COLLECTS on the pre-increment tree and each test fails there
on its own behavioural reason (never a syntax or collection error). The one
exception is the ruling-1 Copy regression, which pins the pre-existing Copy
contract and therefore stays GREEN on base, guarding it through the resolver
refactor.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
from textual.widgets import Button, Input, Label, Select, Static

from s19_app.tui.app import S19TuiApp
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_model import (
    A2B_INPUT_FILE,
    A2B_INPUT_FLOW,
    A2BBlock,
    A2BInputBinding,
    EXTERNAL_MODE_TERMINAL,
    CheckBlock,
    CrcBlock,
    ExternalStepBlock,
    Flow,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)
from tests.b97_fixtures import HOSTILE_NAME, flow_project, open_flow_builder
from tests.b97_probes import record_statuses, settle

SIZE = (118, 54)

#: The exact invalid-pick notice of R-B102-FB-005 / ruling 1, ``<N>`` = the
#: chain length (TC-B102-FB-05 expects the exact ``1 and 2`` form for a
#: 2-block flow). Asserted verbatim, never imported from the product.
def _needs_block_notice(n: int) -> str:
    return f"Edit/Remove needs a block # between 1 and {n}."


#: The exact remove question of the codewire graph / prototype
#: (``Remove block #<n> (<kind>)? This cannot be undone.``).
def _remove_question(n: int, kind: str) -> str:
    return f"Remove block #{n} ({kind})? This cannot be undone."


#: The extended copy/paste strip census (ruling 11): the two new chips ride
#: the SAME row, between Paste and the clipboard status.
ROW_IDS = ("flow_pick", "flow_copy", "flow_paste", "flow_edit", "flow_remove", "flow_clip_status")

#: Span-style tokens that prove Rich markup was applied instead of literal
#: text (the batch-102 Inc-4 hostile oracle).
MARKUP_SPAN_RE = re.compile(r"link|click|bold|^red$")

#: C0/C1 control bytes that must never be painted (R-B102-FB-006).
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

#: A hostile instruction carrying every markup token family, no whitespace
#: and no control bytes (the TC paints it inside a live Input).
HOSTILE_SENTINEL = HOSTILE_NAME
assert "[red]" in HOSTILE_SENTINEL and "[link=e]" in HOSTILE_SENTINEL


# --------------------------------------------------------------------------- #
# Drivers and readers (Layer B — the shipped chain under Textual Pilot).
# --------------------------------------------------------------------------- #


def run(tmp_path: Path, size, body, *, project: bool = False):
    """Open the Flow Builder at ``size`` (with the flow project loaded through
    the app's own load when ``project``) and return ``await body(...)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            project_dir = await flow_project(app) if project else None
            panel = await open_flow_builder(app, pilot)
            return await body(app, pilot, panel, project_dir)

    return asyncio.run(_drive())


def need(root, selector: str, kind=None):
    """The one widget ``selector`` names, or a named assertion failure (PC-11)."""
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    widget = found[0]
    if kind is not None:
        assert isinstance(widget, kind), f"{selector}: expected {kind.__name__}, got {type(widget).__name__}"
    return widget


def _seed(panel, blocks, funnel=()) -> list:
    """Load ``blocks`` through the panel's public seam; return the originals."""
    panel.set_blocks(Flow(name="fb_case", blocks=list(blocks), funnel=tuple(funnel)))
    return list(blocks)


def _clip_seed(panel, block) -> None:
    """Seed the clipboard with ``block``'s WIRE projection (what Copy stores),
    without Copy's dirty side effect — the preservation oracle reads it back."""
    panel._clipboard = fps.flow_to_dict(Flow(name="clipboard", blocks=[block]))["blocks"][0]


def _pick(panel, raw: str) -> None:
    need(panel, "#flow_pick", Input).value = raw


async def _press_chip(panel, pilot, wid: str) -> None:
    """Press one of the strip chips; RED-safe via ``need()`` (assertion, not
    a ``query_one`` miss) on the pre-increment tree."""
    need(panel, f"#{wid}", Button).press()
    await settle(pilot, 2)


async def _wait_modal(app, pilot, class_name: str, attempts: int = 150):
    """Pump until a screen of ``class_name`` tops (bounded, named on failure)."""
    for _ in range(attempts):
        await pilot.pause()
        if type(app.screen).__name__ == class_name:
            return app.screen
    raise AssertionError(f"{class_name} never topped")


async def _wait_modal_closed(app, pilot, class_name: str, attempts: int = 150) -> None:
    for _ in range(attempts):
        await pilot.pause()
        if type(app.screen).__name__ != class_name:
            return
    raise AssertionError(f"{class_name} never dismissed")


async def _press_labeled(root, pilot, label_prefix: str) -> None:
    """Press the one Button whose label starts with ``label_prefix`` (Save /
    Cancel / Remove — the verbs the requirements and prototype pin)."""
    prefix = label_prefix.lower()
    matches = [
        b for b in root.query(Button)
        if str(b.label).strip().lower().startswith(prefix)
    ]
    assert len(matches) == 1, f"{label_prefix!r}: expected exactly 1 button, found {len(matches)}"
    matches[0].press()
    await settle(pilot, 2)


def _modal_input_values(modal) -> list:
    return [w.value for w in modal.query(Input)]


def _modal_texts(modal) -> list:
    """The plain text of every Static/Label the modal paints."""
    texts = []
    for widget in modal.query("*"):
        if isinstance(widget, (Static, Label)):
            rendered = widget.render()
            plain = rendered.plain if hasattr(rendered, "plain") else str(rendered)
            if plain.strip():
                texts.append(plain)
    return texts


def _modal_static_texts(modal) -> list:
    texts = []
    for widget in modal.query(Static):
        rendered = widget.render()
        plain = rendered.plain if hasattr(rendered, "plain") else str(rendered)
        if plain.strip():
            texts.append(plain)
    return texts


def _screen_text(app) -> str:
    """Everything the terminal paints right now, one row per line."""
    strips = app.screen._compositor.render_strips()
    return "\n".join("".join(segment.text for segment in strip) for strip in strips)


def _notice(panel):
    """The wiring notice's plain text and whether it is displayed."""
    widget = need(panel, "#flow_wiring_notice", Static)
    rendered = widget.render()
    plain = rendered.plain if hasattr(rendered, "plain") else str(rendered)
    return plain, widget.display


def _assert_zero_markup_spans(modal) -> None:
    """No Static/Label span may carry a Rich markup style (R-B102-FB-006)."""
    offenders = []
    for widget in modal.query("*"):
        if not isinstance(widget, (Static, Label)):
            continue
        rendered = widget.render()
        for span in getattr(rendered, "spans", []):
            if MARKUP_SPAN_RE.search(str(span.style)):
                offenders.append((widget.id, span.style))
    assert offenders == [], f"markup spans painted in the modal: {offenders}"


def _all_kinds_blocks() -> list:
    """One block of every kind — the TC-B102-FB-01 8/8 threshold."""
    return [
        SourceBlock("prg.s19"),
        PatchBlock("calib_hotfix.json"),
        CheckBlock("baseline.chk.json"),
        WriteOutBlock("out.s19"),
        CrcBlock("crc.json"),
        A2BBlock(
            image_a=A2BInputBinding(A2B_INPUT_FLOW, "0"),
            image_b=A2BInputBinding(A2B_INPUT_FILE, "other.s19"),
        ),
        ExternalStepBlock(
            mode=EXTERNAL_MODE_TERMINAL,
            instruction="python flash.py",
            log_ref="run.log",
            output_path="out.s19",
        ),
        ReportBlock(),
    ]


# --------------------------------------------------------------------------- #
# TC-B102-FB-01 — Edit opens an initialized modal for every block kind (8/8).
# --------------------------------------------------------------------------- #

TC01_CASES = [
    ("source", 1, ["prg.s19"], []),
    ("patch", 2, ["calib_hotfix.json"], []),
    ("check", 3, ["baseline.chk.json"], []),
    ("write_out", 4, ["out.s19"], []),
    ("crc", 5, ["crc.json"], []),
    ("a2b", 6, ["#1", "other.s19"], []),
    ("external_step", 7, ["python flash.py", "run.log", "out.s19"], ["terminal"]),
    ("report", 8, [], []),
]


@pytest.mark.parametrize("kind,ledger,expected_inputs,screen_bits", TC01_CASES, ids=[c[0] for c in TC01_CASES])
def test_tc_b102_fb_01_edit_opens_initialized_modal(tmp_path: Path, kind, ledger, expected_inputs, screen_bits) -> None:
    """TC-B102-FB-01 (R-B102-FB-001): pick the ledger number, press Edit, and
    the modal opens with the block's kind in the title and its CURRENT field
    values prefilled (the add-row grammar, kind fixed). Mutant control: an
    empty/default modal, or the wrong kind, or values re-typed by the modal.
    RED on base: ``#flow_edit`` does not ship (``need()`` finds 0 widgets).
    """

    async def body(app, pilot, panel, project_dir):
        _seed(panel, _all_kinds_blocks())
        await settle(pilot, 2)
        _pick(panel, str(ledger))
        await _press_chip(panel, pilot, "flow_edit")
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        await settle(pilot, 2)
        texts = _modal_texts(modal)
        title = [t for t in texts if f"#{ledger}" in t and kind in t.lower()]
        assert title, f"the modal title must name block #{ledger} ({kind}): {texts!r}"
        assert _modal_input_values(modal) == expected_inputs, (
            f"the {kind} modal fields must carry the current values "
            f"{expected_inputs!r}: got {_modal_input_values(modal)!r}"
        )
        painted = " ".join(_modal_texts(modal)).lower()
        for bit in screen_bits:
            assert bit.lower() in painted, f"{bit!r} must paint in the {kind} modal"
        await _press_labeled(modal, pilot, "cancel")
        await _wait_modal_closed(app, pilot, "FlowBlockEditScreen")
        assert [b.kind for b in panel.current_flow.blocks] == [b.kind for b in _all_kinds_blocks()], (
            "Cancel must leave the chain untouched"
        )

    run(tmp_path, SIZE, body)


# --------------------------------------------------------------------------- #
# TC-B102-FB-02 — Save replaces only the selected block (3/3 routes).
# --------------------------------------------------------------------------- #


def _route_blocks(route: str) -> list:
    if route == "source":
        return [SourceBlock("prg.s19"), SourceBlock("old.s19"), WriteOutBlock("out.s19")]
    if route == "a2b":
        return [
            SourceBlock("prg.s19"),
            A2BBlock(
                image_a=A2BInputBinding(A2B_INPUT_FLOW, "0"),
                image_b=A2BInputBinding(A2B_INPUT_FILE, "other.s19"),
            ),
        ]
    return [
        SourceBlock("prg.s19"),
        ExternalStepBlock(
            mode=EXTERNAL_MODE_TERMINAL,
            instruction="python flash.py",
            log_ref="run.log",
            output_path="out.s19",
        ),
    ]


@pytest.mark.parametrize("route", ["source", "a2b", "external_step"], ids=["source", "a2b", "external_step"])
def test_tc_b102_fb_02_save_replaces_only_the_selected_block(tmp_path: Path, route: str) -> None:
    """TC-B102-FB-02 (R-B102-FB-002): the three edit routes (SOURCE / A2B /
    External step) replace exactly index 1 — the other block objects stay
    dataclass-equal to their originals, the pipeline repaints the new value
    and the dirty flag sets. Variables and the clipboard survive. Mutant
    control: the whole flow replaced, or the dirty flag skipped. RED on base:
    ``#flow_edit`` does not ship.
    """

    async def body(app, pilot, panel, project_dir):
        originals = _route_blocks(route)
        _seed(panel, originals, funnel=(("BOOST", "1.5"),))
        await settle(pilot, 2)
        _clip_seed(panel, originals[0])
        clipboard_before = dict(panel._clipboard)
        funnel_before = list(panel._funnel)
        assert not panel.is_dirty, "a seeded flow starts clean"

        _pick(panel, "2")
        await _press_chip(panel, pilot, "flow_edit")
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        await settle(pilot, 2)
        inputs = list(modal.query(Input))
        if route == "source":
            assert len(inputs) == 1, f"the SOURCE modal exposes the one ref field: {len(inputs)} inputs"
            inputs[0].value = "new_image.s19"
        elif route == "a2b":
            assert [i.value for i in inputs] == ["#1", "other.s19"]
            inputs[1].value = "other_v2.s19"
        else:
            assert [i.value for i in inputs] == ["python flash.py", "run.log", "out.s19"]
            inputs[0].value = "python flash_v2.py"
        await _press_labeled(modal, pilot, "save")
        await _wait_modal_closed(app, pilot, "FlowBlockEditScreen")

        blocks = panel.current_flow.blocks
        if route == "source":
            assert blocks[1].image_ref == "new_image.s19", f"got {blocks[1]!r}"
            assert "new_image.s19" in _screen_text(app), "the pipeline must repaint the new ref"
            assert "old.s19" not in _screen_text(app)
        elif route == "a2b":
            assert blocks[1].image_b == A2BInputBinding(A2B_INPUT_FILE, "other_v2.s19"), f"got {blocks[1]!r}"
            assert blocks[1].image_a == originals[1].image_a, "the untouched binding must survive"
        else:
            assert blocks[1].instruction == "python flash_v2.py", f"got {blocks[1]!r}"
            assert blocks[1].log_ref == "run.log" and blocks[1].output_path == "out.s19"
            assert blocks[1].mode == EXTERNAL_MODE_TERMINAL
        assert blocks[0] == originals[0], "block 1 must stay dataclass-equal to its original"
        if route == "source":
            assert blocks[2] == originals[2], "block 3 must stay dataclass-equal to its original"
        assert panel.is_dirty, "a changed save must set the dirty flag"
        assert panel._clipboard == clipboard_before, "the clipboard must survive the edit"
        assert panel._funnel == funnel_before, "the variables must survive the edit"

    run(tmp_path, SIZE, body, project=True)


# --------------------------------------------------------------------------- #
# TC-B102-FB-03 — an invalid edit is refused inside the modal (2/2).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", ["a2b_downstream", "external_step_no_log"], ids=["a2b_downstream", "external_step_no_log"])
def test_tc_b102_fb_03_invalid_edit_refused_and_original_remains(tmp_path: Path, case: str) -> None:
    """TC-B102-FB-03 (R-B102-FB-003): a candidate that fails validation keeps
    the ORIGINAL block — the refusal paints in the modal (naming the binding /
    the missing log), the modal stays open, the chain and the dirty state are
    unchanged, and variables/clipboard survive. Mutant control: the invalid
    candidate replaces the original. RED on base: ``#flow_edit`` does not ship.
    """

    async def body(app, pilot, panel, project_dir):
        if case == "a2b_downstream":
            originals = [
                SourceBlock("prg.s19"),
                A2BBlock(
                    image_a=A2BInputBinding(A2B_INPUT_FLOW, "0"),
                    image_b=A2BInputBinding(A2B_INPUT_FILE, "other.s19"),
                ),
            ]
            refusal_hint = "image_a"
        else:
            originals = [
                SourceBlock("prg.s19"),
                ExternalStepBlock(
                    mode=EXTERNAL_MODE_TERMINAL,
                    instruction="python flash.py",
                    log_ref="run.log",
                    output_path="out.s19",
                ),
            ]
            refusal_hint = "log"
        _seed(panel, originals, funnel=(("BOOST", "1.5"),))
        await settle(pilot, 2)
        _clip_seed(panel, originals[0])
        clipboard_before = dict(panel._clipboard)
        funnel_before = list(panel._funnel)
        assert not panel.is_dirty

        _pick(panel, "2")
        await _press_chip(panel, pilot, "flow_edit")
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        await settle(pilot, 2)
        inputs = list(modal.query(Input))
        if case == "a2b_downstream":
            assert inputs[0].value == "#1"
            inputs[0].value = "#2"  # downstream/self: only 1 upstream block
        else:
            log_input = next(i for i in inputs if i.value == "run.log")
            log_input.value = ""  # the log is mandatory, never optional
        await _press_labeled(modal, pilot, "save")
        await settle(pilot, 3)

        assert type(app.screen).__name__ == "FlowBlockEditScreen", (
            "a refused save must keep the modal open with the original intact"
        )
        refusal = [t for t in _modal_static_texts(modal) if refusal_hint in t.lower()]
        assert refusal, f"the refusal must name {refusal_hint!r}: {_modal_static_texts(modal)!r}"
        assert panel.current_flow.blocks == originals, "the chain must be unchanged by the failed edit"
        assert not panel.is_dirty, "a failed edit must not mark the flow dirty"
        assert panel._clipboard == clipboard_before, "the clipboard must survive the refusal"
        assert panel._funnel == funnel_before, "the variables must survive the refusal"
        await _press_labeled(modal, pilot, "cancel")
        await _wait_modal_closed(app, pilot, "FlowBlockEditScreen")
        assert panel.current_flow.blocks == originals

    run(tmp_path, SIZE, body, project=True)


# --------------------------------------------------------------------------- #
# TC-B102-FB-04 — Remove touches exactly the picked block (3/3 positions).
# --------------------------------------------------------------------------- #


def test_tc_b102_fb_04_remove_first_middle_last(tmp_path: Path) -> None:
    """TC-B102-FB-04 (R-B102-FB-004): with variables, a seeded clipboard and a
    3-block chain, confirming the remove of #1 three times deletes the FIRST,
    then the MIDDLE, then the LAST of the original chain — one index each
    time, variables and clipboard untouched, dirty set. The confirm asks the
    exact ``Remove block #<n> (<kind>)? This cannot be undone.`` question.
    Mutant control: variables/clipboard cleared, or the whole chain removed.
    RED on base: ``#flow_remove`` does not ship.
    """

    async def body(app, pilot, panel, project_dir):
        blocks = [SourceBlock("a.s19"), PatchBlock("p.json"), WriteOutBlock("w.s19")]
        _seed(panel, blocks, funnel=(("BOOST", "1.5"),))
        await settle(pilot, 2)
        _clip_seed(panel, blocks[0])
        clipboard_before = dict(panel._clipboard)
        funnel_before = list(panel._funnel)

        for gone_kind, remaining in (
            ("source", ["patch", "write_out"]),
            ("patch", ["write_out"]),
            ("write_out", []),
        ):
            _pick(panel, "1")
            await _press_chip(panel, pilot, "flow_remove")
            confirm = await _wait_modal(app, pilot, "ConfirmQuestionScreen")
            await settle(pilot, 2)
            title = f"Remove block #1 ({gone_kind})?"
            body = "This cannot be undone."
            confirm_text = _modal_texts(confirm)
            assert any(title in t for t in confirm_text), (
                f"the confirm must ask {title!r}: {confirm_text!r}"
            )
            assert any(body in t for t in confirm_text), (
                f"the confirm must warn {body!r}: {confirm_text!r}"
            )
            await _press_labeled(confirm, pilot, "remove")
            await _wait_modal_closed(app, pilot, "ConfirmQuestionScreen")
            assert [b.kind for b in panel.current_flow.blocks] == remaining, (
                f"after removing the {gone_kind}: {panel.current_flow.blocks!r}"
            )
            assert panel._clipboard == clipboard_before, "the clipboard must survive the remove"
            assert panel._funnel == funnel_before, "the variables must survive the remove"
            assert panel.is_dirty, "a confirmed remove must set the dirty flag"

    run(tmp_path, SIZE, body)


def test_tc_b102_fb_04_escape_cancels_and_focus_starts_on_cancel(tmp_path: Path) -> None:
    """TC-B102-FB-04 + E3 ruling 8: the remove confirm starts with the focus
    on CANCEL and ``escape`` dismisses it — the chain is byte-identical and
    the flow stays clean (a cancelled remove is a no-op, never a dirty mark).
    RED on base: ``#flow_remove`` does not ship.
    """

    async def body(app, pilot, panel, project_dir):
        originals = [SourceBlock("keep.s19")]
        _seed(panel, originals)
        await settle(pilot, 2)
        assert not panel.is_dirty
        _pick(panel, "1")
        await _press_chip(panel, pilot, "flow_remove")
        confirm = await _wait_modal(app, pilot, "ConfirmQuestionScreen")
        focused = None
        for _ in range(60):
            await pilot.pause()
            if app.focused is not None and app.focused.id == "confirm_no":
                focused = app.focused
                break
        assert focused is not None and focused.id == "confirm_no", (
            f"the remove confirm must open with Cancel focused (ruling 8): {app.focused!r}"
        )
        await pilot.press("escape")
        await _wait_modal_closed(app, pilot, "ConfirmQuestionScreen")
        assert panel.current_flow.blocks == originals, "escape must cancel the remove"
        assert not panel.is_dirty, "a cancelled remove must not mark the flow dirty"

    run(tmp_path, SIZE, body)


# --------------------------------------------------------------------------- #
# TC-B102-FB-05 — invalid pick handling for both actions (3/3 + ruling 5).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("action", ["edit", "remove"], ids=["edit", "remove"])
@pytest.mark.parametrize("raw", ["", "x", "9"], ids=["empty", "alpha", "out_of_range"])
def test_tc_b102_fb_05_invalid_pick_paints_exact_notice(tmp_path: Path, action: str, raw: str) -> None:
    """TC-B102-FB-05 (R-B102-FB-005) + ruling 1: for BOTH Edit and Remove, an
    empty, non-numeric or out-of-range pick paints the exact notice
    ``Edit/Remove needs a block # between 1 and 2.`` (empty is INVALID for
    Edit/Remove — the ``last`` affordance stays Copy-only), opens no modal and
    removes nothing. Mutant control: an invalid input mutates the flow or
    opens the modal. RED on base: the chips do not ship.
    """

    async def body(app, pilot, panel, project_dir):
        originals = [SourceBlock("prg.s19"), WriteOutBlock("out.s19")]
        _seed(panel, originals)
        await settle(pilot, 2)
        stack_before = len(app.screen_stack)
        assert not panel.is_dirty
        _pick(panel, raw)
        await _press_chip(panel, pilot, f"flow_{action}")
        await settle(pilot, 3)
        plain, displayed = _notice(panel)
        assert displayed, "the wiring notice must paint the refusal"
        assert plain.strip() == _needs_block_notice(2), f"expected the exact notice, got {plain!r}"
        assert len(app.screen_stack) == stack_before, "an invalid pick must not open a modal"
        assert panel.current_flow.blocks == originals, "an invalid pick must not mutate the chain"
        assert not panel.is_dirty, "an invalid pick must not mark the flow dirty"

    run(tmp_path, SIZE, body)


@pytest.mark.parametrize("action", ["edit", "remove"], ids=["edit", "remove"])
@pytest.mark.parametrize("raw", ["²", "9" * 4301], ids=["superscript_two", "int_over_4300_digits"])
def test_tc_b102_fb_05_defensive_index_parsing(tmp_path: Path, action: str, raw: str) -> None:
    """E3 ruling 5: the shared resolver parses with ``try/except ValueError``
    and a range check — ``'²'`` passes ``str.isdigit()`` yet ``int()`` raises,
    and a 4,301-digit integer blows past CPython's string-to-int digit limit;
    both refuse with the exact notice instead of crashing (the incumbent
    ``isdigit()``-then-``int()`` guard dies on the first arm). Complemented by
    the AST pin in ``test_tc_b102_fb_r5_resolver_parses_without_isdigit_guard``.
    RED on base: the chips do not ship.
    """

    async def body(app, pilot, panel, project_dir):
        originals = [SourceBlock("prg.s19"), WriteOutBlock("out.s19")]
        _seed(panel, originals)
        await settle(pilot, 2)
        stack_before = len(app.screen_stack)
        _pick(panel, raw)
        await _press_chip(panel, pilot, f"flow_{action}")
        await settle(pilot, 3)
        plain, displayed = _notice(panel)
        assert displayed, "the wiring notice must paint the refusal"
        assert plain.strip() == _needs_block_notice(2), f"expected the exact notice, got {plain!r}"
        assert len(app.screen_stack) == stack_before, "a hostile pick must not open a modal"
        assert panel.current_flow.blocks == originals, "a hostile pick must not mutate the chain"

    run(tmp_path, SIZE, body)


# --------------------------------------------------------------------------- #
# TC-B102-FB-06 — hostile block fields render literally in the modal.
# --------------------------------------------------------------------------- #


def test_tc_b102_fb_06_hostile_fields_render_literally(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """TC-B102-FB-06 (R-B102-FB-006) + rulings 7/10: a block whose instruction
    carries every Rich markup token paints LITERALLY in the edit modal — the
    field keeps the sentinel verbatim, the painted surface shows ``[red]`` /
    ``[link=e]`` / ``[@click=app.quit]`` as text with zero markup spans and
    zero control bytes; a refused save keeps the sentinel literal; and the
    sentinel never reaches the status log. Mutant control: markup rendering
    (the tokens vanish into styled spans) or content logging. RED on base:
    ``#flow_edit`` does not ship.
    """
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        originals = [
            SourceBlock("prg.s19"),
            ExternalStepBlock(
                mode=EXTERNAL_MODE_TERMINAL,
                instruction=HOSTILE_SENTINEL,
                log_ref="run.log",
                output_path="out.s19",
            ),
        ]
        _seed(panel, originals)
        await settle(pilot, 2)
        _pick(panel, "2")
        await _press_chip(panel, pilot, "flow_edit")
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        await settle(pilot, 2)

        values = _modal_input_values(modal)
        assert HOSTILE_SENTINEL in values, (
            f"the instruction field must carry the sentinel verbatim: {values!r}"
        )
        painted = _screen_text(app)
        for token in ("[red]", "[link=e]", "[@click=app.quit]", "[bold]"):
            assert token in painted, f"{token!r} must paint as literal text"
        assert not CONTROL_CHARS_RE.search(painted), "no control byte may paint in the modal"
        _assert_zero_markup_spans(modal)

        # Trigger the refusal: the mandatory log goes empty.
        log_input = next(i for i in modal.query(Input) if i.value == "run.log")
        log_input.value = ""
        await _press_labeled(modal, pilot, "save")
        await settle(pilot, 3)
        assert type(app.screen).__name__ == "FlowBlockEditScreen", (
            "a refused save keeps the modal open"
        )
        assert HOSTILE_SENTINEL in _modal_input_values(modal), (
            "the sentinel must survive the refusal literally"
        )
        refusal = [t for t in _modal_static_texts(modal) if "log" in t.lower()]
        assert refusal, f"the refusal must name the missing log: {_modal_static_texts(modal)!r}"
        _assert_zero_markup_spans(modal)
        assert not CONTROL_CHARS_RE.search(_screen_text(app))
        assert panel.current_flow.blocks == originals, "the refusal leaves the chain unchanged"

    run(tmp_path, SIZE, body)
    leaked = [s for s in statuses if HOSTILE_SENTINEL in s]
    assert leaked == [], f"block content must never be logged (ruling 10): {leaked!r}"


# --------------------------------------------------------------------------- #
# E3 rulings addenda.
# --------------------------------------------------------------------------- #


def test_tc_b102_fb_r1_empty_pick_still_copies_the_last_block(tmp_path: Path) -> None:
    """E3 ruling 1 (GREEN on base — a regression pin, not RED): the shared
    resolver keeps Copy's empty=last arm while Edit/Remove reject empty. A
    refactor that invalidates Copy's empty pick, or copies the wrong block,
    fails here.
    """

    async def body(app, pilot, panel, project_dir):
        originals = [SourceBlock("a.s19"), PatchBlock("p.json")]
        _seed(panel, originals)
        await settle(pilot, 2)
        _pick(panel, "")
        await _press_chip(panel, pilot, "flow_copy")
        status = need(panel, "#flow_clip_status").render()
        status = status.plain if hasattr(status, "plain") else str(status)
        assert status.strip() == "clipboard: patch", (
            f"an empty pick must copy the LAST block: {status!r}"
        )
        assert panel._clipboard is not None and panel._clipboard.get("kind") == "patch"

    run(tmp_path, SIZE, body)


def test_tc_b102_fb_r2_merge_preserves_unexposed_fields(tmp_path: Path) -> None:
    """E3 ruling 2 (merge, never rebuild): saving an edit built from the
    modal's exposed fields preserves the wire fields the modal does not
    expose — SOURCE keeps ``file_type`` and ``a2l_ref``, WRITE-OUT keeps
    ``fmt``. A modal that rebuilds the block from scratch drops them.
    RED on base: ``#flow_edit`` does not ship.
    """

    async def body(app, pilot, panel, project_dir):
        originals = [
            SourceBlock("img.hex", file_type="hex", a2l_ref="map.a2l"),
            WriteOutBlock("out.bin", fmt="hex"),
        ]
        _seed(panel, originals)
        await settle(pilot, 2)

        _pick(panel, "1")
        await _press_chip(panel, pilot, "flow_edit")
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        inputs = list(modal.query(Input))
        assert len(inputs) == 1 and inputs[0].value == "img.hex"
        inputs[0].value = "img_v2.hex"
        await _press_labeled(modal, pilot, "save")
        await _wait_modal_closed(app, pilot, "FlowBlockEditScreen")
        block = panel.current_flow.blocks[0]
        assert block.image_ref == "img_v2.hex", f"got {block!r}"
        assert block.file_type == "hex", f"file_type must survive the merge: {block!r}"
        assert block.a2l_ref == "map.a2l", f"a2l_ref must survive the merge: {block!r}"

        _pick(panel, "2")
        await _press_chip(panel, pilot, "flow_edit")
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        inputs = list(modal.query(Input))
        assert len(inputs) == 1 and inputs[0].value == "out.bin"
        inputs[0].value = "out_v2.bin"
        await _press_labeled(modal, pilot, "save")
        await _wait_modal_closed(app, pilot, "FlowBlockEditScreen")
        block = panel.current_flow.blocks[1]
        assert block.output_name == "out_v2.bin", f"got {block!r}"
        assert block.fmt == "hex", f"fmt must survive the merge: {block!r}"
        assert panel.is_dirty

    run(tmp_path, SIZE, body, project=True)


def test_tc_b102_fb_r4_save_without_containment_base_refuses(tmp_path: Path) -> None:
    """E3 ruling 4 (explicit containment base): with NO project loaded the
    modal still opens, but Save refuses IN THE MODAL — the candidate is never
    persisted to fail later. Mutant control: the ref is stored unchecked, or
    the refusal is painted outside the modal. RED on base: ``#flow_edit`` does
    not ship.
    """

    async def body(app, pilot, panel, project_dir):
        originals = [SourceBlock("prg.s19")]
        _seed(panel, originals)
        await settle(pilot, 2)
        _pick(panel, "1")
        await _press_chip(panel, pilot, "flow_edit")
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        await settle(pilot, 2)
        inputs = list(modal.query(Input))
        inputs[0].value = "nope.s19"
        await _press_labeled(modal, pilot, "save")
        await settle(pilot, 3)
        assert type(app.screen).__name__ == "FlowBlockEditScreen", (
            "without a containment base Save must refuse inside the modal"
        )
        refusal = _modal_static_texts(modal)
        assert refusal, "the refusal must paint in the modal (ruling 4)"
        assert panel.current_flow.blocks == originals, "the unchecked ref must not be saved"
        assert not panel.is_dirty, "a refused save must not mark the flow dirty"
        await _press_labeled(modal, pilot, "cancel")
        await _wait_modal_closed(app, pilot, "FlowBlockEditScreen")

    run(tmp_path, SIZE, body)


def test_tc_b102_fb_r5_resolver_parses_without_isdigit_guard() -> None:
    """E3 ruling 5 (defensive parsing): ``FlowBuilderPanel._selected_block``
    parses the pick with ``try/except ValueError`` + range and carries NO
    ``isdigit()`` guard — the guard is what dies on ``'²'`` and on a
    >4,300-digit integer (behavioural arms in
    ``test_tc_b102_fb_05_defensive_index_parsing``). RED on base: the resolver
    does not ship.
    """
    import ast
    import inspect
    import textwrap

    from s19_app.tui import flow_screens as fs_mod

    resolver = getattr(fs_mod.FlowBuilderPanel, "_selected_block", None)
    assert resolver is not None, "FlowBuilderPanel._selected_block does not ship yet"
    tree = ast.parse(textwrap.dedent(inspect.getsource(resolver)))
    isdigit_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "isdigit"
    ]
    assert isdigit_calls == [], "an isdigit() guard before int() is prohibited (ruling 5)"
    value_error_handlers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                names = [n.id for n in ast.walk(handler) if isinstance(n, ast.Name)]
                value_error_handlers.extend(names)
    assert "ValueError" in value_error_handlers, (
        "the resolver must catch ValueError from int() (ruling 5)"
    )


def test_tc_b102_fb_r6_a2b_binding_round_trip(tmp_path: Path) -> None:
    """E3 ruling 6 (A2B round-trip): the modal shows the flow binding 1-based
    as ``#1`` (never the wire ``0``, never the card grammar ``#1.out``) and a
    save round-trips to the canonical wire form ``{source, ref}`` 0-based — an
    unchanged save yields a dataclass-equal block and NO dirty flag (ruling 9).
    Mutant control: the display form is persisted, or the binding re-bases.
    RED on base: ``#flow_edit`` does not ship.
    """

    async def body(app, pilot, panel, project_dir):
        originals = [
            SourceBlock("prg.s19"),
            A2BBlock(
                image_a=A2BInputBinding(A2B_INPUT_FLOW, "0"),
                image_b=A2BInputBinding(A2B_INPUT_FILE, "other.s19"),
            ),
        ]
        _seed(panel, originals)
        await settle(pilot, 2)
        _pick(panel, "2")
        await _press_chip(panel, pilot, "flow_edit")
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        await settle(pilot, 2)
        assert _modal_input_values(modal) == ["#1", "other.s19"], (
            f"the modal must show the 1-based #n display grammar (ruling 6): "
            f"{_modal_input_values(modal)!r}"
        )
        await _press_labeled(modal, pilot, "save")
        await _wait_modal_closed(app, pilot, "FlowBlockEditScreen")
        blocks = panel.current_flow.blocks
        assert blocks == originals, f"an unchanged save must round-trip: {blocks!r}"
        assert blocks[1].image_a == A2BInputBinding(A2B_INPUT_FLOW, "0"), (
            f"the wire form stays 0-based: {blocks[1]!r}"
        )
        assert not panel.is_dirty, "an unchanged candidate must not mark the flow dirty"

    run(tmp_path, SIZE, body, project=True)


def test_tc_b102_fb_r9_dirty_only_when_the_candidate_changes(tmp_path: Path) -> None:
    """E3 ruling 9 (honest dirty), SOURCE arm: opening the modal, changing
    nothing and saving leaves the chain dataclass-equal and the flow CLEAN —
    dirty sets only when the candidate differs (the changed arms pin the True
    direction in TC-B102-FB-02). RED on base: ``#flow_edit`` does not ship.
    """

    async def body(app, pilot, panel, project_dir):
        originals = [SourceBlock("prg.s19"), PatchBlock("p.json")]
        _seed(panel, originals)
        await settle(pilot, 2)
        _pick(panel, "2")
        await _press_chip(panel, pilot, "flow_edit")
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        await settle(pilot, 2)
        assert _modal_input_values(modal) == ["p.json"]
        await _press_labeled(modal, pilot, "save")
        await _wait_modal_closed(app, pilot, "FlowBlockEditScreen")
        assert panel.current_flow.blocks == originals
        assert not panel.is_dirty, "an unchanged candidate must not mark the flow dirty"

    run(tmp_path, SIZE, body, project=True)


@pytest.mark.parametrize("size", [(80, 24), (118, 54)], ids=["80x24", "118x54"])
def test_tc_b102_fb_r11_extended_clip_row_stays_contained(tmp_path: Path, size) -> None:
    """E3 ruling 11 (contención de la fila extendida): with the two new chips
    the copy/paste strip keeps every widget on ONE row, 1 cell tall, inside
    the panel — at 80x24 AND at 118x54. RED on base: the chips do not ship.
    """

    async def body(app, pilot, panel, project_dir):
        _seed(panel, [SourceBlock("prg.s19"), PatchBlock("p.json")])
        await settle(pilot, 2)
        box = panel.region
        regions = {wid: need(panel, f"#{wid}").region for wid in ROW_IDS}
        outside = [w for w, r in regions.items() if r.x < box.x or r.right > box.right]
        assert outside == [], f"at {size}: outside the panel: {outside}"
        assert len({r.y for r in regions.values()}) == 1, (
            f"at {size}: the strip must stay on one row: {regions!r}"
        )
        assert {r.height for r in regions.values()} == {1}, (
            f"at {size}: every strip widget paints 1 row tall: {regions!r}"
        )

    run(tmp_path, size, body)
