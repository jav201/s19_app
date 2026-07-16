"""Patch Editor BIG — the check glyph, folded into the ``Kind`` cell (batch-48, Inc-3).

Verdicts HLR-077 (R-TUI-077, US-P2) through the shipped Patch Editor surface.
Each entries row's ``Kind`` cell leads with the last check run's verdict for
THAT entry: ``✓`` pass · ``✗`` fail · ``◐`` uncheckable · ``·`` no current
result.

**The shape is a FOLD, not a column** (BL-3). ``_ENTRIES_COLUMNS`` stays a
5-tuple and the glyph rides as the leading SPAN of cell 0 — the house idiom
(A2L ``app.py:9548``, MAC ``app.py:9223-9226``, both column-count-preserving).
The free correctness signal this buys: the entries table's existing
index-readers assert ``Coordinate(row, 1)`` = address and ``(row, 2)`` = value
(``tests/test_tui_patch_editor_v2.py:2578``, ``:3208-3209``). Column 0 is
unasserted by them, so the fold needs ZERO edits to that 32-hit census file.
**Measured: ``git diff main -- tests/test_tui_patch_editor_v2.py`` == 0 lines.**
If that ever goes non-zero, a column was added and the DESIGN is wrong.

The two wrong-answer gates (both ★, both GATE-BLOCKING). A glyph is an
**alignment claim**: it asserts "this row's verdict is that record's". The
claim is false in two independent ways, and neither has an error path — the
table just lies quietly:

- **AT-077c (the DOCUMENT axis).** ``last_check_result`` survives
  ``add_entry`` / ``remove_entry`` / ``load`` / ``load_text``; it is reset ONLY
  by ``undo`` (``change_service.py:474``) / ``redo`` (``:506``). Harmless
  before this batch — ``check_rows`` renders self-describing, address-labelled
  rows and makes no alignment claim — but the glyph creates one.
- **AT-077e (the IMAGE axis, the BL-4 branch MISSED at Phase 1).**
  ``run_checks`` reads each entry's ``actual_bytes`` from the **image**
  (``change_service.py:1258-1259``), and ``ChangeService()`` is built once at
  ``app.py:1171`` and never rebuilt on load. So: check image A (all ``✓``) →
  load image B → the document is untouched → **a document-only signature still
  matches** → the glyphs render, describing image A. Reachable via the most
  routine action in the app.

Both are covered by ONE two-part stamp, ``(document_signature,
image_generation)``, refusing on either mismatch.

MEASURED RED LEDGER — every mutation below was APPLIED to the shipped tree, the
suite RUN, the output READ, then reverted. Nothing here is reasoned; where my
prediction disagreed with the run, the run won and the prediction is struck.

    M-1  drop the `image_generation` arm of the stamp (document signature only)
         -> AT-077e FAILED: glyphs ['✓','✓'] after loading image B — the EXACT
            BL-4 defect, rendered. TC-077.2 also FAILED (its image-axis arm).
            [my note "the ONLY test that moved" was WRONG — TC-077.2 is the
            unit-level arm of the same LLR and correctly moves with it]
    M-2  drop the `document_signature` arm (generation only)
         -> AT-077c FAILED. 11 passed.
    M-3  weaken the signature to a LENGTH (`len(self.document.entries)`)
         -> AT-077c FAILED **on arm (c) alone** — verified by reading the
            failure message, not inferred: arms (a)/(b) ran and passed, and the
            loop reached (c) before raising. Confirms arm (c) IS the
            count-equality counterfactual, and that (a)/(b) alone ship the hole.
    M-4  reverse the glyph list (`glyphs[::-1]`) — a positional mislabel
         -> AT-077d FAILED (with this file's 4-entry fixture). AT-077a,
            AT-077c and TC-077.1 also FAILED.
    M-4b ⚠ **the same reversal against 01b's OWN prescribed AT-077d fixture**
         (3 entries, only the MIDDLE fails -> ['✓','✗','✓'])
         -> **PASSED. 1 passed in 1.31s.** Measured by rebuilding the test to
            the spec's shape and re-running, NOT reasoned. 01b calls that
            fixture "the off-by-one killer": it does kill a ±1 shift, but the
            glyph list is a PALINDROME, so a full reversal is invisible to it.
            This file therefore uses an ASYMMETRIC 4-entry fixture; the
            obligation 01b states (assert the full ordered list) is discharged
            more strongly, not weakened. See `test_at077d_index_alignment`.
    M-5  `check_glyph` never read by the panel (`glyph = "·"` in `_kind_cell`)
         -> AT-077a, AT-077c, AT-077d, AT-077e all FAILED.
    M-6  rename the service's `GLYPH_UNCHECKABLE` to a char absent from the
         panel's `_GLYPH_STYLE`
         -> TC-077.3 FAILED (the two-map totality guard fired) AND AT-077a
            FAILED (it asserts the YELLOW span, so it catches the mis-colour
            too). [my note "every AT still PASSED" was WRONG. The totality
            guard still earns its place: it names the CAUSE — two maps drifted
            — where AT-077a only reports a missing span.]
    M-7  keep the stamp, remove `_apply_prepared_load`'s refresh-on-load
         -> AT-077e FAILED, 11 passed. **This was the FIRST red of the
            increment and it was not predicted**: the stamp alone invalidates
            in the SERVICE while the TABLE keeps painting the previous image's
            verdicts, because nothing re-renders the entries table on an image
            load. See that call site's comment.

⚠ The fixtures use ``kind: "check"``. A ``kind: "change"`` document BLOCKS the
run entirely (``CHECK_REASON_DOC_KIND``, ``changes/check.py``) and every entry
comes back ``uncheckable`` — an all-``◐`` table that would silently pass a
weaker AT-077a while proving nothing about the pass/fail branches.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.text import Text
from textual.coordinate import Coordinate
from textual.widgets import Button, DataTable, Input

from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.changes.model import CHECK_RESULT_DOMAIN
from s19_app.tui.insight_style import DGRAY, GREEN, RED, YELLOW
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services.change_service import (
    _CHECK_RESULT_GLYPH,
    GLYPH_FAIL,
    GLYPH_NO_RESULT,
    GLYPH_PASS,
    GLYPH_UNCHECKABLE,
    ChangeService,
)

#: The ``Kind`` cell — column 0, where the glyph folds in (LLR-077.4).
_KIND_COLUMN = 0

#: An address well outside every fixture image, so its entry is `uncheckable`.
_OUTSIDE_ADDRESS = 0x9000


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_check_document(path: Path, entries: list[dict]) -> Path:
    """Write a v2 ``kind="check"`` document — the only kind checks RUN over."""
    import json

    path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "check",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_image(path: Path, mem_map: dict[int, int]) -> Path:
    """Write a well-formed S19 whose image is exactly ``mem_map``.

    Ranges are derived from the map's own contiguous runs, so the fixture
    cannot drift out of agreement with itself.
    """
    addresses = sorted(mem_map)
    ranges: list[tuple[int, int]] = []
    for address in addresses:
        if ranges and address == ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], address + 1)
        else:
            ranges.append((address, address + 1))
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="utf-8")
    return path


def _kind_cells(app: S19TuiApp) -> list[object]:
    """Return every entries row's ``Kind`` cell, UNSTRINGIFIED.

    Not stringified: ``Text`` vs bare ``str`` is a live security property of
    this cell (LLR-075.6), and the glyph's SPAN is only readable off a ``Text``.
    """
    table = app.query_one("#patch_doc_entries_table", DataTable)
    return [
        table.get_cell_at(Coordinate(row, _KIND_COLUMN))
        for row in range(table.row_count)
    ]


def _glyphs(app: S19TuiApp) -> list[str]:
    """Return each row's LEADING glyph character, in table order."""
    return [cell.plain[0] for cell in _kind_cells(app)]


def _open_patch(app: S19TuiApp, doc_path: Path) -> None:
    """Open the Patch Editor and load a change document through its REAL ingress."""
    app.action_show_screen("patch")
    app.query_one("#patch_doc_path_input", Input).value = str(doc_path)
    app.query_one("#patch_editor_panel", PatchEditorPanel).request_action("load_doc")


def _run_checks(app: S19TuiApp) -> None:
    """Press the REAL ``#patch_checks_run_button`` (C-10(a) — never the service)."""
    app.query_one("#patch_checks_run_button", Button).press()


# ---------------------------------------------------------------------------
# The three-branch fixture: entry 0 passes, entry 1 fails, entry 2 is OUTSIDE
# ---------------------------------------------------------------------------

_BRANCH_IMAGE = {0x100: 0xAA, 0x101: 0xBB, 0x110: 0x00, 0x111: 0x00}
_BRANCH_ENTRIES = [
    # matches the image at 0x100-0x101 -> pass
    {"type": "bytes", "address": "0x100", "bytes": "AA BB"},
    # image holds 00 00 at 0x110-0x111 -> fail
    {"type": "bytes", "address": "0x110", "bytes": "11 22"},
    # no image coverage at all -> uncheckable
    {"type": "bytes", "address": f"0x{_OUTSIDE_ADDRESS:X}", "bytes": "EE"},
]


# ===========================================================================
# AT-077a — the three post-run branches, by GLYPH CONTENT
# ===========================================================================


def test_at077a_branches(tmp_path: Path) -> None:
    """A run renders ``✓`` / ``✗`` / ``◐`` on the right rows.

    Intent (AT-077a, C-10(b) — three policy branches in one fixture): the
    per-entry verdict exists in ``CheckRunResult.entries`` but is readable today
    only by cross-referencing the CHECKS panel's address-labelled lines. Each
    branch is asserted by its exact glyph CONTENT, driven through the REAL
    ``#patch_checks_run_button`` over a REAL image loaded through the REAL load
    surface — never a value the test injected.

    ``len(_ENTRIES_COLUMNS) == 5`` is asserted here too (LLR-077.4): the fold
    must not have quietly become a column.
    """
    image = _write_image(tmp_path / "image.s19", _BRANCH_IMAGE)
    doc = _write_check_document(tmp_path / "checks.json", _BRANCH_ENTRIES)

    async def _drive() -> tuple[list[object], list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.load_selected_file(image)
            await pilot.pause()
            _open_patch(app, doc)
            await pilot.pause()
            _run_checks(app)
            await pilot.pause()
            return _kind_cells(app), _glyphs(app)

    cells, glyphs = asyncio.run(_drive())

    assert len(PatchEditorPanel._ENTRIES_COLUMNS) == 5, (
        "the glyph FOLDS into the Kind cell (BL-3) — _ENTRIES_COLUMNS must stay "
        f"a 5-tuple; got {PatchEditorPanel._ENTRIES_COLUMNS!r}. A sixth column "
        "shifts Coordinate(row,1)/(row,2) under every existing index-reader."
    )
    assert glyphs == [GLYPH_PASS, GLYPH_FAIL, GLYPH_UNCHECKABLE], (
        "each entry's own verdict must lead its Kind cell: entry 0 matches the "
        "image (pass), entry 1 does not (fail), entry 2 is outside the image "
        f"(uncheckable). Got {glyphs!r}"
    )

    # The glyph is a SPAN, not just characters — and the cell keeps its role.
    for cell, glyph, style in zip(
        cells, glyphs, (GREEN, RED, YELLOW)
    ):
        assert isinstance(cell, Text), (
            f"the Kind cell must be a rich.text.Text, not a "
            f"{type(cell).__name__} — a bare str is markup-parsed by "
            "default_cell_formatter (LLR-075.6)"
        )
        assert cell.plain.startswith(glyph), (
            f"the glyph must LEAD the Kind cell; got {cell.plain!r}"
        )
        glyph_spans = [
            span
            for span in cell.spans
            if span.start == 0 and str(span.style) == style
        ]
        assert glyph_spans, (
            f"the {glyph!r} glyph must carry its own leading span styled "
            f"{style!r} (LLR-077.3); the cell's spans are {cell.spans!r}. "
            "Characters with no span render in the kind's own colour and "
            "convey no verdict."
        )


# ===========================================================================
# AT-077b — no run yet -> `·` on every row
# ===========================================================================


def test_at077b_no_run(tmp_path: Path) -> None:
    """Before any check run every row leads with a grey ``·``.

    Intent (AT-077b, C-10(b) fourth branch): the no-run default is asserted BY
    CONTENT, not by absence. "No glyph" and "the no-result glyph" are different
    products, and only the second tells the analyst that a run would tell them
    something.
    """
    image = _write_image(tmp_path / "image.s19", _BRANCH_IMAGE)
    doc = _write_check_document(tmp_path / "checks.json", _BRANCH_ENTRIES)

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.load_selected_file(image)
            await pilot.pause()
            _open_patch(app, doc)
            await pilot.pause()
            # deliberately NO run
            return _glyphs(app)

    glyphs = asyncio.run(_drive())
    assert glyphs == [GLYPH_NO_RESULT] * 3, (
        f"with no check run every row must lead with {GLYPH_NO_RESULT!r}; got "
        f"{glyphs!r}"
    )


# ===========================================================================
# AT-077c ★ — DOCUMENT provenance (GATE-BLOCKING)
# ===========================================================================


def test_at077c_stale_provenance(tmp_path: Path) -> None:
    """Mutating the document reverts every glyph to ``·`` — three ways.

    Intent (AT-077c ★, LLR-077.2, GATE-BLOCKING — the wrong-answer class):
    ``last_check_result`` is NOT reset by document mutation (only by undo/redo),
    so without the provenance stamp a mutated document is index-aligned onto a
    stale result and rows are labelled with verdicts belonging to entries that
    no longer exist at that index. There is no error path — the table simply
    lies.

    Three arms, each through a REAL button:

      (a) ``#patch_entry_add_button``    — count grows
      (b) ``#patch_entry_remove_button`` — count shrinks
      (c) ``#patch_entry_edit_button``   — **count UNCHANGED**, bytes replaced

    Arm (c) is the counterfactual that makes this AT non-vacuous: a
    count-equality guard passes (a) and (b) and silently mislabels (c). Measured
    (M-3): weakening the signature to ``len(entries)`` fails arm (c) ALONE.

    The **non-invalidation** arm is asserted first and is equally load-bearing:
    without it, an implementation that renders ``·`` unconditionally passes
    every other assertion here.
    """
    image = _write_image(tmp_path / "image.s19", _BRANCH_IMAGE)

    def _drive(mutate) -> list[str]:
        async def _run() -> list[str]:
            doc = _write_check_document(
                tmp_path / f"checks-{id(mutate)}.json", list(_BRANCH_ENTRIES)
            )
            app = S19TuiApp(base_dir=tmp_path)
            async with app.run_test(size=(120, 30)) as pilot:
                await pilot.pause()
                app.load_selected_file(image)
                await pilot.pause()
                _open_patch(app, doc)
                await pilot.pause()
                _run_checks(app)
                await pilot.pause()
                assert _glyphs(app) != [GLYPH_NO_RESULT] * 3, (
                    "PRECONDITION: the run must render real verdicts before the "
                    "mutation, or the post-mutation assertion is vacuous"
                )
                mutate(app)
                await pilot.pause()
                return _glyphs(app)

        return asyncio.run(_run())

    def _no_mutation(app: S19TuiApp) -> None:
        pass

    def _add(app: S19TuiApp) -> None:
        app.query_one("#patch_entry_address_input", Input).value = "0x200"
        app.query_one("#patch_entry_value_input", Input).value = "added"
        app.query_one("#patch_entry_bytes_input", Input).value = ""
        app.query_one("#patch_entry_add_button", Button).press()

    def _remove(app: S19TuiApp) -> None:
        app.query_one("#patch_entry_address_input", Input).value = "0x110"
        app.query_one("#patch_entry_remove_button", Button).press()

    def _edit_in_place(app: S19TuiApp) -> None:
        # Same address, NEW bytes -> the entry count is IDENTICAL.
        app.query_one("#patch_entry_address_input", Input).value = "0x100"
        app.query_one("#patch_entry_value_input", Input).value = ""
        app.query_one("#patch_entry_bytes_input", Input).value = "DE AD"
        app.query_one("#patch_entry_edit_button", Button).press()

    # Non-invalidation FIRST — the anti-vacuity arm.
    unchanged = _drive(_no_mutation)
    assert unchanged == [GLYPH_PASS, GLYPH_FAIL, GLYPH_UNCHECKABLE], (
        "with NO mutation the stamp must still match and the glyphs must "
        f"render; got {unchanged!r}. If this reads all-'·' the implementation "
        "refuses unconditionally and every arm below is vacuous."
    )

    for arm, mutate, expected_rows in (
        ("(a) add_entry", _add, 4),
        ("(b) remove_entry", _remove, 2),
        ("(c) in-place edit, COUNT UNCHANGED", _edit_in_place, 3),
    ):
        glyphs = _drive(mutate)
        assert len(glyphs) == expected_rows, (
            f"arm {arm}: the mutation must actually have taken effect; "
            f"expected {expected_rows} rows, got {len(glyphs)}"
        )
        assert glyphs == [GLYPH_NO_RESULT] * expected_rows, (
            f"arm {arm}: after the document is mutated the completed run "
            f"describes a document that no longer exists — every glyph must "
            f"revert to {GLYPH_NO_RESULT!r}. Got {glyphs!r}; a retained "
            "'✓'/'✗' is a verdict attributed to the wrong entry."
        )


# ===========================================================================
# AT-077d — index alignment (the off-by-one killer)
# ===========================================================================


def test_at077d_index_alignment(tmp_path: Path) -> None:
    """The full ORDERED glyph list lands on the right rows.

    Intent (AT-077d, LLR-077.1): entry ↔ result correlation is POSITIONAL —
    neither ``ChangeEntry`` nor ``CheckRunEntry`` carries an id, and the
    contract is document order (``changes/model.py:660-661``). An off-by-one
    silently mislabels a row's verdict with no error path. "Some row shows ✗"
    passes under a ±1 shift; the FULL ORDERED list does not.

    ⚠ **The fixture is deliberately ASYMMETRIC, and the spec's was not.**
    01b prescribes 3 entries with only the MIDDLE failing -> ``['✓','✗','✓']``
    — a PALINDROME. It does kill a ±1 shift, but a full REVERSAL of the glyph
    list leaves it identical. Measured (M-4b), not reasoned: rebuilt to the
    spec's own 3-entry shape and run against ``glyphs[::-1]``, this test
    **PASSED**. The 4-entry ``['✓','✗','◐','✓']`` below is asymmetric under
    both reversal and shift; against the same mutation it FAILS (M-4). The
    obligation 01b states — assert the FULL ORDERED list — is discharged more
    strongly, not weakened.
    """
    image = _write_image(
        tmp_path / "image.s19",
        {0x100: 0xAA, 0x110: 0x00, 0x130: 0xCC},
    )
    doc = _write_check_document(
        tmp_path / "ordered.json",
        [
            {"type": "bytes", "address": "0x100", "bytes": "AA"},  # pass
            {"type": "bytes", "address": "0x110", "bytes": "11"},  # fail
            {"type": "bytes", "address": "0x9000", "bytes": "EE"},  # uncheckable
            {"type": "bytes", "address": "0x130", "bytes": "CC"},  # pass
        ],
    )

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.load_selected_file(image)
            await pilot.pause()
            _open_patch(app, doc)
            await pilot.pause()
            _run_checks(app)
            await pilot.pause()
            return _glyphs(app)

    glyphs = asyncio.run(_drive())
    expected = [GLYPH_PASS, GLYPH_FAIL, GLYPH_UNCHECKABLE, GLYPH_PASS]
    assert glyphs == expected, (
        f"the glyphs must land in DOCUMENT ORDER: expected {expected!r}, got "
        f"{glyphs!r}. This list is asymmetric under both reversal and a ±1 "
        "shift, so any positional drift fails here."
    )


# ===========================================================================
# AT-077e ★ — IMAGE provenance, the BL-4 branch (GATE-BLOCKING)
# ===========================================================================


def test_at077e_image_generation_invalidates(tmp_path: Path) -> None:
    """Loading a different image reverts the glyphs to ``·``, not a stale ``✓``.

    Intent (AT-077e ★, LLR-077.2 image arm, GATE-BLOCKING — the branch MISSED
    at Phase 1): a check run's ``actual_bytes`` come from the IMAGE
    (``change_service.py:1258-1259``), and ``ChangeService()`` is constructed
    once at ``app.py:1171`` and never rebuilt on load. So checking image A,
    then loading image B, leaves the document **untouched** — a document-only
    signature still matches, and the glyphs keep describing image A. Reachable
    via the most routine action in the app.

    The document is not touched at any point here; the ONLY thing that changes
    is which image is loaded, through the REAL load surface. Image B's bytes
    differ at BOTH checked addresses, so the stale answer (``✓``) and the
    honest answer (``·``) are maximally far apart — and a re-run against B
    would say ``✗``, which is neither.

    Two mechanisms are required and this AT pins BOTH — it fails if either is
    missing, which is why it is one node and not two:

      * M-1 (stamp's image arm removed) -> FAILED ``['✓','✓']``
      * M-7 (stamp intact, ``_apply_prepared_load``'s refresh-on-load removed)
        -> FAILED. The service invalidates correctly and the TABLE still paints
        image A's verdicts, because nothing else re-renders it on a load.
    """
    image_a = _write_image(
        tmp_path / "image_a.s19", {0x100: 0xAA, 0x101: 0xBB, 0x110: 0xCC}
    )
    image_b = _write_image(
        tmp_path / "image_b.s19", {0x100: 0x11, 0x101: 0x22, 0x110: 0x33}
    )
    doc = _write_check_document(
        tmp_path / "checks.json",
        [
            {"type": "bytes", "address": "0x100", "bytes": "AA BB"},
            {"type": "bytes", "address": "0x110", "bytes": "CC"},
        ],
    )

    async def _drive() -> tuple[list[str], list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.load_selected_file(image_a)
            await pilot.pause()
            _open_patch(app, doc)
            await pilot.pause()
            _run_checks(app)
            await pilot.pause()
            after_run = _glyphs(app)

            # The ONLY action: load a DIFFERENT image. No document mutation,
            # no re-run, no undo.
            app.load_selected_file(image_b)
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            return after_run, _glyphs(app)

    after_run, after_load = asyncio.run(_drive())

    assert after_run == [GLYPH_PASS, GLYPH_PASS], (
        "PRECONDITION: both entries must PASS against image A, or the stale "
        f"verdict this AT hunts never exists; got {after_run!r}"
    )
    assert after_load == [GLYPH_NO_RESULT, GLYPH_NO_RESULT], (
        "after image B is loaded the completed run describes an image that is "
        f"no longer there — every glyph must revert to {GLYPH_NO_RESULT!r}. Got "
        f"{after_load!r}: a retained '✓' claims image B matches the entries "
        "when it does not (a re-run says '✗'). The document was never touched, "
        "so a document-only signature CANNOT catch this — this is BL-4."
    )


# ===========================================================================
# TC-077.1 — index-aligned derivation, unit level (no address matching)
# ===========================================================================


def test_tc077_1_index_alignment(tmp_path: Path) -> None:
    """``rows()`` joins glyphs by index, and two entries may share an address.

    Intent (TC-077.1, LLR-077.1): the unit-level arm of AT-077d, plus the case
    that makes ADDRESS-matching structurally impossible rather than merely
    discouraged — **two entries at the SAME start address with DIFFERENT
    verdicts**. Any address-keyed join collapses them and must return the same
    glyph for both; the index join keeps them distinct.

    ⚠ The colliding pair is built through ``load_text``, NOT ``add_entry``:
    ``add_entry`` REFUSES a duplicate address (``change_service.py:696``,
    "use Edit"), so via that ingress the case looks unreachable — a comfortable
    reading that would have retired this test for the wrong reason. The FILE
    ingress does construct colliding entries (it flags them ``CHG-COLLISION``
    and carries on — the engine's own taint-attribution path exists precisely
    because these reach the document). So the case is real, and reachable by
    the route change-sets actually arrive through.
    """
    service = ChangeService()
    service.load_text(
        '{"format": "s19app-changeset", "version": "2.0", "kind": "check",'
        ' "encoding": "utf-8", "value_mode": "text", "entries": ['
        '{"type": "bytes", "address": "0x100", "bytes": "AA"},'
        '{"type": "bytes", "address": "0x100", "bytes": "BB"},'
        '{"type": "bytes", "address": "0x200", "bytes": "CC"}]}'
    )
    assert len(service.document.entries) == 3, (
        "PRECONDITION: the file ingress must construct BOTH colliding entries; "
        f"got {len(service.document.entries)}"
    )

    class _Record:
        def __init__(self, result: str) -> None:
            self.result = result

    class _Result:
        entries = [_Record("pass"), _Record("fail"), _Record("uncheckable")]

    service.check_runner = lambda *args, **kwargs: _Result()
    service.run_checks(None, None, None, None)

    glyphs = [row.check_glyph for row in service.rows(None)]
    assert glyphs == [GLYPH_PASS, GLYPH_FAIL, GLYPH_UNCHECKABLE], (
        "entries 0 and 1 declare the SAME address 0x100 but hold different "
        f"verdicts; an address-keyed join cannot tell them apart. Got {glyphs!r}"
    )


def test_tc077_1_short_result_does_not_raise() -> None:
    """A result with fewer records than the document degrades, never raises.

    Intent (TC-077.1 boundary): the ``check_runner`` seam is injectable, so a
    stub may return fewer records than the document has entries. Surplus rows
    fall back to ``·`` rather than raising ``IndexError`` out of a renderer.
    """
    service = ChangeService()
    service.add_entry("0x100", "", "AA")
    service.add_entry("0x200", "", "BB")

    class _Record:
        result = "pass"

    class _Result:
        entries = [_Record()]

    service.check_runner = lambda *args, **kwargs: _Result()
    service.run_checks(None, None, None, None)

    glyphs = [row.check_glyph for row in service.rows(None)]
    assert glyphs == [GLYPH_PASS, GLYPH_NO_RESULT], (
        f"the surplus row must fall back to the no-result glyph; got {glyphs!r}"
    )


# ===========================================================================
# TC-077.2 ★ — the stamp's shape and its input set
# ===========================================================================


def test_tc077_2_provenance() -> None:
    """The stamp is ``(document_signature, image_generation)`` — and no more.

    Intent (TC-077.2 ★, LLR-077.2): pins the mechanism the two gate-blocking
    ATs rest on. (Node name is 01b's executed-verification id verbatim, so its
    command resolves — C-18.)

      * ``image_generation`` is the app's monotonic token, NOT ``id(mem_map)``:
        CPython reuses ``id()`` after GC, so a freed map and a freshly-loaded
        one can collide into a false "same image" match — precisely the bug.
      * ``mac_records`` / ``a2l_tags`` are ``check_runner`` inputs too, but they
        drive ``CheckRunEntry.linkage``, NOT ``.result``, and the glyph renders
        ``.result`` only. Asserting they do NOT invalidate stops Phase 3 (and
        any later batch) from over-building the stamp into a nuisance that
        blanks the glyphs on an unrelated MAC reload.
    """
    service = ChangeService()
    service.add_entry("0x100", "", "AA")

    class _Result:
        entries = [type("R", (), {"result": "pass"})()]

    service.check_runner = lambda *args, **kwargs: _Result()

    service.set_image_generation(7)
    service.run_checks({0x100: 0xAA}, None, None, None)
    assert [row.check_glyph for row in service.rows(None)] == [GLYPH_PASS]

    # The signature is over CONTENT, and it is a tuple of the three fields the
    # run consumed — not a length.
    assert service._document_signature() == (("bytes", 0x100, (0xAA,)),), (
        "the signature must be the ordered (entry_type, address, "
        f"encoded_bytes) tuple; got {service._document_signature()!r}"
    )

    # Axis 2: the generation alone invalidates, document untouched.
    service.set_image_generation(8)
    assert [row.check_glyph for row in service.rows(None)] == [GLYPH_NO_RESULT], (
        "an image-generation bump alone must invalidate (BL-4)"
    )

    # ...and it is an equality check on a token, not object identity.
    service.set_image_generation(7)
    assert [row.check_glyph for row in service.rows(None)] == [GLYPH_PASS], (
        "returning to the stamped generation must restore the glyphs — the "
        "stamp compares tokens, it does not hash the map"
    )


def test_tc077_2_linkage_inputs_do_not_invalidate() -> None:
    """MAC / A2L inputs are outside the stamp — they drive linkage, not result."""
    service = ChangeService()
    service.add_entry("0x100", "", "AA")

    class _Result:
        entries = [type("R", (), {"result": "pass"})()]

    service.check_runner = lambda *args, **kwargs: _Result()
    service.run_checks({0x100: 0xAA}, None, [{"tag": "A", "address": 0x100}], None)

    assert [row.check_glyph for row in service.rows(None)] == [GLYPH_PASS], (
        "the stamp's input set is exactly (document, image); a MAC record set "
        "must not participate — it drives CheckRunEntry.linkage, never .result"
    )


# ===========================================================================
# TC-077.3 — the glyph vocabulary, and the two maps' totality
# ===========================================================================


def test_tc077_3_glyph_map() -> None:
    """The glyph vocabulary is total over ``CHECK_RESULT_DOMAIN``, unknown → ``◐``.

    Intent (TC-077.3, LLR-077.3): the map is a CLOSED vocabulary. Totality over
    ``CHECK_RESULT_DOMAIN`` is asserted against the domain itself, so a future
    result token added to the engine fails HERE rather than rendering a blank
    cell in the field.

    The **cross-module totality clause** is the one that is not redundant with
    the ATs: the service owns token → glyph and the panel owns glyph → style
    (C-7 keeps the panel import-free of the service), so the two maps are keyed
    on the same four characters in two modules. Measured (M-6): renaming a
    glyph on the service side turns this clause RED — and AT-077a red too, so
    the guard is not the only net. It earns its place by naming the CAUSE (two
    maps drifted apart) where AT-077a can only report a missing span.
    """
    assert set(_CHECK_RESULT_GLYPH) == set(CHECK_RESULT_DOMAIN), (
        "every check-result token must map to a glyph; unmapped: "
        f"{set(CHECK_RESULT_DOMAIN) - set(_CHECK_RESULT_GLYPH)!r}"
    )
    assert _CHECK_RESULT_GLYPH["pass"] == GLYPH_PASS
    assert _CHECK_RESULT_GLYPH["fail"] == GLYPH_FAIL
    assert _CHECK_RESULT_GLYPH["uncheckable"] == GLYPH_UNCHECKABLE

    # Unknown token -> `◐`, mirroring `_CHECK_RESULT_SEVERITY`'s WARNING
    # default rather than inventing a second policy.
    service = ChangeService()
    service.add_entry("0x100", "", "AA")

    class _Result:
        entries = [type("R", (), {"result": "sideways"})()]

    service.check_runner = lambda *args, **kwargs: _Result()
    service.run_checks(None, None, None, None)
    assert [row.check_glyph for row in service.rows(None)] == [
        GLYPH_UNCHECKABLE
    ], "an unrecognised result token must render ◐ — never a blank, never a raise"

    # Cross-module totality: every glyph the service can emit has a style.
    emitted = set(_CHECK_RESULT_GLYPH.values()) | {GLYPH_NO_RESULT}
    styled = set(PatchEditorPanel._GLYPH_STYLE)
    assert emitted == styled, (
        "the service's glyph vocabulary and the panel's style map must stay "
        f"TOTAL over each other; service-only: {emitted - styled!r}, "
        f"panel-only: {styled - emitted!r}. A drift here mis-colours silently: "
        "_kind_cell falls back to DGRAY and the verdict reads as 'no result'."
    )
    assert PatchEditorPanel._GLYPH_STYLE == {
        GLYPH_PASS: GREEN,
        GLYPH_FAIL: RED,
        GLYPH_UNCHECKABLE: YELLOW,
        GLYPH_NO_RESULT: DGRAY,
    }, "the LLR-077.3 colour assignment"


# ===========================================================================
# TC-077.4 — the fold: the table's own contract is untouched
# ===========================================================================


def test_tc077_4_glyph_folded_into_kind(tmp_path: Path) -> None:
    """The fold changes cell 0's content only — never the table's shape.

    Intent (TC-077.4, LLR-077.4 / BL-3): the glyph is a span inside an existing
    cell, so the table's id, column set, ``cursor_type`` and empty-state toggle
    are all invariants a column would have broken. ``cursor_type="row"`` is
    load-bearing beyond styling: it is what makes the cursor's row index the
    entry index (LLR-077.1).
    """
    doc = _write_check_document(
        tmp_path / "one.json", [{"type": "bytes", "address": "0x100", "bytes": "AA"}]
    )
    empty = _write_check_document(tmp_path / "empty.json", [])

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _open_patch(app, doc)
            await pilot.pause()
            table = app.query_one("#patch_doc_entries_table", DataTable)
            outcomes["columns"] = len(table.columns)
            outcomes["cursor_type"] = table.cursor_type
            outcomes["zebra"] = table.zebra_stripes
            outcomes["table_hidden"] = table.has_class("hidden")
            outcomes["empty_hidden"] = app.query_one(
                "#patch_doc_empty_state"
            ).has_class("hidden")

            # The empty-state toggle still fires off the same seam.
            app.query_one("#patch_doc_path_input", Input).value = str(empty)
            app.query_one("#patch_editor_panel", PatchEditorPanel).request_action(
                "load_doc"
            )
            await pilot.pause()
            outcomes["table_hidden_empty"] = table.has_class("hidden")
            outcomes["empty_hidden_empty"] = app.query_one(
                "#patch_doc_empty_state"
            ).has_class("hidden")
        return outcomes

    outcomes = asyncio.run(_drive())

    assert PatchEditorPanel._ENTRIES_COLUMNS == (
        "Kind",
        "Address",
        "Value / bytes",
        "Status",
        "Linkage",
    ), "the 5-column set is unchanged by the fold"
    assert outcomes["columns"] == 5, (
        f"the live table must carry 5 columns; got {outcomes['columns']}"
    )
    assert outcomes["cursor_type"] == "row", (
        "cursor_type='row' is what makes the cursor's row index the entry "
        f"index (LLR-077.1); got {outcomes['cursor_type']!r}"
    )
    assert outcomes["zebra"] is True, "zebra_stripes is unchanged"
    assert outcomes["table_hidden"] is False and outcomes["empty_hidden"] is True, (
        "a populated document shows the table and hides the empty state"
    )
    assert (
        outcomes["table_hidden_empty"] is True
        and outcomes["empty_hidden_empty"] is False
    ), "an empty document must still toggle to the empty state — no glyph crash"


# ===========================================================================
# TC-077.6 — C-17 disposition for the glyph SPAN
# ===========================================================================


def test_tc077_6_glyph_carries_no_file_derived_text(tmp_path: Path) -> None:
    """No file-derived string reaches the glyph span.

    Intent (TC-077.6, LLR-077.6): the glyph's value set is the 4-token closed
    vocabulary — ``linkage_symbol`` / ``reason`` never reach it. This is
    asserted rather than inspected, because the ``Kind`` cell now holds an
    author-owned glyph NEXT TO file-derived ``kind_text`` in one ``Text``, and
    an inspection-only N/A sitting beside an untrusted string in the same cell
    is exactly the shape that has bitten this project before.

    Scope: this covers the SPAN. The CELL's file-derived text half is covered
    by AT-075e ★★ (LLR-075.6), which is a real gate-blocking hostile-input AT.
    """
    hostile = "[red]PWNED[/red]"
    doc = _write_check_document(
        tmp_path / "hostile.json",
        [{"type": "string", "address": "0x100", "value": hostile}],
    )

    async def _drive() -> Text:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _open_patch(app, doc)
            await pilot.pause()
            _run_checks(app)
            await pilot.pause()
            return _kind_cells(app)[0]

    cell = asyncio.run(_drive())

    assert cell.plain[0] in set(_CHECK_RESULT_GLYPH.values()) | {GLYPH_NO_RESULT}, (
        f"the leading character must be a vocabulary glyph; got {cell.plain!r}"
    )
    assert cell.plain == f"{cell.plain[0]} string", (
        "the Kind cell is exactly '<glyph> <kind>' — no reason text, no linkage "
        f"symbol, no interpolated file data; got {cell.plain!r}"
    )
    assert not any("link" in str(span.style) for span in cell.spans), (
        f"no span may carry a link style; got {cell.spans!r}"
    )
