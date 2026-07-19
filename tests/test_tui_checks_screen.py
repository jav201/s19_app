"""Behavioral + white-box tests for the dedicated CHECKS rail screen.

Batch-49 Inc-3 (HLR-083 / HLR-084, US-083). These drive the SHIPPED surface —
the activity rail key ``9`` and the ``#screen_checks`` subtree — through a
Textual ``Pilot``, verifying the navigation contract (AT-083a/b), the two honest
empty states (AT-084d no-file, AT-084e file-but-no-run), and the
``update_checks_view`` group/aggregate render off an injected
``last_check_result`` (TC-084.3, the consumer-contract guard of TC-084.9).

Inc-4 (this file, extended) adds the through-surface behavioral ATs that Inc-3
deferred: the hex peek on row-select (LLR-084.5 → AT-084c, TC-084.11), the
run/undo/redo refresh wiring (LLR-084.7 → AT-084f), the real-run grouped render
+ aggregate strip over the REAL ``#patch_checks_run_button`` (LLR-084.1/.3/.4 →
AT-084a/AT-084b, C-12 through-surface), and the C-17 hostile-input proof through
``update_checks_view`` (LLR-084.8 → AT-084g). The run-checks driver is REUSED
from ``tests/test_tui_patch_checks_strip.py`` (``_open_patch_with_paste`` /
``_run_checks`` / the asymmetric 2-pass/1-fail@0x102/3-uncheckable fixture) so
the CHECKS screen observes exactly the run the Patch Editor produced.

Reuses ``_make_s19_image`` / ``_load_image`` / ``_set_entry_inputs`` from
``tests/test_tui_patch_editor_v2.py`` (image load + entry input), the run-checks
driver from ``tests/test_tui_patch_checks_strip.py``, and the rail-nav Pilot
idiom of ``tests/test_tui_directionb.py``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button, Static

from s19_app.tui.app import EmptyStatePanel, S19TuiApp
from s19_app.tui.changes.model import CheckRunEntry, CheckRunResult
from s19_app.tui.checks_view import (
    CheckGroupHeader,
    CheckRow,
    GroupedChecksPanel,
    build_checks_aggregate_strip,
)
from tests.test_tui_patch_checks_strip import (
    _ASYMMETRIC_ENTRIES,
    _EXPECTED_AGGREGATES,
    _open_patch_with_paste,
    _run_checks,
)
from tests.test_tui_patch_editor_v2 import (
    _load_image,
    _make_s19_image,
    _set_entry_inputs,
)


def _synthetic_check_result() -> tuple[CheckRunResult, dict[str, int]]:
    """A 2-pass / 1-fail / 1-uncheckable run — all three group tokens present.

    The counts are DISTINCT so a group/count mislabel (a pass<->fail swap, a
    dropped uncheckable) must fail the assertions rather than silently balance.
    """
    entries = [
        CheckRunEntry(
            entry_type="bytes",
            address_start=0x100,
            address_end=0x101,
            expected_bytes=(0x00,),
            actual_bytes=(0x00,),
            result="pass",
            linkage="",
            linkage_symbol=None,
        ),
        CheckRunEntry(
            entry_type="bytes",
            address_start=0x101,
            address_end=0x102,
            expected_bytes=(0x00,),
            actual_bytes=(0x00,),
            result="pass",
            linkage="",
            linkage_symbol=None,
        ),
        CheckRunEntry(
            entry_type="bytes",
            address_start=0x102,
            address_end=0x103,
            expected_bytes=(0xFF,),
            actual_bytes=(0x00,),
            result="fail",
            linkage="",
            linkage_symbol=None,
        ),
        CheckRunEntry(
            entry_type="bytes",
            address_start=0x9000,
            address_end=0x9001,
            expected_bytes=(0xEE,),
            actual_bytes=None,
            result="uncheckable",
            linkage="",
            linkage_symbol=None,
            reason="no image coverage",
        ),
    ]
    aggregates = {"passed": 2, "failed": 1, "uncheckable": 1}
    result = CheckRunResult(
        source_path=None,
        timestamp_utc="2026-07-18T00:00:00Z",
        variant_id=None,
        aggregates=aggregates,
        entries=entries,
    )
    return result, aggregates


# ---------------------------------------------------------------------------
# AT-083a (GATE) — key 9 activates #screen_checks, hides the default screen,
#                  moves the rail's active marker to Checks.
# ---------------------------------------------------------------------------


def test_at083a_key_9_activates_checks_screen(tmp_path: Path) -> None:
    """Pressing ``9`` shows ``#screen_checks``, hides Workspace, marks the rail.

    Intent (HLR-083, C-10): the active screen must CHANGE off the default —
    ``#screen_checks`` loses ``hidden`` while the previously-visible
    ``#screen_workspace`` gains it — and the rail's single active marker moves
    to the Checks item. A missing ``9`` binding / absent screen makes the query
    raise or the classes never move, so this fails RED pre-change.
    """

    async def _drive() -> tuple[bool, bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("9")
            await pilot.pause()
            checks_hidden = "hidden" in app.query_one("#screen_checks").classes
            workspace_hidden = (
                "hidden" in app.query_one("#screen_workspace").classes
            )
            rail_active = app.query_one("#rail_item_checks").has_class("-active")
            return checks_hidden, workspace_hidden, rail_active

    checks_hidden, workspace_hidden, rail_active = asyncio.run(_drive())
    assert not checks_hidden, "key 9 must reveal #screen_checks"
    assert workspace_hidden, "activating Checks must hide the default Workspace"
    assert rail_active, "the Checks rail item must carry the -active marker"


# ---------------------------------------------------------------------------
# AT-083b — activating another rail screen hides #screen_checks again.
# ---------------------------------------------------------------------------


def test_at083b_other_screen_hides_checks(tmp_path: Path) -> None:
    """After ``9`` then ``5`` (Issues), ``#screen_checks`` is hidden again."""

    async def _drive() -> tuple[bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("9")
            await pilot.pause()
            visible_after_9 = (
                "hidden" not in app.query_one("#screen_checks").classes
            )
            await pilot.press("5")
            await pilot.pause()
            hidden_after_5 = "hidden" in app.query_one("#screen_checks").classes
            return visible_after_9, hidden_after_5

    visible_after_9, hidden_after_5 = asyncio.run(_drive())
    assert visible_after_9, "key 9 must first reveal #screen_checks"
    assert hidden_after_5, "activating Issues must hide #screen_checks"


# ---------------------------------------------------------------------------
# AT-084d — no file loaded -> EmptyStatePanel visible, #checks_content hidden.
# ---------------------------------------------------------------------------


def test_at084d_no_file_shows_empty_state(tmp_path: Path) -> None:
    """With no file, ``9`` shows the EmptyStatePanel and hides the content."""

    async def _drive() -> tuple[bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("9")
            await pilot.pause()
            screen = app.query_one("#screen_checks")
            empty_visible = not screen.query_one(
                EmptyStatePanel
            ).has_class("hidden")
            content_hidden = "hidden" in screen.query_one(
                "#checks_content"
            ).classes
            return empty_visible, content_hidden

    empty_visible, content_hidden = asyncio.run(_drive())
    assert empty_visible, "no-file Checks screen must show the EmptyStatePanel"
    assert content_hidden, "no-file Checks screen must hide #checks_content"


# ---------------------------------------------------------------------------
# AT-084e — file loaded but no check run -> the "no check run yet" note,
#           the content visible, and DISTINCT from AT-084d's empty state.
# ---------------------------------------------------------------------------


def test_at084e_file_no_run_shows_no_run_note(tmp_path: Path) -> None:
    """A loaded image with no check run shows the NO_RUN note, not a zeroed list.

    Intent (HLR-084 / LLR-084.6, R-6): the file-loaded-but-no-run state must be
    VISIBLY distinct from the no-file empty state (AT-084d) AND from a real
    0/0/0 run. Here ``#checks_content`` is visible (not the EmptyStatePanel) and
    the grouped panel carries the ``.checks-no-run-note`` marker — never the
    ``.checks-empty-note`` a real empty run would show.
    """

    s19_path = _make_s19_image(tmp_path)

    async def _drive() -> tuple[bool, bool, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            _load_image(app, s19_path)
            await pilot.press("9")
            await pilot.pause()
            screen = app.query_one("#screen_checks")
            content_visible = "hidden" not in screen.query_one(
                "#checks_content"
            ).classes
            empty_state_hidden = screen.query_one(EmptyStatePanel).has_class(
                "hidden"
            )
            panel = app.query_one("#checks_grouped", GroupedChecksPanel)
            no_run_notes = len(panel.query(".checks-no-run-note"))
            empty_notes = len(panel.query(".checks-empty-note"))
            return content_visible, empty_state_hidden, no_run_notes, empty_notes

    content_visible, empty_state_hidden, no_run_notes, empty_notes = asyncio.run(
        _drive()
    )
    assert content_visible, "file-loaded Checks screen must show #checks_content"
    assert empty_state_hidden, "file-loaded Checks screen hides the EmptyStatePanel"
    assert no_run_notes == 1, "the no-run note must be shown when no check ran"
    assert empty_notes == 0, (
        "the no-run state must be DISTINCT from a real 0/0/0 empty run"
    )


# ---------------------------------------------------------------------------
# TC-084.3 — update_checks_view groups the rows + drives the aggregate strip
#            from an injected last_check_result (consumer guard, TC-084.9).
# ---------------------------------------------------------------------------


def test_tc084_3_update_checks_view_groups_and_aggregates(tmp_path: Path) -> None:
    """An injected run renders one row per entry, its groups, and the strip.

    Intent (LLR-084.3): ``update_checks_view`` reads the service accessors,
    groups fail -> uncheckable -> pass, and paints ``#checks_aggregate_strip``
    from ``check_aggregates()``. Injecting ``last_check_result`` directly (not
    the real run button) is the consumer-contract guard — never the gate (C-12,
    the through-surface AT-084a rides Inc-4).
    """

    s19_path = _make_s19_image(tmp_path)
    result, aggregates = _synthetic_check_result()

    async def _drive() -> tuple[int, int, dict[str, int], str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            _load_image(app, s19_path)
            app._change_service.last_check_result = result
            await pilot.press("9")
            await pilot.pause()
            panel = app.query_one("#checks_grouped", GroupedChecksPanel)
            row_count = len(panel.query(CheckRow))
            header_count = len(panel.query(CheckGroupHeader))
            live_aggregates = app._change_service.check_aggregates()
            strip_plain = app.query_one(
                "#checks_aggregate_strip", Static
            ).render().plain
            return row_count, header_count, live_aggregates, strip_plain

    row_count, header_count, live_aggregates, strip_plain = asyncio.run(_drive())
    # Fixture integrity first (C-31): the injected run really is 2/1/1.
    assert live_aggregates == aggregates, (
        f"check_aggregates() must mirror the injected run, got {live_aggregates}"
    )
    assert row_count == 4, f"one CheckRow per entry expected, got {row_count}"
    assert header_count == 3, (
        f"all three outcome groups present -> 3 headers, got {header_count}"
    )
    assert strip_plain == build_checks_aggregate_strip(aggregates).plain, (
        "the aggregate strip must render the check_aggregates() counts"
    )


# ---------------------------------------------------------------------------
# Inc-4 — through-surface behavioral ATs over the REAL run-checks producer.
# ---------------------------------------------------------------------------

#: The result-token -> ``sev-*`` class the accessor derives (via
#: ``_CHECK_RESULT_SEVERITY`` -> ``css_class_for_severity``). Distinct per
#: outcome, so a row that carries the wrong class fails visibly (a swap cannot
#: balance).
_RESULT_CLASS = {"fail": "sev-error", "uncheckable": "sev-warning", "pass": "sev-ok"}

#: The fail entry's address in ``_ASYMMETRIC_ENTRIES`` (the ``0x102`` FF byte
#: inside the all-0x00 image). Its 16-byte-aligned hex-view row is labelled
#: ``0x00000100``.
_FAIL_ADDR = 0x102

#: The first uncheckable entry's address in ``_ASYMMETRIC_ENTRIES`` (outside the
#: image, ``actual_bytes=None``).
_UNCHECKABLE_ADDR = 0x9000


async def _run_checks_and_show(app: S19TuiApp, pilot) -> GroupedChecksPanel:
    """Load nothing new; paste the asymmetric doc, run checks via the REAL
    ``#patch_checks_run_button``, then activate the CHECKS screen (key ``9``).

    The caller has already loaded the image. Returns the mounted
    ``#checks_grouped`` panel. C-12: the run is produced through the shipped
    Patch Editor surface, never by setting ``last_check_result`` directly.
    """
    _open_patch_with_paste(app, _ASYMMETRIC_ENTRIES)
    await pilot.pause()
    _run_checks(app)
    await pilot.pause()
    await pilot.press("9")
    await pilot.pause()
    return app.query_one("#checks_grouped", GroupedChecksPanel)


async def _select_check_row(app: S19TuiApp, pilot, address: int) -> str:
    """Select the CHECKS row whose entry address == ``address`` through the real
    ``CheckRow`` (focus + Enter, the C-16 real-mechanism path) and return the
    ``#checks_hex_pane`` rendered text.
    """
    row = next(r for r in app.query(CheckRow) if r.address == address)
    row.focus()
    await pilot.pause()
    await pilot.press("enter")
    await pilot.pause()
    return str(app.query_one("#checks_hex_pane", Static).render())


# ---------------------------------------------------------------------------
# AT-084a (GATE, C-12) — a REAL run renders grouped fail->uncheckable->pass,
#                        each row coloured by its result.
# ---------------------------------------------------------------------------


def test_at084a_real_run_grouped_and_coloured(tmp_path: Path) -> None:
    """A run through the REAL run button renders the CHECKS screen grouped + coloured.

    Intent (HLR-084 / LLR-084.1/.3, C-12): drive the real
    ``#patch_checks_run_button`` over the asymmetric 2-pass/1-fail/3-uncheckable
    fixture, activate the Checks screen, and assert the grouped panel orders the
    headers fail -> uncheckable -> pass with each row carrying the ``sev-*``
    class its result maps to. Fixture integrity is asserted FIRST (C-31): if the
    run did not yield 2/1/3 the whole assertion is meaningless.
    """

    image = _make_s19_image(tmp_path)

    async def _drive() -> tuple[dict[str, int], list[str], list[tuple[str, str]]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            panel = await _run_checks_and_show(app, pilot)
            aggregates = app._change_service.check_aggregates()
            headers = [h.result_label for h in panel.query(CheckGroupHeader)]
            rows = [(r.row.result, r._sev_class) for r in panel.query(CheckRow)]
            return aggregates, headers, rows

    aggregates, headers, rows = asyncio.run(_drive())

    # Fixture integrity FIRST (C-31): the real run produced the asymmetric shape.
    assert aggregates == _EXPECTED_AGGREGATES, (
        f"fixture integrity: the run must yield {_EXPECTED_AGGREGATES}; "
        f"got {aggregates!r}"
    )
    # Group headers appear in the fixed fail -> uncheckable -> pass order.
    assert headers == ["FAILED", "UNCHECKABLE", "PASSED"], (
        f"the grouped panel must order headers fail->uncheckable->pass; "
        f"got {headers!r}"
    )
    # Rows are emitted group-major in the same order (1 fail, 3 uncheckable, 2 pass).
    assert [r[0] for r in rows] == (
        ["fail"] + ["uncheckable"] * 3 + ["pass"] * 2
    ), f"rows must be grouped fail->uncheckable->pass; got {[r[0] for r in rows]!r}"
    # Each row's class is the DISTINCT sev-* its result maps to — a colour that
    # drifts from the result fails here (fail!=uncheckable!=pass).
    for result, sev_class in rows:
        assert sev_class == _RESULT_CLASS[result], (
            f"a {result!r} row must carry {_RESULT_CLASS[result]!r}; "
            f"got {sev_class!r}"
        )


# ---------------------------------------------------------------------------
# AT-084b (GATE, C-31) — the aggregate strip counts == check_aggregates() live.
# ---------------------------------------------------------------------------


def test_at084b_aggregate_strip_matches_live_counts(tmp_path: Path) -> None:
    """After a REAL run the strip's counts equal ``check_aggregates()`` recomputed live.

    Intent (LLR-084.4, C-31): the ``#checks_aggregate_strip`` is not allowed to
    report numbers of its own — its rendered ``.plain`` must equal
    ``build_checks_aggregate_strip(check_aggregates())`` where the aggregates are
    re-read from the service after the run. Fixture integrity asserted first.
    """

    image = _make_s19_image(tmp_path)

    async def _drive() -> tuple[dict[str, int], str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            await _run_checks_and_show(app, pilot)
            aggregates = app._change_service.check_aggregates()
            strip_plain = (
                app.query_one("#checks_aggregate_strip", Static).render().plain
            )
            return aggregates, strip_plain, build_checks_aggregate_strip(
                aggregates
            ).plain

    aggregates, strip_plain, expected_plain = asyncio.run(_drive())

    assert aggregates == _EXPECTED_AGGREGATES, (
        f"fixture integrity: the run must yield {_EXPECTED_AGGREGATES}; "
        f"got {aggregates!r}"
    )
    assert strip_plain == expected_plain, (
        "the aggregate strip must render the live check_aggregates() counts; "
        f"got {strip_plain!r}, expected {expected_plain!r}"
    )


# ---------------------------------------------------------------------------
# AT-084c (GATE, C-12) — selecting the FAIL row shows its address in the pane.
# ---------------------------------------------------------------------------


def test_at084c_fail_row_select_shows_address_in_hex_pane(tmp_path: Path) -> None:
    """Selecting the fail row (0x102) renders its address window in ``#checks_hex_pane``.

    Intent (LLR-084.5, C-12): after a real run, focus the fail ``CheckRow``
    (entry at 0x102) and press Enter; the hex pane must repaint to the window
    around 0x102. The image is all-0x00, so the ADDRESS — not the byte value —
    is the discriminator.

    ⚠ SPEC DEVIATION (fail-loud, Rule 12): the requirement text (AT-084c /
    MIN-5) says to assert ``"102"`` or ``"0x00000102"`` appears. Neither can:
    ``render_hex_view_text`` labels each row by its 16-byte-aligned base, so the
    row holding 0x102 is labelled ``0x00000100`` and 0x102 is never emitted as
    text (verified empirically pre-write). The honest, equally-strong
    discriminator is the aligned base ``0x00000100``: it appears ONLY when the
    focus address resolves to 0x102's neighbourhood, so a wrong/None address or
    a no-op handler (the RED pre-change state — the pane keeps its initial empty
    ``""``) fails this. The placeholder is also asserted absent.
    """

    image = _make_s19_image(tmp_path)

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            await _run_checks_and_show(app, pilot)
            return await _select_check_row(app, pilot, _FAIL_ADDR)

    pane = asyncio.run(_drive())

    assert "0x00000100" in pane, (
        f"selecting the 0x{_FAIL_ADDR:X} fail row must render its 16-aligned "
        f"hex-view row (0x00000100); pane={pane!r}"
    )
    assert "has no address" not in pane, (
        f"an addressed fail row must NOT show the no-address placeholder; "
        f"pane={pane!r}"
    )


# ---------------------------------------------------------------------------
# AT-084f — undo clears the CHECKS list + strip; no stale rows.
# ---------------------------------------------------------------------------


def test_at084f_undo_clears_list_and_strip(tmp_path: Path) -> None:
    """A real ctrl+z clears the CHECKS screen off its populated post-run state.

    Intent (LLR-084.7, C-10): the CHECKS screen rides the SAME undo/redo reset of
    ``last_check_result``. The populated post-run state is captured and asserted
    NON-EMPTY FIRST (a "0 rows" assertion alone would pass on a screen that
    never rendered), then a real ctrl+z through the Patch Editor must clear the
    grouped list to zero rows (the no-run note) and the strip to 0/0/0 — the
    batch-38 Inc-4 F1 stale-panel shape must NOT recur.
    """

    image = _make_s19_image(tmp_path)
    zeroed = build_checks_aggregate_strip(
        {"passed": 0, "failed": 0, "uncheckable": 0}
    ).plain

    async def _drive() -> tuple[int, str, int, int, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            _open_patch_with_paste(app, _ASYMMETRIC_ENTRIES)
            await pilot.pause()
            # A history step for ctrl+z to pop (the test_undo_redo_ux idiom):
            # a freshly-pasted doc with no later edit has nothing to restore.
            _set_entry_inputs(app, address="0x9003", bytes_text="EE")
            app.query_one("#patch_entry_add_button", Button).press()
            await pilot.pause()
            _run_checks(app)
            await pilot.pause()

            # Populated CHECKS screen (post-run + nav refresh).
            await pilot.press("9")
            await pilot.pause()
            panel = app.query_one("#checks_grouped", GroupedChecksPanel)
            populated_rows = len(panel.query(CheckRow))
            populated_strip = (
                app.query_one("#checks_aggregate_strip", Static).render().plain
            )

            # Undo through the REAL ctrl+z binding in the Patch Editor.
            app.action_show_screen("patch")
            await pilot.pause()
            app.query_one("#patch_doc_entries_table").focus()
            await pilot.pause()
            await pilot.press("ctrl+z")
            await pilot.pause()

            # Re-observe the CHECKS screen.
            await pilot.press("9")
            await pilot.pause()
            cleared_rows = len(panel.query(CheckRow))
            no_run_notes = len(panel.query(".checks-no-run-note"))
            cleared_strip = (
                app.query_one("#checks_aggregate_strip", Static).render().plain
            )
            return (
                populated_rows,
                populated_strip,
                cleared_rows,
                no_run_notes,
                cleared_strip,
            )

    populated_rows, populated_strip, cleared_rows, no_run_notes, cleared_strip = (
        asyncio.run(_drive())
    )

    # Precondition: the run left a NON-EMPTY, non-zero populated screen.
    assert populated_rows > 0, (
        f"precondition: the run must populate the CHECKS list; got "
        f"{populated_rows} rows"
    )
    assert populated_strip != cleared_strip and populated_strip != zeroed, (
        f"precondition: the strip must be non-zero after the run; got "
        f"{populated_strip!r}"
    )
    # Undo clears both surfaces — no stale rows.
    assert cleared_rows == 0, (
        f"undo must clear every CheckRow (no stale rows); got {cleared_rows}"
    )
    assert no_run_notes == 1, (
        "after undo the panel resets to the no-run note (last_check_result None)"
    )
    assert cleared_strip == zeroed, (
        f"undo must clear the strip to 0/0/0; got {cleared_strip!r}"
    )


# ---------------------------------------------------------------------------
# AT-084g (GATE, C-17) — hostile linkage_symbol/reason render LITERAL through
#                        the shipped update_checks_view surface.
# ---------------------------------------------------------------------------


def test_at084g_hostile_input_renders_literal(tmp_path: Path) -> None:
    """A hostile ``linkage_symbol``/``reason`` renders literal in the CHECKS cells.

    Intent (LLR-084.8, C-17): through the shipped ``update_checks_view`` render
    path (press ``9`` with a run current), a check entry whose file-derived
    ``linkage_symbol`` and ``reason`` carry Rich-markup + ANSI payloads must
    render VERBATIM — ``.plain`` equals the payload and ``spans == []`` (no
    injected link/bold span, no OSC-8 escape) with no ``MarkupError``.

    The engine never composes hostile strings into ``linkage_symbol``/``reason``
    (they are author-domain codes/hex today), so this is the WIDGET-level guard:
    the run result is injected with the hostile entry, then the SHIPPED render
    path (nav key ``9`` -> ``update_checks_view`` -> ``GroupedChecksPanel`` ->
    ``CheckRow`` -> ``safe_text``) is driven. The through-surface producer AT is
    AT-084a; this proves the C-17 defence end-to-end on the render side.
    """

    hostile_linkage = "[bold]X[/][link=file:///etc]click[/nope]\x1b[31mRED\x1b[0m"
    hostile_reason = "reason[/bold][link=file:///pwn]\x1b[32m!"
    s19_path = _make_s19_image(tmp_path)

    result = CheckRunResult(
        source_path=None,
        timestamp_utc="2026-07-18T00:00:00Z",
        variant_id=None,
        aggregates={"passed": 0, "failed": 0, "uncheckable": 1},
        entries=[
            CheckRunEntry(
                entry_type="bytes",
                address_start=0x9000,
                address_end=0x9001,
                expected_bytes=(0xEE,),
                actual_bytes=None,
                result="uncheckable",
                linkage="",
                linkage_symbol=hostile_linkage,
                reason=hostile_reason,
            )
        ],
    )

    async def _drive() -> tuple[str, list, str, list]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, s19_path)
            app._change_service.last_check_result = result
            await pilot.press("9")
            await pilot.pause()
            panel = app.query_one("#checks_grouped", GroupedChecksPanel)
            linkage = next(
                w for w in panel.query(Static) if w.has_class("check-linkage")
            )
            detail = next(
                w for w in panel.query(Static) if w.has_class("check-detail")
            )
            linkage_content = linkage.render()
            detail_content = detail.render()
            return (
                linkage_content.plain,
                list(linkage_content.spans),
                detail_content.plain,
                list(detail_content.spans),
            )

    linkage_plain, linkage_spans, detail_plain, detail_spans = asyncio.run(_drive())

    # The dedicated linkage cell renders the payload verbatim, unstyled.
    assert linkage_plain == hostile_linkage, (
        f"the linkage cell must render the payload verbatim; got {linkage_plain!r}"
    )
    assert linkage_spans == [], (
        f"the linkage cell must carry NO injected spans; got {linkage_spans!r}"
    )
    # The reason folds into the detail cell text — also literal, unstyled.
    assert hostile_reason in detail_plain, (
        f"the hostile reason must appear verbatim in the detail cell; "
        f"got {detail_plain!r}"
    )
    assert detail_spans == [], (
        f"the detail cell must carry NO injected spans; got {detail_spans!r}"
    )


# ---------------------------------------------------------------------------
# TC-084.11 (boundary) — selecting an UNCHECKABLE row (0x9000, outside image,
#                        actual_bytes=None) shows the address window, no crash.
# ---------------------------------------------------------------------------


def test_tc084_11_uncheckable_row_hex_window(tmp_path: Path) -> None:
    """Selecting an uncheckable row (0x9000, outside the image) shows its window, no crash.

    Intent (LLR-084.5 boundary, MIN-6): an uncheckable entry has an address but
    no image bytes (``actual_bytes=None``); selecting it must render the hex
    window around 0x9000 (its 16-aligned row 0x00009000, with empty byte cells)
    without raising — never the no-address placeholder, since the entry DOES
    carry an address.
    """

    image = _make_s19_image(tmp_path)

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            await _run_checks_and_show(app, pilot)
            return await _select_check_row(app, pilot, _UNCHECKABLE_ADDR)

    pane = asyncio.run(_drive())

    assert "0x00009000" in pane, (
        f"selecting the 0x{_UNCHECKABLE_ADDR:X} uncheckable row must render its "
        f"address window (0x00009000); pane={pane!r}"
    )
    assert "has no address" not in pane, (
        f"an addressed (but uncheckable) row must NOT show the no-address "
        f"placeholder; pane={pane!r}"
    )
