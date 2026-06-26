"""A↔B compare real-path regression — s19_app batch-15, US-016 (HLR-016).

These are BLACK-BOX acceptance tests for the false "no diff" escape: a
degenerate on-disk image (a non-empty file whose every line is a malformed
S-record, so it parses to an *empty* memory map WITHOUT the constructor
raising) was silently compared as a valid empty image. The well-formed side's
bytes then classified as ``only_a`` / ``only_b`` runs and the panel reported a
green ``sev-ok`` status — the comparison neither refused nor flagged that one
side carried no image at all.

Every test drives the REAL ``#diff_compare_button`` through the shipped panel
via Textual ``Pilot`` — there is intentionally NO ``compare_images``
monkeypatch here, so the production resolve → parse → classify → render path is
the thing under test. Fixtures are written inline to ``tmp_path`` (degenerate
text by hand, well-formed S19 via ``emit_s19_from_mem_map``); no ``examples/``
asset and no ``conftest.py`` change.

Test -> AT -> behavior:
    test_at_016_1_two_wellformed_images_show_changed_runs   AT-016.1  regression lock (GREEN pre-fix)
    test_at_016_2_degenerate_image_is_flagged_not_silent    AT-016.2  the escaped bug (RED pre-fix)
    test_at_016_3_unresolvable_path_refuses_without_crash    AT-016.3  over-correction guard, raise path (GREEN)
    test_at_016_4_legit_small_valid_image_is_not_flagged     AT-016.4  over-correction guard, valid empty-ish (GREEN)

AT-016.2 expresses the POST-FIX expectation (``sev-error``); on the pre-fix
tree it FAILS because the panel reports ``sev-ok`` for the empty-vs-full
compare. That failure is the captured RED gate evidence for increment 1; the
fix lands in increment 2.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Input, Static

from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map


def _write_s19(path: Path, mem_map: dict[int, int], ranges: list[tuple[int, int]]) -> None:
    """Write a well-formed S19 file re-readable by ``S19File`` (round-trip emitter)."""
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="utf-8")


def _drive_compare(tmp_path: Path, path_a: Path, path_b: Path) -> tuple[bool, bool, bool, str, str]:
    """Drive the real Compare button for an external A/B path pair.

    Summary:
        Activate the diff screen with no project loaded (so both variant Selects
        sit on the external sentinel and the typed paths are used), type the two
        external paths, press the REAL ``#diff_compare_button``, then read back
        black-box state: the ``#diff_status`` severity classes, the
        ``#diff_range_list`` text, and the app-level pre-condition flag.

    Args:
        tmp_path (Path): The app ``base_dir`` (external-path resolution root).
        path_a (Path): Absolute path typed into ``#diff_path_a``.
        path_b (Path): Absolute path typed into ``#diff_path_b``.

    Returns:
        tuple[bool, bool, bool, str, str]: ``(reached_display_path, is_error,
        is_ok, status_text, range_text)`` where ``reached_display_path`` is
        ``app._diff_last_result is not None and not refused`` (proves the
        silent non-refused display branch was taken, not the early refusal
        return), ``is_error`` / ``is_ok`` are the ``sev-error`` / ``sev-ok``
        class flags on ``#diff_status``, and the two strings are the rendered
        status line and run list.

    Dependencies:
        Uses:
            - S19TuiApp.run_test / action_show_screen
        Used by:
            - the four AT-016 tests
    """

    async def _run() -> tuple[bool, bool, bool, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            app.query_one("#diff_path_a", Input).value = str(path_a)
            app.query_one("#diff_path_b", Input).value = str(path_b)
            app.query_one("#diff_compare_button").press()
            await pilot.pause()
            status = app.query_one("#diff_status", Static)
            reached_display_path = (
                app._diff_last_result is not None
                and app._diff_last_result.refused is False
            )
            return (
                reached_display_path,
                status.has_class("sev-error"),
                status.has_class("sev-ok"),
                str(status.render()),
                str(app.query_one("#diff_range_list").render()),
            )

    return asyncio.run(_run())


def test_at_016_1_two_wellformed_images_show_changed_runs(tmp_path: Path) -> None:
    """AT-016.1 — two genuinely-different well-formed images show changed runs.

    Intent: this is the regression LOCK that guards the happy path the fix must
    not break. Two valid on-disk S19 images that share an address range but
    differ at four bytes must compare to >= 1 ``changed`` run with a green
    ``sev-ok`` status. This already passes pre-fix; it must still pass post-fix.
    """
    a = tmp_path / "image_a.s19"
    b = tmp_path / "image_b.s19"
    ranges = [(0x100, 0x108)]
    _write_s19(a, {0x100 + i: i & 0xFF for i in range(8)}, ranges)
    # Same range, four bytes flipped -> a contiguous "changed" run.
    flipped = {0x100 + i: i & 0xFF for i in range(8)}
    for i in range(4):
        flipped[0x100 + i] = (0xF0 + i) & 0xFF
    _write_s19(b, flipped, ranges)

    _, is_error, is_ok, status_text, range_text = _drive_compare(tmp_path, a, b)

    assert is_ok is True, f"a valid differing pair must be sev-ok; status={status_text!r}"
    assert is_error is False
    assert "changed" in range_text, (
        f"the differing bytes must produce a changed run; runs={range_text!r}"
    )


def test_at_016_2_degenerate_image_is_flagged_not_silent(tmp_path: Path) -> None:
    """AT-016.2 — a degenerate (empty-map) image vs a full one is flagged, not silent.

    Intent: this is THE escaped-bug proof. One side is a non-empty file whose
    every line is a malformed S-record, so ``S19File`` parses it to an empty
    memory map without raising; the other side is a valid image. The compare
    reaches the non-refused display path (pre-condition: ``_diff_last_result``
    is set and ``refused is False``), proving the bug is exercised through the
    SILENT display branch and not the early refusal return.

    The POST-FIX expectation is that the panel flags the empty side with a
    ``sev-error`` status naming the failed side. On the PRE-FIX tree the panel
    reports ``sev-ok`` instead, so the ``sev-error`` assertion below FAILS —
    that failure is the captured RED gate evidence for increment 1.
    """
    degenerate = tmp_path / "degenerate.s19"
    degenerate.write_text("S1ZZGARBAGE\nNOTANSREC\nS1!!!!\n", encoding="utf-8")
    # Fixture-durability guard (C-8): this test's RED depends on the degenerate
    # file parsing to an EMPTY map WITHOUT raising (every record rejected by the
    # collect-don't-abort reader). Assert that precondition inline so a future
    # S19File parser change that made this content parse non-empty (or raise)
    # fails LOUDLY here instead of silently neutering the escaped-bug regression.
    assert S19File(str(degenerate)).get_memory_map() == {}, (
        "AT-016.2 fixture must parse to an empty map for the degenerate-load path "
        "to be exercised; the parser made it non-empty/raised — the regression is "
        "no longer testing the silent-load-failure bug"
    )
    full = tmp_path / "full.s19"
    _write_s19(full, {0x200 + i: (0x10 + i) & 0xFF for i in range(8)}, [(0x200, 0x208)])

    reached_display_path, is_error, _is_ok, status_text, _range_text = _drive_compare(
        tmp_path, degenerate, full
    )

    # Pre-condition (passes pre- and post-fix): the bug was reached through the
    # non-refused display path, not the existing refusal branch.
    assert reached_display_path is True, (
        "the degenerate-vs-full compare must reach the non-refused display path "
        "(_diff_last_result set, refused is False) for this to prove the silent bug"
    )
    # Post-fix expectation (FAILS pre-fix -> the captured RED): the empty side
    # is flagged with an error status that names the offending side.
    assert is_error is True, (
        "an empty-map image vs a full image must surface a sev-error status, not "
        f"a silent sev-ok; status was {status_text!r}"
    )
    assert "degenerate.s19" in status_text, (
        f"the diagnostic must name the failed side; status was {status_text!r}"
    )


def test_at_016_3_unresolvable_path_refuses_without_crash(tmp_path: Path) -> None:
    """AT-016.3 — an unresolvable path refuses cleanly (over-correction guard, raise path).

    Intent: guards that the existing refusal branch keeps working. One side is a
    path that does not exist, so the service refuses; the panel must show a
    ``sev-error`` status and ``run_test`` must complete with no unhandled
    exception. This passes pre-fix and must still pass post-fix.
    """
    missing = tmp_path / "does_not_exist.s19"
    full = tmp_path / "present.s19"
    _write_s19(full, {0x300 + i: i & 0xFF for i in range(4)}, [(0x300, 0x304)])

    _, is_error, _is_ok, status_text, _range_text = _drive_compare(tmp_path, missing, full)

    assert is_error is True, (
        f"an unresolvable path must refuse with sev-error; status was {status_text!r}"
    )


def test_at_016_4_legit_small_valid_image_is_not_flagged(tmp_path: Path) -> None:
    """AT-016.4 — a small but valid image compares normally (over-correction guard).

    Intent: guards that the increment-2 fix will not false-flag a legitimately
    small valid image. One side maps only a couple of bytes from well-formed
    records (NOT all-malformed), the other is a fuller valid image. The compare
    must proceed normally — a green ``sev-ok`` status, never ``sev-error``. The
    distinction the fix must honour is empty-map (degenerate) vs few-bytes
    (valid), so this passes pre-fix and must still pass post-fix.
    """
    tiny = tmp_path / "tiny.s19"
    _write_s19(tiny, {0x400: 0xAB, 0x401: 0xCD}, [(0x400, 0x402)])
    full = tmp_path / "fuller.s19"
    _write_s19(full, {0x400 + i: (0x20 + i) & 0xFF for i in range(8)}, [(0x400, 0x408)])

    _, is_error, is_ok, status_text, _range_text = _drive_compare(tmp_path, tiny, full)

    assert is_error is False, (
        f"a small but valid image must not be flagged as an error; status was {status_text!r}"
    )
    assert is_ok is True, (
        f"a valid small-vs-full compare must proceed to sev-ok; status was {status_text!r}"
    )


def _drive_compare_hex(tmp_path: Path, path_a: Path, path_b: Path) -> tuple[str, str, str]:
    """Drive the real Compare button and read back the two hex-window panes.

    Summary:
        Same shipped path as :func:`_drive_compare` (activate the diff screen with
        no project loaded, type the two external paths, press the REAL
        ``#diff_compare_button``), but read back the rendered text of the two hex
        windows ``#diff_hex_a`` / ``#diff_hex_b`` — auto-populated with the FIRST
        run's window by ``AbDiffPanel.render_comparison`` — plus the run list. This
        observes the hex-pane CONTENT the four AT-016 status/run-list tests never
        read: a blanked or stale hex pane passes those but fails a byte-content
        assertion here (C-9).

    Args:
        tmp_path (Path): The app ``base_dir`` (external-path resolution root).
        path_a (Path): Absolute path typed into ``#diff_path_a``.
        path_b (Path): Absolute path typed into ``#diff_path_b``.

    Returns:
        tuple[str, str, str]: ``(hex_a_text, hex_b_text, range_text)`` — the
        rendered text of ``#diff_hex_a``, ``#diff_hex_b`` and ``#diff_range_list``.

    Dependencies:
        Uses:
            - S19TuiApp.run_test / action_show_screen
        Used by:
            - the compare hex-window ATs (#6 / C-9)
    """

    async def _run() -> tuple[str, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            app.query_one("#diff_path_a", Input).value = str(path_a)
            app.query_one("#diff_path_b", Input).value = str(path_b)
            app.query_one("#diff_compare_button").press()
            await pilot.pause()
            return (
                str(app.query_one("#diff_hex_a", Static).render()),
                str(app.query_one("#diff_hex_b", Static).render()),
                str(app.query_one("#diff_range_list", Static).render()),
            )

    return asyncio.run(_run())


def test_compare_hex_windows_render_the_differing_bytes(tmp_path: Path) -> None:
    """AT-COMPARE-HEX (#6 / C-9) — the compare hex panes show the run's real bytes.

    Intent: the four AT-016 tests assert the status severity and the run LIST but
    never read the hex windows, so a blanked / content-swapped ``#diff_hex_a`` /
    ``#diff_hex_b`` pane would pass them all. This drives the real Compare on two
    on-disk S19 images that differ at four known bytes and asserts those EXACT bytes
    are rendered in the correct pane — image A shows ``00 01 02 03`` where image B
    shows ``F0 F1 F2 F3`` — so a blank or swapped pane fails. (C-10: a non-default
    differing pair, asserting byte CONTENT, not merely non-emptiness.)
    """
    a = tmp_path / "hex_a.s19"
    b = tmp_path / "hex_b.s19"
    ranges = [(0x500, 0x508)]
    _write_s19(a, {0x500 + i: i & 0xFF for i in range(8)}, ranges)
    # Same range, first four bytes flipped to 0xF0..0xF3 -> a contiguous changed run.
    flipped = {0x500 + i: i & 0xFF for i in range(8)}
    for i in range(4):
        flipped[0x500 + i] = (0xF0 + i) & 0xFF
    _write_s19(b, flipped, ranges)

    hex_a, hex_b, range_text = _drive_compare_hex(tmp_path, a, b)

    # The differing bytes render in their own pane...
    assert "00 01 02 03" in hex_a, f"image A pane must show A's original bytes; pane={hex_a!r}"
    assert "F0 F1 F2 F3" in hex_b, f"image B pane must show B's flipped bytes; pane={hex_b!r}"
    # ...and B's bytes are NOT in A's pane (content-discriminating: a swapped/blank pane fails).
    assert "F0 F1 F2 F3" not in hex_a, f"image A pane must not carry B's bytes; pane={hex_a!r}"
    # The shared context bytes render as real bytes on BOTH sides (fails on a blank pane).
    assert "04 05 06 07" in hex_a and "04 05 06 07" in hex_b, (
        f"the shared tail bytes must render on both panes; a={hex_a!r} b={hex_b!r}"
    )
    # Sanity: a changed run is in fact driving the windows.
    assert "changed" in range_text, (
        f"the differing bytes must classify as a changed run; runs={range_text!r}"
    )


def test_compare_hex_windows_report_no_runs_for_identical_images(tmp_path: Path) -> None:
    """AT-COMPARE-HEX-EQUAL (#6 boundary) — identical images hit the no-run branch.

    Intent: the boundary / negative control for the hex panes and the SECOND branch
    of ``render_comparison`` (C-10 (b): one AT per branch). Two byte-identical on-disk
    images produce zero differing runs, so the panel takes the no-run branch and the
    hex windows must SAY so ("no differing runs") rather than going blank or showing
    a stale window — distinguishing a real no-run message from a blanked pane.
    """
    same_map = {0x500 + i: i & 0xFF for i in range(8)}
    ranges = [(0x500, 0x508)]
    a = tmp_path / "same_a.s19"
    b = tmp_path / "same_b.s19"
    _write_s19(a, same_map, ranges)
    _write_s19(b, dict(same_map), ranges)

    hex_a, hex_b, range_text = _drive_compare_hex(tmp_path, a, b)

    assert "no differing runs" in hex_a, f"identical images -> A pane must state no runs; pane={hex_a!r}"
    assert "no differing runs" in hex_b, f"identical images -> B pane must state no runs; pane={hex_b!r}"
    assert "Runs: 0" in range_text, f"identical images must classify as zero runs; runs={range_text!r}"
