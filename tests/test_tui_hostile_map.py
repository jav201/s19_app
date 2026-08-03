"""batch-77 Inc-2 — the Memory Map inspector is hostile-input safe (LLR-116.7).

Summary:
    ``#map_detail_body`` is the map's only sink for untrusted, file-derived
    text: A2L symbol names (``build_detail_text`` → ``symbol_list_text``) and
    ``ValidationIssue.code``/``.message``/``.symbol``. Every one of them goes
    through ``safe_text``.

    Before batch-77 ``safe_text`` was ``Text(value, style=style)`` and its own
    docstring claimed it neutralised *"raw ANSI bytes … no style/ANSI leak"*.
    **Executed, half that claim was false:** ``Text()`` does not parse markup,
    so ``sensor[red]`` is inert — but it does not remove anything either, so
    ``safe_text('sensor\\x1b[31m_evil[red]')`` returned the string unchanged,
    ESC included, billing 21 characters for 16 visible ones. ``LLR-116.7``
    lands the missing half: a C0/C1 scrub, selected as a **byte class**.

    Two gates, six verdicts, reported per limb per size — an aggregate verdict
    is what hid the original defect:

    - **AT-B77-15a** limb 1 (every NON-CONTROL character of the payload
      verbatim in ``render().plain``) ∧ limb 2 (``render().spans == []``).
      *Non-control*, not *payload verbatim*: post-scrub the ESC payload is
      deliberately not verbatim, and that is the fix working.
    - **AT-B77-15b** limb 3 (no C0/C1 byte in the **painted strip**). The
      strip, not ``.plain`` — ``.plain`` is where the byte lives, the strip is
      where it escapes the terminal.

**Why this file drives the sink instead of reading it.**
    At Inc-2 there was no auto-select, so with zero interaction the body still
    showed ``_DETAIL_HINT`` — no file-derived text at either regime. A test
    that rendered and read would have been **green on any implementation,
    including one with no scrub at all**; that vacuity is exactly what an
    earlier revision of this acceptance shipped. Each arm therefore drives the
    inspector explicitly and then **asserts its own precondition** — that the
    payload actually reached the body — before any safety limb is evaluated.
    The fix for a gesture that misses is *detection*, not a better gesture: a
    better click only moves the failure.

**Two drive paths since Inc-7 (HLR-116), both gated.**
    ``click`` is the original: a real ``pilot.click`` on a region row.
    ``autoselect`` is the path Inc-7 created — the panel populates the
    inspector for run 1 as a consequence of LOADING, with zero clicks and zero
    keys. That is the reason ``LLR-116.6`` exists at all, so the safety limbs
    are re-run over it: it reaches the same sink through a path no operator
    gesture guards. Both drives keep the precondition assertion, and each names
    ITS OWN mechanism in the failure message — an ``autoselect`` arm that
    reported "the click missed" would send a reader to the wrong place.

**Why the payload carries C1 bytes.**
    ``U+009B`` is single-byte CSI and ``U+009D`` single-byte OSC — functional
    equivalents of ``ESC [`` and ``ESC ]`` that carry **no ``\\x1b`` at all**.
    An implementation written as "strip ``\\x1b``-introduced sequences" passes
    a payload built only from ``ESC`` and silently reopens the hole with every
    test still green. The payload below contains both C1 forms, so the
    byte-class requirement has a subject here and a regex over escape
    sequences cannot pass this file.

Data Flow:
    - Builds the two-band fixture, seeds a hostile A2L symbol name overlapping
      the constant region, renders the map, clicks the region row, then reads
      ``#map_detail_body``'s ``render()`` and its painted ``render_line`` rows.

Dependencies:
    Uses:
        - ``s19_app.tui.screens_directionb.safe_text`` / ``RegionRow``
        - ``tests.test_tui_directionb._two_band_loaded``
    Used by:
        - the batch-77 Inc-2 acceptance gate (AT-B77-15a, AT-B77-15b)
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Tuple

import pytest

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import MemoryMapPanel, RegionRow, safe_text
from tests.test_tui_directionb import _two_band_loaded

_SIZES = [(80, 24), (120, 30)]

#: The class LLR-116.7 names: C0, DEL, C1. Re-derived here rather than imported
#: from the module under test — importing ``_CONTROL_SCRUB`` would make the
#: oracle agree with the implementation by construction, so a wrong class would
#: produce a wrong expectation and a wrong result that agree.
_CONTROL = frozenset(range(0x00, 0x20)) | frozenset(range(0x7F, 0xA0))

#: A control-free, markup-free marker. It survives BOTH the correct scrub and
#: every mutation of it, which is what makes it usable as a precondition: it
#: answers "did the click land and did the symbol reach the sink?" without
#: answering "is the scrub correct?". A sentinel containing ``[red]`` would be
#: eaten by the ``Text.from_markup`` mutation and report a missed gesture that
#: did not happen.
_SENTINEL = "b77hostilemark"

#: ESC-introduced CSI + Rich markup + single-byte C1 CSI + single-byte C1 OSC
#: with a BEL terminator + NUL + DEL.
_HOSTILE_SYMBOL = (
    _SENTINEL + "\x1b[31m" + "_evil[red]" + "\x9b1m" + "\x9d8;;u\x07" + "\x00\x7f"
)

_REGION_START = 0x80000000


def _noncontrol(value: str) -> str:
    """Project ``value`` onto its non-control characters, preserving order."""
    return "".join(ch for ch in value if ord(ch) not in _CONTROL)


#: The two paths that reach ``#map_detail_body`` with file-derived text.
_DRIVES = ["click", "autoselect"]


def _drive_hostile_inspector(
    tmp_path: Path, size: Tuple[int, int], drive: str = "click"
) -> Tuple[str, list, List[str], str]:
    """Render the map, populate the inspector via ``drive``, read it back.

    Args:
        tmp_path (Path): pytest temp dir for the app base.
        size (Tuple[int, int]): Terminal geometry.
        drive (str): ``"click"`` — a real ``pilot.click`` on the hostile
            region row (the pre-Inc-7 path, still shipped). ``"autoselect"`` —
            no gesture at all: Inc-7's post-refresh hook selects run 1, which
            IS the hostile region, so the payload reaches the sink purely as a
            consequence of loading the file.

    Returns:
        Tuple[str, list, List[str], str]: ``render().plain``, ``render().spans``,
        the painted ``render_line`` rows, and a mechanism note used by the
        precondition's failure message (the widget the click resolved to, or
        the resolved auto-selection).
    """
    loaded = _two_band_loaded(tmp_path)

    async def _run() -> Tuple[str, list, List[str], str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app._a2l_enriched_tags = [
                {"name": _HOSTILE_SYMBOL, "address": _REGION_START + 0x10,
                 "byte_size": 4},
            ]
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            panel = app.query_one("#memory_map_panel", MemoryMapPanel)
            if drive == "autoselect":
                # ZERO gestures. Wait only for the deferred resolution.
                for _ in range(10):
                    await pilot.pause()
                    if panel._selected_cell_start is not None:
                        break
                await pilot.pause()
                hit = (
                    "auto-selection resolved to "
                    f"{panel._selected_cell_start!r}"
                )
            else:
                row = next(
                    r for r in app.query(RegionRow)
                    if r.region_start == _REGION_START
                )
                # Scroll the OWNING viewport, not the row's own
                # ``scroll_visible``: Inc-1 (LLR-111.9) grew the band row 4 ->
                # 6 rows at 120x30, so the region list sits at the viewport
                # edge where ``scroll_visible`` treats the row as already
                # visible, does not scroll, and the click then lands on the
                # container. Same pattern as
                # ``tests/test_map_click_chain.py::_drive_clicks``.
                app.query_one("#map_content").scroll_to_widget(
                    row, animate=False, top=True
                )
                await pilot.pause()
                widget = app.screen.get_widget_at(*row.region.center)[0]
                hit = f"click coordinate resolved to a {type(widget).__name__}"
                await pilot.click(row)
                await pilot.pause()
                await pilot.pause()
            body = app.query_one("#map_detail_body")
            rendered = body.render()
            strip = [
                body.render_line(y).text for y in range(body.region.height)
            ]
            return rendered.plain, list(rendered.spans), strip, hit

    return asyncio.run(_run())


def _assert_payload_reached_the_body(
    size: Tuple[int, int], plain: str, strip: List[str], hit: str,
    drive: str = "click",
) -> None:
    """Fail loudly, naming the missed mechanism, unless the payload is present.

    A safety limb evaluated over a body that still shows ``_DETAIL_HINT`` is a
    tautology: there is no file-derived text for the scrub to have failed on,
    so the limb reads green on an implementation with no scrub at all. This
    runs FIRST at every size arm and never lets the limbs proceed on a run
    where the drive missed.

    The message names the mechanism of THIS drive. An ``autoselect`` arm that
    blamed a click would point a reader at code that never ran.
    """
    mechanism = {
        "click": (
            f"the real pilot.click on the RegionRow at 0x{_REGION_START:08X} "
            f"(after #map_content.scroll_to_widget)"
        ),
        "autoselect": (
            f"Inc-7's post-refresh auto-selection of run 1 "
            f"(0x{_REGION_START:08X}), which takes NO gesture at all"
        ),
    }[drive]
    joined = "".join(strip)
    assert strip, (
        f"{size}/{drive}: DRIVE MISSED — #map_detail_body painted ZERO rows, "
        f"so the control-byte limb would have no subject. Expected "
        f"{mechanism} to populate the inspector; {hit}."
    )
    assert _SENTINEL in plain, (
        f"{size}/{drive}: DRIVE MISSED — the hostile A2L symbol never reached "
        f"#map_detail_body. {mechanism} did not populate the inspector "
        f"({hit}); the body still reads {plain!r}. The safety limbs are NOT "
        f"evaluated on this run — a body showing _DETAIL_HINT makes them "
        f"vacuously green."
    )
    assert _SENTINEL in joined, (
        f"{size}/{drive}: DRIVE MISSED at the PAINTED layer — the symbol is in "
        f".plain but not in the painted strip, so it is laid out but clipped "
        f"or scrolled out of #map_detail_body's {len(strip)}-row region. The "
        f"control-byte limb reads the strip and would be vacuous. "
        f"Painted rows: {strip!r}"
    )


# ---------------------------------------------------------------------------
# AT-B77-15a — markup literal ∧ no span (HLR-116 / LLR-116.6, LLR-116.7)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("drive", _DRIVES)
@pytest.mark.parametrize("size", _SIZES)
def test_b77_hostile_symbol_is_literal_and_carries_no_span(
    tmp_path: Path, size: Tuple[int, int], drive: str
) -> None:
    """AT-B77-15a — limb 1 ∧ limb 2, per limb, per size, per drive.

    Limb 1 is *every NON-CONTROL character of the payload verbatim*, not
    *payload verbatim*. Post-scrub the ESC bytes are gone by design, so the
    stricter wording would go RED on a correct implementation — an earlier
    revision of this acceptance said exactly that and would have done so.

    Mutation (executed, Inc-2): ``safe_text`` → ``Text.from_markup``. Limb 1
    False (``[red]`` is consumed as a tag and the projection is no longer
    contiguous in ``.plain``) and limb 2 False (the tag becomes a style span).
    """
    plain, spans, strip, hit = _drive_hostile_inspector(tmp_path, size, drive)
    _assert_payload_reached_the_body(size, plain, strip, hit, drive)

    expected = _noncontrol(_HOSTILE_SYMBOL)
    limb1 = expected in plain
    limb2 = spans == []
    verdicts = {"limb1_noncontrol_verbatim": limb1, "limb2_no_spans": limb2}

    assert limb1, (
        f"{size}/{drive}: LIMB 1 — every non-control character of the hostile "
        f"symbol must survive verbatim and contiguous. Expected {expected!r} "
        f"as a substring of the rendered plain text; got {plain!r}. "
        f"per-limb={verdicts}"
    )
    assert limb2, (
        f"{size}/{drive}: LIMB 2 — a file-derived string must carry NO style "
        f"span and no hyperlink; a span here means the payload was "
        f"markup-parsed instead of rendered literally. spans={spans!r}. "
        f"per-limb={verdicts}"
    )


# ---------------------------------------------------------------------------
# AT-B77-15b — no C0/C1 byte reaches the painted strip (LLR-116.7)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("drive", _DRIVES)
@pytest.mark.parametrize("size", _SIZES)
def test_b77_hostile_symbol_emits_no_control_byte_into_the_strip(
    tmp_path: Path, size: Tuple[int, int], drive: str
) -> None:
    """AT-B77-15b — limb 3, per size, per drive.

    Reads the **painted strip** (``render_line``), not ``.plain``. ``.plain``
    is where the byte lives; the strip is what is handed to the terminal, and
    it is the only layer where an escape sequence can act.

    Mutation (executed, Inc-2): revert the filter — substituted value
    ``scrubbed`` → ``raw``. Limb 3 True → False at both sizes.
    """
    plain, _spans, strip, hit = _drive_hostile_inspector(tmp_path, size, drive)
    _assert_payload_reached_the_body(size, plain, strip, hit, drive)

    offenders = {
        (y, hex(ord(ch)))
        for y, row in enumerate(strip)
        for ch in row
        if ord(ch) in _CONTROL
    }
    assert not offenders, (
        f"{size}/{drive}: LIMB 3 — no C0/C1 control byte may reach the painted "
        f"strip. Found {sorted(offenders)} as (row, codepoint). A control byte "
        f"here is executed by the terminal, not displayed. Painted rows: "
        f"{strip!r}"
    )


# ---------------------------------------------------------------------------
# LLR-116.7 — the scrub is a BYTE CLASS, not an escape-sequence pattern
# ---------------------------------------------------------------------------
def test_b77_safe_text_scrubs_the_control_byte_class_without_damaging_identity(
) -> None:
    """LLR-116.7's executed thresholds, at the function boundary.

    The e2e arms above prove the sink is safe for one payload. This node pins
    the *form* of the fix, which is normative: the C1 rows are the ones a
    ``\\x1b``-anchored regex passes, and the identity rows are what stops the
    scrub becoming a shape-inference redactor (the batch-62 failure). Both
    halves are asserted in one node because either alone is satisfiable by a
    wrong implementation — deleting everything passes the C1 rows, and
    deleting nothing passes the identity rows.
    """
    removed = [
        # (input, expected) — every threshold LLR-116.7 states.
        ("sensor\x1b[31m_evil[red]", "sensor[31m_evil[red]"),
        ("a\x07b\x00c", "abc"),
        ("a\x9b31mb", "a31mb"),            # C1 single-byte CSI, no ESC present
        ("a\x9d8;;ub", "a8;;ub"),          # C1 single-byte OSC, no ESC present
        ("a\x7fb", "ab"),                  # DEL
        ("a\nb\tc\rd", "abcd"),            # C0 whitespace is C0
    ]
    for source, expected in removed:
        got = safe_text(source).plain
        assert got == expected, (
            f"safe_text({source!r}) must scrub the control byte CLASS -> "
            f"{expected!r}; got {got!r}"
        )
        assert not any(ord(ch) in _CONTROL for ch in got), (
            f"safe_text({source!r}) left a residual control byte in {got!r}"
        )

    preserved = [
        "x[link=file:///C:/W]click[/link]",
        "plain_ok",
        "sensor_rpm",
        "ECU.Table[3]",
        "http://vendor.example/a?b=1&c=2",
        "C:\\proj\\cal.a2l",
        "K\xfchlmittel_Temp",
        "\u65e5\u672c\u8a9e",
        "name\xa0with\xa0nbsp",  # U+00A0 is one codepoint ABOVE the class
        "emoji_\U0001f600_name",
    ]
    for source in preserved:
        got = safe_text(source).plain
        assert got == source, (
            f"safe_text must preserve every non-control character verbatim; "
            f"{source!r} came back as {got!r} — the scrub has become a "
            f"shape-inference redactor rather than a byte-class filter"
        )
