"""N8 unit + Pilot tests — comprehensive per-view Legend.

Batch 2026-07-23-batch-n8. Two layers:
- **Inc-1 (data)** — white-box ``TC-N8-*`` pinning the ``LEGEND_EXAMPLES`` card
  content, the ``ENTROPY_BANDS``-derived band-key helper and the single-source
  cutoff formatter in ``s19_app.tui.legend``, plus the ``TC-N8-11`` markup
  round-trip tripwire (AMD-9 / F3).
- **Inc-2 (render)** — Pilot black-box ``AT-N8-01..05`` driving the real
  ``action_show_legend`` path so ``view_key`` + ``sections`` flow from the
  active screen; each asserts the per-view example card renders above the
  view's colour/band key. ``AT-N8-06/07`` (Static-wrap, painted orange) land in
  Inc-3.

Batch-91 contract adoption (HLR-122):
# TC-643 — this module pins the N8 legend and logwidth scope (LLR-122.5).

Batch-93 inc-003 (HLR-132): the MAP example card retired — the map view's
``k``-legend is the spec sheet now (``tests/test_legend_map_sheet.py``), so
``LEGEND_EXAMPLES`` carries the four card views. The registry-bound node
NAMES stay (TC-643's row binds them; the batch-77 precedent: a rename is a
registry change) — ``test_at_n8_03_map_band_key_and_overlays``,
``test_tc_n8_05_map_example_data``,
``test_map_card_band_bar_sample_uses_band_and_gap_glyphs`` and
``test_map_card_contains_both_hex_overlay_meanings`` keep their names with
bodies re-aimed at the sheet (the overlay arm now pins legend A's NO-overlay
block, the meanings staying sourced in the Hex table data).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from s19_app.tui import legend as L
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import LegendScreen
from s19_app.tui.services.entropy_service import ENTROPY_BANDS

# Textual's Static/Label default to markup=True, so the modal renders each line
# through Content.from_markup — the same path TC-N8-11 must guard.
from textual.content import Content
from textual.widgets import DataTable, Static

#: The card-carrying views (batch-93 HLR-132: the map card retired to the spec
#: sheet — ``tests/test_legend_map_sheet.py`` owns the map path).
VIEW_KEYS = ("workspace", "a2l", "mac", "issues")


def _text(view_key: str) -> str:
    """Concatenate every card line's text for a view (space-joined)."""
    return " ".join(line.text for line in L.LEGEND_EXAMPLES[view_key])


# --------------------------------------------------------------------------- #
# LEGEND_EXAMPLES shape (LLR-N8-1.1 .. 5.1)
# --------------------------------------------------------------------------- #
def test_legend_examples_has_all_five_view_keys():
    """NAME retained per TC-643's registry binding (batch-77 precedent: the
    binding wins over accuracy) — the body pins the POST-HLR-132 reality:
    the four card-carrying views, with the map card retired to the spec
    sheet (``tests/test_legend_map_sheet.py`` owns the map path)."""
    assert set(L.LEGEND_EXAMPLES) == set(VIEW_KEYS)
    assert "map" not in L.LEGEND_EXAMPLES


@pytest.mark.parametrize("view_key", VIEW_KEYS)
def test_each_view_card_is_non_empty(view_key):
    lines = L.LEGEND_EXAMPLES[view_key]
    assert lines, f"{view_key} card is empty"
    assert all(isinstance(line, L.LegendLine) for line in lines)
    assert all(line.text.strip() for line in lines)


def test_every_line_role_is_known():
    known = {L.ROLE_SUB, L.ROLE_LINE, L.ROLE_CAPTION, L.ROLE_WARNING_SAMPLE}
    for view_key in VIEW_KEYS:
        for line in L.LEGEND_EXAMPLES[view_key]:
            assert line.role in known, f"{view_key}: bad role {line.role!r}"


# --------------------------------------------------------------------------- #
# TC-N8-01 — workspace example data (LLR-N8-1.1) + example-only contract
# --------------------------------------------------------------------------- #
def test_tc_n8_01_workspace_example_data():
    text = _text("workspace")
    for needle in (
        "Memory strip",
        "Loaded panel",
        "Data Sections",
        "Hex view",
        "Coverage",
        "Status bar",
    ):
        assert needle in text, f"workspace card missing {needle!r}"


def test_workspace_is_example_only_no_severity_key_required():
    """The workspace card is example-only: it must not depend on a severity
    colour key (the empty-section mapping + no-key note are Inc-2's job). Here
    we assert the card itself carries the 'no severity colour key' closing
    note, proving the example-only intent lives in the data."""
    text = _text("workspace")
    assert "no severity colour key" in text


def test_workspace_memory_strip_glyphs_are_band_derived():
    """AMD-10b: the memory-strip glyphs are derived from band_style, not a
    hand-list — so an upstream band glyph change flows through."""
    from s19_app.tui.entropy_style import band_style

    derived = [band_style(label)[1] for label, _lo, _hi in ENTROPY_BANDS]
    text = _text("workspace")
    for glyph in derived:
        assert glyph in text, f"derived band glyph {glyph!r} absent from strip"


# --------------------------------------------------------------------------- #
# TC-N8-04 — a2l example data (LLR-N8-2.1)
# --------------------------------------------------------------------------- #
def test_tc_n8_04_a2l_example_data():
    text = _text("a2l")
    for needle in (
        "Explorer columns",
        "Address",
        "InMem",
        "Summary",
        "Filter",
        "Detail card",
    ):
        assert needle in text, f"a2l card missing {needle!r}"


# --------------------------------------------------------------------------- #
# TC-N8-05's map limb — the map view's legend is the spec sheet (HLR-132,
# inc-003). NAMES retained per TC-643's registry binding (batch-77 precedent);
# the bodies pin the sheet's DATA (the retired card arms went away with the
# card — legend A carries no overlay block — while the overlay meanings stay
# sourced in the Hex table's _HEX_STYLE_MEANINGS).
# --------------------------------------------------------------------------- #
def test_tc_n8_05_map_example_data():
    """The map sheet's DATA (the retired map-card pin's successor): the live
    band meanings, the anatomy sample/meaning pairs, the region sample + field
    key and the Keys line are all present and non-blank."""
    text = " ".join(
        [
            *[row.meaning for row in L.build_band_key_rows()],
            *[sample for sample, meaning in L.build_map_anatomy_samples()],
            *[meaning for sample, meaning in L.build_map_anatomy_samples()],
            L.MAP_REGION_ROW_SAMPLE,
            L.MAP_REGION_ROW_FIELD_KEY,
            L.MAP_KEYS_LINE,
            *L.BAND_GAP_FIELDS,
        ]
    )
    for needle in ("band bar", "ruler", "glance", "stats", "unmapped gap"):
        assert needle in text, f"map sheet data missing {needle!r}"
    assert all(text.strip() for text in L.MAP_ANATOMY_MEANINGS)


def test_map_card_contains_both_hex_overlay_meanings():
    """NAME retained per TC-643's binding; body pins the RETIREMENT (legend A):
    the map sheet carries NO hex-overlay prose (zero prose paragraphs, no
    overlay block — AT-N8-03's overlay arm superseded), while both overlay
    meanings stay sourced in the Hex table data so the knowledge is not lost
    with the card."""
    sheet_text = " ".join(
        [
            *[row.meaning for row in L.build_band_key_rows()],
            *[sample for sample, meaning in L.build_map_anatomy_samples()],
            *[meaning for sample, meaning in L.build_map_anatomy_samples()],
            L.MAP_REGION_ROW_SAMPLE,
            L.MAP_REGION_ROW_FIELD_KEY,
            L.MAP_KEYS_LINE,
            *L.BAND_GAP_FIELDS,
        ]
    )
    assert "search / goto-focus highlight" not in sheet_text, (
        "the retired overlay explanation leaked back into the map sheet"
    )
    assert "MAC address overlay" not in sheet_text, (
        "the retired overlay explanation leaked back into the map sheet"
    )
    hex_meanings = " ".join(meaning for _colour, meaning in L.LEGEND_TABLE["Hex"].values())
    assert "search / goto-focus highlight" in hex_meanings
    assert "MAC address overlay" in hex_meanings


def test_map_card_band_bar_sample_uses_band_and_gap_glyphs():
    """NAME retained per TC-643's binding; body pins the sheet's anatomy
    samples (the retired map-card band-bar sample's successor): the samples
    use the DERIVED band glyphs + the gap hatch — never a hand-listed glyph."""
    from s19_app.tui.entropy_style import band_style

    samples = L.build_map_anatomy_samples()
    text = " ".join(sample for sample, _meaning in samples[:3])
    for glyph in (
        band_style("constant/padding")[1],
        band_style("low")[1],
        band_style("medium")[1],
        band_style("high/random")[1],
        "╱",
    ):
        assert glyph in text, f"derived band glyph {glyph!r} absent from samples"
    assert len(samples) == len(L.MAP_ANATOMY_MEANINGS) == 4


# --------------------------------------------------------------------------- #
# TC-N8-08 — mac example data + status glyphs (LLR-N8-4.1) + reconciliation
# --------------------------------------------------------------------------- #
def test_tc_n8_08_mac_example_data_and_glyphs():
    text = _text("mac")
    for needle in ("Coverage strip", "8 columns", "status glyph", "Status"):
        assert needle in text, f"mac card missing {needle!r}"
    for glyph in ("✗", "⚠", "✓", "·"):
        assert glyph in text, f"mac card missing status glyph {glyph!r}"


def test_mac_card_carries_orange_reconciliation():
    """AMD-7: the reconciliation names the inline orange table paint and the
    C-10 trust-the-glyph rule (glyph + Status over hue)."""
    text = _text("mac")
    assert "orange" in text
    assert "hue" in text
    assert "Status" in text


def test_mac_card_has_a_warning_sample_row():
    """AMD-11: exactly one warning_sample line marks the row Inc-2 will paint
    orange3 and tag #legend_mac_warning_sample."""
    samples = [
        line
        for line in L.LEGEND_EXAMPLES["mac"]
        if line.role == L.ROLE_WARNING_SAMPLE
    ]
    assert len(samples) == 1
    assert "NOT_IN_A2L" in samples[0].text


# --------------------------------------------------------------------------- #
# TC-N8-09 — issues example data (LLR-N8-5.1)
# --------------------------------------------------------------------------- #
def test_tc_n8_09_issues_example_data():
    text = _text("issues")
    for needle in ("Severity strip", "Grouped list", "families", "Hex Peek"):
        assert needle in text, f"issues card missing {needle!r}"


# --------------------------------------------------------------------------- #
# TC-N8-05 (band count) / LLR-N8-3.2 — band key derived from ENTROPY_BANDS
# --------------------------------------------------------------------------- #
def test_band_key_row_count_equals_entropy_bands():
    rows = L.build_band_key_rows()
    assert len(rows) == len(ENTROPY_BANDS) == 4


def test_band_key_rows_are_derived_from_entropy_bands():
    """Each row's glyph/label/meaning/class comes from band_style over
    ENTROPY_BANDS in order — so an upstream band change flows through (D-3)."""
    from s19_app.tui.entropy_style import band_style

    rows = L.build_band_key_rows()
    for row, (label, _lo, _hi) in zip(rows, ENTROPY_BANDS):
        css_class, glyph, meaning = band_style(label)
        assert row.label == label
        assert row.glyph == glyph
        assert row.meaning == meaning
        assert row.css_class == css_class
        # band-* class, never a severity class.
        assert row.css_class.startswith("band-")
        assert not row.css_class.startswith("sev-")


def test_band_key_ranges_are_half_open_with_closed_final_band():
    rows = L.build_band_key_rows()
    assert rows[0].range_text == "[0,1)"
    assert rows[1].range_text == "[1,5)"
    assert rows[2].range_text == "[5,7.2)"
    assert rows[-1].range_text == "[7.2,8]"


def test_band_key_meanings_present():
    meanings = {row.meaning for row in L.build_band_key_rows()}
    for expected in (
        "padding / fill",
        "structured / tables",
        "calibration / data",
        "code / compressed / random",
    ):
        assert expected in meanings


# --------------------------------------------------------------------------- #
# TC-N8 cutoff formatter (AMD-10a) — single source of the display transform
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value,expected",
    [
        (0.0, "0"),
        (1.0, "1"),
        (5.0, "5"),
        (7.2, "7.2"),
        (8.0, "8"),
        (8.000001, "8"),
    ],
)
def test_format_cutoff(value, expected):
    assert L.format_cutoff(value) == expected


# --------------------------------------------------------------------------- #
# TC-N8-11 (AMD-9 / security F3) — markup round-trip guard.
# Iterate EVERY line of EVERY LEGEND_EXAMPLES entry through the modal's markup
# path (Content.from_markup): (a) no MarkupError raised, (b) escaped literal
# brackets round-trip to a visible '['. A future unescaped '[' would either
# raise here or drop the bracket from .plain — the tripwire.
# --------------------------------------------------------------------------- #
def _all_lines():
    for view_key in VIEW_KEYS:
        for line in L.LEGEND_EXAMPLES[view_key]:
            yield view_key, line.text


def test_tc_n8_11_every_line_parses_without_markup_error():
    for view_key, text in _all_lines():
        try:
            Content.from_markup(text)
        except Exception as exc:  # pragma: no cover - failure path
            pytest.fail(f"{view_key}: markup error on {text!r}: {exc!r}")


def test_tc_n8_11_escaped_brackets_round_trip_to_literal():
    checked = 0
    for view_key, text in _all_lines():
        if "\\[" not in text:
            continue
        checked += 1
        plain = Content.from_markup(text).plain
        assert "[" in plain, f"{view_key}: escaped '[' lost in {text!r}"
        assert "\\[" not in plain, f"{view_key}: backslash leaked in {text!r}"
    # At least the a2l filter row and the issues filter row carry escaped
    # brackets — guard against the check silently matching nothing.
    assert checked >= 2


# --------------------------------------------------------------------------- #
# AT-N8-01..05 (Inc-2) — Pilot black-box: the per-view Legend renders its
# example card above the view's colour/band key. Driven through the real
# `action_show_legend` path (view_key + sections flow from the active screen).
# --------------------------------------------------------------------------- #
def _legend_body_text(screen: LegendScreen) -> str:
    """Concatenated plain text of every rendered row in the legend modal body
    (`Static` matches the `Label` artifact headers too — `Label ⊂ Static`)."""
    parts: list[str] = []
    for widget in screen.query("#legend_body Static"):
        rendered = widget.render()
        parts.append(getattr(rendered, "plain", str(rendered)))
    return " ".join(parts)


async def _open_legend_on(app: S19TuiApp, pilot, screen_key: str) -> LegendScreen:
    app.action_show_screen(screen_key)
    await pilot.pause()
    app.action_show_legend()
    await pilot.pause()
    assert isinstance(app.screen, LegendScreen), f"legend did not open on {screen_key}"
    return app.screen


def _legend_text_on(screen_key: str, tmp_path: Path) -> str:
    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            legend = await _open_legend_on(app, pilot, screen_key)
            return _legend_body_text(legend)

    return asyncio.run(_drive())


def test_at_n8_01_workspace_card_and_no_severity_key(tmp_path: Path) -> None:
    """AT-N8-01 — Workspace legend shows the example card + the example-only
    closing note, and NO foreign severity rows (LLR-N8-1.3)."""
    text = _legend_text_on("workspace", tmp_path)
    assert "Memory strip" in text, "workspace example card missing"
    assert "no severity colour key" in text, "example-only closing note missing"
    # example-only: the A2L Red severity meaning must be absent.
    assert L.LEGEND_TABLE["A2L"]["Red"][1] not in text


def test_at_n8_02_a2l_card_above_key(tmp_path: Path) -> None:
    """AT-N8-02 — A2L legend shows the column-gloss card AND the A2L key rows
    (Red schema-failure + Green memory-checked) (LLR-N8-2.2)."""
    text = _legend_text_on("a2l", tmp_path)
    assert "Explorer columns" in text or "Address" in text, "a2l card missing"
    assert L.LEGEND_TABLE["A2L"]["Red"][1] in text
    assert L.LEGEND_TABLE["A2L"]["Green"][1] in text


def test_at_n8_03_map_band_key_and_overlays(tmp_path: Path) -> None:
    """AT-N8-03 (body re-aimed at batch-93 HLR-132; NAME retained — TC-643's
    registry row binds this exact node path, and per the batch-77 TC-519
    precedent a rename is a registry change, not a test change) — through the
    real ``action_show_legend`` path the map view renders the SPEC SHEET: the
    four grouped boxes (band key + gap row, anatomy samples, region sample +
    field key, Keys line) and NO A2L severity row. The full
    structure/liveness arms live in ``tests/test_legend_map_sheet.py``
    (TC-676/677); the retired card arms (band-bar card, domain note, Hex
    overlay explanations) went away with the card — legend A carries no
    overlay block (see this module's docstring)."""
    text = _legend_text_on("map", tmp_path)
    assert "band bar" in text and "ruler" in text, "sheet anatomy box missing"
    for meaning in (
        "padding / fill",
        "structured / tables",
        "calibration / data",
        "code / compressed / random",
    ):
        assert meaning in text, f"map band meaning missing: {meaning!r}"
    assert "unmapped gap" in text, "sheet gap row missing"
    assert L.MAP_REGION_ROW_SAMPLE in text, "sheet region sample missing"
    assert L.MAP_KEYS_LINE in text, "sheet Keys line missing"
    # negative: the sheet renders no A2L/Hex severity key rows.
    assert L.LEGEND_TABLE["A2L"]["Red"][1] not in text


def test_at_n8_04_mac_card_key_and_reconciliation(tmp_path: Path) -> None:
    """AT-N8-04 — MAC legend shows the MAC card, the MAC key rows and the
    orange↔pale-yellow reconciliation naming the orange table paint and the
    trust-the-glyph rule (LLR-N8-4.2/4.3)."""
    text = _legend_text_on("mac", tmp_path)
    assert "8 columns" in text or "Status" in text, "mac card missing"
    assert L.LEGEND_TABLE["MAC"]["Pale yellow"][1] in text, "MAC key row missing"
    assert "orange" in text and "hue" in text, "reconciliation missing"


def test_at_n8_05_issues_card_above_key(tmp_path: Path) -> None:
    """AT-N8-05 — Issues legend shows the code-family/severity-strip card AND
    the Issues key rows (Errors + Optional info) (LLR-N8-5.2)."""
    text = _legend_text_on("issues", tmp_path)
    assert "families" in text or "Severity strip" in text, "issues card missing"
    assert L.LEGEND_TABLE["Issues"]["Errors"][1] in text
    assert L.LEGEND_TABLE["Issues"]["Optional info"][1] in text


# --------------------------------------------------------------------------- #
# AT-N8-06 (Inc-3, AMD-5) — the long Issues "Errors" key meaning (148 chars)
# renders as a `Static` that actually WRAPS (height >= 2) at 120 cols, so its
# tail survives. The wrap (not the tail substring) is the counterfactual: a
# pre-N8 `Label` row would be height 1 (`type(row) is Static`, not isinstance —
# `Label ⊂ Static`).
# --------------------------------------------------------------------------- #
def test_at_n8_06_long_key_row_is_static_and_wraps(tmp_path: Path) -> None:
    tail = "same-name mismatch"  # tail of the 148-char Issues "Errors" meaning
    assert tail in L.LEGEND_TABLE["Issues"]["Errors"][1]  # oracle: it IS the tail

    async def _drive() -> tuple[bool, int, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            legend = await _open_legend_on(app, pilot, "issues")
            rows = [
                w
                for w in legend.query("#legend_body Static")
                if tail in str(w.render())
            ]
            assert len(rows) == 1, f"expected one row carrying {tail!r}, got {len(rows)}"
            row = rows[0]
            return type(row) is Static, row.size.height, tail in str(row.render())

    is_static, height, tail_present = asyncio.run(_drive())
    assert is_static, "the long key row must be a Static (wraps), not a Label"
    assert height >= 2, f"expected the row to wrap (height>=2), got {height}"
    assert tail_present  # secondary readability check (the tail is present)


# --------------------------------------------------------------------------- #
# AT-N8-07 (Inc-3, AMD-7/AMD-11) — the MAC reconciliation sample row is painted
# the SAME inline style the MAC DataTable paints a WARNING row with
# (`app._SEVERITY_TO_RICH_STYLE[WARNING]`), coupled to that live value — NOT a
# hex literal. Reads the painted segment's colour off `#legend_mac_warning_sample`.
# --------------------------------------------------------------------------- #
def test_at_n8_07_mac_warning_sample_painted_warning_style(tmp_path: Path) -> None:
    from s19_app.tui.app import _SEVERITY_TO_RICH_STYLE
    from s19_app.tui.screens import _MAC_WARNING_SAMPLE_STYLE
    from s19_app.validation import ValidationSeverity

    warning_style = _SEVERITY_TO_RICH_STYLE[ValidationSeverity.WARNING]
    # (a) anti-drift coupling: screens paints with the SAME style the MAC table
    # uses — if app re-values WARNING, screens.py must follow or this goes RED.
    assert _MAC_WARNING_SAMPLE_STYLE == warning_style, (
        "the legend orange sample must track app's MAC WARNING inline style"
    )

    async def _drive() -> tuple[set, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            legend = await _open_legend_on(app, pilot, "mac")
            sample = legend.query_one("#legend_mac_warning_sample", Static)
            # The rendered Content carries the painted span styles; the widget's
            # own `render_line` is pre-compositor (base CSS colour only), so read
            # the paint intent off the Content spans.
            content = sample.render()
            span_styles = {span.style for span in getattr(content, "spans", [])}
            return span_styles, content.plain

    span_styles, plain = asyncio.run(_drive())
    # (b) painted-segment check: the sample row's segment carries exactly the MAC
    # WARNING inline style (not a hex literal, not a sev-*/band-* class).
    assert warning_style in span_styles, (
        f"warning sample not painted {warning_style!r}: {span_styles}"
    )
    assert "NOT_IN_A2L" in plain  # it IS the warning-row sample, not a stray row


# --------------------------------------------------------------------------- #
# TC-N8-04 (Inc-3, AMD-8) — C-31 live-column oracle: every LIVE #a2l_tags_list
# column label has a legend line in the a2l card, so a 17th A2L column added
# without a legend entry goes RED. Derived from the shipped table, not a hand-list.
# --------------------------------------------------------------------------- #
def test_tc_n8_04_a2l_card_covers_every_live_column(tmp_path: Path) -> None:
    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            table = app.query_one("#a2l_tags_list", DataTable)
            return [str(col.label) for col in table.columns.values()]

    labels = asyncio.run(_drive())
    assert len(labels) >= 16, f"expected >=16 live A2L columns, got {len(labels)}"
    card = _text("a2l")
    for label in labels:
        assert label in card, f"live A2L column {label!r} has no legend line (AMD-8)"


# --------------------------------------------------------------------------- #
# TC-N8-11b (AMD-9 defense-in-depth, re-aimed at batch-93 HLR-132) — the map
# spec-sheet lines live OUTSIDE LEGEND_EXAMPLES (the retired band notes went
# away with the map card), so the _all_lines() tripwire does not reach them.
# Guard them here so a future markup-sensitive character added to any sheet
# line can't open a tag and crash the modal if a line ever flips markup=True.
# --------------------------------------------------------------------------- #
def test_tc_n8_11b_band_notes_are_markup_safe():
    """TC-N8-11b (body re-aimed at batch-93 HLR-132; NAME retained — TC-643's
    registry row binds it): the retired band notes went away with the map
    card, so the tripwire guards the spec-sheet lines instead — they live
    OUTSIDE LEGEND_EXAMPLES, so the _all_lines() tripwire does not reach
    them. A future markup-sensitive character added to any sheet line can't
    open a tag and crash the modal if a line ever flips markup=True."""
    sheet_lines = [
        *[row.range_text for row in L.build_band_key_rows()],
        *[sample for sample, _meaning in L.build_map_anatomy_samples()],
        *[meaning for _sample, meaning in L.build_map_anatomy_samples()],
        L.MAP_REGION_ROW_SAMPLE,
        L.MAP_REGION_ROW_FIELD_KEY,
        L.MAP_KEYS_LINE,
        *L.BAND_GAP_FIELDS,
    ]
    for line in sheet_lines:
        content = Content.from_markup(line)  # no MarkupError
        assert content.plain  # renders to visible text
    # The sheet renders markup=False — a literal '[' must round-trip untouched
    # (the [lo,hi) range texts are the carriers).
    bracketed = [line for line in sheet_lines if "[" in line]
    assert bracketed, "the tripwire expects the [lo,hi) range texts to carry '['"
    for line in bracketed:
        assert "[" in Content.from_markup(line).plain, (
            f"literal bracket lost in {line!r}"
        )
