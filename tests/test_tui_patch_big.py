"""Patch Editor BIG — EASY layer tests (batch-48, Inc-1).

Verdicts HLR-075 (R-TUI-075, US-P1) through the shipped Patch Editor surface:

- **AT-075a** — the three windows carry border titles + LIVE subtitles: the
  SCRIPT subtitle's entry count moves ``3`` -> ``4`` when a 4th entry is added
  (liveness asserted, not "a subtitle exists"); the JSON subtitle names the
  schema.
- **AT-075b** — every entries cell is a Rich ``Text`` and the kind/address/value
  cells carry >=3 DISTINCT style tokens (structural invariant, C-29-safe —
  never "K columns fit"), over both a ``string``- and a ``bytes``-kind row.
- **AT-075c** — the variant+scope line moves off its default when the REAL
  ``#patch_execute_scope_button`` is clicked (C-10(a)).
- **AT-075d** ★★ — GATE-BLOCKING C-17: a project-file-derived variant id
  carrying each MD-1 payload renders VERBATIM on the variant/scope line with no
  payload-derived span and no ``MarkupError``.
- **AT-075e** ★★ — GATE-BLOCKING C-17 (LLR-075.6): the entries table is a LIVE
  ``Text.from_markup`` sink at HEAD. See the sink note below.

RED counterfactual (RECORDED — run against the pre-fix HEAD ``6551aed``, where
``change_service.py:1402-1425`` sets ``value_text = entry.value`` raw and
``refresh_entries`` passed it to ``add_row()`` as a bare ``str``):

    AT-075e FAILED on the vulnerable code, three ways:
      * ``[red]PWNED[/red]``            -> cell was a bare ``str``; rendered
        ``plain='PWNED'`` + ``Span(0,5,'red')`` — content mangled, style injected
      * ``[link=http://evil]click[/link]`` -> ``Span(0,5,'link http://evil')`` —
        a LINK injected from file data (the batch-43 class)
      * ``[/nope]``                     -> ``MarkupError`` raised out of
        ``refresh_entries`` — a file-triggered CRASH

    AT-075b FAILED: cells were bare ``str``, 0 role styles.
    AT-075a/c/d FAILED: the subtitles and the variant/scope line did not exist.

**A SECOND live sink, found in Phase 3 and NOT in the spec** (surfaced for
security review — same class as BL-1, different widget): ``#patch_variant_select``.
``app.py:3740-3742`` maps each project ``variant.variant_id`` to BOTH the option
label and its value, and Textual's ``SelectCurrent.update(prompt)``
(``_select.py:615``) hands the bare ``str`` label to a markup-enabled ``Static``
-> ``Content.from_markup`` (``visual.py:103``). Measured at ``textual==8.2.8``:
a variant id of ``[red]PWNED[/red]`` rendered ``plain='PWNED'`` with an injected
``Span(0,5,'red')``; ``[/nope]`` and ``[link=http://evil]click[/link]`` each
raised ``MarkupError`` **out of ``set_variants``** (the ``Content`` grammar
rejects the unquoted value). AT-075d's "no ``MarkupError``" clause names
``set_variants`` as its ingress, so this sink sits directly on the gate-blocking
path and could not be dodged without weakening the AT — i.e. exactly the
partial-fix trap BL-1 names. Fixed at the panel's render boundary (literal
``Text`` labels); ``app.py`` unchanged.

**Inc-1b — the class is THREE sites wide; the other two are now closed.** The
Inc-1 security review probed every ``Select`` option-label site against the
installed ``textual==8.2.8`` and measured two more LIVE in ``main``:
``#patch_doc_file_select`` (label = a FILENAME read off disk) and
``AbDiffPanel``'s ``#diff_select_a``/``#diff_select_b`` (same project-derived
variant ids). Both are fixed here. ``screens.py:1057`` was probed and is **NOT
live** — it already carries ``escape_markup(name)`` under a C-15 probe comment
dated 2026-07-10; it is the precedent, not a bug. AT-075f asserts all three.

**⚠ TWO MARKUP ENGINES, DIFFERENT GRAMMARS — do not conflate them** (the F3
correction). ``rich.text.Text.from_markup`` drives the DataTable cell path
(AT-075e) and ACCEPTS a bare ``[link=http://evil]``, injecting a real link span
— AT-075e's traceback confirms it. Textual's ``Content.from_markup`` drives the
``Static``/Select-label path (AT-075f) and REQUIRES a quoted value, so the same
payload RAISES ``MarkupError`` there instead of injecting. Link *injection* is
therefore real only on the DataTable path. The exposure is identical on both;
only the consequence differs. Scoping the next sweep by the wrong engine's
behaviour would mis-classify the sites.

**AT-075e sink note (what this AT discriminates).** Textual's
``default_cell_formatter`` (``_data_table.py:202-222``) sets
``possible_markup=True`` and calls ``Text.from_markup(content)`` — but **only
for a ``str``**. A ``Text`` cell is passed through untouched. Therefore:

- Asserting ``get_cell_at(...) == payload`` is **TAUTOLOGICAL** — it round-trips
  the stored string and **PASSES on the vulnerable code at HEAD**. It proves
  nothing.
- Clause **(i)** (``isinstance(cell, Text)``) is the load-bearing one — it is
  the only clause that distinguishes the safe path from the live sink.
- Clause **(iv)** is what ``[/nope]`` discriminates (the crash class).

Per MJ-6 the ANSI and ``sensor[unclosed`` payloads are carried as **regression
fixtures only** — measured, they render IDENTICALLY on the safe and the unsafe
path and are NOT credited as counterfactuals here.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from rich.text import Text
from textual.content import Content
from textual.coordinate import Coordinate
from textual.widgets import Button, DataTable, Input, Select

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import AbDiffPanel, PatchEditorPanel

# The batch-46 FOLD-8 reachable-under-scroll primitive, reused rather than
# re-implemented — `_reach` is the established way to drive a docked patch
# button, and the measured viewport cannot show all 17 buttons at once.
from tests.test_tui_patch_layout import _reach

# ---------------------------------------------------------------------------
# C-17 payload set (MD-1) — the batch-48 canonical set (01b §"C-17 payload set")
# ---------------------------------------------------------------------------

#: The three payloads that DISCRIMINATE the safe path from ``Text.from_markup``.
#: Both bracket PAIRS inject a span; ``[/nope]`` is the only crash-class payload.
MD1_DISCRIMINATORS = (
    "[red]PWNED[/red]",
    "[link=http://evil]click[/link]",
    "[/nope]",
)

#: Regression fixtures ONLY (MJ-6): measured to render identically on the safe
#: and the unsafe path. They must still render verbatim with 0 ``MarkupError``,
#: but they are NOT counterfactuals and are not credited as such.
MD1_REGRESSION_FIXTURES = (
    "\x1b[31mX\x1b[0m",
    "sensor[unclosed",
)

MD1_PAYLOADS = MD1_DISCRIMINATORS + MD1_REGRESSION_FIXTURES

#: ``_ENTRIES_COLUMNS`` (``screens_directionb.py:2264``) — unchanged at five.
_ENTRY_COLUMN_COUNT = 5

#: The entries column carrying the raw, file-derived ``ChangeEntry.value``.
_VALUE_COLUMN = 2


def _write_v2_document(path: Path, entries: list[dict]) -> Path:
    """Write a v2 ``s19app-changeset`` JSON document fixture."""
    path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return path


def _load_document(app: S19TuiApp, doc_path: Path) -> None:
    """Load a change document through the REAL panel load ingress."""
    app.query_one("#patch_doc_path_input", Input).value = str(doc_path)
    panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
    panel.request_action("load_doc")


def _row_cells(app: S19TuiApp, row: int) -> list[object]:
    """Return every stored cell of an entries row, unstringified.

    ``get_cell_at`` returns what ``add_row`` stored — a ``Text`` on the fixed
    path, a bare ``str`` on the vulnerable one. NOT stringified: the ``str``
    vs ``Text`` distinction IS the security property under test.
    """
    table = app.query_one("#patch_doc_entries_table", DataTable)
    return [
        table.get_cell_at(Coordinate(row, column))
        for column in range(_ENTRY_COLUMN_COUNT)
    ]


def _payload_derived_spans(cell: Text) -> list:
    """Return the spans of ``cell`` that the payload's own bracket text produced.

    A correct (literal-``Text``) implementation carries at most ONE span: the
    whole-cell role style applied by the renderer. Any span carrying a ``link``
    style, or any span that does not cover the WHOLE cell, is markup the
    payload's own bracket text produced — i.e. injection.

    The payload itself is deliberately NOT a parameter: the test does not need
    to know what the payload was. Injection is detectable from the cell's own
    shape (a link span, or a span that fails to cover the whole cell), so the
    check stays honest for any payload — including ones nobody enumerated.
    """
    suspect = []
    for span in cell.spans:
        style_token = str(span.style)
        if "link" in style_token:
            suspect.append(span)
            continue
        if not (span.start == 0 and span.end >= len(cell.plain)):
            suspect.append(span)
    return suspect


# ===========================================================================
# AT-075e ★★ — GATE-BLOCKING C-17: the entries table (LLR-075.6)
# ===========================================================================


def test_at075e_c17_entries_table(tmp_path: Path) -> None:
    """Hostile ``ChangeEntry.value`` renders literally in every entries cell.

    Intent (AT-075e ★★, LLR-075.6 — the live-sink fix): a change-set loaded
    from DISK (the real ingress, so nothing sanitises the payload en route)
    whose ``value`` carries each MD-1 payload must render with:

      (i)   the stored cell an ``rich.text.Text``, NOT a bare ``str`` — the
            TAUTOLOGY GUARD. ``default_cell_formatter`` markup-parses ONLY
            ``str``, so this clause is the one that makes the AT non-vacuous;
            an ``== payload`` assertion passes on the vulnerable HEAD.
      (ii)  its ``.plain`` carrying the payload char-for-char VERBATIM;
      (iii) ZERO payload-derived spans (no injected ``red``, no injected
            ``link``);
      (iv)  NO ``MarkupError`` (or any exception) raised — ``[/nope]``.

    Clause (i) is asserted over ALL FIVE columns, not just the value column:
    that is the PARTIAL-FIX TRAP this AT exists to catch. ``status_text`` and
    ``linkage_text`` carry no role style (LLR-075.2), so a role-driven
    conversion leaves them bare ``str`` and the ``from_markup`` sink LIVE.
    """
    doc_path = _write_v2_document(
        tmp_path / "hostile.json",
        [
            {"type": "string", "address": f"0x{0x100 + index * 0x10:X}", "value": payload}
            for index, payload in enumerate(MD1_PAYLOADS)
        ],
    )

    async def _drive() -> list[list[object]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            # Clause (iv): a MarkupError out of refresh_entries surfaces HERE.
            _load_document(app, doc_path)
            await pilot.pause()
            return [_row_cells(app, row) for row in range(len(MD1_PAYLOADS))]

    rows = asyncio.run(_drive())

    assert len(rows) == len(MD1_PAYLOADS), (
        "every hostile entry must render a row — a payload that silently "
        f"dropped its row would hide the sink; got {len(rows)} rows"
    )

    for payload, cells in zip(MD1_PAYLOADS, rows):
        # (i) THE TAUTOLOGY GUARD — every cell, styled or not.
        for column, cell in enumerate(cells):
            assert isinstance(cell, Text), (
                f"entries cell (column {column}) for payload {payload!r} is a "
                f"{type(cell).__name__}, not a rich.text.Text. Textual's "
                "default_cell_formatter markup-parses bare str via "
                "Text.from_markup — a str cell IS the live sink (LLR-075.6). "
                "A role-only conversion that leaves status/linkage bare is the "
                "PARTIAL FIX this clause exists to catch."
            )

        value_cell = cells[_VALUE_COLUMN]

        # (ii) verbatim — char-for-char, the payload's own brackets intact.
        assert value_cell.plain == payload, (
            f"payload {payload!r} must render VERBATIM in the value cell; got "
            f"{value_cell.plain!r}. A mangled plain (e.g. 'PWNED' from "
            "'[red]PWNED[/red]') means from_markup consumed the brackets."
        )

        # (iii) no span the payload's own text produced.
        injected = _payload_derived_spans(value_cell)
        assert injected == [], (
            f"payload {payload!r} produced payload-derived span(s) {injected!r} "
            "— file data must never name a style or inject a link"
        )


# ===========================================================================
# AT-075a — window border titles + LIVE subtitles (LLR-075.1)
# ===========================================================================


def _window_chrome(app: S19TuiApp, window_id: str) -> tuple[str, str]:
    """Return one patch window's (border_title, border_subtitle)."""
    from textual.containers import Container

    window = app.query_one(f"#{window_id}", Container)
    return (str(window.border_title or ""), str(window.border_subtitle or ""))


def test_at075a_titles(tmp_path: Path) -> None:
    """The three windows carry border titles and LIVE subtitles.

    Intent (AT-075a, LLR-075.1): the three windows are structurally distinct
    (batch-46) but visually anonymous. This asserts the CONTENT — the literal
    entry count, the no-run token, the schema token — and its LIVENESS: adding
    a 4th entry through the REAL add ingress moves the SCRIPT subtitle 3 -> 4.
    "A subtitle exists" is deliberately NOT the assertion; a hard-coded
    subtitle would pass that and fail this.
    """
    doc_path = _write_v2_document(
        tmp_path / "three.json",
        [
            {"type": "bytes", "address": "0x100", "bytes": "AA BB"},
            {"type": "bytes", "address": "0x110", "bytes": "CC DD"},
            {"type": "string", "address": "0x120", "value": "sensor"},
        ],
    )

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            _load_document(app, doc_path)
            await pilot.pause()

            outcomes["script"] = _window_chrome(app, "patch_win_script")
            outcomes["checks"] = _window_chrome(app, "patch_win_checks")
            outcomes["json"] = _window_chrome(app, "patch_win_json")

            # Liveness: add a 4th entry through the REAL add ingress.
            app.query_one("#patch_entry_address_input", Input).value = "0x130"
            app.query_one("#patch_entry_value_input", Input).value = "added"
            app.query_one("#patch_entry_add_button", Button).press()
            await pilot.pause()
            outcomes["script_after_add"] = _window_chrome(app, "patch_win_script")
        return outcomes

    outcomes = asyncio.run(_drive())

    script_title, script_subtitle = outcomes["script"]
    checks_title, checks_subtitle = outcomes["checks"]
    json_title, json_subtitle = outcomes["json"]

    # Every window self-describes with a non-empty border title.
    assert "PATCH SCRIPT" in script_title, script_title
    assert "CHECKS" in checks_title, checks_title
    assert "JSON EDIT" in json_title, json_title

    # The subtitles carry CONTENT, not decoration.
    assert "3" in script_subtitle, (
        f"the SCRIPT subtitle must name the live entry count 3; got "
        f"{script_subtitle!r}"
    )
    assert "no run yet" in checks_subtitle, (
        f"the CHECKS subtitle must carry the no-run state token; got "
        f"{checks_subtitle!r}"
    )
    assert "v2" in json_subtitle, (
        f"the JSON subtitle must name the change-set schema; got "
        f"{json_subtitle!r}"
    )

    # LIVENESS — the discriminator against a hard-coded subtitle.
    _, script_subtitle_after = outcomes["script_after_add"]
    assert "4" in script_subtitle_after, (
        "after adding a 4th entry the SCRIPT subtitle must read 4; got "
        f"{script_subtitle_after!r} (a static subtitle passes a "
        "'subtitle exists' check and fails here)"
    )


# ===========================================================================
# AT-075b — entries role styles (LLR-075.2) + Text construction (LLR-075.6)
# ===========================================================================


def test_at075b_role_colours(tmp_path: Path) -> None:
    """Entries cells are role-styled Rich ``Text`` over both entry kinds.

    Intent (AT-075b, LLR-075.2 + LLR-075.6): the entries table reads by ROLE —
    kind PURPLE, address CYAN, value VALUE. Asserted as a STRUCTURAL INVARIANT
    (>=3 DISTINCT style tokens across the three role cells), never as "K
    columns fit" — a geometry claim would be C-29-unsafe here.

    A5 re-check: ``refresh_entries`` applies no row-level style override, so
    unlike batch-47's A2L table (§6.5 Amendment E) these accents ARE visible
    on the live table. Both a ``string``- and a ``bytes``-kind row are covered
    because they take different ``value_text`` branches in
    ``ChangeService.rows``.
    """
    doc_path = _write_v2_document(
        tmp_path / "kinds.json",
        [
            {"type": "string", "address": "0x100", "value": "sensor"},
            {"type": "bytes", "address": "0x110", "bytes": "AA BB CC"},
        ],
    )

    async def _drive() -> list[list[object]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            _load_document(app, doc_path)
            await pilot.pause()
            return [_row_cells(app, row) for row in range(2)]

    rows = asyncio.run(_drive())
    assert len(rows) == 2, f"both entry kinds must render a row; got {rows!r}"

    for kind, cells in zip(("string", "bytes"), rows):
        # LLR-075.6 — every cell, styled or not.
        for column, cell in enumerate(cells):
            assert isinstance(cell, Text), (
                f"{kind} row column {column} is a {type(cell).__name__}, not a "
                "rich.text.Text (LLR-075.6)"
            )
        # LLR-075.2 — the three role cells carry >=3 DISTINCT styles.
        role_styles = {str(cells[column].style) for column in range(3)}
        assert len(role_styles) >= 3, (
            f"the {kind} row's kind/address/value cells must carry >=3 "
            f"distinct role styles; got {role_styles!r}"
        )
        assert all(style for style in role_styles), (
            f"every role cell must carry a NON-EMPTY style; got {role_styles!r}"
        )


# ===========================================================================
# AT-075c — the variant + scope line (LLR-075.3)
# ===========================================================================


def _scope_line(app: S19TuiApp) -> Content:
    """Return the variant/scope line's RENDER-PATH content.

    At the ``textual==8.2.8`` pin ``Static.update(Text)`` visualises the Rich
    ``Text`` into a ``textual.content.Content`` via ``Content.from_rich_text``
    — a LITERAL conversion, never ``from_markup``. ``.visual`` is therefore
    the real render path, and reading it (rather than the ``Text`` the test
    itself built) is what keeps the C-17 assertion non-tautological: it
    observes what the widget will actually paint.
    """
    from textual.widgets import Static

    return app.query_one("#patch_variant_scope_line", Static).visual


def test_at075c_variant_scope_line(tmp_path: Path) -> None:
    """The scope line moves off its default when the REAL button is clicked.

    Intent (AT-075c, LLR-075.3, C-10(a)): today the execution scope is legible
    ONLY from ``#patch_execute_scope_button``'s own label — the analyst cannot
    see what a run would target without decoding a button. This drives the REAL
    button to a NON-DEFAULT value and asserts the observed line CHANGED
    (``active variant`` -> ``all variants``). Asserting only the default would
    pass against a line hard-wired to the default.
    """

    async def _drive() -> dict[str, str]:
        outcomes: dict[str, str] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            outcomes["before"] = _scope_line(app).plain
            # FOLD-8 (batch-46): the docked buttons are REACHABLE-UNDER-SCROLL,
            # not all visible at once — the measured panel viewport cannot show
            # all 17. `pilot.click` needs the target in the visible region, so
            # reach it first with the established primitive, then click for
            # real (C-10(a) — the operator's actual path to this control).
            button = app.query_one("#patch_execute_scope_button", Button)
            await _reach(app, pilot, button)
            await pilot.click("#patch_execute_scope_button")
            await pilot.pause()
            outcomes["after"] = _scope_line(app).plain
        return outcomes

    outcomes = asyncio.run(_drive())

    assert "Variant" in outcomes["before"] and "Scope" in outcomes["before"], (
        f"the line must read 'Variant <id> · Scope <label>'; got "
        f"{outcomes['before']!r}"
    )
    assert "active variant" in outcomes["before"], (
        f"the default scope label must render; got {outcomes['before']!r}"
    )
    # The no-variant boundary: a neutral placeholder, never a crash.
    assert "Variant -" in outcomes["before"], (
        "with no project loaded the line must show the neutral variant "
        f"placeholder; got {outcomes['before']!r}"
    )
    # C-10(a) — the observed value MOVED off its default.
    assert "all variants" in outcomes["after"], (
        "one click of the REAL scope button must advance the line to the next "
        f"scope; got {outcomes['after']!r}"
    )
    assert outcomes["after"] != outcomes["before"], (
        "the scope line must change when the scope cycles — a line hard-wired "
        "to the default passes a default-only assertion and fails here"
    )


# ===========================================================================
# AT-075d ★★ — GATE-BLOCKING C-17: the variant/scope line (LLR-075.4)
# ===========================================================================


@pytest.mark.parametrize("payload", MD1_PAYLOADS)
def test_at075d_c17_variant(tmp_path: Path, payload: str) -> None:
    """A hostile project-derived variant id renders literally on the line.

    Intent (AT-075d ★★, LLR-075.4): the variant id reaching ``set_variants``
    is PROJECT-FILE-DERIVED, so the NEW variant/scope line is a new sink for
    untrusted text. Each MD-1 payload must appear VERBATIM in the line's
    ``Text.plain``, contribute no ``link`` span, and raise NO ``MarkupError``.

    NOT "no span": ``label_value`` legitimately applies its own LABEL/CYAN
    spans, so a blanket ``spans == []`` here would assert a falsehood. The
    VERBATIM ``.plain`` clause is what discriminates injection — any injected
    span must consume the payload's brackets, which mangles ``plain``. The
    link filter catches the one span class that injects without consuming.

    The counterfactual is an f-string into markup
    (``f"Variant {variant_id}"`` handed to a markup-enabled ``Static``):
    ``[red]PWNED[/red]`` would inject a span and ``[/nope]`` would crash.
    """

    async def _drive() -> Content:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            # The real ingress: app.py is the only populator of the dropdown,
            # and it hands the project's variant ids straight through.
            panel.set_variants([(payload, payload), ("other", "other")], payload)
            await pilot.pause()
            return _scope_line(app)

    line = asyncio.run(_drive())

    assert isinstance(line, Content), (
        f"the variant/scope line must visualise to a textual Content, not a "
        f"{type(line).__name__}"
    )
    assert payload in line.plain, (
        f"the hostile variant id {payload!r} must render VERBATIM on the "
        f"line; got {line.plain!r}"
    )
    injected = [
        span for span in line.spans if "link" in str(span.style)
    ]
    assert injected == [], (
        f"variant id {payload!r} injected link span(s) {injected!r} — project "
        "file data must never inject a link"
    )


# ===========================================================================
# AT-075f ★★ — GATE-BLOCKING C-17: the Select OPTION LABEL, all three sites
# (Inc-1b — closes F4: AT-075d guarded this sink only by ACCIDENT)
# ===========================================================================
#
# WHY THIS AT EXISTS (F4, the security review's MEDIUM finding). AT-075d reads
# only `#patch_variant_scope_line` — it never observes the Select's own label.
# It catches the Select sink ONLY through the crash path: `[/nope]` and
# `[link=…]` raise `MarkupError` out of `set_variants`, so the test errors out.
# But `[red]PWNED[/red]` does NOT raise — on a `str` label it silently mangles
# `plain` to 'PWNED' and injects `Span(0,5,'red')`, and AT-075d STILL PASSES.
# A regression to `str` labels would therefore ship the span-injection class
# undetected. This AT asserts the `SelectCurrent` `#label` VISUAL directly.
#
# TWO MARKUP ENGINES ARE IN PLAY — do not conflate them:
#   * `rich.text.Text.from_markup`   — the DataTable cell path (AT-075e).
#     Grammar accepts a bare `[link=http://evil]` -> injects a LINK span.
#   * `textual.content.Content.from_markup` — the `Static` / Select-label path
#     (this AT). Its grammar REQUIRES a quoted value, so the same bare-URL
#     payload RAISES `MarkupError` instead of injecting. Measured, 8.2.8.
# The consequence differs per engine; the exposure does not.


def _select_label_visual(app: S19TuiApp, select_id: str) -> Content:
    """Return a ``Select``'s displayed-label RENDER-PATH content.

    ``Select._watch_value`` hands the chosen option's LABEL to
    ``SelectCurrent.update(prompt)`` (``_select.py:615``), which forwards it to
    a markup-enabled ``Static#label``. Reading that ``Static``'s ``.visual`` is
    the only way to observe what the dropdown will actually paint — the label
    the test itself passed in proves nothing about the sink.
    """
    from textual.widgets import Static
    from textual.widgets._select import SelectCurrent

    current = app.query_one(select_id, Select).query_one(SelectCurrent)
    return current.query_one("#label", Static).visual


def _assert_label_literal(line: Content, payload: str, site: str) -> None:
    """Assert a Select label rendered ``payload`` literally, with no markup."""
    assert line.plain == payload, (
        f"{site}: the hostile option label {payload!r} must render VERBATIM; "
        f"got {line.plain!r}. A mangled plain (e.g. 'PWNED' from "
        "'[red]PWNED[/red]') means Content.from_markup consumed the brackets "
        "— i.e. the label reached the sink as a bare str."
    )
    assert list(line.spans) == [], (
        f"{site}: the option label {payload!r} produced span(s) "
        f"{list(line.spans)!r}. A literal Text label carries NO spans; any "
        "span here is markup the file-derived text itself named. THIS is the "
        "clause AT-075d cannot see: [red]PWNED[/red] does not raise, so a "
        "crash-only guard passes while the injection ships."
    )


@pytest.mark.parametrize("payload", MD1_PAYLOADS)
def test_at075f_c17_patch_variant_select_label(tmp_path: Path, payload: str) -> None:
    """``#patch_variant_select``: a hostile variant id renders literally.

    Intent: ``app.py:3744`` maps each project ``variant.variant_id`` to BOTH
    the option label and its value. The label is the sink. Ingress is the REAL
    populator, ``PatchEditorPanel.set_variants``.
    """

    async def _drive() -> Content:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            panel.set_variants([(payload, payload), ("other", "other")], payload)
            await pilot.pause()
            return _select_label_visual(app, "#patch_variant_select")

    _assert_label_literal(asyncio.run(_drive()), payload, "#patch_variant_select")


@pytest.mark.parametrize("payload", MD1_PAYLOADS)
def test_at075f_c17_patch_doc_file_select_label(tmp_path: Path, payload: str) -> None:
    """``#patch_doc_file_select``: a hostile CHANGE-FILE NAME renders literally.

    Intent: the payload here is a **filename on disk** —
    ``app.py:3693`` -> ``_scan_patch_change_files()`` reads
    ``workarea/patches/`` and hands each bare component name to
    ``set_change_files`` as the option label. An attacker who can drop a file
    into the work area names this label. Ingress is the REAL populator.
    """

    async def _drive() -> Content:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            panel.set_change_files([payload, "other.json"])
            await pilot.pause()
            # Select the hostile option so its label becomes the displayed one.
            app.query_one("#patch_doc_file_select", Select).value = payload
            await pilot.pause()
            return _select_label_visual(app, "#patch_doc_file_select")

    _assert_label_literal(asyncio.run(_drive()), payload, "#patch_doc_file_select")


@pytest.mark.parametrize("payload", MD1_PAYLOADS)
def test_at075f_c17_ab_diff_select_labels(tmp_path: Path, payload: str) -> None:
    """``#diff_select_a`` / ``#diff_select_b``: hostile variant ids render literally.

    Intent: ``app.py:3511`` hands ``AbDiffPanel.set_variants`` the SAME
    project-file-derived ``variant_id``s as the patch panel, and the panel maps
    them to both dropdowns' option labels. Both selects are asserted — the
    populator writes them in one loop, so a fix that missed one is exactly the
    partial-fix trap.
    """

    async def _drive() -> dict[str, Content]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            panel = app.query_one("#ab_diff_panel", AbDiffPanel)
            # set_variants preselects options[0] on BOTH selects, so the
            # hostile label becomes the displayed one with no further driving.
            panel.set_variants([(payload, payload)])
            await pilot.pause()
            return {
                select_id: _select_label_visual(app, select_id)
                for select_id in ("#diff_select_a", "#diff_select_b")
            }

    for select_id, line in asyncio.run(_drive()).items():
        _assert_label_literal(line, payload, select_id)
