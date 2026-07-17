"""Patch Editor BIG — JSON colouring + the paste-cap gauge (batch-48, Inc-5).

HLR-079 (R-TUI-079, US-P4) through the shipped Patch Editor surface: the
``#patch_paste_text`` buffer colours its own JSON in place, and a new
``#patch_paste_gauge`` reads the buffer against the shared 64 KiB cap.

⚠ **THE OBSERVATION POINT IS THE PAINTED RESULT, AND THAT IS AN AMENDMENT**
(§6.5 Amendment E, REQUIREMENTS.md; operator-authorised 2026-07-16). The locked
AT-079b/c observed ``TextArea.get_line(i).spans``. MEASURED at the
``textual==8.2.8`` pin, that accessor **cannot carry a span**:
``_render_line`` (``_text_area.py:1440``) does ``line = self.get_line(i)`` and
stylizes that **local copy**, while ``get_line`` (``:1328``) unconditionally
returns a fresh ``Text(line_string, ...)``. So ``.spans`` is ``[]`` on a safe
implementation, on an unsafe one, and on one never written:

    get_line(0) : '{"a": 1}'  spans= []
    _highlights : {0: [(1,4,'json.key'), (6,7,'json.number')]}

AT-079c ★★ is the batch's GATE-BLOCKING C-17 test. A gate that cannot fail is
not a gate. Both ATs therefore observe ``TextArea._render_line(y)`` — the
composited ``Strip`` of ``(text, style)`` segments, where the styles actually
land. That is 01b's own diagnosis (it correctly reasoned ``ta.text`` is
tautological) carried one accessor further, to the render path itself.

⚠ **THE C-17 ORACLE IS ITSELF UNDER TEST** (``test_tc079_3_c17_oracle_
discriminates``). Seven vacuous checks were found on this batch; the answer to
"how do you know THIS gate can fail?" must be a test, not a paragraph. That arm
runs the AT-079c predicate against a deliberately UNSAFE ``TextArea`` that
markup-parses its lines, and asserts the predicate REJECTS it.

⚠ **KNOW WHICH MARKUP ENGINE THE SINK USES.** Two are in play with DIFFERENT
grammars, and conflating them mis-scopes a payload set (the Inc-1b lesson, and
a correction to an earlier claim of mine): ``rich.text.Text.from_markup``
(``TextArea``'s line path if it ever used it — and the DataTable cells) vs
Textual's ``Content.from_markup`` (``Static`` / ``Select`` labels), which
REJECTS an unquoted ``[link=...]`` with ``MarkupError`` rather than injecting.
So a crash-only payload set is INSUFFICIENT: ``[red]PWNED[/red]`` raises
nothing under rich and injects a span **silently**. Every payload below is
asserted on BOTH axes — text verbatim AND no payload-derived style.

MEASURED RED LEDGER — every mutation was APPLIED to the tree, the suite RUN,
the output READ, then reverted by inverse edit.

    M-1  `#patch_paste_text` reverted to a bare `TextArea` (drops the cap AND
         the colouring)
         -> 4 FAILED: test_capped_text_area::test_five_construction_sites
            (issubclass arm) + AT-079b (0 distinct token styles) + AT-079a
            (no `#patch_paste_gauge` — a bare TextArea took the whole compose
            block with it) + AT-079c (`_assert_no_wrapping` fired: a bare
            TextArea soft-wraps differently). ⚠ Only the FIRST TWO are the
            mutation's intended catch; AT-079a/c failed COLLATERALLY. Recorded
            because a mutation that trips four tests for three different
            reasons proves less than it appears to.
    M-2  the C-17 oracle applied to a `from_markup` TextArea (the natural wrong
         implementation, encoded as a POSITIVE CONTROL rather than prose)
         -> the AT-079c predicate REJECTS it: `[red]PWNED[/red]` renders as
            'PWNED' (brackets CONSUMED) carrying color=red. This is the
            measurement proving the re-pointed oracle discriminates — the thing
            the ORIGINAL `.spans` oracle could never have shown.
         ⚠ **And it is the mutation that exposed the CURSOR-LINE MASKING trap.**
            On line 0 the same unsafe widget paints ('WNED', '#e0e0e0') — the
            injection MASKED by `cursor_line_style` — so the first draft of
            this control "proved" the oracle discriminates using a line on
            which it cannot. See `_assert_off_cursor_line`.
    M-3  tokenizer emits CODEPOINT offsets instead of UTF-8 byte offsets
         -> 1 FAILED: TC-079.2 only (the non-ASCII span lands on the wrong
            characters: bytes[6:16] decoded to '"sensor→' instead of
            '"sensor→α"'). **AT-079b/c/d and AT-079a all PASSED** — a
            byte/codepoint bug is a correctness defect, not a security one,
            and it is SILENT (a missed lookup defaults to offset 0). That is
            precisely why m-2 needs its own POSITIVE oracle: no C-17 arm, and
            no no-raise assertion, can see it.
"""

from __future__ import annotations

import asyncio
import colorsys

from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Static, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui.insight_style import (
    CYAN,
    DGRAY,
    GREEN,
    HILITE,
    LBLUE,
    MAGENTA,
    PURPLE,
    RED,
    YELLOW,
    cap_gauge_style,
)
from s19_app.tui.json_highlight import (
    JsonHighlightTextArea,
    highlights_supported,
    tokenize_json_line,
)
from s19_app.tui.os_clipboard_input import _CLIPBOARD_READ_CAP_CHARS
from s19_app.tui.screens_directionb import PatchEditorPanel

# ---------------------------------------------------------------------------
# The LLR-079.3 payload set — spelled ONCE, reused by every C-17 arm
# ---------------------------------------------------------------------------

#: ⚠ Each payload attacks a DIFFERENT mechanism. A set that only crashes an
#: unsafe implementation is not enough (Inc-1b): `[red]...[/red]` raises
#: NOTHING under rich's grammar and injects a span silently, so the
#: no-payload-derived-style axis is what catches it.
_PAYLOADS = (
    # 1. A balanced rich tag pair. Injects SILENTLY — no exception. The
    #    discriminator for "does anything markup-parse this?".
    "[red]PWNED[/red]",
    # 2. An unmatched CLOSING tag. `Text.from_markup` RAISES on this.
    "[/nope]",
    # 3. A link tag — the one payload with a non-colour effect (`style.link`),
    #    so a "no colour changed" oracle alone would miss it.
    "[link=http://evil]click[/link]",
    # 4. An ANSI SGR escape — a different injection channel entirely (the
    #    terminal, not the markup parser).
    "\x1b[31mX\x1b[0m",
    # 5. An UNBALANCED opening bracket inside a plausible JSON string value —
    #    the JSON-specific hostile case. This is the one that looks like real
    #    change-set content, so it is the one most likely to reach the buffer
    #    by accident rather than by attack.
    '{"symbol": "sensor[unclosed", "v": 1}',
)


def _payload_buffer() -> str:
    """The payload set as a buffer: a control line, then ONE payload per line.

    ⚠ **Line 0 is a deliberate SACRIFICIAL control line, and that is
    load-bearing — see :func:`_segments`.** The cursor sits at (0, 0) and
    ``_render_line`` stylizes the WHOLE cursor line, MASKING any
    payload-derived colour on it. Every payload therefore lives on line >= 1.
    :func:`_assert_off_cursor_line` pins this so the arrangement cannot be
    lost in a later edit.
    """
    return "\n".join(('{"control": 1}',) + _PAYLOADS)


#: Document-line index of each payload in `_payload_buffer()` (0 = control).
_PAYLOAD_LINES = {payload: i + 1 for i, payload in enumerate(_PAYLOADS)}


def _segments(widget: TextArea, line_index: int) -> list[tuple[str, object]]:
    """The PAINTED result of DOCUMENT line ``line_index``: (text, style) per segment.

    This is the oracle §6.5 Amendment E re-points AT-079b/c onto. NOT
    ``get_line(i).spans`` — that accessor returns a fresh unstyled ``Text`` and
    is constant-true (see the module docstring).

    ⚠ **``_render_line(y)`` takes a VISUAL y, not a document line index** —
    measured, after this helper first read the wrong lines. ``y`` indexes the
    WRAPPED document, so at a narrow width one document line spans several
    ``y`` values and the mapping silently shifts: in the real panel at 120x30
    the buffer is ~17 cells wide, and ``_render_line(1)`` returned ``': 1}'``
    — the wrapped TAIL of line 0 — not the payload on document line 1. An
    oracle reading the wrong line is worse than no oracle: it reports on text
    that was never under test.

    Callers must therefore size the fixture so nothing wraps, which
    :func:`_assert_no_wrapping` asserts rather than assumes. Concatenating
    wrapped sections is NOT an option here: each visual line is padded to the
    widget width, so joining them injects spaces and breaks the verbatim
    assertion that is half of AT-079c.
    """
    return [(seg.text, seg.style) for seg in widget._render_line(line_index)]


def _assert_no_wrapping(widget: TextArea) -> None:
    """Pin the precondition that makes visual y == document line index.

    Without this the oracle degrades SILENTLY into reading the wrong lines
    (see :func:`_segments`) — it would not error, it would just assert on the
    wrong text. Fails loudly instead.
    """
    assert widget.wrapped_document.height == widget.document.line_count, (
        f"the fixture WRAPPED ({widget.wrapped_document.height} visual lines "
        f"for {widget.document.line_count} document lines) at widget width "
        f"{widget.size.width} — _render_line(y) indexes VISUAL lines, so every "
        f"assertion below would read the wrong text. Widen the regime or "
        f"shorten the fixture"
    )


def _assert_off_cursor_line(widget: TextArea, line_index: int) -> None:
    """Pin that ``line_index`` is NOT the cursor line — the masking trap.

    ⚠ **MEASURED, and it nearly cost this test its teeth.**
    ``_render_line`` (``_text_area.py:1460-1461``) does
    ``line.stylize(cursor_line_style)`` over the ENTIRE cursor line, AFTER any
    style the line already carries. rich's later span wins, so the cursor line
    OVERWRITES a payload-derived colour with the theme's own.

    Measured on the unsafe positive control, both lines markup-parsed:

        line 0 (cursor): [('P', '#121212'), ('WNED', '#e0e0e0')]  <- MASKED
        line 1         : [('SECOND', 'red')]                      <- injected

    So a C-17 test that placed its payload on line 0 would PASS on a
    markup-parsing buffer — a false green, in the batch's gate-blocking test,
    for a reason no reviewer would see by reading. This is the same class as
    the seven vacuous checks: an oracle that cannot observe what it claims to.
    """
    cursor_row, _ = widget.selection.end
    assert cursor_row != line_index, (
        f"line {line_index} is the CURSOR line; `_render_line` stylizes the "
        f"whole cursor line and would MASK a payload-derived style, making "
        f"this assertion a false green. Keep payloads on non-cursor lines"
    )


def _style_colors(segments: list[tuple[str, object]]) -> set[str]:
    """The distinct colour names painted across ``segments`` (blanks ignored)."""
    colors = set()
    for text, style in segments:
        if text.strip() and style is not None and style.color is not None:
            colors.add(style.color.name)
    return colors


def _assert_payload_is_inert(
    segments: list[tuple[str, object]], payload: str, where: str
) -> None:
    """AT-079c's predicate: ``payload`` painted VERBATIM and carrying NO style
    of its own.

    Both halves are load-bearing and neither implies the other:

    * **Verbatim** catches a parser that CONSUMED the markup — `[red]X[/red]`
      rendering as `X` with the tags eaten.
    * **No payload-derived style** catches a parser that HONOURED the markup —
      the silent case, where the text survives but `PWNED` comes out red, or
      `click` comes out as a live link.

    Asserted against the CONTROL line's own painted colour, so the reference is
    what this widget paints for trusted text rather than a hardcoded hex.
    """
    painted = "".join(text for text, _ in segments)
    assert payload in painted, (
        f"{where}: the payload must paint VERBATIM on the render path; "
        f"{payload!r} is absent from {painted.rstrip()!r} — a markup parser "
        f"consumed it"
    )
    for text, style in segments:
        if not text.strip() or style is None:
            continue
        assert style.link in (None, ""), (
            f"{where}: a payload-derived LINK was applied to {text!r} — the "
            f"[link=...] payload reached a markup parser"
        )
        assert not style.bold and not style.italic, (
            f"{where}: payload-derived emphasis on {text!r}"
        )


# ===========================================================================
# AT-079c ★★ — C-17 GATE-BLOCKING: hostile paste is inert on the RENDER PATH
# ===========================================================================


def test_at079c_hostile_paste_renders_literally() -> None:
    """★★ The full LLR-079.3 payload set paints verbatim, inert, and raises nothing.

    GATE-BLOCKING. Observed on ``_render_line(y)`` — the painted result — per
    §6.5 Amendment E; the locked ``.spans`` oracle was constant-true (module
    docstring). ``test_tc079_3_c17_oracle_discriminates`` proves this predicate
    can fail.
    """

    async def _run() -> dict[str, list[tuple[str, object]]]:
        app = S19TuiApp()
        # 80x24 STACKS the three windows, giving the JSON buffer ~60 cells —
        # wide enough that no payload wraps. At 120x30 the buffer is ~17 cells
        # and every payload wraps, which would silently mis-index the oracle
        # (see `_segments`). The regime is a measurement constraint on the
        # observation point, not a claim that 120x30 is safe: the render path
        # is width-independent, and `_assert_no_wrapping` fails loudly if this
        # assumption ever stops holding.
        async with app.run_test(size=(80, 24)) as pilot:
            app.action_show_screen("patch")
            await pilot.pause()
            buffer = app.query_one("#patch_paste_text", JsonHighlightTextArea)
            # Through the real surface: replace the buffer's whole document.
            buffer.text = _payload_buffer()
            await pilot.pause()
            _assert_no_wrapping(buffer)
            painted = {"__control__": _segments(buffer, 0)}
            for payload, line_index in _PAYLOAD_LINES.items():
                _assert_off_cursor_line(buffer, line_index)
                painted[payload] = _segments(buffer, line_index)
            return painted

    # 0 raises is asserted by the run completing: a MarkupError anywhere on the
    # render path surfaces here.
    painted = asyncio.run(_run())

    for payload in _PAYLOADS:
        _assert_payload_is_inert(
            painted[payload], payload, f"payload {payload!r}"
        )

    # The token hues may NOT be attributed to a payload's own bracket text.
    # Payload 5 is legitimately JSON, so its KEYS colour — that is correct
    # behaviour, not injection; what must not happen is the BRACKETS earning a
    # style. Asserted precisely: the unbalanced-bracket run paints in the same
    # colour as an ordinary JSON string value.
    json_payload = _PAYLOADS[4]
    bracket_segments = [
        (text, style)
        for text, style in painted[json_payload]
        if "sensor[unclosed" in text
    ]
    assert bracket_segments, (
        f"the unbalanced-bracket value must survive as painted text; got "
        f"{[t for t, _ in painted[json_payload]]!r}"
    )
    assert all(
        style.color.name == LBLUE for _, style in bracket_segments
    ), (
        f"the unbalanced bracket must paint as an ORDINARY json.string "
        f"({LBLUE}) — its bracket earns no style of its own; got "
        f"{[(t, s.color.name) for t, s in bracket_segments]!r}"
    )


# ===========================================================================
# TC-079.3 — the C-17 ORACLE IS ITSELF UNDER TEST (the anti-vacuity arm)
# ===========================================================================


class _UnsafeMarkupTextArea(TextArea):
    """The natural WRONG implementation: markup-parse each line.

    This is the exact shortcut LLR-079.1 struck and §2.4-4b names as "the only
    way this surface becomes unsafe". Encoded as a POSITIVE CONTROL so the
    AT-079c predicate's ability to fail is a measurement, not a claim.
    """

    def get_line(self, line_index: int) -> Text:  # type: ignore[override]
        return Text.from_markup(self.document.get_line(line_index))


def test_tc079_3_c17_oracle_discriminates() -> None:
    """AT-079c's predicate REJECTS a markup-parsing buffer (the anti-vacuity proof).

    ⚠ **This arm exists because the ORIGINAL AT-079c could not fail.** Its
    ``.spans`` oracle read ``[]`` on safe and unsafe implementations alike, so
    the batch's gate-blocking C-17 test was non-evidence. Re-pointing it to the
    painted result is only an improvement if the new oracle actually
    discriminates — so this test applies the unsafe implementation and asserts
    the predicate catches it.

    ``[red]PWNED[/red]`` is the payload that makes the point: under rich's
    grammar it raises NOTHING. An unsafe buffer renders it as ``PWNED`` in red
    — text silently rewritten, style silently injected — and a crash-only
    oracle would call that a pass.

    ⚠ The control observes line **1**, not line 0, for the reason
    :func:`_assert_off_cursor_line` records: the cursor line's own styling
    MASKS the injected colour. Measured on this very widget — line 0 paints
    ``[('P', '#121212'), ('WNED', '#e0e0e0')]`` while line 1 paints
    ``[('SECOND', 'red')]``. Had the control sat on line 0 it would have shown
    "no injection" on a provably unsafe buffer, and this whole arm would have
    certified the oracle using a measurement the oracle cannot make.
    """

    class _Host(App):
        def compose(self) -> ComposeResult:
            yield _UnsafeMarkupTextArea(
                '{"control": 1}\n[red]PWNED[/red]', id="unsafe"
            )

    async def _run() -> list[tuple[str, object]]:
        app = _Host()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            widget = app.query_one("#unsafe", _UnsafeMarkupTextArea)
            _assert_no_wrapping(widget)
            _assert_off_cursor_line(widget, 1)
            return _segments(widget, 1)

    unsafe_segments = asyncio.run(_run())

    # The unsafe buffer really did honour the markup — measured, not assumed.
    painted = "".join(text for text, _ in unsafe_segments)
    assert "PWNED" in painted and "[red]" not in painted, (
        f"the positive control must actually be unsafe (markup consumed); got "
        f"{painted!r} — if this fires, the control no longer controls anything"
    )
    injected = {
        style.color.name
        for text, style in unsafe_segments
        if "PWNED" in text and style is not None and style.color is not None
    }
    assert "red" in injected, (
        f"the positive control must carry the INJECTED style; got {injected!r}"
    )

    # ...and the AT-079c predicate REJECTS it. This is the whole point.
    try:
        _assert_payload_is_inert(
            unsafe_segments, "[red]PWNED[/red]", "positive control"
        )
    except AssertionError:
        pass
    else:
        raise AssertionError(
            "AT-079c's predicate PASSED a markup-parsing buffer — the oracle "
            "cannot fail and is therefore non-evidence, which is exactly the "
            "defect this arm exists to prevent recurring"
        )


# ===========================================================================
# AT-079b — structure differentiated IN PLACE (>= 3 distinct token styles)
# ===========================================================================


def test_at079b_structure_differentiated_in_place() -> None:
    """The pasted change-set's structure is differentiated on the RENDER PATH.

    Single pass condition (the ``or`` was struck at registry reconciliation):
    >= 3 distinct token styles across the painted lines, ``.plain`` verbatim,
    correct under non-ASCII, surviving an edit.

    Observed on ``_render_line`` per §6.5 Amendment E — the locked
    ``get_line(i).spans`` oracle is structurally incapable of carrying a span.
    """

    async def _run() -> tuple[set[str], str, set[str]]:
        app = S19TuiApp()
        # 80x24 — the JSON buffer is ~60 cells here, so the fixture does not
        # wrap and `_render_line`'s visual y maps to the document line.
        async with app.run_test(size=(80, 24)) as pilot:
            app.action_show_screen("patch")
            await pilot.pause()
            buffer = app.query_one("#patch_paste_text", JsonHighlightTextArea)
            # Line 0 is sacrificed to the cursor (whose line-styling would mask
            # the token hues, `_assert_off_cursor_line`); the JSON under test
            # sits on line 1.
            buffer.text = '{}\n{"a": 1, "b": "hi", "c": true}'
            await pilot.pause()
            _assert_no_wrapping(buffer)
            _assert_off_cursor_line(buffer, 1)
            before = _style_colors(_segments(buffer, 1))
            painted_text = "".join(t for t, _ in _segments(buffer, 1))
            # m-3: spans must survive an EDIT, not just the initial load.
            buffer.insert(" ")
            await pilot.pause()
            after = _style_colors(_segments(buffer, 1))
            return before, painted_text, after

    before, painted_text, after = asyncio.run(_run())

    token_hues = {CYAN, LBLUE, PURPLE, HILITE}
    painted_tokens = {c for c in before if c in token_hues}
    assert len(painted_tokens) >= 3, (
        f"the buffer must paint >= 3 DISTINCT token styles in place; got "
        f"{painted_tokens!r} from {before!r}"
    )
    assert '{"a": 1, "b": "hi", "c": true}' in painted_text, (
        f"the document text must paint verbatim; got {painted_text!r}"
    )
    # m-3 — `_build_highlight_map` CLEARS the map on every edit; the override
    # re-populates on that same hook. Without it the buffer goes grey on the
    # first keystroke.
    surviving = {c for c in after if c in token_hues}
    assert len(surviving) >= 3, (
        f"token styles must SURVIVE an edit (the base clears _highlights on "
        f"every rebuild); got {surviving!r} after inserting a space"
    )


# ===========================================================================
# TC-079.2 — byte offsets, not codepoints (m-2): the SILENT non-ASCII trap
# ===========================================================================


def test_tc079_2_non_ascii_byte_offsets() -> None:
    """Non-ASCII lines style at the CORRECT offsets (UTF-8 bytes, not codepoints).

    WHY this needs a POSITIVE oracle rather than a no-raise assertion: the
    failure is SILENT. ``_render_line`` maps spans via
    ``byte_to_codepoint.get(start, 0)`` (``_text_area.py:1496-1506``) and a
    missed lookup **defaults to 0**, styling from the line's start with no
    error. A codepoint-offset tokenizer therefore misstyles multi-byte pastes
    quietly — it never crashes, so only an assertion on WHICH characters got
    the style can see it.
    """
    line = '{"n": "sensor→α", "v": 12}'
    spans = tokenize_json_line(line)

    encoded = line.encode("utf-8")
    for start, end, name in spans:
        decoded = encoded[start:end].decode("utf-8")
        if name == "json.string":
            assert decoded == '"sensor→α"', (
                f"the json.string span must cover exactly the string token; "
                f"bytes[{start}:{end}] decoded to {decoded!r}"
            )
    # The trap made concrete: the multi-byte characters sit BEFORE the last
    # token, so a codepoint tokenizer would place this span too early.
    number_spans = [s for s in spans if s[2] == "json.number"]
    assert len(number_spans) == 1
    start, end, _ = number_spans[0]
    assert encoded[start:end].decode("utf-8") == "12", (
        f"the number span must land on '12' AFTER the multi-byte characters; "
        f"bytes[{start}:{end}] = {encoded[start:end]!r}"
    )


# ===========================================================================
# AT-079d — the FALLBACK path itself (the branch CI cannot reach at the pin)
# ===========================================================================


def test_at079d_feature_detect_fallback(monkeypatch) -> None:
    """Internals unavailable -> the buffer renders UNSTYLED and raises nothing.

    ``_highlights`` / ``_build_highlight_map`` are private Textual internals
    (A9 / R8): present at the ``textual==8.2.8`` pin, not guaranteed across the
    ``textual>=8.0.2`` runtime floor. The feature gate keeps the failure mode
    COSMETIC — which is the recorded basis of the operator's in-place decision,
    so it is the branch that decision rests on, and CI can never reach it
    naturally.

    ⚠ This is an ABSENCE assertion, which makes it the most vacuity-prone
    shape in the file: anything that hides the styles makes it pass. So the
    JSON sits on line 1, off the cursor line whose own styling would MASK the
    token hues and green this test on a buffer that was colouring perfectly
    (:func:`_assert_off_cursor_line`). Mutation-verified at Inc-5: with the
    monkeypatch REMOVED this test goes RED, which is the proof that it
    observes the fallback rather than the masking.
    """
    monkeypatch.setattr(
        "s19_app.tui.json_highlight.highlights_supported", lambda widget: False
    )

    class _Host(App):
        def compose(self) -> ComposeResult:
            yield JsonHighlightTextArea('{}\n{"a": 1, "b": true}', id="ta")

    async def _run() -> tuple[set[str], str]:
        app = _Host()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            buffer = app.query_one("#ta", JsonHighlightTextArea)
            _assert_no_wrapping(buffer)
            _assert_off_cursor_line(buffer, 1)
            segments = _segments(buffer, 1)
            return _style_colors(segments), "".join(t for t, _ in segments)

    colors, painted = asyncio.run(_run())

    token_hues = {CYAN, LBLUE, PURPLE, HILITE}
    assert not (colors & token_hues), (
        f"with the feature-detect forced false the buffer must render "
        f"UNSTYLED; got token hues {colors & token_hues!r}"
    )
    assert '{"a": 1, "b": true}' in painted, (
        f"the degraded buffer must still paint its text verbatim; got "
        f"{painted!r}"
    )
    assert highlights_supported(object()) is False


# ===========================================================================
# AT-079a — the gauge tracks the buffer against the 64 KiB cap
# ===========================================================================


def test_at079a_gauge_tracks_buffer() -> None:
    """The gauge reads the buffer's size against the cap, incl. the at-cap boundary.

    The cap is ``_CLIPBOARD_READ_CAP_CHARS`` **chars** — the truncation is a
    character slice (``os_clipboard_input.py:253``), so the gauge is
    char-denominated. A byte-denominated gauge would disagree with the
    truncation it exists to predict on any non-ASCII paste.
    """
    panel = PatchEditorPanel.__new__(PatchEditorPanel)

    # Empty -> 0 (the boundary catalog's `empty`).
    assert panel._paste_gauge_text(0).plain == "0.0K / 64.0K"
    # A known size tracks it.
    assert panel._paste_gauge_text(32768).plain == "32.0K / 64.0K"
    # AT the cap (the boundary catalog's `boundary`): the first point at which
    # the next pasted character is silently dropped.
    assert (
        panel._paste_gauge_text(_CLIPBOARD_READ_CAP_CHARS).plain
        == "64.0K / 64.0K"
    )

    # ...and it is LIVE on the real surface: the gauge follows the buffer.
    async def _run() -> tuple[str, str]:
        app = S19TuiApp()
        async with app.run_test(size=(120, 30)) as pilot:
            app.action_show_screen("patch")
            await pilot.pause()
            gauge = app.query_one("#patch_paste_gauge", Static)
            buffer = app.query_one("#patch_paste_text", JsonHighlightTextArea)
            buffer.text = "x" * 4096
            await pilot.pause()
            small = gauge.render_line(0).text.strip()
            buffer.text = "y" * 40960
            await pilot.pause()
            return small, gauge.render_line(0).text.strip()

    small, large = asyncio.run(_run())
    # C-10(a): asserted as a CHANGE off a prior state, so a gauge that never
    # re-rendered cannot pass by happening to read a plausible number.
    assert small == "4.0K / 64.0K", f"got {small!r}"
    assert large == "40.0K / 64.0K", f"got {large!r}"


# ===========================================================================
# TC-079.5 — the gauge's NEW hue: measured distance from every claimant
# ===========================================================================


def _hue_degrees(hex_color: str) -> float:
    """The HSV hue angle of ``#rrggbb``, in degrees."""
    r, g, b = (int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5))
    return colorsys.rgb_to_hsv(r, g, b)[0] * 360.0


def _hue_distance(a: float, b: float) -> float:
    """The shorter arc between two hue angles, in degrees."""
    delta = abs(a - b) % 360.0
    return min(delta, 360.0 - delta)


#: Every hue already claimed inside the app, with what claims it. Orange is
#: included as TWO entries because Amendment F re-scoped it to a MAC-specific
#: cue rather than removing it: `orange3` (the `⚠` record glyph + the frozen
#: `MAC_ADDRESS_OVERLAY_STYLE`) and `#d9a35b` (`.mac_out_of_range`).
_CLAIMED_HUES = {
    "RED (verdict)": RED,
    "YELLOW (verdict + app-wide warning)": YELLOW,
    "GREEN (verdict)": GREEN,
    "CYAN (address role / checks chip / .sev-info)": CYAN,
    "HILITE (entry chip)": HILITE,
    "LBLUE (json.string / secondary)": LBLUE,
    "PURPLE (kind role / apply chip)": PURPLE,
    "orange3 (MAC record glyph + hex overlay)": "#d75f00",
    "mac_out_of_range (Sections labels)": "#d9a35b",
}

#: The operator's constraint, as a number: the gauge's hue must not be
#: confusable with ANY claimant. Inc-2b measured HILITE<->CYAN at 23.5deg and
#: accepted that pair as "closest, still distinct", so 40 is comfortable.
_MIN_HUE_SEPARATION_DEG = 40.0


def test_tc079_5_magenta_hue_distance() -> None:
    """The gauge's hue is >= 40deg from EVERY claimed hue (operator ruling).

    ⚠ **MEASURED, not eyeballed — and the measurement changed the answer.**
    The ruling authorised a new hue for the cap gauge (the first this batch)
    because the palette is at capacity, but constrained it: it must NOT reuse
    GREEN/YELLOW/RED, so nothing in ``#patch_editor_panel`` can be misread as a
    VERDICT, and it must not be confusable with anything else either.

    **Orange was rejected up front** — it looks free inside the patch panel but
    at ~26deg it sits BETWEEN RED (0deg) and YELLOW (65deg), the two hues most
    confusable with a verdict, and it is the MAC cue Amendment F preserved.

    **The same test rejects the global optimum**, which is the finding worth
    keeping: a full-circle scan shows only TWO arcs clear 40deg from every
    claimant — **[313.9, 320.0]** (magenta) and **[104.9, 114.8]** (a lime).
    The lime's minimum distance is LARGER (45.0 vs 43.1), and it is still
    wrong: at ~110deg it sits between YELLOW (65deg) and GREEN (155deg) —
    flanked by two verdict hues, the exact geometry that disqualified Orange.
    Distance from the nearest claimant is a necessary condition, not the
    objective; "not sitting between two verdicts" is the objective.

    The admissible arc is **6.1deg wide**, which is why this is a test and not
    a comment: MAGENTA cannot be re-picked by eye without re-running this.
    """
    magenta_hue = _hue_degrees(MAGENTA)

    distances = {
        claimant: _hue_distance(magenta_hue, _hue_degrees(hex_color))
        for claimant, hex_color in _CLAIMED_HUES.items()
    }
    for claimant, distance in sorted(distances.items(), key=lambda kv: kv[1]):
        assert distance >= _MIN_HUE_SEPARATION_DEG, (
            f"MAGENTA ({MAGENTA}, hue {magenta_hue:.1f}deg) is only "
            f"{distance:.1f}deg from {claimant} — under the "
            f"{_MIN_HUE_SEPARATION_DEG}deg floor the operator's "
            f"non-confusability ruling requires. Full measurement: "
            f"{ {k: round(v, 1) for k, v in distances.items()} }"
        )

    # The ruling's PRIMARY clause, asserted directly rather than inferred from
    # an angle: the gauge may never paint a verdict hue.
    assert MAGENTA not in {GREEN, YELLOW, RED}, (
        "the gauge's hue must not BE a verdict hue"
    )
    # It sits in the measured admissible arc, not merely far from its nearest
    # neighbour — this is what excludes the lime.
    assert 313.9 <= magenta_hue <= 320.0, (
        f"MAGENTA's hue ({magenta_hue:.1f}deg) must sit in the measured "
        f"admissible arc [313.9, 320.0]. The other >=40deg arc "
        f"([104.9, 114.8], a lime) is REJECTED: it lies between YELLOW and "
        f"GREEN, i.e. between two verdicts"
    )


def test_tc079_5b_cap_gauge_escalates_without_verdict_hues() -> None:
    """``cap_gauge_style`` escalates within ONE family and never returns a verdict hue.

    The operator's ruling has two halves and this pins both: the gauge
    ESCALATES (Amendment F's semantics — a filling buffer is a warning), and it
    escalates WITHOUT the verdict palette. ``threshold_style`` returns exactly
    GREEN/YELLOW/RED, which is why it is not reused here.

    Escalation rides INTENSITY within the magenta family rather than three new
    hues — the smallest addition that reads as escalation, and the shape the
    palette already uses (HILITE and LBLUE are the same hue at 38.6% and 19.4%
    saturation, measured 0.2deg apart).
    """
    warn, bad = 75.0, 100.0

    steps = [cap_gauge_style(pct, warn, bad) for pct in (0.0, 50.0, 74.9)]
    assert set(steps) == {DGRAY}, f"below warn the gauge stays quiet; got {steps!r}"
    # Lower-inclusive bands, asserted AT each cutoff (the off-by-one surface).
    assert cap_gauge_style(warn, warn, bad) == MAGENTA
    assert cap_gauge_style(99.9, warn, bad) == MAGENTA
    assert cap_gauge_style(bad, warn, bad) == f"bold {MAGENTA}"
    # Over the cap is not a new state — content is already being dropped.
    assert cap_gauge_style(150.0, warn, bad) == f"bold {MAGENTA}"

    # The three steps are mutually DISTINCT (an escalation nobody can see is
    # not an escalation) ...
    distinct = {
        cap_gauge_style(pct, warn, bad) for pct in (0.0, warn, bad)
    }
    assert len(distinct) == 3, f"the three bands must be distinguishable; got {distinct!r}"
    # ... and NONE of them is a verdict hue. This is the ruling, as an
    # assertion: no reachable input paints the gauge green/yellow/red.
    for pct in (0.0, 25.0, 74.9, 75.0, 99.9, 100.0, 150.0, -5.0):
        style = cap_gauge_style(pct, warn, bad)
        for verdict_name, verdict in (
            ("GREEN", GREEN),
            ("YELLOW", YELLOW),
            ("RED", RED),
        ):
            assert verdict not in style, (
                f"cap_gauge_style({pct}) returned {style!r}, which carries the "
                f"{verdict_name} VERDICT hue — inside #patch_editor_panel that "
                f"reads as a check result, which is what the operator ruled out"
            )
