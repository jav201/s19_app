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
import pathlib
import re

from rich.color import Color
from rich.style import Style
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
    _JSON_SYNTAX_STYLES,
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


#: The hues the JSON highlighter legitimately paints, READ FROM THE HIGHLIGHTER
#: rather than restated. A payload wearing one of these is not evidence of
#: injection (payload 5 is genuine JSON and correctly highlights); a payload
#: wearing anything else is. Bound to the source dict so a re-theme of the
#: highlighter cannot silently widen or narrow this oracle.
_TOKEN_HUES = {
    style.color.name
    for style in _JSON_SYNTAX_STYLES.values()
    if style.color is not None
}


def _assert_payload_is_inert(
    segments: list[tuple[str, object]],
    payload: str,
    where: str,
    control_segments: list[tuple[str, object]],
) -> None:
    """AT-079c's predicate: ``payload`` painted VERBATIM and carrying NO style
    of its own.

    Both halves are load-bearing and neither implies the other:

    * **Verbatim** catches a parser that CONSUMED the markup — `[red]X[/red]`
      rendering as `X` with the tags eaten.
    * **No payload-derived style** catches a parser that HONOURED the markup —
      the silent case, where the text survives but `PWNED` comes out red, or
      `click` comes out as a live link.

    ⚠ **Inc-5b added the COLOUR axis, which Inc-5 documented but never wrote.**
    Inc-5's version checked ``link`` / ``bold`` / ``italic`` and stopped — it
    never read ``style.color`` — yet this docstring's closing line described
    comparing against the control line's painted colour, and three further
    artifacts (§6.5 Amendment E's "fails on both axes", the AT-079c notes, the
    commit message) claimed a colour check that did not exist. Measured: the
    Inc-5 predicate PASSES on ``[('[red]PWNED[/red]', Style(color='red'))]`` —
    text verbatim, painted red, no complaint.

    This was **not** a false green: the gate discriminated via the verbatim axis,
    because every payload that reaches a real markup parser gets CONSUMED. But
    that is the Inc-1b rule exactly — *assert plain verbatim AND spans, or the
    fix is guarded by accident* — and it was accidental in precisely that way. A
    realistic escape: a highlighter extension that STYLES ``[red]`` without
    CONSUMING it (a regex tokenizer that colours bracket runs) paints verbatim
    and meets no colour check.

    The reference is the CONTROL line's own painted colours plus the legitimate
    token hues, so the oracle is what this widget paints for TRUSTED text rather
    than a hardcoded hex — a restyle moves both sides together.

    Args:
        segments: ``(text, style)`` pairs from ``_render_line`` for the payload.
        payload: The hostile string that must survive verbatim and inert.
        where: Human label for assertion messages.
        control_segments: The same, for the trusted CONTROL line — the colour
            reference. Without it a colour assertion would need a hardcoded hex.
    """
    painted = "".join(text for text, _ in segments)
    assert payload in painted, (
        f"{where}: the payload must paint VERBATIM on the render path; "
        f"{payload!r} is absent from {painted.rstrip()!r} — a markup parser "
        f"consumed it"
    )
    # Colours the widget legitimately paints for TRUSTED text: the control
    # line's own, plus the JSON token hues (payload 5 is real JSON, so its keys
    # and strings correctly colour — that is highlighting, not injection).
    permitted = _style_colors(control_segments) | _TOKEN_HUES
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
        if style.color is None:
            continue
        assert style.color.name in permitted, (
            f"{where}: payload-derived COLOUR {style.color.name!r} on {text!r}. "
            f"The widget paints trusted text in {sorted(permitted)!r}; this hue "
            f"came from the payload's own markup, i.e. a parser HONOURED it "
            f"without consuming it"
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
            painted[payload],
            payload,
            f"payload {payload!r}",
            painted["__control__"],
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

    async def _run() -> tuple[list[tuple[str, object]], list[tuple[str, object]]]:
        app = _Host()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            widget = app.query_one("#unsafe", _UnsafeMarkupTextArea)
            _assert_no_wrapping(widget)
            _assert_off_cursor_line(widget, 1)
            return _segments(widget, 1), _segments(widget, 0)

    unsafe_segments, control_segments = asyncio.run(_run())

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
            unsafe_segments,
            "[red]PWNED[/red]",
            "positive control",
            control_segments,
        )
    except AssertionError:
        pass
    else:
        raise AssertionError(
            "AT-079c's predicate PASSED a markup-parsing buffer — the oracle "
            "cannot fail and is therefore non-evidence, which is exactly the "
            "defect this arm exists to prevent recurring"
        )


def test_tc079_3b_inert_predicate_colour_axis_discriminates() -> None:
    """The COLOUR axis of the inert predicate fires on its own (Inc-5b).

    ⚠ **This arm is the reason Inc-5b's F2 fix is a fix and not a gesture.**
    ``test_tc079_3_c17_oracle_discriminates`` cannot certify the colour axis: its
    unsafe buffer CONSUMES the markup, so the predicate already fails on the
    VERBATIM axis and would fail identically with no colour check at all — which
    is precisely how Inc-5 shipped a documented-but-absent colour axis without
    any test noticing. Adding an axis and certifying it with an arm that cannot
    isolate it would repeat this batch's signature defect one level up.

    So this probes the axis directly, against the realistic escape the axis
    exists to catch: a highlighter that STYLES ``[red]`` without CONSUMING it (a
    regex tokenizer extension that colours bracket runs). Such a renderer paints
    the payload verbatim — passing the verbatim axis — and is caught only here.
    """
    control = [('{"control": 1}', Style(color=LBLUE))]
    payload = "[red]PWNED[/red]"

    # Sanity: a renderer that paints the payload verbatim and INERT passes. If
    # this raised, the arm below would prove nothing about the colour axis.
    _assert_payload_is_inert(
        [(payload, Style(color=LBLUE))], payload, "inert probe", control
    )

    # The escape: verbatim, but wearing a hue the widget never paints.
    try:
        _assert_payload_is_inert(
            [(payload, Style(color="red"))], payload, "styled probe", control
        )
    except AssertionError as exc:
        assert "COLOUR" in str(exc), (
            f"the predicate rejected the styled probe, but not via the colour "
            f"axis — got {exc}. The axis is still unproven"
        )
    else:
        raise AssertionError(
            "the inert predicate PASSED a payload painted in a hue the widget "
            "never paints for trusted text. This is the Inc-5 F2 defect "
            "recurring: the colour axis is documented but not enforced"
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


def _named_hex(name: str) -> str:
    """Resolve a rich colour NAME (``"orange3"``) to ``#rrggbb`` via rich itself.

    ⚠ Resolved, never transcribed. Inc-5 hand-wrote ``orange3`` as ``#d75f00``
    and measured a hue **the app never paints** — ``#d75f00`` is
    ``darkorange3``; rich resolves ``orange3`` to ``#d78700``, 11deg away. The
    app names these colours, so the app's own resolver is the only oracle for
    what they paint.
    """
    rgb = Color.parse(name).get_truecolor()
    return f"#{rgb.red:02x}{rgb.green:02x}{rgb.blue:02x}"


#: Every chromatic hue painted anywhere in the app, with its LIVE site.
#:
#: ⚠ **Inc-5b: this census was WRONG and the error was invisible.** Inc-5 shipped
#: a nine-entry hand-curated list that OMITTED ``#e06c75`` — which sits 38.4deg
#: from the hue this test certifies, i.e. BELOW Inc-5's own 40deg floor. The test
#: passed only because its INPUT SET omitted the input that would fail it: a
#: vacuous input set, not a vacuous assertion (the arithmetic was exact). No
#: mutation of the code under test can catch that — the mutant passes too. The
#: fix is therefore NOT "add the missing entry"; it is
#: :func:`test_tc079_5c_hue_census_is_complete`, which mechanically proves this
#: dict accounts for every colour literal in ``s19_app/``. Hand-curation is fine;
#: UNCHECKED hand-curation is what failed.
#:
#: Two further Inc-5 errors this census corrects, both found by that sweep:
#:
#: * ``orange3`` was recorded as ``#d75f00`` (26.5deg). Rich resolves ``orange3``
#:   to **#d78700 (37.7deg)**; ``#d75f00`` is ``darkorange3``. Inc-5 measured a
#:   colour the app never paints.
#: * The rich NAMED severity styles (``app.py::_SEVERITY_TO_RICH_STYLE`` and the
#:   ``_MAC_GLYPH_*`` pairs) were omitted wholesale. ``green`` is **#008000
#:   (120deg)** — NOT ``GREEN`` ``#54efae`` (154.8deg). This omission is what
#:   invented the "rejected lime arc" (see the test docstring).
_CLAIMED_HUES = {
    "RED (verdict)": RED,
    "YELLOW (verdict + app-wide warning)": YELLOW,
    "GREEN (verdict)": GREEN,
    "CYAN (address role / checks chip / .sev-info)": CYAN,
    "HILITE (entry chip)": HILITE,
    "LBLUE (json.string / secondary)": LBLUE,
    "PURPLE (kind role / apply chip)": PURPLE,
    # Amendment F re-scoped Orange to MAC-specific cues rather than removing it,
    # so it is claimed at BOTH of its surviving sites (orange3 is resolved below).
    "mac_out_of_range (Sections labels; styles.tcss:526)": "#d9a35b",
    # The three Inc-5 omitted. #e06c75 is the one that breaks Inc-5's floor.
    "band-high + AbDiffPanel only_a (tcss:579, screens_directionb.py:4269)": "#e06c75",
    "AbDiffPanel only_b (screens_directionb.py:4270)": "#4ec9d4",
    "band-low (styles.tcss:571)": "#5fb98a",
    # Rich NAMED styles: not hex, so the source sweep cannot see them. RESOLVED
    # through rich rather than transcribed — transcribing is how Inc-5 recorded
    # orange3 as #d75f00 (darkorange3) and measured a hue the app never paints.
    "orange3 (MAC ⚠ glyph + frozen MAC_ADDRESS_OVERLAY_STYLE)": _named_hex("orange3"),
    "rich 'green' (ValidationSeverity.OK + ✓ MAC glyph)": _named_hex("green"),
    "rich 'red' (ValidationSeverity.ERROR + ✗ MAC glyph)": _named_hex("red"),
}

#: Colour literals in ``s19_app/`` that are deliberately NOT hue claimants, each
#: with the reason. The completeness guard requires every swept literal to be
#: either claimed above or excluded HERE — an omission fails the guard rather
#: than silently shrinking the census, which is precisely the Inc-5 defect.
_EXCLUDED_LITERALS = {
    # --- HTML diff-report export: rendered by a BROWSER, never by the TUI. It
    # is a separate document with its own (solarized) palette and shares no
    # container with the gauge, so hue collision there is not confusable.
    "#b58900": "diff_report_service HTML export — browser surface, not the TUI",
    "#dc322f": "diff_report_service HTML export — browser surface, not the TUI",
    "#268bd2": "diff_report_service HTML export — browser surface, not the TUI",
    "#ffd54d": "diff_report_service HTML changed-byte span — browser surface",
    "#fdf6e3": "diff_report_service HTML body background — browser surface",
    "#073642": "diff_report_service HTML body text — browser surface",
    "#93a1a1": "diff_report_service HTML table borders — browser surface",
    "#000000": "diff_report_service HTML kind fallback + changed-byte contrast",
    # --- DEPTH_* navy stack: BACKGROUNDS at value <= 22.7%. A hue is only
    # confusable when it paints a foreground cue; these are near-black fills
    # behind every cue, including the gauge.
    "#0a0e1b": "DEPTH_BG — background fill (val 10.6%), not a foreground cue",
    "#0f1525": "DEPTH_PANEL — background fill (val 14.5%), not a foreground cue",
    "#131a2c": "DEPTH_ODD_ROW — background fill (val 17.3%), not a foreground cue",
    "#1b233a": "DEPTH_BORDER — border fill (val 22.7%), not a foreground cue",
    # --- Achromatic / near-achromatic: hue is not a meaningful coordinate below
    # ~20% saturation — these read as grey, so no hue distance protects anything.
    # (LBLUE is 19.4% and is nonetheless CLAIMED above: claimed beats excluded.)
    "#ffffff": "achromatic (sat 0%) — AbDiffPanel unknown-kind fallback",
    "#e9e9e9": "achromatic (sat 0%) — insight_style.VALUE",
    "#c5c7d2": "near-achromatic (sat 6.2%) — insight_style.LABEL",
    "#969aad": "near-achromatic (sat 13.3%) — insight_style.DGRAY",
    "#6b7280": "near-achromatic (sat 16.4%) — .band-constant / truncation note",
}

#: The floor, and it is NOT the constraint — see the test docstring. Anchored to
#: a measurement the repo already made and accepted rather than to a number
#: invented at the gate: Inc-2b measured HILITE<->CYAN at **23.5deg** and ruled
#: that pair "closest, still distinct". The gauge must beat the closest pair the
#: app already ships and accepts. It clears this by ~17deg; the binding
#: constraints are the flank rule and the optimality assertion below.
_MIN_HUE_SEPARATION_DEG = 24.0

#: How far MAGENTA may fall short of the provable optimum (quantisation slack on
#: the 0.01deg scan + the 8-bit sRGB grid the hex must land on).
_HUE_OPTIMALITY_TOLERANCE_DEG = 0.25


def _min_claimed_distance(hue: float) -> tuple[float, str]:
    """The nearest claimant to ``hue``: its distance in degrees, and its name."""
    claimant, hex_color = min(
        _CLAIMED_HUES.items(),
        key=lambda kv: _hue_distance(hue, _hue_degrees(kv[1])),
    )
    return _hue_distance(hue, _hue_degrees(hex_color)), claimant


def _is_verdict_flanked(hue: float) -> bool:
    """Whether ``hue`` sits BETWEEN two verdict hues — the actual objective.

    The three verdict hues partition the circle into three arcs. Two of them are
    narrow (RED->YELLOW 64.8deg, YELLOW->GREEN 90.0deg); a hue inside either is
    read against a verdict on BOTH sides, which is what disqualified Orange. The
    third arc (GREEN->RED) is 205.2deg — the open field, where a hue has no
    verdict flanking it in any useful sense. So: flanked iff inside an arc
    narrower than a semicircle.
    """
    verdicts = sorted({_hue_degrees(c) for c in (RED, YELLOW, GREEN)})
    for index, low in enumerate(verdicts):
        high = verdicts[(index + 1) % len(verdicts)]
        width = (high - low) % 360.0
        if width >= 180.0:
            continue
        if (hue - low) % 360.0 < width:
            return True
    return False


def _admissible_optimum(step: float = 0.01) -> tuple[float, float]:
    """Scan the circle: the non-flanked hue FARTHEST from every claimant.

    Returns:
        tuple[float, float]: ``(hue_degrees, distance_to_nearest_claimant)``.
    """
    best_hue, best_distance = 0.0, -1.0
    for tick in range(int(360.0 / step)):
        hue = tick * step
        if _is_verdict_flanked(hue):
            continue
        distance, _ = _min_claimed_distance(hue)
        if distance > best_distance:
            best_hue, best_distance = hue, distance
    return best_hue, best_distance


def test_tc079_5_magenta_hue_distance() -> None:
    """The gauge's hue is the PROVABLY most-separated hue the palette allows.

    ⚠ **Inc-5b rewrote this test, and the rewrite is the point.** Inc-5's
    version hardcoded its verdict — ``assert 313.9 <= h <= 320.0`` — while the
    RULE that produced those numbers lived only in prose. Census and arc were
    two hand-maintained constants with nothing binding them, so when the census
    turned out to be missing ``#e06c75`` (38.4deg away, under Inc-5's own 40deg
    floor) the arc did not move and nothing went red. This version COMPUTES the
    arc from the census on every run: the two cannot drift apart again.

    **What the operator actually ruled** is two clauses, and only one of them is
    a distance:

    1. The gauge must never paint a VERDICT hue — nothing inside
       ``#patch_editor_panel`` may be misread as "check passed / failed".
    2. It must not be confusable with anything else the app paints.

    **The objective is the FLANK RULE, not the floor.** Orange is the worked
    example: it looks free inside the patch panel, but at 37.7deg it sits
    between RED (0deg) and YELLOW (64.8deg) — a verdict on each side. That is
    what disqualifies it, and no distance threshold expresses it.
    :func:`test_tc079_5d_flank_rule_has_teeth` proves this predicate can fire.

    **Why the 40deg floor is gone (Inc-5b, deliberate — not to make this pass).**
    Inc-5 invented ">= 40deg" from a single anecdote (Inc-2b called HILITE<->CYAN
    at 23.5deg "distinct"), and three shipped artifacts hardened it into
    ">= 43.0deg from every chromatic claimant". Measured against the COMPLETE
    census, that claim is not merely false — it is **unsatisfiable**: the best
    any hue on the circle achieves is **40.77deg**. A 43deg floor admits the
    empty set; a 40deg floor admits a 1.53deg arc, i.e. it sits 0.77deg from
    infeasible and constrains nothing — it just happens to admit its own answer.
    Meanwhile the app ships HILITE<->LBLUE at **0.19deg** and RED<->#e06c75 at
    **4.66deg** and reads them fine, because hue is not the only discriminator
    (saturation, value, glyph, and container all carry). A floor two orders of
    magnitude stricter than the palette applies to itself was never measuring
    non-confusability.

    So the floor is demoted to an in-repo ANCHOR (beat 23.5deg, the closest pair
    the repo already accepted) and the real assertion is **optimality**: MAGENTA
    is the max-min point of the non-flanked circle. That is self-calibrating —
    it can never become unsatisfiable, it cannot be gamed by nudging a constant,
    and if the palette grows it fails with the NEW optimum in the message.

    **The "rejected lime arc" does not exist.** Inc-5's headline finding — a
    second, farther arc at [104.9, 114.8] rejected for sitting between two
    verdicts — was itself a census artifact. It came from omitting rich
    ``green`` (**#008000, 120deg**, the ``ValidationSeverity.OK`` style and the
    ``✓`` MAC glyph), which sits ~13deg from that arc and rules it out on
    distance alone. With the census complete, the global optimum and the
    admissible optimum are the SAME point, and it is this magenta. The prose
    reasoning ("distance is necessary, not the objective") was right; every
    number attached to it was wrong.
    """
    magenta_hue = _hue_degrees(MAGENTA)
    distances = {
        claimant: _hue_distance(magenta_hue, _hue_degrees(hex_color))
        for claimant, hex_color in _CLAIMED_HUES.items()
    }
    nearest_distance, nearest = _min_claimed_distance(magenta_hue)
    measurement = {k: round(v, 2) for k, v in sorted(distances.items(), key=lambda kv: kv[1])}

    # Clause 1, asserted directly rather than inferred from an angle.
    assert MAGENTA not in {GREEN, YELLOW, RED}, (
        "the gauge's hue must not BE a verdict hue"
    )
    # Clause 1, the geometric half: the objective.
    assert not _is_verdict_flanked(magenta_hue), (
        f"MAGENTA ({MAGENTA}, hue {magenta_hue:.2f}deg) sits BETWEEN two "
        f"verdict hues. Distance cannot buy this back — it is the geometry "
        f"that disqualified Orange"
    )
    # Clause 2, as an anchored sanity floor (NOT the binding constraint).
    assert nearest_distance >= _MIN_HUE_SEPARATION_DEG, (
        f"MAGENTA ({MAGENTA}, hue {magenta_hue:.2f}deg) is only "
        f"{nearest_distance:.2f}deg from {nearest} — closer than "
        f"HILITE<->CYAN (23.5deg), the tightest pair this repo has explicitly "
        f"accepted as distinct. Full measurement: {measurement}"
    )
    # Clause 2, the binding constraint: it is the BEST available, not merely
    # adequate. This is what replaces Inc-5's hardcoded arc.
    optimum_hue, optimum_distance = _admissible_optimum()
    assert nearest_distance >= optimum_distance - _HUE_OPTIMALITY_TOLERANCE_DEG, (
        f"MAGENTA ({MAGENTA}, hue {magenta_hue:.2f}deg) is {nearest_distance:.2f}deg "
        f"from its nearest claimant ({nearest}), but a non-flanked hue at "
        f"{optimum_hue:.2f}deg reaches {optimum_distance:.2f}deg. Re-pick MAGENTA "
        f"at ~{optimum_hue:.2f}deg (keep sat ~45% / val ~96% so it stays in the "
        f"pastel band), then update insight_style.MAGENTA's comment and "
        f"REQUIREMENTS.md §6.5 Amendment F-1 with the NEW measured distance. Do "
        f"not relax this tolerance to make it pass. Full measurement: {measurement}"
    )


def test_tc079_5c_hue_census_is_complete() -> None:
    """Every colour literal in ``s19_app/`` is CLAIMED or EXCLUDED-with-a-reason.

    ⚠ **This test exists because Inc-5's census was hand-curated and wrong, and
    nothing could see it.** ``test_tc079_5_magenta_hue_distance`` certifies a
    universal ("MAGENTA is far from EVERY claimant"), and a universal is only as
    true as its input set. Mutating the code under test cannot catch a missing
    input — the mutant passes. The only oracle for a census is a sweep of the
    thing being censused, so that is what this is.

    It does NOT replace the hand-written census: a sweep cannot tell a live rule
    from a commented-out one (``styles.tcss`` says ``was #4ec9d4`` right next to
    a live ``#4ec9d4``), and it cannot see rich's NAMED colours at all. What it
    CAN do is make the hand-curation checkable — a new colour literal lands in
    neither dict and this fails, forcing a human to classify it rather than
    letting it be omitted in silence.

    ⚠ **Known gap, stated rather than papered over:** rich named styles
    (``"orange3"``, ``"green"``, ``"red"``, ``"grey50"``) are invisible to a hex
    sweep. They are enumerated in ``_CLAIMED_HUES`` by hand from
    ``app.py::_SEVERITY_TO_RICH_STYLE`` and the ``_MAC_GLYPH_*`` pairs, and a new
    named chromatic style would NOT be caught here. Widening the sweep to resolve
    named colours is the honest next step; it is out of Inc-5b's scope.
    """
    source_root = pathlib.Path(__file__).resolve().parents[1] / "s19_app"
    assert source_root.is_dir(), f"cannot locate the package at {source_root}"

    literal = re.compile(r"#[0-9a-fA-F]{6}\b")
    swept: dict[str, list[str]] = {}
    for path in sorted(source_root.rglob("*")):
        if path.suffix not in (".py", ".tcss"):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in literal.findall(line):
                swept.setdefault(match.lower(), []).append(
                    f"{path.relative_to(source_root).as_posix()}:{number}"
                )
    assert swept, "the sweep found no colour literals at all — it is broken"

    # MAGENTA is the SUBJECT of the census, not a claimant against itself.
    accounted = (
        {c.lower() for c in _CLAIMED_HUES.values()}
        | set(_EXCLUDED_LITERALS)
        | {MAGENTA.lower()}
    )
    unaccounted = {c: sites for c, sites in swept.items() if c not in accounted}
    assert not unaccounted, (
        f"colour literals in s19_app/ are in NEITHER _CLAIMED_HUES nor "
        f"_EXCLUDED_LITERALS: { {c: s[:2] for c, s in unaccounted.items()} }. "
        f"Add each to _CLAIMED_HUES (if it paints a foreground cue an analyst "
        f"could confuse with the gauge) or to _EXCLUDED_LITERALS WITH A REASON. "
        f"Do not omit it — an omitted claimant is exactly the Inc-5 defect this "
        f"guard exists to prevent: it makes the hue test certify a universal "
        f"that is false. If you add a claimant, re-run "
        f"test_tc079_5_magenta_hue_distance: MAGENTA may need to move."
    )

    # The excluded set may not rot into a list of colours nobody paints any
    # more: a stale exclusion is a reason nobody re-examines.
    stale = set(_EXCLUDED_LITERALS) - set(swept)
    assert not stale, (
        f"_EXCLUDED_LITERALS names colours that no longer appear in s19_app/: "
        f"{sorted(stale)}. Drop them — a stale exclusion is dead justification"
    )
    # Same for the hex claimants. The rich NAMED claimants are legitimately
    # absent from a hex sweep, so they are excused — resolved through rich, not
    # restated, so this cannot drift out of step with _CLAIMED_HUES.
    named = {_named_hex(n) for n in ("orange3", "green", "red")}
    stale_claims = {
        c.lower() for c in _CLAIMED_HUES.values()
    } - set(swept) - named
    assert not stale_claims, (
        f"_CLAIMED_HUES names hues no longer painted in s19_app/: "
        f"{sorted(stale_claims)}. A phantom claimant over-constrains the hue "
        f"search and could push MAGENTA off its optimum for no reason"
    )


def test_tc079_5d_flank_rule_has_teeth() -> None:
    """The flank predicate FIRES — it is not a constant-false decoration.

    ``test_tc079_5_magenta_hue_distance`` leans on ``_is_verdict_flanked`` for
    its primary clause, so a predicate that can never return True would make
    that assertion vacuous — the same class of defect as the census omission it
    was written to fix, one level up. Pinned against the two hues the reasoning
    actually rejected, plus MAGENTA's own arc.
    """
    # Orange: the worked example in the ruling. 37.7deg, between RED and YELLOW.
    assert _is_verdict_flanked(_hue_degrees("#d78700"))
    # The lime Inc-5 wrongly believed was a contender: between YELLOW and GREEN.
    assert _is_verdict_flanked(110.0)
    # A verdict hue is trivially flanked by its own neighbours' arcs.
    assert _is_verdict_flanked(_hue_degrees(YELLOW) + 1.0)
    # The GREEN->RED arc is the open field — 205deg wide, not "between".
    assert not _is_verdict_flanked(_hue_degrees(MAGENTA))
    assert not _is_verdict_flanked(200.0)


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
