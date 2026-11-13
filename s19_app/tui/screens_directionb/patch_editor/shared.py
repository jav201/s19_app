"""s19_app.tui.screens_directionb.patch_editor.shared - module-level names of the old patch_editor.py (moved verbatim at 2dbd7d5a)."""
from __future__ import annotations

from typing import Mapping, NamedTuple, Optional, Sequence
from rich.text import Text
from textual.widgets import Static
from ...insight_style import DGRAY
from ..shared import CARD_UNMAPPED_TOKEN, STRIP_ROW_BYTES, before_after_card_text


class _Unset:
    """Sentinel type for "argument not supplied" (batch-48 LLR-080.2).

    ``None`` cannot serve: it is a MEANINGFUL value for ``mem_map`` — "no
    image is loaded" (LLR-080.4) — and conflating it with "not supplied" is
    the bug. ``refresh_entries`` has FIVE call sites and one of them (the
    panel's own ``on_mount`` self-call) has no ``mem_map`` to give; an
    unconditional retain would let that call NULL a map a real load had
    already supplied. Sentinel ⇒ preserve; explicit ``None`` ⇒ clear.
    """


_UNSET = _Unset()

#: The before/after strip's neutral states (batch-48 LLR-080.4; batch-97
#: D5 (h), LLR-148.9). Author-fixed literals, each at most 38 cells (the
#: card's content width at 118 columns) — nothing file-derived reaches the
#: card (LLR-080.7).
CARD_NO_ENTRIES = "No entry yet: Add one or Load a file."


class BeforeAfterCard(Static):
    """The inspector's before→after hex strip (batch-48 LLR-080.1; batch-97 D5).

    Summary:
        A read-only card at the top of the Patch Editor's Inspector pane
        (batch-97 moved it there from the JSON window, D5). Selecting a ledger
        row shows the image bytes at that entry's span beside the bytes the
        entry would write, as the stacked pe_A grid of
        :func:`before_after_card_text` — live, BEFORE any apply. It applies
        nothing (LLR-080.5). Its ``border-top`` row carries the title
        ``BEFORE → AFTER``, so the title costs no row. Height is the content's
        (no cap): the strip itself caps its rows (``STRIP_ROW_CAP``).

    Note (Textual internal-name shadowing):
        The only members added are the public ``show_entry`` / ``show_state``
        methods and ``on_mount`` — no Widget private name is introduced
        (TC-080.1).
    """

    DEFAULT_CSS = """
    BeforeAfterCard {
        height: auto;
        padding: 0 1;
        border-top: solid $panel;
    }
    """

    def on_mount(self) -> None:
        self.border_title = "BEFORE → AFTER"

    def show_entry(
        self,
        address: Optional[int],
        before: Optional[Sequence[Optional[int]]],
        after: Sequence[int],
        per_row: int = 8,
        lead: Sequence[Optional[int]] = (),
        trail: Sequence[Optional[int]] = (),
    ) -> None:
        """Update the card to preview one entry (LLR-080.3/.4, D5)."""
        self.update(
            before_after_card_text(address, before, after, per_row, lead=lead, trail=trail)
        )

    def show_state(self, line: str) -> None:
        """Paint one of the card's author-fixed state lines (LLR-148.9)."""
        self.update(Text(line, style=DGRAY))


#: batch-97 (LLR-148.7, D7): the Patch Editor's closed glyph vocabulary —
#: glyph -> its one meaning. The four check-run verdicts lead each ledger
#: row's Kind cell (``_GLYPH_STYLE``); ``--`` is the strip's unmapped byte
#: (``CARD_UNMAPPED_TOKEN``). ``#patch_legend`` is generated from it.
PATCH_GLYPHS: Mapping[str, str] = {
    "✓": "check passed",
    "✗": "check failed",
    "◐": "uncheckable",
    "·": "not checked",
    CARD_UNMAPPED_TOKEN: "byte not in the image",
}


def json_stamp_text(n: Optional[int], hhmmss: Optional[str], dirty: bool) -> str:
    """The JSON view's stamp (LLR-144.6, D4).

    Example:
        >>> json_stamp_text(6, "10:20:30", False)
        '6 entries · 10:20:30 · saved'
        >>> json_stamp_text(None, None, True)
        'no document yet · unsaved changes'
    """
    if n is None:
        return "no document yet" + (" · unsaved changes" if dirty else "")
    noun = "entry" if n == 1 else "entries"
    return f"{n} {noun} · {hhmmss} · {'unsaved changes' if dirty else 'saved'}"


class PatchLayout(NamedTuple):
    """The Patch Editor widths Python derives (D21); CSS sizes everything else."""

    kind: int
    address: int
    value: int
    status: int
    linkage: int
    strip_bytes: int
    ribbon: int


def patch_layout(
    ledger_w: int, inspector_w: int, status_longest: int = 0, ribbon_w: int = 110
) -> PatchLayout:
    """Derive the Patch Editor's painted widths from its measured content widths.

    Summary:
        D21 / D5 (f). ``ledger_w`` is the PATCH SCRIPT frame's content width
        (the table fills it; its 1-cell vertical scrollbar gutter is always
        reserved and every column pays 2 cells of padding). Kind (glyph +
        ``string``) is 8, Address 10 (``0x`` + 8 digits, never clipped),
        Linkage 7 (its header) and Status the longest status text, between 7
        and 20; Value / bytes takes the rest (never below 12).
        ``inspector_w`` is ``#patch_inspector``'s content width: the strip's
        bytes per row is the largest of :data:`STRIP_ROW_BYTES` whose line
        (``3·k + 8``) fits the card (``inspector_w − 3``: the pane's scrollbar
        gutter and the card's padding). ``ribbon_w`` is the identity ribbon's
        content width (the file name keeps its tail inside it).

    Example:
        >>> tuple(patch_layout(65, 41, 6))
        (8, 10, 22, 7, 7, 8, 110)
        >>> patch_layout(115, 75, 6).strip_bytes
        16
    """
    status = max(7, min(status_longest, 20))
    usable = ledger_w - 1 - 2 * 5
    value = max(12, usable - 8 - 10 - 7 - status)
    fitting = [k for k in STRIP_ROW_BYTES if 3 * k + 8 <= inspector_w - 3]
    strip = max(fitting) if fitting else STRIP_ROW_BYTES[0]
    return PatchLayout(8, 10, value, status, 7, strip, max(8, ribbon_w))
