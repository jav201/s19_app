"""s19_app.tui.screens_directionb.shared — shared helpers (moved verbatim from s19_app/tui/screens_directionb.py at 4f721985)."""
from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from typing import List, NamedTuple, Optional, Sequence, Tuple
from rich.cells import cell_len, set_cell_size
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, Label, Static
from ..color_policy import css_class_for_severity
from ..entropy_style import ENTROPY_BAND_LABELS
from ..insight_style import CYAN, DGRAY, LABEL, VALUE
from textual.screen import ModalScreen
from ..services.entropy_service import EntropyWindow
from ...validation import ValidationSeverity


class EmptyStatePanel(Static):
    """Neutral empty-state panel shown when a rail screen has no file loaded.

    Summary:
        Renders the LLR-002.3 no-file-loaded prompt ("no file loaded -
        Ctrl+L to load") as a single neutral static panel. It is mounted
        inside the rail screen scaffolds so activating Workspace, A2L
        Explorer, MAC View or Memory Map with no ``LoadedFile`` shows a
        prompt instead of a blank pane or an error.

    Args:
        None

    Returns:
        None

    Data Flow:
        - Static text only; reads no engine state and no ``LoadedFile``.

    Dependencies:
        Used by:
            - ``ScreenScaffold`` (the rail screen slots)

    Example:
        >>> panel = EmptyStatePanel()
        >>> panel.id
        'empty_state_panel'
    """

    PROMPT_TEXT = (
        "No file loaded - press Ctrl+L (or 'l') to load a file, "
        "or 'p' to load a saved project."
    )

    def __init__(self) -> None:
        super().__init__(self.PROMPT_TEXT, id="empty_state_panel", markup=False)


class ScreenScaffold(Container):
    """Neutral container scaffold for a Direction B rail screen slot.

    Summary:
        A titled, neutral container used as the real screen slot for the
        rail screens whose rich content lands in later increments (Memory
        Map, Issues Report, Patch Editor, A2B Diff, Bookmarks). It carries
        an ``EmptyStatePanel`` so an activated slot is never blank, plus a
        short title label. Increments 5-10 replace the body of these
        scaffolds with their real panes.

    Args:
        screen_id (str): The container id for this screen slot
            (e.g. ``"screen_map"``).
        title (str): Human-readable screen title shown at the top.
        hidden (bool): When True the slot carries the ``.hidden`` class so
            it is not visible until activated. Defaults to True — only the
            startup Workspace screen is composed visible.

    Returns:
        None

    Data Flow:
        - Composition only; reads no engine state.

    Dependencies:
        Uses:
            - ``EmptyStatePanel``
        Used by:
            - ``S19TuiApp.compose`` (the ``#workspace_body`` screen slots)

    Example:
        >>> scaffold = ScreenScaffold("screen_bookmarks", "Bookmarks")
        >>> scaffold.id
        'screen_bookmarks'
    """

    def __init__(self, screen_id: str, title: str, hidden: bool = True) -> None:
        classes = "db-screen hidden" if hidden else "db-screen"
        super().__init__(id=screen_id, classes=classes)
        self._title = title

    def compose(self) -> ComposeResult:
        yield Label(self._title, classes="db-screen-title")
        yield EmptyStatePanel()

#: Rendered width of one address-ruler tick label — 8 hex digits, the ``0x``
#: prefix already spent as a C-13.1 deficit-matched fallback (batch-47).
_RULER_LABEL_WIDTH = 8

#: Columns one ruler tick claims: its label plus at least one blank separator
#: column (batch-77, LLR-112.2). The separator is NORMATIVE, not cosmetic — two
#: adjacent 8-hex labels with no gap render as an unreadable 16-digit run, and
#: the pitch is what decides whether an image is inside HLR-112's domain. At
#: pitch 8 the ceiling reads 8/6 instead of 7/5 and ``case_07_stress_smoke``
#: (6 ticks) would appear in domain at 120x30 when it is not.
_RULER_TICK_PITCH = _RULER_LABEL_WIDTH + 1

#: 9-glyph entropy ramp (0.0 → 8.0 bits/byte) for the At-a-glance sparkline
#: (batch-45, R-TUI-061 / LLR-045B.2). Index 0 = a space (near-zero entropy),
#: index 8 = a full block (maximal entropy). Mirrors the prototype ``BARS``.
_ENTROPY_BAR_RAMP = " ▁▂▃▄▅▆▇█"

#: Fixed number of sparkline columns the profile is sampled to (LLR-045B.2).
#: Retired from the always-on surface at batch-93 (the docked glance block
#: folded to one chips line) but kept — ``sparkline_glyphs`` remains a tested
#: unit of the entropy-profile sampling. (The glance histogram's
#: ``_GLANCE_BAR_WIDTH`` constant retired with the docked block it sized.)
_SPARKLINE_WIDTH = 24


def entropy_ramp_glyph(entropy: float) -> str:
    """Map a Shannon entropy value (0.0–8.0) to its :data:`_ENTROPY_BAR_RAMP` glyph.

    Summary:
        Round ``entropy`` to the nearest integer band index and clamp it into
        ``[0, 8]`` to pick one of the nine ramp glyphs (batch-45, R-TUI-061 /
        LLR-045B.2). A constant-fill window (``0.0``) maps to the leading space;
        a maximal-entropy window (``8.0``) to the full block.

    Args:
        entropy (float): Entropy in bits/byte, normally ``0.0 ≤ H ≤ 8.0``.

    Returns:
        str: The single ramp glyph for ``entropy``.

    Data Flow:
        - Called once per sampled window by :func:`sparkline_glyphs` /
          :func:`_sparkline_segments`.

    Dependencies:
        Uses:
            - _ENTROPY_BAR_RAMP
        Used by:
            - sparkline_glyphs / _sparkline_segments / tests

    Example:
        >>> entropy_ramp_glyph(0.0), entropy_ramp_glyph(8.0)
        (' ', '█')
    """
    index = int(round(entropy))
    index = max(0, min(len(_ENTROPY_BAR_RAMP) - 1, index))
    return _ENTROPY_BAR_RAMP[index]


def band_histogram(
    runs: Sequence[Tuple[str, int, int]],
) -> List[Tuple[str, int, float]]:
    """Tally merged region runs per band into ``(band, count, pct)`` rows.

    Summary:
        Count how many merged region runs fall in each band and compute each
        band's share of the total region count (batch-45, R-TUI-061 /
        LLR-045B.1). Rows are returned for OCCUPIED bands only (count > 0), in
        the canonical :data:`ENTROPY_BAND_LABELS` order. The count is a REGION
        (merged-run) count — consistent with the region list — not a raw
        window count. A pure tally over the already-merged runs; no re-parse.

    Args:
        runs (Sequence[Tuple[str, int, int]]): The merged
            ``(band, bytes, start)`` runs from :func:`_merge_band_runs`.

    Returns:
        List[Tuple[str, int, float]]: One ``(band_label, region_count,
        percentage)`` per occupied band, in band order; ``[]`` when ``runs`` is
        empty. Percentages are ``100 * count / total`` and sum to ~100.

    Data Flow:
        - Reads each run's band; produces the histogram rows the At-a-glance
          panel renders.

    Dependencies:
        Uses:
            - ENTROPY_BAND_LABELS
        Used by:
            - MemoryMapPanel._build_glance_widgets / tests

    Example:
        >>> band_histogram([("low", 256, 0), ("low", 256, 4096),
        ...                 ("high/random", 256, 8192)])
        [('low', 2, 66.66666666666667), ('high/random', 1, 33.33333333333333)]
    """
    total = len(runs)
    if total == 0:
        return []
    counts = {label: 0 for label in ENTROPY_BAND_LABELS}
    for band, _bytes, _start in runs:
        if band in counts:
            counts[band] += 1
    return [
        (label, counts[label], 100.0 * counts[label] / total)
        for label in ENTROPY_BAND_LABELS
        if counts[label] > 0
    ]


def sparkline_glyphs(windows: Sequence[EntropyWindow], width: int) -> str:
    """Sample the entropy profile to a fixed-width ramp-glyph string.

    Summary:
        Sub-sample ``windows`` with step ``max(1, N // width)`` and map each
        sampled window's entropy to its :func:`entropy_ramp_glyph` (batch-45,
        R-TUI-061 / LLR-045B.2). The plain (uncoloured) glyph string; the
        rendered sparkline colours it per band via :func:`_sparkline_segments`.

    Args:
        windows (Sequence[EntropyWindow]): The loader-computed entropy windows.
        width (int): Target column budget the profile is sampled down to.

    Returns:
        str: One ramp glyph per sampled window; ``""`` for empty input.

    Data Flow:
        - Reads each sampled window's ``entropy``; used by the pure unit test
          and any plain-text sparkline read.

    Dependencies:
        Uses:
            - entropy_ramp_glyph
        Used by:
            - tests (TC-061.2)

    Example:
        >>> from s19_app.tui.services.entropy_service import EntropyWindow
        >>> w = lambda e: EntropyWindow(0, 256, 256, e, "x", False)
        >>> sparkline_glyphs([w(0.0), w(8.0)], 24)
        ' █'
    """
    if not windows:
        return ""
    step = max(1, len(windows) // max(1, width))
    return "".join(entropy_ramp_glyph(w.entropy) for w in windows[::step])


def _sparkline_segments(
    windows: Sequence[EntropyWindow], width: int
) -> List[Tuple[str, str]]:
    """Sample the profile and group it into ``(band, glyphs)`` colour segments.

    Summary:
        Sub-sample ``windows`` (step ``max(1, N // width)``) and group
        consecutive sampled windows of the SAME band into runs, each carrying
        that band's concatenated ramp glyphs (batch-45, LLR-045B.2). One
        band-styled ``Static`` per segment lets the sparkline be band-coloured
        through the ``band-*`` CSS classes (single colour source) rather than
        per-glyph widgets or hard-coded Rich colours.

    Args:
        windows (Sequence[EntropyWindow]): The loader-computed entropy windows.
        width (int): Target column budget for sampling.

    Returns:
        List[Tuple[str, str]]: ``(band, glyphs)`` colour segments in profile
        order; ``[]`` for empty input.

    Data Flow:
        - Reads each sampled window's ``band`` + ``entropy``; produces the
          per-band sparkline segments the panel mounts.

    Dependencies:
        Uses:
            - entropy_ramp_glyph
        Used by:
            - MemoryMapPanel._build_glance_widgets
    """
    if not windows:
        return []
    step = max(1, len(windows) // max(1, width))
    segments: List[Tuple[str, str]] = []
    for window in windows[::step]:
        glyph = entropy_ramp_glyph(window.entropy)
        if segments and segments[-1][0] == window.band:
            band, glyphs = segments[-1]
            segments[-1] = (band, glyphs + glyph)
        else:
            segments.append((window.band, glyph))
    return segments


def cell_count_for_geometry(span: int, cols: int, rows: int) -> int:
    """Choose the number of grid cells for a span and measured geometry.

    Summary:
        Return ``cols * rows`` capped so the whole ``span`` fits, i.e. never
        more cells than there are bytes. The result is a pure function of
        ``(span, cols, rows)`` — no live layout is read here, so the grid is
        deterministic and snapshot-stable (LLR-041.2, R-4).

    Args:
        span (int): Image span in bytes (``span_end - span_start``).
        cols (int): Grid columns available in the content region.
        rows (int): Grid rows available in the content region.

    Returns:
        int: Number of cells to render; ``0`` when ``span <= 0`` (empty
        state, no ratio computed → no divide-by-zero).

    Data Flow:
        - Called by ``render_ranges`` with ``derive_image_span`` output and
          the measured (or default) geometry; feeds ``bytes_per_cell``.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> cell_count_for_geometry(1000, 16, 8)
        128
        >>> cell_count_for_geometry(10, 16, 8)
        10
        >>> cell_count_for_geometry(0, 16, 8)
        0
    """
    if span <= 0:
        return 0
    capacity = max(1, cols) * max(1, rows)
    return min(capacity, span)


def bytes_per_cell(span: int, cell_count: int) -> int:
    """Compute the bytes-per-cell size for the grid.

    Summary:
        Return ``ceil(span / cell_count)`` — the address window each cell
        covers so the whole span fits the grid (LLR-041.2). Guards against a
        zero ``cell_count`` (empty state) so no division occurs.

    Args:
        span (int): Image span in bytes.
        cell_count (int): Number of cells from ``cell_count_for_geometry``.

    Returns:
        int: Bytes covered by one cell; ``0`` when ``cell_count <= 0``.

    Data Flow:
        - Called by ``render_ranges``; drives per-cell window boundaries and
          the "≈ N KiB/cell" header.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> bytes_per_cell(1000, 128)
        8
        >>> bytes_per_cell(0, 0)
        0
    """
    if cell_count <= 0:
        return 0
    return ceil(span / cell_count)


def status_to_css_class(status: str) -> str:
    """Map a cell status to its canonical ``sev-*`` CSS class.

    Summary:
        Route ``"invalid"``→``ERROR``, ``"valid"``→``OK``, ``"gap"``→
        ``NEUTRAL`` through the frozen ``css_class_for_severity`` — the
        single source of truth for severity colours. The panel hard-codes no
        severity hex or inline style (LLR-041.3).

    Args:
        status (str): ``"valid"``, ``"invalid"`` or ``"gap"``.

    Returns:
        str: The matching CSS class (``"sev-ok"`` / ``"sev-error"`` /
        ``"sev-neutral"``).

    Data Flow:
        - Applied by ``render_ranges`` as a cell widget class.

    Dependencies:
        Uses:
            - ``css_class_for_severity`` (frozen, consumed read-only)
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> status_to_css_class("invalid")
        'sev-error'
    """
    severity = {
        "invalid": ValidationSeverity.ERROR,
        "valid": ValidationSeverity.OK,
        "gap": ValidationSeverity.NEUTRAL,
    }.get(status, ValidationSeverity.NEUTRAL)
    return css_class_for_severity(severity)


def _clip_to_cells(text: str, cap: int) -> str:
    """Clip ``text`` to ``cap`` terminal COLUMNS, marking the loss with an ellipsis.

    Summary:
        The house clip seam (``S19TuiApp._clip_to``, app.py), reimplemented at
        module scope because ``app.py`` imports this module (a circular import
        would otherwise pull the whole app into the panel). Columns, not code
        points: ``cell_len`` / ``set_cell_size`` come from ``rich`` (already a
        hard dependency via Textual), and ``set_cell_size`` handles a cap
        falling in the MIDDLE of a double-width character — the correct result
        there is a pad space, not half a glyph. An over-long authored or
        file-derived line is shortened AT A CELL BOUNDARY here so the painted
        line never wraps mid-content (batch-93 inc-002, HLR-130 — the wrap
        audit asserts the no-wrap law over every authored surface).

    Args:
        text (str): The line to clip (authored or file-derived).
        cap (int): The maximum cell width the painted line may claim.

    Returns:
        str: ``text`` when it already fits; otherwise its first ``cap - 1``
        columns plus an ellipsis.

    Example:
        >>> _clip_to_cells("abcdef", 4)
        'abc…'
        >>> _clip_to_cells("ab", 4)
        'ab'
    """
    if cap <= 0:
        return ""
    if cell_len(text) <= cap:
        return text
    if cap == 1:
        return "…"
    return set_cell_size(text, cap - 1) + "…"
CARD_NO_SELECTION = "Select a ledger row to see its bytes."
CARD_NO_IMAGE = "No image loaded: ^l loads one."
#: Rendered for an address the loaded image does not map (A4: absence is
#: UNMAPPED, never zero). MUST stay distinguishable from a real ``0x00``, whose
#: rendering is ``"00"`` — asserted by TC-080.3, not left to inspection.
CARD_UNMAPPED_TOKEN = "--"
#: The PATCH family teal (batch-94 spike; operator, Inc-4 gate 2026-10-21,
#: D5 (e) amended): the strip's changed ``now`` bytes and its ``N changed``
#: count, both bold. Claimed in the hue census (``test_tc079_5c``).
PATCH_TEAL = "#56e0d6"
#: batch-97 (D5 (c), D12): the strip stacks at most this many byte rows; a
#: longer run paints its first rows and one note line naming how much is shown.
STRIP_ROW_CAP = 8
#: batch-97 (D5 (f), D12): the byte-row widths the strip can take; the panel
#: picks the largest one whose line (``3·k + 8`` cells) fits the card.
STRIP_ROW_BYTES = (4, 8, 16, 32)
#: The strip's label column: ``  was    `` / ``  now    `` — 9 cells, so a
#: row line is ``3·per_row + 8`` cells wide, like its offset header.
_STRIP_LABEL_CELLS = 9


def before_after_card_text(
    address: Optional[int],
    before: Optional[Sequence[Optional[int]]],
    after: Sequence[int],
    per_row: int = 8,
    *,
    lead: Sequence[Optional[int]] = (),
    trail: Sequence[Optional[int]] = (),
    row_cap: int = STRIP_ROW_CAP,
) -> Text:
    """Compose the inspector's before→after hex strip (LLR-080.3, LLR-144.8).

    Summary:
        The pe_A grid (batch-97 D5): the selected entry's span, aligned down to
        a multiple of ``per_row``, painted as stacked byte rows. Each row is
        three lines — the offset header (row address as 8 hex digits, then
        ``+X`` per column, ``X`` = the address's low nibble), ``was`` (the
        image bytes) and ``now`` (the bytes the entry writes; a context
        position repeats its image byte). At most ``row_cap`` rows are
        painted; a longer run adds one note line ``showing N of M bytes``.
        A summary line ``M B @ 0x…… · C changed`` closes the strip, ``C``
        counted over the whole span by the shipped rule (image byte unmapped
        or different = changed). Pure, and fed ints only (LLR-080.7).

        Colour + attribute (LLR-144.8, D5 (e)): a changed span byte paints
        ``VALUE`` on the ``was`` line and ``bold PATCH_TEAL`` on the ``now``
        line, and a non-zero ``C changed`` count is ``bold PATCH_TEAL``; an
        unchanged span byte and every context byte paint ``DGRAY`` and are
        never bold. An unmapped byte paints ``--``.

    Args:
        address (Optional[int]): The entry's start address; ``None`` → the
            no-selection state.
        before (Optional[Sequence[Optional[int]]]): The image byte per span
            position (``None`` per unmapped position); ``None`` for the whole
            sequence → the no-image state.
        after (Sequence[int]): The entry's ``encoded_bytes``.
        per_row (int): Bytes per row (one of :data:`STRIP_ROW_BYTES`).
        lead (Sequence[Optional[int]]): Image bytes from the aligned row start
            up to ``address`` (context).
        trail (Sequence[Optional[int]]): Image bytes from the span end to the
            end of its last row (context).
        row_cap (int): The most byte rows painted.

    Returns:
        Text: Built with ``append`` only — never markup-parsed (C-17).

    Example:
        >>> t = before_after_card_text(0x203, [0xAA, 0xBB], [0x01, 0xBB], 8,
        ...     lead=[0, 0, 0], trail=[0, 0, 0])
        >>> t.plain.splitlines()[0]
        '00000200 +0 +1 +2 +3 +4 +5 +6 +7'
    """
    text = Text()
    if address is None:
        text.append(CARD_NO_SELECTION, style=DGRAY)
        return text
    if before is None:
        text.append(CARD_NO_IMAGE, style=DGRAY)
        return text

    span = len(after)
    start = address - len(lead)
    # One cell per painted position: (image byte, written byte, in the span).
    cells: list = [(byte, byte, False) for byte in lead]
    cells += [
        (before[i] if i < len(before) else None, after[i], True) for i in range(span)
    ]
    cells += [(byte, byte, False) for byte in trail]
    rows = -(-len(cells) // per_row) if cells else 0
    shown = min(rows, row_cap)

    def token(value: Optional[int]) -> str:
        return CARD_UNMAPPED_TOKEN if value is None else f"{value:02X}"

    for row in range(shown):
        row_start = start + row * per_row
        chunk = cells[row * per_row:(row + 1) * per_row]
        if row:
            text.append("\n")
        text.append(f"{row_start & 0xFFFFFFFF:08X}", style=CYAN)
        for col in range(len(chunk)):
            text.append(f" +{(row_start + col) % 16:X}", style=DGRAY)
        for label, written in (("was", False), ("now", True)):
            text.append("\n")
            text.append(f"  {label}".ljust(_STRIP_LABEL_CELLS), style=LABEL)
            for col, (image_byte, write_byte, in_span) in enumerate(chunk):
                if col:
                    text.append(" ")
                changed = in_span and (image_byte is None or image_byte != write_byte)
                value = write_byte if written else image_byte
                if not changed:
                    style = DGRAY
                elif written:
                    style = f"bold {PATCH_TEAL}"
                else:
                    style = VALUE
                text.append(token(value), style=style)
    if shown < rows:
        span_shown = max(0, shown * per_row - len(lead))
        text.append("\n" if shown else "")
        text.append(f"showing {span_shown} of {span} bytes", style=DGRAY)
    changed_count = sum(
        1
        for i in range(span)
        if (before[i] if i < len(before) else None) is None or before[i] != after[i]
    )
    if rows:
        text.append("\n")
    text.append(f"{span} B @ ", style=LABEL)
    text.append(f"0x{address & 0xFFFFFFFF:08X}", style=CYAN)
    text.append(" · ", style=LABEL)
    text.append(
        f"{changed_count} changed", style=f"bold {PATCH_TEAL}" if changed_count else DGRAY
    )
    return text


class LoadGuardScreen(ModalScreen[bool]):
    """The dirty-load warning popup (batch-94, HLR-005 / LLR-005.2).

    Summary:
        Modal raised by ``app.py`` when the Patch Editor's Load control is
        activated while unsaved edits exist in either editor region. It
        states the loss and offers the two policy branches: **Accept loss
        and load** continues the load of the path the operator typed (the
        document is replaced; the unsaved edits are lost), **Cancel** aborts
        the load and retains both the document and the dirty flag. Escape
        dismisses with Cancel, mirroring the sibling modals' Escape bond
        (batch-41 fold). Composed in this module (the ``screens.py`` modal
        idiom) because the popup is private to the panel that posts
        :class:`PatchEditorPanel.DirtyLoadRequested` — no fifth SOURCE file.

    Args:
        None

    Returns:
        bool: ``True`` when the operator accepted the loss, ``False`` on
            Cancel / Escape (``ModalScreen[bool]``).

    Data Flow:
        - ``compose`` builds a ``.modal-dialog`` with the warning text and
          the Accept / Cancel buttons.
        - ``on_button_pressed`` dismisses with the branch's value.

    Dependencies:
        Used by:
            - ``S19TuiApp.on_patch_editor_panel_dirty_load_requested``
    """

    #: Route initial focus to Cancel — the SAFE branch. Accept sits one Tab
    #: away; a popup whose default action destroys work would be a trap.
    AUTO_FOCUS = "#load_guard_cancel"

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-dialog"):
            yield Label(
                "Unsaved changes will be lost",
                id="load_guard_title",
                classes="modal-title",
            )
            yield Static(
                "The change editor and the text editor carry unsaved "
                "changes. Loading a new document replaces them.",
                id="load_guard_body",
                markup=False,
            )
            yield Horizontal(
                Button(
                    "Accept loss and load",
                    id="load_guard_accept",
                    classes="patch-chip",
                ),
                Button(
                    "Cancel",
                    id="load_guard_cancel",
                    classes="patch-chip",
                ),
                id="load_guard_buttons",
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with the branch the operator chose (LLR-005.2)."""
        button_id = event.button.id or ""
        if button_id == "load_guard_accept":
            event.stop()
            self.dismiss(True)
        elif button_id == "load_guard_cancel":
            event.stop()
            self.dismiss(False)

    def action_cancel(self) -> None:
        """Escape bond — dismiss with the Cancel branch (batch-41 fold)."""
        self.dismiss(False)


#: batch-97 (LLR-145.6 / LLR-144.5): the JSON tab shows at most this many lines
#: of a serialised document, then one note line naming the full count.
JSON_TAB_LINE_CAP = 5000


def cap_json_lines(text: str, cap: int = JSON_TAB_LINE_CAP) -> str:
    """Cap a JSON tab's text at ``cap`` lines plus one note line (LLR-144.5).

    Example:
        >>> cap_json_lines("a\\nb\\nc", cap=2)
        'a\\nb\\nshowing 2 of 3 lines'
    """
    lines = text.split("\n")
    if len(lines) <= cap:
        return text
    return "\n".join(lines[:cap] + [f"showing {cap} of {len(lines)} lines"])


@dataclass(frozen=True)
class PatchDocumentView:
    """The Patch Editor document as plain data (batch-97 D2, I-2/I-3).

    Built by ``S19TuiApp._patch_document_view`` and pushed through
    ``PatchEditorPanel.refresh_entries(…, document=)``, so the panel keeps
    importing nothing from the service layer (C-7).

    Attributes:
        name: The document file's name, or ``None`` for a draft.
        kind: ``change`` or ``check``.
        json_text: The whole serialised document, uncapped (the panel caps it
            when it paints, ``cap_json_lines``).
        entry_count: The document's entry count.
    """

    name: Optional[str]
    kind: str
    json_text: str
    entry_count: int


class CheckLayout(NamedTuple):
    """The Check Editor widths Python derives (D21); CSS sizes everything else."""

    param: int
    fmt: int
    fmt_label: str
    fields_name: int
    mem_label: int
    full_name: int


def check_layout(table_w: int, card_w: int, fmt_longest: int) -> CheckLayout:
    """Derive the Check Editor's painted widths from its measured content widths.

    Summary:
        D21 / PC-5. ``table_w`` is ``#check_param_table``'s content width, its
        1-cell vertical scrollbar gutter always reserved; the fixed cells are
        the mark (1 + 2 padding), Address (10 + 2) and the two remaining
        paddings (19 in all). ``Fmt · Unit`` is sized first — the longest unit
        text, capped at 16, never below ``u128``'s 4 cells and never eating the
        Parameter floor of 42 — and Parameter takes the rest. ``card_w`` is
        ``#check_right_column``'s content width: the REPORT FIELDS name field
        is ``card_w − 14`` (mark 2, address 11, the pane's scrollbar gutter 1)
        and the memory table's Label column ``card_w − 21``. The full-name line
        under the ledger is as wide as the table less its 1-cell paddings
        (``table_w − 2``). Below the range (LLR-149.6) the widths shrink to
        their floors and the table scrolls.

    Example:
        >>> tuple(check_layout(68, 38, 11))
        (42, 6, 'Fmt', 24, 17, 66)
        >>> tuple(check_layout(120, 70, 11))
        (89, 11, 'Fmt · Unit', 56, 49, 118)
    """
    usable = table_w - 1
    fmt = max(4, min(fmt_longest, 16, usable - 19 - 42))
    param = max(8, usable - 19 - fmt)
    label = "Fmt · Unit" if fmt >= 10 else "Fmt"
    return CheckLayout(
        param, fmt, label, max(8, card_w - 14), max(4, card_w - 21), max(8, table_w - 2)
    )


class TabChip(Button):
    """A one-row tab chip: ``enter`` (Button's own) and ``space`` press it (D16)."""

    BINDINGS = [Binding("space", "press", "Press", show=False)]
