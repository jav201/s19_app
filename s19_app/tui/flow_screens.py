"""Flow Builder + Flow Execution surfaces (batch-94, ARQ R8; Inc-002 fb_a).

This module is the R8 home of the flow family: the reworked fb_a
:class:`FlowBuilderPanel` (Inc-002) and, at Inc-003, the fx_a
``FlowExecutionPanel``. Pure view layer — the panels and their
``ActionRequested``-kin message types; flow execution SEMANTICS stays in
``services/flow_*`` (messages out, services never called directly; the one
declared data edge ``flow_screens → services/flow_model`` is read-only
constants/dataclasses per ``docs/architecture.md`` §10).

fb_a doctrine (the ratified spike graduation call, ``flow_bench.NOTES.md`` —
"connectivity is the builder's job"): a block palette rail, a framed canvas
with sparse grid dots, full-cell box-drawn blocks (header bar, typed ``in`` /
``out`` IO rows, ``┤├`` stubs) and ``─│└┐`` cable runs between stubs; the
fb_c audit precision folds in as the numbered ledger strip (``#flow_blocks``).
The A2B diff block binds each image input to a flow output (``#<n>`` — an
upstream block of the CURRENT flow) or a project-relative file, with ≥1 input
from this flow enforced at wiring time (HLR-014); SOURCE blocks render as file
chips dropping onto the next block's image row.

No engine code is imported beyond the read-only flow-model data types; every
file-derived string renders through ``safe_text`` (C-17).
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import (
    Container,
    Horizontal,
    ScrollableContainer,
    Vertical,
    VerticalScroll,
)
from textual.message import Message
from textual.widget import Widget
from textual.widgets import (
    Button,
    Input,
    Label,
    Select,
    Static,
)

from .insight_style import (
    CYAN,
    DGRAY,
    LABEL,
    LBLUE,
    RED,
    VALUE,
    DEPTH_BORDER,
)
from .os_clipboard_input import OsClipboardInput
from .services.flow_model import (
    A2BBlock,
    A2B_INPUT_FILE,
    A2B_INPUT_FLOW,
    BLOCK_A2B,
    BLOCK_CHECK,
    BLOCK_CRC,
    BLOCK_PATCH,
    BLOCK_SOURCE,
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    BLOCK_WRITE_OUT,
    CHECK_GATING_ADVISORY,
    CHECK_GATING_BLOCK_OWN,
    FLOW_SCOPE_ALL_VARIANTS,
    FLOW_SCOPE_ASSIGNMENTS,
    FLOW_SCOPE_SINGLE,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    CheckBlock,
    CrcBlock,
    Flow,
    FlowBlock,
    FlowRunResult,
    FusedFlowRunResult,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
    parse_a2b_binding,
    validate_a2b_bindings,
)
from ..utils import safe_text
from ..validation import ValidationIssue


def _make_flow_block(
    kind: str, ref: str, gating: str = CHECK_GATING_ADVISORY
) -> Optional[FlowBlock]:
    """Build a typed :class:`FlowBlock` from the panel's selection.

    Args:
        kind (str): The block-kind discriminator (``BLOCK_SOURCE`` — surfaced
            as "Load" — / ``BLOCK_PATCH`` / ``BLOCK_CHECK`` / ``BLOCK_WRITE_OUT``
            / ``BLOCK_CRC``). A2B blocks take the two-binding path
            (:meth:`FlowBuilderPanel._add_a2b_block`), not this single-ref
            helper.
        ref (str): The block's project-relative ref (image / doc / output name).
        gating (str): The CHECK gating flag (``CHECK_GATING_ADVISORY`` default
            or ``CHECK_GATING_BLOCK_OWN``); used only when
            ``kind == BLOCK_CHECK``.

    Returns:
        Optional[FlowBlock]: The built block, or ``None`` for an unknown kind
        or an empty ref (the panel no-ops).
    """
    ref = ref.strip()
    if not ref:
        return None
    if kind == BLOCK_SOURCE:
        return SourceBlock(ref)
    if kind == BLOCK_PATCH:
        return PatchBlock(ref)
    if kind == BLOCK_CHECK:
        return CheckBlock(ref, gating=gating)
    if kind == BLOCK_WRITE_OUT:
        return WriteOutBlock(ref)
    if kind == BLOCK_CRC:
        return CrcBlock(ref)
    return None


def _binding_label(binding) -> str:
    """One-line label for an A2B binding (plain text — markup-safe render)."""
    if binding.source == A2B_INPUT_FLOW:
        return f"#{int(binding.ref) + 1}.out"
    return binding.ref


def _flow_block_label(block: FlowBlock) -> str:
    """One-line display label for a block (plain text — rendered markup-safe)."""
    if isinstance(block, SourceBlock):
        return f"LOAD  {block.image_ref}  ({block.file_type})"
    if isinstance(block, PatchBlock):
        return f"PATCH   {block.change_doc_ref}"
    if isinstance(block, CheckBlock):
        return f"CHECK  {block.check_doc_ref}  ({block.gating})"
    if isinstance(block, WriteOutBlock):
        return f"WRITE-OUT  {block.output_name}  ({block.fmt})"
    if isinstance(block, CrcBlock):
        return f"CRC  {block.config_ref}"
    if isinstance(block, A2BBlock):
        return (
            f"A2B-DIFF  {_binding_label(block.image_a)}  "
            f"vs  {_binding_label(block.image_b)}"
        )
    if isinstance(block, ReportBlock):
        return "REPORT  (generation deferred - FB-P1b)"
    return "?"


#: Block-status → frozen ``sev-*`` CSS class (LLR-088.1). Lives HERE, not in
#: the frozen ``color_policy.py`` (D4): the flow render maps a block STATUS
#: token to an existing ``.sev-*`` class directly, it does not route through
#: ``SEVERITY_CLASS_MAP`` (which keys on ``ValidationSeverity``). 0 diff to the
#: frozen file. Every ``BLOCK_STATUS_*`` token has an entry (no unmapped status).
_BLOCK_STATUS_SEV_CLASS = {
    BLOCK_STATUS_OK: "sev-ok",
    BLOCK_STATUS_NOTICES: "sev-warning",
    BLOCK_STATUS_ERROR: "sev-error",
    BLOCK_STATUS_SKIPPED: "sev-neutral",
}

#: A per-status gutter glyph (enum-derived, never file-derived).
_BLOCK_STATUS_GLYPH = {
    BLOCK_STATUS_OK: "●",        # ● ok
    BLOCK_STATUS_NOTICES: "◈",   # ◈ notices
    BLOCK_STATUS_ERROR: "✖",     # ✖ error
    BLOCK_STATUS_SKIPPED: "○",   # ○ skipped
}

#: Flow-status → (banner text, ``sev-*`` class) (LLR-088.5). The banner text is
#: derived from the status ENUM, so it is NOT a markup sink (out of the C-17
#: sweep — the coordinator's exclusion, security F1).
_FLOW_STATUS_BANNER = {
    FLOW_STATUS_OK: ("CLEAN", "sev-ok"),
    FLOW_STATUS_ISSUES: ("ISSUES", "sev-warning"),
    FLOW_STATUS_ERROR: ("FAILED", "sev-error"),
}

#: The memory ribbon's fixed cell budget. A FIXED strip sized to clear the
#: tightest supported regime's measured content width — so it fits the 80×24
#: floor AND every wider regime with no horizontal overflow (LLR-088.4,
#: C-13/C-23/C-29). MEASURED in the mounted ``#flow_result`` via
#: ``App.run_test`` — NOT inherited from the HTML prototype's ~82/150-col
#: budget (C-16). Measured content widths (both axes, over a real
#: LOAD→WRITE-OUT run):
#:
#: ===========  ==============================  ====================
#: regime       ``#flow_result`` content width  region (border+pad)
#: ===========  ==============================  ====================
#: 80×24        **70**  ← binding floor          74  (= 70 + 2 + 2)
#: 120×30       92                               96
#: 160×40       132                              136
#: ===========  ==============================  ====================
#:
#: 48 cells clears the binding 70-col floor by 22, so the strip never wraps or
#: overflows at any regime. ``test_flow_builder_render.py::
#: test_ribbon_geometry_measured`` re-measures and asserts ``ribbon.region.width
#: <= container content width`` at 80×24 AND wide rather than trusting this table.
_RIBBON_CELLS = 48

_RIBBON_FILLED = "█"  # █ mapped
_RIBBON_GAP = "░"     # ░ gap


def _memory_ribbon_text(
    ranges: Sequence[Tuple[int, int]],
    cells: int = _RIBBON_CELLS,
    window: Optional[Tuple[int, int]] = None,
) -> Text:
    """Render the working image's address footprint as a fixed-width strip.

    Summary:
        Map ``[min_start, max_end)`` (or the explicit ``window``) across
        ``cells`` columns; a column is filled (mapped) when any range intersects
        it, else a gap. Pure + int-derived (address integers only — NOT file
        text), so the strip is NOT a markup sink and is deterministically
        unit-testable. Batch-52 (§6.5 AMD-1) renders a twin before/after pair
        over a COMMON ``window`` (the grown extent) so the CRC-added window
        shows as EXTRA filled cells on the after strip.

    Args:
        ranges (Sequence[Tuple[int, int]]): The image's ``(start, end)`` ranges
            (``FlowRunResult.image_ranges`` / ``pre_crc_ranges``); empty when no
            image was loaded.
        cells (int): The fixed cell budget (defaults to the measured
            ``_RIBBON_CELLS``).
        window (Optional[Tuple[int, int]]): An explicit ``(low, high)`` address
            axis to map across — used to render the before + after strips on a
            SHARED axis so growth is visible. ``None`` derives the axis from
            ``ranges`` (batch-51 single-strip behaviour, unchanged).

    Returns:
        Text: A ``Text`` of exactly ``cells`` block/gap glyphs, or an empty
        ``Text`` when there is no footprint / a non-positive budget.
    """
    if not ranges or cells <= 0:
        return Text("")
    if window is not None:
        low, high = window
    else:
        low = min(start for start, _ in ranges)
        high = max(end for _, end in ranges)
    if high <= low:
        return Text(_RIBBON_FILLED * cells)
    span = high - low
    glyphs = []
    for i in range(cells):
        col_lo = low + span * i / cells
        col_hi = low + span * (i + 1) / cells
        filled = any(start < col_hi and end > col_lo for start, end in ranges)
        glyphs.append(_RIBBON_FILLED if filled else _RIBBON_GAP)
    return Text("".join(glyphs))


def _ribbon_caption(ranges: Sequence[Tuple[int, int]]) -> str:
    """One-line ribbon caption (int-derived: range count + hex extents)."""
    if not ranges:
        return "no image loaded"
    low = min(start for start, _ in ranges)
    high = max(end for _, end in ranges)
    plural = "" if len(ranges) == 1 else "s"
    return f"{len(ranges)} range{plural} · 0x{low:X}‥ 0x{high:X}"


# ---------------------------------------------------------------------------
# fb_a canvas — the painted grid (single-style-per-cell discipline, the
# ``flow_bench.proto.py`` Grid ported to the production panel).
# ---------------------------------------------------------------------------

#: Painted canvas grid width. The canvas is painted at a FIXED width so its
#: oracle is layout-independent (C-32): 88 cells clear the measured 92-cell
#: ``#screen_flow`` content width at 120×30 with margin, and the scrollable
#: panel carries narrower regimes (74 cells at 80×24) without overflow.
_CANVAS_COLS = 88

#: PLC block geometry: full-cell box width (the spike's 24-cell block).
_BLOCK_W = 24

#: Canvas styles — real palette hexes (``insight_style`` / ``render.format``
#: tokens); one char + one style per cell, no cell carries two free variables.
_S_RULE = DEPTH_BORDER
_S_WIRE = LBLUE
_S_DIM = DGRAY
_S_LABEL = LABEL
_S_VALUE = VALUE
_S_OUT = CYAN
_S_HEAD = "bold " + VALUE
_S_ERR = RED


class _Grid:
    """Single-style-per-cell character grid → aligned Textual ``Text`` lines."""

    def __init__(self, w: int, h: int) -> None:
        self.w, self.h = w, h
        self.ch = [[" "] * w for _ in range(h)]
        self.st = [[""] * w for _ in range(h)]

    def put(self, x: int, y: int, s: str, style: str = "") -> None:
        for i, c in enumerate(s):
            xx = x + i
            if 0 <= xx < self.w and 0 <= y < self.h:
                self.ch[y][xx] = c
                self.st[y][xx] = style

    def puts(self, x: int, y: int, *segs: Tuple[str, str]) -> None:
        for s, style in segs:
            self.put(x, y, s, style)
            x += len(s)

    def box(self, x: int, y: int, w: int, h: int, style: str = _S_RULE) -> None:
        self.put(x, y, "┌" + "─" * (w - 2) + "┐", style)
        for r in range(y + 1, y + h - 1):
            self.put(x, r, "│", style)
            self.put(x + w - 1, r, "│", style)
        self.put(x, y + h - 1, "└" + "─" * (w - 2) + "┘", style)

    def fill(self, x: int, y: int, n: int, ch: str, style: str = "") -> None:
        self.put(x, y, ch * n, style)

    def text(self, x: int, y: int, s: str, style: str = _S_VALUE) -> None:
        """Label inside a box row (bounded by the block's inner width)."""
        self.put(x, y, s[: max(0, self.w - x)], style)

    def lines(self) -> List[Text]:
        out: List[Text] = []
        for y in range(self.h):
            txt, x = Text(), 0
            while x < self.w:
                c, s = self.ch[y][x], self.st[y][x]
                x2 = x
                while x2 < self.w and self.ch[y][x2] == c and self.st[y][x2] == s:
                    x2 += 1
                if c == " " and not s:
                    txt.append(" " * (x2 - x))
                else:
                    txt.append(c * (x2 - x), style=s or None)
                x = x2
            out.append(txt)
        return out


def _plc_block(
    g: _Grid,
    x: int,
    y: int,
    w: int,
    title: str,
    rows: Sequence[Tuple[str, str, str]],
) -> int:
    """Full-cell fb_a block: header bar on the top edge, typed IO rows inside.

    Returns the block's total height in rows (header + IO rows + bottom).
    """
    inner = f"[ {title} ]"
    g.put(x, y, "┌─" + inner + "─" * max(0, w - 3 - len(inner)) + "┐", _S_DIM)
    g.put(x + 4, y, title, _S_HEAD)
    for i, (io, text_, tstyle) in enumerate(rows):
        yy = y + 1 + i
        left = f"│ {io:<3} {text_}"
        g.put(x, yy, left + " " * max(0, w - 1 - len(left)) + "│", _S_DIM)
        g.put(x + 2, yy, io, _S_LABEL if io in ("in", "out") else _S_ERR)
        g.put(x + 6, yy, text_, tstyle)
    g.put(x, y + len(rows) + 1, "└" + "─" * (w - 2) + "┘", _S_DIM)
    return len(rows) + 2


def _chip(g: _Grid, x: int, y: int, label: str, w: int) -> int:
    """Source chip (a file feeding a block); returns the drop column."""
    g.put(x, y, "┌" + "─" * (w - 2) + "┐", _S_DIM)
    g.put(x, y + 1, "│" + label[: w - 2].ljust(w - 2) + "│", _S_DIM)
    g.put(x, y + 2, "└" + "─" * (w - 2) + "┘", _S_DIM)
    g.put(x + 1, y + 1, label[: w - 2], _S_LABEL)
    return x + w // 2


def _wire_bend(g: _Grid, x_from: int, y_out: int, x_to: int, y_in: int) -> None:
    """─│└┐ line run: right-edge out stub -> bend column -> next in stub."""
    if x_to <= x_from + 1:
        return
    xv = (x_from + x_to) // 2
    g.put(x_from, y_out, "┤", _S_WIRE)
    g.fill(x_from + 1, y_out, xv - x_from - 1, "─", _S_WIRE)
    g.put(xv, y_out, "┘", _S_WIRE)
    if y_out - y_in > 1:
        g.fill(xv, y_in + 1, y_out - y_in - 1, "│", _S_WIRE)
    g.put(xv, y_in, "└", _S_WIRE)
    g.fill(xv + 1, y_in, x_to - xv - 1, "─", _S_WIRE)
    g.put(x_to, y_in, "├", _S_WIRE)


class FlowBuilderPanel(ScrollableContainer):
    """Rail-8 Flow Builder — the fb_a block-diagram composer (batch-94 Inc-002).

    Summary:
        The reworked builder (HLR-013): a block PALETTE rail (patch / CRC /
        A2B-diff — the three fb_a placeable types), a framed CANVAS with grid
        dots painting the composed flow as box-drawn blocks with typed
        ``in``/``out`` stubs and ``─│└┐`` cable runs (SOURCE blocks render as
        file chips dropping onto the next block's image row), and the fb_c
        audit strip (``#flow_blocks``). The A2B diff block (HLR-014) binds each
        image input to a flow output (``#<n>``) or a file, refused at wiring
        time when both inputs are external / the reference is downstream / the
        target produces no image — a refused binding never enters the flow, so
        0 reports are produced for it. Run/Save/Load post the same message
        family as the tracer (the B2 move changed the panel's ADDRESS, not its
        contract). Presentational — it imports the ``flow_model`` data types
        read-only (no engine), and EVERY dynamic string renders markup-safe
        via ``safe_text`` (C-17).

    Data Flow:
        - Palette button / Add → block appended to ``self._blocks`` → canvas
          + ledger repaint.
        - Run → ``RunRequested(Flow(blocks=self._blocks), scope)`` → app →
          ``run_flow`` → :meth:`render_result`.

    Dependencies:
        Uses:
            - ``flow_model`` (block dataclasses + the A2B binding grammar,
              read-only per the R8 declared edge)
            - ``safe_text`` (markup-safe render)
        Used by:
            - ``S19TuiApp._compose_screen_flow`` /
              ``S19TuiApp.on_flow_builder_panel_run_requested``
    """

    #: The dropdown block-kind options (label, ``kind`` value). SOURCE is
    #: surfaced as "Load" (LLR-088.7 / D1) but keeps the ``BLOCK_SOURCE``
    #: ("source") discriminator so batch-53 persistence is unaffected. The A2B
    #: entry rides the same single-select; its two bindings use the dedicated
    #: ``#flow_ref_a`` / ``#flow_ref_b`` inputs (visible only for A2B).
    _KIND_OPTIONS = [
        ("Load (image)", BLOCK_SOURCE),
        ("Patch (change doc)", BLOCK_PATCH),
        ("Check (address list)", BLOCK_CHECK),
        ("CRC (template)", BLOCK_CRC),
        ("Write-out (file)", BLOCK_WRITE_OUT),
        ("A2B diff (2 inputs)", BLOCK_A2B),
    ]

    #: The fb_a palette rail — the three placeable block types the contract
    #: pins (TC-B94-20 census): patch / CRC / A2B-diff. Each button selects
    #: the matching ``#flow_kind`` entry (the chain kinds stay on the select).
    _PALETTE_TYPES = (
        ("▣", "PATCH", BLOCK_PATCH),
        ("⊕", "CRC", BLOCK_CRC),
        ("⏚", "A2B-DIFF", BLOCK_A2B),
    )

    #: The CHECK per-block gating options (label, gating value) — the minimal
    #: user-visible setter (LLR-086.1, the OPEN gating-UI flag). Read by Add
    #: only when the kind is CHECK; ignored otherwise.
    _GATING_OPTIONS = [
        ("advisory", CHECK_GATING_ADVISORY),
        ("block-own-op", CHECK_GATING_BLOCK_OWN),
    ]

    #: Run-scope options (batch-70 FB-P2, LLR-104.6). "This image" is the
    #: DEFAULT and is today's single-image run, so the new dimension is opt-in
    #: and an operator who never touches this control sees no change (AC-6).
    _SCOPE_OPTIONS = [
        ("This image", FLOW_SCOPE_SINGLE),
        ("All variants", FLOW_SCOPE_ALL_VARIANTS),
        ("Assigned variants", FLOW_SCOPE_ASSIGNMENTS),
    ]

    class RunRequested(Message):
        """The operator pressed Run — carries the composed flow to the app.

        Args:
            flow (Flow): The ordered typed-block flow to execute.
            scope (str): One of ``FLOW_SCOPES`` — which images to run over
                (batch-70 FB-P2). Defaults to the single-image run.
        """

        def __init__(self, flow: Flow, scope: str = FLOW_SCOPE_SINGLE) -> None:
            super().__init__()
            self.flow = flow
            self.scope = scope

    class SaveRequested(Message):
        """The operator pressed Save… — carries the current flow to the app.

        The app opens :class:`SaveFlowScreen` for the target name, then persists
        via ``save_flow_json`` (batch-53 FB-P1, LLR-003.2/.7).

        Args:
            flow (Flow): The current composed flow (name = the display name).
        """

        def __init__(self, flow: Flow) -> None:
            super().__init__()
            self.flow = flow

    class LoadRequested(Message):
        """The operator pressed Load… — the app opens :class:`LoadFlowScreen`.

        Carries nothing: the app lists ``flows/*.json`` and, on a chosen stem,
        loads through the hardened ``load_flow_json`` (LLR-003.3/.7).
        """

    def __init__(self) -> None:
        super().__init__(id="flow_panel")
        self._blocks: List[FlowBlock] = []
        #: Display name shown in the name strip; identity is the FILENAME on save.
        self._flow_name: str = "flow"
        #: Unsaved-edits flag — glyph ``●`` (dirty) / ``✓`` (saved), C-10 primary.
        self._dirty: bool = False

    def compose(self) -> ComposeResult:
        yield Static(
            self._name_strip_text(),
            id="flow_name_strip",
            markup=False,
            classes=self._name_strip_class(),
        )
        yield Label(
            "Flow Builder (fb_a): pick a block kind, enter its ref(s), Add; "
            "wire A2B inputs as a file name or #<n> (a flow output).",
            id="flow_help",
            markup=False,
        )
        yield Horizontal(
            *(
                Button(f"{glyph} {name}", id=f"flow_palette_{kind}")
                for glyph, name, kind in self._PALETTE_TYPES
            ),
            id="flow_palette",
        )
        yield Horizontal(
            Select(
                self._KIND_OPTIONS,
                value=BLOCK_SOURCE,
                allow_blank=False,
                id="flow_kind",
            ),
            Select(
                self._GATING_OPTIONS,
                value=CHECK_GATING_ADVISORY,
                allow_blank=False,
                id="flow_gating",
            ),
            OsClipboardInput(
                placeholder="ref (image / change-doc / output name)",
                id="flow_ref",
            ),
            OsClipboardInput(
                placeholder="image A — file or #n",
                id="flow_ref_a",
            ),
            OsClipboardInput(
                placeholder="image B — file or #n",
                id="flow_ref_b",
            ),
            Button("Add", id="flow_add"),
            id="flow_add_row",
        )
        yield Static(self._canvas_text(), id="flow_canvas", markup=False)
        yield Static("", id="flow_wiring_notice", markup=False)
        yield Static(self._blocks_text(), id="flow_blocks", markup=False)
        yield Horizontal(
            Select(
                self._SCOPE_OPTIONS,
                value=FLOW_SCOPE_SINGLE,
                allow_blank=False,
                id="flow_scope",
            ),
            Button("Run", id="flow_run", variant="primary"),
            Button("Clear", id="flow_clear"),
            Button("Save…", id="flow_save"),
            Button("Load…", id="flow_load"),
            id="flow_run_row",
        )
        yield VerticalScroll(id="flow_result")

    # -- name strip (unchanged tracer contract) ------------------------------

    def _name_strip_text(self) -> Text:
        """The name-strip line: ``Flow: <name>  <glyph>`` (glyph-primary, C-10).

        The name is rendered markup-safe (a loaded/imported name can be hostile);
        the glyph ``●`` (dirty) / ``✓`` (saved) is the PRIMARY state cue, colour
        the secondary one.
        """
        glyph = "●" if self._dirty else "✓"
        text = Text()
        text.append("Flow: ")
        text.append(safe_text(self._flow_name))
        text.append(f"  {glyph}")
        return text

    def _name_strip_class(self) -> str:
        """``sev-warning`` when dirty, ``sev-neutral`` when saved (secondary cue)."""
        return "flow-name-strip " + ("sev-warning" if self._dirty else "sev-neutral")

    def _refresh_name_strip(self) -> None:
        strip = self.query_one("#flow_name_strip", Static)
        strip.update(self._name_strip_text())
        strip.set_classes(self._name_strip_class())

    def _mark_dirty(self) -> None:
        """Flag unsaved edits and repaint the name strip."""
        self._dirty = True
        self._refresh_name_strip()

    @property
    def current_flow(self) -> Flow:
        """The current composed flow (name = the display name), for Save."""
        return Flow(name=self._flow_name, blocks=list(self._blocks))

    @property
    def is_dirty(self) -> bool:
        """Whether the flow has unsaved edits (the dirty-guard reads this)."""
        return self._dirty

    def set_blocks(self, flow: Flow, name: Optional[str] = None) -> None:
        """Replace the composed flow from a loaded :class:`Flow` (LLR-003.7).

        Summary:
            Swap in the loaded blocks, set the display name (the on-disk stem
            when the app passes ``name``, else the envelope name), clear the
            dirty flag (a just-loaded flow is clean), repaint the canvas +
            ledger strip + name strip, and clear any prior run/quarantine output.

        Args:
            flow (Flow): The validated, loaded flow.
            name (Optional[str]): The filename stem to show as identity; defaults
                to ``flow.name`` (the embedded display name).
        """
        self._blocks = list(flow.blocks)
        self._flow_name = name if name is not None else flow.name
        self._dirty = False
        self._refresh_blocks()
        self._refresh_name_strip()
        self.query_one("#flow_result", VerticalScroll).remove_children()

    def mark_saved(self, stem: str) -> None:
        """Record a successful save: identity = ``stem``, clear dirty, confirm.

        Mounts a ``✓ saved flows/<stem>.json`` note into ``#flow_result`` and
        repaints the name strip to the saved (``✓``) state (LLR-003.2).
        """
        self._flow_name = stem
        self._dirty = False
        self._refresh_name_strip()
        container = self.query_one("#flow_result", VerticalScroll)
        container.remove_children()
        container.mount(
            Static(
                safe_text(f"✓ saved flows/{stem}.json"),
                markup=False,
                classes="flow-save-note sev-ok",
            )
        )

    def render_quarantine(
        self, flow_name: str, findings: List[ValidationIssue]
    ) -> None:
        """Paint a rejected load's findings WITHOUT touching the current flow.

        Summary:
            Mount a bordered ``sev-error`` quarantine card into ``#flow_result``
            with a header, one markup-safe line per finding, and a
            ``Current flow unchanged.`` footer. ``set_blocks`` is NOT called, so
            the canvas + ledger and name strip are unchanged (LLR-003.5 / C-32).
            Every file-derived string (the picked name, each finding message) is
            rendered ``safe_text`` + ``markup=False`` (C-17).

        Args:
            flow_name (str): The rejected file's stem (untrusted — markup-safe).
            findings (List[ValidationIssue]): The loader's fail-closed findings.
        """
        container = self.query_one("#flow_result", VerticalScroll)
        container.remove_children()
        children: List[Static] = [
            Static(
                safe_text(
                    f"✗ LOAD REJECTED — flows/{flow_name}.json "
                    f"({len(findings)} findings)"
                ),
                markup=False,
                classes="flow-quarantine-head",
            )
        ]
        for finding in findings:
            children.append(
                Static(
                    safe_text(finding.message),  # SINK: file-derived finding text
                    markup=False,
                    classes="flow-quarantine-line",
                )
            )
        children.append(
            Static(
                "Current flow unchanged.",
                markup=False,
                classes="flow-quarantine-foot",
            )
        )
        container.mount(
            Container(*children, classes="flow-quarantine sev-error")
        )

    # -- fb_a canvas + ledger -------------------------------------------------

    def _block_rows(self, block: FlowBlock, index: int) -> List[Tuple[str, str, str]]:
        """The typed IO rows of one canvas block: (io, text, style) triples.

        Every file-derived label is scrubbed through ``safe_text`` (C-17 — the
        painted grid is a ``.plain`` surface, so control bytes must not survive
        into it); the structural tokens are author constants.
        """
        scrub = lambda s: safe_text(s).plain  # noqa: E731 - one-line sink guard
        chain_in = ("in", "← image", _S_VALUE)
        if isinstance(block, PatchBlock):
            return [
                chain_in,
                ("in", scrub(block.change_doc_ref), _S_VALUE),
                ("out", "image →", _S_OUT),
            ]
        if isinstance(block, CrcBlock):
            return [
                chain_in,
                ("in", scrub(block.config_ref), _S_VALUE),
                ("out", "image →", _S_OUT),
            ]
        if isinstance(block, CheckBlock):
            return [
                chain_in,
                ("in", scrub(block.check_doc_ref), _S_VALUE),
                ("out", "image →", _S_OUT),
            ]
        if isinstance(block, WriteOutBlock):
            return [
                chain_in,
                ("out", scrub(f"{block.output_name} ({block.fmt})"), _S_OUT),
            ]
        if isinstance(block, A2BBlock):
            return [
                ("in", scrub(_binding_label(block.image_a)), _S_VALUE),
                ("in", scrub(_binding_label(block.image_b)), _S_VALUE),
                ("out", "report →", _S_OUT),
            ]
        if isinstance(block, ReportBlock):
            return [("out", "report marker", _S_OUT)]
        return [("in", "?", _S_ERR)]

    def _layout(
        self,
    ) -> Tuple[List[Tuple[int, int, int, int]], dict[int, Tuple[int, int, int]], int]:
        """Walk the composed chain and lay out the fb_a canvas geometry.

        Returns:
            Tuple: ``(positions, chips, height)`` — ``positions`` holds one
            ``(x, y, height, out_row)`` per NON-source block in block order;
            ``chips`` maps source-block indices to ``(x, y, width)``; ``height``
            is the grid row count. Bands wrap left→right; every caller of this
            layout paints the SAME geometry (the canvas text and its height
            can never diverge).
        """
        blocks = self._blocks
        positions: List[Tuple[int, int, int, int]] = []  # x, y, h, out_row
        chips: dict[int, Tuple[int, int, int]] = {}
        y = 4
        x = 2
        band_bottom = y
        for index, block in enumerate(blocks):
            if isinstance(block, SourceBlock):
                label = safe_text(block.image_ref).plain
                label = f"{label} ({block.file_type})"
                w = max(10, len(label) + 2)
                if x > 2 and x + w > _CANVAS_COLS - 1:
                    x = 2
                    y = band_bottom + 2
                chips[index] = (x, y, w)
                x += w + 6
                continue
            h = len(self._block_rows(block, index)) + 2
            if x > 2 and x + _BLOCK_W > _CANVAS_COLS - 1:
                x = 2
                y = band_bottom + 2
            out_row = y + h - 2  # the last IO row carries the block's output
            positions.append((x, y, h, out_row))
            band_bottom = max(band_bottom, y + h)
            x += _BLOCK_W + 6
        height = max(band_bottom + 2, 6)
        return positions, chips, height

    def _canvas_text(self) -> Text:
        """Paint the fb_a canvas: framed grid, source chips, box blocks, cables.

        Pure projection of ``self._blocks`` — the composed chain IS the model
        (SOURCE blocks paint as file chips, everything else as box-drawn
        blocks with typed in/out stubs), so the canvas can never disagree
        with what Run executes. All file-derived labels ride ``safe_text``
        into the grid (C-17).
        """
        blocks = self._blocks
        positions, chips, height = self._layout()
        g = _Grid(_CANVAS_COLS, height)
        g.box(0, 0, _CANVAS_COLS, height)
        g.put(
            2,
            0,
            f" canvas · grid on · {len(blocks)} block"
            f"{'' if len(blocks) == 1 else 's'} ",
            _S_DIM,
        )
        for yy in (2, height - 2):
            if 0 < yy < height - 1:
                for xx in range(4, _CANVAS_COLS - 2, 8):
                    if g.ch[yy][xx] == " ":
                        g.put(xx, yy, "·", _S_RULE)
        if not blocks:
            g.puts(
                4,
                height // 2,
                ("(empty canvas — place a block from the palette)", _S_DIM),
            )
            return _join_lines(g.lines())

        live = [i for i in range(len(blocks)) if i not in chips]
        pos_of = dict(zip(live, positions))

        # Block pass: box-drawn blocks (header bar on the top edge, typed IO
        # rows inside, ``┤├`` stubs where cables land).
        titles = {
            BLOCK_PATCH: "PATCH",
            BLOCK_CRC: "CRC",
            BLOCK_CHECK: "CHECK",
            BLOCK_WRITE_OUT: "WRITE-OUT",
            BLOCK_A2B: "A2B-DIFF",
        }
        for index in live:
            block = blocks[index]
            x, y, h, _out_row = pos_of[index]
            rows = self._block_rows(block, index)
            _plc_block(
                g, x, y, _BLOCK_W,
                titles.get(block.kind, block.kind.upper()), rows,
            )

        # Chip pass: source file chips with their drop onto the next block.
        for index, (cx, cy, w) in chips.items():
            label = safe_text(blocks[index].image_ref).plain
            label = f"{label} ({blocks[index].file_type})"
            col = _chip(g, cx, cy, label, w)
            if index + 1 < len(blocks) and (index + 1) in pos_of:
                nxt_x, nxt_y, _h, _o = pos_of[index + 1]
                if nxt_y > cy + 3:
                    g.fill(col, cy + 3, nxt_y - cy - 3, "│", _S_WIRE)
                g.put(col, nxt_y, "┬", _S_WIRE)

        # Cable pass: threaded-image cables between consecutive blocks (never
        # INTO an A2B — its image inputs are explicit bindings), plus explicit
        # A2B binding cables from the producing block's out stub.
        for index in live:
            if index == 0:
                continue
            pos = pos_of[index]
            block = blocks[index]
            if not isinstance(block, A2BBlock) and (index - 1) in pos_of:
                prev_pos = pos_of[index - 1]
                _wire_bend(
                    g,
                    prev_pos[0] + _BLOCK_W - 1,
                    prev_pos[3],
                    pos[0],
                    pos[1] + 1,
                )
            if isinstance(block, A2BBlock):
                for binding, row in (
                    (block.image_a, 1),
                    (block.image_b, 2),
                ):
                    if binding.source != A2B_INPUT_FLOW:
                        continue
                    src = int(binding.ref)
                    if src in pos_of:
                        src_pos = pos_of[src]
                        _wire_bend(
                            g,
                            src_pos[0] + _BLOCK_W - 1,
                            src_pos[3],
                            pos[0],
                            pos[1] + row,
                        )
                    elif src in chips:
                        # A flow binding onto a source chip: drop onto the row.
                        cx, cy, w = chips[src]
                        col = cx + w // 2
                        target_row = pos[1] + row
                        if target_row > cy + 3:
                            g.fill(col, cy + 3, target_row - cy - 3, "│", _S_WIRE)
                        g.put(col, target_row, "┬", _S_WIRE)

        return _join_lines(g.lines())

    def _blocks_text(self) -> Text:
        if not self._blocks:
            return safe_text("(no blocks yet)")
        text = Text()
        for position, block in enumerate(self._blocks, start=1):
            text.append(f"{position}. ")
            text.append(safe_text(_flow_block_label(block)))
            text.append("\n")
        return text

    def _refresh_blocks(self) -> None:
        self.query_one("#flow_blocks", Static).update(self._blocks_text())
        self.query_one("#flow_canvas", Static).update(self._canvas_text())

    # -- wiring -------------------------------------------------------------

    def _show_wiring_notice(self, message: str) -> None:
        """Paint/clear the wiring refusal line (markup-safe; empty hides it)."""
        notice = self.query_one("#flow_wiring_notice", Static)
        if message:
            notice.update(safe_text(message))  # SINK: file-derived ref text
            notice.display = True
            notice.set_classes("sev-warning")
        else:
            notice.update("")
            notice.display = False

    def _add_a2b_block(self) -> None:
        """Parse + validate the two A2B bindings; refuse illegal wiring (HLR-014).

        A refusal paints the wiring notice and adds NOTHING — a refused
        binding never enters the flow, so no report is ever produced for it.
        """
        binding_a = parse_a2b_binding(
            self.query_one("#flow_ref_a", Input).value
        )
        binding_b = parse_a2b_binding(
            self.query_one("#flow_ref_b", Input).value
        )
        if binding_a is None or binding_b is None:
            self._show_wiring_notice(
                "A2B wiring refused: empty or malformed binding — use a file "
                "name or #<n> (a flow output)."
            )
            return
        block = A2BBlock(image_a=binding_a, image_b=binding_b)
        reasons = validate_a2b_bindings(block, self._blocks)
        if reasons:
            self._show_wiring_notice("A2B wiring refused: " + "; ".join(reasons))
            return
        self._show_wiring_notice("")
        self._blocks.append(block)
        self.query_one("#flow_ref_a", Input).value = ""
        self.query_one("#flow_ref_b", Input).value = ""
        self._refresh_blocks()
        self._mark_dirty()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id is not None and event.button.id.startswith(
            "flow_palette_"
        ):
            kind = event.button.id.removeprefix("flow_palette_")
            self.query_one("#flow_kind", Select).value = kind
            self._sync_kind_dependent_visibility(kind)
            return
        if event.button.id == "flow_add":
            kind = str(self.query_one("#flow_kind", Select).value)
            if kind == BLOCK_A2B:
                self._add_a2b_block()
                return
            ref = self.query_one("#flow_ref", Input).value
            gating = str(self.query_one("#flow_gating", Select).value)
            block = _make_flow_block(kind, ref, gating)
            if block is None:
                return
            self._blocks.append(block)
            self.query_one("#flow_ref", Input).value = ""
            self._show_wiring_notice("")
            self._refresh_blocks()
            self._mark_dirty()
        elif event.button.id == "flow_run":
            self.post_message(
                self.RunRequested(
                    Flow(name=self._flow_name, blocks=list(self._blocks)),
                    str(self.query_one("#flow_scope", Select).value),
                )
            )
        elif event.button.id == "flow_save":
            self.post_message(self.SaveRequested(self.current_flow))
        elif event.button.id == "flow_load":
            self.post_message(self.LoadRequested())
        elif event.button.id == "flow_clear":
            had_blocks = bool(self._blocks)
            self._blocks.clear()
            self._refresh_blocks()
            self._show_wiring_notice("")
            self.query_one("#flow_result", VerticalScroll).remove_children()
            if had_blocks:
                self._mark_dirty()

    def on_mount(self) -> None:
        # F3 (LLR-094.3): the per-block gating control is CHECK-only — hidden
        # for SOURCE (default), PATCH, WRITE-OUT, CRC and A2B; the A2B binding
        # inputs show only for A2B, the single ref for every other kind.
        self._sync_kind_dependent_visibility(
            str(self.query_one("#flow_kind", Select).value)
        )
        self._show_wiring_notice("")

    def on_select_changed(self, event: Select.Changed) -> None:
        # Only the block-kind selector toggles the ref-row visibility.
        if event.select.id == "flow_kind":
            self._sync_kind_dependent_visibility(str(event.value))

    def _sync_kind_dependent_visibility(self, kind: str) -> None:
        """Show the gating control only for CHECK, the binding inputs only for
        A2B, and the single ref for every other kind (F3)."""
        self.query_one("#flow_gating", Select).display = kind == BLOCK_CHECK
        self.query_one("#flow_ref", Input).display = kind != BLOCK_A2B
        self.query_one("#flow_ref_a", Input).display = kind == BLOCK_A2B
        self.query_one("#flow_ref_b", Input).display = kind == BLOCK_A2B

    # -- run result ledger (Direction A Pipeline Ledger, unchanged) -----------

    def render_result(self, result: FlowRunResult) -> None:
        """Paint the ``#flow_result`` pane as the Direction-A Pipeline Ledger.

        Summary:
            Mount, into the ``#flow_result`` :class:`VerticalScroll`, the
            flow-status banner (LLR-088.5), one vertical block-node per
            ``BlockResult`` with a ``sev-*`` status gutter (LLR-088.1/.2), an
            ``N−1`` bordered separator between nodes (LLR-088.3), the single
            memory ribbon of the image footprint (LLR-088.4 / §6.5 AMD-1), and
            the written-path lines. EVERY file-derived string is rendered in its
            OWN ``Static(safe_text(...), markup=False)`` so a hostile payload
            renders literally (LLR-088.6 / C-17); the banner + ribbon are
            enum/int-derived and are correctly out of that sweep.

        Args:
            result (FlowRunResult): The run outcome to paint.

        Returns:
            None
        """
        container = self.query_one("#flow_result", VerticalScroll)
        container.remove_children()

        widgets: List[Widget] = []

        banner_text, banner_class = _FLOW_STATUS_BANNER.get(
            result.status, (result.status.upper(), "sev-neutral")
        )
        widgets.append(
            Static(banner_text, markup=False, classes=f"flow-banner {banner_class}")
        )

        blocks = result.block_results
        for position, block_result in enumerate(blocks):
            sev = _BLOCK_STATUS_SEV_CLASS.get(block_result.status, "sev-neutral")
            glyph = _BLOCK_STATUS_GLYPH.get(block_result.status, "·")
            head = Text(f"{glyph} {block_result.kind:<9} {block_result.status}")
            node_children: List[Static] = [
                Static(head, markup=False, classes="flow-node-head")
            ]
            if block_result.summary:
                node_children.append(
                    Static(
                        safe_text(block_result.summary),  # SINK: summary
                        markup=False,
                        classes="flow-node-summary",
                    )
                )
            for finding in block_result.findings:
                node_children.append(
                    Static(
                        safe_text(finding.message),  # SINK: finding message
                        markup=False,
                        classes="flow-finding sev-warning",
                    )
                )
            for diagnostic in block_result.diagnostics:
                node_children.append(
                    Static(
                        safe_text(diagnostic),  # SINK: diagnostic
                        markup=False,
                        classes="flow-diag sev-error",
                    )
                )
            widgets.append(
                Vertical(*node_children, classes=f"flow-node {sev}")
            )
            if position < len(blocks) - 1:
                widgets.append(Static("", classes="flow-sep"))

        # §6.5 AMD-1 twin ribbon (LLR-094.1/.2): when a CRC block grew the image
        # (pre_crc_ranges differs from the final footprint), render a "before"
        # strip over a COMMON axis so the CRC-added window shows as extra filled
        # cells on the after strip. No growth → single strip (batch-51 behaviour,
        # existing `.flow-ribbon` class + caption unchanged).
        after_ranges = result.image_ranges
        before_ranges = result.pre_crc_ranges
        grown = bool(before_ranges) and list(before_ranges) != list(after_ranges)
        if grown and after_ranges:
            axis = (
                min(start for start, _ in after_ranges),
                max(end for _, end in after_ranges),
            )
            widgets.append(
                Static(
                    _memory_ribbon_text(before_ranges, window=axis),
                    markup=False,
                    classes="flow-ribbon-before sev-neutral",
                )
            )
            widgets.append(
                Static(
                    "before: " + _ribbon_caption(before_ranges),
                    markup=False,
                    classes="flow-ribbon-before-cap sev-neutral",
                )
            )
        widgets.append(
            Static(
                _memory_ribbon_text(after_ranges),
                markup=False,
                classes="flow-ribbon sev-info",
            )
        )
        widgets.append(
            Static(
                (("after: " if grown else "") + _ribbon_caption(after_ranges)),
                markup=False,
                classes="flow-ribbon-cap sev-neutral",
            )
        )

        for path in result.written_paths:
            widgets.append(
                Static(
                    safe_text(str(path)),  # SINK: written path
                    markup=False,
                    classes="flow-wrote sev-ok",
                )
            )
        for diagnostic in result.diagnostics:
            widgets.append(
                Static(
                    safe_text(diagnostic),  # SINK: flow-diagnostic
                    markup=False,
                    classes="flow-run-diag sev-error",
                )
            )

        container.mount(*widgets)

    def render_fused_result(self, fused: FusedFlowRunResult) -> None:
        """Paint ``#flow_result`` for a MULTI-IMAGE run (batch-70 FB-P2).

        Summary:
            Mount the rolled-up status banner, the line that INVERTS it
            (``n_ok`` / ``n_issues`` / ``n_error``, D-5 — a single word over N
            images hides exactly what the operator pressed Run to see), one
            node per variant carrying that variant's own status and block
            summaries, and the single fused report path. Every file-derived
            string — ``variant_id``, block summaries, diagnostics, the report
            path — gets its OWN ``Static(safe_text(...), markup=False)`` so a
            hostile payload renders literally (C-17); the banner and the counts
            are enum/int-derived and are correctly outside that sweep.

        Args:
            fused (FusedFlowRunResult): The multi-image run outcome.

        Returns:
            None

        Dependencies:
            Uses:
                - ``safe_text`` / ``_FLOW_STATUS_BANNER`` / ``_BLOCK_STATUS_SEV_CLASS``
            Used by:
                - ``S19TuiApp.on_flow_builder_panel_run_requested``
        """
        container = self.query_one("#flow_result", VerticalScroll)
        container.remove_children()

        banner_text, banner_class = _FLOW_STATUS_BANNER.get(
            fused.status, (fused.status.upper(), "sev-neutral")
        )
        widgets: List[Widget] = [
            Static(banner_text, markup=False, classes=f"flow-banner {banner_class}"),
            Static(
                f"{len(fused.variant_outcomes)} variant(s): "
                f"{fused.n_ok} ok / {fused.n_issues} issues / {fused.n_error} error",
                markup=False,
                classes="flow-node-summary sev-neutral",
            ),
        ]

        for position, outcome in enumerate(fused.variant_outcomes):
            # Reuse the banner map's severity half rather than forking a second
            # status→class table that could drift out of step with it.
            sev = _FLOW_STATUS_BANNER.get(
                outcome.result.status, ("", "sev-neutral")
            )[1]
            node_children: List[Static] = [
                Static(
                    safe_text(f"{outcome.variant_id}  —  {outcome.result.status}"),
                    markup=False,  # SINK: variant_id
                    classes="flow-node-head",
                )
            ]
            for block_result in outcome.result.block_results:
                glyph = _BLOCK_STATUS_GLYPH.get(block_result.status, "·")
                node_children.append(
                    Static(
                        safe_text(  # SINK: block kind + summary
                            f"{glyph} {block_result.kind:<9} {block_result.summary}"
                        ),
                        markup=False,
                        classes="flow-node-summary",
                    )
                )
            for diagnostic in outcome.result.diagnostics:
                node_children.append(
                    Static(
                        safe_text(diagnostic),  # SINK: diagnostic
                        markup=False,
                        classes="flow-diag sev-error",
                    )
                )
            widgets.append(Vertical(*node_children, classes=f"flow-node {sev}"))
            if position < len(fused.variant_outcomes) - 1:
                widgets.append(Static("", classes="flow-sep"))

        if fused.report_path is not None:
            widgets.append(
                Static(
                    safe_text(f"fused report: {fused.report_path}"),  # SINK: path
                    markup=False,
                    classes="flow-wrote sev-ok",
                )
            )
        for diagnostic in fused.diagnostics:
            widgets.append(
                Static(
                    safe_text(diagnostic),  # SINK: run diagnostic
                    markup=False,
                    classes="flow-run-diag sev-error",
                )
            )

        container.mount(*widgets)


def _join_lines(lines: List[Text]) -> Text:
    """Join painted grid lines into one multi-line ``Text`` (markup-safe:
    built by append, never markup-parsed)."""
    out = Text()
    for i, line in enumerate(lines):
        if i:
            out.append("\n")
        out.append_text(line)
    return out
