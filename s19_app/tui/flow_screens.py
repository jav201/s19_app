"""Flow Builder + Flow Execution surfaces (batch-94, ARQ R8; Inc-002 fb_a,
Inc-003 fx_a).

This module is the R8 home of the flow family: the reworked fb_a
:class:`FlowBuilderPanel` (Inc-002) and the fx_a
:class:`FlowExecutionPanel` (Inc-003 — US-007, HLR-017…021). Pure view layer —
the panels and their ``ActionRequested``-kin message types; flow execution
SEMANTICS stays in ``services/flow_*`` (messages out, services never called
directly; the one declared data edge ``flow_screens → services/flow_model``
is read-only constants/dataclasses per ``docs/architecture.md`` §10).

fb_a doctrine (the ratified spike graduation call, ``flow_bench.NOTES.md`` —
"connectivity is the builder's job"): a block palette rail, a framed canvas
with sparse grid dots, full-cell box-drawn blocks (header bar, typed ``in`` /
``out`` IO rows, ``┤├`` stubs) and ``─│└┐`` cable runs between stubs; the
fb_c audit precision folds in as the numbered ledger strip (``#flow_blocks``).
The A2B diff block binds each image input to a flow output (``#<n>`` — an
upstream block of the CURRENT flow) or a project-relative file, with ≥1 input
from this flow enforced at wiring time (HLR-014); SOURCE blocks render as file
chips dropping onto the next block's image row.

fx_a doctrine (``flow_bench.NOTES.md``: per-chain carriles + the RUN LOG
strip — the operator's suggestion #1, mid-chain failure visible inline):
imported templates mount one lane per chain, side by side; each lane paints
its pinned inputs, a shaded ``▓/░`` progress bar and a status glyph
(``▶✗✓``); the run-log strip below names a failed chain's block and its
missing config on one inline ``✗`` line. The panel is presentational — Run
posts the lane payloads to the app, the app runs the service's chain-set
runner and hands the record back for painting; Save Set / Load Set post the
same way. Every file-derived string renders through ``safe_text`` (C-17).

No engine code is imported beyond the read-only flow-model data types; every
file-derived string renders through ``safe_text`` (C-17).

batch-96 B1/B2 additions: the FUNNEL table editor (a flow-level name→value
declaration, batch-96 B1) and block COPY/PASTE (batch-96 B2) reuse the real
persistence serializer/loader (``flow_persistence_service.flow_to_dict`` /
``dict_to_flow``) — the clipboard stores the WIRE projection of one block,
never a live instance, and paste re-validates the wire dict through the
hardened loader against the current flow's own blocks. That is the second
declared ``flow_screens → services`` edge; both are pure
serialize/validate, no execution semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

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
    YELLOW,
)
from .os_clipboard_input import OsClipboardInput
from .services import flow_persistence_service as fps
from .services.flow_model import (
    A2BBlock,
    A2B_INPUT_FILE,
    A2B_INPUT_FLOW,
    BLOCK_A2B,
    BLOCK_CHECK,
    BLOCK_CRC,
    BLOCK_EXTERNAL_STEP,
    BLOCK_PATCH,
    BLOCK_SOURCE,
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    BLOCK_STATUS_WAITING,
    BLOCK_WRITE_OUT,
    CHECK_GATING_ADVISORY,
    CHECK_GATING_BLOCK_OWN,
    EXTERNAL_MODE_MANUAL,
    EXTERNAL_MODE_TERMINAL,
    FLOW_SCOPE_ALL_VARIANTS,
    FLOW_SCOPE_ASSIGNMENTS,
    FLOW_SCOPE_SINGLE,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    FLOW_STATUS_PAUSED,
    FUNNEL_NAME_RE,
    CheckBlock,
    CrcBlock,
    ExternalStepBlock,
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
    if isinstance(block, ExternalStepBlock):
        noun = "CMD" if block.mode == EXTERNAL_MODE_TERMINAL else "INSTR"
        return (
            f"EXT-STEP ({block.mode})  {noun} {block.instruction}  "
            f"log {block.log_ref}  ->  {block.output_path}"
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
    # prototype v3: a waiting external step is a PAUSE, not a failure —
    # amber, the advisory carrier.
    BLOCK_STATUS_WAITING: "sev-warning",
}

#: A per-status gutter glyph (enum-derived, never file-derived).
_BLOCK_STATUS_GLYPH = {
    BLOCK_STATUS_OK: "●",        # ● ok
    BLOCK_STATUS_NOTICES: "◈",   # ◈ notices
    BLOCK_STATUS_ERROR: "✖",     # ✖ error
    BLOCK_STATUS_SKIPPED: "○",   # ○ skipped
    # prototype v3: □ — a queued chain cell (the fx_a ▓/□ doctrine): a
    # waiting external step is the chain waiting for the human. (⏸ U+23F8
    # falls to a blue emoji in Windows Terminal even with VS15 — measured.)
    BLOCK_STATUS_WAITING: "□",   # □ waiting (esperando humano)
}

#: Flow-status → (banner text, ``sev-*`` class) (LLR-088.5). The banner text is
#: derived from the status ENUM, so it is NOT a markup sink (out of the C-17
#: sweep — the coordinator's exclusion, security F1).
_FLOW_STATUS_BANNER = {
    FLOW_STATUS_OK: ("CLEAN", "sev-ok"),
    FLOW_STATUS_ISSUES: ("ISSUES", "sev-warning"),
    FLOW_STATUS_ERROR: ("FAILED", "sev-error"),
    # prototype v3 (spec "paso externo"): the paused banner — the run waits
    # for the human at an external step.
    FLOW_STATUS_PAUSED: ("PAUSED - ESPERANDO HUMANO", "sev-warning"),
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

#: External-step block geometry (prototype v3): the block carries the mode,
#: the instruction/command, the MANDATORY log row and the output row — 24
#: cells clip every real value, so the human-gated block paints wider (the
#: same box composer, just a wider cell budget).
_EXT_BLOCK_W = 44


def _block_width(block: FlowBlock) -> int:
    """The canvas cell budget of one block's box (EXT-STEP paints wider)."""
    if isinstance(block, ExternalStepBlock):
        return _EXT_BLOCK_W
    return _BLOCK_W


def _short_ext(text: str, width: int) -> str:
    """Ellipsis-tail fit for a painted row (the lane-paint ``[:w-4]`` idiom,
    but keeping the TAIL — paths keep their name, not their root)."""
    if len(text) <= width:
        return text
    return "…" + text[-(width - 1):]

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
        for yy in range(y_in + 1, y_out):
            g.put(xv, yy, "│", _S_WIRE)
    g.put(xv, y_in, "└", _S_WIRE)
    g.fill(xv + 1, y_in, x_to - xv - 1, "─", _S_WIRE)
    g.put(x_to, y_in, "├", _S_WIRE)


def _wire_drop(
    g: _Grid,
    x_from: int,
    y_out: int,
    col_in: int,
    y_dest: int,
) -> None:
    """Band-wrap drop (the chip-drop idiom): the next block wrapped to a new
    band, so the threaded-image cable leaves the out stub, steps right one
    cell, drops to the free row above the destination band and lands on the
    block's TOP edge (``┬``, ``col_in`` clear of the title) — never crossing
    a block cell."""
    xv = x_from + 1
    if col_in >= xv:
        return  # no honest path — leave the blocks uncabled
    y_tramo = y_dest - 1
    g.put(x_from, y_out, "┤", _S_WIRE)
    g.put(xv, y_out, "┐", _S_WIRE)
    for yy in range(y_out + 1, y_tramo):
        g.put(xv, yy, "│", _S_WIRE)
    g.put(xv, y_tramo, "┘", _S_WIRE)
    g.fill(col_in + 1, y_tramo, xv - col_in - 1, "─", _S_WIRE)
    # Landing elbow: arriving from the right, turning DOWN into the block's
    # top edge — ┌ (right+down). (A backwards └ here drew a spurious up-stub
    # that read as a doubled line; caught in the operator's 2026-10-18 review.)
    g.put(col_in, y_tramo, "┌", _S_WIRE)
    g.put(col_in, y_dest, "┬", _S_WIRE)


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
        # prototype v3 (spec "paso externo"): the human-gated step.
        ("External step (human)", BLOCK_EXTERNAL_STEP),
    ]

    #: The external-step mode options (label, mode value) — TERMINAL runs an
    #: exact command outside the app; MANUAL shows the instruction. Both
    #: ALWAYS carry the mandatory log + the output file (spec v3).
    _EXT_MODE_OPTIONS = [
        ("Terminal (exact command)", EXTERNAL_MODE_TERMINAL),
        ("Manual (instruction)", EXTERNAL_MODE_MANUAL),
    ]

    #: The fb_a palette rail — the three placeable block types the contract
    #: pins (TC-B94-20 census): patch / CRC / A2B-diff. Each button selects
    #: the matching ``#flow_kind`` entry (the chain kinds stay on the select).
    #: prototype v3 adds the external-step type to the same rail idiom.
    _PALETTE_TYPES = (
        ("▣", "PATCH", BLOCK_PATCH),
        ("⊕", "CRC", BLOCK_CRC),
        ("⏚", "A2B-DIFF", BLOCK_A2B),
        ("»", "EXT-STEP", BLOCK_EXTERNAL_STEP),
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
        #: The session artifact dir (the active project work area) — ALWAYS
        #: shown under the add row (spec v3); set by the app via
        #: :meth:`set_session_dir`.
        self._session_dir: Optional[str] = None
        #: The flow-level FUNNEL table (batch-96 B1) — ordered (name, value)
        #: pairs declared beside the canvas; rides ``current_flow`` into
        #: Run/Save and is restored by ``set_blocks``.
        self._funnel: List[Tuple[str, str]] = []
        #: The block COPY/PASTE clipboard (batch-96 B2) — the WIRE dict of
        #: ONE block (the ``flow_to_dict`` projection), never a live
        #: instance, so a paste always builds a fresh block object.
        self._clipboard: Optional[dict] = None

    def set_session_dir(self, path: str) -> None:
        """Publish the session artifact dir (spec v3: ALWAYS on screen)."""
        self._session_dir = path
        try:
            strip = self.query_one("#flow_ext_session", Static)
        except Exception:
            return  # not mounted yet — the compose default paints instead
        strip.update(
            safe_text(
                f"sesión: {path} — al confirmar, la SALIDA se copia aquí"
            )
        )

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
        palette_row = Horizontal(
            *(
                Button(f"{glyph} {name}", id=f"flow_palette_{kind}")
                for glyph, name, kind in self._PALETTE_TYPES
            ),
            id="flow_palette",
        )
        palette_row.styles.height = 3
        yield palette_row
        kind_select = Select(
            self._KIND_OPTIONS,
            value=BLOCK_SOURCE,
            allow_blank=False,
            id="flow_kind",
        )
        kind_select.styles.width = 28
        gating_select = Select(
            self._GATING_OPTIONS,
            value=CHECK_GATING_ADVISORY,
            allow_blank=False,
            id="flow_gating",
        )
        gating_select.styles.width = 18
        ref_input = OsClipboardInput(
            placeholder="ref (image / change-doc / output name)",
            id="flow_ref",
        )
        ref_input.styles.width = 50
        ref_a_input = OsClipboardInput(
            placeholder="image A — file or #n",
            id="flow_ref_a",
        )
        ref_a_input.styles.width = 22
        ref_b_input = OsClipboardInput(
            placeholder="image B — file or #n",
            id="flow_ref_b",
        )
        ref_b_input.styles.width = 22
        add_button = Button("Add", id="flow_add")
        add_button.styles.width = 8
        add_row = Horizontal(
            kind_select,
            gating_select,
            ref_input,
            ref_a_input,
            ref_b_input,
            add_button,
            id="flow_add_row",
        )
        #: Altura explícita: los hijos (Select/Input/Button) miden 3 filas y
        #: un Horizontal de altura 1 solapa al hermano siguiente (artefacto
        #: de rasterización con overflow del panel).
        add_row.styles.height = 3
        yield add_row
        # prototype v3 (spec "paso externo"): the external-step config row —
        # mode, instruction/command, MANDATORY log ref, output path. Visible
        # only when the kind select is on External step (the F3 idiom).
        ext_mode_select = Select(
            self._EXT_MODE_OPTIONS,
            value=EXTERNAL_MODE_TERMINAL,
            allow_blank=False,
            id="flow_ext_mode",
        )
        ext_mode_select.styles.width = 26
        ext_instruction_input = OsClipboardInput(
            placeholder="comando exacto (terminal) / instrucción (manual)",
            id="flow_ext_instruction",
        )
        ext_instruction_input.styles.width = 28
        ext_log_input = OsClipboardInput(
            placeholder="LOG — obligatorio (texto de constancia)",
            id="flow_ext_log",
        )
        ext_log_input.styles.width = 26
        ext_output_input = OsClipboardInput(
            placeholder="SALIDA — path absoluto preferido",
            id="flow_ext_output",
        )
        ext_output_input.styles.width = 28
        ext_row = Horizontal(
            ext_mode_select,
            ext_instruction_input,
            ext_log_input,
            ext_output_input,
            id="flow_ext_row",
        )
        ext_row.styles.height = 3
        yield ext_row
        #: The session directory is ALWAYS on screen (spec v3): on confirm the
        #: flow copies the external step's output file INTO this folder and
        #: downstream blocks reference that copy.
        yield Static(
            "sesión: (sin proyecto activo — el directorio de sesión se "
            "muestra al cargar un proyecto)",
            id="flow_ext_session",
            markup=False,
            classes="flow-node-summary sev-neutral",
        )
        # batch-96 B1: the FUNNEL editor — a collapsible flow-level table of
        # ${NAME} → value declarations (one per flow), applied to PATCH
        # change-doc texts at run time.
        yield Button("Funnel (0)", id="flow_funnel_toggle")
        funnel_name_input = OsClipboardInput(
            placeholder="VARIABLE ([A-Z0-9_])",
            id="flow_funnel_name",
        )
        funnel_name_input.styles.width = 24
        funnel_value_input = OsClipboardInput(
            placeholder="valor a sustituir",
            id="flow_funnel_value",
        )
        funnel_value_input.styles.width = 30
        funnel_add = Button("Añadir var", id="flow_funnel_add")
        funnel_add.styles.width = 14
        funnel_editor = Horizontal(
            funnel_name_input,
            funnel_value_input,
            funnel_add,
            id="flow_funnel_editor",
        )
        funnel_editor.styles.height = 3
        yield funnel_editor
        yield Static("", id="flow_funnel_list", markup=False)
        # batch-96 B2: block COPY/PASTE — the canvas has no block selection,
        # so the ledger number (1-based, empty = last) picks the block.
        pick_input = OsClipboardInput(
            placeholder="nº",
            id="flow_pick",
        )
        pick_input.styles.width = 6
        copy_button = Button("Copiar", id="flow_copy")
        copy_button.styles.width = 10
        paste_button = Button("Pegar", id="flow_paste")
        paste_button.styles.width = 10
        clip_status = Static("", id="flow_clip_status", markup=False)
        clip_row = Horizontal(
            pick_input,
            copy_button,
            paste_button,
            clip_status,
            id="flow_clip_row",
        )
        clip_row.styles.height = 3
        yield clip_row
        yield Static(self._canvas_text(), id="flow_canvas", markup=False)
        yield Static("", id="flow_wiring_notice", markup=False)
        yield Static(self._blocks_text(), id="flow_blocks", markup=False)
        run_row = Horizontal(
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
        run_row.styles.height = 3
        yield run_row
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
        return Flow(
            name=self._flow_name,
            blocks=list(self._blocks),
            funnel=tuple(self._funnel),
        )

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
        #: batch-96 B1: a loaded flow's funnel table replaces the canvas one.
        self._funnel = list(flow.funnel)
        self._dirty = False
        self._refresh_blocks()
        self._refresh_funnel_list()
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
        if isinstance(block, ExternalStepBlock):
            # prototype v3 (spec "paso externo"): the block shows the mode's
            # payload (the exact command for TERMINAL, the instruction for
            # MANUAL), the MANDATORY log row and the output row. Rows are
            # tail-fitted to the wider EXT-STEP box (paths keep their name).
            inner = _EXT_BLOCK_W - 8
            noun = "cmd" if block.mode == EXTERNAL_MODE_TERMINAL else "instr"
            return [
                chain_in,
                ("in", scrub(f"{noun} {_short_ext(block.instruction, inner)}"), _S_VALUE),
                ("out", scrub(f"log → {_short_ext(block.log_ref, inner - 5)}"), _S_OUT),
                ("out", scrub(f"file → {_short_ext(block.output_path, inner - 7)}"), _S_OUT),
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
    ) -> Tuple[List[Tuple[int, int, int, int, int]], dict[int, Tuple[int, int, int]], int]:
        """Walk the composed chain and lay out the fb_a canvas geometry.

        Returns:
            Tuple: ``(positions, chips, height)`` — ``positions`` holds one
            ``(x, y, height, out_row, width)`` per NON-source block in block
            order (``width`` is the block's own box budget — EXT-STEP paints
            wider); ``chips`` maps source-block indices to ``(x, y, width)``;
            ``height`` is the grid row count. Bands wrap left→right; every
            caller of this layout paints the SAME geometry (the canvas text
            and its height can never diverge).
        """
        blocks = self._blocks
        positions: List[Tuple[int, int, int, int, int]] = []  # x, y, h, out_row, w
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
            bw = _block_width(block)
            h = len(self._block_rows(block, index)) + 2
            if x > 2 and x + bw > _CANVAS_COLS - 1:
                x = 2
                y = band_bottom + 2
            out_row = y + h - 2  # the last IO row carries the block's output
            positions.append((x, y, h, out_row, bw))
            band_bottom = max(band_bottom, y + h)
            x += bw + 6
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
            x, y, h, _out_row, w = pos_of[index]
            rows = self._block_rows(block, index)
            if isinstance(block, ExternalStepBlock):
                mode_tag = (
                    "TERMINAL" if block.mode == EXTERNAL_MODE_TERMINAL
                    else "MANUAL"
                )
                title = f"EXT-STEP · {mode_tag}"
            else:
                title = titles.get(block.kind, block.kind.upper())
            _plc_block(g, x, y, w, title, rows)

        # Chip pass: source file chips with their drop onto the next block.
        for index, (cx, cy, w) in chips.items():
            label = safe_text(blocks[index].image_ref).plain
            label = f"{label} ({blocks[index].file_type})"
            col = _chip(g, cx, cy, label, w)
            if index + 1 < len(blocks) and (index + 1) in pos_of:
                nxt_x, nxt_y, _h, _o, _w = pos_of[index + 1]
                if nxt_y > cy + 3:
                    for yy in range(cy + 3, nxt_y):
                        g.put(col, yy, "│", _S_WIRE)
                g.put(col, nxt_y, "┬", _S_WIRE)

        # Cable pass: threaded-image cables between consecutive blocks (never
        # INTO an A2B — its image inputs are explicit bindings), plus explicit
        # A2B binding cables from the producing block's out stub. A block that
        # wrapped to a NEW band takes the chip-drop cable (_wire_drop), not
        # the in-stub bend.
        for index in live:
            if index == 0:
                continue
            pos = pos_of[index]
            block = blocks[index]
            if not isinstance(block, A2BBlock) and (index - 1) in pos_of:
                prev_pos = pos_of[index - 1]
                if prev_pos[1] != pos[1]:
                    if isinstance(block, ExternalStepBlock):
                        mode_tag = (
                            "TERMINAL"
                            if block.mode == EXTERNAL_MODE_TERMINAL
                            else "MANUAL"
                        )
                        dest_title = f"[ EXT-STEP · {mode_tag} ]"
                    else:
                        dest_title = f"[ {titles.get(block.kind, block.kind.upper())} ]"
                    drop_col = max(
                        pos[0] + len(dest_title) + 3,
                        pos[0] + pos[4] // 2,
                    )
                    _wire_drop(
                        g,
                        prev_pos[0] + prev_pos[4] - 1,
                        prev_pos[3],
                        drop_col,
                        pos[1],
                    )
                else:
                    _wire_bend(
                        g,
                        prev_pos[0] + prev_pos[4] - 1,
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
                            src_pos[0] + src_pos[4] - 1,
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
                            for yy in range(cy + 3, target_row):
                                g.put(col, yy, "│", _S_WIRE)
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

    # -- funnel (batch-96 B1) -------------------------------------------------

    def _funnel_list_text(self) -> Text:
        """One ``NAME = value`` line per declared variable (markup-safe)."""
        if not self._funnel:
            return safe_text(
                "(funnel vacío — los ${NAME} de los change-docs pasan intactos)"
            )
        text = Text()
        for name, value in self._funnel:
            text.append(safe_text(f"${{{name}}} = "))
            text.append(safe_text(value))
            text.append("\n")
        return text

    def _refresh_funnel_list(self) -> None:
        """Repaint the funnel table + the toggle's count badge."""
        self.query_one("#flow_funnel_list", Static).update(self._funnel_list_text())
        toggle = self.query_one("#flow_funnel_toggle", Button)
        toggle.label = f"Funnel ({len(self._funnel)})"

    def _add_funnel_entry(self) -> None:
        """Declare (or update) one funnel variable from the editor row.

        The name must match the EXACT placeholder charset ``[A-Z0-9_]`` and
        the value must be non-empty; a refusal paints the wiring notice and
        adds nothing. Re-declaring a name UPDATES its value (table
        semantics — one value per name).
        """
        name = self.query_one("#flow_funnel_name", Input).value.strip()
        value = self.query_one("#flow_funnel_value", Input).value
        if not FUNNEL_NAME_RE.match(name):
            self._show_wiring_notice(
                "funnel rechazado: el nombre debe ser un placeholder "
                "[A-Z0-9_] (p.ej. BOOST) — sin minúsculas ni espacios."
            )
            return
        if not value.strip():
            self._show_wiring_notice(
                "funnel rechazado: el valor no puede estar vacío."
            )
            return
        table = [(n, v) for n, v in self._funnel if n != name]
        table.append((name, value))
        self._funnel = table
        self.query_one("#flow_funnel_name", Input).value = ""
        self.query_one("#flow_funnel_value", Input).value = ""
        self._show_wiring_notice("")
        self._refresh_funnel_list()
        self._mark_dirty()

    # -- block copy/paste (batch-96 B2) ---------------------------------------

    def _refresh_clip_status(self, message: str = "") -> None:
        """Paint the clipboard status line (markup-safe)."""
        self.query_one("#flow_clip_status", Static).update(safe_text(message))

    def _copy_block(self) -> None:
        """Serialize the picked block to the clipboard's WIRE dict.

        The pick is the LEDGER number (1-based; empty = the last block).
        The clipboard carries ``flow_to_dict``'s projection of that ONE
        block — the same wire format persistence uses, never a live
        instance, so a paste can never share mutable state.
        """
        raw = self.query_one("#flow_pick", Input).value.strip()
        if raw:
            if not raw.isdigit() or not (1 <= int(raw) <= len(self._blocks)):
                self._show_wiring_notice(
                    f"copiar rechazado: no hay bloque nº {raw} (hay "
                    f"{len(self._blocks)})."
                )
                return
            block = self._blocks[int(raw) - 1]
        else:
            if not self._blocks:
                self._show_wiring_notice(
                    "copiar rechazado: el canvas está vacío."
                )
                return
            block = self._blocks[-1]
        self._clipboard = fps.flow_to_dict(
            Flow(name="clipboard", blocks=[block])
        )["blocks"][0]
        self._show_wiring_notice("")
        self._refresh_clip_status(f"clipboard: {block.kind}")
        self._mark_dirty()

    def _paste_block(self) -> None:
        """Paste the clipboard's wire dict as a NEW block.

        An EMPTY clipboard is a friendly no-op (wiring notice, nothing
        added, never a crash). The wire dict is re-validated through the
        hardened loader against the CURRENT flow's own blocks, so an A2B
        ``#<n>`` binding is checked against the real upstream context.
        Pasted blocks keep their refs VERBATIM — a flow-bound A2B ref may
        need re-editing after the paste (the minimal renumbering contract:
        the builder never rewrites operator wiring silently). The ledger
        numbers the pasted block anew; the clipboard survives the paste
        (it can be pasted again).
        """
        if self._clipboard is None:
            self._show_wiring_notice(
                "pegar: el portapapeles está vacío — nada que pegar."
            )
            return
        base: Optional[Path] = None
        if self._session_dir:
            base = Path(self._session_dir)
        else:
            # The shipped app publishes the active project through
            # ``active_project_dir`` (the crc_designer_view idiom) — the
            # paste validation base comes from there when the session strip
            # was never set.
            active = getattr(self.app, "active_project_dir", None)
            base = active() if callable(active) else None
        if base is None:
            self._show_wiring_notice(
                "pegar rechazado: cargue un proyecto (se valida contra el "
                "directorio de sesión)."
            )
            return
        wire_blocks = fps.flow_to_dict(self.current_flow)["blocks"]
        envelope = {
            "schema_version": 1,
            "name": "clipboard-paste",
            "blocks": [*wire_blocks, self._clipboard],
        }
        parsed, findings = fps.dict_to_flow(envelope, base)
        if parsed is None or findings:
            message = findings[0].message if findings else "bloque inválido"
            self._show_wiring_notice(f"pegar rechazado: {message}")
            return
        block = parsed.blocks[-1]
        self._blocks.append(block)
        self._show_wiring_notice("")
        self._refresh_blocks()
        self._refresh_clip_status(f"pegado: {block.kind}")
        self._mark_dirty()

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

    def _add_external_step_block(self) -> None:
        """Build an external-step block from the config row (spec v3).

        The LOG is MANDATORY (never optional) — an empty log ref refuses the
        block with the wiring notice, exactly like a refused A2B binding. The
        instruction and the output path must be non-empty too; the output
        path prefers an ABSOLUTE one (a relative plain filename is accepted).
        """
        mode = str(self.query_one("#flow_ext_mode", Select).value)
        instruction = self.query_one("#flow_ext_instruction", Input).value.strip()
        log_ref = self.query_one("#flow_ext_log", Input).value.strip()
        output_path = self.query_one("#flow_ext_output", Input).value.strip()
        if not instruction:
            noun = (
                "el comando exacto" if mode == EXTERNAL_MODE_TERMINAL
                else "la instrucción"
            )
            self._show_wiring_notice(
                f"paso externo rechazado: falta {noun} a correr fuera de la app."
            )
            return
        if not log_ref:
            self._show_wiring_notice(
                "paso externo rechazado: el LOG es OBLIGATORIO (texto de "
                "constancia, nunca opcional)."
            )
            return
        if not output_path:
            self._show_wiring_notice(
                "paso externo rechazado: falta el ARCHIVO DE SALIDA "
                "(path absoluto preferido)."
            )
            return
        self._show_wiring_notice("")
        self._blocks.append(
            ExternalStepBlock(
                mode=mode,
                instruction=instruction,
                log_ref=log_ref,
                output_path=output_path,
            )
        )
        self.query_one("#flow_ext_instruction", Input).value = ""
        self.query_one("#flow_ext_log", Input).value = ""
        self.query_one("#flow_ext_output", Input).value = ""
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
            if kind == BLOCK_EXTERNAL_STEP:
                self._add_external_step_block()
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
                    self.current_flow,
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
            self._funnel.clear()
            self._clipboard = None
            self._refresh_blocks()
            self._refresh_funnel_list()
            self._refresh_clip_status("")
            self._show_wiring_notice("")
            self.query_one("#flow_result", VerticalScroll).remove_children()
            if had_blocks:
                self._mark_dirty()
        elif event.button.id == "flow_funnel_toggle":
            editor = self.query_one("#flow_funnel_editor")
            editor.display = not editor.display
            self.query_one("#flow_funnel_list").display = editor.display
        elif event.button.id == "flow_funnel_add":
            self._add_funnel_entry()
        elif event.button.id == "flow_copy":
            self._copy_block()
        elif event.button.id == "flow_paste":
            self._paste_block()

    def on_mount(self) -> None:
        # F3 (LLR-094.3): the per-block gating control is CHECK-only — hidden
        # for SOURCE (default), PATCH, WRITE-OUT, CRC and A2B; the A2B binding
        # inputs show only for A2B, the single ref for every other kind.
        self._sync_kind_dependent_visibility(
            str(self.query_one("#flow_kind", Select).value)
        )
        # batch-96 B1: the funnel editor starts COLLAPSED (a declaration
        # table, not a canvas element) — the toggle opens it.
        self.query_one("#flow_funnel_editor").display = False
        self.query_one("#flow_funnel_list").display = False
        self._refresh_funnel_list()
        self._show_wiring_notice("")

    def on_select_changed(self, event: Select.Changed) -> None:
        # Only the block-kind selector toggles the ref-row visibility.
        if event.select.id == "flow_kind":
            self._sync_kind_dependent_visibility(str(event.value))

    def _sync_kind_dependent_visibility(self, kind: str) -> None:
        """Show the gating control only for CHECK, the binding inputs only for
        A2B, the single ref for every other kind, and the external-step config
        row only for EXTERNAL_STEP (F3)."""
        self.query_one("#flow_gating", Select).display = kind == BLOCK_CHECK
        # The single ref is for the ref-bearing kinds only — A2B wires two
        # bindings, the external step its own config row (F3, spec v3).
        self.query_one("#flow_ref", Input).display = kind not in (
            BLOCK_A2B,
            BLOCK_EXTERNAL_STEP,
        )
        self.query_one("#flow_ref_a", Input).display = kind == BLOCK_A2B
        self.query_one("#flow_ref_b", Input).display = kind == BLOCK_A2B
        self.query_one("#flow_ext_row").display = kind == BLOCK_EXTERNAL_STEP

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


# ---------------------------------------------------------------------------
# fx_a — Flow Execution (batch-94 Inc-003, US-007; HLR-017…021): per-chain
# lanes + shaded progress + status glyph + the RUN LOG strip with the inline
# ✗ naming the block and the missing config (the operator's suggestion #1).
# ---------------------------------------------------------------------------

#: The painted lane width. Two lanes at 46 cells (44 + frame) sit inside the
#: measured 96×18 workspace at 120×30 (A3's boxed budget); the 74-cell floor
#: at 80×24 scrolls horizontally inside ``#fx_lanes_scroll`` (LLR-017.2's
#: reachable-under-scroll fallback — 74×12 cannot host two full lanes).
_FX_LANE_W = 44

#: The shaded progress bar's cell budget (fx_a doctrine: ▓ done / □ queued —
#: the state carrier, never decoration).
_FX_BAR_CELLS = 14
_FX_BAR_DONE = "▓"
_FX_BAR_GAP = "░"

#: The pause shade (prototype v3) — bold YELLOW, the same hex as the
#: ``.sev-warning`` class (insight_style is the token's home).
_S_PAUSE = "bold " + YELLOW

#: Terminal status → (glyph, shade style). Enum-derived, never file-derived
#: (correctly outside the C-17 sweep, like ``_FLOW_STATUS_BANNER``).
_FX_STATUS_STYLE = {
    "": ("·", _S_DIM),
    FLOW_STATUS_OK: ("✓", _S_OUT),
    FLOW_STATUS_ISSUES: ("◈", _S_LABEL),
    FLOW_STATUS_ERROR: ("✗", _S_ERR),
    # prototype v3 (spec "paso externo"): the PAUSED pair — □ (a queued chain
    # cell, the fx_a ▓/□ doctrine) in bold yellow (the .sev-warning hex).
    FLOW_STATUS_PAUSED: ("□", _S_PAUSE),
}


@dataclass(frozen=True)
class FxLaneSpec:
    """The panel-side lane payload posted to the app (Run / Save Set).

    The app translates it into the service's ``ChainSpec`` / ``ChainSetEntry``
    — the panel never imports the execution/persistence modules (the declared
    ``flow_screens → services/flow_model`` edge stays read-only dataclasses).

    Args:
        name (str): The lane name (unique inside the set).
        template (str): The ``flows/<stem>.json`` template reference.
        flow (Flow): The loaded template (the app hands it back at import).
        bindings (Tuple[Tuple[int, str], ...]): Bound input records —
            ``(SOURCE block index, project-relative ref)`` — LLR-018.1's
            per-chain independent state.
        outputs (Tuple[str, ...]): The chain's recorded last outputs.
    """

    name: str
    template: str
    flow: Flow
    bindings: Tuple[Tuple[int, str], ...] = ()
    outputs: Tuple[str, ...] = ()


@dataclass
class _FxLane:
    """One live lane's view state (the mounted widgets mirror this list)."""

    name: str
    template: str
    flow: Flow
    bindings: Dict[int, str] = field(default_factory=dict)
    last_outputs: List[Path] = field(default_factory=list)
    last_status: str = ""
    last_elapsed: float = 0.0
    fail_block: Optional[int] = None
    missing: List[str] = field(default_factory=list)
    #: prototype v3: the external-step block index the chain is PAUSED at
    #: (``None`` when not paused) — drives the pending log/output rows and
    #: the confirm button.
    paused_block: Optional[int] = None
    #: The session artifact dir shown in the lane (spec v3: ALWAYS visible).
    session_dir: str = ""


def _fx_stamp(seconds: float) -> str:
    """``mm:ss.mmm`` — the fx_a run-log timestamp shape (the spike's form)."""
    seconds = max(0.0, seconds)
    minutes = int(seconds // 60)
    return f"{minutes:02d}:{seconds % 60:06.3f}"


def _fx_progress_bar(frac: float) -> Text:
    """The shaded ▓/░ bar — ``frac`` of :data:`_FX_BAR_CELLS` cells filled."""
    filled = max(0, min(_FX_BAR_CELLS, round(_FX_BAR_CELLS * max(0.0, min(1.0, frac)))))
    return Text(_FX_BAR_DONE * filled + _FX_BAR_GAP * (_FX_BAR_CELLS - filled))


class FlowExecutionPanel(ScrollableContainer):
    """Rail-9 Flow Execution — the fx_a chain-set supervisor (batch-94 Inc-003).

    Summary:
        The HLR-017…021 surface: Import… mounts one lane per builder template
        (side by side, LLR-017); each lane paints its pinned inputs and offers
        per-input rebinding that touches exactly that lane's record
        (LLR-018.1); Run dispatches the set through the app's chain-set
        runner — sequential by default, parallel per chain on demand
        (LLR-019) — and paints each lane's shaded progress + status glyph +
        elapsed, plus the RUN LOG strip: one start and one terminal status
        line per chain, and a failed chain's inline ``✗`` line naming the
        block and its missing config (LLR-020.1). Save Set persists the whole
        set (chains + bound inputs + recorded outputs) and Load Set restores
        it for a re-run without re-binding (LLR-021). Presentational — every
        control posts a message the app routes; every file-derived string
        renders markup-safe via ``safe_text`` (C-17).

    Data Flow:
        - Import… → ``ImportRequested`` → app (template picker) →
          :meth:`add_lane` / :meth:`render_import_refusal`.
        - Run → ``RunRequested(lane_specs, mode, set_name)`` → app →
          ``run_chain_set`` → :meth:`render_run` (lanes + run log).
        - Save Set → ``SaveRequested`` → app persists → :meth:`mark_saved`.
        - Load Set → ``LoadSetRequested`` → app restores →
          :meth:`restore_set`.

    Dependencies:
        Uses:
            - ``flow_model`` (read-only dataclasses, the declared R8 edge)
            - ``safe_text`` / the ``_Grid`` painter (markup-safe paint)
        Used by:
            - ``S19TuiApp._compose_screen_flow_execution`` + the
              ``on_flow_execution_panel_*`` handlers
    """

    #: The run-mode control options (label, mode token). ``sequential`` is
    #: the untouched default (LLR-019.1); the operator drives ``parallel``
    #: per run (the C-10 non-default arm).
    _MODE_OPTIONS = [
        ("Sequential (default)", "sequential"),
        ("Parallel per chain", "parallel"),
    ]

    class ImportRequested(Message):
        """The operator pressed Import… — the app opens the template picker."""

    class RunRequested(Message):
        """The operator pressed Run — carries the lane set to the app.

        Args:
            lanes (List[FxLaneSpec]): The current lanes, in lane order.
            mode (str): ``sequential`` (default) or ``parallel``.
            set_name (str): The set's display name (the report header).
        """

        def __init__(
            self, lanes: List[FxLaneSpec], mode: str, set_name: str
        ) -> None:
            super().__init__()
            self.lanes = lanes
            self.mode = mode
            self.set_name = set_name

    class SaveRequested(Message):
        """The operator pressed Save Set — carries the lanes + the raw name.

        Args:
            lanes (List[FxLaneSpec]): The current lanes, in lane order.
            raw_name (str): The operator-typed set name (untrusted text).
        """

        def __init__(self, lanes: List[FxLaneSpec], raw_name: str) -> None:
            super().__init__()
            self.lanes = lanes
            self.raw_name = raw_name

    class LoadSetRequested(Message):
        """The operator pressed Load Set — carries the chosen set stem.

        Args:
            stem (str): The ``flowsets/<stem>.json`` identity to restore.
        """

        def __init__(self, stem: str) -> None:
            super().__init__()
            self.stem = stem

    class ExternalStepConfirmed(Message):
        """The operator confirmed a paused external step (spec v3).

        Posted by the lane's confirm button; the app re-runs THAT lane with
        the block's confirmation in the run context and hands the outcome
        back via :meth:`apply_confirmed_run`.

        Args:
            lane_index (int): The paused lane's position.
            block_index (int): The external-step block's position in the
                lane's flow.
        """

        def __init__(self, lane_index: int, block_index: int) -> None:
            super().__init__()
            self.lane_index = lane_index
            self.block_index = block_index

    def __init__(self) -> None:
        super().__init__(id="fx_panel")
        self._lanes: List[_FxLane] = []
        #: The set's display name; identity is the FILENAME on save.
        self._set_name = "chain-set"
        #: Unsaved-edits flag — glyph ● (dirty) / ✓ (saved), the C-10 idiom.
        self._dirty = False
        self._last_record = None
        #: The retained run-log Text (append target for a lane's confirm
        #: re-run — prototype v3).
        self._log_text = Text()
        #: The session artifact dir (spec v3: ALWAYS visible in every lane).
        self._session_dir: str = ""

    def set_session_dir(self, path: str) -> None:
        """Publish the session artifact dir (spec v3) and repaint the lanes."""
        self._session_dir = path
        for index in range(len(self._lanes)):
            self._lanes[index].session_dir = path
            self._repaint_lane(index)

    # -- composition ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(
            self._name_strip_text(),
            id="fx_name_strip",
            markup=False,
            classes=self._name_strip_class(),
        )
        yield Label(
            "Flow Execution (fx_a): Import… adds a chain lane from a builder "
            "template; bind each lane's inputs; Run (sequential default, "
            "parallel per chain); Save Set persists chains + inputs + outputs.",
            id="fx_help",
            markup=False,
        )
        run_row = Horizontal(
            Button("Import…", id="fx_import"),
            Select(
                self._MODE_OPTIONS,
                value="sequential",
                allow_blank=False,
                id="fx_mode",
            ),
            Button("Run", id="fx_run", variant="primary"),
            id="fx_run_row",
        )
        run_row.styles.height = 3
        yield run_row
        set_row = Horizontal(
            OsClipboardInput(placeholder="set name", id="fx_set_name"),
            Button("Save Set", id="fx_save"),
            Select(
                [("(no saved sets)", "")],
                value="",
                allow_blank=False,
                id="fx_set_select",
            ),
            Button("Load Set", id="fx_load"),
            id="fx_set_row",
        )
        set_row.styles.height = 3
        yield set_row
        yield Static("", id="fx_notice", markup=False)
        yield ScrollableContainer(
            Horizontal(
                Static(
                    "(no chains — Import… adds a lane)",
                    id="fx_empty",
                    markup=False,
                ),
                id="fx_lanes",
            ),
            id="fx_lanes_scroll",
        )
        yield Static("", id="fx_log", markup=False)

    def on_mount(self) -> None:
        self.query_one("#fx_set_name", Input).value = self._set_name

    # -- name strip (the C-10 dirty-guard idiom) -----------------------------

    def _name_strip_text(self) -> Text:
        glyph = "●" if self._dirty else "✓"
        text = Text()
        text.append("Set: ")
        text.append(safe_text(self._set_name))
        text.append(f"  {glyph}")
        return text

    def _name_strip_class(self) -> str:
        return "flow-name-strip " + ("sev-warning" if self._dirty else "sev-neutral")

    def _refresh_name_strip(self) -> None:
        strip = self.query_one("#fx_name_strip", Static)
        strip.update(self._name_strip_text())
        strip.set_classes(self._name_strip_class())

    def _mark_dirty(self) -> None:
        self._dirty = True
        self._refresh_name_strip()

    def mark_saved(self, stem: str) -> None:
        """Record a successful save: identity = ``stem``, clear the flag."""
        self._set_name = stem
        self._dirty = False
        self.query_one("#fx_set_name", Input).value = stem
        self._refresh_name_strip()
        self._show_notice(f"✓ saved flowsets/{stem}.json")

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    # -- lanes ---------------------------------------------------------------

    def _source_indices(self, flow: Flow) -> List[int]:
        return [
            index
            for index, block in enumerate(flow.blocks)
            if isinstance(block, SourceBlock)
        ]

    def _unique_lane_name(self, stem: str) -> str:
        names = {lane.name for lane in self._lanes}
        if stem not in names:
            return stem
        counter = 2
        while f"{stem}_{counter}" in names:
            counter += 1
        return f"{stem}_{counter}"

    def add_lane(self, template: str, flow: Flow) -> str:
        """Mount one lane for an imported template (LLR-017.1).

        The lane binds the template's own SOURCE refs by default; the
        operator rebinds per lane afterwards (LLR-018). Duplicate template
        imports uniquify with the ``_<N>`` idiom (0 duplicate lanes).

        Returns:
            str: The mounted lane's unique name.
        """
        lane = _FxLane(
            name=self._unique_lane_name(template),
            template=template,
            flow=flow,
            session_dir=self._session_dir,
        )
        self._lanes.append(lane)
        empty = self.query_one("#fx_empty", Static)
        empty.display = False
        self.query_one("#fx_lanes", Horizontal).mount(self._lane_widgets(lane))
        self._mark_dirty()
        return lane.name

    def restore_lane(
        self,
        name: str,
        template: str,
        flow: Flow,
        bindings: Dict[int, str],
        outputs: Sequence[str],
        missing: Sequence[str],
    ) -> None:
        """Mount one lane from a reloaded set (LLR-021.2), notices included.

        ``missing`` carries the bound refs whose files are absent at reload
        time — the LLR-021.2 moved-input arm paints a per-lane
        provenance-mismatch notice instead of running silently stale.
        """
        lane = _FxLane(
            name=name,
            template=template,
            flow=flow,
            bindings=dict(bindings),
            last_outputs=[Path(out) for out in outputs],
            last_status=FLOW_STATUS_OK if outputs else "",
            missing=list(missing),
            session_dir=self._session_dir,
        )
        self._lanes.append(lane)
        self.query_one("#fx_empty", Static).display = False
        self.query_one("#fx_lanes", Horizontal).mount(self._lane_widgets(lane))

    def _lane_widgets(self, lane: _FxLane) -> Vertical:
        index = len(self._lanes) - 1
        children: List[Widget] = [
            Static(
                self._lane_paint(lane),
                id=f"fx_lane_{index}_paint",
                markup=False,
            )
        ]
        for src_index in self._source_indices(lane.flow):
            edit_row = Horizontal(
                OsClipboardInput(
                    placeholder=f"input {src_index + 1} ref",
                    id=f"fx_in_{index}_{src_index}",
                    value=self._effective_ref(lane, src_index),
                ),
                Button("Bind", id=f"fx_bind_{index}_{src_index}"),
                id=f"fx_lane_{index}_edit_{src_index}",
            )
            edit_row.styles.height = 3
            children.append(edit_row)
        #: prototype v3: the confirm affordance for a PAUSED external step —
        #: hidden until the lane's run pauses on one (spec v3 semantics: the
        #: execution waits for the human until log + output are confirmed).
        confirm = Button(
            "✓ Confirmar paso externo",
            id=f"fx_confirm_{index}",
            variant="primary",
        )
        confirm.display = False
        children.append(confirm)
        lane_widget = Vertical(*children, id=f"fx_lane_{index}", classes="fx-lane")
        lane_widget.styles.width = _FX_LANE_W + 2
        return lane_widget

    def _effective_ref(self, lane: _FxLane, src_index: int) -> str:
        if src_index in lane.bindings:
            return lane.bindings[src_index]
        block = lane.flow.blocks[src_index]
        return block.image_ref if isinstance(block, SourceBlock) else ""

    def _lane_paint(self, lane: _FxLane) -> Text:
        """Paint one lane box: name, template, block list, pinned inputs,
        missing-input notices, the session dir (spec v3: ALWAYS), the paused
        external-step pending rows, and the shaded status bar (fx_a density)."""
        src_indices = self._source_indices(lane.flow)
        kinds = " → ".join(block.kind for block in lane.flow.blocks)
        ext_paused = (
            lane.paused_block is not None
            and lane.last_status == FLOW_STATUS_PAUSED
        )
        rows = (
            2  # title + template/blocks lines
            + max(1, len(src_indices))  # pinned inputs
            + len(lane.missing)  # reload mismatch notices
            + 1  # session dir (spec v3 — always)
            + (2 if ext_paused else 0)  # pending LOG + SALIDA (spec v3)
            + 1  # status bar
        )
        g = _Grid(_FX_LANE_W, rows + 2)
        g.box(0, 0, _FX_LANE_W, rows + 2)
        title = f"[ {safe_text(lane.name).plain} ]"
        g.put(2, 0, title[: _FX_LANE_W - 4], _S_HEAD)
        g.put(2, 1, f"tpl {safe_text(lane.template).plain}", _S_DIM)
        g.put(
            2 + len(lane.template) + 4,
            1,
            f"· {len(lane.flow.blocks)} blocks",
            _S_DIM,
        )
        g.put(2, 2, safe_text(kinds).plain[: _FX_LANE_W - 4], _S_LABEL)
        row = 3
        for src_index in src_indices:
            ref = self._effective_ref(lane, src_index)
            g.put(2, row, f"in{src_index + 1}", _S_LABEL)
            g.put(6, row, safe_text(ref).plain[: _FX_LANE_W - 8], _S_VALUE)
            row += 1
        for missing in lane.missing:
            g.put(
                2,
                row,
                ("⚠ '" + safe_text(missing).plain + "' missing — re-bind").replace(
                    "—", "-"
                )[: _FX_LANE_W - 4],
                _S_ERR,
            )
            row += 1
        #: The session artifact dir is ALWAYS painted (spec v3) — on confirm
        #: the external step's output is copied INTO it.
        session = lane.session_dir or "(sin proyecto activo)"
        g.put(
            2,
            row,
            f"sesión: {_short_ext(safe_text(session).plain, _FX_LANE_W - 12)}",
            _S_DIM,
        )
        row += 1
        if ext_paused:
            #: The pending evidence rows — the ⚠ idiom of the missing-input
            #: notices, in the error shade: the MANDATORY log and the output
            #: file are still owed by the human.
            block = lane.flow.blocks[lane.paused_block]
            log_ref = getattr(block, "log_ref", "?")
            g.put(
                2,
                row,
                ("⚠ LOG '" + safe_text(log_ref).plain + "' pendiente").replace(
                    "—", "-"
                )[: _FX_LANE_W - 4],
                _S_ERR,
            )
            row += 1
            g.put(
                2,
                row,
                "⚠ SALIDA sin confirmar - esperando humano"[: _FX_LANE_W - 4],
                _S_ERR,
            )
            row += 1
        glyph, style = _FX_STATUS_STYLE.get(lane.last_status, ("·", _S_DIM))
        blocks = max(1, len(lane.flow.blocks))
        if lane.last_status == FLOW_STATUS_OK:
            frac = 1.0
        elif lane.last_status and lane.fail_block is not None:
            frac = lane.fail_block / blocks
        elif lane.last_status:
            frac = 1.0
        else:
            frac = 0.0
        bar = _fx_progress_bar(frac)
        g.put(2, row, bar.plain, style)
        pct = round(100 * frac)
        g.put(2 + _FX_BAR_CELLS + 1, row, f"{pct:>3d}%", _S_VALUE)
        g.put(2 + _FX_BAR_CELLS + 6, row, glyph, style)
        if lane.last_status == FLOW_STATUS_PAUSED:
            #: A paused lane has no terminal elapsed — the state word rides
            #: the elapsed seat (cols 24..41, 16 of 18 cells — fits).
            g.put(2 + _FX_BAR_CELLS + 9, row, "ESPERANDO HUMANO", _S_LABEL)
        elif lane.last_status:
            g.put(
                2 + _FX_BAR_CELLS + 9,
                row,
                f"{lane.last_elapsed:.3f}s",
                _S_LABEL,
            )
        return _join_lines(g.lines())

    def _repaint_lane(self, lane_index: int) -> None:
        self.query_one(f"#fx_lane_{lane_index}_paint", Static).update(
            self._lane_paint(self._lanes[lane_index])
        )

    def lane_names(self) -> List[str]:
        return [lane.name for lane in self._lanes]

    def lane_count(self) -> int:
        return len(self._lanes)

    def lane_bindings(self, lane_name: str) -> Dict[int, str]:
        for lane in self._lanes:
            if lane.name == lane_name:
                return dict(lane.bindings)
        raise KeyError(lane_name)

    def lane_specs(self) -> List[FxLaneSpec]:
        """The current lanes as payloads for Run / Save Set.

        The bindings are the EFFECTIVE inputs — every SOURCE block's ref with
        the operator overrides merged over it (LLR-021.1's ``>=1 input per
        chain`` contract records what the chain consumes, not only what the
        operator re-typed; a reloaded set restores 100% without consulting
        the template's defaults).
        """
        return [
            FxLaneSpec(
                name=lane.name,
                template=lane.template,
                flow=lane.flow,
                bindings=tuple(
                    (index, lane.bindings.get(index, block.image_ref))
                    for index, block in enumerate(lane.flow.blocks)
                    if isinstance(block, SourceBlock)
                ),
                outputs=tuple(str(path) for path in lane.last_outputs),
            )
            for lane in self._lanes
        ]

    # -- notices -------------------------------------------------------------

    def _show_notice(self, message: str) -> None:
        notice = self.query_one("#fx_notice", Static)
        if message:
            notice.update(safe_text(message))  # SINK: file-derived notice text
            notice.display = True
            notice.set_classes("sev-warning")
        else:
            notice.update("")
            notice.display = False

    def render_import_refusal(self, stem: str, findings: List[ValidationIssue]) -> None:
        """Paint a rejected template import — the current lanes are untouched."""
        first = findings[0].message if findings else "unreadable template"
        self._show_notice(
            f"import refused: flows/{stem}.json — {first}"
        )

    # -- run -----------------------------------------------------------------

    def _failure_detail(
        self, lane: _FxLane, outcome
    ) -> Tuple[int, str, str, str]:
        """The inline-✗ detail: (block index, kind, noun, ref).

        The ``'<ref>' missing`` wording is used for the unresolved-ref arms
        (the block result says so); every other failure carries its own
        recorded diagnostic, never invented text.
        """
        for block_result in outcome.block_results:
            if block_result.status != BLOCK_STATUS_ERROR:
                continue
            index = block_result.index
            block = lane.flow.blocks[index]
            noun, ref = _block_ref_noun(block)
            if block_result.summary.endswith("unresolved"):
                return index, block.kind, noun, ref
            diagnostic = (
                block_result.diagnostics[-1]
                if block_result.diagnostics
                else block_result.summary
            )
            return index, block.kind, "", safe_text(diagnostic).plain
        return 0, "?", "", "unknown failure"

    def render_run(self, record) -> None:
        """Paint the lanes + the RUN LOG strip from the set run record.

        Args:
            record (ChainSetRunRecord): The completed run — one outcome per
                lane in lane order, the captured mode, and the report path.
        """
        self._last_record = record
        run_start = min(
            (outcome.started_at for outcome in record.outcomes), default=0.0
        )
        log = Text()
        for lane_index, lane in enumerate(self._lanes):
            outcome = record.outcomes[lane_index]
            lane.last_status = outcome.status
            lane.last_elapsed = outcome.finished_at - outcome.started_at
            lane.last_outputs = list(outcome.written_paths)
            lane.fail_block = next(
                (
                    block_result.index
                    for block_result in outcome.block_results
                    if block_result.status == BLOCK_STATUS_ERROR
                ),
                None,
            )
            #: prototype v3: a WAITING block result is a PAUSED external step
            #: — the bar stops there (``fail_block`` is "where the chain
            #: stopped", the pause seat) and the confirm button mounts.
            lane.paused_block = next(
                (
                    block_result.index
                    for block_result in outcome.block_results
                    if block_result.status == BLOCK_STATUS_WAITING
                ),
                None,
            )
            if lane.paused_block is not None:
                lane.fail_block = lane.paused_block
            self._repaint_lane(lane_index)
            try:
                self.query_one(
                    f"#fx_confirm_{lane_index}", Button
                ).display = lane.paused_block is not None
            except Exception:
                pass  # lane widgets not mounted (pre-mount call) — no button

            log.append(f"{_fx_stamp(outcome.started_at - run_start)} ")
            log.append("▶ ", style=_S_LABEL)
            log.append(safe_text(outcome.chain))
            log.append(" · started\n", style=_S_DIM)
            if outcome.status == FLOW_STATUS_ERROR:
                index, kind, noun, ref = self._failure_detail(lane, outcome)
                total = max(1, len(outcome.block_results))
                log.append(f"{_fx_stamp(outcome.finished_at - run_start)} ")
                log.append("✗ ", style=_S_ERR)
                log.append(safe_text(outcome.chain))
                if noun:
                    log.append(
                        f" · block {index + 1}/{total} {kind.upper()} — "
                        f"{noun} '{safe_text(ref).plain}' missing",
                        style=_S_DIM,
                    )
                else:
                    log.append(
                        f" · block {index + 1}/{total} {kind.upper()} — {ref}",
                        style=_S_DIM,
                    )
                log.append(" · chain halted\n", style=_S_DIM)
            elif outcome.status == FLOW_STATUS_PAUSED:
                #: The paused chain's inline line — names the block and the
                #: MANDATORY log still owed (the ✗-line idiom, □ shade).
                index = lane.paused_block if lane.paused_block is not None else 0
                total = max(1, len(outcome.block_results))
                block = lane.flow.blocks[index]
                log.append(f"{_fx_stamp(outcome.finished_at - run_start)} ")
                log.append("□ ", style=_S_PAUSE)
                log.append(safe_text(outcome.chain))
                log.append(
                    f" · ESPERANDO HUMANO — paso externo (block "
                    f"{index + 1}/{total}) · LOG "
                    f"'{safe_text(getattr(block, 'log_ref', '?')).plain}' "
                    f"pendiente\n",
                    style=_S_DIM,
                )
            else:
                glyph, _ = _FX_STATUS_STYLE.get(outcome.status, ("·", _S_DIM))
                log.append(f"{_fx_stamp(outcome.finished_at - run_start)} ")
                log.append(f"{glyph} ", style=_S_LABEL)
                log.append(safe_text(outcome.chain))
                log.append(" · done", style=_S_DIM)
                if outcome.written_paths:
                    names = ", ".join(path.name for path in outcome.written_paths)
                    log.append(f" · wrote {safe_text(names).plain}", style=_S_DIM)
                log.append("\n")
        for diagnostic in record.diagnostics:
            log.append(safe_text(diagnostic))
            log.append("\n")
        self._log_text = log
        self.query_one("#fx_log", Static).update(log)
        if record.outcomes:
            self._mark_dirty()

    def apply_confirmed_run(self, lane_index: int, record) -> None:
        """Paint ONE lane's re-run after an external-step confirmation (v3).

        The lane keeps its identity; only the run outcome is replaced — the
        confirm button hides again and the run-log strip gains the re-run's
        start/terminal lines under the paused entry.
        """
        lane = self._lanes[lane_index]
        outcome = record.outcomes[0]
        lane.last_status = outcome.status
        lane.last_elapsed = outcome.finished_at - outcome.started_at
        lane.last_outputs = list(outcome.written_paths)
        lane.fail_block = next(
            (
                block_result.index
                for block_result in outcome.block_results
                if block_result.status == BLOCK_STATUS_ERROR
            ),
            None,
        )
        lane.paused_block = None
        self._repaint_lane(lane_index)
        try:
            self.query_one(f"#fx_confirm_{lane_index}", Button).display = False
        except Exception:
            pass
        log = self._log_text
        log.append(f"{_fx_stamp(outcome.started_at)} ")
        log.append("▶ ", style=_S_LABEL)
        log.append(safe_text(outcome.chain))
        log.append(" · re-run tras confirmar paso externo\n", style=_S_DIM)
        glyph, _ = _FX_STATUS_STYLE.get(outcome.status, ("·", _S_DIM))
        log.append(f"{_fx_stamp(outcome.finished_at)} ")
        log.append(f"{glyph} ", style=_S_LABEL)
        log.append(safe_text(outcome.chain))
        log.append(" · done", style=_S_DIM)
        if outcome.written_paths:
            names = ", ".join(path.name for path in outcome.written_paths)
            log.append(f" · wrote {safe_text(names).plain}", style=_S_DIM)
        log.append("\n")
        self.query_one("#fx_log", Static).update(log)

    def render_run_error(self, message: str) -> None:
        """Paint a no-project run refusal into the log strip (the Run idiom)."""
        log = Text()
        log.append("✗ ", style=_S_ERR)
        log.append(safe_text(message))
        self.query_one("#fx_log", Static).update(log)

    @property
    def last_run_record(self):
        """The retained run record (the AT reads the captured mode from it)."""
        return self._last_record

    def run_log_plain(self) -> str:
        """The painted run-log text (the C-32 painted oracle seam)."""
        return self.query_one("#fx_log", Static).render().plain

    def lane_paint_plain(self, lane_index: int) -> str:
        """One lane's painted text (the C-32 painted oracle seam)."""
        return self.query_one(f"#fx_lane_{lane_index}_paint", Static).render().plain

    # -- save / load set -----------------------------------------------------

    def set_available_sets(self, stems: Sequence[str]) -> None:
        """Repopulate the set picker (the app's on-entry prefill)."""
        options = [(f"flowsets/{stem}.json", stem) for stem in stems]
        if not options:
            options = [("(no saved sets)", "")]
        select = self.query_one("#fx_set_select", Select)
        select.set_options(options)
        select.value = stems[0] if stems else ""

    async def begin_set_restore(self, stem: str) -> None:
        """Clear the lanes ahead of a set reload — the restored set REPLACES
        the current one (LLR-021.2; the reload is a restore, not a merge).

        Async: the removal of the old lane widgets is AWAITED before the
        caller mounts the restored lanes — mounting into a half-removed tree
        would collide on the lane ids.
        """
        await self.query_one("#fx_lanes", Horizontal).remove_children(".fx-lane")
        self._lanes.clear()
        empty = self.query_one("#fx_empty", Static)
        empty.display = True
        self._set_name = stem
        self._dirty = False
        self.query_one("#fx_set_name", Input).value = stem
        self._refresh_name_strip()

    def restore_set(self, stem: str, lanes: int, notices: Sequence[str]) -> None:
        """Finish a successful set reload: identity + notices for what moved."""
        self._set_name = stem
        self._dirty = False
        self.query_one("#fx_set_name", Input).value = stem
        self._refresh_name_strip()
        self._show_notice(" · ".join(notices))

    def render_set_refusal(self, stem: str, findings: List[ValidationIssue]) -> None:
        """Paint a rejected set load — the current lanes are untouched."""
        first = findings[0].message if findings else "unreadable set"
        self._show_notice(f"load refused: flowsets/{stem}.json — {first}")

    # -- events --------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "fx_import":
            self.post_message(self.ImportRequested())
        elif button_id == "fx_run":
            self.post_message(
                self.RunRequested(
                    self.lane_specs(),
                    str(self.query_one("#fx_mode", Select).value),
                    self._set_name,
                )
            )
        elif button_id == "fx_save":
            self.post_message(
                self.SaveRequested(
                    self.lane_specs(),
                    self.query_one("#fx_set_name", Input).value,
                )
            )
        elif button_id == "fx_load":
            stem = str(self.query_one("#fx_set_select", Select).value)
            if stem:
                self.post_message(self.LoadSetRequested(stem))
        elif button_id.startswith("fx_bind_"):
            parts = button_id.removeprefix("fx_bind_").split("_")
            self._rebind(int(parts[0]), int(parts[1]))
        elif button_id.startswith("fx_confirm_"):
            #: prototype v3: confirm a paused external step — the app re-runs
            #: that lane with the confirmation in the run context.
            lane_index = int(button_id.removeprefix("fx_confirm_"))
            lane = self._lanes[lane_index]
            if lane.paused_block is None:
                return
            self.post_message(
                self.ExternalStepConfirmed(lane_index, lane.paused_block)
            )

    def _rebind(self, lane_index: int, src_index: int) -> None:
        """Bind one lane's input — exactly that lane's record is written.

        LLR-018.1: an edit touches exactly one binding record; rebinding to
        the same ref is a no-op (the writer does not even mark dirty).
        """
        lane = self._lanes[lane_index]
        value = self.query_one(f"#fx_in_{lane_index}_{src_index}", Input).value.strip()
        if not value:
            self._show_notice(
                f"binding refused: lane '{lane.name}' input {src_index + 1} "
                "needs a non-empty ref"
            )
            return
        # Rebind-to-same is a no-op (LLR-018.1's boundary arm) — the EFFECTIVE
        # ref is the comparison base, so typing the path the lane already
        # consumes (its override or the template's own ref) writes nothing.
        if value == self._effective_ref(lane, src_index):
            return
        lane.bindings[src_index] = value
        self._repaint_lane(lane_index)
        self._show_notice("")
        self._mark_dirty()


def _block_ref_noun(block: FlowBlock) -> Tuple[str, str]:
    """The (noun, ref) pair naming a block's own file ref (the ✗ line seam)."""
    if isinstance(block, SourceBlock):
        return "source", block.image_ref
    if isinstance(block, PatchBlock):
        return "change doc", block.change_doc_ref
    if isinstance(block, CheckBlock):
        return "check doc", block.check_doc_ref
    if isinstance(block, CrcBlock):
        return "config", block.config_ref
    if isinstance(block, WriteOutBlock):
        return "output", block.output_name
    if isinstance(block, ExternalStepBlock):
        return "log", block.log_ref
    return "ref", getattr(block, "kind", "?")


def _join_lines(lines: List[Text]) -> Text:
    """Join painted grid lines into one multi-line ``Text`` (markup-safe:
    built by append, never markup-parsed)."""
    out = Text()
    for i, line in enumerate(lines):
        if i:
            out.append("\n")
        out.append_text(line)
    return out
