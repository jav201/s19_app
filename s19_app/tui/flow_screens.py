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

fx_A doctrine (batch-97 Inc-6, HLR-147; batch-94 fx_a before it): imported
templates mount one lane per chain, stacked; each lane is one row of block
cards whose cables carry each block's run status (``▓ ░ ✗ ◇ □``), the SOURCE
card holding its rebind input; the run-log strip below names a failed
chain's block and its missing config on one inline ``✗`` line, and a lane
waiting for a human shows its pending lines and Confirm. The panel is presentational — Run
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

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import (
    Container,
    Horizontal,
    ScrollableContainer,
    Vertical,
    VerticalScroll,
)
from textual.css.query import NoMatches
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
    CRC_FAMILY,
    CYAN,
    DGRAY,
    GREEN,
    HILITE,
    LABEL,
    LBLUE,
    PURPLE,
    RED,
    VALUE,
    DEPTH_BORDER,
    WAITING_HUMAN,
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
    BLOCK_REPORT,
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
from .changes.model import DISPOSITION_APPLIED


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

#: A per-status gutter glyph (enum-derived, never file-derived). batch-97
#: Inc-5 (D7): every glyph here paints one cell in Windows Terminal; the
#: error mark is ``✗`` (U+2717) — ``✖`` (U+2716) painted as a two-cell emoji
#: over the next cell, and ``✗`` already means error in the Execution cables.
_BLOCK_STATUS_GLYPH = {
    BLOCK_STATUS_OK: "●",        # ● ok
    BLOCK_STATUS_NOTICES: "◈",   # ◈ notices
    BLOCK_STATUS_ERROR: "✗",     # ✗ error
    BLOCK_STATUS_SKIPPED: "○",   # ○ skipped
    # prototype v3: □ — a queued chain cell (the fx_a ▓/□ doctrine): a
    # waiting external step is the chain waiting for the human. (⏸ U+23F8
    # falls to a blue emoji in Windows Terminal even with VS15 — measured.)
    BLOCK_STATUS_WAITING: "□",   # □ waiting for a human
}

#: Flow-status → (banner text, ``sev-*`` class) (LLR-088.5). The banner text is
#: derived from the status ENUM, so it is NOT a markup sink (out of the C-17
#: sweep — the coordinator's exclusion, security F1).
_FLOW_STATUS_BANNER = {
    FLOW_STATUS_OK: ("CLEAN", "sev-ok"),
    FLOW_STATUS_ISSUES: ("ISSUES", "sev-warning"),
    FLOW_STATUS_ERROR: ("FAILED", "sev-error"),
    # prototype v3 (the external step): the paused banner — the run waits
    # for the human at an external step (English since batch-97 LLR-147.5).
    FLOW_STATUS_PAUSED: ("PAUSED - WAITING FOR A HUMAN", "sev-warning"),
}

#: The Builder's banner for a finished run whose blocks carry notices only
#: (no block in error): ``ISSUES`` read as a failure (batch-97 operator
#: decision 4, LED-…97.27, superseding LLR-088.5's word for that case);
#: ``ISSUES`` stays for a finished run with a block in error.
_NOTICES_BANNER = ("NOTICES", "sev-warning")

#: The memory ribbon's fixed cell budget. A FIXED strip sized to clear the
#: tightest supported regime's measured content width — so it fits the 80×24
#: floor AND every wider regime with no horizontal overflow (LLR-088.4,
#: C-13/C-23/C-29). MEASURED in the mounted ``#flow_result`` via
#: ``App.run_test`` — NOT inherited from the HTML prototype's ~82/150-col
#: budget (C-16). The table is batch-51's, when ``#flow_result`` had a full
#: border and padding; since batch-97 Inc-5 it has only a top rule row and
#: ``padding: 0 1``, so every content width is wider than listed and 48 cells
#: still clear the floor. Measured content widths (both axes, over a real
#: LOAD→WRITE-OUT run, batch-51):
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


# ---------------------------------------------------------------------------
# batch-97 Inc-5 — the pipeline rail (fb_A, HLR-146): vocabularies and the
# pure painters. The rail replaces the grid canvas and the numbered list on
# screen (both stay mounted and repainted, not displayed — LLR-146.1).
# ---------------------------------------------------------------------------

#: Block-kind glyphs (D7, one meaning each; the help entry names them). ``≡``
#: paints only when a loaded flow carries a report block — the palette offers
#: the other seven. Every glyph paints one cell in Windows Terminal (the
#: 2026-10-21 ruler capture).
FLOW_KIND_GLYPHS: Mapping[str, str] = {
    "◉": "load",
    "▣": "patch",
    "✓": "check",
    "⊕": "CRC",
    "▼": "write-out",
    "⏚": "A2B diff",
    "»": "external step",
    "≡": "report",
}
#: The cable between two cards (D7): ``─`` run, ``▶`` into the next card.
FLOW_CABLE_GLYPHS: Mapping[str, str] = {"─": "cable", "▶": "feeds the next block"}

#: The PATCH family teal (``screens_directionb.PATCH_TEAL``, in the hue
#: census); ``flow_screens`` imports nothing from ``screens_directionb``.
_PATCH_TEAL = "#56e0d6"

#: kind -> (glyph, chip and card label, family colour, what the block does).
#: CRC paints in ``CRC_FAMILY``, never in the waiting colour (LLR-146.6).
_KIND_LOOK: Mapping[str, Tuple[str, str, str, str]] = {
    BLOCK_SOURCE: ("◉", "LOAD", HILITE, "reads an image"),
    BLOCK_PATCH: ("▣", "PATCH", _PATCH_TEAL, "applies a change doc"),
    BLOCK_CHECK: ("✓", "CHECK", GREEN, "verifies addresses"),
    BLOCK_CRC: ("⊕", "CRC", CRC_FAMILY, "stamps a CRC"),
    BLOCK_WRITE_OUT: ("▼", "WRITE-OUT", GREEN, "writes the image"),
    BLOCK_A2B: ("⏚", "A2B-DIFF", PURPLE, "diffs two images"),
    BLOCK_EXTERNAL_STEP: ("»", "EXT-STEP", LBLUE, "human: log + file"),
    BLOCK_REPORT: ("≡", "REPORT", DGRAY, "report marker"),
}

#: The single-ref input's field label and placeholder, per kind (fb_A: the
#: contextual add form names what the kind needs).
_REF_FIELD: Mapping[str, Tuple[str, str]] = {
    BLOCK_SOURCE: ("image file", "e.g. prg.s19"),
    BLOCK_PATCH: ("change doc", "e.g. calib_hotfix.json"),
    BLOCK_CHECK: ("check doc", "e.g. baseline.chk.json"),
    BLOCK_CRC: ("CRC template", "e.g. crc.json"),
    BLOCK_WRITE_OUT: ("output file", "e.g. fw_app_patched.s19"),
}

#: The path-bearing add inputs of each kind (LLR-146.3 order) and the label
#: the form shows beside each — the NUL refusal of the add form (S4-1, I-6)
#: names the field by that label (gate fold ux L1, LED-…97.28).
_ADD_PATH_INPUTS: Mapping[str, Tuple[Tuple[str, str], ...]] = {
    BLOCK_SOURCE: (("#flow_ref", _REF_FIELD[BLOCK_SOURCE][0]),),
    BLOCK_PATCH: (("#flow_ref", _REF_FIELD[BLOCK_PATCH][0]),),
    BLOCK_CHECK: (("#flow_ref", _REF_FIELD[BLOCK_CHECK][0]),),
    BLOCK_CRC: (("#flow_ref", _REF_FIELD[BLOCK_CRC][0]),),
    BLOCK_WRITE_OUT: (("#flow_ref", _REF_FIELD[BLOCK_WRITE_OUT][0]),),
    BLOCK_A2B: (("#flow_ref_a", "image A"), ("#flow_ref_b", "image B")),
    BLOCK_EXTERNAL_STEP: (("#flow_ext_log", "log"), ("#flow_ext_output", "output file")),
}


def nul_add_refusal(kind: str, values: Mapping[str, str]) -> Optional[str]:
    """The add form's NUL refusal line, or ``None`` (LLR-146.14, S4-1).

    Summary:
        Checks the chosen kind's path-bearing inputs, in form order, for a
        NUL character — the one character no path may hold.

    Args:
        kind (str): The chosen block kind.
        values (Mapping[str, str]): Input id (``#flow_ref`` …) → typed text.

    Returns:
        Optional[str]: For the first path-bearing input of ``kind`` holding a
        NUL character, one English line naming the loader's code for that
        field (``FLOW-UNSAFE-REF``) and the kind and field as the form labels
        them, e.g. ``Add refused: [FLOW-UNSAFE-REF] WRITE-OUT output file
        holds a NUL character - not a path`` (the value is never echoed);
        ``None`` when every path-bearing input is clean.

    Data Flow:
        - ``_ADD_PATH_INPUTS[kind]`` → (input id, field label) pairs → the
          first id whose text holds a NUL → the refusal line.

    Dependencies:
        Uses:
            - ``_ADD_PATH_INPUTS`` / ``_KIND_LOOK`` (labels),
              ``flow_persistence_service.FLOW_UNSAFE_REF`` (the loader's code)
        Used by:
            - ``FlowBuilderPanel.on_button_pressed`` (the ``flow_add`` branch,
              before any block is built)
    """
    for input_id, field_label in _ADD_PATH_INPUTS.get(kind, ()):
        if "\x00" in values.get(input_id, ""):
            kind_label = _KIND_LOOK.get(kind, ("", kind.upper(), "", ""))[1]
            return (
                f"Add refused: [{fps.FLOW_UNSAFE_REF}] {kind_label} {field_label} "
                "holds a NUL character - not a path"
            )
    return None


def clip_head(text: str, width: int) -> str:
    """Keep the head: labels, titles and commands (LLR-146.4).

    Args:
        text (str): The plain text to fit.
        width (int): The cells available.

    Returns:
        str: ``text`` when it fits, else its first ``width − 1`` characters
        and one ``…``.

    Data Flow:
        - ``len(text)`` vs ``width`` → unchanged, or head + ``…``.

    Dependencies:
        Used by:
            - ``_card_lines`` (titles, notes, commands), ``ribbon_text`` (name,
              kind summary)
    """
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def clip_tail(text: str, width: int) -> str:
    """Keep the tail: file names and paths (LLR-146.4).

    Args:
        text (str): The plain text to fit.
        width (int): The cells available.

    Returns:
        str: ``text`` when it fits, else one ``…`` and its last ``width − 1``
        characters.

    Data Flow:
        - ``len(text)`` vs ``width`` → unchanged, or ``…`` + tail.

    Dependencies:
        Used by:
            - ``_card_lines`` (refs, logs, outputs), ``ribbon_text`` (session
              path), ``FlowBuilderPanel._wrote_line`` (written paths)
    """
    if len(text) <= width:
        return text
    return "…" + text[len(text) - max(0, width - 1):]


#: The narrowest card (LLR-149.5) and the cable between two cards (``───▶``).
CARD_MIN_W = 21
CABLE_W = 4


class PipelineLayout(NamedTuple):
    """The Builder's derived widths (D21): one card width for the whole chain,
    and the spare cells integer card widths leave, one on each of the first
    ``spare`` cables."""

    card_w: int
    spare: int = 0


def pipeline_layout(avail_w: int, n_cards: int) -> PipelineLayout:
    """Cards share the rail's measured width, never below ``CARD_MIN_W``.

    Args:
        avail_w (int): ``#flow_pipeline_scroll``'s scrollable content width.
        n_cards (int): The chain's block count.

    Returns:
        PipelineLayout: Four cards fill a 108-cell rail at 24 cells each; from
        the 5th card at 118 columns the cards keep 21 cells and the rail
        scrolls sideways inside its own frame. When the cards are wider than
        the minimum, ``spare`` (0 … ``n_cards − 1``) is what the integer
        division left, so the chain paints exactly ``avail_w`` cells and no
        void lies right of the last card (LLR-149.5; gate fold F2).

    Data Flow:
        - ``avail_w − CABLE_W·(n − 1)`` → ``card_w = ⌊…/n⌋`` (≥ 21) → the
          remainder → ``spare`` (0 when the minimum binds: the rail scrolls).

    Dependencies:
        Used by:
            - ``FlowBuilderPanel._refresh_blocks`` (the D21 layout pass) →
              ``pipeline_text``
    """
    if n_cards <= 0:
        return PipelineLayout(CARD_MIN_W)
    room = avail_w - CABLE_W * (n_cards - 1)
    card_w = room // n_cards
    if card_w < CARD_MIN_W:
        return PipelineLayout(CARD_MIN_W)
    return PipelineLayout(card_w, room - card_w * n_cards)


_S_CABLE = "bold " + HILITE


def _card_rows(blocks: Sequence[FlowBlock], index: int) -> Tuple[List[Tuple[str, str]], Tuple[str, str], str]:
    """(inputs as (label, painted value), (output label, value), note) of one
    card. Values are clipped by kind of text: a command keeps its head, every
    ref and path its tail (LLR-146.4); file-derived text is scrubbed (C-17)."""
    block = blocks[index]
    scrub = lambda s: safe_text(s).plain  # noqa: E731 - the one sink guard
    prev = ("image", f"← #{index}" if index > 0 else "—")
    if isinstance(block, SourceBlock):
        return [("file", scrub(block.image_ref)), ("fmt", block.file_type)], ("out", "image"), ""
    if isinstance(block, PatchBlock):
        return [prev, ("doc", scrub(block.change_doc_ref))], ("out", "image"), ""
    if isinstance(block, CheckBlock):
        return [prev, ("doc", scrub(block.check_doc_ref))], ("out", "image"), f"gating {block.gating}"
    if isinstance(block, CrcBlock):
        return [prev, ("tpl", scrub(block.config_ref))], ("out", "image"), ""
    if isinstance(block, WriteOutBlock):
        return [prev], ("out · file", scrub(block.output_name)), f"fmt {block.fmt}"
    if isinstance(block, ExternalStepBlock):
        noun = "cmd" if block.mode == EXTERNAL_MODE_TERMINAL else "instr"
        return (
            [prev, (noun, scrub(block.instruction)), ("log", scrub(block.log_ref))],
            ("out · file", scrub(block.output_path)),
            "",
        )
    if isinstance(block, A2BBlock):
        return (
            [("A", scrub(_binding_label(block.image_a))), ("B", scrub(_binding_label(block.image_b)))],
            ("out", "report"),
            "",
        )
    return [], ("out", "report marker"), ""


def _card_lines(blocks: Sequence[FlowBlock], index: int, card_w: int, rows_in: int) -> List[Text]:
    """One card as ``7 + 2·rows_in`` lines, each exactly ``card_w`` cells."""
    block = blocks[index]
    glyph, label, colour, does = _KIND_LOOK.get(block.kind, ("·", block.kind.upper(), DGRAY, ""))
    ins, (out_label, out_value), note = _card_rows(blocks, index)
    inner = card_w - 4
    ext = isinstance(block, ExternalStepBlock)

    def row(text: str = "", style: str = VALUE) -> Text:
        line = Text("│ ", style=_S_RULE)
        line.append(text, style=style)
        line.append(" " * (inner - len(text)) + " │", style=_S_RULE)
        return line

    number = str(index + 1)
    head = Text("╭─ ", style=_S_RULE)
    head.append(number, style=_S_DIM)
    head.append(" " + "─" * (card_w - 5 - len(number)) + "╮", style=_S_RULE)
    sub = f"{block.mode} · human" if ext else does
    lines = [head, row(clip_head(f"{glyph} {label}", inner), "bold " + colour), row(clip_head(sub, inner), _S_DIM)]
    for slot in range(rows_in):
        if slot < len(ins):
            name, value = ins[slot]
            keep = clip_head if ext and name in ("cmd", "instr") else clip_tail
            lines.append(row(clip_head(f"in · {name}", inner), _S_DIM))
            lines.append(row(keep(value, inner)))
        else:
            lines.extend([row(), row()])
    lines.append(row(clip_head(note, inner), _S_DIM))
    lines.append(row(clip_head(out_label, inner), _S_DIM))
    lines.append(row(clip_tail(out_value, inner), _S_OUT))
    lines.append(Text("╰" + "─" * (card_w - 2) + "╯", style=_S_RULE))
    return lines


def pipeline_text(blocks: Sequence[FlowBlock], card_w: int, spare: int = 0) -> Text:
    """The chain as one row of equal-height cards joined by cables (fb_A).

    Args:
        blocks (Sequence[FlowBlock]): The chain, in order.
        card_w (int): Every card's width (``pipeline_layout``).
        spare (int): How many cables, the first ones, take one more cell
            (``pipeline_layout``), so the chain fills the rail.

    Returns:
        Text: Every card ``card_w`` cells and ``7 + 2·m`` rows, ``m`` the most
        inputs any card shows (2, or 3 with an EXT-STEP); the cable ``───▶``
        (``────▶`` when widened) on the output row between consecutive cards;
        with no blocks, the one empty-state line.

    Data Flow:
        - ``blocks`` → ``_card_rows`` / ``_card_lines`` per card → rows joined
          left to right with the cables. Pure projection of ``blocks``; every
          file-derived string goes through ``safe_text`` in ``_card_rows``.

    Dependencies:
        Uses:
            - ``_card_lines``, ``clip_head`` / ``clip_tail``, ``_KIND_LOOK``
        Used by:
            - ``FlowBuilderPanel.compose`` / ``_refresh_blocks``
    """
    if not blocks:
        text = Text()
        text.append("No blocks yet", style="bold " + VALUE)
        text.append(" — a chain starts with ", style=_S_DIM)
        text.append("◉ LOAD", style="bold " + HILITE)
        text.append(": pick it below, type the image file, press ", style=_S_DIM)
        text.append("Add", style="bold " + HILITE)
        text.append(".", style=_S_DIM)
        return text
    rows_in = max(len(_card_rows(blocks, i)[0]) for i in range(len(blocks)))
    cards = [_card_lines(blocks, i, card_w, rows_in) for i in range(len(blocks))]
    height = len(cards[0])
    out_row = height - 2
    lines: List[Text] = []
    for y in range(height):
        line = Text()
        for i, card in enumerate(cards):
            line.append_text(card[y])
            if i < len(cards) - 1:
                cable_w = CABLE_W + (1 if i < spare else 0)
                if y == out_row:
                    line.append("─" * (cable_w - 1) + "▶", style=_S_CABLE)
                else:
                    line.append(" " * cable_w)
        lines.append(line)
    return _join_lines(lines)


#: The ribbon's no-session state (LLR-146.11 empty arm, LLR-148.9).
RIBBON_NO_SESSION = "(no active project)"


def ribbon_text(
    name: str, dirty: bool, kinds: Sequence[str], session: str, width: int, *, prefix: str = "Flow: "
) -> Text:
    """The identity ribbon, ``width`` cells (LLR-146.11).

    Args:
        name (str): The flow's display name.
        dirty (bool): Unsaved edits exist.
        kinds (Sequence[str]): The chain's block kinds, in order.
        session (str): The session directory, ``""`` with no project.
        width (int): The ribbon's measured content width.
        prefix (str): The identity label — ``Flow: `` on the Builder,
            ``Set: `` on Flow Execution (batch-97 Inc-6, LLR-147.4).

    Returns:
        Text: ``Flow: <name>  · saved|· unsaved  LOAD → PATCH …`` and,
        right-aligned, ``session <path tail>``. The saved state is a word
        (gate fold, operator decision 3, LED-…97.26; batch-53's ``✓`` / ``●``
        also meant check block / ok on this screen): ``· saved`` in
        ``DGRAY``, ``· unsaved`` in ``YELLOW`` — the attention colour the
        dirty strip already carried (``.sev-warning``); the amber
        ``WAITING_HUMAN`` stays reserved for what waits for a human. The name
        keeps its head, the kind summary its head (clipped first), the
        session path its tail.

    Data Flow:
        - name / state / kinds / session → one line; every file-derived
          string is scrubbed by ``safe_text`` (C-17).

    Dependencies:
        Uses:
            - ``clip_head`` / ``clip_tail``, ``_KIND_LOOK``, ``safe_text``
        Used by:
            - ``FlowBuilderPanel._name_strip_text``,
              ``FlowExecutionPanel._name_strip_text``
    """
    state, state_style = ("· unsaved", YELLOW) if dirty else ("· saved", DGRAY)
    path = safe_text(session).plain if session else ""
    right_full = ("session " + path) if path else ("session " + RIBBON_NO_SESSION)
    right_w = min(len(right_full), max(len("session ") + 12, width * 2 // 5))
    right = Text("session ", style=_S_DIM)
    if path:
        right.append(clip_tail(path, right_w - len("session ")), style=_S_OUT)
    else:
        right.append(clip_tail(RIBBON_NO_SESSION, right_w - len("session ")), style=_S_DIM)
    left = Text(prefix)
    room = max(4, width - right.cell_len - 2 - len(prefix) - 2 - len(state))
    left.append(clip_head(safe_text(name).plain, room), style="bold " + VALUE)
    left.append("  ")
    left.append(state, style=state_style)
    summary = " → ".join(_KIND_LOOK.get(k, ("", k.upper(), "", ""))[1] for k in kinds)
    gap = width - left.cell_len - right.cell_len
    if summary and gap > 6:
        left.append("  ")
        left.append(clip_head(summary, gap - 4), style=_S_DIM)
    left.append(" " * max(1, width - left.cell_len - right.cell_len))
    left.append_text(right)
    return left


def flow_legend_text(with_report: bool) -> Text:
    """The one-row legend, generated from the two Builder vocabularies.

    Args:
        with_report (bool): The chain carries a report block.

    Returns:
        Text: ``glyph meaning`` pairs of ``FLOW_KIND_GLYPHS`` then
        ``FLOW_CABLE_GLYPHS``; ``≡ report`` only while ``with_report`` (all
        ten pairs, 116 cells, do not fit the 112-cell panel at 118 columns —
        D7, the legend from the mapping).

    Data Flow:
        - the two mappings → filtered pairs → one styled line.

    Dependencies:
        Uses:
            - ``FLOW_KIND_GLYPHS``, ``FLOW_CABLE_GLYPHS``
        Used by:
            - ``FlowBuilderPanel.compose`` / ``_refresh_blocks``
    """
    pairs = [(g, m) for g, m in FLOW_KIND_GLYPHS.items() if with_report or g != "≡"]
    pairs += list(FLOW_CABLE_GLYPHS.items())
    text = Text()
    for i, (glyph, meaning) in enumerate(pairs):
        if i:
            text.append("  ")
        text.append(glyph, style=VALUE)
        text.append(f" {meaning}", style=_S_DIM)
    return text


class FlowChip(Button):
    """A one-row chip of the two flow screens: ``enter`` (Button's own) and
    ``space`` press it (batch-97 D13, PC-3). Every button the flow screens
    compose is a ``FlowChip``, so ``space`` works the same on all of them with
    no import edge to ``screens_directionb.TabChip``; CSS type selectors
    (``Button``) match the subclass, so the paint is unchanged.

    Dependencies:
        Uses:
            - ``textual.widgets.Button`` (``action_press``)
        Used by:
            - ``FlowBuilderPanel.compose``, ``FlowExecutionPanel`` (header
              rows, Bind, Confirm), ``KindChip``, ``ModeToggle``
    """

    BINDINGS = [Binding("space", "press", "Press", show=False)]


class KindChip(FlowChip):
    """A one-row block-kind chip: ``enter`` (Button's own) and ``space`` set
    the kind (LLR-146.13). Declared here, not reused from
    ``screens_directionb.TabChip``, so ``flow_screens`` gains no import edge.

    Data Flow:
        - ``enter`` / ``space`` / click → ``Button.Pressed`` →
          ``FlowBuilderPanel.on_button_pressed`` (``flow_palette_<kind>``) →
          ``#flow_kind`` set → the add form shows that kind's inputs.

    Dependencies:
        Uses:
            - ``FlowChip`` (the ``space`` binding)
        Used by:
            - ``FlowBuilderPanel.compose`` (one per ``_KIND_OPTIONS`` kind)
    """


#: The run modes the toggle offers, in label order (LLR-019.1: sequential is
#: the untouched default).
FX_MODES: Tuple[str, str] = ("sequential", "parallel")


class ModeToggle(FlowChip):
    """Flow Execution's one-row run-mode control, ``sequential · parallel``
    (batch-97 D13, LLR-147.4).

    Summary:
        A click selects the word under the pointer (it never toggles: a click
        on the active word keeps it); ``enter`` / ``space`` toggle. The active
        word paints in the ``mode-toggle--active`` component style, the other
        word and the separator in ``DGRAY``. It posts no ``Button.Pressed``:
        the panel reads :attr:`mode` when Run is pressed.

    Data Flow:
        - click → ``event.x`` → the word under it → :meth:`set_mode`.
        - ``enter`` / ``space`` → ``action_press`` → :meth:`press` → toggle.

    Dependencies:
        Uses:
            - ``FlowChip``
        Used by:
            - ``FlowExecutionPanel.compose`` (``#fx_mode``) and its ``mode``
    """

    COMPONENT_CLASSES = {"mode-toggle--active"}

    #: The last cell of ``sequential`` and the first of ``parallel`` in widget
    #: coordinates (Button's 1-cell line pad at x 0): ``sequential`` 1–10,
    #: `` · `` 11–13, ``parallel`` 14–21.
    _SEQUENTIAL_LAST_X = 10
    _PARALLEL_FIRST_X = 14

    def __init__(self, *, id: Optional[str] = None, mode: str = FX_MODES[0]) -> None:
        self.mode = mode
        super().__init__(self._label_text(None), id=id)

    def _label_text(self, active_style) -> Text:
        text = Text()
        for index, word in enumerate(FX_MODES):
            if index:
                text.append(" · ", style=DGRAY)
            if word == self.mode:
                text.append(word, style=active_style or "bold")
            else:
                text.append(word, style=DGRAY)
        return text

    def _repaint(self) -> None:
        style = self.get_component_rich_style("mode-toggle--active") if self.is_mounted else None
        self.label = self._label_text(style)

    def on_mount(self) -> None:
        self._repaint()

    def set_mode(self, mode: str) -> None:
        """Select ``mode`` (one of :data:`FX_MODES`) and repaint."""
        if mode in FX_MODES and mode != self.mode:
            self.mode = mode
            self._repaint()

    def press(self) -> "ModeToggle":
        """``enter`` / ``space``: toggle the mode; no ``Button.Pressed``."""
        if self.disabled or not self.display:
            return self
        self.set_mode(FX_MODES[1] if self.mode == FX_MODES[0] else FX_MODES[0])
        return self

    async def _on_click(self, event: events.Click) -> None:
        event.stop()
        event.prevent_default()
        if self.disabled:
            return
        if event.x <= self._SEQUENTIAL_LAST_X:
            self.set_mode(FX_MODES[0])
        elif event.x >= self._PARALLEL_FIRST_X:
            self.set_mode(FX_MODES[1])


class FlowBuilderPanel(ScrollableContainer):
    """Rail-8 Flow Builder — the pipeline rail (batch-97 Inc-5, fb_A).

    Summary:
        batch-97 (HLR-146): an identity ribbon (name, saved glyph, kind
        summary, session path tail), the chain as ONE row of cards joined by
        cables in a frame exactly as tall as the cards, a kind-chip palette
        with an add form showing only the chosen kind's inputs, the copy /
        paste strip with ``Variables (n)``, the foot row with Run as the one
        filled action, and the result area under Run as the growing region.
        The batch-94 grid canvas and numbered list (``#flow_canvas``,
        ``#flow_blocks``) stay mounted and painted, not displayed. The A2B
        diff block (HLR-014) binds each
        image input to a flow output (``#<n>``) or a file, refused at wiring
        time when both inputs are external / the reference is downstream / the
        target produces no image — a refused binding never enters the flow, so
        0 reports are produced for it. Run/Save/Load post the same message
        family as the tracer (the B2 move changed the panel's ADDRESS, not its
        contract). Presentational — it imports the ``flow_model`` data types
        read-only (no engine), and EVERY dynamic string renders markup-safe
        via ``safe_text`` (C-17).

    Data Flow:
        - Kind chip / Add → block appended to ``self._blocks`` → pipeline,
          ribbon and legend repaint (the hidden canvas and list too).
        - Run → ``RunRequested(Flow(blocks=self._blocks), FLOW_SCOPE_SINGLE)``
          → app → ``run_flow`` → :meth:`render_result`.

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
    #: ALWAYS carry the mandatory log + the output file (spec v3). Labels fit
    #: the one-row mode select (batch-97 Inc-5).
    _EXT_MODE_OPTIONS = [
        ("Terminal", EXTERNAL_MODE_TERMINAL),
        ("Manual", EXTERNAL_MODE_MANUAL),
    ]

    #: The CHECK per-block gating options (label, gating value) — the minimal
    #: user-visible setter (LLR-086.1, the OPEN gating-UI flag). Read by Add
    #: only when the kind is CHECK; ignored otherwise.
    _GATING_OPTIONS = [
        ("advisory", CHECK_GATING_ADVISORY),
        ("block-own-op", CHECK_GATING_BLOCK_OWN),
    ]

    class RunRequested(Message):
        """The operator pressed Run — carries the composed flow to the app.

        Args:
            flow (Flow): The ordered typed-block flow to execute.
            scope (str): One of ``FLOW_SCOPES``. The Builder always sends
                ``FLOW_SCOPE_SINGLE`` (batch-97 LLR-146.12: multi-variant runs
                live in Flow Execution, one chain per variant); the field stays
                for the frozen message shape (batch-94 ``#D3``).
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
        #: The session artifact dir (the active project work area), shown on
        #: the ribbon (LLR-146.11); set by the app via :meth:`set_session_dir`.
        self._session_dir: Optional[str] = None
        #: The flow-level FUNNEL table (batch-96 B1) — ordered (name, value)
        #: pairs declared beside the canvas; rides ``current_flow`` into
        #: Run/Save and is restored by ``set_blocks``.
        self._funnel: List[Tuple[str, str]] = []
        #: The block COPY/PASTE clipboard (batch-96 B2) — the WIRE dict of
        #: ONE block (the ``flow_to_dict`` projection), never a live
        #: instance, so a paste always builds a fresh block object.
        self._clipboard: Optional[dict] = None
        #: D21 layout state: the measured (rail width, ribbon width) of the
        #: last layout pass, and the card width it derived for the chain.
        self._layout_key: Optional[Tuple[int, int]] = None
        self._card_w: int = CARD_MIN_W
        self._spare: int = 0
        #: The last run's written paths, re-clipped by the layout pass.
        self._wrote_paths: List[str] = []

    def set_session_dir(self, path: str) -> None:
        """Publish the session artifact dir; it rides the ribbon (LLR-146.11)."""
        self._session_dir = path or None
        if not self.is_mounted:
            return
        self.query_one("#flow_ext_session", Static).update(
            safe_text(f"session: {path} — on confirm, the output file is copied here")
            if path
            else safe_text(f"session: {RIBBON_NO_SESSION}")
        )
        self._refresh_name_strip()

    def compose(self) -> ComposeResult:
        with Horizontal(id="flow_ribbon"):
            yield Static(
                self._name_strip_text(),
                id="flow_name_strip",
                markup=False,
                classes=self._name_strip_class(),
            )
        yield Label(
            "Flow Builder: pick a block kind, enter its refs, Add; wire A2B "
            "inputs as a file name or #<n> (a flow output).",
            id="flow_help",
            markup=False,
        )
        with ScrollableContainer(id="flow_pipeline_scroll"):
            yield Static(
                pipeline_text(self._blocks, self._card_w),
                id="flow_pipeline",
                classes="nowrap-pipeline",
            )
        yield Static(self._canvas_text(), id="flow_canvas", markup=False)
        yield Static(self._blocks_text(), id="flow_blocks", markup=False)
        with Horizontal(id="flow_palette"):
            yield Label("add block", classes="flow-field-label")
            for _label, kind in self._KIND_OPTIONS:
                glyph, name, _colour, _does = _KIND_LOOK[kind]
                yield KindChip(f"{glyph} {name}", id=f"flow_palette_{kind}", classes="kind-chip")
        with Horizontal(id="flow_add_row"):
            yield Select(self._KIND_OPTIONS, value=BLOCK_SOURCE, allow_blank=False, id="flow_kind")
            yield Static("", classes="flow-kind-tag")
            with Vertical(classes="flow-add-fields"):
                with Horizontal(classes="flow-add-line"):
                    yield Label("", classes="flow-field-label flow-ref-label")
                    yield OsClipboardInput(placeholder="", id="flow_ref", compact=True)
                    yield Label("gating", classes="flow-field-label flow-gating-label")
                    yield Select(
                        self._GATING_OPTIONS,
                        value=CHECK_GATING_ADVISORY,
                        allow_blank=False,
                        id="flow_gating",
                        compact=True,
                    )
                    yield Label("image A", classes="flow-field-label flow-a2b-label")
                    yield OsClipboardInput(placeholder="file or #n", id="flow_ref_a", compact=True)
                    yield Label("image B", classes="flow-field-label flow-a2b-label")
                    yield OsClipboardInput(placeholder="file or #n", id="flow_ref_b", compact=True)
                    yield Label("mode", classes="flow-field-label flow-ext-label")
                    yield Select(
                        self._EXT_MODE_OPTIONS,
                        value=EXTERNAL_MODE_TERMINAL,
                        allow_blank=False,
                        id="flow_ext_mode",
                        compact=True,
                    )
                    yield Label("command", classes="flow-field-label flow-ext-label flow-instruction-label")
                    yield OsClipboardInput(
                        placeholder="the exact command run outside the app",
                        id="flow_ext_instruction",
                        compact=True,
                    )
                # The EXT-STEP second row (LLR-146.3: two rows). It sits inside
                # the add fields, so the focus chain reaches the log and the
                # output before Add (LLR-146.13).
                with Horizontal(id="flow_ext_row"):
                    yield Label("log", classes="flow-field-label")
                    yield OsClipboardInput(placeholder="log file (required)", id="flow_ext_log", compact=True)
                    yield Label("output file", classes="flow-field-label")
                    yield OsClipboardInput(
                        placeholder="the file the step leaves, absolute path preferred",
                        id="flow_ext_output",
                        compact=True,
                    )
            yield FlowChip("+ Add", id="flow_add")
        with Horizontal(id="flow_clip_row"):
            yield Label("copy block #", classes="flow-field-label")
            yield OsClipboardInput(placeholder="last", id="flow_pick", compact=True)
            yield FlowChip("Copy", id="flow_copy")
            yield FlowChip("Paste", id="flow_paste")
            yield Static("", id="flow_clip_status", markup=False)
            yield FlowChip("Variables (0)", id="flow_funnel_toggle")
        with Horizontal(id="flow_funnel_editor"):
            yield Label("variable", classes="flow-field-label")
            yield OsClipboardInput(placeholder="NAME [A-Z0-9_]", id="flow_funnel_name", compact=True)
            yield Label("value", classes="flow-field-label")
            yield OsClipboardInput(placeholder="the value to substitute", id="flow_funnel_value", compact=True)
            yield FlowChip("+ Add var", id="flow_funnel_add")
        yield Static("", id="flow_funnel_list", markup=False)
        yield Static("", id="flow_wiring_notice", markup=False)
        #: Kept mounted, never displayed: the session rides the ribbon now.
        yield Static(f"session: {RIBBON_NO_SESSION}", id="flow_ext_session", markup=False)
        with Horizontal(id="flow_run_row"):
            yield FlowChip("Run", id="flow_run", classes="fill-accent")
            yield FlowChip("Clear", id="flow_clear")
            yield FlowChip("Save…", id="flow_save")
            yield FlowChip("Load…", id="flow_load")
        yield VerticalScroll(id="flow_result")
        yield Static(
            flow_legend_text(False),
            id="flow_legend",
            classes="glyph-legend nowrap-legend",
        )

    # -- the identity ribbon (the tracer's name strip, widened) --------------

    def _name_strip_text(self) -> Text:
        """The ribbon line: ``Flow: <name>  <glyph>``, the kind summary and the
        session path's tail (LLR-146.11), at the ribbon's measured width.

        The glyph ``●`` (dirty) / ``✓`` (saved) stays the PRIMARY state cue
        (C-10), colour the secondary one; every file-derived string is
        scrubbed (C-17).
        """
        width = self._layout_key[1] if self._layout_key else 108
        return ribbon_text(
            self._flow_name,
            self._dirty,
            [block.kind for block in self._blocks],
            self._session_dir or "",
            width,
        )

    def _name_strip_class(self) -> str:
        """``sev-warning`` when dirty, ``sev-neutral`` when saved (secondary cue)."""
        return "flow-name-strip nowrap-ribbon " + ("sev-warning" if self._dirty else "sev-neutral")

    def _refresh_name_strip(self) -> None:
        strip = self.query_one("#flow_name_strip", Static)
        strip.update(self._name_strip_text())
        strip.set_classes(self._name_strip_class())

    def _mark_dirty(self) -> None:
        """Flag unsaved edits and repaint the name strip; a chain edit also
        retires the frame's load-refusal line."""
        self._dirty = True
        self.query_one("#flow_pipeline_scroll").border_subtitle = None
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
        self.query_one("#flow_pipeline_scroll").border_subtitle = None
        self._refresh_blocks()
        self._refresh_funnel_list()
        self._refresh_name_strip()
        self._show_result_empty()

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

        batch-97 (LLR-148.9): the pipeline frame names the refusal on its
        bottom border row — one English line, the chain kept — while the card
        under Run holds the findings.

        Args:
            flow_name (str): The rejected file's stem (untrusted — markup-safe).
            findings (List[ValidationIssue]): The loader's fail-closed findings.
        """
        self.query_one("#flow_pipeline_scroll").border_subtitle = safe_text(
            f"load refused: flows/{flow_name}.json — this chain is kept"
        )
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
                    # batch-97 (HLR-146): the line names its finding code.
                    safe_text(f"[{finding.code}] {finding.message}"),  # SINK: file-derived finding text
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
        """Repaint the pipeline, its frame title, the legend and the ribbon;
        the hidden canvas and list are repainted too (their readers stay)."""
        self.query_one("#flow_blocks", Static).update(self._blocks_text())
        self.query_one("#flow_canvas", Static).update(self._canvas_text())
        if self._layout_key is not None:
            self._card_w, self._spare = pipeline_layout(self._layout_key[0], len(self._blocks))
        self.query_one("#flow_pipeline", Static).update(pipeline_text(self._blocks, self._card_w, self._spare))
        count = len(self._blocks)
        self.query_one("#flow_pipeline_scroll").border_title = f"chain · {count} block{'' if count == 1 else 's'}"
        self.query_one("#flow_legend", Static).update(
            flow_legend_text(any(isinstance(b, ReportBlock) for b in self._blocks))
        )
        self._refresh_name_strip()

    # -- the layout pass (D21): widths read from the regions after layout ----

    def on_resize(self) -> None:
        self.call_after_refresh(self._apply_layout)

    def on_show(self) -> None:
        self.call_after_refresh(self._apply_layout)

    def _apply_layout(self) -> None:
        """Derive the card width from the rail's measured width and recompose
        the width-dependent text (cards, ribbon tail); an equal reading
        repaints nothing."""
        rail = self.query_one("#flow_pipeline_scroll").scrollable_content_region.width
        ribbon = self.query_one("#flow_name_strip").content_region.width
        if rail <= 0 or ribbon <= 0 or (rail, ribbon) == self._layout_key:
            return
        self._layout_key = (rail, ribbon)
        self._refresh_blocks()
        for line, path in zip(self.query(".flow-wrote-path"), self._wrote_paths):
            line.update(safe_text(self._wrote_line(path)))

    def _wrote_line(self, path: str) -> str:
        """One written-path line, ``wrote <path>``, the path's tail kept at the
        result area's content width (ux M1, LLR-149.4); the caller renders it
        through ``safe_text`` (C-17)."""
        width = self.query_one("#flow_result").scrollable_content_region.width - 1
        plain = safe_text(path).plain
        if width > len("wrote ") + 4:
            plain = clip_tail(plain, width - len("wrote "))
        return "wrote " + plain

    # -- funnel (batch-96 B1) -------------------------------------------------

    def _funnel_list_text(self) -> Text:
        """One ``NAME = value`` line per declared variable (markup-safe)."""
        if not self._funnel:
            return safe_text(
                "no variables — ${NAME} placeholders in change docs pass through unchanged"
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
        toggle.label = f"Variables ({len(self._funnel)})"

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
                "Variable refused: the name must be a placeholder "
                "[A-Z0-9_] (e.g. BOOST) - no lower case, no spaces."
            )
            return
        if not value.strip():
            self._show_wiring_notice(
                "Variable refused: the value cannot be empty."
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
                    f"Copy refused: there is no block #{raw} (the chain has "
                    f"{len(self._blocks)})."
                )
                return
            block = self._blocks[int(raw) - 1]
        else:
            if not self._blocks:
                self._show_wiring_notice(
                    "Copy refused: the chain is empty."
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
                "Paste: the clipboard is empty - nothing to paste."
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
                "Paste refused: load a project first (the paste is checked "
                "against the session directory)."
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
            message = findings[0].message if findings else "invalid block"
            self._show_wiring_notice(f"Paste refused: {message}")
            return
        block = parsed.blocks[-1]
        self._blocks.append(block)
        self._show_wiring_notice("")
        self._refresh_blocks()
        self._refresh_clip_status(f"pasted: {block.kind}")
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
                "the exact command" if mode == EXTERNAL_MODE_TERMINAL
                else "the instruction"
            )
            self._show_wiring_notice(
                f"External step refused: {noun} to run outside the app is missing."
            )
            return
        if not log_ref:
            self._show_wiring_notice(
                "External step refused: the log file is required (the record "
                "of the step, never optional)."
            )
            return
        if not output_path:
            self._show_wiring_notice(
                "External step refused: the output file is missing (an "
                "absolute path is preferred)."
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
            # A notice about the previous kind no longer applies (ux L-a).
            self._show_wiring_notice("")
            return
        if event.button.id == "flow_add":
            kind = str(self.query_one("#flow_kind", Select).value)
            # S4-1 (LLR-146.14): a NUL in a path-bearing input refuses the
            # Add before any block is built; the inputs keep their text.
            refusal = nul_add_refusal(
                kind,
                {
                    input_id: self.query_one(input_id, Input).value
                    for input_id, _field in _ADD_PATH_INPUTS.get(kind, ())
                },
            )
            if refusal is not None:
                self._show_wiring_notice(refusal)
                return
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
                # LLR-148.9 add-form error state (gate fold ux M3): name what
                # the press needs instead of doing nothing silently.
                field = _REF_FIELD.get(kind, ("a ref", ""))[0]
                self._show_wiring_notice(f"Add needs {field} — nothing added")
                return
            self._blocks.append(block)
            self.query_one("#flow_ref", Input).value = ""
            self._show_wiring_notice("")
            self._refresh_blocks()
            self._mark_dirty()
        elif event.button.id == "flow_run":
            self._show_wiring_notice("")
            self.post_message(self.RunRequested(self.current_flow, FLOW_SCOPE_SINGLE))
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
            self.query_one("#flow_pipeline_scroll").border_subtitle = None
            self._show_result_empty()
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
        # batch-97 Inc-5 (LLR-146.1, 146.11): the help sentence, the grid
        # canvas, the numbered list, the kind select and the session line stay
        # mounted, not displayed — the pipeline, the chips and the ribbon carry
        # them.
        for hidden in ("#flow_help", "#flow_canvas", "#flow_blocks", "#flow_kind", "#flow_ext_session"):
            self.query_one(hidden).display = False
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
        self._refresh_blocks()
        self._show_result_empty()
        self.call_after_refresh(self._apply_layout)

    def on_select_changed(self, event: Select.Changed) -> None:
        # The block-kind selector toggles the add form; the EXT-STEP mode
        # renames the command field.
        if event.select.id == "flow_kind":
            self._sync_kind_dependent_visibility(str(event.value))
        elif event.select.id == "flow_ext_mode":
            terminal = event.value == EXTERNAL_MODE_TERMINAL
            self.query_one(".flow-instruction-label", Label).update("command" if terminal else "instruction")
            self.query_one("#flow_ext_instruction", Input).placeholder = (
                "the exact command run outside the app" if terminal else "what the human does"
            )

    def _sync_kind_dependent_visibility(self, kind: str) -> None:
        """Show only the chosen kind's add inputs (LLR-146.3): the gating
        control for CHECK, the binding inputs for A2B, mode + command and the
        log + output row for EXTERNAL_STEP, the single ref for every other
        kind; tag the row with the kind and mark its chip selected."""
        ext = kind == BLOCK_EXTERNAL_STEP
        single = kind not in (BLOCK_A2B, BLOCK_EXTERNAL_STEP)
        self.query_one("#flow_gating", Select).display = kind == BLOCK_CHECK
        self.query_one(".flow-gating-label", Label).display = kind == BLOCK_CHECK
        self.query_one("#flow_ref", Input).display = single
        self.query_one(".flow-ref-label", Label).display = single
        for widget in (
            self.query_one("#flow_ref_a", Input),
            self.query_one("#flow_ref_b", Input),
            *self.query(".flow-a2b-label"),
        ):
            widget.display = kind == BLOCK_A2B
        for widget in (
            self.query_one("#flow_ext_mode", Select),
            self.query_one("#flow_ext_instruction", Input),
            *self.query(".flow-ext-label"),
        ):
            widget.display = ext
        self.query_one("#flow_ext_row").display = ext
        if single:
            label, hint = _REF_FIELD.get(kind, ("ref", ""))
            self.query_one(".flow-ref-label", Label).update(label)
            self.query_one("#flow_ref", Input).placeholder = hint
        glyph, name, colour, _does = _KIND_LOOK.get(kind, ("·", kind.upper(), DGRAY, ""))
        self.query_one(".flow-kind-tag", Static).update(Text(f"{glyph} {name}", style="bold " + colour))
        for chip in self.query(KindChip):
            chip.set_class(chip.id == f"flow_palette_{kind}", "chip-selected")

    def _show_result_empty(self) -> None:
        """The result area before a run: one line, the rest plain background
        (decision B, LLR-149.5)."""
        container = self.query_one("#flow_result", VerticalScroll)
        container.remove_children()
        line = Text()
        line.append("No run yet", style="bold " + VALUE)
        line.append(" — ", style=_S_DIM)
        line.append("Run", style="bold " + HILITE)
        line.append(" executes this chain against the loaded image; the block verdicts land here.", style=_S_DIM)
        container.mount(Static(line, classes="flow-result-empty"))

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
        if result.status == FLOW_STATUS_ISSUES and all(
            b.status != BLOCK_STATUS_ERROR for b in result.block_results
        ):
            banner_text, banner_class = _NOTICES_BANNER
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

        self._wrote_paths = [str(path) for path in result.written_paths]
        for path in self._wrote_paths:
            widgets.append(
                Static(
                    safe_text(self._wrote_line(path)),  # SINK: written path
                    markup=False,
                    classes="flow-wrote flow-wrote-path sev-ok",
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
# Flow Execution (batch-94 Inc-003 fx_a; batch-97 Inc-6 fx_A, HLR-147): one
# pipeline per lane, stacked; each cable carries its block's run status from
# the retained record; a waiting lane shows its pending lines, its Confirm and
# the REQUIRED line; the run log and the legend close the panel.
# ---------------------------------------------------------------------------

#: The cable vocabulary (D7, LLR-147.1): the mark painted on the cable after
#: block *j*, the lane head's worst-status mark (LLR-147.12) and the run log's
#: terminal marks. One meaning per glyph; the legend is generated from it.
FX_CABLE_GLYPHS: Mapping[str, str] = {
    "▓": "done",
    "░": "not run / skipped",
    "✗": "error",
    "◇": "notices",
    "□": "waiting for a human",
}

#: Heads the two red pending lines and the reload notice (D7 (a)): owed by
#: the engineer before the lane can go on. Not in the cable vocabulary.
FX_PENDING_GLYPH = "▪"

#: A ``c`` press confirms the attention lane only once its attention class
#: has been painted this long (LLR-147.13, D15).
CONFIRM_DWELL_S = 0.5

#: The cells every lane keeps right of its cards for Confirm (D24, PC-4): a
#: 1-cell gap + the 9-cell ``Confirm`` chip (7 + the chip's two line pads),
#: taken whether or not a lane waits, so no card moves when one starts.
CONFIRM_RESERVE = 10

#: The run log paints at most this many lines (LLR-147.8); the chain-set
#: report keeps every line.
FX_LOG_MAX_ROWS = 8

#: An error line is clipped to this many cells (LLR-148.9, D14 (4)).
FX_ERROR_LINE_MAX = 160

#: The dwell clock seam (D15): tests may monkeypatch it (the ``_json_clock``
#: idiom of the Patch Editor).
_fx_clock = time.monotonic

_S_WAIT = WAITING_HUMAN

#: Lane (flow) status → (mark, lane status word, colour): the lane head's
#: worst-status mark and the run log's terminal mark, on the cable vocabulary
#: (D7 (b), PC-2). Enum-derived, never file-derived.
_FX_STATUS_STYLE: Mapping[str, Tuple[str, str, str]] = {
    "": ("░", "not run", _S_DIM),
    FLOW_STATUS_OK: ("▓", "done", GREEN),
    FLOW_STATUS_ISSUES: ("◇", "done with notices", YELLOW),
    FLOW_STATUS_ERROR: ("✗", "failed", RED),
    FLOW_STATUS_PAUSED: ("□", "waiting for a human", _S_WAIT),
}

#: Block status → (mark, card status word, colour): each card's status line.
_FX_BLOCK_STYLE: Mapping[Optional[str], Tuple[str, str, str]] = {
    BLOCK_STATUS_OK: ("▓", "done", GREEN),
    BLOCK_STATUS_NOTICES: ("◇", "notices", YELLOW),
    BLOCK_STATUS_ERROR: ("✗", "error", RED),
    BLOCK_STATUS_SKIPPED: ("░", "skipped", _S_DIM),
    BLOCK_STATUS_WAITING: ("□", "waiting", _S_WAIT),
    None: ("░", "not run", _S_DIM),
}

#: The card row (0 = the top border) that carries the cables and Confirm.
_FX_OUT_ROW = 2


def cable_glyph(status: Optional[str], next_status: Optional[str]) -> str:
    """The mark on the cable after a block (LLR-147.1's truth table).

    Args:
        status (Optional[str]): Block *j*'s recorded status (``None``: no
            record yet).
        next_status (Optional[str]): Block *j+1*'s recorded status.

    Returns:
        str: ``□`` into a waiting block; otherwise ``▓`` ok, ``◇`` notices,
        ``✗`` error, ``░`` skipped / waiting / no record.

    Dependencies:
        Used by:
            - ``FlowExecutionPanel._cable_text`` / ``lane_paint_plain``
    """
    if next_status == BLOCK_STATUS_WAITING:
        return "□"
    return {
        BLOCK_STATUS_OK: "▓",
        BLOCK_STATUS_NOTICES: "◇",
        BLOCK_STATUS_ERROR: "✗",
    }.get(status, "░")


class LaneLayout(NamedTuple):
    """Flow Execution's derived widths (D24): one card width for every lane,
    and the spare cells, one more on each of the first ``spare`` cables."""

    card_w: int
    spare: int = 0


def lane_layout(viewport_w: int, n_max: int) -> LaneLayout:
    """The card width once per set (D24, PC-4).

    Args:
        viewport_w (int): ``#fx_lanes_scroll``'s scrollable content width.
        n_max (int): The largest block count over all lanes (1 with none).

    Returns:
        LaneLayout: ``pipeline_layout(viewport_w − CONFIRM_RESERVE, n_max)``,
        the Builder's rule over the viewport minus the Confirm reserve —
        applied to every lane, so card *k* starts at the same x in every lane.

    Dependencies:
        Uses:
            - ``pipeline_layout``
        Used by:
            - ``FlowExecutionPanel._apply_layout``
    """
    card_w, spare = pipeline_layout(viewport_w - CONFIRM_RESERVE, max(1, n_max))
    return LaneLayout(card_w, spare)


def fx_run_error_line(exc: BaseException) -> str:
    """One English line for a run that raised (D14 (4), LLR-148.9).

    Args:
        exc (BaseException): What the run raised.

    Returns:
        str: ``run failed - <Type>: <first line of the message>``, scrubbed
        through ``safe_text`` and clipped to ``FX_ERROR_LINE_MAX`` cells —
        never a traceback.

    Dependencies:
        Used by:
            - ``S19TuiApp`` Run and confirm handlers (their ``except`` limbs)
    """
    message = str(exc).splitlines()[0] if str(exc) else ""
    line = safe_text(f"run failed - {type(exc).__name__}: {message}").plain
    return clip_head(line, FX_ERROR_LINE_MAX)


def fx_legend_text() -> Text:
    """The one-row Execution legend, generated from ``FX_CABLE_GLYPHS`` and
    ``FX_PENDING_GLYPH`` (LLR-148.7); kind glyphs are named in the help."""
    pairs = list(FX_CABLE_GLYPHS.items()) + [(FX_PENDING_GLYPH, "owed before the lane goes on")]
    text = Text()
    for index, (glyph, meaning) in enumerate(pairs):
        if index:
            text.append("  ")
        text.append(glyph, style=VALUE)
        text.append(f" {meaning}", style=_S_DIM)
    return text


#: Before the first run the log paints this one line (LLR-148.9, LLR-147.8).
FX_LOG_EMPTY = "No run yet — Run executes every lane."
#: The lanes area with no lanes (LLR-148.9).
FX_LANES_EMPTY = "No chains yet — Import… adds a lane from a saved flow."
#: Run pressed with no lanes (HLR-147 empty arm).
FX_NO_LANES_RUN = "No chains to run — Import… adds a lane first."


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
    #: When the lane's last outcome finished, on the set run's clock (the
    #: head reads the same time as the log stamps, gate fold ux L2).
    last_finished: float = 0.0
    fail_block: Optional[int] = None
    missing: List[str] = field(default_factory=list)
    #: The external-step block index the lane waits at (``None`` when not
    #: waiting) — drives the pending lines and Confirm.
    paused_block: Optional[int] = None
    #: The session artifact dir (rides the ribbon since batch-97 Inc-6).
    session_dir: str = ""
    #: The EXT-STEP blocks confirmed in the current wait sequence (I-7 (b)):
    #: every one rides the next re-run, so a lane with two external steps
    #: reaches its end (LED-…97.29).
    confirmed: Tuple[int, ...] = ()
    #: Block index → recorded status of the lane's last run (the cables).
    block_status: Dict[int, str] = field(default_factory=dict)


def _fx_stamp(seconds: float) -> str:
    """``mm:ss.mmm`` — the run-log timestamp shape."""
    seconds = max(0.0, seconds)
    minutes = int(seconds // 60)
    return f"{minutes:02d}:{seconds % 60:06.3f}"


def _fx_card_io(block: FlowBlock, inner: int) -> List[Tuple[str, str]]:
    """The two io lines of a non-SOURCE card, each ``(text, style)`` clipped
    at ``inner`` cells: refs and paths keep the tail, commands the head
    (LLR-146.4's classes); file-derived text is scrubbed (C-17)."""

    def scrub(value: str) -> str:
        return safe_text(value).plain

    if isinstance(block, PatchBlock):
        lines = [(clip_tail(scrub(block.change_doc_ref), inner), VALUE), ("→ image", _S_DIM)]
    elif isinstance(block, CheckBlock):
        lines = [(clip_tail(scrub(block.check_doc_ref), inner), VALUE), (f"{block.gating} → image", _S_DIM)]
    elif isinstance(block, CrcBlock):
        lines = [(clip_tail(scrub(block.config_ref), inner), VALUE), ("→ image", _S_DIM)]
    elif isinstance(block, WriteOutBlock):
        lines = [(clip_tail(scrub(block.output_name), inner), VALUE), (f"fmt {block.fmt} → file", _S_DIM)]
    elif isinstance(block, ExternalStepBlock):
        lines = [
            (clip_head(scrub(block.instruction), inner), VALUE),
            ("→ " + clip_tail(scrub(block.output_path), max(1, inner - 2)), _S_DIM),
        ]
    elif isinstance(block, A2BBlock):
        lines = [
            ("A " + clip_tail(scrub(_binding_label(block.image_a)), max(1, inner - 2)), VALUE),
            ("B " + clip_tail(scrub(_binding_label(block.image_b)), max(1, inner - 2)), VALUE),
        ]
    elif isinstance(block, ReportBlock):
        lines = [("report marker", _S_DIM), ("", _S_DIM)]
    else:
        lines = [(scrub(block.kind), _S_DIM), ("", _S_DIM)]
    return [(clip_head(text, inner), style) for text, style in lines]


def _fx_kind_title(block: FlowBlock) -> Text:
    """A card's border title: the kind glyph and label in the kind colour."""
    glyph, label, colour, _does = _KIND_LOOK.get(block.kind, ("·", block.kind.upper(), DGRAY, ""))
    return Text(f"{glyph} {label}", style="bold " + colour)


class FlowExecutionPanel(ScrollableContainer):
    """Rail Flow Execution — one pipeline per lane (batch-97 Inc-6, fx_A).

    Summary:
        The HLR-017…021 surface re-composed for HLR-147: a ribbon (set
        identity, saved state, session folder, Import…, the mode toggle,
        Run) and a set row (name, Save Set, saved sets, Load Set); the lanes
        stacked in ``#fx_lanes_scroll``, each a head line (worst-status mark,
        chain, status, elapsed, blocks, written files), its pending lines
        while it waits, and one row of block cards joined by cables that
        carry each block's run status from the retained record (LLR-147.1);
        the SOURCE card holds its rebind input and Bind (LLR-147.2); a
        waiting lane shows Confirm after its last card and the REQUIRED line
        names the attention lane (LLR-147.3); the run log (at most
        ``FX_LOG_MAX_ROWS`` lines) and the legend close the panel. The panel
        owns the attention state (I-7 (b)–(c)); ``c`` confirms the attention
        lane after ``CONFIRM_DWELL_S`` (LLR-147.13); one run at a time
        (D14). Presentational — every control posts a message the app
        routes; every file-derived string renders through ``safe_text``.

    Data Flow:
        - Import… → ``ImportRequested`` → app → :meth:`add_lane` /
          :meth:`render_import_refusal`.
        - Run → ``RunRequested(lane_specs, mode, set_name)`` → app →
          ``run_chain_set`` → :meth:`render_run` / :meth:`render_run_error`.
        - Confirm / ``c`` → :meth:`_post_confirm` → ``ExternalStepConfirmed``
          → app (every :meth:`confirmed_blocks` confirmation) →
          :meth:`apply_confirmed_run` / :meth:`render_confirm_error`.
        - Save Set → ``SaveRequested`` → app → :meth:`mark_saved`.
        - Load Set → ``LoadSetRequested`` → app → :meth:`begin_set_restore`
          / :meth:`restore_lane` / :meth:`restore_set`.

    Dependencies:
        Uses:
            - ``flow_model`` (read-only dataclasses, the declared R8 edge)
            - ``safe_text``, ``clip_head`` / ``clip_tail``, ``lane_layout``
        Used by:
            - ``S19TuiApp._compose_screen_flow_execution`` + the
              ``on_flow_execution_panel_*`` handlers, ``action_confirm_attention``
    """

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
        """The operator confirmed a waiting external step.

        Posted by the one confirm path (:meth:`_post_confirm`: the lane's
        Confirm or ``c``); the app re-runs THAT lane with every confirmed
        block's confirmation (:meth:`confirmed_blocks`) and hands the outcome
        back via :meth:`apply_confirmed_run`.

        Args:
            lane_index (int): The waiting lane's position.
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
        #: Unsaved-edits flag — the ribbon's ``· saved`` / ``· unsaved``.
        self._dirty = False
        self._last_record = None
        #: The run log's lines (each a ``Text``); a confirm re-run appends.
        self._log: List[Text] = []
        #: The session artifact dir (the ribbon's right end).
        self._session_dir: str = ""
        #: D21 / D24 layout state: the last layout key and its result.
        self._layout_key: Optional[tuple] = None
        self._layout = LaneLayout(CARD_MIN_W)
        self._viewport_w = 0
        self._lanes_version = 0
        #: The attention state (I-7 (b)); ``_rearm_attention`` is its only
        #: writer of the three attention fields.
        self._attention: Optional[int] = None
        self._attention_block: Optional[int] = None
        self._attention_since: Optional[float] = None
        #: The set run's earliest ``started_at`` (the log stamps' origin).
        self._run_start: float = 0.0
        #: D14: a run (set run or confirm re-run) is in flight.
        self._in_flight = False

    def set_session_dir(self, path: str) -> None:
        """Publish the session artifact dir; it rides the ribbon."""
        self._session_dir = path
        for lane in self._lanes:
            lane.session_dir = path
        if self.is_mounted:
            self._refresh_name_strip()

    # -- composition ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="fx_ribbon"):
            yield Static(
                self._name_strip_text(),
                id="fx_name_strip",
                markup=False,
                classes=self._name_strip_class(),
            )
            with Horizontal(id="fx_run_row"):
                yield FlowChip("Import…", id="fx_import")
                yield ModeToggle(id="fx_mode")
                yield FlowChip("Run", id="fx_run", classes="fill-accent")
        yield Label(
            "Flow Execution: Import… adds a chain lane from a saved flow; bind "
            "each lane's inputs; Run (sequential default, parallel per chain); "
            "Save Set persists chains + inputs + outputs.",
            id="fx_help",
            markup=False,
        )
        with Horizontal(id="fx_set_row"):
            yield Label("set name", classes="fx-field-label")
            yield OsClipboardInput(placeholder="set name", id="fx_set_name", compact=True)
            yield FlowChip("Save Set", id="fx_save")
            yield Label("saved sets", classes="fx-field-label")
            yield Select(
                [(Text("(no saved sets)"), "")],
                value="",
                allow_blank=False,
                id="fx_set_select",
                compact=True,
            )
            yield FlowChip("Load Set", id="fx_load")
        yield Static("", id="fx_notice", markup=False)
        with ScrollableContainer(id="fx_lanes_scroll"):
            with Vertical(id="fx_lanes"):
                yield Static(self._lanes_empty_text(), id="fx_empty", classes="nowrap-pipeline")
        yield Static("", id="fx_required", markup=False, classes="nowrap-log")
        yield Static(Text(FX_LOG_EMPTY, style=_S_DIM), id="fx_log", classes="nowrap-log")
        yield Static(fx_legend_text(), id="fx_legend", classes="glyph-legend nowrap-legend")

    def on_mount(self) -> None:
        self.query_one("#fx_set_name", Input).value = self._set_name
        self.query_one("#fx_help").display = False
        self.query_one("#fx_required").display = False
        self._show_notice("")
        self._refresh_frame_title()
        self.call_after_refresh(self._apply_layout)

    @staticmethod
    def _lanes_empty_text() -> Text:
        text = Text("No chains yet", style="bold " + VALUE)
        text.append(" — ", style=_S_DIM)
        text.append("Import…", style="bold " + HILITE)
        text.append(" adds a lane from a saved flow.", style=_S_DIM)
        return text

    def _refresh_frame_title(self) -> None:
        count = len(self._lanes)
        self.query_one("#fx_lanes_scroll").border_title = (
            f"lanes · {count} chain{'' if count == 1 else 's'}"
        )

    # -- the ribbon (the C-10 dirty-guard idiom, a word since Inc-6) ---------

    def _name_strip_text(self) -> Text:
        """``Set: <name>  · saved|· unsaved`` and, right-aligned, the session
        path's tail (LLR-147.4; the Builder's ``ribbon_text``)."""
        width = self._layout_key[1] if self._layout_key else 60
        return ribbon_text(self._set_name, self._dirty, (), self._session_dir, width, prefix="Set: ")

    def _name_strip_class(self) -> str:
        return "flow-name-strip nowrap-ribbon " + ("sev-warning" if self._dirty else "sev-neutral")

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
        self._show_notice(f"saved flowsets/{stem}.json")

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    @property
    def mode(self) -> str:
        """The run mode the toggle shows (``sequential`` / ``parallel``)."""
        return self.query_one("#fx_mode", ModeToggle).mode

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
        self._mount_lane(lane)
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
        time — the lane paints one ``▪ '<ref>' missing - re-bind`` line each
        instead of running silently stale.
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
        self._mount_lane(lane)

    def _mount_lane(self, lane: _FxLane) -> None:
        self._lanes.append(lane)
        self._lanes_version += 1
        self.query_one("#fx_empty", Static).display = False
        self.query_one("#fx_lanes", Vertical).mount(self._lane_widgets(len(self._lanes) - 1))
        self._refresh_frame_title()
        self._rearm_attention()
        self.call_after_refresh(self._apply_layout)

    def _lane_height(self, index: int) -> int:
        """Card height of lane ``index`` (D24): border 2 + its largest card.
        Every card holds three content rows: the SOURCE input, its Bind row
        and its status line, or two io lines and the status line."""
        return 2 + (3 if self._lanes[index].flow.blocks else 1)

    def _lane_widgets(self, index: int) -> Vertical:
        """Build lane ``index`` fully painted at the current layout."""
        lane = self._lanes[index]
        card_w, spare = self._layout
        height = self._lane_height(index)
        head = Static(
            self._lane_head_text(index),
            id=f"fx_lane_{index}_head",
            classes="fx-lane-head nowrap-pipeline",
        )
        pending_lines = self._pending_lines(index)
        pending = Static(
            self._pending_text(pending_lines),
            id=f"fx_lane_{index}_pending",
            classes="fx-lane-pending nowrap-pipeline",
        )
        pending.display = bool(pending_lines)
        row: List[Widget] = []
        blocks = lane.flow.blocks
        for j, block in enumerate(blocks):
            row.append(self._card_widget(index, j, card_w, height))
            if j < len(blocks) - 1:
                cable_w = CABLE_W + (1 if j < spare else 0)
                cable = Static(
                    self._cable_text(index, j, cable_w),
                    id=f"fx_cable_{index}_{j}",
                    classes="fx-cable nowrap-pipeline",
                )
                cable.styles.width = cable_w
                cable.styles.height = height
                row.append(cable)
        confirm = FlowChip("Confirm", id=f"fx_confirm_{index}", variant="primary", classes="fx-confirm")
        confirm.display = lane.paused_block is not None
        row.append(confirm)
        lane_row = Horizontal(*row, id=f"fx_lane_{index}_row", classes="fx-lane-row")
        lane_row.styles.height = height
        return Vertical(head, pending, lane_row, id=f"fx_lane_{index}", classes="fx-lane")

    def _card_widget(self, index: int, j: int, card_w: int, height: int) -> Vertical:
        lane = self._lanes[index]
        block = lane.flow.blocks[j]
        inner = card_w - 4
        children: List[Widget] = []
        if isinstance(block, SourceBlock):
            children.append(
                Vertical(
                    OsClipboardInput(
                        placeholder="image file",
                        id=f"fx_in_{index}_{j}",
                        value=self._effective_ref(lane, j),
                        compact=True,
                    ),
                    Horizontal(
                        FlowChip("Bind", id=f"fx_bind_{index}_{j}"),
                        Static(Text(f"fmt {block.file_type}", style=_S_DIM), classes="fx-card-note"),
                        classes="fx-bind-row",
                    ),
                    id=f"fx_lane_{index}_edit_{j}",
                    classes="fx-card-edit",
                )
            )
        else:
            children.append(Static(self._card_body_text(block, inner), classes="fx-card-body nowrap-pipeline"))
        children.append(Static(self._card_status_text(index, j, inner), classes="fx-card-status nowrap-pipeline"))
        card = Vertical(*children, id=f"fx_card_{index}_{j}", classes="fx-card")
        card.border_title = _fx_kind_title(block)
        card.styles.width = card_w
        card.styles.height = height
        card.set_class(self._is_waiting_block(index, j), "fx-waiting")
        return card

    def _effective_ref(self, lane: _FxLane, src_index: int) -> str:
        if src_index in lane.bindings:
            return lane.bindings[src_index]
        block = lane.flow.blocks[src_index]
        return block.image_ref if isinstance(block, SourceBlock) else ""

    # -- lane painters (pure over the lane state + the layout) ---------------

    def _is_waiting_block(self, index: int, j: int) -> bool:
        lane = self._lanes[index]
        return lane.paused_block == j and lane.last_status == FLOW_STATUS_PAUSED

    def _block_status(self, index: int, j: int) -> Optional[str]:
        return self._lanes[index].block_status.get(j)

    @staticmethod
    def _card_body_text(block: FlowBlock, inner: int) -> Text:
        text = Text()
        for row, (line, style) in enumerate(_fx_card_io(block, inner)):
            if row:
                text.append("\n")
            text.append(line, style=style)
        return text

    def _card_status_text(self, index: int, j: int, inner: int) -> Text:
        mark, word, style = _FX_BLOCK_STYLE.get(self._block_status(index, j), _FX_BLOCK_STYLE[None])
        return Text(clip_head(f"{mark} {word}", max(1, inner)), style=style)

    def _cable_text(self, index: int, j: int, cable_w: int) -> Text:
        mark = cable_glyph(self._block_status(index, j), self._block_status(index, j + 1))
        text = Text("\n" * _FX_OUT_ROW)
        if mark == "□":
            text.append("─" * (cable_w - 3) + mark + "─▶", style="bold " + _S_WAIT)
            return text
        wire = _S_DIM if mark == "░" else _S_CABLE
        _glyph, _word, colour = next(
            (look for look in _FX_BLOCK_STYLE.values() if look[0] == mark), _FX_BLOCK_STYLE[None]
        )
        text.append("─" * (cable_w - 3), style=wire)
        text.append(mark, style="bold " + colour)
        text.append("─▶", style=wire)
        return text

    def _lane_head_text(self, index: int) -> Text:
        """``<mark> <chain> · <status> · <elapsed> · N blocks · wrote <names>``
        (LLR-147.12: the worst-status mark reads at scroll 0)."""
        lane = self._lanes[index]
        mark, word, colour = _FX_STATUS_STYLE.get(lane.last_status, _FX_STATUS_STYLE[""])
        text = Text(mark, style="bold " + colour)
        text.append(" ")
        text.append(safe_text(lane.name).plain, style="bold " + VALUE)
        text.append(" · ", style=_S_DIM)
        waiting = lane.last_status == FLOW_STATUS_PAUSED and lane.paused_block is not None
        text.append(word + (f" at #{lane.paused_block + 1}" if waiting else ""), style=colour)
        if lane.last_status and not waiting:
            text.append(f" · {_fx_stamp(lane.last_finished - self._run_start)}", style=_S_DIM)
        count = len(lane.flow.blocks)
        text.append(f" · {count} block{'' if count == 1 else 's'}", style=_S_DIM)
        if lane.template != lane.name:
            text.append(f" · tpl {safe_text(lane.template).plain}", style=_S_DIM)
        if lane.last_outputs:
            text.append(" · wrote ", style=_S_DIM)
            text.append(safe_text(", ".join(path.name for path in lane.last_outputs)).plain, style=_S_OUT)
        width = self._viewport_w
        if width > 8 and text.cell_len > width:
            text.truncate(width, overflow="ellipsis")
        return text

    def _pending_lines(self, index: int) -> List[str]:
        """The lane's red lines: one per missing reload input, then the two
        pending lines while it waits (LLR-147.3; the leading glyph is
        ``FX_PENDING_GLYPH``, outside the cable vocabulary)."""
        lane = self._lanes[index]
        width = self._viewport_w or 104
        lines = []
        for missing in lane.missing:
            ref = safe_text(missing).plain
            room = max(8, width - len(f"{FX_PENDING_GLYPH} '' missing - re-bind"))
            lines.append(f"{FX_PENDING_GLYPH} '{clip_tail(ref, room)}' missing - re-bind")
        if lane.paused_block is not None and self._is_waiting_block(index, lane.paused_block):
            block = lane.flow.blocks[lane.paused_block]
            ref = safe_text(getattr(block, "log_ref", "?")).plain
            room = max(8, width - len(f"{FX_PENDING_GLYPH} log '' pending"))
            lines.append(f"{FX_PENDING_GLYPH} log '{clip_tail(ref, room)}' pending")
            lines.append(f"{FX_PENDING_GLYPH} output file not confirmed — waiting for a human")
        return [clip_head(line, width) for line in lines]

    @staticmethod
    def _pending_text(lines: Sequence[str]) -> Text:
        text = Text()
        for row, line in enumerate(lines):
            if row:
                text.append("\n")
            text.append(line, style=RED)
        return text

    def _repaint_lane(self, index: int) -> bool:
        """Repaint lane ``index``'s head, pending lines, cards, cables and
        Confirm from its state at the current layout (D21 item 4).

        Returns:
            bool: ``False`` while the lane's widgets are not composed yet (a
            lane mounted this tick), so the layout pass runs again.
        """
        try:
            lane_widget = self.query_one(f"#fx_lane_{index}", Vertical)
            lane_widget.query_one(f"#fx_confirm_{index}")
        except NoMatches:
            return False
        if len(lane_widget.query(".fx-card-status")) != len(self._lanes[index].flow.blocks):
            return False
        lane = self._lanes[index]
        card_w, spare = self._layout
        height = self._lane_height(index)
        inner = card_w - 4
        lane_widget.query_one(f"#fx_lane_{index}_head", Static).update(self._lane_head_text(index))
        pending_lines = self._pending_lines(index)
        pending = lane_widget.query_one(f"#fx_lane_{index}_pending", Static)
        pending.update(self._pending_text(pending_lines))
        pending.display = bool(pending_lines)
        lane_widget.query_one(f"#fx_lane_{index}_row").styles.height = height
        blocks = lane.flow.blocks
        for j, block in enumerate(blocks):
            card = lane_widget.query_one(f"#fx_card_{index}_{j}")
            card.styles.width = card_w
            card.styles.height = height
            card.set_class(self._is_waiting_block(index, j), "fx-waiting")
            for body in card.query(".fx-card-body"):
                body.update(self._card_body_text(block, inner))
            for status in card.query(".fx-card-status"):
                status.update(self._card_status_text(index, j, inner))
            if j < len(blocks) - 1:
                cable_w = CABLE_W + (1 if j < spare else 0)
                cable = lane_widget.query_one(f"#fx_cable_{index}_{j}", Static)
                cable.styles.width = cable_w
                cable.styles.height = height
                cable.update(self._cable_text(index, j, cable_w))
        lane_widget.query_one(f"#fx_confirm_{index}").display = lane.paused_block is not None
        return True

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

    def confirmed_blocks(self, lane_index: int) -> Tuple[int, ...]:
        """The EXT-STEP blocks lane ``lane_index`` has confirmed in its current
        wait sequence, the one just posted included (I-7 (a)); the app sends
        a confirmation for each (LED-…97.29)."""
        return tuple(self._lanes[lane_index].confirmed)

    # -- the layout pass (D21, D24) ------------------------------------------

    def on_resize(self) -> None:
        self.call_after_refresh(self._apply_layout)

    def on_show(self) -> None:
        self.call_after_refresh(self._apply_layout)

    def _apply_layout(self) -> None:
        """Derive the card width once per set from the lanes viewport and
        repaint every lane, the ribbon and the head / pending clips; an equal
        reading repaints nothing."""
        try:
            scroll = self.query_one("#fx_lanes_scroll")
            ribbon = self.query_one("#fx_name_strip").content_region.width
        except NoMatches:
            return
        viewport = scroll.scrollable_content_region.width
        if viewport <= 0 or ribbon <= 0:
            return
        n_max = max((len(lane.flow.blocks) for lane in self._lanes), default=1)
        layout = lane_layout(viewport, n_max)
        heights = tuple(self._lane_height(i) for i in range(len(self._lanes)))
        key = (viewport, ribbon, layout, heights, self._lanes_version)
        if key == self._layout_key:
            return
        self._layout_key = key
        self._layout = layout
        self._viewport_w = viewport
        self._refresh_name_strip()
        composed = [self._repaint_lane(index) for index in range(len(self._lanes))]
        if not all(composed):
            # A lane mounted this tick is not composed yet: derive again
            # after the next refresh so its cards take this layout.
            self._layout_key = None
            self.call_after_refresh(self._apply_layout)

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
        """Paint a rejected template import — the current lanes are untouched.
        The line names the loader's code (``[FLOW-UNSAFE-REF] …``), as the
        Builder's refusal does (LLR-148.9)."""
        first = _coded(findings[0]) if findings else "unreadable template"
        self._show_notice(
            f"import refused: flows/{stem}.json — {first}"
        )

    # -- the run log ---------------------------------------------------------

    def _paint_log(self) -> None:
        """Paint the retained log, at most ``FX_LOG_MAX_ROWS`` lines: the
        newest ``FX_LOG_MAX_ROWS − 1`` under one ``… <k> earlier lines`` line
        when it holds more (LLR-147.8)."""
        lines = list(self._log)
        if not lines:
            painted = [Text(FX_LOG_EMPTY, style=_S_DIM)]
        elif len(lines) > FX_LOG_MAX_ROWS:
            kept = lines[-(FX_LOG_MAX_ROWS - 1):]
            earlier = len(lines) - len(kept)
            painted = [Text(f"… {earlier} earlier lines — the full log is in the run report", style=_S_DIM)] + kept
        else:
            painted = lines
        self.query_one("#fx_log", Static).update(_join_lines(painted))

    def _log_lines(self, lane: _FxLane, outcome, rerun_block: Optional[int] = None) -> List[Text]:
        """One start line and one terminal line for a lane's outcome — the one
        composer of a set run and a confirm re-run (I-7 (e)). The stamps are
        the time since the set run began; the start line carries no mark
        (Q-B97-6a: ``▶`` is the cable arrowhead on this screen)."""
        total = max(1, len(lane.flow.blocks))
        chain = safe_text(outcome.chain)
        start = Text(f"{_fx_stamp(outcome.started_at - self._run_start)} ")
        start.append_text(chain)
        if rerun_block is None:
            start.append(" · started", style=_S_DIM)
        else:
            start.append(
                f" · re-run after confirming the external step (block {rerun_block + 1}/{total})",
                style=_S_DIM,
            )
        mark, _word, colour = _FX_STATUS_STYLE.get(outcome.status, _FX_STATUS_STYLE[""])
        end = Text(f"{_fx_stamp(outcome.finished_at - self._run_start)} ")
        end.append(f"{mark} ", style="bold " + colour)
        end.append_text(safe_text(outcome.chain))
        if outcome.status == FLOW_STATUS_ERROR:
            index, kind, noun, ref = self._failure_detail(lane, outcome)
            if noun:
                end.append(
                    f" · block {index + 1}/{total} {kind.upper()} — {noun} '{safe_text(ref).plain}' missing",
                    style=_S_DIM,
                )
            else:
                end.append(f" · block {index + 1}/{total} {kind.upper()} — {ref}", style=_S_DIM)
            end.append(" · chain halted", style=_S_DIM)
        elif outcome.status == FLOW_STATUS_PAUSED:
            index = lane.paused_block if lane.paused_block is not None else 0
            block = lane.flow.blocks[index]
            end.append(
                f" · WAITING FOR A HUMAN — external step (block {index + 1}/{total}) · log "
                f"'{safe_text(getattr(block, 'log_ref', '?')).plain}' pending",
                style=_S_DIM,
            )
        else:
            end.append(" · done" if outcome.status == FLOW_STATUS_OK else " · done with notices", style=_S_DIM)
            note = self._patch_not_applied_note(outcome)
            if note is not None:
                # UX-C1: a lane whose PATCH ended with entries not applied
                # names the block and what was not applied on its terminal
                # line — count, first address and disposition (the umbrella
                # "not applied" wording, never the block-level "skipped" —
                # UX-C3b). Clipped at FX_ERROR_LINE_MAX; the full list stays
                # in the chain-set and flow reports.
                end.append(clip_head(f" · {note}", FX_ERROR_LINE_MAX), style=_S_DIM)
            if outcome.written_paths:
                names = ", ".join(path.name for path in outcome.written_paths)
                end.append(f" · wrote {safe_text(names).plain}", style=_S_DIM)
        return [start, end]

    @staticmethod
    def _patch_not_applied_note(outcome) -> Optional[str]:
        """The UX-C1 terminal-line rider: ``PATCH: <k> of <n> entries not
        applied (0xADDR DISP)`` for the first PATCH arm that ended ``notices``
        with entries not applied, else ``None``.

        The address and disposition are int/enum-derived (they paint from
        ``outcome.change_records``, never from file text), so the note is
        markup-safe by construction; a refusal-driven failure paints its
        coded cause through ``_failure_detail`` on the ``error`` branch
        instead.
        """
        for block_result in outcome.block_results:
            if (
                block_result.kind != "patch"
                or block_result.status != BLOCK_STATUS_NOTICES
            ):
                continue
            records = [
                record
                for record in outcome.change_records
                if record.block_index == block_result.index
            ]
            not_applied = [
                record
                for record in records
                if record.disposition != DISPOSITION_APPLIED
            ]
            if not_applied:
                first = not_applied[0]
                return (
                    f"PATCH: {len(not_applied)} of {len(records)} entries "
                    f"not applied (0x{first.address_start:08X} "
                    f"{first.disposition})"
                )
        return None

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
                # A refused ref names its code (``[MANIFEST-PATH-ESCAPE] …``,
                # LLR-148.9); a missing file names the ref the lane read — a
                # bound input, not the template's own ref.
                coded = next((d for d in block_result.diagnostics if d.startswith("[")), None)
                if coded is not None:
                    return index, block.kind, "", safe_text(coded).plain
                if isinstance(block, SourceBlock):
                    ref = lane.bindings.get(index, ref)
                return index, block.kind, noun, ref
            diagnostic = (
                block_result.diagnostics[-1]
                if block_result.diagnostics
                else block_result.summary
            )
            return index, block.kind, "", safe_text(diagnostic).plain
        return 0, "?", "", "unknown failure"

    # -- run -----------------------------------------------------------------

    @staticmethod
    def _take_outcome(lane: _FxLane, outcome) -> None:
        """Read one outcome into the lane: status, elapsed, outputs, the
        first error and the first waiting block (``fail_block`` = where the
        chain stopped), and every block's status for the cables."""
        lane.last_status = outcome.status
        lane.last_elapsed = outcome.finished_at - outcome.started_at
        lane.last_finished = outcome.finished_at
        lane.last_outputs = list(outcome.written_paths)
        lane.block_status = {result.index: result.status for result in outcome.block_results}
        lane.fail_block = next(
            (result.index for result in outcome.block_results if result.status == BLOCK_STATUS_ERROR),
            None,
        )
        lane.paused_block = next(
            (result.index for result in outcome.block_results if result.status == BLOCK_STATUS_WAITING),
            None,
        )
        if lane.paused_block is not None:
            lane.fail_block = lane.paused_block

    def render_run(self, record) -> None:
        """Paint the lanes + the run log from the set run record.

        A new run starts every wait over: each lane's ``confirmed`` is
        cleared and the attention is re-armed (its dwell restarts after the
        repaint, I-7 (c)); Run and every Confirm are enabled again after the
        paint (D14).

        Args:
            record (ChainSetRunRecord): The completed run — one outcome per
                lane in lane order, the captured mode, and the report path.
        """
        self._last_record = record
        self._run_start = min((outcome.started_at for outcome in record.outcomes), default=0.0)
        lines: List[Text] = []
        for index, lane in enumerate(self._lanes):
            if index >= len(record.outcomes):
                break
            outcome = record.outcomes[index]
            self._take_outcome(lane, outcome)
            lane.confirmed = ()
            lines.extend(self._log_lines(lane, outcome))
            self._repaint_lane(index)
        for diagnostic in record.diagnostics:
            lines.append(safe_text(diagnostic))
        self._log = lines
        self._paint_log()
        if record.outcomes:
            self._mark_dirty()
        self._rearm_attention(restart=True)
        self.call_after_refresh(self._enable_runs)

    def apply_confirmed_run(self, lane_index: int, record) -> Optional[str]:
        """Paint ONE lane's re-run after an external-step confirmation.

        Derives the lane's state exactly as :meth:`render_run` does (I-7
        (d)): a lane that waits again at its next external step shows that
        wait and its Confirm; when the wait sequence ends its ``confirmed``
        is cleared. The log gains the re-run's start and terminal lines; the
        attention is re-armed and Run / Confirm are enabled after the paint.

        Returns:
            Optional[str]: When the re-run failed, one status line —
            ``<chain> failed at block i/n — <reason>; Run re-runs the set.``
            (gate fold ux M2) — else ``None``.
        """
        lane = self._lanes[lane_index]
        confirmed_block = lane.paused_block
        outcome = record.outcomes[0]
        self._take_outcome(lane, outcome)
        if lane.paused_block is None:
            lane.confirmed = ()
        else:
            lane.confirmed = tuple(b for b in lane.confirmed if b != lane.paused_block)
        self._log.extend(self._log_lines(lane, outcome, rerun_block=confirmed_block))
        self._paint_log()
        self._repaint_lane(lane_index)
        self._rearm_attention()
        self.call_after_refresh(self._enable_runs)
        if outcome.status != FLOW_STATUS_ERROR:
            return None
        index, _kind, noun, ref = self._failure_detail(lane, outcome)
        reason = f"{noun} '{safe_text(ref).plain}' missing" if noun else ref
        return (
            f"{safe_text(lane.name).plain} failed at block {index + 1}/{len(lane.flow.blocks)} — "
            f"{reason}; Run re-runs the set."
        )

    def render_run_error(self, message: str) -> None:
        """Replace the log with one ``✗`` line (a refused or raised set run,
        LLR-148.9) and enable Run again after the paint (D14)."""
        line = Text("✗ ", style=_S_ERR)
        line.append_text(safe_text(message))
        self._log = [line]
        self._paint_log()
        self.call_after_refresh(self._enable_runs)

    def render_confirm_error(self, lane_index: int, line: str) -> None:
        """A confirm re-run that raised or was refused (D14 (4)): append
        ``✗ <chain> · confirm re-run failed - <line>`` to the log, leave the
        lane waiting at the same entry, unconfirmed (it can be confirmed
        again), re-arm the attention and enable Run / Confirm after the
        paint."""
        if 0 <= lane_index < len(self._lanes):
            lane = self._lanes[lane_index]
            chain = safe_text(lane.name)
            if lane.paused_block is not None:
                lane.confirmed = tuple(b for b in lane.confirmed if b != lane.paused_block)
            self._repaint_lane(lane_index)
        else:
            chain = Text(f"lane {lane_index + 1}")
        entry = Text("✗ ", style=_S_ERR)
        entry.append_text(chain)
        entry.append(" · confirm re-run failed - ", style=_S_DIM)
        entry.append_text(safe_text(line))
        self._log.append(entry)
        self._paint_log()
        self._rearm_attention()
        self.call_after_refresh(self._enable_runs)

    @property
    def last_run_record(self):
        """The retained run record (the AT reads the captured mode from it)."""
        return self._last_record

    def run_log_plain(self) -> str:
        """The painted run-log text (the C-32 painted oracle seam)."""
        return self.query_one("#fx_log", Static).render().plain

    def lane_paint_plain(self, lane_index: int) -> str:
        """One lane's painted text: its head, its pending lines while shown,
        and its card rows — each card's border with its kind title, its io
        lines (the SOURCE card: the input's value and ``Bind``) and its status
        line, the cables between, and ``Confirm`` while displayed (the C-32
        seam, I-7)."""
        lane = self._lanes[lane_index]
        card_w, spare = self._layout
        inner = card_w - 4
        height = self._lane_height(lane_index)
        lines = [self._lane_head_text(lane_index).plain]
        lines.extend(self._pending_lines(lane_index))
        columns: List[List[str]] = []
        blocks = lane.flow.blocks
        for j, block in enumerate(blocks):
            title = _fx_kind_title(block).plain
            top = "╭" + clip_head(f"─ {title} ", card_w - 2).ljust(card_w - 2, "─") + "╮"
            if isinstance(block, SourceBlock):
                body = [
                    clip_tail(safe_text(self._effective_ref(lane, j)).plain, inner),
                    f"Bind fmt {block.file_type}",
                ]
            else:
                body = [text for text, _style in _fx_card_io(block, inner)]
            body.append(self._card_status_text(lane_index, j, inner).plain)
            rows = [top] + ["│ " + clip_head(text, inner).ljust(inner) + " │" for text in body]
            rows += ["│" + " " * (card_w - 2) + "│"] * (height - 2 - len(body))
            rows.append("╰" + "─" * (card_w - 2) + "╯")
            columns.append(rows)
            if j < len(blocks) - 1:
                cable_w = CABLE_W + (1 if j < spare else 0)
                cable = self._cable_text(lane_index, j, cable_w).plain.split("\n")
                columns.append([(cable[y] if y < len(cable) else "").ljust(cable_w) for y in range(height)])
        if lane.paused_block is not None:
            columns.append([" Confirm" if y == _FX_OUT_ROW else "" for y in range(height)])
        for y in range(height):
            lines.append("".join(column[y] for column in columns).rstrip())
        return "\n".join(lines)

    # -- the attention lane (I-7 (b)–(c), PC-21) -----------------------------

    def _rearm_attention(self, restart: bool = False) -> None:
        """Recompute the attention lane — the first lane, in lane order,
        waiting at an entry it has not confirmed — and, when it moved, move
        the ``fx-attention`` class to its Confirm, update the REQUIRED line,
        bring its waiting card and Confirm into the lanes viewport and stamp
        the dwell base after the paint. With no lane waiting, the lanes
        return to horizontal scroll 0 so every head reads from its start
        (gate fold ux M1), as far as a focused widget inside the lanes
        allows. ``restart`` (a new set run, :meth:`render_run`) treats the
        attention as new even when the same lane waits at the same block, so
        its dwell restarts after the repaint. The only writer of
        ``_attention``, ``_attention_block`` and ``_attention_since``, directly
        or through its scheduled :meth:`_stamp_attention` (gate fold,
        code-reviewer F1, F7)."""
        if restart:
            self._attention = None
            self._attention_block = None
        target = next(
            (
                (index, lane.paused_block)
                for index, lane in enumerate(self._lanes)
                if lane.paused_block is not None and lane.paused_block not in lane.confirmed
            ),
            None,
        )
        current = None if self._attention is None else (self._attention, self._attention_block)
        if target == current and not restart:
            return
        for confirm in self.query(".fx-confirm"):
            confirm.remove_class("fx-attention")
        self._attention_since = None
        required = self.query_one("#fx_required", Static)
        if target is None:
            self._attention = None
            self._attention_block = None
            required.update("")
            required.display = False
            self.call_after_refresh(self._scroll_lanes_home)
            return
        lane_index, block = target
        self._attention, self._attention_block = lane_index, block
        for confirm in self.query(f"#fx_confirm_{lane_index}"):
            confirm.add_class("fx-attention")
        line = Text("log + output file: REQUIRED for ", style="bold " + _S_WAIT)
        line.append(safe_text(self._lanes[lane_index].name).plain, style="bold " + _S_WAIT)
        line.append(" · press c to confirm", style="bold " + _S_WAIT)
        required.update(line)
        required.display = True
        self.call_after_refresh(self._bring_attention_into_view, lane_index, block)
        self.call_after_refresh(self._stamp_attention, lane_index, block)

    def _scroll_lanes_home(self) -> None:
        """No lane waits: scroll the lanes back to x 0, keeping a focused
        widget inside the lanes in view (LLR-147.3's retained-focus rule)."""
        if self._attention is not None:
            return
        try:
            scroll = self.query_one("#fx_lanes_scroll")
        except NoMatches:
            return
        dx = -int(scroll.scroll_x)
        focused = self.app.focused
        if focused is not None and scroll in focused.ancestors:
            view = scroll.scrollable_content_region
            dx = max(dx, focused.region.right - view.right)
        if dx:
            scroll.scroll_to(x=scroll.scroll_x + dx, animate=False, immediate=True)

    def _stamp_attention(self, lane_index: int, block: int) -> None:
        """The dwell base: taken once the attention class has been painted,
        and only while ``(lane, block)`` is still the attention (H-X2)."""
        if (self._attention, self._attention_block) == (lane_index, block) and self._attention_since is None:
            self._attention_since = _fx_clock()

    @staticmethod
    def _scroll_delta(low: int, high: int, view_low: int, view_high: int) -> int:
        """How far to scroll so ``[low, high)`` lies in ``[view_low,
        view_high)``, never pushing ``low`` out to bring ``high`` in."""
        if high > view_high:
            return min(high - view_high, low - view_low)
        if low < view_low:
            return low - view_low
        return 0

    def _bring_attention_into_view(self, lane_index: int, block: int) -> None:
        """Scroll ``#fx_lanes_scroll`` on both axes so the attention lane's
        waiting card and its Confirm lie in the viewport; a focused widget
        inside the lanes stays in view (LLR-147.3). The focus never moves."""
        if (self._attention, self._attention_block) != (lane_index, block):
            return
        try:
            scroll = self.query_one("#fx_lanes_scroll")
            card = self.query_one(f"#fx_card_{lane_index}_{block}")
            confirm = self.query_one(f"#fx_confirm_{lane_index}")
        except NoMatches:
            return
        view = scroll.scrollable_content_region
        target = card.region.union(confirm.region) if confirm.display else card.region
        dx = self._scroll_delta(target.x, target.right, view.x, view.right)
        dy = self._scroll_delta(target.y, target.bottom, view.y, view.bottom)
        focused = self.app.focused
        if focused is not None and scroll in focused.ancestors:
            held = focused.region
            dx = max(held.right - view.right, min(dx, held.x - view.x))
            dy = max(held.bottom - view.bottom, min(dy, held.y - view.y))
        if dx or dy:
            scroll.scroll_to(scroll.scroll_x + dx, scroll.scroll_y + dy, animate=False, immediate=True)

    def confirm_attention(self) -> str:
        """The ``c`` key (LLR-147.13): confirm the attention lane's current
        waiting entry once it has held the attention for ``CONFIRM_DWELL_S``.

        Returns:
            str: One line for the status line — I-9's three (the confirm line
            superseded at the gate fold, ux M2: it says what happens next,
            not an outcome nobody knows yet) plus the in-flight line
            (code-reviewer F5).
        """
        if self._attention is None:
            return "c: no lane is waiting for confirmation."
        if self._in_flight:
            return "c: a run is in progress — wait for it to finish."
        lane_index = self._attention
        lane = self._lanes[lane_index]
        chain = safe_text(lane.name).plain
        block = lane.paused_block
        since = self._attention_since
        if since is None or _fx_clock() - since < CONFIRM_DWELL_S or not self._post_confirm(lane_index):
            return f"c ignored — {chain} started waiting a moment ago. Press c again to confirm."
        return f"Confirmed {chain} — re-running from block {block + 1}/{len(lane.flow.blocks)}."

    def _post_confirm(self, lane_index: int) -> bool:
        """The one confirm path (Confirm button and ``c``): once per waiting
        entry and never while a run is in flight; records the entry in the
        lane's ``confirmed``, disables Run and every Confirm (D14 (1)), moves
        the attention on and posts ``ExternalStepConfirmed``."""
        if not 0 <= lane_index < len(self._lanes) or self._in_flight:
            return False
        lane = self._lanes[lane_index]
        block = lane.paused_block
        if block is None or block in lane.confirmed:
            return False
        lane.confirmed = lane.confirmed + (block,)
        self._disable_runs()
        self._rearm_attention()
        self.post_message(self.ExternalStepConfirmed(lane_index, block))
        return True

    # -- one run at a time (D14) ---------------------------------------------

    def _run_controls(self) -> List[Widget]:
        controls: List[Widget] = [self.query_one("#fx_run")]
        controls.extend(confirm for confirm in self.query(".fx-confirm") if confirm.display)
        return controls

    def _disable_runs(self) -> None:
        """A run starts: Run and every displayed Confirm are disabled, so a
        press or key queued during the synchronous run reaches a disabled
        button and does nothing (P-44).

        The flag is set without Textual's ``disabled`` watcher, which would
        blur a focused button and hand the focus — and the queued key — to
        its neighbour (Import… or the mode switch); the focus stays where it
        was (LLR-147.3) and the disabled style is applied by
        ``update_node_styles``.
        """
        self._in_flight = True
        for control in self._run_controls():
            control.set_reactive(Widget.disabled, True)
            control.update_node_styles()

    def _enable_runs(self) -> None:
        """The run ended or raised: enable Run and every Confirm again."""
        self._in_flight = False
        self.query_one("#fx_run").disabled = False
        for confirm in self.query(".fx-confirm"):
            confirm.disabled = False

    # -- save / load set -----------------------------------------------------

    def set_available_sets(self, stems: Sequence[str]) -> None:
        """Repopulate the set picker (the app's on-entry prefill); each option
        renders literally (``safe_text``, LLR-147.6)."""
        options = [(safe_text(f"flowsets/{stem}.json"), stem) for stem in stems]
        if not options:
            options = [(Text("(no saved sets)"), "")]
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
        await self.query_one("#fx_lanes", Vertical).remove_children(".fx-lane")
        self._lanes.clear()
        self._lanes_version += 1
        self.query_one("#fx_empty", Static).display = True
        self._set_name = stem
        self._dirty = False
        self.query_one("#fx_set_name", Input).value = stem
        self._refresh_name_strip()
        self._refresh_frame_title()
        self._rearm_attention()
        self.call_after_refresh(self._apply_layout)

    def restore_set(self, stem: str, lanes: int, notices: Sequence[str]) -> None:
        """Finish a successful set reload: identity + notices for what moved."""
        self._set_name = stem
        self._dirty = False
        self.query_one("#fx_set_name", Input).value = stem
        self._refresh_name_strip()
        self._show_notice(" · ".join(notices))

    def render_set_refusal(self, stem: str, findings: List[ValidationIssue]) -> None:
        """Paint a rejected set load — the current lanes are untouched."""
        first = _coded(findings[0]) if findings else "unreadable set"
        self._show_notice(f"load refused: flowsets/{stem}.json — {first}")

    # -- events --------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "fx_import":
            self.post_message(self.ImportRequested())
        elif button_id == "fx_run":
            if not self._lanes:
                self._log = [Text(FX_NO_LANES_RUN, style=_S_DIM)]
                self._paint_log()
                return
            self._disable_runs()
            self.post_message(self.RunRequested(self.lane_specs(), self.mode, self._set_name))
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
            # A press of a visible Confirm is deliberate: no dwell, but the
            # same once-per-entry refusal and the D14 disable.
            self._post_confirm(int(button_id.removeprefix("fx_confirm_")))

    def _rebind(self, lane_index: int, src_index: int) -> None:
        """Bind one lane's input — exactly that lane's record is written.

        LLR-018.1: an edit touches exactly one binding record; rebinding to
        the same ref is a no-op (the writer does not even mark dirty). A
        successful bind clears the lane's confirmed entries (I-7 (c)): an
        input changed, so the human's earlier outputs no longer apply.
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
        lane.confirmed = ()
        self._repaint_lane(lane_index)
        self._show_notice("")
        self._mark_dirty()
        self._rearm_attention()


def _coded(finding: ValidationIssue) -> str:
    """A loader finding as one line led by its code: ``[CODE] message``."""
    code = getattr(finding, "code", "")
    return f"[{code}] {finding.message}" if code else finding.message


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
