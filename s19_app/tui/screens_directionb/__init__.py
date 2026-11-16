"""Direction B screen widgets for the s19tui Textual app.

This module is the home for the Direction B "Rail + Command" view-layer
widgets and screen scaffolds introduced by batch-02-direction-b-restyle.

Increment 2 establishes the module with:
  - ``EmptyStatePanel`` — the LLR-002.3 neutral no-file-loaded panel;
  - ``ScreenScaffold`` — the neutral container scaffold for the rail screen
    slots that do not yet have rich content (Memory Map, Issues Report,
    Patch Editor, A2B Diff, Bookmarks).

Increment 9 adds the first two real scaffold contents:
  - ``MemoryMapPanel`` — a read-only coverage visualization of the loaded
    image, rendered from the existing ``LoadedFile.ranges`` and
    ``range_validity`` fields (LLR-012.1); it computes no coverage itself;
  - ``FlowBuilderPanel`` — MOVED to ``s19_app/tui/flow_screens.py`` (batch-94
    Inc-002, the R8/B2 move): the fb_a reworked Flow Builder now lives in the
    flow family's own module; this file keeps the Direction-B shell.

Increment 10 (batch-02) added the last two scaffold contents:
  - ``PatchEditorPanel`` — *(superseded by batch-03 increment 9 — see below)*;
  - ``AbDiffPanel`` — a static three-column placeholder (range list, hex A,
    hex B) filled with constant, clearly-labelled sample hex rows and a
    visible "PLACEHOLDER / diff deferred" marker (LLR-012.3).

batch-07 increment E3a consolidates the Patch Editor to the single v2 JSON
change flow (LLR-003.1), superseding the batch-03 parameter editor and the
batch-04 memory/unified halves:
  - ``PatchEditorPanel`` — one change-flow section: an entries ``DataTable``
    (kind / address / value-or-bytes / status / linkage), entry inputs for
    both v2 kinds, a Load / Validate / Apply / Save / Run-checks control
    row, the persistent declaration-fault area (LLR-002.8), the post-apply
    save-back prompt (LLR-002.7), and the check-results display
    (LLR-004.5). The widget stays presentational — it emits
    ``PatchEditorPanel.ActionRequested`` / ``SaveBackDecision`` messages
    and renders rows the app hands back; the ``changes``-package work is
    done by ``services.change_service``.

No engine code is imported here — these are presentational widgets that
receive their data via method calls and emit messages back to ``app.py``. The
Memory Map and A2B Diff panels are unchanged.
"""
from __future__ import annotations

import bisect
import json
from dataclasses import dataclass
from datetime import datetime
from math import ceil
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
)
from rich.cells import cell_len, set_cell_size
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.content import Content
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical, VerticalScroll
from textual.message import Message
from textual.widget import Widget
from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    Input,
    Label,
    ListItem,
    ListView,
    Select,
    Static,
    TextArea,
)
from ..a2l import MAX_A2L_DECODE_BYTES
from ..a2l_parameter_picker import (
    A2LParameterPicker,
    IncludeTable,
    _clip_fmt_unit,
    clip_param,
    clip_tail,
)
from ..screens import BulkParameterAddScreen
from ..changes.io import DUMMY_CHANGESET_TEXT, is_check_spec_name
from ..color_policy import css_class_for_severity
from ..entropy_style import ENTROPY_BAND_LABELS, band_style
from ..insight_style import (
    CYAN,
    DGRAY,
    GREEN,
    LABEL,
    PURPLE,
    RED,
    VALUE,
    YELLOW,
    cap_gauge_style,
    human_bytes,
    label_value,
    microbar,
)
from ..json_highlight import JsonHighlightTextArea
from ..os_clipboard_input import _CLIPBOARD_READ_CAP_CHARS
from ..os_clipboard_input import OsClipboardInput
from ...range_index import address_in_sorted_ranges, build_sorted_range_index
from textual.screen import ModalScreen
from ..services.entropy_service import EntropyWindow
from ...validation import ValidationIssue, ValidationSeverity
from ...utils import safe_text
from .deps import (_json_clock)
from .shared import (
    EmptyStatePanel,
    ScreenScaffold,
    _RULER_LABEL_WIDTH,
    _RULER_TICK_PITCH,
    _ENTROPY_BAR_RAMP,
    _SPARKLINE_WIDTH,
    entropy_ramp_glyph,
    band_histogram,
    sparkline_glyphs,
    _sparkline_segments,
    cell_count_for_geometry,
    bytes_per_cell,
    status_to_css_class,
    _clip_to_cells,
    CARD_NO_SELECTION,
    CARD_NO_IMAGE,
    CARD_UNMAPPED_TOKEN,
    PATCH_TEAL,
    STRIP_ROW_CAP,
    STRIP_ROW_BYTES,
    _STRIP_LABEL_CELLS,
    before_after_card_text,
    LoadGuardScreen,
    JSON_TAB_LINE_CAP,
    cap_json_lines,
    PatchDocumentView,
    CheckLayout,
    check_layout,
    TabChip,
)
from .map_parts import (
    _BAND_GAP_FOLD,
    _REGION_MICROBAR_WIDTH,
    _BAND_SHORT_LABELS,
    _STATS_FULL_MIN_WIDTH,
    _REGION_ROW_MICROBAR_MIN_WIDTH,
    _MAP_PANEL_TO_ROWS_INSET,
    _MAP_PANEL_TO_ROWS_INSET_STACKED,
    _MAP_PANEL_WIDE_FALLBACK,
    _MAP_STACK_MIN_WIDTH,
    _INSPECTOR_BODY_FALLBACK_WIDTH,
    _INSPECTOR_SCROLLBAR_GUTTER,
    _PEEK_BYTES_PER_ROW,
    _PEEK_UNMAPPED_CELL,
    _INSPECTOR_FIELD_ROWS,
    _INSPECTOR_LABEL_WIDTH,
    _MAP_GAP_HATCH,
    _OPEN_IN_HEX_GLYPH,
    _PEEK_ROWS_FALLBACK,
    _merge_band_runs,
    _allocate_band_widths,
    _retained_tick_addresses,
    derive_image_span,
    cell_status,
    issues_in_window,
    covering_range,
    _tag_address,
    symbols_in_window,
    symbol_list_text,
    CoverageStats,
    coverage_stats,
    RegionRow,
    BandSegment,
    BandBar,
    MapRuler,
)
from .memory_map import (MemoryMapPanel)
from .loaded_artifacts import (LoadedArtifactsPanel)
from .patch_editor import (
    _Unset,
    _UNSET,
    CARD_NO_ENTRIES,
    BeforeAfterCard,
    PatchEditorPanel,
    PATCH_GLYPHS,
    json_stamp_text,
    PatchLayout,
    patch_layout,
)
from .check_editor import (CHECK_GLYPHS, _count, CheckEditorPanel)
from .ab_diff import (_DIFF_WIDE_MIN, _DIFF_MIN_W, _DIFF_MIN_H, AbDiffPanel)
