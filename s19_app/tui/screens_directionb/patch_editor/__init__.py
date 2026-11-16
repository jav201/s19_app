"""s19_app.tui.screens_directionb.patch_editor - PatchEditorPanel as a package of zone mixins (split from patch_editor.py at 2dbd7d5a).

Every module-level name of the old single module is still importable from here, as the same
object."""
from __future__ import annotations

from typing import List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union  # noqa: F401
from rich.cells import cell_len  # noqa: F401
from rich.text import Text  # noqa: F401
from textual import events  # noqa: F401
from textual.app import ComposeResult  # noqa: F401
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical, VerticalScroll  # noqa: F401
from textual.message import Message  # noqa: F401
from textual.widgets import (  # noqa: F401
    Button,
    ContentSwitcher,
    DataTable,
    Input,
    Label,
    Select,
    Static,
    TextArea,
)
from ...a2l import MAX_A2L_DECODE_BYTES  # noqa: F401
from ...a2l_parameter_picker import A2LParameterPicker, clip_tail  # noqa: F401
from ...screens import BulkParameterAddScreen  # noqa: F401
from ...changes.io import DUMMY_CHANGESET_TEXT  # noqa: F401
from ...insight_style import (  # noqa: F401
    CYAN,
    DGRAY,
    GREEN,
    LABEL,
    PURPLE,
    RED,
    VALUE,
    YELLOW,
    cap_gauge_style,
    label_value,
    microbar,
)
from ...json_highlight import JsonHighlightTextArea  # noqa: F401
from ...os_clipboard_input import _CLIPBOARD_READ_CAP_CHARS  # noqa: F401
from ...os_clipboard_input import OsClipboardInput  # noqa: F401
from ....utils import safe_text  # noqa: F401
from .. import deps  # noqa: F401
from ..shared import (  # noqa: F401
    _clip_to_cells,
    CARD_UNMAPPED_TOKEN,
    STRIP_ROW_BYTES,
    before_after_card_text,
    cap_json_lines,
    CheckLayout,
    check_layout,
    TabChip,
)
from .shared import (  # noqa: F401
    _Unset,
    _UNSET,
    CARD_NO_ENTRIES,
    BeforeAfterCard,
    PATCH_GLYPHS,
    json_stamp_text,
    PatchLayout,
    patch_layout,
)
from .panel import PatchEditorPanel  # noqa: F401
