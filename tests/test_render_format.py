"""Batch-92 Inc-A — TC-655: the render/format copies pinned to the frozen origins.

The module ``s19_app/render/format.py`` owns the 5 style constants the moved
hex renderer consumes plus the microbar unit and the two pinned copies of the
frozen ``s19_app/tui/color_policy.py`` highlight styles (PDR #D3, review
C1-(c), operator-ratified). TC-655 pins every value to its frozen tui origin
so drift at either side fails a test by construction — the ``color_policy``
freeze is respected AND enforced (LLR-004.1).

Negative control (executed RED arm recorded in the increment packet):
drifting a copied value at the new address reddens the matching identity
assertion below.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import s19_app
import s19_app.render.format as render_format
import s19_app.tui.color_policy as color_policy
import s19_app.tui.insight_style as insight_style

PRODUCT_ROOT = Path(s19_app.__file__).resolve().parent


def test_tc655_render_format_values_pinned_to_frozen_origins() -> None:
    """TC-655 — every value at the new address equals its frozen tui origin."""
    # The 5 style constants the moved hexview consumes (LLR-001.1 import block).
    assert render_format.CYAN == "#7dd3fc"
    assert render_format.DGRAY == "#969aad"
    assert render_format.VALUE == "#e9e9e9"
    assert render_format.GREEN == "#54efae"
    assert render_format.LABEL == "#c5c7d2"

    # ...equal to their frozen tui origins (insight_style still canonical today;
    # the Inc-B shim re-exports these same objects).
    assert render_format.CYAN == insight_style.CYAN
    assert render_format.DGRAY == insight_style.DGRAY
    assert render_format.VALUE == insight_style.VALUE
    assert render_format.GREEN == insight_style.GREEN
    assert render_format.LABEL == insight_style.LABEL

    # microbar moves with its glyphs as one unit (PDR #D5, LLR-004.1).
    assert render_format.MICROBAR_FILLED == "█"
    assert render_format.MICROBAR_EMPTY == "░"
    assert render_format.microbar(0.5, 8).plain.count("█") == 4
    # Clamp arms from the existing test_microbar domain hold at the new address.
    assert render_format.microbar(-0.5, 8).plain == "░" * 8
    assert render_format.microbar(1.5, 8).plain == "█" * 8
    assert render_format.microbar(1.0, 0).plain == ""
    # The floor opt-in contract travels with the function.
    assert render_format.microbar(0.01, 8, floor=True).plain == "█" + "░" * 7

    # The pinned copies of the frozen color_policy pair (TC-655's reason to exist).
    assert render_format.FOCUS_HIGHLIGHT_STYLE == "bold yellow"
    assert render_format.MAC_ADDRESS_OVERLAY_STYLE == "bold orange3"
    assert (
        render_format.FOCUS_HIGHLIGHT_STYLE == color_policy.FOCUS_HIGHLIGHT_STYLE
    ), "render/format FOCUS_HIGHLIGHT_STYLE drifted from frozen tui/color_policy"
    assert (
        render_format.MAC_ADDRESS_OVERLAY_STYLE == color_policy.MAC_ADDRESS_OVERLAY_STYLE
    ), "render/format MAC_ADDRESS_OVERLAY_STYLE drifted from frozen tui/color_policy"

    # The moved module consumes the copies, not the tui addresses (tui-free rule).
    # Scoped to import lines — the byte-preserved docstrings still MENTION the
    # old owners (e.g. ``_hex_byte_style``'s insight_style references).
    hexview_path = PRODUCT_ROOT / "render" / "hexview.py"
    source = hexview_path.read_text(encoding="utf-8")
    assert "from .format import CYAN, DGRAY, VALUE, FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE" in source
    import ast as _ast

    for node in _ast.walk(_ast.parse(source)):
        if isinstance(node, _ast.ImportFrom):
            resolved = node.module or ""
            if node.level:
                resolved = f"{'..' * (node.level - 1)}{resolved}"
            assert "color_policy" not in resolved and "insight_style" not in resolved, (
                f"render/hexview.py imports {resolved} — the tui-free rule forbids it"
            )
        elif isinstance(node, _ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("s19_app.tui"), (
                    f"render/hexview.py imports {alias.name} — the tui-free rule forbids it"
                )

    # microbar's source moved verbatim (byte-extractable from insight_style).
    moved = inspect.getsource(render_format.microbar)
    assert moved == inspect.getsource(insight_style.microbar)
