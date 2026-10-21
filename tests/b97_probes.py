"""Batch-97 shared probes (design-proposal §5.1).

Inc-1 adds the open-folder chip helpers; Inc-3 adds the painted-surface
predicates (``painted_rows``, ``chip_style``, ``clipped_overflow``,
``blank_panel_rows``); ``span_colours`` arrives with Inc-5 (PC-7).
Every probe reads the shipped surface: the chip widget itself and the app's
status line (``S19TuiApp.log_lines``, the buffer ``#status_log`` paints).
"""
from __future__ import annotations

from typing import Optional

from s19_app.tui.open_folder_chip import OpenFolderChip

#: The terminal the chip tests run at: wide enough that a status line naming a
#: full ``tmp_path`` target is not clipped by the status cap (``app.py``
#: ``_append_log_line`` keeps ``max(50, width)`` cells).
CHIP_TEST_SIZE = (220, 60)


async def settle(pilot, rounds: int = 4) -> None:
    """Pump the event loop so a press or a mount has run its handlers."""
    for _ in range(rounds):
        await pilot.pause()


async def mount_chip(
    app, pilot, family: str, *, id_suffix: Optional[str] = None
) -> OpenFolderChip:
    """Mount a chip of ``family`` on the active screen and let it refresh.

    Used for the families no screen header carries yet (``flows`` and
    ``session`` land in the headers at Inc-5 / Inc-6) and for the
    ``id_suffix`` mechanism; the chip runs its own ``on_mount`` refresh.
    """
    if id_suffix is None:
        chip = OpenFolderChip(family)
    else:
        chip = OpenFolderChip(family, id_suffix=id_suffix)
    await app.screen.mount(chip)
    await settle(pilot)
    return chip


def last_status(app) -> str:
    """The newest status line the app painted."""
    return app.log_lines[-1] if app.log_lines else ""


def chip_label(chip: OpenFolderChip) -> str:
    """The chip's painted label as plain text."""
    return str(chip.label)


# --------------------------------------------------------------------------- #
# Inc-3: painted-surface predicates (C-32 — read the compositor, never a
# widget's own declared width or text)
# --------------------------------------------------------------------------- #


def painted_rows(app, widget, region=None) -> list:
    """The text painted inside ``widget``'s region, one string per terminal row.

    Read off ``app.screen._compositor.render_strips()`` (the idiom of
    ``tests/test_tui_diff_screen.py:872``), cropped to the region's columns
    with ``Strip.crop`` so a double-width glyph cannot shift the slice.
    """
    strips = app.screen._compositor.render_strips()
    region = widget.region if region is None else region
    rows = []
    for y in range(region.y, min(region.y + region.height, len(strips))):
        strip = strips[y].crop(region.x, region.x + region.width)
        rows.append("".join(segment.text for segment in strip))
    return rows


def painted_style(app, x: int, y: int):
    """The rich ``Style`` of the cell painted at screen column ``x``, row ``y``."""
    strips = app.screen._compositor.render_strips()
    for segment in strips[y].crop(x, x + 1):
        if segment.text:
            return segment.style
    return None


def chip_style(app, chip):
    """The painted (fg, bg, bold, reverse, underline) of a one-row chip's first label cell."""
    region = chip.region
    row = painted_rows(app, chip)[0]
    offset = len(row) - len(row.lstrip())
    style = painted_style(app, region.x + offset, region.y)
    if style is None:
        return None
    return (
        str(style.color.triplet) if style.color and style.color.triplet else str(style.color),
        str(style.bgcolor.triplet) if style.bgcolor and style.bgcolor.triplet else str(style.bgcolor),
        bool(style.bold),
        bool(style.reverse),
        bool(style.underline),
    )


def is_displayed(widget) -> bool:
    """``display`` holds for the widget and every ancestor up to the screen."""
    node = widget
    while node is not None and getattr(node, "parent", None) is not None:
        if not node.display:
            return False
        node = node.parent
    return True


def clipped_overflow(panel) -> list:
    """Displayed descendants of ``panel`` whose clipped region leaves it on x.

    The clipped region (contract §1.3, P-52) is ``widget.region`` intersected
    with the ``content_region`` of every ancestor strictly inside the panel whose
    ``overflow_x`` is ``auto`` or ``scroll``: a part scrolled out of such an
    ancestor is reachable, not overflow; a non-scrolling ancestor clips nothing.
    Returns the offending widgets; the caller guards the population size.
    """
    offenders = []
    panel_region = panel.region
    for widget in panel.query("*"):
        if not is_displayed(widget) or widget.region.width == 0:
            continue
        region = widget.region
        node = widget.parent
        while node is not None and node is not panel:
            if node.styles.overflow_x in ("auto", "scroll"):
                region = region.intersection(node.content_region)
            node = node.parent
        if region.width == 0:
            continue
        if region.right > panel_region.right or region.x < panel_region.x:
            offenders.append(widget)
    return offenders


def displayed_descendants(panel) -> list:
    """The displayed, non-empty descendants of ``panel`` (the guard population)."""
    return [w for w in panel.query("*") if is_displayed(w) and w.region.width > 0]


def blank_panel_rows(app, panel, outside=None) -> list:
    """Panel rows painted blank across the panel's whole width.

    ``outside`` (a widget) excludes the rows of that widget's band — the growing
    region whose own empty rows are allowed (LLR-149.5). A row is blank when its
    panel-wide slice holds only spaces.
    """
    rows = painted_rows(app, panel)
    skip = set()
    if outside is not None:
        band = outside.region
        skip = set(range(band.y, band.y + band.height))
    return [
        panel.region.y + index
        for index, text in enumerate(rows)
        if panel.region.y + index not in skip and text.strip() == ""
    ]


def string_constants(source: str, scope: Optional[str] = None) -> list:
    """The string constants of ``source`` — docstrings excluded.

    ``scope`` limits the walk to one top-level ``ClassDef`` by name (keyed on
    the node, never on line spans); ``None`` walks the whole module. f-string
    literal parts are constants too (``JoinedStr`` children), so a Spanish
    fragment inside an f-string is counted.
    """
    import ast

    tree = ast.parse(source)
    root = tree
    if scope is not None:
        matches = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == scope]
        assert len(matches) == 1, f"scope {scope!r} found {len(matches)} times"
        root = matches[0]
    docstrings = set()
    for node in ast.walk(root):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return [
        node.value
        for node in ast.walk(root)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]
