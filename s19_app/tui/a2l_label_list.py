"""The A2L Explorer label-list resolver and text builders (batch-103 Inc 7).

Pure, headless module for list mode: :func:`is_list_text` decides list mode
from the filter text (:func:`s19_app.tui.a2l_parameter_picker.parse_parameter_list`,
I-5); :func:`resolve_label_list` marks each pasted name found / missing /
duplicate / hidden against the current A2L (R-A2L-LIST.002-.005) into a
:class:`LabelListResolution`; and :func:`list_summary_texts`,
:func:`list_row_cells` and :func:`list_card_text` paint the counts / ribbon /
missing lines, the nine list-table cells and the detail-card lines.

Every name painted to the screen goes through :func:`display_text`, which
replaces the C0/C1 controls, the bidi controls, the zero-width characters and
U+FEFF with U+FFFD one-for-one (offsets kept), and every caller builds
``rich.text.Text`` from plain strings — never markup — so a hostile A2L or
clipboard name renders literally (I-3 obligations 1-2, E3S-04/.06/.R1,
R-A2L-LIST.076/.077).

Later units add ``LabelRanker``, ``LabelSuggestBox``, ``ListAwareFilterInput``,
``LabelListPasteModal`` and ``A2LExplorerBody`` to this same module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from rich.text import Text

from .a2l_parameter_picker import parse_parameter_list
from .insight_style import DGRAY, GREEN, RED, YELLOW

FOUND, MISSING, DUPLICATE, HIDDEN = "found", "missing", "duplicate", "hidden"
GLYPH = {FOUND: "●", MISSING: "✗", DUPLICATE: "=", HIDDEN: "◐"}
MODE_LABEL = {"all": "All", "invalid": "Invalid", "inmem": "In-memory"}
LIST_COLUMNS = ("#", "Tag", "Status", "Kind", "Address", "Len", "Physical", "Unit", "Limits")
TEXT_CELL_LABELS = ("Address", "Length", "Physical", "Unit", "Limits")
DROPDOWN_ROWS = 8
RANK_LIMIT = 20
CLOSEST_LIMIT = 3
SIMILAR_MAX = 10
MISSING_MAX = 20
VIEWER_RIBBON = 80
WINDOW_RIBBON = 50
SHORT_AT = 64
PREVIEW_MAX = 200
WIDE_AT = 180
STACK_MIN_WIDTH = 110
STACK_MIN_HEIGHT = 32

#: Per-status Rich style (R-A2L-LIST.017 etc.): found accent, missing red,
#: duplicate and hidden yellow.
_STATUS_STYLE = {FOUND: GREEN, MISSING: RED, DUPLICATE: YELLOW, HIDDEN: YELLOW}

#: The translation table of :func:`display_text`: each control / bidi /
#: zero-width character maps to U+FFFD, one for one.
_REPLACE = str.maketrans(
    {
        **{cp: "\ufffd" for cp in range(0x00, 0x20)},
        **{cp: "\ufffd" for cp in range(0x7F, 0xA0)},
        0x061C: "\ufffd",
        **{cp: "\ufffd" for cp in range(0x200B, 0x2010)},
        **{cp: "\ufffd" for cp in range(0x202A, 0x202F)},
        0x2060: "\ufffd",
        **{cp: "\ufffd" for cp in range(0x2066, 0x206A)},
        0xFEFF: "\ufffd",
    }
)


@dataclass(frozen=True, slots=True)
class LabelListEntry:
    """One pasted name resolved against the current A2L (frozen, slotted).

    Two entries with equal fields compare equal. ``pos`` is the 1-based pasted
    position, ``name`` the pasted name as pasted, ``status`` one of ``FOUND``
    / ``MISSING`` / ``DUPLICATE`` / ``HIDDEN``, ``tag`` the enriched tag
    (``None`` when the name has no tag), and ``first_pos`` the first
    occurrence's position for a duplicate (``None`` otherwise).
    """

    pos: int
    name: str
    status: str
    tag: dict | None
    first_pos: int | None


@dataclass(frozen=True, slots=True)
class LabelListResolution:
    """A resolved pasted list (frozen, slotted; the viewer keeps the last one).

    ``entries`` holds one entry per pasted name in order; ``rows`` holds, in
    the same order, the tag object itself for a found / duplicate / hidden
    entry (so the jump handler and the write route read the real tag) or a new
    ``{"name": ..., "_list_pos": ...}`` dict for a missing entry. The values
    are not hashable (they hold dicts); nothing hashes them.
    """

    entries: tuple[LabelListEntry, ...]
    rows: tuple[dict, ...]

    def count(self, status: str) -> int:
        """Return the number of entries with the given ``status``.

        Args:
            status (str): One of ``FOUND`` / ``MISSING`` / ``DUPLICATE`` /
                ``HIDDEN``.

        Returns:
            int: The number of entries whose ``status`` equals ``status``.
        """
        return sum(1 for entry in self.entries if entry.status == status)


def is_list_text(text: str) -> bool:
    """
    Summary:
        Decide whether a filter text is a *list text*: its pasted names number
        two or more (R-A2L-LIST.001, .006, .062).

    Args:
        text (str): The filter box's text, as pasted or typed.

    Returns:
        bool: True when ``parse_parameter_list`` yields at least two names.

    Data Flow:
        - Parse ``text`` with the label-list parser (I-5).
        - Report whether the name count reaches two.

    Dependencies:
        Uses:
            - s19_app.tui.a2l_parameter_picker.parse_parameter_list
        Used by:
            - (Inc 7) the A2L Viewer filter and the paste window
    """
    return len(parse_parameter_list(text)) >= 2


def display_text(name: str, cap: int | None = None) -> str:
    """
    Summary:
        Sanitize a name or operator text for painting: replace each control,
        bidi and zero-width character with U+FFFD one-for-one, then optionally
        clip to ``cap`` characters with an ellipsis (R-A2L-LIST.076, .077).

    Args:
        name (str): The name or text to paint (possibly hostile).
        cap (int | None): Optional character limit. When given and the
            sanitized text is longer than ``cap``, keep the first ``cap - 1``
            characters followed by ``…``. ``display_text(name, 64)`` is the
            *short text* of the definitions.

    Returns:
        str: The sanitized (and possibly clipped) text. Never raises for any
            ``str``.

    Data Flow:
        - Replace each character in U+0000-U+001F, U+007F-U+009F, U+061C,
          U+200B-U+200F, U+202A-U+202E, U+2060, U+2066-U+2069 and U+FEFF with
          U+FFFD, one for one (offsets kept, so match spans still index it).
        - When ``cap`` is given and the result is longer than ``cap``, keep its
          first ``cap - 1`` characters and ``…``.

    Dependencies:
        Uses:
            - _REPLACE
        Used by:
            - (Inc 7) every list-mode painter in this module
    """
    shown = name.translate(_REPLACE)
    if cap is not None and len(shown) > cap:
        shown = shown[: cap - 1] + "…"
    return shown


def resolve_label_list(
    names: Sequence[str],
    tags: Sequence[dict],
    hidden: Callable[[dict], bool] | None = None,
) -> LabelListResolution:
    """
    Summary:
        Resolve the pasted names against the current A2L into a
        :class:`LabelListResolution`, marking each name found / missing /
        duplicate / hidden (R-A2L-LIST.002-.005).

    Args:
        names (Sequence[str]): The pasted names in order.
        tags (Sequence[dict]): The enriched tags of the current A2L.
        hidden (Callable[[dict], bool] | None): Optional predicate that is
            True for a tag the active filter mode leaves out, so its name is
            hidden rather than found.

    Returns:
        LabelListResolution: ``entries`` one per pasted name in order, and
            ``rows`` in the same order holding the tag object itself for
            found / duplicate / hidden and ``{"name": ..., "_list_pos": ...}``
            for missing.

    Data Flow:
        - Build one ``name -> first tag`` map from ``tags``, keyed by
          ``str(tag.get("name") or "")``.
        - Walk ``names`` in order: a repeated name is a duplicate of its first
          position; an absent name is missing; a hidden tag is hidden; else
          found. Case kept: no fold.
        - Build ``entries`` and ``rows`` side by side (no entry refers to a row
          or to itself).

    Dependencies:
        Uses:
            - LabelListEntry ; LabelListResolution
        Used by:
            - (Inc 7) the A2L Viewer and the paste window
    """
    first_tag: dict[str, dict] = {}
    for tag in tags:
        name = str(tag.get("name") or "")
        if name and name not in first_tag:
            first_tag[name] = tag

    entries: list[LabelListEntry] = []
    rows: list[dict] = []
    seen: dict[str, int] = {}
    for pos, name in enumerate(names, start=1):
        first = seen.get(name)
        if first is not None:
            tag = first_tag.get(name)
            entries.append(LabelListEntry(pos, name, DUPLICATE, tag, first))
            rows.append(tag if tag is not None else {"name": name, "_list_pos": pos})
            continue
        seen[name] = pos
        tag = first_tag.get(name)
        if tag is None:
            entries.append(LabelListEntry(pos, name, MISSING, None, None))
            rows.append({"name": name, "_list_pos": pos})
        elif hidden is not None and hidden(tag):
            entries.append(LabelListEntry(pos, name, HIDDEN, tag, None))
            rows.append(tag)
        else:
            entries.append(LabelListEntry(pos, name, FOUND, tag, None))
            rows.append(tag)
    return LabelListResolution(tuple(entries), tuple(rows))


def list_summary_texts(
    res: LabelListResolution, budget: int
) -> tuple[Text, Text, Text]:
    """
    Summary:
        Build the three list-mode summary lines — the counts line, the ribbon
        and the missing line — from a resolution (R-A2L-LIST.017, .018, .022,
        .024, .046, .048).

    Args:
        res (LabelListResolution): The resolution to summarize.
        budget (int): The ribbon's cell budget (:data:`VIEWER_RIBBON` or
            :data:`WINDOW_RIBBON`).

    Returns:
        tuple[Text, Text, Text]: ``(counts, ribbon, missing)``, each a
            markup-safe ``Text`` with found accent, missing red, duplicate and
            hidden yellow, the rest muted.

    Data Flow:
        - Count the four statuses; build the counts line, spaced by ``·``.
        - Lay the ribbon: one glyph per pasted name in order, spaced when
          ``2 * n <= budget``, else at most ``budget`` glyphs then `` +<k>``.
        - Build the missing line with at most :data:`MISSING_MAX` names of each
          kind then `` +<k>``, each name as its short text.

    Dependencies:
        Uses:
            - _counts_line ; _ribbon ; _missing_line
        Used by:
            - (Inc 7) the A2L Viewer and the paste window
    """
    return _counts_line(res), _ribbon(res, budget), _missing_line(res)


def _counts_line(res: LabelListResolution) -> Text:
    """Build the counts line of ``res`` (R-A2L-LIST.017)."""
    n = len(res.entries)
    found = res.count(FOUND)
    missing = res.count(MISSING)
    dup = res.count(DUPLICATE)
    hidden = res.count(HIDDEN)
    s = "" if dup == 1 else "s"
    text = Text()
    text.append(f"{n} pasted", style=DGRAY)
    text.append("  ·  ", style=DGRAY)
    text.append(f"{GLYPH[FOUND]} {found} found", style=GREEN)
    text.append("  ·  ", style=DGRAY)
    text.append(f"{GLYPH[MISSING]} {missing} missing", style=RED)
    text.append("  ·  ", style=DGRAY)
    text.append(f"{GLYPH[DUPLICATE]} {dup} duplicate{s}", style=YELLOW)
    if hidden:
        text.append("  ·  ", style=DGRAY)
        text.append(f"{GLYPH[HIDDEN]} {hidden} hidden by mode", style=YELLOW)
    return text


def _ribbon(res: LabelListResolution, budget: int) -> Text:
    """Build the ribbon of ``res`` within ``budget`` cells (R-A2L-LIST.018)."""
    entries = res.entries
    n = len(entries)
    text = Text()
    if 2 * n <= budget:
        for entry in entries:
            text.append(GLYPH[entry.status], style=_STATUS_STYLE[entry.status])
            text.append(" ")
    else:
        for entry in entries[:budget]:
            text.append(GLYPH[entry.status], style=_STATUS_STYLE[entry.status])
        if n > budget:
            text.append(f" +{n - budget}", style=DGRAY)
    return text


def _missing_line(res: LabelListResolution) -> Text:
    """Build the missing line of ``res`` (R-A2L-LIST.022, .024)."""
    entries = res.entries
    missing = [e for e in entries if e.status == MISSING]
    dupes = [e for e in entries if e.status == DUPLICATE]
    text = Text()
    text.append(f"Missing {len(missing)} ", style=RED)
    if missing:
        shown = missing[:MISSING_MAX]
        text.append("▸ ", style=DGRAY)
        text.append(
            " · ".join(f"#{e.pos} {display_text(e.name, SHORT_AT)}" for e in shown),
            style=RED,
        )
        if len(missing) > MISSING_MAX:
            text.append(f" +{len(missing) - MISSING_MAX}", style=DGRAY)
    text.append("    ")
    text.append(f"Duplicates {len(dupes)} ", style=YELLOW)
    if dupes:
        shown = dupes[:MISSING_MAX]
        text.append("▸ ", style=DGRAY)
        text.append(
            " · ".join(
                f"#{e.pos} {display_text(e.name, SHORT_AT)} (= #{e.first_pos})"
                for e in shown
            ),
            style=YELLOW,
        )
        if len(dupes) > MISSING_MAX:
            text.append(f" +{len(dupes) - MISSING_MAX}", style=DGRAY)
    return text


def list_row_cells(
    entry: LabelListEntry,
    text_cells: Mapping[str, Text] | None,
    mode: str,
) -> tuple[Text, ...]:
    """
    Summary:
        Build the nine list-mode table cells of one entry, in the order of
        :data:`LIST_COLUMNS` (R-A2L-LIST.011-.015).

    Args:
        entry (LabelListEntry): The pasted name to render.
        text_cells (Mapping[str, Text] | None): The text-mode cells keyed by
            the shipped column labels; read only at the keys of
            :data:`TEXT_CELL_LABELS`, and only for a non-missing entry.
        mode (str): The active filter mode (for the hidden status word).

    Returns:
        tuple[Text, ...]: Nine ``Text`` cells — position, tag (glyph + display
            text), status word, kind, then the five text-mode cells. A missing
            entry leaves the kind and the five text cells blank.

    Data Flow:
        - Paint the position, the status glyph + display text, and the status
          word.
        - For a non-missing entry, derive the kind from ``char_type`` /
          ``MEASUREMENT`` / ``section`` and copy the five text-mode cells; a
          missing entry leaves those six cells blank.

    Dependencies:
        Uses:
            - _status_word ; _kind_cell ; display_text
        Used by:
            - (Inc 7) the A2L Viewer list-mode table
    """
    tag_cell = Text()
    tag_cell.append(GLYPH[entry.status])
    tag_cell.append(" ")
    tag_cell.append(display_text(entry.name))
    cells: list[Text] = [
        Text(str(entry.pos)),
        tag_cell,
        Text(_status_word(entry, mode)),
    ]
    if entry.status == MISSING:
        cells.append(Text(""))
        cells.extend(Text("") for _ in TEXT_CELL_LABELS)
    else:
        cells.append(Text(_kind_cell(entry.tag)))
        cells.extend(text_cells[label] for label in TEXT_CELL_LABELS)
    return tuple(cells)


def _status_word(entry: LabelListEntry, mode: str) -> str:
    """Return the status word of ``entry`` (the ``Status`` cell)."""
    if entry.status == FOUND:
        return "found"
    if entry.status == MISSING:
        return "not in A2L"
    if entry.status == DUPLICATE:
        return f"dup of #{entry.first_pos}"
    return f"hidden: {MODE_LABEL[mode]}"


def _kind_cell(tag: dict) -> str:
    """Return the ``Kind`` cell text of a non-missing ``tag``."""
    char_type = tag.get("char_type")
    if char_type:
        return str(char_type)
    if tag.get("section") == "MEASUREMENT":
        return "MEASURE"
    return str(tag.get("section") or "")


def list_card_text(
    entry: LabelListEntry, closest: Sequence[str] | None
) -> Text:
    """
    Summary:
        Build the detail-card lines for a list-mode row: the missing card, or
        the one-line duplicate / hidden addendum, or an empty ``Text`` for a
        found entry (R-A2L-LIST.027-.030).

    Args:
        entry (LabelListEntry): The highlighted row's entry.
        closest (Sequence[str] | None): The ranked closest names for a missing
            name, or ``None`` when no ranking was requested.

    Returns:
        Text: The card lines — for a missing name, the ``✗`` line, the
            ``pasted #<p>`` line and (when ``closest`` is not ``None``) the
            ``closest`` line; for a duplicate or hidden name, a one-line
            addendum; empty for a found name.

    Data Flow:
        - A found entry yields an empty ``Text``.
        - A duplicate / hidden entry yields its fixed addendum line.
        - A missing entry paints its short text, its pasted position, and the
          closest names (each as its short text) or ``closest —``.

    Dependencies:
        Uses:
            - display_text
        Used by:
            - (Inc 7) the A2L Viewer detail card
    """
    if entry.status == FOUND:
        return Text()
    if entry.status == DUPLICATE:
        return Text(f"duplicate of pasted #{entry.first_pos}")
    if entry.status == HIDDEN:
        return Text("hidden by the active filter mode")
    text = Text()
    text.append(f"✗ {display_text(entry.name, SHORT_AT)}  not in this A2L")
    text.append(f"\npasted #{entry.pos}")
    if closest is not None:
        text.append("\n")
        if closest:
            text.append(
                "closest " + " · ".join(display_text(name, SHORT_AT) for name in closest)
            )
        else:
            text.append("closest —")
    return text
