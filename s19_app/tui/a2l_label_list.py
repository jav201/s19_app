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

import logging
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from rich.text import Text
from textual.actions import SkipAction
from textual.app import App
from textual.binding import Binding
from textual.widgets import Static

from s19_app.tui.os_clipboard_input import OsClipboardInput
from s19_app.tui.services.label_match import (
    LabelIndex,
    LabelMatch,
    MatchRule,
    build_label_index,
    rank,
)
from .a2l_parameter_picker import parse_parameter_list
from .insight_style import DGRAY, GREEN, HILITE, RED, YELLOW

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


logger = logging.getLogger(__name__)


class LabelRanker:
    """Rank tag names for the list-mode dropdown and closest names (I-3, I-7).

    One instance per app; the viewer (G-V V9) creates it. :meth:`prepare` builds
    the prepared name list once per A2L load generation off the UI thread;
    :meth:`request` ranks a text per consumer key off the UI thread and hands the
    result to its ``deliver`` callback. Every worker runs through :meth:`_work`
    on a thread with ``exit_on_error=False`` and touches no widget.
    """

    def __init__(self, app: App) -> None:
        """
        Summary:
            Create a ranker bound to ``app``, with no prepared name list.

        Args:
            app (App): The running Textual app; workers hand their result back
                through ``app.call_from_thread``.

        Returns:
            None
        """
        self._app = app
        self._generation: int | None = None
        self._index: LabelIndex | None = None
        self._names: tuple[str, ...] = ()
        self._retry = False
        self._tokens: dict[str, int] = {}
        self._held: dict[str, tuple] = {}
        self._running: set[str] = set()
        self._waiting: dict[str, tuple] = {}

    @property
    def ready(self) -> bool:
        """Whether the prepared name list is built and current (``_index`` set)."""
        return self._index is not None

    def prepare(self, names: Sequence[str], generation: int) -> None:
        """
        Summary:
            Build the prepared name list of ``generation`` off the UI thread,
            once per generation (R-A2L-LIST.072).

        Args:
            names (Sequence[str]): The distinct tag names of the A2L load, in
                order; copied to a tuple on the UI thread before the worker runs.
            generation (int): The A2L load generation this list belongs to. An
                equal generation (already prepared or being prepared) returns.

        Returns:
            None

        Data Flow:
            - Record ``generation`` and ``names``, drop the old index (``ready``
              becomes False) and reset the one build retry.
            - Start one thread worker whose body is :meth:`_work` running
              ``build_label_index(names)`` and handing the index to
              :meth:`_install`.

        Dependencies:
            Uses:
                - build_label_index (I-3)
                - _work ; _install ; _start_build
            Used by:
                - (Inc 7) the A2L viewer refresh (V9)
        """
        if generation == self._generation:
            return
        self._generation = generation
        self._index = None
        self._names = tuple(names)
        self._retry = False
        self._start_build(generation)

    def request(
        self,
        key: str,
        query: str,
        limit: int,
        deliver: Callable[[list[LabelMatch]], None],
        current: Callable[[], bool],
    ) -> None:
        """
        Summary:
            Rank ``query`` for the consumer ``key`` off the UI thread and
            deliver the result once it is still current (R-A2L-LIST.071, .073,
            .075, .050, .087).

        Args:
            key (str): The consumer key — ``filter``, ``add``, ``card`` or
                ``similar:1`` … ``similar:10``; one token per key.
            query (str): The text to rank.
            limit (int): The largest number of names; capped at
                :data:`RANK_LIMIT` (20).
            deliver (Callable[[list[LabelMatch]], None]): Holds the widget it
                serves; called on the UI thread with the ranked names.
            current (Callable[[], bool]): Holds the widget it serves; returns
                False once ``not widget.is_attached``.

        Returns:
            None

        Data Flow:
            - Give the key a new token (the latest token per key wins).
            - Not ready: retry a failed build once (E3A-R4) or hold the request
              for :meth:`_install`.
            - Ready: when a ranking for the key runs, keep this as its one
              waiting request; else mark the key running and start one thread
              worker running ``rank(query, index, min(limit, 20))`` and handing
              the result to :meth:`_deliver`. ``rank`` never runs on the UI
              thread.

        Dependencies:
            Uses:
                - rank (I-3)
                - _work ; _deliver ; _start_build ; _start_ranking
            Used by:
                - (Inc 7) the A2L viewer filter debounce and the paste window
        """
        token = self._tokens.get(key, 0) + 1
        self._tokens[key] = token
        if not self.ready:
            if self._retry:
                self._retry = False
                self._start_build(self._generation, retry=True)
            self._held[key] = (token, query, limit, deliver, current)
            return
        if key in self._running:
            self._waiting[key] = (token, query, limit, deliver, current)
            return
        self._start_ranking(key, token, query, limit, deliver, current)

    def _install(self, generation: int, index: LabelIndex | None) -> None:
        """Hand a built ``index`` (or its failure) to the UI thread."""
        if not self._app.is_running:
            return
        if generation != self._generation:
            return
        if index is None:
            self._held.clear()
            self._retry = True
            return
        self._index = index
        self._retry = False
        held, self._held = self._held, {}
        for key, request in held.items():
            if request[0] == self._tokens.get(key):
                self._start_ranking(key, *request)

    def _deliver(
        self,
        key: str,
        token: int,
        generation: int,
        matches: list[LabelMatch] | None,
        deliver: Callable[[list[LabelMatch]], None],
        current: Callable[[], bool],
    ) -> None:
        """Deliver ``matches`` only while its request is still current."""
        if not self._app.is_running:
            return
        self._running.discard(key)
        waiting = self._waiting.pop(key, None)
        if waiting is not None and self.ready:
            self._start_ranking(key, *waiting)
        if matches is None:
            return
        if token != self._tokens.get(key):
            return
        if generation != self._generation:
            return
        if not current():
            return
        deliver(matches)

    def _work(
        self, job: Callable[[], object], hand_over: Callable[[object], None]
    ) -> None:
        """Run ``job`` on the worker thread and hand its result back; never raises."""
        try:
            result = job()
        except Exception:
            result = None
        try:
            self._app.call_from_thread(hand_over, result)
        except RuntimeError:
            return

    def _start_build(self, generation: int, retry: bool = False) -> None:
        """Start the name-list build worker for ``generation`` (``retry`` = rebuild)."""
        names = self._names

        def job() -> object:
            try:
                return build_label_index(names)
            except Exception as exc:
                logger.warning("label-list build failed: %s", type(exc).__name__)
                raise

        def hand_over(result: object) -> None:
            self._install(generation, result)
            if retry and result is None:
                self._retry = False

        self._app.run_worker(
            lambda: self._work(job, hand_over),
            thread=True,
            exit_on_error=False,
            group="a2l_label_list",
        )

    def _start_ranking(
        self,
        key: str,
        token: int,
        query: str,
        limit: int,
        deliver: Callable[[list[LabelMatch]], None],
        current: Callable[[], bool],
    ) -> None:
        """Mark ``key`` running and rank ``query`` off the UI thread."""
        self._running.add(key)
        index = self._index
        generation = self._generation
        limit = min(limit, RANK_LIMIT)

        def job() -> object:
            try:
                return rank(query, index, limit)
            except Exception as exc:
                logger.warning(
                    "label-list rank failed: %s key=%s", type(exc).__name__, key
                )
                raise

        def hand_over(result: object) -> None:
            self._deliver(key, token, generation, result, deliver, current)

        self._app.run_worker(
            lambda: self._work(job, hand_over),
            thread=True,
            exit_on_error=False,
            group="a2l_label_list",
        )


def _rule_tag(match: LabelMatch) -> str:
    """Return the rule tag of ``match`` (``fuzzy · <k> edit(s)``, else the word)."""
    if match.rule is MatchRule.FUZZY:
        if match.edits == 1:
            return "fuzzy · 1 edit"
        return f"fuzzy · {match.edits} edits"
    return match.rule.value


def _highlight_name(match: LabelMatch) -> Text:
    """Paint ``match``'s short display text with its match spans highlighted.

    The spans index the original name; ``display_text(name, 64)`` keeps the
    offsets one-for-one but clips a longer name to 63 characters plus ``…``, so
    a span past that cut is dropped and one that straddles it is clipped.
    """
    shown = display_text(match.name, SHORT_AT)
    cut = SHORT_AT - 1 if len(match.name) > SHORT_AT else len(shown)
    text = Text(shown)
    for start, end in match.spans:
        if end > cut:
            end = cut
        if start > cut:
            start = cut
        if end > start:
            text.stylize(HILITE, start, end)
    return text


class LabelSuggestBox(Static):
    """The filter / add-line suggestion dropdown (R-A2L-LIST.060-.070, .076, .077).

    A ``Static`` the host composes under its filter box or paste-window add
    line. It shows at most ``DROPDOWN_ROWS`` (8) ranked names, one per row:
    ``▸ `` for the highlighted row or two spaces otherwise, the name's short
    display text with its match spans highlighted, a space, and the rule tag.
    It is open while the ``-open`` class is set; ``choice`` holds the real
    ``LabelMatch.name`` of the highlighted row (never its display text).
    """

    # Closed: not shown and no height. Open: a overlay under its box.
    DEFAULT_CSS = """
    LabelSuggestBox {
        display: none;
        height: auto;
        max-height: 14;
        overlay: screen;
    }
    LabelSuggestBox.-open {
        display: block;
    }
    """

    is_open: bool
    choice: str | None

    def __init__(self, *, accept: str, id: str) -> None:
        """
        Summary:
            Create a closed suggestion box with ``accept`` as its key-line
            accept phrase.

        Args:
            accept (str): The accept phrase — ``tab complete`` under the filter
                box or ``enter add to the list`` under the add line.
            id (str): The widget id — ``a2l_filter_suggest`` or
                ``a2l_list_add_suggest``.

        Returns:
            None
        """
        super().__init__(id=id, markup=False)
        self._accept = accept
        self._rows: list[LabelMatch] = []
        self._total = 0
        self._choice_index = 0
        self._query = ""
        self.is_open = False
        self.choice = None

    def show_ranked(self, query: str, matches: Sequence[LabelMatch]) -> None:
        """
        Summary:
            Open the dropdown and paint the first ``DROPDOWN_ROWS`` ranked names
            of ``query``, or the ``no similar name`` empty state when there are
            none (R-A2L-LIST.060-.067, .076, .077).

        Args:
            query (str): The text the names were ranked for.
            matches (Sequence[LabelMatch]): The ranked names, best first (at
                most ``RANK_LIMIT``); only the first 8 are shown.

        Returns:
            None

        Data Flow:
            - Keep the first 8 matches, remember the total, set the choice to
              row 1 and open (``is_open`` True, class ``-open`` added).
            - Paint the title, the rows and the key line; with no match paint
              the ``no similar name`` state and set the choice to ``None``.

        Dependencies:
            Uses:
                - _rows_text
            Used by:
                - (Inc 7) the viewer / paste-window ranking deliver callback
        """
        self._rows = list(matches[:DROPDOWN_ROWS])
        self._total = len(matches)
        self._choice_index = 0
        self._query = query
        self.choice = self._rows[0].name if self._rows else None
        self.is_open = True
        self.add_class("-open")
        self.update(self._rows_text())

    def close(self) -> None:
        """
        Summary:
            Close the dropdown: drop the ``-open`` class and clear the open
            flag, leaving the box text untouched (R-A2L-LIST.070).

        Returns:
            None
        """
        self.is_open = False
        self.remove_class("-open")

    def move(self, step: int) -> None:
        """
        Summary:
            Move the choice by ``step`` rows, clamped to the shown rows, and
            repaint (R-A2L-LIST.068). No-op while closed or with no rows.

        Args:
            step (int): The signed number of rows to move (+1 down, -1 up).

        Returns:
            None
        """
        if not self.is_open or not self._rows:
            return
        last = len(self._rows) - 1
        self._choice_index = max(0, min(last, self._choice_index + step))
        self.choice = self._rows[self._choice_index].name
        self.update(self._rows_text())

    def _rows_text(self) -> Text:
        """Paint the open dropdown from the shown rows, total and accept phrase."""
        if not self._rows:
            return self._empty_text()
        text = Text()
        total = "20+" if self._total == RANK_LIMIT else str(self._total)
        text.append(f"{len(self._rows)} of {total} similar names\n")
        for index, match in enumerate(self._rows):
            text.append("▸ " if index == self._choice_index else "  ")
            text.append(_highlight_name(match))
            text.append(" ")
            text.append(_rule_tag(match))
            text.append("\n")
        text.append(f"↑↓ choose  {self._accept}  esc close\n")
        text.append("rank: exact › prefix › substring › token › fuzzy › subsequence")
        return text

    def _empty_text(self) -> Text:
        """Paint the ``no similar name`` empty state for the last query."""
        text = Text()
        text.append("no similar name\n")
        text.append(f"nothing matches '{display_text(self._query, SHORT_AT)}'\n")
        text.append("digits must match exactly; a word may have 1–2 typos")
        return text


class ListAwareFilterInput(OsClipboardInput):
    """The A2L Explorer filter box, aware of list mode (R-A2L-LIST.032-.034, .068-.070).

    An ``OsClipboardInput`` whose paste hook takes a whole multi-name paste and
    joins it into list text, and whose ``escape`` / ``up`` / ``down`` / ``tab``
    bindings drive its sibling :class:`LabelSuggestBox` dropdown, raising
    ``SkipAction`` whenever they do not apply so the shipped handling runs.
    """

    BINDINGS = [
        Binding("escape", "esc", "Close", show=False),
        Binding("up", "move_choice(-1)", show=False),
        Binding("down", "move_choice(1)", show=False),
        Binding("tab", "complete", show=False),
    ]

    def __init__(
        self,
        *,
        suggest: LabelSuggestBox,
        list_enabled: Callable[[], bool],
        placeholder: str,
        id: str,
    ) -> None:
        """
        Summary:
            Create the filter box bound to its sibling ``suggest`` dropdown and
            a ``list_enabled`` gate that is True while the filter field is
            ``name`` or ``all``.

        Args:
            suggest (LabelSuggestBox): The sibling dropdown the box drives.
            list_enabled (Callable[[], bool]): True while the filter field is
                ``name`` or ``all``.
            placeholder (str): The box placeholder.
            id (str): The widget id (``a2l_tags_filter_input``).

        Returns:
            None
        """
        super().__init__(placeholder=placeholder, id=id)
        self._suggest = suggest
        self._list_enabled = list_enabled

    def action_move_choice(self, step: int) -> None:
        """
        Summary:
            Move the open dropdown's choice by ``step`` rows; with no dropdown
            raise ``SkipAction`` so the box's shipped Up/Down handling runs
            (R-A2L-LIST.068).

        Args:
            step (int): The signed number of rows (-1 up, +1 down).

        Returns:
            None

        Raises:
            textual.actions.SkipAction: When the dropdown is closed.
        """
        if self._suggest.is_open:
            self._suggest.move(step)
            return
        raise SkipAction()

    def action_esc(self) -> None:
        """
        Summary:
            Close an open dropdown (keep the box text); else clear the box text
            when it is a list text; else raise ``SkipAction`` so the shipped
            Esc handling runs (R-A2L-LIST.032, .070).

        Returns:
            None

        Raises:
            textual.actions.SkipAction: When there is no dropdown and the value
                is not a list text.
        """
        if self._suggest.is_open:
            self._suggest.close()
            return
        if is_list_text(self.value):
            self.value = ""
            return
        raise SkipAction()

    def action_complete(self) -> None:
        """
        Summary:
            Replace the box text with the open dropdown's chosen name (the real
            ``LabelMatch.name``, never its display text), put the cursor at its
            end and close the dropdown; else raise ``SkipAction`` so the app's
            tab moves the focus on (R-A2L-LIST.069).

        Returns:
            None

        Raises:
            textual.actions.SkipAction: When no dropdown is open with a choice.
        """
        if self._suggest.is_open and self._suggest.choice is not None:
            self.value = self._suggest.choice
            self.cursor_position = len(self.value)
            self._suggest.close()
            return
        raise SkipAction()

    def _take_paste(self, text: str) -> bool:
        """
        Summary:
            Override the I-1 paste hook: when the filter field is ``name`` or
            ``all`` and the stripped paste holds two or more names, replace the
            box text with the names joined by ``, `` and put the cursor at its
            start (R-A2L-LIST.033, .034, R-PASTE.1, R-TUI-043.4, R-PASTE.29).

        Args:
            text (str): The paste text, already stripped by the route (I-1).

        Returns:
            bool: ``True`` once the joined names replaced the box text;
                ``False`` when the field gate is closed or the paste holds one
                name, so the stock first-line insert runs.

        Data Flow:
            - The field gate closed → ``False`` (the stock route inserts).
            - Parse the names; fewer than two → ``False``.
            - Otherwise set ``value`` to the names joined by ``, `` and the
              cursor to 0, and return ``True``.

        Dependencies:
            Uses:
                - parse_parameter_list (I-5)
            Used by:
                - OsClipboardInput._on_paste / action_paste (I-1)
        """
        if not self._list_enabled():
            return False
        names = parse_parameter_list(text)
        if len(names) < 2:
            return False
        self.value = ", ".join(names)
        self.cursor_position = 0
        return True
