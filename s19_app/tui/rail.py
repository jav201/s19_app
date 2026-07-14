"""Activity-rail widget for the s19tui Direction B "Rail + Command" view.

This module is the home for the left activity rail introduced by
batch-02-direction-b-restyle, increment 3:

  - ``RailEntry`` — the immutable description of one rail item (screen key,
    Unicode glyph, ASCII-fallback glyph, label);
  - ``RAIL_ENTRIES`` — the eight ordered rail items (Workspace, A2L, MAC,
    Map, Issues, Patch, Diff, Bookmarks) on keys ``1``-``8``, carrying the
    normative LLR-001.3 glyph -> screen mapping;
  - ``RailItem`` — one selectable row in the rail;
  - ``Rail`` — the vertical rail composing the eight items, tracking the
    single active item and emitting ``Rail.Selected`` on click.

The rail is a presentational widget (s19_app CLAUDE.md TUI architecture):
it takes its entries at construction, emits a ``Rail.Selected`` message on
click, and exposes ``set_active``; it never calls the engine or a service.
``S19TuiApp`` owns the routing — it handles ``Rail.Selected`` and the
``1``-``8`` key bindings, calls ``action_show_screen``, and keeps the rail's
active marker in sync via ``set_active``.
"""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Static


@dataclass(frozen=True)
class RailEntry:
    """Immutable description of a single activity-rail item.

    Summary:
        Pairs a Direction B rail screen with its keymap key, its Unicode
        glyph and its ASCII-fallback glyph (the LLR-001.3 glyph -> screen
        mapping) plus the human-readable label shown next to the glyph.

    Args:
        key (str): The screen key understood by ``action_show_screen``
            (e.g. ``"workspace"``, ``"a2l"``); also the rail item's
            ``1``-``8`` keymap key is its 1-based position.
        glyph (str): The Unicode glyph rendered by default (LLR-001.3).
        ascii_glyph (str): The single-character ASCII fallback glyph for
            terminals that cannot render the Unicode glyph (LLR-001.3).
        label (str): Human-readable screen name shown beside the glyph.

    Returns:
        None

    Data Flow:
        - Static data only; reads no engine state.

    Dependencies:
        Used by:
            - ``RAIL_ENTRIES``
            - ``RailItem`` / ``Rail``

    Example:
        >>> RailEntry("workspace", "◫", "#", "Workspace").label
        'Workspace'
    """

    key: str
    glyph: str
    ascii_glyph: str
    label: str


#: The eight ordered Direction B rail items on keys ``1``-``8`` (LLR-001.1).
#: The glyph / ascii_glyph columns are the normative LLR-001.3 mapping table:
#: Workspace=(U+25EB,#), A2L=(U+2261,=), MAC=(U+25C9,@), Map=(U+25A4,M),
#: Issues=(!,!), Patch=(U+270E,P), Diff=(U+23DA,D), Flow=(U+2726,F).
RAIL_ENTRIES: tuple[RailEntry, ...] = (
    RailEntry("workspace", "◫", "#", "Workspace"),
    RailEntry("a2l", "≡", "=", "A2L Explorer"),
    RailEntry("mac", "◉", "@", "MAC View"),
    RailEntry("map", "▤", "M", "Memory Map"),
    RailEntry("issues", "!", "!", "Issues Report"),
    RailEntry("patch", "✎", "P", "Patch Editor"),
    RailEntry("diff", "⏚", "D", "A2B Diff"),
    RailEntry("flow", "✦", "F", "Flow Builder"),
)


class RailItem(Static, can_focus=True):
    """One selectable row in the activity rail.

    Summary:
        Renders a single rail item (its glyph and label) as a focusable
        ``Static`` row. Tracks whether it is the active item via the
        ``-active`` CSS class and whether it renders the Unicode glyph or
        the ASCII fallback. Emits ``RailItem.Selected`` (carrying the
        screen key) when clicked.

    Args:
        entry (RailEntry): The rail item this row represents.
        position (int): 1-based rail position; also the item's ``1``-``8``
            keymap key.
        active (bool): When True the row is composed with the ``-active``
            accent marker. Defaults to False.
        ascii_mode (bool): When True the row renders ``entry.ascii_glyph``
            instead of ``entry.glyph`` (LLR-001.3 fallback). Defaults to
            False (Unicode default).

    Returns:
        None

    Data Flow:
        - Composition only; reads no engine state.
        - A click posts a ``RailItem.Selected`` message up to ``Rail`` /
          ``S19TuiApp``; the row does not route navigation itself.

    Dependencies:
        Uses:
            - ``RailEntry``
        Used by:
            - ``Rail``

    Example:
        >>> item = RailItem(RAIL_ENTRIES[0], 1, active=True)
        >>> item.entry.key
        'workspace'
    """

    class Selected(Message):
        """Posted when a rail item is clicked; carries the target screen key."""

        def __init__(self, key: str) -> None:
            super().__init__()
            self.key = key

    def __init__(
        self,
        entry: RailEntry,
        position: int,
        active: bool = False,
        ascii_mode: bool = False,
    ) -> None:
        self.entry = entry
        self.position = position
        self.ascii_mode = ascii_mode
        super().__init__(
            self._render_label(entry, ascii_mode),
            id=f"rail_item_{entry.key}",
            classes="rail-item",
            markup=False,
        )
        if active:
            self.add_class("-active")

    @staticmethod
    def _render_label(entry: RailEntry, ascii_mode: bool) -> str:
        """Build the ``"<position-key> <glyph>  <label>"`` row text.

        Args:
            entry (RailEntry): The rail item being rendered.
            ascii_mode (bool): When True use ``entry.ascii_glyph``.

        Returns:
            str: The plain row text (``markup=False`` — no Rich markup).
        """
        glyph = entry.ascii_glyph if ascii_mode else entry.glyph
        return f"{glyph}  {entry.label}"

    @property
    def current_glyph(self) -> str:
        """Return the glyph currently rendered (Unicode or ASCII fallback)."""
        return self.entry.ascii_glyph if self.ascii_mode else self.entry.glyph

    def on_click(self) -> None:
        """Post ``RailItem.Selected`` so the app routes to this item's screen."""
        self.post_message(self.Selected(self.entry.key))


class Rail(Widget):
    """Vertical activity rail listing the eight Direction B screens.

    Summary:
        Composes the eight ordered ``RailItem`` rows (LLR-001.1) and keeps
        exactly one of them marked active with the ``-active`` accent
        marker (LLR-001.2). It is a presentational widget: clicking a row
        bubbles a ``Rail.Selected`` message to ``S19TuiApp``; the app does
        the routing and calls ``set_active`` to move the marker. The rail
        never calls the engine.

    Args:
        entries (tuple[RailEntry, ...]): The ordered rail items. Defaults
            to ``RAIL_ENTRIES`` (the eight Direction B screens).
        active (str): The screen key of the item active at startup.
            Defaults to ``"workspace"`` (LLR-001.2 — Workspace active at
            startup).
        ascii_mode (bool): When True every item renders its ASCII-fallback
            glyph (LLR-001.3). Defaults to False (Unicode default).

    Returns:
        None

    Data Flow:
        - ``compose`` yields one ``RailItem`` per entry, marking the
          startup-active one.
        - ``set_active`` clears the previous ``-active`` marker and sets it
          on the target item — keeping the single-active invariant.
        - A ``RailItem.Selected`` click is re-posted as ``Rail.Selected``;
          ``S19TuiApp`` handles it and routes the navigation.

    Dependencies:
        Uses:
            - ``RailEntry`` / ``RailItem`` / ``RAIL_ENTRIES``
        Used by:
            - ``S19TuiApp.compose`` (mounted into ``#rail_slot``)

    Example:
        >>> rail = Rail()
        >>> rail.active_key
        'workspace'
    """

    class Selected(Message):
        """Posted when a rail screen is selected; carries the target screen key."""

        def __init__(self, key: str) -> None:
            super().__init__()
            self.key = key

    def __init__(
        self,
        entries: tuple[RailEntry, ...] = RAIL_ENTRIES,
        active: str = "workspace",
        ascii_mode: bool = False,
    ) -> None:
        super().__init__(id="activity_rail")
        self._entries = entries
        self.active_key = active
        self.ascii_mode = ascii_mode

    def compose(self) -> ComposeResult:
        with Vertical():
            for position, entry in enumerate(self._entries, start=1):
                yield RailItem(
                    entry,
                    position,
                    active=(entry.key == self.active_key),
                    ascii_mode=self.ascii_mode,
                )

    def set_active(self, key: str) -> None:
        """
        Summary:
            Move the single active marker to the rail item for ``key``,
            clearing it from the previously active item (LLR-001.2).

        Args:
            key (str): The screen key of the item to mark active. An
                unknown key is ignored (the marker does not move).

        Returns:
            None

        Data Flow:
            - Removes the ``-active`` class from every rail item, then adds
              it to the target item — guaranteeing exactly one active item.

        Dependencies:
            Used by:
                - ``S19TuiApp.action_show_screen`` (key and click paths)

        Example:
            >>> # app.query_one(Rail).set_active("mac")
        """
        if not any(entry.key == key for entry in self._entries):
            return
        self.active_key = key
        for item in self.query(RailItem):
            if item.entry.key == key:
                item.add_class("-active")
            else:
                item.remove_class("-active")

    def on_rail_item_selected(self, event: RailItem.Selected) -> None:
        """Re-post a ``RailItem`` click as a ``Rail.Selected`` for the app."""
        event.stop()
        self.post_message(self.Selected(event.key))
