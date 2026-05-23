"""Top command-bar widget for the s19tui Direction B "Rail + Command" view.

This module is the home for the Direction B command bar introduced by
batch-02-direction-b-restyle, increment 4:

  - ``PaletteEntry`` — the immutable description of one command-palette
    command (visible label + the ``S19TuiApp`` action id it dispatches);
  - ``CommandBar`` — the persistent top bar exposing the project / A2L
    context labels (relocated from the old Status tile, LLR-011.3), a
    type-to-filter command palette (``Ctrl+K``, LLR-003.2 / LLR-003.3), a
    find input (``/``, LLR-004.1) and a go-to-address input (``g``,
    LLR-004.2).

The command bar is a presentational widget (s19_app CLAUDE.md TUI
architecture): it composes inputs and emits messages — ``CommandBar.Find``,
``CommandBar.Goto`` and ``CommandBar.PaletteAction`` — and never calls the
engine, parses an address, decodes a search string, or writes to the log
(LLR-004.6 / LLR-004.2 / LLR-013.3). ``S19TuiApp`` owns the routing: it
hands the find / go-to text to the existing validated ``find_string_in_mem``
/ ``_handle_goto`` handlers and dispatches palette actions via ``run_action``.
"""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Input, Label, ListItem, ListView


@dataclass(frozen=True)
class PaletteEntry:
    """Immutable description of a single command-palette command.

    Summary:
        Pairs a human-readable command label with the ``S19TuiApp`` action
        id it dispatches, so the palette can run the *same* handler as the
        command's key binding (LLR-003.2 parity).

    Args:
        label (str): The text shown in the palette list and matched by the
            type-to-filter search.
        action (str): The action id passed to ``S19TuiApp.run_action``
            (e.g. ``"load_file"``, ``"show_screen('a2l')"``).

    Returns:
        None

    Data Flow:
        - Static data only; reads no engine state.

    Dependencies:
        Used by:
            - ``CommandBar`` (palette population and dispatch)

    Example:
        >>> PaletteEntry("Load file", "load_file").action
        'load_file'
    """

    label: str
    action: str


class CommandBar(Vertical):
    """Persistent top command bar — palette, find, go-to and context labels.

    Summary:
        Composes the Direction B command bar mounted above the rail and the
        workspace body (LLR-003.1). The bar row carries a ``"›"`` accent
        prompt, the project-name / A2L-filename context labels (LLR-011.3),
        a find ``Input`` and a go-to-address ``Input``. A type-to-filter
        command palette (a trigger ``Input`` plus a ``ListView``) drops down
        below the bar and is hidden until ``Ctrl+K`` opens it. The widget is
        presentational — it emits messages and never touches the engine.

    Args:
        palette_entries (tuple[PaletteEntry, ...]): The ordered command
            list shown in the palette. ``S19TuiApp`` builds this 1:1 from
            its ``BINDINGS`` so every action has a palette entry by
            construction (LLR-003.2).

    Returns:
        None

    Data Flow:
        - ``compose`` yields the bar row (prompt, labels, find, go-to) and
          the hidden palette dropdown (trigger input + list).
        - Typing in the palette trigger filters the listed commands to the
          substring matches (LLR-003.3) — pure view-side string matching.
        - Submitting find / go-to text, or selecting a palette command,
          posts ``CommandBar.Find`` / ``CommandBar.Goto`` /
          ``CommandBar.PaletteAction``; the app does the routing.

    Dependencies:
        Uses:
            - ``PaletteEntry``
        Used by:
            - ``S19TuiApp.compose`` (mounted into ``#command_bar_slot``)

    Example:
        >>> bar = CommandBar((PaletteEntry("Quit", "quit"),))
        >>> bar.id
        'command_bar'
    """

    class Find(Message):
        """Posted when find text is submitted; carries the raw typed text."""

        def __init__(self, query: str) -> None:
            super().__init__()
            self.query = query

    class Goto(Message):
        """Posted when go-to text is submitted; carries the raw typed text."""

        def __init__(self, address_text: str) -> None:
            super().__init__()
            self.address_text = address_text

    class PaletteAction(Message):
        """Posted when a palette command is chosen; carries its action id."""

        def __init__(self, action: str) -> None:
            super().__init__()
            self.action = action

    def __init__(self, palette_entries: tuple[PaletteEntry, ...]) -> None:
        super().__init__(id="command_bar")
        self._palette_entries = palette_entries
        #: The entries currently listed in the palette after the active
        #: type-to-filter (LLR-003.3); the full set until the user filters.
        self._visible_entries: tuple[PaletteEntry, ...] = palette_entries

    def compose(self) -> ComposeResult:
        with Horizontal(id="command_bar_row"):
            yield Label("›", id="command_bar_prompt", markup=False)
            yield Label("Project: (none)", id="cmdbar_project", markup=False)
            yield Label("A2L: (none)", id="cmdbar_a2l", markup=False)
            yield Input(placeholder="Find ASCII text  ( / )", id="find_input")
            yield Input(placeholder="Goto 0xADDR  ( g )", id="cmdbar_goto_input")
        with Vertical(id="command_palette", classes="hidden"):
            yield Input(placeholder="Command palette  (Ctrl+K)", id="palette_input")
            yield ListView(id="palette_list")

    def on_mount(self) -> None:
        """Populate the palette list with the full command set on mount."""
        self._render_palette(self._palette_entries)

    def _render_palette(self, entries: tuple[PaletteEntry, ...]) -> None:
        """Rebuild the palette ``ListView`` rows from ``entries``.

        Args:
            entries (tuple[PaletteEntry, ...]): The (already filtered)
                commands to show, in order.

        Returns:
            None

        Data Flow:
            - Clears the list, then appends one ``ListItem`` per entry,
              stashing the entry's action id on ``ListItem.data`` so a
              selection can dispatch it.
        """
        palette_list = self.query_one("#palette_list", ListView)
        palette_list.clear()
        for entry in entries:
            item = ListItem(Label(entry.label, markup=False))
            item.data = entry.action
            palette_list.append(item)
        self._visible_entries = entries

    def open_palette(self) -> None:
        """Show the palette dropdown and focus its filter input (LLR-004.3)."""
        self.query_one("#command_palette").remove_class("hidden")
        palette_input = self.query_one("#palette_input", Input)
        palette_input.value = ""
        self._render_palette(self._palette_entries)
        palette_input.focus()

    def close_palette(self) -> None:
        """Hide the palette dropdown."""
        self.query_one("#command_palette").add_class("hidden")

    @property
    def palette_is_open(self) -> bool:
        """Return True while the palette dropdown is visible."""
        return not self.query_one("#command_palette").has_class("hidden")

    def visible_palette_labels(self) -> list[str]:
        """Return the labels currently listed in the palette (post-filter)."""
        return [entry.label for entry in self._visible_entries]

    def visible_palette_actions(self) -> list[str]:
        """Return the action ids currently listed in the palette (post-filter)."""
        return [entry.action for entry in self._visible_entries]

    def focus_find(self) -> None:
        """Move keyboard focus to the find input (LLR-004.1)."""
        self.query_one("#find_input", Input).focus()

    def focus_goto(self) -> None:
        """Move keyboard focus to the go-to-address input (LLR-004.2)."""
        self.query_one("#cmdbar_goto_input", Input).focus()

    def set_context_labels(self, project: str, a2l: str) -> None:
        """
        Summary:
            Refresh the project-name / A2L-filename context labels shown in
            the command bar (LLR-011.3).

        Args:
            project (str): Project name to display, or a "(none)" sentinel.
            a2l (str): A2L filename to display, or a "(none)" sentinel.

        Returns:
            None

        Data Flow:
            - Writes the two display strings into the bar's context labels;
              reads no engine state and writes nothing to the log.

        Dependencies:
            Used by:
                - ``S19TuiApp.update_project_labels``
        """
        self.query_one("#cmdbar_project", Label).update(f"Project: {project}")
        self.query_one("#cmdbar_a2l", Label).update(f"A2L: {a2l}")

    def on_input_changed(self, event: Input.Changed) -> None:
        """Filter the palette command list as the user types (LLR-003.3)."""
        if event.input.id != "palette_input":
            return
        event.stop()
        needle = event.value.strip().lower()
        if not needle:
            self._render_palette(self._palette_entries)
            return
        matches = tuple(
            entry
            for entry in self._palette_entries
            if needle in entry.label.lower()
        )
        self._render_palette(matches)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Route a submitted find / go-to / palette input to an app message."""
        if event.input.id == "find_input":
            event.stop()
            self.post_message(self.Find(event.value))
        elif event.input.id == "cmdbar_goto_input":
            event.stop()
            self.post_message(self.Goto(event.value))
        elif event.input.id == "palette_input":
            event.stop()
            visible = self._current_filtered_entries(event.value)
            if visible:
                self._dispatch_palette_entry(visible[0])

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Dispatch the chosen palette command via a ``PaletteAction`` message."""
        if event.list_view.id != "palette_list":
            return
        event.stop()
        if event.item is None:
            return
        action = getattr(event.item, "data", None)
        if isinstance(action, str):
            self.close_palette()
            self.post_message(self.PaletteAction(action))

    def _current_filtered_entries(self, filter_text: str) -> tuple[PaletteEntry, ...]:
        """Return the palette entries matching ``filter_text`` (substring)."""
        needle = filter_text.strip().lower()
        if not needle:
            return self._palette_entries
        return tuple(
            entry
            for entry in self._palette_entries
            if needle in entry.label.lower()
        )

    def _dispatch_palette_entry(self, entry: PaletteEntry) -> None:
        """Close the palette and post the entry's action for the app to run."""
        self.close_palette()
        self.post_message(self.PaletteAction(entry.action))
