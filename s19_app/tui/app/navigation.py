"""s19_app.tui.app.navigation — S19TuiApp mixin: navigation (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from typing import Optional
from textual import events
from textual.binding import Binding
from textual.widget import Widget
from textual.widgets import DataTable, Input, ListView, TextArea
from ..command_bar import CommandBar, PaletteEntry
from ..rail import Rail, RailItem
from ..screens import LegendScreen
from ..flow_screens import FlowExecutionPanel
from ..screens_directionb import EmptyStatePanel
from ..segment_split_view import SplitJoinWindow
from . import deps
from .shared import (A2LDetailCard)


class NavigationMixin:

    def _is_layout_visible(self, layout_id: str) -> bool:
        """Return True when a layout container is currently visible."""
        return "hidden" not in self.query_one(layout_id).classes

    def _active_view_name(self) -> str:
        """
        Summary:
            Report which legacy view (``main`` / ``alt`` / ``mac``) is the
            visible Direction B rail screen.

        Args:
            None

        Returns:
            str: ``"alt"`` when A2L Explorer is visible, ``"mac"`` when MAC
            View is visible, otherwise ``"main"`` (Workspace or any other
            rail screen).

        Data Flow:
            - Reads the ``.hidden`` class on the ``#screen_a2l`` /
              ``#screen_mac`` rail screen containers.

        Dependencies:
            Used by:
                - The paging actions (``action_page_*``, ``action_hex_page_*``)
                  that route by active view.
        """
        if self._is_layout_visible("#screen_a2l"):
            return "alt"
        if self._is_layout_visible("#screen_mac"):
            return "mac"
        return "main"

    def _focus_activity_rail(self) -> None:
        """Move keyboard focus to the active activity-rail item, if present."""
        try:
            rail = self.query_one(Rail)
        except Exception:
            return
        for item in rail.query(RailItem):
            if item.has_class("-active"):
                item.focus()
                return

    def _build_palette_entries(self) -> tuple[PaletteEntry, ...]:
        """
        Summary:
            Build the command-palette command list from ``BINDINGS`` so
            every key-bound action has exactly one palette entry that
            dispatches the same action id (LLR-003.2 parity by construction),
            except the ``q`` binding's ``help_quit`` which projects to
            ``PaletteEntry("Quit", "quit")`` so palette Quit keeps the
            unchanged ``action_quit`` (Inc 1b, R-COPY.24).

        Args:
            None

        Returns:
            tuple[PaletteEntry, ...]: One ``PaletteEntry`` per ``BINDINGS``
            action id (de-duplicated — the ``ctrl+l``/``l`` aliases share
            one action and one entry) plus the resurfaced "Viewer settings"
            command.

        Data Flow:
            - Walks ``BINDINGS``, keeping the first description seen for
              each distinct action id so aliased keys collapse to one entry.
            - Projects the ``help_quit`` binding to ``PaletteEntry("Quit",
              "quit")`` (never ``help_quit``) so palette Quit still exits
              immediately while idle.
            - Appends ``EXTRA_PALETTE_ENTRIES`` (the keyboard-reachable
              viewer settings command).

        Dependencies:
            Used by:
                - ``compose`` (the ``CommandBar`` palette)
        """
        entries: list[PaletteEntry] = []
        seen_actions: set[str] = set()
        for binding in self.BINDINGS:
            if isinstance(binding, Binding):
                action = binding.action
                description = binding.description
            else:
                action = binding[1]
                description = binding[2]
            if action in seen_actions:
                continue
            seen_actions.add(action)
            if action == "help_quit":
                entries.append(PaletteEntry("Quit", "quit"))
                continue
            entries.append(PaletteEntry(description, action))
        for label, action in self.EXTRA_PALETTE_ENTRIES:
            entries.append(PaletteEntry(label, action))
        return tuple(entries)

    def action_show_screen(self, screen_key: str) -> None:
        """
        Summary:
            Activate a Direction B rail screen, showing its container and
            hiding the other eight (LLR-002.1).

        Args:
            screen_key (str): One of the keys of ``SCREEN_CONTAINER_IDS``
                (``workspace`` / ``a2l`` / ``mac`` / ``map`` / ``issues`` /
                ``patch`` / ``diff`` / ``flow`` / ``checks``).

        Returns:
            None

        Raises:
            None: An unknown ``screen_key`` is ignored (no screen change).

        Data Flow:
            - Reuses the existing ``.hidden``-class show/hide mechanism: the
              target ``#screen_*`` container loses ``.hidden`` and every
              other rail screen gains it. No ``push_screen`` is used, so the
              persistent command bar, rail and footer stay mounted.
            - Moves the activity rail's single active marker to the target
              screen via ``Rail.set_active`` (LLR-001.2), so the rail
              reflects the active screen for both the ``1``-``9`` key path
              and the rail-click path.

        Dependencies:
            Uses:
                - ``SCREEN_CONTAINER_IDS``
                - ``Rail.set_active``
            Used by:
                - The ``1``-``9`` key bindings
                - ``on_rail_selected`` (the activity rail click path)

        Example:
            >>> # bound to key "2"
            >>> app.action_show_screen("a2l")
        """
        if screen_key not in self.SCREEN_CONTAINER_IDS:
            return
        self._active_screen_key = screen_key  # N1: track for the Legend scope.
        target_id = self.SCREEN_CONTAINER_IDS[screen_key]
        # E3 A10-01 / D-8: a landing is scheduled only when this call
        # changes what is shown — the target container was hidden, or the
        # palette-first Split / Join / Export window was displayed (the
        # swap hides it below). A call that re-shows the already-shown
        # window schedules no landing and a healthy focus there stays
        # (AR2-4).
        target_container = self.query_one(f"#{target_id}")
        changed = target_container.has_class("hidden")
        try:
            split_join = self.query_one("#screen_split_join")
        except Exception:
            split_join = None
        if split_join is not None and not split_join.has_class("hidden"):
            changed = True
        for container_id in self.SCREEN_CONTAINER_IDS.values():
            container = self.query_one(f"#{container_id}")
            if container_id == target_id:
                container.remove_class("hidden")
            else:
                container.add_class("hidden")
        # batch-95 change 4 (LLR-135.6): any rail key closes the
        # palette-first Split / Join / Export window — it is not in
        # SCREEN_CONTAINER_IDS (the TC-B79-03 census stays at the ten rail
        # screens), so the swap hides it here.
        try:
            self.query_one("#screen_split_join").add_class("hidden")
        except Exception:
            pass
        self.query_one(Rail).set_active(screen_key)
        self._apply_empty_state()
        if screen_key == "diff":
            self._prefill_diff_variants()
            self._prefill_diff_check_files()
        elif screen_key == "patch":
            self._prefill_patch_change_files()
            # batch-102 Inc 5 (R-B102-PE-001): the A2L picker populates on
            # entry — the ``_prefill_check_editor`` idiom; the signature
            # keeps the filter/page/highlight across re-entries.
            self._prefill_patch_editor()
        elif screen_key == "check_editor":
            # batch-94 (LLR-001.2): the collector is populated on entry — the
            # suffix-distinguished spec dropdown from the folder scan, and the
            # A2L parameter picker from the loaded A2L.
            self._prefill_check_editor()
        elif screen_key == "checks":
            # Lazy read-only mirror rebuilt on entry (batch-49, LLR-083.6);
            # checks state changes only on run/undo/redo, so no load hook.
            self.update_checks_view()
        elif screen_key == "flow_execution":
            # batch-94 Inc-003 (LLR-021.2): the set picker repopulates on
            # entry, the ``_prefill_check_editor`` idiom.
            self._prefill_flow_execution_sets()
        # E3 A10-01 / D-8 (1): a focused widget sitting in a window the
        # swap just hid is cleared at once (a class test, valid before any
        # layout), so single keys reach the app bindings until the landing.
        try:
            focused = self.default_screen.focused
            if focused is not None:
                for ancestor in focused.ancestors:
                    if ancestor.id in self._WINDOW_CONTAINER_IDS:
                        if ancestor.has_class("hidden"):
                            self.default_screen.set_focus(None)
                            focused = None
                        break
        except Exception:
            focused = None
        if changed:
            self.call_after_refresh(
                self._land_focus, focused, self._active_screen_key, on_switch=True
            )
        # batch-97 Inc-8 (D29): the key bar's row 2 follows the window.
        self.refresh_bindings()

    def key_condition(self, when: str) -> bool:
        """Evaluate a window-key ``when`` condition for the key bar (I-10);
        a false one paints that key dimmed."""
        if when == "has_image":
            return self.current_file is not None
        if when == "patch_history":
            return self._patch_history_action_allowed()
        if when == "has_variants":
            return self._variant_set is not None and bool(self._variant_set.variants)
        raise ValueError(f"unknown key condition {when!r}")

    def action_confirm_attention(self) -> None:
        """``c`` on Flow Execution: confirm the attention lane's waiting
        external step (LLR-147.13) and write the panel's one-line answer to
        the status line (D15)."""
        panel = self.query_one("#fx_panel", FlowExecutionPanel)
        self.set_status(panel.confirm_attention())

    def action_open_split_join_export(self) -> None:
        """
        Summary:
            Open the Split / Join / Export screen (batch-95 change 4,
            HLR-135; LLR-135.6): the palette-first, rail-less entry — the
            ``^K`` palette command named exactly "Split / Join / Export"
            dispatches here. The window rides the rail body beside the ten
            rail screens but is NOT in ``SCREEN_CONTAINER_IDS`` (ruling
            Q6/7a pins zero rail keys; TC-B79-03 pins that map's census at
            the ten rail screens) — this action hides all ten rail
            containers, shows ``#screen_split_join``, and remembers the
            active rail screen so ``Esc`` (the window's own binding) closes
            back to exactly where the operator was.

        Args:
            None

        Returns:
            None

        Data Flow:
            - ``_active_screen_key`` is stashed on
              ``_split_join_return_screen`` and then set to
              ``"split_join"`` so the find/go-to keys degrade to the
              honest "no such input on this screen" status notice while the
              window is up (the Legend scope falls back to the full table
              for an unmapped key, the shipped fallback). The rail's active
              marker is untouched — there is no rail item for this screen.
            - The window's ``refresh_window`` re-reads the loaded image +
              A2L and focuses the range table.

        Dependencies:
            Uses:
                - ``SplitJoinWindow`` / ``SCREEN_CONTAINER_IDS``
            Used by:
                - The ``^K`` palette entry "Split / Join / Export"
                - ``action_show_screen`` (the reverse hide on any rail key)
        """
        self._split_join_return_screen = self._active_screen_key
        for container_id in self.SCREEN_CONTAINER_IDS.values():
            self.query_one(f"#{container_id}").add_class("hidden")
        window = self.query_one("#screen_split_join", SplitJoinWindow)
        window.remove_class("hidden")
        self._active_screen_key = "split_join"
        window.refresh_window()
        self.refresh_bindings()

    def action_show_legend(self) -> None:
        """
        Summary:
            Open the read-only classification-legend modal (HLR-023). The
            single Legend surface shared by every colour-coded view: the
            ``k`` key binding (reachable from the A2L explorer, where the
            dense filter row has no geometry budget for a button — C-13)
            and the MAC / Issues "Legend" buttons all route here.

        Returns:
            None

        Data Flow:
            - Pushes a fresh :class:`LegendScreen`, which renders
              ``legend.LEGEND_TABLE`` and dismisses itself on Close.

        Dependencies:
            Uses:
                - ``LegendScreen``
            Used by:
                - The ``k`` key binding
                - ``on_button_pressed`` (the MAC / Issues Legend buttons)
        """
        # N1: scope the legend to the active screen's section(s); a screen with
        # no mapped section falls back to the full table (AC-3). N8: also pass
        # the active view key so the modal renders the per-view example card and
        # the map's entropy band key (LLR-N8-1.4).
        sections = self._SCREEN_LEGEND_SECTIONS.get(self._active_screen_key)
        self.push_screen(
            LegendScreen(sections=sections, view_key=self._active_screen_key)
        )

    def _apply_empty_state(self) -> None:
        """
        Summary:
            Toggle the no-file empty-state panels of the content-bearing rail
            screens — show the ``EmptyStatePanel`` and hide the real content
            while no file is loaded, and the reverse once a file is present
            (LLR-002.3).

        Args:
            None

        Returns:
            None

        Data Flow:
            - For each screen in ``_EMPTY_STATE_SCREENS``, resolve its real
              content child and its ``EmptyStatePanel``.
            - When ``current_file`` is unset, hide the content child and show
              the panel; otherwise show the content and hide the panel.
            - A missing widget tree (app not yet mounted) is tolerated — the
              helper is a no-op then, matching ``_focus_activity_rail``.

        Dependencies:
            Uses:
                - ``EmptyStatePanel``
            Used by:
                - ``action_show_screen``
                - ``_apply_prepared_load`` (post-load refresh)
        """
        no_file = self.current_file is None
        for screen_id, content_id in self._EMPTY_STATE_SCREENS:
            try:
                screen = self.query_one(f"#{screen_id}")
                content = screen.query_one(f"#{content_id}")
                panel = screen.query_one(EmptyStatePanel)
            except Exception:
                # App not mounted (e.g. headless unit tests of the load
                # pipeline) — empty-state has no tree to toggle yet.
                continue
            content.set_class(no_file, "hidden")
            panel.set_class(not no_file, "hidden")

    def on_rail_selected(self, event: Rail.Selected) -> None:
        """
        Summary:
            Route an activity-rail click to ``action_show_screen`` (LLR-002.1).

        Args:
            event (Rail.Selected): The rail-selection message carrying the
                clicked item's screen key.

        Returns:
            None

        Data Flow:
            - Delegates to ``action_show_screen`` so the rail-click path and
              the ``1``-``8`` key path share one routing implementation
              (including the active-marker move).

        Dependencies:
            Uses:
                - ``action_show_screen``
            Used by:
                - Textual message dispatch (``Rail.Selected`` bubbles up)
        """
        self.action_show_screen(event.key)

    def action_focus_palette(self) -> None:
        """Open and focus the command-bar palette (``Ctrl+K`` — LLR-004.3)."""
        self.query_one(CommandBar).open_palette()

    def action_focus_find(self) -> None:
        """Focus the ACTIVE screen's own find input (``/`` — LLR-119.1)."""
        self._focus_local_input("find")

    def action_focus_goto(self) -> None:
        """Focus the ACTIVE screen's own go-to input (``g`` — LLR-119.1)."""
        self._focus_local_input("goto")

    def _focus_local_input(self, kind: str) -> None:
        """Move focus to the active screen's find or go-to input (LLR-119.1/.2).

        Summary:
            Resolve the target from ``_active_screen_key`` through
            ``_FIND_GOTO_INPUTS`` and focus it; when the active screen owns no
            such input, append exactly one line to the log tail and return
            without raising.

        Args:
            kind (str): ``"find"`` or ``"goto"`` — selects which half of the
                screen's ``(find, goto)`` pair to focus.

        Returns:
            None

        Raises:
            None: a screen with no entry, an unmounted tree and an unresolvable
                target all degrade to a notice or a no-op.

        Data Flow:
            - Read ``_active_screen_key``, look it up in ``_FIND_GOTO_INPUTS``,
              and focus the resolved id. **Never queries which inputs exist**:
              all eight resolve on every screen because ``action_show_screen``
              only toggles a ``hidden`` class, so a presence-based resolution
              would be green while writing into another pane.
            - No entry -> ``set_status`` (the LOG TAIL, not ``#status_text``)
              with exactly one line naming the absence. That is the majority
              path: 7 of the 10 screens.

        Dependencies:
            Uses:
                - ``_FIND_GOTO_INPUTS`` / ``_active_screen_key`` / ``set_status``
            Used by:
                - ``action_focus_find`` / ``action_focus_goto``
        """
        targets = self._FIND_GOTO_INPUTS.get(self._active_screen_key)
        if targets is None:
            self.set_status(
                f"This screen has no {'find' if kind == 'find' else 'go-to'} "
                f"input. Use the rail to switch to Workspace, A2L or MAC."
            )
            return
        target_id = targets[0] if kind == "find" else targets[1]
        try:
            self.query_one(f"#{target_id}", Input).focus()
        except Exception:
            # TC-B78-41: before mount there is no tree to focus into. A no-op,
            # matching `_refresh_loaded_panel` / `update_project_labels`.
            return

    def _focus_needs_rehome(self, widget: Widget) -> bool:
        """
        Summary:
            Decide whether the focused widget violates HLR-166's landing
            rule and the load tail must re-home it onto the active window's
            focus target (LLR-166.1): the painted region has zero area, the
            widget is a STALE text input (an ``Input`` / ``TextArea`` in a
            hidden window or of area 0 — LED .58 (c)), or it sits inside a
            window that is not displayed. A region row takes the same rule:
            the visible Map row LLR-116.5 lands on is never stale, so it
            stays; a row left in a hidden Map window is re-homed (R3-1).

        Args:
            widget (Widget): The currently focused widget.

        Returns:
            bool: ``True`` when the caller must move the focus to the
            active window's target.

        Data Flow:
            - No widget type is exempt (review R3-1). The Map window's
              LLR-116.5 row paints a region in a displayed window, so it
              is healthy and keeps the focus (HLR-115); a row left focused
              in a HIDDEN Map window paints area 0 and still swallows
              ``up`` / ``down`` / ``enter``, so it is re-homed like any
              other stale widget.
            - Text inputs take the same stale rule as every other widget
              (LED .58 (c)), so no separate branch exists for them: only a
              STALE input — in a hidden window or of area 0 — is re-homed.
              A VISIBLE input
              in the active window — a per-window Find field — is where
              the operator is typing and keeps the focus; the command
              palette's ``#palette_input`` sits in no window and falls
              through to the same ``False``.
            - A zero-area region is the executed P-16 shape: the hidden
              Split / Join table holds the focus (``display: none`` paints
              no region) and the single keys die there.
            - The window lookup walks the ancestor chain against
              ``_WINDOW_CONTAINER_IDS``; a widget in the
              persistent chrome (the rail, the command bar) sits in no
              window and is never re-homed by this rule.

        Dependencies:
            Uses:
                - ``_WINDOW_CONTAINER_IDS``
            Used by:
                - ``_rehome_focus_after_load``
        """
        if widget.region.area <= 0:
            return True
        for ancestor in widget.ancestors:
            if ancestor.id in self._WINDOW_CONTAINER_IDS:
                return ancestor.has_class("hidden")
        return False

    def _fallback_focus_target(self, target: Widget) -> Widget:
        """
        Summary:
            Resolve the landing widget when the active window's declared
            focus target paints no region (an empty-state window whose
            target is hidden or zero-area): the window's first visible,
            focusable, non-text widget, else the rail's active entry
            (LLR-166.1 — the focus must always land where the operator can
            work; the rail is always visible and keeps the single keys
            reaching the app bindings).

        Args:
            target (Widget): The declared target that failed the
                visibility check.

        Returns:
            Widget: The fallback widget — never an ``Input`` /
            ``TextArea``; ``target`` itself when the app has no ``Rail``
            (a landing during teardown).

        Data Flow:
            - The window is the focused-out ancestor whose id is in
              ``_WINDOW_CONTAINER_IDS``; its descendants are scanned in
              document order, so the fallback is deterministic.
            - A widget with a zero painted region (inside a hidden
              sub-container, not yet laid out) is not a landing spot and
              is skipped, exactly like the declared target.
            - The rail's active entry is the ``RailItem`` carrying the
              ``-active`` marker (LLR-001.2).
            - With no ``Rail`` in the tree (a landing that runs while the
              app exits, SE5-5) the lookup is guarded and ``target`` — the
              widget that failed the visibility check — is returned.

        Dependencies:
            Uses:
                - ``_WINDOW_CONTAINER_IDS`` / ``Rail`` / ``RailItem``
            Used by:
                - ``_resolve_focus_target``
        """
        window = next(
            (
                ancestor
                for ancestor in target.ancestors
                if ancestor.id in self._WINDOW_CONTAINER_IDS
            ),
            None,
        )
        if window is not None:
            for candidate in window.query(Widget):
                if (
                    candidate.focusable
                    and candidate.region.area > 0
                    and not isinstance(candidate, (Input, TextArea))
                ):
                    return candidate
        try:
            rail = self.query_one(Rail)
        except Exception:
            # Inc 10a (E5, SE5-5): a landing that runs during teardown finds
            # no rail; it must not raise at exit.
            return target
        for item in rail.query(RailItem):
            if item.has_class("-active"):
                return item
        return target

    def _resolve_focus_target(self) -> "Widget | None":
        """
        Summary:
            Resolve the active window's focus landing widget: the declared
            target (``_FOCUS_TARGETS``) when it is focusable and paints a
            region, else the empty-state fallback
            (``_fallback_focus_target``).

        Args:
            None

        Returns:
            Optional[Widget]: The landing widget, or ``None`` when the
            active window declares no target or the tree is not mounted.

        Dependencies:
            Uses:
                - ``_FOCUS_TARGETS`` / ``_fallback_focus_target``
            Used by:
                - ``_rehome_focus_after_load``
        """
        target_id = self._FOCUS_TARGETS.get(self._active_screen_key)
        if target_id is None:
            return None
        try:
            target = self.query_one(f"#{target_id}")
        except Exception:
            # Before mount there is no tree to focus into (TC-B78-41's
            # no-op shape, matching `_focus_local_input`).
            return None
        if not target.focusable or target.region.area <= 0:
            # R2-4: a target that is painted but not focusable (a disabled
            # widget) would still be a silent ``set_focus`` no-op — fall
            # back exactly like a zero-area (empty-state) target.
            target = self._fallback_focus_target(target)
        return target

    def _rehome_focus_after_load(self) -> None:
        """
        Summary:
            Re-home the keyboard focus at the end of a load tail
            (LLR-166.1 / LLR-166.2): when the focused widget fails
            ``_focus_needs_rehome``, move the focus to the active window's
            declared target (``_FOCUS_TARGETS``); a healthy focus is left
            untouched. ``watch_current_file`` re-focuses the Split / Join
            table (``refresh_window`` does it only while that window is
            shown), so without this the tail of a load can leave the focus
            on a hidden zero-area widget (CW-U-2).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Reads ``default_screen.focused`` — never ``self.focused`` —
              so a widget inside an open modal is never judged or moved:
              the modal keeps its focus and the rule only re-homes behind
              it.
            - ``None`` (nothing focused) re-homes onto the target, like a
              violation would.
            - Resolves the target through ``_active_screen_key`` — the
              displayed window: a rail screen or the Split / Join / Export
              window alike.
            - A target that is not focusable or paints no region (an
              empty-state window) lands on ``_fallback_focus_target``
              instead of an invisible widget.
            - On the Map window the tail's landing is the panel, and the
              panel's LLR-116.5 selection-follow hook — queued by
              ``update_memory_map`` and running AFTER the tail — then
              moves the focus onto the auto-selected region row. That row
              is the Map window's landing (LED .58 (a)); a visible row is
              healthy, so a later tail leaves it (``_focus_needs_rehome``),
              and the deferred re-assertion fix pass 1 added to fight the hook is
              GONE (LED .58 (b)) — it is what broke the Map's arrow keys.
            - The landing is synchronous through ``Screen.set_focus`` —
              ``Widget.focus()`` only QUEUES the focus (a ``call_later``)
              and the callbacks queued behind this tail would then
              override it in order; ``set_focus`` lands now, so the tail's
              focus is the state the queue drains into.
            - An unmounted tree is a documented no-op at both ends — the
              focus read (no screen) and an unresolvable target — matching
              ``_refresh_loaded_panel`` / ``update_project_labels``.

        Dependencies:
            Uses:
                - ``_focus_needs_rehome`` / ``_resolve_focus_target``
            Used by:
                - The image load tail ``_step_finalize`` and the A2L load
                  tail of ``load_a2l_from_path``
        """
        try:
            focused = self.default_screen.focused
        except Exception:
            # Before mount there is no screen to read the focus from
            # (TC-B78-41's no-op shape, matching `_focus_local_input`;
            # test_apply_prepared_load_chains_updates_via_call_later
            # drives `_step_finalize` on an app that never mounted).
            return
        if focused is not None and not self._focus_needs_rehome(focused):
            return
        target = self._resolve_focus_target()
        if target is None:
            return
        try:
            target.screen.set_focus(target)
        except Exception:
            # Before mount there is no tree to focus into (TC-B78-41's
            # no-op shape, matching `_focus_local_input`).
            return
        self._note_focus_landing(target)

    def _note_focus_landing(self, target: Widget) -> None:
        """
        Summary:
            Inc 10a E4-R3: remember a landing that did not reach the shown
            window's declared target (a fallback, or E4-R4's A2L switch
            landing), so a completed load can still move it there once it
            is shown.

        Args:
            target (Widget): The widget the landing focused.

        Returns:
            None

        Data Flow:
            - ``_focus_landing_fallback`` becomes ``None`` when ``target``
              carries the shown window's declared id (``_FOCUS_TARGETS``),
              else ``target`` itself (the declared-vs-fallback rule).

        Dependencies:
            Uses:
                - ``_FOCUS_TARGETS`` / ``_active_screen_key``
            Used by:
                - ``_rehome_focus_after_load``,
                  ``_rehome_placeholder_focus_after_load`` and
                  ``_land_focus``
        """
        declared = self._FOCUS_TARGETS.get(self._active_screen_key)
        self._focus_landing_fallback = None if target.id == declared else target

    def _rehome_placeholder_focus_after_load(
        self, switch: Optional[str] = None, *, layout_waits: int = 3
    ) -> None:
        """
        Summary:
            Inc 10a E4-R3 (HLR-166): at the end of a completed load, move a
            focus that sits on a rail item, or on the widget a focus landing
            chose because the shown window's target was not shown, to that
            target once the loaded view shows it. A focus the operator put
            on a real control is kept (R-SHELL-FOCUS.4).

        Args:
            switch (Optional[str]): The window the first call saw; a later
                call for another window does nothing.
            layout_waits (int): How many more refreshes the call may wait
                for the target to get its region.

        Returns:
            None

        Data Flow:
            - Reads ``default_screen.focused`` (a dialog keeps its own
              focus); an unmounted tree is a no-op.
            - The target is ``_FOCUS_TARGETS`` of the shown window — never
              its fallback: a target that stays hidden keeps the focus where
              it is.
            - While the target has no region the call re-schedules itself
              after a refresh, at most ``layout_waits`` times; each call
              acts only while the focus is still a ``RailItem`` or the
              recorded fallback (``_focus_landing_fallback``), and returns
              first when the tree is gone (E4-R5 guard included).

        Dependencies:
            Uses:
                - ``_FOCUS_TARGETS`` / ``_focus_landing_fallback`` /
                  ``_note_focus_landing`` / ``_load_tree_gone``
            Used by:
                - ``_step_finalize`` and the A2L load tail
        """
        if self._load_tree_gone():
            return
        if switch is None:
            switch = self._active_screen_key
        elif switch != self._active_screen_key:
            return
        try:
            focused = self.default_screen.focused
        except Exception:
            return
        if focused is None:
            return
        if not isinstance(focused, RailItem) and focused is not self._focus_landing_fallback:
            return
        try:
            target = self.query_one(f"#{self._FOCUS_TARGETS[switch]}")
        except Exception:
            return
        if target is focused:
            return
        if target.focusable and target.region.area > 0:
            target.screen.set_focus(target)
            self._note_focus_landing(target)
            return
        if layout_waits > 0:
            self.call_after_refresh(
                self._rehome_placeholder_focus_after_load,
                switch,
                layout_waits=layout_waits - 1,
            )

    def _load_tree_gone(self) -> bool:
        """
        Summary:
            Inc 10a E4-R5 (I-D17): ``True`` once the default screen a
            deferred load step renders into is no longer attached — Textual
            reports every node detached once ``App.exit`` has run, and a
            pruned screen has no parent. A tree that never mounted (the
            headless chain test) is not gone: its steps still run.

        Args:
            None

        Returns:
            bool: ``True`` when the default screen is detached, else
            ``False`` (also when the screen cannot be read).

        Data Flow:
            - Reads ``default_screen.is_attached``; an exception reading
              it counts as not gone.

        Dependencies:
            Uses:
                - ``default_screen``
            Used by:
                - ``_rehome_placeholder_focus_after_load``,
                  ``_land_focus`` and the three deferred steps of
                  ``_apply_prepared_load`` (``_step_sections``,
                  ``_step_hex``, ``_step_finalize``)
        """
        try:
            screen = self.default_screen
        except Exception:
            return False
        return not screen.is_attached

    def _land_focus(
        self,
        trigger: Optional[Widget],
        switch: Optional[str],
        *,
        on_switch: bool,
        layout_waits: int = 3,
    ) -> None:
        """
        Summary:
            Land the keyboard focus on the shown window's focus target once
            the window is laid out, moving only when the focus is ``None``,
            stale, or has not moved away from the trigger in the expected
            direction (E3 A10-01 / D-8, AR2-1, AR2-2).

        Args:
            trigger (Optional[Widget]): The widget focused when the landing
                was scheduled (``None`` after a synchronous clear).
            switch (Optional[str]): The ``_active_screen_key`` the landing
                was scheduled for (a switch and, since E5 CR-3, an unload); a
                stale value makes the landing a no-op.
            on_switch (bool): ``True`` for a window switch (move when the
                focus is still the trigger), ``False`` for an unload (move
                when the focus is no longer the trigger).
            layout_waits (int): How many more refreshes the landing may wait
                for the shown window to get its region.

        Returns:
            None

        Data Flow:
            - A landing that runs once the tree is gone (``App.exit`` has
              run) does nothing (E5, SE5-5).
            - An after-refresh callback can run before the layout that gives
              the window just shown its region (Inc 10a E4 integration
              I-D3: ``#screen_mac`` had area 0 at the landing of a two-key
              burst); while the shown window has no region the landing
              re-schedules itself, at most ``layout_waits`` times.
            - Reads ``default_screen.focused`` — never ``self.focused`` —
              so a dialog's own focus is never judged or moved.
            - Resolves the target through ``_resolve_focus_target`` (which
              reads ``_active_screen_key``) and lands via
              ``Screen.set_focus``; otherwise the focus stays. A window
              switch to a window of ``_SWITCH_LANDING_TARGETS`` lands on
              that widget while it is shown (E4-R4: A2L, the ``?`` chip;
              E4-R6: MAC, the Page Prev button).
            - Records a landing that missed the declared target
              (``_note_focus_landing``, E4-R3).

        Dependencies:
            Uses:
                - ``_load_tree_gone`` / ``_focus_needs_rehome`` /
                  ``_resolve_focus_target``
            Used by:
                - ``action_show_screen`` / ``_apply_unload``
        """
        if self._load_tree_gone():
            return
        if switch is not None and switch != self._active_screen_key:
            return
        container_id = (
            "screen_split_join"
            if self._active_screen_key == "split_join"
            else self.SCREEN_CONTAINER_IDS.get(self._active_screen_key)
        )
        if layout_waits > 0 and container_id is not None:
            try:
                laid_out = self.query_one(f"#{container_id}").region.area > 0
            except Exception:
                laid_out = True
            if not laid_out:
                self.call_after_refresh(
                    self._land_focus,
                    trigger,
                    switch,
                    on_switch=on_switch,
                    layout_waits=layout_waits - 1,
                )
                return
        try:
            focused = self.default_screen.focused
        except Exception:
            return
        move = (
            focused is None
            or self._focus_needs_rehome(focused)
            or (on_switch and focused is trigger)
            or (not on_switch and focused is not trigger)
        )
        if not move:
            return
        target = None
        landing_id = self._SWITCH_LANDING_TARGETS.get(self._active_screen_key)
        if on_switch and landing_id is not None:
            try:
                landing = self.query_one(f"#{landing_id}")
            except Exception:
                landing = None
            if landing is not None and landing.focusable and landing.region.area > 0:
                target = landing
        if target is None:
            target = self._resolve_focus_target()
        if target is None:
            return
        try:
            target.screen.set_focus(target)
        except Exception:
            return
        self._note_focus_landing(target)

    def action_open_settings_menu(self) -> None:
        """Open the viewer page-size settings menu (resurfaced via the palette)."""
        menu = self.query_one("#settings_menu")
        if "hidden" in menu.classes:
            self._update_settings_menu()
            menu.remove_class("hidden")

    async def on_command_bar_palette_action(
        self, event: CommandBar.PaletteAction
    ) -> None:
        """
        Summary:
            Dispatch a chosen command-palette command through the standard
            Textual action runner so it executes the *same* handler as the
            command's key binding (LLR-003.2).

        Args:
            event (CommandBar.PaletteAction): The palette message carrying
                the action id (e.g. ``"load_file"``, ``"show_screen('a2l')"``).

        Returns:
            None

        Data Flow:
            - Awaits ``run_action`` so the palette dispatch path is
              identical to a key binding firing the same action id.

        Dependencies:
            Uses:
                - ``run_action``
            Used by:
                - Textual message dispatch (``CommandBar.PaletteAction``)
        """
        await self.run_action(event.action)

    def _command_bar_input_focused(self) -> bool:
        """Return True while a find/go-to ``Input`` holds keyboard focus.

        batch-79 Inc-9 widened this from "a command-bar Input" to "any input
        `/` or `g` can focus", and the widening is NOT cosmetic — without it
        LLR-119.1 would have silently un-done LLR-004.5.

        The suppressed set is `. , + - g q /`. While one of those is typed into
        a focused find box it must become TEXT, not fire a paging or navigation
        binding. That protection was keyed on the input living inside
        `CommandBar`; the moment `/` started focusing the screens' own inputs,
        every one of those characters would have fired its binding instead of
        reaching the search box — the exact defect LLR-004.5 exists to prevent,
        relocated rather than fixed. Caught by `test_tc008_single_keys_...`,
        which is a pre-batch node this increment would otherwise have broken.
        """
        focused = self.focused
        if not isinstance(focused, Input):
            return False
        if focused.id in self._FIND_GOTO_INPUT_IDS:
            return True
        try:
            command_bar = self.query_one(CommandBar)
        except Exception:
            return False
        return focused in command_bar.query(Input)

    def on_key(self, event: events.Key) -> None:
        """
        Summary:
            Suppress unmodified single-key bindings while a command-bar
            ``Input`` holds focus, routing the keystroke into the input as
            text instead (LLR-004.5 / keymap proposal §4).

        Args:
            event (events.Key): The key event delivered to the app after
                the focused widget declined to consume it.

        Returns:
            None

        Data Flow:
            - This handler only sees keys the focused ``Input`` did not
              already consume (Textual delivers an unhandled key up the
              focus chain). The focused ``Input`` already consumes the
              printable single keys; this handler catches the residual
              leaked single-key bindings (notably ``.``) that would
              otherwise fire a paging / navigation action.
            - While a command-bar input is focused and the key is one of
              ``_COMMAND_BAR_SUPPRESSED_KEYS``, its character is inserted
              into the focused input and the event is stopped, so the
              binding action does not fire. Modified-key bindings
              (``ctrl+*``) are not in the suppressed set and stay live.

        Dependencies:
            Uses:
                - ``_command_bar_input_focused``
            Used by:
                - Textual key-event dispatch
        """
        # LLR-119.3 -- `Escape` releases a focused find/goto input.
        #
        # MECHANISM (C-16 flagged this "assumed -- verify in target framework at
        # Phase 3"): a handler gated on the FOCUSED WIDGET'S ID, not an
        # Input-scoped binding and not a screen-level priority binding. The six
        # targets are stock `Input` / `OsClipboardInput` instances, so binding
        # `escape` on them would mean subclassing six widgets to add one key;
        # and a screen-level or app-level binding would fire on every `escape`
        # in the application. Gating on the id set makes the handler narrow by
        # PREDICATE rather than by placement — it cannot fire anywhere else.
        #
        # PALETTE DISPOSITION, written rather than inherited, as LLR-119.3
        # requires. The palette has NO `escape`-to-close: `command_bar.py`
        # declares no `BINDINGS` and handles no `escape`; re-executed at this
        # increment, `ctrl+k` then `escape` leaves `palette_is_open` True. The
        # spec's own suggested justification for deferring -- "the bar is being
        # deleted anyway" -- is FALSE: `HLR-118` deletes `#command_bar_row`,
        # while `#command_bar_slot` and `#command_bar` SURVIVE to host the
        # palette, so the gap outlives Lane 1 rather than dissolving with it.
        #
        # Deferred anyway, for the reason that does hold: closing it is a new
        # capability on a DIFFERENT widget, outside HLR-119's statement, and it
        # needs its own requirement rather than being smuggled in beside this
        # one. Registered as a carry. What this handler does guarantee is that
        # it cannot make the palette's behaviour worse OR appear better: the
        # palette's focused widget is `#palette_input`, which is not in the
        # target set, so `escape` there is untouched -- asserted, not assumed.
        if event.key == "escape":
            focused = self.focused
            if isinstance(focused, Input) and focused.id in self._FIND_GOTO_INPUT_IDS:
                self.set_focus(None)
                event.stop()
            return

        if event.key not in self._COMMAND_BAR_SUPPRESSED_KEYS:
            return
        if not self._command_bar_input_focused():
            return
        focused = self.focused
        if isinstance(focused, Input):
            focused.insert_text_at_cursor(self._COMMAND_BAR_SUPPRESSED_KEYS[event.key])
        event.stop()
        event.prevent_default()

    def action_cycle_density(self) -> None:
        """
        Summary:
            Cycle the workspace layout density between compact and
            comfortable (LLR-006.1), toggling a density CSS class on the
            ``#workspace_body`` root.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Reads the current ``density-compact`` / ``density-comfortable``
              class on ``#workspace_body``, swaps to the other, and reports
              the new mode via ``set_status``.

        Dependencies:
            Uses:
                - ``set_status``
            Used by:
                - The ``ctrl+d`` key binding

        Example:
            >>> app.action_cycle_density()  # comfortable -> compact
        """
        body = self.query_one("#workspace_body")
        if body.has_class("density-compact"):
            body.remove_class("density-compact")
            body.add_class("density-comfortable")
            self.set_status("Density: comfortable")
        else:
            body.remove_class("density-comfortable")
            body.add_class("density-compact")
            self.set_status("Density: compact")

    def _apply_width_regime(self, width: int) -> None:
        """
        Summary:
            Toggle the ``width-narrow`` class for the two-regime width
            layout (LLR-007.1): narrow below the 120-column breakpoint,
            wide at or above it. The class is set on both ``#workspace_shell``
            and ``#workspace_body``.

        Args:
            width (int): Current terminal width in columns.

        Returns:
            None

        Data Flow:
            - At ``width < 120`` the ``width-narrow`` class is set so the
              proportional-pane and collapsed-rail rules apply; at
              ``width >= 120`` it is cleared so the fixed-width rules apply.
            - The class is set on ``#workspace_shell`` so the collapsed-rail
              rule can reach ``#rail_slot`` (a sibling of ``#workspace_body``,
              not a descendant), and also on ``#workspace_body`` so the
              per-screen proportional-pane rules keep their existing selector.

        Dependencies:
            Used by:
                - ``on_resize``
        """
        narrow = width < 120
        for widget_id in ("#workspace_shell", "#workspace_body"):
            widget = self.query_one(widget_id)
            if narrow:
                widget.add_class("width-narrow")
            else:
                widget.remove_class("width-narrow")

    def on_resize(self, event: events.Resize) -> None:
        """Update the width/diff regimes AND recompose the context line.

        The context line is the reason this handler does a third thing.
        ``_compose_context_line`` bounds the project and A2L halves against a
        budget derived from the terminal width AT WRITE TIME, so a line
        composed at one terminal size is stale at the next. Without this call
        the ``HLR-120`` bound is applied once and never re-applied: composed at
        160x40 and resized to 80x24, the A2L was evicted on 10 of 10 screens --
        byte-for-byte the defect the bound was added to remove.

        Recomposing here is what makes the threshold *"contains both on 10 of
        10 screens"* unconditional rather than true only of the size the line
        happened to be written at.

        **It goes through ``call_after_refresh``, and that is load-bearing:
        ``App.size`` is STALE inside this handler.** ``event.size`` (which the
        two lines above use) is the new size; ``self.size`` still reports the
        old one until the refresh lands, and the composer reads ``self.size``.
        Executed with a direct call instead: the full 91-column line survived
        against a 53-column cell at 160x40 -> 80x24 -- no observable change at
        all. ``TC-B79-04``'s resize axis reddens on that substitution.

        (A reader may reasonably ask why the composer does not simply take the
        width as an argument. It has five other call sites that have no event
        to hand; deferring here keeps one signature and one source of truth.)
        """
        self._apply_width_regime(event.size.width)
        self._apply_diff_regime(event.size.width, event.size.height)
        self.call_after_refresh(self.update_project_labels)

    def action_page_next_context(self) -> None:
        """
        Summary:
            Route context page-next to the active non-main viewer table.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Inspect current visible layout.
            - Forward to A2L or MAC page-next action.

        Dependencies:
            Uses:
                - ``_active_view_name``
                - ``action_a2l_tags_page_next``
                - ``action_mac_records_page_next``
        """
        active = self._active_view_name()
        if active == "alt":
            self.action_a2l_tags_page_next()
        elif active == "mac":
            self.action_mac_records_page_next()

    def action_page_prev_context(self) -> None:
        """
        Summary:
            Route context page-prev to the active non-main viewer table.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Inspect current visible layout.
            - Forward to A2L or MAC page-prev action.

        Dependencies:
            Uses:
                - ``_active_view_name``
                - ``action_a2l_tags_page_prev``
                - ``action_mac_records_page_prev``
        """
        active = self._active_view_name()
        if active == "alt":
            self.action_a2l_tags_page_prev()
        elif active == "mac":
            self.action_mac_records_page_prev()

    def action_page_down_context(self) -> None:
        """
        Summary:
            Route PgDn to the visible pageable surface — the Issues grouped
            panel when the Issues screen is active, else the ``+`` context
            paging (A2L / MAC tables) (batch-31 AC-3 / B-04).

        Args:
            None

        Returns:
            None

        Data Flow:
            - When ``#screen_issues`` is visible, forward to
              ``action_validation_issues_page_next``.
            - Otherwise forward to ``action_page_next_context`` so PgDn is a
              synonym of ``+`` on the A2L/MAC screens.

        Dependencies:
            Uses:
                - ``_is_layout_visible``
                - ``action_validation_issues_page_next``
                - ``action_page_next_context``
            Used by:
                - the ``pagedown`` key binding
        """
        if self._is_layout_visible("#screen_issues"):
            self.action_validation_issues_page_next()
        else:
            self.action_page_next_context()

    def action_page_up_context(self) -> None:
        """
        Summary:
            Route PgUp to the visible pageable surface — the Issues grouped
            panel when the Issues screen is active, else the ``-`` context
            paging (A2L / MAC tables) (batch-31 AC-3 / B-04).

        Args:
            None

        Returns:
            None

        Data Flow:
            - When ``#screen_issues`` is visible, forward to
              ``action_validation_issues_page_prev``.
            - Otherwise forward to ``action_page_prev_context``.

        Dependencies:
            Uses:
                - ``_is_layout_visible``
                - ``action_validation_issues_page_prev``
                - ``action_page_prev_context``
            Used by:
                - the ``pageup`` key binding
        """
        if self._is_layout_visible("#screen_issues"):
            self.action_validation_issues_page_prev()
        else:
            self.action_page_prev_context()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "files_list":
            if event.item is None:
                return
            self._load_from_item(event.item)
            return
        if event.list_view.id == "sections_list":
            if event.item is None:
                return
            self._jump_to_section(event.item)
            return
        if event.list_view.id == "a2l_filter_menu_list":
            if event.item is None:
                return
            field = getattr(event.item, "data", None)
            if field:
                self._set_a2l_filter_field(field)
            return
        if event.list_view.id == "settings_menu_list":
            if event.item is None:
                return
            payload = getattr(event.item, "data", None)
            if (
                isinstance(payload, tuple)
                and len(payload) == 2
                and isinstance(payload[0], str)
                and isinstance(payload[1], int)
            ):
                self._apply_viewer_setting(payload[0], payload[1])
            return
        # ``mac_records_list`` and ``a2l_tags_list`` are ``DataTable`` widgets;
        # selection for those IDs arrives via ``on_data_table_row_selected``
        # instead of this ListView handler.

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """
        Summary:
            Dispatch a ``DataTable.RowSelected`` event to the correct jump helper by
            looking at the selected table's id and the encoded row_key.

        Args:
            event (DataTable.RowSelected): Event payload with ``data_table`` and
                ``row_key`` attributes.

        Returns:
            None

        Data Flow:
            - Pull the table id from ``event.data_table`` and the row_key value.
            - MAC rows -> ``_jump_to_mac_address`` via the ``_mac_row_key_to_address`` map.
            - A2L rows -> ``_jump_to_tag_by_data`` via the ``_a2l_row_key_to_tag`` map.
            - Issues rows are NOT dispatched here: since batch-29 the Issues
              surface is the ``GroupedIssuesPanel`` whose ``IssueRow.Selected``
              message is handled by ``on_issue_row_selected`` (no DataTable).

        Dependencies:
            Uses:
                - ``_jump_to_mac_address``
                - ``_jump_to_tag_by_data``
            Used by:
                - Textual event dispatch for ``DataTable.RowSelected``
        """
        table = getattr(event, "data_table", None)
        table_id = getattr(table, "id", None) if table is not None else None
        row_key = getattr(event, "row_key", None)
        key_value = getattr(row_key, "value", row_key)
        if not isinstance(key_value, str):
            return
        if table_id == "mac_records_list":
            address = self._mac_row_key_to_address.get(key_value)
            if isinstance(address, int):
                self._jump_to_mac_address(address)
            return
        if table_id == "a2l_tags_list":
            tag = self._a2l_row_key_to_tag.get(key_value)
            if isinstance(tag, dict):
                self._jump_to_tag_by_data(tag)
            return

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted
    ) -> None:
        """
        Summary:
            Update the A2L detail card as the ``#a2l_tags_list`` cursor moves
            (batch-47, LLR-069.2). Distinct from ``on_data_table_row_selected``
            (which JUMPS the hex view on enter/click): highlight fires on cursor
            move, giving live per-tag feedback in the card without changing the
            hex position.

        Args:
            event (DataTable.RowHighlighted): Event payload carrying
                ``data_table`` and ``row_key``.

        Returns:
            None

        Data Flow:
            - Ignore non-A2L tables.
            - Resolve the row_key to an enriched tag via ``_a2l_row_key_to_tag``.
            - Hand the tag (or ``None``) to the mounted ``A2LDetailCard``.

        Dependencies:
            Uses:
                - ``A2LDetailCard.show_tag``
            Used by:
                - Textual event dispatch for ``DataTable.RowHighlighted``
        """
        table = getattr(event, "data_table", None)
        table_id = getattr(table, "id", None) if table is not None else None
        if table_id != "a2l_tags_list":
            return
        row_key = getattr(event, "row_key", None)
        key_value = getattr(row_key, "value", row_key)
        tag = (
            self._a2l_row_key_to_tag.get(key_value)
            if isinstance(key_value, str)
            else None
        )
        try:
            card = self.query_one("#a2l_detail_card", A2LDetailCard)
        except Exception:
            return
        card.show_tag(tag if isinstance(tag, dict) else None)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        """
        Summary:
            Reserved for list highlight hooks; A2L tags use explicit page keys instead.

        Args:
            event (ListView.Highlighted): Highlight change event emitted by list views.

        Returns:
            None

        Data Flow:
            - A2L tag paging is driven by ``+`` / ``-`` and find; moving highlight does not repage.

        Dependencies:
            Used by:
                - Textual list highlight event loop
        """
        if event.list_view.id == "a2l_tags_list":
            return

    def _toggle_settings_menu(self) -> None:
        """Show or hide the viewer settings dropdown menu."""
        menu = self.query_one("#settings_menu")
        if "hidden" in menu.classes:
            self._update_settings_menu()
            menu.remove_class("hidden")
        else:
            menu.add_class("hidden")

    def _update_settings_menu(self) -> None:
        """Populate settings menu rows with current viewer limits."""
        menu_list = self.query_one("#settings_menu_list", ListView)
        menu_list.clear()
        menu_list.append(deps.ListItem(deps.Label("Viewer limits (max 200)")))
        menu_list.append(deps.ListItem(deps.Label("-" * 30)))
        target_rows = [
            ("hex_rows_page_size", "Hex rows"),
            ("a2l_tags_page_size", "A2L tags"),
            ("mac_records_page_size", "MAC rows"),
        ]
        for attr_name, label in target_rows:
            current = self._clamp_viewer_page_size(getattr(self, attr_name))
            for option in self.viewer_page_size_options:
                marker = "*" if option == current else " "
                item = deps.ListItem(deps.Label(f"[{marker}] {label}: {option}"))
                item.data = (attr_name, option)
                menu_list.append(item)

    def _apply_viewer_setting(self, setting_name: str, setting_value: int) -> None:
        """Apply a viewer page-size setting and refresh dependent views."""
        safe_value = self._clamp_viewer_page_size(setting_value)
        if setting_name == "hex_rows_page_size":
            self.hex_rows_page_size = safe_value
            self.update_hex_view()
            self.update_alt_hex_view()
            self.update_mac_hex_view()
        elif setting_name == "a2l_tags_page_size":
            self.a2l_tags_page_size = safe_value
            self._a2l_window_start = self._a2l_clamp_page_start(len(self._a2l_filtered_tags))
            self.update_a2l_tags_view(self._a2l_filtered_tags)
        elif setting_name == "mac_records_page_size":
            self.mac_records_page_size = safe_value
            total_records = len(self.current_file.mac_records or []) if self.current_file else 0
            self._mac_window_start = self._mac_clamp_page_start(total_records)
            self.update_mac_view()
        else:
            return
        self.set_status(f"Updated {setting_name} to {safe_value}.")
        self._update_settings_menu()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "a2l_tags_filter_input":
            self.a2l_tags_filter_text = event.value.strip()
            self._schedule_a2l_filter_refresh()
        elif event.input.id == "a2l_tag_find_input":
            self._a2l_tag_find_last_index = -1
