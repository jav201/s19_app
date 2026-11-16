"""s19_app.tui.screens_directionb.loaded_artifacts — LoadedArtifactsPanel (moved verbatim from s19_app/tui/screens_directionb.py at 4f721985)."""
from __future__ import annotations

from typing import List, Optional, Tuple
from textual.app import ComposeResult
from textual.content import Content
from textual.containers import Container, Horizontal
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button, Label, Static
from ..insight_style import human_bytes
from ...utils import safe_text
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..models import LoadedFile


class LoadedArtifactsPanel(Container):
    """The Workspace "Loaded" panel — the persistent load-state readout.

    Summary:
        A compact, always-visible panel on the Workspace rail screen showing the
        three typed artifact slots (S19/HEX spine, MAC, A2L companion). Each slot
        renders either present (kind + escaped file name + a counts/sizes
        summary) with an active ``[u]`` unload affordance, or a dim ``(none)``
        when absent; a footer ``[U]`` unloads everything. The panel is purely
        presentational — it holds no load state, reads the ``LoadedFile``
        snapshot handed to ``render_slots``, and drives unloads by posting
        ``UnloadRequested`` for ``S19TuiApp`` to act on. Every file-derived name
        is wrapped by ``safe_text`` and every summary is counts/sizes only
        (bytes / ranges / records / tags) — no file-derived markup sink
        (security B3).

    Args:
        None

    Returns:
        None

    Data Flow:
        - ``render_slots`` receives the current ``LoadedFile`` (or ``None``) from
          ``S19TuiApp._refresh_loaded_panel`` after every load and unload, clears
          ``#loaded_slots`` and re-mounts the three slot rows plus the
          unload-all row. Re-mounted children carry only CLASSES (never ids), so
          repeated renders never trip ``DuplicateIds`` — the same pattern as
          ``MemoryMapPanel.render_ranges``.
        - A slot's ``[u]`` / the footer ``[U]`` post ``UnloadRequested`` with the
          artifact key; ``S19TuiApp.on_loaded_artifacts_panel_unload_requested``
          dispatches to ``_apply_unload``.

    Dependencies:
        Uses:
            - ``safe_text`` (markup-safe names) / ``Content`` (literal button
              labels) / ``human_bytes`` (byte summary).
            - The three presence predicates inlined here (spine
              ``file_type``+``ranges``; ``mac_path``/``mac_records``;
              ``a2l_path``/``a2l_data``) — a mirror of ``app._has_primary`` /
              ``_has_mac`` / ``_has_a2l``, inlined to avoid the ``app`` import
              cycle (``app`` imports this module).
        Used by:
            - ``S19TuiApp._compose_screen_workspace`` (mounts the widget).
            - ``S19TuiApp._refresh_loaded_panel`` (drives ``render_slots``).

    Example:
        >>> panel = LoadedArtifactsPanel()
        >>> panel.id
        'loaded_panel'
    """

    #: (artifact-key, column-label) for the three slots, in display order.
    _SLOTS: Tuple[Tuple[str, str], ...] = (
        ("primary", "S19"),
        ("mac", "MAC"),
        ("a2l", "A2L"),
    )
    _ABSENT_TEXT = "(none)"
    #: LLR-120.2's absent sentinel for the project row. Bound here, in the class
    #: body, so `render_slots`'s default argument resolves it at definition time
    #: and the panel's "nothing loaded shows a sentinel, never a blank" contract
    #: (TC-B78-09) holds even for a caller that omits the argument entirely --
    #: `on_mount` is exactly such a caller.
    _PROJECT_ABSENT = _ABSENT_TEXT
    #: The project row's kind-cell token. `.loaded-kind` is `width: 6`, so the
    #: obvious `"project"` CLIPS to `"projec"` and runs into the detail cell —
    #: found by the Inc-6/Inc-7 independent review, and only visible through the
    #: PAINTED strip; `render()` returned the full word throughout. Four
    #: uppercase characters also match the siblings (`S19` / `MAC` / `A2L`)
    #: rather than introducing a second style of label in one column. Named so
    #: the acceptances match the EMITTED token instead of re-typing it.
    _PROJECT_KIND = "PROJ"

    class UnloadRequested(Message):
        """A slot's ``[u]`` / the footer ``[U]`` asked to unload an artifact.

        Summary:
            Posted by ``LoadedArtifactsPanel`` when an unload affordance is
            pressed; ``app.py`` handles it and calls ``_apply_unload``. The panel
            performs no teardown itself — it only names the artifact.

        Args:
            artifact (str): One of ``"primary"`` / ``"mac"`` / ``"a2l"`` /
                ``"all"`` — the ``_apply_unload`` kind.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_loaded_artifacts_panel_unload_requested``
        """

        def __init__(self, artifact: str) -> None:
            super().__init__()
            self.artifact = artifact

    def __init__(self) -> None:
        super().__init__(id="loaded_panel")

    def compose(self) -> ComposeResult:
        """Yield the panel title and the re-mount target container.

        Returns:
            ComposeResult: the ``Loaded`` title label and the empty
            ``#loaded_slots`` container that ``render_slots`` fills.

        Dependencies:
            Used by:
                - Textual mount pipeline
        """
        yield Label("Loaded", id="loaded_title", markup=False)
        yield Container(id="loaded_slots")

    def on_mount(self) -> None:
        """Render the initial all-absent slots once the tree is mounted.

        Returns:
            None

        Dependencies:
            Used by:
                - Textual mount pipeline
        """
        self.render_slots(None)

    def render_slots(
        self, loaded: Optional["LoadedFile"], project: str = _PROJECT_ABSENT
    ) -> None:
        """Rebuild the project row + three slot rows (+ unload-all) from a snapshot.

        Summary:
            Clear ``#loaded_slots`` and re-mount the project row, one row per
            artifact and the unload-all footer, reflecting ``loaded``'s
            present/absent state. Re-mounted children carry only CLASSES (never
            ids), so repeated renders never trip ``DuplicateIds`` (the
            ``MemoryMapPanel`` pattern).

        Args:
            loaded (Optional[LoadedFile]): The current snapshot, or ``None`` when
                nothing is loaded (all three slots render ``(none)``).
            project (str): The already-composed project string for the project
                row (``LLR-120.2``) — the plain name at one variant,
                ``project:variant (index/total)`` above that. The FORM is the
                caller's: this panel renders what it is handed and never
                re-derives it, which is what keeps the two context surfaces from
                drifting apart (``LLR-120.5``). Defaults to the absent sentinel
                so ``on_mount``, which passes nothing, renders ``(none)`` rather
                than a blank.

        Returns:
            None

        Raises:
            None

        Data Flow:
            - Read-only over ``loaded`` and ``project``; per slot compute
              (present, name, summary) via ``_slot_state`` and build a row via
              ``_build_slot_row``; the project row via ``_build_project_row``.
            - Tolerates a not-yet-mounted tree (headless render before compose).

        Dependencies:
            Uses:
                - ``_slot_state`` / ``_build_slot_row`` / ``_build_project_row``
                  / ``_build_unload_all_row``.
            Used by:
                - ``S19TuiApp._refresh_loaded_panel`` and ``on_mount``.
        """
        try:
            slots = self.query_one("#loaded_slots", Container)
        except Exception:
            # Tree not mounted yet (headless render before compose).
            return
        slots.remove_children()
        rows: List[Widget] = []
        # LLR-120.2 -- the project row. FIRST, above the artifact slots: the
        # project is the context the three artifacts sit inside, not a fourth
        # artifact. It is built through `safe_text` like every other
        # file-derived cell in this panel (LLR-120.4): a project name is a
        # DIRECTORY name on the operator's own disk, and `U+009B` / `U+009D`
        # are single-byte C1 introducers that carry no `\x1b` and are legal
        # Windows filename characters. A `markup=False`-only row would sit
        # scrub-inconsistent beside scrubbed siblings, and
        # `grep -rl "loaded_slots\|_build_slot_row" tests/` returns 0 files, so
        # nothing in the repo would have caught it.
        rows.append(self._build_project_row(project))
        for artifact, kind in self._SLOTS:
            present, name, summary = self._slot_state(loaded, artifact)
            rows.append(self._build_slot_row(artifact, kind, present, name, summary))
        rows.append(self._build_unload_all_row(loaded is not None))
        slots.mount(*rows)

    def _build_project_row(self, project: str) -> Horizontal:
        """Build the Loaded panel's project row (LLR-120.2).

        Summary:
            One row naming the active project, in whichever display form the
            caller computed -- the plain name at N <= 1 variants, the
            ``project:variant (index/total)`` form above that (LLR-120.5). The
            FORM is the caller's business: this panel renders the string it is
            handed and never re-derives it, which is what keeps the two context
            surfaces from drifting apart.

        Args:
            project (str): The already-composed project string, or the absent
                sentinel.

        Returns:
            Horizontal: the project row, shaped like a slot row so it inherits
            the panel's existing column rhythm.
        """
        absent = project == self._PROJECT_ABSENT
        kind_cell = Static(Content(self._PROJECT_KIND), classes="loaded-kind")
        # `loaded-project-detail`, NOT `loaded-detail`. The latter is the
        # marker the three ARTIFACT slots carry, and two shipped readers select
        # on it and index the result POSITIONALLY as [primary, mac, a2l]
        # (`tests/test_unload_feature.py::_detail_texts`,
        # `tests/test_help_toggle_and_a2l_panel.py`). Reusing it here made the
        # query return four cells with the project at index 0, shifting every
        # artifact index by one and reddening six shipped tests -- while
        # violating LLR-120.2's "shall not alter the existing three artifact
        # slots" verbatim. The row still carries `loaded-slot` for the column
        # rhythm; nothing selects that positionally.
        detail = Static(
            safe_text(project),
            classes=(
                "loaded-project-detail loaded-absent"
                if absent
                else "loaded-project-detail"
            ),
        )
        return Horizontal(
            kind_cell,
            detail,
            classes="loaded-slot loaded-slot-absent" if absent else "loaded-slot",
        )

    def _slot_state(
        self, loaded: Optional["LoadedFile"], artifact: str
    ) -> Tuple[bool, str, str]:
        """Resolve one slot's (present, name, summary) triple from a snapshot.

        Summary:
            Inline the three presence predicates (spine / MAC / A2L) and, when
            present, source the name from the artifact's OWN path field
            (``path`` for the image spine, ``mac_path`` for MAC, ``a2l_path`` for
            A2L — never the bare ``path`` for MAC/A2L, which a MAC-only state
            leaves pointing at the former image) and build a counts/sizes-only
            summary.

        Args:
            loaded (Optional[LoadedFile]): The current snapshot or ``None``.
            artifact (str): ``"primary"`` / ``"mac"`` / ``"a2l"``.

        Returns:
            Tuple[bool, str, str]: ``(present, name, summary)``; ``name`` is the
                raw file-derived name (the caller escapes it) and ``summary`` is
                counts/sizes only. Empty names when absent.

        Raises:
            None

        Data Flow:
            - Read-only over ``loaded`` fields; no mutation, no re-derivation.

        Dependencies:
            Uses:
                - ``human_bytes`` (byte-count formatting).
            Used by:
                - ``render_slots``.
        """
        if loaded is None:
            # Inc 8b D-5 (AT-B100-10): an A2L-only project opens with no
            # image, so no ``LoadedFile`` exists; the A2L slot then names
            # the session's own A2L.
            a2l_path = getattr(self.app, "current_a2l_path", None)
            if artifact != "a2l" or a2l_path is None:
                return False, "", ""
            count = len((getattr(self.app, "current_a2l_data", None) or {}).get("tags", []))
            return True, a2l_path.name, f"{count} tag{'' if count == 1 else 's'}"
        if artifact == "primary":
            present = loaded.file_type in {"s19", "hex"} and bool(loaded.ranges)
            if not present:
                return False, "", ""
            summary = f"{human_bytes(len(loaded.mem_map))} · {len(loaded.ranges)} rng"
            return True, loaded.path.name, summary
        if artifact == "mac":
            present = loaded.mac_path is not None or bool(loaded.mac_records)
            if not present:
                return False, "", ""
            name = loaded.mac_path.name if loaded.mac_path else "mac"
            count = len(loaded.mac_records)
            summary = f"{count} record{'' if count == 1 else 's'}"
            return True, name, summary
        # artifact == "a2l"
        present = loaded.a2l_path is not None or loaded.a2l_data is not None
        if not present:
            return False, "", ""
        name = loaded.a2l_path.name if loaded.a2l_path else "a2l"
        count = len((loaded.a2l_data or {}).get("tags", []))
        summary = f"{count} tag{'' if count == 1 else 's'}"
        return True, name, summary

    def _build_slot_row(
        self, artifact: str, kind: str, present: bool, name: str, summary: str
    ) -> Horizontal:
        """Build one slot row: kind cell + detail cell + (present) ``[u]``.

        Summary:
            Compose a single slot row. A present slot shows the escaped name and
            summary with an active ``[u]`` ``Button`` carrying the artifact key
            on its ``name`` (no id — re-render safe). An absent slot shows a dim
            ``(none)`` and no affordance.

        Args:
            artifact (str): The artifact key set as the ``[u]`` button ``name``.
            kind (str): The fixed column label (``S19`` / ``MAC`` / ``A2L``).
            present (bool): Whether the artifact is loaded.
            name (str): File-derived name (escaped here via ``safe_text``).
            summary (str): Counts/sizes-only summary (empty when absent).

        Returns:
            Horizontal: the slot row.

        Raises:
            None

        Data Flow:
            - Pure widget construction; ``safe_text`` neutralises the file name;
              the button label is a literal ``Content`` (no markup parse).

        Dependencies:
            Uses:
                - ``safe_text`` / ``Content`` / ``Button`` / ``Static``.
            Used by:
                - ``render_slots``.
        """
        kind_cell = Static(safe_text(kind), classes="loaded-kind")
        if present:
            detail = Static(
                safe_text(f"{name}  {summary}"), classes="loaded-detail"
            )
            unload = Button(
                Content("[u]"),
                name=artifact,
                compact=True,
                classes="loaded-unload",
            )
            return Horizontal(kind_cell, detail, unload, classes="loaded-slot")
        detail = Static(
            safe_text(self._ABSENT_TEXT), classes="loaded-detail loaded-absent"
        )
        return Horizontal(
            kind_cell, detail, classes="loaded-slot loaded-slot-absent"
        )

    def _build_unload_all_row(self, any_loaded: bool) -> Horizontal:
        """Build the footer row: an ``unload all`` label + the ``[U]`` button.

        Summary:
            The ``[U]`` button is present (active) only when something is loaded;
            with nothing loaded the row shows a dim label and no affordance.

        Args:
            any_loaded (bool): Whether any artifact is loaded.

        Returns:
            Horizontal: the unload-all footer row.

        Raises:
            None

        Data Flow:
            - Pure widget construction; constant labels only (no file-derived
              text); the ``[U]`` button carries ``name="all"``.

        Dependencies:
            Uses:
                - ``safe_text`` / ``Content`` / ``Button`` / ``Static``.
            Used by:
                - ``render_slots``.
        """
        label_cls = (
            "loaded-alllabel" if any_loaded else "loaded-alllabel loaded-absent"
        )
        children: List[Widget] = [Static(safe_text("unload all"), classes=label_cls)]
        if any_loaded:
            children.append(
                Button(
                    Content("[U]"),
                    name="all",
                    compact=True,
                    classes="loaded-unload loaded-unload-all",
                )
            )
        return Horizontal(*children, classes="loaded-allrow")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Translate an unload button press into an ``UnloadRequested`` post.

        Summary:
            Every button in this panel is an unload affordance whose ``name`` is
            the artifact key; read it, stop the event so it does not reach the
            app's id-keyed ``on_button_pressed``, and post ``UnloadRequested``.

        Args:
            event (Button.Pressed): The button-press message.

        Returns:
            None

        Raises:
            None

        Data Flow:
            - ``event.button.name`` → ``UnloadRequested`` posted to the app.

        Dependencies:
            Uses:
                - ``UnloadRequested`` / ``Message.stop``.
            Used by:
                - Textual message dispatch (child ``Button`` presses).
        """
        artifact = event.button.name
        if not artifact:
            return
        event.stop()
        self.post_message(self.UnloadRequested(artifact))
