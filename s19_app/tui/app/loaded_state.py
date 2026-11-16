"""s19_app.tui.app.loaded_state — S19TuiApp mixin: loaded_state (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import time
from typing import Any, List, Optional, Sequence
from ...core import load_notice_code
from ..models import LoadedFile
from ..flow_screens import FlowBuilderPanel
from ..screens_directionb import LoadedArtifactsPanel, PatchEditorPanel
from ..services.project_gather_service import painted_names
from .shared import (PreparedLoad, _INTEGRITY_NOTICE_CODES, _has_primary)


def _integrity_notice_codes(errors: Optional[Sequence[dict]]) -> List[str]:
    """
    Summary:
        Ordered, de-duplicated HLR-154 integrity-notice codes carried by a
        ``LoadedFile.errors`` list (``S19-NO-TERMINATOR``,
        ``S19-COUNT-MISMATCH``, ``S19-AFTER-TERMINATOR``, ``HEX-NO-EOF``,
        ``HEX-AFTER-EOF``); plain parser errors contribute nothing.

    Args:
        errors (Optional[Sequence[dict]]): Loader error dicts from
            ``S19File.get_errors()`` / ``IntelHexFile.get_errors()``.

    Returns:
        List[str]: The codes in first-appearance order (empty when the load
        carries no integrity notice).
    """
    codes: List[str] = []
    for err in errors or []:
        code = load_notice_code(err)
        if code in _INTEGRITY_NOTICE_CODES and code not in codes:
            codes.append(code)
    return codes


def _unload_a2l(loaded: LoadedFile) -> Optional[LoadedFile]:
    """
    Summary:
        Rebuild a snapshot with the A2L companion removed, keeping the spine
        and every derived loader fact (the inverse of an A2L attach).

    Args:
        loaded (LoadedFile): Current snapshot with an A2L to drop.

    Returns:
        Optional[LoadedFile]: A copy with ``a2l_path``/``a2l_data`` cleared.
            Never ``None`` — the A2L is a companion, so the spine always
            survives its removal.

    Raises:
        None

    Data Flow:
        - ``dataclasses.replace`` copies every field, overriding only the two
          A2L fields, so the image/MAC spine and all derived facts
          (``entropy_windows`` / ``source_s0_header`` / ``out_of_order_count``
          / ``entry_point``) carry forward untouched.

    Dependencies:
        Uses:
            - ``dataclasses.replace``.
        Used by:
            - ``S19TuiApp._apply_unload`` for ``kind == "a2l"``.

    Example:
        >>> lf = LoadedFile(path=Path("f.s19"), file_type="s19",
        ...     mem_map={0: 1}, row_bases=[0], ranges=[(0, 1)],
        ...     range_validity=[True], errors=[], a2l_path=Path("m.a2l"),
        ...     a2l_data={"x": 1})
        >>> _unload_a2l(lf).a2l_data is None
        True
    """
    return replace(loaded, a2l_path=None, a2l_data=None)


def _unload_mac(loaded: LoadedFile) -> Optional[LoadedFile]:
    """
    Summary:
        Rebuild a snapshot with MAC metadata removed (the inverse of a MAC
        attach), keeping the image spine when one is present.

    Args:
        loaded (LoadedFile): Current snapshot with MAC data to drop.

    Returns:
        Optional[LoadedFile]: A copy with ``mac_path``/``mac_records``/
            ``mac_diagnostics`` cleared when a primary image spine survives;
            ``None`` when the MAC was itself the spine (MAC-only load), since
            nothing remains to render.

    Raises:
        None

    Data Flow:
        - When ``_has_primary`` holds, ``dataclasses.replace`` clears only the
          three MAC fields; the image, A2L companion, and every derived fact
          carry forward.
        - Otherwise the MAC was the spine, so the result is ``None``.

    Dependencies:
        Uses:
            - ``_has_primary`` / ``dataclasses.replace``.
        Used by:
            - ``S19TuiApp._apply_unload`` for ``kind == "mac"``.

    Example:
        >>> lf = LoadedFile(path=Path("f.s19"), file_type="s19",
        ...     mem_map={0: 1}, row_bases=[0], ranges=[(0, 1)],
        ...     range_validity=[True], errors=[], a2l_path=None,
        ...     a2l_data=None, mac_records=[{"name": "RPM"}])
        >>> _unload_mac(lf).mac_records
        []
    """
    if _has_primary(loaded):
        return replace(loaded, mac_path=None, mac_records=[], mac_diagnostics=[])
    return None


def _unload_primary(loaded: LoadedFile) -> Optional[LoadedFile]:
    """
    Summary:
        Rebuild a snapshot with the S19/HEX image (and every image-derived
        fact) removed, degrading to a MAC-only spine when a MAC file is
        present.

    Args:
        loaded (LoadedFile): Current snapshot whose primary image is dropped.

    Returns:
        Optional[LoadedFile]: A MAC-only copy (``file_type="mac"``; ``path``
            set to the MAC file and ``errors`` rebuilt from the MAC's own
            diagnostics; image map/rows/ranges and all image-derived facts
            and caches cleared; ``mac_*`` and ``a2l_*`` kept) when a MAC
            file is loaded; ``None`` when no MAC file is present, since the
            image was the last spine and a companion A2L cannot outlive it.

    Raises:
        None

    Data Flow:
        - When ``mac_path`` is set, ``dataclasses.replace`` clears the image
          map/rows/ranges, the derived facts (``entropy_windows`` /
          ``source_s0_header`` / ``out_of_order_count`` / ``entry_point``),
          the lazy caches (``range_index`` / ``bases_set``), and
          ``variant_id``, while retaining MAC and A2L fields.
        - Otherwise no spine survives, so the result is ``None`` (the companion
          A2L clears with it).

    Dependencies:
        Uses:
            - ``mac_path`` / ``dataclasses.replace``.
        Used by:
            - ``S19TuiApp._apply_unload`` for ``kind == "primary"``.

    Example:
        >>> lf = LoadedFile(path=Path("f.s19"), file_type="s19",
        ...     mem_map={0: 1}, row_bases=[0], ranges=[(0, 1)],
        ...     range_validity=[True], errors=[], a2l_path=None,
        ...     a2l_data=None, mac_path=Path("t.mac"),
        ...     mac_records=[{"name": "RPM"}])
        >>> _unload_primary(lf).file_type
        'mac'
    """
    if loaded.mac_path is not None:
        return replace(
            loaded,
            file_type="mac",
            path=loaded.mac_path,
            mem_map={},
            row_bases=[],
            ranges=[],
            range_validity=[],
            errors=[{"line": None, "message": d} for d in loaded.mac_diagnostics],
            entropy_windows=[],
            source_s0_header=None,
            out_of_order_count=0,
            entry_point=None,
            range_index=None,
            bases_set=None,
            variant_id=None,
        )
    return None


class LoadedStateMixin:

    def _merge_primary_with_existing_mac(
        self, primary_loaded: LoadedFile, existing: Optional[LoadedFile]
    ) -> LoadedFile:
        """
        Summary:
            Preserve the existing MAC payload when a new S19/HEX primary image is loaded.

        Args:
            primary_loaded (LoadedFile): Newly parsed primary artifact payload (``s19`` or ``hex``).
            existing (Optional[LoadedFile]): The merge target (the live session, or the worker's own image).

        Returns:
            LoadedFile: Primary payload with MAC metadata copied from ``existing`` when available.

        Dependencies:
            Uses:
                - ``LoadedFile`` dataclass constructor
            Used by:
                - ``_parse_data_file`` primary branches
        """
        if existing is None:
            return primary_loaded
        if not existing.mac_path and not existing.mac_records and not existing.mac_diagnostics:
            return primary_loaded
        return LoadedFile(
            path=primary_loaded.path,
            file_type=primary_loaded.file_type,
            mem_map=primary_loaded.mem_map,
            row_bases=primary_loaded.row_bases,
            ranges=primary_loaded.ranges,
            range_validity=primary_loaded.range_validity,
            errors=primary_loaded.errors,
            a2l_path=primary_loaded.a2l_path or existing.a2l_path,
            a2l_data=primary_loaded.a2l_data or existing.a2l_data,
            mac_path=existing.mac_path,
            mac_records=existing.mac_records,
            mac_diagnostics=existing.mac_diagnostics,
            # A new primary is a new image: keep the incoming payload's
            # variant identity (stamped at apply time), never the old one.
            variant_id=primary_loaded.variant_id,
            # Derived loader facts belong to the NEW primary image — carry them
            # forward so the merge does not reset them to defaults (LLR-066.7).
            # entropy_windows + source_s0_header were previously dropped here: the
            # empty entropy list made the Memory Map falsely report "No file
            # loaded" whenever an S19/HEX coexisted with a MAC (fix-memmap-entropy).
            out_of_order_count=primary_loaded.out_of_order_count,
            entry_point=primary_loaded.entry_point,
            entropy_windows=primary_loaded.entropy_windows,
            source_s0_header=primary_loaded.source_s0_header,
        )

    def _merge_mac_with_existing_primary(
        self, mac_loaded: LoadedFile, existing: Optional[LoadedFile]
    ) -> LoadedFile:
        """
        Summary:
            Attach parsed MAC metadata to the existing S19/HEX payload when one is already loaded.

        Args:
            mac_loaded (LoadedFile): Parsed MAC payload from ``_load_mac_file``.
            existing (Optional[LoadedFile]): The merge target (the live session, or the worker's own image).

        Returns:
            LoadedFile: Existing primary payload with refreshed MAC fields, or ``mac_loaded`` when no primary exists.

        Dependencies:
            Uses:
                - ``LoadedFile`` dataclass constructor
            Used by:
                - ``_parse_data_file`` MAC branch
        """
        if not existing or existing.file_type not in {"s19", "hex"}:
            return mac_loaded
        return LoadedFile(
            path=existing.path,
            file_type=existing.file_type,
            mem_map=existing.mem_map,
            row_bases=existing.row_bases,
            ranges=existing.ranges,
            range_validity=existing.range_validity,
            errors=existing.errors,
            a2l_path=mac_loaded.a2l_path or existing.a2l_path,
            a2l_data=mac_loaded.a2l_data or existing.a2l_data,
            mac_path=mac_loaded.mac_path,
            mac_records=mac_loaded.mac_records,
            mac_diagnostics=mac_loaded.mac_diagnostics,
            # The primary image is unchanged — its variant identity survives
            # the MAC overlay (project MAC follow-up load, LLR-005.6).
            variant_id=existing.variant_id,
            # The primary's derived loader facts survive the MAC overlay — carry
            # them forward so the merge does not reset them (LLR-066.7, AT-066d).
            # entropy_windows + source_s0_header were previously dropped here: the
            # empty entropy list made the Memory Map falsely report "No file
            # loaded" once a MAC was overlaid on a loaded image (fix-memmap-entropy).
            out_of_order_count=existing.out_of_order_count,
            entry_point=existing.entry_point,
            entropy_windows=existing.entropy_windows,
            source_s0_header=existing.source_s0_header,
        )

    def _apply_unload(self, kind: str) -> None:
        """
        Summary:
            Tear down one artifact (or all) from ``current_file`` and refresh
            every view so each renderer reaches its no-file branch when the
            snapshot becomes ``None``.

        Args:
            kind (str): One of ``"primary"``, ``"mac"``, ``"a2l"``, ``"all"``.
                ``"all"`` clears ``current_file`` outright; the others dispatch
                to the matching module-level ``_unload_*`` rebuild.

        Returns:
            None

        Raises:
            ValueError: When ``kind`` is not one of the four accepted values.

        Data Flow:
            - ``"all"`` sets the new snapshot to ``None``; otherwise, when a
              file is loaded, dispatch to ``_unload_primary``/``_unload_mac``/
              ``_unload_a2l`` over ``current_file``. With nothing loaded the
              per-artifact path is a status-line no-op.
            - Install the rebuilt (or ``None``) snapshot, reset the view-row
              memo (``_hex_view_rows_cache``, CR-1), invalidate the MAC
              view cache, toggle empty state, refresh sections/hex and run the
              common A2L fan-out before project labels.
            - Defer the ordered file-status and message-log unload outcomes
              behind the fan-out's detail-card barrier.
            - Schedule ``_land_focus`` after a refresh, stamped with the
              window shown now, so a rail key in the same burst makes it
              stale (CR-3).

        Dependencies:
            Uses:
                - ``_unload_primary`` / ``_unload_mac`` / ``_unload_a2l``.
                - ``_invalidate_mac_view_cache`` / ``_apply_empty_state`` and
                  the ``update_*`` renderers.
            Used by:
                - ``action_unload_all`` (``U`` binding) and the Inc-2
                  Workspace "Loaded" panel (per-artifact ``[u]`` controls).
        """
        if kind == "all" and self.current_file is None and self.current_a2l_path is None:
            self.set_status("Nothing to unload.")
            return
        try:
            trigger = self.default_screen.focused
        except Exception:
            trigger = None
        if kind == "all":
            new: Optional[LoadedFile] = None
            label = "all artifacts"
        elif self.current_file is None:
            # F3: an A2L-only session (no image) holds its A2L outside
            # ``current_file``; its unload clears that A2L.
            if kind != "a2l" or self.current_a2l_path is None:
                self.set_status("Nothing to unload.")
                return
            new = None
            label = "A2L"
        else:
            if kind == "primary":
                new = _unload_primary(self.current_file)
                label = "primary image"
            elif kind == "mac":
                new = _unload_mac(self.current_file)
                label = "MAC"
            elif kind == "a2l":
                new = _unload_a2l(self.current_file)
                label = "A2L"
            else:
                raise ValueError(f"unknown unload kind: {kind!r}")

        self.current_file = new
        self._hex_view_rows_cache = None
        # `current_a2l_path` is the OTHER half of "which A2L is in effect", and
        # until batch-79 nothing ever cleared it — it is written in exactly two
        # places (`load_a2l_from_path`'s copy and the load path's
        # `loaded.a2l_path`) and reset in none. So after an unload the app held
        # two sources of truth for one fact: `current_file.a2l_path`, cleared
        # here, and `current_a2l_path`, left pointing at the artifact that had
        # just been unloaded.
        #
        # That divergence is PRE-EXISTING — the command bar read the stale value
        # and the Loaded panel read the fresh one, so the two disagreed on
        # screen. Inc-7 did not introduce it, but it moved the stale reader to
        # `#status_context`, which sits on the same screen as the panel that
        # contradicts it. Found by the Inc-6/Inc-7 independent review (F6).
        #
        # Cleared at the SOURCE rather than papered over in the display: a
        # composer that picks between two mirrors keeps the second source alive
        # and only hides the symptom.
        if kind in ("all", "a2l"):
            # LLR-165.4 (P-25): the A2L artifact is the path AND the
            # parsed payload — the payload is the fallback the next
            # S19/HEX/MAC parse re-attaches (`else self.current_a2l_data`
            # at the parse branches), so clearing the path alone left the
            # tags alive after an unload. Cleared beside the path, for
            # the kinds that drop the artifact — through
            # ``_replace_current_a2l`` (batch-102 Inc 2), the
            # single-writer seam whose generation bump makes the stale
            # enrichment key unreachable and whose cache clear empties
            # the tag rows the render below repaints.
            self._replace_current_a2l(None, None)
        if kind in ("primary", "all"):
            # batch-102 Inc 5 (E3 ruling 4): dropping the primary image
            # drops the memory map the Patch panel retained — push ``None``
            # so the before/after strip and the A2L tab's ``Use parameter``
            # read "no image" instead of the unloaded image's stale bytes.
            try:
                panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
            except Exception:
                # App not mounted (headless unit path) — the same tolerance
                # the load install tail documents.
                pass
            else:
                panel.set_image_mem_map(None)
        # Mirror the load-path install: the MAC cache is keyed on the previous
        # records, and the empty-state panels key on `current_file is None`.
        self._invalidate_mac_view_cache()
        self._apply_empty_state()
        # Unload is cheap: refresh synchronously, then order its outcome behind
        # the common fan-out's detail-card barrier.
        self.update_sections()
        self.update_hex_view()
        self.update_alt_hex_view()
        self.update_mac_hex_view()
        self._refresh_a2l_dependent_views()
        self.update_project_labels()
        self.call_after_refresh(self.set_file_status, f"Unloaded {label}.")
        self.call_after_refresh(self.set_status, f"Unloaded {label}.")
        # Inc 10a (E5, CR-3): stamped with the window shown now, so a rail
        # key in the same burst makes this landing stale and its own wins.
        self.call_after_refresh(
            self._land_focus, trigger, self._active_screen_key, on_switch=False
        )

    def _refresh_loaded_panel(self, project: Optional[str] = None) -> None:
        """
        Summary:
            Drive the Workspace "Loaded" panel to redraw its project row and
            three artifact slots from the current ``current_file`` snapshot
            (unload feature Inc-2; project row batch-79 ``LLR-120.2``). Guarded
            so a not-yet-mounted tree (headless unit tests) is a no-op, matching
            ``_apply_empty_state`` / ``update_memory_map``.

        Args:
            project (Optional[str]): The already-composed project string to
                render in the panel's project row — the plain name at one
                variant, ``project:variant (index/total)`` above that. ``None``
                means "compose it here", which is what the unload path and the
                load path's ``_step_finalize`` pass; the string is never
                composed by the panel itself, so both context surfaces show the
                same form (``LLR-120.5``).

        Returns:
            None

        Raises:
            None

        Data Flow:
            - Resolve ``#loaded_panel``; a missing widget tree is tolerated.
            - Call ``render_slots(current_file, project)``, composing the
              project string via ``_compose_project_label`` when the caller
              passed ``None``.

        Dependencies:
            Uses:
                - ``LoadedArtifactsPanel.render_slots`` / ``_compose_project_label``.
            Used by:
                - ``_apply_unload`` (post-unload refresh), the load path's
                  ``_step_finalize`` (post-load refresh) and
                  ``update_project_labels`` (``LLR-120.1``'s single entry point).
        """
        try:
            panel = self.query_one("#loaded_panel", LoadedArtifactsPanel)
        except Exception:
            return
        # LLR-120.5: when a caller does not hand a composed string, compose it
        # HERE from the one composer rather than letting the panel invent a
        # form. `_apply_unload` and the load path's `_step_finalize` are such
        # callers, and a panel-side default would show `(none)` beside a
        # perfectly loaded project.
        panel.render_slots(
            self.current_file,
            self._compose_project_label() if project is None else project,
        )
        #: batch-102 Inc 7: a load/unload changes the ``loaded`` half of the
        #: flow card-annotation context (E3 ruling 7) — repaint the Builder
        #: without a block edit.  Guarded like the panel lookup above.
        try:
            self.query_one("#flow_panel", FlowBuilderPanel).refresh_flow_ref_annotations()
        except Exception:  # noqa: BLE001 - panel not mounted yet
            pass

    def on_loaded_artifacts_panel_unload_requested(
        self, message: "LoadedArtifactsPanel.UnloadRequested"
    ) -> None:
        """
        Summary:
            Handle a ``[u]`` / ``[U]`` press from the Workspace "Loaded" panel by
            unloading the named artifact (unload feature Inc-2).

        Args:
            message (LoadedArtifactsPanel.UnloadRequested): Carries the artifact
                key (``"primary"`` / ``"mac"`` / ``"a2l"`` / ``"all"``).

        Returns:
            None

        Raises:
            None

        Data Flow:
            - Stop the message and dispatch to ``_apply_unload(message.artifact)``,
              which rebuilds ``current_file`` and refreshes every view (including
              this panel via ``_refresh_loaded_panel``).

        Dependencies:
            Uses:
                - ``_apply_unload``.
            Used by:
                - Textual message dispatch (from ``LoadedArtifactsPanel``).
        """
        if self._refuse_if_busy():
            return
        message.stop()
        self._apply_unload(message.artifact)

    def action_unload_all(self) -> None:
        """
        Summary:
            ``U`` binding handler — unload every artifact at once.

        Args:
            None

        Returns:
            None

        Raises:
            None

        Data Flow:
            - Delegates to ``_apply_unload("all")``.

        Dependencies:
            Uses:
                - ``_apply_unload``.
            Used by:
                - The ``U`` key binding.
        """
        if self._refuse_if_busy():
            return
        self._apply_unload("all")

    def _apply_prepared_load(
        self,
        prepared: PreparedLoad,
        path: Path,
        load_started: float,
        *,
        publish_a2l: bool = True,
    ) -> bool:
        """
        Summary:
            Accept and install a fresh ``PreparedLoad``, or reject the whole
            bundle before any mutation when its generation snapshot is stale.

        Args:
            prepared (PreparedLoad): Parsed payload and optional worker-precomputed
                MAC, validation, A2L and hex caches.
            path (Path): Source path used for status messaging and log lines.
            load_started (float): ``time.perf_counter`` value captured at start.
            publish_a2l (bool): Whether to run the common fan-out synchronously;
                project installation leaves its single final publication to C7.

        Returns:
            bool: ``True`` when the complete bundle was accepted; ``False`` when
            a keyed enrichment snapshot was superseded before installation.

        Data Flow:
            - Compare every keyed snapshot with the expected post-install A2L
              and image generations before cache, session, widget or log work.
            - Preserve the existing state/cache installation and deferred
              sections/hex/focus chain for an accepted bundle.
            - Install accepted precomputed A2L values directly and optionally
              publish the common fan-out before returning.

        Dependencies:
            Uses:
                - ``_replace_current_a2l`` / ``_refresh_a2l_dependent_views``
                - ``call_later`` / ``update_sections`` / ``update_hex_view``
            Used by:
                - ``_complete_prepared_load`` / ``_install_prepared_project``
                - ``_apply_loaded_file`` (synchronous fallback)
        """
        if prepared.a2l_enriched_key is not None:
            actual = (
                prepared.a2l_view_generation,
                prepared.a2l_image_generation,
            )
            expected = (
                self._a2l_view_generation + int(bool(prepared.loaded.a2l_data)),
                self._image_generation + 1,
            )
            if actual != expected:
                return False
        loaded = prepared.loaded
        # Q-h1: the file-load worker's cache entry is stored on the main
        # thread here (never off main).
        if prepared.a2l_cache is not None:
            self._store_a2l_cache(prepared.a2l_cache)
        # Variant stamping happens HERE, at apply time on the main UI thread:
        # the pending id was set on the main thread by the dispatching handler
        # (project load / variant selector), the parse worker never reads it,
        # and the worker signatures stay untouched (LLR-005.4 thread contract).
        pending_variant = self._pending_variant_id
        if pending_variant is not None and loaded.file_type in {"s19", "hex"}:
            loaded.variant_id = pending_variant
            self._pending_variant_id = None
            if self._variant_set is not None and any(
                variant.variant_id == pending_variant
                for variant in self._variant_set.variants
            ):
                self._variant_set.active_id = pending_variant
        previous_map = self.current_file.mem_map if self.current_file else None
        self.current_file = loaded
        # LLR-167.5 (B100-I18): a load records the saved-image state. Only a
        # NEW image dict counts — a MAC/A2L attach keeps the live dict (and
        # any unsaved patch in it), so recording there would hide that patch.
        if loaded.mem_map is not previous_map:
            self._change_service.mark_saved(loaded.mem_map)
        # batch-48 (LLR-077.2, the BL-4 arm): a NEW image is now installed, so
        # any completed check run describes a PREVIOUS one. Bump the monotonic
        # generation and push it into the change service, which compares it
        # against the token it stamped at run time and degrades every entry
        # glyph to `·` on a mismatch. The bump lives HERE — the single install
        # point F-09 below names — rather than in `_apply_loaded_file`: that
        # method is only the SYNCHRONOUS wrapper, and the worker path reaches
        # this method directly via `call_from_thread` (`_start_load_worker`),
        # so a bump one frame up would miss every real async load.
        #
        # This bumps on EVERY install, including a MAC/A2L attach that leaves
        # the image bytes alone — deliberately, and it is the conservative
        # direction, not an oversight. Over-refusing costs the analyst a
        # re-run and shows `·`, which is honest; under-refusing renders a
        # verdict that is a lie. Narrowing the trigger would mean deciding
        # here whether an install "really" changed the image, which is the
        # kind of inference that produced the BL-4 defect in the first place.
        self._image_generation += 1
        self._change_service.set_image_generation(self._image_generation)
        # ...and RE-RENDER the entries table, or the invalidation is invisible.
        # Nothing else re-renders it on load: the four existing `refresh_entries`
        # sites all hang off a Patch-Editor action, an undo/redo, or the panel's
        # own mount. So the stamp alone would go stale in the service while the
        # TABLE kept painting the verdicts of the previous image — the user-facing
        # half of the same defect. This is a render call over data the service
        # already holds; it re-derives nothing and applies nothing. (It also
        # refreshes each row's containment `status_text`, which was likewise
        # stale-until-next-action before this batch.)
        try:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        except Exception:
            # App not mounted (headless unit tests drive this pipeline on a
            # bare `S19TuiApp()` with no screen stack) — no tree to render
            # into, the same tolerance `_apply_empty_state` documents just
            # below. NOT a real-app path: the panel mounts during compose,
            # which precedes both `App.on_mount`'s startup load and any
            # user-triggered one. The service-side stamp above is set either
            # way, so nothing is skipped that a later render would need.
            pass
        else:
            # batch-48 (LLR-080.2) — site 4 of 5, and the one the Phase-2
            # writer census MISSED: it was added by Inc-3 (the BL-4 arm) after
            # that census was written, and nothing re-derived the census.
            #
            # This is the ONLY load-triggered site, which makes it the one the
            # CARD most depends on: a new image means new "before" bytes. The
            # panel's retain semantics are sentinel⇒preserve, so omitting
            # `mem_map` here would leave the card holding the PREVIOUS image's
            # map and painting stale before-bytes — the exact staleness defect
            # this site exists to fix (the glyph half, above), one seam over.
            panel.refresh_entries(
                self._change_service.rows(loaded.ranges),
                # batch-99 HLR-157 (LLR-157.4): the strip reads the journal
                # overlay — source bytes at every address an apply wrote.
                mem_map=self._strip_source_map(loaded),
                document=self._patch_document_view(),
            )
            # batch-97 Inc-8 (PC-23): the key bar dims Undo / Redo by the
            # document's source, which this refresh may have changed.
            self.refresh_bindings()
            # Inc 6 (R-TUI-049.3.1/.3.2, S-1): a NEW image dict installs a
            # new image — hide the old apply's controls; a MAC attach keeps
            # the dict, so it hides nothing.
            if loaded.mem_map is not previous_map:
                self._hide_replaced_document_controls(panel)
            # Inc 6 (R-CHK-PE-009 … -012): every install bumps the image
            # generation, so the run ends (a MAC load included).
            self._refresh_patch_checks_tab(panel)
        # Inc 6 (E3A-02, R-CHKS-004/-009): a displayed Checks screen
        # repaints with the no-run note (a guarded no-op when not mounted).
        self.update_checks_view()
        # F-09 (LLR-056.3): every load path — project load, loose-file
        # load, variant activation — funnels through this install point,
        # so the sticky report-filter selection dies with the previous
        # loaded-file set here (the batch-24 cross-project survivor
        # class). The project-CREATE swap, which installs no file, resets
        # in ``_handle_save_dialog``.
        self._report_filter_path = None
        # A file is now present — reveal the real content of the
        # content-bearing rail screens and hide their empty-state panels
        # (LLR-002.3).
        self._apply_empty_state()
        self._invalidate_mac_view_cache()
        self._mac_window_start = 0
        # Inc 10a E4-R1 (R-TUI-007.9): a NEW image is shown from its first
        # view row — the window a jump placed in the previous image is not
        # carried over. A MAC / A2L attach keeps the live image and its
        # window (the MAC re-anchor stays BL-I10-1).
        if loaded.mem_map is not previous_map:
            self._hex_window_start = 0
        self._validation_issues_window_start = 0
        self._a2l_tag_hex_highlight = None
        # A new file invalidates every per-view goto focus address (LLR-003.6 file-load).
        self._goto_focus_address = None
        self._alt_goto_focus_address = None
        self._mac_goto_focus_address = None
        if loaded.a2l_data:
            # batch-102 Inc 2 (R-B102-A2L-001/.004): the install routes
            # through the single-writer seam so the attach generation
            # bumps and the stale enrichment key can never satisfy
            # ``_compute_a2l_enriched_tags``.
            self._replace_current_a2l(loaded.a2l_path, loaded.a2l_data)
        # Attach worker-precomputed bases_set so hex renders skip rebuilding sets of
        # millions of addresses on every refresh.
        try:
            if prepared.bases_set is not None:
                loaded.bases_set = prepared.bases_set
        except Exception:
            # Legacy LoadedFile in test fixtures may not support the attribute; ignore.
            pass
        if prepared.precomputed:
            self._mac_view_cache_key = prepared.mac_cache_key
            self._mac_view_cache_rows = prepared.mac_rows
            self._mac_view_cache_meta = prepared.mac_meta
            self._mac_view_cache_summary = prepared.mac_summary
            self._mac_view_cache_coverage_line = prepared.mac_coverage_line
            self._validation_report = prepared.validation_report
            self._validation_issues = list(prepared.validation_issues)
            # Stash worker-precomputed DataTable payloads so the populate helpers
            # skip re-formatting cells on the UI thread.
            self._mac_view_cache_widths = prepared.mac_widths
            self._mac_view_cache_cell_rows = list(prepared.mac_cell_rows)
            self._mac_view_cache_cell_styles = list(prepared.mac_cell_styles)
            if prepared.a2l_enriched_key is not None:
                # The preflight already proved both post-install generations;
                # accepted precomputed enrichment is therefore installed as-is.
                self._a2l_enriched_tags = prepared.a2l_enriched_tags
                self._a2l_enriched_key = prepared.a2l_enriched_key
                self._a2l_summary_lines = prepared.a2l_summary_lines
                self._a2l_summary_start = 0
        # Surface the new file name right away so the user sees immediate feedback
        # even before the deferred sections/hex refreshes complete.
        status_message = self._format_coexistence_status(loaded, path)
        self.set_file_status(status_message)
        self._append_log_line(status_message)
        self.logger.info(
            "Load phase boundary: apply_install_state path=%s precomputed=%s",
            path.name,
            prepared.precomputed,
        )
        self._flush_logger()

        precomputed_oor = prepared.mac_out_of_range if prepared.precomputed else None

        # Inc 10a E4-R5 (I-D17): each deferred step returns without acting —
        # and ends the chain — once the tree it renders into is gone (a quit
        # confirmed while the load was held: the app is exiting).
        def _step_sections() -> None:
            if self._load_tree_gone():
                return
            try:
                if precomputed_oor is not None:
                    self.update_sections(precomputed_out_of_range=precomputed_oor)
                else:
                    self.update_sections()
            finally:
                self.logger.info(
                    "Load phase boundary: apply_sections_done path=%s", path.name
                )
                self._flush_logger()
                self.call_later(_step_hex)

        def _step_hex() -> None:
            if self._load_tree_gone():
                return
            try:
                self.update_hex_view()
                self.update_alt_hex_view()
                self.update_mac_hex_view()
            finally:
                self.logger.info(
                    "Load phase boundary: apply_hex_done path=%s", path.name
                )
                self._flush_logger()
                self.call_later(_step_finalize)

        def _step_finalize() -> None:
            if self._load_tree_gone():
                return
            try:
                self.update_project_labels()
                # LLR-166.1: the install may have re-focused the Split / Join
                # table through ``watch_current_file`` (``refresh_window``
                # does so only while that window is shown); land the focus
                # on the displayed window's target.
                self._rehome_focus_after_load()
                # Inc 10a E4-R3 (HLR-166): a rail-item or fallback focus
                # moves to the target once the loaded view shows it.
                self._rehome_placeholder_focus_after_load()
            finally:
                total_elapsed = time.perf_counter() - load_started
                self.logger.info(
                    "Loaded file successfully: path=%s file_type=%s elapsed_seconds=%.3f has_mac=%s precomputed=%s",
                    path,
                    loaded.file_type,
                    total_elapsed,
                    bool(loaded.mac_records),
                    prepared.precomputed,
                )
                self._flush_logger()

        if publish_a2l:
            self._refresh_a2l_dependent_views()
        self.call_later(_step_sections)
        return True

    def _format_coexistence_status(self, loaded: LoadedFile, path: Path) -> str:
        """
        Summary:
            Compose a short status line that reflects whether S19/HEX and MAC coexist.

        Args:
            loaded (LoadedFile): Payload about to be rendered.
            path (Path): Current source file used for the human-readable name.

        Returns:
            str: Status text for the file-status label, activity log, and progress bar.

        Data Flow:
            - Classify the loaded payload as primary-only, MAC-only, or primary+MAC.
            - Include the source file name and, when available, an attached MAC name.
            - HLR-154 / UX-C7: when the load carries an integrity notice (a
              truncated or inconsistent image), the line LEADS with the
              defect — ``Loaded <name> with integrity notices: <code>`` —
              never a plain ``Loaded <name>``. The text is file-derived and
              reaches ``#status_text`` (``markup=False``), so a hostile file
              name renders literally (UX-C10).

        Dependencies:
            Used by:
                - ``_apply_loaded_file``
        """
        codes = _integrity_notice_codes(getattr(loaded, "errors", None))
        name = painted_names([path.name])
        if codes:
            return (
                f"Loaded {name} with integrity notices: "
                f"{', '.join(codes)}"
            )
        if loaded.file_type in {"s19", "hex"} and loaded.mac_records:
            if loaded.mac_path and loaded.mac_path != path:
                return (
                    f"Loaded {name} ({loaded.file_type.upper()}+MAC: "
                    f"{painted_names([loaded.mac_path.name])})"
                )
            return f"Loaded {name} ({loaded.file_type.upper()}+MAC)"
        if loaded.file_type in {"s19", "hex"}:
            return f"Loaded {name} ({loaded.file_type.upper()} only)"
        if loaded.file_type == "mac":
            return f"Loaded {name} (MAC only)"
        return f"Loaded {name}"

    def _log_loaded_file_summary(
        self,
        file_type: str,
        path: Path,
        mem_map: dict[int, int],
        ranges: list[tuple[int, int]],
        errors: list[dict[str, Any]],
    ) -> None:
        """
        Summary:
            Emit standardized post-parse diagnostics for S19, HEX, and MAC load branches.

        Args:
            file_type (str): Loader branch identifier (``s19``, ``hex``, ``mac``).
            path (Path): Parsed file path.
            mem_map (dict[int, int]): Materialized memory map keyed by absolute address.
            ranges (list[tuple[int, int]]): Contiguous ranges as ``(start, end_exclusive)``.
            errors (list[dict[str, Any]]): Parser diagnostics in normalized dict form.

        Returns:
            None

        Data Flow:
            - Compute aggregate metrics (address count, total bytes, range count, error count).
            - Emit INFO summary for searchable diagnostics.
            - Emit WARNING with compact samples when parser errors exist.

        Dependencies:
            Uses:
                - ``logger.info`` / ``logger.warning``
            Used by:
                - ``load_selected_file``
        """
        range_bytes = sum(max(0, end - start) for start, end in ranges)
        self.logger.info(
            "Load summary: file_type=%s path=%s addresses=%d range_count=%d range_bytes=%d errors=%d",
            file_type,
            path,
            len(mem_map),
            len(ranges),
            range_bytes,
            len(errors),
        )
        if errors:
            sample = []
            for item in errors[:3]:
                segment = item.get("segment")
                line_number = item.get("line_number")
                message = item.get("error") or item.get("message")
                sample.append(f"line={line_number} segment={segment} error={message}")
            self.logger.warning("Load diagnostics: file_type=%s path=%s sample=%s", file_type, path, " | ".join(sample))
