"""s19_app.tui.app.flow — S19TuiApp mixin: flow (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from pathlib import Path
import stat
from typing import List, Optional, Tuple
from ...utils import safe_text
from ..screens import (
    ConfirmDiscardScreen,
    ConfirmQuestionScreen,
    FileRefCandidate,
    FileRefChoice,
    FileRefChooserScreen,
    FlowBlockEditScreen,
    LoadFlowScreen,
    SaveFlowScreen,
)
from ..flow_screens import (
    BrowseRequested,
    FlowBuilderPanel,
    FlowExecutionPanel,
    FlowRefContext,
    fx_run_error_line,
)
from ..workspace import WorkareaContainmentError, list_workarea_files
from . import deps


class FlowMixin:

    def on_flow_builder_panel_run_requested(
        self, event: "FlowBuilderPanel.RunRequested"
    ) -> None:
        """Run the composed flow over the active project and paint the result.

        Summary:
            Handle the rail-8 Run (R-TUI-059): resolve the active project
            directory and execute the flow via the Textual-free
            ``flow_execution_service`` (reads bounded to the project, writes to
            the work area — batch-44 security F1/F2), then hand the result back
            to the panel. A no-project state renders an error result instead of
            running. Runs synchronously — acceptable for the tracer's small
            images; a worker is deferred to polish.

            batch-97 (D8, LLR-146.12): the Builder runs the single image only;
            the batch-70 variant branch is deleted — multi-variant runs live in
            Flow Execution, one chain per variant. ``RunRequested.scope`` stays
            in the frozen message shape and always carries
            ``FLOW_SCOPE_SINGLE``.

        Args:
            event (FlowBuilderPanel.RunRequested): Carries the composed flow.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``run_flow``
            Used by:
                - ``FlowBuilderPanel`` Run button (message dispatch)
        """
        from ..services.flow_execution_service import run_flow
        from ..services.flow_model import (
            FLOW_STATUS_ERROR,
            FlowContext,
            FlowRunResult,
        )

        panel = self.query_one("#flow_panel", FlowBuilderPanel)
        project_dir = self._active_project_dir()
        if project_dir is None:
            panel.render_result(
                FlowRunResult(
                    status=FLOW_STATUS_ERROR,
                    diagnostics=["no project loaded - load a project first"],
                )
            )
            return
        # batch-95 inc-004b (LLR-143.2): retain the run result so the A2B
        # diff report can later attribute an image B this flow produced —
        # the provenance seat mirrors the retained _diff_last_result.
        self._last_flow_run = run_flow(
            event.flow, FlowContext(project_dir=project_dir)
        )
        panel.render_result(self._last_flow_run)

    def _flow_no_project_error(self, panel: "FlowBuilderPanel") -> None:
        """Render the no-project error card on the flow panel (mirrors Run)."""
        from ..services.flow_model import FLOW_STATUS_ERROR, FlowRunResult

        panel.render_result(
            FlowRunResult(
                status=FLOW_STATUS_ERROR,
                diagnostics=["no project loaded - load or save a project first"],
            )
        )

    def on_flow_builder_panel_save_requested(
        self, event: "FlowBuilderPanel.SaveRequested"
    ) -> None:
        """Save the composed flow to ``flows/<name>.json`` (batch-53, LLR-003.7).

        Summary:
            Resolve the active project, list existing saved flows for the
            overwrite notice, and open :class:`SaveFlowScreen`. On confirm, write
            through ``save_flow_json`` (``sanitize_project_name`` is the write-side
            containment authority) and mark the panel saved; a no-project state
            renders the error card, an un-sanitisable name a status message.
            A ``flows/`` home that passes through a link or lies outside the
            work area (``WorkareaContainmentError``) refuses the save with
            its own status line (R-FB-SAVE.8), and nothing is marked saved.

        Args:
            event (FlowBuilderPanel.SaveRequested): Carries the current flow.
        """
        from ..services.flow_persistence_service import list_saved_flows, save_flow_json

        panel = self.query_one("#flow_panel", FlowBuilderPanel)
        project_dir = self._active_project_dir()
        if project_dir is None:
            self._flow_no_project_error(panel)
            return
        existing = list_saved_flows(project_dir)

        def _do_save(raw_name: Optional[str]) -> None:
            if raw_name is None:
                return
            try:
                saved = save_flow_json(
                    event.flow, raw_name, project_dir, workarea_root=self.workarea
                )
            except WorkareaContainmentError:
                self.set_status(
                    "Flow not saved - the project's flows folder is a link or is "
                    "outside the work area."
                )
                return
            if saved is None:
                self.set_status("Flow name is empty after sanitising - not saved.")
                return
            panel.mark_saved(saved.stem)

        self.push_screen(SaveFlowScreen(event.flow.name, existing), _do_save)

    def on_flow_builder_panel_load_requested(
        self, event: "FlowBuilderPanel.LoadRequested"
    ) -> None:
        """Load a saved flow into the panel, hardened (batch-53, LLR-003.7).

        Summary:
            Resolve the active project, list ``flows/*.json``, and open
            :class:`LoadFlowScreen` (which also handles Import). On a chosen stem,
            load through the fail-closed ``load_flow_json``: a valid flow is routed
            to ``panel.set_blocks`` (identity = the stem), a rejection to the
            quarantine card (current flow untouched). A no-project state renders
            the error card.

        Args:
            event (FlowBuilderPanel.LoadRequested): The Load request (no payload).
        """
        from ..services.flow_persistence_service import (
            FLOWS_SUBDIR,
            list_saved_flows,
            load_flow_json,
        )

        panel = self.query_one("#flow_panel", FlowBuilderPanel)
        project_dir = self._active_project_dir()
        if project_dir is None:
            self._flow_no_project_error(panel)
            return
        flows = list_saved_flows(project_dir)

        def _do_load(stem: Optional[str]) -> None:
            if stem is None:
                return
            flow_path = project_dir / FLOWS_SUBDIR / f"{stem}.json"
            loaded, findings = load_flow_json(flow_path, project_dir)
            if loaded is None:
                panel.render_quarantine(stem, findings)
                return
            # Dirty-guard (OQ-3 / LLR-003.6): confirm-discard before replacing
            # UNSAVED edits; a clean flow loads without the prompt.
            if panel.is_dirty:
                def _after_confirm(discard: Optional[bool]) -> None:
                    if discard:
                        panel.set_blocks(loaded, name=stem)

                self.push_screen(ConfirmDiscardScreen(stem), _after_confirm)
            else:
                panel.set_blocks(loaded, name=stem)

        self.push_screen(LoadFlowScreen(flows, project_dir), _do_load)

    def on_flow_builder_panel_edit_requested(
        self, event: "FlowBuilderPanel.EditRequested"
    ) -> None:
        """Open the block-edit modal for the picked block (batch-102 Inc 6).

        Summary:
            The Edit half of the panel's message coordination (E3 ruling 3):
            the panel resolved the pick and the containment base (as Paste
            does) and posted the target; the app snapshots the chain's wire
            projection, pushes :class:`FlowBlockEditScreen` and, on a saved
            candidate, applies it through the panel's PUBLIC
            ``replace_block`` — the panel is never touched through a
            private seam. A cancel dismisses with ``None`` and changes
            nothing (R-B102-FB-003 keeps the original on a refused save —
            the modal itself never dismisses with a finding).

        Args:
            event (FlowBuilderPanel.EditRequested): Carries the target
                index, the block and the resolved base (possibly ``None`` —
                the modal's Save then refuses in-modal, E3 ruling 4).
        """
        from ..services import flow_persistence_service as fps

        panel = self.query_one("#flow_panel", FlowBuilderPanel)
        #: The CURRENT wire envelope the candidate validates against — the
        #: same ``flow_to_dict`` projection persistence uses.
        wire_blocks = fps.flow_to_dict(panel.current_flow)["blocks"]
        index = event.index

        def _apply(replacement: Optional["FlowBlock"]) -> None:
            if replacement is None:
                return  # cancelled (or refused — the modal stays, so None is a cancel)
            panel.replace_block(index, replacement)

        self.push_screen(
            FlowBlockEditScreen(index, event.block, wire_blocks, event.base_dir),
            _apply,
        )

    def on_flow_builder_panel_remove_requested(
        self, event: "FlowBuilderPanel.RemoveRequested"
    ) -> None:
        """Confirm, then remove exactly the picked block (batch-102 Inc 6).

        Summary:
            The Remove half of the message coordination (E3 ruling 3): the
            app pushes the safe confirm — initial focus and the accent on
            Cancel, ``escape`` cancels (E3 ruling 8) — and on a yes applies
            the removal through the panel's PUBLIC ``remove_block``, which
            re-checks the range immediately before mutating. The index is
            captured here, when the screen opens; the funnel and the
            clipboard survive (R-B102-FB-004).

        Args:
            event (FlowBuilderPanel.RemoveRequested): Carries the target
                index and the block (its kind names the confirm).
        """
        panel = self.query_one("#flow_panel", FlowBuilderPanel)
        index = event.index
        title = safe_text(
            f"Remove block #{index + 1} ({event.block.kind})?"
        ).plain
        body = safe_text("This cannot be undone.").plain

        def _apply(confirmed: Optional[bool]) -> None:
            if confirmed:
                panel.remove_block(index)

        question = ConfirmQuestionScreen(title, body, "Remove (y)", "Cancel (n)")
        # The safe default carries the emphasis (OBS-12b-2): focus already starts
        # on Cancel via AUTO_FOCUS; the primary style follows it as well.
        question.PRIMARY_BUTTON = "confirm_no"
        self.push_screen(question, _apply)

    # -- flow file refs (batch-102 Inc 7, US-102-07; R-B102-FILE-001..007) -----

    def _flow_project_file_names(self, project_dir: Optional[Path]) -> Tuple[str, ...]:
        """The active project's direct-child FILE names (Inc 7 candidates
        and the card-annotation project list).

        Regular, non-link direct children only — a symlink or junction in
        the project dir NEVER appears in the chooser (E3-ruling addendum),
        and neither do subfolders.  An unlistable/missing dir is ``()``.
        """
        if project_dir is None:
            return ()
        try:
            entries = sorted(Path(project_dir).iterdir())
        except OSError:
            return ()
        names: List[str] = []
        for entry in entries:
            try:
                entry_stat = deps.os.lstat(entry)
            except OSError:
                continue
            if not stat.S_ISREG(entry_stat.st_mode) or deps._is_reparse_point(entry):
                continue
            names.append(entry.name)
        return tuple(names)

    def _loaded_artifact_paths(self) -> Tuple[Path, ...]:
        """The DISTINCT on-disk paths of the currently loaded artifacts
        (primary image, MAC, A2L) — the chooser's Loaded section and the
        annotation's ``loaded`` list."""
        loaded = self.current_file
        if loaded is None:
            return ()
        paths: List[Path] = []
        for raw in (loaded.path, loaded.mac_path, loaded.a2l_path):
            if raw is None:
                continue
            path = Path(raw)
            if path not in paths:
                paths.append(path)
        return tuple(paths)

    def _flow_ref_context(self) -> Optional[FlowRefContext]:
        """The CURRENT card-annotation context (E3 ruling 7): the panel's
        provider calls this at every repaint, so the annotations always
        classify against the live project/temp/loaded listing.  The app
        side MAY list directories; the classifier it feeds never does
        (E3 ruling 5)."""
        project_dir = self._active_project_dir()
        try:
            temp_names = tuple(p.name for p in list_workarea_files(self.workarea))
        except OSError:
            temp_names = ()
        return FlowRefContext(
            project_root=project_dir,
            project_names=self._flow_project_file_names(project_dir),
            temp_names=temp_names,
            loaded_names=tuple(p.name for p in self._loaded_artifact_paths()),
        )

    def _flow_ref_candidates(
        self, project_dir: Optional[Path]
    ) -> List[FileRefCandidate]:
        """The chooser's candidates (R-B102-FILE-002): project files, then
        workarea temp files, then the loaded artifacts — each temp/loaded
        entry carrying its source path so a pick outside the project
        imports through the hardened safe path first (E3 ruling 1)."""
        candidates: List[FileRefCandidate] = []
        for name in self._flow_project_file_names(project_dir):
            candidates.append(
                FileRefCandidate(label=name, ref=name, origin="project")
            )
        for path in list_workarea_files(self.workarea):
            candidates.append(
                FileRefCandidate(
                    label=path.name, ref=path.name, origin="temp", source=path
                )
            )
        project_resolved: Optional[Path] = None
        if project_dir is not None:
            try:
                project_resolved = Path(project_dir).resolve()
            except (OSError, ValueError, RuntimeError):
                project_resolved = None
        for path in self._loaded_artifact_paths():
            label = f"current ({path.name})"
            if project_resolved is not None:
                try:
                    relative = path.resolve().relative_to(project_resolved)
                except (OSError, ValueError, RuntimeError):
                    relative = None
                if relative is not None and relative.as_posix() not in ("", "."):
                    # Already inside the project: the direct relative ref
                    # is written, no copy (E3 ruling 1).
                    candidates.append(
                        FileRefCandidate(
                            label=label,
                            ref=relative.as_posix(),
                            origin="loaded",
                        )
                    )
                    continue
            if project_dir is not None and (Path(project_dir) / path.name).is_file():
                # The shipped load synced this artifact into the project; the
                # project-relative name is the runnable ref, not a new import.
                candidates.append(
                    FileRefCandidate(label=label, ref=path.name, origin="loaded")
                )
                continue
            candidates.append(
                FileRefCandidate(
                    label=label, ref=path.name, origin="loaded", source=path
                )
            )
        return candidates

    def on_browse_requested(self, event: BrowseRequested) -> None:
        """Open the file-ref chooser for a flow host's Browse chip
        (batch-102 Inc 7, R-B102-FILE-002; E3 ruling 2 — the app
        coordinates the modal, never the host)."""
        self._open_file_ref_chooser(event.input_id)

    def _open_file_ref_chooser(self, input_id: str) -> None:
        """Push :class:`FileRefChooserScreen` over the requesting host and
        route the pick back to it."""
        project_dir = self._active_project_dir()
        candidates = self._flow_ref_candidates(project_dir)

        def _apply(choice: Optional[FileRefChoice]) -> None:
            if choice is None:
                return  # cancelled — the host field keeps its text
            self._apply_flow_ref_choice(input_id, choice)

        self.push_screen(
            FileRefChooserScreen(candidates, project_dir), _apply
        )

    def _apply_flow_ref_choice(self, input_id: str, choice: FileRefChoice) -> None:
        """Write the browsed ref into the host that owns the field
        (R-B102-FILE-003; E3 ruling 2): the ``FlowBlockEditScreen`` when it
        sits under the chooser, else the Flow Builder's add form.  Only
        the field changes — no block is added or edited."""
        screen = self.screen
        if isinstance(screen, FlowBlockEditScreen):
            screen.apply_browsed_ref(input_id, choice.ref)
        else:
            try:
                panel = self.query_one("#flow_panel", FlowBuilderPanel)
            except Exception:  # noqa: BLE001 - panel not mounted: nothing to fill
                return
            panel.apply_browsed_ref(input_id, choice.ref)
        if choice.origin == "external":
            self.set_status(safe_text(f"imported as {choice.ref}").plain)

    # -- Flow Execution (fx_a, batch-94 Inc-003; US-007, HLR-017…021) ---------

    def _prefill_flow_execution_sets(self) -> None:
        """Repopulate the set picker on entry (LLR-021.2's restore seam)."""
        from ..services.flow_persistence_service import list_chain_sets

        panel = self.query_one("#fx_panel", FlowExecutionPanel)
        project_dir = self._active_project_dir()
        panel.set_available_sets(
            list_chain_sets(project_dir) if project_dir is not None else []
        )

    def on_flow_execution_panel_import_requested(
        self, event: "FlowExecutionPanel.ImportRequested"
    ) -> None:
        """Import a builder template as a new lane (HLR-017, LLR-017.1).

        Summary:
            Resolve the active project, list ``flows/*.json``, and open the
            existing :class:`LoadFlowScreen` picker (its Import… arm copies
            an external template into ``flows/`` containment-guarded, so the
            operator can import from anywhere). On a chosen stem, load through
            the fail-closed ``load_flow_json``: a valid template mounts one
            lane via :meth:`FlowExecutionPanel.add_lane`; a rejection paints
            the import notice (0 lanes mounted — LLR-017.1's invalid arm). A
            cancelled picker changes nothing (the cancel arm).

        Args:
            event (FlowExecutionPanel.ImportRequested): The import request
                (no payload).
        """
        from ..services.flow_persistence_service import (
            FLOWS_SUBDIR,
            list_saved_flows,
            load_flow_json,
        )

        panel = self.query_one("#fx_panel", FlowExecutionPanel)
        project_dir = self._active_project_dir()
        if project_dir is None:
            panel.render_import_refusal(
                "?", [self._flow_issue("no project loaded - load or save a project first")]
            )
            return
        flows = list_saved_flows(project_dir)

        def _do_import(stem: Optional[str]) -> None:
            if stem is None:
                return  # cancelled — 0 lanes mounted (LLR-017.1 cancel arm)
            flow_path = project_dir / FLOWS_SUBDIR / f"{stem}.json"
            loaded, findings = load_flow_json(flow_path, project_dir)
            if loaded is None:
                panel.render_import_refusal(stem, findings)
                return
            panel.add_lane(stem, loaded)

        self.push_screen(LoadFlowScreen(flows, project_dir), _do_import)

    @staticmethod
    def _flow_issue(message: str):
        from ...validation.model import ValidationIssue, ValidationSeverity

        return ValidationIssue(
            code="FX-NO-PROJECT",
            severity=ValidationSeverity.ERROR,
            message=message,
            artifact="flow",
        )

    def on_flow_execution_panel_run_requested(
        self, event: "FlowExecutionPanel.RunRequested"
    ) -> None:
        """Run the lane set and paint the fx_a lanes + run log (HLR-019/020).

        Summary:
            Translate the panel's lane payloads into the service's
            ``ChainSpec`` plan (per-chain independent bindings, LLR-018) and
            dispatch ``run_chain_set`` — sequential default, parallel per
            chain when the operator drove the mode control (LLR-019.2's C-10
            non-default arm). The service wraps the union ``run_flow`` per
            chain; this handler re-implements no block semantics. The record
            comes back to :meth:`FlowExecutionPanel.render_run` for the lanes
            + the run-log strip; a REFUSED set (no outcomes, D7
            diagnostics) also paints its outcome-first line on the status
            line (LLR-155.5, finding F2); a no-project state paints the log
            error instead of running.

        Args:
            event (FlowExecutionPanel.RunRequested): Carries the lanes, the
                mode token, and the set name.
        """
        from ..services.flow_execution_service import ChainSpec, run_chain_set
        from ..services.flow_model import FlowContext

        panel = self.query_one("#fx_panel", FlowExecutionPanel)
        project_dir = self._active_project_dir()
        if project_dir is None:
            panel.render_run_error(
                "no project loaded - load or save a project first"
            )
            return
        chains = [
            ChainSpec(
                name=lane.name,
                template=lane.template,
                flow=lane.flow,
                bindings=dict(lane.bindings),
            )
            for lane in event.lanes
        ]
        # batch-97 D14: a run that raises paints one English line and
        # enables Run again; it never escapes the handler.
        try:
            record = run_chain_set(
                chains,
                FlowContext(project_dir=project_dir),
                mode=event.mode,
                set_name=event.set_name,
            )
        except Exception as exc:  # noqa: BLE001 - every raise becomes one line
            panel.render_run_error(fx_run_error_line(exc))
            return
        panel.render_run(record)
        if not record.outcomes and record.diagnostics:
            # HLR-155 D7 / LLR-155.5 (review finding F2): a refused set's
            # outcome-first line must reach the status line (#log_line_4),
            # not only the run log — the label's markup stays off, so the
            # lane names paint literally (UX-C10) and the outcome leads
            # inside UX-C4's first 50 characters. (The confirm re-run below
            # drives ONE lane, which D7 can never refuse — a collision needs
            # two lanes — so it needs no such paint.)
            self.set_status(record.diagnostics[0])

    def on_flow_execution_panel_save_requested(
        self, event: "FlowExecutionPanel.SaveRequested"
    ) -> None:
        """Persist the chain set to ``flowsets/<name>.json`` (HLR-021).

        Summary:
            Translate the lane payloads into the ``ChainSetEntry`` envelope
            (chains + bound inputs + recorded outputs, LLR-021.1) and write
            through ``save_chain_set`` — the sanitiser is the write-side
            containment authority; an empty set (0 lanes) or an un-sanitisable
            name writes NOTHING and surfaces one status line. A successful
            save marks the panel saved (identity = the stem). A ``flowsets/``
            home that passes through a link or lies outside the work area
            (``WorkareaContainmentError``) refuses the save with its own
            status line (R-FX-SET.15), and nothing is marked saved.

        Args:
            event (FlowExecutionPanel.SaveRequested): Carries the lanes and
                the raw operator-typed name.
        """
        from ..services.flow_persistence_service import ChainSet, ChainSetEntry, save_chain_set

        panel = self.query_one("#fx_panel", FlowExecutionPanel)
        project_dir = self._active_project_dir()
        if project_dir is None:
            self.set_status("No project loaded - load or save a project first.")
            return
        chain_set = ChainSet(
            name=event.raw_name.strip() or "chain-set",
            chains=tuple(
                ChainSetEntry(
                    chain=lane.name,
                    template=lane.template,
                    # lane.bindings rides as (index, ref) pairs — the panel's
                    # effective-input contract (>=1 input per chain).
                    inputs=tuple(sorted(lane.bindings)),
                    outputs=tuple(lane.outputs),
                )
                for lane in event.lanes
            ),
        )
        try:
            saved = save_chain_set(
                chain_set, event.raw_name, project_dir, workarea_root=self.workarea
            )
        except WorkareaContainmentError:
            self.set_status(
                "Chain set not saved - the project's flowsets folder is a link or is "
                "outside the work area."
            )
            return
        if saved is None:
            self.set_status(
                "Chain set not saved - the set is empty or the name sanitised away."
            )
            return
        panel.mark_saved(saved.stem)
        self._prefill_flow_execution_sets()

    async def on_flow_execution_panel_load_set_requested(
        self, event: "FlowExecutionPanel.LoadSetRequested"
    ) -> None:
        """Reload a saved set and restore its lanes for a re-run (LLR-021.2).

        Summary:
            Load the set fail-closed through ``load_chain_set`` (a corrupt set
            is refused with the notice, 0 lanes change). For every chain,
            re-load its template through the hardened ``load_flow_json`` and
            restore the lane with its bound inputs + recorded outputs; a
            chain whose template is gone is skipped and NAMED in the notice.
            A bound input whose file moved is NOT a refusal — the lane mounts
            with the per-lane provenance-mismatch notice (LLR-021.2's error
            arm: never a silent stale run).

        Args:
            event (FlowExecutionPanel.LoadSetRequested): Carries the chosen
                ``flowsets/<stem>.json`` identity.
        """
        from ..services.flow_persistence_service import (
            FLOWS_SUBDIR,
            load_chain_set,
            load_flow_json,
        )

        panel = self.query_one("#fx_panel", FlowExecutionPanel)
        project_dir = self._active_project_dir()
        if project_dir is None:
            self.set_status("No project loaded - load or save a project first.")
            return
        set_path = project_dir / "flowsets" / f"{event.stem}.json"
        loaded, findings = load_chain_set(set_path, project_dir)
        if loaded is None:
            first = findings[0].message if findings else "unreadable set"
            panel.render_set_refusal(event.stem, findings)
            self.set_status(f"Chain set load refused: {first}")
            return
        # A successful reload REPLACES the lanes with the restored set (the
        # C-12 chain: the reloaded set is what re-runs, never a merge). The
        # lane clearing is awaited — the restored lanes mount onto the emptied
        # container, never a half-removed tree.
        await panel.begin_set_restore(event.stem)
        skipped: List[str] = []
        restored = 0
        for entry in loaded.chains:
            template_path = project_dir / FLOWS_SUBDIR / f"{entry.template}.json"
            flow, template_findings = load_flow_json(template_path, project_dir)
            if flow is None:
                skipped.append(entry.chain)
                continue
            bindings = {index: ref for index, ref in entry.inputs}
            missing = [
                ref
                for ref in bindings.values()
                if not (project_dir / ref).exists()
            ]
            panel.restore_lane(
                entry.chain,
                entry.template,
                flow,
                bindings,
                entry.outputs,
                missing,
            )
            restored += 1
        notices: List[str] = []
        if skipped:
            notices.append(
                "chain(s) skipped, template missing: " + ", ".join(skipped)
            )
        if restored:
            notices.append(f"{restored} chain(s) restored")
        panel.restore_set(event.stem, restored, notices)

    def _publish_flow_session_dir(self) -> None:
        """Push the active project dir to the flow panels' session strip.

        The external-step contract (spec v3, PENDIENTES-batch96) shows the
        session artifacts dir at all times; the executor copies the confirmed
        step output into this very dir (flow_execution_service), so the
        displayed value IS the copy destination. No project -> "" restores
        the panels' shipped default text.
        """
        project_dir = self.active_project_dir()
        value = str(project_dir) if project_dir is not None else ""
        for panel_type in (FlowBuilderPanel, FlowExecutionPanel):
            try:
                panel = self.query_one(panel_type)
            except Exception:  # noqa: BLE001 - panels not mounted yet
                continue
            panel.set_session_dir(value)
        #: batch-102 Inc 7: the project change also changes the card
        #: annotation context (E3 ruling 7) — repaint without a block edit.
        try:
            self.query_one("#flow_panel", FlowBuilderPanel).refresh_flow_ref_annotations()
        except Exception:  # noqa: BLE001 - panel not mounted yet
            pass
