"""s19_app.tui.app.checks_diff — S19TuiApp mixin: checks_diff (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence
from ...core import S19File
from ..changes.check import run_check_document
from ..changes.io import read_change_document
from ..changes.model import ChangeDocument, ChangeEntry
from ..screens_directionb import AbDiffPanel, CheckEditorPanel
from ..color_policy import css_class_for_severity
from ...validation import ValidationSeverity
from ..services.compare_service import SOURCE_EXTERNAL, SOURCE_PROJECT_VARIANT, ImageSource
from ..services.diff_report_service import flow_change_attribution
from ..services.load_service import build_loaded_hex
from . import deps


#: The Check Editor's routable action set (LLR-001.2) — write and validate
#: only; the no-apply doctrine (LLR-009.3) means the set has no apply member
#: by construction. A non-member action is one status error, never a crash.
CHECK_EDITOR_ACTIONS: frozenset[str] = frozenset({"write_doc", "validate_doc"})


class ChecksDiffMixin:

    def _prefill_diff_variants(self) -> None:
        """
        Summary:
            Prefill the A↔B Diff panel's variant ``Select`` dropdowns from the
            active project's ``ProjectVariantSet`` (LLR-005.1). Called when the
            diff screen activates; a no-project session yields an empty list
            (the panel keeps only its external-path option).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Map each ``VariantDescriptor`` to a ``(label, variant_id)`` pair
              and hand them to ``AbDiffPanel.set_variants``.

        Dependencies:
            Uses:
                - ``AbDiffPanel.set_variants``
            Used by:
                - ``action_show_screen`` (diff activation)
        """
        panel = self.query_one("#ab_diff_panel", AbDiffPanel)
        variants = (
            [(v.variant_id, v.variant_id) for v in self._variant_set.variants]
            if self._variant_set is not None
            else []
        )
        panel.set_variants(variants)

    def _prefill_diff_check_files(self) -> None:
        """Populate the A2B Diff check-spec dropdown (LLR-010.1).

        Summary:
            Hand the patches-folder scan (patch ``*.json`` AND check-spec
            ``*.chk.json`` files, sorted, symlinks skipped) to
            ``AbDiffPanel.set_check_files`` so the dropdown lists both kinds
            suffix-distinguished. Called on diff-screen activation; a
            not-yet-mounted panel is tolerated as a no-op.
        """
        try:
            panel = self.query_one("#ab_diff_panel", AbDiffPanel)
        except Exception:
            return
        panel.set_check_files(self._scan_spec_files())

    # ------------------------------------------------------------------
    # Check Editor (batch-94, US-003 — the ce_a collector)
    # ------------------------------------------------------------------

    def _prefill_check_editor(self) -> None:
        """Populate the Check Editor collector on screen entry (LLR-001.2).

        Summary:
            Hand the suffix-distinguished patches-folder listing to the
            spec dropdown and the loaded A2L's measurable parameters to the
            picker. The picker signature is the safe Inc-2
            ``_a2l_enriched_key``: re-entering the screen with the same A2L
            and image is a no-op that preserves the filter, the page and the
            picks (R-B102-SEL-004). A not-yet-mounted panel (headless unit
            path) is tolerated as a no-op, matching
            ``_prefill_patch_change_files``.
        """
        try:
            panel = self.query_one("#check_editor_panel", CheckEditorPanel)
        except Exception:
            return
        panel.set_spec_files(self._scan_spec_files())
        tags = self._compute_a2l_enriched_tags()
        measurable = [
            tag for tag in tags if isinstance(tag.get("address"), int)
        ]
        panel.set_a2l_parameters(measurable, self._a2l_enriched_key)

    def _check_items_to_document(
        self, items: Sequence[dict]
    ) -> tuple[ChangeDocument, int]:
        """Assemble the ``kind="check"`` document from collector items (LLR-009.1).

        Summary:
            One :class:`ChangeEntry` per collected field, in collector order.
            A field loaded from a spec carries its spec entry's bytes in
            ``expected`` (a tuple of exactly ``size`` ints); they are
            declared as they are and the image is not read, so such a field
            is never skipped for lack of an image (amended *declared field*,
            R-CHKED-026 / R-CHKED-027). Any other field takes the EXPECTED
            bytes read from the loaded image's memory map at
            ``[address, address + size)`` — the current image state. Such a
            field whose address is missing, negative or not fully mapped in
            the loaded image cannot declare expected bytes and is SKIPPED
            (counted in the return); with no image loaded every such field
            is skipped, and a spec with no field left still writes EMPTY
            (LLR-009.1's empty arm). No bytes are ever written to the image
            — the document is data, and the apply gate is what keeps it
            inert (LLR-009.3).
        """
        from ..changes.io import FORMAT_ID, FORMAT_VERSION

        loaded = self.current_file
        mem_map = loaded.mem_map if loaded is not None else None
        entries: list[ChangeEntry] = []
        skipped = 0
        for item in items:
            address = item.get("address")
            size = int(item.get("size") or 1)
            if not isinstance(address, int) or address < 0 or size <= 0:
                skipped += 1
                continue
            spec_expected = item.get("expected")
            if isinstance(spec_expected, tuple) and len(spec_expected) == size:
                # A field loaded from a spec declares the spec's bytes at its
                # own entry's range; the image is not read (amended "declared
                # field", Inc 5 D9-11 / R-CHKED-026).
                entries.append(
                    ChangeEntry("bytes", address, spec_expected, value=None)
                )
                continue
            expected: list[int] = []
            if mem_map is not None:
                for offset in range(size):
                    byte = mem_map.get(address + offset)
                    if byte is None:
                        expected = []
                        break
                    expected.append(int(byte))
            if not expected:
                skipped += 1
                continue
            entries.append(
                ChangeEntry("bytes", address, tuple(expected), value=None)
            )
        return (
            ChangeDocument(
                format=FORMAT_ID,
                version=FORMAT_VERSION,
                kind="check",
                encoding="utf-8",
                value_mode="text",
                entries=entries,
            ),
            skipped,
        )

    def on_check_editor_panel_action_requested(
        self, event: CheckEditorPanel.ActionRequested
    ) -> None:
        """Route a Check Editor write/validate action (LLR-001.2/.009).

        Summary:
            Exactly the two :data:`CHECK_EDITOR_ACTIONS` — a non-member
            action is one status error, never a crash. ``write_doc``
            assembles the ``kind="check"`` document (expected bytes from the
            spec for a field loaded from one, else from the loaded image),
            writes it through ``changes.io.
            write_change_document`` under the operator's name (the
            ``.chk.json`` suffix is preserved by ``_safe_name``), surfaces
            the outcome and refreshes the folder listing so the new spec
            appears suffix-distinguished in every dropdown. ``validate_doc``
            assembles the same document and runs it through the shipped
            ``run_check_document`` (no image → every entry ``uncheckable``),
            feeding one verdict row per entry back to the panel.
        """
        panel = self.query_one("#check_editor_panel", CheckEditorPanel)
        if event.action not in CHECK_EDITOR_ACTIONS:
            self.set_status(
                f"Check Editor: unsupported action {event.action!r}"
            )
            return
        loaded = self.current_file
        loaded_ranges = loaded.ranges if loaded is not None else None
        mac_records = loaded.mac_records if loaded is not None else None
        a2l_tags = self._compute_a2l_enriched_tags() or None
        document, skipped = self._check_items_to_document(event.items)
        file_name = event.file_name_text.strip() or "spec.chk.json"
        if skipped:
            self.set_status(
                f"Check Editor: {skipped} field(s) outside the loaded "
                "image — not declared."
            )
        if event.action == "write_doc":
            path, issues = deps.write_change_document(
                document, self.base_dir, file_name, dest_dir=self._check_home()
            )
            for issue in issues:
                self.set_status(
                    f"[{issue.code}] {issue.severity.value}: {issue.message}"
                )
            if path is None:
                self.set_status("Check Editor: spec NOT written.")
                # LLR-148.9: the refusal also paints one English line in the
                # REPORT FIELDS card, naming the finding codes.
                codes = ", ".join(sorted({issue.code for issue in issues}))
                panel.show_status_line(
                    f"Write refused: {codes or 'not written'}."
                )
            else:
                # R-CHKED-032: name the file as the Spec list lists it
                # (``checks/<n>`` in a project), not only its bare name.
                home_prefix = self._spec_homes()[0][0]
                self.set_status(
                    f"Check Editor: wrote {home_prefix}{path.name} "
                    f"({len(document.entries)} fields, kind=check)."
                )
                # The new spec joins the suffix-distinguished listings.
                self._prefill_check_editor()
                self._prefill_patch_change_files()
                self._prefill_diff_check_files()
        else:  # validate_doc
            result = run_check_document(
                document,
                loaded.mem_map if loaded is not None else None,
                loaded_ranges,
                mac_records,
                a2l_tags,
            )
            if result.run_blocked_reason_code is not None:
                self.set_status(
                    f"Check Editor: run blocked — {result.run_blocked_reason}"
                )
            aggregates = result.aggregates
            self.set_status(
                "Checks: {passed} passed, {failed} failed, "
                "{uncheckable} uncheckable".format(
                    passed=aggregates.get("passed", 0),
                    failed=aggregates.get("failed", 0),
                    uncheckable=aggregates.get("uncheckable", 0),
                )
            )
            rows: list[tuple[str, str]] = []
            for record in result.entries:
                token = str(getattr(record, "result", "uncheckable"))
                severity = {
                    "pass": ValidationSeverity.OK,
                    "fail": ValidationSeverity.ERROR,
                }.get(token, ValidationSeverity.WARNING)
                start = int(getattr(record, "address_start", 0))
                end = int(getattr(record, "address_end", start + 1))
                expected = " ".join(
                    f"{byte:02X}"
                    for byte in (getattr(record, "expected_bytes", ()) or ())
                )
                actual_bytes = getattr(record, "actual_bytes", None)
                actual = (
                    " ".join(f"{byte:02X}" for byte in actual_bytes)
                    if actual_bytes is not None
                    else "-"
                )
                reason = getattr(record, "reason", None)
                suffix = f" ({reason})" if reason else ""
                rows.append(
                    (
                        f"0x{start:X}-0x{end - 1:X} expected [{expected}] "
                        f"actual [{actual}] -> {token}{suffix}",
                        css_class_for_severity(severity),
                    )
                )
            panel.refresh_check_results(rows, "validation complete")

    def on_check_editor_panel_spec_file_selected(
        self, event: CheckEditorPanel.SpecFileSelected
    ) -> None:
        """Load a dropdown-chosen spec into the collector (LLR-009.1 read arm).

        Summary:
            Resolve the picked listed value against the spec homes
            (``_spec_homes``) through the pick guard shared with the patch
            editor's change-file handler (``_resolve_listed_file``: an
            unknown prefix, a name that is not a plain file name, a link on
            the walk from the work area or a file outside it is refused),
            read it through the shipped ``read_change_document``
            seam and, for a clean ``kind="check"`` document, mirror the
            declared fields into the collector via
            :meth:`CheckEditorPanel.load_spec`. A failing read surfaces its
            collected issues on the status path (never silently loaded);
            a non-check document is refused with its kind named.
        """
        candidate = self._resolve_listed_file(
            event.filename, self._spec_homes()
        )
        if candidate is None:
            self.set_status(
                f"Check Editor: file {event.filename!r} is outside the "
                "patches folder — not loaded."
            )
            return
        document = read_change_document(
            str(candidate), self.base_dir, a2l_context=self.current_a2l_data
        )
        if document.has_errors:
            for issue in document.issues:
                self.set_status(
                    f"[{issue.code}] {issue.severity.value}: {issue.message}"
                )
            self.set_status("Check Editor: spec NOT loaded.")
            return
        if document.kind != "check":
            self.set_status(
                f"Check Editor: {event.filename!r} is a kind="
                f"{document.kind!r} document — not a check spec."
            )
            return
        items = [
            {
                "address": entry.address,
                "size": max(1, len(entry.encoded_bytes)),
                "expected": tuple(entry.encoded_bytes),
                "symbol": entry.symbol,
            }
            for entry in document.entries
        ]
        panel = self.query_one("#check_editor_panel", CheckEditorPanel)
        # Inc 6 (R-CHKED-042): the Write-as input takes the bare file name —
        # the listed value would put ``library/`` into it.
        panel.load_spec(items, candidate.name)
        self.set_status(
            f"Check Editor: loaded {event.filename!r} "
            f"({len(items)} fields)."
        )

    def _diff_image_source(self, variant_id: Optional[str], raw_path: str) -> ImageSource:
        """
        Summary:
            Build one ``compare_service.ImageSource`` from the panel's raw
            selection — an in-project variant when ``variant_id`` is set, else
            an external path (LLR-005.1). The service does the resolution; this
            only packages the request.

        Args:
            variant_id (Optional[str]): The chosen project variant id, or
                ``None`` to use the external path.
            raw_path (str): The operator-typed external path.

        Returns:
            ImageSource: The packaged source for one comparison side.

        Dependencies:
            Used by:
                - ``on_ab_diff_panel_compare_requested``
        """
        if variant_id is not None:
            return ImageSource(kind=SOURCE_PROJECT_VARIANT, variant_id=variant_id)
        return ImageSource(kind=SOURCE_EXTERNAL, raw_path=raw_path)

    def _diff_sources_identical(self, event: AbDiffPanel.CompareRequested) -> bool:
        """
        Summary:
            Detect an A↔B compare request whose two sides resolve to the same
            on-disk file, which would silently compare the image against
            itself (BUG B7, operator report 2026-10-18): the B path input
            keeps its stale previous value when the OS clipboard paste fails
            silently (see ``OsClipboardInput.action_paste``), so the request
            arrives with the A path on both sides. The parse/compare itself
            has no cache — this stale-input routing is the whole bug.

        Args:
            event (AbDiffPanel.CompareRequested): The raw image-pair selection.

        Returns:
            bool: ``True`` when both sides are the same file: identical raw
            strings, or two external paths that both resolve through
            ``resolve_input_path`` to the same file. Variant-vs-variant with
            the same id also counts; anything else (including an
            unresolvable side, which the service will refuse named) is
            ``False``.

        Data Flow:
            - Same variant id on both selects → identical.
            - Mixed kinds (variant vs external) → never identical.
            - External/external: identical raw strings → identical; otherwise
              resolve both against ``self.base_dir`` with the same
              ``resolve_input_path`` the compare flow uses and compare.

        Dependencies:
            Uses:
                - ``resolve_input_path``
            Used by:
                - ``_apply_compare_request`` (early guard)
        """
        if event.variant_a is not None or event.variant_b is not None:
            return (
                event.variant_a is not None
                and event.variant_a == event.variant_b
            )
        raw_a = (event.path_a or "").strip()
        raw_b = (event.path_b or "").strip()
        # Empty-on-both-sides is NOT "the same file" — it is "no file at
        # all", and the service's own refusal names the empty side. Routing
        # it here would replace that named diagnostic with a misleading
        # same-file message (caught by the diff suites driving the shipped
        # button with untouched inputs).
        if raw_a and raw_a == raw_b:
            return True
        if not raw_a or not raw_b:
            return False
        resolved_a = deps.resolve_input_path(Path(raw_a), self.base_dir)
        resolved_b = deps.resolve_input_path(Path(raw_b), self.base_dir)
        return (
            resolved_a is not None
            and resolved_b is not None
            and resolved_a == resolved_b
        )

    async def on_ab_diff_panel_compare_requested(
        self, event: AbDiffPanel.CompareRequested
    ) -> None:
        """Run a compare request and mark its completion (batch-78 Inc-2 F7).

        Summary:
            Thin wrapper around :meth:`_apply_compare_request` whose only job is
            to bump :attr:`_diff_compare_generation` in a ``finally``, so the
            completion signal is TOTAL — it fires on the refusal branch, the
            load-failure branch, the success branch and on an exception. A
            signal that only fires on the happy path turns a refusal into a
            hang, and an exception into a hang, which is strictly worse than
            the race it was added to remove.

        Dependencies:
            Used by:
                - Textual message dispatch for ``AbDiffPanel``
        """
        try:
            await self._apply_compare_request(event)
        finally:
            self._diff_compare_generation += 1

    async def _apply_compare_request(
        self, event: AbDiffPanel.CompareRequested
    ) -> None:
        """
        Summary:
            Route an A↔B compare request exclusively through
            ``compare_service.compare_images`` (LLR-005.1) and feed the result
            back to the panel; a refused comparison surfaces its diagnostic in
            the panel status and the screen keeps running (LLR-005.3). The app
            computes no run classification or coverage itself.

        Args:
            event (AbDiffPanel.CompareRequested): The raw image-pair selection
                the panel posted (variant id or external path per side).

        Returns:
            None

        Data Flow:
            - Package each side as an ``ImageSource`` (``_diff_image_source``).
            - Call ``compare_images`` with the active project's variant set and
              shared A2L/MAC context; never the TUI snapshot for the images.
            - Refused -> ``panel.set_status`` with the joined diagnostics.
            - Otherwise re-parse the two maps for display via the service-
              returned result is run-only; the panel renders runs + windows.

        Dependencies:
            Uses:
                - ``compare_images`` / ``_diff_image_source``
                - ``AbDiffPanel.render_comparison`` / ``set_status``
            Used by:
                - Textual message dispatch for ``AbDiffPanel``
        """
        panel = self.query_one("#ab_diff_panel", AbDiffPanel)
        # BUG B7 guard (operator report 2026-10-18): a silently failed OS
        # clipboard paste leaves the B path input with its stale previous
        # value, so the request arrives as A-vs-A and the operator reads it
        # as "only one file was ever loaded". Refuse before any compare work
        # and name the likely cause instead of comparing a file to itself.
        if self._diff_sources_identical(event):
            panel.set_status(
                "Compare refused: both sides are the same file — the B path "
                "was not updated (clipboard paste failed?)",
                "sev-error",
            )
            return
        loaded = self.current_file
        mac_records = loaded.mac_records if loaded is not None else None
        result = deps.compare_images(
            self._diff_image_source(event.variant_a, event.path_a),
            self._diff_image_source(event.variant_b, event.path_b),
            variant_set=self._variant_set,
            base_dir=self.base_dir,
            a2l_data=self.current_a2l_data,
            mac_records=mac_records,
        )
        if result.refused:
            panel.set_status(
                "Compare refused: " + "; ".join(result.diagnostics),
                "sev-error",
            )
            return
        mem_map_a, mem_map_b, failed_sides = self._diff_load_maps(result)
        runs = [(run.start, run.end, run.kind) for run in result.runs]
        usage_a = result.notes.get("image_a")
        usage_b = result.notes.get("image_b")
        # AWAITED: `render_comparison` is a coroutine as of batch-78 Inc-2 —
        # the run list's rows are widgets and their removal must complete
        # before the next set mounts (review F1).
        await panel.render_comparison(
            runs,
            mem_map_a,
            mem_map_b,
            usage_a.summary if usage_a is not None else "none",
            usage_b.summary if usage_b is not None else "none",
        )
        if failed_sides:
            panel.set_status(
                f"Compare failed: {', '.join(failed_sides)} loaded no image "
                "(file has content but no valid records).",
                "sev-error",
            )
        else:
            panel.set_status(
                f"Compared {result.image_a.label} vs {result.image_b.label}: "
                f"{len(result.runs)} runs.",
                "sev-ok",
            )
        self._diff_last_result = result

    def _diff_load_maps(self, result) -> tuple[dict, dict, list[str]]:
        """
        Summary:
            Re-load the two compared images' memory maps for the on-screen hex
            windows and the report (LLR-005.2 / LLR-005.4), and detect a
            per-side load failure so the caller can surface an honest
            diagnostic instead of a silent clean compare (LLR-016.1). The
            comparison service returns runs but not the maps; the panel and the
            report generator both need the raw bytes, so this re-parses by path
            through the existing headless loaders.

            A side is a load failure when its source file has content on disk
            yet re-parses to an empty memory map (every record rejected, the
            collect-don't-abort degenerate case the service does not refuse),
            or the re-parse raises for a non-empty source. A legitimately small
            but valid image maps ≥1 byte and is NOT a failure.

        Args:
            result (ComparisonResult): The completed comparison.

        Returns:
            tuple[dict, dict, list[str]]: ``(mem_map_a, mem_map_b,
            failed_sides)`` where the two maps feed the hex windows unchanged
            (an unreadable image still yields an empty map — non-fatal) and
            ``failed_sides`` carries the human label of each side that loaded no
            image, out-of-band from the maps tuple the report path consumes.

        Data Flow:
            - Re-parse each side's path through ``build_loaded_s19`` /
              ``build_loaded_hex``; a raised parse becomes an empty map.
            - A non-empty source path whose map is empty is appended to
              ``failed_sides`` by its ``image.label``.

        Dependencies:
            Uses:
                - ``build_loaded_s19`` / ``build_loaded_hex``
            Used by:
                - ``on_ab_diff_panel_compare_requested``
        """
        def _load(image) -> dict:
            if not image.path:
                return {}
            path = Path(image.path)
            try:
                if path.suffix.lower() in (".hex", ".ihex"):
                    return build_loaded_hex(path, deps.IntelHexFile(str(path)), None, None).mem_map
                return deps.build_loaded_s19(path, S19File(str(path)), None, None).mem_map
            except Exception:  # noqa: BLE001 — display-side, non-fatal
                return {}

        def _source_has_content(image) -> bool:
            if not image.path:
                return False
            try:
                return Path(image.path).stat().st_size > 0
            except OSError:
                return False

        mem_map_a = _load(result.image_a)
        mem_map_b = _load(result.image_b)
        failed_sides: list[str] = []
        for image, mem_map in ((result.image_a, mem_map_a), (result.image_b, mem_map_b)):
            if not mem_map and _source_has_content(image):
                failed_sides.append(image.label or str(image.path))
        return mem_map_a, mem_map_b, failed_sides

    def on_ab_diff_panel_check_file_selected(
        self, event: AbDiffPanel.CheckFileSelected
    ) -> None:
        """Load a check spec for the diff report addendum (LLR-010.1/.2).

        Summary:
            The operator picked a file from the check-spec dropdown. The
            blank pick (``""``) clears the stashed spec — the next report
            emits no addendum. A concrete pick resolves against the spec
            homes (``_spec_homes``) through the pick guard shared with the
            patch editor's change-file handler (``_resolve_listed_file``)
            and reads through the shipped
            ``read_change_document`` seam. Only a clean ``kind="check"``
            document is stashed for the report; a failing read surfaces its
            collected issues (never silently loaded) and a non-check
            document is refused with its kind named — patch files stay
            listed and loadable, but they add no check addendum (the kind
            gate is the enforcement, LLR-009.3's sibling ruling).
        """
        panel = self.query_one("#ab_diff_panel", AbDiffPanel)
        if not event.filename:
            self._diff_check_spec = None
            self._diff_check_spec_name = ""
            panel.set_status("Check spec: none — the report gains no addendum.")
            return
        candidate = self._resolve_listed_file(
            event.filename, self._spec_homes()
        )
        if candidate is None:
            self._diff_check_spec = None
            self._diff_check_spec_name = ""
            panel.set_status(
                f"Check spec: {event.filename!r} is outside the patches "
                "folder — not loaded.",
                "sev-warning",
            )
            return
        document = read_change_document(
            str(candidate), self.base_dir, a2l_context=self.current_a2l_data
        )
        if document.has_errors:
            self._diff_check_spec = None
            self._diff_check_spec_name = ""
            messages = "; ".join(
                f"[{issue.code}] {issue.severity.value}: {issue.message}"
                for issue in document.issues[:3]
            )
            panel.set_status(
                f"Check spec not loaded — {messages}", "sev-warning"
            )
            return
        if document.kind != "check":
            self._diff_check_spec = None
            self._diff_check_spec_name = ""
            panel.set_status(
                f"Check spec: {event.filename!r} is a kind="
                f"{document.kind!r} document, not a check spec — the report "
                "gains no addendum.",
                "sev-warning",
            )
            return
        self._diff_check_spec = document
        self._diff_check_spec_name = event.filename
        panel.set_status(
            f"Check spec {event.filename!r} loaded — {len(document.entries)} "
            "declared field(s) will ride the report."
        )

    def on_ab_diff_panel_report_requested(
        self, event: AbDiffPanel.ReportRequested
    ) -> None:
        """
        Summary:
            Generate the diff report (Markdown + HTML) exclusively through
            ``diff_report_service`` (LLR-005.1) and surface the written
            path(s) — or the refusal diagnostic — in the panel status
            (LLR-005.4). The app computes no report content itself.

        Args:
            event (AbDiffPanel.ReportRequested): The operator-typed no-project
                destination directory (ignored when a project is active).

        Returns:
            None

        Data Flow:
            - Guard: no completed comparison -> one status line, no write.
            - Build the annotation inputs (enriched A2L tags + project MAC).
            - Call both generators with the project ``reports/`` dir, or the
              operator destination when no project is active (G-8).
            - Both written -> status with both paths; either refused -> the
              refusal diagnostic; the screen keeps running.

        Dependencies:
            Uses:
                - ``generate_diff_report`` / ``generate_diff_report_html``
                - ``AbDiffPanel.set_status``
            Used by:
                - Textual message dispatch for ``AbDiffPanel``
        """
        panel = self.query_one("#ab_diff_panel", AbDiffPanel)
        result = getattr(self, "_diff_last_result", None)
        if result is None or not panel.has_comparison():
            panel.set_status("No comparison yet — press Compare first.", "sev-warning")
            return
        project_dir = self._active_project_dir()
        dest_input = event.dest_input if project_dir is None else None
        loaded = self.current_file
        mac_records = loaded.mac_records if loaded is not None else None
        a2l_tags = self._compute_a2l_enriched_tags() or None
        kwargs = dict(
            mem_map_a=panel.mem_map_a,
            mem_map_b=panel.mem_map_b,
            project_dir=project_dir,
            dest_input=dest_input,
            a2l_records=a2l_tags,
            mac_records=mac_records,
            # batch-94 (LLR-010.2): the stashed check spec rides the report
            # as the ``## Checks`` addendum; ``None`` (the default) leaves
            # the emitted report byte-identical to the pre-batch-94 form.
            check_spec=self._diff_check_spec,
            check_spec_name=self._diff_check_spec_name,
        )
        # batch-95 inc-004b (LLR-143.2): when image B is a product of the last
        # flow run, the A2B diff must reference ALL the flow's changes — the
        # run's own record (change_records + named refusals) rides the kwargs
        # as the flow-change census. A B from anywhere else leaves the report
        # byte-identical to the shipped output.
        last_flow_run = getattr(self, "_last_flow_run", None)
        image_b_path = getattr(result.image_b, "path", None) if result else None
        if last_flow_run is not None and image_b_path:
            written = {
                Path(p).resolve() for p in last_flow_run.written_paths
            }
            if Path(image_b_path).resolve() in written and (
                last_flow_run.change_records or last_flow_run.refusals
            ):
                kwargs["flow_changes"] = flow_change_attribution(last_flow_run)
        diff_source = (
            project_dir.name if project_dir is not None else (dest_input or "-")
        )
        # N5 (batch-68): BOTH generators used to run here, on the UI event
        # loop, back to back — the diff path was the worst freeze in the app
        # because it pays the cost twice. Everything above stays on the UI
        # thread (widget reads + the "no comparison yet" early return).
        gen = self._busy_begin_action("diff_report")
        self._start_diff_report_worker(panel, result, kwargs, diff_source, gen=gen)

    def _apply_diff_regime(self, width: int, height: int) -> None:
        """
        Summary:
            Hand the terminal size to the A2B diff panel so it can select
            HLR-124's width/height regime. The threshold arithmetic and the
            constants live in ``AbDiffPanel`` (LLR-124.1) — this is the
            delivery of the two integers, deliberately kept out of the panel's
            own event surface because the panel's ``Resize`` reports the
            PANEL's size, and the regime constants are TERMINAL dimensions.

        Args:
            width (int): Terminal width in columns.
            height (int): Terminal height in rows.

        Returns:
            None

        Data Flow:
            - ``on_resize`` -> ``AbDiffPanel.apply_regime`` -> a CSS class on
              ``#ab_diff_panel``.

        Dependencies:
            Used by:
                - ``on_resize``
        """
        self.query_one("#ab_diff_panel", AbDiffPanel).apply_regime(width, height)
