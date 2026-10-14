"""Flow Builder — the run engine (batch-44 tracer, R-TUI-059).

:func:`run_flow` executes an ordered :class:`flow_model.Flow` over a project
image, threading a working ``(mem_map, ranges)`` pair through the blocks:
SOURCE seeds it (``build_loaded_*``), PATCH mutates it in place
(``apply_change_document``), WRITE-OUT sinks it (``save_patched_image``). It
mirrors ``variant_execution_service._execute_one_variant``'s discipline —
collect-don't-abort, per-block isolation, ``len(block_results) ==
len(flow.blocks)`` — but over an EXPLICIT block list.

Security (batch-44 pre-code security review):

- **F1** — the reused readers apply NO path containment, so EVERY file ref
  (``SourceBlock.image_ref`` / ``PatchBlock.change_doc_ref``) is resolved
  through the manifest guard :func:`_resolve_manifest_entry` (absolute /
  escape-project-root / reparse-point triad) BEFORE any open; an unsafe or
  missing ref fails the block (diagnostic) and aborts the chain.
- **F2** — WRITE-OUT for BOTH ``s19`` and ``hex`` goes through
  ``save_patched_image`` (F-S-01 sanitiser + ``copy_into_workarea``
  containment/dedup); the emitter string is never written directly.
- **F5** — each block runs under an ``except Exception`` isolation boundary.

No Textual import (service-layer contract C-7).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ...compare import ComparisonResult, ImageRef, diff_mem_maps
from ...core import S19File
from ...hexfile import IntelHexFile
from ...validation.model import ValidationIssue, ValidationSeverity
from ..changes import (
    apply_change_document,
    read_change_document,
    save_patched_image,
)
from ..changes.check import run_check_document
from ..a2l_parse import parse_a2l_file
from .a2l_service import enrich_tags_and_render
from .compare_service import SOURCE_EXTERNAL
from .diff_report_service import generate_diff_report
from .markdown_safety import md_code, md_safe
from .flow_model import (
    A2BBlock,
    A2B_INPUT_FILE,
    A2B_INPUT_FLOW,
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    CHECK_GATING_BLOCK_OWN,
    FINDING_WARN,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    WRITE_FMT_HEX,
    WRITE_FMT_S19,
    BlockResult,
    CheckBlock,
    CrcBlock,
    Finding,
    Flow,
    FlowChangeRecord,
    FlowContext,
    FlowRefusal,
    FlowRunResult,
    FusedFlowRunResult,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    VariantRunOutcome,
    WriteOutBlock,
)
from .flow_fused_report_service import (
    build_fused_report_state,
    write_fused_flow_report,
)
from .flow_report_service import FlowReportState, write_flow_report
from .load_service import build_loaded_hex, build_loaded_s19
from .variant_execution_service import (
    MANIFEST_PATH_ESCAPE,
    SCOPE_ALL,
    _resolve_manifest_entry,
    plan_variant_executions,
)
from ..models import ProjectVariantSet, VariantDescriptor  # noqa: F401 - typing
from ..operations.crc import check_regions, inject_crcs
from ..operations.crc_config import parse_crc_config
from ..operations.model import OperationInput


def run_flow(flow: Flow, ctx: FlowContext) -> FlowRunResult:
    """Execute a flow's blocks in order, threading the working image.

    Summary:
        Run each block against a working ``(mem_map, ranges)`` pair seeded by
        the SOURCE block: PATCH mutates the map in place, WRITE-OUT emits it
        to a file under the work area. Every file ref is containment-checked
        (F1) before opening; one failing block records a diagnostic and skips
        the rest (a broken source cannot feed a patch), but the result is
        always well-formed — ``len(block_results) == len(flow.blocks)`` — and
        this function never raises (F5 per-block isolation).

    Args:
        flow (Flow): The ordered typed-block list.
        ctx (FlowContext): The project directory + optional MAC/A2L context.

    Returns:
        FlowRunResult: ``status="ok"`` (CLEAN) when every block is clean,
        ``"completed-with-issues"`` when output was produced with advisories (a
        LOAD integrity notice or a non-aborting CHECK finding), else
        ``"error"`` (FAILED — image broken); the per-block outcomes and the
        written paths.

    Data Flow:
        - SOURCE → ``build_loaded_s19/hex`` → seed ``mem_map``/``ranges``;
          parser ``errors`` → advisory WARN findings (``notices``, LLR-085.2).
          Change-5 (LLR-142): a declared ``a2l_ref`` resolves through the
          manifest guard and its tag map becomes the run's symbol-resolution
          context before any PATCH; a dangling reference refuses the run,
          naming the reference.
        - PATCH → ``read_change_document`` (with the patch's effective A2L
          context — its own ``a2l_ref`` override, else the SOURCE block's) →
          ``apply_change_document`` (mutates ``mem_map``); batch-95 inc-004b
          (LLR-143.1/.2) retains every arm's per-entry change identities
          (``result.change_records``) and named refusals
          (``result.refusals``) — the run's own record for the reports.
        - CHECK → ``read_change_document`` → ``run_check_document`` (read-only,
          image passed through unchanged; never aborts the chain — LLR-086.4).
        - WRITE-OUT → ``save_patched_image(source_kind=fmt)`` → written path.
        - REPORT → ``write_flow_report`` composes from ``FlowReportState``
          (batch-95 inc-004b carries the retained change records — the
          change-attribution section, LLR-143.1).
        - A2B (batch-94 Inc-002, LLR-013.3/014.2) → each input resolved
          independently (file binding: F1 guard + headless loaders; flow
          binding: per-block image snapshots) → ``diff_mem_maps`` →
          ``generate_diff_report`` under ``reports/``. A sink: the threaded
          image passes through unchanged; a failed report records an error
          without aborting (the REPORT-block idiom).

    Dependencies:
        Uses:
            - _resolve_manifest_entry (F1 containment)
            - build_loaded_s19 / build_loaded_hex / enrich_tags_and_render
            - read_change_document / apply_change_document / save_patched_image
            - diff_mem_maps / generate_diff_report (A2B arm, reuse-not-fork)
        Used by:
            - s19_app.tui.flow_screens.FlowBuilderPanel (rail-8 Run)
    """
    result = FlowRunResult(status=FLOW_STATUS_OK)
    mem_map: Optional[dict] = None
    ranges: Optional[Sequence[Tuple[int, int]]] = None
    s0_header: Optional[bytes] = None
    a2l_tags = None
    # batch-95 change-5 (LLR-142): the run-effective A2L payload — the tag
    # map a declared ``a2l_ref`` resolved to (SOURCE block first; a PATCH
    # override is parsed per patch arm and never leaks here). Symbol entries
    # resolve ONLY against a declared reference; with none declared anywhere
    # this stays ``None`` and the reader refuses them named (no implicit A2L
    # — ``ctx.a2l_data``, the project's loaded A2L, is never consulted).
    declared_a2l: Optional[dict] = None
    # batch-95 inc-004b (LLR-143.1): the SOURCE block's DECLARED ref string,
    # retained so each PATCH arm's effective reference (its own override, else
    # this declaration, else None) lands in the run's change record — the
    # "resolved against" attribution. Never the implicit ctx.a2l_data.
    source_a2l_ref: Optional[str] = None
    aborted = False
    # batch-94 Inc-002 (LLR-014): per-block image snapshots, consumed by
    # downstream A2B flow bindings (`#k` references an upstream block's
    # output). Captured only when the flow actually carries an A2B block, so
    # the tracer chains pay nothing. A shallow dict copy per boundary is
    # enough: PATCH mutates in place (the copy freezes the boundary), CRC
    # reassigns to a fresh map (inject_crcs builds a working copy).
    snapshots: Optional[Dict[int, Tuple[dict, List[Tuple[int, int]]]]] = (
        {} if any(isinstance(b, A2BBlock) for b in flow.blocks) else None
    )

    for index, block in enumerate(flow.blocks):
        kind = getattr(block, "kind", "?")
        # batch-60 FB-P1b (§6.5 AMD-3 / D-6): a REPORT block is EXEMPT from the
        # upstream-abort skip. The run you most need a durable record of is the
        # one where the image broke, so the report still writes — carrying
        # ``aborted=True`` into its state (FAILED label). It does NOT clear the
        # flag: every block after it still skips.
        if aborted and not isinstance(block, ReportBlock):
            result.block_results.append(
                BlockResult(index, kind, BLOCK_STATUS_SKIPPED,
                            "skipped (upstream error)")
            )
            continue
        try:
            if isinstance(block, SourceBlock):
                issues: List[ValidationIssue] = []
                # batch-70 FB-P2 (LLR-104.1): when the run is variant-scoped the
                # SOURCE ref/type come from the variant, NOT from the block. The
                # binding is a project-RELATIVE ref precisely so it still passes
                # through the reused containment seam below — the descriptor's
                # own absolute path is rejected by that seam by design.
                binding = _bound_source_ref(ctx, block, issues)
                if binding is None:
                    aborted = _record_error(
                        result, index, kind, "variant image rejected", issues,
                        "variant image is not inside the project directory",
                    )
                    continue
                image_ref, file_type = binding
                path = _resolve_manifest_entry(
                    ctx.project_dir, image_ref,
                    "SourceBlock.image_ref", issues,
                )
                if path is None or not path.exists():
                    aborted = _record_error(
                        result, index, kind, "source unresolved", issues,
                        "source image not found or not inside the project",
                    )
                    continue
                if file_type == WRITE_FMT_HEX:
                    loaded = build_loaded_hex(
                        path, IntelHexFile(str(path)), None, ctx.a2l_data
                    )
                else:
                    loaded = build_loaded_s19(
                        path, S19File(str(path)), None, ctx.a2l_data
                    )
                mem_map = loaded.mem_map
                ranges = loaded.ranges
                s0_header = getattr(loaded, "source_s0_header", None)
                # batch-95 change-5 (LLR-142.1): a SOURCE block declaring an
                # A2L reference loads its tag map into the run context BEFORE
                # any PATCH applies; a reference that resolves to no A2L
                # refuses the run, naming the reference. Resolution rides the
                # SAME manifest containment guard as every other block ref
                # (project folder; the no-project home is a FlowContext whose
                # project_dir IS the workarea containment root, LLR-142.2).
                if block.a2l_ref:
                    a2l_issues: List[ValidationIssue] = []
                    a2l_path = _resolve_manifest_entry(
                        ctx.project_dir, block.a2l_ref,
                        "SourceBlock.a2l_ref", a2l_issues,
                    )
                    if a2l_path is None or not a2l_path.exists():
                        aborted = _record_error(
                            result, index, kind, "a2l reference unresolved",
                            a2l_issues,
                            f"a2l reference {block.a2l_ref!r} not found or "
                            "not inside the project",
                        )
                        continue
                    try:
                        declared_a2l = parse_a2l_file(a2l_path)
                    except OSError as exc:
                        aborted = _record_error(
                            result, index, kind, "a2l reference unreadable", [],
                            f"a2l reference {block.a2l_ref!r} could not be "
                            f"read: {type(exc).__name__}",
                        )
                        continue
                    source_a2l_ref = block.a2l_ref
                run_a2l_data = (
                    declared_a2l if declared_a2l is not None else ctx.a2l_data
                )
                a2l_tags = (
                    enrich_tags_and_render(run_a2l_data, mem_map)[0]
                    if run_a2l_data else None
                )
                load_errors = getattr(loaded, "errors", None) or []
                if load_errors:
                    # LLR-085.2: surface parser-collected per-record errors as
                    # advisory WARN notices; the image is still threaded
                    # downstream (notify, don't block — no `aborted`).
                    notices = BlockResult(
                        index, kind, BLOCK_STATUS_NOTICES,
                        f"loaded {path.name} ({len(ranges)} ranges, "
                        f"{len(load_errors)} integrity notice"
                        f"{'' if len(load_errors) == 1 else 's'})",
                    )
                    notices.findings.extend(
                        Finding(FINDING_WARN, _load_error_message(err))
                        for err in load_errors
                    )
                    result.block_results.append(notices)
                else:
                    result.block_results.append(
                        BlockResult(index, kind, BLOCK_STATUS_OK,
                                    f"loaded {path.name} ({len(ranges)} ranges)")
                    )

            elif isinstance(block, PatchBlock):
                if mem_map is None or ranges is None:
                    aborted = _record_error(
                        result, index, kind, "no source", [],
                        "patch block has no upstream source image",
                    )
                    continue
                issues = []
                path = _resolve_manifest_entry(
                    ctx.project_dir, block.change_doc_ref,
                    "PatchBlock.change_doc_ref", issues,
                )
                if path is None or not path.exists():
                    aborted = _record_error(
                        result, index, kind, "change doc unresolved", issues,
                        "change document not found or not inside the project",
                    )
                    continue
                # batch-95 change-5 (LLR-142.1): the PATCH block may carry its
                # OWN a2l_ref, overriding the SOURCE block's for THIS
                # change-set only (never leaking to sibling patches — the
                # override payload stays local to this arm). The change
                # document is read with that context so its symbol entries
                # resolve; with NO declared reference anywhere the context is
                # ``None`` and symbol entries are refused named (no implicit
                # A2L, even when the project holds a loaded A2L).
                patch_a2l_context = declared_a2l
                if block.a2l_ref:
                    override_issues: List[ValidationIssue] = []
                    override_path = _resolve_manifest_entry(
                        ctx.project_dir, block.a2l_ref,
                        "PatchBlock.a2l_ref", override_issues,
                    )
                    if override_path is None or not override_path.exists():
                        aborted = _record_error(
                            result, index, kind, "a2l reference unresolved",
                            override_issues,
                            f"a2l reference {block.a2l_ref!r} not found or "
                            "not inside the project",
                        )
                        continue
                    try:
                        patch_a2l_context = parse_a2l_file(override_path)
                    except OSError as exc:
                        aborted = _record_error(
                            result, index, kind, "a2l reference unreadable", [],
                            f"a2l reference {block.a2l_ref!r} could not be "
                            f"read: {type(exc).__name__}",
                        )
                        continue
                document = read_change_document(
                    str(path), ctx.project_dir,
                    a2l_context=patch_a2l_context,
                )
                summary = apply_change_document(
                    document, mem_map, ranges, ctx.mac_records, a2l_tags
                )
                # batch-95 inc-004b (LLR-143.1/.2): retain the arm's per-entry
                # change identities and its named refusals — the run's OWN
                # record, from which the flow report's change-attribution
                # section and the A2B diff's flow-change census enumerate what
                # the flow did (previously reduced to "applied N entries" and
                # discarded). The effective reference is the patch's override,
                # else the SOURCE declaration, else None — never implicit.
                effective_a2l_ref = block.a2l_ref or source_a2l_ref
                for entry in summary.entries:
                    result.change_records.append(
                        FlowChangeRecord(
                            block_index=index,
                            change_doc_ref=block.change_doc_ref,
                            a2l_ref=effective_a2l_ref,
                            entry_type=entry.entry_type,
                            symbol=entry.symbol,
                            address_start=entry.address_start,
                            address_end=entry.address_end,
                            disposition=entry.disposition,
                            before_bytes=entry.before_bytes,
                            after_bytes=entry.after_bytes,
                        )
                    )
                for issue in summary.issues:
                    if issue.severity is not ValidationSeverity.ERROR:
                        continue
                    result.refusals.append(
                        FlowRefusal(
                            block_index=index,
                            change_doc_ref=block.change_doc_ref,
                            a2l_ref=effective_a2l_ref,
                            code=issue.code,
                            symbol=issue.symbol,
                            address=issue.address,
                            message=issue.message,
                        )
                    )
                applied = summary.counts.get("applied", 0)
                result.block_results.append(
                    BlockResult(index, kind, BLOCK_STATUS_OK,
                                f"applied {applied} entr"
                                f"{'y' if applied == 1 else 'ies'}")
                )

            elif isinstance(block, WriteOutBlock):
                if mem_map is None or ranges is None:
                    aborted = _record_error(
                        result, index, kind, "no image", [],
                        "write-out block has no upstream image",
                    )
                    continue
                fmt = (
                    WRITE_FMT_HEX if block.fmt == WRITE_FMT_HEX
                    else WRITE_FMT_S19
                )
                saved_path, save_issues = save_patched_image(
                    mem_map, ranges, ctx.project_dir, block.output_name,
                    source_kind=fmt, bytes_per_line=32,
                    s0_header=s0_header if fmt == WRITE_FMT_S19 else None,
                )
                if saved_path is None:
                    aborted = _record_error(
                        result, index, kind, "write failed", save_issues,
                        "write-out produced no file",
                    )
                    continue
                result.written_paths.append(saved_path)
                result.block_results.append(
                    BlockResult(index, kind, BLOCK_STATUS_OK,
                                f"wrote {saved_path.name}")
                )

            elif isinstance(block, CheckBlock):
                # LLR-086.2..086.5: read-only verification. A CHECK NEVER
                # aborts the chain — the working image is never reassigned and
                # `aborted` is never set here (LLR-086.4).
                if mem_map is None or ranges is None:
                    _record_check_own_op(
                        result, index, kind, block.gating, [],
                        "check block has no upstream image",
                    )
                    continue
                issues = []
                path = _resolve_manifest_entry(
                    ctx.project_dir, block.check_doc_ref,
                    "CheckBlock.check_doc_ref", issues,
                )
                if path is None or not path.exists():
                    _record_check_own_op(
                        result, index, kind, block.gating, issues,
                        "check document not found or not inside the project",
                    )
                    continue
                # STRUCTURAL chain-never-blocked guard (LLR-086.4): the WHOLE
                # CHECK branch body — read, run, aggregate extraction, and the
                # BlockResult build — runs under this inner `except` so ANY
                # exception routes to the NON-aborting own-op path and can never
                # reach the outer `aborted = True` handler.
                try:
                    document = read_change_document(
                        str(path), ctx.project_dir,
                        a2l_context=declared_a2l,
                    )
                    check_result = run_check_document(
                        document, mem_map, ranges, ctx.mac_records, a2l_tags
                    )
                    agg = check_result.aggregates
                    passed, failed, uncheckable = (
                        agg["passed"], agg["failed"], agg["uncheckable"]
                    )
                    status = (
                        BLOCK_STATUS_NOTICES if failed > 0 else BLOCK_STATUS_OK
                    )
                    check_block = BlockResult(
                        index, kind, status,
                        f"passed={passed} failed={failed} "
                        f"uncheckable={uncheckable}",
                    )
                    if failed > 0:
                        check_block.findings.append(
                            Finding(FINDING_WARN,
                                    f"{failed} check entr"
                                    f"{'y' if failed == 1 else 'ies'} failed")
                        )
                    result.block_results.append(check_block)
                except Exception as exc:  # noqa: BLE001 - CHECK never aborts
                    _record_check_own_op(
                        result, index, kind, block.gating, [],
                        f"{type(exc).__name__}: {exc}",
                    )
                    continue

            elif isinstance(block, CrcBlock):
                # LLR-089.2..092.3: compute a CRC over the CURRENT (post-patch)
                # threaded image via the shared kernel, inject it, and thread the
                # (possibly grown) working image forward. A malformed/unsafe
                # config fails the block CLOSED (aborts); a CRC before any PATCH
                # is a non-blocking WARN. crc.py is reused verbatim, never edited.
                if mem_map is None or ranges is None:
                    aborted = _record_error(
                        result, index, kind, "no image", [],
                        "crc block has no upstream image",
                    )
                    continue
                issues = []
                path = _resolve_manifest_entry(
                    ctx.project_dir, block.config_ref,
                    "CrcBlock.config_ref", issues,
                )
                if path is None or not path.exists():
                    # LLR-092.1: containment reject (absolute/escape/reparse) or
                    # a missing target — fail closed BEFORE opening any file.
                    aborted = _record_error(
                        result, index, kind, "config unresolved", issues,
                        "crc config not found or not inside the project",
                    )
                    continue
                config, config_errors = parse_crc_config(
                    path.read_text(encoding="utf-8")
                )
                if config is None or config_errors:
                    # LLR-092.2: malformed config → error, image un-injected.
                    aborted = _record_error(
                        result, index, kind, "config malformed", [],
                        "crc config invalid: "
                        + "; ".join(config_errors[:3]),
                    )
                    continue
                # LLR-094.1: capture the pre-CRC footprint ONCE, before the first
                # growth (PATCH mutates in place and never grows, so this is the
                # SOURCE/post-patch footprint).
                if not result.pre_crc_ranges:
                    result.pre_crc_ranges = [
                        (int(start), int(end)) for start, end in ranges
                    ]
                op_input = OperationInput(
                    mem_map=mem_map,
                    ranges=list(ranges),
                    input_path=None,
                    variant_id=None,
                    file_type=WRITE_FMT_S19,
                )
                crc_regions = check_regions(op_input, config)
                # LLR-089.3 / LLR-090.1: inject_crcs builds a WORKING COPY (never
                # mutates the input map/ranges) and grows ranges via
                # _extend_ranges; reassign the threaded image to it.
                mem_map, ranges, written_regions = inject_crcs(
                    op_input, crc_regions
                )
                injected = len(written_regions)
                # LLR-091.1: a CRC before any PATCH (or a flow with no PATCH) →
                # non-blocking WARN + notices; `aborted` stays unset.
                patch_indices = [
                    i for i, b in enumerate(flow.blocks)
                    if isinstance(b, PatchBlock)
                ]
                crc_before_patch = (
                    not patch_indices or index < min(patch_indices)
                )
                summary = (
                    f"injected {injected} CRC region"
                    f"{'' if injected == 1 else 's'}"
                )
                if crc_before_patch:
                    crc_block = BlockResult(
                        index, kind, BLOCK_STATUS_NOTICES, summary
                    )
                    crc_block.findings.append(
                        Finding(
                            FINDING_WARN,
                            "CRC before PATCH: the image is finalized before "
                            "any patch is applied",
                        )
                    )
                    result.block_results.append(crc_block)
                else:
                    result.block_results.append(
                        BlockResult(index, kind, BLOCK_STATUS_OK, summary)
                    )

            elif isinstance(block, A2BBlock):
                # batch-94 Inc-002 (LLR-013.3/014.2): run the A2B diff through
                # the EXISTING diff-report service — the app computes no report
                # content. Each input resolves independently: a file binding
                # through the F1 containment guard + the headless loaders; a
                # flow binding through the per-block snapshots. Wiring
                # validation (≥1 from this flow, no both-external pair) ran at
                # build/load time, so a refused binding never reaches this arm;
                # an upstream block that failed still leaves NO snapshot and
                # fails this block closed with a named diagnostic (error arm,
                # LLR-014.2 — and the generic upstream skip keeps the rest
                # `skipped`). The block is a SINK: the threaded image passes
                # through unchanged, so a failed report records an error but
                # does NOT abort the chain (the REPORT-block idiom).
                sides: List[Tuple[dict, str, str, str, int]] = []
                side_failed = False
                for side, binding in (
                    ("A", block.image_a),
                    ("B", block.image_b),
                ):
                    if binding.source == A2B_INPUT_FILE:
                        issues = []
                        path = _resolve_manifest_entry(
                            ctx.project_dir, binding.ref,
                            f"A2BBlock.image_{side.lower()}", issues,
                        )
                        if path is None or not path.exists():
                            aborted = _record_error(
                                result, index, kind, "input unresolved",
                                issues,
                                f"A2B image {side} file not found or not "
                                "inside the project",
                            )
                            side_failed = True
                            break
                        try:
                            if path.suffix.lower() in (".hex", ".ihex"):
                                loaded_side = build_loaded_hex(
                                    path, IntelHexFile(str(path)), None,
                                    ctx.a2l_data,
                                )
                            else:
                                loaded_side = build_loaded_s19(
                                    path, S19File(str(path)), None,
                                    ctx.a2l_data,
                                )
                        except Exception as exc:  # noqa: BLE001 - per-input arm
                            aborted = _record_error(
                                result, index, kind, "input unreadable", [],
                                f"A2B image {side}: "
                                f"{type(exc).__name__}: {exc}",
                            )
                            side_failed = True
                            break
                        # HLR-016: the report identity is file-derived — the
                        # bare label rides the escaper (Mode A) and the path
                        # rides the code-span form (Mode B, the truth table).
                        # Both are IDENTITY on clean values, so the external
                        # arm keeps the producer's established emitted form
                        # (C-42 paste, TC-B94-24); flow-arm values are
                        # model-derived vocabulary and need no scrub.
                        sides.append(
                            (
                                loaded_side.mem_map or {},
                                md_safe(path.stem, limit=120),
                                SOURCE_EXTERNAL,
                                md_code(str(path)),
                                len(getattr(loaded_side, "errors", None) or []),
                            )
                        )
                    else:
                        ref = binding.ref.strip()
                        snap = snapshots.get(int(ref)) if ref.isdigit() else None
                        if snap is None:
                            aborted = _record_error(
                                result, index, kind,
                                "flow output unavailable", [],
                                f"A2B image {side}: flow block "
                                f"{int(ref) + 1 if ref.isdigit() else ref} "
                                "produced no image (failed or skipped upstream)",
                            )
                            side_failed = True
                            break
                        producer = flow.blocks[int(ref)]
                        name = f"block {int(ref) + 1} ({producer.kind}).out"
                        sides.append(
                            (
                                snap[0],
                                f"{producer.kind}.out",
                                A2B_INPUT_FLOW,
                                name,
                                0,
                            )
                        )
                if side_failed:
                    continue
                mem_map_a, label_a, src_a, path_a, err_a = sides[0]
                mem_map_b, label_b, src_b, path_b, err_b = sides[1]
                runs, stats = diff_mem_maps(mem_map_a, mem_map_b)
                comparison = ComparisonResult(
                    image_a=ImageRef(
                        label=label_a, path=path_a, source_kind=src_a,
                        variant_id=None, parse_error_count=err_a,
                    ),
                    image_b=ImageRef(
                        label=label_b, path=path_b, source_kind=src_b,
                        variant_id=None, parse_error_count=err_b,
                    ),
                    runs=runs,
                    stats=stats,
                )
                try:
                    # Fixed stem (never flow.name — operator text): the report
                    # filename stays inside the producer's M-5 scheme.
                    report = generate_diff_report(
                        comparison,
                        mem_map_a=mem_map_a,
                        mem_map_b=mem_map_b,
                        project_dir=ctx.project_dir,
                        filename_stem="flow-a2b",
                    )
                except Exception as exc:  # noqa: BLE001 - degrade, never abort
                    result.block_results.append(
                        BlockResult(index, kind, BLOCK_STATUS_ERROR,
                                    "report write failed",
                                    [f"{type(exc).__name__}: {exc}"])
                    )
                else:
                    if not report.written:
                        result.block_results.append(
                            BlockResult(index, kind, BLOCK_STATUS_ERROR,
                                        "report write failed",
                                        list(report.diagnostics))
                        )
                    else:
                        result.block_results.append(
                            BlockResult(index, kind, BLOCK_STATUS_OK,
                                        f"wrote reports/{report.path.name}")
                        )

            elif isinstance(block, ReportBlock) and ctx.defer_report:
                # batch-70 FB-P2 (D-4): under a fused run the report is written
                # ONCE, by run_flow_over_variants, with a section per variant.
                # Writing here too would emit one file per variant — precisely
                # the N-file collation this feature exists to remove. The block
                # still reports, so the ledger never hides that it ran.
                result.block_results.append(
                    BlockResult(index, kind, BLOCK_STATUS_OK,
                                "deferred to the fused report")
                )

            elif isinstance(block, ReportBlock):
                # batch-60 FB-P1b (LLR-003.1/.3): compose a POSITIONAL report of
                # the run so far and write it under <project>/reports/. The
                # working (mem_map, ranges) thread forward UNCHANGED — a report
                # is a record, not an operation on the image.
                #
                # Field sources matter (AMD-9): ``result.image_ranges`` is only
                # assigned AFTER this loop, so the footprint must come from the
                # LOCAL threaded ``ranges``; ``pre_crc_ranges`` is read as it
                # stands NOW, so a pre-CRC report legitimately omits its line.
                # The report's own path is NOT appended to ``written_paths``
                # (AMD-11 — that list is the image-output contract).
                report_state = FlowReportState(
                    flow_name=flow.name,
                    block_results=list(result.block_results),
                    aborted=aborted,
                    image_ranges=(
                        [(int(start), int(end)) for start, end in ranges]
                        if ranges else None
                    ),
                    pre_crc_ranges=list(result.pre_crc_ranges),
                    written_paths=list(result.written_paths),
                    project_dir=ctx.project_dir,
                    # batch-95 inc-004b (LLR-143.1): the change records
                    # retained SO FAR — a positional report attributes only
                    # the patches before it (D-2), exactly like the ledger.
                    change_records=list(result.change_records),
                )
                try:
                    report_path = write_flow_report(report_state, ctx.project_dir)
                except Exception as exc:  # noqa: BLE001 - degrade, never abort
                    # LLR-003.1 (AMD-12): a failed report write is recorded, not
                    # swallowed and not fatal — the diagnostic names the exception
                    # type (mirroring the generic handler) so a permission or
                    # containment failure stays distinguishable from a benign miss.
                    # `aborted` is deliberately NOT set: later blocks still run.
                    result.block_results.append(
                        BlockResult(index, kind, BLOCK_STATUS_ERROR,
                                    "report write failed",
                                    [f"{type(exc).__name__}: {exc}"])
                    )
                else:
                    result.block_results.append(
                        BlockResult(index, kind, BLOCK_STATUS_OK,
                                    f"wrote reports/{report_path.name}")
                    )

            else:  # pragma: no cover - guards an unknown block kind
                aborted = _record_error(
                    result, index, kind, "unknown block", [],
                    f"unknown block kind {kind!r}",
                )
            # batch-94 Inc-002: freeze the threaded image at this boundary for
            # downstream A2B flow bindings (only when the flow carries an A2B
            # block, so tracer chains pay nothing). Only a branch that ran
            # clean reaches here — every abort path above `continue`d — so the
            # snapshot always names a successfully produced image.
            if snapshots is not None and mem_map is not None:
                snapshots[index] = (
                    dict(mem_map),
                    [(int(s), int(e)) for s, e in ranges] if ranges else [],
                )
        except Exception as exc:  # noqa: BLE001 - per-block isolation (F5)
            result.block_results.append(
                BlockResult(index, kind, BLOCK_STATUS_ERROR, "error",
                            [f"{type(exc).__name__}: {exc}"])
            )
            aborted = True

    # LLR-087.2: three-way roll-up. FAILED keys on `aborted` ALONE (an image
    # broken by a LOAD/PATCH/WRITE-OUT STOP); ISSUES when output was produced
    # with advisories (a notices/error block, or any WARN finding); else CLEAN.
    if aborted:
        result.status = FLOW_STATUS_ERROR
    elif any(
        br.status in {BLOCK_STATUS_NOTICES, BLOCK_STATUS_ERROR} or br.findings
        for br in result.block_results
    ):
        result.status = FLOW_STATUS_ISSUES
    else:
        result.status = FLOW_STATUS_OK

    # LLR-088.4 (§6.5 AMD-1): carry the working image's final address footprint
    # so the Direction-A ribbon renders it. Additive per §6.3 R-6; empty when no
    # image was loaded (an unresolvable SOURCE left `ranges` unset). A CHECK is
    # read-only and PATCH mutates in place, so this is the SOURCE footprint until
    # the batch-52 CRC block first grows the image.
    if ranges is not None:
        result.image_ranges = [(int(start), int(end)) for start, end in ranges]
    # LLR-094.1: when no CRC block ran, the "before" ribbon equals the "after"
    # (no growth) — default pre_crc_ranges to the final footprint.
    if not result.pre_crc_ranges:
        result.pre_crc_ranges = list(result.image_ranges)
    return result


def _bound_source_ref(
    ctx: FlowContext,
    block: SourceBlock,
    issues: List[ValidationIssue],
) -> Optional[Tuple[str, str]]:
    """Resolve the SOURCE block's ``(image_ref, file_type)`` for THIS run.

    Summary:
        Unscoped (``ctx.variant is None``) this is the identity — the block's
        own ref and type, so today's single-image path is untouched (AC-6).
        Variant-scoped it binds the variant's image instead (D-2), as a
        **project-relative POSIX ref**: the caller feeds that ref to the REUSED
        :func:`_resolve_manifest_entry`, which rejects absolute refs by design,
        so handing it ``VariantDescriptor.path`` directly would fail every
        variant. Relativising here is what keeps the containment seam shared
        rather than forked (batch-69 spec §7).

    Args:
        ctx (FlowContext): The run context; ``ctx.variant`` selects the mode.
        block (SourceBlock): The SOURCE block being executed.
        issues (List[ValidationIssue]): Finding collector, appended in place.

    Returns:
        Optional[Tuple[str, str]]: ``(image_ref, file_type)``, or ``None`` when
        the variant's image lies outside the project directory — one
        ``MANIFEST-PATH-ESCAPE`` finding is recorded and the caller fails THAT
        block, hence that variant, closed (LLR-104.7 / AC-7).

    Data Flow:
        - ``ctx.variant.path`` → ``relative_to(project_dir)`` → POSIX ref →
          ``_resolve_manifest_entry`` (in the caller).

    Dependencies:
        Used by:
            - run_flow (the SOURCE branch)

    Example:
        >>> _bound_source_ref(FlowContext(project_dir=Path(".")),
        ...                   SourceBlock(image_ref="fw.s19"), [])
        ('fw.s19', 's19')
    """
    if ctx.variant is None:
        return block.image_ref, block.file_type
    try:
        relative = Path(ctx.variant.path).resolve().relative_to(
            Path(ctx.project_dir).resolve()
        )
    except (ValueError, OSError):
        issues.append(
            ValidationIssue(
                code=MANIFEST_PATH_ESCAPE,
                severity=ValidationSeverity.ERROR,
                message=(
                    "variant image resolves outside the project directory - "
                    f"variant skipped: {ctx.variant.variant_id!r}"
                ),
                artifact="flow",
            )
        )
        return None
    return relative.as_posix(), ctx.variant.file_type


def _roll_up_variants(fused: FusedFlowRunResult) -> None:
    """Fill the fused counts and the worst-across-variants status (D-5).

    Summary:
        Count each variant's own terminal status, then roll up: any ``error``
        wins, else any ``completed-with-issues``, else ``ok``. The counts are
        recorded ALONGSIDE the rolled-up word on purpose — one word over N
        images hides exactly what the operator opened the report to see, and a
        roll-up that cannot be inverted into per-variant outcomes is a summary
        that lies by omission (LLR-104.4).

    Args:
        fused (FusedFlowRunResult): The result to fill, mutated in place.

    Returns:
        None

    Dependencies:
        Used by:
            - run_flow_over_variants
    """
    fused.n_ok = sum(
        1 for outcome in fused.variant_outcomes
        if outcome.result.status == FLOW_STATUS_OK
    )
    fused.n_issues = sum(
        1 for outcome in fused.variant_outcomes
        if outcome.result.status == FLOW_STATUS_ISSUES
    )
    fused.n_error = sum(
        1 for outcome in fused.variant_outcomes
        if outcome.result.status == FLOW_STATUS_ERROR
    )
    if fused.n_error:
        fused.status = FLOW_STATUS_ERROR
    elif fused.n_issues:
        fused.status = FLOW_STATUS_ISSUES
    else:
        fused.status = FLOW_STATUS_OK


def run_flow_over_variants(
    flow: Flow,
    ctx: FlowContext,
    variant_set: Optional["ProjectVariantSet"] = None,
    manifest: Optional[object] = None,
    scope: str = SCOPE_ALL,
    *,
    plan: Optional[Iterable["VariantDescriptor"]] = None,
    run_one: Optional[Callable[[Flow, FlowContext], FlowRunResult]] = None,
) -> FusedFlowRunResult:
    """Execute ``flow`` once per planned variant, isolated, and fuse the results.

    Summary:
        Derive the planned image set from the project's OWN variant machinery
        (``plan_variant_executions``) rather than a second parallel concept —
        a flow-local path list would let a flow name images outside the project
        and would fork the containment seam (D-1). Each variant runs under its
        own :class:`FlowContext` and its own isolation boundary: an abort, or an
        exception escaping :func:`run_flow`, is recorded as THAT variant's
        outcome and the loop continues (D-3), because a fused report missing 4
        of 5 images because the 1st failed is worse than useless.

    Args:
        flow (Flow): The flow to run; never mutated — the per-variant binding
            lives on the context, not on the blocks (D-2).
        ctx (FlowContext): The base context; ``ctx.variant`` is replaced per
            variant.
        variant_set (Optional[ProjectVariantSet]): The project's variant
            inventory. Required unless ``plan`` is given.
        manifest (Optional[ProjectManifest]): The parsed manifest, or ``None``.
        scope (str): A ``variant_execution_service`` execution scope —
            ``"active"`` / ``"all"`` / ``"assignments"``.
        plan (Optional[Iterable[VariantDescriptor]]): The planned set, supplied
            verbatim. This is the AC-1 observation seam: a counting iterable
            passed here measures how many images the runner consumed, which is
            a structural oracle — unlike wall-clock or peak-memory, which
            batch-63 proved cannot distinguish cap-and-continue from
            cap-and-break.
        run_one (Optional[Callable[[Flow, FlowContext], FlowRunResult]]): The
            per-variant executor; defaults to :func:`run_flow`. The second AC-1
            seam — it makes the EXECUTION count directly observable rather than
            inferred from the outcome list.

    Returns:
        FusedFlowRunResult: One :class:`VariantRunOutcome` per planned variant
        in plan order, the D-5 roll-up, the inverted counts, and the union of
        every variant's written image paths.

    Data Flow:
        - ``variant_set`` + ``manifest`` + ``scope`` → ``plan_variant_executions``
          → descriptors → per-variant ``FlowContext`` → :func:`run_flow`.
        - outcomes → :func:`_roll_up_variants` → status + ``n_ok``/``n_issues``/
          ``n_error``.

    Dependencies:
        Uses:
            - plan_variant_executions (D-1 reuse, never a parallel image list)
            - run_flow / _roll_up_variants
        Used by:
            - s19_app.tui.app.S19TuiApp.on_flow_builder_panel_run_requested

    Example:
        >>> run_flow_over_variants(Flow(name="f"), FlowContext(project_dir=Path(".")),
        ...                        plan=[]).diagnostics
        ['no variants in scope - nothing was executed']
    """
    if plan is not None:
        planned = list(plan)
    elif variant_set is None:
        raise ValueError("run_flow_over_variants needs a variant_set or a plan")
    else:
        planned = [
            descriptor
            for descriptor, _files in plan_variant_executions(
                variant_set, manifest, scope
            )
        ]
    execute = run_one if run_one is not None else run_flow
    fused = FusedFlowRunResult(status=FLOW_STATUS_OK)
    if not planned:
        fused.diagnostics.append("no variants in scope - nothing was executed")
        return fused
    for descriptor in planned:
        variant_ctx = replace(ctx, variant=descriptor, defer_report=True)
        try:
            variant_result = execute(flow, variant_ctx)
        except Exception as exc:  # noqa: BLE001 - per-variant isolation (D-3)
            # run_flow is itself non-raising, so reaching here means an injected
            # executor or a future regression broke that contract. Isolating it
            # is the whole point: the remaining variants still run.
            variant_result = FlowRunResult(
                status=FLOW_STATUS_ERROR,
                diagnostics=[f"{type(exc).__name__}: {exc}"],
            )
        fused.variant_outcomes.append(
            VariantRunOutcome(str(descriptor.variant_id), variant_result)
        )
        fused.written_paths.extend(variant_result.written_paths)
    _roll_up_variants(fused)
    # D-4: ONE fused document, and only when the flow asked for a report at all
    # — a flow with no REPORT block still writes none, exactly as unscoped.
    if any(isinstance(block, ReportBlock) for block in flow.blocks):
        try:
            fused.report_path = write_fused_flow_report(
                build_fused_report_state(flow.name, fused, ctx.project_dir),
                ctx.project_dir,
            )
        except Exception as exc:  # noqa: BLE001 - degrade, never lose the run
            # Mirrors run_flow's report handler: a failed write is RECORDED, not
            # swallowed, and never costs the operator the run's results.
            fused.diagnostics.append(
                f"fused report write failed: {type(exc).__name__}: {exc}"
            )
    return fused


def _load_error_message(err: dict) -> str:
    """Render a parser error dict as a one-line WARN finding message.

    Args:
        err (dict): A ``S19File``/``IntelHexFile`` error record with
            ``line_number`` / ``error`` keys (``core.py:369-374``).

    Returns:
        str: ``"line <n>: <error text>"`` when the numeric line is known, else
        just the ``<error text>``. The raw file-line content (the ``line`` key)
        is NEVER echoed — C-9; only the numeric line + diagnostic text.
    """
    line = err.get("line_number")
    text = err.get("error", "load error")
    return f"line {line}: {text}" if line is not None else str(text)


def _record_check_own_op(
    result: FlowRunResult,
    index: int,
    kind: str,
    gating: str,
    issues: Sequence[ValidationIssue],
    note: str,
) -> None:
    """Record a CHECK own-operation problem WITHOUT aborting the chain.

    Summary:
        Under ``CHECK_GATING_BLOCK_OWN`` the CHECK block is marked ``error``
        (its own operation is invalid); under ``CHECK_GATING_ADVISORY`` it is
        ``notices`` with an advisory WARN finding. In BOTH cases the chain is
        left running and the working image is untouched (LLR-086.4/086.5) —
        this helper NEVER sets ``aborted``.
    """
    diagnostics = [f"[{issue.code}] {issue.message}" for issue in issues]
    diagnostics.append(note)
    if gating == CHECK_GATING_BLOCK_OWN:
        result.block_results.append(
            BlockResult(index, kind, BLOCK_STATUS_ERROR,
                        "check operation invalid", diagnostics)
        )
    else:
        block = BlockResult(index, kind, BLOCK_STATUS_NOTICES,
                            "could not check", diagnostics)
        block.findings.append(Finding(FINDING_WARN, note))
        result.block_results.append(block)


def _record_error(
    result: FlowRunResult,
    index: int,
    kind: str,
    summary: str,
    issues: Sequence[ValidationIssue],
    note: str,
) -> bool:
    """Append an ``error`` :class:`BlockResult` and signal the chain to abort.

    Returns ``True`` so the caller can do ``aborted = _record_error(...)``.
    """
    diagnostics = [f"[{issue.code}] {issue.message}" for issue in issues]
    diagnostics.append(note)
    result.block_results.append(
        BlockResult(index, kind, BLOCK_STATUS_ERROR, summary, diagnostics)
    )
    return True
