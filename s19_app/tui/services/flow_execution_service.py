"""Flow Builder — the run engine (batch-44 tracer, R-TUI-059).

:func:`run_flow` executes an ordered :class:`flow_model.Flow` over a project
image, threading a working ``(mem_map, ranges)`` pair through the blocks:
SOURCE seeds it (``build_loaded_*``), PATCH mutates it in place
(``apply_change_document``), WRITE-OUT sinks it (``save_patched_image``). It
mirrors ``variant_execution_service._execute_one_variant``'s discipline —
collect-don't-abort, per-block isolation, ``len(block_results) ==
len(flow.blocks)`` — but over an EXPLICIT block list.

batch-94 Inc-003 (US-007, fx_a) adds the CHAIN-SET orchestration layer at the
bottom of this module: :func:`run_chain_set` wraps ``run_flow`` per chain
(never re-implementing block semantics) — per-chain input rebinding by a
per-run copy of the template's blocks (LLR-018), sequential-default /
parallel-per-chain dispatch with per-lane failure isolation (LLR-019, A5),
and the chain-set report with one provenance line per consumed input
(LLR-020.2, the C-42 paste pinned by TC-B94-30).

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

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ...compare import ComparisonResult, ImageRef, diff_mem_maps
from ...core import S19File, S19_INTEGRITY_NOTICE_CODES, load_notice_code
from ...hexfile import HEX_INTEGRITY_NOTICE_CODES, IntelHexFile
from ...validation.model import ValidationIssue, ValidationSeverity
from ..changes import (
    READ_SIZE_CAP_BYTES,
    apply_change_document,
    read_change_document,
    save_patched_image,
)
from ..changes.check import run_check_document
from ..changes.io import parse_change_document
from ..changes.model import DISPOSITION_APPLIED, DISPOSITION_BLOCKED
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
    BLOCK_STATUS_WAITING,
    CHECK_GATING_BLOCK_OWN,
    EXTERNAL_MODE_TERMINAL,
    FINDING_WARN,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    FLOW_STATUS_PAUSED,
    WRITE_FMT_HEX,
    WRITE_FMT_S19,
    BlockResult,
    CheckBlock,
    CrcBlock,
    ExternalStepBlock,
    Finding,
    Flow,
    FlowBlock,
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
    substitute_funnel,
)
from .flow_fused_report_service import (
    build_fused_report_state,
    write_fused_flow_report,
)
from .flow_report_service import (
    REPORT_BODY_TIMESTAMP_FORMAT,
    FlowReportState,
    write_flow_report,
)
from .report_service import (
    REPORTS_DIR_NAME,
    REPORT_TIMESTAMP_FORMAT,
    document_bytes,
)
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
from ..workspace import copy_into_workarea


#: Load-integrity notice codes that turn the flow SOURCE block into an
#: ``error`` and abort the chain (HLR-154 / LLR-154.3, map row B99-I10).
#: Every other load notice keeps the advisory ``notices`` mapping (LLR-085.2).
SOURCE_INTEGRITY_CODES = frozenset(
    S19_INTEGRITY_NOTICE_CODES + HEX_INTEGRITY_NOTICE_CODES
)


def _read_change_doc_with_funnel(
    path: Path,
    base_dir: Path,
    funnel: "Sequence[Tuple[str, str]]",
    a2l_context: Optional[dict],
) -> "Tuple[ChangeDocument, List[str]]":
    """Read a PATCH change-doc through the flow-level funnel (batch-96 B1).

    Summary:
        The file's raw text is read with the SAME pre-parse size cap the
        plain reader enforces; over-cap or undecodable files FALL BACK to
        the plain :func:`read_change_document` so its honest ``MF-*`` issues
        surface verbatim (the funnel never weakens a reader guard). A
        readable file passes through :func:`flow_model.substitute_funnel`
        and is parsed by the shared :func:`parse_change_document` string
        seam — the substitution happens on the TEXT, before the parse, so
        placeholders can appear anywhere in the JSON (values, addresses,
        refs). The returned missing list carries one entry per ``${NAME}``
        token with no declared value (left intact in the text).

    Args:
        path (Path): The F1-resolved change-doc path (exists, contained).
        base_dir (Path): The project dir handed to the fallback reader.
        funnel (Sequence[Tuple[str, str]]): The flow's declared table.
        a2l_context (Optional[dict]): The patch's effective A2L context.

    Returns:
        Tuple[ChangeDocument, List[str]]: The parsed document (source_path
        pinned to ``path``) and the sorted, de-duplicated undeclared
        placeholder names.
    """
    try:
        if path.stat().st_size > READ_SIZE_CAP_BYTES:
            raise OSError("over the read cap - the fallback reader reports it")
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return (
            read_change_document(str(path), base_dir, a2l_context=a2l_context),
            [],
        )
    substituted, missing = substitute_funnel(text, funnel)
    document = parse_change_document(substituted, a2l_context=a2l_context)
    document.source_path = path
    return document, missing


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
          parser ``errors`` → advisory WARN findings (``notices``, LLR-085.2),
          EXCEPT the five HLR-154 integrity codes (LLR-154.3) which end the
          block ``error`` and abort the chain, writing no file.
          Change-5 (LLR-142): a declared ``a2l_ref`` resolves through the
          manifest guard and its tag map becomes the run's symbol-resolution
          context before any PATCH; a dangling reference refuses the run,
          naming the reference.
        - PATCH → ``read_change_document`` (with the patch's effective A2L
          context — its own ``a2l_ref`` override, else the SOURCE block's) →
          ``apply_change_document`` (mutates ``mem_map``); batch-96 B1: when
          the FLOW declares a funnel, the change-doc TEXT is substituted
          BEFORE the parse (exact ``${NAME}`` tokens; undeclared names stay
          intact + one named NOTICE each, never a failure); batch-95
          inc-004b (LLR-143.1/.2) retains every arm's per-entry change
          identities (``result.change_records``) and named refusals
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
    # prototype v3 (spec "paso externo"): the run PAUSED at an external-step
    # block (waiting for the human). Like ``aborted`` it skips downstream
    # blocks, but it is NOT an error — the image is intact and the run can
    # continue once the operator confirms log + output.
    paused = False
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
        if (aborted or paused) and not isinstance(block, ReportBlock):
            skip_reason = (
                "skipped (upstream error)"
                if aborted
                else "skipped (waiting on external step)"
            )
            result.block_results.append(
                BlockResult(index, kind, BLOCK_STATUS_SKIPPED, skip_reason)
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
                integrity_errors = [
                    err for err in load_errors
                    if load_notice_code(err) in SOURCE_INTEGRITY_CODES
                ]
                if integrity_errors:
                    # LLR-154.3: a truncated/inconsistent source image is a
                    # STOP, not an advisory — the SOURCE block ends ``error``,
                    # the chain aborts and no file is written. Every
                    # diagnostic (so the LAST one, the painted cause) names
                    # the code and the file (UX-C2).
                    diagnostics = [
                        f"[{load_notice_code(err)}] {path.name}: "
                        f"{err.get('error', 'load error')}"
                        for err in integrity_errors
                    ]
                    result.block_results.append(
                        BlockResult(
                            index, kind, BLOCK_STATUS_ERROR,
                            f"loaded {path.name} with integrity notices",
                            diagnostics,
                        )
                    )
                    aborted = True
                elif load_errors:
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
                # batch-96 B1 (the funnel): when the FLOW declares a variable
                # table, the change-doc text passes through substitution
                # BEFORE the parse — every exact ${NAME} token with a
                # declared value is replaced; undeclared names stay intact
                # and ride back as `funnel_missing` (one named NOTICE each,
                # never a failure). With NO funnel the reader runs verbatim
                # (today's path, untouched).
                funnel_missing: List[str] = []
                if flow.funnel:
                    document, funnel_missing = _read_change_doc_with_funnel(
                        path, ctx.project_dir, flow.funnel,
                        patch_a2l_context,
                    )
                else:
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
                applied = summary.counts.get(DISPOSITION_APPLIED, 0)
                entries = summary.entries
                arm_refusals = [
                    refusal for refusal in result.refusals
                    if refusal.block_index == index
                ]
                non_applied = [
                    entry for entry in entries
                    if entry.disposition != DISPOSITION_APPLIED
                ]
                # batch-99 Inc-8 (LLR-156.1): the PATCH arm's status comes from
                # its OWN dispositions and refusals — first match wins:
                # ``error`` when the document could not be read, was blocked
                # document-wide (every entry it still carried ``blocked`` — a
                # document-level ERROR refusal), or applied 0 of at least 1
                # entry; ``notices`` when some entry was not applied and at
                # least one was; ``ok`` otherwise. An ``error`` stops the flow
                # BEFORE any later WRITE-OUT (the ``_record_error`` abort path
                # below) — P-4's ``outside_0x20000 run=ok patch='applied 0
                # entries'`` is the defect this replaces. The block's LAST
                # diagnostic is the user-facing cause (UX-C2): the first
                # refusal code, else the count with the first address and its
                # disposition.
                if document.has_errors and not entries:
                    # Document-level refusals (``MF-*`` parse/structure codes,
                    # the retired v1 format) mean the document itself could
                    # not be read; an entry-level refusal (``CHG-*``) means it
                    # was read but every entry was refused — the summary says
                    # which. The cause below names the first refusal either
                    # way (UX-C2); the detail lines name EVERY refusal code
                    # (batch-99 Inc-8 review fix F3).
                    document_level = any(
                        refusal.code.startswith("MF-")
                        or refusal.code == "CHG-V1-FORMAT"
                        for refusal in arm_refusals
                    )
                    cause = (
                        f"[{arm_refusals[0].code}] {arm_refusals[0].message}"
                        if arm_refusals
                        else "change document could not be read"
                    )
                    aborted = _record_error(
                        result, index, kind,
                        "change document unreadable"
                        if document_level else "change document refused",
                        [],
                        cause,
                        detail=[
                            f"[{refusal.code}] {refusal.message}"
                            for refusal in arm_refusals
                        ],
                    )
                    continue
                if entries and all(
                    entry.disposition == DISPOSITION_BLOCKED for entry in entries
                ):
                    cause = (
                        f"[{arm_refusals[0].code}] {arm_refusals[0].message}"
                        if arm_refusals
                        else (
                            f"applied 0 of {len(entries)} entries: "
                            f"0x{entries[0].address_start:08X} "
                            f"{entries[0].disposition}"
                        )
                    )
                    aborted = _record_error(
                        result, index, kind, "change document blocked", [],
                        cause,
                        detail=(
                            [
                                f"[{refusal.code}] {refusal.message}"
                                for refusal in arm_refusals
                            ]
                            + [
                                f"0x{entry.address_start:08X} {entry.disposition}"
                                for entry in entries
                            ]
                        ),
                    )
                    continue
                if entries and applied == 0:
                    first = non_applied[0]
                    aborted = _record_error(
                        result, index, kind,
                        f"applied 0 of {len(entries)} entries", [],
                        f"applied 0 of {len(entries)} entries: "
                        f"0x{first.address_start:08X} {first.disposition}",
                        detail=[
                            f"0x{entry.address_start:08X} {entry.disposition}"
                            for entry in non_applied
                        ],
                    )
                    continue
                patch_summary = (
                    f"applied {applied} entr"
                    f"{'y' if applied == 1 else 'ies'}"
                    if not non_applied else
                    f"applied {applied} of {len(entries)} entries, "
                    f"{len(non_applied)} not applied"
                )
                patch_result = BlockResult(
                    index, kind, BLOCK_STATUS_OK, patch_summary,
                )
                if non_applied:
                    # LLR-156.1: some entry was not applied while at least one
                    # was — the arm reports ``notices`` (the umbrella word for
                    # entry-level outcomes, never the block-level ``skipped`` —
                    # UX-C3b) and the summary names the count. The not-applied
                    # lines name EVERY non-applied address with its disposition
                    # (batch-99 Inc-8 review fix F3) and ride ``findings`` as
                    # FINDING_WARN — the funnel arm's idiom (review round 2 fix
                    # N1): Flow Builder paints diagnostics ``sev-error`` and
                    # findings ``sev-warning``, and a notices arm is not an
                    # error. ``diagnostics`` stays the ``error`` arm's channel
                    # (its cause LAST, UX-C2). The lane's terminal log line
                    # keeps the count + first address (UX-C1) from the change
                    # records; the chain-set / flow / fused reports read both
                    # channels (LLR-156.3 / LLR-156.4).
                    patch_result.status = BLOCK_STATUS_NOTICES
                    patch_result.findings.extend(
                        Finding(
                            FINDING_WARN,
                            f"0x{entry.address_start:08X} {entry.disposition}",
                        )
                        for entry in non_applied
                    )
                if funnel_missing:
                    # batch-96 B1: an undeclared ${NAME} NEVER fails the run —
                    # the placeholder rode into the doc intact, so the block
                    # reports NOTICES with one named finding per variable.
                    patch_result.status = BLOCK_STATUS_NOTICES
                    patch_result.findings.extend(
                        Finding(
                            FINDING_WARN,
                            f"funnel: ${{{name}}} is not declared in the flow — "
                            "the placeholder stays intact",
                        )
                        for name in funnel_missing
                    )
                result.block_results.append(patch_result)

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

            elif isinstance(block, ExternalStepBlock):
                # prototype v3 (spec "paso externo"): a HUMAN-GATED step.
                # WITHOUT a confirmation the run PAUSES here ("esperando
                # humano") — the image is intact (NOT an error) and every
                # downstream block skips until the operator confirms. WITH
                # one, the executor validates the MANDATORY log evidence +
                # the output file, COPIES the output into the session
                # artifact folder (the project work area — the SAME
                # copy_into_workarea WRITE idiom the imports use), records
                # the copied path as a written artifact, and the chain goes
                # on. The threaded image passes through UNCHANGED — the
                # step is human-gated, not an image transform.
                confirmations = ctx.external_confirmations or {}
                confirmation = confirmations.get(index)
                if confirmation is None:
                    noun = (
                        "command" if block.mode == EXTERNAL_MODE_TERMINAL
                        else "instruction"
                    )
                    result.block_results.append(
                        BlockResult(
                            index, kind, BLOCK_STATUS_WAITING,
                            f"paused - waiting for a human: {noun} "
                            f"'{block.instruction}' | LOG '{block.log_ref}' "
                            f"+ OUTPUT '{block.output_path}' pending",
                        )
                    )
                    paused = True
                    continue
                log_path = Path(confirmation.log_ref)
                if not log_path.is_absolute():
                    log_path = Path(ctx.project_dir) / log_path
                source_path = Path(confirmation.source_path)
                if not log_path.is_file():
                    aborted = _record_error(
                        result, index, kind, "external step refused", [],
                        f"log '{confirmation.log_ref}' does not exist - the "
                        "log is mandatory evidence, never optional",
                    )
                    continue
                if not source_path.is_file():
                    aborted = _record_error(
                        result, index, kind, "external step refused", [],
                        f"output '{confirmation.source_path}' does not exist - "
                        "run the external step before confirming",
                    )
                    continue
                try:
                    copied = copy_into_workarea(
                        source_path, Path(ctx.project_dir)
                    )
                except Exception as exc:  # noqa: BLE001 - degrade, never abort ugly
                    aborted = _record_error(
                        result, index, kind, "external step copy failed", [],
                        f"{type(exc).__name__}: {exc}",
                    )
                    continue
                result.written_paths.append(copied)
                result.block_results.append(
                    BlockResult(
                        index, kind, BLOCK_STATUS_OK,
                        f"log '{log_path.name}' received · output copied to "
                        f"{copied.name} (session)",
                    )
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
                    # batch-99 Inc-8 (LLR-156.4): the refusals ride the same
                    # positional contract — the report's "## Refusals"
                    # section lists each one, ``- none`` when empty.
                    change_records=list(result.change_records),
                    refusals=list(result.refusals),
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
    # prototype v3: a PAUSED run (an unconfirmed external step) is terminal
    # too — it is NOT FAILED (the image is intact) and NOT CLEAN (the run is
    # not finished): it reports ``paused``.
    if aborted:
        result.status = FLOW_STATUS_ERROR
    elif paused:
        result.status = FLOW_STATUS_PAUSED
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
    detail: Sequence[str] = (),
) -> bool:
    """Append an ``error`` :class:`BlockResult` and signal the chain to abort.

    ``detail`` lines (batch-99 Inc-8 review fix F3) name EVERY non-applied
    address / refusal code between the issue lines and the note — the note
    stays LAST, the user-facing cause (UX-C2).

    Returns ``True`` so the caller can do ``aborted = _record_error(...)``.
    """
    diagnostics = [f"[{issue.code}] {issue.message}" for issue in issues]
    diagnostics.extend(detail)
    diagnostics.append(note)
    result.block_results.append(
        BlockResult(index, kind, BLOCK_STATUS_ERROR, summary, diagnostics)
    )
    return True


# ---------------------------------------------------------------------------
# batch-94 Inc-003 — the chain-set runner (fx_a, US-007; HLR-017…021).
#
# The UNION :func:`run_flow` above keeps owning BLOCK semantics; this layer
# only ORCHESTRATES it per chain: substitute each chain's bound input refs
# into a copy of the template's blocks (LLR-018.2 — the template itself is
# never mutated), dispatch sequential-by-default or parallel-per-chain
# (LLR-019), and emit the chain-set report with one provenance line per
# consumed input (LLR-020.2, the C-42 paste lives in TC-B94-30).
# ---------------------------------------------------------------------------

#: Run-mode tokens (LLR-019.1/.2). The operator control defaults to
#: ``sequential``; ``parallel`` rides the same per-chain isolation boundary.
CHAIN_RUN_SEQUENTIAL = "sequential"
CHAIN_RUN_PARALLEL = "parallel"
CHAIN_RUN_MODES = (CHAIN_RUN_SEQUENTIAL, CHAIN_RUN_PARALLEL)

#: The chain-set report filename stem (M-5 idiom: ``<ts>-chain-set-report.md``).
CHAIN_SET_REPORT_STEM = "chain-set-report"

#: Status → ledger glyph (enum-derived, never file-derived).
_CHAIN_STATUS_GLYPH = {
    FLOW_STATUS_OK: "✓",
    FLOW_STATUS_ISSUES: "◈",
    FLOW_STATUS_ERROR: "✗",
}


@dataclass(frozen=True)
class ChainSpec:
    """One chain of the set: a loaded template + its bound input overrides.

    Args:
        name (str): The lane name (unique inside the set — the panel
            uniquifies duplicate template imports with the ``_<N>`` idiom).
        template (str): The ``flows/<stem>.json`` template reference (the
            saved-template identity, LLR-021.1's one-template-ref-per-chain).
        flow (Flow): The loaded template (owned copy — the runner substitutes
            bindings into a per-run copy, never mutating this object).
        bindings (Dict[int, str]): SOURCE block index → project-relative file
            ref override for THIS run (LLR-018.1 — per-chain independent
            state). An empty mapping runs the template's own refs.
    """

    name: str
    template: str
    flow: Flow
    bindings: Dict[int, str] = field(default_factory=dict)


@dataclass(slots=True)
class ChainRunOutcome:
    """One chain's isolated run outcome inside the set.

    ``len(block_results) == len(flow.blocks)`` holds per chain (the union
    run_flow's contract), so a failed chain still records its ``skipped``
    tail — the fx_a log's "later blocks read skipped" arm (LLR-020.1).

    Args:
        chain (str): The lane name (file-derived on render — markup-safe).
        template (str): The template stem the chain was imported from.
        status (str): The chain's own terminal status (``ok`` /
            ``completed-with-issues`` / ``error``).
        block_results (List[BlockResult]): Per-block outcomes in chain order.
        written_paths (List[Path]): The chain's regenerated outputs.
        inputs (List[Tuple[str, str]]): Per-run input provenance — one
            ``(bound ref, resolved absolute path)`` per consumed input, in
            SOURCE-block order (LLR-020.2; the resolved half is ``""`` when
            the ref failed containment — the chain records why it failed).
        started_at (float): Monotonic clock reading at chain start.
        finished_at (float): Monotonic clock reading at chain end. The
            (started_at, finished_at) pair is the elapsed-window oracle the
            sequential/parallel arms assert on (LLR-019).
        diagnostics (List[str]): Whole-chain notes.
        change_records (List[FlowChangeRecord]): The chain's own per-entry
            PATCH record — every entry its patch arms read, applied and not
            applied, in arm then document order (batch-99 Inc-8, LLR-156.2:
            the fx lane's PATCH cell and the UX-C1 terminal log line read the
            not-applied entries from here). Copied from the run's
            ``FlowRunResult.change_records``.
        refusals (List[FlowRefusal]): The chain's named refusals, copied from
            ``FlowRunResult.refusals`` (LLR-156.2).
        image_ranges (List[Tuple[int, int]]): The chain's final image
            footprint, copied from ``FlowRunResult.image_ranges`` (LLR-156.2).
    """

    chain: str
    template: str
    status: str
    block_results: List[BlockResult] = field(default_factory=list)
    written_paths: List[Path] = field(default_factory=list)
    inputs: List[Tuple[str, str]] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    diagnostics: List[str] = field(default_factory=list)
    change_records: List[FlowChangeRecord] = field(default_factory=list)
    refusals: List[FlowRefusal] = field(default_factory=list)
    image_ranges: List[Tuple[int, int]] = field(default_factory=list)


@dataclass(slots=True)
class ChainSetRunRecord:
    """The whole-set run record — the fx_a run-log's data source.

    Args:
        mode (str): The dispatched mode — ``sequential`` (default) or
            ``parallel`` (LLR-019.2's captured-value assertion arm: the field
            MUST differ between the untouched default arm and the driven
            non-default arm, C-10).
        outcomes (List[ChainRunOutcome]): One per chain, in lane order —
            a chain that failed never drops its sibling (A5 / LLR-019.2's
            error arm), and the order never depends on which thread finished
            first (parallel collects futures in submission order).
        report_path (Optional[Path]): The emitted chain-set report
            (LLR-020.2), or ``None`` when nothing ran or the write degraded.
        diagnostics (List[str]): Whole-set notes.
    """

    mode: str
    outcomes: List[ChainRunOutcome] = field(default_factory=list)
    report_path: Optional[Path] = None
    diagnostics: List[str] = field(default_factory=list)


def _chain_blocks_with_bindings(
    flow: Flow, bindings: Dict[int, str]
) -> List[FlowBlock]:
    """Return the template's blocks with bound SOURCE refs substituted.

    LLR-018.2: the run consumes each chain's OWN bindings — a per-run copy is
    built (``SourceBlock`` is frozen — ``dataclasses.replace``) so the loaded
    template object and the ``flows/*.json`` file are never mutated (D-2's
    unscoped-run precedent: the binding lives on the run, not the blocks).
    A binding whose index is not a SOURCE block is ignored (trusted-side UI
    state only ever binds SOURCE inputs).
    """
    blocks = list(flow.blocks)
    for index, ref in bindings.items():
        if 0 <= index < len(blocks) and isinstance(blocks[index], SourceBlock):
            blocks[index] = replace(blocks[index], image_ref=ref)
    return blocks


def _chain_inputs(
    ctx: FlowContext, blocks: Sequence[FlowBlock]
) -> List[Tuple[str, str]]:
    """Per-run input provenance for one chain — (bound ref, resolved path).

    Every consumed input (each SOURCE block, in block order) resolves through
    the SAME reused containment guard the run itself uses, so the report's
    provenance half can never name a file the run was not allowed to read. A
    ref the guard rejects records ``""`` — the run's own block result carries
    the containment finding (the chain fails closed, LLR-018.2's invalid arm).
    """
    inputs: List[Tuple[str, str]] = []
    for block in blocks:
        if not isinstance(block, SourceBlock):
            continue
        issues: List[ValidationIssue] = []
        resolved = _resolve_manifest_entry(
            ctx.project_dir, block.image_ref, "ChainSpec.input", issues
        )
        inputs.append((block.image_ref, str(resolved) if resolved else ""))
    return inputs


def run_chain_set(
    chains: Sequence[ChainSpec],
    ctx: FlowContext,
    mode: str = CHAIN_RUN_SEQUENTIAL,
    *,
    set_name: str = "chain-set",
    run_one: Optional[Callable[[Flow, FlowContext], FlowRunResult]] = None,
    clock: Optional[Callable[[], float]] = None,
) -> ChainSetRunRecord:
    """Run a chain set — sequential by default, parallel-per-chain on demand.

    Summary:
        The fx_a orchestration layer (HLR-017…021): for each chain, substitute
        its bound input refs into a per-run copy of the template and execute
        the UNION :func:`run_flow` — block semantics are never re-implemented
        here. Sequential mode (the default, LLR-019.1) runs lane order;
        parallel mode (LLR-019.2) submits every chain to a thread pool before
        waiting on any, with per-chain isolation — a failing chain records its
        own outcome and 0 siblings halt (the A5 assumption: each chain threads
        its own ``(mem_map, ranges)`` pair, exactly as the sequential executor
        does). After the last chain, the chain-set report (one provenance line
        per consumed input, LLR-020.2) is written under ``reports/``; a
        failed write is RECORDED, never raised (the fused-report idiom).

    Args:
        chains (Sequence[ChainSpec]): The lanes to run, in lane order.
        ctx (FlowContext): The project directory + optional MAC/A2L context.
        mode (str): ``CHAIN_RUN_SEQUENTIAL`` (default) or ``CHAIN_RUN_PARALLEL``.
        set_name (str): The set's display name for the report header
            (operator text — rendered through ``md_safe`` at emission).
        run_one (Optional[Callable]): The per-chain executor; defaults to
            :func:`run_flow`. The AC seam — it makes the EXECUTION itself
            directly observable (mirrors ``run_flow_over_variants.run_one``).
        clock (Optional[Callable[[], float]]): The monotonic clock; defaults
            to :func:`time.perf_counter`. The elapsed-window seam.

    Returns:
        ChainSetRunResult: One :class:`ChainRunOutcome` per chain in lane
        order, the captured mode, the report path, and whole-set notes.

    Raises:
        ValueError: When ``mode`` is not one of ``CHAIN_RUN_MODES``
            (trusted-side caller — the panel's select only offers the two).

    Data Flow:
        - ``chains`` → per-chain bound copy → ``run_flow`` → outcomes.
        - outcomes → :func:`compose_chain_set_report` → ``reports/<ts>-chain-set-report.md``.

    Dependencies:
        Uses:
            - run_flow (block semantics, reuse-not-fork)
            - _resolve_manifest_entry (the provenance seam, reused guard)
            - compose_chain_set_report / write_chain_set_report
        Used by:
            - s19_app.tui.app.on_flow_execution_panel_run_requested
    """
    if mode not in CHAIN_RUN_MODES:
        raise ValueError(f"unknown chain-run mode {mode!r}")
    execute = run_one if run_one is not None else run_flow
    tick = clock if clock is not None else time.perf_counter
    record = ChainSetRunRecord(mode=mode)
    if not chains:
        record.diagnostics.append("no chains in set - nothing was executed")
        return record

    def _run_one(spec: ChainSpec) -> ChainRunOutcome:
        started = tick()
        blocks = _chain_blocks_with_bindings(spec.flow, spec.bindings)
        inputs = _chain_inputs(ctx, blocks)
        bound_flow = Flow(
            name=spec.flow.name,
            blocks=blocks,
            schema_version=spec.flow.schema_version,
            # batch-96 B1: the funnel is flow-scoped state, not a block — a
            # bound per-run copy keeps the template's declared table.
            funnel=spec.flow.funnel,
        )
        try:
            result = execute(bound_flow, ctx)
        except Exception as exc:  # noqa: BLE001 - per-chain isolation (A5)
            # run_flow is itself non-raising, so reaching here means an
            # injected executor or a future regression broke that contract.
            # Isolating it is the point: the remaining chains still run.
            result = FlowRunResult(
                status=FLOW_STATUS_ERROR,
                diagnostics=[f"{type(exc).__name__}: {exc}"],
            )
        finished = tick()
        return ChainRunOutcome(
            chain=spec.name,
            template=spec.template,
            status=result.status,
            block_results=list(result.block_results),
            written_paths=list(result.written_paths),
            inputs=inputs,
            started_at=started,
            finished_at=finished,
            diagnostics=list(result.diagnostics),
            # batch-99 Inc-8 (LLR-156.2): the chain's own record of what its
            # PATCH arms did and refused — the fx lane painters and the
            # chain-set report enumerate the not-applied entries from here.
            change_records=list(result.change_records),
            refusals=list(result.refusals),
            image_ranges=list(result.image_ranges),
        )

    if mode == CHAIN_RUN_PARALLEL:
        with ThreadPoolExecutor(max_workers=len(chains), thread_name_prefix="fx-chain") as pool:
            record.outcomes.extend(pool.map(_run_one, chains))
    else:
        for spec in chains:
            record.outcomes.append(_run_one(spec))

    try:
        record.report_path = write_chain_set_report(record, set_name, ctx.project_dir)
    except Exception as exc:  # noqa: BLE001 - degrade, never lose the run
        # Mirrors the fused-report idiom: a failed write is RECORDED, not
        # swallowed, and never costs the operator the run's results.
        record.diagnostics.append(
            f"chain-set report write failed: {type(exc).__name__}: {exc}"
        )
    return record


def compose_chain_set_report(
    record: ChainSetRunRecord,
    set_name: str,
    generated_at: datetime,
) -> str:
    """Compose the chain-set report — pure and deterministic (LLR-020.2).

    Summary:
        Emit, in order: a header block (set name, generated timestamp, the
        captured MODE — LLR-019.2's persisted arm — and chain count), the
        **Chain ledger** table (one row per chain with its terminal status
        and elapsed window), the **Input provenance** section — exactly
        ONE line per consumed chain input, ``- Chain <name> input <j>: <ref>
        [bound] path=<code-span>``, the C-42 emitted form TC-B94-30 pins —
        and the batch-99 Inc-8 (LLR-156.3) **Written files**, **Not applied**
        and **Refusals** sections: per lane the written paths, each
        non-applied entry (address + disposition) and each refusal (code +
        message), a clean lane listing ``none``.
        Every file-derived field passes :func:`md_safe` / :func:`md_code`
        (the chain name, template stem, bound ref, change document, refusal
        text); every glyph, label and number is enum/int-derived.

    Args:
        record (ChainSetRunResult): The completed set run.
        set_name (str): The set's display name (operator text).
        generated_at (datetime): The generation instant (injected — the same
            record and instant always produce byte-identical output).

    Returns:
        str: The markdown document.

    Dependencies:
        Uses:
            - md_safe / md_code (markdown_safety — the C-17 render seam)
        Used by:
            - write_chain_set_report
    """
    lines: List[str] = [
        f"# Chain-set report — {md_safe(set_name, limit=120)}",
        "",
        f"- **Generated:** {generated_at.strftime(REPORT_BODY_TIMESTAMP_FORMAT)}",
        f"- **Mode:** {record.mode}",
        f"- **Chains:** {len(record.outcomes)}",
        "",
        "## Chain ledger",
        "",
        "| # | Chain | Template | Status | Blocks | Elapsed |",
        "|---|-------|----------|--------|--------|---------|",
    ]
    for position, outcome in enumerate(record.outcomes, start=1):
        glyph = _CHAIN_STATUS_GLYPH.get(outcome.status, "·")
        elapsed = outcome.finished_at - outcome.started_at
        lines.append(
            f"| {position} | {md_safe(outcome.chain, limit=64)} | "
            f"{md_safe(outcome.template, limit=64)} | "
            f"{glyph} {md_safe(outcome.status, limit=32)} | "
            f"{len(outcome.block_results)} | {elapsed:.3f}s |"
        )
    lines.extend(["", "## Input provenance", ""])
    for outcome in record.outcomes:
        for index, (ref, resolved) in enumerate(outcome.inputs, start=1):
            lines.append(
                f"- Chain {md_safe(outcome.chain, limit=64)} input {index}: "
                f"{md_safe(ref, limit=120)} [bound] "
                f"path=`{md_code(resolved)}`"
            )
    if not any(outcome.inputs for outcome in record.outcomes):
        lines.append("- (no inputs consumed)")
    # batch-99 Inc-8 (LLR-156.3): what the run did NOT apply, per lane — the
    # written file paths, each non-applied entry (address + disposition) and
    # each refusal (code + message). A clean lane lists ``none``; the sections
    # are always present. Every file-derived field rides md_safe / md_code;
    # addresses and counts are int-derived.
    lines.extend(["", "## Written files", ""])
    for outcome in record.outcomes:
        name = md_safe(outcome.chain, limit=64)
        if not outcome.written_paths:
            lines.append(f"- Chain {name}: none")
            continue
        for path in outcome.written_paths:
            lines.append(f"- Chain {name}: `{md_code(str(path))}`")
    lines.extend(["", "## Not applied", ""])
    for outcome in record.outcomes:
        name = md_safe(outcome.chain, limit=64)
        changes = [
            change for change in outcome.change_records
            if change.disposition != DISPOSITION_APPLIED
        ]
        if not changes:
            lines.append(f"- Chain {name}: none")
            continue
        for change in changes:
            lines.append(
                f"- Chain {name}: 0x{change.address_start:08X} "
                f"{md_safe(change.disposition, limit=32)} "
                f"({md_safe(change.change_doc_ref, limit=120)})"
            )
    lines.extend(["", "## Refusals", ""])
    for outcome in record.outcomes:
        name = md_safe(outcome.chain, limit=64)
        if not outcome.refusals:
            lines.append(f"- Chain {name}: none")
            continue
        for refusal in outcome.refusals:
            lines.append(
                f"- Chain {name}: [{md_safe(refusal.code, limit=64)}] "
                f"{md_safe(refusal.message, limit=240)}"
            )
    lines.extend(
        [
            "",
            "---",
            "*Generated by the s19_app Flow Execution (chain-set run).*",
        ]
    )
    return "\n".join(lines)


def _chain_set_report_filename(dest_dir: Path, timestamp: datetime) -> str:
    """Build the chain-set report filename — the M-5 idiom with its own stem.

    ``<ts>-chain-set-report.md``, then ``<ts>-01-chain-set-report.md`` ..
    ``<ts>-99-`` on a same-second collision (the ``_diff_report_filename``
    pattern applied unchanged) — never a silent overwrite.
    """
    base = timestamp.strftime(REPORT_TIMESTAMP_FORMAT)
    candidate = f"{base}-{CHAIN_SET_REPORT_STEM}.md"
    if not (dest_dir / candidate).exists():
        return candidate
    for counter in range(1, 100):
        candidate = f"{base}-{counter:02d}-{CHAIN_SET_REPORT_STEM}.md"
        if not (dest_dir / candidate).exists():
            return candidate
    raise FileExistsError(
        f"100 chain-set reports already exist for second {base} - refusing "
        "to overwrite an existing report"
    )


def _default_chain_set_now() -> datetime:
    """The chain-set report clock — UTC, like every report producer."""
    return datetime.now(timezone.utc)


def write_chain_set_report(
    record: ChainSetRunRecord,
    set_name: str,
    project_dir: Path,
    now_fn=None,
) -> Path:
    """Compose and write the chain-set report under ``<project>/reports/``.

    Summary:
        Create the reports directory, pick a non-colliding name via
        :func:`_chain_set_report_filename` (the M-5 scheme), and write UTF-8
        through :func:`document_bytes` (the BOM/encoding seam every report
        producer shares). No file-derived string reaches the path: the
        directory is code-derived and the filename is timestamp-derived, so a
        hostile set NAME can only ever appear in report CONTENT (escaped).

    Args:
        record (ChainSetRunResult): The completed set run.
        set_name (str): The set's display name.
        project_dir (Path): The active project directory.
        now_fn (Optional[Callable[[], datetime]]): Injectable clock; defaults
            to :func:`_default_chain_set_now`.

    Returns:
        Path: The written report path.

    Dependencies:
        Uses:
            - compose_chain_set_report / _chain_set_report_filename
        Used by:
            - run_chain_set
    """
    clock = now_fn if now_fn is not None else _default_chain_set_now
    generated_at = clock()
    reports_dir = Path(project_dir) / REPORTS_DIR_NAME
    reports_dir.mkdir(parents=True, exist_ok=True)
    target = reports_dir / _chain_set_report_filename(reports_dir, generated_at)
    target.write_bytes(document_bytes(compose_chain_set_report(record, set_name, generated_at)))
    return target
