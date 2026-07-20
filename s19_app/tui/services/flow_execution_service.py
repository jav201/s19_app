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

from typing import List, Optional, Sequence, Tuple

from ...core import S19File
from ...hexfile import IntelHexFile
from ...validation.model import ValidationIssue
from ..changes import (
    apply_change_document,
    read_change_document,
    save_patched_image,
)
from ..changes.check import run_check_document
from .a2l_service import enrich_tags_and_render
from .flow_model import (
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
    Finding,
    Flow,
    FlowContext,
    FlowRunResult,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)
from .load_service import build_loaded_hex, build_loaded_s19
from .variant_execution_service import _resolve_manifest_entry


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
        - PATCH → ``read_change_document`` → ``apply_change_document`` (mutates
          ``mem_map``).
        - CHECK → ``read_change_document`` → ``run_check_document`` (read-only,
          image passed through unchanged; never aborts the chain — LLR-086.4).
        - WRITE-OUT → ``save_patched_image(source_kind=fmt)`` → written path.

    Dependencies:
        Uses:
            - _resolve_manifest_entry (F1 containment)
            - build_loaded_s19 / build_loaded_hex / enrich_tags_and_render
            - read_change_document / apply_change_document / save_patched_image
        Used by:
            - s19_app.tui.screens_directionb.FlowBuilderPanel (rail-8 Run)
    """
    result = FlowRunResult(status=FLOW_STATUS_OK)
    mem_map: Optional[dict] = None
    ranges: Optional[Sequence[Tuple[int, int]]] = None
    s0_header: Optional[bytes] = None
    a2l_tags = None
    aborted = False

    for index, block in enumerate(flow.blocks):
        kind = getattr(block, "kind", "?")
        if aborted:
            result.block_results.append(
                BlockResult(index, kind, BLOCK_STATUS_SKIPPED,
                            "skipped (upstream error)")
            )
            continue
        try:
            if isinstance(block, SourceBlock):
                issues: List[ValidationIssue] = []
                path = _resolve_manifest_entry(
                    ctx.project_dir, block.image_ref,
                    "SourceBlock.image_ref", issues,
                )
                if path is None or not path.exists():
                    aborted = _record_error(
                        result, index, kind, "source unresolved", issues,
                        "source image not found or not inside the project",
                    )
                    continue
                if block.file_type == WRITE_FMT_HEX:
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
                a2l_tags = (
                    enrich_tags_and_render(ctx.a2l_data, mem_map)[0]
                    if ctx.a2l_data else None
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
                document = read_change_document(str(path), ctx.project_dir)
                summary = apply_change_document(
                    document, mem_map, ranges, ctx.mac_records, a2l_tags
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
                    document = read_change_document(str(path), ctx.project_dir)
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

            else:  # pragma: no cover - guards an unknown block kind
                aborted = _record_error(
                    result, index, kind, "unknown block", [],
                    f"unknown block kind {kind!r}",
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
    return result


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
