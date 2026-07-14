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
from .a2l_service import enrich_tags_and_render
from .flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_OK,
    WRITE_FMT_HEX,
    WRITE_FMT_S19,
    BlockResult,
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
        FlowRunResult: ``status="ok"`` when every block succeeded, else
        ``"error"``; the per-block outcomes and the written paths.

    Data Flow:
        - SOURCE → ``build_loaded_s19/hex`` → seed ``mem_map``/``ranges``.
        - PATCH → ``read_change_document`` → ``apply_change_document`` (mutates
          ``mem_map``).
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

    if aborted or any(
        br.status == BLOCK_STATUS_ERROR for br in result.block_results
    ):
        result.status = FLOW_STATUS_ERROR
    return result


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
