"""Flow Builder — typed functional-block vocabulary (batch-44 tracer, R-TUI-059).

The Flow Builder composes an ordered list of typed blocks
(SOURCE → PATCH → WRITE-OUT for the tracer slice) that
:func:`flow_execution_service.run_flow` executes over a project image,
threading a working ``(mem_map, ranges)`` pair — the state model of
``variant_execution_service._execute_one_variant`` generalized from a
variant's fixed change-file list to an explicit block list.

This module is pure data (frozen block dataclasses + run-result containers);
it imports stdlib only and carries NO Textual and NO execution logic
(service-layer contract C-7). The blocks are JSON-serialisable by shape so
batch-45 can persist a flow to ``flow.json`` without a model change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, Union

#: Block ``kind`` discriminators (the JSON-persistence tag, batch-45).
BLOCK_SOURCE = "source"
BLOCK_PATCH = "patch"
BLOCK_WRITE_OUT = "write_out"
BLOCK_CHECK = "check"

#: WRITE-OUT emit formats — the ``save_patched_image`` ``source_kind`` values.
WRITE_FMT_S19 = "s19"
WRITE_FMT_HEX = "hex"

#: CHECK per-block gating vocabulary (batch-51, LLR-086.1). ``advisory`` (the
#: default) never changes any status beyond informational; ``block-own-op``
#: marks ONLY the CHECK block itself ``error`` when its own operation is
#: invalid (an unresolvable/unreadable check document) — the CHAIN is never
#: blocked either way (LLR-086.4).
CHECK_GATING_ADVISORY = "advisory"
CHECK_GATING_BLOCK_OWN = "block-own-op"

#: Per-block outcome tokens (mirrors ``variant_execution_service`` VARIANT_*).
BLOCK_STATUS_OK = "ok"
BLOCK_STATUS_ERROR = "error"
BLOCK_STATUS_SKIPPED = "skipped"
#: Advisory outcome — the block ran, the image is intact, but it carries WARN
#: findings (integrity notices, non-blocking check faults) (batch-51, LLR-085.1).
BLOCK_STATUS_NOTICES = "notices"

#: Whole-flow outcome tokens.
FLOW_STATUS_OK = "ok"
FLOW_STATUS_ERROR = "error"
#: Amber outcome — output was produced WITH advisories (a ``notices`` block, a
#: non-aborting block ``error``, or a WARN finding); distinct from ``error``
#: (image broken, no/partial output) (batch-51, LLR-087.1).
FLOW_STATUS_ISSUES = "completed-with-issues"

#: Advisory finding severity (batch-51, LLR-085.1). ``FINDING_WARN`` is the
#: non-aborting notice channel surfaced on ``BlockResult.findings``. The value
#: is internal — block/flow status, not this string, drives the frozen
#: ``sev-*`` render. (STOP is modelled by ``aborted`` + ``BLOCK_STATUS_ERROR``,
#: so no separate finding severity is needed.)
FINDING_WARN = "warn"


@dataclass(frozen=True)
class Finding:
    """An advisory finding attached to a block (collect-don't-abort).

    Args:
        severity (str): ``FINDING_WARN`` (advisory, non-aborting).
        message (str): The human-readable finding text. May be file-derived
            (parser error text) — render markup-safe at the UI boundary.
    """

    severity: str
    message: str


@dataclass(frozen=True)
class SourceBlock:
    """Seed block — load a project image into the working ``(mem_map, ranges)``.

    Args:
        image_ref (str): A PROJECT-RELATIVE image filename, resolved against
            the project directory through the manifest containment guard
            before opening (never an absolute/escaping path).
        file_type (str): ``"s19"`` (default) or ``"hex"``.
    """

    image_ref: str
    file_type: str = WRITE_FMT_S19
    kind: str = BLOCK_SOURCE


@dataclass(frozen=True)
class PatchBlock:
    """Transform block — apply a change document to the working ``mem_map``.

    Args:
        change_doc_ref (str): A PROJECT-RELATIVE change-document filename,
            resolved against the project directory through the containment
            guard, then read via the hardened ``read_change_document`` seam.
    """

    change_doc_ref: str
    kind: str = BLOCK_PATCH


@dataclass(frozen=True)
class WriteOutBlock:
    """Sink block — emit the working image to a file under the work area.

    Args:
        output_name (str): The output filename — sanitised by
            ``save_patched_image`` (F-S-01) and placed via
            ``copy_into_workarea`` (containment + dedup); a hostile name
            cannot escape the work area.
        fmt (str): ``"s19"`` (default) or ``"hex"`` — the emitter selector.
    """

    output_name: str
    fmt: str = WRITE_FMT_S19
    kind: str = BLOCK_WRITE_OUT


@dataclass(frozen=True)
class CheckBlock:
    """Verify block — run a check document against the working image, read-only.

    The block reports which addresses are present/absent (present/absent
    aggregate counts) and passes the working ``(mem_map, ranges)`` through
    UNCHANGED to downstream blocks; a CHECK never aborts the chain (LLR-086.4).

    Args:
        check_doc_ref (str): A PROJECT-RELATIVE check-document filename,
            resolved against the project directory through the containment
            guard, then read via ``read_change_document``.
        gating (str): ``CHECK_GATING_ADVISORY`` (default) or
            ``CHECK_GATING_BLOCK_OWN`` — affects ONLY this block's own status
            when its operation is invalid; never the chain.
    """

    check_doc_ref: str
    gating: str = CHECK_GATING_ADVISORY
    kind: str = BLOCK_CHECK


#: A tracer-slice block (open for CRC extension — ADR §7/§9).
FlowBlock = Union[SourceBlock, PatchBlock, WriteOutBlock, CheckBlock]


@dataclass(frozen=True)
class Flow:
    """An ordered, named list of typed blocks.

    Args:
        name (str): The flow's display name.
        blocks (Sequence[FlowBlock]): The blocks in execution order.
        schema_version (int): For the batch-45 ``flow.json`` envelope.
    """

    name: str
    blocks: Sequence[FlowBlock] = ()
    schema_version: int = 1


@dataclass(frozen=True)
class FlowContext:
    """The read-only execution context threaded alongside the working image.

    Args:
        project_dir (Path): The ``.s19tool/workarea/<project>/`` directory —
            the ref-resolution base AND the write-out destination.
        mac_records (Optional[Sequence[dict]]): Parsed project MAC records
            (shared linkage source), or ``None``.
        a2l_data (Optional[dict]): Parsed project A2L payload, or ``None``.
    """

    project_dir: Path
    mac_records: Optional[Sequence[dict]] = None
    a2l_data: Optional[dict] = None


@dataclass(slots=True)
class BlockResult:
    """The isolated outcome of executing one block (collect-don't-abort).

    Args:
        index (int): The block's position in the flow.
        kind (str): The block ``kind``.
        status (str): ``"ok"`` / ``"notices"`` / ``"error"`` / ``"skipped"``
            (skipped when an upstream block failed — a broken source can't feed
            a patch; notices when the block ran with advisory findings).
        summary (str): A one-line human-readable outcome.
        diagnostics (List[str]): Failure text / containment findings.
        findings (List[Finding]): Advisory (non-aborting) findings — parser
            integrity notices, non-blocking check faults (batch-51, LLR-085.1).
    """

    index: int
    kind: str
    status: str
    summary: str = ""
    diagnostics: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


@dataclass(slots=True)
class FlowRunResult:
    """The whole-flow run outcome — always well-formed, never raised.

    ``len(block_results) == len(flow.blocks)`` always (mirrors
    ``VariantExecutionResult`` isolation, LLR-006.4).

    Args:
        status (str): ``"ok"`` (CLEAN — every block clean),
            ``"completed-with-issues"`` (output produced with advisories), or
            ``"error"`` (FAILED — image broken by an aborting block).
        block_results (List[BlockResult]): One per block, in flow order.
        written_paths (List[Path]): The files WRITE-OUT blocks produced.
        diagnostics (List[str]): Whole-flow notes.
        image_ranges (List[Tuple[int, int]]): The working image's final
            ``(start, end)`` address footprint — the ranges after the last
            block, used by the Direction-A memory ribbon (batch-51, LLR-088.4,
            §6.5 AMD-1). Empty when no image was ever loaded (an unresolvable
            SOURCE). Additive per §6.3 R-6. A separate ``before`` footprint is a
            batch-52 carry (CRC is the first range-growing block).
    """

    status: str
    block_results: List[BlockResult] = field(default_factory=list)
    written_paths: List[Path] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    image_ranges: List[Tuple[int, int]] = field(default_factory=list)
