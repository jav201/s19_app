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
from typing import List, Optional, Sequence, Union

#: Block ``kind`` discriminators (the JSON-persistence tag, batch-45).
BLOCK_SOURCE = "source"
BLOCK_PATCH = "patch"
BLOCK_WRITE_OUT = "write_out"

#: WRITE-OUT emit formats — the ``save_patched_image`` ``source_kind`` values.
WRITE_FMT_S19 = "s19"
WRITE_FMT_HEX = "hex"

#: Per-block outcome tokens (mirrors ``variant_execution_service`` VARIANT_*).
BLOCK_STATUS_OK = "ok"
BLOCK_STATUS_ERROR = "error"
BLOCK_STATUS_SKIPPED = "skipped"

#: Whole-flow outcome tokens.
FLOW_STATUS_OK = "ok"
FLOW_STATUS_ERROR = "error"


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


#: A tracer-slice block (open for CHECK/CRC extension — ADR §7/§9).
FlowBlock = Union[SourceBlock, PatchBlock, WriteOutBlock]


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
        status (str): ``"ok"`` / ``"error"`` / ``"skipped"`` (skipped when an
            upstream block failed — a broken source can't feed a patch).
        summary (str): A one-line human-readable outcome.
        diagnostics (List[str]): Failure text / containment findings.
    """

    index: int
    kind: str
    status: str
    summary: str = ""
    diagnostics: List[str] = field(default_factory=list)


@dataclass(slots=True)
class FlowRunResult:
    """The whole-flow run outcome — always well-formed, never raised.

    ``len(block_results) == len(flow.blocks)`` always (mirrors
    ``VariantExecutionResult`` isolation, LLR-006.4).

    Args:
        status (str): ``"ok"`` when every block succeeded, else ``"error"``.
        block_results (List[BlockResult]): One per block, in flow order.
        written_paths (List[Path]): The files WRITE-OUT blocks produced.
        diagnostics (List[str]): Whole-flow notes.
    """

    status: str
    block_results: List[BlockResult] = field(default_factory=list)
    written_paths: List[Path] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
