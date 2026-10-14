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
from typing import TYPE_CHECKING, List, Optional, Sequence, Tuple, Union

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the runtime stdlib-only
    from ..models import VariantDescriptor

#: Block ``kind`` discriminators (the JSON-persistence tag, batch-45).
BLOCK_SOURCE = "source"
BLOCK_PATCH = "patch"
BLOCK_WRITE_OUT = "write_out"
BLOCK_CHECK = "check"
BLOCK_CRC = "crc"
#: Ref-less report block (batch-53 FB-P1, D2 / AMD-5) — persists + round-trips;
#: content generation is deferred to FB-P1b (run_flow treats it as a no-op).
BLOCK_REPORT = "report"

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
#: Run-scope discriminators (batch-70 FB-P2, LLR-104.6). They live HERE, in the
#: pure-data layer, so ``FlowBuilderPanel`` can offer the choice without
#: importing the execution engine (the panel's no-engine contract). The app maps
#: them onto ``variant_execution_service``'s scopes EXPLICITLY — the string
#: values coincide, and a coincidence is not an interface.
FLOW_SCOPE_SINGLE = "single"
FLOW_SCOPE_ALL_VARIANTS = "all"
FLOW_SCOPE_ASSIGNMENTS = "assignments"

#: Every scope the Run path accepts.
FLOW_SCOPES = (FLOW_SCOPE_SINGLE, FLOW_SCOPE_ALL_VARIANTS, FLOW_SCOPE_ASSIGNMENTS)

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
        a2l_ref (Optional[str]): Change-5 (batch-95 LLR-142) — an optional
            PROJECT-RELATIVE A2L filename, resolved through the SAME
            containment guard; the run loads its tag map as the flow's
            symbol-resolution context BEFORE any PATCH applies. ``None``
            (the default) declares no reference — symbol entries are then
            refused at load (no implicit A2L).
    """

    image_ref: str
    file_type: str = WRITE_FMT_S19
    a2l_ref: Optional[str] = None
    kind: str = BLOCK_SOURCE


@dataclass(frozen=True)
class PatchBlock:
    """Transform block — apply a change document to the working ``mem_map``.

    Args:
        change_doc_ref (str): A PROJECT-RELATIVE change-document filename,
            resolved against the project directory through the containment
            guard, then read via the hardened ``read_change_document`` seam.
        a2l_ref (Optional[str]): Change-5 (batch-95 LLR-142) — an optional
            per-patch A2L reference overriding the SOURCE block's for THIS
            change-set only, same grammar and guard; ``None`` (the default)
            inherits the SOURCE block's declared reference (or refuses
            symbol entries when none is declared anywhere).
    """

    change_doc_ref: str
    a2l_ref: Optional[str] = None
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


@dataclass(frozen=True)
class CrcBlock:
    """Finalization block — compute a CRC over the working (post-patch) image
    and inject it, growing the image when the output window is outside the
    loaded ranges (batch-52, ADR §7 "CRC-into-loop seam").

    The block computes over the CURRENT threaded ``(mem_map, ranges)`` — i.e.
    after all upstream PATCH mutations — via the shared CRC kernel
    (``parse_crc_config`` → ``check_regions`` → ``inject_crcs``), then threads
    the CRC-injected working image forward. A CRC positioned before any PATCH
    (or in a flow with no PATCH) emits a non-blocking WARN (LLR-091.1).

    Args:
        config_ref (str): A PROJECT-RELATIVE CRC template-config filename
            (a ``.s19tool/templates/`` JSON parsed by ``parse_crc_config``),
            resolved against the project directory through the SAME manifest
            containment guard the other refs use (never an absolute/escaping
            path); an untrusted input — a malformed or unsafe ref fails the
            block closed (LLR-092.1/.2).
    """

    config_ref: str
    kind: str = BLOCK_CRC


@dataclass(frozen=True)
class ReportBlock:
    """Report block — a ref-less terminal marker that a flow produces a report.

    Field-less by design (AMD-5, LOCKED for FB-P1): it carries no ``*_ref`` and
    no WRITE target, so it serializes as ``{"kind": "report"}`` and round-trips
    through the hardened loader's ref-less path (strict-keys ``{"kind"}`` still
    fires on any smuggled field). ``run_flow`` treats it as a no-op emitting
    ``BLOCK_STATUS_OK`` — report CONTENT generation is deferred to FB-P1b. Any
    future output field must pass the loader's V7 ``FLOW-UNSAFE-OUTPUT-NAME``
    shape check, which is why none is added here yet.
    """

    kind: str = BLOCK_REPORT


#: A tracer-slice block (SOURCE/PATCH/CHECK/WRITE-OUT + the batch-52 CRC block +
#: the batch-53 ref-less REPORT block).
FlowBlock = Union[
    SourceBlock, PatchBlock, WriteOutBlock, CheckBlock, CrcBlock, ReportBlock
]


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
            Change-5 note (batch-95 LLR-142): this is the PROJECT's loaded
            A2L — the enrichment/linkage source. Symbol-entry RESOLUTION
            never rides it implicitly; a run resolves symbols only against
            the A2L a block DECLARES via ``a2l_ref`` (a declared reference
            becomes the run-effective tag map for the run's duration).
        variant (Optional[VariantDescriptor]): The image this run is bound to
            (batch-70 FB-P2, LLR-104.1). ``None`` — the default — is today's
            unscoped single-image run, in which the SOURCE block's own
            ``image_ref`` is used and nothing downstream changes (AC-6). When
            set, the SOURCE block's ``image_ref``/``file_type`` are overridden
            for the duration of THIS run; neither the ``Flow`` object nor the
            flow file on disk is mutated (D-2).
        defer_report (bool): When ``True`` a REPORT block records its outcome
            but writes NO file — its content is carried into the single fused
            document instead (D-4: a fused run emits ONE report, never one per
            variant, because N files re-create the manual collation FB-P2
            exists to remove). Set by ``run_flow_over_variants``; ``False`` — the
            default — is today's per-run report.
    """

    project_dir: Path
    mac_records: Optional[Sequence[dict]] = None
    a2l_data: Optional[dict] = None
    variant: Optional["VariantDescriptor"] = None
    defer_report: bool = False


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
class FlowChangeRecord:
    """One per-entry change record a flow run retained from a PATCH arm
    (batch-95 inc-004b, change-5c — LLR-143.1's run-side record).

    ``run_flow`` used to reduce each PATCH arm to an ``"applied N entries"``
    summary line and discard the per-entry detail — which left nothing from
    which a report could attribute the flow's changes. This record retains
    ONE per-entry identity (its OWN A2L symbol when symbol-referenced, always
    its resolved address, the applied byte runs, the disposition) together
    with the arm it came from and the A2L reference the entry resolved
    against (the patch's override, else the SOURCE block's declaration).

    Args:
        block_index (int): The PATCH block's position in the flow.
        change_doc_ref (str): The project-relative change document ref the
            entry was read from (file-derived — markup-safe on render).
        a2l_ref (Optional[str]): The A2L reference the entry resolved against
            (``PatchBlock.a2l_ref`` override, else the SOURCE block's declared
            ref, else ``None`` — an address-form change-set under no declared
            reference). LLR-143.1's "resolved against" column.
        entry_type (str): The source entry's kind — ``"string"`` / ``"bytes"``.
        symbol (Optional[str]): The entry's OWN A2L symbol for a change-5
            symbol-referenced entry; ``None`` for the address form.
        address_start (int): Inclusive start of the addressed byte range.
        address_end (int): Exclusive end — ``address_end - address_start``
            is the encoded byte length.
        disposition (str): One token of the change-set
            :data:`DISPOSITION_DOMAIN` — ``applied`` / ``skipped-*`` /
            ``blocked`` (a refused document blocks every entry it still
            carried).
        before_bytes (Optional[Tuple[int, ...]]): The prior image bytes over
            the addressed range — ``None`` for every non-``applied``
            disposition (mirrors ``ChangeSummaryEntry.before_bytes``).
        after_bytes (Tuple[int, ...]): The entry's encoded run.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by ``flow_execution_service.run_flow`` (one per
          ``ChangeSummaryEntry`` of every PATCH arm's apply summary), in arm
          then document order; consumed by ``flow_report_service`` (the
          change-attribution section) and by ``diff_report_service`` (the
          A2B flow-change census over a flow-produced image, LLR-143.2).

    Dependencies:
        Used by:
            - flow_execution_service.run_flow
            - flow_report_service / diff_report_service (batch-95 inc-004b)
    """

    block_index: int
    change_doc_ref: str
    a2l_ref: Optional[str]
    entry_type: str
    symbol: Optional[str]
    address_start: int
    address_end: int
    disposition: str
    before_bytes: Optional[Tuple[int, ...]]
    after_bytes: Tuple[int, ...]


@dataclass(slots=True)
class FlowRefusal:
    """One named refusal a flow run retained from a PATCH arm's read
    (batch-95 inc-004b, change-5c — LLR-143.2's "a named refusal is still an
    attribution line" carrier).

    A change-set read that refuses an entry (change-5:
    ``CHG-SYMBOL-UNRESOLVED`` / ``CHG-SYMBOL-VALUE``, …) DROPS the entry — the
    summary has no per-entry record of it, so without this record the refusal
    would be silently absent from every downstream report. It retains the
    refusal's code, the symbol/address it names, and the arm it fired in.

    Args:
        block_index (int): The PATCH block's position in the flow.
        change_doc_ref (str): The project-relative change document ref
            (file-derived — markup-safe on render).
        a2l_ref (Optional[str]): The effective A2L reference (override, else
            SOURCE declaration, else ``None``) — as for
            :class:`FlowChangeRecord`.
        code (str): The refusal's finding code (e.g.
            ``CHG-SYMBOL-UNRESOLVED``).
        symbol (Optional[str]): The symbol the refusal names, when it names
            one (the issues' ``symbol`` field); ``None`` otherwise.
        address (Optional[int]): The address the refusal names, when it names
            one; ``None`` otherwise.
        message (str): The refusal's one-line message (already names the
            symbol/reference — file-derived, markup-safe on render).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by ``flow_execution_service.run_flow`` (one per
          ERROR-severity issue of every PATCH arm's read/apply); consumed by
          ``diff_report_service`` (the A2B flow-change census).

    Dependencies:
        Used by:
            - flow_execution_service.run_flow
            - diff_report_service (batch-95 inc-004b)
    """

    block_index: int
    change_doc_ref: str
    a2l_ref: Optional[str]
    code: str
    symbol: Optional[str]
    address: Optional[int]
    message: str


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
            SOURCE). Additive per §6.3 R-6.
        pre_crc_ranges (List[Tuple[int, int]]): The working image footprint
            captured immediately BEFORE the first CRC growth — the "before"
            side of the Direction-A twin ribbon (batch-52, LLR-094.1). Defaults
            to (and equals) the SOURCE/post-patch footprint; when no CRC block
            grows the image it equals ``image_ranges`` (before == after).
            Additive; empty when no image was ever loaded.
        change_records (List[FlowChangeRecord]): The run's OWN record of every
            change entry its PATCH arms read — one :class:`FlowChangeRecord`
            per summary entry, in arm then document order (batch-95 inc-004b,
            change-5c LLR-143.1/143.2: the retention from which the flow
            report's change-attribution section and the A2B diff's flow-change
            census enumerate the flow's changes — ``run_flow`` previously
            discarded the per-entry detail). Additive per §6.3 R-6; empty when
            no PATCH arm ran.
        refusals (List[FlowRefusal]): The run's OWN record of every named
            refusal its PATCH arms' reads produced — one :class:`FlowRefusal`
            per ERROR-severity issue (batch-95 inc-004b, LLR-143.2: "a named
            refusal is still an attribution line, never silently dropped").
            Additive per §6.3 R-6; empty when nothing was refused.
    """

    status: str
    block_results: List[BlockResult] = field(default_factory=list)
    written_paths: List[Path] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    image_ranges: List[Tuple[int, int]] = field(default_factory=list)
    pre_crc_ranges: List[Tuple[int, int]] = field(default_factory=list)
    change_records: List[FlowChangeRecord] = field(default_factory=list)
    refusals: List[FlowRefusal] = field(default_factory=list)


@dataclass(slots=True)
class VariantRunOutcome:
    """One variant's isolated flow-run outcome (batch-70 FB-P2, LLR-104.2).

    Args:
        variant_id (str): The executed variant's id — file-derived, so every
            consumer renders it markup-safe (D-6).
        result (FlowRunResult): That variant's whole-flow outcome, exactly as
            an unscoped run would have produced it.
    """

    variant_id: str
    result: FlowRunResult


@dataclass(slots=True)
class FusedFlowRunResult:
    """The multi-image run outcome — one entry per PLANNED variant (LLR-104.2).

    ``len(variant_outcomes) == len(planned)`` always: a variant that aborted, or
    whose image ref failed containment, still contributes an outcome (D-3). A
    fused run that dropped a variant would be exactly the silent omission this
    feature exists to remove.

    Args:
        status (str): The roll-up across variants — any ``"error"`` →
            ``"error"``; else any ``"completed-with-issues"`` → that; else
            ``"ok"`` (D-5).
        variant_outcomes (List[VariantRunOutcome]): One per planned variant, in
            plan order.
        n_ok (int): Variants whose own status was ``"ok"``.
        n_issues (int): Variants whose own status was ``"completed-with-issues"``.
        n_error (int): Variants whose own status was ``"error"``.
        written_paths (List[Path]): Every image output across all variants, in
            plan order — the image-output contract, unioned.
        report_path (Optional[Path]): The ONE fused report, written when the
            flow carries a REPORT block (D-4). ``None`` when it does not — a
            flow with no REPORT block still writes none, exactly as unscoped.
        diagnostics (List[str]): Whole-run notes (e.g. an empty planned set).

    Data Flow:
        - Built by ``flow_execution_service.run_flow_over_variants``.
        - Consumed by ``flow_fused_report_service.compose_fused_flow_report``
          and by ``FlowBuilderPanel.render_result``.

    Example:
        >>> FusedFlowRunResult(status="ok").n_ok
        0
    """

    status: str
    variant_outcomes: List[VariantRunOutcome] = field(default_factory=list)
    n_ok: int = 0
    n_issues: int = 0
    n_error: int = 0
    written_paths: List[Path] = field(default_factory=list)
    report_path: Optional[Path] = None
    diagnostics: List[str] = field(default_factory=list)
