"""Flow Builder — flow.json persistence service (batch-53 FB-P1, HLR-001/002).

Serialize a :class:`flow_model.Flow` to the schema-v1 JSON envelope and load an
**untrusted** ``flow.json`` back with a hardened, fail-closed, whole-flow
validator. Every embedded READ ref is re-validated through the SAME
``_resolve_manifest_entry`` containment guard the runtime already uses
(reuse-not-fork); any finding rejects the whole flow (never a partial pipeline).

Textual-free (service-layer contract C-7): imports stdlib + the flow model + the
manifest guard + the validation model only. UI wiring (modals, panel, handlers)
lands in a later increment; this module owns serialize/deserialize/load.

Finding taxonomy (OQ-1, §6.2 — mixed and honest):

- ``FLOW-*`` codes are the loader's OWN envelope/schema/block findings.
- ``MANIFEST-*`` codes travel VERBATIM with the reused guard — the reader sees
  exactly which component fired. The loader never rewrites them.
- ``FLOW-UNSAFE-REF`` is the one loader-side path-shape reject that closes a gap
  the reused guard does not cover: a Windows *drive-relative* ref (``C:foo`` —
  a drive letter with no root). ``PureWindowsPath("C:foo").is_absolute()`` is
  ``False``, so the guard's absolute-path arms miss it, yet joining it against a
  project on a different drive escapes the work area. Rejected loader-side
  WITHOUT forking the guard (AMD-11/F4).
"""

from __future__ import annotations

import json
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, List, Optional, Set, Tuple

from ...validation.model import ValidationIssue, ValidationSeverity
from .flow_model import (
    BLOCK_CHECK,
    BLOCK_CRC,
    BLOCK_PATCH,
    BLOCK_REPORT,
    BLOCK_SOURCE,
    BLOCK_WRITE_OUT,
    CHECK_GATING_ADVISORY,
    CHECK_GATING_BLOCK_OWN,
    WRITE_FMT_HEX,
    WRITE_FMT_S19,
    CheckBlock,
    CrcBlock,
    Flow,
    FlowBlock,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)
from .variant_execution_service import (
    MANIFEST_PATH_ESCAPE,
    _resolve_manifest_entry,
)

#: The one supported envelope version (``Flow.schema_version`` defaults to 1).
FLOW_SCHEMA_VERSION = 1

#: Byte cap for a flow.json read (probed BEFORE parse — a pre-parse DoS guard).
#: Deliberately tight: a flow is a small pipeline description, not a payload.
FLOW_SIZE_CAP_BYTES = 1_048_576  # 1 MiB

#: Structural sanity caps (fail closed outside them).
FLOW_MIN_BLOCKS = 1
FLOW_MAX_BLOCKS = 64
FLOW_MAX_NAME_LEN = 64

#: Loader-OWN finding codes (public test contract — OQ-1/R-2).
FLOW_SIZE_CAP = "FLOW-SIZE-CAP"
FLOW_JSON_PARSE = "FLOW-JSON-PARSE"
FLOW_BAD_STRUCTURE = "FLOW-BAD-STRUCTURE"
FLOW_SCHEMA_UNSUPPORTED = "FLOW-SCHEMA-UNSUPPORTED"
FLOW_UNKNOWN_KIND = "FLOW-UNKNOWN-KIND"
FLOW_BAD_FIELD = "FLOW-BAD-FIELD"
FLOW_UNSAFE_OUTPUT_NAME = "FLOW-UNSAFE-OUTPUT-NAME"
#: Loader-side path-shape reject for a Windows drive-relative READ ref (the gap
#: the reused guard's ``is_absolute()`` arms miss — AMD-11/F4).
FLOW_UNSAFE_REF = "FLOW-UNSAFE-REF"

#: kind → (required ref field | None, enum fields {name: allowed values}).
#: ``report`` is ref-less (AMD-5): ``None`` ref field means the loader skips the
#: required-ref check, V6 (READ-ref containment) and V7 (WRITE-target shape) for
#: that block while STILL enforcing strict-keys ``{"kind"}``.
_KIND_SPEC: Dict[str, Tuple[Optional[str], Dict[str, Set[str]]]] = {
    BLOCK_SOURCE: ("image_ref", {"file_type": {WRITE_FMT_S19, WRITE_FMT_HEX}}),
    BLOCK_PATCH: ("change_doc_ref", {}),
    BLOCK_WRITE_OUT: ("output_name", {"fmt": {WRITE_FMT_S19, WRITE_FMT_HEX}}),
    BLOCK_CHECK: (
        "check_doc_ref",
        {"gating": {CHECK_GATING_ADVISORY, CHECK_GATING_BLOCK_OWN}},
    ),
    BLOCK_CRC: ("config_ref", {}),
    BLOCK_REPORT: (None, {}),
}

#: READ-ref fields → containment-checked at load through the reused guard.
#: ``output_name`` is a WRITE target (V7 shape pre-check, authority stays
#: ``save_patched_image``); ``report`` has neither.
_READ_REF_FIELDS = {"image_ref", "change_doc_ref", "check_doc_ref", "config_ref"}

#: The complete set of codes the loader can emit as a REJECTION — the "input set
#: is an oracle" completeness vocabulary (C-31, AMD-6). The security-battery
#: census asserts every code here is exercised by ≥1 hostile case, so a new
#: reject arm shipped without a battery row goes RED. ``MANIFEST-BAD-STRUCTURE``
#: is intentionally ABSENT: V5 rejects a non-string/empty ref with
#: ``FLOW-BAD-FIELD`` before the guard is ever called, so the guard's
#: non-string arm is unreachable from this loader.
REJECTING_CODES: frozenset = frozenset(
    {
        FLOW_SIZE_CAP,
        FLOW_JSON_PARSE,
        FLOW_BAD_STRUCTURE,
        FLOW_SCHEMA_UNSUPPORTED,
        FLOW_UNKNOWN_KIND,
        FLOW_BAD_FIELD,
        FLOW_UNSAFE_OUTPUT_NAME,
        FLOW_UNSAFE_REF,
        MANIFEST_PATH_ESCAPE,
    }
)


def _finding(code: str, message: str) -> ValidationIssue:
    """Build one flow-load finding — artifact ``flow``, always ERROR (fail-closed)."""
    return ValidationIssue(
        code=code,
        severity=ValidationSeverity.ERROR,
        message=message,
        artifact="flow",
    )


def _is_drive_relative(ref: str) -> bool:
    """Report whether ``ref`` is a Windows drive-relative path (``C:foo``).

    Summary:
        A drive-relative path carries a drive letter but no root
        (``PureWindowsPath("C:foo").drive == "C:"`` and ``is_absolute()`` is
        ``False``). The reused containment guard only rejects *absolute* paths,
        so this shape slips through and — when joined against a project on a
        different drive — escapes the work area. This predicate flags it so the
        loader can reject it WITHOUT reimplementing (forking) the guard.

    Args:
        ref (str): The already-stripped, non-empty ref string.

    Returns:
        bool: ``True`` for a drive-relative path (drive present, not absolute);
        ``False`` for a plain relative ref, an absolute path (the guard's job),
        or a POSIX path.

    Data Flow:
        - Called from the V6 READ-ref arm of :func:`dict_to_flow` before
          ``_resolve_manifest_entry``.

    Dependencies:
        Uses:
            - pathlib.PureWindowsPath
        Used by:
            - dict_to_flow
    """
    win = PureWindowsPath(ref)
    return bool(win.drive) and not win.is_absolute()


def flow_to_dict(flow: Flow) -> dict:
    """Serialize a :class:`Flow` to the schema-v1 envelope dict.

    Summary:
        Emit ``{"schema_version", "name", "blocks": [{"kind", …}]}`` with each
        block's ``kind`` first and its field names verbatim from the frozen
        dataclasses. The original relative ref strings are stored VERBATIM
        (AMD-12/m-2 ref-retention) — no path resolution happens here. The
        report block serializes ref-less as ``{"kind": "report"}``.

    Args:
        flow (Flow): The in-memory flow (trusted-side — built by the operator).

    Returns:
        dict: The JSON-ready schema-v1 envelope.

    Raises:
        TypeError: When a block is an unknown model type — the serializer is
            trusted-side, so an unserializable block is a programming error, not
            a validation finding.

    Data Flow:
        - ``flow.blocks`` → per-kind field projection → ``blocks`` list.
        - The inverse of :func:`dict_to_flow`; a round-trip preserves every
          field of every shipped kind.

    Dependencies:
        Uses:
            - flow_model block dataclasses
        Used by:
            - save_flow_json (later increment), the round-trip AT

    Example:
        >>> flow_to_dict(Flow(name="n", blocks=[ReportBlock()]))
        {'schema_version': 1, 'name': 'n', 'blocks': [{'kind': 'report'}]}
    """
    blocks: List[dict] = []
    for block in flow.blocks:
        if isinstance(block, SourceBlock):
            blocks.append(
                {
                    "kind": block.kind,
                    "image_ref": block.image_ref,
                    "file_type": block.file_type,
                }
            )
        elif isinstance(block, PatchBlock):
            blocks.append({"kind": block.kind, "change_doc_ref": block.change_doc_ref})
        elif isinstance(block, WriteOutBlock):
            blocks.append(
                {"kind": block.kind, "output_name": block.output_name, "fmt": block.fmt}
            )
        elif isinstance(block, CheckBlock):
            blocks.append(
                {
                    "kind": block.kind,
                    "check_doc_ref": block.check_doc_ref,
                    "gating": block.gating,
                }
            )
        elif isinstance(block, CrcBlock):
            blocks.append({"kind": block.kind, "config_ref": block.config_ref})
        elif isinstance(block, ReportBlock):
            blocks.append({"kind": block.kind})
        else:  # trusted-side serializer — an unknown model object is a bug
            raise TypeError(f"unserializable block type: {type(block)!r}")
    return {
        "schema_version": flow.schema_version,
        "name": flow.name,
        "blocks": blocks,
    }


def dict_to_flow(
    payload: Any,
    project_dir: Path,
) -> Tuple[Optional[Flow], List[ValidationIssue]]:
    """Validate an UNTRUSTED envelope dict into a Flow — whole-flow fail-closed.

    Summary:
        Run the fixed validation order and collect findings; ANY finding rejects
        the WHOLE flow (never a partial pipeline). Reuses the manifest
        containment guard for every READ ref (never forks it) and pre-rejects
        the Windows drive-relative ref shape the guard misses.

        Validation order:
          V1  top level is a JSON object                         → FLOW-BAD-STRUCTURE
          V2  schema_version is EXACTLY int 1 (bool/str/absent rejected)
                                                                  → FLOW-SCHEMA-UNSUPPORTED
          V3  name (when present) is a non-empty str ≤ cap        → FLOW-BAD-FIELD
          V4  blocks is a list of FLOW_MIN..FLOW_MAX_BLOCKS       → FLOW-BAD-STRUCTURE
          V5  per block: object; known kind; strict keys; required
              ref (ref-bearing kinds); valid enums                → FLOW-UNKNOWN-KIND /
                                                                     FLOW-BAD-FIELD
          V6  per READ ref: drive-relative reject, then the reused
              containment guard (no fs open, existence NOT required)
                                                                  → FLOW-UNSAFE-REF /
                                                                     MANIFEST-PATH-ESCAPE
          V7  output_name: no separator / no ``..`` / not absolute /
              not hidden                                          → FLOW-UNSAFE-OUTPUT-NAME
        A ref-less kind (``report``, ``ref_field is None``) skips the required-ref
        check, V6 and V7, but STILL enforces strict-keys ``{"kind"}``.

    Args:
        payload (Any): The parsed, UNTRUSTED envelope (any JSON value).
        project_dir (Path): The ``.s19tool/workarea/<project>/`` directory refs
            resolve against (containment base).

    Returns:
        Tuple[Optional[Flow], List[ValidationIssue]]: ``(Flow, [])`` only when
        finding-free; otherwise ``(None, findings)``. Never raises; never opens
        an embedded path.

    Data Flow:
        - ``payload`` → V1..V7 → ``(Flow | None, findings)``.
        - Each READ ref → ``_resolve_manifest_entry`` (guard-appended findings).
        - The inverse of :func:`flow_to_dict` on a finding-free good envelope.

    Dependencies:
        Uses:
            - _resolve_manifest_entry (reused containment guard)
            - _is_drive_relative / _KIND_SPEC / _READ_REF_FIELDS
            - flow_model block dataclasses
        Used by:
            - load_flow_json
    """
    findings: List[ValidationIssue] = []

    # V1 — envelope shape.
    if not isinstance(payload, dict):
        findings.append(_finding(FLOW_BAD_STRUCTURE, "flow.json top level is not a JSON object"))
        return None, findings

    # V2 — schema-version gate (type-strict; a future/string/bool/absent value rejects).
    version = payload.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool) or version != FLOW_SCHEMA_VERSION:
        findings.append(
            _finding(
                FLOW_SCHEMA_UNSUPPORTED,
                f"flow schema_version {version!r} is not supported "
                f"(this build reads version {FLOW_SCHEMA_VERSION} only)",
            )
        )
        return None, findings

    # V3 — display name (identity is the FILENAME; this is cosmetic).
    name = payload.get("name", "flow")
    if not isinstance(name, str) or not name.strip():
        findings.append(_finding(FLOW_BAD_FIELD, "flow name is not a non-empty string"))
    elif len(name) > FLOW_MAX_NAME_LEN:
        findings.append(
            _finding(FLOW_BAD_FIELD, f"flow name exceeds {FLOW_MAX_NAME_LEN} characters")
        )

    # V4 — blocks array bounds.
    blocks_raw = payload.get("blocks")
    if not isinstance(blocks_raw, list):
        findings.append(_finding(FLOW_BAD_STRUCTURE, "flow blocks is not an array"))
        return None, findings
    if len(blocks_raw) < FLOW_MIN_BLOCKS:
        findings.append(_finding(FLOW_BAD_STRUCTURE, "flow has no blocks"))
    if len(blocks_raw) > FLOW_MAX_BLOCKS:
        findings.append(
            _finding(
                FLOW_BAD_STRUCTURE,
                f"flow has {len(blocks_raw)} blocks, over the {FLOW_MAX_BLOCKS}-block cap",
            )
        )
        return None, findings

    project_root = project_dir.resolve()
    blocks: List[FlowBlock] = []
    for index, entry in enumerate(blocks_raw):
        label = f"blocks[{index}]"
        # V5 — object + known kind + strict keys + required ref + enums.
        if not isinstance(entry, dict):
            findings.append(_finding(FLOW_BAD_STRUCTURE, f"{label} is not a JSON object"))
            continue
        kind = entry.get("kind")
        if kind not in _KIND_SPEC:
            findings.append(
                _finding(
                    FLOW_UNKNOWN_KIND,
                    f"{label} has unknown kind {kind!r} - known kinds: {sorted(_KIND_SPEC)}",
                )
            )
            continue
        ref_field, enum_fields = _KIND_SPEC[kind]
        allowed_keys = {"kind", *enum_fields}
        if ref_field is not None:
            allowed_keys.add(ref_field)
        unknown = set(entry) - allowed_keys
        if unknown:
            findings.append(
                _finding(
                    FLOW_BAD_FIELD,
                    f"{label} ({kind}) carries unknown field(s) {sorted(unknown)} - "
                    f"schema v{FLOW_SCHEMA_VERSION} is strict",
                )
            )
            continue

        ref: Optional[str] = None
        if ref_field is not None:
            ref = entry.get(ref_field)
            if not isinstance(ref, str) or not ref.strip():
                findings.append(
                    _finding(
                        FLOW_BAD_FIELD,
                        f"{label} ({kind}) is missing required field "
                        f"'{ref_field}' (non-empty string)",
                    )
                )
                continue

        enum_ok = True
        for field_name, allowed in enum_fields.items():
            value = entry.get(field_name)
            if value is not None and value not in allowed:
                findings.append(
                    _finding(
                        FLOW_BAD_FIELD,
                        f"{label} ({kind}) field '{field_name}' value {value!r} "
                        f"not in {sorted(allowed)}",
                    )
                )
                enum_ok = False
        if not enum_ok:
            continue

        # V6 — READ-ref containment. Drive-relative pre-reject (guard gap), then
        # the REUSED guard (no open; existence not required; MANIFEST-* verbatim).
        if ref_field in _READ_REF_FIELDS:
            if _is_drive_relative(ref):  # ref is a non-empty str here (V5)
                findings.append(
                    _finding(
                        FLOW_UNSAFE_REF,
                        f"{label} ({kind}) {ref_field} {ref!r} is a Windows "
                        "drive-relative path - refs resolve against the project "
                        "directory only",
                    )
                )
                continue
            resolved = _resolve_manifest_entry(project_root, ref, f"{label}.{ref_field}", findings)
            if resolved is None:
                continue  # the guard appended its finding — block rejected
        # V7 — WRITE-target shape pre-check (runtime authority stays save_patched_image).
        elif ref_field == "output_name":
            if (
                "/" in ref
                or "\\" in ref
                or ".." in ref
                or Path(ref).is_absolute()
                or ref.strip().startswith(".")
            ):
                findings.append(
                    _finding(
                        FLOW_UNSAFE_OUTPUT_NAME,
                        f"{label} output_name {ref!r} must be a plain filename "
                        "(no separators, no traversal, not hidden)",
                    )
                )
                continue

        # Construct the frozen block (defaults fill optional enums).
        if kind == BLOCK_SOURCE:
            blocks.append(SourceBlock(image_ref=ref, file_type=entry.get("file_type", WRITE_FMT_S19)))
        elif kind == BLOCK_PATCH:
            blocks.append(PatchBlock(change_doc_ref=ref))
        elif kind == BLOCK_WRITE_OUT:
            blocks.append(WriteOutBlock(output_name=ref, fmt=entry.get("fmt", WRITE_FMT_S19)))
        elif kind == BLOCK_CHECK:
            blocks.append(CheckBlock(check_doc_ref=ref, gating=entry.get("gating", CHECK_GATING_ADVISORY)))
        elif kind == BLOCK_CRC:
            blocks.append(CrcBlock(config_ref=ref))
        elif kind == BLOCK_REPORT:
            blocks.append(ReportBlock())

    # FAIL-CLOSED aggregate: an executable pipeline is never partially loaded.
    if findings:
        return None, findings
    return Flow(name=name, blocks=blocks, schema_version=FLOW_SCHEMA_VERSION), findings


def load_flow_json(
    flow_path: Path,
    project_dir: Path,
) -> Tuple[Optional[Flow], List[ValidationIssue]]:
    """File-level hardened load: size cap → parse guard → :func:`dict_to_flow`.

    Summary:
        Probe the file size BEFORE reading (a pre-parse DoS guard) and catch
        every read/parse error, then hand the parsed payload to
        :func:`dict_to_flow`. Never raises. Mirrors ``read_project_manifest``'s
        file gate (``variant_execution_service.py`` — size-probe then guarded
        ``json.load``).

    Args:
        flow_path (Path): The ``flows/<name>.json`` file to read (untrusted).
        project_dir (Path): The containment base passed through to
            :func:`dict_to_flow`.

    Returns:
        Tuple[Optional[Flow], List[ValidationIssue]]: ``(Flow, [])`` on a clean
        load; ``(None, findings)`` on an oversize/unreadable/malformed file or
        any envelope finding.

    Data Flow:
        - ``stat`` size → ``FLOW-SIZE-CAP`` when over ``FLOW_SIZE_CAP_BYTES``.
        - guarded ``json.load`` → ``FLOW-JSON-PARSE`` on any read/decode error.
        - payload → :func:`dict_to_flow`.

    Dependencies:
        Uses:
            - dict_to_flow / json
        Used by:
            - the app Load/Import handlers (later increment)
    """
    findings: List[ValidationIssue] = []
    try:
        size = flow_path.stat().st_size
    except OSError as exc:
        findings.append(_finding(FLOW_JSON_PARSE, f"flow file unreadable: {type(exc).__name__}"))
        return None, findings
    if size > FLOW_SIZE_CAP_BYTES:
        findings.append(
            _finding(
                FLOW_SIZE_CAP,
                f"flow file is {size} bytes, over the {FLOW_SIZE_CAP_BYTES}-byte cap - not loaded",
            )
        )
        return None, findings
    try:
        with flow_path.open("rb") as handle:
            payload = json.load(handle)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, OSError) as exc:
        findings.append(
            _finding(FLOW_JSON_PARSE, f"flow file is not well-formed JSON - {type(exc).__name__}")
        )
        return None, findings
    return dict_to_flow(payload, project_dir)
