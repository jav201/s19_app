"""Flow Builder — flow.json persistence service (batch-53 FB-P1, HLR-001/002).

Serialize a :class:`flow_model.Flow` to the schema-v1 JSON envelope and load an
**untrusted** ``flow.json`` back with a hardened, fail-closed, whole-flow
validator. Every embedded READ ref is re-validated through the SAME
``_resolve_manifest_entry`` containment guard the runtime already uses
(reuse-not-fork); any finding rejects the whole flow (never a partial pipeline).

batch-94 Inc-003 (US-007, HLR-021) adds the chain-set envelope at the bottom
of this module: ``save_chain_set`` / ``load_chain_set`` persist the US-007
save-set artifact — every chain's template reference, its bound inputs, and
its recorded outputs in ONE document inside the work area (``flowsets/``) —
with the flow loader's fail-closed vocabulary namespaced (CHAIN-SET-*) and
the same reused containment guard for every bound input ref.

Textual-free (service-layer contract C-7): imports stdlib + the flow model + the
manifest guard + the validation model only. UI wiring (modals, panel, handlers)
lands in a later increment; this module owns serialize/deserialize/load.

Finding taxonomy (OQ-1, §6.2 — mixed and honest):

- ``FLOW-*`` codes are the loader's OWN envelope/schema/block findings.
- ``MANIFEST-*`` codes travel VERBATIM with the reused guard — the reader sees
  exactly which component fired. The loader never rewrites them.
- ``FLOW-UNSAFE-REF`` is the loader-side path-shape reject that closes the gaps
  the reused guard does not cover: a Windows *drive-relative* ref (``C:foo`` —
  a drive letter with no root), and an A2B file-binding ref whose separators
  normalize to a traversal (``..`` component). ``PureWindowsPath("C:foo").is_absolute()`` is
  ``False``, so the guard's absolute-path arms miss it, yet joining it against a
  project on a different drive escapes the work area; a backslash traversal
  reads as one in-project literal on a POSIX host, so the guard's
  ``resolve()`` containment arm misses it. Both rejected loader-side
  WITHOUT forking the guard (AMD-11/F4). A NUL character in any path-bearing
  block field is the same kind of shape reject (batch-97 LLR-146.14): it is
  refused here with ``FLOW-UNSAFE-REF`` before the guard (whose ``resolve()``
  would raise) and before the output-name shape check; a chain-set template
  or input ref carrying one gets ``CHAIN-SET-UNSAFE-REF``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, List, Optional, Set, Tuple

from ...validation.model import ValidationIssue, ValidationSeverity
from .flow_model import (
    A2BBlock,
    A2BInputBinding,
    A2B_INPUT_FILE,
    A2B_INPUT_FLOW,
    BLOCK_A2B,
    BLOCK_CHECK,
    BLOCK_CRC,
    BLOCK_EXTERNAL_STEP,
    BLOCK_PATCH,
    BLOCK_REPORT,
    BLOCK_SOURCE,
    BLOCK_WRITE_OUT,
    CHECK_GATING_ADVISORY,
    CHECK_GATING_BLOCK_OWN,
    EXTERNAL_MODES,
    FUNNEL_MAX_ENTRIES,
    FUNNEL_NAME_MAX_LEN,
    FUNNEL_NAME_RE,
    FUNNEL_VALUE_MAX_LEN,
    WRITE_FMT_HEX,
    WRITE_FMT_S19,
    CheckBlock,
    CrcBlock,
    ExternalStepBlock,
    Flow,
    FlowBlock,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
    parse_a2b_binding,
    validate_a2b_bindings,
)
from .variant_execution_service import (
    MANIFEST_PATH_ESCAPE,
    _resolve_manifest_entry,
)
from ..workspace import copy_into_workarea, sanitize_project_name

#: The one supported envelope version (``Flow.schema_version`` defaults to 1).
FLOW_SCHEMA_VERSION = 1

#: Byte cap for a flow.json read (probed BEFORE parse — a pre-parse DoS guard).
#: Deliberately tight: a flow is a small pipeline description, not a payload.
FLOW_SIZE_CAP_BYTES = 1_048_576  # 1 MiB

#: Named-flow storage subdirectory under the active project work area
#: (``.s19tool/workarea/<project>/flows/``). A subdirectory, so
#: ``validate_project_files`` (which skips subdirs) is unaffected — no
#: ``workspace.py`` edit is needed.
FLOWS_SUBDIR = "flows"

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
#: Loader-side path-shape reject for a Windows drive-relative READ ref or an
#: A2B file-binding traversal ref after separator normalization (the gaps
#: the reused guard's ``is_absolute()`` / POSIX ``resolve()`` arms miss —
#: AMD-11/F4 and the PR #211 CI fix).
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
    # batch-94 Inc-002 (LLR-013.2): A2B carries NO single ref — its two input
    # bindings get the dedicated V5 arm below (strict keys {kind, image_a,
    # image_b}, per-binding grammar + containment).
    BLOCK_A2B: (None, {}),
    # prototype v3 (spec "paso externo"): external_step carries NO project
    # ref — its output path is an EXTERNAL absolute path by design. The
    # dedicated V5 arm below validates strict keys {kind, mode, instruction,
    # log_ref, output_path} with its own shape checks (the output path is
    # containment-external, so the reused guard does NOT apply to it).
    BLOCK_EXTERNAL_STEP: (None, {"mode": set(EXTERNAL_MODES)}),
}

#: READ-ref fields → containment-checked at load through the reused guard.
#: ``output_name`` is a WRITE target (V7 shape pre-check, authority stays
#: ``save_patched_image``); ``report`` has neither.
_READ_REF_FIELDS = {"image_ref", "change_doc_ref", "check_doc_ref", "config_ref"}

#: Change-5 (batch-95 LLR-142.1): block kinds that may carry the OPTIONAL
#: ``a2l_ref`` — an A2L reference in the same project-relative ref grammar,
#: containment-checked at load through the SAME reused guard (V6) when
#: present; absent is the default and round-trips as ``None``.
_A2L_REF_KINDS = frozenset({BLOCK_SOURCE, BLOCK_PATCH})

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
            source: Dict[str, Any] = {
                "kind": block.kind,
                "image_ref": block.image_ref,
                "file_type": block.file_type,
            }
            if block.a2l_ref is not None:
                source["a2l_ref"] = block.a2l_ref
            blocks.append(source)
        elif isinstance(block, PatchBlock):
            patch: Dict[str, Any] = {
                "kind": block.kind,
                "change_doc_ref": block.change_doc_ref,
            }
            if block.a2l_ref is not None:
                patch["a2l_ref"] = block.a2l_ref
            blocks.append(patch)
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
        elif isinstance(block, A2BBlock):
            blocks.append(
                {
                    "kind": block.kind,
                    "image_a": {
                        "source": block.image_a.source,
                        "ref": block.image_a.ref,
                    },
                    "image_b": {
                        "source": block.image_b.source,
                        "ref": block.image_b.ref,
                    },
                }
            )
        elif isinstance(block, ExternalStepBlock):
            blocks.append(
                {
                    "kind": block.kind,
                    "mode": block.mode,
                    "instruction": block.instruction,
                    "log_ref": block.log_ref,
                    "output_path": block.output_path,
                }
            )
        else:  # trusted-side serializer — an unknown model object is a bug
            raise TypeError(f"unserializable block type: {type(block)!r}")
    envelope = {
        "schema_version": flow.schema_version,
        "name": flow.name,
        "blocks": blocks,
    }
    # batch-96 B1 (the funnel): the flow-level variable table rides the wire
    # as [[name, value], …] pairs (the chain-set inputs idiom — a JSON object
    # would coerce and a table is a map, not a payload). Absent when empty,
    # so pre-B1 envelopes and new ones inter-read (the grammar is additive).
    if flow.funnel:
        envelope["funnel"] = [[name, value] for name, value in flow.funnel]
    return envelope


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
          V4b funnel (OPTIONAL, batch-96 B1): a list of ≤32 unique
              [NAME, value] pairs, NAME = [A-Z0-9_]                → FLOW-BAD-FIELD
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

    # V4b — funnel (batch-96 B1, ADDITIVE grammar): the optional flow-level
    # variable table. ABSENT → () (today's behavior, pre-B1 envelopes load
    # untouched). PRESENT → a list of at most FUNNEL_MAX_ENTRIES
    # [name, value] pairs: name is a non-empty str of at most
    # FUNNEL_NAME_MAX_LEN chars matching the EXACT placeholder charset
    # [A-Z0-9_], value a non-empty str of at most FUNNEL_VALUE_MAX_LEN —
    # and names must be UNIQUE (a table is a map). ANY malformed pair,
    # duplicate or over-cap entry → FLOW-BAD-FIELD.
    funnel: List[Tuple[str, str]] = []
    funnel_raw = payload.get("funnel")
    if funnel_raw is not None:
        funnel_ok = isinstance(funnel_raw, list) and len(
            funnel_raw
        ) <= FUNNEL_MAX_ENTRIES
        seen: Set[str] = set()
        if funnel_ok:
            for pair in funnel_raw:
                if (
                    not isinstance(pair, list)
                    or len(pair) != 2
                    or not isinstance(pair[0], str)
                    or not FUNNEL_NAME_RE.match(pair[0].strip())
                    or len(pair[0].strip()) > FUNNEL_NAME_MAX_LEN
                    or not isinstance(pair[1], str)
                    or not pair[1].strip()
                    or len(pair[1]) > FUNNEL_VALUE_MAX_LEN
                ):
                    funnel_ok = False
                    break
                name = pair[0].strip()
                if name in seen:
                    funnel_ok = False
                    break
                seen.add(name)
                funnel.append((name, pair[1]))
        if not funnel_ok:
            findings.append(
                _finding(
                    FLOW_BAD_FIELD,
                    "flow funnel is not a list of unique "
                    f"[NAME, value] pairs (NAME = [A-Z0-9_], ≤ "
                    f"{FUNNEL_NAME_MAX_LEN} chars, non-empty value ≤ "
                    f"{FUNNEL_VALUE_MAX_LEN} chars, at most "
                    f"{FUNNEL_MAX_ENTRIES} entries)",
                )
            )

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
        # V5 (A2B arm, batch-94 Inc-002 / LLR-013.2) — the A2B kind carries no
        # single ref: its two input bindings get the dedicated parser below
        # (strict keys, per-binding grammar, file-ref containment through the
        # SAME reused guard, and the wiring matrix via the model helper).
        if kind == BLOCK_A2B:
            block_a2b = _parse_a2b_entry(
                entry, label, project_root, blocks, findings
            )
            if block_a2b is not None:
                blocks.append(block_a2b)
            continue
        # V5 (external-step arm, prototype v3) — the kind carries no project
        # ref: its output path is external by design, so it gets the
        # dedicated parser below (strict keys, per-field shape checks).
        if kind == BLOCK_EXTERNAL_STEP:
            block_ext = _parse_external_step_entry(entry, label, findings)
            if block_ext is not None:
                blocks.append(block_ext)
            continue
        ref_field, enum_fields = _KIND_SPEC[kind]
        allowed_keys = {"kind", *enum_fields}
        if ref_field is not None:
            allowed_keys.add(ref_field)
        if kind in _A2L_REF_KINDS:
            allowed_keys.add("a2l_ref")
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
            if "\x00" in ref:
                findings.append(
                    _finding(
                        FLOW_UNSAFE_REF,
                        f"{label} ({kind}) {ref_field} {ref!r} carries a NUL "
                        "character - not a path",
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
        # V6b — change-5 (LLR-142.1): the OPTIONAL a2l_ref rides the SAME
        # grammar and guard as every other READ ref (present-only; absent
        # round-trips as None).
        a2l_ref: Optional[str] = None
        if kind in _A2L_REF_KINDS and entry.get("a2l_ref") is not None:
            a2l_ref = entry.get("a2l_ref")
            if not isinstance(a2l_ref, str) or not a2l_ref.strip():
                findings.append(
                    _finding(
                        FLOW_BAD_FIELD,
                        f"{label} ({kind}) field 'a2l_ref' is not a non-empty "
                        "string",
                    )
                )
                continue
            if "\x00" in a2l_ref:
                findings.append(
                    _finding(
                        FLOW_UNSAFE_REF,
                        f"{label} ({kind}) a2l_ref {a2l_ref!r} carries a NUL "
                        "character - not a path",
                    )
                )
                continue
            if _is_drive_relative(a2l_ref):
                findings.append(
                    _finding(
                        FLOW_UNSAFE_REF,
                        f"{label} ({kind}) a2l_ref {a2l_ref!r} is a Windows "
                        "drive-relative path - refs resolve against the project "
                        "directory only",
                    )
                )
                continue
            resolved_a2l = _resolve_manifest_entry(
                project_root, a2l_ref, f"{label}.a2l_ref", findings
            )
            if resolved_a2l is None:
                continue  # the guard appended its finding — block rejected
        # V7 — WRITE-target shape pre-check (runtime authority stays save_patched_image).
        # The drive-relative arm mirrors V6: ``C:foo`` has a drive but is not
        # absolute, so ``is_absolute()`` alone would let it through — reject it
        # here too so the WRITE pre-check is symmetric with the READ one (F1).
        elif ref_field == "output_name":
            if (
                "/" in ref
                or "\\" in ref
                or ".." in ref
                or Path(ref).is_absolute()
                or _is_drive_relative(ref)
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
            blocks.append(SourceBlock(image_ref=ref, file_type=entry.get("file_type", WRITE_FMT_S19), a2l_ref=a2l_ref))
        elif kind == BLOCK_PATCH:
            blocks.append(PatchBlock(change_doc_ref=ref, a2l_ref=a2l_ref))
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
    return Flow(
        name=name,
        blocks=blocks,
        schema_version=FLOW_SCHEMA_VERSION,
        funnel=tuple(funnel),
    ), findings


def _parse_a2b_entry(
    entry: Dict[str, Any],
    label: str,
    project_root: Path,
    upstream_blocks: List[FlowBlock],
    findings: List[ValidationIssue],
) -> Optional[A2BBlock]:
    """V5 arm for the A2B kind — validate the two input bindings, fail closed.

    Summary:
        Strict keys ``{kind, image_a, image_b}`` (schema v1 is strict); each
        binding is an object of exactly ``{source, ref}`` with a known source
        discriminator; a ``file`` binding's separators normalize to ``/``
        BEFORE the SAME drive-relative pre-reject + reused containment guard
        as every other READ ref, with a traversal (``..`` component) pre-reject
        beside the drive-relative one (the refusal is platform-independent —
        the wire grammar is Windows-shaped but must refuse on any host); a
        ``flow`` binding keeps its decimal index grammar (range/kind checks
        ride the model's wiring matrix). ANY problem appends one finding and
        returns ``None`` — the whole-flow fail-closed aggregate still applies.
        The wiring matrix (:func:`flow_model.validate_a2b_bindings`) re-runs
        over the parsed block here, so a template smuggling a both-external
        pair or a downstream/self reference is refused AT LOAD, never mounted
        (LLR-013.2 invalid arm / LLR-014.1).

    Args:
        entry (Dict[str, Any]): The untrusted ``blocks[i]`` object.
        label (str): The ``blocks[i]`` finding prefix.
        project_root (Path): The containment base (resolved project dir).
        upstream_blocks (List[FlowBlock]): The blocks already parsed BEFORE
            this one — the only legal flow-binding targets.
        findings (List[ValidationIssue]): Finding collector, appended in place.

    Returns:
        Optional[A2BBlock]: The validated block, or ``None`` on any finding.
    """
    unknown = set(entry) - {"kind", "image_a", "image_b"}
    if unknown:
        findings.append(
            _finding(
                FLOW_BAD_FIELD,
                f"{label} (a2b) carries unknown field(s) {sorted(unknown)} - "
                f"schema v{FLOW_SCHEMA_VERSION} is strict",
            )
        )
        return None
    bindings: Dict[str, A2BInputBinding] = {}
    for field in ("image_a", "image_b"):
        raw = entry.get(field)
        if not isinstance(raw, dict) or set(raw) != {"source", "ref"}:
            findings.append(
                _finding(
                    FLOW_BAD_FIELD,
                    f"{label} (a2b) {field} must be an object of exactly "
                    "{'source', 'ref'}",
                )
            )
            return None
        source = raw.get("source")
        ref = raw.get("ref")
        if source not in (A2B_INPUT_FLOW, A2B_INPUT_FILE):
            findings.append(
                _finding(
                    FLOW_BAD_FIELD,
                    f"{label} (a2b) {field} source {source!r} is not one of "
                    f"{sorted((A2B_INPUT_FLOW, A2B_INPUT_FILE))}",
                )
            )
            return None
        if not isinstance(ref, str) or not ref.strip():
            findings.append(
                _finding(
                    FLOW_BAD_FIELD,
                    f"{label} (a2b) {field} ref is not a non-empty string",
                )
            )
            return None
        ref = ref.strip()
        if "\x00" in ref:
            findings.append(
                _finding(
                    FLOW_UNSAFE_REF,
                    f"{label} (a2b) {field}.ref {ref!r} carries a NUL "
                    "character - not a path",
                )
            )
            return None
        if source == A2B_INPUT_FILE:
            # The binding ref is WIRE text and the operator file grammar is
            # Windows-shaped, so normalize its separators to '/' BEFORE the
            # shape pre-rejects and the reused containment guard. On a POSIX
            # host a backslash is an ordinary filename character: without this
            # the guard's resolve() reads '..\..\evil.s19' as ONE in-project
            # literal and the traversal loads — the refusal must hold on any
            # host (batch-94 CI fix, PR #211). The loaded binding carries the
            # normalized (canonical wire) form.
            wire_ref = ref
            ref = ref.replace("\\", "/")
            if _is_drive_relative(ref) or ".." in PurePosixPath(ref).parts:
                findings.append(
                    _finding(
                        FLOW_UNSAFE_REF,
                        f"{label} (a2b) {field}.ref {wire_ref!r} is not a "
                        "plain project-relative ref (a drive-relative or "
                        "traversal path) - refs resolve against the project "
                        "directory only",
                    )
                )
                return None
            resolved = _resolve_manifest_entry(
                project_root, ref, f"{label}.{field}.ref", findings
            )
            if resolved is None:
                return None  # the guard appended its finding — binding rejected
        bindings[field] = A2BInputBinding(source=source, ref=ref)
    block = A2BBlock(image_a=bindings["image_a"], image_b=bindings["image_b"])
    reasons = validate_a2b_bindings(block, upstream_blocks)
    if reasons:
        findings.append(
            _finding(
                FLOW_BAD_FIELD,
                f"{label} (a2b) refused: " + "; ".join(reasons),
            )
        )
        return None
    return block


def _parse_external_step_entry(
    entry: Dict[str, Any],
    label: str,
    findings: List[ValidationIssue],
) -> Optional[ExternalStepBlock]:
    """V5 arm for the external_step kind — validate the human-gated step.

    Summary:
        Strict keys ``{kind, mode, instruction, log_ref, output_path}``
        (schema v1 is strict). ``mode`` rides the generic enum check;
        ``instruction`` and ``log_ref`` must be non-empty strings (the LOG
        is MANDATORY — an empty one refuses the block); ``output_path``
        must be non-empty — an ABSOLUTE path is preferred, a relative one
        must be a plain name (no traversal / drive-relative shape, the V7
        idiom) because it would resolve against the operator's CWD at
        confirm time. The path is EXTERNAL by design, so the reused
        containment guard does NOT apply (there is nothing to contain —
        the confirm step copies the file INTO the session artifact folder).
        ANY problem appends one finding and returns ``None``.
    """
    unknown = set(entry) - {"kind", "mode", "instruction", "log_ref", "output_path"}
    if unknown:
        findings.append(
            _finding(
                FLOW_BAD_FIELD,
                f"{label} (external_step) carries unknown field(s) {sorted(unknown)} - "
                f"schema v{FLOW_SCHEMA_VERSION} is strict",
            )
        )
        return None
    mode = entry.get("mode", "terminal")
    if mode not in EXTERNAL_MODES:
        findings.append(
            _finding(
                FLOW_BAD_FIELD,
                f"{label} (external_step) mode {mode!r} is not one of "
                f"{sorted(EXTERNAL_MODES)}",
            )
        )
        return None
    instruction = entry.get("instruction")
    if not isinstance(instruction, str) or not instruction.strip():
        findings.append(
            _finding(
                FLOW_BAD_FIELD,
                f"{label} (external_step) needs a non-empty 'instruction' "
                "(the exact command for mode=terminal, the shown instruction "
                "for mode=manual)",
            )
        )
        return None
    log_ref = entry.get("log_ref")
    if not isinstance(log_ref, str) or not log_ref.strip():
        findings.append(
            _finding(
                FLOW_BAD_FIELD,
                f"{label} (external_step) needs a non-empty 'log_ref' - the "
                "log is MANDATORY evidence, never optional",
            )
        )
        return None
    if "\x00" in log_ref:
        findings.append(
            _finding(
                FLOW_UNSAFE_REF,
                f"{label} (external_step) log_ref {log_ref!r} carries a NUL "
                "character - not a path",
            )
        )
        return None
    output_path = entry.get("output_path")
    if not isinstance(output_path, str) or not output_path.strip():
        findings.append(
            _finding(
                FLOW_BAD_FIELD,
                f"{label} (external_step) needs a non-empty 'output_path' - "
                "the expected output file",
            )
        )
        return None
    output_path = output_path.strip()
    if "\x00" in output_path:
        findings.append(
            _finding(
                FLOW_UNSAFE_REF,
                f"{label} (external_step) output_path {output_path!r} carries "
                "a NUL character - not a path",
            )
        )
        return None
    if not Path(output_path).is_absolute():
        # Relative output paths are accepted but must be plain names — the
        # same WRITE-target shape pre-check as V7 (no traversal, not
        # drive-relative, not hidden).
        if (
            "/" in output_path
            or "\\" in output_path
            or ".." in output_path
            or _is_drive_relative(output_path)
            or output_path.strip().startswith(".")
        ):
            findings.append(
                _finding(
                    FLOW_UNSAFE_OUTPUT_NAME,
                    f"{label} (external_step) output_path {output_path!r} "
                    "must be absolute, or a plain relative filename "
                    "(no separators, no traversal)",
                )
            )
            return None
    return ExternalStepBlock(
        mode=mode,
        instruction=instruction.strip(),
        log_ref=log_ref.strip(),
        output_path=output_path,
    )


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
    except (OSError, ValueError) as exc:
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


def save_flow_json(flow: Flow, raw_name: str, project_dir: Path) -> Optional[Path]:
    """Serialize ``flow`` and write it to ``flows/<sanitized>.json`` (LLR-001.2).

    Summary:
        Compute the write-side filename through the SAME ``sanitize_project_name``
        the project-save path uses (write-side containment — the sanitiser, not
        the embedded display name, is the identity). When the raw name sanitises
        to ``None`` (empty / punctuation-only) NOTHING is written and ``None`` is
        returned. Otherwise the ``flows/`` subdirectory is created and the
        schema-v1 envelope is written pretty-printed UTF-8.

    Args:
        flow (Flow): The in-memory flow to persist (trusted-side).
        raw_name (str): The operator-typed flow name (untrusted text → sanitised
            to a filesystem-safe stem).
        project_dir (Path): The active ``.s19tool/workarea/<project>/`` directory.

    Returns:
        Optional[Path]: The absolute path written (``flows/<clean>.json``), or
        ``None`` when ``raw_name`` sanitises to ``None`` (no file created).

    Data Flow:
        - ``raw_name`` → ``sanitize_project_name`` → ``clean`` (or ``None`` stop).
        - ``flow`` → :func:`flow_to_dict` → ``json.dumps(..., indent=2)`` → file.
        - The write-side inverse of :func:`load_flow_json`; a saved file round-trips.

        batch-94 Inc-002 (LLR-015.1): a name collision dedup-suffixes
        (``<clean>_2.json``, ``_3``, … — the house ``_<N>`` idiom) instead of
        clobbering the existing template; the returned path names the file
        actually written.

    Dependencies:
        Uses:
            - sanitize_project_name (write-side containment, workspace.py)
            - flow_to_dict / json
        Used by:
            - the app Save handler (later increment)

    Example:
        >>> save_flow_json(Flow(name="n", blocks=[ReportBlock()]),
        ...                "Nightly Release!  ", project_dir).name
        'NightlyRelease.json'
    """
    clean = sanitize_project_name(raw_name)
    if clean is None:
        return None
    flows_dir = project_dir / FLOWS_SUBDIR
    flows_dir.mkdir(parents=True, exist_ok=True)
    target = flows_dir / f"{clean}.json"
    if target.exists():
        # Collision dedup-suffix (LLR-015.1) — a second same-name save must
        # never overwrite the first template.
        counter = 2
        while (flows_dir / f"{clean}_{counter}.json").exists():
            counter += 1
        target = flows_dir / f"{clean}_{counter}.json"
    target.write_text(json.dumps(flow_to_dict(flow), indent=2), encoding="utf-8")
    return target


def list_saved_flows(project_dir: Path) -> List[str]:
    """List the saved flow stems under ``flows/`` (LLR-003.3).

    Summary:
        Return the sorted stems of every ``flows/*.json`` file in the project
        (the names the Load modal lists). A missing ``flows/`` directory yields an
        empty list — a project with no saved flows is not an error.

    Args:
        project_dir (Path): The active ``.s19tool/workarea/<project>/`` directory.

    Returns:
        List[str]: Sorted ``*.json`` stems (e.g. ``["nightly", "release"]``);
        empty when the ``flows/`` directory is absent or holds no ``.json`` file.

    Data Flow:
        - ``project_dir/flows`` → ``glob("*.json")`` → sorted stems.
        - Feeds the ``LoadFlowScreen`` ListView (later increment).

    Dependencies:
        Uses:
            - pathlib.Path.glob
        Used by:
            - the app Load handler / LoadFlowScreen (later increment)
    """
    flows_dir = project_dir / FLOWS_SUBDIR
    if not flows_dir.is_dir():
        return []
    return sorted(entry.stem for entry in flows_dir.glob("*.json") if entry.is_file())


def import_flow_file(picked: Path, project_dir: Path) -> Path:
    """Copy an external ``flow.json`` into ``flows/`` (never loaded in place).

    Summary:
        Copy the operator-picked external file into the project's ``flows/``
        subdirectory through the SAME ``copy_into_workarea`` containment guard the
        project-save path uses (reparse-point / workarea-containment / size cap),
        binding the size cap to :data:`FLOW_SIZE_CAP_BYTES` (AMD-4/F1) so an
        oversize import is refused AT THE COPY STEP — the 1 MiB flow DoS cap is
        not defeated by the guard's 256 MB default. The caller then loads the
        RETURNED copy (C-12 output-then-consume), never the external source.

    Args:
        picked (Path): The external file the operator selected (untrusted).
        project_dir (Path): The active ``.s19tool/workarea/<project>/`` directory;
            the copy lands in its ``flows/`` subdirectory.

    Returns:
        Path: The absolute path of the copy inside ``flows/`` (name collisions
        deduplicated with an ``_<N>`` suffix by ``copy_into_workarea``).

    Raises:
        WorkareaContainmentError: When the destination is not workarea-contained,
            the source/destination traverses a reparse point, or the source
            exceeds :data:`FLOW_SIZE_CAP_BYTES`. Surfaced by the app handler as an
            error card, never a crash (LLR-003.4).
        FileNotFoundError: When ``picked`` does not exist.

    Data Flow:
        - ``picked`` → ``copy_into_workarea(..., max_size_bytes=FLOW_SIZE_CAP_BYTES)``
          → a file under ``project_dir/flows/`` → the app then ``load_flow_json``\\ s
          THAT path (the handler-produced artifact, not the external source).

    Dependencies:
        Uses:
            - copy_into_workarea (containment + size cap, workspace.py)
        Used by:
            - the app Import handler (later increment)
    """
    return copy_into_workarea(
        picked, project_dir / FLOWS_SUBDIR, max_size_bytes=FLOW_SIZE_CAP_BYTES
    )


# ---------------------------------------------------------------------------
# batch-94 Inc-003 — the chain-set envelope (US-007 save/load, HLR-021;
# LLR-021.1/.2). The US-007 artifact: every chain's template reference, its
# bound inputs, and its recorded outputs in ONE document inside the work
# area. The fail-closed read path reuses the flow loader's vocabulary
# (size cap → parse guard → validated envelope), the SAME containment guard
# for every bound input ref, and the SAME write-side sanitiser authority.
# ---------------------------------------------------------------------------

#: Chain-set storage subdirectory under the active project work area
#: (``.s19tool/workarea/<project>/flowsets/`` — the FLOWS_SUBDIR idiom: a
#: subdirectory, so ``validate_project_files`` is unaffected).
FLOWSETS_SUBDIR = "flowsets"

#: The one supported chain-set envelope version.
CHAIN_SET_SCHEMA_VERSION = 1

#: The envelope discriminator (the flow envelope has no ``kind`` — a set file
#: is never read as a flow template and vice versa).
CHAIN_SET_KIND = "chain-set"

#: Structural sanity caps (fail closed outside them).
CHAIN_SET_MIN_CHAINS = 1
CHAIN_SET_MAX_CHAINS = 32
CHAIN_SET_MAX_NAME_LEN = 64
CHAIN_SET_MAX_INPUTS = 64
CHAIN_SET_MAX_OUTPUTS = 64

#: Loader-OWN finding codes (the flow loader's taxonomy, namespaced).
CHAIN_SET_SIZE_CAP = "CHAIN-SET-SIZE-CAP"
CHAIN_SET_JSON_PARSE = "CHAIN-SET-JSON-PARSE"
CHAIN_SET_BAD_STRUCTURE = "CHAIN-SET-BAD-STRUCTURE"
CHAIN_SET_SCHEMA_UNSUPPORTED = "CHAIN-SET-SCHEMA-UNSUPPORTED"
CHAIN_SET_BAD_FIELD = "CHAIN-SET-BAD-FIELD"
#: Loader-side path-shape reject for a Windows drive-relative ref / a template
#: stem that is not a plain file name (the V6/V7 read arms, namespaced).
CHAIN_SET_UNSAFE_REF = "CHAIN-SET-UNSAFE-REF"


@dataclass(frozen=True)
class ChainSetEntry:
    """One saved chain: template ref + bound inputs + recorded outputs.

    Args:
        chain (str): The lane name (unique inside the set).
        template (str): The ``flows/<stem>.json`` template reference
            (LLR-021.1's one-template-ref-per-chain).
        inputs (Tuple[Tuple[int, str], ...]): The bound input records —
            ``(SOURCE block index, project-relative ref)``, one per bound
            input (LLR-021.1's ≥1-input-per-chain). Unbound SOURCE blocks are
            not recorded: a reload restores them from the template itself.
        outputs (Tuple[str, ...]): The chain's recorded last outputs (file
            names written by the last run — regenerated on the re-run).
    """

    chain: str
    template: str
    inputs: Tuple[Tuple[int, str], ...] = ()
    outputs: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ChainSet:
    """The whole saved set — chains + inputs + outputs under one name.

    Args:
        name (str): The set's display name (identity is the FILENAME on save,
            the ``save_flow_json`` write-side idiom).
        chains (Tuple[ChainSetEntry, ...]): One per lane, in lane order.
    """

    name: str
    chains: Tuple[ChainSetEntry, ...] = ()


def _chain_set_finding(code: str, message: str) -> ValidationIssue:
    """Build one chain-set-load finding — artifact ``chain-set``, always ERROR."""
    return ValidationIssue(
        code=code,
        severity=ValidationSeverity.ERROR,
        message=message,
        artifact="chain-set",
    )


def _is_plain_template_stem(ref: str) -> bool:
    """Report whether ``ref`` is a plain file stem (a ``flows/`` identity).

    A template ref names a file inside ``flows/`` — the same WRITE-target
    shape pre-check as the flow loader's V7 (no separators, no traversal, not
    absolute, not drive-relative, not hidden, no NUL) so a set can never point its
    chains at a template outside the work area.
    """
    return not (
        "\x00" in ref
        or "/" in ref
        or "\\" in ref
        or ".." in ref
        or Path(ref).is_absolute()
        or _is_drive_relative(ref)
        or ref.strip().startswith(".")
    )


def chain_set_to_dict(chain_set: ChainSet) -> dict:
    """Serialize a :class:`ChainSet` to the envelope dict (trusted side).

    The inputs ride as ``[[index, ref], …]`` pairs (JSON object keys would
    coerce the int index to a string — the pair form round-trips honestly).
    """
    return {
        "schema_version": CHAIN_SET_SCHEMA_VERSION,
        "kind": CHAIN_SET_KIND,
        "name": chain_set.name,
        "chains": [
            {
                "chain": entry.chain,
                "template": entry.template,
                "inputs": [[index, ref] for index, ref in entry.inputs],
                "outputs": list(entry.outputs),
            }
            for entry in chain_set.chains
        ],
    }


def dict_to_chain_set(
    payload: Any,
    project_dir: Path,
) -> Tuple[Optional[ChainSet], List[ValidationIssue]]:
    """Validate an UNTRUSTED chain-set envelope — fail-closed, never partial.

    Summary:
        The flow loader's fixed-order vocabulary, namespaced:
          V1  top level is a JSON object                  → CHAIN-SET-BAD-STRUCTURE
          V2  schema_version is EXACTLY int 1 and
              kind is EXACTLY ``chain-set``                 → CHAIN-SET-SCHEMA-UNSUPPORTED
          V3  name is a non-empty str ≤ cap                 → CHAIN-SET-BAD-FIELD
          V4  chains is a list of CHAIN_SET_MIN..MAX        → CHAIN-SET-BAD-STRUCTURE
          V5  per chain: chain/template names, inputs
              (index/ref pairs), outputs (names)            → CHAIN-SET-BAD-FIELD
          V6  template stem shape + every bound input ref:
              drive-relative pre-reject, then the REUSED
              containment guard (no fs open; existence is
              NOT required — a moved input is the LLR-021.2
              notice arm, not a load refusal)               → CHAIN-SET-UNSAFE-REF /
                                                              MANIFEST-PATH-ESCAPE
        ANY finding rejects the WHOLE set (never a partial restore).

    Args:
        payload (Any): The parsed, UNTRUSTED envelope (any JSON value).
        project_dir (Path): The containment base for the bound input refs.

    Returns:
        Tuple[Optional[ChainSet], List[ValidationIssue]]: ``(ChainSet, [])``
        only when finding-free; otherwise ``(None, findings)``. Never raises;
        never opens an embedded path.
    """
    findings: List[ValidationIssue] = []

    if not isinstance(payload, dict):
        findings.append(
            _chain_set_finding(
                CHAIN_SET_BAD_STRUCTURE,
                "chain-set top level is not a JSON object",
            )
        )
        return None, findings

    version = payload.get("schema_version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != CHAIN_SET_SCHEMA_VERSION
        or payload.get("kind") != CHAIN_SET_KIND
    ):
        findings.append(
            _chain_set_finding(
                CHAIN_SET_SCHEMA_UNSUPPORTED,
                f"chain-set schema_version {version!r}/kind "
                f"{payload.get('kind')!r} is not supported (this build reads "
                f"version {CHAIN_SET_SCHEMA_VERSION} '{CHAIN_SET_KIND}' only)",
            )
        )
        return None, findings

    name = payload.get("name")
    if not isinstance(name, str) or not name.strip():
        findings.append(
            _chain_set_finding(CHAIN_SET_BAD_FIELD, "chain-set name is not a non-empty string")
        )
    elif len(name) > CHAIN_SET_MAX_NAME_LEN:
        findings.append(
            _chain_set_finding(
                CHAIN_SET_BAD_FIELD,
                f"chain-set name exceeds {CHAIN_SET_MAX_NAME_LEN} characters",
            )
        )

    chains_raw = payload.get("chains")
    if not isinstance(chains_raw, list):
        findings.append(
            _chain_set_finding(CHAIN_SET_BAD_STRUCTURE, "chain-set chains is not an array")
        )
        return None, findings
    if len(chains_raw) < CHAIN_SET_MIN_CHAINS:
        findings.append(
            _chain_set_finding(CHAIN_SET_BAD_STRUCTURE, "chain-set has no chains")
        )
    if len(chains_raw) > CHAIN_SET_MAX_CHAINS:
        findings.append(
            _chain_set_finding(
                CHAIN_SET_BAD_STRUCTURE,
                f"chain-set has {len(chains_raw)} chains, over the "
                f"{CHAIN_SET_MAX_CHAINS}-chain cap",
            )
        )
        return None, findings

    project_root = project_dir.resolve()
    chains: List[ChainSetEntry] = []
    for index, entry in enumerate(chains_raw):
        label = f"chains[{index}]"
        if not isinstance(entry, dict):
            findings.append(
                _chain_set_finding(
                    CHAIN_SET_BAD_STRUCTURE, f"{label} is not a JSON object"
                )
            )
            continue
        if set(entry) != {"chain", "template", "inputs", "outputs"}:
            findings.append(
                _chain_set_finding(
                    CHAIN_SET_BAD_FIELD,
                    f"{label} carries unknown or missing field(s) "
                    f"{sorted(set(entry) ^ {'chain', 'template', 'inputs', 'outputs'})} "
                    f"- the {CHAIN_SET_KIND} schema is strict",
                )
            )
            continue
        chain_name = entry["chain"]
        if not isinstance(chain_name, str) or not chain_name.strip():
            findings.append(
                _chain_set_finding(
                    CHAIN_SET_BAD_FIELD, f"{label}.chain is not a non-empty string"
                )
            )
            continue
        template = entry["template"]
        if not isinstance(template, str) or not template.strip():
            findings.append(
                _chain_set_finding(
                    CHAIN_SET_BAD_FIELD, f"{label}.template is not a non-empty string"
                )
            )
            continue
        template = template.strip()
        if not _is_plain_template_stem(template):
            findings.append(
                _chain_set_finding(
                    CHAIN_SET_UNSAFE_REF,
                    f"{label}.template {template!r} must be a plain flows/ file name "
                    "(no separators, no traversal, not absolute, no NUL)",
                )
            )
            continue
        inputs_raw = entry["inputs"]
        if (
            not isinstance(inputs_raw, list)
            or not inputs_raw
            or len(inputs_raw) > CHAIN_SET_MAX_INPUTS
        ):
            findings.append(
                _chain_set_finding(
                    CHAIN_SET_BAD_FIELD,
                    f"{label}.inputs is not a non-empty list of at most "
                    f"{CHAIN_SET_MAX_INPUTS} [index, ref] pairs",
                )
            )
            continue
        inputs: List[Tuple[int, str]] = []
        input_ok = True
        for pair in inputs_raw:
            if (
                not isinstance(pair, list)
                or len(pair) != 2
                or not isinstance(pair[0], int)
                or isinstance(pair[0], bool)
                or pair[0] < 0
                or not isinstance(pair[1], str)
                or not pair[1].strip()
            ):
                findings.append(
                    _chain_set_finding(
                        CHAIN_SET_BAD_FIELD,
                        f"{label}.inputs carries a malformed [index, ref] pair "
                        f"{pair!r}",
                    )
                )
                input_ok = False
                break
            ref = pair[1].strip()
            if "\x00" in ref:
                findings.append(
                    _chain_set_finding(
                        CHAIN_SET_UNSAFE_REF,
                        f"{label}.inputs ref {ref!r} carries a NUL character "
                        "- not a path",
                    )
                )
                input_ok = False
                break
            if _is_drive_relative(ref):
                findings.append(
                    _chain_set_finding(
                        CHAIN_SET_UNSAFE_REF,
                        f"{label}.inputs ref {ref!r} is a Windows drive-relative "
                        "path - refs resolve against the project directory only",
                    )
                )
                input_ok = False
                break
            resolved = _resolve_manifest_entry(
                project_root, ref, f"{label}.inputs.ref", findings
            )
            if resolved is None:
                input_ok = False
                break  # the guard appended its finding — chain rejected
            inputs.append((pair[0], ref))
        if not input_ok:
            continue
        outputs_raw = entry["outputs"]
        if (
            not isinstance(outputs_raw, list)
            or len(outputs_raw) > CHAIN_SET_MAX_OUTPUTS
            or any(not isinstance(out, str) or not out.strip() for out in outputs_raw)
        ):
            findings.append(
                _chain_set_finding(
                    CHAIN_SET_BAD_FIELD,
                    f"{label}.outputs is not a list of at most "
                    f"{CHAIN_SET_MAX_OUTPUTS} non-empty file names",
                )
            )
            continue
        chains.append(
            ChainSetEntry(
                chain=chain_name.strip(),
                template=template,
                inputs=tuple(inputs),
                outputs=tuple(out.strip() for out in outputs_raw),
            )
        )

    if findings:
        return None, findings
    return ChainSet(name=name.strip(), chains=tuple(chains)), findings


def save_chain_set(
    chain_set: ChainSet,
    raw_name: str,
    project_dir: Path,
) -> Optional[Path]:
    """Serialize the set and write it to ``flowsets/<sanitized>.json`` (LLR-021.1).

    Summary:
        The ``save_flow_json`` write-side idiom verbatim: ``sanitize_project_name``
        is the containment authority; an empty set (or a name that sanitises
        to ``None``) writes NOTHING and returns ``None`` — LLR-021.1's empty
        arm, ``0 empty sets written as non-empty``; a name collision
        dedup-suffixes (``_<N>``) instead of clobbering.

    Args:
        chain_set (ChainSet): The in-memory set to persist (trusted-side).
        raw_name (str): The operator-typed set name (untrusted text).
        project_dir (Path): The active ``.s19tool/workarea/<project>/`` dir.

    Returns:
        Optional[Path]: The absolute path written (``flowsets/<clean>.json``),
        or ``None`` when nothing was written (empty set / un-sanitisable name).
    """
    if not chain_set.chains:
        return None
    clean = sanitize_project_name(raw_name)
    if clean is None:
        return None
    flowsets_dir = project_dir / FLOWSETS_SUBDIR
    flowsets_dir.mkdir(parents=True, exist_ok=True)
    target = flowsets_dir / f"{clean}.json"
    if target.exists():
        counter = 2
        while (flowsets_dir / f"{clean}_{counter}.json").exists():
            counter += 1
        target = flowsets_dir / f"{clean}_{counter}.json"
    target.write_text(
        json.dumps(chain_set_to_dict(chain_set), indent=2), encoding="utf-8"
    )
    return target


def load_chain_set(
    set_path: Path,
    project_dir: Path,
) -> Tuple[Optional[ChainSet], List[ValidationIssue]]:
    """File-level hardened load: size cap → parse guard → :func:`dict_to_chain_set`.

    The ``load_flow_json`` idiom verbatim (the size cap is bound to the same
    ``FLOW_SIZE_CAP_BYTES`` — a set is a small binding document, not a
    payload). Never raises.
    """
    findings: List[ValidationIssue] = []
    try:
        size = set_path.stat().st_size
    except (OSError, ValueError) as exc:
        findings.append(
            _chain_set_finding(
                CHAIN_SET_JSON_PARSE, f"chain-set file unreadable: {type(exc).__name__}"
            )
        )
        return None, findings
    if size > FLOW_SIZE_CAP_BYTES:
        findings.append(
            _chain_set_finding(
                CHAIN_SET_SIZE_CAP,
                f"chain-set file is {size} bytes, over the "
                f"{FLOW_SIZE_CAP_BYTES}-byte cap - not loaded",
            )
        )
        return None, findings
    try:
        with set_path.open("rb") as handle:
            payload = json.load(handle)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, OSError) as exc:
        findings.append(
            _chain_set_finding(
                CHAIN_SET_JSON_PARSE,
                f"chain-set file is not well-formed JSON - {type(exc).__name__}",
            )
        )
        return None, findings
    return dict_to_chain_set(payload, project_dir)


def list_chain_sets(project_dir: Path) -> List[str]:
    """List the saved chain-set stems under ``flowsets/`` (the listing seam)."""
    flowsets_dir = project_dir / FLOWSETS_SUBDIR
    if not flowsets_dir.is_dir():
        return []
    return sorted(entry.stem for entry in flowsets_dir.glob("*.json") if entry.is_file())
