"""PROTOTYPE (throwaway) — FB-P1 batch-53: flow.json serialize + HARDENED load.

Run:  python prototypes/fb_p1_flow_persistence.prototype.py

QUESTION ON TRIAL
    Is the untrusted flow.json loader safe-by-construction when every embedded
    ref is re-validated through the SAME `_resolve_manifest_entry` containment
    guard the runtime already uses (reuse, never fork), with a fail-CLOSED
    whole-flow reject on any finding?

WHAT IT DEMONSTRATES
    1. `flow_to_dict` / `dict_to_flow` round-trip fidelity across ALL 5 shipped
       block kinds (SourceBlock / PatchBlock / WriteOutBlock / CheckBlock /
       CrcBlock — s19_app/tui/services/flow_model.py).
    2. A security-rejection battery: (a) absolute ref, (b) ../ traversal ref,
       (c) reparse-point ref (real NTFS junction when creatable, else SKIP-ENV),
       (d) unknown block kind, (e) future/invalid schema_version, (f) malformed
       or missing required fields.  Each must FAIL CLOSED (flow is None) with a
       readable finding, never crash, never open the path.
    3. The file-level path: save to `.s19tool/workarea/<proj>/flows/<name>.json`
       (name via the SAME `sanitize_project_name`), import an external file via
       the SAME `copy_into_workarea` guard, size-cap + parse guards mirroring
       `read_project_manifest` (variant_execution_service.py:364).

NOT PRODUCTION CODE.  The real implementation lands in a new
`s19_app/tui/services/flow_persistence_service.py` in batch-53; this file only
answers the loader-design question and is deleted/absorbed afterwards.
State lives in a tempfile workarea labelled PROTOTYPE-wipe-me.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, List, Optional, Tuple

# --- make the package importable when run from the repo root -----------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from s19_app.tui.services.flow_model import (  # noqa: E402
    BLOCK_CHECK,
    BLOCK_CRC,
    BLOCK_PATCH,
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
    SourceBlock,
    WriteOutBlock,
)

# THE guard being reused (never forked): the manifest containment triad —
# absolute / escape-project-root / reparse-point
# (s19_app/tui/services/variant_execution_service.py:205).
from s19_app.tui.services.variant_execution_service import (  # noqa: E402
    _resolve_manifest_entry,
)
from s19_app.tui.workspace import (  # noqa: E402
    copy_into_workarea,
    sanitize_project_name,
)
from s19_app.validation.model import (  # noqa: E402
    ValidationIssue,
    ValidationSeverity,
)

# =============================================================================
# Proposed public contract (batch-53) — envelope + codes
# =============================================================================

#: The one supported envelope version. `Flow.schema_version` already defaults
#: to 1 (flow_model.py:189, "for the batch-45 flow.json envelope").
FLOW_SCHEMA_VERSION = 1

#: Byte cap for a flow.json read — a flow is a small pipeline description, so
#: a deliberately TIGHT cap (vs the manifest's 256 MB copy-cap reuse).
FLOW_SIZE_CAP_BYTES = 1 * 1024 * 1024  # 1 MiB

#: Structural sanity caps (fail closed above them).
FLOW_MAX_BLOCKS = 64
FLOW_MAX_NAME_LEN = 64

#: Proposed FLOW-* finding codes (mirrors the MANIFEST-* family). Note that
#: findings raised INSIDE the reused `_resolve_manifest_entry` keep their
#: MANIFEST-PATH-ESCAPE / MANIFEST-BAD-STRUCTURE codes — reuse-not-fork means
#: the codes travel with the guard (open design question OQ-1 in NOTES).
FLOW_SIZE_CAP = "FLOW-SIZE-CAP"
FLOW_JSON_PARSE = "FLOW-JSON-PARSE"
FLOW_BAD_STRUCTURE = "FLOW-BAD-STRUCTURE"
FLOW_SCHEMA_UNSUPPORTED = "FLOW-SCHEMA-UNSUPPORTED"
FLOW_UNKNOWN_KIND = "FLOW-UNKNOWN-KIND"
FLOW_BAD_FIELD = "FLOW-BAD-FIELD"
FLOW_UNSAFE_OUTPUT_NAME = "FLOW-UNSAFE-OUTPUT-NAME"

#: kind → (required ref field, optional enum fields {name: allowed}).
_KIND_SPEC: dict[str, Tuple[str, dict[str, set]]] = {
    BLOCK_SOURCE: ("image_ref", {"file_type": {WRITE_FMT_S19, WRITE_FMT_HEX}}),
    BLOCK_PATCH: ("change_doc_ref", {}),
    BLOCK_WRITE_OUT: ("output_name", {"fmt": {WRITE_FMT_S19, WRITE_FMT_HEX}}),
    BLOCK_CHECK: (
        "check_doc_ref",
        {"gating": {CHECK_GATING_ADVISORY, CHECK_GATING_BLOCK_OWN}},
    ),
    BLOCK_CRC: ("config_ref", {}),
}

#: The ref fields that are READ targets → containment-checked at load through
#: `_resolve_manifest_entry`. `output_name` is a WRITE target whose runtime
#: authority is `save_patched_image` (F-S-01) — at load we only pre-reject
#: separators/absolute shapes (defense-in-depth, not a new authority).
_READ_REF_FIELDS = {"image_ref", "change_doc_ref", "check_doc_ref", "config_ref"}


def _finding(code: str, message: str) -> ValidationIssue:
    """One flow-load finding (artifact tag `flow`, always ERROR — fail closed)."""
    return ValidationIssue(
        code=code,
        severity=ValidationSeverity.ERROR,
        message=message,
        artifact="flow",
    )


# =============================================================================
# Serialize — trivially shape-preserving (the model is JSON-ready by design)
# =============================================================================

def flow_to_dict(flow: Flow) -> dict:
    """Serialize a Flow to the schema-v1 envelope dict.

    Envelope: {"schema_version": 1, "name": str, "blocks": [{"kind", ...}]}.
    Field names come straight from the frozen dataclasses; `kind` is emitted
    first per block for human readability (dict order is preserved by json).
    """
    blocks: List[dict] = []
    for block in flow.blocks:
        if isinstance(block, SourceBlock):
            blocks.append({"kind": block.kind, "image_ref": block.image_ref,
                           "file_type": block.file_type})
        elif isinstance(block, PatchBlock):
            blocks.append({"kind": block.kind,
                           "change_doc_ref": block.change_doc_ref})
        elif isinstance(block, WriteOutBlock):
            blocks.append({"kind": block.kind, "output_name": block.output_name,
                           "fmt": block.fmt})
        elif isinstance(block, CheckBlock):
            blocks.append({"kind": block.kind,
                           "check_doc_ref": block.check_doc_ref,
                           "gating": block.gating})
        elif isinstance(block, CrcBlock):
            blocks.append({"kind": block.kind, "config_ref": block.config_ref})
        else:  # unknown model object — serializer is trusted-side, so raise
            raise TypeError(f"unserializable block type: {type(block)!r}")
    return {
        "schema_version": flow.schema_version,
        "name": flow.name,
        "blocks": blocks,
    }


# =============================================================================
# HARDENED load — the artifact under trial
# =============================================================================

def dict_to_flow(
    payload: Any,
    project_dir: Path,
) -> Tuple[Optional[Flow], List[ValidationIssue]]:
    """Validate an UNTRUSTED envelope dict into a Flow — whole-flow fail-closed.

    Validation order (each stage collects findings; ANY finding ⇒ (None, findings)):
      V1 top level is a JSON object
      V2 schema_version is EXACTLY the supported int (future/absent/wrong-type reject)
      V3 name: optional str, display-only, length-capped (filename stays identity)
      V4 blocks: a list, 1..FLOW_MAX_BLOCKS entries
      V5 per block: an object; `kind` known; NO unknown keys (strict — schema_version
         gates evolution); required ref present as non-empty str; enum fields valid
      V6 per READ ref: `_resolve_manifest_entry(project_dir, ref, ...)` — the
         absolute/escape/reparse triad, NO filesystem open, existence NOT required
         (missing files surface at RUN time, the manifest precedent)
      V7 output_name: no path separators / no '..' / not absolute (runtime
         authority stays save_patched_image)

    Never raises; never opens any embedded path.
    """
    findings: List[ValidationIssue] = []

    # V1 — envelope shape
    if not isinstance(payload, dict):
        findings.append(_finding(
            FLOW_BAD_STRUCTURE, "flow.json top level is not a JSON object"))
        return None, findings

    # V2 — schema version gate (future versions REJECT, never best-effort)
    version = payload.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool) \
            or version != FLOW_SCHEMA_VERSION:
        findings.append(_finding(
            FLOW_SCHEMA_UNSUPPORTED,
            f"flow schema_version {version!r} is not supported "
            f"(this build reads version {FLOW_SCHEMA_VERSION} only)"))
        return None, findings

    # V3 — display name (identity is the FILENAME, this is cosmetic)
    name = payload.get("name", "flow")
    if not isinstance(name, str) or not name.strip():
        findings.append(_finding(
            FLOW_BAD_FIELD, "flow name is not a non-empty string"))
    elif len(name) > FLOW_MAX_NAME_LEN:
        findings.append(_finding(
            FLOW_BAD_FIELD,
            f"flow name exceeds {FLOW_MAX_NAME_LEN} characters"))

    # V4 — blocks array
    blocks_raw = payload.get("blocks")
    if not isinstance(blocks_raw, list):
        findings.append(_finding(
            FLOW_BAD_STRUCTURE, "flow blocks is not an array"))
        return None, findings
    if not blocks_raw:
        findings.append(_finding(FLOW_BAD_STRUCTURE, "flow has no blocks"))
    if len(blocks_raw) > FLOW_MAX_BLOCKS:
        findings.append(_finding(
            FLOW_BAD_STRUCTURE,
            f"flow has {len(blocks_raw)} blocks, over the "
            f"{FLOW_MAX_BLOCKS}-block cap"))
        return None, findings

    project_root = project_dir.resolve()
    blocks: List[FlowBlock] = []
    for index, entry in enumerate(blocks_raw):
        label = f"blocks[{index}]"
        # V5 — block object + kind + strict keys + fields
        if not isinstance(entry, dict):
            findings.append(_finding(
                FLOW_BAD_STRUCTURE, f"{label} is not a JSON object"))
            continue
        kind = entry.get("kind")
        if kind not in _KIND_SPEC:
            findings.append(_finding(
                FLOW_UNKNOWN_KIND,
                f"{label} has unknown kind {kind!r} - known kinds: "
                f"{sorted(_KIND_SPEC)}"))
            continue
        ref_field, enum_fields = _KIND_SPEC[kind]
        allowed_keys = {"kind", ref_field, *enum_fields}
        unknown = set(entry) - allowed_keys
        if unknown:
            findings.append(_finding(
                FLOW_BAD_FIELD,
                f"{label} ({kind}) carries unknown field(s) "
                f"{sorted(unknown)} - schema v{FLOW_SCHEMA_VERSION} is strict"))
            continue
        ref = entry.get(ref_field)
        if not isinstance(ref, str) or not ref.strip():
            findings.append(_finding(
                FLOW_BAD_FIELD,
                f"{label} ({kind}) is missing required field "
                f"'{ref_field}' (non-empty string)"))
            continue
        enum_ok = True
        for field_name, allowed in enum_fields.items():
            value = entry.get(field_name)
            if value is not None and value not in allowed:
                findings.append(_finding(
                    FLOW_BAD_FIELD,
                    f"{label} ({kind}) field '{field_name}' value {value!r} "
                    f"not in {sorted(allowed)}"))
                enum_ok = False
        if not enum_ok:
            continue

        # V6 — READ-ref containment through the REUSED guard (no open, no
        # existence requirement; MANIFEST-* codes travel with the guard).
        if ref_field in _READ_REF_FIELDS:
            resolved = _resolve_manifest_entry(
                project_root, ref, f"{label}.{ref_field}", findings)
            if resolved is None:
                continue  # the guard appended its finding — block rejected
        # V7 — WRITE-target shape pre-check (authority stays save_patched_image)
        elif ref_field == "output_name":
            if ("/" in ref or "\\" in ref or ".." in ref
                    or Path(ref).is_absolute() or ref.strip().startswith(".")):
                findings.append(_finding(
                    FLOW_UNSAFE_OUTPUT_NAME,
                    f"{label} output_name {ref!r} must be a plain filename "
                    "(no separators, no traversal, not hidden)"))
                continue

        # construct the frozen block (defaults fill the optional enums)
        if kind == BLOCK_SOURCE:
            blocks.append(SourceBlock(
                image_ref=ref,
                file_type=entry.get("file_type", WRITE_FMT_S19)))
        elif kind == BLOCK_PATCH:
            blocks.append(PatchBlock(change_doc_ref=ref))
        elif kind == BLOCK_WRITE_OUT:
            blocks.append(WriteOutBlock(
                output_name=ref, fmt=entry.get("fmt", WRITE_FMT_S19)))
        elif kind == BLOCK_CHECK:
            blocks.append(CheckBlock(
                check_doc_ref=ref,
                gating=entry.get("gating", CHECK_GATING_ADVISORY)))
        elif kind == BLOCK_CRC:
            blocks.append(CrcBlock(config_ref=ref))

    # FAIL-CLOSED aggregate: an executable pipeline is never partially loaded.
    if findings:
        return None, findings
    return Flow(name=name, blocks=blocks,
                schema_version=FLOW_SCHEMA_VERSION), findings


def load_flow_json(
    flow_path: Path,
    project_dir: Path,
) -> Tuple[Optional[Flow], List[ValidationIssue]]:
    """File-level hardened load: size cap → parse guards → dict_to_flow.

    Mirrors `read_project_manifest`'s file gate (variant_execution_service.py:
    427-454): probe size BEFORE parse; catch JSONDecodeError / RecursionError /
    UnicodeDecodeError / OSError. Never raises.
    """
    findings: List[ValidationIssue] = []
    try:
        size = flow_path.stat().st_size
    except OSError as exc:
        findings.append(_finding(
            FLOW_JSON_PARSE, f"flow file unreadable: {type(exc).__name__}"))
        return None, findings
    if size > FLOW_SIZE_CAP_BYTES:
        findings.append(_finding(
            FLOW_SIZE_CAP,
            f"flow file is {size} bytes, over the {FLOW_SIZE_CAP_BYTES}-byte "
            "cap - not loaded"))
        return None, findings
    try:
        with flow_path.open("rb") as handle:
            payload = json.load(handle)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError,
            OSError) as exc:
        findings.append(_finding(
            FLOW_JSON_PARSE,
            f"flow file is not well-formed JSON - {type(exc).__name__}"))
        return None, findings
    return dict_to_flow(payload, project_dir)


def save_flow_json(flow: Flow, raw_name: str,
                   project_dir: Path) -> Optional[Path]:
    """Save under flows/<sanitized>.json — name via the SAME project sanitiser."""
    clean = sanitize_project_name(raw_name)
    if clean is None:
        return None
    flows_dir = project_dir / "flows"
    flows_dir.mkdir(parents=True, exist_ok=True)
    target = flows_dir / f"{clean}.json"
    target.write_text(
        json.dumps(flow_to_dict(flow), indent=2), encoding="utf-8")
    return target


# =============================================================================
# Demo harness
# =============================================================================

_OK = "\x1b[32m"
_BAD = "\x1b[31m"
_DIM = "\x1b[2m"
_BOLD = "\x1b[1m"
_RST = "\x1b[0m"


def _print_findings(findings: List[ValidationIssue]) -> None:
    for issue in findings:
        print(f"      {_DIM}[{issue.code}]{_RST} {issue.message}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="PROTOTYPE-wipe-me-fb-p1-"))
    # Real workarea shape so copy_into_workarea's containment applies honestly.
    project_dir = tmp / ".s19tool" / "workarea" / "protoproj"
    (project_dir / "flows").mkdir(parents=True)
    failures = 0

    print(f"{_BOLD}FB-P1 prototype — flow.json persistence "
          f"(PROTOTYPE, throwaway){_RST}")
    print(f"{_DIM}workarea: {project_dir}{_RST}\n")

    # ---- 1. round-trip across ALL 5 block kinds -----------------------------
    print(f"{_BOLD}[1] round-trip fidelity (all 5 kinds){_RST}")
    original = Flow(
        name="nightly-release",
        blocks=[
            SourceBlock(image_ref="prg.s19"),
            PatchBlock(change_doc_ref="calib_patch.json"),
            CheckBlock(check_doc_ref="post_checks.json",
                       gating=CHECK_GATING_BLOCK_OWN),
            CrcBlock(config_ref="crc32_blocks.json"),
            WriteOutBlock(output_name="prg_patched.s19", fmt=WRITE_FMT_S19),
        ],
        schema_version=FLOW_SCHEMA_VERSION,
    )
    envelope = flow_to_dict(original)
    print(f"{_DIM}{json.dumps(envelope, indent=2)}{_RST}")
    reloaded, findings = dict_to_flow(
        json.loads(json.dumps(envelope)), project_dir)
    round_trip_ok = (
        reloaded is not None
        and not findings
        and reloaded.name == original.name
        and reloaded.schema_version == original.schema_version
        and list(reloaded.blocks) == list(original.blocks)
    )
    print(f"  round-trip equal: "
          f"{_OK + 'PASS' if round_trip_ok else _BAD + 'FAIL'}{_RST}")
    failures += 0 if round_trip_ok else 1

    # file-level save + reload through the flows/ dir
    saved = save_flow_json(original, "Nightly Release!  ", project_dir)
    from_disk, disk_findings = (
        load_flow_json(saved, project_dir) if saved else (None, []))
    disk_ok = (saved is not None and saved.name == "NightlyRelease.json"
               and from_disk is not None and not disk_findings
               and list(from_disk.blocks) == list(original.blocks))
    print(f"  save→flows/{saved.name if saved else '?'} → reload: "
          f"{_OK + 'PASS' if disk_ok else _BAD + 'FAIL'}{_RST}\n")
    failures += 0 if disk_ok else 1

    # ---- 2. security-rejection battery --------------------------------------
    print(f"{_BOLD}[2] security-rejection battery "
          f"(each must FAIL CLOSED with a readable finding){_RST}")

    def valid_envelope() -> dict:
        return json.loads(json.dumps(envelope))  # deep copy of the good one

    battery: List[Tuple[str, dict]] = []

    e = valid_envelope()
    e["blocks"][0]["image_ref"] = "C:\\Windows\\System32\\evil.s19"
    battery.append(("(a) absolute ref (win)", e))

    e = valid_envelope()
    e["blocks"][1]["change_doc_ref"] = "/etc/passwd"
    battery.append(("(a2) absolute ref (posix)", e))

    e = valid_envelope()
    e["blocks"][3]["config_ref"] = "../../other_project/secrets.json"
    battery.append(("(b) ../ traversal ref", e))

    e = valid_envelope()
    e["blocks"].append({"kind": "shell", "cmd_ref": "run_me.bat"})
    battery.append(("(d) unknown kind 'shell'", e))

    e = valid_envelope()
    e["schema_version"] = 99
    battery.append(("(e) future schema_version 99", e))

    e = valid_envelope()
    e["schema_version"] = "1"
    battery.append(("(e2) schema_version as string", e))

    e = valid_envelope()
    del e["blocks"][0]["image_ref"]
    battery.append(("(f) missing required image_ref", e))

    e = valid_envelope()
    e["blocks"][2]["gating"] = "chain-kill"
    battery.append(("(f2) invalid enum gating", e))

    e = valid_envelope()
    e["blocks"][4]["output_name"] = "..\\..\\escape.s19"
    battery.append(("(f3) traversal output_name", e))

    e = valid_envelope()
    e["blocks"][0]["extra_hook"] = "x"
    battery.append(("(f4) unknown extra field (strict)", e))

    battery.append(("(f5) top level not an object", ["not", "a", "dict"]))

    for label, bad_payload in battery:
        flow, batt_findings = dict_to_flow(bad_payload, project_dir)
        closed = flow is None and len(batt_findings) > 0
        print(f"  {label:<38} "
              f"{_OK + 'REJECTED-CLOSED' if closed else _BAD + 'LEAKED'}{_RST}")
        _print_findings(batt_findings)
        failures += 0 if closed else 1

    # (c) reparse point — a REAL NTFS junction inside the project pointing out.
    junction = project_dir / "jdir"
    outside = tmp / "outside_project"
    outside.mkdir(exist_ok=True)
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True, text=True).returncode == 0
    if made:
        e = valid_envelope()
        e["blocks"][1]["change_doc_ref"] = "jdir/patch.json"
        flow, j_findings = dict_to_flow(e, project_dir)
        closed = flow is None and len(j_findings) > 0
        print(f"  {'(c) reparse-point ref (NTFS junction)':<38} "
              f"{_OK + 'REJECTED-CLOSED' if closed else _BAD + 'LEAKED'}{_RST}")
        _print_findings(j_findings)
        failures += 0 if closed else 1
    else:
        print(f"  {'(c) reparse-point ref (NTFS junction)':<38} "
              f"{_DIM}SKIP-ENV (mklink /J unavailable){_RST}")

    # not-even-JSON file-level case
    hostile = project_dir / "flows" / "broken.json"
    hostile.write_text("{not json", encoding="utf-8")
    flow, parse_findings = load_flow_json(hostile, project_dir)
    closed = flow is None and parse_findings
    print(f"  {'(g) malformed JSON file':<38} "
          f"{_OK + 'REJECTED-CLOSED' if closed else _BAD + 'LEAKED'}{_RST}")
    _print_findings(parse_findings)
    failures += 0 if closed else 1

    # ---- 3. import-external path (COPY into flows/, never run in place) -----
    print(f"\n{_BOLD}[3] import external flow.json "
          f"(copy_into_workarea, never executed in place){_RST}")
    external = tmp / "downloads" / "vendor_flow.json"
    external.parent.mkdir(exist_ok=True)
    external.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    try:
        imported = copy_into_workarea(external, project_dir / "flows")
        flow, imp_findings = load_flow_json(imported, project_dir)
        ok = flow is not None and not imp_findings \
            and imported.parent == project_dir / "flows"
        print(f"  import {external.name} → flows/{imported.name} → load: "
              f"{_OK + 'PASS' if ok else _BAD + 'FAIL'}{_RST}")
        failures += 0 if ok else 1
    except Exception as exc:  # prototype-level guard only
        print(f"  {_BAD}FAIL{_RST} import raised {type(exc).__name__}: {exc}")
        failures += 1

    # a hostile import target: destination outside any workarea must refuse
    try:
        copy_into_workarea(external, tmp / "not_workarea")
        print(f"  hostile dest (outside workarea): {_BAD}LEAKED{_RST}")
        failures += 1
    except Exception as exc:
        print(f"  hostile dest (outside workarea): "
              f"{_OK}REFUSED{_RST} {_DIM}({type(exc).__name__}){_RST}")

    # ---- verdict -------------------------------------------------------------
    print(f"\n{_BOLD}VERDICT: "
          f"{(_OK + 'ALL CASES HELD') if failures == 0 else (_BAD + str(failures) + ' CASE(S) FAILED')}"
          f"{_RST}")
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
