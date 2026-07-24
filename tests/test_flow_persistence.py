"""FB-P1 (batch-53) flow.json persistence — data-layer tests (Inc-1).

Layer-A white-box tests over the Textual-free
``flow_persistence_service`` + the ``run_flow`` report no-op. Covers:

- AT-001 round-trip fidelity FIELD-BY-FIELD with NON-DEFAULT enums (AMD-7).
- The C-31 security battery: one hostile axis per row, each fail-closed with its
  mapped code, DERIVED from declared tables (a dropped/added arm changes the
  tables), plus the reject-arm CENSUS ``battery_codes >= REJECTING_CODES``
  (AMD-6) so a new reject arm without a battery row goes RED.
- Negative controls (a good envelope + a benign output_name load clean) so the
  battery cannot pass vacuously by rejecting everything.
- ReportBlock ref-less round-trip + strict-keys still firing on a smuggled field.
- The ReportBlock no-op keeps the ``run_flow`` whole-flow rollup ``ok`` (AMD-1),
  driven over a report-only flow so no source block can abort the chain first
  (AMD-12/m-6).

The security-load path is the load-bearing surface — its assertions are
non-vacuous (field-by-field, per-branch codes, a "no open" control).
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path
from typing import Callable, List, Tuple

import pytest

from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_OK,
    CHECK_GATING_BLOCK_OWN,
    FLOW_STATUS_OK,
    WRITE_FMT_HEX,
    CheckBlock,
    CrcBlock,
    Flow,
    FlowContext,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.flow_persistence_service import (
    FLOW_BAD_FIELD,
    FLOW_BAD_STRUCTURE,
    FLOW_JSON_PARSE,
    FLOW_SCHEMA_UNSUPPORTED,
    FLOW_SIZE_CAP,
    FLOW_UNKNOWN_KIND,
    FLOW_UNSAFE_OUTPUT_NAME,
    FLOW_UNSAFE_REF,
    REJECTING_CODES,
    dict_to_flow,
    flow_to_dict,
    load_flow_json,
)
from s19_app.tui.services.variant_execution_service import MANIFEST_PATH_ESCAPE


@pytest.fixture
def project_dir(tmp_path: Path) -> Path:
    """A real work-area project directory (containment base for refs)."""
    proj = tmp_path / ".s19tool" / "workarea" / "proj"
    proj.mkdir(parents=True)
    return proj


def _good_flow() -> Flow:
    """A 5-kind flow with NON-DEFAULT enums (file_type/gating/fmt all off-default).

    Non-default enums are the anti-vacuity lever (AMD-7 / C-31): a serializer
    that drops an enum field and lets the dataclass default backfill would
    reload to the DEFAULT value and fail the field-by-field assert.
    """
    return Flow(
        name="nightly-release",
        blocks=[
            SourceBlock(image_ref="prg.s19", file_type=WRITE_FMT_HEX),
            PatchBlock(change_doc_ref="calib_patch.json"),
            CheckBlock(check_doc_ref="post_checks.json", gating=CHECK_GATING_BLOCK_OWN),
            CrcBlock(config_ref="crc32_blocks.json"),
            WriteOutBlock(output_name="prg_patched.s19", fmt=WRITE_FMT_HEX),
        ],
        schema_version=fps.FLOW_SCHEMA_VERSION,
    )


def _good_envelope() -> dict:
    """A JSON-round-tripped plain dict of :func:`_good_flow` (deep-copyable)."""
    return json.loads(json.dumps(flow_to_dict(_good_flow())))


# --------------------------------------------------------------------------- #
# AT-001 — round-trip fidelity, field-by-field, non-default enums
# --------------------------------------------------------------------------- #

def test_roundtrip_all_kinds_field_by_field(project_dir: Path) -> None:
    original = _good_flow()
    reloaded, findings = dict_to_flow(json.loads(json.dumps(flow_to_dict(original))), project_dir)

    assert findings == []
    assert reloaded is not None
    assert reloaded.name == original.name
    assert reloaded.schema_version == original.schema_version
    # Frozen-dataclass equality is field-by-field; with non-default enums a
    # dropped field would reload as its default and break this.
    assert list(reloaded.blocks) == list(original.blocks)
    # Explicit per-field co-asserts on the off-default enums (AMD-7).
    src, _patch, chk, _crc, wo = reloaded.blocks
    assert src.file_type == WRITE_FMT_HEX
    assert chk.gating == CHECK_GATING_BLOCK_OWN
    assert wo.fmt == WRITE_FMT_HEX


def test_roundtrip_via_file(project_dir: Path) -> None:
    """load_flow_json reads a written envelope back to an equal flow."""
    original = _good_flow()
    path = project_dir / "flows_probe.json"
    path.write_text(json.dumps(flow_to_dict(original), indent=2), encoding="utf-8")
    reloaded, findings = load_flow_json(path, project_dir)
    assert findings == []
    assert reloaded is not None
    assert list(reloaded.blocks) == list(original.blocks)


# --------------------------------------------------------------------------- #
# C-31 security battery — one hostile axis per row, derived + census-guarded
# --------------------------------------------------------------------------- #

#: (id, mutate_fn over a deep-copied good envelope, expected reject code).
DICT_HOSTILE_CASES: List[Tuple[str, Callable[[dict], None], str]] = [
    ("win-abs", lambda e: e["blocks"][0].__setitem__("image_ref", "C:\\Windows\\evil.s19"), MANIFEST_PATH_ESCAPE),
    ("posix-abs", lambda e: e["blocks"][1].__setitem__("change_doc_ref", "/etc/passwd"), MANIFEST_PATH_ESCAPE),
    ("traversal", lambda e: e["blocks"][3].__setitem__("config_ref", "../../other/secrets.json"), MANIFEST_PATH_ESCAPE),
    ("drive-rel", lambda e: e["blocks"][0].__setitem__("image_ref", "C:relative_evil.s19"), FLOW_UNSAFE_REF),
    ("unknown-kind", lambda e: e["blocks"].append({"kind": "shell", "cmd_ref": "run.bat"}), FLOW_UNKNOWN_KIND),
    ("strict-key", lambda e: e["blocks"][0].__setitem__("extra_hook", "x"), FLOW_BAD_FIELD),
    ("missing-ref", lambda e: e["blocks"][0].pop("image_ref"), FLOW_BAD_FIELD),
    ("bad-enum", lambda e: e["blocks"][2].__setitem__("gating", "chain-kill"), FLOW_BAD_FIELD),
    ("schema-int", lambda e: e.__setitem__("schema_version", 99), FLOW_SCHEMA_UNSUPPORTED),
    ("schema-str", lambda e: e.__setitem__("schema_version", "1"), FLOW_SCHEMA_UNSUPPORTED),
    ("schema-bool", lambda e: e.__setitem__("schema_version", True), FLOW_SCHEMA_UNSUPPORTED),
    ("output-name", lambda e: e["blocks"][4].__setitem__("output_name", "..\\..\\escape.s19"), FLOW_UNSAFE_OUTPUT_NAME),
    ("empty-blocks", lambda e: e.__setitem__("blocks", []), FLOW_BAD_STRUCTURE),
    ("top-not-object", lambda e: None, FLOW_BAD_STRUCTURE),  # replaced below
]

#: File-level hostile cases exercised through load_flow_json (id, writer, code).
FILE_HOSTILE_CASES: List[Tuple[str, Callable[[Path], None], str]] = [
    ("oversize", lambda p: p.write_bytes(b" " * (fps.FLOW_SIZE_CAP_BYTES + 1)), FLOW_SIZE_CAP),
    ("malformed", lambda p: p.write_text("{not json", encoding="utf-8"), FLOW_JSON_PARSE),
]

#: The union of every code the battery actually exercises — the completeness
#: oracle input for the census below.
BATTERY_EXPECTED_CODES = frozenset(
    {code for _id, _fn, code in DICT_HOSTILE_CASES} | {code for _id, _fn, code in FILE_HOSTILE_CASES}
)


@pytest.mark.parametrize("case_id,mutate,expected", DICT_HOSTILE_CASES, ids=[c[0] for c in DICT_HOSTILE_CASES])
def test_security_battery_dict(project_dir: Path, case_id: str, mutate: Callable[[dict], None], expected: str) -> None:
    if case_id == "top-not-object":
        payload: object = ["not", "a", "dict"]
    else:
        payload = copy.deepcopy(_good_envelope())
        mutate(payload)
    flow, findings = dict_to_flow(payload, project_dir)
    assert flow is None, f"{case_id} leaked a Flow"
    assert findings, f"{case_id} produced no finding"
    assert expected in {f.code for f in findings}, f"{case_id} missing {expected}"


@pytest.mark.parametrize("case_id,write,expected", FILE_HOSTILE_CASES, ids=[c[0] for c in FILE_HOSTILE_CASES])
def test_security_battery_file(project_dir: Path, case_id: str, write: Callable[[Path], None], expected: str) -> None:
    path = project_dir / f"hostile_{case_id}.json"
    write(path)
    flow, findings = load_flow_json(path, project_dir)
    assert flow is None
    assert expected in {f.code for f in findings}


def test_reject_arm_census() -> None:
    """Every code the loader can emit as a rejection is exercised by ≥1 battery
    row (C-31 / AMD-6). Add a new FLOW-* reject arm without a battery case → this
    goes RED because REJECTING_CODES grows but BATTERY_EXPECTED_CODES does not.
    """
    missing = REJECTING_CODES - BATTERY_EXPECTED_CODES
    assert not missing, f"reject arms with no battery case: {sorted(missing)}"


def test_size_probed_before_parse(project_dir: Path) -> None:
    """An oversize AND malformed file trips SIZE-CAP, not PARSE (order matters)."""
    path = project_dir / "big_and_broken.json"
    path.write_bytes(b"{not json " + b"x" * (fps.FLOW_SIZE_CAP_BYTES + 1))
    flow, findings = load_flow_json(path, project_dir)
    assert flow is None
    assert {f.code for f in findings} == {FLOW_SIZE_CAP}


@pytest.mark.skipif(os.name != "nt", reason="NTFS junction is Windows-only")
def test_security_reparse_junction(project_dir: Path, tmp_path: Path) -> None:
    """A REAL NTFS junction escaping the project is rejected via the guard's
    reparse arm (C-12: a mocked reparse check would make this vacuous)."""
    junction = project_dir / "jdir"
    outside = tmp_path / "outside_project"
    outside.mkdir()
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True, text=True,
    ).returncode == 0
    if not made:
        pytest.skip("mklink /J unavailable — reparse arm unverified")
    payload = copy.deepcopy(_good_envelope())
    payload["blocks"][1]["change_doc_ref"] = "jdir/patch.json"
    flow, findings = dict_to_flow(payload, project_dir)
    assert flow is None
    assert MANIFEST_PATH_ESCAPE in {f.code for f in findings}


# --------------------------------------------------------------------------- #
# Negative controls — the battery is not blanket-rejecting
# --------------------------------------------------------------------------- #

def test_negative_control_good_envelope_loads_clean(project_dir: Path) -> None:
    flow, findings = dict_to_flow(_good_envelope(), project_dir)
    assert findings == []
    assert flow is not None


def test_negative_control_benign_output_name(project_dir: Path) -> None:
    payload = copy.deepcopy(_good_envelope())
    payload["blocks"][4]["output_name"] = "prg_patched.s19"
    flow, findings = dict_to_flow(payload, project_dir)
    assert findings == []
    assert flow is not None


def test_no_open_nonexistent_but_safe_ref(project_dir: Path) -> None:
    """A valid relative ref that does NOT exist on disk still loads clean —
    existence is not required and no path is opened (OQ-2)."""
    payload = copy.deepcopy(_good_envelope())
    payload["blocks"][0]["image_ref"] = "does_not_exist_yet.s19"
    flow, findings = dict_to_flow(payload, project_dir)
    assert findings == []
    assert flow is not None


# --------------------------------------------------------------------------- #
# ReportBlock — ref-less round-trip + strict-keys still fires
# --------------------------------------------------------------------------- #

def test_report_block_roundtrip(project_dir: Path) -> None:
    original = Flow(name="with-report", blocks=[SourceBlock(image_ref="prg.s19"), ReportBlock()])
    reloaded, findings = dict_to_flow(json.loads(json.dumps(flow_to_dict(original))), project_dir)
    assert findings == []
    assert reloaded is not None
    assert list(reloaded.blocks) == list(original.blocks)
    assert isinstance(reloaded.blocks[-1], ReportBlock)


def test_report_serializes_ref_less() -> None:
    envelope = flow_to_dict(Flow(name="r", blocks=[ReportBlock()]))
    assert envelope["blocks"] == [{"kind": "report"}]


def test_report_strict_keys_reject_smuggled_field(project_dir: Path) -> None:
    payload = {"schema_version": 1, "name": "r", "blocks": [{"kind": "report", "x": 1}]}
    flow, findings = dict_to_flow(payload, project_dir)
    assert flow is None
    assert FLOW_BAD_FIELD in {f.code for f in findings}


# --------------------------------------------------------------------------- #
# ReportBlock run_flow no-op — whole-flow rollup stays ok (AMD-1)
# --------------------------------------------------------------------------- #

def test_report_noop_keeps_rollup_ok(project_dir: Path) -> None:
    """A report-only flow runs without error; the report block is OK and the
    whole-flow rollup stays `ok` (AMD-1: not SKIPPED/NOTICES). Report-only so no
    source block can abort the chain first (AMD-12/m-6)."""
    result = run_flow(Flow(name="report-only", blocks=[ReportBlock()]), FlowContext(project_dir=project_dir))
    assert result.status == FLOW_STATUS_OK
    assert len(result.block_results) == 1
    report = result.block_results[0]
    assert report.status == BLOCK_STATUS_OK
    assert "deferred" in report.summary
