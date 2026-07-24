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
    FLOW_SIZE_CAP_BYTES,
    FLOWS_SUBDIR,
    REJECTING_CODES,
    dict_to_flow,
    flow_to_dict,
    import_flow_file,
    list_saved_flows,
    load_flow_json,
    save_flow_json,
)
from s19_app.tui.services.variant_execution_service import MANIFEST_PATH_ESCAPE
from s19_app.tui.workspace import WorkareaContainmentError, copy_into_workarea


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


# --------------------------------------------------------------------------- #
# Inc-2 · AT-001 / TC-002 — save_flow_json: sanitiser is write-side containment
# --------------------------------------------------------------------------- #

def test_save_flow_json_sanitises_and_roundtrips(project_dir: Path) -> None:
    """A raw name saves under the SANITISED stem, on disk, and reloads equal.

    The observable US-001 deliverable: a file at
    ``flows/<sanitize_project_name(name)>.json`` that is non-empty, valid JSON,
    ``schema_version:1``, with the built blocks — then round-trips through
    ``load_flow_json`` field-by-field.
    """
    flow = _good_flow()
    saved = save_flow_json(flow, "Nightly Release!  ", project_dir)

    # Landed under flows/ at the sanitised stem (spaces + '!' stripped).
    assert saved is not None
    assert saved == project_dir / FLOWS_SUBDIR / "NightlyRelease.json"
    assert saved.parent == project_dir / FLOWS_SUBDIR
    assert saved.exists() and saved.stat().st_size > 0

    # On-disk envelope is valid JSON, schema v1, block count matches.
    payload = json.loads(saved.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert len(payload["blocks"]) == len(flow.blocks)

    # Round-trips back to an equal Flow (non-default enums preserved).
    reloaded, findings = load_flow_json(saved, project_dir)
    assert findings == []
    assert reloaded is not None
    assert list(reloaded.blocks) == list(flow.blocks)


def test_save_flow_json_empty_after_clean_writes_nothing(project_dir: Path) -> None:
    """A whitespace- / punctuation-only name sanitises to ``None`` → no file, no dir."""
    for bad in ("   ", "!!!", "@@@"):
        assert save_flow_json(_good_flow(), bad, project_dir) is None, bad
    assert not (project_dir / FLOWS_SUBDIR).exists()


def test_save_flow_json_sanitiser_contains_traversal(project_dir: Path) -> None:
    """The sanitiser IS the write-side containment: a ``../``-bearing name is
    reduced to a safe stem that stays INSIDE ``flows/``, never one level up.

    Counterfactual: were the raw name written verbatim, ``../../escape`` would
    land above ``flows/`` — this asserts the sanitised copy is contained and the
    naive-escape target does not exist.
    """
    flows_dir = (project_dir / FLOWS_SUBDIR).resolve()
    for hostile in ("../../escape", "..\\..\\escape"):
        saved = save_flow_json(_good_flow(), hostile, project_dir)
        assert saved is not None
        # Contained: the write is inside flows/, and the traversal target is not.
        assert saved.parent == project_dir / FLOWS_SUBDIR
        assert saved.resolve().is_relative_to(flows_dir)
        assert not (project_dir / "escape.json").exists()


# --------------------------------------------------------------------------- #
# Inc-2 · LLR-003.3 — list_saved_flows
# --------------------------------------------------------------------------- #

def test_list_saved_flows_empty_when_no_dir(project_dir: Path) -> None:
    assert list_saved_flows(project_dir) == []


def test_list_saved_flows_returns_sorted_stems(project_dir: Path) -> None:
    save_flow_json(_good_flow(), "release", project_dir)
    save_flow_json(_good_flow(), "nightly", project_dir)
    save_flow_json(_good_flow(), "alpha", project_dir)
    assert list_saved_flows(project_dir) == ["alpha", "nightly", "release"]


# --------------------------------------------------------------------------- #
# Inc-2 · AT-P1-10 / TC-014 — Import: COPY then Load-what-was-written (C-12)
# --------------------------------------------------------------------------- #

def test_import_copies_then_loads_the_copy_not_the_source(
    project_dir: Path, tmp_path: Path
) -> None:
    """C-12 output-then-consume: the consumer (load) observes the HANDLER-PRODUCED
    copy under ``flows/``, never the external source.

    The discriminator: after the copy, MUTATE the external file and assert the
    loaded content still matches the COPY. A handler that loaded the external in
    place (copying only as a side-effect) would reload the mutated content → RED.
    """
    external_dir = tmp_path / "outside"
    external_dir.mkdir()
    external = external_dir / "vendor_flow.json"
    external.write_text(json.dumps(flow_to_dict(_good_flow())), encoding="utf-8")

    imported = import_flow_file(external, project_dir)
    assert imported.parent == project_dir / FLOWS_SUBDIR  # handler-produced artifact

    # Mutate the EXTERNAL source AFTER the copy — the copy must be untouched.
    external.write_text(
        json.dumps(flow_to_dict(Flow(name="tampered", blocks=[ReportBlock()]))),
        encoding="utf-8",
    )

    reloaded, findings = load_flow_json(imported, project_dir)
    assert findings == []
    assert reloaded is not None
    # Loaded from the COPY (5 kinds), not the post-copy external (1 report block).
    assert list(reloaded.blocks) == list(_good_flow().blocks)


def test_import_dedups_second_import_of_same_name(
    project_dir: Path, tmp_path: Path
) -> None:
    """A second import of the same filename dedups to ``_1``; both loadable (TC-035)."""
    external = tmp_path / "flow.json"
    external.write_text(json.dumps(flow_to_dict(_good_flow())), encoding="utf-8")

    first = import_flow_file(external, project_dir)
    second = import_flow_file(external, project_dir)
    assert first != second
    assert second.stem.endswith("_1")
    for copied in (first, second):
        reloaded, findings = load_flow_json(copied, project_dir)
        assert findings == [] and reloaded is not None


def test_import_over_size_cap_refused_at_copy_step(
    project_dir: Path, tmp_path: Path
) -> None:
    """AMD-4/F1: an external file over the 1 MiB FLOW cap is refused AT THE COPY,
    proving the copy binds ``FLOW_SIZE_CAP_BYTES`` — not the 256 MB copy default.

    Counterfactual: the handler copies with the default cap → a >1 MiB flow lands
    and defeats the DoS bound → RED (this raise would not fire).
    """
    oversize = tmp_path / "huge.json"
    oversize.write_bytes(b"{}" + b" " * (FLOW_SIZE_CAP_BYTES + 1))
    assert oversize.stat().st_size > FLOW_SIZE_CAP_BYTES
    with pytest.raises(WorkareaContainmentError):
        import_flow_file(oversize, project_dir)
    # Nothing landed under flows/.
    assert list_saved_flows(project_dir) == []


# --------------------------------------------------------------------------- #
# Inc-2 · AT-P1-11 / TC-036 — Hostile import destination refused
# --------------------------------------------------------------------------- #

def test_import_hostile_dest_outside_workarea_refused(tmp_path: Path) -> None:
    """A destination OUTSIDE any ``.s19tool/workarea/`` root is refused; nothing
    is written (the containment guard is the authority, not the handler)."""
    external = tmp_path / "flow.json"
    external.write_text(json.dumps(flow_to_dict(_good_flow())), encoding="utf-8")
    hostile_dest = tmp_path / "not_a_workarea" / FLOWS_SUBDIR
    with pytest.raises(WorkareaContainmentError):
        copy_into_workarea(external, hostile_dest, max_size_bytes=FLOW_SIZE_CAP_BYTES)
    assert not hostile_dest.exists()
