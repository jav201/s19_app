"""Batch-94 Inc-002 — the A2B diff block + builder templates (service layer).

TC-B94-04 (LLR-015.1/015.2) · TC-B94-21 (LLR-013.2) · TC-B94-22 (LLR-013.3,
the C-1 re-arm) · TC-B94-23 (LLR-014.1) · TC-B94-24 (LLR-014.2, C-42) ·
TC-B94-25 (LLR-016.1).

The headless drives are the shipped services (``run_flow``,
``save_flow_json``/``load_flow_json``/``dict_to_flow``) — no TUI. The v2
change-document + CRC config helper shapes mirror ``tests/test_flow_crc_block.py``
(the established engine-layer oracle idiom).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from s19_app.core import S19File
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    A2BBlock,
    A2BInputBinding,
    A2B_INPUT_FILE,
    A2B_INPUT_FLOW,
    BLOCK_A2B,
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_OK,
    CheckBlock,
    CrcBlock,
    Flow,
    FlowContext,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
    parse_a2b_binding,
    validate_a2b_bindings,
)
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.tui.services.markdown_safety import md_code, md_safe
from s19_app.tui.workspace import sanitize_project_name

#: Minimal CLEAN S19 — 01 02 03 04 at 0x1000 (checksum-verified).
_S19_A = "S107100001020304DE\nS9030000FC\n"


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _patch_doc(entries: list[dict]) -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        }
    )


def _reload(path: Path) -> dict[int, int]:
    return build_loaded_s19(path, S19File(str(path)), None, None).mem_map


def _flow_a2b_block(ref_a: str, ref_b: str) -> A2BBlock:
    binding_a = parse_a2b_binding(ref_a)
    binding_b = parse_a2b_binding(ref_b)
    assert binding_a is not None and binding_b is not None
    return A2BBlock(image_a=binding_a, image_b=binding_b)


# --------------------------------------------------------------------------- #
# TC-B94-21 — flow_to_dict / dict_to_flow round-trip with one of each kind
# --------------------------------------------------------------------------- #


def test_tc_b94_21_roundtrip_one_of_each_kind_incl_a2b(tmp_path: Path) -> None:
    """TC-B94-21 (LLR-013.2): a serialized flow with one of each block kind —
    SOURCE / PATCH / CHECK / CRC / WRITE-OUT / REPORT + the NEW A2B — round-
    trips through flow_to_dict/dict_to_flow with kind equality and per-kind
    fields intact (the two A2B bindings survive verbatim); schema_version
    stays 1; a foreign kind is refused fail-closed."""
    project = _make_project(tmp_path, {"prg.s19": _S19_A, "base.s19": _S19_A})
    flow = Flow(
        name="all-kinds",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("hotfix.json"),
            CheckBlock("audit.chk.json"),
            CrcBlock("crc.json"),
            WriteOutBlock("out.s19"),
            ReportBlock(),
            _flow_a2b_block("#2", "base.s19"),
        ],
    )

    envelope = fps.flow_to_dict(flow)
    assert envelope["schema_version"] == 1
    kinds = [b["kind"] for b in envelope["blocks"]]
    assert kinds == [
        "source", "patch", "check", "crc", "write_out", "report", "a2b",
    ]
    a2b_env = envelope["blocks"][6]
    assert a2b_env["image_a"] == {"source": "flow", "ref": "1"}
    assert a2b_env["image_b"] == {"source": "file", "ref": "base.s19"}

    loaded, findings = fps.dict_to_flow(envelope, project)
    assert findings == []
    assert loaded is not None
    assert loaded.schema_version == 1
    assert [b.kind for b in loaded.blocks] == kinds
    a2b = loaded.blocks[6]
    assert isinstance(a2b, A2BBlock)
    assert a2b.image_a == A2BInputBinding(source=A2B_INPUT_FLOW, ref="1")
    assert a2b.image_b == A2BInputBinding(source=A2B_INPUT_FILE, ref="base.s19")
    # The upstream blocks survive verbatim too (batch-95's a2l_ref grammar
    # untouched by the A2B addition).
    assert loaded.blocks[0].image_ref == "prg.s19"

    # Negative control (LLR-013.2): a foreign kind refuses fail-closed.
    envelope["blocks"].append({"kind": "shell", "cmd_ref": "run.bat"})
    refused, refuse_findings = fps.dict_to_flow(envelope, project)
    assert refused is None
    assert any(f.code == fps.FLOW_UNKNOWN_KIND for f in refuse_findings)


def test_tc_b94_21_loader_refuses_a2b_binding_arm(tmp_path: Path) -> None:
    """TC-B94-21 invalid arm (LLR-013.2/014.1): an A2B block whose bindings
    both point at files — illegal wiring — is refused AT LOAD (whole-flow
    fail-closed), never mounted; a binding object of the wrong shape and a
    file ref escaping the project are refused with the loader's own codes."""
    project = _make_project(tmp_path, {"prg.s19": _S19_A, "base.s19": _S19_A})

    def _envelope(image_a: dict, image_b: dict) -> dict:
        return {
            "schema_version": 1,
            "name": "bad-a2b",
            "blocks": [
                {"kind": "source", "image_ref": "prg.s19"},
                {
                    "kind": "a2b",
                    "image_a": image_a,
                    "image_b": image_b,
                },
            ],
        }

    both_external = _envelope(
        {"source": "file", "ref": "base.s19"},
        {"source": "file", "ref": "prg.s19"},
    )
    flow, findings = fps.dict_to_flow(both_external, project)
    assert flow is None
    assert any(f.code == fps.FLOW_BAD_FIELD for f in findings)

    malformed = _envelope({"source": "file"}, {"source": "flow", "ref": "0"})
    flow, findings = fps.dict_to_flow(malformed, project)
    assert flow is None
    assert any(f.code == fps.FLOW_BAD_FIELD for f in findings)

    escaping = _envelope(
        {"source": "flow", "ref": "0"},
        {"source": "file", "ref": "..\\..\\evil.s19"},
    )
    flow, findings = fps.dict_to_flow(escaping, project)
    assert flow is None
    assert any(
        f.code in (fps.FLOW_UNSAFE_REF, "MANIFEST-PATH-ESCAPE") for f in findings
    )


# --------------------------------------------------------------------------- #
# TC-B94-22 — headless two-block run + the C-1 skipped-arm policy
# --------------------------------------------------------------------------- #


def test_tc_b94_22_patch_write_out_run_records_per_block_results(
    tmp_path: Path,
) -> None:
    """TC-B94-22 (LLR-013.3): a headless patch → write-out run writes an image
    whose declared addresses 100% hold the patch's new bytes; every block's
    result is recorded (0 missing)."""
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_A,
            "hotfix.json": _patch_doc(
                [{"type": "bytes", "address": "0x1001", "bytes": "AA"}]
            ),
        },
    )
    flow = Flow(
        name="hotfix",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("hotfix.json"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.status == FLOW_STATUS_OK
    assert len(result.block_results) == len(flow.blocks)
    assert all(br.status == BLOCK_STATUS_OK for br in result.block_results)
    written = project / "out.s19"
    assert written.exists()
    mem_map = _reload(written)
    assert mem_map[0x1000] == 0x01  # untouched declared address
    assert mem_map[0x1001] == 0xAA  # 100% of the patch's addresses hold new bytes
    assert mem_map[0x1002] == 0x03


def test_tc_b94_22_upstream_crc_failure_skips_write_out(tmp_path: Path) -> None:
    """TC-B94-22 error arm + the C-1 re-arm (PDR-2026-10-12-batch-94#C-1):
    over the patch → CRC → write-out chain, a MISSING CRC config fails the
    CRC block closed; the write-out downstream reads ``skipped``; ZERO image
    files are written. Precedent: tests/test_flow_crc_block.py AT-126 — the
    authoring-time mutation 'a missing CRC config applies anyway' turns this
    node RED."""
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_A,
            "hotfix.json": _patch_doc(
                [{"type": "bytes", "address": "0x1001", "bytes": "AA"}]
            ),
            # NOTE: no crc.json — the CRC block's config is missing.
        },
    )
    flow = Flow(
        name="c1-arm",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("hotfix.json"),
            CrcBlock("crc.json"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert len(result.block_results) == len(flow.blocks)  # never raised
    assert result.block_results[2].status == BLOCK_STATUS_ERROR
    assert result.block_results[3].status == BLOCK_STATUS_SKIPPED
    assert result.status == FLOW_STATUS_ERROR
    assert not result.written_paths  # image un-injected, nothing written
    assert not (project / "out.s19").exists()


# --------------------------------------------------------------------------- #
# TC-B94-23 — the A2B binding accept/refuse matrix
# --------------------------------------------------------------------------- #


def test_tc_b94_23_binding_validation_matrix(tmp_path: Path) -> None:
    """TC-B94-23 (LLR-014.1): accepted (flow,flow) / (flow,file) / (file,flow);
    refused (file,file), out-of-range/downstream flow refs, and flow bindings
    to blocks that produce no image — a refused binding yields its reasons and
    never reaches the runner (0 reports)."""
    project = _make_project(tmp_path, {"prg.s19": _S19_A, "base.s19": _S19_A})
    upstream = [
        SourceBlock("prg.s19"),
        PatchBlock("hotfix.json"),
        _flow_a2b_block("#1", "base.s19"),  # produces a REPORT, not an image
    ]

    def _reasons(ref_a: str, ref_b: str, blocks=upstream) -> list[str]:
        return validate_a2b_bindings(_flow_a2b_block(ref_a, ref_b), blocks)

    # Accepted combos (the boundary arm is exactly one flow + one file).
    # 1-based canvas numbering: #1 = SOURCE, #2 = PATCH, #3 = the A2B itself.
    assert _reasons("#1", "#2") == []
    assert _reasons("#2", "base.s19") == []
    assert _reasons("base.s19", "#2") == []
    # Refused: both external.
    assert any("at least one" in r for r in _reasons("prg.s19", "base.s19"))
    # Refused: downstream / out-of-range references.
    assert any("upstream" in r or "only" in r for r in _reasons("#4", "base.s19"))
    # Refused: a flow binding onto a non-image-producing block (the A2B's
    # report output can never feed an image input).
    reasons = _reasons("#3", "base.s19")
    assert any("no image output" in r for r in reasons)
    # Sanity: the accepted (flow,file) binding RUNS and produces a report.
    flow = Flow(
        name="matrix-arm",
        blocks=[
            SourceBlock("prg.s19"),
            _flow_a2b_block("#1", "base.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.block_results[1].status == BLOCK_STATUS_OK
    assert list((project / "reports").glob("*flow-a2b*.md"))


def test_tc_b94_23_binding_text_grammar(tmp_path: Path) -> None:
    """TC-B94-23 grammar arm: ``#<n>`` (1-based, as numbered on the canvas)
    parses to a 0-based flow ref; any other non-empty text is a file ref;
    empty / ``#0`` / malformed hashes refuse (``None`` — never a block)."""
    assert parse_a2b_binding("#2") == A2BInputBinding(
        source=A2B_INPUT_FLOW, ref="1"
    )
    assert parse_a2b_binding("  base.s19 ") == A2BInputBinding(
        source=A2B_INPUT_FILE, ref="base.s19"
    )
    assert parse_a2b_binding("") is None
    assert parse_a2b_binding("   ") is None
    assert parse_a2b_binding("#0") is None
    assert parse_a2b_binding("#x") is None
    assert parse_a2b_binding("#") is None


# --------------------------------------------------------------------------- #
# TC-B94-24 — A2B report provenance lines (C-42 emitted form)
# --------------------------------------------------------------------------- #

#: The Phase-3 C-42 paste of the FLOW-output arm — what run_flow's A2B block
#: actually emits for a flow binding (provisional per V-5, pinned here).
_TC_B94_24_FLOW_ARM_PASTE = (
    "- Image A: patch.out [flow] path=`block 2 (patch).out` parse-errors=0"
)
#: The external arm's fixed parts — character-for-character against the
#: executed base form in evidence/p1_probe_diff_report_emitted.txt
#: (``- Image A: prg [external] path=`C:\…\prg.s19` parse-errors=0``).
_TC_B94_24_EXTERNAL_ARM_RE = re.compile(
    r"^- Image B: base \[external\] path=`.*[\\/]base\.s19` parse-errors=0$"
)


def test_tc_b94_24_a2b_report_states_each_inputs_provenance(tmp_path: Path) -> None:
    """TC-B94-24 (LLR-014.2, C-42): the flow-run A2B report emits exactly two
    provenance lines; the flow arm matches the increment's own Phase-3 paste
    character-for-character; the external arm matches the executed base form's
    fixed parts; the flow arm NAMES THE PRODUCING BLOCK."""
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_A,
            "base.s19": _S19_A,
            "hotfix.json": _patch_doc(
                [{"type": "bytes", "address": "0x1001", "bytes": "AA"}]
            ),
        },
    )
    flow = Flow(
        name="provenance",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("hotfix.json"),
            _flow_a2b_block("#2", "base.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[2].status == BLOCK_STATUS_OK
    reports = sorted((project / "reports").glob("*flow-a2b*.md"))
    assert len(reports) == 1
    text = reports[0].read_text(encoding="utf-8")
    provenance = [
        ln
        for ln in text.splitlines()
        if ln.startswith("- Image A:") or ln.startswith("- Image B:")
    ]
    assert len(provenance) == 2, provenance
    line_a, line_b = provenance
    # The flow arm: the increment's own paste, asserted character-for-character.
    assert line_a == _TC_B94_24_FLOW_ARM_PASTE, line_a
    assert "block 2 (patch).out" in line_a  # names the producing block
    # The external arm: the executed base form's fixed parts (C-42 lineage).
    assert _TC_B94_24_EXTERNAL_ARM_RE.match(line_b), line_b
    # The diff actually ran over the real images: the patched byte shows up
    # as a changed run starting at 0x00001001.
    assert "| 0x00001001 |" in text


def test_tc_b94_24_upstream_failure_yields_no_report(tmp_path: Path) -> None:
    """TC-B94-24 error arm (LLR-014.2): when the flow-bound source block
    failed, the A2B block errors ('flow output unavailable'), no report is
    produced, and the flow status is error."""
    project = _make_project(tmp_path, {"base.s19": _S19_A})
    flow = Flow(
        name="no-output",
        blocks=[
            SourceBlock("missing.s19"),  # fails: not inside the project
            _flow_a2b_block("#1", "base.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[0].status == BLOCK_STATUS_ERROR
    assert result.block_results[1].status == BLOCK_STATUS_SKIPPED
    assert result.status == FLOW_STATUS_ERROR
    assert not list((project / "reports").glob("*flow-a2b*.md"))


# --------------------------------------------------------------------------- #
# TC-B94-25 — markdown-safety mode truth table over the A2B report identity
# --------------------------------------------------------------------------- #

#: The batch-77 hostile payload family, re-derived locally (the hostile_map
#: idiom: a wrong class would produce a wrong expectation and a wrong result
#: that agree). The control-free sentinel survives both the correct scrub and
#: every mutation of it.
_SENTINEL = "b77hostilemark"
_HOSTILE_STEM = _SENTINEL + "_evil[red]"
#: A Windows-legal hostile file name (no control bytes — NTFS rejects those).
_HOSTILE_FILE_NAME = _HOSTILE_STEM + ".s19"


def test_tc_b94_25_md_safe_md_code_mode_truth_table(tmp_path: Path) -> None:
    """TC-B94-25 (LLR-016.1): the A2B report identity selection —
    a bare label (Mode A context) rides ``md_safe``; a code-span path rides
    ``md_code``; clean values pass through IDENTICALLY (the C-42 external arm
    is byte-preserved); a hostile file-derived name never emits raw markup in
    a Mode-A context and never carries a control byte."""
    clean_label = md_safe("base", limit=120)
    clean_path = md_code(str(tmp_path / "base.s19"))
    assert clean_label == "base"  # identity on clean values (C-42 preserved)
    assert clean_path.endswith("base.s19")

    hostile_label = md_safe(_HOSTILE_STEM, limit=120)
    assert _SENTINEL in hostile_label
    assert "[red]" not in hostile_label  # escaped, never raw in Mode A
    assert "\\[red\\]" in hostile_label
    hostile_path = md_code(str(tmp_path / _HOSTILE_FILE_NAME))
    assert _SENTINEL in hostile_path
    assert "\x1b" not in hostile_path and "\x00" not in hostile_path
    assert "`" not in hostile_path  # a backtick would break the code span

    # The emitted line shape stays well-formed for the hostile name.
    line = f"- Image B: {hostile_label} [external] path=`{hostile_path}` parse-errors=0"
    assert "\n" not in line and "\r" not in line


def test_tc_b94_25_hostile_file_name_in_emitted_report(tmp_path: Path) -> None:
    """TC-B94-25 hostile arm (LLR-016.1): a hostile (Windows-legal) file name
    bound to an A2B input renders in the EMITTED report with the sentinel
    visible, zero control bytes, and no unescaped markup in the Mode-A label
    cell; the producer raises nothing."""
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_A,
            _HOSTILE_FILE_NAME: _S19_A,
        },
    )
    flow = Flow(
        name="hostile",
        blocks=[
            SourceBlock("prg.s19"),
            _flow_a2b_block("#1", _HOSTILE_FILE_NAME),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[1].status == BLOCK_STATUS_OK
    reports = sorted((project / "reports").glob("*flow-a2b*.md"))
    assert len(reports) == 1
    raw = reports[0].read_bytes()
    text = raw.decode("utf-8")
    assert _SENTINEL in text
    # The Mode-A label (everything before the " [external]" kind tag) carries
    # the ESCAPED spelling — no raw markup; the code-span path (Mode B) keeps
    # the literal name inert inside the backticks.
    image_lines = [
        ln for ln in text.splitlines() if ln.startswith("- Image B:")
    ]
    assert len(image_lines) == 1, image_lines
    label_part = image_lines[0].split(" [external]")[0]
    assert "[red]" not in label_part
    assert "\\[red\\]" in label_part
    assert _HOSTILE_FILE_NAME in image_lines[0]  # literal inside the code span
    # Zero control bytes in the emitted report (the file's CRLF line-ending
    # convention is the producer's own, canonical_report_bytes idiom — the
    # hostile sweep runs on the newline-normalized bytes).
    normalized = raw.replace(bytes([13, 10]), bytes([10]))
    for byte in normalized:
        assert byte >= 0x20 or byte == 0x0A, hex(byte)


# --------------------------------------------------------------------------- #
# TC-B94-04 — template save / reload contract (LLR-015.1/015.2)
# --------------------------------------------------------------------------- #


def test_tc_b94_04_template_save_reload_and_dedup(tmp_path: Path) -> None:
    """TC-B94-04 (LLR-015.1/015.2): a saved template parses as the schema-v1
    envelope and reloads with equal block count + kinds; a name collision
    dedup-suffixes (``hotfix_2.json``) instead of clobbering — the first
    template's bytes are untouched; corrupt and oversized payloads are refused
    fail-closed (0 blocks mounted + findings)."""
    project = _make_project(tmp_path, {"prg.s19": _S19_A, "base.s19": _S19_A})
    flow_one = Flow(
        name="hotfix",
        blocks=[SourceBlock("prg.s19"), _flow_a2b_block("#1", "base.s19")],
    )
    flow_two = Flow(
        name="hotfix",
        blocks=[SourceBlock("base.s19"), WriteOutBlock("out.s19")],
    )

    first = fps.save_flow_json(flow_one, "hotfix", project)
    assert first is not None and first.name == "hotfix.json"
    envelope = json.loads(first.read_text(encoding="utf-8"))
    assert envelope["schema_version"] == 1
    assert envelope["name"] == "hotfix"
    assert [b["kind"] for b in envelope["blocks"]] == ["source", "a2b"]

    second = fps.save_flow_json(flow_two, "hotfix", project)
    assert second is not None and second.name == "hotfix_2.json"
    # The first template is NOT clobbered (LLR-015.1 negative control); its
    # A2B binding points at the source block (``#1`` → stored ref "0").
    reloaded_first, findings = fps.load_flow_json(first, project)
    assert findings == []
    assert [b.kind for b in reloaded_first.blocks] == ["source", "a2b"]
    assert reloaded_first.blocks[1].image_a.ref == "0"
    # The dedup-suffixed template reloads its OWN blocks.
    reloaded_second, findings = fps.load_flow_json(second, project)
    assert findings == []
    assert [b.kind for b in reloaded_second.blocks] == ["source", "write_out"]
    assert fps.list_saved_flows(project) == ["hotfix", "hotfix_2"]

    # Corrupt payload refused fail-closed (LLR-015.2).
    corrupt = project / "flows" / "corrupt.json"
    corrupt.write_text("{ not json", encoding="utf-8")
    loaded, corrupt_findings = fps.load_flow_json(corrupt, project)
    assert loaded is None
    assert any(f.code == fps.FLOW_JSON_PARSE for f in corrupt_findings)

    # Oversized payload refused at the size probe.
    oversized = project / "flows" / "oversized.json"
    oversized.write_bytes(b" " * (fps.FLOW_SIZE_CAP_BYTES + 1))
    loaded, size_findings = fps.load_flow_json(oversized, project)
    assert loaded is None
    assert any(f.code == fps.FLOW_SIZE_CAP for f in size_findings)


def test_tc_b94_04_zero_block_template_saves(tmp_path: Path) -> None:
    """TC-B94-04 empty arm (LLR-015.1): a zero-block flow SAVES as the
    schema-v1 envelope. Its reload refusal is the pre-existing batch-53 V4
    law (``flow has no blocks`` → FLOW-BAD-STRUCTURE, pinned by that batch's
    security battery) — the V1–V7 fail-closed discipline this increment does
    not re-open; recorded in the increment packet."""
    project = _make_project(tmp_path, {})
    saved = fps.save_flow_json(Flow(name="empty", blocks=[]), "empty", project)
    assert saved is not None and saved.exists()
    envelope = json.loads(saved.read_text(encoding="utf-8"))
    assert envelope["schema_version"] == 1
    assert envelope["blocks"] == []
    # The V4 reload law (batch-53) — unchanged by this increment.
    loaded, findings = fps.load_flow_json(saved, project)
    assert loaded is None
    assert any(f.code == fps.FLOW_BAD_STRUCTURE for f in findings)


def test_tc_b94_04_name_sanitiser_is_the_write_authority(tmp_path: Path) -> None:
    """TC-B94-04 containment arm (LLR-015.1): the sanitised name is the file
    identity — a hostile raw name neither escapes the flows/ folder nor
    stops at the save boundary un-sanitised."""
    project = _make_project(tmp_path, {})
    saved = fps.save_flow_json(
        Flow(name="n", blocks=[SourceBlock("prg.s19")]),
        "../../evil name!",
        project,
    )
    assert saved is not None
    assert saved.parent == project / "flows"
    assert sanitize_project_name("../../evil name!") == saved.stem
    assert fps.list_saved_flows(project) == [saved.stem]
