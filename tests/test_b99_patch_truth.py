"""batch-99 Increment 8 — HLR-156: PATCH status and run records say what was
not applied (TC-B99-17..20, AT-B99-06/07).

TC-B99-18 riders arm (DDR finding F-2): one lane whose PATCH and CRC steps both
end ``notices`` paints BOTH clipped riders — the ``PATCH: … not applied`` note
and the ``CRC: … region bytes absent`` note — plus the ``wrote …`` segment on
its terminal line.

The 8-case matrix ports the ``rw-p01`` / ``rw-p06`` probes (P-4, P-13, P-14):
a flow PATCH arm used to report ``ok`` — ``applied 0 entries`` — for an
out-of-image, straddling, wrong-kind, v1 or malformed change document, and the
chain-set / flow reports reduced the run to ``Status: CLEAN``. HLR-156 derives
the PATCH status from the arm's dispositions and refusals (``error`` /
``notices`` / ``ok``, first match wins), stops the flow before any later
WRITE-OUT on ``error``, and makes every run record list what was not applied.

Every byte comparison against a written image uses the independent reader
(``tests/support/independent_reader.py``), never the app's own loader.

Traceability: LLR-156.1..156.4 · TC-B99-17..20 · AT-B99-06/07 · UX-C1/UX-C2/
UX-C3/UX-C10/PQ-7.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from s19_app.tui.changes.model import DISPOSITION_APPLIED
from s19_app.tui.services.flow_execution_service import (
    ChainSpec,
    compose_chain_set_report,
    run_chain_set,
    run_flow,
)
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    FINDING_WARN,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    CrcBlock,
    Flow,
    FlowContext,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.markdown_safety import md_safe
from tests.b97_fixtures import write_flow
from tests.b97_probes import painted_rows, settle
from tests.support.independent_reader import read_s19
from tests.support.b100_projects import dismiss_load_result_panel

REPO_ROOT = Path(__file__).resolve().parent.parent
#: The public example image (no S0 record) the rw-p0x probes ran against —
#: 11 ranges ending at 0x10000, so 0x20000 is outside and 0xFFFE straddles.
_PRG_S19 = REPO_ROOT / "examples" / "case_00_public" / "prg.s19"

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _project(tmp_path: Path) -> Path:
    """A project dir inside the ``.s19tool/workarea`` tree (the WRITE-OUT
    containment contract), holding a copy of the probe image."""
    project = tmp_path / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True)
    shutil.copyfile(_PRG_S19, project / "prg.s19")
    return project


def _bytes_entry(address: int, hex_bytes: str, symbol: str | None = None) -> dict:
    entry = {"type": "bytes", "address": f"0x{address:X}", "bytes": hex_bytes}
    if symbol is not None:
        entry["symbol"] = symbol
    return entry


def _doc(entries: list, kind: str = "change") -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": kind,
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        },
        indent=2,
    ) + "\n"


#: The case-3/case-4 pair: one in-image entry + one outside.
_MIX_ENTRIES = [_bytes_entry(0xEB10, "DE AD"), _bytes_entry(0x20000, "01 02 03 04")]
#: The p06b document (written one-line, exactly as the probe did): two good
#: entries + one symbol entry under no declared A2L — the read refuses the
#: symbol (``CHG-SYMBOL-UNRESOLVED``) and blocks the whole document.
_BLOCKED_DOC = json.dumps(
    {
        "format": "s19app-changeset",
        "version": "2.0",
        "kind": "change",
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": [
            _bytes_entry(0xEB10, "DE AD"),
            _bytes_entry(0xEB40, "01"),
            _bytes_entry(0xEC00, "FF", symbol="NO_SUCH"),
        ],
    }
)
#: Case 5 — the retired v1 unified shape (LLR-001.8's ``CHG-V1-FORMAT``).
_V1_RAW = (
    '{"format": "s19app-unified-changeset", "parameters": [], '
    '"memory": [{"address": "0xEB10", "bytes": "DE AD"}]}'
)
#: Case 6 — a truncated document (``MF-JSON-PARSE``).
_MALFORMED_RAW = '{"format": "s19app-changeset", "version": "2.0", "entries": [ {"type":"bytes"'

#: The 8-case matrix of HLR-156's numeric pass threshold (outside, straddle,
#: one-in-one-out, wrong-kind document, v1, malformed, two good + one
#: unresolved symbol, all applied) → expected PATCH status.
_MATRIX = [
    ("outside", _doc([_bytes_entry(0x20000, "01 02 03 04")]), "error"),
    ("straddle", _doc([_bytes_entry(0xFFFE, "AA BB CC DD")]), "error"),
    ("one_in_one_out", _doc(_MIX_ENTRIES), "notices"),
    ("kind_check", _doc(_MIX_ENTRIES, kind="check"), "error"),
    ("v1", _V1_RAW, "error"),
    ("malformed", _MALFORMED_RAW, "error"),
    ("blocked_symbol", _BLOCKED_DOC, "error"),
    ("all_applied", _doc([_bytes_entry(0xEB10, "DE AD")]), "ok"),
]


def _run_case(project: Path, name: str):
    return run_flow(
        Flow(
            name=name,
            blocks=[
                SourceBlock("prg.s19"),
                PatchBlock(f"{name}.json"),
                WriteOutBlock(f"out_{name}.s19"),
            ],
        ),
        FlowContext(project_dir=project),
    )


@pytest.mark.parametrize("name, content, expected", _MATRIX, ids=[c[0] for c in _MATRIX])
def test_tc_b99_17_patch_status_matrix(tmp_path: Path, name: str, content: str, expected: str) -> None:
    """TC-B99-17 (LLR-156.1): the 8-case matrix → ``error, error, notices,
    error, error, error, error, ok``; 0 WRITE-OUT files after ``error``; the
    notices run writes an image holding only the applied entry (independent
    reader), and ``notices``/``error`` stop nothing the rule does not name."""
    project = _project(tmp_path)
    (project / f"{name}.json").write_text(content, encoding="utf-8")
    result = _run_case(project, name)
    patch = result.block_results[1]
    out_path = project / f"out_{name}.s19"
    if expected == "error":
        assert result.status == FLOW_STATUS_ERROR, (name, result.status)
        assert patch.status == BLOCK_STATUS_ERROR, (name, patch.status, patch.summary)
        assert result.written_paths == [], (name, result.written_paths)
        assert not out_path.exists(), f"{name}: WRITE-OUT ran after the PATCH error"
        assert result.block_results[2].status == BLOCK_STATUS_SKIPPED
    elif expected == "notices":
        assert result.status == FLOW_STATUS_ISSUES, (name, result.status)
        assert patch.status == BLOCK_STATUS_NOTICES, (name, patch.status, patch.summary)
        assert out_path.exists(), f"{name}: the notices run must still WRITE-OUT"
        image = read_s19(out_path)
        assert image.data[0xEB10] == 0xDE and image.data[0xEB11] == 0xAD
        assert 0x20000 not in image.data, "the not-applied entry reached the image"
    else:
        assert result.status == FLOW_STATUS_OK, (name, result.status)
        assert patch.status == BLOCK_STATUS_OK, (name, patch.status, patch.summary)
        assert out_path.exists(), f"{name}: the clean run must WRITE-OUT"


def test_tc_b99_17_error_cause_is_the_last_diagnostic(tmp_path: Path) -> None:
    """TC-B99-17 (LLR-156.1, UX-C2): the PATCH ``error`` block's LAST
    diagnostic is the user-facing cause — count, first address and
    disposition — never an incidental line."""
    project = _project(tmp_path)
    (project / "outside.json").write_text(
        _doc([_bytes_entry(0x20000, "01 02 03 04")]), encoding="utf-8"
    )
    result = _run_case(project, "outside")
    patch = result.block_results[1]
    assert patch.diagnostics, "an error block records its cause"
    assert patch.diagnostics[-1] == (
        "applied 0 of 1 entries: 0x00020000 skipped-outside"
    ), patch.diagnostics
    assert patch.summary == "applied 0 of 1 entries"


def test_tc_b99_17_named_refusals_are_retained(tmp_path: Path) -> None:
    """TC-B99-17 (LLR-156.1): every matrix refusal is named in the run's own
    record — v1, malformed and the unresolved symbol — each such arm is an
    ``error`` that wrote nothing, and the document-block case blocks every
    entry it carried."""
    project = _project(tmp_path)
    (project / "v1.json").write_text(_V1_RAW, encoding="utf-8")
    (project / "malformed.json").write_text(_MALFORMED_RAW, encoding="utf-8")
    (project / "blocked_symbol.json").write_text(_BLOCKED_DOC, encoding="utf-8")
    codes = {}
    for name in ("v1", "malformed", "blocked_symbol"):
        result = _run_case(project, name)
        codes[name] = [r.code for r in result.refusals if r.block_index == 1]
        assert result.status == FLOW_STATUS_ERROR, (name, result.status)
        assert result.written_paths == [], (name, result.written_paths)
    assert codes["v1"] == ["CHG-V1-FORMAT"], codes
    assert codes["malformed"] == ["MF-JSON-PARSE"], codes
    assert codes["blocked_symbol"] == ["CHG-SYMBOL-UNRESOLVED"], codes
    blocked = _run_case(project, "blocked_symbol")
    dispositions = [r.disposition for r in blocked.change_records]
    assert dispositions == ["blocked", "blocked"], dispositions
    assert blocked.change_records[0].before_bytes is None


def test_tc_b99_17_empty_document_is_ok(tmp_path: Path) -> None:
    """TC-B99-17 (LLR-156.1, QC-3 boundary catalog): a document with 0 entries
    applies nothing, reports nothing and stays ``ok``."""
    project = _project(tmp_path)
    (project / "empty.json").write_text(_doc([]), encoding="utf-8")
    result = _run_case(project, "empty")
    assert result.status == FLOW_STATUS_OK, result.status
    assert result.block_results[1].status == BLOCK_STATUS_OK
    assert result.change_records == [] and result.refusals == []
    assert (project / "out_empty.s19").exists()


_THREE_NOT_APPLIED = _doc(
    [
        _bytes_entry(0xEB10, "DE AD"),
        _bytes_entry(0x20000, "01 02"),
        _bytes_entry(0x20010, "03 04"),
        _bytes_entry(0xFFFE, "AA BB CC"),
    ]
)


def test_tc_b99_17_diagnostics_name_every_non_applied_address(tmp_path: Path) -> None:
    """TC-B99-17 (LLR-156.1, batch-99 Inc-8 review fix F3, re-pinned by review
    round 2 fix N1): the ``notices`` arm's not-applied lines name EVERY
    non-applied address with its disposition as ``FINDING_WARN`` findings
    (the funnel arm's idiom — Flow Builder paints ``diagnostics`` as
    ``sev-error``, a notices arm is not an error), and the ``error`` arm's
    diagnostics name every non-applied address and refusal code — 3
    non-applied entries (2 outside + 1 straddling) in the ``notices`` arm:
    all 3 addresses paint as warnings; the same 3 with 0 applied: all 3 in
    the diagnostics, the cause LAST (UX-C2); the unresolved-symbol arm:
    ``CHG-SYMBOL-UNRESOLVED`` named."""
    project = _project(tmp_path)
    (project / "triple.json").write_text(_THREE_NOT_APPLIED, encoding="utf-8")
    result = _run_case(project, "triple")
    patch = result.block_results[1]
    assert result.status == FLOW_STATUS_ISSUES, result.status
    assert patch.status == BLOCK_STATUS_NOTICES, patch.status
    assert patch.diagnostics == [], patch.diagnostics
    finding_lines = [finding.message for finding in patch.findings]
    assert patch.findings and all(
        finding.severity == FINDING_WARN for finding in patch.findings
    ), patch.findings
    for needle in (
        "0x00020000 skipped-outside",
        "0x00020010 skipped-outside",
        "0x0000FFFE skipped-partial",
    ):
        assert needle in finding_lines, (needle, finding_lines)
    # The error arm (0 applied): the same census, cause LAST (UX-C2).
    (project / "all_out.json").write_text(
        _doc(
            [
                _bytes_entry(0x20000, "01 02"),
                _bytes_entry(0x20010, "03 04"),
                _bytes_entry(0xFFFE, "AA BB CC"),
            ]
        ),
        encoding="utf-8",
    )
    failed = _run_case(project, "all_out")
    fail_patch = failed.block_results[1]
    assert failed.status == FLOW_STATUS_ERROR, failed.status
    assert fail_patch.status == BLOCK_STATUS_ERROR, fail_patch.status
    assert fail_patch.diagnostics[-1] == (
        "applied 0 of 3 entries: 0x00020000 skipped-outside"
    ), fail_patch.diagnostics
    assert len(fail_patch.diagnostics) == 4, fail_patch.diagnostics
    for needle in (
        "0x00020000 skipped-outside",
        "0x00020010 skipped-outside",
        "0x0000FFFE skipped-partial",
    ):
        assert needle in fail_patch.diagnostics, (needle, fail_patch.diagnostics)
    # The refusal arm: every refusal code named in the diagnostics.
    (project / "blocked_symbol.json").write_text(_BLOCKED_DOC, encoding="utf-8")
    blocked = _run_case(project, "blocked_symbol")
    block_patch = blocked.block_results[1]
    assert block_patch.status == BLOCK_STATUS_ERROR, block_patch.status
    assert any(
        ln.startswith("[CHG-SYMBOL-UNRESOLVED]") for ln in block_patch.diagnostics
    ), block_patch.diagnostics


def test_tc_b99_17_notices_lines_paint_warning(tmp_path: Path) -> None:
    """TC-B99-17 (LLR-156.1, review round 2 fix N1): a ``notices`` PATCH arm's
    not-applied lines ride ``findings`` as ``FINDING_WARN`` — the funnel arm's
    idiom — never ``diagnostics``: Flow Builder paints findings
    ``sev-warning`` and diagnostics ``sev-error``, so service-side every line
    is a WARN finding with ``diagnostics`` left empty, and painted the PATCH
    node's address lines carry the warning severity class with no
    ``sev-error`` line. The ``error`` arm keeps its census and its cause LAST
    in ``diagnostics`` (UX-C2) — the channel is not abolished, it stays the
    error arm's."""
    project = _project(tmp_path)
    (project / "triple.json").write_text(_THREE_NOT_APPLIED, encoding="utf-8")
    result = _run_case(project, "triple")
    patch = result.block_results[1]
    assert result.status == FLOW_STATUS_ISSUES, result.status
    assert patch.status == BLOCK_STATUS_NOTICES, patch.status
    assert patch.diagnostics == [], patch.diagnostics
    finding_lines = [finding.message for finding in patch.findings]
    assert patch.findings and all(
        finding.severity == FINDING_WARN for finding in patch.findings
    ), patch.findings
    for needle in (
        "0x00020000 skipped-outside",
        "0x00020010 skipped-outside",
        "0x0000FFFE skipped-partial",
    ):
        assert needle in finding_lines, (needle, finding_lines)
    # The error arm is untouched: the same census stays in ``diagnostics``
    # with the cause LAST (UX-C2).
    (project / "all_out.json").write_text(
        _doc(
            [
                _bytes_entry(0x20000, "01 02"),
                _bytes_entry(0x20010, "03 04"),
                _bytes_entry(0xFFFE, "AA BB CC"),
            ]
        ),
        encoding="utf-8",
    )
    failed = _run_case(project, "all_out")
    fail_patch = failed.block_results[1]
    assert failed.status == FLOW_STATUS_ERROR, failed.status
    assert fail_patch.status == BLOCK_STATUS_ERROR, fail_patch.status
    assert len(fail_patch.diagnostics) == 4, fail_patch.diagnostics
    assert fail_patch.diagnostics[-1] == (
        "applied 0 of 3 entries: 0x00020000 skipped-outside"
    ), fail_patch.diagnostics

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await settle(pilot)
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)
            panel._blocks = [
                SourceBlock("prg.s19"),
                PatchBlock("triple.json"),
                WriteOutBlock("out_triple.s19"),
            ]
            app.query_one("#flow_run", Button).press()
            for _ in range(100):
                await pilot.pause()
                if len(list(app.query("#flow_result .flow-node"))) >= 3:
                    break
            else:
                raise AssertionError("Flow Builder never painted the run")
            patch_node = list(app.query("#flow_result .flow-node"))[1]
            finding_widgets = list(patch_node.query(".flow-finding"))
            diag_widgets = list(patch_node.query(".flow-diag"))
            painted = [w.render().plain for w in finding_widgets]
            warn_classes = [
                w.has_class("sev-warning") and not w.has_class("sev-error")
                for w in finding_widgets
            ]
            return painted, warn_classes, diag_widgets

    painted, warn_classes, diag_widgets = asyncio.run(_drive())
    assert painted, "the notices PATCH node painted no finding lines"
    assert all(warn_classes), warn_classes
    for needle in (
        "0x00020000 skipped-outside",
        "0x00020010 skipped-outside",
        "0x0000FFFE skipped-partial",
    ):
        assert any(needle in line for line in painted), (needle, painted)
    assert diag_widgets == [], (
        "a notices PATCH line painted through the sev-error diagnostics sink"
    )


# --------------------------------------------------------------------------- #
# TC-B99-18 — LLR-156.2, the chain outcome carries dispositions
# --------------------------------------------------------------------------- #


def _chain(project: Path, name: str, doc: str, output: str) -> ChainSpec:
    return ChainSpec(
        name=name,
        template=name,
        flow=Flow(
            name=name,
            blocks=[
                SourceBlock("prg.s19"),
                PatchBlock(doc),
                WriteOutBlock(output),
            ],
        ),
        bindings={},
    )


def test_tc_b99_18_chain_outcome_carries_refusals(tmp_path: Path) -> None:
    """TC-B99-18 (LLR-156.2): a malformed-document lane's outcome holds
    ``MF-JSON-PARSE`` in ``refusals``, carries the image footprint, and its
    PATCH block is ``error``. (The lane cell's painted error glyph is
    asserted on the painted cell by AT-B99-06 — review fix F5 dropped this
    arm's constant-map read of ``_FX_BLOCK_STYLE``.)"""
    project = _project(tmp_path)
    (project / "bad.json").write_text("{nope", encoding="utf-8")
    record = run_chain_set(
        [_chain(project, "badlane", "bad.json", "bad_out.s19")],
        FlowContext(project_dir=project),
    )
    outcome = record.outcomes[0]
    assert outcome.status == FLOW_STATUS_ERROR
    assert [r.code for r in outcome.refusals] == ["MF-JSON-PARSE"], outcome.refusals
    assert outcome.change_records == []
    assert outcome.image_ranges, "the outcome carries the image footprint"
    patch = outcome.block_results[1]
    assert patch.status == BLOCK_STATUS_ERROR
    assert patch.diagnostics[-1].startswith("[MF-JSON-PARSE]")
    assert record.report_path is not None


def test_tc_b99_18_chain_outcome_carries_change_records(tmp_path: Path) -> None:
    """TC-B99-18 (LLR-156.2): the notices lane's outcome carries every entry
    the PATCH arm read — applied and not applied — in document order."""
    project = _project(tmp_path)
    (project / "mix.json").write_text(_doc(_MIX_ENTRIES), encoding="utf-8")
    record = run_chain_set(
        [_chain(project, "mixlane", "mix.json", "mix_out.s19")],
        FlowContext(project_dir=project),
    )
    outcome = record.outcomes[0]
    assert outcome.status == FLOW_STATUS_ISSUES
    assert [(r.address_start, r.disposition) for r in outcome.change_records] == [
        (0xEB10, "applied"),
        (0x20000, "skipped-outside"),
    ], outcome.change_records
    assert outcome.written_paths and outcome.written_paths[0].name == "mix_out.s19"


# --------------------------------------------------------------------------- #
# TC-B99-18 (DDR finding F-2) — one lane carries BOTH terminal-line riders
# --------------------------------------------------------------------------- #


def test_tc_b99_18_lane_line_carries_patch_and_crc_riders(tmp_path: Path) -> None:
    """TC-B99-18 (DDR finding F-2, Phase-4 coverage gap): a lane whose PATCH
    ends ``notices`` (one entry applied, one ``skipped-outside``) and whose
    CRC step ends ``notices`` (a legacy region straddling the 0xFA2E-0xFCB0
    gap) paints BOTH separately-clipped riders on its terminal log line —
    the UX-C1 ``PATCH: … not applied (0x… skipped-outside)`` note AND the
    UX-C2 ``CRC: … of … region bytes absent`` note (absent count computed
    independently from the reader's map) — followed by the ``wrote …``
    segment, and still writes the file. The app appends the riders and never
    overwrites; no other test drove a lane carrying both."""
    docs = {
        "mix.json": _doc(_MIX_ENTRIES),
        "partial_crc.json": json.dumps(
            {
                "polynomial": "0x04C11DB7",
                "init": "0xFFFFFFFF",
                "reverse": True,
                "final_xor": "0xFFFFFFFF",
                "regions": [
                    {
                        "start": "0x0000FA00",
                        "end": "0x0000FC00",
                        "output_address": "0x0000FC00",
                    }
                ],
            }
        ),
    }
    flows = {
        "b99_r": [
            SourceBlock("prg.s19"),
            PatchBlock("mix.json"),
            CrcBlock("partial_crc.json"),
            WriteOutBlock("o.s19"),
        ],
    }
    project_dir = _stage_project(tmp_path, "proj1", docs, flows)
    oracle = read_s19(_PRG_S19)
    absent = sum(1 for addr in range(0xFA00, 0xFC00) if addr not in oracle.data)

    async def body(app, pilot):
        await _load_project_dialog(app, pilot, "proj1")
        panel = await _open_flow_execution_key(app, pilot)
        await _import_flow_picker(app, pilot, "b99_r", 0)
        await _run_until_heads(app, pilot, {0: "◇"})
        return "\n".join(painted_rows(app, panel.query_one("#fx_log")))

    # Wider than ``_run_fx``'s 220: both clipped riders plus the ``wrote …``
    # segment push the terminal line past 220 cells (the F-2 gap itself).
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(280, 60)) as pilot:
            await settle(pilot)
            return await body(app, pilot)

    log = asyncio.run(drive())

    # Both riders ride the same painted terminal line, then the write segment.
    assert "PATCH: 1 of 2 entries not applied (0x00020000 skipped-outside)" in log
    assert f"CRC: {absent} of 512 region bytes absent (0xFA00-0xFC00)" in log
    assert "wrote o.s19" in log
    assert (project_dir / "o.s19").exists(), "the notices lane must still WRITE-OUT"


# --------------------------------------------------------------------------- #
# TC-B99-19 — LLR-156.3, the chain-set report lists what was not applied
# --------------------------------------------------------------------------- #

_HOSTILE_DOC = "we[red]ird.json"


def test_tc_b99_19_chain_set_report_lists_what_was_not_applied(tmp_path: Path) -> None:
    """TC-B99-19 (LLR-156.3): per lane the report lists the written paths, each
    non-applied entry (address + disposition) and each refusal (code), a clean
    lane lists ``none``, and every file-derived field rides ``md_safe`` /
    ``md_code`` (the hostile change-doc name appears escaped, never raw)."""
    project = _project(tmp_path)
    (project / "mix.json").write_text(_doc(_MIX_ENTRIES), encoding="utf-8")
    (project / "bad.json").write_text("{nope", encoding="utf-8")
    (project / "good.json").write_text(
        _doc([_bytes_entry(0xEB10, "DE AD")]), encoding="utf-8"
    )
    (project / _HOSTILE_DOC).write_text(
        _doc([_bytes_entry(0x20000, "01")]), encoding="utf-8"
    )
    chains = [
        _chain(project, "mix", "mix.json", "out_mix.s19"),
        _chain(project, "bad", "bad.json", "out_bad.s19"),
        _chain(project, "good", "good.json", "out_good.s19"),
        _chain(project, "hostile", _HOSTILE_DOC, "out_hostile.s19"),
    ]
    record = run_chain_set(chains, FlowContext(project_dir=project))
    text = compose_chain_set_report(
        record, "b99 truth set", datetime(2026, 10, 25, tzinfo=timezone.utc)
    )
    # 100 % of non-applied addresses, refusal codes and written paths.
    assert "0x00020000" in text and "skipped-outside" in text
    assert "MF-JSON-PARSE" in text
    assert "out_mix.s19" in text and "out_good.s19" in text
    assert "out_bad.s19" not in text, "the error lane wrote nothing"
    # Clean lanes list `none`; sections are always present. RE-PINNED
    # (batch-99 Inc-5 review fix F1, LLR-159.2): the chain-set report gained
    # the always-present `## Notices` section (advisory block findings), so
    # the clean lane now lists `none` in three sections (old value: 2; new
    # value: 3).
    assert "## Not applied" in text and "## Refusals" in text and "## Written files" in text
    assert text.count("- Chain good: none") == 3, text
    # The hostile change-doc name is file-derived: escaped, never raw.
    assert md_safe(_HOSTILE_DOC, limit=120) in text
    assert _HOSTILE_DOC not in text


# --------------------------------------------------------------------------- #
# TC-B99-20 — LLR-156.4, the flow report lists what was not applied
# --------------------------------------------------------------------------- #


def _flow_report(project: Path, flow_name: str, doc: str):
    """Run SOURCE → PATCH → WRITE-OUT → REPORT and return the newest report."""
    reports_dir = project / "reports"
    before = set(reports_dir.glob("*.md")) if reports_dir.exists() else set()
    result = run_flow(
        Flow(
            name=flow_name,
            blocks=[
                SourceBlock("prg.s19"),
                PatchBlock(doc),
                WriteOutBlock("o.s19"),
                ReportBlock(),
            ],
        ),
        FlowContext(project_dir=project),
    )
    new = set(reports_dir.glob("*.md")) - before
    assert len(new) == 1, f"expected exactly one new report, got {new}"
    return result, next(iter(new)).read_text(encoding="utf-8")


def test_tc_b99_20_flow_report_lists_what_was_not_applied(tmp_path: Path) -> None:
    """TC-B99-20 (LLR-156.4): ``mix.json`` → the report names ``0x00020000``
    and ``skipped-outside``; ``bad.json`` → names ``MF-JSON-PARSE``; neither
    says ``CLEAN``; a clean run still says ``CLEAN`` with both sections
    reading ``none`` (the always-present sections, LLR-156.4's boundary)."""
    project = _project(tmp_path)
    (project / "bad.json").write_text("{nope", encoding="utf-8")
    (project / "mix.json").write_text(_doc(_MIX_ENTRIES), encoding="utf-8")
    (project / "good.json").write_text(
        _doc([_bytes_entry(0xEB10, "DE AD")]), encoding="utf-8"
    )

    bad, bad_text = _flow_report(project, "bad", "bad.json")
    assert bad.status == FLOW_STATUS_ERROR
    assert "## Not applied" in bad_text and "## Refusals" in bad_text
    assert "MF-JSON-PARSE" in bad_text
    assert "- **Status:** CLEAN" not in bad_text
    assert not (project / "o.s19").exists(), "the PATCH error stopped WRITE-OUT"

    mix, mix_text = _flow_report(project, "mix", "mix.json")
    assert mix.status == FLOW_STATUS_ISSUES
    assert "## Not applied" in mix_text and "## Refusals" in mix_text
    assert "0x00020000" in mix_text and "skipped-outside" in mix_text
    assert "- **Status:** CLEAN" not in mix_text
    assert (project / "o.s19").exists(), "notices must not stop WRITE-OUT"

    good, good_text = _flow_report(project, "good", "good.json")
    assert good.status == FLOW_STATUS_OK
    assert "- **Status:** CLEAN" in good_text
    assert "## Not applied" in good_text and "## Refusals" in good_text
    assert "- none" in good_text


# --------------------------------------------------------------------------- #
# AT-B99-06 / AT-B99-07 — the pilot arms (Flow Execution, `#fx_run`)
# --------------------------------------------------------------------------- #

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.flow_screens import FlowBuilderPanel  # noqa: E402
from textual.widgets import Button  # noqa: E402


def _payload_spans(renderable) -> list:
    """Spans a markup parser would create from a hostile payload (the b97 idiom)."""
    from rich.text import Text as _Text
    from textual.content import Content

    if isinstance(renderable, str):
        try:
            renderable = Content.from_markup(renderable)
        except Exception as exc:  # noqa: BLE001 - a markup error is a payload effect
            return [f"markup error: {type(exc).__name__}"]
    if not isinstance(renderable, (_Text, Content)):
        return []
    found = []
    for span in renderable.spans:
        style = str(span.style)
        if style in ("bold", "red") or "link" in style or "@click" in style or "meta" in style:
            found.append(style)
    return found


def _fx_reports(project_dir: Path) -> list:
    return [
        path
        for path in (project_dir / "reports").glob("*.md")
        if "chain-set" not in path.name
    ]


# --------------------------------------------------------------------------- #
# Black-box pilot helpers (batch-99 Inc-8 review fix F2): the project loads
# through the Load project dialog, Flow Execution opens by its rail key, the
# flow picker and Run are clicked — no ``_handle_load_project``,
# ``action_show_screen``, ``Button.press()`` or attribute reads anywhere.
# --------------------------------------------------------------------------- #


def _status_text(app) -> str:
    """The painted newest status line (``#log_line_4``, the test_b99_s0 idiom)."""
    from textual.widgets import Label

    return str(app.query_one("#log_line_4", Label).render())


def _stage_project(
    tmp_path: Path, name: str, docs: dict, flows: dict
) -> Path:
    """Write the project folder on disk (setup only): the workarea project
    dir with a copy of the probe image, the change documents and the flow
    templates."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True)
    shutil.copyfile(_PRG_S19, project_dir / "prg.s19")
    for doc_name, content in docs.items():
        (project_dir / doc_name).write_text(content, encoding="utf-8")
    for stem, blocks in flows.items():
        write_flow(project_dir, stem, blocks)
    return project_dir


async def _load_project_dialog(app, pilot, name: str) -> None:
    """Load ``name`` through the Load project dialog: rail key ``p``, click
    the named item in ``#project_list``, confirm with ``#project_ok``."""
    from textual.widgets import Label

    await pilot.press("p")
    for _ in range(20):
        await pilot.pause()
        if app.screen.query("#project_list"):
            break
    else:
        raise AssertionError("the Load project dialog did not open")
    target, labels = None, []
    for item in app.screen.query("#project_list ListItem"):
        label = str(item.query_one(Label).render())
        labels.append(label)
        if label.strip() == name:
            target = item
    assert target is not None, f"{name} is not listed: {labels}"
    target.scroll_visible(animate=False)
    await pilot.pause()
    await pilot.pause()
    # The click return value is informational (the child Label sits under the
    # pointer); the outcome is verified by the load status line below.
    await pilot.click(target)
    await pilot.pause()
    assert await pilot.click("#project_ok"), "click missed #project_ok"
    for _ in range(100):
        await pilot.pause()
        if f"Loaded project '{name}'" in _status_text(app):
            # Inc 6 (HLR-178): the dialog route opens the Load-result panel;
            # dismiss it first with its shown key ``esc``.
            await dismiss_load_result_panel(pilot, app)
            return
    raise AssertionError(f"project {name} did not load")


async def _open_flow_execution_key(app, pilot) -> object:
    """Open Flow Execution by its rail key (``]``) and wait until the panel
    paints (any non-empty painted row)."""
    await pilot.press("right_square_bracket")
    panel = app.query_one("#fx_panel")
    for _ in range(100):
        await pilot.pause()
        if any(r.strip() for r in painted_rows(app, panel)):
            return panel
    raise AssertionError("Flow Execution never painted")


async def _import_flow_picker(app, pilot, stem: str, lane: int) -> None:
    """Import ``flows/<stem>.json`` as lane ``lane`` through ``#fx_import``
    and the picker: click the stem's item in ``#flow_list``, confirm with
    ``#flow_load_ok``, wait for the lane to mount."""
    from textual.widgets import Label

    panel = app.query_one("#fx_panel")
    assert await pilot.click("#fx_import"), "click missed #fx_import"
    for _ in range(60):
        await pilot.pause()
        if app.screen.query("#flow_list"):
            break
    else:
        raise AssertionError("the flow picker did not open")
    target, labels = None, []
    for item in app.screen.query("#flow_list ListItem"):
        label = str(item.query_one(Label).render())
        labels.append(label)
        if label.strip() == stem:
            target = item
    assert target is not None, f"{stem} is not listed: {labels}"
    target.scroll_visible(animate=False)
    await pilot.pause()
    await pilot.pause()
    await pilot.click(target)
    await pilot.pause()
    assert await pilot.click("#flow_load_ok"), "click missed #flow_load_ok"
    for _ in range(100):
        await pilot.pause()
        if panel.query(f"#fx_lane_{lane}"):
            return
    raise AssertionError(f"lane {lane} never mounted")


async def _run_until_heads(app, pilot, marks: dict) -> None:
    """Click ``#fx_run`` and wait until every named lane head paints its
    terminal status mark (``✗`` error / ``◇`` notices)."""
    from textual.widgets import Static

    panel = app.query_one("#fx_panel")
    assert await pilot.click("#fx_run"), "click missed #fx_run"
    for _ in range(300):
        await pilot.pause()
        if all(
            mark in panel.query_one(f"#fx_lane_{lane}_head", Static).render().plain
            for lane, mark in marks.items()
        ):
            return
    raise AssertionError(f"the run never finished: {marks}")


def _run_fx(tmp_path: Path, body) -> object:
    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(220, 60)) as pilot:
            await settle(pilot)
            return await body(app, pilot)

    return asyncio.run(_drive())


def test_at_b99_06_flow_execution_patch_truth(tmp_path: Path) -> None:
    """AT-B99-06 (HLR-156, black box): three lanes over `#fx_run` — all-outside
    → the PATCH cell is the error glyph, no file is written, the painted log
    names the cause and the flow report names the address and
    ``skipped-outside``; partial → notices (the PATCH card paints ``notices``,
    PDR-ux row 97), the written file holds only the applied entry
    (independent reader), the log names ``1 of 2 entries not applied``;
    malformed → error, the report names ``MF-JSON-PARSE``. No report says
    ``CLEAN``. The project loads through the Load project dialog, Flow
    Execution opens by its rail key and Run is clicked (review fix F2)."""
    docs = {
        "outside.json": _doc([_bytes_entry(0x20000, "01 02 03 04")]),
        "mix.json": _doc(_MIX_ENTRIES),
        "bad.json": "{nope",
    }
    flows = {
        "b99_outside": [
            SourceBlock("prg.s19"),
            PatchBlock("outside.json"),
            WriteOutBlock("out_outside.s19"),
            ReportBlock(),
        ],
        "b99_mix": [
            SourceBlock("prg.s19"),
            PatchBlock("mix.json"),
            WriteOutBlock("out_mix.s19"),
            ReportBlock(),
        ],
        "b99_bad": [
            SourceBlock("prg.s19"),
            PatchBlock("bad.json"),
            WriteOutBlock("out_bad.s19"),
            ReportBlock(),
        ],
    }
    project_dir = _stage_project(tmp_path, "proj1", docs, flows)

    async def body(app, pilot):
        await _load_project_dialog(app, pilot, "proj1")
        panel = await _open_flow_execution_key(app, pilot)
        for lane, stem in enumerate(flows):
            await _import_flow_picker(app, pilot, stem, lane)
        await _run_until_heads(app, pilot, {0: "✗", 1: "◇", 2: "✗"})
        log = "\n".join(painted_rows(app, panel.query_one("#fx_log")))
        head = panel.query_one("#fx_lane_0_head").render().plain
        patch_cell = panel.query_one("#fx_card_0_1 .fx-card-status").render().plain
        mix_patch_cell = panel.query_one("#fx_card_1_1 .fx-card-status").render().plain
        return log, head, patch_cell, mix_patch_cell

    log, head, patch_cell, mix_patch_cell = _run_fx(tmp_path, body)

    # all-outside: PATCH failed, no file written.
    assert not (project_dir / "out_outside.s19").exists()
    assert not (project_dir / "out_bad.s19").exists()
    assert "✗" in head and "error" in patch_cell, (head, patch_cell)
    assert "applied 0 of 1 entries: 0x00020000 skipped-outside" in log
    assert "chain halted" in log
    # partial: the PATCH card paints ``notices`` (PDR-ux row 97), the UX-C1
    # line, and only the applied entry on disk.
    assert "notices" in mix_patch_cell, mix_patch_cell
    assert "PATCH: 1 of 2 entries not applied (0x00020000 skipped-outside)" in log
    mix_out = project_dir / "out_mix.s19"
    assert mix_out.exists(), "the notices lane must still WRITE-OUT"
    image = read_s19(mix_out)
    assert image.data[0xEB10] == 0xDE and image.data[0xEB11] == 0xAD
    assert 0x20000 not in image.data, "the not-applied entry reached the image"
    # the flow reports: none says CLEAN; each names what was not applied.
    reports = _fx_reports(project_dir)
    assert len(reports) == 3, [p.name for p in reports]
    texts = [p.read_text(encoding="utf-8") for p in reports]
    assert all("- **Status:** CLEAN" not in t for t in texts)
    joined = "\n".join(texts)
    assert "0x00020000" in joined and "skipped-outside" in joined
    assert "MF-JSON-PARSE" in joined


_HOSTILE_SYMBOL = "b99[bold]x[/]y[red]z[@click=app.quit]q\x07\x1b[31m"


def test_at_b99_07_hostile_symbol_name_renders_literally(tmp_path: Path) -> None:
    """AT-B99-07 (HLR-156, UX-C10/PQ-7): a change document whose unresolved
    symbol carries Rich-active markup and control bytes is refused, and every
    surface it reaches — the painted lane log and cells, the flow report —
    renders it literally: 0 markup spans, 0 control characters on the painted
    strip, the raw payload absent from the report file (``md_safe`` escaped).
    The project loads through the Load project dialog, Flow Execution opens
    by its rail key and Run is clicked (review fix F2)."""
    hostile_doc = json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                _bytes_entry(0xEB10, "DE AD"),
                _bytes_entry(0xEC00, "FF", symbol=_HOSTILE_SYMBOL),
            ],
        }
    )
    docs = {"hostile.json": hostile_doc}
    flows = {
        "b99_hostile": [
            SourceBlock("prg.s19"),
            PatchBlock("hostile.json"),
            WriteOutBlock("out_hostile.s19"),
            ReportBlock(),
        ],
    }
    project_dir = _stage_project(tmp_path, "proj1", docs, flows)

    async def body(app, pilot):
        await _load_project_dialog(app, pilot, "proj1")
        panel = await _open_flow_execution_key(app, pilot)
        await _import_flow_picker(app, pilot, "b99_hostile", 0)
        await _run_until_heads(app, pilot, {0: "✗"})
        log = "\n".join(painted_rows(app, panel.query_one("#fx_log")))
        painted = "\n".join(painted_rows(app, panel))
        widgets = [panel.query_one("#fx_log"), panel.query_one("#fx_lane_0_head")]
        widgets += list(panel.query(".fx-card-body")) + list(panel.query(".fx-card-status"))
        spans = [s for w in widgets for s in _payload_spans(w.render())]
        return log, painted, spans

    log, painted, spans = _run_fx(tmp_path, body)

    assert not (project_dir / "out_hostile.s19").exists()
    assert _CONTROL.findall(painted) == [], "a control byte reached the painted strip"
    assert spans == [], f"the payload created markup spans: {spans}"
    # The brackets paint as literal text (the C0/C1 bytes are scrubbed).
    assert "[bold]x[/]" in log and "[@click=app.quit]" in log, log
    reports = _fx_reports(project_dir)
    assert len(reports) == 1, [p.name for p in reports]
    text = reports[0].read_text(encoding="utf-8")
    assert "CHG-SYMBOL-UNRESOLVED" in text
    assert _HOSTILE_SYMBOL not in text, "the raw hostile payload reached the report"
    # The payload renders literally: every markdown-structural character is
    # escaped (the reader echoes the symbol through ``repr``, so the two
    # control bytes arrive as their ``\\x07`` / ``\\x1b`` spellings).
    assert (
        "\\[bold\\]x\\[\\/\\]y\\[red\\]z\\[\\@click=app\\.quit\\]q"
        in text
    ), text
    assert "[bold]x[/]" not in text
