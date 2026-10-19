"""Check-spec chain tests — batch-94 Inc-001 (US-003 / HLR-009/010).

Coverage map (test -> AT/TC -> LLR):

- AT-B94-12 — ``test_at_b94_12_writer_dropdown_report_chain``: the C-12
  output-then-consume chain — the Check Editor's shipped writer produces the
  ``.chk.json``, the A2B Diff dropdown lists it suffix-distinguished, loading
  THAT file puts every declared parameter/location into the emitted report
  (HLR-010).
- TC-B94-13 — ``test_tc_b94_13_chk_write_round_trip``: the ``.chk.json``
  write round-trip — suffix preserved by ``_safe_name``, re-read
  ``kind == "check"``, 0 blocking errors, entry count == collected count
  (LLR-009.1/009.3). The containment-refusal arm itself lives with its
  pre-existing owners, ``tests/test_unified_write.py:416-420`` and
  ``tests/test_project_gather.py:639-662`` — this file pins the round-trip
  and the suffix only.
- TC-B94-14 — ``test_tc_b94_14_run_check_document``: one verdict row per
  entry, each exactly one of pass/fail/uncheckable; a ``kind="change"``
  document is run-blocked with reason ``doc-kind`` (LLR-009.2).
- TC-B94-15 — ``test_tc_b94_15_dropdown_population``: the dropdown option
  set == the directory scan set; every check entry's label carries the CHECK
  distinction; a failing-read spec surfaces its issues on load (LLR-010.1).
- TC-B94-16 — ``test_tc_b94_16_report_addendum``: 100% of the declared
  parameter/location names appear in the emitted report; the addendum's
  emitted form matches the Phase-3 paste byte-for-byte in its fixed parts
  (LLR-010.2, C-42).

Harness: the ``asyncio.run(_drive())`` idiom; the report worker is awaited
through ``app.workers.wait_for_complete()`` (the batch-23 idiom).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Input, Select

from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.check import run_check_document
from s19_app.tui.changes.io import (
    _safe_name,
    is_check_spec_name,
    parse_change_document,
    write_change_document,
)
from s19_app.tui.changes.model import ChangeDocument
from s19_app.tui.models import LoadedFile
from s19_app.tui.services.diff_report_service import (
    _check_addendum_lines,
    generate_diff_report,
)

ROOT = Path(__file__).resolve().parent.parent
FIX_A = ROOT / "examples" / "case_00_public" / "prg.s19"
FIX_B = ROOT / "examples" / "case_00_public" / "s19_sample.s19"

# The C-42 paste of the addendum's fixed form (produced by this increment's
# own producer run — see the packet §3 evidence). The variable parts are the
# spec name, the counts, and the table rows.
SPEC_TEXT = """{
  "format": "s19app-changeset",
  "version": "2.0",
  "kind": "check",
  "encoding": "utf-8",
  "value_mode": "text",
  "entries": [
    {"type": "bytes", "address": "0x00000000", "bytes": "08 00 10 00"},
    {"type": "bytes", "address": "0x00008000", "bytes": "F2"}
  ]
}"""


def _loaded(mem: dict, ranges: list) -> LoadedFile:
    return LoadedFile(
        path=Path("ecu.s19"),
        file_type="s19",
        mem_map=mem,
        row_bases=sorted({a - a % 16 for a in mem}),
        ranges=ranges,
        range_validity=[True] * len(ranges),
        errors=[],
        a2l_path=None,
        a2l_data=None,
        entropy_windows=None,
    )


# ---------------------------------------------------------------------------
# AT-B94-12 — the C-12 writer -> dropdown -> report chain (HLR-010)
# ---------------------------------------------------------------------------


def test_at_b94_12_writer_dropdown_report_chain(tmp_path: Path) -> None:
    """AT-B94-12 — the shipped writer's file reaches the emitted report.

    Intent (HLR-010, C-12 output-then-consume): the acceptance input is the
    Check Editor's own output — never a hand-written artifact. The Check
    Editor writes ``baseline.chk.json``; the A2B Diff dropdown lists it
    suffix-distinguished; loading THAT file and running the report puts the
    declared fields into the emitted report.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        mem = {0x0: 0x08, 0x1: 0x00, 0x2: 0x10, 0x3: 0x00}
        app.current_file = _loaded(mem, [(0x0, 0x4)])
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # 1. The Check Editor writes the spec through the shipped panel.
            await pilot.press("equals_sign")
            await pilot.pause()
            await pilot.pause()
            app.query_one("#check_file_name_input", Input).value = (
                "baseline.chk.json"
            )
            app.query_one("#check_mem_address_input", Input).value = "0x00000000"
            app.query_one("#check_mem_label_input", Input).value = "blk0"
            app.query_one("#check_mem_size_input", Input).value = "4"
            app.query_one("#check_mem_add_button").focus()
            await pilot.press("enter")
            await pilot.pause()
            app.query_one("#check_write_button").focus()
            await pilot.press("enter")
            await pilot.pause()
            written = list((app.workarea / "patches").glob("*.chk.json"))
            assert len(written) == 1, f"the writer wrote one spec, got {written}"
            # 2. The A2B Diff dropdown lists it suffix-distinguished.
            await pilot.press("7")
            await pilot.pause()
            await pilot.pause()
            select = app.query_one("#diff_check_select", Select)
            labels = [
                (label.plain if hasattr(label, "plain") else str(label))
                for label, _v in select._options
            ]
            check_labels = [x for x in labels if "baseline.chk.json" in x]
            assert len(check_labels) == 1 and "CHECK" in check_labels[0], (
                f"the written spec is listed with the CHECK distinction, got "
                f"{labels!r}"
            )
            # 3. Load THAT file through the dropdown's shipped message path.
            select.value = "baseline.chk.json"
            await pilot.pause()
            await pilot.pause()
            assert app._diff_check_spec is not None, (
                "the app stashes the loaded check spec"
            )
            assert app._diff_check_spec_name == "baseline.chk.json"
            # 4. Compare two real fixtures, then report.
            app.query_one("#diff_path_a", Input).value = str(FIX_A)
            app.query_one("#diff_path_b", Input).value = str(FIX_B)
            dest = tmp_path / "reports"
            dest.mkdir()
            app.query_one("#diff_report_dest", Input).value = str(dest)
            app.query_one("#diff_compare_button").focus()
            await pilot.press("enter")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            app.query_one("#diff_report_button").focus()
            await pilot.press("enter")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            reports = sorted(dest.glob("*.md"))
            text = reports[-1].read_text(encoding="utf-8") if reports else ""
            return labels, text

    labels, report_text = asyncio.run(_drive())
    assert "## Checks" in report_text, (
        "the emitted report carries the check addendum"
    )
    assert "baseline\\.chk\\.json" in report_text, (
        "the spec file name appears (md_safe-escaped, C-42 mechanic 2)"
    )
    assert "Declared fields: 1" in report_text, (
        "one declared field (the memory row written above)"
    )
    # The declared address AND its expected bytes ride the report.
    assert "0x00000000" in report_text, "the declared location is in the report"
    assert "08 00 10 00" in report_text, (
        "the expected bytes at the declared location are in the report"
    )
    assert "0 byte changes" in report_text, (
        "the no-apply doctrine is carried in the addendum"
    )


# ---------------------------------------------------------------------------
# TC-B94-13 — the .chk.json write round-trip (LLR-009.1/009.3)
# ---------------------------------------------------------------------------


def test_tc_b94_13_chk_write_round_trip(tmp_path: Path) -> None:
    """The suffix survives the save boundary; the re-read round-trips."""
    assert _safe_name("baseline.chk.json") == "baseline.chk.json", (
        "the double suffix is preserved (the name-mangling negative control)"
    )
    assert _safe_name("../escape/x") == "x.json"
    assert is_check_spec_name("baseline.chk.json")
    assert not is_check_spec_name("hotfix.pch.json")

    document = parse_change_document(SPEC_TEXT)
    assert document.kind == "check" and not document.has_errors
    path, issues = write_change_document(
        document, tmp_path, "baseline.chk.json"
    )
    assert path is not None and issues == []
    assert path.name.endswith(".chk.json"), f"written name keeps the suffix: {path.name}"
    reread = parse_change_document(path.read_text(encoding="utf-8"))
    assert reread.kind == "check"
    assert not reread.has_errors
    assert len(reread.entries) == len(document.entries) == 2

    # Empty spec still writes (the empty arm).
    empty = ChangeDocument(
        format="s19app-changeset",
        version="2.0",
        kind="check",
        encoding="utf-8",
        value_mode="text",
        entries=[],
    )
    empty_path, empty_issues = write_change_document(empty, tmp_path, "empty.chk.json")
    assert empty_path is not None and empty_issues == []
    assert len(parse_change_document(empty_path.read_text(encoding="utf-8")).entries) == 0


# ---------------------------------------------------------------------------
# TC-B94-14 — run_check_document verdicts (LLR-009.2)
# ---------------------------------------------------------------------------


def test_tc_b94_14_run_check_document() -> None:
    """One verdict row per entry; wrong-kind docs are run-blocked doc-kind."""
    doc = parse_change_document(SPEC_TEXT)
    mem_map = {0x0: 0x08, 0x1: 0x00, 0x2: 0x10, 0x3: 0x00, 0x8000: 0xF2}
    result = run_check_document(doc, mem_map, [(0x0, 0x4), (0x8000, 0x8001)], [], [])
    assert result.run_blocked_reason_code is None
    assert len(result.entries) == 2, (
        f"verdict row count == entry count, got {len(result.entries)}"
    )
    tokens = {e.result for e in result.entries}
    assert tokens <= {"pass", "fail", "uncheckable"}, tokens
    assert all(e.result == "pass" for e in result.entries), (
        "expected bytes == image bytes -> every entry passes"
    )
    # Boundary arm: entries outside the loaded image read uncheckable.
    outside = run_check_document(doc, {}, [], [], [])
    assert len(outside.entries) == 2
    assert all(e.result == "uncheckable" for e in outside.entries)
    # Wrong-kind arm: a change document is run-blocked with reason doc-kind.
    change_doc = parse_change_document(
        SPEC_TEXT.replace('"kind": "check"', '"kind": "change"')
    )
    blocked = run_check_document(change_doc, mem_map, [], [], [])
    assert blocked.run_blocked_reason_code == "doc-kind", (
        f"a kind=change doc is run-blocked doc-kind, got "
        f"{blocked.run_blocked_reason_code!r}"
    )


# ---------------------------------------------------------------------------
# TC-B94-15 — dropdown population (LLR-010.1)
# ---------------------------------------------------------------------------


def test_tc_b94_15_dropdown_population(tmp_path: Path) -> None:
    """The dropdown lists the scan set; CHECK labels carry the distinction;
    a failing-read spec surfaces its issues on load."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        patches = app.workarea / "patches"
        patches.mkdir(parents=True, exist_ok=True)
        (patches / "hotfix.pch.json").write_text(
            SPEC_TEXT.replace('"kind": "check"', '"kind": "change"'),
            encoding="utf-8",
        )
        (patches / "baseline.chk.json").write_text(SPEC_TEXT, encoding="utf-8")
        (patches / "broken.chk.json").write_text("{ not json", encoding="utf-8")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("7")
            await pilot.pause()
            await pilot.pause()
            select = app.query_one("#diff_check_select", Select)
            scan = app._scan_patch_change_files()
            labels = [
                (label.plain if hasattr(label, "plain") else str(label))
                for label, _v in select._options
            ]
            # The failing-read arm: loading the broken spec surfaces issues.
            select.value = "broken.chk.json"
            await pilot.pause()
            await pilot.pause()
            status_broken = str(app.query_one("#diff_status").render())
            assert app._diff_check_spec is None, (
                "a failing spec is never stashed"
            )
            return scan, labels, status_broken

    scan, labels, status_broken = asyncio.run(_drive())
    listed = sorted(
        item for item in labels if ".json" in item and "broken" not in item
    )
    assert listed == [
        "baseline.chk.json CHECK",
        "hotfix.pch.json PATCH",
    ], f"the dropdown lists the scan set with distinctions, got {listed}"
    assert sorted(scan) == ["baseline.chk.json", "broken.chk.json", "hotfix.pch.json"]
    assert "MF-JSON-PARSE" in status_broken or "not loaded" in status_broken, (
        f"the failing read surfaces its issues, got {status_broken!r}"
    )


# ---------------------------------------------------------------------------
# TC-B94-16 — the report addendum's emitted form (LLR-010.2, C-42)
# ---------------------------------------------------------------------------


def test_tc_b94_16_report_addendum() -> None:
    """100% of the declared names appear in the emitted report; the fixed
    form matches the increment's own paste."""
    from s19_app.core import S19File
    from s19_app.tui.services.compare_service import (
        SOURCE_EXTERNAL,
        ImageSource,
        compare_images,
    )
    from s19_app.tui.services.load_service import build_loaded_s19

    spec = parse_change_document(SPEC_TEXT)
    # The declared fields are NAMED by the artifact symbol at their address
    # (the v2 wire grammar carries no names) — two named symbols cover both
    # declared addresses.
    symbol_addresses = [(0x00000000, "EngineSpeed"), (0x00008000, "Torque_Pct")]
    lines = _check_addendum_lines(spec, "baseline.chk.json", symbol_addresses)
    addendum = "\n".join(lines)

    # The Phase-3 paste (fixed parts — the C-42 predicate is written against
    # THIS form, emitted by the shipped producer over the public fixtures):
    #   ## Checks
    #   - Check spec: `baseline\.chk\.json`
    #   - Declared fields: 2 (0 byte changes — image never modified)
    #   | # | Field | Address | Expected |
    assert lines[0] == "## Checks"
    assert "- Check spec: `baseline\\.chk\\.json`" in lines, (
        "the md_safe-escaped spelling (C-42 mechanic 2), not the raw name"
    )
    assert (
        "- Declared fields: 2 (0 byte changes — image never modified)"
        in lines
    ), lines
    assert "| # | Field | Address | Expected |" in lines
    assert "| 1 | EngineSpeed | 0x00000000 | 08 00 10 00 |" in lines
    assert r"| 2 | Torque\_Pct | 0x00008000 | F2 |" in lines
    # 100% of the declared names appear in their EMITTED (md_safe) spelling —
    # found == declared, 0 missing (C-42 mechanic 2: the escaped form, not
    # the raw characters).
    for name in ("EngineSpeed", r"Torque\_Pct"):
        assert name in addendum, f"declared name {name!r} is missing"

    # The end-to-end producer arm over the public fixtures: the addendum
    # rides a real generated report, and the report is non-empty with the
    # same section structure.
    cmp_res = compare_images(
        ImageSource(kind=SOURCE_EXTERNAL, raw_path=str(FIX_A), label="prg"),
        ImageSource(kind=SOURCE_EXTERNAL, raw_path=str(FIX_B), label="sample"),
    )
    loaded_a = build_loaded_s19(FIX_A, S19File(str(FIX_A)), None, None)
    loaded_b = build_loaded_s19(FIX_B, S19File(str(FIX_B)), None, None)
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        result = generate_diff_report(
            cmp_res,
            mem_map_a=loaded_a.mem_map,
            mem_map_b=loaded_b.mem_map,
            dest_input=tmp,
            filename_stem="tc_b94_16",
            check_spec=spec,
            check_spec_name="baseline.chk.json",
        )
        text = Path(result.path).read_text(encoding="utf-8")
    assert result.written and len(text) > 0
    index = text.index("## Checks")
    assert text[index:].splitlines()[:6] == addendum.splitlines()[:6], (
        "the shipped report's addendum header is the pasted form"
    )
    # Empty arm: an empty spec renders an empty addendum, not an error.
    empty = ChangeDocument(
        format="s19app-changeset",
        version="2.0",
        kind="check",
        encoding="utf-8",
        value_mode="text",
        entries=[],
    )
    empty_lines = _check_addendum_lines(empty, "empty.chk.json", [])
    assert "No declared fields." in empty_lines
