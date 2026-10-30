"""Batch-99 HLR-154: truncated and inconsistent images are reported.

TC-B99-08 (LLR-154.1) — the S19 loader attaches one notice per defect kind:
``S19-NO-TERMINATOR`` (no S7/S8/S9 record), ``S19-COUNT-MISMATCH`` (an S5
count compared only while the data-record count is <= 0xFFFF, an S6 count
while <= 0xFFFFFF), and ``S19-AFTER-TERMINATOR`` (non-empty lines after the
terminator are counted, never parsed, never imaged; the notice states the
count). Controls: every ``examples/**/*.s19`` and every well-formed corpus
file loads with zero of these notices; trailing blank lines add none; an
S6-counted image wider than 65 535 data records adds none; a wrong S6 count
on such a wide image carries exactly one ``S19-COUNT-MISMATCH``; a data
line that fails to parse gives its own parse issue and never a false count
mismatch (it still counts toward the S5/S6 tally).

TC-B99-09 (LLR-154.2) — the HEX loader attaches ``HEX-NO-EOF`` (no type-01
record) and ``HEX-AFTER-EOF`` (non-empty lines after the first EOF are
counted, never parsed, never imaged; the notice states the count). The file
is read in binary: lines are split with bytes ``splitlines()`` (``\\r``,
``\\n`` and ``\\r\\n`` alike — CR-only, LF-only and CRLF files load the same
image), the tail after the first EOF record is counted by stripping the
BYTES, never decoded, so raw padding (e.g. ``0xFF``) after newlines cannot
fail the load.

TC-B99-10 (LLR-154.3) — a flow whose SOURCE image carries any of the five
codes ends the SOURCE block with status ``error`` (the last diagnostic names
the code and the file), the chain aborts and no file is written; other load
notices keep the ``notices`` mapping and a clean image keeps ``ok``. A
hostile file name in the notice path renders literally (UX-C10).

AT-B99-03 (US-143) — one black-box Textual pilot session drives the whole
observable outcome: Load file (``l``) of the cut corpus S19 paints
``Loaded cut.s19 with integrity notices: S19-NO-TERMINATOR`` (never a plain
``Loaded <name> (S19 only)``), the Issues panel names the code, and Flow
Execution (``#fx_run``) over the same defect fails the SOURCE lane and
writes no file.

Oracle: expected image bytes come from the corpus manifest / the independent
reader (``tests/support/independent_reader.py``), never from the app's own
emitters; the loader under test is exercised through its public
``S19File`` / ``IntelHexFile`` parse.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    FLOW_STATUS_ERROR,
    WRITE_FMT_HEX,
    WRITE_FMT_S19,
    Flow,
    FlowContext,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.load_service import build_loaded_s19
from tests.support.independent_reader import read_hex, read_s19
from tests.support.b100_projects import dismiss_load_result_panel

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "synth"
EXAMPLE_S19 = sorted((ROOT / "examples").rglob("*.s19"))

#: The five HLR-154 integrity-notice codes (map row B99-I10).
INTEGRITY_CODES = (
    "S19-NO-TERMINATOR",
    "S19-COUNT-MISMATCH",
    "S19-AFTER-TERMINATOR",
    "HEX-NO-EOF",
    "HEX-AFTER-EOF",
)
_INTEGRITY_RE = re.compile(r"^((?:S19|HEX)-[A-Z0-9-]+)")

#: Full expected notice messages for the committed defect corpus files.
DEFECT_MESSAGES = {
    "synth_no_terminator.s19": (
        "S19-NO-TERMINATOR: no S7/S8/S9 terminator record; "
        "the image may be truncated"
    ),
    "synth_wrong_s5.s19": (
        "S19-COUNT-MISMATCH: S5 count 3 does not match 2 data records"
    ),
    "synth_after_terminator.s19": (
        "S19-AFTER-TERMINATOR: 1 record(s) after the terminator were ignored"
    ),
    "synth_hex_no_eof.hex": (
        "HEX-NO-EOF: no type 01 EOF record; the image may be truncated"
    ),
    "synth_hex_after_eof.hex": (
        "HEX-AFTER-EOF: 1 record(s) after the EOF record were ignored"
    ),
}


def _codes(errors: list[dict]) -> list[str]:
    """The integrity-notice codes carried by loader error dicts, in order."""
    out = []
    for err in errors:
        match = _INTEGRITY_RE.match(str(err.get("error", "")))
        if match and match.group(1) in INTEGRITY_CODES:
            out.append(match.group(1))
    return out


def _manifest() -> dict:
    return json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))


def _manifest_entry(name: str) -> dict:
    return next(e for e in _manifest()["files"] if e["name"] == name)


def _expand_runs(runs: dict) -> dict:
    data = {}
    for key, hex_bytes in runs.items():
        addr = int(key, 16)
        for i, b in enumerate(bytes.fromhex(hex_bytes)):
            data[addr + i] = b
    return data


def _s1_record(address: int, payload: bytes) -> str:
    """One checksum-correct S1 record line."""
    body = bytes([2 + len(payload) + 1, (address >> 8) & 0xFF, address & 0xFF]) + payload
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def _s5_record(count: int) -> str:
    body = bytes([3, (count >> 8) & 0xFF, count & 0xFF])
    return "S5" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def _s6_record(count: int) -> str:
    body = bytes([4, (count >> 16) & 0xFF, (count >> 8) & 0xFF, count & 0xFF])
    return "S6" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


# --------------------------------------------------------------------------- #
# TC-B99-08 — LLR-154.1: S19 terminator and count checks
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", [n for n in DEFECT_MESSAGES if n.endswith(".s19")])
def test_tc_b99_08_defect_files(name: str):
    """Each S19 defect file yields exactly its notice, naming the defect.

    The image holds only the pre-defect bytes (oracle: the corpus manifest).
    """
    path = CORPUS / name
    s19 = S19File(str(path))

    errors = s19.get_errors()
    assert len(errors) == 1, errors
    assert errors[0]["error"] == DEFECT_MESSAGES[name], errors
    assert _codes(errors) == [_INTEGRITY_RE.match(DEFECT_MESSAGES[name]).group(1)]

    loaded = build_loaded_s19(path, s19, None, None)
    assert loaded.mem_map == _expand_runs(_manifest_entry(name)["data"]), name


def test_tc_b99_08_examples_and_corpus_controls():
    """Every examples/**/*.s19 and every well-formed corpus S19: 0 notices."""
    well_formed = [
        CORPUS / e["name"]
        for e in _manifest()["files"]
        if e["format"] == "s19" and e["verdict"] == "ok"
    ]
    assert len(well_formed) >= 5, well_formed
    for path in EXAMPLE_S19 + well_formed:
        s19 = S19File(str(path))
        assert _codes(s19.get_errors()) == [], path.name
        if path.parent == CORPUS:
            # The well-formed corpus files carry no loader error at all; the
            # public examples may hold pre-existing unrelated validation
            # errors (e.g. case_02's deliberate bad checksums) — only the
            # five integrity codes are pinned to zero here.
            assert s19.get_errors() == [], (path.name, s19.get_errors())


def test_tc_b99_08_junk_tail_counted_not_parsed(tmp_path):
    """A 100 000-line junk tail after the terminator: ONE notice stating the
    count, zero per-line issues, zero image bytes from the tail."""
    base = (CORPUS / "synth_s1.s19").read_text(encoding="ascii")
    target = tmp_path / "junk_tail.s19"
    target.write_text(
        base + "".join(f"S1JUNKLINE{i:06X}\n" for i in range(100_000)),
        encoding="ascii",
    )

    s19 = S19File(str(target))
    errors = s19.get_errors()
    assert len(errors) == 1, f"expected exactly one notice, got {len(errors)}"
    assert (
        errors[0]["error"]
        == "S19-AFTER-TERMINATOR: 100000 record(s) after the terminator were ignored"
    ), errors[0]

    loaded = build_loaded_s19(target, s19, None, None)
    assert loaded.mem_map == _expand_runs(_manifest_entry("synth_s1.s19")["data"])


def test_tc_b99_08_trailing_blank_lines_no_notice(tmp_path):
    """Blank/whitespace-only lines after the terminator add no notice."""
    base = (CORPUS / "synth_s1.s19").read_text(encoding="ascii")
    target = tmp_path / "blank_tail.s19"
    target.write_text(base + "\n\n   \n\t\n", encoding="ascii")

    s19 = S19File(str(target))
    assert s19.get_errors() == [], s19.get_errors()


def test_tc_b99_08_wide_s6_image_no_notice(tmp_path):
    """An S6-counted image of MORE than 65 535 data records: the S5 width
    gate skips the (wrong) S5 count and the matching S6 count passes — 0
    notices. Generated into tmp (no big file committed)."""
    records = [
        _s1_record(0x1000 + (i % 480) * 32, bytes([i & 0xFF]) * 16)
        for i in range(0x10000)
    ]
    lines = records + [_s5_record(7), _s6_record(0x10000), "S9030000FC"]
    target = tmp_path / "wide_s6.s19"
    target.write_text("\n".join(lines) + "\n", encoding="ascii")

    s19 = S19File(str(target))
    assert _codes(s19.get_errors()) == [], s19.get_errors()[:3]
    assert len(s19.records) == 0x10000 + 3  # data + S5 + S6 + S9 terminator


def test_tc_b99_08_s6_mismatch_wide_image(tmp_path):
    """An S6-counted image of MORE than 65 535 data records with a WRONG S6
    count: the S5 width gate skips the (wrong) S5 count, the S6 gate fires —
    exactly one ``S19-COUNT-MISMATCH`` naming the S6 count and the real
    data-record count. Generated into tmp (no big file committed)."""
    records = [
        _s1_record(0x1000 + (i % 480) * 32, bytes([i & 0xFF]) * 16)
        for i in range(0x10000)
    ]
    lines = records + [_s5_record(7), _s6_record(0x10001), "S9030000FC"]
    target = tmp_path / "wide_s6_wrong.s19"
    target.write_text("\n".join(lines) + "\n", encoding="ascii")

    s19 = S19File(str(target))
    errors = s19.get_errors()
    assert _codes(errors) == ["S19-COUNT-MISMATCH"], errors[:3]
    assert (
        errors[0]["error"]
        == "S19-COUNT-MISMATCH: S6 count 65537 does not match 65536 data records"
    ), errors[0]
    assert len(errors) == 1, errors


def test_tc_b99_08_damaged_data_line_no_false_count_mismatch(tmp_path):
    """A data line that fails to parse still counts toward the S5/S6 tally
    (LLR-154.1): the damaged line gives its OWN parse issue and never a
    false ``S19-COUNT-MISMATCH`` — the S5 count matching the parsed-plus-
    damaged tally is the control that pins this."""
    good = [
        _s1_record(0x1000 + i * 16, bytes([0xA0 + i]) * 8)
        for i in range(2)
    ]
    damaged = good[1][:-2] + "ZZ"  # S1-prefixed, not hexadecimal
    # S5 declares the parsed-plus-damaged tally (1 + 1 = 2): matching it
    # proves the damaged line counted; a false mismatch would fire otherwise.
    lines = [good[0], damaged, _s5_record(2), "S9030000FC"]
    target = tmp_path / "damaged_data_line.s19"
    target.write_text("\n".join(lines) + "\n", encoding="ascii")

    s19 = S19File(str(target))
    errors = s19.get_errors()
    assert _codes(errors) == [], errors
    assert len(errors) == 1, errors
    assert errors[0]["segment"] == "SRecord constructor", errors[0]
    assert errors[0]["line"] == damaged, errors[0]


# --------------------------------------------------------------------------- #
# TC-B99-09 — LLR-154.2: HEX EOF checks
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", [n for n in DEFECT_MESSAGES if n.endswith(".hex")])
def test_tc_b99_09_defect_files(name: str):
    """Each HEX defect file yields exactly its notice, naming the defect.

    The image holds only the pre-EOF bytes (oracle: the independent reader).
    """
    path = CORPUS / name
    hex_file = IntelHexFile(str(path))

    errors = hex_file.get_errors()
    assert len(errors) == 1, errors
    assert errors[0]["error"] == DEFECT_MESSAGES[name], errors

    oracle = read_hex(path)
    assert dict(hex_file.memory) == oracle.data, name


def test_tc_b99_09_well_formed_corpus_controls():
    """Every well-formed corpus HEX file (EOF as the last line): 0 notices."""
    well_formed = [
        CORPUS / e["name"]
        for e in _manifest()["files"]
        if e["format"] == "hex" and e["verdict"] == "ok"
    ]
    assert well_formed, "manifest holds no well-formed HEX file"
    for path in well_formed:
        hex_file = IntelHexFile(str(path))
        assert hex_file.get_errors() == [], (path.name, hex_file.get_errors())


def test_tc_b99_09_junk_tail_counted_not_parsed(tmp_path):
    """A 100 000-line junk tail after the EOF: ONE notice stating the count,
    zero per-line issues, zero image bytes from the tail."""
    base = (CORPUS / "synth_hex_basic.hex").read_text(encoding="ascii")
    target = tmp_path / "junk_tail.hex"
    tail = "".join(
        (":garbage\n" if i % 2 else f"junk{i}\n") for i in range(100_000)
    )
    target.write_text(base + tail, encoding="ascii")

    hex_file = IntelHexFile(str(target))
    errors = hex_file.get_errors()
    assert len(errors) == 1, f"expected exactly one notice, got {len(errors)}"
    assert (
        errors[0]["error"]
        == "HEX-AFTER-EOF: 100000 record(s) after the EOF record were ignored"
    ), errors[0]

    oracle = read_hex(target)
    assert oracle.records_after_end == 100_000
    assert dict(hex_file.memory) == oracle.data


def test_tc_b99_09_binary_tail_after_eof(tmp_path):
    """A valid HEX (272 data bytes) followed by 50 000 newlines and raw
    ``0xFF`` padding: the load succeeds — the tail after the first EOF record
    is counted by stripping the BYTES, never decoded — with ONE
    ``HEX-AFTER-EOF`` notice for the single non-empty tail line."""
    base = CORPUS / "synth_hex_basic.hex"
    target = tmp_path / "binary_tail.hex"
    target.write_bytes(base.read_bytes() + b"\n" * 50_000 + b"\xff" * 4096)

    hex_file = IntelHexFile(str(target))
    errors = hex_file.get_errors()
    assert len(errors) == 1, errors
    assert (
        errors[0]["error"]
        == "HEX-AFTER-EOF: 1 record(s) after the EOF record were ignored"
    ), errors[0]
    assert len(hex_file.memory) == 272

    oracle = read_hex(base)
    assert dict(hex_file.memory) == oracle.data


def test_tc_b99_09_line_endings_cr_lf_crlf(tmp_path):
    """The same HEX content saved CR-only, LF-only and CRLF: every encoding
    loads the same 272-byte image with ZERO notices (bytes ``splitlines``
    splits on ``\\r``, ``\\n`` and ``\\r\\n`` alike; the old binary iteration
    read a CR-only file as ONE line — 0 image bytes and a false
    ``HEX-NO-EOF``)."""
    base = (CORPUS / "synth_hex_basic.hex").read_text(encoding="ascii")
    assert "\r" not in base, "fixture assumed LF-only"
    oracle = read_hex(CORPUS / "synth_hex_basic.hex")
    variants = {
        "cr_only": base.replace("\n", "\r").encode("ascii"),
        "lf_only": base.encode("ascii"),
        "crlf": base.replace("\n", "\r\n").encode("ascii"),
    }
    for name, content in variants.items():
        target = tmp_path / f"line_endings_{name}.hex"
        target.write_bytes(content)
        hex_file = IntelHexFile(str(target))
        assert hex_file.get_errors() == [], (name, hex_file.get_errors())
        assert dict(hex_file.memory) == oracle.data, name


def test_tc_b99_09_cr_only_binary_tail_after_eof(tmp_path):
    """A CR-only HEX file followed by raw ``0xFF`` padding: the load succeeds
    with ONE ``HEX-AFTER-EOF`` notice — after the CR-split the padding is a
    single stripped non-empty line, counted, never decoded — and the pre-EOF
    image matches the oracle."""
    base = (CORPUS / "synth_hex_basic.hex").read_text(encoding="ascii")
    target = tmp_path / "cr_only_binary_tail.hex"
    target.write_bytes(base.replace("\n", "\r").encode("ascii") + b"\xff" * 4096)

    hex_file = IntelHexFile(str(target))
    errors = hex_file.get_errors()
    assert len(errors) == 1, errors
    assert (
        errors[0]["error"]
        == "HEX-AFTER-EOF: 1 record(s) after the EOF record were ignored"
    ), errors[0]

    oracle = read_hex(CORPUS / "synth_hex_basic.hex")
    assert dict(hex_file.memory) == oracle.data


# --------------------------------------------------------------------------- #
# TC-B99-10 — LLR-154.3: SOURCE fails on an integrity notice
# --------------------------------------------------------------------------- #

_FLOW_DEFECTS = [
    ("synth_no_terminator.s19", WRITE_FMT_S19, "S19-NO-TERMINATOR"),
    ("synth_wrong_s5.s19", WRITE_FMT_S19, "S19-COUNT-MISMATCH"),
    ("synth_after_terminator.s19", WRITE_FMT_S19, "S19-AFTER-TERMINATOR"),
    ("synth_hex_no_eof.hex", WRITE_FMT_HEX, "HEX-NO-EOF"),
    ("synth_hex_after_eof.hex", WRITE_FMT_HEX, "HEX-AFTER-EOF"),
]


@pytest.mark.parametrize("name,file_type,code", _FLOW_DEFECTS)
def test_tc_b99_10_source_error_no_file(
    tmp_path: Path, name: str, file_type: str, code: str
):
    """A flow over a defect source: SOURCE ``error`` whose LAST diagnostic
    names the code and the file, WRITE-OUT skipped, no file written."""
    project = tmp_path / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True)
    shutil.copyfile(CORPUS / name, project / name)
    out_name = "out.hex" if file_type == WRITE_FMT_HEX else "out.s19"
    flow = Flow(
        name="t",
        blocks=[
            SourceBlock(name, file_type=file_type),
            WriteOutBlock(out_name, fmt=file_type),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    source = result.block_results[0]
    assert source.status == BLOCK_STATUS_ERROR, source
    last = source.diagnostics[-1]
    assert last.startswith(f"[{code}]"), last
    assert name in last, last
    assert result.block_results[1].status == BLOCK_STATUS_SKIPPED
    assert result.status == FLOW_STATUS_ERROR
    assert result.written_paths == []
    assert not (project / out_name).exists()


def test_tc_b99_10_clean_source_still_writes(tmp_path: Path):
    """Control: a well-formed source keeps ``ok`` and WRITE-OUT runs."""
    project = tmp_path / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True)
    shutil.copyfile(CORPUS / "synth_s1.s19", project / "synth_s1.s19")
    flow = Flow(
        name="t",
        blocks=[SourceBlock("synth_s1.s19"), WriteOutBlock("out.s19")],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[0].status == BLOCK_STATUS_OK
    assert result.block_results[1].status == BLOCK_STATUS_OK
    assert len(result.written_paths) == 1
    assert result.written_paths[0].exists()


def test_tc_b99_10_hostile_name_renders_literally(tmp_path):
    """A hostile file name in the integrity-notice path renders literally:
    the painted status carries the verbatim ``[@click=app.quit]`` name with
    zero markup interpretation (UX-C10)."""
    name = "[@click=app.quit]cut.s19"
    src = tmp_path / name
    shutil.copyfile(CORPUS / "synth_no_terminator.s19", src)
    app = S19TuiApp(base_dir=tmp_path)

    async def _drive():
        async with app.run_test(size=(120, 54)) as pilot:
            await pilot.pause()
            await pilot.press("l")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#load_path"), "click missed #load_path"
            await pilot.press(*str(src))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            await _wait_for(
                pilot,
                lambda: "integrity notices" in _status_text(app),
                "load status line",
            )
            status = _status_text(app)
            assert name in status, status
            assert "S19-NO-TERMINATOR" in status, status

    asyncio.run(_drive())


# --------------------------------------------------------------------------- #
# AT-B99-03 — US-143: black-box pilot through the TUI
# --------------------------------------------------------------------------- #


def _status_text(app: S19TuiApp) -> str:
    """The painted file-status label (``#status_text`` — the status line the
    load leads with; the rolling log-tail lines can scroll it out of view)."""
    from textual.widgets import Label

    return str(app.query_one("#status_text", Label).render())


async def _wait_for(pilot, predicate, description: str, attempts: int = 100):
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


def test_at_b99_03_status_leads_defect_flow_source_fails(tmp_path):
    """One pilot session drives the whole HLR-154 observable outcome: Load
    file (``l``) of the cut corpus S19 paints ``Loaded cut.s19 with
    integrity notices: S19-NO-TERMINATOR`` (never a plain
    ``Loaded <name> (S19 only)``), the Issues panel names the code, and Flow
    Execution (``#fx_run``) over the same defect fails the SOURCE lane and
    writes no file."""
    from textual.widgets import Label
    from textual.widgets import Static

    from s19_app.tui.screens import LoadFlowScreen, LoadProjectScreen

    from tests.b97_fixtures import write_flow

    app = S19TuiApp(base_dir=tmp_path)
    project_dir = app.workarea / "proj1"
    project_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CORPUS / "synth_no_terminator.s19", project_dir / "cut.s19")
    write_flow(
        project_dir,
        "cut_flow",
        [SourceBlock("cut.s19"), WriteOutBlock("out.s19")],
    )

    def painted_log() -> str:
        return str(app.query_one("#fx_log", Static).render())

    async def _drive():
        async with app.run_test(size=(120, 54)) as pilot:
            await pilot.pause()
            # 1. Load file dialog: the cut corpus S19 leads with the defect.
            await pilot.press("l")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#load_path"), "click missed #load_path"
            await pilot.press(*str(project_dir / "cut.s19"))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            await _wait_for(
                pilot,
                lambda: "integrity notices" in _status_text(app),
                "load status line",
            )
            status = _status_text(app)
            assert status.startswith(
                "Loaded cut.s19 with integrity notices: S19-NO-TERMINATOR"
            ), status
            assert "(S19 only)" not in status, status
            await _wait_for(
                pilot,
                lambda: any(
                    "S19-NO-TERMINATOR" in str(chip.render())
                    for chip in app.query(".issue-code-chip")
                ),
                "issues panel names the code",
            )
            # 2. Flow Execution over the same defect: SOURCE fails, no file.
            # The file-load worker leaves focus on the segment table, whose
            # window binds ``p`` (pad cycle); ``tab`` walks focus back out so
            # the rail key reaches the app binding.
            await pilot.press("tab")
            await pilot.press("p")
            await _wait_for(
                pilot,
                lambda: isinstance(app.screen, LoadProjectScreen),
                "the Load project dialog",
            )
            # The row pick is a CLICK on the painted row (the flow-picker
            # idiom below), never an assignment to ``listing.index``.
            row = next(
                row
                for row in app.screen.query("#project_list ListItem")
                if "proj1" in str(row.query_one(Label).render())
            )
            await pilot.click(row)
            await pilot.pause()
            assert await pilot.click("#project_ok"), "click missed #project_ok"
            # Inc 6 (HLR-178): the dialog route opens the Load-result panel;
            # dismiss it first with its shown key ``esc``.
            await dismiss_load_result_panel(pilot, app)
            # ``#status_context`` carries the project name durably; the rolling
            # ``#status_text`` line can be overwritten by the file-load worker.
            await _wait_for(
                pilot,
                lambda: "proj1"
                in str(app.query_one("#status_context").render()),
                "the project context label",
            )
            await pilot.press("right_square_bracket")
            await _wait_for(
                pilot,
                lambda: len(app.query("#fx_panel")) > 0,
                "the Flow Execution panel",
            )
            assert await pilot.click("#fx_import"), "click missed #fx_import"
            await _wait_for(
                pilot,
                lambda: isinstance(app.screen, LoadFlowScreen)
                and any(
                    item.name == "cut_flow"
                    for item in app.screen.query("#flow_list ListItem")
                ),
                "the flow picker lists cut_flow",
            )
            item = next(
                item
                for item in app.screen.query("#flow_list ListItem")
                if item.name == "cut_flow"
            )
            await pilot.click(item)
            await pilot.pause()
            assert await pilot.click("#flow_load_ok"), "click missed #flow_load_ok"
            await _wait_for(
                pilot,
                lambda: len(app.query("#fx_lane_0")) > 0,
                "the imported lane",
            )
            assert await pilot.click("#fx_run"), "click missed #fx_run"
            await _wait_for(
                pilot,
                lambda: "S19-NO-TERMINATOR" in painted_log()
                and not app.query_one("#fx_run").disabled,
                "the failed run painted in the lane log",
                attempts=200,
            )
            log = painted_log()
            assert "S19-NO-TERMINATOR" in log, log
            assert "cut.s19" in log, log
            assert not (project_dir / "out.s19").exists(), (
                "WRITE-OUT ran despite the integrity notice"
            )

    asyncio.run(_drive())
