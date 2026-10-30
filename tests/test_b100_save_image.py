"""Batch-100 increment 5 — Save project saves the image you see (HLR-167).

Covers HLR-167 / LLR-167.1–LLR-167.8 (PH-1, D1, R-PC):

  - TC-B100-14 — LLR-167.1: the emit decision is made on DATA. The change
    document is re-derived onto a copy of the source image; Save project
    emits iff that data differs from the source's. A check document never
    counts; ``image_differs_from_source`` is only the fast path into the
    comparison; deciding writes nothing to the session map.
  - TC-B100-15 — LLR-167.2: ``_handle_save_dialog`` emits through the
    split (32 bytes per line, the source's S0, the landed image becomes the
    active variant) or byte-copies the source; MAC and A2L stay copies.
  - TC-B100-16 — LLR-167.3: the status of an emitting save names how many
    document entries the image carries and how many this save applied.
  - TC-B100-17 — LLR-167.4: a blocked re-derive refuses the whole save
    (0 files, 0 folders); an emit that returns ``ok=False`` writes no
    manifest and leaves no folder.
  - TC-B100-58 — LLR-167.5: ``mark_saved`` / ``differs_from_last_saved``
    and the three writers of the record (load, save-back, Save project).
  - TC-B100-59 — LLR-167.6: the save plan — Inc 5 rows (fresh, open
    project, pending patch, refused): the plan's rows equal the written
    tree by full path and action; planning writes 0 bytes and hashes no
    payload; ``project_gather_service`` gains no ``changes`` import.
  - TC-B100-69 — LLR-167.7: ``rederive_for_save`` writes 0 bytes into the
    session map; ``save_patched`` composed of the split writes the bytes
    the pre-split write path wrote, for 4 documents; SEC-4 (LED .56): a
    save-back with a junction project open leaves 0 entries in the other
    work area.
  - TC-B100-70 — LLR-167.8: a refused Save project keeps the Patch Editor's
    dirty flag set; a Save project that did not write the editor's document
    keeps it set too (see the increment packet §6 for the Inc 5 scope of
    this LLR).
  - AT-B100-05 — HLR-167 black-box: a pending patch, Save project by keys
    through the current dialog, reopen in a fresh app — the project image
    read by the independent reader equals source + patch.

Byte oracles: ``tests/support/independent_reader.py`` (never the app's own
loader) and raw file bytes.
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from textual.widgets import Label

import s19_app.tui.app as app_module
import s19_app.tui.services.change_service as change_service_module
import s19_app.tui.workspace as workspace_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.changes.model import DISPOSITION_APPLIED
from s19_app.tui.changes.model import DISPOSITION_BLOCKED
from s19_app.tui.screens import LoadFileScreen
from s19_app.tui.screens import LoadProjectScreen
from s19_app.tui.screens import SaveProjectScreen
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services import project_gather_service as gather_module
from s19_app.tui.services.change_service import ChangeService
from s19_app.tui.services.project_gather_service import PROJECT_CHECKS_DIR
from s19_app.tui.workspace import WORKAREA_DIRNAME
from s19_app.tui.workspace import WORKAREA_PATCHES
from s19_app.tui.workspace import WORKAREA_SUBDIR

from tests import b97_fixtures
from tests.support import b100_links
from tests.support import b100_projects as projects
from tests.support import b100_projects
from tests.support.independent_reader import read_hex
from tests.support.independent_reader import read_s19

ROOT = Path(__file__).resolve().parents[1]
CASE01_DIR = ROOT / "examples" / "case_01_basic_valid"
CASE02_S19 = ROOT / "examples" / "case_02_gaps_and_patch_targets" / "firmware.s19"

#: The acceptance patch (HLR-167's observable outcome).
PATCH_ADDRESS = 0x8000007C
PATCH_BYTES = (0xDE, 0xAD, 0xBE, 0xEF)
#: A second, non-overlapping entry inside case_01's image.
SECOND_ADDRESS = 0x80000060
SECOND_BYTES = (0xAA,)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _copy_case01(tmp_path: Path, *names: str) -> Path:
    """Scratch copies of case_01 files; returns their folder."""
    folder = tmp_path / "sources"
    folder.mkdir(parents=True, exist_ok=True)
    for name in names or ("firmware.s19",):
        shutil.copy2(CASE01_DIR / name, folder / name)
    return folder


def _source_data() -> dict:
    return read_s19(CASE01_DIR / "firmware.s19").data


def _patched(data: dict, address: int, run) -> dict:
    out = dict(data)
    for offset, byte in enumerate(run):
        out[address + offset] = byte
    return out


def _differing(left: dict, right: dict) -> list:
    return sorted(
        address
        for address in set(left) | set(right)
        if left.get(address) != right.get(address)
    )


def _s19_data_record_lengths(path: Path) -> list:
    """Data bytes per S1/S2/S3 record, parsed from the raw text."""
    widths = {"S1": 2, "S2": 3, "S3": 4}
    lengths = []
    for line in path.read_text(encoding="ascii").splitlines():
        kind = line[:2]
        if kind in widths:
            lengths.append(int(line[2:4], 16) - widths[kind] - 1)
    return lengths


def _tree_digests(root: Path) -> dict:
    if not root.exists():
        return {}
    return {
        str(p.resolve()).casefold(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


async def _wait_for(pilot, predicate, description: str, attempts: int = 200) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {description}")


def _status_text(app: S19TuiApp) -> str:
    return str(app.query_one("#log_line_4", Label).render())


def _painted_log(app: S19TuiApp) -> str:
    """The four painted log-strip lines, joined (oldest first)."""
    return "\n".join(
        str(app.query_one(f"#log_line_{i}", Label).render()) for i in (1, 2, 3, 4)
    )


def _payload(app: S19TuiApp, name: str):
    return app_module.SaveProjectPayload(
        parent_folder=str(app.workarea), project_name=name
    )


async def _load_image(pilot, app: S19TuiApp, path: Path) -> None:
    app.load_selected_file(path)
    await _wait_for(
        pilot,
        lambda: app.current_file is not None
        and app.current_file.path.name == path.name,
        f"the load of {path.name}",
    )


async def _load_project(pilot, app: S19TuiApp, name: str) -> None:
    app._handle_load_project(name)
    await _wait_for(
        pilot,
        lambda: app.current_project == name and app.current_file is not None,
        f"the project load of {name}",
    )


def _apply(app: S19TuiApp):
    loaded = app.current_file
    return app._change_service.apply(
        loaded.mem_map, loaded.ranges, loaded.mac_records, None
    )


def _add(app: S19TuiApp, address: int, run) -> None:
    app._change_service.add_entry(
        f"0x{address:08X}", "", " ".join(f"{byte:02X}" for byte in run)
    )


async def _save_back(pilot, app: S19TuiApp, filename: str) -> None:
    """The app's own save-back handler (the panel's decision message)."""
    app.on_patch_editor_panel_save_back_decision(
        PatchEditorPanel.SaveBackDecision(filename, 32)
    )
    await _wait_for(
        pilot,
        lambda: "Saved + verified" in _painted_log(app)
        or "not saved" in _painted_log(app).lower(),
        "the save-back outcome",
    )


async def _save(pilot, app: S19TuiApp, name: str) -> None:
    app._handle_save_dialog(_payload(app, name))
    await pilot.pause()


class _TrapDict(dict):
    """A session map that counts writes and can forbid iteration."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.writes = 0
        self.forbid_iteration = False

    def __setitem__(self, key, value) -> None:
        self.writes += 1
        super().__setitem__(key, value)

    def _guard(self) -> None:
        if self.forbid_iteration:
            raise AssertionError("the session map was iterated")

    def __iter__(self):
        self._guard()
        return super().__iter__()

    def keys(self):
        self._guard()
        return super().keys()

    def items(self):
        self._guard()
        return super().items()

    def values(self):
        self._guard()
        return super().values()


def _small_image() -> tuple:
    """A two-range image as a trap map plus its ranges."""
    data = {0x1000 + i: i for i in range(16)}
    data.update({0x2000 + i: 0x40 + i for i in range(8)})
    return _TrapDict(data), [(0x1000, 0x1010), (0x2000, 0x2008)]


# ---------------------------------------------------------------------------
# TC-B100-14 — LLR-167.1: the emit decision is made on data
# ---------------------------------------------------------------------------


def _decide(tmp_path: Path, scenario) -> tuple:
    """Load case_01, run ``scenario(app, pilot)`` (async), then return the
    pre-check value and the decision (emit, refusal)."""
    src = _copy_case01(tmp_path) / "firmware.s19"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_image(pilot, app, src)
            await scenario(app, pilot)
            mem_map = app.current_file.mem_map
            pre = app._change_service.image_differs_from_source(mem_map)
            before = dict(mem_map)
            step = app._decide_project_image()
            unchanged = dict(mem_map) == before
        return pre, step.emit, step.refusal, unchanged

    return asyncio.run(_drive())


def test_tc_b100_14_no_entry_copies(tmp_path: Path) -> None:
    """Empty document, unchanged image → copy (QC-3 empty)."""

    async def scenario(app, pilot) -> None:
        assert not app._change_service.document.entries

    pre, emit, refusal, _ = _decide(tmp_path, scenario)
    assert (pre, emit, refusal) == (False, False, None)


def test_tc_b100_14_new_bytes_emit(tmp_path: Path) -> None:
    """A change entry writing new bytes, applied → emit."""

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        assert _apply(app).counts[DISPOSITION_APPLIED] == 1

    pre, emit, refusal, _ = _decide(tmp_path, scenario)
    assert (pre, emit, refusal) == (True, True, None)


def test_tc_b100_14_same_bytes_copy(tmp_path: Path) -> None:
    """An entry that writes the bytes already there → copy (P-38: the
    round-2 rule emitted a byte-different ``_1`` file here)."""
    same = tuple(_source_data()[0x80000070 + i] for i in range(4))

    async def scenario(app, pilot) -> None:
        _add(app, 0x80000070, same)
        assert _apply(app).counts[DISPOSITION_APPLIED] == 1

    pre, emit, refusal, _ = _decide(tmp_path, scenario)
    assert (emit, refusal) == (False, None), (pre, emit, refusal)


def test_tc_b100_14_check_document_copies(tmp_path: Path) -> None:
    """A check document with entries never counts → copy, never a refusal
    (P-37: the round-2 rule re-derived it and every entry was blocked)."""

    async def scenario(app, pilot) -> None:
        doc = b97_fixtures.baseline_check(app.workarea / WORKAREA_PATCHES)
        result = app._change_service.load(str(doc), app.base_dir)
        assert result.ok, result.message
        assert app._change_service.document.kind == "check"
        assert app._change_service.document.entries

    pre, emit, refusal, _ = _decide(tmp_path, scenario)
    assert (emit, refusal) == (False, None), (pre, emit, refusal)


def test_tc_b100_14_applied_then_undone_copies(tmp_path: Path) -> None:
    """Applied, then the entry undone (the image still holds the applied
    bytes): the pre-check is true, the comparison runs, the re-derived
    data equals the source → copy."""

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)
        app._change_service.undo()
        assert not app._change_service.document.entries

    pre, emit, refusal, _ = _decide(tmp_path, scenario)
    assert (pre, emit, refusal) == (True, False, None)


def test_tc_b100_14_unapplied_entry_emits(tmp_path: Path) -> None:
    """Only an unapplied change entry writing new bytes: the pre-check is
    false, the comparison still runs → emit."""

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)

    pre, emit, refusal, _ = _decide(tmp_path, scenario)
    assert (pre, emit, refusal) == (False, True, None)


def test_tc_b100_14_save_back_then_emit(tmp_path: Path) -> None:
    """Save-back, then the decision: pre-check true → emit."""

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)
        await _save_back(pilot, app, "firmware.s19")
        assert "Saved + verified" in _painted_log(app)

    pre, emit, refusal, _ = _decide(tmp_path, scenario)
    assert (pre, emit, refusal) == (True, True, None)


def test_tc_b100_14_deciding_writes_nothing(tmp_path: Path) -> None:
    """0 writes to the session map while deciding (the trap map is the
    session map from before the apply, so the journal binds to it)."""

    async def scenario(app, pilot) -> None:
        trap = _TrapDict(app.current_file.mem_map)
        app.current_file.mem_map = trap
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)
        _add(app, SECOND_ADDRESS, SECOND_BYTES)
        trap.writes = 0

    src = _copy_case01(tmp_path) / "firmware.s19"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_image(pilot, app, src)
            await scenario(app, pilot)
            trap = app.current_file.mem_map
            step = app._decide_project_image()
        return step.emit, trap.writes

    emit, writes = asyncio.run(_drive())
    assert emit is True
    assert writes == 0, f"deciding wrote {writes} bytes into the session map"


# ---------------------------------------------------------------------------
# TC-B100-15 — LLR-167.2: emit through the split, or copy the source
# ---------------------------------------------------------------------------


def _save_session(
    tmp_path: Path, scenario, name: str = "P1", statuses: list | None = None
) -> tuple:
    """Load case_01, run ``scenario``, Save project ``name``; return the
    app's status lines, the project folder and the current variant id.
    ``statuses``, when given, collects the FULL message of every
    ``set_status`` call: the log line is capped at the terminal width, so a
    long work-area path clips it."""
    src = _copy_case01(tmp_path) / "firmware.s19"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        if statuses is not None:
            real_set_status = app.set_status

            def _capture(message, *args, **kwargs):
                statuses.append(str(message))
                return real_set_status(message, *args, **kwargs)

            app.set_status = _capture
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, src)
            await scenario(app, pilot)
            await _save(pilot, app, name)
            await _wait_for(
                pilot,
                lambda: _status_text(app).startswith("Saved project to")
                or "NOT saved" in _status_text(app)
                or "Manifest verify MISMATCH" in _status_text(app),
                "the Save project outcome",
            )
            variant = app.current_file.variant_id
        return list(app.log_lines), app.workarea / name, variant

    return asyncio.run(_drive())


def test_tc_b100_15_patched_s19_is_emitted(tmp_path: Path) -> None:
    """A patched S19 → the project image is source + document (0 differing
    addresses), every data record ≤ 32 bytes, the S0 equal to the
    source's; the landed image is the active variant."""

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)

    lines, project, variant = _save_session(tmp_path, scenario)
    image = project / "firmware.s19"
    written = read_s19(image)
    assert written.errors == [], written.errors
    expected = _patched(_source_data(), PATCH_ADDRESS, PATCH_BYTES)
    assert _differing(written.data, expected) == []
    lengths = _s19_data_record_lengths(image)
    assert lengths and max(lengths) <= 32 and max(lengths) > 16, lengths
    assert written.header == read_s19(CASE01_DIR / "firmware.s19").header
    assert variant == "firmware"
    assert sorted(p.name for p in project.iterdir()) == [
        "firmware.s19",
        "project.json",
    ]


def test_tc_b100_15_check_document_only_copies(tmp_path: Path) -> None:
    """Check document only → byte copy (0 differing bytes) + the document
    under ``checks/``, 0 refusals (the TC-700 pattern)."""

    async def scenario(app, pilot) -> None:
        doc = b97_fixtures.baseline_check(app.workarea / WORKAREA_PATCHES)
        assert app._change_service.load(str(doc), app.base_dir).ok

    lines, project, _ = _save_session(tmp_path, scenario)
    assert not any("NOT saved" in line for line in lines), lines
    assert (project / "firmware.s19").read_bytes() == (
        CASE01_DIR / "firmware.s19"
    ).read_bytes()
    assert (project / PROJECT_CHECKS_DIR / "baseline.chk.json").is_file()


def test_tc_b100_15_unchanged_document_copies(tmp_path: Path) -> None:
    """A change entry that writes the bytes already there → byte copy,
    0 new variants."""
    same = tuple(_source_data()[0x80000070 + i] for i in range(4))

    async def scenario(app, pilot) -> None:
        _add(app, 0x80000070, same)
        _apply(app)

    lines, project, _ = _save_session(tmp_path, scenario)
    assert (project / "firmware.s19").read_bytes() == (
        CASE01_DIR / "firmware.s19"
    ).read_bytes()
    primaries = [p.name for p in project.iterdir() if p.suffix == ".s19"]
    assert primaries == ["firmware.s19"], primaries


def test_tc_b100_15_entry_removed_after_apply_is_absent(tmp_path: Path) -> None:
    """Two entries applied, one removed → the saved image holds only the
    remaining one; the removed address holds the source byte."""

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _add(app, SECOND_ADDRESS, SECOND_BYTES)
        assert _apply(app).counts[DISPOSITION_APPLIED] == 2
        app._change_service.remove_entry(f"0x{SECOND_ADDRESS:08X}")

    _, project, _ = _save_session(tmp_path, scenario)
    written = read_s19(project / "firmware.s19").data
    expected = _patched(_source_data(), PATCH_ADDRESS, PATCH_BYTES)
    assert _differing(written, expected) == []


def _hex_line(address: int, data: bytes, record_type: int = 0) -> str:
    body = bytes([len(data), (address >> 8) & 0xFF, address & 0xFF, record_type]) + data
    return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()


def test_tc_b100_15_patched_hex_is_emitted(tmp_path: Path) -> None:
    """A patched Intel HEX source → 0 differing addresses."""
    src = tmp_path / "sources" / "image.hex"
    src.parent.mkdir(parents=True)
    source = {0x1000 + i: i for i in range(32)}
    src.write_text(
        "\n".join(
            [
                _hex_line(0x1000, bytes(range(16))),
                _hex_line(0x1010, bytes(range(16, 32))),
                ":00000001FF",
            ]
        )
        + "\n",
        encoding="ascii",
    )

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, src)
            _add(app, 0x1004, (0xAA, 0xBB))
            _apply(app)
            await _save(pilot, app, "H1")
            await _wait_for(
                pilot,
                lambda: _status_text(app).startswith("Saved project to"),
                "the HEX Save project",
            )
        return app.workarea / "H1"

    project = asyncio.run(_drive())
    written = read_hex(project / "image.hex")
    assert written.errors == [], written.errors
    assert _differing(written.data, _patched(source, 0x1004, (0xAA, 0xBB))) == []


def test_tc_b100_15_mac_and_a2l_stay_byte_copies(tmp_path: Path) -> None:
    """A project holding S19 + MAC + A2L, patched and saved as another
    project → the image emitted, the MAC and the A2L byte-identical."""
    base = tmp_path / "app"

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=base)
        p1 = app.workarea / "P1"
        p1.mkdir(parents=True)
        for name in ("firmware.s19", "firmware.mac", "firmware.a2l"):
            shutil.copy2(CASE01_DIR / name, p1 / name)
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_project(pilot, app, "P1")
            assert app.current_file.mac_path is not None
            assert app.current_a2l_path is not None
            _add(app, PATCH_ADDRESS, PATCH_BYTES)
            _apply(app)
            await _save(pilot, app, "P2")
            await _wait_for(
                pilot,
                lambda: _status_text(app).startswith("Saved project to"),
                "the P2 save",
            )
        return app.workarea / "P2"

    p2 = asyncio.run(_drive())
    for name in ("firmware.mac", "firmware.a2l"):
        assert (p2 / name).read_bytes() == (CASE01_DIR / name).read_bytes(), name
    expected = _patched(_source_data(), PATCH_ADDRESS, PATCH_BYTES)
    assert _differing(read_s19(p2 / "firmware.s19").data, expected) == []


def test_tc_b100_15_save_back_then_save_project_keeps_the_patch(
    tmp_path: Path,
) -> None:
    """Save-back, then Save project → the patch is in the project image
    (A-08: deciding on ``differs_from_last_saved`` would copy the
    unpatched source here, because the save-back recorded the state)."""

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)
        await _save_back(pilot, app, "firmware.s19")
        assert not app._change_service.differs_from_last_saved(
            app.current_file.mem_map
        )

    _, project, _ = _save_session(tmp_path, scenario)
    expected = _patched(_source_data(), PATCH_ADDRESS, PATCH_BYTES)
    assert _differing(read_s19(project / "firmware.s19").data, expected) == []


def test_tc_b100_15_clashing_name_lands_as_the_next_variant(tmp_path: Path) -> None:
    """The target already holds a DIFFERENT ``firmware.s19`` → the patched
    image lands as ``firmware_1.s19`` and becomes the active variant; the
    existing file is untouched."""
    base = tmp_path / "app"
    existing = CASE02_S19.read_bytes()

    async def scenario(app, pilot) -> None:
        target = app.workarea / "P1"
        target.mkdir(parents=True)
        (target / "firmware.s19").write_bytes(existing)
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)

    _, project, variant = _save_session(tmp_path, scenario)
    assert (project / "firmware.s19").read_bytes() == existing
    expected = _patched(_source_data(), PATCH_ADDRESS, PATCH_BYTES)
    assert _differing(read_s19(project / "firmware_1.s19").data, expected) == []
    assert variant == "firmware_1"
    manifest = (project / "project.json").read_text(encoding="utf-8")
    assert '"active_variant": "firmware_1"' in manifest, manifest


# ---------------------------------------------------------------------------
# TC-B100-16 — LLR-167.3: the status names the entries the image carries
# ---------------------------------------------------------------------------


def test_tc_b100_16_one_applied_entry(tmp_path: Path) -> None:
    """1 applied entry → the status carries 1 entry and 0 applied by this
    save; the verify line names it through ``save_back_status_suffix``."""

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)

    statuses: list = []
    lines, _, _ = _save_session(tmp_path, scenario, statuses=statuses)
    final = statuses[-1]
    assert final.startswith("Saved project to"), statuses
    assert "firmware.s19 + 1 change entry, 0 applied by this save" in final, final
    assert any(
        "1 entry applied before this save (0x8000007C)" in line for line in lines
    ), lines


def test_tc_b100_16_entry_added_after_the_apply(tmp_path: Path) -> None:
    """1 applied + 1 added after the apply → 2 entries, 1 applied by this
    save."""

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)
        _add(app, SECOND_ADDRESS, SECOND_BYTES)

    statuses: list = []
    lines, project, _ = _save_session(tmp_path, scenario, statuses=statuses)
    final = statuses[-1]
    assert "firmware.s19 + 2 change entries, 1 applied by this save" in final, final
    assert any(
        "includes 1 entry not applied before this save (0x80000060)" in line
        for line in lines
    ), lines
    expected = _patched(
        _patched(_source_data(), PATCH_ADDRESS, PATCH_BYTES),
        SECOND_ADDRESS,
        SECOND_BYTES,
    )
    assert _differing(read_s19(project / "firmware.s19").data, expected) == []


# ---------------------------------------------------------------------------
# TC-B100-17 — LLR-167.4: a blocked re-derive refuses the whole save
# ---------------------------------------------------------------------------


def _one_blocked_document_text() -> str:
    """A change document whose second entry has a malformed address: the
    reader drops that entry and keeps an ERROR finding, so the ONE entry
    left is blocked by the apply gate."""
    return (
        '{"format": "s19app-changeset", "version": "2.0", "kind": "change",'
        ' "encoding": "utf-8", "value_mode": "text", "entries": ['
        '{"type": "bytes", "address": "0x8000007C", "bytes": "DE AD BE EF"},'
        '{"type": "bytes", "address": "0xZZ", "bytes": "01"}]}'
    )


def test_tc_b100_17_blocked_entry_refuses_the_whole_save(tmp_path: Path) -> None:
    """A document with 1 blocked entry → 1 status naming it, 0 files,
    0 folders left."""
    before: dict = {}

    async def scenario(app, pilot) -> None:
        app._change_service.load_text(_one_blocked_document_text())
        document = app._change_service.document
        assert len(document.entries) == 1 and document.has_errors, (
            document.entries,
            document.issues,
        )
        before.update(_tree_digests(app.workarea))

    lines, project, _ = _save_session(tmp_path, scenario)
    refusal = lines[-1]
    assert "Project NOT saved: 1 blocked entry (0x8000007C)" in refusal, lines
    assert not project.exists(), "a refused save created the project folder"
    assert _tree_digests(project.parent) == before


def test_tc_b100_17_emit_refusal_writes_no_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``save_patched`` / the emit returning ``ok=False`` → no file, no
    manifest, the folder this save created removed."""

    def _refuse(*args, **kwargs):
        return None, [
            change_service_module.ValidationIssue(
                code="MF-WRITE-CONTAINMENT",
                message="forced emit refusal",
                severity=change_service_module.ValidationSeverity.WARNING,
                artifact="change",
            )
        ]

    monkeypatch.setattr(change_service_module, "save_patched_image", _refuse)

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)

    lines, project, _ = _save_session(tmp_path, scenario)
    assert "the patched image was not written: forced emit refusal" in lines[-1], lines
    assert not project.exists(), sorted(project.rglob("*"))


def test_tc_b100_17_verify_reread_failure_rolls_the_emit_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review F1 / SEC-7 (LLR-167.4, LED .53): the emit LANDS, then the
    verify re-read raises ``OSError`` (an AV or indexer lock on the
    just-written file) → the status says not saved, and the emitted image
    and the folder this save created are both gone. The emitted file must
    join the rollback list the moment it lands — recording it only after
    the emit returns leaves ``P1/firmware.s19`` and a folder ``list_projects``
    treats as a project."""

    def _refuse_reread(path, image, kind):
        assert Path(path).is_file(), "the emit has not landed yet"
        raise PermissionError(13, "re-read refused", str(path))

    monkeypatch.setattr(
        change_service_module, "verify_written_image", _refuse_reread
    )
    before: dict = {}

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        _apply(app)
        before.update(_tree_digests(app.workarea))

    lines, project, _ = _save_session(tmp_path, scenario)
    assert "Project NOT saved: could not save" in lines[-1], lines
    assert not project.exists(), sorted(project.rglob("*"))
    assert _tree_digests(project.parent) == before


def test_tc_b100_17_non_os_error_after_the_emit_rolls_back_then_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review F1 / SEC-7 (LLR-167.4): an error that is not an ``OSError``
    after the emit landed still rolls the save back — no folder, no
    image — and then surfaces (it is a defect, never swallowed)."""

    def _defect(path, image, kind):
        raise ValueError("forced defect after the emit")

    monkeypatch.setattr(change_service_module, "verify_written_image", _defect)
    src = _copy_case01(tmp_path) / "firmware.s19"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, src)
            _add(app, PATCH_ADDRESS, PATCH_BYTES)
            _apply(app)
            before = _tree_digests(app.workarea)
            with pytest.raises(ValueError, match="forced defect"):
                app._handle_save_dialog(_payload(app, "P1"))
            return before, _tree_digests(app.workarea), app.workarea / "P1"

    before, after, project = asyncio.run(_drive())
    assert not project.exists(), sorted(project.rglob("*"))
    assert after == before


def test_tc_b100_17_failed_manifest_write_adopts_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review F4 (LLR-167.2, LLR-167.4): an UNAPPLIED entry makes the save
    emit, then the manifest write fails → the save rolls back AND the
    session view is not the re-derived image: the session map still holds
    the source bytes at the entry and no summary carries a saved path.
    Adopting before ``project.json`` is on disk would show the operator a
    patched image that no file holds."""
    monkeypatch.setattr(
        S19TuiApp, "_write_and_verify_manifest", lambda self, *a, **k: False
    )
    seen: dict = {}

    async def scenario(app, pilot) -> None:
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        seen["map"] = app.current_file.mem_map
        seen["service"] = app._change_service

    lines, project, _ = _save_session(tmp_path, scenario)
    assert "project.json was not written" in lines[-1], lines
    assert not project.exists(), sorted(project.rglob("*"))
    source = _source_data()
    span = range(PATCH_ADDRESS, PATCH_ADDRESS + len(PATCH_BYTES))
    assert [seen["map"][a] for a in span] == [source[a] for a in span]
    summary = seen["service"].last_summary
    assert summary is None or summary.saved_path is None, summary.saved_path


# ---------------------------------------------------------------------------
# Review F2 — LLR-164.4: an unreadable source refuses, the app keeps running
# ---------------------------------------------------------------------------


class _UnreadableHandle:
    """An open handle whose read fails like a byte-range-locked file: the
    open succeeds and the read raises ``PermissionError`` (no filename)."""

    def __init__(self, handle) -> None:
        self._handle = handle

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self._handle.close()

    def read(self, *args):
        raise PermissionError(13, "Permission denied")


async def _save_as_callback(pilot, app: S19TuiApp, name: str) -> None:
    """Run Save project the way the dialog's dismiss runs it: as an app
    callback, so an escaping exception ends the session."""
    app.call_next(app._handle_save_dialog, _payload(app, name))
    for _ in range(10):
        await pilot.pause()


@pytest.mark.parametrize("locked", ["image", "a2l"])
def test_f2_unreadable_source_refuses_and_the_app_keeps_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, locked: str
) -> None:
    """Review F2 (LLR-164.4): a source the plan must digest cannot be read
    — the image on the copy branch, or the A2L while a patch is pending on
    the emit branch → the status says not saved and names the file, no
    folder exists, the app is still running, and the pending patch is
    still in memory (base painted ``… Nothing written.`` and kept
    running; the decide/plan block let ``PermissionError`` escape)."""
    folder = _copy_case01(tmp_path, "firmware.s19", "firmware.a2l")
    real_open = open

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, folder / "firmware.s19")
            if locked == "a2l":
                app.load_a2l_from_path(folder / "firmware.a2l")
                await _wait_for(
                    pilot, lambda: app.current_a2l_path is not None, "the A2L"
                )
                _add(app, PATCH_ADDRESS, PATCH_BYTES)
                _apply(app)
                target = app.current_a2l_path
            else:
                target = app.current_file.path

            def _open(file, mode="r", *args, **kwargs):
                handle = real_open(file, mode, *args, **kwargs)
                if "b" in mode and Path(file) == Path(target):
                    return _UnreadableHandle(handle)
                return handle

            monkeypatch.setattr(app_module, "open", _open, raising=False)
            await _save_as_callback(pilot, app, "P1")
            monkeypatch.undo()
            status = _status_text(app)
            alive = (app.is_running, app.return_code)
            unsaved = app._change_service.differs_from_last_saved(
                app.current_file.mem_map
            )
            return status, alive, unsaved, target.name, app.workarea / "P1"

    status, alive, unsaved, name, project = asyncio.run(_drive())
    assert status.startswith("Project NOT saved:"), status
    assert f"{name} could not be read" in status and "Nothing written." in status
    assert alive == (True, None)
    assert not project.exists()
    assert unsaved is (locked == "a2l")


@pytest.mark.skipif(sys.platform != "win32", reason="msvcrt byte-range lock")
def test_f2_byte_range_locked_image_refuses_and_the_app_keeps_running(
    tmp_path: Path,
) -> None:
    """Review F2, probe P2b: the image byte-range-locked by another handle
    (copy branch), Save project run as an app callback → the refusal is
    painted, no folder exists and the session is still running."""
    import msvcrt

    src = _copy_case01(tmp_path) / "firmware.s19"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, src)
            image = app.current_file.path
            size = image.stat().st_size
            with open(image, "r+b") as handle:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, size)
                try:
                    await _save_as_callback(pilot, app, "P1")
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, size)
            return (
                _status_text(app),
                (app.is_running, app.return_code),
                app.workarea / "P1",
            )

    status, alive, project = asyncio.run(_drive())
    assert status.startswith("Project NOT saved:"), status
    assert "could not be read" in status and "Nothing written." in status
    assert alive == (True, None)
    assert not project.exists()


# ---------------------------------------------------------------------------
# TC-B100-58 — LLR-167.5: the unsaved predicate and the saved-state record
# ---------------------------------------------------------------------------


def test_tc_b100_58_predicate_sequence_unit() -> None:
    """loaded → False; applied → True; recorded → False; patched again →
    True; recorded, then undone and re-applied → True; nothing journaled →
    False; the predicate and the record never iterate the session map."""
    service = ChangeService()
    mem_map, ranges = _small_image()
    service.mark_saved(mem_map)
    mem_map.forbid_iteration = True
    assert service.differs_from_last_saved(mem_map) is False
    mem_map.forbid_iteration = False

    service.add_entry("0x1000", "", "AA BB")
    service.apply(mem_map, ranges, None, None)
    mem_map.forbid_iteration = True
    assert service.differs_from_last_saved(mem_map) is True
    service.mark_saved(mem_map)
    assert service.differs_from_last_saved(mem_map) is False
    mem_map.forbid_iteration = False

    service.add_entry("0x2000", "", "01")
    service.apply(mem_map, ranges, None, None)
    mem_map.forbid_iteration = True
    assert service.differs_from_last_saved(mem_map) is True
    service.mark_saved(mem_map)
    assert service.differs_from_last_saved(mem_map) is False
    mem_map.forbid_iteration = False

    # "saved → undone": the undo changes the document; the apply that
    # follows brings the image back to the source — now unsaved.
    service.undo()
    service.apply(mem_map, ranges, None, None)
    mem_map.forbid_iteration = True
    assert service.differs_from_last_saved(mem_map) is True
    mem_map.forbid_iteration = False

    fresh = ChangeService()
    other, _ = _small_image()
    other.forbid_iteration = True
    assert fresh.differs_from_last_saved(other) is False


def _predicate_after(tmp_path: Path, scenario) -> tuple:
    src = _copy_case01(tmp_path) / "firmware.s19"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, src)
            loaded = app._change_service.differs_from_last_saved(
                app.current_file.mem_map
            )
            _add(app, PATCH_ADDRESS, PATCH_BYTES)
            _apply(app)
            applied = app._change_service.differs_from_last_saved(
                app.current_file.mem_map
            )
            await scenario(app, pilot)
            after = app._change_service.differs_from_last_saved(
                app.current_file.mem_map
            )
        return loaded, applied, after

    return asyncio.run(_drive())


def test_tc_b100_58_save_project_records_the_saved_state(tmp_path: Path) -> None:
    """loaded → False; applied → True; applied → Save project → False."""

    async def scenario(app, pilot) -> None:
        await _save(pilot, app, "P1")
        await _wait_for(
            pilot,
            lambda: _status_text(app).startswith("Saved project to"),
            "the Save project success line",
        )

    assert _predicate_after(tmp_path, scenario) == (False, True, False)


def test_tc_b100_58_save_back_records_the_saved_state(tmp_path: Path) -> None:
    """applied → save-back → False."""

    async def scenario(app, pilot) -> None:
        await _save_back(pilot, app, "patched.s19")
        assert "Saved + verified" in _painted_log(app)

    assert _predicate_after(tmp_path, scenario) == (False, True, False)


def test_tc_b100_58_mac_attach_keeps_an_unsaved_patch_unsaved(
    tmp_path: Path,
) -> None:
    """Review F5 (LLR-167.5): attaching a MAC re-installs the SAME image
    dict, so it is not a load — an applied, unsaved patch must stay
    unsaved, or the Inc 10 load question would not ask before replacing
    it."""
    folder = _copy_case01(tmp_path, "firmware.s19", "firmware.mac")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, folder / "firmware.s19")
            _add(app, PATCH_ADDRESS, PATCH_BYTES)
            _apply(app)
            mem_map = app.current_file.mem_map
            assert app._change_service.differs_from_last_saved(mem_map)
            app.load_selected_file(folder / "firmware.mac")
            await _wait_for(
                pilot,
                lambda: app.current_file is not None
                and app.current_file.mac_path is not None,
                "the MAC attach",
            )
            return (
                app.current_file.mem_map is mem_map,
                app._change_service.differs_from_last_saved(
                    app.current_file.mem_map
                ),
            )

    assert asyncio.run(_drive()) == (True, True)


# ---------------------------------------------------------------------------
# TC-B100-59 — LLR-167.6: one save plan, executed
# ---------------------------------------------------------------------------


def _capture_plans(monkeypatch: pytest.MonkeyPatch) -> list:
    plans: list = []
    original = app_module.plan_project_save

    def _spy(*args, **kwargs):
        plan = original(*args, **kwargs)
        plans.append(plan)
        return plan

    monkeypatch.setattr(app_module, "plan_project_save", _spy)
    return plans


def _assert_plan_equals_tree(plan, before: dict, after: dict) -> None:
    """The plan's rows equal the written tree, by full path and action."""
    written = {
        path for path, digest in after.items() if before.get(path) != digest
    }
    planned_writes = {
        str(row.landing).casefold()
        for row in plan.rows
        if row.action in ("new", "rewrite")
    }
    assert written == planned_writes, (sorted(written), sorted(planned_writes))
    for row in plan.rows:
        key = str(row.landing).casefold()
        if row.action == "new":
            assert key not in before and key in after, row
        elif row.action == "rewrite":
            assert key in before and key in after, row
        elif row.action == "keep":
            assert before.get(key) == after.get(key) is not None, row
        else:
            raise AssertionError(f"unexpected action at Inc 5: {row}")


def test_tc_b100_59_fresh_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh target, S19 + A2L loaded, nothing patched → image, A2L and
    ``project.json`` rows, all ``new``; the tree equals the rows."""
    plans = _capture_plans(monkeypatch)
    folder = _copy_case01(tmp_path, "firmware.s19", "firmware.a2l")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, folder / "firmware.s19")
            app.load_a2l_from_path(folder / "firmware.a2l")
            await _wait_for(
                pilot, lambda: app.current_a2l_path is not None, "the A2L load"
            )
            before = _tree_digests(app.workarea)
            await _save(pilot, app, "P1")
            await _wait_for(
                pilot,
                lambda: _status_text(app).startswith("Saved project to"),
                "the save",
            )
            after = _tree_digests(app.workarea)
        return before, after, app.workarea / "P1"

    before, after, project = asyncio.run(_drive())
    assert len(plans) == 1
    plan = plans[0]
    assert plan.target_kind == "new" and plan.refusal is None
    assert [(row.role, row.landing.name, row.action) for row in plan.rows] == [
        ("image", "firmware.s19", "new"),
        ("a2l", "firmware.a2l", "new"),
        ("manifest", "project.json", "new"),
    ]
    assert plan.image == "firmware.s19 unchanged copy"
    assert plan.manifest_keys[:4] == (
        "schema_version",
        "active_variant",
        "batch",
        "assignments",
    )
    # Review F8: the plan's keys are the keys the written project.json
    # carries (no gather ran, so ``gathered`` is rightly absent).
    written = json.loads((project / "project.json").read_text(encoding="utf-8"))
    assert tuple(written) == plan.manifest_keys
    _assert_plan_equals_tree(plan, before, after)


def test_tc_b100_59_files_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Inc 7 (LED .63, LED .19 B-06): the plan's ``project.json`` keys
    include ``files``, and the written ``files`` records name exactly the
    files the plan's rows land, each with the size and SHA-256 of its bytes.

    RED (base 80052cb): neither the plan nor the manifest has ``files``."""
    import hashlib

    plans = _capture_plans(monkeypatch)
    folder = _copy_case01(tmp_path, "firmware.s19", "firmware.a2l")

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, folder / "firmware.s19")
            app.load_a2l_from_path(folder / "firmware.a2l")
            await _wait_for(pilot, lambda: app.current_a2l_path is not None, "the A2L load")
            await _save(pilot, app, "P1")
            await _wait_for(
                pilot, lambda: _status_text(app).startswith("Saved project to"), "the save"
            )
        return app.workarea / "P1"

    project = asyncio.run(_drive())
    plan = plans[0]
    assert "files" in plan.manifest_keys, plan.manifest_keys
    written = json.loads((project / "project.json").read_text(encoding="utf-8"))
    landed = {row.landing.name for row in plan.rows if row.role != "manifest"}
    assert set(written.get("files", {})) == landed, written
    for name, record in written["files"].items():
        data = (project / name).read_bytes()
        assert record == {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    assert tuple(written) == plan.manifest_keys


def _carried_derived_from_save(tmp_path: Path) -> Path:
    """Reviewer probe P1: open project P1 (S19 + MAC, ``files`` and one
    ``derived_from`` record) and Save project P1 again, unchanged (a copy:
    the record is carried, nothing is emitted)."""

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=tmp_path / "app")
        p1 = app.workarea / "P1"
        p1.mkdir(parents=True)
        for name in ("firmware.s19", "firmware.mac"):
            shutil.copy2(CASE01_DIR / name, p1 / name)
        (p1 / "project.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "active_variant": "firmware",
                    "files": projects.file_records(p1),
                    "derived_from": {
                        "firmware.s19": {"base": "orig.s19", "sha256": "a" * 64, "differ": 3}
                    },
                }
            ),
            encoding="utf-8",
        )
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_project(pilot, app, "P1")
            await _save(pilot, app, "P1")
            await _wait_for(
                pilot,
                lambda: _status_text(app).startswith("Saved project to"),
                "the save into the open project",
            )
        return p1

    return asyncio.run(_drive())


@pytest.mark.parametrize(
    "case, derived",
    [("carried", True), ("emit", True), ("emit-base-unreadable", False)],
)
def test_tc_b100_59_plan_keys_equal_written_keys_with_derived_from(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, derived: bool
) -> None:
    """Inc 7 corrective F3 (LLR-167.6: the plan lists the keys the app
    writes; LLR-168.4): the plan's ``project.json`` keys equal the keys the
    save writes, ``derived_from`` included, in all three cases — a record
    carried from the target (a copy into the open project), an emit that
    records its base, and an emit whose base cannot be read again (no
    record, so the plan shows none).

    RED (corrective-pass base): ``carried`` — the plan omits
    ``derived_from``; ``emit-base-unreadable`` — the plan lists it, the
    save writes none."""
    plans = _capture_plans(monkeypatch)
    if case == "carried":
        project = _carried_derived_from_save(tmp_path)
    else:
        if case == "emit-base-unreadable":

            def _unreadable(path):
                raise OSError(13, "Permission denied", str(path))

            monkeypatch.setattr(app_module, "_image_map", _unreadable)

        async def scenario(app, pilot) -> None:
            _add(app, PATCH_ADDRESS, PATCH_BYTES)
            _apply(app)

        _lines, project, _variant = _save_session(tmp_path, scenario)
    written = json.loads((project / "project.json").read_text(encoding="utf-8"))
    plan = plans[-1]
    assert ("derived_from" in written) is derived, written
    assert tuple(written) == plan.manifest_keys, (tuple(written), plan.manifest_keys)


def _open_project_session(tmp_path: Path, patch: bool) -> tuple:
    """P1 holds S19 + MAC (no A2L: a save into a project that already
    holds an A2L is refused by the pre-existing single-A2L guard, even for
    its own A2L — recorded in the increment packet §6)."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        p1 = app.workarea / "P1"
        p1.mkdir(parents=True)
        for name in ("firmware.s19", "firmware.mac"):
            shutil.copy2(CASE01_DIR / name, p1 / name)
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_project(pilot, app, "P1")
            if patch:
                _add(app, PATCH_ADDRESS, PATCH_BYTES)
                _apply(app)
            before = _tree_digests(app.workarea)
            await _save(pilot, app, "P1")
            await _wait_for(
                pilot,
                lambda: _status_text(app).startswith("Saved project to"),
                "the save into the open project",
            )
            after = _tree_digests(app.workarea)
        return before, after

    return asyncio.run(_drive())


def test_tc_b100_59_open_project_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The open project saved again unchanged → image and MAC ``keep``,
    ``project.json`` ``new`` (the seeded project had none);
    nothing else is written."""
    plans = _capture_plans(monkeypatch)
    before, after = _open_project_session(tmp_path, patch=False)
    plan = plans[-1]
    assert plan.target_kind == "open project"
    assert [(row.role, row.landing.name, row.action) for row in plan.rows] == [
        ("image", "firmware.s19", "keep"),
        ("mac", "firmware.mac", "keep"),
        ("manifest", "project.json", "new"),
    ]
    _assert_plan_equals_tree(plan, before, after)


def test_tc_b100_59_pending_patch_in_the_open_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pending patch saved into the open project → the image row is
    ``firmware_1.s19`` ``new`` (a clashing landing name), the MAC ``keep``;
    the tree equals the rows."""
    plans = _capture_plans(monkeypatch)
    before, after = _open_project_session(tmp_path, patch=True)
    plan = plans[-1]
    assert [(row.role, row.landing.name, row.action) for row in plan.rows] == [
        ("image", "firmware_1.s19", "new"),
        ("mac", "firmware.mac", "keep"),
        ("manifest", "project.json", "new"),
    ]
    assert plan.image == "firmware.s19 + 1 change entry, 0 applied by this save"
    _assert_plan_equals_tree(plan, before, after)


def test_tc_b100_59_refused_plan_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A blocked document → the plan carries the refusal and no row;
    0 files written."""
    plans = _capture_plans(monkeypatch)
    before: dict = {}

    async def scenario(app, pilot) -> None:
        app._change_service.load_text(_one_blocked_document_text())
        before.update(_tree_digests(app.workarea))

    _, project, _ = _save_session(tmp_path, scenario)
    plan = plans[-1]
    assert plan.rows == () and "1 blocked entry" in (plan.refusal or "")
    assert _tree_digests(project.parent) == before


@pytest.mark.parametrize("patch", [True, False], ids=["emit", "copy"])
def test_tc_b100_59_landing_that_differs_from_its_row_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patch: bool
) -> None:
    """Review F3 (LLR-163.7, LLR-167.6): another writer claims the planned
    landing between the plan and the placement, so the image lands at
    ``firmware_1.s19`` instead of the planned ``firmware.s19`` → the save
    refuses with a line naming BOTH paths, removes the file it wrote and
    writes no ``project.json``; the other writer's file survives
    byte-identical. A silent mismatch would leave a project whose files
    are not the ones the plan showed."""
    foreign = b"S0030000FC\r\nS9030000FC\r\n"
    original = app_module.plan_project_save

    def _plan_then_race(target, **kwargs):
        plan = original(target, **kwargs)
        Path(target).mkdir(parents=True, exist_ok=True)
        (Path(target) / "firmware.s19").write_bytes(foreign)
        return plan

    monkeypatch.setattr(app_module, "plan_project_save", _plan_then_race)
    # The painted line is capped at the terminal width; the full message is
    # read where the app sets it.
    statuses: list = []
    real_set_status = S19TuiApp.set_status

    def _set_status(self, message, *args, **kwargs):
        statuses.append(str(message))
        return real_set_status(self, message, *args, **kwargs)

    monkeypatch.setattr(S19TuiApp, "set_status", _set_status)

    async def scenario(app, pilot) -> None:
        if patch:
            _add(app, PATCH_ADDRESS, PATCH_BYTES)
            _apply(app)

    _save_session(tmp_path, scenario)
    project = _workarea(tmp_path / "app") / "P1"
    refusal = statuses[-1]
    planned = f"{os.sep}P1{os.sep}firmware.s19 (new) but the file landed at "
    landed = f"{os.sep}P1{os.sep}firmware_1.s19 (new)"
    assert refusal.startswith("Project NOT saved: the plan named "), statuses
    assert planned in refusal and landed in refusal, refusal
    assert sorted(p.name for p in project.iterdir()) == ["firmware.s19"]
    assert (project / "firmware.s19").read_bytes() == foreign


def test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``plan_project_save`` over a target holding files of other sizes:
    0 bytes written, 0 digests computed by the planner (the digests are
    inputs), and the session map is untouched by the app's planning."""
    hashed: list = []
    original_hash_file = workspace_module._hash_file
    monkeypatch.setattr(
        workspace_module,
        "_hash_file",
        lambda path: hashed.append(path) or original_hash_file(path),
    )
    workarea = _workarea(tmp_path / "app")
    target = workarea / "P1"
    target.mkdir(parents=True)
    (target / "firmware.s19").write_bytes(b"S9030000FC\n")
    before = _tree_digests(workarea)
    payload = b"emitted image bytes"
    plan = gather_module.plan_project_save(
        target,
        target_kind=gather_module.PLAN_TARGET_MERGE,
        files=[
            gather_module.PlannedFile(
                "image",
                tmp_path / "src.s19",
                "firmware.s19",
                hashlib.sha256(payload).hexdigest(),
                len(payload),
            )
        ],
        image="src.s19 + 1 change entry, 1 applied by this save",
        manifest_keys=("schema_version",),
    )
    assert _tree_digests(workarea) == before
    assert hashed == []
    assert [(row.landing.name, row.action) for row in plan.rows] == [
        ("firmware_1.s19", "new"),
        ("project.json", "new"),
    ]
    with pytest.raises(Exception):
        plan.rows = ()  # frozen: a reader cannot change the plan

    src = _copy_case01(tmp_path) / "firmware.s19"

    async def _drive() -> bool:
        app = S19TuiApp(base_dir=tmp_path / "app2")
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_image(pilot, app, src)
            _add(app, PATCH_ADDRESS, PATCH_BYTES)
            mem_map = app.current_file.mem_map
            snapshot = dict(mem_map)
            step = app._decide_project_image()
            app._plan_project_save(app.workarea / "P9", "P9", step)
            return dict(mem_map) == snapshot and not (app.workarea / "P9").exists()

    assert asyncio.run(_drive())


def test_tc_b100_59_gather_service_imports_no_change_module() -> None:
    """0 new imports from ``project_gather_service``: no edge to the change
    service or the ``changes`` package (the digests are inputs)."""
    tree = ast.parse(Path(gather_module.__file__).read_text(encoding="utf-8"))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.add("." * node.level + (node.module or ""))
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    assert modules == {
        "__future__",
        "json",
        "os",
        "dataclasses",
        "pathlib",
        "typing",
        "...validation.model",
        "..workspace",
        ".variant_execution_service",
    }, sorted(modules)


# ---------------------------------------------------------------------------
# TC-B100-69 — LLR-167.7: the split
# ---------------------------------------------------------------------------


def test_tc_b100_69_rederive_writes_nothing_into_the_session_map() -> None:
    """``rederive_for_save`` → 0 writes to the session map; the copy holds
    source + the current document (the journal restored on the copy)."""
    service = ChangeService()
    mem_map, ranges = _small_image()
    source = dict(mem_map)
    service.add_entry("0x1000", "", "AA BB")
    service.apply(mem_map, ranges, None, None)
    service.remove_entry("0x1000")
    service.add_entry("0x2000", "", "01 02")
    mem_map.writes = 0
    derived, summary = service.rederive_for_save(
        dict(mem_map), ranges=ranges, session_map=mem_map
    )
    assert mem_map.writes == 0
    assert summary.counts[DISPOSITION_APPLIED] == 1
    assert _differing(derived, _patched(source, 0x2000, (0x01, 0x02))) == []
    assert mem_map[0x1000] == 0xAA, "the session map must keep the old apply"


def _pre_split_bytes(tmp_path: Path, image: dict, ranges, name: str) -> bytes:
    """The bytes the pre-split write path produced: the S19 emitter's text
    written in text mode (``Path.write_text``)."""
    scratch = tmp_path / "pre-split" / name
    scratch.parent.mkdir(parents=True, exist_ok=True)
    scratch.write_text(
        emit_s19_from_mem_map(dict(image), list(ranges), bytes_per_line=32),
        encoding="ascii",
    )
    return scratch.read_bytes()


@pytest.mark.parametrize("document", ["applied", "undone", "added_after_apply", "blocked"])
def test_tc_b100_69_save_patched_writes_the_pre_split_bytes(
    tmp_path: Path, document: str
) -> None:
    """``save_patched`` composed of the split writes byte-identical files to
    the pre-split write path for 4 documents; the blocked one writes none."""
    service = ChangeService()
    mem_map, ranges = _small_image()
    source = dict(mem_map)
    project = _workarea(tmp_path) / "proj"
    project.mkdir(parents=True)
    service.add_entry("0x1000", "", "AA BB")
    service.apply(mem_map, ranges, None, None)
    expected = _patched(source, 0x1000, (0xAA, 0xBB))
    if document == "undone":
        service.undo()
        expected = dict(source)
    elif document == "added_after_apply":
        service.add_entry("0x2000", "", "01")
        expected = _patched(expected, 0x2000, (0x01,))
    elif document == "blocked":
        service.add_entry("0x1001", "", "01 02")  # overlaps 0x1000..0x1001
    result = service.save_patched(
        mem_map, ranges, project, f"{document}.s19", source_kind="s19"
    )
    written = sorted(project.glob("*.s19"))
    if document == "blocked":
        assert not result.ok and written == [], (result.message, written)
        return
    assert result.ok, result.message
    assert [p.name for p in written] == [f"{document}.s19"]
    assert written[0].read_bytes() == _pre_split_bytes(
        tmp_path, expected, ranges, f"{document}.s19"
    )
    assert dict(mem_map) == expected, "the in-place view update"


def test_tc_b100_69_sec4_junction_save_back_stages_in_this_work_area(
    tmp_path: Path,
) -> None:
    """SEC-4 (LED .56): with a junction project open, a save-back leaves
    0 entries in the other work area — no ``temp/`` or ``temp/.staging/``
    is created there (the executed RED at base created both)."""
    b100_links.require_junctions()
    other_workarea = _workarea(tmp_path / "other")
    other_project = other_workarea / "T"
    other_project.mkdir(parents=True)
    shutil.copy2(CASE01_DIR / "firmware.s19", other_project / "firmware.s19")
    base = tmp_path / "app"
    app = S19TuiApp(base_dir=base)
    b100_links.create_junction(app.workarea / "J", other_project)
    other_before = sorted(
        str(p.relative_to(other_workarea)) for p in other_workarea.rglob("*")
    )

    async def _drive() -> str:
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_project(pilot, app, "J")
            _add(app, PATCH_ADDRESS, PATCH_BYTES)
            _apply(app)
            await _save_back(pilot, app, "patched.s19")
            return _painted_log(app)

    status = asyncio.run(_drive())
    other_after = sorted(
        str(p.relative_to(other_workarea)) for p in other_workarea.rglob("*")
    )
    assert "Patched image not saved" in status, status
    assert other_after == other_before, (status, other_after)


# ---------------------------------------------------------------------------
# TC-B100-70 — LLR-167.8: the Patch Editor's dirty flag
# ---------------------------------------------------------------------------


async def _add_entry_through_the_panel(
    pilot, app: S19TuiApp, address: str, run: str, *, entries_after: int = 0
) -> None:
    """Add one entry through the panel's own inputs. ``entries_after``
    (white-box nodes only) waits for that document size, so a second add
    is not satisfied by the first add's painted line."""
    await pilot.press("6")
    await _wait_for(
        pilot,
        lambda: len(app.query("#patch_entry_add_button")) > 0,
        "the Patch Editor panel",
    )
    assert await pilot.click("#patch_entry_address_input")
    await pilot.press("ctrl+a", "delete")
    await pilot.press(*address)
    assert await pilot.click("#patch_entry_bytes_input")
    await pilot.press("ctrl+a", "delete")
    await pilot.press(*run)
    assert await pilot.click("#patch_entry_add_button")
    await _wait_for(
        pilot,
        lambda: "Patch Editor: entry added." in _status_text(app)
        and (
            not entries_after
            or len(app._change_service.document.entries) == entries_after
        ),
        "the painted entry-added line",
    )


def _dirty_after_save(tmp_path: Path, blocked: bool) -> tuple:
    src = _copy_case01(tmp_path) / "firmware.s19"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            await _load_image(pilot, app, src)
            await _add_entry_through_the_panel(
                pilot, app, "0x8000007C", "DE AD BE EF", entries_after=1
            )
            if blocked:
                # The panel's add refuses an overlapping entry, so the
                # blocked document is loaded into the service (the panel's
                # dirty flag, set by the add above, is untouched by it).
                app._change_service.load_text(_one_blocked_document_text())
                assert app._change_service.document.has_errors
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            dirty_before = panel._dirty
            await _save(pilot, app, "P1")
            await _wait_for(
                pilot,
                lambda: _status_text(app).startswith("Saved project to")
                or "NOT saved" in _status_text(app),
                "the Save project outcome",
            )
            return dirty_before, panel._dirty, _status_text(app)

    return asyncio.run(_drive())


def test_tc_b100_70_refused_save_keeps_the_flag(tmp_path: Path) -> None:
    """A refused Save project (a blocked document) → the flag is still set
    (1 assertion after the vacuity guard)."""
    dirty_before, dirty_after, status = _dirty_after_save(tmp_path, blocked=True)
    assert dirty_before is True
    assert "blocked" in status, status
    assert dirty_after is True


def test_tc_b100_70_unwritten_document_keeps_the_flag(tmp_path: Path) -> None:
    """A Save project that emits the image but does NOT write the editor's
    document into the project (an unsaved, typed document — the document
    is written by Save project only from Inc 8a) keeps the flag set: the
    entries exist only in the editor and the image, so nothing on disk
    holds the document."""
    dirty_before, dirty_after, status = _dirty_after_save(tmp_path, blocked=False)
    assert dirty_before is True
    assert status.startswith("Saved project to"), status
    assert dirty_after is True


# ---------------------------------------------------------------------------
# AT-B100-05 — HLR-167 black-box
# ---------------------------------------------------------------------------


async def _load_file_through_dialog(pilot, app: S19TuiApp, src: Path) -> None:
    await pilot.press("l")
    await _wait_for(
        pilot, lambda: isinstance(app.screen, LoadFileScreen), "the Load file dialog"
    )
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*str(src))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await _wait_for(
        pilot,
        lambda: not isinstance(app.screen, LoadFileScreen)
        and str(app.query_one("#status_text", Label).render()).startswith("Loaded "),
        f"the durable load line after loading {src.name}",
    )


async def _open_project_through_dialog(pilot, app: S19TuiApp, name: str) -> None:
    await pilot.press("1")
    for _ in range(4):
        await pilot.pause()
    await pilot.press("p")
    await _wait_for(
        pilot, lambda: isinstance(app.screen, LoadProjectScreen), "the Load project dialog"
    )
    row = next(
        item
        for item in app.screen.query("#project_list ListItem")
        if str(item.query_one(Label).render()) == name
    )
    await pilot.click(row)
    await pilot.pause()
    assert await pilot.click("#project_ok"), "click missed #project_ok"
    await _wait_for(
        pilot,
        lambda: not isinstance(app.screen, LoadProjectScreen),
        f"the Load project dialog to close after loading {name}",
    )


@pytest.mark.parametrize("size", [(118, 54), (220, 60)])
def test_at_b100_05_save_project_saves_the_patched_image(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-167's acceptance scene, by keys and clicks: load ``case_01``
    ``firmware.s19`` through the Load file dialog, add and apply
    ``0x8000007C DE AD BE EF`` in the Patch Editor (no save-back), Save
    project P1 through the current dialog (``ctrl+s``), then open P1 in a
    FRESH app through the Load project dialog (``p``). The project image,
    read by the independent reader, equals source + patch (0 differing
    addresses); the save status names 1 entry; the reopened Loaded panel
    names ``firmware.s19``. Both reference sizes, notifications on.

    RED (executed on 1d677ba, P-1): ``project firmware.s19 == in-memory
    patched image? False`` — the save copied the unpatched work copy."""
    src = _copy_case01(tmp_path) / "firmware.s19"
    base = tmp_path / "app"

    statuses: list = []

    async def _save_scene() -> str:
        app = S19TuiApp(base_dir=base)
        real_set_status = app.set_status

        def _capture(message, *args, **kwargs):
            statuses.append(str(message))
            return real_set_status(message, *args, **kwargs)

        app.set_status = _capture
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _load_file_through_dialog(pilot, app, src)
            await _add_entry_through_the_panel(pilot, app, "0x8000007C", "DE AD BE EF")
            assert await pilot.click("#patch_doc_apply_button"), (
                "click missed #patch_doc_apply_button"
            )
            await _wait_for(
                pilot, lambda: "Apply:" in _status_text(app), "the painted apply line"
            )
            await pilot.press("ctrl+s")
            await _wait_for(
                pilot,
                lambda: isinstance(app.screen, SaveProjectScreen),
                "the Save project dialog",
            )
            assert await pilot.click("#project_name"), "click missed #project_name"
            await pilot.press(*"P1")
            assert await pilot.click("#save_ok"), "click missed #save_ok"
            await _wait_for(
                pilot,
                lambda: _status_text(app).startswith("Saved project to"),
                "the painted Save project success line",
            )
            return _painted_log(app)

    async def _reopen_scene() -> str:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _open_project_through_dialog(pilot, app, "P1")
            await _wait_for(
                pilot,
                lambda: "Loaded project 'P1'" in " ".join(
                    str(app.query_one(f"#log_line_{i}", Label).render())
                    for i in (1, 2, 3, 4)
                ),
                "the painted line naming the reopened project",
            )
            # Inc 6 (HLR-178): the dialog route opens the Load-result
            # panel; it is the oracle of what opened and why, then its
            # shown key ``esc`` closes it.
            await _wait_for(
                pilot,
                lambda: len(app.screen.query("#result_ok")) > 0,
                "the Load-result panel",
            )
            panel = await b100_projects.read_load_result_panel(pilot, app)
            await pilot.press("escape")
            await _wait_for(
                pilot,
                lambda: len(app.screen.query("#result_ok")) == 0,
                "the Load-result panel closed",
            )
            await _wait_for(
                pilot,
                lambda: "firmware.s19"
                in " ".join(
                    str(static.render()) for static in app.query("#loaded_slots Static")
                ),
                "the Loaded panel naming firmware.s19",
            )
            reopened_panels.append(panel)
            return " ".join(
                str(static.render()) for static in app.query("#loaded_slots Static")
            )

    painted = asyncio.run(_save_scene())
    project_image = _workarea(base) / "P1" / "firmware.s19"
    written = read_s19(project_image)
    expected = _patched(_source_data(), PATCH_ADDRESS, PATCH_BYTES)
    assert _differing(written.data, expected) == [], (
        "project firmware.s19 == in-memory patched image? False"
    )
    # The save status names the entry at both sizes: the verify line
    # (``save_back_status_suffix``) is checked as painted. The success
    # line's own clause is capped at the terminal width by the log, and
    # follows the project path, so it is checked on the full message the
    # app passed to ``set_status`` (independent of the temp-path depth).
    assert "1 entry applied before this save (0x8000007C)" in painted, painted
    success = next((m for m in statuses if m.startswith("Saved project to")), "")
    assert "1 change entry, 0 applied by this save" in success, statuses
    reopened_panels: list = []
    loaded_panel = asyncio.run(_reopen_scene())
    assert "firmware.s19" in loaded_panel, loaded_panel
    assert "Opened    firmware.s19" in reopened_panels[0], reopened_panels
    assert "recorded as the active variant" in reopened_panels[0], reopened_panels
    # Inc 7 (AT index: the "patched" line against ``derived_from``): the
    # base is the loaded source, which is not a file of P1, so the line
    # names it as outside the project; the patch is the 4 differing bytes.
    assert (
        "patched from firmware.s19 (not in this project); 4 bytes differ from it"
        in b100_projects.flat(reopened_panels[0])
    ), reopened_panels
    assert "identical" not in reopened_panels[0], reopened_panels
