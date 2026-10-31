"""Batch-100 increment 7 — Load opens what is valid and lists every problem
(HLR-169) — plus the Inc 7 seam arm of LLR-171.4.

Covers:

  - TC-B100-21 — LLR-169.1: Save project records ``files`` (size and the
    ``hashlib`` SHA-256 of each file's bytes); a manifest with no ``files``
    serializes byte-identically to the base; a 0-byte file.
  - TC-B100-22 — LLR-169.2: the seam computes ``files`` from disk over the
    top-level data and A2L files only (``.srec`` included, no sub-folder).
  - TC-B100-23 — LLR-169.3: verify reports a ``files`` digest and a
    ``derived_from`` count changed between write and verify; unchanged → 0.
  - TC-B100-24 — LLR-169.4: the reader's caps (1 MiB, 1 000 entries per
    array, ``assignments`` in total), the hostile and malformed ``files``
    records, timing arms under 1 s.
  - TC-B100-25 — LLR-169.5: ``check_project_files`` over the ``p04`` cases,
    a legacy project and a hand-copied variant; an unreadable file; a
    recorded device name.
  - TC-B100-26 — LLR-169.6: Load opens the next valid variant, or the MAC,
    and writes one summary line; no "activating the first variant".
  - TC-B100-27 — LLR-169.7: 8 concurrent manifest writes x 10 trials; no
    shared staging name in the writer's source.
  - TC-B100-60 — LLR-169.8: the manifest-keys mode refuses 14 hostile
    entries and accepts plain ones; the default mode is unchanged.
  - TC-B100-61 — LLR-169.9: one problem per file by precedence, 7 kinds ->
    7 next-step tokens, no internal code painted; SEC6-5: every array at
    the cap with every entry bad opens and paints the panel under 1 s.
  - TC-B100-62 — LLR-171.4 (Inc 7 seam arm, SEC6-3): a project folder
    swapped for a junction into another work area receives no manifest.
  - AT-B100-07 — HLR-169 black-box at 118 and 220 columns.

The service symbols new at Inc 7 are imported inside their nodes, so the
behavioural nodes of this module still run (and fail) at the base.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import threading
import time
from pathlib import Path

import pytest
from textual.widgets import Label

from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import ProjectVariantSet
from s19_app.tui.screens import LoadFileScreen
from s19_app.tui.screens import LoadProjectScreen
from s19_app.tui.screens import SaveProjectScreen
from s19_app.tui.services import manifest_writer
from s19_app.tui.services import variant_execution_service as service
from s19_app.tui.services.manifest_writer import serialize_manifest
from s19_app.tui.services.manifest_writer import write_project_manifest
from s19_app.tui.services.report_addendum import DeclaredRegion
from s19_app.tui.services.variant_execution_service import MANIFEST_BAD_STRUCTURE
from s19_app.tui.services.variant_execution_service import MANIFEST_PATH_ESCAPE
from s19_app.tui.services.variant_execution_service import MANIFEST_SIZE_CAP
from s19_app.tui.services.variant_execution_service import read_project_manifest
from s19_app.tui.workspace import A2L_EXTENSIONS
from s19_app.tui.workspace import PROJECT_DATA_EXTENSIONS
from s19_app.tui.workspace import WORKAREA_DIRNAME
from s19_app.tui.workspace import WORKAREA_SUBDIR
from s19_app.tui.workspace import build_variant_set

from tests.support import b100_links
from tests.support import b100_manifests as hostile
from tests.support import b100_projects as projects

SIZES = [(118, 54), (220, 60)]
INTERNAL_CODE = re.compile(r"MANIFEST-[A-Z-]+")
EXCEPTION_NAME = re.compile(r"\b[A-Z][A-Za-z]*(Error|Exception)\b")


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


async def _wait_for(pilot, predicate, description: str, attempts: int = 400) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {description}")


def _write_manifest(project_dir: Path, payload) -> None:
    project_dir.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (project_dir / "project.json").write_text(text, encoding="utf-8")


def _codes(manifest) -> list:
    return [issue.code for issue in manifest.issues]


def _load_directly(base: Path, name: str = "P") -> S19TuiApp:
    """Open ``name`` through the project-load handler in a fresh app and
    return the app after it settled (its log lines, announcement and image
    stay readable)."""

    async def _drive() -> S19TuiApp:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            app._handle_load_project(name)
            for _ in range(12):
                await pilot.pause()
        return app

    return asyncio.run(_drive())


def _problems(app: S19TuiApp) -> list:
    return [(p.label, p.file) for p in app._last_load_announcement.problems]


# ---------------------------------------------------------------------------
# TC-B100-21 — LLR-169.1: the ``files`` envelope
# ---------------------------------------------------------------------------


def test_tc_b100_21_save_records_every_file_digest(tmp_path: Path) -> None:
    """Save project of S19 + MAC + A2L → 3 ``files`` records, each equal to
    the size and ``hashlib`` SHA-256 of the bytes on disk.

    RED (base 80052cb): ``project.json`` has no ``files`` key."""
    project_dir = projects.build_p04_case(tmp_path / "app", "clean")
    written = projects.read_manifest(project_dir)
    assert written.get("files") == projects.file_records(project_dir), written
    assert len(written["files"]) == 3


#: ``serialize_manifest``'s output for this composition at the base
#: (80052cb), captured before any Inc 7 change: a manifest with no ``files``
#: and no ``derived_from`` must stay byte-identical.
BASE_SERIALIZED = (
    '{\n  "schema_version": 1,\n  "active_variant": "firmware_1",\n  "batch": [\n'
    '    "patches/a.json"\n  ],\n  "assignments": {\n    "firmware": [\n'
    '      "checks/c.json"\n    ]\n  },\n  "declared_regions": [\n    {\n'
    '      "name": "cal",\n      "start": 16,\n      "end": 31\n    }\n  ],\n'
    '  "gathered": {\n    "patches": [\n      "patches/a.json"\n    ]\n  }\n}'
)


def test_tc_b100_21_no_files_is_byte_identical(tmp_path: Path) -> None:
    vs = build_variant_set("P", [Path("firmware.s19"), Path("firmware_1.s19")])
    vs.active_id = "firmware_1"
    text, issues = serialize_manifest(
        vs,
        tmp_path / "P",
        batch=["patches/a.json"],
        assignments={"firmware": ["checks/c.json"]},
        declared_regions=[DeclaredRegion("cal", 0x10, 0x1F)],
        gathered={"patches": ["patches/a.json"]},
    )
    assert issues == []
    assert text == BASE_SERIALIZED


def test_tc_b100_21_zero_byte_file_and_round_trip(tmp_path: Path) -> None:
    from s19_app.tui.services.manifest_writer import file_record

    empty = tmp_path / "P" / "empty.s19"
    empty.parent.mkdir()
    empty.write_bytes(b"")
    record = file_record(empty)
    assert (record.size, record.sha256) == (0, hashlib.sha256(b"").hexdigest())
    vs = ProjectVariantSet(project_name="P", variants=(), active_id=None)
    text, issues = serialize_manifest(vs, empty.parent, files={"empty.s19": record})
    assert issues == []
    assert json.loads(text)["files"] == {
        "empty.s19": {"size": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    }


# ---------------------------------------------------------------------------
# TC-B100-22 — LLR-169.2: the seam computes ``files`` over the O-2 scope
# ---------------------------------------------------------------------------


def test_tc_b100_22_seam_scope_is_top_level_data_and_a2l(tmp_path: Path) -> None:
    """``firmware.s19``, ``firmware.mac``, ``firmware.a2l``, ``prg.srec``,
    ``flows/f1.json`` and ``reports/r.md`` (plus ``checks/inner.s19``, a
    data suffix under a sub-folder, so a walking mutant shows): the seam's
    ``files`` keys are the 4 top-level files the suffix constants select.

    RED (base 80052cb): no ``files`` key is written."""
    base = tmp_path / "app"
    project_dir = projects.copy_sources(
        _workarea(base) / "P",
        projects.CASE01_DIR,
        "firmware.s19",
        "firmware.mac",
        "firmware.a2l",
    )
    shutil.copyfile(projects.CASE00_DIR / "prg.s19", project_dir / "prg.srec")
    for relative in ("flows/f1.json", "reports/r.md"):
        (project_dir / relative).parent.mkdir()
        (project_dir / relative).write_text("{}", encoding="utf-8")
    (project_dir / "checks").mkdir()
    shutil.copyfile(projects.CASE01_DIR / "firmware.s19", project_dir / "checks" / "inner.s19")

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("P")
            await pilot.pause()
            assert app._write_and_verify_manifest(project_dir) is True

    asyncio.run(_drive())
    expected = {
        path.name
        for path in project_dir.iterdir()
        if path.is_file() and path.suffix.lower() in PROJECT_DATA_EXTENSIONS | A2L_EXTENSIONS
    }
    assert expected == {"firmware.s19", "firmware.mac", "firmware.a2l", "prg.srec"}
    written = projects.read_manifest(project_dir)
    assert set(written.get("files", {})) == expected, written
    assert written["files"] == projects.file_records(project_dir)


# ---------------------------------------------------------------------------
# TC-B100-23 — LLR-169.3: verify covers the new keys
# ---------------------------------------------------------------------------


def test_tc_b100_23_digest_changed_between_write_and_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The seam writes ``files``; one recorded digest is changed on disk
    before the verify re-read → the verify reports ``files`` drift.

    RED (base 80052cb): the written manifest holds no ``files`` record to
    change, so no drift can be reported."""
    from s19_app.tui import app as app_module

    project_dir = projects.build_p04_case(tmp_path / "app", "clean")
    real_verify = app_module.verify_written_manifest
    seen: list = []

    def _tamper_then_verify(project, *args, **kwargs):
        manifest = projects.read_manifest(project)
        records = manifest.get("files", {})
        seen.append(sorted(records))
        if records:
            first = sorted(records)[0]
            records[first]["sha256"] = "0" * 64
            (project / "project.json").write_text(json.dumps(manifest), encoding="utf-8")
        return real_verify(project, *args, **kwargs)

    monkeypatch.setattr(app_module, "verify_written_manifest", _tamper_then_verify)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("P")
            await pilot.pause()
            app._write_and_verify_manifest(project_dir)
            return app._last_manifest_verify_result

    result = asyncio.run(_drive())
    assert seen and seen[0], f"the written manifest holds no files record: {seen}"
    assert result.status == manifest_writer.MANIFEST_MISMATCH
    assert result.drift == ["files"], result.drift


def _written_manifest_with_derived(tmp_path: Path):
    from s19_app.tui.services.variant_execution_service import DerivedFrom

    base = tmp_path / "app"
    project_dir = projects.copy_sources(_workarea(base) / "P", projects.CASE01_DIR, "firmware.s19")
    vs = build_variant_set("P", [project_dir / "firmware.s19"])
    vs.active_id = "firmware"
    files = manifest_writer.project_file_records(project_dir)
    derived = {"firmware.s19": DerivedFrom("base.s19", "a" * 64, 4)}
    written, issues = write_project_manifest(
        vs, project_dir, base, files=files, derived_from=derived
    )
    assert issues == [] and written is not None
    return project_dir, vs, files, derived


def test_tc_b100_23_derived_from_count_changed_is_one_mismatch(tmp_path: Path) -> None:
    project_dir, vs, files, derived = _written_manifest_with_derived(tmp_path)
    manifest = projects.read_manifest(project_dir)
    manifest["derived_from"]["firmware.s19"]["differ"] = 5
    (project_dir / "project.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = manifest_writer.verify_written_manifest(
        project_dir, vs, project_dir, files=files, derived_from=derived
    )
    assert result.drift == ["derived_from"], result.drift


def test_tc_b100_23_unchanged_is_verified(tmp_path: Path) -> None:
    project_dir, vs, files, derived = _written_manifest_with_derived(tmp_path)
    result = manifest_writer.verify_written_manifest(
        project_dir, vs, project_dir, files=files, derived_from=derived
    )
    assert (result.status, result.drift) == (manifest_writer.MANIFEST_VERIFIED, [])


# ---------------------------------------------------------------------------
# TC-B100-24 — LLR-169.4: the reader treats ``project.json`` as untrusted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", hostile.HOSTILE_FILES_KEYS)
def test_tc_b100_24_hostile_files_key_is_one_path_escape(tmp_path: Path, key: str) -> None:
    """RED (base 80052cb): ``files`` is ignored, 0 issues."""
    _write_manifest(tmp_path / "P", hostile.manifest(files={key: hostile.VALID_RECORD}))
    manifest = read_project_manifest(tmp_path / "P")
    assert _codes(manifest) == [MANIFEST_PATH_ESCAPE], (key, _codes(manifest))
    assert getattr(manifest, "files", None) == {}


def test_tc_b100_24_sub_folder_key_is_one_bad_structure(tmp_path: Path) -> None:
    _write_manifest(tmp_path / "P", hostile.manifest(files={"sub/x.s19": hostile.VALID_RECORD}))
    manifest = read_project_manifest(tmp_path / "P")
    assert _codes(manifest) == [MANIFEST_BAD_STRUCTURE]


@pytest.mark.parametrize(
    "record", hostile.MALFORMED_RECORDS, ids=["bool-size", "negative", "str-size", "XYZ", "63hex", "65hex"]
)
def test_tc_b100_24_malformed_record_is_one_bad_structure(tmp_path: Path, record: dict) -> None:
    _write_manifest(tmp_path / "P", hostile.manifest(files={"x.s19": record}))
    manifest = read_project_manifest(tmp_path / "P")
    assert _codes(manifest) == [MANIFEST_BAD_STRUCTURE], (record, _codes(manifest))
    assert getattr(manifest, "files", None) == {}


def test_tc_b100_24_valid_record_is_one_record(tmp_path: Path) -> None:
    from s19_app.tui.services.variant_execution_service import FileRecord

    _write_manifest(tmp_path / "P", hostile.manifest(files={"x.s19": hostile.VALID_RECORD}))
    manifest = read_project_manifest(tmp_path / "P")
    assert manifest.issues == []
    assert manifest.files == {
        (tmp_path / "P" / "x.s19").resolve(): FileRecord(0, hostile.EMPTY_SHA256)
    }


@pytest.mark.parametrize("key", ["batch", "files", "declared_regions", "gathered", "derived_from"])
def test_tc_b100_24_one_entry_over_the_cap_is_one_issue_fast(tmp_path: Path, key: str) -> None:
    """1 001 entries in one array → 1 issue, the manifest read as damaged,
    read under 1 s.

    RED (base 80052cb): no cap, 0 issues."""
    _write_manifest(tmp_path / "P", hostile.over_cap(key))
    started = time.perf_counter()
    manifest = read_project_manifest(tmp_path / "P")
    elapsed = time.perf_counter() - started
    assert _codes(manifest) == [MANIFEST_BAD_STRUCTURE], (key, _codes(manifest)[:3])
    assert service.manifest_is_damaged(manifest)
    assert elapsed < 1.0, f"{key}: read took {elapsed:.2f} s"


def test_tc_b100_24_exactly_the_cap_is_read(tmp_path: Path) -> None:
    _write_manifest(tmp_path / "P", hostile.over_cap("batch", hostile.ENTRY_CAP))
    manifest = read_project_manifest(tmp_path / "P")
    assert manifest.issues == []
    assert len(manifest.batch) == hostile.ENTRY_CAP


def test_tc_b100_24_assignments_75_by_1000_is_one_issue_fast(tmp_path: Path) -> None:
    """SEC PDR-C2: 75 keys x 1 000 entries (14.80 s uncapped) → 1 issue,
    read under 1 s.

    RED (base 80052cb): every entry resolved, 0 issues."""
    _write_manifest(tmp_path / "P", hostile.dumps(hostile.assignments_75_by_1000()))
    started = time.perf_counter()
    manifest = read_project_manifest(tmp_path / "P")
    elapsed = time.perf_counter() - started
    assert _codes(manifest) == [MANIFEST_BAD_STRUCTURE], _codes(manifest)[:3]
    assert elapsed < 1.0, f"read took {elapsed:.2f} s"


def test_tc_b100_24_one_byte_over_one_mib_is_size_cap(tmp_path: Path) -> None:
    """RED (base 80052cb): the cap was 256 MB, the file is read."""
    _write_manifest(tmp_path / "P", hostile.text_of_size(hostile.SIZE_CAP + 1))
    assert _codes(read_project_manifest(tmp_path / "P")) == [MANIFEST_SIZE_CAP]
    _write_manifest(tmp_path / "Q", hostile.text_of_size(hostile.SIZE_CAP))
    assert _codes(read_project_manifest(tmp_path / "Q")) == []


# ---------------------------------------------------------------------------
# TC-B100-25 — LLR-169.5: ``check_project_files``
# ---------------------------------------------------------------------------

CHECK_CASES = [
    "clean",
    "2-image-edited",
    "5-image-deleted",
    "7-manifest-corrupt",
    "9-no-manifest-two-variants",
    "legacy",
    "hand-copied",
]


@pytest.mark.parametrize("case", CHECK_CASES)
def test_tc_b100_25_check_reports_each_case(tmp_path: Path, case: str) -> None:
    from s19_app.tui.services.manifest_writer import check_project_files
    from s19_app.tui.services.variant_execution_service import merge_load_problems

    project_dir = projects.build_p04_case(tmp_path / "app", case)
    found = merge_load_problems(
        check_project_files(project_dir, read_project_manifest(project_dir))
    )
    kind, file_name = projects.P04_CASES[case]
    expected = [] if kind is None else [(kind, file_name)]
    assert [(p.kind, p.file) for p in found] == expected


@pytest.mark.parametrize("case", ["2-image-edited", "7-manifest-corrupt"])
def test_tc_b100_25_load_reports_the_case(tmp_path: Path, case: str) -> None:
    """P-4 cases 2 and 7 through the project-load handler: exactly one
    problem, of the case's kind, naming its file.

    RED (base 80052cb, P-4): case 2 → 0 problems; case 7 → the Inc 6
    label, not the ``manifest damaged`` token."""
    projects.build_p04_case(tmp_path / "app", case)
    app = _load_directly(tmp_path / "app")
    assert _problems(app) == [projects.P04_CASES[case]]


def test_tc_b100_25_unreadable_file_is_one_problem_never_a_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from s19_app.tui.services.manifest_writer import check_project_files

    project_dir = projects.build_p04_case(tmp_path / "app", "clean")
    manifest = read_project_manifest(project_dir)

    def _denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(manifest_writer, "file_record", _denied)
    found = check_project_files(project_dir, manifest)
    assert [(p.kind, p.file) for p in found] == [
        ("not readable", "firmware.a2l"),
        ("not readable", "firmware.mac"),
        ("not readable", "firmware.s19"),
    ]


def test_tc_b100_25_recorded_device_name_is_not_readable(tmp_path: Path) -> None:
    """``P/NUL`` recorded (a manifest built in memory, past the reader's
    refusal) → ``not readable``, never ``ok``."""
    if os.name != "nt":
        pytest.skip("NUL is a device only on Windows (PDR C-QA-6)")
    from s19_app.tui.services.manifest_writer import check_project_files
    from s19_app.tui.services.variant_execution_service import FileRecord
    from s19_app.tui.services.variant_execution_service import ProjectManifest

    project_dir = tmp_path / "P"
    project_dir.mkdir()
    manifest = ProjectManifest(
        schema_version=1,
        active_variant=None,
        files={project_dir / "NUL": FileRecord(0, hostile.EMPTY_SHA256)},
    )
    found = check_project_files(project_dir, manifest)
    assert [(p.kind, p.file) for p in found] == [("not readable", "NUL")]


# ---------------------------------------------------------------------------
# TC-B100-26 — LLR-169.6: Load opens the valid files, one summary line
# ---------------------------------------------------------------------------


def _summaries(app: S19TuiApp) -> list:
    return [line for line in app.log_lines if line.endswith("details: p")]


def test_tc_b100_26_active_deleted_the_other_opens(tmp_path: Path) -> None:
    """P holds ``firmware.s19`` and the recorded active ``firmware_1.s19``;
    the active one is deleted → ``firmware.s19`` opens, 1 problem
    (``missing``), exactly 1 summary line, no "activating the first variant".

    RED (base 80052cb, P-5): "activating the first variant" is written."""
    base = tmp_path / "app"
    project_dir = projects.save_case01_project(base, files=("firmware.s19",))
    src = projects.copy_sources(tmp_path / "second", projects.CASE02_DIR, "firmware.s19")
    projects.append_variant(base, src / "firmware.s19")
    assert projects.read_manifest(project_dir)["active_variant"] == "firmware_1"
    (project_dir / "firmware_1.s19").unlink()
    app = _load_directly(base)
    assert app.current_file.path.name == "firmware.s19"
    assert _problems(app) == [("missing", "firmware_1.s19")]
    assert len(_summaries(app)) == 1, list(app.log_lines)
    assert not [line for line in app.log_lines if "activating the first variant" in line]


def test_tc_b100_26_every_image_deleted_the_mac_opens(tmp_path: Path) -> None:
    """``p04`` case 5: the only image is deleted → the MAC opens, 1 problem
    per missing image, one summary line whose count is inside 118 columns.

    RED (base 80052cb, P-5): "activating the first variant", then
    ``-> firmware.mac``."""
    projects.build_p04_case(tmp_path / "app", "5-image-deleted")
    app = _load_directly(tmp_path / "app")
    assert app.current_file is not None and app.current_file.file_type == "mac"
    assert _problems(app) == [("missing", "firmware.s19")]
    summaries = _summaries(app)
    assert len(summaries) == 1, list(app.log_lines)
    assert "1 problem" in summaries[0][:118], summaries
    assert not [line for line in app.log_lines if "activating the first variant" in line]


# ---------------------------------------------------------------------------
# TC-B100-27 — LLR-169.7: the manifest is staged privately
# ---------------------------------------------------------------------------


def test_tc_b100_27_concurrent_manifest_writes(tmp_path: Path) -> None:
    """8 writers, one per project, started together, 10 trials: 80 of 80
    return a path and each manifest holds its own ``active_variant``.

    RED (base 80052cb, the QA race probe): the shared ``temp/project.json``
    crosses content between writers and fails writes."""
    base = tmp_path / "app"
    workarea = _workarea(base)
    names = [f"P{index}" for index in range(8)]
    for name in names:
        (workarea / name).mkdir(parents=True)
    returned = 0
    for trial in range(10):
        barrier = threading.Barrier(len(names))
        results: dict = {}

        def _write(name: str) -> None:
            vs = ProjectVariantSet(project_name=name, variants=(), active_id=f"{name}_{trial}")
            barrier.wait()
            results[name] = write_project_manifest(vs, workarea / name, base)

        threads = [threading.Thread(target=_write, args=(name,)) for name in names]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for name in names:
            written, issues = results[name]
            assert issues == [] and written is not None, (trial, name, issues)
            returned += 1
            on_disk = projects.read_manifest(workarea / name)["active_variant"]
            assert on_disk == f"{name}_{trial}", (trial, name, on_disk)
    assert returned == 80


def test_tc_b100_27_no_shared_staging_name_in_the_writer_source() -> None:
    source = Path(manifest_writer.__file__).read_text(encoding="utf-8")
    assert not re.findall(r"WORKAREA_TEMP\s*/\s*PROJECT_MANIFEST_NAME", source)


# ---------------------------------------------------------------------------
# TC-B100-60 — LLR-169.8: the manifest-keys mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry", hostile.MANIFEST_MODE_REFUSED)
def test_tc_b100_60_reader_refuses_a_hostile_entry(tmp_path: Path, entry: str) -> None:
    """RED (base 80052cb, S-09): ``C:x.s19`` and the stream, trailing-dot,
    trailing-space and device names resolve inside the project, 0 issues."""
    _write_manifest(tmp_path / "P", hostile.manifest(batch=[entry]))
    manifest = read_project_manifest(tmp_path / "P")
    assert _codes(manifest) == [MANIFEST_PATH_ESCAPE], (entry, _codes(manifest))
    assert manifest.batch == []


def test_tc_b100_60_reader_accepts_plain_entries(tmp_path: Path) -> None:
    _write_manifest(tmp_path / "P", hostile.manifest(batch=list(hostile.MANIFEST_MODE_ACCEPTED)))
    manifest = read_project_manifest(tmp_path / "P")
    root = (tmp_path / "P").resolve()
    assert manifest.issues == []
    assert manifest.batch == [(root / entry).resolve() for entry in hostile.MANIFEST_MODE_ACCEPTED]


def test_tc_b100_60_default_mode_is_unchanged(tmp_path: Path) -> None:
    """P-41: the flow references keep the default mode — a trailing-dot
    name is not refused there."""
    root = tmp_path.resolve()
    issues: list = []
    resolved = service._resolve_manifest_entry(root, "x.s19.", "batch", issues)
    assert resolved is not None and issues == []
    refused: list = []
    assert (
        service._resolve_manifest_entry(
            root, "x.s19.", "batch", refused, service.ENTRY_MODE_MANIFEST_KEYS
        )
        is None
    )
    assert [issue.code for issue in refused] == [MANIFEST_PATH_ESCAPE]


# ---------------------------------------------------------------------------
# TC-B100-61 — LLR-169.9: one problem per file, worded for the user
# ---------------------------------------------------------------------------


def test_tc_b100_61_case_6_is_only_not_readable(tmp_path: Path) -> None:
    """``p04`` case 6 (``S3FFgarbage``): the image is both changed on disk
    and not readable → 1 problem, ``not readable``; the MAC opens.

    RED (base 80052cb, P-4): 0 problems."""
    projects.build_p04_case(tmp_path / "app", "6-image-corrupt")
    app = _load_directly(tmp_path / "app")
    assert _problems(app) == [("not readable", "firmware.s19")]
    assert app._last_load_announcement.unreadable == ("firmware.s19",)


def _variant_id(project_dir: Path, file_name: str) -> str:
    variants = build_variant_set(project_dir.name, [project_dir / file_name]).variants
    return variants[0].variant_id


def test_tc_b100_61_checksum_errors_only_keep_the_image_open(tmp_path: Path) -> None:
    """OQ-7a (orchestrator ruling): ``not readable`` is an image that yields
    NO data. An image with data and record-level errors only (``case_04``,
    one bad checksum) stays open with its errors on the loaded file, as
    before this batch, and is not a problem: 0 ``not readable``.

    Mutant: treat record errors as ``not readable`` → the MAC-less project
    opens nothing and 1 ``not readable`` is listed."""
    base = tmp_path / "app"
    project_dir = projects.copy_sources(
        _workarea(base) / "P", projects.ROOT / "examples" / "case_04_bad_checksums",
        "firmware.s19", "firmware.a2l",
    )
    _write_manifest(
        project_dir,
        {
            "schema_version": 1,
            "active_variant": _variant_id(project_dir, "firmware.s19"),
            "files": projects.file_records(project_dir),
        },
    )
    app = _load_directly(base)
    assert _problems(app) == []
    assert app._last_load_announcement.unreadable == ()
    assert app.current_file is not None
    assert app.current_file.path.name == "firmware.s19"
    assert app.current_file.mem_map and app.current_file.errors


def test_tc_b100_61_empty_image_is_not_readable_and_load_moves_on(tmp_path: Path) -> None:
    """OQ-7a / LLR-169.6: the recorded variant parses but holds no data
    (a terminator record only) → ``not readable``, and Load opens the next
    valid variant instead."""
    base = tmp_path / "app"
    project_dir = projects.copy_sources(
        _workarea(base) / "P", projects.CASE01_DIR, "firmware.s19"
    )
    (project_dir / "aaa.s19").write_text("S9030000FC\n", encoding="ascii")
    _write_manifest(
        project_dir,
        {
            "schema_version": 1,
            "active_variant": _variant_id(project_dir, "aaa.s19"),
            "files": projects.file_records(project_dir),
        },
    )
    app = _load_directly(base)
    assert _problems(app) == [("not readable", "aaa.s19")]
    assert app._last_load_announcement.unreadable == ("aaa.s19",)
    assert app.current_file is not None
    assert app.current_file.path.name == "firmware.s19"


def test_tc_b100_61_unreadable_a2l_is_its_own_problem_and_the_image_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inc 7 corrective F1 (LLR-169.9, reviewer probe PA): the project's
    A2L cannot be read (``parse_a2l_file`` raises ``PermissionError``, the
    shipped parser's behaviour on a read error) → ``not readable:
    firmware.a2l`` is the one problem, ``firmware.s19`` opens without the
    A2L, and no problem names the valid image.

    RED (corrective-pass base): ``not readable: firmware.s19 - not an S19
    or HEX file``, no image opened."""
    import s19_app.tui.app as app_module

    base = tmp_path / "app"
    project_dir = projects.copy_sources(
        _workarea(base) / "P", projects.CASE01_DIR, "firmware.s19", "firmware.a2l"
    )
    _write_manifest(
        project_dir,
        {
            "schema_version": 1,
            "active_variant": "firmware",
            "files": projects.file_records(project_dir),
        },
    )

    def _denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(app_module, "parse_a2l_file", _denied)
    app = _load_directly(base)
    assert _problems(app) == [("not readable", "firmware.a2l")]
    assert app._last_load_announcement.unreadable == ()
    assert app.current_file is not None
    assert app.current_file.path.name == "firmware.s19"
    assert app._last_load_announcement.a2l is None


def test_tc_b100_61_case_7_is_only_manifest_damaged(tmp_path: Path) -> None:
    projects.build_p04_case(tmp_path / "app", "7-manifest-corrupt")
    app = _load_directly(tmp_path / "app")
    assert _problems(app) == [("manifest damaged", "project.json")]


def test_tc_b100_61_changed_and_unrecorded_is_changed_on_disk() -> None:
    from s19_app.tui.services.variant_execution_service import ProjectFileProblem
    from s19_app.tui.services.variant_execution_service import merge_load_problems

    merged = merge_load_problems(
        [
            ProjectFileProblem("not recorded", "x.s19"),
            ProjectFileProblem("changed on disk", "x.s19"),
            ProjectFileProblem("not readable", "x.s19"),
        ]
    )
    assert [(p.kind, p.file) for p in merged] == [("not readable", "x.s19")]
    merged = merge_load_problems(
        [ProjectFileProblem("not recorded", "y.s19"), ProjectFileProblem("changed on disk", "y.s19")]
    )
    assert [(p.kind, p.file) for p in merged] == [("changed on disk", "y.s19")]
    # Precedence, never input order: the same kinds reversed keep the same one.
    merged = merge_load_problems(
        [ProjectFileProblem("changed on disk", "y.s19"), ProjectFileProblem("not recorded", "y.s19")]
    )
    assert [(p.kind, p.file) for p in merged] == [("changed on disk", "y.s19")]


def test_tc_b100_61_seven_kinds_seven_next_steps_no_codes() -> None:
    from s19_app.tui.services.variant_execution_service import ProjectFileProblem

    kinds = list(service.PROBLEM_NEXT_STEP)
    assert len(kinds) == 7
    problems = [
        ProjectFileProblem(kind, f"f{index}.s19", "", code="MANIFEST-BAD-STRUCTURE")
        for index, kind in enumerate(kinds)
    ]
    vs = build_variant_set("P", [Path("f0.s19")])
    announcement = service.compose_load_announcement(
        "P", vs, service.ProjectManifest(schema_version=1, active_variant="f0"), problems=problems
    )
    painted = [(p.label, p.detail) for p in announcement.problems]
    assert [label for label, _ in painted] == kinds
    steps = [service.PROBLEM_NEXT_STEP[label] for label, _ in painted]
    assert len(set(steps)) == 7
    for (label, detail), step in zip(painted, steps):
        assert step in detail, (label, detail)
        assert not INTERNAL_CODE.search(detail) and not EXCEPTION_NAME.search(detail), detail


async def _open_panel_through_the_dialog(pilot, app: S19TuiApp, name: str = "P") -> None:
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


def test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second(
    tmp_path: Path,
) -> None:
    """SEC6-5: every capped array at exactly 1 000 entries, every entry an
    escaping path, distinct across arrays (5 000 skipped entries plus 1 000
    malformed regions). The load and the panel are bounded: the load runs
    under 1 s, the panel opens and is painted, and the panel holds at most
    :data:`LOAD_PANEL_ROW_BOUND` rows.

    RED (reviewed Inc 6 tree): 6 000 bad entries froze load and panel for
    10.2 s."""
    base = tmp_path / "app"
    project_dir = projects.copy_sources(_workarea(base) / "P", projects.CASE01_DIR, "firmware.s19")
    _write_manifest(project_dir, hostile.dumps(hostile.every_array_at_cap_all_bad()))

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        real_load = app._handle_load_project
        timing: list = []

        def _timed(name):
            started = time.perf_counter()
            real_load(name)
            timing.append(time.perf_counter() - started)

        app._handle_load_project = _timed
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            await _open_panel_through_the_dialog(pilot, app)
            pressed = time.perf_counter()
            await _wait_for(
                pilot,
                lambda: len(app.screen.query("#result_summary")) > 0
                and app.screen.query_one("#result_summary").size.height > 0,
                "the painted Load-result panel",
                attempts=4000,
            )
            painted = time.perf_counter() - pressed
            rows = len(app.screen.query("#result_body .result-problem"))
            return timing, painted, rows

    timing, painted, rows = asyncio.run(_drive())
    assert timing and timing[0] < 1.0, f"the load took {timing}"
    assert painted < 1.0, f"the panel took {painted:.2f} s to paint"
    assert rows <= LOAD_PANEL_ROW_BOUND, rows


#: SEC6-5's named bound (packet §6, Inc 7 corrective F2): the composer
#: lists at most ``LOAD_PROBLEM_ROWS`` = 102 problems one by one (the
#: reader's 100 entry rows, its fold row and one manifest-level row) and
#: counts any further problem in one more row — whatever the source.
LOAD_PANEL_ROW_BOUND = 100 + 2 + 1


def test_tc_b100_61_skipped_entries_beyond_the_bound_are_counted(tmp_path: Path) -> None:
    """Inc 7 corrective F5 (reviewer probe PF; HLR-169: every unsafe record
    is reported): 150 escaping entries → 100 findings one by one plus ONE
    finding that counts the other 50, painted as ``50 more recorded
    entries``. A fold that drops entries silently fails here."""
    project_dir = tmp_path / "P"
    _write_manifest(
        project_dir,
        hostile.manifest(batch=[f"../escape_{i:03d}.json" for i in range(150)]),
    )
    manifest = read_project_manifest(project_dir)
    entries = [issue.details.get("entry") for issue in manifest.issues]
    assert len(entries) == 101, entries[-3:]
    assert entries[:100] == [f"../escape_{i:03d}.json" for i in range(100)]
    assert entries[-1] == "50 more recorded entries"
    problems = service.manifest_problems(manifest)
    assert (problems[-1].kind, problems[-1].file) == (
        "manifest damaged",
        "50 more recorded entries",
    )


async def _timed_load_panel_and_append(pilot, app: S19TuiApp, source: Path) -> tuple:
    """Open P through the Load dialog (the timed load), wait for the
    painted panel, close it, then load ``source`` so the variant append
    re-reads ``project.json`` (an in-project writer); returns the load
    time, the panel paint time, the painted problem rows and the append
    time to its manifest outcome line."""
    await _open_panel_through_the_dialog(pilot, app)
    pressed = time.perf_counter()
    await _wait_for(
        pilot,
        lambda: len(app.screen.query("#result_summary")) > 0
        and app.screen.query_one("#result_summary").size.height > 0,
        "the painted Load-result panel",
        attempts=4000,
    )
    painted = time.perf_counter() - pressed
    rows = len(app.screen.query("#result_body .result-problem"))
    await pilot.press("escape")
    await _wait_for(pilot, lambda: len(app.screen.query("#result_ok")) == 0, "the panel closed")
    started = time.perf_counter()
    app.load_from_path(source)
    await _wait_for(
        pilot,
        lambda: any(
            "was not rewritten" in line or "manifest verified" in line
            for line in app._statuses
        ),
        "the append's manifest outcome",
        attempts=4000,
    )
    appended = time.perf_counter() - started
    return painted, rows, appended


def _sec6_5_filesystem_scene(tmp_path: Path, payload: dict, setup=None) -> dict:
    """The SEC6-5 time bound on entries that need filesystem calls (Inc 7
    corrective SEC7-1): read, Load + panel, and one in-project writer's
    re-read, each timed; ``setup`` builds the folders or junction first."""
    base = tmp_path / "app"
    project_dir = projects.copy_sources(_workarea(base) / "P", projects.CASE01_DIR, "firmware.s19")
    source = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    (source / "firmware.s19").rename(source / "extra.s19")
    if setup is not None:
        setup(project_dir)
    _write_manifest(project_dir, hostile.dumps(payload))
    started = time.perf_counter()
    manifest = read_project_manifest(project_dir)
    read = time.perf_counter() - started

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        app._statuses = []
        real_set_status = app.set_status

        def _capture(message, *args, **kwargs):
            app._statuses.append(str(message))
            return real_set_status(message, *args, **kwargs)

        app.set_status = _capture
        real_load = app._handle_load_project
        timing: list = []

        def _timed(name):
            begun = time.perf_counter()
            real_load(name)
            timing.append(time.perf_counter() - begun)

        app._handle_load_project = _timed
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            painted, rows, appended = await _timed_load_panel_and_append(
                pilot, app, source / "extra.s19"
            )
            problems = app._last_load_announcement.problems
        return timing, painted, rows, appended, problems

    timing, painted, rows, appended, problems = asyncio.run(_drive())
    return {
        "read": read,
        "load": timing[0] if timing else None,
        "painted": painted,
        "rows": rows,
        "appended": appended,
        "problems": problems,
        "manifest": manifest,
    }


def _assert_sec6_5_bounded(scene: dict) -> None:
    timings = {key: scene[key] for key in ("read", "load", "painted", "appended")}
    print("SEC6-5 timings (s):", {key: round(value, 3) for key, value in timings.items()})
    assert scene["read"] < 1.0, timings
    assert scene["load"] is not None and scene["load"] < 1.0, timings
    assert scene["painted"] < 1.0, timings
    assert scene["appended"] < 1.0, timings
    assert scene["rows"] <= LOAD_PANEL_ROW_BOUND, scene["rows"]
    assert scene["rows"] == len(scene["problems"])


def _counted_read(project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> tuple:
    """Read ``project_dir``'s manifest counting the reader's filesystem
    checks (one ``_lstat_state`` per call; the seam exists from the Inc 7
    corrective pass on, so the count is 0 before it)."""
    calls: list = []
    real = getattr(service, "_lstat_state", None)
    if real is not None:

        def _counting(path):
            calls.append(path)
            return real(path)

        monkeypatch.setattr(service, "_lstat_state", _counting)
    started = time.perf_counter()
    manifest = read_project_manifest(project_dir)
    return manifest, len(calls), time.perf_counter() - started


def test_tc_b100_61_sec6_5_each_name_is_checked_once_per_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inc 7 corrective SEC7-1, the filesystem budget of one read:
    (a) 3 000 deep entries under one missing folder → 1 check (the folder),
    and the 2 000 nested ``files`` / ``derived_from`` keys cost none (their
    scope is decided on the text first); (b) 1 000 ``files`` keys under
    1 000 distinct folders → 0 checks; (c) entries deeper than 32
    components → refused on the text, 0 checks; (d) 3 000 entries under an
    existing 8-folder chain → 8 folder checks + 3 000 file checks, every
    entry checked (corrective pass 2, R2-2: the file an entry ends on is
    always checked); (e) 3 000 entries under 3 000 distinct missing folders
    → exactly ``MANIFEST_FOLDER_CHECK_CAP`` (1 000) folder checks, the other
    2 000 unchecked and counted. Each read under 1 s.

    RED (corrective-pass base): no walk — every entry resolved. RED (cp1
    tree) for (d): the 2 000-call ceiling skipped 1 000 valid entries."""
    deep = tmp_path / "deep"
    _write_manifest(deep, hostile.dumps(hostile.deep_missing_at_cap()))
    manifest, calls, took = _counted_read(deep, monkeypatch)
    assert calls == 1 and took < 1.0, (calls, took)
    assert len(manifest.batch) == hostile.ENTRY_CAP

    keyed = tmp_path / "keyed"
    _write_manifest(
        keyed,
        hostile.dumps(
            hostile.manifest(files={f"d{i}/x.s19": hostile.VALID_RECORD for i in range(1000)})
        ),
    )
    manifest, calls, took = _counted_read(keyed, monkeypatch)
    assert calls == 0 and took < 1.0, (calls, took)
    assert _codes(manifest)[:100] == [MANIFEST_BAD_STRUCTURE] * 100

    too_deep = tmp_path / "too_deep"
    _write_manifest(too_deep, hostile.manifest(batch=["/".join(["s"] * 40) + "/x.json"]))
    manifest, calls, took = _counted_read(too_deep, monkeypatch)
    assert calls == 0, calls
    assert _codes(manifest) == [MANIFEST_PATH_ESCAPE]
    assert manifest.batch == []

    parent = "/".join(["d"] * 8)
    chain = tmp_path / "chain"
    (chain / parent).mkdir(parents=True)
    _write_manifest(chain, hostile.dumps(hostile.existing_parent_at_cap(parent)))
    manifest, calls, took = _counted_read(chain, monkeypatch)
    assert calls == 8 + 3 * hostile.ENTRY_CAP, calls
    assert took < 1.0, took
    assert manifest.issues == [], manifest.issues[-1:]

    spread = tmp_path / "spread"
    _write_manifest(
        spread,
        hostile.dumps(
            hostile.manifest(
                batch=[f"m{i}/x.json" for i in range(1000)],
                assignments={"firmware": [f"n{i}/x.json" for i in range(1000)]},
                gathered={"patches": [f"o{i}/x.json" for i in range(1000)]},
            )
        ),
    )
    manifest, calls, took = _counted_read(spread, monkeypatch)
    assert calls == service.MANIFEST_FOLDER_CHECK_CAP == 1000, calls
    assert took < 1.0, took
    assert manifest.issues[-1].details["entry"] == "2000 more recorded entries"


def test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_parent(tmp_path: Path) -> None:
    """Inc 7 corrective SEC7-1 (the security probe A1's shape at a depth
    the reader walks): 5 x 1 000 entries, 30 components deep, none on disk
    and none escaping on the text. The first missing folder ends each walk
    and is checked once per read → read, Load + panel and the variant
    append's re-read each under 1 s; the 3 000 deep entries are kept and
    the 2 000 nested ``files`` / ``derived_from`` keys are refused on the
    text (100 rows + 1 counting row).

    RED (corrective-pass base): one ``resolve()`` per entry (A1: read
    9.94 s, Load 10.74 s, append 10.64 s)."""
    scene = _sec6_5_filesystem_scene(tmp_path, hostile.deep_missing_at_cap())
    _assert_sec6_5_bounded(scene)
    manifest = scene["manifest"]
    kept = len(manifest.batch) + sum(len(v) for v in manifest.assignments.values()) + sum(
        len(v) for v in manifest.gathered.values()
    )
    assert kept == 3 * hostile.ENTRY_CAP
    assert manifest.issues[-1].details["entry"] == "1900 more recorded entries"


def test_tc_b100_61_sec6_5_entries_under_an_existing_folder_are_all_checked(
    tmp_path: Path,
) -> None:
    """Inc 7 corrective SEC7-1, re-pinned by corrective pass 2 (R2-2: the
    ceiling bounds distinct folders; the file an entry ends on is always
    checked): 3 x 1 000 entries under a real 8-level folder chain, so every
    entry's own name needs a filesystem check. Every entry is kept, no
    entry is unchecked, and every timing stays under 1 s.

    RED (cp1 tree): 1 000 valid entries skipped unchecked past the
    2 000-call ceiling."""
    parent = "/".join(["d"] * 8)

    def _folders(project_dir: Path) -> None:
        (project_dir / parent).mkdir(parents=True)

    scene = _sec6_5_filesystem_scene(
        tmp_path, hostile.existing_parent_at_cap(parent), setup=_folders
    )
    _assert_sec6_5_bounded(scene)
    manifest = scene["manifest"]
    kept = len(manifest.batch) + sum(len(v) for v in manifest.assignments.values()) + sum(
        len(v) for v in manifest.gathered.values()
    )
    assert kept == 3 * hostile.ENTRY_CAP, kept
    assert manifest.issues == [], manifest.issues[-1:]


def test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folder_ceiling(tmp_path: Path) -> None:
    """Inc 7 corrective pass 2 (R2-2), the folder ceiling's worst case: 3 x
    1 000 entries each under its own real folder, 1 000 ``files`` records
    and 1 000 ``derived_from`` records with distinct bases (the most folder
    and file checks the caps allow). Folder checks stop at
    ``MANIFEST_FOLDER_CHECK_CAP`` (1 000); the 2 000 entries past it are skipped
    unchecked and counted in one row (never silently); read, Load + panel
    and the variant append's re-read each stay under 1 s."""

    def _folders(project_dir: Path) -> None:
        for name in hostile.distinct_folder_names():
            (project_dir / name).mkdir()
            (project_dir / name / "x.json").write_text("{}", encoding="utf-8")

    scene = _sec6_5_filesystem_scene(tmp_path, hostile.distinct_folders_at_cap(), setup=_folders)
    _assert_sec6_5_bounded(scene)
    manifest = scene["manifest"]
    kept = len(manifest.batch) + sum(len(v) for v in manifest.assignments.values()) + sum(
        len(v) for v in manifest.gathered.values()
    )
    assert kept == service.MANIFEST_FOLDER_CHECK_CAP, kept
    assert len(manifest.files) + len(manifest.derived_from) == 2 * hostile.ENTRY_CAP
    fold = manifest.issues[-1].details
    assert fold["entry"] == "2000 more recorded entries", fold
    assert fold["reason"] == "skipped - more entries than one load checks", fold


def test_tc_b100_61_r2_2_legitimate_manifest_inside_every_cap_is_checked_whole(
    tmp_path: Path,
) -> None:
    """Inc 7 corrective pass 2, R2-2 (reviewer probe Q3): a well-formed
    manifest inside every cap — 1 000 real change files under ``p/`` in
    ``batch``, 1 000 under ``q/`` in ``assignments``, and the image's
    ``files`` record — is read whole: every entry and the record kept, no
    finding, no ``no digests saved``, and an in-project rewrite allowed.

    RED (cp1 tree): ``assignments`` 998, ``files`` 0, one fold row,
    ``no digests saved`` and the rewrite refused."""
    from s19_app.tui.services.manifest_writer import check_project_files

    project_dir = projects.copy_sources(
        _workarea(tmp_path) / "P", projects.CASE01_DIR, "firmware.s19"
    )
    (project_dir / "p").mkdir()
    (project_dir / "q").mkdir()
    batch, assigned = [], []
    for i in range(1000):
        (project_dir / "p" / f"c{i:04d}.json").write_text("{}", encoding="utf-8")
        (project_dir / "q" / f"k{i:04d}.json").write_text("{}", encoding="utf-8")
        batch.append(f"p/c{i:04d}.json")
        assigned.append(f"q/k{i:04d}.json")
    records = projects.file_records(project_dir)
    _write_manifest(
        project_dir,
        hostile.manifest(
            active_variant="firmware",
            batch=batch,
            assignments={"firmware": assigned},
            files=records,
        ),
    )
    started = time.perf_counter()
    manifest = read_project_manifest(project_dir)
    took = time.perf_counter() - started
    assert took < 1.0, took
    assert manifest.issues == [], manifest.issues[-1:]
    assert len(manifest.batch) == 1000
    assert len(manifest.assignments["firmware"]) == 1000
    assert {path.name for path in manifest.files} == set(records)
    assert check_project_files(project_dir, manifest) == []
    assert service.manifest_rewrite_refusal(manifest) is None


@pytest.mark.parametrize("first", ["sub/missing.json", "sub/real.json"])
def test_tc_b100_61_sec7_r2_1_case_sensitive_folder_checks_each_spelling(
    tmp_path: Path, first: str
) -> None:
    """Inc 7 corrective pass 2, SEC7-R2-1 (security probe W2a / W2c): in a
    case-sensitive project folder ``sub`` and ``SUB`` are two objects. An
    entry under ``sub`` (a missing folder, or a real one) must never stand
    for ``SUB``, a junction to an outside folder: ``SUB/secret.json`` is
    refused with one ``MANIFEST-PATH-ESCAPE`` in ``batch``,
    ``assignments`` and ``gathered``, and no rewrite carries it.

    RED (cp1 tree): the walk's cache folded case, so ``SUB/secret.json`` was
    accepted with no finding and the execution plan's reader opened the
    outside file."""
    b100_links.require_junctions()
    project_dir = tmp_path / "P"
    project_dir.mkdir()
    b100_links.enable_case_sensitive(project_dir)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.json").write_text("{}", encoding="utf-8")
    if first == "sub/real.json":
        (project_dir / "sub").mkdir()
        (project_dir / "sub" / "real.json").write_text("{}", encoding="utf-8")
    b100_links.create_junction(project_dir / "SUB", outside)
    entries = [first, "SUB/secret.json"]
    try:
        _write_manifest(
            project_dir,
            hostile.manifest(
                batch=entries, assignments={"firmware": entries}, gathered={"patches": entries}
            ),
        )
        manifest = read_project_manifest(project_dir)
    finally:
        os.rmdir(project_dir / "SUB")
    found = [(issue.code, issue.details.get("entry")) for issue in manifest.issues]
    assert found == [(MANIFEST_PATH_ESCAPE, "SUB/secret.json")] * 3, found
    kept = [manifest.batch, manifest.assignments["firmware"], manifest.gathered["patches"]]
    assert [[path.name for path in paths] for paths in kept] == [[Path(first).name]] * 3, kept
    assert service.manifest_rewrite_refusal(manifest) == "holds entries that were skipped"


def test_tc_b100_61_sec7_r2_2_one_serialize_checks_each_name_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inc 7 corrective pass 2, SEC7-R2-2: ``serialize_manifest`` (every
    in-project writer's refusal predicate) checks all its entries with ONE
    walk. The security probe T2's composition — 1 000 real files at the end
    of a 31-folder chain, listed in ``batch``, ``assignments`` and
    ``gathered`` — costs 31 folder checks + 1 000 file checks and
    serialises under 1 s with no finding.

    RED (cp1 tree): a fresh walk per entry, about 99 000 checks."""
    project_dir = tmp_path / "P"
    names = projects.real_files_under_a_chain(project_dir)
    calls: list = []
    real = service._lstat_state

    def _counting(path):
        calls.append(path)
        return real(path)

    monkeypatch.setattr(service, "_lstat_state", _counting)
    vs = ProjectVariantSet(project_name="P", variants=(), active_id=None)
    started = time.perf_counter()
    text, issues = serialize_manifest(
        vs,
        project_dir.resolve(),
        batch=names,
        assignments={"firmware": names},
        gathered={"patches": names},
    )
    took = time.perf_counter() - started
    assert issues == [] and text is not None, issues[:1]
    assert len(calls) == len(projects.CHAIN) + 1000, len(calls)
    assert took < 1.0, took


def test_tc_b100_61_sec6_5_junction_loop_costs_one_failure(tmp_path: Path) -> None:
    """Inc 7 corrective SEC7-1 (the security probe A3): 5 x 1 000 entries
    through ``loop``, a junction to itself. The walk refuses at the
    junction once; every later entry is refused from the cache → read,
    Load + panel and the append's re-read each under 1 s, 100 rows + 1.

    RED (corrective-pass base): A3 read 19.57 s."""
    b100_links.require_junctions()
    loops: list = []

    def _loop(project_dir: Path) -> None:
        loops.append(projects.create_junction_loop(project_dir / "loop"))

    try:
        scene = _sec6_5_filesystem_scene(tmp_path, hostile.junction_loop_at_cap(), setup=_loop)
    finally:
        for link in loops:
            os.rmdir(link)
    _assert_sec6_5_bounded(scene)
    manifest = scene["manifest"]
    assert not manifest.batch and not manifest.assignments.get("firmware")
    assert manifest.issues[-1].details["entry"].endswith("more recorded entries")


def test_tc_b100_61_files_at_the_cap_all_missing_are_bounded(tmp_path: Path) -> None:
    """Inc 7 corrective F2 (reviewer probe PB): ``files`` holds the image's
    record plus 999 well-formed records for files not on disk (exactly the
    cap: not damaged) → 999 ``missing`` problems; the panel lists 102 of
    them and ONE row counting the other 897, paints under 1 s, and the
    summary line still counts all 999.

    RED (corrective-pass base): 999 panel rows, painted in 2.45 s."""
    base = tmp_path / "app"
    project_dir = projects.copy_sources(_workarea(base) / "P", projects.CASE01_DIR, "firmware.s19")
    _write_manifest(
        project_dir, hostile.dumps(hostile.files_at_cap_missing(projects.file_records(project_dir)))
    )

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        real_load = app._handle_load_project
        timing: list = []

        def _timed(name):
            begun = time.perf_counter()
            real_load(name)
            timing.append(time.perf_counter() - begun)

        app._handle_load_project = _timed
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            await _open_panel_through_the_dialog(pilot, app)
            pressed = time.perf_counter()
            await _wait_for(
                pilot,
                lambda: len(app.screen.query("#result_summary")) > 0
                and app.screen.query_one("#result_summary").size.height > 0,
                "the painted Load-result panel",
                attempts=4000,
            )
            painted = time.perf_counter() - pressed
            rows = len(app.screen.query("#result_body .result-problem"))
            title = str(app.screen.query_one(".modal-title", Label).render())
            summary = [line for line in app.log_lines if line.endswith("details: p")]
            return timing, painted, rows, app._last_load_announcement, title, summary

    timing, painted, rows, announcement, title, summary = asyncio.run(_drive())
    print(f"load {timing} s; panel painted {painted:.2f} s; rows {rows}")
    assert timing and timing[0] < 1.0, timing
    assert painted < 1.0, painted
    assert rows == LOAD_PANEL_ROW_BOUND, rows
    last = announcement.problems[-1]
    assert (last.label, last.file) == ("more problems", "897 more files"), last
    assert [p.label for p in announcement.problems[:-1]] == ["missing"] * 102
    assert announcement.problem_count == 999
    assert "999 problems" in title, title
    assert summary and "999 problems" in summary[-1], summary


# ---------------------------------------------------------------------------
# TC-B100-62 — LLR-171.4, the Inc 7 seam arm (SEC6-3)
# ---------------------------------------------------------------------------


def test_tc_b100_62_manifest_write_refuses_a_project_swapped_for_a_junction(
    tmp_path: Path,
) -> None:
    """After placement, project folder P of work area W1 is replaced by a
    junction to project Q of another work area W2; the manifest write for
    W1/P is refused and Q receives no ``project.json``.

    RED (base 80052cb): the writer resolved P first, found W2's work-area
    anchor and wrote ``project.json`` into Q."""
    b100_links.require_junctions()
    base_one = tmp_path / "one"
    base_two = tmp_path / "two"
    project = _workarea(base_one) / "P"
    other = _workarea(base_two) / "Q"
    project.mkdir(parents=True)
    other.mkdir(parents=True)
    project.rmdir()
    b100_links.create_junction(project, other)
    try:
        vs = ProjectVariantSet(project_name="P", variants=(), active_id=None)
        written, issues = write_project_manifest(vs, project, base_one)
    finally:
        os.rmdir(project)
    assert written is None, written
    assert [issue.code for issue in issues] == [manifest_writer.MANIFEST_WRITE_CONTAINMENT]
    assert not (other / "project.json").exists()


def test_tc_b100_62_swap_after_the_check_is_reported_never_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inc 7 corrective SEC7-2 (the security probe B2): project folder P is
    swapped for a junction to another work area's Q AFTER the containment
    check and before the replace. The replace follows the junction, so the
    writer must detect it: no written path, one
    ``MANIFEST-WRITE-CONTAINMENT`` naming where the bytes landed — never a
    success.

    RED (corrective-pass base): ``written`` = P/project.json, no finding."""
    b100_links.require_junctions()
    base_one = tmp_path / "one"
    base_two = tmp_path / "two"
    project = _workarea(base_one) / "P"
    other = _workarea(base_two) / "Q"
    project.mkdir(parents=True)
    other.mkdir(parents=True)
    real_stage = manifest_writer._private_stage_dir

    def _swap_then_stage(workarea):
        project.rmdir()
        b100_links.create_junction(project, other)
        return real_stage(workarea)

    monkeypatch.setattr(manifest_writer, "_private_stage_dir", _swap_then_stage)
    try:
        vs = ProjectVariantSet(project_name="P", variants=(), active_id=None)
        written, issues = write_project_manifest(vs, project, base_one)
    finally:
        if os.path.lexists(project):
            os.rmdir(project)
    assert written is None, written
    assert [issue.code for issue in issues] == [manifest_writer.MANIFEST_WRITE_CONTAINMENT]
    assert str(other.resolve()) in issues[0].message, issues[0].message


def test_tc_b100_62_swap_toast_and_status_paint_no_exception_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inc 7 corrective pass 2, SEC7-R2-3 / R2-4 (HLR-169, as SEC7-5: class
    names go to the log only): the same swap after the check, through the
    app's manifest write. The error toast and the status line name where
    ``project.json`` landed and carry no exception class; the class is in
    the app's log file.

    RED (cp1 tree): the toast ended ``WorkareaContainmentError: ...``."""
    b100_links.require_junctions()
    app = S19TuiApp(base_dir=tmp_path / "one")
    project = app.workarea / "P"
    other = _workarea(tmp_path / "two") / "Q"
    project.mkdir(parents=True)
    other.mkdir(parents=True)
    real_stage = manifest_writer._private_stage_dir

    def _swap_then_stage(workarea):
        project.rmdir()
        b100_links.create_junction(project, other)
        return real_stage(workarea)

    painted: list = []
    monkeypatch.setattr(manifest_writer, "_private_stage_dir", _swap_then_stage)
    monkeypatch.setattr(app, "notify", lambda message, **kw: painted.append(str(message)))
    monkeypatch.setattr(app, "set_status", lambda message, *a, **k: painted.append(str(message)))
    app._variant_set = ProjectVariantSet(project_name="P", variants=(), active_id=None)
    try:
        ok = app._write_and_verify_manifest(project)
    finally:
        if os.path.lexists(project):
            os.rmdir(project)
    assert ok is False
    assert painted[0] == "Manifest write failed", painted
    assert len(painted) == 2 and str(other.resolve()) in painted[1], painted
    assert not [text for text in painted if EXCEPTION_NAME.search(text)], painted
    log_file = tmp_path / "one" / WORKAREA_DIRNAME / "logs" / "s19tui.log"
    logged = [
        line
        for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if "Manifest write refused" in line
    ]
    assert logged and "WorkareaContainmentError" in logged[-1], logged


# ---------------------------------------------------------------------------
# AT-B100-07 — HLR-169 black-box
# ---------------------------------------------------------------------------


def _log_line_4(app: S19TuiApp) -> str:
    return str(app.query_one("#log_line_4", Label).render())


async def _load_file_through_dialog(pilot, app: S19TuiApp, src: Path) -> None:
    await pilot.press("l")
    await _wait_for(pilot, lambda: isinstance(app.screen, LoadFileScreen), "the Load file dialog")
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


async def _save_project_through_dialog(pilot, app: S19TuiApp, name: str) -> None:
    await pilot.press("ctrl+s")
    await _wait_for(
        pilot, lambda: isinstance(app.screen, SaveProjectScreen), "the Save project dialog"
    )
    assert await pilot.click("#project_name"), "click missed #project_name"
    await pilot.press(*name)
    assert await pilot.click("#save_ok"), "click missed #save_ok"
    await _wait_for(
        pilot,
        lambda: _log_line_4(app).startswith("Saved project to")
        or "manifest verified" in _log_line_4(app),
        "the painted Save project outcome",
    )


async def _reopen_and_read(base: Path, size: tuple) -> tuple:
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=size, notifications=True) as pilot:
        await pilot.pause()
        await pilot.press("1")
        for _ in range(4):
            await pilot.pause()
        await _open_panel_through_the_dialog(pilot, app)
        text = await projects.read_load_result_panel(pilot, app)
        line = _log_line_4(app)
        painted_log = [str(app.query_one(f"#log_line_{i}", Label).render()) for i in (1, 2, 3, 4)]
        await pilot.press("escape")
        await _wait_for(
            pilot, lambda: len(app.screen.query("#result_ok")) == 0, "the panel closed"
        )
    return text, line, painted_log


@pytest.mark.parametrize("size", SIZES)
def test_at_b100_07_load_names_the_changed_file_and_the_hostile_record(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-169's acceptance scene by keys and clicks: Load file, Save
    project P; a byte of ``P/firmware.s19`` changes on disk; reopen P in a
    fresh app through the Load project dialog → the summary line on
    ``#log_line_4`` carries ``1 problem`` within 118 columns, and the panel
    names ``firmware.s19`` as ``changed on disk`` with ``Save project
    records the new state``. Then ``project.json`` is hand-edited to record
    ``../outside.s19``: reopening paints ``manifest damaged`` naming that
    record, "a file path points outside the project", no internal code on
    screen, and the code in the log file only.

    RED (base 80052cb, P-4): ``[2 image edited on disk] … notices=[]`` —
    the summary line says ``0 problems`` and the panel lists none."""
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    base = tmp_path / "app"
    project_dir = _workarea(base) / "P"

    async def _save_scene() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _load_file_through_dialog(pilot, app, src / "firmware.s19")
            await _save_project_through_dialog(pilot, app, "P")

    asyncio.run(_save_scene())
    projects.flip_data_byte(project_dir / "firmware.s19")
    text, line, _log = asyncio.run(_reopen_and_read(base, size))
    flat = projects.flat(text)
    assert "1 problem" in line[:118], line
    assert line.endswith("details: p"), line
    assert "changed on disk: firmware.s19" in flat, text
    assert "Save project records the new state" in flat, text

    manifest = projects.read_manifest(project_dir)
    manifest["files"]["../outside.s19"] = {"size": 1, "sha256": "0" * 64}
    (project_dir / "project.json").write_text(json.dumps(manifest), encoding="utf-8")
    text, line, painted_log = asyncio.run(_reopen_and_read(base, size))
    flat = projects.flat(text)
    assert "manifest damaged: ../outside.s19" in flat, text
    assert "a file path points outside the project" in flat, text
    assert not INTERNAL_CODE.search(text), text
    assert not [entry for entry in painted_log if INTERNAL_CODE.search(entry)], painted_log
    log_file = base / WORKAREA_DIRNAME / "logs" / "s19tui.log"
    assert "MANIFEST-PATH-ESCAPE" in log_file.read_text(encoding="utf-8", errors="replace")



# ---------------------------------------------------------------------------
# Inc 8a arms (E4): TC-B100-23 / -24 / -25 for the recorded active document
# (LLR-169.3, LLR-169.4, LLR-169.5 incl. E3 R7)
# ---------------------------------------------------------------------------


def _document_project(tmp_path: Path) -> tuple:
    base = tmp_path / "app"
    project_dir = projects.copy_sources(_workarea(base) / "P", projects.CASE01_DIR, "firmware.s19")
    (project_dir / "patches").mkdir()
    (project_dir / "patches" / "boost.json").write_bytes(projects.change_document_bytes())
    (project_dir / "patches" / "other.json").write_bytes(
        projects.change_document_bytes([projects.address_entry(0x80000060, (1,))])
    )
    vs = build_variant_set("P", [project_dir / "firmware.s19"])
    vs.active_id = "firmware"
    return base, project_dir, vs


def test_tc_b100_23_active_document_changed_between_write_and_verify(tmp_path: Path) -> None:
    """LLR-169.3 Inc 8a boundary: written and verified with
    ``active_document`` "patches/boost.json" → verified, 0 drift; then
    project.json edited so it records "patches/other.json" → mismatch,
    drift exactly ``["active_document"]``. The leave-it-out-of-the-domain
    mutant → 0 drift → RED."""
    base, project_dir, vs = _document_project(tmp_path)
    files = manifest_writer.project_file_records(project_dir)
    written, issues = write_project_manifest(
        vs, project_dir, base, files=files, active_document="patches/boost.json"
    )
    assert issues == [] and written is not None, issues
    unchanged = manifest_writer.verify_written_manifest(
        project_dir, vs, project_dir, files=files, active_document="patches/boost.json"
    )
    assert (unchanged.status, unchanged.drift) == (manifest_writer.MANIFEST_VERIFIED, [])
    manifest = projects.read_manifest(project_dir)
    manifest["active_document"] = "patches/other.json"
    (project_dir / "project.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = manifest_writer.verify_written_manifest(
        project_dir, vs, project_dir, files=files, active_document="patches/boost.json"
    )
    assert result.status == manifest_writer.MANIFEST_MISMATCH
    assert result.drift == ["active_document"], result.drift


def _record(path: Path) -> dict:
    return projects.file_record_of(path)


def test_tc_b100_24_files_key_of_the_active_document_is_read(tmp_path: Path) -> None:
    """LLR-169.4 Inc 8a: the ``files`` key equal to the accepted
    ``active_document`` is read (2 records, 0 issues); a second key under a
    document home is refused (1 BAD-STRUCTURE naming it)."""
    _base, project_dir, _vs = _document_project(tmp_path)
    payload = {
        "schema_version": 1,
        "active_variant": "firmware",
        "files": {
            "firmware.s19": _record(project_dir / "firmware.s19"),
            "patches/boost.json": _record(project_dir / "patches" / "boost.json"),
        },
        "active_document": "patches/boost.json",
    }
    _write_manifest(project_dir, payload)
    manifest = read_project_manifest(project_dir)
    assert manifest.issues == [], manifest.issues
    assert len(manifest.files) == 2, manifest.files
    payload["files"]["patches/other.json"] = _record(project_dir / "patches" / "other.json")
    _write_manifest(project_dir, payload)
    manifest = read_project_manifest(project_dir)
    assert len(manifest.files) == 2, manifest.files
    assert _codes(manifest) == [MANIFEST_BAD_STRUCTURE], manifest.issues
    assert "patches/other.json" in json.dumps(manifest.issues[0].details) + manifest.issues[0].message


def test_tc_b100_24_refused_document_refuses_its_files_key(tmp_path: Path) -> None:
    """A refused ``active_document`` (``7``) → its ``files`` key is refused
    too: 1 record (the image), 2 BAD-STRUCTURE issues."""
    _base, project_dir, _vs = _document_project(tmp_path)
    _write_manifest(
        project_dir,
        {
            "schema_version": 1,
            "active_variant": "firmware",
            "files": {
                "firmware.s19": _record(project_dir / "firmware.s19"),
                "patches/boost.json": _record(project_dir / "patches" / "boost.json"),
            },
            "active_document": 7,
        },
    )
    manifest = read_project_manifest(project_dir)
    assert manifest.unknown_keys == ()
    assert len(manifest.files) == 1, manifest.files
    assert _codes(manifest) == [MANIFEST_BAD_STRUCTURE, MANIFEST_BAD_STRUCTURE], manifest.issues


def test_tc_b100_24_derived_from_gets_no_document_exception(tmp_path: Path) -> None:
    """The exception is ``files``-only: a ``derived_from`` key equal to the
    active document → 0 records, 1 BAD-STRUCTURE (and the document itself
    accepted)."""
    _base, project_dir, _vs = _document_project(tmp_path)
    _write_manifest(
        project_dir,
        {
            "schema_version": 1,
            "active_variant": "firmware",
            "active_document": "patches/boost.json",
            "derived_from": {
                "patches/boost.json": {"base": "firmware.s19", "sha256": "a" * 64, "differ": 1}
            },
        },
    )
    manifest = read_project_manifest(project_dir)
    assert manifest.unknown_keys == ()
    assert getattr(manifest, "active_document", None) == "patches/boost.json"
    assert len(manifest.derived_from) == 0
    assert _codes(manifest) == [MANIFEST_BAD_STRUCTURE], manifest.issues


def _check(project_dir: Path) -> list:
    manifest = read_project_manifest(project_dir)
    return [
        (problem.kind, problem.file)
        for problem in manifest_writer.check_project_files(project_dir, manifest)
    ]


@pytest.mark.parametrize("recorded", [True, False], ids=["with-record", "without-record"])
def test_tc_b100_25_missing_active_document_is_one_problem(tmp_path: Path, recorded: bool) -> None:
    """LLR-169.5 (2 arms): a recorded ``active_document`` absent from disk →
    exactly 1 ``missing`` labelled "change document patches/boost.json"
    (E3 R20; re-pinned in Inc 8a cp1 from the bare text), with and without
    a ``files`` record. Mutants: the document skipped → 0 on the
    without-record arm; the helper also run for a recorded one → 2 → RED."""
    project_dir = projects.seed_document_project(tmp_path, record_document=recorded)
    (project_dir / "patches" / "boost.json").unlink()
    assert _check(project_dir) == [("missing", "change document patches/boost.json")]


def test_tc_b100_25_missing_document_survives_the_no_digests_return(tmp_path: Path) -> None:
    """P-B2: no ``files`` key and the document absent → 2 problems, 1
    ``missing`` labelled as the change document (E3 R20, Inc 8a cp1
    re-pin) and 1 ``no digests saved``."""
    project_dir = tmp_path / "P"
    projects.copy_sources(project_dir, projects.CASE01_DIR, "firmware.s19")
    _write_manifest(
        project_dir,
        {"schema_version": 1, "active_variant": "firmware", "active_document": "patches/boost.json"},
    )
    assert sorted(_check(project_dir)) == [
        ("missing", "change document patches/boost.json"),
        ("no digests saved", "project.json"),
    ]


def test_tc_b100_25_recorded_document_present_and_equal_is_clean(tmp_path: Path) -> None:
    project_dir = projects.seed_document_project(tmp_path)
    assert _check(project_dir) == []


def test_tc_b100_25_changed_document_is_named_by_its_project_text(tmp_path: Path) -> None:
    """A3-1 / E3 R20: a recorded document whose bytes changed (same size)
    → 1 ``changed on disk`` labelled "change document patches/boost.json"
    (not "boost.json", not the bare text: re-pinned in Inc 8a cp1), the
    label the reopen uses, so the load merge keeps one problem per file."""
    project_dir = projects.seed_document_project(tmp_path)
    target = project_dir / "patches" / "boost.json"
    data = bytearray(target.read_bytes())
    data[data.index(b"DE AD")] = ord("F")
    target.write_bytes(bytes(data))
    assert _check(project_dir) == [("changed on disk", "change document patches/boost.json")]


def test_tc_b100_25_r7_missing_variant_never_names_the_document(tmp_path: Path) -> None:
    """E3 R7 (LLR-169.5): a missing variant id ``boost`` with the document
    ``patches/boost.json`` recorded first → the problem names the variant's
    data file ``boost.s19`` (or the id when no data file is recorded), never
    the document. The drop-the-suffix-restriction mutant → "boost.json" →
    RED."""
    from s19_app.tui.services.variant_execution_service import FileRecord
    from s19_app.tui.services.variant_execution_service import ProjectManifest

    root = (tmp_path / "P").resolve()
    record = FileRecord(1, "0" * 64)
    both = ProjectManifest(
        schema_version=1,
        active_variant="boost",
        files={root / "patches" / "boost.json": record, root / "boost.s19": record},
    )
    assert service._missing_recorded(both, "boost") == "boost.s19"
    only_document = ProjectManifest(
        schema_version=1,
        active_variant="boost",
        files={root / "patches" / "boost.json": record},
    )
    assert service._missing_recorded(only_document, "boost") == "boost"
