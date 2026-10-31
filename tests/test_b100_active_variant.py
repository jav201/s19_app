"""Batch-100 increment 6 — a save-back becomes the active variant (HLR-168).

Covers HLR-168 / LLR-168.1–LLR-168.3 (PH-4, D2, O-1, O-10):

  - TC-B100-18 — LLR-168.1: ``read_project_manifest`` exposes ``gathered``
    as ``dict[str, list[Path]]``; a malformed value gives one
    ``MANIFEST-BAD-STRUCTURE`` and is skipped, an escaping entry gives one
    issue and no entry, an absent key gives ``{}`` and no issue.
  - TC-B100-19 — LLR-168.2: a save-back into the open project makes the
    written file the active variant in the session and in ``project.json``
    (``p02`` A -> ``firmware_1``, ``p02`` B -> ``firmware-patched``), and
    ``current_file.path`` stays on the image the session loaded; a
    save-back with no project open writes no manifest.
  - TC-B100-20 — LLR-168.3: the four in-project writers (the save-back,
    the Load-file variant append, the MAC sync, the A2L sync) each rewrite
    ``project.json`` through the manifest seam, carrying ``batch``,
    ``assignments``, ``declared_regions`` and ``gathered`` unchanged and
    project-relative; the append makes the appended file active and paints
    a line naming the project and the file it now opens — only when
    ``project.json`` was written (a read-only ``project.json``: 0 such
    lines). Corrective pass 1 (OQ-1 ruling (b), review F1 / SEC6-1): a
    DAMAGED ``project.json`` (not JSON, a top level that is not an object,
    over the read cap) is never rewritten by any of the four writers — its
    bytes are identical afterwards, the placed file stays, and one status
    line says it was not rewritten. Corrective pass 2 (SEC6-7): an A2L sync
    into a project whose manifest records a 40 000-character entry does not
    crash; the entry is skipped and the rest is carried. Corrective pass 3:
    a variant append into a project whose ``gathered`` entry goes through a
    junction that points to itself (SEC6-7) does not crash; a manifest with
    an integer over Python's digit limit (SEC6-8) is a damaged manifest, so
    no writer rewrites it.
  - AT-B100-06 — HLR-168 black-box: Load file, Save project, apply a patch,
    save back (``p02`` A and B), then reopen the project in a fresh app:
    the summary line names the saved-back file, the independent reader
    finds the patch in it, and ``project.json`` names it as active.
  - AT-B100-20 — HLR-168 black-box: with every not-owned key recorded, a
    new S19, a MAC and an A2L loaded through Load each leave the keys equal
    with 0 absolute paths; a fresh app opening the project names the new
    variant in the Load-result panel.

Byte oracles: ``tests/support/independent_reader.py``; manifest oracles:
the stdlib ``json`` reader (``tests/support/b100_projects.py``), never the
app's own manifest reader.

Inc 6 scope notes (declared in the increment packet): ``derived_from``
(LLR-168.4) and ``active_document`` are written from Inc 7 / Inc 8a, so the
carry arms here cover the four keys the writer emits today; AT-B100-20's
Execute-scope arm lands with Inc 8a / 9b.

Inc 7 adds:

  - TC-B100-20 (SEC6-2, LED .68): a manifest the rewrite cannot carry whole
    — an unknown top-level key, a ``schema_version`` above 1, a skipped
    entry — is never rewritten by an in-project writer: its bytes are
    identical and one status line says why. The two SEC6-7 arms are
    re-pinned to that rule (their skipped entries were dropped silently).
  - TC-B100-71 — LLR-168.4: ``derived_from`` — a save-back to
    ``firmware_1.s19`` and to ``firmware-patched.s19`` records
    ``firmware.s19`` with its SHA-256 and 4 differing bytes; a Save project
    emit of a session loaded from outside the project records the base,
    absent from the project; a byte copy records nothing; ``../x.s19`` as a
    base is 1 issue and 0 entries; a variant append carries the record.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest
from textual.widgets import Label

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import LoadFileScreen
from s19_app.tui.screens import LoadProjectScreen
from s19_app.tui.screens import SaveProjectScreen
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services.variant_execution_service import MANIFEST_BAD_STRUCTURE
from s19_app.tui.services.variant_execution_service import MANIFEST_PATH_ESCAPE
from s19_app.tui.services.variant_execution_service import read_project_manifest
from s19_app.tui.workspace import WORKAREA_DIRNAME
from s19_app.tui.workspace import WORKAREA_SUBDIR

from tests.support import b100_projects as projects
from tests.support.independent_reader import read_s19
from tests.support.timing import timing_bound

SIZES = [(118, 54), (220, 60)]
PATCH_ADDRESS = 0x8000007C
PATCH_BYTES = (0xDE, 0xAD, 0xBE, 0xEF)


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


async def _wait_for(pilot, predicate, description: str, attempts: int = 200) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {description}")


def _status_text(app: S19TuiApp) -> str:
    return str(app.query_one("#log_line_4", Label).render())


def _painted_log(app: S19TuiApp) -> str:
    return "\n".join(
        str(app.query_one(f"#log_line_{i}", Label).render()) for i in (1, 2, 3, 4)
    )


def _patch_found(path: Path) -> bool:
    data = read_s19(path).data
    return all(
        data.get(PATCH_ADDRESS + offset) == byte
        for offset, byte in enumerate(PATCH_BYTES)
    )


# ---------------------------------------------------------------------------
# TC-B100-18 — LLR-168.1: the reader parses ``gathered``
# ---------------------------------------------------------------------------


def _write_manifest(project_dir: Path, payload: dict) -> None:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "project.json").write_text(json.dumps(payload), encoding="utf-8")


def test_tc_b100_18_valid_gathered_is_an_equal_dict(tmp_path: Path) -> None:
    """A valid ``gathered`` comes back as the same homes and entries,
    resolved inside the project, with no issue."""
    project_dir = tmp_path / "P"
    _write_manifest(
        project_dir,
        {
            "schema_version": 1,
            "active_variant": "firmware",
            "gathered": {
                "patches": ["patches/a.json", "patches/b.json"],
                "checks": ["checks/c.json"],
            },
        },
    )
    manifest = read_project_manifest(project_dir)
    root = project_dir.resolve()
    assert manifest.issues == []
    assert manifest.gathered == {
        "patches": [root / "patches" / "a.json", root / "patches" / "b.json"],
        "checks": [root / "checks" / "c.json"],
    }


def test_tc_b100_18_list_instead_of_object_is_one_issue(tmp_path: Path) -> None:
    project_dir = tmp_path / "P"
    _write_manifest(
        project_dir,
        {"schema_version": 1, "active_variant": None, "gathered": ["patches/a.json"]},
    )
    manifest = read_project_manifest(project_dir)
    assert manifest.gathered == {}
    assert [issue.code for issue in manifest.issues] == [MANIFEST_BAD_STRUCTURE]


def test_tc_b100_18_home_value_not_a_list_is_one_issue(tmp_path: Path) -> None:
    project_dir = tmp_path / "P"
    _write_manifest(
        project_dir,
        {
            "schema_version": 1,
            "active_variant": None,
            "gathered": {"patches": "patches/a.json", "checks": ["checks/c.json"]},
        },
    )
    manifest = read_project_manifest(project_dir)
    assert manifest.gathered == {"checks": [project_dir.resolve() / "checks" / "c.json"]}
    assert [issue.code for issue in manifest.issues] == [MANIFEST_BAD_STRUCTURE]


def test_tc_b100_18_escaping_entry_is_one_issue_and_no_entry(tmp_path: Path) -> None:
    project_dir = tmp_path / "P"
    _write_manifest(
        project_dir,
        {"schema_version": 1, "active_variant": None, "gathered": {"patches": ["../x.json"]}},
    )
    manifest = read_project_manifest(project_dir)
    assert manifest.gathered == {"patches": []}
    assert [issue.code for issue in manifest.issues] == [MANIFEST_PATH_ESCAPE]


def test_tc_b100_18_absent_key_is_empty_with_no_issue(tmp_path: Path) -> None:
    project_dir = tmp_path / "P"
    _write_manifest(project_dir, {"schema_version": 1, "active_variant": "firmware"})
    manifest = read_project_manifest(project_dir)
    assert manifest.gathered == {}
    assert manifest.issues == []


# ---------------------------------------------------------------------------
# Shared white-box scene (TC-B100-19 / TC-B100-20): Load file -> Save
# project P -> add + apply a patch -> save back.
# ---------------------------------------------------------------------------


async def _load_through_handler(pilot, app: S19TuiApp, src: Path) -> None:
    app._handle_load_dialog(src)
    await _wait_for(
        pilot,
        lambda: app.current_file is not None
        and app.current_file.path.name.startswith(src.stem)
        and app.current_file.path.suffix == src.suffix,
        f"the load of {src.name}",
    )


async def _save_project(pilot, app: S19TuiApp, name: str) -> None:
    from s19_app.tui.app import SaveProjectPayload

    app._handle_save_dialog(
        SaveProjectPayload(parent_folder=str(app.workarea), project_name=name)
    )
    await _wait_for(pilot, lambda: app.current_project == name, "the project save")


def _apply_patch(app: S19TuiApp) -> None:
    app._change_service.add_entry(
        f"0x{PATCH_ADDRESS:08X}", "", " ".join(f"{b:02X}" for b in PATCH_BYTES)
    )
    loaded = app.current_file
    app._change_service.apply(loaded.mem_map, loaded.ranges, loaded.mac_records, None)


async def _save_back(pilot, app: S19TuiApp, filename: str) -> None:
    app.on_patch_editor_panel_save_back_decision(
        PatchEditorPanel.SaveBackDecision(filename, 32)
    )
    await _wait_for(
        pilot,
        lambda: "Saved + verified" in _painted_log(app)
        or "not saved" in _painted_log(app).lower(),
        "the save-back outcome",
    )


@pytest.mark.parametrize("case", ["A", "B"])
def test_tc_b100_19_save_back_becomes_the_active_variant(tmp_path: Path, case: str) -> None:
    """``p02`` A (typed ``firmware.s19`` -> ``firmware_1.s19``) and B (the
    default ``firmware-patched.s19``): after the save-back the session's
    active variant, the image's variant id and ``project.json`` all name the
    written file; ``current_file.path`` is still the loaded image.

    RED (executed on 1d677ba, P-3): ``active_variant 'firmware'``."""
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    base = tmp_path / "app"

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_through_handler(pilot, app, src / "firmware.s19")
            await _save_project(pilot, app, "P")
            loaded_path = app.current_file.path
            _apply_patch(app)
            typed = projects.typed_name(case) or f"{app.current_file.variant_id}-patched.s19"
            await _save_back(pilot, app, typed)
            return (
                loaded_path,
                app.current_file.path,
                app._variant_set.active_id,
                app.current_file.variant_id,
            )

    loaded_path, path_after, active_id, variant_id = asyncio.run(_drive())
    expected = Path(projects.landed_name(case)).stem
    project_dir = _workarea(base) / "P"
    assert (project_dir / projects.landed_name(case)).is_file()
    assert projects.read_manifest(project_dir)["active_variant"] == expected, (
        f"active_variant {projects.read_manifest(project_dir)['active_variant']!r}"
    )
    assert active_id == expected
    assert variant_id == expected
    assert path_after == loaded_path
    assert loaded_path.parent.name == "temp"


def test_tc_b100_19_save_back_with_no_project_writes_no_manifest(tmp_path: Path) -> None:
    """Boundary: no project open -> the save-back lands in the work area and
    no ``project.json`` is written anywhere."""
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    base = tmp_path / "app"

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_through_handler(pilot, app, src / "firmware.s19")
            _apply_patch(app)
            await _save_back(pilot, app, "out.s19")

    asyncio.run(_drive())
    assert (_workarea(base) / "out.s19").is_file()
    assert list(base.rglob("project.json")) == []


# ---------------------------------------------------------------------------
# TC-B100-20 — LLR-168.3: every in-project writer carries the keys it does
# not own
# ---------------------------------------------------------------------------


async def _open_seeded_project(pilot, app: S19TuiApp, name: str = "P") -> None:
    app._handle_load_project(name)
    await _wait_for(
        pilot,
        lambda: app.current_project == name and app.current_file is not None,
        f"the project load of {name}",
    )
    for _ in range(6):
        await pilot.pause()


def _assert_carried(project_dir: Path, before_bytes: bytes) -> dict:
    """The manifest was rewritten (bytes changed), keeps the four
    not-owned keys equal, and holds 0 absolute paths."""
    after_bytes = (project_dir / "project.json").read_bytes()
    assert after_bytes != before_bytes, "project.json was not rewritten"
    manifest = json.loads(after_bytes)
    assert projects.not_owned(manifest) == projects.seeded_keys(), manifest
    assert projects.absolute_strings(manifest) == [], manifest
    return manifest


def test_tc_b100_20_save_back_carries_every_key(tmp_path: Path) -> None:
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    before = (project_dir / "project.json").read_bytes()

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _open_seeded_project(pilot, app)
            _apply_patch(app)
            await _save_back(pilot, app, "firmware.s19")

    asyncio.run(_drive())
    manifest = _assert_carried(project_dir, before)
    assert manifest["active_variant"] == "firmware_1"


def test_tc_b100_20_variant_append_carries_every_key_and_activates(tmp_path: Path) -> None:
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    before = (project_dir / "project.json").read_bytes()
    src = projects.copy_sources(tmp_path / "src", projects.CASE02_DIR, "firmware.s19")
    statuses: list = []

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        real_set_status = app.set_status

        def _capture(message, *args, **kwargs):
            statuses.append(str(message))
            return real_set_status(message, *args, **kwargs)

        app.set_status = _capture
        async with app.run_test() as pilot:
            await pilot.pause()
            await _open_seeded_project(pilot, app)
            statuses.clear()
            app.load_from_path(src / "firmware.s19")
            await _wait_for(
                pilot,
                lambda: any(s.startswith("Added variant") for s in statuses),
                "the variant append",
            )

    asyncio.run(_drive())
    manifest = _assert_carried(project_dir, before)
    assert manifest["active_variant"] == "firmware_1"
    opens = [s for s in statuses if "now opens" in s]
    assert opens == ["Project 'P' now opens firmware_1.s19"], statuses


def test_tc_b100_20_mac_sync_carries_every_key(tmp_path: Path) -> None:
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    before = (project_dir / "project.json").read_bytes()
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.mac")

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _open_seeded_project(pilot, app)
            app.load_from_path(src / "firmware.mac")
            await _wait_for(
                pilot,
                lambda: (project_dir / "firmware.mac").is_file()
                and (project_dir / "project.json").read_bytes() != before,
                "the MAC sync and its manifest rewrite",
            )

    asyncio.run(_drive())
    manifest = _assert_carried(project_dir, before)
    assert manifest["active_variant"] == "firmware"


def test_tc_b100_20_a2l_sync_carries_every_key(tmp_path: Path) -> None:
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    before = (project_dir / "project.json").read_bytes()
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.a2l")

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _open_seeded_project(pilot, app)
            app.load_a2l_from_path(src / "firmware.a2l")
            await _wait_for(
                pilot,
                lambda: (project_dir / "firmware.a2l").is_file()
                and (project_dir / "project.json").read_bytes() != before,
                "the A2L sync and its manifest rewrite",
            )

    asyncio.run(_drive())
    manifest = _assert_carried(project_dir, before)
    assert manifest["active_variant"] == "firmware"

# ---------------------------------------------------------------------------
# TC-B100-20, corrective pass 1 — a damaged project.json is never rewritten
# (OQ-1 ruling (b), review F1 / SEC6-1) and "now opens" follows only a
# written manifest (review F2 / SEC6-4)
# ---------------------------------------------------------------------------

#: The three whole-file damage kinds. ``over-cap`` is a valid manifest read
#: with the reader's cap lowered below its size (the real cap is 256 MB).
DAMAGE_KINDS = ("not-json", "not-an-object", "over-cap", "int-over-digit-limit")
WRITERS = ("save-back", "variant-append", "mac-sync", "a2l-sync")
#: writer -> the file it places in P (seeded with case_01 ``firmware.s19``).
PLACED = {
    "save-back": "firmware_1.s19",
    "variant-append": "firmware_1.s19",
    "mac-sync": "firmware.mac",
    "a2l-sync": "firmware.a2l",
}


def _damage(project_dir: Path, kind: str, monkeypatch) -> bytes:
    path = project_dir / "project.json"
    if kind == "not-json":
        # one stray character away from the seeded manifest: truncated
        path.write_bytes(path.read_bytes()[:-1] + b",")
    elif kind == "not-an-object":
        path.write_text('["firmware"]', encoding="utf-8")
    elif kind == "int-over-digit-limit":
        # SEC6-8: json.load raises a plain ValueError, not JSONDecodeError
        path.write_text(projects.OVERLONG_INT_MANIFEST, encoding="utf-8")
    else:
        from s19_app.tui.services import variant_execution_service as service

        monkeypatch.setattr(service, "MANIFEST_SIZE_CAP_BYTES", 16)
    return path.read_bytes()


def _run_writer(tmp_path: Path, base: Path, writer: str) -> list:
    """Open the seeded P directly, run ``writer`` once, return every status
    line painted after the project load."""
    project_dir = _workarea(base) / "P"
    sources = {
        "variant-append": (projects.CASE02_DIR, "firmware.s19"),
        "mac-sync": (projects.CASE01_DIR, "firmware.mac"),
        "a2l-sync": (projects.CASE01_DIR, "firmware.a2l"),
    }
    src = None
    if writer in sources:
        folder, name = sources[writer]
        src = projects.copy_sources(tmp_path / "src", folder, name) / name
    statuses: list = []

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        real_set_status = app.set_status

        def _capture(message, *args, **kwargs):
            statuses.append(str(message))
            return real_set_status(message, *args, **kwargs)

        app.set_status = _capture
        async with app.run_test() as pilot:
            await pilot.pause()
            await _open_seeded_project(pilot, app)
            statuses.clear()
            if writer == "save-back":
                _apply_patch(app)
                await _save_back(pilot, app, "firmware.s19")
            elif writer == "variant-append":
                app.load_from_path(src)
                await _wait_for(
                    pilot,
                    lambda: any(s.startswith("Added variant") for s in statuses),
                    "the variant append",
                )
            else:
                if writer == "mac-sync":
                    app.load_from_path(src)
                else:
                    app.load_a2l_from_path(src)
                await _wait_for(
                    pilot,
                    lambda: (project_dir / PLACED[writer]).is_file(),
                    f"the {writer} placing {PLACED[writer]}",
                )
            for _ in range(6):
                await pilot.pause()

    asyncio.run(_drive())
    return statuses


@pytest.mark.parametrize("damage", DAMAGE_KINDS)
@pytest.mark.parametrize("writer", WRITERS)
def test_tc_b100_20_damaged_manifest_is_never_rewritten(
    tmp_path: Path, monkeypatch, writer: str, damage: str
) -> None:
    """Each in-project writer, with a ``project.json`` the reader cannot
    read as a manifest: the damaged bytes are identical afterwards (the
    user's records in them survive), the writer's file is placed, the status
    says the manifest is damaged and was not rewritten, and nothing claims
    a save, a verify or a new opening variant.

    RED (executed on the reviewed Inc 6 tree, d37ee857): every arm —
    the writer replaced the file with an almost empty manifest and painted
    ``Project saved + manifest verified``."""
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    damaged = _damage(project_dir, damage, monkeypatch)
    statuses = _run_writer(tmp_path, base, writer)
    placed = PLACED[writer]
    assert (project_dir / "project.json").read_bytes() == damaged, (
        "the damaged project.json was rewritten"
    )
    assert (project_dir / placed).is_file(), f"{placed} was not placed"
    expected = (
        f"project.json in project 'P' is damaged and was not rewritten - "
        f"{placed} stays in the project; Save project rewrites it"
    )
    assert statuses.count(expected) == 1, statuses
    assert not [s for s in statuses if "manifest verified" in s], statuses
    assert not [s for s in statuses if "now opens" in s], statuses


def test_tc_b100_20_a2l_sync_with_an_overlong_entry_does_not_crash(tmp_path: Path) -> None:
    """SEC6-7: the manifest records a 40 000-character entry in ``batch``,
    ``assignments`` and ``gathered`` next to the seeded keys. The project
    opens and an A2L sync (which re-reads the manifest to build the carry)
    places ``firmware.a2l`` and rewrites ``project.json``: the over-long
    entries are skipped (reported, never trusted) and every seeded key is
    carried.

    RED (executed on the corrective-pass-1 tree, 395dcbde): ``ValueError``
    out of ``Path.resolve()``."""
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    manifest = projects.read_manifest(project_dir)
    overlong = "q" * 40_000
    manifest["batch"].append(overlong)
    manifest["assignments"]["firmware"].append(overlong)
    manifest["gathered"]["patches"].append(overlong)
    (project_dir / "project.json").write_text(
        json.dumps(manifest, separators=(",", ":")), encoding="utf-8"
    )
    before = (project_dir / "project.json").read_bytes()
    statuses = _run_writer(tmp_path, base, "a2l-sync")
    # Inc 7 re-pin (SEC6-2): the entries are skipped and the manifest is
    # left as it is — a rewrite would drop them silently.
    assert (project_dir / "firmware.a2l").is_file()
    assert (project_dir / "project.json").read_bytes() == before
    assert [s for s in statuses if "holds entries that were skipped and was not rewritten" in s], statuses


def test_tc_b100_20_variant_append_with_a_junction_loop_entry_does_not_crash(
    tmp_path: Path,
) -> None:
    """SEC6-7 remainder: ``gathered`` records ``loop/x.json`` where ``loop``
    is a junction to itself, next to the seeded keys. The project opens and
    a variant append (which re-reads the manifest after placing) keeps
    ``firmware_1.s19`` and rewrites ``project.json``: the loop entry is
    skipped and every seeded key is carried.

    RED (executed on the corrective-pass-2 tree, e494c50c): ``RuntimeError:
    Symlink loop`` out of ``Path.resolve()``."""
    import os

    from tests.support import b100_links

    b100_links.require_junctions()
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    loop = projects.create_junction_loop(project_dir / "loop")
    manifest = projects.read_manifest(project_dir)
    manifest["gathered"]["patches"].append("loop/x.json")
    (project_dir / "project.json").write_text(
        json.dumps(manifest, separators=(",", ":")), encoding="utf-8"
    )
    before = (project_dir / "project.json").read_bytes()
    try:
        statuses = _run_writer(tmp_path, base, "variant-append")
    finally:
        os.rmdir(loop)
    assert (project_dir / "firmware_1.s19").is_file()
    # Inc 7 re-pin (SEC6-2): the skipped entry is never dropped silently —
    # the manifest is left as it is and no line claims Load now opens it.
    assert (project_dir / "project.json").read_bytes() == before
    assert [s for s in statuses if "holds entries that were skipped and was not rewritten" in s], statuses
    assert not [s for s in statuses if "now opens" in s], statuses


WRITER_OUTCOMES = ("manifest verified", "not rewritten", "Manifest write failed", "Saved project", "NOT saved")


@pytest.mark.parametrize(
    "writer", ["variant-append", "mac-sync", "a2l-sync", "save-back", "save-project"]
)
def test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second(
    tmp_path: Path, writer: str
) -> None:
    """Inc 7 corrective pass 2, SEC7-R2-2 (SEC6-5's time bound for the
    writers; security probe T2): P records 1 000 real files at the end of a
    31-folder chain in ``batch``, ``assignments`` and ``gathered`` (no
    finding, so every writer rewrites). Each in-project writer — variant
    append, MAC sync, A2L sync, save-back — and Save project with that
    composition reach their verified manifest line under 1 s from the
    trigger.

    RED (cp1 tree): append 6.89 s, MAC sync 7.12 s, A2L sync 6.44 s,
    save-back 6.42 s (one fresh walk per entry in the serializer)."""
    from s19_app.tui.app import SaveProjectPayload

    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    names = projects.real_files_under_a_chain(project_dir)
    manifest = projects.read_manifest(project_dir)
    manifest.update(batch=names, assignments={"firmware": names}, gathered={"patches": names})
    (project_dir / "project.json").write_text(
        json.dumps(manifest, separators=(",", ":")), encoding="utf-8"
    )
    sources = {
        "variant-append": (projects.CASE02_DIR, "firmware.s19"),
        "mac-sync": (projects.CASE01_DIR, "firmware.mac"),
        "a2l-sync": (projects.CASE01_DIR, "firmware.a2l"),
    }
    src = None
    if writer in sources:
        folder, name = sources[writer]
        src = projects.copy_sources(tmp_path / "src", folder, name) / name
    statuses: list = []

    async def _drive() -> float:
        app = S19TuiApp(base_dir=base)
        real_set_status = app.set_status

        def _capture(message, *args, **kwargs):
            statuses.append(str(message))
            return real_set_status(message, *args, **kwargs)

        app.set_status = _capture
        async with app.run_test() as pilot:
            await pilot.pause()
            await _open_seeded_project(pilot, app)
            statuses.clear()
            started = time.perf_counter()
            if writer == "save-back":
                _apply_patch(app)
                app.on_patch_editor_panel_save_back_decision(
                    PatchEditorPanel.SaveBackDecision("firmware.s19", 32)
                )
            elif writer == "variant-append" or writer == "mac-sync":
                app.load_from_path(src)
            elif writer == "a2l-sync":
                app.load_a2l_from_path(src)
            else:
                app._handle_save_dialog(
                    SaveProjectPayload(
                        parent_folder=str(app.workarea),
                        project_name="P",
                        batch=tuple(names),
                        assignments={"firmware": tuple(names)},
                    )
                )
            await _wait_for(
                pilot,
                lambda: any(o in s for s in statuses for o in WRITER_OUTCOMES),
                f"the {writer}'s manifest outcome",
                attempts=4000,
            )
            return time.perf_counter() - started

    took = asyncio.run(_drive())
    outcomes = [s for s in statuses if any(o in s for o in WRITER_OUTCOMES)]
    print(f"{writer}: trigger -> outcome {took:.3f} s; {outcomes[:1]}")
    assert "manifest verified" in outcomes[0], outcomes
    assert took < timing_bound(1.0), took


def test_tc_b100_20_append_says_now_opens_only_after_the_write(tmp_path: Path) -> None:
    """A real write failure (``project.json`` read-only, review probe P2):
    the append still adds the variant, the status says the manifest write
    failed, and 0 lines claim that Load now opens the new file — on disk
    ``active_variant`` is still the old one.

    RED (executed on the reviewed Inc 6 tree, d37ee857): ``'Manifest write
    failed', "Project 'P' now opens firmware_1.s19"``."""
    import os
    import stat

    if os.name != "nt":
        # CI-6-1: a POSIX rename replaces a read-only file; the sibling
        # ``..._on_any_platform`` forces the same failure without the bit.
        pytest.skip("a read-only file blocks a replace only on Windows (PDR C-QA-6)")
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    manifest_path = project_dir / "project.json"
    before = manifest_path.read_bytes()
    os.chmod(manifest_path, stat.S_IREAD)
    try:
        statuses = _run_writer(tmp_path, base, "variant-append")
    finally:
        os.chmod(manifest_path, stat.S_IREAD | stat.S_IWRITE)
    assert manifest_path.read_bytes() == before
    assert projects.read_manifest(project_dir)["active_variant"] == "firmware"
    assert "Manifest write failed" in statuses, statuses
    assert not [s for s in statuses if "now opens" in s], statuses
    assert "Added variant 'firmware_1' to project 'P'" in statuses, statuses


def test_tc_b100_20_append_says_now_opens_only_after_the_write_on_any_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CI-6-1: the same scene with the failure forced on every platform —
    every ``os.replace`` onto ``project.json`` raises ``PermissionError``
    (what Windows raises for a read-only target). The variant is added, the
    status says the manifest write failed, 0 lines claim "now opens", and
    ``project.json`` is byte-identical."""
    import os

    real_replace = os.replace

    def _refuse_manifest(src, dst, *args, **kwargs):
        if Path(dst).name == "project.json":
            raise PermissionError(13, "forced by the test", str(dst))
        return real_replace(src, dst, *args, **kwargs)

    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    manifest_path = project_dir / "project.json"
    before = manifest_path.read_bytes()
    monkeypatch.setattr(os, "replace", _refuse_manifest)
    statuses = _run_writer(tmp_path, base, "variant-append")
    monkeypatch.undo()
    assert manifest_path.read_bytes() == before
    assert projects.read_manifest(project_dir)["active_variant"] == "firmware"
    assert "Manifest write failed" in statuses, statuses
    assert not [s for s in statuses if "now opens" in s], statuses
    assert "Added variant 'firmware_1' to project 'P'" in statuses, statuses


SEC6_2_CASES = {
    "unknown-key": lambda manifest: manifest.update({"future_key": {"keep": [1, 2]}}),
    "newer-schema": lambda manifest: manifest.update({"schema_version": 2}),
    "skipped-entry": lambda manifest: manifest["batch"].append("../outside.json"),
    # Inc 7 corrective F8 / SEC7-4 (a): only the integer 1 is version 1.
    "bool-schema": lambda manifest: manifest.update({"schema_version": True}),
    "string-schema": lambda manifest: manifest.update({"schema_version": "1"}),
    "float-schema": lambda manifest: manifest.update({"schema_version": 1.0}),
}


@pytest.mark.parametrize(
    "version, phrase",
    [
        (1, None),
        (None, None),
        (2, "was written by a newer version"),
        (7, "was written by a newer version"),
        (True, "was written by an unknown version"),
        ("1", "was written by an unknown version"),
        (1.0, "was written by an unknown version"),
        (0, "was written by an unknown version"),
        (-1, "was written by an unknown version"),
    ],
)
def test_tc_b100_20_schema_version_is_the_integer_one(version, phrase) -> None:
    """Inc 7 corrective F8 / SEC7-4 (a): only the integer ``1`` (never
    ``True``, ``"1"`` or ``1.0``) — or no key — is this version; the
    refusal says "newer version" only for an integer above 1 and "unknown
    version" otherwise.

    RED (corrective-pass base): ``True`` and ``1.0`` were version 1 and
    every other value "a newer version"."""
    from s19_app.tui.services.variant_execution_service import ProjectManifest
    from s19_app.tui.services.variant_execution_service import manifest_rewrite_refusal

    manifest = ProjectManifest(schema_version=version, active_variant=None)
    assert manifest_rewrite_refusal(manifest) == phrase


def test_tc_b100_20_reader_keeps_a_float_schema_version(tmp_path: Path) -> None:
    """Inc 7 corrective F8: the reader keeps ``1.0`` as found (it is not
    version 1), so the refusal names it, not a skipped entry."""
    from s19_app.tui.services.variant_execution_service import manifest_rewrite_refusal
    from s19_app.tui.services.variant_execution_service import read_project_manifest

    project = tmp_path / "P"
    project.mkdir()
    (project / "project.json").write_text('{"schema_version": 1.0}', encoding="utf-8")
    manifest = read_project_manifest(project)
    assert manifest.schema_version == 1.0 and type(manifest.schema_version) is float
    assert manifest.issues == []
    assert manifest_rewrite_refusal(manifest) == "was written by an unknown version"


@pytest.mark.parametrize("case", sorted(SEC6_2_CASES))
def test_tc_b100_20_rewrite_never_drops_what_it_cannot_carry(tmp_path: Path, case: str) -> None:
    """SEC6-2 (LED .68): a variant append into a project whose manifest has
    an unknown top-level key, a ``schema_version`` of 2, or an entry the
    reader skips → the variant is placed, ``project.json`` is
    byte-identical, and one status line says it was not rewritten.

    RED (base 80052cb): the rewrite drops the unknown key, writes
    ``schema_version`` 1, and drops the skipped entry."""
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    manifest = projects.read_manifest(project_dir)
    SEC6_2_CASES[case](manifest)
    (project_dir / "project.json").write_text(
        json.dumps(manifest, separators=(",", ":")), encoding="utf-8"
    )
    before = (project_dir / "project.json").read_bytes()
    statuses = _run_writer(tmp_path, base, "variant-append")
    assert (project_dir / "firmware_1.s19").is_file()
    assert (project_dir / "project.json").read_bytes() == before, case
    assert [s for s in statuses if "and was not rewritten" in s], statuses


# ---------------------------------------------------------------------------
# TC-B100-71 — LLR-168.4: ``derived_from``
# ---------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("case", ["A", "B"])
def test_tc_b100_71_save_back_records_derived_from(tmp_path: Path, case: str) -> None:
    """``p02`` A (``firmware_1.s19``) and B (``firmware-patched.s19``): the
    saved variant's ``derived_from`` names ``firmware.s19`` with its SHA-256
    and the 4 bytes the patch changed.

    RED (base 80052cb): no ``derived_from`` key."""
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    base = tmp_path / "app"

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_through_handler(pilot, app, src / "firmware.s19")
            await _save_project(pilot, app, "P")
            _apply_patch(app)
            typed = projects.typed_name(case) or f"{app.current_file.variant_id}-patched.s19"
            await _save_back(pilot, app, typed)

    asyncio.run(_drive())
    project_dir = _workarea(base) / "P"
    written = projects.read_manifest(project_dir)
    assert written.get("derived_from") == {
        projects.landed_name(case): {
            "base": "firmware.s19",
            "sha256": _sha256(src / "firmware.s19"),
            "differ": len(PATCH_BYTES),
        }
    }, written


def test_tc_b100_71_emit_records_a_base_outside_the_project(tmp_path: Path) -> None:
    """Save project emits a patched image of a session loaded from outside
    the project: ``derived_from`` records the base's name and digest, and
    no project file has that digest (the base is not in the project).

    RED (base 80052cb): no ``derived_from`` key."""
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    base = tmp_path / "app"

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_through_handler(pilot, app, src / "firmware.s19")
            _apply_patch(app)
            await _save_project(pilot, app, "P")

    asyncio.run(_drive())
    project_dir = _workarea(base) / "P"
    written = projects.read_manifest(project_dir)
    base_digest = _sha256(src / "firmware.s19")
    assert written.get("derived_from") == {
        "firmware.s19": {"base": "firmware.s19", "sha256": base_digest, "differ": len(PATCH_BYTES)}
    }, written
    assert base_digest not in {record["sha256"] for record in written["files"].values()}


def test_tc_b100_71_byte_copy_records_nothing(tmp_path: Path) -> None:
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    base = tmp_path / "app"

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_through_handler(pilot, app, src / "firmware.s19")
            await _save_project(pilot, app, "P")

    asyncio.run(_drive())
    assert "derived_from" not in projects.read_manifest(_workarea(base) / "P")


def test_tc_b100_71_unsafe_base_is_one_issue_and_no_entry(tmp_path: Path) -> None:
    """RED (base 80052cb): ``derived_from`` is ignored, 0 issues."""
    record = {"base": "../x.s19", "sha256": "a" * 64, "differ": 4}
    _write_manifest(
        tmp_path / "P",
        {"schema_version": 1, "active_variant": None, "derived_from": {"x.s19": record}},
    )
    manifest = read_project_manifest(tmp_path / "P")
    assert [issue.code for issue in manifest.issues] == [MANIFEST_PATH_ESCAPE]
    assert getattr(manifest, "derived_from", None) == {}


def test_tc_b100_71_variant_append_carries_derived_from(tmp_path: Path) -> None:
    """A save-back records ``derived_from``; a later variant append keeps
    it (B100-I7: every rewrite carries it)."""
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    other = projects.copy_sources(tmp_path / "other", projects.CASE02_DIR, "firmware.s19")
    base = tmp_path / "app"

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_through_handler(pilot, app, src / "firmware.s19")
            await _save_project(pilot, app, "P")
            _apply_patch(app)
            await _save_back(pilot, app, "firmware-patched.s19")

    asyncio.run(_drive())
    project_dir = _workarea(base) / "P"
    recorded = projects.read_manifest(project_dir).get("derived_from")
    assert recorded and "firmware-patched.s19" in recorded, recorded
    projects.append_variant(base, other / "firmware.s19")
    after = projects.read_manifest(project_dir)
    assert after["active_variant"] == "firmware_1"
    assert after.get("derived_from") == recorded, after


# ---------------------------------------------------------------------------
# AT-B100-06 — HLR-168 black-box
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


async def _add_and_apply_through_the_panel(pilot, app: S19TuiApp) -> None:
    await pilot.press("6")
    await _wait_for(
        pilot,
        lambda: len(app.query("#patch_entry_add_button")) > 0,
        "the Patch Editor panel",
    )
    assert await pilot.click("#patch_entry_address_input")
    await pilot.press("ctrl+a", "delete")
    await pilot.press(*f"0x{PATCH_ADDRESS:08X}")
    assert await pilot.click("#patch_entry_bytes_input")
    await pilot.press("ctrl+a", "delete")
    await pilot.press(*" ".join(f"{b:02X}" for b in PATCH_BYTES))
    assert await pilot.click("#patch_entry_add_button")
    await _wait_for(
        pilot,
        lambda: "Patch Editor: entry added." in _status_text(app),
        "the painted entry-added line",
    )
    assert await pilot.click("#patch_doc_apply_button"), "click missed apply"
    await _wait_for(pilot, lambda: "Apply:" in _status_text(app), "the painted apply line")


async def _save_back_through_the_prompt(pilot, app: S19TuiApp, typed) -> None:
    await _wait_for(
        pilot,
        lambda: not app.query_one("#patch_saveback_row").has_class("hidden"),
        "the save-back prompt",
    )
    # The prompt renders in the editor's JSON pane: pick that tab by its
    # chip, then wait for the prompt to be painted.
    assert await pilot.click("#patch_tab_json"), "click missed #patch_tab_json"
    await _wait_for(
        pilot,
        lambda: app.query_one("#patch_saveback_name_input").region.area > 0,
        "the painted save-back prompt",
    )
    if typed is not None:
        assert await pilot.click("#patch_saveback_name_input")
        await pilot.press("ctrl+shift+a")
        await pilot.press(*typed)
    assert await pilot.click("#patch_saveback_confirm_button"), "click missed confirm"
    await _wait_for(
        pilot,
        lambda: "Saved + verified" in _painted_log(app),
        "the painted save-back outcome",
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
        lambda: _status_text(app).startswith("Saved project to"),
        "the painted Save project success line",
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


@pytest.mark.parametrize("case", ["A", "B"])
@pytest.mark.parametrize("size", SIZES)
def test_at_b100_06_reopen_opens_the_saved_back_variant(
    tmp_path: Path, size: tuple, case: str
) -> None:
    """HLR-168's acceptance scene by keys and clicks: Load file
    ``firmware.s19``, Save project P (``ctrl+s``), add and apply
    ``0x8000007C DE AD BE EF``, save back (``p02`` A typed ``firmware.s19``
    -> ``firmware_1.s19``; ``p02`` B the default ``firmware-patched.s19``),
    then open P in a FRESH app through the Load project dialog (``p``). The
    painted summary line names the saved-back file, the independent reader
    finds the patch in it, and ``project.json`` names it as active.

    RED (executed on 1d677ba, P-3): ``RELOAD -> file=firmware.s19 …
    image_is_patched=False``."""
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    base = tmp_path / "app"
    landed = projects.landed_name(case)

    async def _save_scene() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _load_file_through_dialog(pilot, app, src / "firmware.s19")
            await _save_project_through_dialog(pilot, app, "P")
            await _add_and_apply_through_the_panel(pilot, app)
            await _save_back_through_the_prompt(pilot, app, projects.typed_name(case))

    async def _reopen_scene() -> str:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _open_project_through_dialog(pilot, app, "P")
            await _wait_for(
                pilot,
                lambda: "Loaded project 'P' ->" in _painted_log(app),
                "the painted line naming the reopened project",
            )
            return _painted_log(app)

    asyncio.run(_save_scene())
    painted = asyncio.run(_reopen_scene())
    summary = next(
        line for line in painted.splitlines() if "Loaded project 'P' ->" in line
    )
    assert f"-> {landed}" in summary and summary.endswith("details: p"), painted
    project_dir = _workarea(base) / "P"
    assert _patch_found(project_dir / landed), f"the patch is not in {landed}"
    assert projects.read_manifest(project_dir)["active_variant"] == Path(landed).stem
    # Inc 7 (AT index: ``derived_from`` on disk): the saved-back variant
    # records the image it was derived from.
    derived = projects.read_manifest(project_dir).get("derived_from", {})
    assert derived.get(landed, {}).get("base") == "firmware.s19", derived


# ---------------------------------------------------------------------------
# AT-B100-20 — HLR-168 black-box: every writer carries the keys
# ---------------------------------------------------------------------------


async def _load_through_dialog_until(pilot, app: S19TuiApp, src: Path, until, what: str) -> None:
    await pilot.press("l")
    await _wait_for(
        pilot, lambda: isinstance(app.screen, LoadFileScreen), "the Load file dialog"
    )
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*str(src))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await _wait_for(pilot, lambda: not isinstance(app.screen, LoadFileScreen) and until(), what)


async def _open_and_close_the_panel(pilot, app: S19TuiApp, name: str) -> str:
    await _open_project_through_dialog(pilot, app, name)
    await _wait_for(pilot, lambda: len(app.screen.query("#result_ok")) > 0, "the Load-result panel")
    text = await projects.read_load_result_panel(pilot, app)
    await pilot.press("escape")
    await _wait_for(
        pilot, lambda: len(app.screen.query("#result_ok")) == 0, "the panel closed"
    )
    return text


@pytest.mark.parametrize("size", SIZES)
def test_at_b100_20_every_writer_carries_the_keys_it_does_not_own(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-168's carry scene by keys and clicks: P records ``batch``,
    ``assignments``, ``declared_regions`` and ``gathered``. With P open, the
    engineer loads (1) a new S19, (2) a MAC and (3) an A2L through Load;
    after each, ``project.json`` on disk was rewritten, keeps those keys
    equal (JSON compare) with 0 absolute paths, and after (1) names the new
    variant as active. A fresh app opening P names it in the Load-result
    panel. Inc 7 (AT index: ``derived_from`` carried): P also records a
    ``derived_from`` for ``firmware.s19``; every rewrite keeps it equal.

    RED (A-03 / P-3 shape): at the base no writer rewrites the manifest, so
    after (1) ``project.json`` is unchanged and still names ``firmware``."""
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    seeded = projects.read_manifest(project_dir)
    seeded_derived = {
        "firmware.s19": {"base": "firmware_base.s19", "sha256": "ab" * 32, "differ": 4}
    }
    seeded["derived_from"] = seeded_derived
    (project_dir / "project.json").write_text(json.dumps(seeded), encoding="utf-8")
    s19 = projects.copy_sources(tmp_path / "s19", projects.CASE02_DIR, "firmware.s19")
    side = projects.copy_sources(
        tmp_path / "side", projects.CASE01_DIR, "firmware.mac", "firmware.a2l"
    )
    manifest_path = project_dir / "project.json"
    snapshots: list = []

    def _stamp() -> tuple:
        # The write replaces the file (staged, then moved in): a new file
        # identity or time stamp proves a rewrite even when a step leaves
        # the bytes identical (the MAC and A2L steps change no key).
        stat = manifest_path.stat()
        return (stat.st_ino, stat.st_mtime_ns)

    async def _writers() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            # Open P; the Load-result panel this route opens (asserted on
            # the final reopen below) is closed by its shown key first.
            await _open_project_through_dialog(pilot, app, "P")
            await _wait_for(
                pilot,
                lambda: "Loaded project 'P' ->" in _painted_log(app),
                "the painted line naming P",
            )
            for _ in range(20):
                if len(app.screen.query("#result_ok")) > 0:
                    await pilot.press("escape")
                    break
                await pilot.pause()
            await _wait_for(
                pilot, lambda: len(app.screen.query("#result_ok")) == 0, "no panel open"
            )
            for src, landed in (
                (s19 / "firmware.s19", "firmware_1.s19"),
                (side / "firmware.mac", "firmware.mac"),
                (side / "firmware.a2l", "firmware.a2l"),
            ):
                previous = _stamp()
                await _load_through_dialog_until(
                    pilot,
                    app,
                    src,
                    lambda: (project_dir / landed).is_file() and _stamp() != previous,
                    f"{landed} placed and project.json rewritten",
                )
                snapshots.append(json.loads(manifest_path.read_bytes()))

    async def _reopen() -> str:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            return await _open_and_close_the_panel(pilot, app, "P")

    asyncio.run(_writers())
    assert len(snapshots) == 3
    for step, manifest in enumerate(snapshots, start=1):
        assert projects.not_owned(manifest) == projects.seeded_keys(), (step, manifest)
        assert projects.absolute_strings(manifest) == [], (step, manifest)
        assert manifest["active_variant"] == "firmware_1", (step, manifest)
        assert manifest.get("derived_from") == seeded_derived, (step, manifest)
    panel = asyncio.run(_reopen())
    assert "Opened    firmware_1.s19" in panel, panel



# ---------------------------------------------------------------------------
# TC-B100-20 / AT-B100-20 Inc 8a arm (E4) — LLR-168.3: every in-project
# writer carries ``active_document``
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("writer", ["save-back", "variant-append", "mac-sync", "a2l-sync"])
def test_tc_b100_20_writers_carry_the_active_document(tmp_path: Path, writer: str) -> None:
    """``P`` records ``active_document`` "patches/boost.json"; each of the
    four carry writers rewrites ``project.json`` (bytes changed) and keeps
    the key equal, with 0 absolute paths. On the base the key is unknown,
    so the writer refuses the rewrite (SEC6-2)."""
    base = tmp_path / "app"
    project_dir = projects.seed_document_project(_workarea(base))
    before = (project_dir / "project.json").read_bytes()
    sources = {
        "variant-append": (projects.CASE02_DIR, "firmware.s19"),
        "mac-sync": (projects.CASE01_DIR, "firmware.mac"),
        "a2l-sync": (projects.CASE01_DIR, "firmware.a2l"),
    }

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _open_seeded_project(pilot, app)
            if writer == "save-back":
                _apply_patch(app)
                await _save_back(pilot, app, "firmware.s19")
                return
            folder, name = sources[writer]
            src = projects.copy_sources(tmp_path / "src", folder, name) / name
            if writer == "a2l-sync":
                app.load_a2l_from_path(src)
            else:
                app.load_from_path(src)
            await _wait_for(
                pilot,
                lambda: (project_dir / "project.json").read_bytes() != before,
                f"the {writer} manifest rewrite",
            )

    asyncio.run(_drive())
    after = (project_dir / "project.json").read_bytes()
    assert after != before, "project.json was not rewritten"
    manifest = json.loads(after)
    assert manifest.get("active_document") == "patches/boost.json", manifest
    assert projects.absolute_strings(manifest) == [], manifest


# ---------------------------------------------------------------------------
# AT-B100-20 Inc 8a extension (AT index: ``active_document`` carried) —
# black-box: the four carry writers keep the key and a fresh Load still
# reopens the document
# ---------------------------------------------------------------------------


def _ledger(app: S19TuiApp) -> str:
    """The Patch Editor ledger as painted (its rendered strips)."""
    return "\n".join(projects.painted_lines(app.query_one("#patch_doc_entries_table")))


def _script_border(app: S19TuiApp) -> str:
    """The SCRIPT window's bottom border row as the screen paints it (the
    composited strip; a widget's own ``render_line`` excludes its border):
    it carries ``N entries`` and the unsaved marker (LLR-005.1)."""
    region = app.query_one("#patch_win_script").region
    strips = app.screen._compositor.render_strips()
    return strips[region.y + region.height - 1].text[region.x : region.x + region.width]


@pytest.mark.parametrize("size", SIZES)
def test_at_b100_20_inc8a_every_writer_carries_the_active_document(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-168's carry scene, Inc 8a arm, by keys and clicks: P records
    ``batch``, ``assignments``, ``declared_regions``, ``gathered`` and
    ``active_document`` "patches/boost.json" (one entry at ``0x80000010``).
    With P open through the Load project dialog, the engineer (1) adds and
    applies ``0x8000007C DE AD BE EF`` in the Patch Editor and saves back
    under the default name, then loads through Load (2) a new S19, (3) a
    MAC and (4) an A2L. After each writer ``project.json`` on disk was
    rewritten, keeps ``active_document`` and the four other not-owned keys
    equal (JSON compare) with 0 absolute paths, and the document file's
    bytes are unchanged. A fresh app opening P through the dialog paints
    no problem naming the document in the Load-result panel, and the Patch
    Editor ledger paints the document's entry ``80000010`` with the SCRIPT
    window at ``1 entry`` and no unsaved marker.

    RED (base dc3b314): ``active_document`` is an unknown key there, so
    the in-project writers refuse to rewrite the manifest (SEC6-2) and the
    first writer's rewrite never comes."""
    base = tmp_path / "app"
    project_dir = projects.seed_document_project(_workarea(base), extra=projects.seeded_keys())
    for relative in (projects.SEEDED_PATCH, projects.SEEDED_CHECK):
        target = project_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('{"entries": []}', encoding="utf-8")
    document_bytes = (project_dir / projects.DOCUMENT_TEXT).read_bytes()
    s19 = projects.copy_sources(tmp_path / "s19", projects.CASE02_DIR, "firmware.s19")
    side = projects.copy_sources(
        tmp_path / "side", projects.CASE01_DIR, "firmware.mac", "firmware.a2l"
    )
    manifest_path = project_dir / "project.json"
    dirty_marker = "●"
    snapshots: list = []

    def _stamp() -> tuple:
        stat = manifest_path.stat()
        return (stat.st_ino, stat.st_mtime_ns, manifest_path.read_bytes())

    async def _writers() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _open_project_through_dialog(pilot, app, "P")
            await projects.dismiss_load_result_panel(pilot, app)
            # (1) save-back
            previous = _stamp()
            await _add_and_apply_through_the_panel(pilot, app)
            await _save_back_through_the_prompt(pilot, app, None)
            await _wait_for(
                pilot,
                lambda: (project_dir / "firmware-patched.s19").is_file()
                and _stamp() != previous,
                "firmware-patched.s19 placed and project.json rewritten by the save-back",
            )
            snapshots.append(("save-back", json.loads(manifest_path.read_bytes())))
            # (2) variant append, (3) MAC sync, (4) A2L sync, through Load
            for writer, src, landed in (
                ("variant-append", s19 / "firmware.s19", "firmware_1.s19"),
                ("mac-sync", side / "firmware.mac", "firmware.mac"),
                ("a2l-sync", side / "firmware.a2l", "firmware.a2l"),
            ):
                previous = _stamp()
                await _load_through_dialog_until(
                    pilot,
                    app,
                    src,
                    lambda: (project_dir / landed).is_file() and _stamp() != previous,
                    f"{landed} placed and project.json rewritten by the {writer}",
                )
                snapshots.append((writer, json.loads(manifest_path.read_bytes())))

    async def _reopen() -> tuple:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            panel = await _open_and_close_the_panel(pilot, app, "P")
            await pilot.press("6")
            await _wait_for(
                pilot,
                lambda: len(app.query("#patch_doc_entries_table")) > 0
                and f"{projects.DOCUMENT_ADDRESS:08X}" in _ledger(app).upper(),
                "the reopened document's entry painted in the ledger",
            )
            return panel, _ledger(app), _script_border(app)

    asyncio.run(_writers())
    assert [writer for writer, _ in snapshots] == [
        "save-back", "variant-append", "mac-sync", "a2l-sync"
    ]
    for writer, manifest in snapshots:
        assert manifest.get("active_document") == projects.DOCUMENT_TEXT, (writer, manifest)
        assert projects.not_owned(manifest) == projects.seeded_keys(), (writer, manifest)
        assert projects.absolute_strings(manifest) == [], (writer, manifest)
    assert snapshots[0][1]["active_variant"] == "firmware-patched", snapshots[0]
    assert [m["active_variant"] for _, m in snapshots[1:]] == ["firmware_1"] * 3, snapshots
    # No writer rewrote the document file itself.
    assert (project_dir / projects.DOCUMENT_TEXT).read_bytes() == document_bytes

    panel, ledger, border = asyncio.run(_reopen())
    flat = projects.flat(panel)
    assert "Opened    firmware_1.s19" in panel, panel
    assert "boost.json" not in flat, panel  # no problem row names the document
    assert f"{projects.DOCUMENT_ADDRESS:08X}" in ledger.upper(), ledger
    assert "1 entry" in border and "1 entry" == border.split("─")[-2].strip(), border
    assert dirty_marker not in border, border
