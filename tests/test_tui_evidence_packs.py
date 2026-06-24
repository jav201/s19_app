"""Black-box e2e acceptance for the demo-evidence packs (gap #4, batch-01).

Audit-gaps follow-up (gap #4, batch-01 demo evidence / LLR-004.1). Spec
``.fast-dev-flow/spec.md`` §3 AC-B1/AC-B2.

These are the Pilot e2e tests the 2026-06-23 audit found missing: the
batch-01 demo evidence claims — "saving a project creates a project folder
under ``.s19tool/workarea/<project>/`` with the saved primary" and "dumping
A2L JSON writes an ``<name>.a2l.json`` file" — were asserted *manually*
(REQUIREMENTS rows R-TUI-012 / R-PROJ-001 / R-A2L-003 marked ``Manual`` /
``Partial``). This module drives each real action/binding through the shipped
surface and observes the deliverable ON DISK, so the manual-evidence gap is
closed by an automated black-box AT.

- AC-B1 (``test_save_project_creates_project_folder_on_disk``): saving a
  project through the real ``_handle_save_dialog`` handler (the seam
  ``action_save_project`` invokes after the Save modal returns a
  ``SaveProjectPayload``) creates ``.s19tool/workarea/<sanitized-name>/`` on
  disk containing the saved primary file and a ``project.json`` manifest.
- AC-B2 (``test_dump_a2l_json_writes_file_on_disk``): pressing ``j`` (the
  ``dump_a2l_json`` binding → ``action_dump_a2l_json``) after loading a real
  A2L writes ``<name>.a2l.json`` into the work-area temp dir; the file exists,
  is non-empty, and re-parses as JSON.

Outcome: both surfaces ship today and pass green, so these tests LOCK each
deliverable as a regression observed through the shipped surface (no
production change was required). If either surface were broken, the failing
leg would show red before any fix.

Harness: the ``asyncio.run`` + ``App.run_test()`` Pilot pattern of
``tests/test_tui_manifest_save.py``, driving the real save handler with a
``SaveProjectPayload`` and the real ``j`` binding for the A2L dump. Fixture
data is synthetic / public-only and lives under ``tmp_path`` (F-S-07): the
test never writes into the repo.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Tuple

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services.variant_execution_service import PROJECT_MANIFEST_NAME
from s19_app.tui.workspace import WORKAREA_TEMP

# Minimal valid S19 image (checksum verified against s19_app.core.S19File) —
# the same fixture used by tests/test_tui_manifest_save.py.
S19_A = "S107100001020304DE\nS9030000FC\n"

# Minimal valid A2L with one MEASUREMENT + one CHARACTERISTIC — mirrors the
# parser fixture of tests/test_tui_a2l.py so the dump has real tags to emit.
A2L_SRC = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin MEASUREMENT RPM\n"
    "      ECU_ADDRESS 0x1000\n"
    "      DATA_SIZE 2\n"
    "      LOWER_LIMIT 0\n"
    "      UPPER_LIMIT 7000\n"
    "    /end MEASUREMENT\n"
    "    /begin CHARACTERISTIC TORQUE\n"
    "      ECU_ADDRESS 0x2000\n"
    "      LENGTH 4\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so the deferred apply chain runs."""
    for _ in range(count):
        await pilot.pause()


# ---------------------------------------------------------------------------
# AC-B1 — saving a project creates the project folder + primary on disk
# ---------------------------------------------------------------------------


def test_save_project_creates_project_folder_on_disk(tmp_path: Path) -> None:
    """Saving a project writes the project folder + primary file on disk.

    Intent (AC-B1): driving the real save through ``_handle_save_dialog`` (the
    handler ``action_save_project`` invokes after the Save modal) on a loaded
    S19 must create ``.s19tool/workarea/<sanitized-name>/`` on disk, copy the
    loaded primary into it, and write a ``project.json`` manifest. We read the
    directory off disk to prove the demo-evidence claim instead of assuming it.
    This is a locked regression: the save surface ships today and was green.
    """
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> Tuple[Path, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            payload = app_module.SaveProjectPayload(
                parent_folder=str(app.workarea), project_name="Demo Pack!"
            )
            app._handle_save_dialog(payload)
            await _flush(pilot)
            # The active project dir is resolved by the handler from the
            # sanitized name — read it back rather than re-deriving the name.
            assert app.current_project_dir is not None
            return app.current_project_dir, external.name

    project_dir, primary_name = asyncio.run(_drive())

    assert project_dir.is_dir(), (
        "AC-B1: the save must create the project folder on disk — "
        f"none at {project_dir}"
    )
    assert project_dir.parent.name == "workarea", (
        "AC-B1: the project folder must live under .s19tool/workarea/, "
        f"got parent {project_dir.parent}"
    )
    primary = project_dir / primary_name
    assert primary.is_file(), (
        "AC-B1: the saved primary must land in the project folder — "
        f"missing {primary}"
    )
    assert primary.read_text(encoding="utf-8") == S19_A, (
        "AC-B1: the saved primary must be a real copy of the loaded image"
    )
    manifest = project_dir / PROJECT_MANIFEST_NAME
    assert manifest.is_file() and manifest.stat().st_size > 0, (
        "AC-B1: the save must also write a non-empty project.json manifest"
    )


# ---------------------------------------------------------------------------
# AC-B2 — dumping A2L JSON writes a non-empty <name>.a2l.json on disk
# ---------------------------------------------------------------------------


def test_dump_a2l_json_writes_file_on_disk(tmp_path: Path) -> None:
    """Pressing ``j`` after loading an A2L writes a real JSON file on disk.

    Intent (AC-B2): with an A2L loaded, the ``j`` binding
    (``action_dump_a2l_json``) must write ``<name>.a2l.json`` into the
    work-area temp dir; the file must exist, be non-empty, and re-parse as
    JSON carrying the parsed A2L payload. The deliverable is observed on disk
    through the shipped key binding, not assumed. Locked regression: the dump
    surface ships today and was green.
    """
    a2l_src = tmp_path / "engine.a2l"
    a2l_src.write_text(A2L_SRC, encoding="utf-8")

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_a2l_from_path(a2l_src)
            await _flush(pilot)
            assert app.current_a2l_data, (
                "precondition: loading the A2L must populate current_a2l_data"
            )
            # Drive the real key binding rather than calling the action.
            await pilot.press("j")
            await _flush(pilot)
            return app.workarea / WORKAREA_TEMP

    temp_dir = asyncio.run(_drive())

    dumps = list(temp_dir.glob("*.a2l.json"))
    assert dumps, (
        "AC-B2: pressing j must write an <name>.a2l.json into the temp dir — "
        f"found none in {temp_dir}"
    )
    dump = dumps[0]
    assert dump.name == "engine.a2l.json", (
        "AC-B2: the dump must be named from the loaded A2L stem, got "
        f"{dump.name!r}"
    )
    assert dump.stat().st_size > 0, "AC-B2: the dumped A2L JSON must be non-empty"
    payload = json.loads(dump.read_text(encoding="utf-8"))
    assert payload.get("tags"), (
        "AC-B2: the dumped JSON must carry the parsed A2L payload (tags)"
    )
