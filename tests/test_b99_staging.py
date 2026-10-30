"""
Batch-99 Increment 3a — private staging, atomic placement (HLR-155;
LLR-155.1/.2/.3/.4/.7; TC-B99-11/12/13/14/39; AT-B99-05; AT-B99-04, both
arms in one joined node; UX-C4/UX-C5/UX-C10 sinks).

Batch-99 Increment 3b — HLR-155 D7 + D9 (LLR-155.5/.6 and LLR-155.3's
LED-.7 gather conversion; TC-B99-15/16, TC-B99-13's census + gather-drift
arms; UX-C4/UX-C2/UX-C10 for the D7/D9
sinks).

Layer A (engine, direct calls):
- **TC-B99-11** (LLR-155.1) — a same-name save-back keeps the loaded work
  copy: byte-equal to its pre-save bytes, the placed name is the requested
  one, and no staging directory survives (success and forced failure).
  Forced-failure arm (review finding F3): a junction/symlink at ``temp``
  (the staging seam) is refused and nothing is written through it.
  Review round 2 (security finding S-F3): a DANGLING junction at ``temp``
  is caught by the ``lstat`` check itself — the refusal names the reparse
  point, not a generic mkdir failure.
- Review round 2, security finding S-F1: a DANGLING symlink at the
  requested final name counts as taken — on Windows ``O_EXCL`` follows it
  and would create the claim outside the work area (TC-B99-12 arm).
- Review round 2, security finding S-F4: B8 byte-identical reuse never
  returns a name that is a link or reparse point (TC-B99-13 arm).
- Review round 2, security finding S-F6: an ``OSError`` from the staging
  copy (e.g. a source that vanishes mid-copy) is wrapped in
  ``WorkareaPlacementError``, outcome first, naming the source
  (TC-B99-12 arm).
- Review round 2, code finding LOW-1: TC-B99-13 gained the same
  deterministic pause-on-shared-name hook as TC-B99-12, so the restored
  check-then-copy mutant shows a NONZERO mismatch count.
- Review round 2, code findings F6a/S-F5: a placement failure during Save
  project removes exactly the folder THIS call created; a pre-existing
  folder of the same name survives untouched (TC-B99-14 arms).
- **TC-B99-12** (LLR-155.2) — 8 threads x 20 trials requesting ONE name with
  distinct markers; every reported path re-read with the independent reader.
  A deterministic interleaving hook (PQ-8: a monkeypatched pause inside the
  copy when the destination is the shared name) guarantees the RED shows a
  NONZERO mismatch count on the pre-fix tree. Arms: the race; a forced
  ``PermissionError`` (``WorkareaPlacementError``, 0 zero-byte files, 0
  leftover staging dirs); the source bytes + mtime arm; a DIRECTORY
  squatting the requested name (taken → next ``_<N>``, review finding F1);
  a forced non-``PermissionError`` ``OSError`` in the replace (wrapped in
  ``WorkareaPlacementError``, review finding F1).
- **TC-B99-13** (LLR-155.3, amended by LED .7) — concurrent threads run
  ``copy_into_workarea`` on ONE name, with identical and with differing
  bytes, over 20 trials: every caller's returned path holds its own bytes
  and a 0-byte target is never reused (C1(a)).
- **TC-B99-44** (LLR-155.1, PDR C2; review finding F4) — the converted
  ``write_change_document`` path stages in a private ``mkdtemp`` directory
  under the reparse-checked ``temp/.staging`` home (never directly under
  ``temp/``) and places correctly; a junction at ``temp`` is refused.
- **TC-B99-39** (LLR-155.7) — AST census of the delete calls in the six
  placement writers (``save_patched_image``, ``write_change_document``,
  ``copy_into_workarea``, ``place_group_into_workarea`` (B99-I2a, added by
  batch-99 Inc 6, PQ-3), the flow
  WRITE-OUT arm in ``run_flow``, the CRC write in ``write_crc_image``):
  every ``unlink`` / ``rmtree`` / ``os.remove`` deletes a name bound in the
  same function to a ``tempfile.mkdtemp`` result (or to
  ``workspace._private_stage_dir``, the one helper that owns the mkdtemp)
  or to the path passed as the
  first argument of an ``os.open(..., O_EXCL)`` claim, inside a branch
  guarded by a boolean assigned immediately after that creation. Zero known
  exceptions: the CRC write site converted to private staging in batch-99
  Inc-5 (LLR-155.8) — the census passes with zero exceptions.

Layer B (black-box, Textual pilot over the shipped chain; review finding
F5 — every drive is keys and clicks: rail keys, clicked inputs and buttons,
typed text; every wait observes the PAINTED status line (``#log_line_4``)
or the painted screen, never an internal attribute and never a patched
method):
- **TC-B99-14** (LLR-155.4) — Save project with a missing source: a
  failure-severity status that leads with the outcome and names the file,
  no empty project folder, app still running.
- **AT-B99-05** — load ``firmware.s19``, Patch Editor add + apply, save back
  as ``firmware.s19``, then Save project through the real
  ``SaveProjectScreen``: the work copy survives, the app is running, the
  project folder holds the image and the status names it (P-15 flips).
- **AT-B99-04** — ONE black-box session drives both HLR-155 arms: 8
  distinct-name lanes run in parallel through Flow Execution (the
  ``parallel`` word of ``#fx_mode`` clicked, Run clicked on ``#fx_run``)
  write 8 files, each its lane's marker (the chain-set report reads
  ``Mode: parallel``); two lanes resolving to one WRITE-OUT name
  (``same.s19`` / ``SAME.s19``, case-folded) refuse the whole set — the
  painted log and the status line name both lanes and nothing new is
  written.
- **UX-C10** — one hostile-name TC per new file-derived sink: the Save
  project file name and the placement-error path; the hostile literal
  renders with 0 markup spans.

Oracles: every image byte comparison re-reads the file with
``tests/support/independent_reader.py``; fixtures are built with the engine
emitters (fixture construction is not an oracle).
"""
from __future__ import annotations

import ast
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import pytest

from s19_app.tui import workspace
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes import emit_s19_from_mem_map
from s19_app.tui.changes.apply import save_patched_image
from s19_app.tui.changes.io import (
    FORMAT_ID,
    FORMAT_VERSION,
    MF_WRITE_CONTAINMENT,
    write_change_document,
)
from s19_app.tui.changes.model import ChangeDocument, ChangeEntry
from s19_app.tui.services import flow_execution_service as fx_service
from s19_app.tui.services.flow_execution_service import (
    ChainSpec,
    run_chain_set,
    run_flow,
)
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_OK,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_OK,
    Flow,
    FlowContext,
    FlowRunResult,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.project_gather_service import gather_project_artifacts
from s19_app.tui.workspace import WorkareaContainmentError, copy_into_workarea

from tests.support import independent_reader
from tests.support.b100_projects import dismiss_load_result_panel

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Pre-Inc-3a trees lack the subclass; the UX/forced-failure arms assert its
#: presence so their RED is explicit instead of an AttributeError.
PlacementError = getattr(workspace, "WorkareaPlacementError", None)

#: A Windows-legal hostile payload (a ``/`` can never appear in a file name
#: on this platform, so the markup-close tag is exercised through the
#: Rich-active open tag + click directive only).
HOSTILE_NAME = "[red]x[@click=app.quit]"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _workarea(tmp_path: Path) -> Path:
    """A bare ``.s19tool/workarea`` with its ``temp/`` directory."""
    root = tmp_path / ".s19tool" / "workarea"
    (root / "temp").mkdir(parents=True, exist_ok=True)
    return root


def _emit(marker: int, addr: int = 0x1000) -> str:
    """A one-byte S19 image whose only data byte is ``marker``."""
    return emit_s19_from_mem_map({addr: marker}, [(addr, addr + 1)])


def _emit_two(first: int, second: int) -> str:
    """A two-byte S19 image at 0x1000 and 0x2000 (the patch target inside
    the loaded image, so a Patch Editor entry at 0x2000 applies)."""
    return emit_s19_from_mem_map(
        {0x1000: first, 0x2000: second}, [(0x1000, 0x1001), (0x2000, 0x2001)]
    )


def _image(tmp_path: Path, name: str, marker: int, addr: int = 0x1000) -> Path:
    path = tmp_path / name
    path.write_text(_emit(marker, addr), encoding="ascii")
    return path


def _staging_leftovers(root: Path) -> list:
    staging = root / "temp" / ".staging"
    return sorted(staging.iterdir()) if staging.is_dir() else []


def _data(path: Path) -> dict:
    """The address -> byte map of a written image, via the independent reader."""
    image = independent_reader.read_s19(path)
    assert image.errors == [], f"independent reader errors for {path}: {image.errors}"
    return image.data


def _painted_status(app) -> str:
    """The painted newest status line (the ``#log_line_4`` label) — a
    black-box read of what the operator sees."""
    from textual.widgets import Label

    return str(app.query_one("#log_line_4", Label).render())


def _painted_text(app) -> str:
    """The painted screen as text: the SVG export's ``<text>`` elements
    joined (the snapshot idiom). Entities stay escaped (spaces export as
    ``&#160;``), so match single space-free words."""
    svg = app.export_screenshot()
    return "".join(re.findall(r"<text[^>]*>(.*?)</text>", svg, re.S))


def _plant_temp_junction(root: Path, tmp_path: Path) -> Path:
    """Replace ``<root>/temp`` with a junction (Windows) or directory symlink
    (POSIX) pointing OUTSIDE the work area. Returns the outside directory.
    Skips with the stated reason when the platform forbids link creation."""
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    temp = root / "temp"
    if temp.is_symlink() or temp.is_file():
        temp.unlink()
    elif temp.is_dir():
        shutil.rmtree(temp)
    if sys.platform == "win32":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(temp), str(outside)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip(
                "junction creation not permitted: "
                f"{result.stdout.strip()} {result.stderr.strip()}"
            )
    else:
        try:
            os.symlink(outside, temp, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"symlink creation not permitted: {exc}")
    return outside


# ---------------------------------------------------------------------------
# TC-B99-11 — same-name save-back keeps the work copy (LLR-155.1)
# ---------------------------------------------------------------------------


def test_tc_b99_11_same_name_save_back_keeps_work_copy(tmp_path: Path) -> None:
    """A save-back under the loaded image's own name keeps the work copy.

    RED at HEAD (P-15): ``save_patched_image`` stages at ``temp/<user name>``
    — the loaded work copy — and its ``finally`` unlinks it.
    """
    root = _workarea(tmp_path)
    project_dir = root / "proj"
    project_dir.mkdir()
    work_copy = root / "temp" / "firmware.s19"
    work_copy.write_text(_emit(0x11), encoding="ascii")
    pre_save_bytes = work_copy.read_bytes()

    mem_map = {0x1000: 0x11, 0x2000: 0x99}
    ranges = [(0x1000, 0x1001), (0x2000, 0x2001)]
    target, issues = save_patched_image(
        mem_map, ranges, project_dir, "firmware.s19", source_kind="s19"
    )

    assert target is not None, f"save-back refused: {[i.message for i in issues]}"
    assert target.name == "firmware.s19", target
    assert work_copy.exists(), (
        "the loaded work copy temp/firmware.s19 must survive the save-back"
    )
    assert work_copy.read_bytes() == pre_save_bytes, (
        "the work copy must stay byte-equal to its pre-save content"
    )
    assert _data(target) == {0x1000: 0x11, 0x2000: 0x99}, (
        "the placed file must hold this write's bytes"
    )
    assert _staging_leftovers(root) == [], _staging_leftovers(root)


def test_tc_b99_11_junction_at_staging_temp_is_refused(tmp_path: Path) -> None:
    """A junction/symlink at ``temp`` (the staging seam) is refused
    (LLR-155.1, review finding F3): ``save_patched_image`` reports one
    ``MF-WRITE-CONTAINMENT`` issue and nothing is written anywhere — in
    particular nothing THROUGH the junction, outside the work area. On
    Windows the junction is created with ``mklink /J``; when that is not
    permitted the arm skips with the stated reason.

    RED at the review-round tree: staging ran directly under ``temp/`` with
    no reparse check, so the write rode the junction and landed outside the
    work area.
    """
    root = _workarea(tmp_path)
    outside = _plant_temp_junction(root, tmp_path)
    project_dir = root / "proj"
    project_dir.mkdir()

    mem_map = {0x1000: 0x11, 0x2000: 0x99}
    ranges = [(0x1000, 0x1001), (0x2000, 0x2001)]
    target, issues = save_patched_image(
        mem_map, ranges, project_dir, "firmware.s19", source_kind="s19"
    )

    assert target is None, f"the junction must refuse the write: {target}"
    assert [i.code for i in issues] == [MF_WRITE_CONTAINMENT], (
        [i.message for i in issues]
    )
    assert [p for p in project_dir.iterdir()] == [], list(project_dir.iterdir())
    assert [p for p in outside.iterdir()] == [], (
        f"nothing may be written through the junction: {list(outside.iterdir())}"
    )


def test_tc_b99_11_dangling_junction_at_staging_temp_is_refused(
    tmp_path: Path,
) -> None:
    """A DANGLING junction at ``temp`` — target deleted after the junction
    was made — is caught by the staging check ITSELF (LLR-155.1; security
    findings S-F2/S-F3): ``Path.exists()`` follows the link and reports
    False, so an ``exists()``-based guard never evaluates the reparse
    check; only an ``os.lstat``-based one does. The refusal must name the
    reparse point (not a generic "cannot be prepared" mkdir failure), and
    nothing may be created anywhere — in particular not through the
    junction. Skips with the stated reason when link creation is not
    permitted.

    RED at the review-round-2 tree: the ``exists()`` guard skipped the
    reparse check and the refusal came from the ``mkdir`` fallback with a
    generic message.
    """
    root = _workarea(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    temp = root / "temp"
    if temp.is_symlink() or temp.is_file():
        temp.unlink()
    elif temp.is_dir():
        shutil.rmtree(temp)
    if sys.platform == "win32":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(temp), str(outside)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip(
                "junction creation not permitted: "
                f"{result.stdout.strip()} {result.stderr.strip()}"
            )
    else:
        try:
            os.symlink(outside, temp, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"symlink creation not permitted: {exc}")
    shutil.rmtree(outside)  # the junction now dangles
    assert not temp.exists(), "the junction must dangle for this arm"
    dest = root / "out"
    dest.mkdir()
    src = _image(tmp_path, "fw.s19", 0x77)

    with pytest.raises(WorkareaContainmentError) as excinfo:
        copy_into_workarea(src, dest)

    assert "symbolic link or reparse point" in str(excinfo.value), (
        f"the refusal must come from the reparse check itself: {excinfo.value}"
    )
    assert [p for p in dest.iterdir()] == [], list(dest.iterdir())
    assert not (tmp_path / "outside").exists(), (
        "nothing may be created through the dangling junction"
    )
    assert _staging_leftovers(root) == [], _staging_leftovers(root)


# ---------------------------------------------------------------------------
# TC-B99-12 — exclusive, atomic placement (LLR-155.2)
# ---------------------------------------------------------------------------

_WRITERS = 8
_TRIALS = 20
_SHARED_NAME = "same.s19"


def _pause_on_shared_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic interleaving hook (PQ-8): pause inside the copy when the
    destination is the shared name, so every thread's existence check races
    the other writers' copies instead of relying on scheduler luck."""

    real_copy2 = shutil.copy2

    def _pausing(src, dst, *args, **kwargs):
        if Path(str(dst)).name == _SHARED_NAME:
            time.sleep(0.05)
        return real_copy2(src, dst, *args, **kwargs)

    monkeypatch.setattr(shutil, "copy2", _pausing)


def test_tc_b99_12_eight_writers_one_name_zero_mismatches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """8 threads x 20 trials request ONE name with distinct markers.

    RED at HEAD: placement is check-then-copy into a shared target, so the
    forced interleaving clobbers bytes; the assertion message prints the
    decisive ``parallel mismatches: N`` line (PQ-8 requires N > 0).
    """
    root = _workarea(tmp_path)
    sources_root = tmp_path / "sources"
    _pause_on_shared_name(monkeypatch)

    mismatches = 0
    reported_total = 0
    for trial in range(_TRIALS):
        dest = root / "out" / f"trial{trial:02d}"
        dest.mkdir(parents=True)
        trial_sources = sources_root / f"trial{trial:02d}"
        trial_sources.mkdir(parents=True)

        def place(writer: int) -> tuple[int, Path]:
            src_dir = trial_sources / f"w{writer}"
            src_dir.mkdir(exist_ok=True)
            src = src_dir / _SHARED_NAME
            src.write_text(_emit(0x41 + writer), encoding="ascii")
            return writer, copy_into_workarea(src, dest)

        with ThreadPoolExecutor(max_workers=_WRITERS, thread_name_prefix="b99-tc12") as pool:
            results = list(pool.map(place, range(_WRITERS)))
        reported_total += len(results)
        for writer, reported in results:
            if _data(reported) != {0x1000: 0x41 + writer}:
                mismatches += 1

    assert reported_total == _WRITERS * _TRIALS
    assert mismatches == 0, f"parallel mismatches: {mismatches}"


def test_tc_b99_12_forced_permission_error_refuses_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A locked target -> ``WorkareaPlacementError`` naming the file, the
    cause and the next step; 0 zero-byte files; 0 leftover staging dirs.

    RED at HEAD: no ``WorkareaPlacementError`` exists and no retry/claim
    machinery runs (``os.replace`` is never called).
    """
    assert PlacementError is not None, (
        "WorkareaPlacementError must exist (WorkareaContainmentError subclass)"
    )
    assert issubclass(PlacementError, WorkareaContainmentError)
    root = _workarea(tmp_path)
    dest = root / "out"
    dest.mkdir()
    src = _image(tmp_path, "locked.s19", 0x77)

    def _always_locked(src_path, dst_path):
        raise PermissionError(13, "locked by another program", str(dst_path))

    monkeypatch.setattr(os, "replace", _always_locked)
    with pytest.raises(PlacementError) as excinfo:
        copy_into_workarea(src, dest)

    message = str(excinfo.value)
    assert message.index("Not saved") < 50, message
    assert "locked.s19" in message
    assert "close it and retry" in message.lower()
    assert "Nothing written" in message
    assert "containment" not in message.lower()
    assert "outside the work area" not in message.lower()
    assert [p for p in dest.iterdir()] == [], list(dest.iterdir())
    assert [p for p in dest.iterdir() if p.stat().st_size == 0] == []
    assert _staging_leftovers(root) == [], _staging_leftovers(root)


def test_tc_b99_12_directory_squatting_requested_name_takes_next_free(
    tmp_path: Path,
) -> None:
    """A DIRECTORY squatting the requested name counts as taken (review
    finding F1): on Windows ``os.open(O_CREAT|O_EXCL)`` against an existing
    directory raises ``PermissionError``, not ``FileExistsError`` — the
    writer must move on to the next ``_<N>`` and never touch the squatter.

    RED at the review-round tree: the raw ``PermissionError`` escapes; no
    ``_<N>`` fallback exists.
    """
    root = _workarea(tmp_path)
    dest = root / "out"
    dest.mkdir()
    squat = dest / "fw.s19"
    squat.mkdir()
    src = _image(tmp_path, "fw.s19", 0x77)

    placed = copy_into_workarea(src, dest)

    assert placed.name == "fw_1.s19", placed
    assert placed.read_bytes() == src.read_bytes()
    assert squat.is_dir() and not squat.is_symlink()
    assert list(squat.iterdir()) == [], "the squatter must be untouched"
    assert _staging_leftovers(root) == [], _staging_leftovers(root)


def test_tc_b99_12_forced_oserror_in_replace_raises_placement_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A forced ``OSError`` (NOT ``PermissionError``) in the replace is
    wrapped in ``WorkareaPlacementError`` (review finding F1): callers that
    catch only ``WorkareaContainmentError`` must never see a raw
    ``OSError``; the own claim is removed, so no 0-byte leftover survives.

    RED at the review-round tree: the raw ``OSError`` propagates uncaught.
    """
    assert PlacementError is not None
    root = _workarea(tmp_path)
    dest = root / "out"
    dest.mkdir()
    src = _image(tmp_path, "fw.s19", 0x77)

    def _cross_device(src_path, dst_path):
        raise OSError(18, "cross-device link", str(dst_path))

    monkeypatch.setattr(os, "replace", _cross_device)
    with pytest.raises(PlacementError) as excinfo:
        copy_into_workarea(src, dest)

    message = str(excinfo.value)
    assert message.index("Not saved") < 50, message
    assert "fw.s19" in message
    assert "Nothing written" in message
    assert [p for p in dest.iterdir()] == [], list(dest.iterdir())
    assert _staging_leftovers(root) == [], _staging_leftovers(root)


def test_tc_b99_12_dangling_symlink_at_requested_name_takes_next_free(
    tmp_path: Path,
) -> None:
    """A DANGLING symlink at the requested final name counts as taken
    (security finding S-F1): on Windows ``os.open(O_CREAT|O_EXCL)``
    FOLLOWS a dangling symlink — the claim would create a 0-byte file at
    the link's target OUTSIDE the work area and ``os.replace`` would then
    replace the link. The placement must lstat the candidate first, land
    on the next ``_<N>``, and leave the link and its (nonexistent) target
    untouched. Skips with the stated reason when symlink creation is not
    permitted.

    RED at the review-round-2 tree: verified empirically on this host —
    the bare O_EXCL claim followed the link and created the 0-byte file
    at its target.
    """
    root = _workarea(tmp_path)
    dest = root / "out"
    dest.mkdir()
    target = tmp_path / "outside" / "fw.s19"  # parent exists, file never created
    target.parent.mkdir(exist_ok=True)
    link = dest / "fw.s19"
    try:
        os.symlink(target, link)
    except OSError as exc:
        pytest.skip(f"symlink creation not permitted: {exc}")
    assert not target.exists(), "the link must start dangling"

    src = _image(tmp_path, "fw.s19", 0x77)
    placed = copy_into_workarea(src, dest)

    assert placed.name == "fw_1.s19", placed
    assert placed.read_bytes() == src.read_bytes()
    assert placed.is_file() and not placed.is_symlink()
    assert link.is_symlink(), "the dangling link must be untouched"
    assert not target.exists(), (
        "nothing may be created at the dangling link's target (S-F1)"
    )
    assert _staging_leftovers(root) == [], _staging_leftovers(root)


def test_tc_b99_12_source_vanishes_mid_copy_is_wrapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ``OSError`` from the staging copy — e.g. the source vanishing
    after the size check — is wrapped in ``WorkareaPlacementError``
    (security finding S-F6): outcome first, naming the source, never a
    raw ``OSError`` past callers that catch only the containment class; no
    claim and no staging dir survives.

    RED at the review-round-2 tree: the raw ``FileNotFoundError`` escapes
    ``copy_into_workarea`` uncaught.
    """
    assert PlacementError is not None
    root = _workarea(tmp_path)
    dest = root / "out"
    dest.mkdir()
    src = _image(tmp_path, "fw.s19", 0x77)

    def _vanish(source, target, *args, **kwargs):
        raise FileNotFoundError(2, "source vanished mid-copy", str(source))

    monkeypatch.setattr(shutil, "copy2", _vanish)
    with pytest.raises(PlacementError) as excinfo:
        copy_into_workarea(src, dest)

    message = str(excinfo.value)
    assert message.index("Not saved") < 50, message
    assert "fw.s19" in message, message
    assert "Nothing written" in message
    assert [p for p in dest.iterdir()] == [], list(dest.iterdir())
    assert _staging_leftovers(root) == [], _staging_leftovers(root)


def test_tc_b99_12_source_bytes_and_mtime_unchanged(tmp_path: Path) -> None:
    """Every placement leaves the source's bytes and mtime untouched."""
    root = _workarea(tmp_path)
    dest = root / "out"
    dest.mkdir()
    src = _image(tmp_path, "source.s19", 0x55)
    pre_stat = src.stat()
    placed = copy_into_workarea(src, dest)
    assert placed.read_bytes() == src.read_bytes()
    post_stat = src.stat()
    assert post_stat.st_mtime_ns == pre_stat.st_mtime_ns
    assert post_stat.st_size == pre_stat.st_size


# ---------------------------------------------------------------------------
# TC-B99-13 — byte-identical reuse stays race-free (LLR-155.3)
# ---------------------------------------------------------------------------


_WRITERS_13 = 4

#: The name every TC-B99-13 writer places (the hook pauses on it).
_SHARED_NAME_13 = "shared.s19"


def _pause_on_shared_name_13(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic interleaving hook (review finding LOW-1): pause inside
    the copy when the destination is the shared name, so the restored
    check-then-copy mutant shows a NONZERO mismatch count instead of
    relying on scheduler luck (the hook fires on both the staged copy and
    the mutant's direct-to-final copy, keyed on the file name only)."""

    real_copy2 = shutil.copy2

    def _pausing(src, dst, *args, **kwargs):
        if Path(str(dst)).name == _SHARED_NAME_13:
            time.sleep(0.05)
        return real_copy2(src, dst, *args, **kwargs)

    monkeypatch.setattr(shutil, "copy2", _pausing)


def test_tc_b99_13_concurrent_placements_one_name_own_bytes_returned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent in-app placements of ONE name (LLR-155.3, amended by
    LED .7): threads running ``copy_into_workarea`` with identical and with
    differing bytes, over 20 trials — every caller's returned path holds its
    own bytes, and a returned 0-byte target never appears. A deterministic
    pause hook (LOW-1) forces the interleaving so the RED mutant evidence
    carries a real, NONZERO mismatch count.

    RED at HEAD (check-then-copy mutation form, and at base ``a52e2be``):
    placement is an unconditional take of the requested name, so the
    differing-bytes arm clobbers concurrent writers and the assertion prints
    the decisive ``parallel mismatches: N`` line.
    """
    root = _workarea(tmp_path)
    _pause_on_shared_name_13(monkeypatch)
    mismatches = 0
    zero_byte_returned = 0
    reported_total = 0
    for trial in range(_TRIALS):
        for identical in (True, False):
            dest = root / "out" / f"trial{trial:02d}" / ("same" if identical else "diff")
            dest.mkdir(parents=True)

            def marker_for(writer: int) -> int:
                return 0x11 if identical else 0x41 + writer

            def place(writer: int) -> tuple[int, Path]:
                # every writer places the SAME name from its own source
                # directory, so the contention is real
                src_dir = tmp_path / f"t13-{trial:02d}-{identical}-{writer}"
                src_dir.mkdir(exist_ok=True)
                src = src_dir / "shared.s19"
                src.write_text(_emit(marker_for(writer)), encoding="ascii")
                return writer, copy_into_workarea(src, dest)

            with ThreadPoolExecutor(
                max_workers=_WRITERS_13, thread_name_prefix="b99-tc13"
            ) as pool:
                results = list(pool.map(place, range(_WRITERS_13)))
            reported_total += len(results)
            for writer, reported in results:
                if _data(reported) != {0x1000: marker_for(writer)}:
                    mismatches += 1
                if reported.stat().st_size == 0:
                    zero_byte_returned += 1

    assert reported_total == _WRITERS_13 * _TRIALS * 2
    assert mismatches == 0, f"parallel mismatches: {mismatches}"
    assert zero_byte_returned == 0, (
        "a returned 0-byte path is another writer's claim placeholder"
    )


def test_tc_b99_13_zero_byte_target_is_never_reused(tmp_path: Path) -> None:
    """A 0-byte target may be another writer's claim placeholder (C1(a))."""
    root = _workarea(tmp_path)
    dest = root / "out"
    dest.mkdir()
    target = dest / "empty.s19"
    target.write_bytes(b"")
    src = tmp_path / "empty.s19"
    src.write_bytes(b"")

    returned = copy_into_workarea(src, dest)
    assert returned.name != "empty.s19", (
        "a 0-byte target (another writer's claim) must never be reused"
    )
    assert returned.read_bytes() == b""


def test_tc_b99_13_symlink_target_is_never_reused(tmp_path: Path) -> None:
    """B8 content dedup must SKIP a target that is a link or reparse point
    (security finding S-F4): a byte-identical file reached THROUGH a
    symlink is not this work area's placed file — reusing the name would
    return a path whose bytes live outside the work area. The placement
    must claim the next ``_<N>`` as a regular file and leave the link and
    its target untouched. Skips with the stated reason when symlink
    creation is not permitted.

    RED at the review-round-2 tree: the dedup read followed the link,
    matched the bytes and returned the symlink itself.
    """
    root = _workarea(tmp_path)
    dest = root / "out"
    dest.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    payload = _emit(0x77)
    outside_file = outside / "fw.s19"
    outside_file.write_bytes(payload.encode("ascii"))
    link = dest / "fw.s19"
    try:
        os.symlink(outside_file, link)
    except OSError as exc:
        pytest.skip(f"symlink creation not permitted: {exc}")
    src = tmp_path / "fw.s19"
    src.write_bytes(payload.encode("ascii"))

    returned = copy_into_workarea(src, dest)

    assert returned.name == "fw_1.s19", returned
    assert returned.is_file() and not returned.is_symlink()
    assert returned.read_bytes() == src.read_bytes()
    assert link.is_symlink(), "the link must be untouched"
    assert outside_file.read_bytes() == payload.encode("ascii"), (
        "the bytes behind the link must be untouched"
    )
    assert _staging_leftovers(root) == [], _staging_leftovers(root)


# ---------------------------------------------------------------------------
# TC-B99-39 — LLR-155.7 delete census of the four writers
# ---------------------------------------------------------------------------


def _function_source(path: Path, func_name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return node
    raise AssertionError(f"{func_name} not found in {path}")


def _parent_map(fn: ast.FunctionDef) -> dict:
    parents: dict = {}
    for node in ast.walk(fn):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _statement_body(assign: ast.AST, parents: dict) -> tuple:
    """The body list holding ``assign`` and its index within it."""
    parent = parents[assign]
    body = getattr(parent, "body", None)
    if not isinstance(body, list):
        grand = parents.get(parent)
        body = getattr(grand, "body", None) if grand is not None else None
    if not isinstance(body, list) or assign not in body:
        return (), -1
    return body, body.index(assign)


def _flag_assigned_right_after(stmt: ast.AST, parents: dict) -> Optional[str]:
    """The boolean name assigned in the statement immediately after ``stmt``."""
    body, index = _statement_body(stmt, parents)
    if index < 0 or index + 1 >= len(body):
        return None
    nxt = body[index + 1]
    if (
        isinstance(nxt, ast.Assign)
        and len(nxt.targets) == 1
        and isinstance(nxt.targets[0], ast.Name)
        and isinstance(nxt.value, ast.Constant)
        and isinstance(nxt.value.value, bool)
    ):
        return nxt.targets[0].id
    return None


def _root_name(expr: ast.AST) -> Optional[str]:
    node = expr
    while isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "str":
        if not node.args:
            return None
        node = node.args[0]
    if isinstance(node, ast.Name):
        return node.id
    return None


def _delete_census(path: Path, func_name: str) -> list:
    """LLR-155.7: every unlink/rmtree/os.remove in ``func_name`` must delete a
    name bound in the same function to a ``tempfile.mkdtemp`` result (or to
    ``workspace._private_stage_dir``, the one helper that owns the mkdtemp —
    review finding F3) or to the first argument of an ``os.open(..., O_EXCL)``
    claim, inside a branch guarded by the boolean assigned immediately after
    that creation."""
    fn = _function_source(path, func_name)
    parents = _parent_map(fn)

    def _is_mkdtemp_value(value: ast.AST) -> bool:
        # X = tempfile.mkdtemp(...) or X = Path(tempfile.mkdtemp(...)) or
        # X = _private_stage_dir(...) — either way the target name is bound
        # to a private per-write mkdtemp directory.
        for node in ast.walk(value):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr == "mkdtemp":
                return True
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "_private_stage_dir"
            ):
                return True
        return False

    def _is_excl_open(call: ast.Call) -> bool:
        if not (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "open"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "os"
        ):
            return False
        return any(
            isinstance(node, ast.Attribute) and "O_EXCL" in node.attr
            for node in ast.walk(call)
        )

    def _aliased_name(assign: ast.Assign) -> Optional[str]:
        # X = Y chains: the name ultimately aliased.
        value = assign.value
        while isinstance(value, ast.Name):
            return value.id
        return None

    bound: dict[str, str] = {}  # name -> flag name ("" = no flag found)
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        flag = _flag_assigned_right_after(node, parents)
        if _is_mkdtemp_value(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bound[target.id] = flag or ""
        elif _is_excl_open(node.value):
            if node.value.args:
                claimed = _root_name(node.value.args[0])
                if claimed is not None:
                    # the claim name is the os.open first argument; flag
                    # rides the statement right after the binding call
                    bound[claimed] = flag or ""

    # alias resolution: X = Y where Y is itself bound
    changed = True
    while changed:
        changed = False
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Name)
                and node.value.id in bound
                and node.targets[0].id not in bound
            ):
                bound[node.targets[0].id] = bound[node.value.id]
                changed = True

    def _guarded_by(delete: ast.Call, flag: str) -> bool:
        node = parents.get(delete)
        while node is not None:
            if isinstance(node, ast.If):
                for name in ast.walk(node.test):
                    if (
                        isinstance(name, ast.Name)
                        and name.id == flag
                        and isinstance(name.ctx, ast.Load)
                    ):
                        return True
            node = parents.get(node)
        return False

    violations: list = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        deleted_name: Optional[str] = None
        if isinstance(node.func, ast.Attribute) and node.func.attr == "unlink":
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.args
            ):
                # os.unlink(path) — the deleted path is the argument
                deleted_name = _root_name(node.args[0])
            else:
                # Path.unlink() carries the deleted path as the RECEIVER
                deleted_name = _root_name(node.func.value)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "rmtree":
            if node.args:
                deleted_name = _root_name(node.args[0])
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "remove"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.args
        ):
            deleted_name = _root_name(node.args[0])
        if deleted_name is None:
            continue
        flag = bound.get(deleted_name)
        if flag is None or flag == "" or not _guarded_by(node, flag):
            violations.append(
                f"{path.name}:{func_name}:{node.lineno} deletes {deleted_name!r} "
                f"without an owned-binding guard"
            )
    return violations


_CENSUS_TARGETS = [
    (Path("s19_app/tui/changes/apply.py"), "save_patched_image"),
    (Path("s19_app/tui/changes/io.py"), "write_change_document"),
    (Path("s19_app/tui/workspace.py"), "copy_into_workarea"),
    (Path("s19_app/tui/workspace.py"), "place_group_into_workarea"),
    (Path("s19_app/tui/services/flow_execution_service.py"), "run_flow"),
    (Path("s19_app/tui/operations/crc.py"), "write_crc_image"),
]

#: The CRC write converted to private staging in batch-99 Inc-5 (LLR-155.8):
#: it now stages via ``workspace._private_stage_dir`` (a per-write mkdtemp
#: under ``temp/.staging/``) and removes only the owned staging directory, so
#: the census holds with ZERO exceptions.
def test_tc_b99_39_delete_calls_delete_only_owned_staging() -> None:
    """The five placement writers delete only what they created: 0
    violations, no exceptions (the Inc-5 LLR-155.8 CRC conversion removed
    the last known site)."""
    all_violations: list = []
    for rel, func_name in _CENSUS_TARGETS:
        all_violations.extend(_delete_census(REPO_ROOT / rel, func_name))
    assert all_violations == [], (
        f"LLR-155.7 violations: {all_violations}"
    )


# ---------------------------------------------------------------------------
# TC-B99-44 — the converted io.py path stages privately (LLR-155.1, PDR C2)
# ---------------------------------------------------------------------------


def _change_document() -> ChangeDocument:
    return ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="change",
        encoding="utf-8",
        value_mode="codes",
        entries=[ChangeEntry("bytes", 0x1000, (0x11, 0x99))],
    )


def test_tc_b99_44_change_document_stages_in_private_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The converted ``write_change_document`` path (PDR C2; the app-level
    caller is ``S19TuiApp._on_check_editor_action``'s ``write_doc`` arm and
    ``change_service``) stages the serialised bytes in a private
    ``tempfile.mkdtemp`` directory under the reparse-checked
    ``temp/.staging`` home — never directly under ``temp/`` — and places
    the document correctly (review finding F4).

    RED at the review-round tree: staging ran a ``mkdtemp`` directly under
    ``temp/`` (no reparse check), so the mkdtemp spy sees the wrong home.
    """
    real_mkdtemp = tempfile.mkdtemp
    dirs_seen: list = []

    def _spy_mkdtemp(*args, **kwargs):
        created = real_mkdtemp(*args, **kwargs)
        dirs_seen.append((kwargs.get("dir"), Path(created)))
        return created

    monkeypatch.setattr(workspace.tempfile, "mkdtemp", _spy_mkdtemp)

    written_path, issues = write_change_document(_change_document(), tmp_path)

    assert issues == [], [i.message for i in issues]
    assert written_path is not None
    expected_home = (
        tmp_path / ".s19tool" / "workarea" / "temp" / ".staging"
    ).resolve()
    assert dirs_seen, "the write must stage in a private mkdtemp directory"
    for parent, created in dirs_seen:
        assert Path(parent).resolve() == expected_home, (
            f"staging must live under {expected_home}, not {parent}"
        )
        assert Path(created).resolve().is_relative_to(expected_home)
    # the placed file holds the serialised document
    payload = json.loads(written_path.read_text(encoding="utf-8"))
    assert payload["format"] == FORMAT_ID
    assert len(payload["entries"]) == 1
    # only the owned per-write staging dir is removed; the home persists
    assert list(expected_home.iterdir()) == [], list(expected_home.iterdir())


def test_tc_b99_44_junction_at_staging_temp_is_refused(tmp_path: Path) -> None:
    """A junction/symlink at ``temp`` refuses the converted ``io.py`` write
    too (LLR-155.1, review finding F3): one ``MF-WRITE-CONTAINMENT`` issue,
    nothing written anywhere — in particular nothing through the junction.
    Skips with the stated reason when link creation is not permitted.

    RED at the review-round tree: no reparse check existed on this path, so
    the write rode the junction and landed outside the work area.
    """
    root = tmp_path / ".s19tool" / "workarea"
    root.mkdir(parents=True)
    outside = _plant_temp_junction(root, tmp_path)

    written_path, issues = write_change_document(_change_document(), tmp_path)

    assert written_path is None, f"the junction must refuse the write: {written_path}"
    assert [i.code for i in issues] == [MF_WRITE_CONTAINMENT], (
        [i.message for i in issues]
    )
    assert [p for p in outside.iterdir()] == [], (
        f"nothing may be written through the junction: {list(outside.iterdir())}"
    )


# ---------------------------------------------------------------------------
# Pilot helpers (Layer B)
# ---------------------------------------------------------------------------


def _notices(app) -> list:
    captured: list = []
    original = app.notify

    def _patched(message, *, title="", severity="information", **kwargs):
        captured.append((title, str(message), severity))
        return original(message, title=title, severity=severity, **kwargs)

    app.notify = _patched  # type: ignore[method-assign]
    return captured


def _statuses(app) -> list:
    captured: list = []
    original = app.set_status
    app.set_status = lambda message: (  # type: ignore[method-assign]
        captured.append(message),
        original(message),
    )[1]
    return captured


# ---------------------------------------------------------------------------
# TC-B99-14 — Save project survives a missing source (LLR-155.4)
# ---------------------------------------------------------------------------


async def _poll(pilot, predicate, attempts: int = 200) -> bool:
    """Bounded pump-until that returns the outcome (assertion stays in the
    test body so a RED names its own clause)."""
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return True
    return False


def test_tc_b99_14_save_project_missing_source(tmp_path: Path) -> None:
    """A missing source at Save project: failure-severity status leading with
    the outcome and naming the file, no empty project folder, app still
    running. Driven entirely by keys and clicks through the real Load file
    dialog and the real ``SaveProjectScreen`` (review finding F5): inputs
    are clicked and typed, buttons are clicked, and every wait observes the
    painted status line (``#log_line_4``) or the painted screen — never an
    internal attribute and never a patched method.

    RED at HEAD (P-15): ``copy_into_workarea`` raises ``FileNotFoundError``
    from ``source.stat()``, which ``_handle_save_dialog`` does not catch — the
    escape ends the app run.
    """
    from textual.widgets import Label

    image = _image(tmp_path, "firmware.s19", 0x11)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # Load through the Load file dialog (rail key ``l``).
            await pilot.press("l")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#load_path"), "click missed #load_path"
            await pilot.press(*str(image))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            await _poll(
                pilot, lambda: "Loaded firmware.s19" in _painted_status(app)
            )
            work_copy = tmp_path / ".s19tool" / "workarea" / "temp" / "firmware.s19"
            assert work_copy.is_file()
            work_copy.unlink()
            # Save project through the real dialog (key ``s``).
            await pilot.press("s")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#project_parent_path"), (
                "click missed #project_parent_path"
            )
            await pilot.press("ctrl+shift+a")
            await pilot.press(*str(tmp_path / ".s19tool" / "workarea"))
            assert await pilot.click("#project_name"), "click missed #project_name"
            await pilot.press(*"proj")
            assert await pilot.click("#save_ok"), "click missed #save_ok"
            await _poll(
                pilot, lambda: "Project NOT saved" in _painted_status(app)
            )
            outcomes["status"] = _painted_status(app)
            outcomes["app_running"] = bool(app.query_one("#status_text", Label).render())
        return outcomes

    outcomes = asyncio.run(_drive())

    status = outcomes["status"]
    assert status.startswith("Project NOT saved") and "firmware.s19" in status, status
    assert status.index("NOT saved") < 50, status
    # the painted status line carries the notice text verbatim (this app
    # mounts no ToastRack, so ``notify`` has no toast overlay to paint)
    assert not (tmp_path / ".s19tool" / "workarea" / "proj").exists(), "no empty project folder"
    assert outcomes["app_running"] is True


def test_tc_b99_14_placement_failure_removes_created_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A placement failure AFTER this call created the project folder
    removes exactly that folder (review finding F6a): a forced locked
    target during Save project -> painted failure status, the created
    folder is gone, the app keeps running. Driven by keys and clicks
    through the real dialogs (review finding F5).

    GREEN at the review-round-2 tree — the cleanup landed with round 1 —
    so the RED proof is the F6a mutant (``_remove_created_project_dir``
    no-op) in ``mut-fix2-f6a.txt``.
    """
    from textual.widgets import Label

    image = _image(tmp_path, "firmware.s19", 0x11)

    def _always_locked(src_path, dst_path):
        raise PermissionError(13, "locked by another program", str(dst_path))

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("l")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#load_path"), "click missed #load_path"
            await pilot.press(*str(image))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            await _poll(
                pilot, lambda: "Loaded firmware.s19" in _painted_status(app)
            )
            await pilot.press("s")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#project_parent_path"), (
                "click missed #project_parent_path"
            )
            await pilot.press("ctrl+shift+a")
            await pilot.press(*str(tmp_path / ".s19tool" / "workarea"))
            assert await pilot.click("#project_name"), "click missed #project_name"
            await pilot.press(*"proj")
            monkeypatch.setattr(os, "replace", _always_locked)
            assert await pilot.click("#save_ok"), "click missed #save_ok"
            await _poll(pilot, lambda: _painted_status(app).startswith("Not saved"))
            outcomes["status"] = _painted_status(app)
            outcomes["app_running"] = bool(app.query_one("#status_text", Label).render())
        return outcomes

    outcomes = asyncio.run(_drive())

    assert outcomes["status"].startswith("Not saved"), outcomes["status"]
    assert "firmware.s19" in outcomes["status"], outcomes["status"]
    assert not (tmp_path / ".s19tool" / "workarea" / "proj").exists(), (
        "the folder this call created must be removed on placement failure"
    )
    assert outcomes["app_running"] is True


def test_tc_b99_14_preexisting_folder_survives_placement_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A PRE-EXISTING project folder of the same name survives a placement
    failure untouched (review findings F6a/S-F5): the cleanup removes only
    what THIS call created, so a folder that already held operator content
    keeps it. Pairs with the S-F5 flag fix — ``mkdir(exist_ok=False)`` +
    ``FileExistsError`` decides ownership instead of a racy
    ``not exists()`` probe. Driven by keys and clicks through the real
    dialogs.

    GREEN at the review-round-2 tree — the flag was already conservative —
    so the RED proof is the S-F5 mutant (``created_project_dir`` forced
    True) in ``mut-fix2-sf5.txt``.
    """
    from textual.widgets import Label

    image = _image(tmp_path, "firmware.s19", 0x11)
    preexisting = tmp_path / ".s19tool" / "workarea" / "proj"
    preexisting.mkdir(parents=True)
    sentinel = preexisting / "keep.me"
    sentinel.write_text("operator content", encoding="ascii")

    def _always_locked(src_path, dst_path):
        raise PermissionError(13, "locked by another program", str(dst_path))

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("l")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#load_path"), "click missed #load_path"
            await pilot.press(*str(image))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            await _poll(
                pilot, lambda: "Loaded firmware.s19" in _painted_status(app)
            )
            await pilot.press("s")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#project_parent_path"), (
                "click missed #project_parent_path"
            )
            await pilot.press("ctrl+shift+a")
            await pilot.press(*str(tmp_path / ".s19tool" / "workarea"))
            assert await pilot.click("#project_name"), "click missed #project_name"
            await pilot.press(*"proj")
            monkeypatch.setattr(os, "replace", _always_locked)
            assert await pilot.click("#save_ok"), "click missed #save_ok"
            await _poll(pilot, lambda: _painted_status(app).startswith("Not saved"))
            outcomes["status"] = _painted_status(app)
            outcomes["app_running"] = bool(app.query_one("#status_text", Label).render())
        return outcomes

    outcomes = asyncio.run(_drive())

    assert outcomes["status"].startswith("Not saved"), outcomes["status"]
    assert preexisting.is_dir(), "a pre-existing folder must survive the failure"
    assert sentinel.read_text(encoding="ascii") == "operator content", (
        "the pre-existing folder's content must be untouched"
    )
    assert not (preexisting / "firmware.s19").exists(), (
        "the failed placement must not have left a partial file"
    )
    assert outcomes["app_running"] is True


# ---------------------------------------------------------------------------
# AT-B99-05 — full chain: same-name save-back, then Save project
# ---------------------------------------------------------------------------


def test_at_b99_05_save_project_after_same_name_save_back(tmp_path: Path) -> None:
    """Load -> patch -> save back as firmware.s19 -> Save project: the app is
    running, the project folder holds the image and the status names it.
    Driven entirely by keys and clicks through the real Load file dialog,
    the Patch Editor (rail key ``6``) and the real ``SaveProjectScreen``
    (review finding F5) — inputs are clicked and typed, buttons are clicked,
    and every wait observes the painted status line (``#log_line_4``) or the
    painted screen; assertions read the painted status and the files on disk.

    RED at HEAD (P-15): the save-back deletes the work copy and the next Save
    project exits the app with code 1.
    """
    from textual.widgets import Label

    image = tmp_path / "firmware.s19"
    image.write_text(_emit_two(0x11, 0x00), encoding="ascii")

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        outcomes: dict = {}
        # 260x54: the Patch Editor's docked save-back row sits at the foot
        # of the JSON pane and is only clickable/painted at the taller
        # viewport (the b97 ATs and AT-B99-02 drive the panel at 120x54);
        # the extra width keeps the "Saved project to …" success line
        # unpainted-clipped in the four-line log strip (review finding
        # LOW-2).
        async with app.run_test(size=(260, 54)) as pilot:
            await pilot.pause()
            # 1. Load through the Load file dialog (rail key ``l``).
            await pilot.press("l")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#load_path"), "click missed #load_path"
            await pilot.press(*str(image))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            await _poll(
                pilot, lambda: "Loaded firmware.s19" in _painted_status(app)
            )
            work_copy = tmp_path / ".s19tool" / "workarea" / "temp" / "firmware.s19"
            outcomes["pre_save_bytes"] = work_copy.read_bytes()
            # 2. Patch Editor (rail key ``6``): one entry at 0x2000.
            await pilot.press("6")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#patch_entry_address_input"), (
                "click missed #patch_entry_address_input"
            )
            await pilot.press(*"0x2000")
            assert await pilot.click("#patch_entry_bytes_input"), (
                "click missed #patch_entry_bytes_input"
            )
            await pilot.press(*"AA")
            assert await pilot.click("#patch_entry_add_button"), (
                "click missed #patch_entry_add_button"
            )
            await _poll(pilot, lambda: "entry added" in _painted_status(app))
            assert await pilot.click("#patch_doc_apply_button"), (
                "click missed #patch_doc_apply_button"
            )
            await _poll(pilot, lambda: "Apply:" in _painted_status(app))
            # 3. Save-back under the loaded image's own name: the prompt
            #    renders in the editor's JSON pane — pick that tab by
            #    clicking its chip, then wait for the prompt to be PAINTED.
            assert await pilot.click("#patch_tab_json"), (
                "click missed #patch_tab_json"
            )
            await _poll(pilot, lambda: "patched" in _painted_text(app))
            assert await pilot.click("#patch_saveback_name_input"), (
                "click missed #patch_saveback_name_input"
            )
            await pilot.press("ctrl+shift+a")
            await pilot.press(*"firmware.s19")
            assert await pilot.click("#patch_saveback_confirm_button"), (
                "click missed #patch_saveback_confirm_button"
            )
            await _poll(
                pilot,
                lambda: (
                    tmp_path / ".s19tool" / "workarea" / "firmware.s19"
                ).is_file(),
            )
            outcomes["work_copy_exists"] = work_copy.is_file()
            outcomes["work_copy_bytes"] = (
                work_copy.read_bytes() if work_copy.is_file() else None
            )
            # 4. Save project through the real dialog (key ``s``).
            await pilot.press("s")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#project_parent_path"), (
                "click missed #project_parent_path"
            )
            await pilot.press("ctrl+shift+a")
            await pilot.press(*str(tmp_path / ".s19tool" / "workarea"))
            assert await pilot.click("#project_name"), "click missed #project_name"
            await pilot.press(*"proj")
            assert await pilot.click("#save_ok"), "click missed #save_ok"
            # the manifest line paints FIRST and the save's success —
            # "Saved project to … (variant 'firmware')" — is the NEWEST
            # line (batch-100 Inc 2 fix pass 1, F1 / LED .52(b): a save
            # that can still fail must not have said "Saved"), so the
            # success line survives as the newest line. Wait for the final
            # line, then read the PAINTED log lines (review finding LOW-2:
            # the wait and the assertion are consistent, and the painted
            # status names the image file).
            await _poll(
                pilot, lambda: _painted_status(app).startswith("Saved project to")
            )
            outcomes["status"] = _painted_status(app)
            outcomes["log_lines"] = [
                str(app.query_one(f"#log_line_{i}", Label).render())
                for i in (1, 2, 3, 4)
            ]
            outcomes["app_running"] = bool(
                app.query_one("#status_text", Label).render()
            )
        return outcomes

    outcomes = asyncio.run(_drive())

    assert outcomes["work_copy_exists"] is True, "the save-back deleted the work copy"
    assert outcomes["work_copy_bytes"] == outcomes["pre_save_bytes"]
    assert outcomes["app_running"] is True
    assert outcomes["status"].startswith("Saved project to"), outcomes["status"]
    save_lines = [line for line in outcomes["log_lines"] if line.startswith("Saved project to")]
    assert save_lines, (
        f"the 'Saved project to' success line must be painted: {outcomes['log_lines']}"
    )
    assert "firmware" in save_lines[-1], (
        f"the painted status must name the image file: {save_lines[-1]}"
    )
    manifest_lines = [
        line for line in outcomes["log_lines"] if "manifest verified" in line
    ]
    assert manifest_lines, (
        f"the manifest-verify line must be painted: {outcomes['log_lines']}"
    )
    placed = tmp_path / ".s19tool" / "workarea" / "proj" / "firmware.s19"
    assert placed.is_file(), "the project folder must hold the image"
    # batch-100 HLR-167 / LLR-167.2 re-pin: the project image is the image
    # the session shows — source + the document (the save-back's patch at
    # 0x2000) — and the success line names the entries it carries
    # (LLR-167.3). Before batch-100 Inc 5 the save copied the unpatched
    # work copy (P-1).
    assert _data(placed) == {0x1000: 0x11, 0x2000: 0xAA}, _data(placed)
    assert "1 change entry" in save_lines[-1], save_lines[-1]


# ---------------------------------------------------------------------------
# AT-B99-04 — duplicate refused, distinct parallel markers (HLR-155, one node)
# ---------------------------------------------------------------------------


async def _fx_import_lane_click(app, pilot, stem: str, lane: int) -> None:
    """Import ``flows/<stem>.json`` as lane ``lane`` through the shipped
    picker — real clicks only (``#fx_import``, the stem's painted row, then
    ``#flow_load_ok``), never ``Button.press()``."""
    from textual.widgets import Label

    panel = app.query_one("#fx_panel")
    assert await pilot.click("#fx_import"), "click missed #fx_import"
    assert await _poll(pilot, lambda: bool(app.screen.query("#flow_list"))), (
        "the flow picker did not open"
    )
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
    assert await _poll(pilot, lambda: bool(panel.query(f"#fx_lane_{lane}"))), (
        f"lane {lane} never mounted"
    )


def test_at_b99_04_duplicate_refused_distinct_parallel_markers(tmp_path: Path) -> None:
    """AT-B99-04 (HLR-155 D7 + the distinct-name parallel arm, LLR-155.5):
    ONE black-box pilot session drives both outcomes through the shipped
    surface. (b) First — a chain set of 8 lanes with distinct output names,
    run in PARALLEL through Flow Execution (the ``parallel`` word of
    ``#fx_mode`` clicked, Run clicked on ``#fx_run``), writes 8 files, each
    holding its lane's marker; the run's chain-set report reads
    ``- **Mode:** parallel`` (a written artifact, never an attribute read).
    (a) Then — two more lanes whose WRITE-OUT names resolve to one file
    (``same.s19`` / ``SAME.s19``, case-folded) refuse the WHOLE set: the
    painted run log (``#fx_log``) leads with the outcome inside the first
    50 characters (UX-C4), names both lanes and the file, the refusal also
    reaches the status line (``#log_line_4``), and nothing new is written.

    Lanes cannot be removed from the panel, so the distinct set runs first
    and the colliding pair is imported after it — a refused set is observed
    as ``nothing new on disk``, not as ``the directory is empty`` (the 8
    lane files and the reports of run (b) legitimately stay).

    Every entry is the shipped control: the project loads through the Load
    project dialog (rail key ``p``, the ``proj`` row, ``#project_ok``), the
    lanes import through ``#fx_import`` clicks, the mode and Run are
    clicks; every wait and assertion reads the painted surface, a file on
    disk, or an ``isinstance`` screen predicate — never
    ``app._handle_load_project``, ``Button.press()``,
    ``ModeToggle.set_mode``, ``Input.value =``, or an internal attribute.
    """
    from textual.widgets import Label, Static

    from s19_app.tui.screens import LoadProjectScreen
    from tests.b97_fixtures import make_project, write_flow
    from tests.b97_probes import settle

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        outcomes: dict = {}
        async with app.run_test(size=(260, 90)) as pilot:
            await settle(pilot)
            # fixture staging through the accepted residual: app.workarea
            project_dir = make_project(app, "proj")
            for i in range(8):
                (project_dir / f"base{i}.s19").write_text(
                    _emit(0x41 + i), encoding="ascii"
                )
                write_flow(
                    project_dir,
                    f"lane{i}",
                    [SourceBlock(f"base{i}.s19"), WriteOutBlock(f"lane{i}.s19")],
                )
            (project_dir / "base_a.s19").write_text(_emit(0x41), "ascii")
            (project_dir / "base_b.s19").write_text(_emit(0x42), "ascii")
            write_flow(
                project_dir,
                "lane_a",
                [SourceBlock("base_a.s19"), WriteOutBlock("same.s19")],
            )
            write_flow(
                project_dir,
                "lane_b",
                [SourceBlock("base_b.s19"), WriteOutBlock("SAME.s19")],
            )

            # load the project through the Load project dialog (rail key ``p``)
            await pilot.press("p")
            assert await _poll(
                pilot, lambda: isinstance(app.screen, LoadProjectScreen)
            ), "the Load project dialog never opened"
            row = next(
                item
                for item in app.screen.query("#project_list ListItem")
                if str(item.query_one(Label).render()) == "proj"
            )
            await pilot.click(row)
            await pilot.pause()
            assert await pilot.click("#project_ok"), "click missed #project_ok"
            assert await _poll(
                pilot, lambda: "Loaded project 'proj'" in _painted_status(app)
            ), f"the project load did not paint: {_painted_status(app)}"
            # Inc 6 (HLR-178): the dialog route opens the Load-result panel;
            # dismiss it first with its shown key ``esc``.
            await dismiss_load_result_panel(pilot, app)

            # Flow Execution (rail key ``]``)
            await pilot.press("right_square_bracket")
            panel = app.query_one("#fx_panel")
            await _poll(pilot, lambda: panel.region.height > 0)

            # (b) the 8-lane distinct-name set, run in parallel
            for i in range(8):
                await _fx_import_lane_click(app, pilot, f"lane{i}", i)
            assert await pilot.click("#fx_mode", offset=(18, 0)), (
                "click missed the parallel word of #fx_mode"
            )
            await settle(pilot)
            assert await pilot.click("#fx_run"), "click missed #fx_run"
            assert await _poll(
                pilot,
                lambda: all(
                    (project_dir / f"lane{i}.s19").is_file() for i in range(8)
                ),
                attempts=400,
            ), "the parallel run did not write all 8 lane files"
            assert await _poll(
                pilot,
                lambda: "· done" in app.query_one("#fx_log", Static).render().plain
                and not app.query_one("#fx_run").disabled,
                attempts=400,
            ), "the run never painted its terminal line"

            # (a) the duplicate-name pair refuses the whole set
            await _fx_import_lane_click(app, pilot, "lane_a", 8)
            await _fx_import_lane_click(app, pilot, "lane_b", 9)
            outcomes["pre_refusal"] = sorted(p.name for p in project_dir.iterdir())
            assert await pilot.click("#fx_run"), "click missed #fx_run"
            assert await _poll(
                pilot,
                lambda: "Chain set not run"
                in app.query_one("#fx_log", Static).render().plain,
            ), f"the refusal never painted: {_painted_status(app)}"
            outcomes["log"] = app.query_one("#fx_log", Static).render().plain
            outcomes["status"] = _painted_status(app)
            outcomes["after"] = sorted(p.name for p in project_dir.iterdir())
            outcomes["project_dir"] = project_dir
        return outcomes

    outcomes = asyncio.run(_drive())
    project_dir: Path = outcomes["project_dir"]

    # (b) 8 files, each holding its own lane's marker (independent reader)
    for i in range(8):
        lane_file = project_dir / f"lane{i}.s19"
        assert lane_file.is_file(), (
            f"lane {i} wrote no file: {sorted(p.name for p in project_dir.iterdir())}"
        )
        assert _data(lane_file) == {0x1000: 0x41 + i}, (
            f"lane{i}.s19 must hold its own marker: {_data(lane_file)}"
        )
    reports = sorted((project_dir / "reports").glob("*chain-set-report*.md"))
    assert reports, "the set run writes a chain-set report"
    report_text = reports[-1].read_text(encoding="utf-8")
    assert "- **Mode:** parallel" in report_text, (
        f"the run's report must record the parallel mode: {report_text}"
    )

    # (a) the painted refusal names both lanes and the file; nothing written
    lines = [l for l in outcomes["log"].splitlines() if "Chain set not run" in l]
    assert lines, (
        f"the refusal must be painted in the run log: {outcomes['log']!r}"
    )
    line = lines[-1].strip()
    assert line.index("Chain set not run") < 50, line
    assert "lane_a" in line and "lane_b" in line, line
    assert "same.s19" in line, line
    assert "Nothing written" in line, line
    assert "same.s19" not in outcomes["after"], outcomes["after"]
    assert "SAME.s19" not in outcomes["after"], outcomes["after"]
    assert outcomes["after"] == outcomes["pre_refusal"], (
        f"a refused set writes nothing: {outcomes['after']}"
    )

    # the refusal also reaches the status line (#log_line_4), not only the
    # run log (LLR-155.5, review finding F2): outcome first (UX-C4), the
    # lane names literal (UX-C10 — the label's markup stays off)
    status = outcomes["status"]
    assert "Chain set not run" in status, status
    assert status.index("Chain set not run") < 50, status
    assert "lane_a" in status and "lane_b" in status, status
    assert "same.s19" in status, status


# ---------------------------------------------------------------------------
# UX-C10 — hostile-name TCs for the new file-derived sinks
# ---------------------------------------------------------------------------


def test_tc_b99_ux_c10_save_project_filename_renders_literally(tmp_path: Path) -> None:
    """The Save project file name is a new file-derived sink: a hostile
    source file name must render literally (0 markup spans) in the painted
    status and in the error notice."""
    hostile = f"{HOSTILE_NAME}.s19"
    image = _image(tmp_path, hostile, 0x11)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            notices = _notices(app)
            statuses = _statuses(app)
            app.load_from_path(image)
            await _poll(pilot, lambda: app.current_file is not None)
            work_copy = tmp_path / ".s19tool" / "workarea" / "temp" / hostile
            assert work_copy.is_file()
            work_copy.unlink()
            app.action_save_project()
            await pilot.pause()
            app.screen.query_one("#project_parent_path").value = str(
                tmp_path / ".s19tool" / "workarea"
            )
            app.screen.query_one("#project_name").value = "proj"
            app.screen.query_one("#save_ok").press()
            await pilot.pause()
            outcomes["statuses"] = list(statuses)
            outcomes["notices"] = list(notices)
            outcomes["log_lines"] = list(app.log_lines)
        return outcomes

    outcomes = asyncio.run(_drive())
    painted = "\n".join(outcomes["statuses"] + outcomes["log_lines"])
    assert HOSTILE_NAME in painted, (
        f"the hostile file name must render literally (0 markup spans): {painted!r}"
    )
    error_notices = [n for n in outcomes["notices"] if n[2] == "error"]
    assert error_notices and any(HOSTILE_NAME in n[1] for n in error_notices), (
        outcomes["notices"]
    )


def test_tc_b99_ux_c10_placement_error_path_renders_literally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The placement-error path is a new file-derived sink: the
    ``WorkareaPlacementError`` text names the hostile file and renders
    literally when the handler paints it."""
    from textual.widgets import Label

    assert PlacementError is not None
    hostile = f"{HOSTILE_NAME}.s19"
    image = _image(tmp_path, hostile, 0x11)

    def _always_locked(src_path, dst_path):
        raise PermissionError(13, "locked", str(dst_path))

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        outcomes: dict = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            notices = _notices(app)
            statuses = _statuses(app)
            app.load_from_path(image)
            await _poll(pilot, lambda: app.current_file is not None)
            monkeypatch.setattr(os, "replace", _always_locked)
            app.action_save_project()
            await pilot.pause()
            app.screen.query_one("#project_parent_path").value = str(
                tmp_path / ".s19tool" / "workarea"
            )
            app.screen.query_one("#project_name").value = "proj"
            app.screen.query_one("#save_ok").press()
            await pilot.pause()
            outcomes["statuses"] = list(statuses)
            outcomes["notices"] = list(notices)
            outcomes["log_lines"] = list(app.log_lines)
            outcomes["app_running"] = bool(
                app.query_one("#status_text", Label).render()
            )
        return outcomes

    outcomes = asyncio.run(_drive())
    painted = "\n".join(outcomes["statuses"] + outcomes["log_lines"])
    assert HOSTILE_NAME in painted, (
        f"the placement error must name the hostile file literally: {painted!r}"
    )
    assert outcomes["app_running"] is True
    error_notices = [n for n in outcomes["notices"] if n[2] == "error"]
    assert error_notices and any(HOSTILE_NAME in n[1] for n in error_notices), (
        outcomes["notices"]
    )


# ---------------------------------------------------------------------------
# Increment 3b — HLR-155 D7 + D9 (LLR-155.5/.6, LLR-155.3 LED-.7 conversion)
# ---------------------------------------------------------------------------


def _dup_spec(name: str, output: str) -> ChainSpec:
    """One chain-set lane: a SOURCE input and a WRITE-OUT under ``output``."""
    return ChainSpec(
        name=name,
        template="tpl",
        flow=Flow(
            name="tpl",
            blocks=[SourceBlock("in.s19"), WriteOutBlock(output)],
        ),
    )


# ---------------------------------------------------------------------------
# TC-B99-15 — duplicate output names are refused at start (LLR-155.5)
# ---------------------------------------------------------------------------


def test_tc_b99_15_duplicate_write_out_names_refused(tmp_path: Path) -> None:
    """Two lanes resolving to one output name (compared case-folded —
    ``same.s19`` and ``SAME.s19``) refuse the set BEFORE any lane runs:
    the injected executor is never called, the refusal (existing
    ``ChainSetRunRecord.diagnostics`` shape) leads with the outcome
    (UX-C4), names both lanes and the name, and nothing is written.

    RED at HEAD (P-5): the lanes run and write each other's image —
    ``same.s19`` exists after the run and no refusal exists.
    """
    root = _workarea(tmp_path)
    project_dir = root / "proj"
    project_dir.mkdir()
    calls: list = []

    def _spy(flow: Flow, ctx: FlowContext) -> FlowRunResult:
        calls.append(flow)
        return FlowRunResult(status=FLOW_STATUS_OK)

    record = run_chain_set(
        [_dup_spec("lane_a", "same.s19"), _dup_spec("lane_b", "SAME.s19")],
        FlowContext(project_dir=project_dir),
        run_one=_spy,
    )

    assert calls == [], "no lane may run once the set is refused"
    assert record.outcomes == [], record.outcomes
    assert record.report_path is None, "a refused set writes no report either"
    assert list(project_dir.iterdir()) == [], list(project_dir.iterdir())
    assert record.diagnostics, "the refusal must name the lanes"
    message = record.diagnostics[0]
    assert message.index("Chain set not run") < 50, message
    assert "lane_a" in message and "lane_b" in message, message
    assert "same.s19" in message, message
    assert "Nothing written" in message, message


def test_tc_b99_15_distinct_names_run(tmp_path: Path) -> None:
    """The control arm: distinct output names refuse nothing and every lane
    runs (the invalid/boundary pair of LLR-155.5's catalog)."""
    root = _workarea(tmp_path)
    project_dir = root / "proj"
    project_dir.mkdir()
    calls: list = []

    def _spy(flow: Flow, ctx: FlowContext) -> FlowRunResult:
        calls.append(flow)
        return FlowRunResult(status=FLOW_STATUS_OK)

    record = run_chain_set(
        [_dup_spec("lane_a", "out_a.s19"), _dup_spec("lane_b", "out_b.s19")],
        FlowContext(project_dir=project_dir),
        run_one=_spy,
    )

    assert len(calls) == 2, calls
    assert len(record.outcomes) == 2, record.outcomes
    assert record.diagnostics == [], record.diagnostics


# ---------------------------------------------------------------------------
# TC-B99-16 — WRITE-OUT verifies what it wrote (LLR-155.6, HLR-155 D9)
# ---------------------------------------------------------------------------


def _verify_flow(tmp_path: Path) -> tuple:
    """A project dir + a two-block flow (SOURCE → WRITE-OUT)."""
    project_dir = _workarea(tmp_path) / "proj"
    project_dir.mkdir(parents=True)
    (project_dir / "fw.s19").write_text(_emit_two(0x11, 0x22), encoding="ascii")
    flow = Flow(
        name="verify",
        blocks=[SourceBlock("fw.s19"), WriteOutBlock("out.s19")],
    )
    return project_dir, flow


def test_tc_b99_16_corrupted_write_out_is_error_naming_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A WRITE-OUT whose placed file is corrupted after placement — a hook
    flips one data byte (checksum recomputed, so the record parses with the
    wrong value) between the write and the read-back — ends the block
    ``error``, aborts the run, and the LAST diagnostic, the painted cause
    (UX-C2), names the first differing address.

    RED at HEAD: no read-back exists, so the corrupted write reports
    ``wrote out.s19`` / ``ok``.
    """
    from s19_app.tui.changes.apply import save_patched_image as real_save
    from tests.b97_fixtures import flip_one_data_byte

    project_dir, flow = _verify_flow(tmp_path)
    flipped: list = []

    def _corrupting_save(mem_map, ranges, save_dir, output_name, **kwargs):
        target, issues = real_save(
            mem_map, ranges, save_dir, output_name, **kwargs
        )
        if target is not None:
            flipped.append(flip_one_data_byte(target, target))
        return target, issues

    monkeypatch.setattr(fx_service, "save_patched_image", _corrupting_save)
    result = run_flow(flow, FlowContext(project_dir=project_dir))

    assert flipped, "the corruption hook did not fire"
    assert result.status == FLOW_STATUS_ERROR, result.status
    write_out = result.block_results[1]
    assert write_out.status == BLOCK_STATUS_ERROR, write_out.summary
    last = write_out.diagnostics[-1]
    assert last == f"first difference at 0x{flipped[0]:06X}", (
        write_out.diagnostics
    )


def test_tc_b99_16_intact_write_out_is_ok(tmp_path: Path) -> None:
    """The control arm: an intact write verifies byte-for-byte and the
    WRITE-OUT block stays ``ok`` (LLR-155.6's boundary catalog)."""
    project_dir, flow = _verify_flow(tmp_path)
    result = run_flow(flow, FlowContext(project_dir=project_dir))
    write_out = result.block_results[1]
    assert write_out.status == BLOCK_STATUS_OK, write_out.summary
    assert result.status == FLOW_STATUS_OK, result.status
    assert _data(project_dir / "out.s19") == {0x1000: 0x11, 0x2000: 0x22}


# ---------------------------------------------------------------------------
# TC-B99-13 arms — LLR-155.3: the gather conversion + the final-name census
# ---------------------------------------------------------------------------


def test_tc_b99_13_gather_drift_places_next_free_name(tmp_path: Path) -> None:
    """LLR-155.3 (LED .7): the gather's drift limb rides HLR-155's placement
    (LLR-155.1/.2) — a drifted source is placed under the next free ``_<N>``
    name and the existing final name is never replaced or deleted; a
    byte-identical re-gather is skipped. RED at HEAD: ``_gather_copy``
    unlinks and recopies in place, so the drifted destination is replaced
    (the restored check-then-copy form the LLR's negative control declares).
    """
    root = _workarea(tmp_path)
    project_dir = root / "proj"
    project_dir.mkdir()
    common = tmp_path / "common"
    common.mkdir()
    source = tmp_path / "lib" / "hotfix.json"
    source.parent.mkdir()
    source.write_text('{"v": 1}', encoding="utf-8")

    def _gather() -> object:
        return gather_project_artifacts(
            project_dir,
            active_document=source,
            active_document_kind="change",
            common_patches_dir=common,
            common_templates_dir=common,
            workarea_root=root,
        )

    first = _gather()
    assert first.issues == [], [i.message for i in first.issues]
    assert first.gathered == {"patches": ["patches/hotfix.json"]}, first.gathered
    placed = project_dir / "patches" / "hotfix.json"
    assert placed.read_text(encoding="utf-8") == '{"v": 1}'

    # drift: the changed source takes the next free name, never an overwrite
    source.write_text('{"v": 2}', encoding="utf-8")
    second = _gather()
    assert second.issues == [], [i.message for i in second.issues]
    assert second.gathered == {"patches": ["patches/hotfix_1.json"]}, (
        second.gathered
    )
    assert placed.read_text(encoding="utf-8") == '{"v": 1}', (
        "a placed file is immutable once placed (LLR-155.3)"
    )
    assert (project_dir / "patches" / "hotfix_1.json").read_text(
        encoding="utf-8"
    ) == '{"v": 2}'

    # identical bytes again: skipped, back to the requested name
    source.write_text('{"v": 1}', encoding="utf-8")
    third = _gather()
    assert third.gathered == {"patches": ["patches/hotfix.json"]}, third.gathered


def test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate(
    tmp_path: Path,
) -> None:
    """LLR-138.4 (review finding F1): after ONE drift the changed bytes live
    at the placed ``_<N>`` name, so every later UNCHANGED re-save must
    byte-compare against the ``_<N>`` sibling too and be skipped — two
    unchanged re-saves add no ``_2``/``_3`` copies. RED at HEAD: the compare
    runs only against ``<name>``, so the first unchanged re-save places
    ``hotfix_2.json``.
    """
    root = _workarea(tmp_path)
    project_dir = root / "proj"
    project_dir.mkdir()
    common = tmp_path / "common"
    common.mkdir()
    source = tmp_path / "lib" / "hotfix.json"
    source.parent.mkdir()
    source.write_text('{"v": 1}', encoding="utf-8")

    def _gather() -> object:
        return gather_project_artifacts(
            project_dir,
            active_document=source,
            active_document_kind="change",
            common_patches_dir=common,
            common_templates_dir=common,
            workarea_root=root,
        )

    first = _gather()
    assert first.issues == [], [i.message for i in first.issues]
    assert first.gathered == {"patches": ["patches/hotfix.json"]}, first.gathered

    # one drift: the changed bytes are placed at the next free name
    source.write_text('{"v": 2}', encoding="utf-8")
    second = _gather()
    assert second.issues == [], [i.message for i in second.issues]
    assert second.gathered == {"patches": ["patches/hotfix_1.json"]}, (
        second.gathered
    )

    # two unchanged re-saves: both skipped against the placed sibling — the
    # home still holds exactly ``hotfix.json`` + ``hotfix_1.json``
    for _ in range(2):
        again = _gather()
        assert again.issues == [], [i.message for i in again.issues]
        assert again.gathered == {"patches": ["patches/hotfix_1.json"]}, (
            again.gathered
        )
    home = project_dir / "patches"
    assert sorted(entry.name for entry in home.iterdir()) == [
        "hotfix.json",
        "hotfix_1.json",
    ], sorted(entry.name for entry in home.iterdir())
    assert (home / "hotfix.json").read_text(encoding="utf-8") == '{"v": 1}'
    assert (home / "hotfix_1.json").read_text(encoding="utf-8") == '{"v": 2}'


#: The pinned allow-list (LLR-155.3): the only functions inside ``s19_app/``
#: that may call ``unlink`` / ``os.replace`` / ``shutil.copy2`` /
#: ``write_bytes`` / ``write_text`` onto a final name. The four placement
#: writers own the placement invariant; the fixed-name writers predate LED .7
#: with their own non-clobber / atomic schemes (the manifest's fixed
#: ``project.json`` and the M-5 report names, checked non-existing before
#: the write); ``write_bin_with_sidecar`` was bypassed by Inc 6 (the export no longer calls it) and stays allow-listed as a headless engine API.
#: Review finding F4a extended the census to ``write_text``; the additional
#: pinned writers: the diff reports' M-5 collision-counter names (never an
#: overwrite), the explicit operator-picked export targets (the A2L dump and
#: the split/join export — overwriting the chosen path IS the action's
#: semantics). The CRC designer's same-name template save moved to the
#: declared exceptions below (review round 2).
_FINAL_NAME_ALLOWLIST = {
    # Inc 6 added the group placement (B99-I2a) beside the single-file one.
    # batch-100 Inc 1 (LLR-163.1, B100-I13): the single-file placement moved
    # into place_into_workarea — every guard, the reuse decision and the
    # claim/fill live there now; copy_into_workarea is its one-line wrapper
    # and no longer writes (review finding F10), so only the placement is
    # allow-listed.
    "s19_app/tui/workspace.py": frozenset(
        {
            "_private_stage_dir",
            "place_group_into_workarea",
            "place_into_workarea",
        }
    ),
    # batch-100 Inc 2 fix pass 1 + the LED .53 redesign (review finding
    # F5; security findings SEC2-5/SEC2-6): the Save project abort removes
    # exactly the files and folders THIS save created — each unlink is one
    # path of the placed-files list recorded at placement/gather time, so
    # nothing pre-existing and nothing a concurrent writer added is ever
    # removed; the exact inverse of the placement claim.
    "s19_app/tui/app.py": frozenset({"_abort_save", "action_dump_a2l_json"}),
    "s19_app/tui/changes/apply.py": frozenset({"save_patched_image"}),
    "s19_app/tui/changes/io.py": frozenset({"write_change_document"}),
    "s19_app/tui/operations/crc.py": frozenset({"write_crc_image"}),
    # Inc 6: the export writes its bytes into the private staging dir, then
    # places them through place_group_into_workarea / copy_into_workarea.
    "s19_app/tui/segment_split_view.py": frozenset({"_write", "write_split_join_export"}),
    "s19_app/tui/services/manifest_writer.py": frozenset(
        {"write_project_manifest"}
    ),
    "s19_app/tui/services/flow_execution_service.py": frozenset(
        {"write_chain_set_report"}
    ),
    "s19_app/tui/services/flow_report_service.py": frozenset(
        {"write_flow_report"}
    ),
    "s19_app/tui/services/flow_fused_report_service.py": frozenset(
        {"write_fused_flow_report"}
    ),
    "s19_app/tui/services/report_service.py": frozenset(
        {"generate_project_report"}
    ),
    "s19_app/tui/services/diff_report_service.py": frozenset(
        {"generate_diff_report", "generate_diff_report_html"}
    ),
    "s19_app/segment_ops.py": frozenset({"write_bin_with_sidecar"}),
}

#: Declared exceptions (review finding F4a): ``write_text`` sites the census
#: flags that hold the house ``exists()`` + counter dedup (they never
#: overwrite an existing name, but they are not the pinned placement either —
#: a re-save with changes dedups to ``_<N>`` instead of placing through
#: HLR-155). Recorded here as pinned exceptions and in the increment packet's
#: backlog — conversion candidates, NOT fixed in this round.
_FINAL_NAME_DECLARED_EXCEPTIONS = {
    "s19_app/tui/services/flow_persistence_service.py": frozenset(
        {"save_flow_json", "save_chain_set"}
    ),
    # Review round 2: the CRC designer's same-name template save overwrites
    # in place in the project templates/ folder, which the gather also writes
    # into -- a real violator of the immutability invariant, declared here and
    # routed to the backlog (not converted in this increment).
    "s19_app/tui/crc_designer_view.py": frozenset({"_save_template"}),
}


def _final_name_census(rel: str, source_text: str) -> list:
    """The LLR-155.3 AST census over one module's text: every
    ``unlink`` / ``os.replace`` / ``shutil.copy2`` / ``write_bytes`` /
    ``write_text`` call (review finding F4a added the ``write_text`` limb)
    must sit inside that file's pinned allow-list of functions, unless the
    enclosing function is a pinned declared exception."""
    tree = ast.parse(source_text)
    parents: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def _enclosing_function(call: ast.Call) -> Optional[str]:
        node = parents.get(call)
        while node is not None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node.name
            node = parents.get(node)
        return None

    allowed = _FINAL_NAME_ALLOWLIST.get(rel, frozenset())
    violations: list = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        primitive: Optional[str] = None
        if isinstance(func, ast.Attribute):
            if func.attr == "unlink":
                primitive = "unlink"
            elif func.attr in ("write_bytes", "write_text"):
                primitive = func.attr
            elif (
                func.attr == "copy2"
                and isinstance(func.value, ast.Name)
                and func.value.id == "shutil"
            ):
                primitive = "shutil.copy2"
            elif (
                func.attr == "replace"
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
            ):
                primitive = "os.replace"
        if primitive is None:
            continue
        owner = _enclosing_function(node)
        if owner in allowed:
            continue
        if owner in _FINAL_NAME_DECLARED_EXCEPTIONS.get(rel, frozenset()):
            continue
        violations.append(
            f"{rel}:{node.lineno} {primitive} outside the pinned "
            f"placement allow-list (in {owner!r})"
        )
    return violations


def test_tc_b99_13_no_final_name_replace_outside_placement() -> None:
    """LLR-155.3's census arm (TC-B99-13's second arm): across ``s19_app/``
    no ``unlink`` / ``os.replace`` / ``shutil.copy2`` / ``write_bytes`` /
    ``write_text`` (the ``write_text`` limb is review finding F4a) onto an
    existing final name exists outside the pinned placement functions and
    the pinned declared exceptions — in particular
    ``project_gather_service._gather_copy`` holds none after the Inc-3b
    conversion. RED at HEAD: ``_gather_copy`` still unlinks and recopies in
    place (``project_gather_service.py:297/299``).
    """
    all_violations: list = []
    pkg_root = REPO_ROOT / "s19_app"
    for path in sorted(pkg_root.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        all_violations.extend(
            _final_name_census(rel, path.read_text(encoding="utf-8"))
        )
    assert all_violations == [], (
        "LLR-155.3: a final-name replace/delete/copy outside the placement "
        f"functions: {all_violations}"
    )

    # load-bearing emptiness: the converted gather holds NONE of the five
    # censused primitives
    gather_rel = "s19_app/tui/services/project_gather_service.py"
    gather_text = (REPO_ROOT / gather_rel).read_text(encoding="utf-8")
    gather_hits = _final_name_census(gather_rel, gather_text)
    assert gather_hits == [], (
        f"_gather_copy must place through copy_into_workarea, never "
        f"unlink/copy2: {gather_hits}"
    )

    # positive control: the identical probe on a restored-style module finds
    # the delete-and-recopy pattern (the LLR-155.3 negative control's form)
    sample = (
        "import shutil\n"
        "from pathlib import Path\n\n"
        "def _gather_copy(source: Path, home: Path):\n"
        "    destination = home / source.name\n"
        "    if destination.exists():\n"
        "        destination.unlink()\n"
        "    shutil.copy2(source, destination)\n"
    )
    sample_hits = _final_name_census("sample.py", sample)
    assert len(sample_hits) == 2, sample_hits

    # positive control for the write_text limb (review finding F4a): the
    # identical probe flags a plain ``write_text`` onto a final name in an
    # un-pinned, un-declared function
    text_sample = (
        "from pathlib import Path\n\n"
        "def save_anything(target: Path) -> None:\n"
        "    target.write_text('{}', encoding='utf-8')\n"
    )
    text_hits = _final_name_census("sample_text.py", text_sample)
    assert len(text_hits) == 1, text_hits


# ---------------------------------------------------------------------------
# UX-C10 — the D7 lane-name sink renders literally (0 markup spans)
# ---------------------------------------------------------------------------


def test_tc_b99_ux_c10_d7_lane_name_renders_literally(tmp_path: Path) -> None:
    """The D7 refusal names the lanes — a hostile lane name is a new
    file-derived sink (PDR UX-C10). Driven through the shipped Flow
    Execution panel (review finding F4b): both colliding lanes are imported
    through ``#fx_import`` and run with ``#fx_run``; the assertion reads the
    PAINTED ``#fx_log`` — the hostile literal survives verbatim in the
    painted ``.plain`` and the painted text carries 0 style spans. The test
    never calls ``safe_text`` itself: markup interpretation would show up
    as style spans ON the painted surface.
    """
    from textual.widgets import Static

    from tests.b97_fixtures import (
        import_lanes,
        load_project,
        make_project,
        run_lanes,
        write_flow,
    )
    from tests.b97_probes import settle

    hostile = "[red]x[red]"  # no path separator: a lane name IS a file stem,
    # so the painted-surface drive cannot carry "/" — the markup-opening
    # "[red" token is the hostile part UX-C10 cares about

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(260, 90)) as pilot:
            await settle(pilot)
            make_project(app, "proj")
            project_dir = load_project(app, "proj")
            (project_dir / "base_a.s19").write_text(_emit(0x41), "ascii")
            (project_dir / "base_b.s19").write_text(_emit(0x42), "ascii")
            write_flow(
                project_dir,
                hostile,
                [SourceBlock("base_a.s19"), WriteOutBlock("same.s19")],
            )
            write_flow(
                project_dir,
                "plain",
                [SourceBlock("base_b.s19"), WriteOutBlock("same.s19")],
            )
            panel = await import_lanes(app, pilot, hostile, "plain")
            await run_lanes(app, pilot, panel)
            return app.query_one("#fx_log", Static).render()

    painted = asyncio.run(_drive())

    assert "Chain set not run" in painted.plain, painted.plain
    assert hostile in painted.plain, (
        f"the hostile lane name must survive verbatim in the painted "
        f"log: {painted.plain!r}"
    )
    assert painted.spans == [], (
        f"the hostile lane name must add 0 markup spans: {painted.spans}"
    )


