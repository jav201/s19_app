"""
Batch-99 Increment 3a — private staging, atomic placement (HLR-155;
LLR-155.1/.2/.3/.4/.7; TC-B99-11/12/13/14/39; AT-B99-05; AT-B99-04's
distinct-name parallel arm as a regression guard; UX-C4/UX-C5/UX-C10 sinks).

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
- **TC-B99-39** (LLR-155.7) — AST census of the delete calls in the five
  placement writers (``save_patched_image``, ``write_change_document``,
  ``copy_into_workarea``, the flow
  WRITE-OUT arm in ``run_flow``, the CRC write in ``write_crc_image``):
  every ``unlink`` / ``rmtree`` / ``os.remove`` deletes a name bound in the
  same function to a ``tempfile.mkdtemp`` result (or to
  ``workspace._private_stage_dir``, the one helper that owns the mkdtemp)
  or to the path passed as the
  first argument of an ``os.open(..., O_EXCL)`` claim, inside a branch
  guarded by a boolean assigned immediately after that creation. Exactly one
  known exception: the CRC write site's ``finally`` unlink (expected RED
  until Inc 5, LLR-155.8).

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
- **AT-B99-04 distinct-name arm** — 8 lanes with distinct output names run
  in parallel through Flow Execution (``#fx_run``); each file holds its
  lane's marker. Regression guard — no RED claim.
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
from s19_app.tui.workspace import WorkareaContainmentError, copy_into_workarea

from tests.support import independent_reader

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
    (Path("s19_app/tui/services/flow_execution_service.py"), "run_flow"),
    (Path("s19_app/tui/operations/crc.py"), "write_crc_image"),
]

#: The one known exception: the CRC write stages at ``temp/<name>`` and
#: unlinks a re-derived name in ``finally`` — converted by Inc 5
#: (LLR-155.8). Expected RED until then.
_CRC_EXPECTED = ("crc.py", "write_crc_image")


def test_tc_b99_39_delete_calls_delete_only_owned_staging() -> None:
    """RED at HEAD: ``apply.py``'s ``finally: staged.unlink()`` deletes a path
    rebuilt from the user's name (the LLR-155.7 declared RED site)."""
    all_violations: list = []
    for rel, func_name in _CENSUS_TARGETS:
        all_violations.extend(_delete_census(REPO_ROOT / rel, func_name))
    unexpected = [
        v
        for v in all_violations
        if not (v.startswith(_CRC_EXPECTED[0]) and f":{_CRC_EXPECTED[1]}:" in v)
    ]
    assert unexpected == [], (
        f"LLR-155.7 violations outside the known Inc-5 CRC site: {unexpected}"
    )
    crc_violations = [v for v in all_violations if f":{_CRC_EXPECTED[1]}:" in v]
    assert len(crc_violations) == 1, (
        f"expected exactly the one known CRC site violating until Inc 5, "
        f"got {crc_violations}"
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
            # the save's success paints as "Saved project to … (variant
            # 'firmware')" and is superseded by the manifest line within
            # the same tick, so it never survives as the NEWEST line —
            # but the four-line painted log keeps it on screen as an older
            # line. Wait for the final line, then read the PAINTED log
            # lines (review finding LOW-2: the wait and the assertion are
            # consistent, and the painted status names the image file).
            await _poll(
                pilot, lambda: _painted_status(app).startswith("Project saved")
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
    assert outcomes["status"].startswith("Project saved"), outcomes["status"]
    save_lines = [line for line in outcomes["log_lines"] if line.startswith("Saved project to")]
    assert save_lines, (
        f"the 'Saved project to' success line must be painted: {outcomes['log_lines']}"
    )
    assert "firmware" in save_lines[-1], (
        f"the painted status must name the image file: {save_lines[-1]}"
    )
    placed = tmp_path / ".s19tool" / "workarea" / "proj" / "firmware.s19"
    assert placed.is_file(), "the project folder must hold the image"
    # the project save copies the loaded work copy (the source image) — the
    # patched save-back landed separately under the workarea root
    assert _data(placed) == {0x1000: 0x11, 0x2000: 0x00}, _data(placed)


# ---------------------------------------------------------------------------
# AT-B99-04 distinct-name parallel arm — regression guard (no RED claim)
# ---------------------------------------------------------------------------


def test_at_b99_04_distinct_names_parallel_regression_guard(tmp_path: Path) -> None:
    """8 lanes with distinct output names, run in parallel through Flow
    Execution (``#fx_run``): each file holds its lane's marker.

    Regression guard for HLR-155's placement — no RED claim (the distinct-
    name set already passes on the pre-fix tree; the RED side of AT-B99-04 is
    D7's duplicate-name arm, owned by Inc 3b).
    """
    from tests.b97_fixtures import import_lanes, load_project, make_project, run_lanes, write_flow
    from tests.b97_probes import settle

    from s19_app.tui.flow_screens import ModeToggle
    from s19_app.tui.services.flow_model import SourceBlock, WriteOutBlock

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(260, 90)) as pilot:
            await settle(pilot)
            make_project(app, "proj")
            project_dir = load_project(app, "proj")
            for i in range(8):
                (project_dir / f"base{i}.s19").write_text(
                    _emit(0x41 + i), encoding="ascii"
                )
                write_flow(
                    project_dir,
                    f"lane{i}",
                    [SourceBlock(f"base{i}.s19"), WriteOutBlock(f"lane{i}.s19")],
                )
            panel = await import_lanes(app, pilot, *[f"lane{i}" for i in range(8)])
            panel.query_one("#fx_mode", ModeToggle).set_mode("parallel")
            await run_lanes(app, pilot, panel)
            return project_dir

    project_dir = asyncio.run(_drive())
    for i in range(8):
        lane_file = project_dir / f"lane{i}.s19"
        assert lane_file.is_file(), f"lane {i} wrote no file: {sorted(p.name for p in project_dir.iterdir())}"
        assert _data(lane_file) == {0x1000: 0x41 + i}, (
            f"lane{i}.s19 must hold its own marker: {_data(lane_file)}"
        )


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


