"""Batch-100 increment 1 — one placement function, reuse, containment.

Covers HLR-163 / LLR-163.1-163.7 and the LLR-171.4 placement guard:

  - TC-B100-01 — LLR-163.1: one placement function holds every guard and
    decides reuse (the S7 sequence, the direct-call refusals, the wrapper
    AST shape).
  - TC-B100-02 — LLR-163.2: the size check runs before any candidate bytes
    are read.
  - TC-B100-03 — LLR-163.5: a reused variant is named, never reported added.
  - TC-B100-57 — LLR-163.6: the Split/Join export reports reuse from the
    ``PlacementResult`` of the placement it performed.
  - TC-B100-62 — LLR-171.4 (guard): containment means this work area,
    checked inside the placement; a junction destination is refused with
    nothing written outside.
  - TC-B100-68 — LLR-163.7: ``predict_placement`` walks the same candidates
    and the same free names as the placement, writing nothing.
  - AT-B100-01 — HLR-163 through the shipped surface: repeated loads reuse
    the identical file and the status names the existing variant.

Byte oracles: image comparisons go through ``tests/support/independent_reader``
(the outside reader); the two source fixtures are the E3 enabler files.
"""
from __future__ import annotations

import asyncio
import ast
import hashlib
import os
import shutil
import sys
from pathlib import Path

import pytest
from textual.widgets import Label

from s19_app.tui import workspace as workspace_mod
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import LoadFileScreen
from s19_app.tui.screens import LoadProjectScreen
from s19_app.tui.segment_split_view import SegRow
from s19_app.tui.segment_split_view import write_split_join_export
from s19_app.tui.services.project_gather_service import _gather_copy
from s19_app.tui.services.project_gather_service import gather_project_artifacts
from s19_app.tui.workspace import (
    WORKAREA_DIRNAME,
    WORKAREA_PATCHES,
    WORKAREA_SUBDIR,
    WorkareaContainmentError,
    contained_in_workarea,
    copy_into_workarea,
    find_identical,
    place_group_into_workarea,
    place_into_workarea,
    predict_placement,
)
from tests.support import b100_links
from tests.support.independent_reader import read_s19
from tests.support.b100_projects import dismiss_load_result_panel

ROOT = Path(__file__).resolve().parents[1]
CASE01 = ROOT / "examples" / "case_01_basic_valid" / "firmware.s19"
CASE02 = ROOT / "examples" / "case_02_gaps_and_patch_targets" / "firmware.s19"

#: Small VALID S19 records (checksums computed by hand) used as placement
#: payloads. ``_S19_A`` is also a project file, so every record parses clean.
_S19_A = "S11310000102030405060708090A0B0C0D0E0F1054\nS9030000FC\n"
_S19_B = "S1132000A0B0C0D0E0F00A1B1C1D1E1F101112133B\nS9030000FC\n"
_S19_C = "S1133000FFEEDDCCBBAA99887766554433221100C4\nS9030000FC\n"
#: A deliberately short record — a different size for the size-first arms.
_S19_SMALL = "S10510000102E7\nS9030000FC\n"


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _destination(base: Path, name: str = "target") -> Path:
    destination = _workarea(base) / name
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def _write(base: Path, name: str, content: str = _S19_A) -> Path:
    path = base / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="ascii")
    return path


def _snapshot_tree(root: Path) -> dict:
    """Every file under ``root`` with its size — the no-write oracle."""
    return {
        str(p.relative_to(root)): p.stat().st_size
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


async def _wait_for(pilot, predicate, description: str, attempts: int = 150) -> None:
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


def _status_text(app: S19TuiApp) -> str:
    """The painted newest status line (the ``#log_line_4`` label)."""
    return str(app.query_one("#log_line_4", Label).render())


def _file_status_text(app: S19TuiApp) -> str:
    """The painted durable file-state line (the ``#status_text`` label)."""
    return str(app.query_one("#status_text", Label).render())


# ---------------------------------------------------------------------------
# TC-B100-01 — LLR-163.1: one placement function holds every guard
# ---------------------------------------------------------------------------


def test_tc_b100_01_s7_sequence_reuses_identical_files(tmp_path: Path) -> None:
    """The S7 sequence (case_01, case_02, case_02, case_01, case_02): names
    ``firmware.s19``, ``firmware_1.s19``, ``firmware_1.s19`` (reused),
    ``firmware.s19`` (reused), ``firmware_1.s19`` (reused); two files stay
    in the destination and the wrapper still returns a ``Path``."""
    destination = _destination(tmp_path)
    expected_names = [
        "firmware.s19",
        "firmware_1.s19",
        "firmware_1.s19",
        "firmware.s19",
        "firmware_1.s19",
    ]
    expected_reused = [False, False, True, True, True]
    sequence = [CASE01, CASE02, CASE02, CASE01, CASE02]

    returned = []
    for source in sequence:
        result = place_into_workarea(source, destination)
        assert isinstance(result.path, Path)
        returned.append((result.path.name, result.reused))

    assert returned == list(zip(expected_names, expected_reused)), returned
    on_disk = sorted(p.name for p in destination.iterdir())
    assert on_disk == ["firmware.s19", "firmware_1.s19"], on_disk

    # Byte oracle (the independent reader): each landed file holds its
    # source's image.
    assert read_s19(destination / "firmware.s19").data == read_s19(CASE01).data
    assert read_s19(destination / "firmware_1.s19").data == read_s19(CASE02).data

    # The 15 call sites keep a Path: the wrapper is exercised for real.
    wrapped = copy_into_workarea(CASE02, destination)
    assert isinstance(wrapped, Path)
    assert wrapped.name == "firmware_1.s19"
    assert len(list(destination.iterdir())) == 2


def test_tc_b100_01_direct_calls_refuse_and_write_nothing(tmp_path: Path) -> None:
    """``place_into_workarea`` called directly: a destination outside every
    work area and an over-cap source are refused before anything is staged
    or written."""
    outside = tmp_path / "plain" / "target"
    with pytest.raises(WorkareaContainmentError):
        place_into_workarea(CASE01, outside)
    assert not outside.exists(), "nothing may be created outside a work area"

    destination = _destination(tmp_path)
    with pytest.raises(WorkareaContainmentError):
        place_into_workarea(CASE01, destination, max_size_bytes=10)
    assert list(destination.iterdir()) == [], "an over-cap source wrote bytes"
    assert not (_workarea(tmp_path) / "temp").exists(), (
        "an over-cap source must be refused before private staging runs"
    )


def test_tc_b100_01_wrapper_is_the_one_line_path_return() -> None:
    """LLR-163.1's structure: ``copy_into_workarea`` is exactly
    ``return place_into_workarea(...).path`` — one statement, so no guard
    and no second claim loop can live in the wrapper."""
    source = (ROOT / "s19_app" / "tui" / "workspace.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    wrapper = functions["copy_into_workarea"]
    body = [
        node
        for node in wrapper.body
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
    ]
    assert len(body) == 1, (
        "copy_into_workarea must be the one-line wrapper — every guard "
        "lives in place_into_workarea"
    )
    (only,) = body
    assert isinstance(only, ast.Return) and isinstance(only.value, ast.Attribute)
    assert only.value.attr == "path"
    assert isinstance(only.value.value, ast.Call)
    call = only.value.value
    assert isinstance(call.func, ast.Name) and call.func.id == "place_into_workarea"


def test_tc_b100_01_one_claim_loop_per_placement_kind() -> None:
    """LLR-163.1's AST threshold as amended by LED .49: exactly ONE claim
    loop per placement kind in ``workspace.py`` — the single-file kind
    (``place_into_workarea``) and the group kind
    (``place_group_into_workarea``, B99-I2a) each hold their own."""
    source = (ROOT / "s19_app" / "tui" / "workspace.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    for kind in ("place_into_workarea", "place_group_into_workarea"):
        o_excl_uses = sum(
            1
            for node in ast.walk(functions[kind])
            if isinstance(node, ast.Attribute) and node.attr == "O_EXCL"
        )
        assert o_excl_uses == 1, (
            f"{kind} must hold exactly one O_EXCL claim loop, "
            f"found {o_excl_uses}"
        )


# ---------------------------------------------------------------------------
# TC-B100-01 — LLR-163.1 boundary catalog (review finding F3)
# ---------------------------------------------------------------------------


def test_tc_b100_01_upper_case_suffix_name_is_reused_on_windows(
    tmp_path: Path,
) -> None:
    """Boundary catalog (LLR-163.1): an upper-case ``_<N>`` name on Windows
    names the same file as the requested lower-case name (candidate names
    compare case-folded) — identical bytes there are reused, nothing new is
    claimed.  Windows-only arm; the ``fold`` mutant (case-folding replaced
    by identity) turns it RED."""
    if sys.platform != "win32":
        pytest.skip(
            "case-folding of candidate names is a Windows arm (PDR C-QA-6)"
        )
    destination = _destination(tmp_path)
    existing = _write(destination, "STAGED_2.S19", _S19_B)
    source = _write(tmp_path / "src", "staged.s19", _S19_B)

    result = place_into_workarea(source, destination)
    assert result.reused
    assert result.path == existing
    assert len(list(destination.iterdir())) == 1


def test_tc_b100_01_deleted_lower_suffix_reuses_existing_suffix(
    tmp_path: Path,
) -> None:
    """Boundary catalog (LLR-163.1): with ``_1`` deleted beside an identical
    ``_2``, the placement reuses the existing ``_2`` — the candidate walk
    enumerates EVERY ``_<N>``, not only the lowest free one.  The bare-name
    mutant (comparison restricted to the requested name) turns it RED."""
    destination = _destination(tmp_path)
    existing = _write(destination, "staged_2.s19", _S19_B)
    source = _write(tmp_path / "src", "staged.s19", _S19_B)

    result = place_into_workarea(source, destination)
    assert result.reused
    assert result.path == existing
    assert len(list(destination.iterdir())) == 1


def test_tc_b100_01_link_candidate_is_never_reused(tmp_path: Path) -> None:
    """Boundary catalog (LLR-163.1): a link sitting at a ``_<N>`` candidate
    name is never reused (its bytes live outside the work area, S-F4) and
    never written through — the placement claims the next free name.  The
    link-accepting mutant (reparse skip and regular-file requirement removed
    from the candidate walk) turns it RED."""
    destination = _destination(tmp_path)
    _write(destination, "staged.s19", _S19_A)  # requested name, other bytes
    target = _write(tmp_path / "target", "staged_1.s19", _S19_B)
    try:
        os.symlink(target, destination / "staged_1.s19")
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks need privilege on this platform (PDR C-QA-6)")
    source = _write(tmp_path / "src", "staged.s19", _S19_B)

    result = place_into_workarea(source, destination)
    assert not result.reused
    assert result.path.name == "staged_2.s19", result
    link = destination / "staged_1.s19"
    assert link.is_symlink(), "the link must be left exactly as it was"
    assert target.read_text(encoding="ascii") == _S19_B


def test_tc_b100_01_zero_byte_candidate_is_never_reused(
    tmp_path: Path,
) -> None:
    """Boundary catalog (LLR-163.1): a 0-byte candidate — another writer's
    claim placeholder (PDR C1(a)) — is never reused, even when the staged
    payload is itself empty; the placement claims the next free name and the
    placeholder is left untouched.  The 0-byte-skip mutant turns it RED."""
    destination = _destination(tmp_path)
    placeholder = destination / "staged.s19"
    placeholder.write_bytes(b"")
    source = _write(tmp_path / "src", "staged.s19", "")

    result = place_into_workarea(source, destination)
    assert not result.reused
    assert result.path.name == "staged_1.s19", result
    assert placeholder.read_bytes() == b"", "the placeholder must be untouched"
    assert result.path.read_bytes() == b""


# ---------------------------------------------------------------------------
# TC-B100-02 — LLR-163.2: size before bytes
# ---------------------------------------------------------------------------


def test_tc_b100_02_size_check_runs_before_any_candidate_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Five candidates, one with the staged size: at most that one is read.
    Boundary: the same-size candidate with differing bytes is read and NOT
    reused."""
    destination = _destination(tmp_path)
    staged = _write(tmp_path, "staged.s19", _S19_B)
    sized = _write(destination, "staged_2.s19", _S19_B)
    _write(destination, "staged.s19", _S19_SMALL)  # requested name, other size
    _write(destination, "staged_1.s19", _S19_SMALL)
    _write(destination, "staged_3.s19", _S19_SMALL)
    _write(destination, "staged_4.s19", _S19_SMALL)
    assert len(_S19_B) != len(_S19_SMALL)

    real_hash = workspace_mod._hash_file
    candidate_reads: list[Path] = []

    def counting_hash(path: Path) -> str:
        if Path(path) != staged:
            candidate_reads.append(Path(path))
        return real_hash(path)

    monkeypatch.setattr(workspace_mod, "_hash_file", counting_hash)

    found = find_identical(destination, "staged.s19", staged)
    assert found == sized, found
    assert candidate_reads == [sized], (
        f"only the same-size candidate may be read, got {candidate_reads}"
    )

    # Boundary arm: the one same-size candidate now differs by its bytes —
    # it is read (counted) and not reused.
    differing = _write(destination, "staged_2.s19", _S19_C)
    assert len(_S19_B) == len(_S19_C), "the boundary needs one same-size payload"
    candidate_reads.clear()
    assert find_identical(destination, "staged.s19", staged) is None
    assert candidate_reads == [differing], candidate_reads


# ---------------------------------------------------------------------------
# TC-B100-03 — LLR-163.5: no "added" status for a reused variant
# ---------------------------------------------------------------------------


def test_tc_b100_03_reused_variant_is_named_not_added(tmp_path: Path) -> None:
    """A first load appends and reports the added variant; a repeated load
    of identical bytes names the existing variant with no added-variant
    status, and the project folder keeps one file per distinct image."""
    project_files = {"base.s19": _S19_A}

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = app.workarea / "proj"
        project_dir.mkdir(parents=True, exist_ok=True)
        for name, content in project_files.items():
            (project_dir / name).write_text(content, encoding="ascii")
        statuses: list[str] = []
        original = app.set_status
        app.set_status = lambda message: (
            statuses.append(message),
            original(message),
        )[1]
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            for _ in range(12):
                await pilot.pause()
            app.load_from_path(CASE02)
            await app.workers.wait_for_complete()
            for _ in range(12):
                await pilot.pause()
            app.load_from_path(CASE02)
            await app.workers.wait_for_complete()
            for _ in range(12):
                await pilot.pause()
            on_disk = sorted(p.name for p in project_dir.glob("*.s19"))
            return on_disk, statuses

    on_disk, statuses = asyncio.run(_drive())
    assert on_disk == ["base.s19", "firmware.s19"], on_disk
    added = [s for s in statuses if s.startswith("Added variant")]
    named = [
        s for s in statuses
        if "'firmware' already in project" in s
    ]
    assert len(added) == 1, f"exactly the first load is an add; got {statuses}"
    assert added[0] == "Added variant 'firmware' to project 'proj'", added
    assert len(named) == 1, (
        f"the repeated load names the existing variant; got {statuses}"
    )
    assert named[0] == "Variant 'firmware' already in project 'proj'", named
    # The order is the oracle: the added status belongs to the FIRST load
    # and the existing-variant status to the REPEATED one — a swapped
    # branch produces both messages in reverse and must not pass.
    assert statuses.index(added[0]) < statuses.index(named[0]), statuses


# ---------------------------------------------------------------------------
# TC-B100-57 — LLR-163.6: the export reports reuse from the placement
# ---------------------------------------------------------------------------


def _export_home(tmp_path: Path) -> Path:
    home = _workarea(tmp_path) / "splits"
    home.mkdir(parents=True, exist_ok=True)
    return home


_ISLAND_ROWS = [SegRow("isle", "manual", 0x1000, 8)]
_ISLAND_MAP = {0x1000 + i: 0x11 * (i + 1) for i in range(8)}
_ISLAND_CHANGED = {0x1000 + i: 0xFF for i in range(8)}


def _export(mem_map, home):
    return write_split_join_export(
        mem_map,
        _ISLAND_ROWS,
        mode="split",
        gap="skip",
        pad_byte=0,
        fmt="s19",
        stem="t",
        dest_dir=home,
    )


def test_tc_b100_57_identical_reexport_to_existing_suffix_is_reused(
    tmp_path: Path,
) -> None:
    """An identical re-export that matches an existing ``_<N>`` file reports
    ``reused`` and writes nothing new; changed bytes still report ``wrote``
    under the lowest free name."""
    home = _export_home(tmp_path)

    first = _export(_ISLAND_MAP, home)
    assert [p.path.name for p in first] == ["t_isle.s19"]
    assert all(p.action == "wrote" for p in first)

    again = _export(_ISLAND_MAP, home)
    assert [p.path.name for p in again] == ["t_isle.s19"]
    assert all(p.action == "reused" for p in again)

    changed = _export(_ISLAND_CHANGED, home)
    assert [p.path.name for p in changed] == ["t_isle_1.s19"]
    assert all(p.action == "wrote" for p in changed)

    # The widened reuse: the changed bytes exported again match t_isle_1 —
    # reused, zero new files, the home still holds exactly two files.
    rechanged = _export(_ISLAND_CHANGED, home)
    assert [p.path.name for p in rechanged] == ["t_isle_1.s19"], rechanged
    assert all(p.action == "reused" for p in rechanged)
    assert sorted(p.name for p in home.iterdir()) == [
        "t_isle.s19",
        "t_isle_1.s19",
    ]
    assert read_s19(home / "t_isle.s19").data == _ISLAND_MAP
    assert read_s19(home / "t_isle_1.s19").data == _ISLAND_CHANGED


def test_tc_b100_57_export_holds_no_byte_identity_rule() -> None:
    """Census: the export module decides its ``reused``/``wrote`` word only
    from the placement outcome — its own byte-identity rule is gone — and
    the package holds its byte-identity census BY BEHAVIOUR (a
    ``read_bytes() ==`` comparison or a ``_hash_file`` digest compare), not
    by the name ``find_identical``: the single-file rule is
    ``_match_identical``/``find_identical`` in ``workspace.py``; the only
    other rule is the declared one — the group's frozen rule (R30,
    ``place_group_into_workarea``). Inc 2 fix pass 5 (security finding
    SEC2-7, round 4) re-pinned this census: the gather's sibling byte-scan
    is RETIRED — ``project_gather_service`` places through
    ``place_into_workarea`` and translates only its ``reused`` flag, so the
    placement's rule is the sole judge and no second rule can disagree
    with it (the case-variant deletion SEC2-7's probe executed). A new
    rule under any other name, or a deleted declared one, fails the
    census.
    """
    package = ROOT / "s19_app"
    export_source = (package / "tui" / "segment_split_view.py").read_text(
        encoding="utf-8"
    )
    assert "_export_reuse_target" not in export_source, (
        "the export's own byte-identity rule is retired (LLR-163.6)"
    )
    assert "read_bytes" not in export_source, (
        "the export must not compare file bytes itself"
    )
    assert "find_identical" not in export_source, (
        "no separate find_identical call may decide the export's word"
    )
    assert ".reused" in export_source, (
        "the status word must come from the PlacementResult the placement returned"
    )
    the_single_file_rule = {
        ("s19_app/tui/workspace.py", "_match_identical"),
        ("s19_app/tui/workspace.py", "find_identical"),
    }
    declared_other_rules = {
        # The group's frozen reuse rule (R30, B99-I2a) — converted by no
        # increment; it stays "requested names only".
        ("s19_app/tui/workspace.py", "place_group_into_workarea"),
        # Inc 7 corrective pass 2 (SEC7-R2-4): not a reuse rule — the
        # rollback compares project.json with the previous bytes to decide
        # whether the kept project.json.previous-<UTC> copy may go.
        ("s19_app/tui/app.py", "_abort_save"),
    }
    found: set = set()
    for path in sorted(package.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                compares_bytes = (
                    isinstance(sub, ast.Compare)
                    and isinstance(sub.left, ast.Call)
                    and isinstance(sub.left.func, ast.Attribute)
                    and sub.left.func.attr == "read_bytes"
                )
                hashes_file = (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id == "_hash_file"
                )
                if compares_bytes or hashes_file:
                    found.add((rel, node.name))
    assert the_single_file_rule <= found, (
        f"the single-file byte-identity rule is gone: missing "
        f"{the_single_file_rule - found}"
    )
    assert found - the_single_file_rule == declared_other_rules, (
        f"byte-identity census drifted: unexpected "
        f"{found - the_single_file_rule - declared_other_rules}, "
        f"declared-but-missing "
        f"{declared_other_rules - (found - the_single_file_rule)}"
    )


# ---------------------------------------------------------------------------
# TC-B100-62 — LLR-171.4 (guard): containment means this work area
# ---------------------------------------------------------------------------


def test_tc_b100_62_containment_predicate(tmp_path: Path) -> None:
    """``contained_in_workarea`` resolves links and junctions, then asks
    whether the path is inside the given work area — never inside some
    other ``.s19tool/workarea``."""
    workarea = _workarea(tmp_path)
    inside = workarea / "proj" / "firmware.s19"
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_text(_S19_A, encoding="ascii")
    assert contained_in_workarea(inside, workarea)
    assert contained_in_workarea(workarea, workarea)
    assert not contained_in_workarea(tmp_path / "elsewhere" / "f.s19", workarea)
    other_workarea = tmp_path / "other" / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    assert not contained_in_workarea(other_workarea / "x.s19", workarea)


def test_tc_b100_62_junction_destination_is_refused_nothing_written(
    tmp_path: Path,
) -> None:
    """The S-02 guard: a destination that reaches its bytes through a
    junction into another directory is refused — zero bytes land outside
    this work area.  Windows-only arm (junctions need no privilege there);
    every other platform skips with the named reason (PDR C-QA-6)."""
    b100_links.require_junctions()

    # Arm 1: a junction at the ``.s19tool`` level pointing at a real,
    # fully-formed DIFFERENT work area (the executed S-02 shape).
    other = tmp_path / "other"
    other_target = other / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "target"
    other_target.mkdir(parents=True, exist_ok=True)
    base = tmp_path / "base"
    base.mkdir(parents=True, exist_ok=True)
    b100_links.create_junction(base / WORKAREA_DIRNAME, other / WORKAREA_DIRNAME)
    with pytest.raises(WorkareaContainmentError):
        place_into_workarea(
            CASE01, base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "target"
        )
    assert list(other_target.iterdir()) == [], "bytes escaped through the junction"
    assert not (base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "temp").exists()

    # Arm 2: a junction one level deeper, inside this work area's own
    # tree, pointing outside it.
    deep_base = tmp_path / "deep"
    deep_workarea = _workarea(deep_base)
    deep_workarea.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir(parents=True, exist_ok=True)
    b100_links.create_junction(deep_workarea / "alias", outside)
    with pytest.raises(WorkareaContainmentError):
        place_into_workarea(CASE01, deep_workarea / "alias")
    assert list(outside.iterdir()) == [], "bytes escaped through the junction"
    assert not (deep_workarea / "temp").exists()


def _junctioned_home(tmp_path: Path, base_name: str, victim_base: str, sub: str):
    """A destination ``<base>/.s19tool/workarea/<sub>`` created as a junction
    into a fully-formed OTHER work area — the S-02 shape at a caller's
    destination.  Returns (app_base, destination, victim_home)."""
    victim_home = _workarea(tmp_path / victim_base) / sub
    victim_home.mkdir(parents=True)
    base = tmp_path / base_name
    destination = _workarea(base) / sub
    destination.parent.mkdir(parents=True)
    b100_links.create_junction(destination, victim_home)
    return base, destination, victim_home


def test_tc_b100_62_export_junction_unresolved_destination_refused(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .49), review finding F1: the export passes
    its destination UNRESOLVED through the shared guard — a junction at the
    destination refuses the WHOLE export (s19 and bin alike), 0 bytes in the
    victim.  Windows-only arm."""
    b100_links.require_junctions()
    base, destination, victim_home = _junctioned_home(
        tmp_path, "app", "victimbase", "P/exports"
    )

    for fmt in ("s19", "bin"):
        with pytest.raises(WorkareaContainmentError):
            write_split_join_export(
                _ISLAND_MAP,
                _ISLAND_ROWS,
                mode="split",
                gap="skip",
                pad_byte=0,
                fmt=fmt,
                stem="t",
                dest_dir=destination,
            )
    assert list(victim_home.iterdir()) == [], "bytes escaped through the junction"
    assert not (_workarea(base) / "temp").exists(), (
        "a refused export must not even stage"
    )


def test_tc_b100_62_group_junction_unresolved_destination_refused(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .49), review finding F1: the group
    placement (BIN + ``.addr`` sidecar) runs the SAME shared guard on the
    UNRESOLVED destination — a junction there refuses the group, 0 bytes in
    the victim.  Windows-only arm."""
    b100_links.require_junctions()
    base, destination, victim_home = _junctioned_home(
        tmp_path, "app", "victimbase", "P/exports"
    )
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    bin_source = src_dir / "isle.bin"
    bin_source.write_bytes(b"\x11\x22\x33\x44")
    addr_source = src_dir / "isle.addr"
    addr_source.write_text("0x1000\n", encoding="ascii")

    with pytest.raises(WorkareaContainmentError):
        place_group_into_workarea([bin_source, addr_source], destination)
    assert list(victim_home.iterdir()) == [], "bytes escaped through the junction"
    assert not (_workarea(base) / "temp").exists(), (
        "a refused group must not even stage"
    )


def test_tc_b100_62_gather_junction_unresolved_destination_refused(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .49), review finding F1: Save project's
    gather passes its home UNRESOLVED through the shared guard — a junction
    at the home refuses the copy, 0 bytes in the victim.  Windows-only arm."""
    b100_links.require_junctions()
    base, destination, victim_home = _junctioned_home(
        tmp_path, "app", "victimbase", "P/patches"
    )
    source = _write(tmp_path / "src", "hotfix.json", "{}")

    with pytest.raises(WorkareaContainmentError):
        _gather_copy(source, destination)
    assert list(victim_home.iterdir()) == [], "bytes escaped through the junction"
    assert not (_workarea(base) / "temp").exists(), (
        "a refused gather must not even stage"
    )


def test_tc_b100_62_explicit_root_refuses_another_workarea(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .49), review finding F2: the guard's
    explicit-root limb — an app-level caller that passes THIS work area's
    root sees a destination resolving into ANOTHER work area refused by the
    resolved-pair comparison (``contained_in_workarea``), the check the
    textual walk alone cannot make.  Removing that refusal writes into the
    other work area (mutant ``contained``, transcript ``mut-F2.txt``)."""
    this_root = _workarea(tmp_path / "this")
    this_root.mkdir(parents=True)
    other_home = _workarea(tmp_path / "other") / "victim"
    other_home.mkdir(parents=True)

    with pytest.raises(WorkareaContainmentError):
        place_into_workarea(CASE01, other_home, workarea_root=this_root)
    assert list(other_home.iterdir()) == [], (
        "bytes escaped into the other work area"
    )
    assert not (this_root / "temp").exists()


# ---------------------------------------------------------------------------
# TC-B100-62 — LED .50 / SEC-1: app routes hand the root; paths stay
# unresolved; the derived-root walk reaches the OUTERMOST anchor (N1)
# ---------------------------------------------------------------------------


def _other_workarea_home(tmp_path: Path, sub: str = "victim"):
    """A destination that textually lives inside ANOTHER, fully-formed work
    area — the shape an app route now hands over when a junctioned project
    folder was resolved before the guard existed to see it (SEC-1).  No
    junction sits on the textual path, so ONLY the explicit root can refuse
    it.  Returns (this_root, destination, victim_home)."""
    this_root = _workarea(tmp_path / "this")
    this_root.mkdir(parents=True)
    victim_home = _workarea(tmp_path / "other") / sub
    victim_home.mkdir(parents=True)
    return this_root, victim_home, victim_home


def _nested_anchor_home(tmp_path: Path, sub: str = "x"):
    """A destination ``<this wa>/nest/.s19tool/workarea/<sub>`` where ``nest``
    is a junction into a folder holding ANOTHER ``.s19tool/workarea`` — the
    executed nested-anchor shape (review finding N1).  The textual path holds
    TWO anchors; only the OUTERMOST-anchor walk checks the ``nest`` junction.
    Returns (this_root, destination, victim_home)."""
    b100_links.require_junctions()
    victim_home = _workarea(tmp_path / "other") / sub
    victim_home.mkdir(parents=True)
    this_root = _workarea(tmp_path / "this")
    this_root.mkdir(parents=True)
    b100_links.create_junction(this_root / "nest", tmp_path / "other")
    destination = (
        this_root / "nest" / WORKAREA_DIRNAME / WORKAREA_SUBDIR / sub
    )
    return this_root, destination, victim_home


def test_tc_b100_01_app_placements_name_the_workarea_root() -> None:
    """LLR-163.1 / LLR-171.4 (LED .50), security finding SEC-1 — the AST
    census: EVERY placement call in ``app.py`` names ``workarea_root``
    explicitly, so the guard's containment authority is always THIS app's
    work area (B100-I14), never one the destination's own text names.
    Dropping the root from any single call turns this RED (transcript
    ``mut-census-root.txt``)."""
    source = (ROOT / "s19_app" / "tui" / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    placements = (
        "place_into_workarea",
        "copy_into_workarea",
        "place_group_into_workarea",
    )
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in placements
    ]
    # batch-100 Inc 5 re-pin (LLR-167.6): Save project's three placement
    # calls (image, MAC, A2L) became ONE call inside the plan-row loop, so
    # 9 -> 7; the emitted image is placed by ``save_patched_image`` and its
    # root is threaded through the two emit entry points checked below.
    assert len(calls) == 7, (
        f"expected the 7 app.py placement calls (LED .50), found {len(calls)}"
    )
    emit_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("save_patched", "emit_and_verify")
    ]
    assert len(emit_calls) == 2, (
        f"expected the 2 app.py emit calls (LED .56), found {len(emit_calls)}"
    )
    for call in calls + emit_calls:
        name = getattr(call.func, "id", None) or call.func.attr
        assert any(keyword.arg == "workarea_root" for keyword in call.keywords), (
            f"app.py call {name} at line {call.lineno} must pass "
            "workarea_root explicitly (LED .50, SEC-1, SEC-4)"
        )


def test_tc_b100_62_variant_append_root_refuses_another_workarea(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .50), SEC-1 — the variant-append route:
    ``_sync_loaded_file_to_project`` places through ``place_into_workarea``
    with ``workarea_root=self.workarea``; a destination textually inside
    ANOTHER work area is refused by the resolved-pair comparison, 0 bytes
    outside this work area.  Dropping the root from the placement accepts
    the destination (RED, transcript ``red-07-routes.txt``)."""
    this_root, destination, victim_home = _other_workarea_home(tmp_path, "P")

    with pytest.raises(WorkareaContainmentError):
        place_into_workarea(CASE01, destination, workarea_root=this_root)
    assert list(victim_home.iterdir()) == [], "bytes escaped into the other work area"
    assert not (this_root / "temp").exists(), (
        "a refused placement must not even stage"
    )


def test_tc_b100_62_save_copies_root_refuses_another_workarea(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .50), SEC-1 — the Save project copies
    (primary data, attached MAC, A2L): ``copy_into_workarea`` now accepts and
    forwards ``workarea_root``; a target textually inside ANOTHER work area
    refuses every copy, 0 bytes outside.  Dropping the root from the wrapper
    accepts the destination (RED, transcript ``red-08-save-copies.txt``)."""
    this_root, destination, victim_home = _other_workarea_home(tmp_path, "P")
    mac_source = _write(tmp_path / "src", "firmware.mac", _S19_SMALL)
    a2l_source = _write(tmp_path / "src", "firmware.a2l", "ASAP2_VERSION 1 71\n")

    for source in (CASE01, mac_source, a2l_source):
        with pytest.raises(WorkareaContainmentError):
            copy_into_workarea(source, destination, workarea_root=this_root)
    assert list(victim_home.iterdir()) == [], "bytes escaped into the other work area"
    assert not (this_root / "temp").exists(), (
        "a refused save must not even stage"
    )


def test_tc_b100_62_syncs_root_refuses_another_workarea(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .50), SEC-1 — the MAC/A2L sync routes:
    the same ``copy_into_workarea(..., workarea_root=self.workarea)`` seam
    refuses a project dir textually inside ANOTHER work area, 0 bytes
    outside.  RED side: ``red-08-save-copies.txt`` (the same wrapper
    revert)."""
    this_root, destination, victim_home = _other_workarea_home(tmp_path, "P")
    mac_source = _write(tmp_path / "src", "firmware.mac", _S19_SMALL)
    a2l_source = _write(tmp_path / "src", "firmware.a2l", "ASAP2_VERSION 1 71\n")

    for source in (mac_source, a2l_source):
        with pytest.raises(WorkareaContainmentError):
            copy_into_workarea(source, destination, workarea_root=this_root)
    assert list(victim_home.iterdir()) == [], "bytes escaped into the other work area"
    assert not (this_root / "temp").exists(), (
        "a refused sync must not even stage"
    )


def test_tc_b100_62_gather_root_refuses_another_workarea(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .50), SEC-1 — the Save-project gather:
    ``_gather_copy`` threads ``workarea_root`` from
    ``gather_project_artifacts`` (from ``_handle_save_dialog``) through
    ``_check_home_contained`` AND the placement; a home textually inside
    ANOTHER work area refuses the copy, 0 bytes outside.  Dropping the root
    from the gather accepts the home (RED, transcript ``red-09-gather.txt``).
    """
    this_root, destination, victim_home = _other_workarea_home(tmp_path, "P/patches")
    source = _write(tmp_path / "src", "hotfix.json", "{}")

    with pytest.raises(WorkareaContainmentError):
        _gather_copy(source, destination, workarea_root=this_root)
    assert list(victim_home.iterdir()) == [], "bytes escaped into the other work area"
    assert not (this_root / "temp").exists(), (
        "a refused gather must not even stage"
    )


def test_tc_b100_62_export_root_refuses_another_workarea(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .50), SEC-1 — the Split/Join export:
    ``write_split_join_export`` threads the caller's ``workarea_root`` to
    the guard AND both placements; a destination textually inside ANOTHER
    work area refuses the WHOLE export (s19 and bin alike), 0 bytes
    outside.  Dropping the root from the export accepts the destination
    (RED, transcript ``red-10-export.txt``)."""
    this_root, destination, victim_home = _other_workarea_home(tmp_path, "P/exports")

    for fmt in ("s19", "bin"):
        with pytest.raises(WorkareaContainmentError):
            write_split_join_export(
                _ISLAND_MAP,
                _ISLAND_ROWS,
                mode="split",
                gap="skip",
                pad_byte=0,
                fmt=fmt,
                stem="t",
                dest_dir=destination,
                workarea_root=this_root,
            )
    assert list(victim_home.iterdir()) == [], "bytes escaped into the other work area"
    assert not (this_root / "temp").exists(), (
        "a refused export must not even stage"
    )


def test_tc_b100_62_export_junctioned_base_app_root_writes(
    tmp_path: Path,
) -> None:
    """LLR-163.1 / LLR-171.4 (LED .50), review finding R3-1: an app whose
    base folder is reached THROUGH a junction (the work area lives under a
    junctioned folder) exports exactly its one file INTO the work area when
    the caller passes the app's root — the export's own home guard resolves
    the pair once, then the placements re-run the guard on the UNRESOLVED
    destination with the CALLER'S (unresolved) root, so the base folder's
    own junction sits above the walked span and the bytes write.  Rebinding
    the placements' root to the RESOLVED root instead refuses with
    'traverses a symbolic link' (the reviewer's probe
    ``r3_export_junctioned_base.py`` is the RED side; it WROTE at base and
    after fix pass 1).  Windows-only arm."""
    b100_links.require_junctions()
    real = tmp_path / "real_home"
    real.mkdir()
    linked = b100_links.create_junction(tmp_path / "linked_home", real)
    wa = _workarea(linked)
    dest = wa / "P" / "exports"
    dest.mkdir(parents=True)

    written = write_split_join_export(
        _ISLAND_MAP,
        _ISLAND_ROWS,
        mode="split",
        gap="skip",
        pad_byte=0,
        fmt="s19",
        stem="t",
        dest_dir=dest,
        workarea_root=wa,
    )
    assert [p.path.name for p in written] == ["t_isle.s19"], written
    assert all(p.action == "wrote" for p in written), written
    # The bytes landed at the REAL work area (the junction's target) —
    # exactly one file, byte-oracle clean, staging temp removed.
    real_home = _workarea(real) / "P" / "exports"
    assert sorted(p.name for p in real_home.iterdir()) == ["t_isle.s19"]
    assert read_s19(real_home / "t_isle.s19").data == _ISLAND_MAP
    # The staging landed under the REAL work area too (the resolved root) and
    # the per-write stage dir was removed — the shared ``temp/.staging``
    # home itself persists by design (LLR-155.1).
    staging = _workarea(real) / "temp"
    assert staging.exists()
    assert list(staging.rglob("stage-*")) == [], (
        "the per-write private staging dir is removed after a successful export"
    )


def test_tc_b100_62_gather_requires_workarea_root(
    tmp_path: Path,
) -> None:
    """R3-3 (LED .50, SEC-1): ``gather_project_artifacts`` takes its
    ``workarea_root`` keyword-only with NO default — a caller that omits it
    gets ``TypeError`` at the boundary, never the default-unsafe API whose
    ``None`` derived the root from the project's own textual path (the
    reviewer's probe ``r3_gather_projjunction.py`` WROTE into the victim
    work area through a junctioned project folder that way; with the root
    passed, the same setup refuses)."""
    project = _workarea(tmp_path / "base") / "proj"
    project.mkdir(parents=True)
    patches = _workarea(tmp_path / "base") / WORKAREA_PATCHES
    patches.mkdir(parents=True)

    with pytest.raises(TypeError):
        gather_project_artifacts(
            project,
            common_patches_dir=patches,
            common_templates_dir=tmp_path / "base" / WORKAREA_DIRNAME / "templates",
        )


def test_tc_b100_62_nested_anchor_junction_refused_without_root(
    tmp_path: Path,
) -> None:
    """LLR-163.1 (LED .50), review finding N1: with NO explicit root, the
    derived-root reparse walk runs up to the OUTERMOST ``.s19tool/workarea``
    anchor — a junction BETWEEN this work area and a NESTED anchor
    (``<wa>/nest`` -> a folder holding another ``.s19tool/workarea``) is
    checked and refused, 0 bytes in the victim.  Reverting the walk to the
    NEAREST anchor accepts the destination (mutation ``mut-n1-outermost.txt``
    is the RED side).  Windows-only arm."""
    this_root, destination, victim_home = _nested_anchor_home(tmp_path)

    with pytest.raises(WorkareaContainmentError):
        place_into_workarea(CASE01, destination)
    assert list(victim_home.iterdir()) == [], "bytes escaped through the nested anchor"
    assert not (this_root / "temp").exists(), (
        "a refused placement must not even stage"
    )


def test_tc_b100_62_explicit_root_refuses_nested_anchor(
    tmp_path: Path,
) -> None:
    """LLR-171.4 (LED .50), review finding N1, the explicit-root half: the
    same nested-anchor destination handed over WITH ``workarea_root`` is
    refused by the reparse walk (which now runs to the outermost anchor) and
    by the resolved-pair containment alike — either limb alone suffices,
    0 bytes in the victim.  Windows-only arm."""
    this_root, destination, victim_home = _nested_anchor_home(tmp_path)

    with pytest.raises(WorkareaContainmentError):
        place_into_workarea(CASE01, destination, workarea_root=this_root)
    assert list(victim_home.iterdir()) == [], "bytes escaped through the nested anchor"
    assert not (this_root / "temp").exists(), (
        "a refused placement must not even stage"
    )


def test_tc_b100_62_invalid_path_spelling_is_a_containment_refusal(
    tmp_path: Path,
) -> None:
    """LLR-163.1 (security finding SEC-2): a destination with an invalid
    path spelling (``"`` is illegal in a Windows path) raises the
    containment refusal — ``WorkareaContainmentError``, message leading
    with the outcome — never a bare ``OSError`` (WinError 123) past callers
    that only catch the containment class.  Windows-only arm; removing the
    SEC-2 wraps turns it RED (transcript ``red-11-sec2.txt``)."""
    if sys.platform != "win32":
        pytest.skip("WinError 123 invalid-spelling arm is Windows-only (PDR C-QA-6)")
    destination = _workarea(tmp_path / "base") / 'bad"name'

    with pytest.raises(WorkareaContainmentError) as excinfo:
        place_into_workarea(CASE01, destination)
    assert str(excinfo.value).startswith("Refusing to place"), (
        "the refusal must lead with the outcome (UX-C4)"
    )


def test_tc_b100_62_upper_case_anchor_is_accepted_on_windows(
    tmp_path: Path,
) -> None:
    """Review finding F8/N4: on Windows the anchor parts compare
    case-insensitively — a legitimately created ``.S19TOOL\\WORKAREA`` names
    the same seam and is ACCEPTED (a form the old resolve-first code
    accepted).  The ``anchorcase`` mutant (fold -> identity) is equivalent
    here — the 8.3 fallback resolves the form anyway — which packet §6
    declares.  Windows-only arm."""
    if sys.platform != "win32":
        pytest.skip("case-insensitive anchor names are a Windows arm (PDR C-QA-6)")
    destination = tmp_path / "base" / ".S19TOOL" / "WORKAREA" / "target"
    destination.mkdir(parents=True)

    result = place_into_workarea(CASE01, destination)
    assert result.path.name == "firmware.s19", result
    assert read_s19(result.path).data == read_s19(CASE01).data
    assert contained_in_workarea(result.path, _workarea(tmp_path / "base"))


def test_tc_b100_62_short_name_anchor_is_accepted_on_windows(
    tmp_path: Path,
) -> None:
    """Review finding F8/N4: the 8.3 short-name fallback accepts a
    destination whose anchor survives only in a non-canonical spelling
    (``S19TOO~1\\WORKAR~1``) — reparse-checked per component BEFORE any
    resolution, so the non-canonical form cannot hide a junction.  Removing
    the fallback turns this RED (transcript ``red-12-shortname.txt``).
    Windows-only arm; skips with a named reason where the volume carries no
    8.3 names (PDR C-QA-6)."""
    if sys.platform != "win32":
        pytest.skip("8.3 short-name anchors are a Windows arm (PDR C-QA-6)")
    long_anchor = _workarea(tmp_path / "base")
    destination = _destination(tmp_path / "base")
    short_anchor = b100_links.short_path_name(long_anchor)
    if short_anchor is None:
        pytest.skip("this volume carries no 8.3 short names (PDR C-QA-6)")
    short_destination = short_anchor / "target"

    result = place_into_workarea(CASE01, short_destination)
    assert result.path.name == "firmware.s19", result
    assert read_s19(result.path).data == read_s19(CASE01).data
    # The bytes landed at the LONG-form name — the short spelling named
    # the same seam.
    assert (destination / "firmware.s19").exists()
    assert read_s19(destination / "firmware.s19").data == read_s19(CASE01).data


def test_tc_b100_57_group_word_compares_case_folded(
    tmp_path: Path,
) -> None:
    """LLR-163.6 (review finding N5, the F5 acceptance condition): the
    group's ``reused``/``wrote`` word compares the returned names against
    the pre-listing CASE-FOLDED on Windows — a reused group whose on-disk
    names differ only in case from the requested spelling reads as
    ``reused``, never a false ``wrote``.  Windows-only arm (case-insensitive
    reuse naming); the case-exact comparison turns it RED (transcript
    ``red-13-n5.txt``)."""
    if sys.platform != "win32":
        pytest.skip("case-folded group word is a Windows arm (PDR C-QA-6)")
    home = _export_home(tmp_path)

    def _bin_export():
        return write_split_join_export(
            _ISLAND_MAP,
            _ISLAND_ROWS,
            mode="split",
            gap="skip",
            pad_byte=0,
            fmt="bin",
            stem="t",
            dest_dir=home,
        )

    first = _bin_export()
    assert all(p.action == "wrote" for p in first), first
    # The same bytes, re-exported after a case-only rename on disk: the
    # group is reused, and the word must say so.
    for placed in first:
        placed.path.rename(placed.path.with_name(placed.path.name.upper()))

    again = _bin_export()
    assert sorted(p.path.name for p in again) == ["t_isle.addr", "t_isle.bin"], again
    assert all(p.action == "reused" for p in again), (
        f"a case-only rename must not read as 'wrote': {again}"
    )


# ---------------------------------------------------------------------------
# TC-B100-68 — LLR-163.7: predict_placement uses the placement code itself
# ---------------------------------------------------------------------------


def test_tc_b100_68_prediction_walks_the_same_names_as_the_placement(
    tmp_path: Path,
) -> None:
    """A directory named ``firmware_1.s19`` occupies the name for the
    prediction exactly as it does for the placement: both walk past it to
    ``firmware_2.s19``."""
    destination = _destination(tmp_path)
    _write(destination, "firmware.s19", _S19_A)
    (destination / "firmware_1.s19").mkdir()
    source = _write(tmp_path / "src", "firmware.s19", _S19_B)

    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    predicted = predict_placement(
        digest, source.stat().st_size, destination, "firmware.s19"
    )
    assert predicted.path.name == "firmware_2.s19", predicted
    assert not predicted.reused

    placed = place_into_workarea(source, destination)
    assert placed.path == predicted.path
    assert placed.reused == predicted.reused


def test_tc_b100_68_identical_bytes_predict_reused_and_write_nothing(
    tmp_path: Path,
) -> None:
    """With identical bytes already present the prediction is ``reused`` at
    the existing name; a prediction writes nothing (the tree is unchanged);
    the placement then agrees with the prediction."""
    destination = _destination(tmp_path)
    _write(destination, "firmware.s19", _S19_B)
    source = _write(tmp_path / "src", "firmware.s19", _S19_B)
    payload = source.read_bytes()
    before = _snapshot_tree(tmp_path)

    predicted = predict_placement(payload, len(payload), destination, "firmware.s19")
    assert predicted.reused
    assert predicted.path == destination / "firmware.s19"
    assert _snapshot_tree(tmp_path) == before, "a prediction must write nothing"

    placed = place_into_workarea(source, destination)
    assert placed.path == predicted.path
    assert placed.reused == predicted.reused


def test_tc_b100_68_relative_destination_matches_placed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``predict_placement`` answers in the SAME path FORM the placement
    returns (resolved — review finding F4): with a relative destination the
    predicted path equals the landed path exactly, so the Inc 5 save-plan
    comparison cannot false-mismatch."""
    monkeypatch.chdir(tmp_path)
    rel_destination = Path(WORKAREA_DIRNAME) / WORKAREA_SUBDIR / "target"
    rel_destination.mkdir(parents=True)
    source = _write(tmp_path / "src", "firmware.s19", _S19_B)
    payload = source.read_bytes()

    predicted = predict_placement(
        hashlib.sha256(payload).hexdigest(),
        len(payload),
        rel_destination,
        "firmware.s19",
    )
    placed = place_into_workarea(source, rel_destination)
    assert predicted.path == placed.path, (
        f"predicted {predicted.path}, placed {placed.path}"
    )
    assert predicted.path.is_absolute()
    assert not predicted.reused and not placed.reused


def test_tc_b100_68_forced_claim_between_prediction_and_placement(
    tmp_path: Path,
) -> None:
    """A claim that lands between the prediction and the placement makes
    the two diverge — the mismatch names both paths.  (The handler-side
    mismatch REPORT rides the save plan at a later increment, B100-I17.)"""
    destination = _destination(tmp_path)
    source = _write(tmp_path / "src", "firmware.s19", _S19_B)
    payload = source.read_bytes()

    predicted = predict_placement(payload, len(payload), destination, "firmware.s19")
    assert predicted.path == destination / "firmware.s19"

    # A concurrent writer claims the predicted name with other bytes.
    _write(destination, "firmware.s19", _S19_A)

    placed = place_into_workarea(source, destination)
    assert placed.path != predicted.path, (
        f"prediction/placement mismatch: predicted {predicted.path}, "
        f"landed {placed.path}"
    )
    assert placed.path.name == "firmware_1.s19"


# ---------------------------------------------------------------------------
# AT-B100-01 — HLR-163 through the shipped surface (black-box)
# ---------------------------------------------------------------------------


async def _open_project(pilot, app: S19TuiApp, name: str) -> None:
    """Open a project through the Load project dialog: rail key ``p``,
    click the named row, confirm with ``#project_ok``."""
    await pilot.press("p")
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadProjectScreen),
        "the Load project dialog",
    )
    row = next(
        item
        for item in app.screen.query("#project_list ListItem")
        if str(item.query_one(Label).render()) == name
    )
    await pilot.click(row)
    assert await pilot.click("#project_ok"), "click missed #project_ok"
    await _wait_for(
        pilot,
        lambda: f"Loaded project '{name}'" in _status_text(app),
        f"the status naming the loaded project {name}",
    )
    # Inc 6 (HLR-178): the dialog route opens the Load-result panel;
    # dismiss it first with its shown key ``esc``.
    await dismiss_load_result_panel(pilot, app)


async def _load_file_through_dialog(pilot, app: S19TuiApp, src: Path) -> None:
    """Drive the Load file dialog (rail key ``l``) and wait for the load.

    The load's ``#log_line_4`` line can be pushed off by the project sync
    within one paint, so the settle condition is the DURABLE
    ``#status_text`` file-state line plus the dialog being closed — both
    painted, both black-box observable.
    """
    await pilot.press("l")
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadFileScreen),
        "the Load file dialog",
    )
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*str(src))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await _wait_for(
        pilot,
        lambda: not isinstance(app.screen, LoadFileScreen)
        and _file_status_text(app).startswith("Loaded "),
        f"the durable load line after loading {src.name}",
    )


@pytest.mark.parametrize("size", [(118, 54), (220, 60)])
def test_at_b100_01_repeated_loads_reuse_and_name_existing_variant(
    tmp_path: Path, size: tuple
) -> None:
    """Five loads through the shipped surface — case_01, case_02, then each
    again: the work area holds two image files, the project folder holds two
    data files, and every repeated load's painted status names the existing
    variant instead of reporting an add."""
    base = tmp_path / "app"
    source_copies = tmp_path / "sources"
    # The variant id is the file's stem, so both sources keep the
    # ``firmware.s19`` name (in separate folders — they differ in bytes).
    src01 = source_copies / "case01" / "firmware.s19"
    src01.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CASE01, src01)
    src02 = source_copies / "case02" / "firmware.s19"
    src02.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CASE02, src02)

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=base)
        project_dir = app.workarea / "P"
        project_dir.mkdir(parents=True, exist_ok=True)
        # A project needs at least one data file to load; the MAC seeds it
        # without colliding with the two firmware images under test.
        shutil.copy2(
            ROOT / "examples" / "case_01_basic_valid" / "firmware.mac",
            project_dir / "firmware.mac",
        )
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _open_project(pilot, app, "P")
            await _load_file_through_dialog(pilot, app, src01)
            await _wait_for(
                pilot,
                lambda: "Added variant 'firmware' to project 'P'" in _status_text(app),
                "the first load's added-variant status",
            )
            await _load_file_through_dialog(pilot, app, src02)
            await _wait_for(
                pilot,
                lambda: "Added variant 'firmware_1' to project 'P'" in _status_text(app),
                "the second load's added-variant status",
            )
            # The repeated loads: the painted status names the existing
            # variant and never reports an add.
            await _load_file_through_dialog(pilot, app, src01)
            await _wait_for(
                pilot,
                lambda: "Variant 'firmware' already in project 'P'" in _status_text(app),
                "the repeated case_01 load naming the existing variant",
            )
            repeated_01 = _status_text(app)
            assert "Added variant" not in repeated_01, repeated_01
            await _load_file_through_dialog(pilot, app, src02)
            await _wait_for(
                pilot,
                lambda: "Variant 'firmware_1' already in project 'P'" in _status_text(app),
                "the repeated case_02 load naming the existing variant",
            )
            repeated_02 = _status_text(app)
            assert "Added variant" not in repeated_02, repeated_02
            temp_files = sorted(
                p.name for p in (app.workarea / "temp").iterdir() if p.is_file()
            )
            project_files = sorted(p.name for p in project_dir.glob("*.s19"))
            return temp_files, project_files

    temp_files, project_files = asyncio.run(_drive())
    assert temp_files == ["firmware.s19", "firmware_1.s19"], temp_files
    assert project_files == ["firmware.s19", "firmware_1.s19"], project_files
    workarea = _workarea(base)
    assert read_s19(workarea / "temp" / "firmware.s19").data == read_s19(CASE01).data
    assert read_s19(workarea / "temp" / "firmware_1.s19").data == read_s19(CASE02).data
