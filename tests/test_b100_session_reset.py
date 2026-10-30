"""Batch 100 — Increment 3: a project load starts clean (HLR-165).

White-box TCs:

- TC-B100-08 (LLR-165.1): one reset seam, called once per project load,
  after validation and before the first install; a loose Load file never
  triggers it; exactly one call site in ``s19_app/``.
- TC-B100-09 (LLR-165.2): ``_session_snapshot()`` — the domain is DERIVED
  from the live source by a census at test time (C-31), never hand-listed;
  two cold loads of the same project project equal snapshots (the stat-key
  normaliser proof, QA R2-07); a load of P2 over P1 differs from a cold P2
  load only in the declared K1/K2 allow-list; and the load leaves no P1
  state behind (the executed P-2 / p03 leak names).
- TC-B100-10 (LLR-165.3): the change service is rebound (new object, empty
  document, empty history, the app's image generation re-pushed), a worker
  that captured the outgoing service finishes against it across a load-over
  (the boundary arm), and the interim notice (LED-2026-10-26-batch-100.55(a))
  names the closed Patch Editor document a project load discards.
- TC-B100-11 (LLR-165.4): ``_apply_unload("all" | "a2l")`` clears the
  parsed A2L (P-25: today's code clears the path only, so the tags survive
  a bare-S19 reload through the parse fallback).

Black-box AT:

- AT-B100-03 (HLR-165): through the shipped surface — Load project
  dialog, the Patch Editor rail screen, Save project — a load of P2 over
  unsaved P1 work saves only P2's files. Runs at 118x54 and 220x60 with
  notifications on. The P1 entry is added through the panel's own inputs;
  from Inc 10 on this AT answers the load question with ``y`` (LED .55(a)'s
  notice is observed here until then). The AT also asserts HLR-165's
  painted observables after the load-over: the Patch Editor ledger is
  empty (0 rows + the empty-state line), the paste buffer is empty and
  the SCRIPT window subtitle carries no dirty ``●`` (LED .55(b)).
"""

from __future__ import annotations

import ast
import asyncio
import shutil
from pathlib import Path

import pytest
from textual.containers import Container
from textual.widgets import DataTable, Label, Static, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
CASE01_DIR = EXAMPLES_DIR / "case_01_basic_valid"
P2_SOURCE = EXAMPLES_DIR / "case_00_public" / "prg.s19"
P1_NAME = "P1"
P2_NAME = "P2"

# ---------------------------------------------------------------------------
# The derived domain machinery (LLR-165.2): the census runs at TEST time
# against the live source; the snapshot is cross-checked against it, so a
# new ``self.<name> =`` in S19TuiApp's source that nobody classified fails
# the classification arm instead of silently leaving the snapshot domain.
# ---------------------------------------------------------------------------


def _source_census() -> set[str]:
    """Every name ``S19TuiApp``'s own source assigns via ``self.<name> =``.

    Derived by an AST census of the live module file (C-31) — the same
    derivation the contract's ARQ §2.1 used, re-run here so the domain can
    never drift from the source it claims to cover.
    """
    import s19_app.tui.app as app_module

    tree = ast.parse(Path(app_module.__file__).read_text(encoding="utf-8"))
    cls = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "S19TuiApp"
    )
    names: set[str] = set()
    for node in ast.walk(cls):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        for target in targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                names.add(target.attr)
    return names


# Declared exclusion list (LLR-165.2): Textual internals the snapshot
# domain does not carry, each with its reason. At this commit S19TuiApp's
# own source assigns no Textual-internal attribute (the census above is
# the proof), so the list is declared EMPTY — the mechanism stays, and a
# future Textual-internal assignment must land here with its reason rather
# than breaking cold-vs-cold equality.
SNAPSHOT_EXCLUSIONS: dict[str, str] = {}

# The K1/K2 allow-list (ARQ §2.2): names a load-over may differ in BY
# DESIGN — the monotonic counters (K1) and the kept view state: the log
# deque, the active rail screen, the path-keyed A2L parse cache (K2).
SNAPSHOT_ALLOW_LIST = {
    "_image_generation",
    "_diff_compare_generation",
    "_active_screen_key",
    "log_lines",
    "_a2l_cache_key",
    "_a2l_cache_data",
}


# ---------------------------------------------------------------------------
# Drivers and readers
# ---------------------------------------------------------------------------


async def _wait_for(pilot, predicate, description: str, attempts: int = 150) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {description}")


async def _flush(pilot, count: int = 12) -> None:
    for _ in range(count):
        await pilot.pause()


def _status_text(app: S19TuiApp) -> str:
    return str(app.query_one("#log_line_4", Label).render())


def _seed_project_p1(workarea: Path) -> Path:
    """P1 — the case_01 project: S19 + MAC + A2L (enabler E4)."""
    project_dir = workarea / P1_NAME
    project_dir.mkdir(parents=True, exist_ok=True)
    for name in ("firmware.s19", "firmware.mac", "firmware.a2l"):
        shutil.copy2(CASE01_DIR / name, project_dir / name)
    return project_dir


def _seed_project_p2(workarea: Path) -> Path:
    """P2 — the ``p03`` scenario project: S19 only."""
    project_dir = workarea / P2_NAME
    project_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(P2_SOURCE, project_dir / "prg.s19")
    return project_dir


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _seed_p1_derived_state(app: S19TuiApp, workarea: Path) -> None:
    """Non-default values for every S5-S12 name the P1 scenario does not
    touch (code-review finding F1): the CRC template, the comparison and
    check spec, the flow run, the execution, the report filter, the A2L
    find/summary/filtered views and the pending variant, plus the A-07
    probe names (the validation report/issues and the row-key maps).
    Without this the load-over arms compare default against default for
    those names, and deleting the S7-S11 reset lines stays green (the
    reviewer's mutant R6 survived at round 1 on exactly that vacancy)."""
    project_dir = workarea / P1_NAME
    app._last_template_path = project_dir / "templates" / "crc.tpl"
    app._diff_last_result = ("p1-comparison", 1)
    app._diff_check_spec = ("p1-check-spec", 2)
    app._diff_check_spec_name = "p1-check-spec"
    app._last_flow_run = ("p1-flow-run", 3)
    app._last_execution = ("p1-execution", 4)
    app._report_filter_path = project_dir / "filters" / "report.txt"
    app._a2l_enriched_tags = [("p1-tag", 0x100)]
    app._a2l_filtered_tags = [("p1-tag", 0x100)]
    app._a2l_window_start = 7
    app._a2l_summary_lines = ["p1 summary line"]
    app._a2l_summary_start = 5
    app._a2l_tag_find_query = "p1-find"
    app._a2l_tag_find_last_index = 3
    app._validation_report = ("p1-validation-report", 5)
    app._validation_issues = [("p1-issue",)]
    app._mac_row_key_to_address = {1: 0x8000}
    app._a2l_row_key_to_tag = {1: "p1-tag"}
    app._pending_variant_id = "p1-variant"


# ---------------------------------------------------------------------------
# TC-B100-08 — one reset seam, before the first install (LLR-165.1)
# ---------------------------------------------------------------------------


def test_tc_b100_08_reset_runs_once_before_the_first_install(tmp_path: Path) -> None:
    """One call per project load, ordered before the first install; P1's
    two installs (S19 then MAC) both follow it. A load of the SAME project
    again is a load-over — still exactly one reset."""

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        events: list[str] = []
        original_reset = getattr(app, "_reset_project_session", None)
        # Inc 7 re-pin (LLR-169.6): the project variant now installs through
        # ``_install_project_image`` (parse first, then apply), the MAC
        # through ``load_selected_file``; both apply through
        # ``_apply_loaded_file``, so that is the install marker.
        original_apply = app._apply_loaded_file

        def _recording_reset() -> int:
            events.append("reset")
            if original_reset is None:
                return 0
            return original_reset()

        def _recording_apply(loaded, path, load_started) -> None:
            events.append("install")
            original_apply(loaded, path, load_started)

        app._reset_project_session = _recording_reset
        app._apply_loaded_file = _recording_apply
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project(P1_NAME)
            await _flush(pilot)
            app._handle_load_project(P1_NAME)
            await _flush(pilot)
        return events

    events = asyncio.run(_drive())
    assert events.count("reset") == 2, events
    assert events[0] == "reset", events
    assert events.index("reset") < events.index("install"), events
    # P1 = S19 + MAC: two installs per load, every install after a reset.
    assert events == ["reset", "install", "install"] * 2, events


def test_tc_b100_08_loose_file_load_performs_no_reset(tmp_path: Path) -> None:
    """A Load file composes with the session on purpose (ARQ §2.3): the
    loose-file path performs NO reset — a MAC + S19 + A2L loose sequence
    keeps composing, and the counters stay monotonic."""

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        events: list[str] = []

        def _recording_reset() -> int:
            events.append("reset")
            return 0

        app._reset_project_session = _recording_reset
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            app.load_selected_file(CASE01_DIR / "firmware.mac")
            await _flush(pilot)
            # Loose loads compose with the session on purpose: the MAC
            # merged onto the primary (the seam did not tear the session).
            assert app.current_file is not None
            assert app.current_file.mac_records, "arm setup: the MAC merged"
        return events

    assert asyncio.run(_drive()) == []


def test_tc_b100_08_call_site_census() -> None:
    """Exactly one ``_reset_project_session`` call site in ``s19_app/`` —
    inside ``_handle_load_project`` (an AST census over every product
    module, so a second caller cannot hide in another file)."""

    import s19_app

    product_root = Path(s19_app.__file__).resolve().parent
    callers = []
    for source in sorted(product_root.rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "_reset_project_session"
            ):
                callers.append(source.relative_to(product_root).as_posix())
    assert callers == ["tui/app.py"], callers


# ---------------------------------------------------------------------------
# TC-B100-09 — the session snapshot, derived from the live app (LLR-165.2)
# ---------------------------------------------------------------------------


def test_tc_b100_09_domain_matches_the_live_source_census(tmp_path: Path) -> None:
    """The snapshot domain is the source census minus the declared
    exclusions: >= 60 names, 0 unclassified (every census name is in the
    snapshot or in the exclusion list, each with a reason)."""

    census = _source_census()
    assert len(census) >= 60, len(census)
    for name, reason in SNAPSHOT_EXCLUSIONS.items():
        assert reason.strip(), f"exclusion {name!r} needs its reason"

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            return app._session_snapshot()

    snapshot = asyncio.run(_drive())
    covered = set(snapshot) | set(SNAPSHOT_EXCLUSIONS)
    unclassified = census - covered
    assert not unclassified, f"unclassified census names: {sorted(unclassified)}"
    outside = set(snapshot) - census
    assert not outside, f"snapshot names the census does not assign: {sorted(outside)}"


def _cold_snapshot(tmp_path: Path, project: str) -> dict:
    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project(project)
            await _flush(pilot)
            return app._session_snapshot()

    return asyncio.run(_drive())


def test_tc_b100_09_two_cold_loads_have_equal_snapshots(tmp_path: Path) -> None:
    """Two cold loads of the SAME project -> 0 differing names. This arm
    is the stat-key normaliser proof (QA R2-07): an un-normalised snapshot
    differs here in ``_mac_view_cache_key`` / ``_a2l_enriched_key``
    (id-keyed) — QA's probe — and in ``_a2l_cache_key`` (mtime-keyed)."""

    base = tmp_path / "app"
    _seed_project_p1(_workarea(base))
    first = _cold_snapshot(base, P1_NAME)
    second = _cold_snapshot(base, P1_NAME)
    differing = {
        name for name in first if first[name] != second.get(name)
    } | (set(second) - set(first))
    assert not differing, f"cold-vs-cold differing names: {sorted(differing)}"


def test_tc_b100_09_load_over_matches_cold_outside_the_allow_list(
    tmp_path: Path,
) -> None:
    """A load of P2 over P1 differs from a cold P2 load ONLY in the
    declared K1/K2 allow-list — 0 LEAK names outside it (the p03
    sequence; A-07's derived-domain check). P1's session is first given
    non-default values for every S5-S12 name the scenario does not touch
    (F1): the comparison must see the reset of the CRC template, the
    comparison/check spec, the flow run, the execution and the report
    filter — deleting those reset lines surfaces here (reviewer R6)."""

    base = tmp_path / "app"
    workarea = _workarea(base)
    _seed_project_p1(workarea)
    _seed_project_p2(workarea)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project(P1_NAME)
            await _flush(pilot)
            # Non-default S5-S12 + A-07 state, then outgoing unsaved
            # work, then the load-over.
            _seed_p1_derived_state(app, workarea)
            app._change_service.add_entry("0x8000007C", "", "DE AD BE EF")
            app._handle_load_project(P2_NAME)
            await _flush(pilot)
            return app._session_snapshot()

    warm = asyncio.run(_drive())
    cold = _cold_snapshot(base, P2_NAME)
    differing = {
        name
        for name in cold
        if cold[name] != warm.get(name)
    } | (set(warm) - set(cold))
    leaks = differing - SNAPSHOT_ALLOW_LIST
    assert not leaks, (
        "LEAK " + ", ".join(f"{n}: cold={cold.get(n)!r} warm={warm.get(n)!r}" for n in sorted(leaks))
    )


def test_tc_b100_09_load_over_leaves_no_p1_state(tmp_path: Path) -> None:
    """The executed P-2 leak names AND the full S5-S12 / A-07 inventory,
    asserted directly: P1's session is seeded with non-default values
    (F1) before P2 loads over it (+1 unsaved entry); afterwards the
    session holds none of P1's attachments, parsed A2L, change entries,
    declared regions, CRC template, comparison/check spec, flow run,
    execution, report filter, A2L views or probe names. RED at base:
    every one of these leaked (the p03 probe's LEAK lines)."""

    base = tmp_path / "app"
    workarea = _workarea(base)
    _seed_project_p1(workarea)
    _seed_project_p2(workarea)

    async def _drive() -> S19TuiApp:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project(P1_NAME)
            await _flush(pilot)
            _seed_p1_derived_state(app, workarea)
            app._change_service.add_entry("0x8000007C", "", "DE AD BE EF")
            app._handle_load_project(P2_NAME)
            await _flush(pilot)
        return app

    app = asyncio.run(_drive())
    loaded = app.current_file
    assert loaded is not None and loaded.path.name == "prg.s19"
    assert loaded.mac_path is None, "LEAK mac_path"
    assert loaded.mac_records == [], "LEAK mac_records"
    assert loaded.a2l_path is None, "LEAK a2l_path"
    assert loaded.a2l_data is None, "LEAK a2l_data"
    assert app.current_a2l_path is None, "LEAK current_a2l_path"
    assert app.current_a2l_data is None, "LEAK current_a2l_data"
    assert len(app._change_service.document.entries) == 0, "LEAK change_entries"
    assert app._declared_regions == (), "LEAK declared_regions"
    assert app._last_template_path is None, "LEAK last_template_path"
    assert app._diff_last_result is None, "LEAK diff_last_result"
    assert app._diff_check_spec is None, "LEAK diff_check_spec"
    assert app._diff_check_spec_name == "", "LEAK diff_check_spec_name"
    assert app._last_flow_run is None, "LEAK last_flow_run"
    assert app._last_execution is None, "LEAK last_execution"
    assert app._report_filter_path is None, "LEAK report_filter_path"
    assert app._a2l_enriched_tags == [], "LEAK a2l_enriched_tags"
    assert app._a2l_filtered_tags == [], "LEAK a2l_filtered_tags"
    assert app._a2l_window_start == 0, "LEAK a2l_window_start"
    assert app._a2l_summary_lines == [], "LEAK a2l_summary_lines"
    assert app._a2l_summary_start == 0, "LEAK a2l_summary_start"
    assert app._a2l_tag_find_query == "", "LEAK a2l_tag_find_query"
    assert app._a2l_tag_find_last_index == -1, "LEAK a2l_tag_find_last_index"
    # P2's own install writes a FRESH validation report after the reset,
    # so the honest assertion is that P1's seeded report is gone.
    assert app._validation_report != ("p1-validation-report", 5), (
        "LEAK validation_report"
    )
    assert app._validation_issues == [], "LEAK validation_issues"
    assert app._mac_row_key_to_address == {}, "LEAK mac_row_key_to_address"
    assert app._a2l_row_key_to_tag == {}, "LEAK a2l_row_key_to_tag"
    assert app._pending_variant_id != "p1-variant", "LEAK pending_variant_id"


# ---------------------------------------------------------------------------
# TC-B100-10 — the change service is rebound (LLR-165.3 + LED .51)
# ---------------------------------------------------------------------------


def _load_p1_add_entry_load_p2(tmp_path: Path, entries: int = 1) -> S19TuiApp:
    base = tmp_path / "app"
    workarea = _workarea(base)
    _seed_project_p1(workarea)
    _seed_project_p2(workarea)

    async def _drive() -> S19TuiApp:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project(P1_NAME)
            await _flush(pilot)
            for index in range(entries):
                app._change_service.add_entry(
                    f"0x800000{0x7C + index:02X}", "", "DE AD BE EF"
                )
            app._handle_load_project(P2_NAME)
            await _flush(pilot)
        return app

    return asyncio.run(_drive())


def test_tc_b100_10_change_service_is_rebound(tmp_path: Path) -> None:
    """After a load over P1: a DIFFERENT service object, 0 document
    entries, 0 undo steps, 0 redo steps, and an image generation equal to
    the app's (re-pushed, not stale from the outgoing service)."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        _seed_project_p1(_workarea(tmp_path / "app"))
        _seed_project_p2(_workarea(tmp_path / "app"))
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project(P1_NAME)
            await _flush(pilot)
            outgoing = app._change_service
            app._change_service.add_entry("0x8000007C", "", "DE AD BE EF")
            app._handle_load_project(P2_NAME)
            await _flush(pilot)
            depths = app._change_service.history_depths()
            return (
                outgoing,
                app._change_service,
                len(app._change_service.document.entries),
                depths["back"],
                depths["forward"],
                app._change_service.image_generation,
                app._image_generation,
            )

    (
        outgoing,
        rebound,
        entries,
        undo,
        redo,
        service_generation,
        app_generation,
    ) = asyncio.run(_drive())
    assert rebound is not outgoing, "the reset kept the old ChangeService"
    assert entries == 0, "the rebound service leaked document entries"
    assert undo == 0 and redo == 0, "the rebound service leaked history"
    assert service_generation == app_generation, (
        "set_image_generation was not re-pushed into the rebound service"
    )


def test_tc_b100_10_outgoing_service_finishes_after_rebind(tmp_path: Path) -> None:
    """LLR-165.3's boundary arm (P-26): a worker that captured the
    OUTGOING service stays in flight across a load-over and finishes
    against the captured object — no exception — and the rebound service
    is untouched. This is the property a rebind (not an in-place reset)
    guarantees: the old object stays a valid, independent ChangeService,
    so mutant m4 (old service kept) kills this arm through the shared
    document count."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path / "app")
        _seed_project_p1(_workarea(tmp_path / "app"))
        _seed_project_p2(_workarea(tmp_path / "app"))
        errors: list = []
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project(P1_NAME)
            await _flush(pilot)
            outgoing = app._change_service
            outgoing.add_entry("0x8000007C", "", "DE AD BE EF")
            started = asyncio.Event()
            release = asyncio.Event()

            async def _worker() -> None:
                # Captures the old service, holds across the rebind, then
                # finishes against the captured object — the race P-26's
                # rebind design answers.
                started.set()
                await release.wait()
                try:
                    outgoing.add_entry("0x80000080", "", "00 11 22 33")
                except Exception as exc:  # the arm fails on ANY raise
                    errors.append(exc)

            task = asyncio.create_task(_worker())
            await started.wait()
            app._handle_load_project(P2_NAME)
            await _flush(pilot)
            release.set()
            await task
            depths = app._change_service.history_depths()
            return (
                errors,
                len(app._change_service.document.entries),
                depths["back"],
                depths["forward"],
                app._change_service.image_generation,
                app._image_generation,
            )

    errors, entries, undo, redo, service_gen, app_gen = asyncio.run(_drive())
    assert not errors, f"the finishing worker raised: {errors!r}"
    assert (entries, undo, redo) == (0, 0, 0), (
        "the rebound service was touched by the outgoing worker: "
        f"entries={entries} undo={undo} redo={redo}"
    )
    assert service_gen == app_gen, "the rebound service lost the generation re-push"


def test_tc_b100_10_interim_discard_notice(tmp_path: Path) -> None:
    """LED-2026-10-26-batch-100.55(a): with N > 0 entries outgoing, the
    project load's status names the closed document — ``Closed the Patch
    Editor document (N entries); unsaved changes were not kept`` — so the
    reset's discard is never silent. The line states only what Inc 3 can
    know (the document held N entries); it does not call them unsaved —
    the panel's dirty flag has no public reader until Inc 10 (Inc 10's
    question replaces this line and re-pins this arm)."""

    app = _load_p1_add_entry_load_p2(tmp_path, entries=1)
    assert app.log_lines[-1] == (
        "Closed the Patch Editor document (1 entries); "
        "unsaved changes were not kept"
    ), list(app.log_lines)


def test_tc_b100_10_no_discard_notice_when_nothing_unsaved(tmp_path: Path) -> None:
    """A clean load-over (0 outgoing entries) paints no closed-document
    line; the loaded-project line stays the freshest."""

    base = tmp_path / "app"
    _seed_project_p1(_workarea(base))
    _seed_project_p2(_workarea(base))

    async def _drive() -> list:
        app = S19TuiApp(base_dir=base)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project(P1_NAME)
            await _flush(pilot)
            app._handle_load_project(P2_NAME)
            await _flush(pilot)
            return list(app.log_lines)

    lines = asyncio.run(_drive())
    assert not any("Closed the Patch Editor document" in line for line in lines)
    # Inc 6 (LLR-178.2): the loaded-project line is the load's summary line.
    assert lines[-1] == (
        "Loaded project 'P2' -> prg.s19 - variant 1 of 1, 1 problem - details: p"
    ), lines


def test_tc_b100_10_notice_names_every_discarded_entry(tmp_path: Path) -> None:
    """The count is exact: 3 outgoing entries -> ``(3 entries)``."""

    app = _load_p1_add_entry_load_p2(tmp_path, entries=3)
    assert app.log_lines[-1] == (
        "Closed the Patch Editor document (3 entries); "
        "unsaved changes were not kept"
    ), list(app.log_lines)


# ---------------------------------------------------------------------------
# TC-B100-11 — unload clears the parsed A2L (LLR-165.4)
# ---------------------------------------------------------------------------


def _load_p1(app: S19TuiApp) -> None:
    app._handle_load_project(P1_NAME)


def test_tc_b100_11_unload_all_clears_the_parsed_a2l(tmp_path: Path) -> None:
    """``_apply_unload("all")`` clears ``current_a2l_data`` beside the
    path (P-25: at base the path alone is cleared, so the parsed payload
    survives)."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            _load_p1(app)
            await _flush(pilot)
            assert app.current_a2l_data is not None, "arm setup: P1's A2L parsed"
            app._apply_unload("all")
            await _flush(pilot)
            return app.current_a2l_path, app.current_a2l_data

    a2l_path, a2l_data = asyncio.run(_drive())
    assert a2l_path is None, "unload all kept current_a2l_path"
    assert a2l_data is None, "unload all kept current_a2l_data (P-25)"


def test_tc_b100_11_unload_a2l_alone_clears_the_parsed_a2l(tmp_path: Path) -> None:
    """The ``"a2l"`` kind clears the parsed payload too — the boundary arm
    (LLR-165.4's catalogue marks it)."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            _load_p1(app)
            await _flush(pilot)
            app._apply_unload("a2l")
            await _flush(pilot)
            return app.current_a2l_path, app.current_a2l_data

    a2l_path, a2l_data = asyncio.run(_drive())
    assert a2l_path is None, "unload a2l kept current_a2l_path"
    assert a2l_data is None, "unload a2l kept current_a2l_data"


def test_tc_b100_11_bare_s19_reload_after_unload_shows_no_a2l_tags(
    tmp_path: Path,
) -> None:
    """The contract threshold: load S19 + A2L, unload ``all``, load an S19
    with no A2L -> 0 A2L tags. At base the surviving payload is attached
    to the bare S19 through the parse fallback (``else
    self.current_a2l_data``), so the tags survive -> RED."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            _load_p1(app)
            await _flush(pilot)
            app._apply_unload("all")
            await _flush(pilot)
            app.load_selected_file(P2_SOURCE)
            await _flush(pilot)
            loaded = app.current_file
            tags = 0 if loaded is None else len(loaded.a2l_data or {})
            return app.current_a2l_data, tags

    a2l_data, tags = asyncio.run(_drive())
    assert a2l_data is None, "the bare S19 reload re-attached the stale A2L"
    assert tags == 0, f"stale A2L tags survived the unload: {tags}"


# ---------------------------------------------------------------------------
# AT-B100-03 — through the shipped surface (HLR-165)
# ---------------------------------------------------------------------------


async def _open_project_through_dialog(pilot, app: S19TuiApp, name: str) -> None:
    """Open an existing project through the shipped Load project surface:
    the app-level ``p`` binding opens the Load project dialog (the brief's
    ``p`` route; the Workspace is reached first with rail key ``1`` when a
    rail screen took the focus — only the Segment Split window re-binds
    ``p``, and it is never displayed in this scene)."""
    from s19_app.tui.screens import LoadProjectScreen

    await pilot.press("1")
    await _flush(pilot, 4)
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
    # Inc 6 (HLR-178): the dialog route opens the Load-result panel;
    # dismiss it first with its shown key ``esc``.
    await _wait_for(
        pilot, lambda: len(app.screen.query("#result_ok")) > 0, "the Load-result panel"
    )
    await pilot.press("escape")
    await _wait_for(
        pilot, lambda: len(app.screen.query("#result_ok")) == 0, "the panel closed"
    )


async def _save_project_as(pilot, app: S19TuiApp, name: str) -> None:
    """Open the Save project dialog (``ctrl+s``), type the name, press
    Save; wait for the dialog to close."""
    from s19_app.tui.screens import SaveProjectScreen

    await pilot.press("ctrl+s")
    await _wait_for(
        pilot, lambda: isinstance(app.screen, SaveProjectScreen), "the Save project dialog"
    )
    assert await pilot.click("#project_name"), "click missed #project_name"
    await pilot.press(*name)
    assert await pilot.click("#save_ok"), "click missed #save_ok"
    await _wait_for(
        pilot,
        lambda: not isinstance(app.screen, SaveProjectScreen),
        "the Save project dialog to close",
    )


@pytest.mark.parametrize("size", [(118, 54), (220, 60)])
def test_at_b100_03_project_load_over_unsaved_work_saves_only_p2(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-165's acceptance scene, by keys only: load P1 (S19 + MAC + A2L)
    through the Load project dialog (``p``), add ONE Patch Editor entry
    through the panel's own inputs, load P2 through the dialog (the
    interim closed-document notice names the entry, LED .55(a)), Save
    project as P2 — P2's folder holds ``prg.s19`` + ``project.json`` ONLY
    (P-2's re-save at base also wrote P1's ``firmware.mac`` /
    ``firmware.a2l``), the Loaded panel shows no MAC and no A2L. Both
    reference sizes, notifications on. After the load-over the AT also
    asserts the painted Patch Editor observables: the ledger is empty
    (0 rows + the empty-state line) and the SCRIPT window subtitle shows
    ``0 entries`` with no dirty ``●`` (LED .55(b)).

    RED (executed at base): ``P2 files after save: ['firmware.a2l',
    'firmware.mac', 'prg.s19', 'project.json']`` — the p03/P-2 shape."""

    base = tmp_path / "app"
    app = S19TuiApp(base_dir=base)
    workarea = app.workarea
    _seed_project_p1(workarea)
    _seed_project_p2(workarea)

    async def _drive() -> tuple:
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _open_project_through_dialog(pilot, app, P1_NAME)
            await _wait_for(
                pilot,
                lambda: f"Loaded project '{P1_NAME}'" in _status_text(app),
                "the painted line naming the opened project P1",
            )
            # One Patch Editor entry through the panel's own inputs.
            await pilot.press("6")
            await _wait_for(
                pilot,
                lambda: len(app.query("#patch_entry_add_button")) > 0,
                "the Patch Editor panel",
            )
            assert await pilot.click("#patch_entry_address_input"), (
                "click missed #patch_entry_address_input"
            )
            await pilot.press(*"0x8000007C")
            assert await pilot.click("#patch_entry_bytes_input"), (
                "click missed #patch_entry_bytes_input"
            )
            await pilot.press(*"DE AD BE EF")
            assert await pilot.click("#patch_entry_add_button"), (
                "click missed #patch_entry_add_button"
            )
            await _wait_for(
                pilot,
                lambda: "Patch Editor: entry added." in _status_text(app),
                "the painted confirmation of the added entry",
            )
            # LED .55(b) vacuity guard: the entry went in through the
            # panel's own inputs, so the dirty marker is painted BEFORE
            # the load-over (without this the no-marker assertion below
            # would pass even if the marker had never existed).
            marked = (
                app.query_one("#patch_win_script", Container).border_subtitle
                or ""
            )
            assert "●" in marked, marked
            # A P1 draft in the paste buffer, typed through the panel's
            # own TextArea (writer w2 marks the panel dirty). The buffer
            # lives in the panel's JSON view, so the JSON tab chip is
            # clicked first — the shipped surface a user takes. LED
            # .55(b) says the reset clears the buffer too: without the
            # pre-load non-empty assertion the post-load empty assertion
            # would pass even if the buffer had never held the draft.
            assert await pilot.click("#patch_tab_json"), "click missed #patch_tab_json"
            await _wait_for(
                pilot,
                lambda: app.query_one("#patch_paste_text", TextArea).region.width > 0,
                "the JSON view's paste buffer to become visible",
            )
            assert await pilot.click("#patch_paste_text"), (
                "click missed #patch_paste_text"
            )
            await pilot.press(*"P1 DRAFT")
            paste_buffer = app.query_one("#patch_paste_text", TextArea)
            assert "P1 DRAFT" in paste_buffer.text, repr(paste_buffer.text)
            # Back to the Inspector tab: the TextArea holds the keyboard,
            # and the load-over below starts with the rail key ``1``.
            assert await pilot.click("#patch_tab_inspector"), (
                "click missed #patch_tab_inspector"
            )
            await pilot.pause()
            # The load-over: P2 replaces P1. The closed-document notice is
            # the freshest painted line (LED .55(a)); the loaded-project
            # line stays in the log history and both are asserted on the
            # captured log below.
            await _open_project_through_dialog(pilot, app, P2_NAME)
            await _wait_for(
                pilot,
                lambda: (
                    "Closed the Patch Editor document (1 entries); "
                    "unsaved changes were not kept" in _status_text(app)
                ),
                "the interim closed-document notice (LED .55(a)) as the freshest line",
            )
            # LED .55(b): the reset cleared the panel's paste buffer —
            # P1's draft must not survive into P2's session.
            await _wait_for(
                pilot,
                lambda: app.query_one("#patch_paste_text", TextArea).text == "",
                "the paste buffer cleared by the reset",
            )
            # LED .55(b): the reset cleared the panel's dirty marker — the
            # SCRIPT window subtitle is painted "0 entries" with no ●. The
            # marker repaint is deferred until after the buffer's change
            # message, so it is polled, not read once.
            await _wait_for(
                pilot,
                lambda: (
                    "0 entries"
                    in (
                        app.query_one("#patch_win_script", Container).border_subtitle
                        or ""
                    )
                    and "●"
                    not in (
                        app.query_one("#patch_win_script", Container).border_subtitle
                        or ""
                    )
                ),
                "the clean '0 entries' subtitle after the load-over",
            )
            # HLR-165's painted observable: the Patch Editor ledger is
            # empty — 0 rows and the empty-state line. This pins HLR-165's
            # observable, NOT LLR-165.1's repaint clause: deleting the
            # seam's refresh_entries call is an EQUIVALENT mutant (the
            # reviewer's R8b survives) because the install's deferred
            # chain repaints the ledger anyway.
            table = app.query_one("#patch_doc_entries_table", DataTable)
            assert table.row_count == 0, table.row_count
            empty_state = app.query_one("#patch_doc_empty_state", Static)
            assert not empty_state.has_class("hidden")
            assert str(empty_state.render()) == PatchEditorPanel.EMPTY_STATE_TEXT
            # The Loaded panel: no MAC, no A2L in any slot.
            loaded_text = " ".join(
                str(static.render())
                for static in app.query("#loaded_slots Static")
            )
            assert "firmware.mac" not in loaded_text, loaded_text
            assert "firmware.a2l" not in loaded_text, loaded_text
            # Save project as P2 (the open project).
            await _save_project_as(pilot, app, P2_NAME)
            await _wait_for(
                pilot,
                lambda: "Saved project" in _status_text(app),
                "the P2 save success line",
            )
            await _flush(pilot)
        p2_files = sorted(item.name for item in (workarea / P2_NAME).iterdir())
        return p2_files, list(app.log_lines)

    p2_files, log_lines = asyncio.run(_drive())
    assert p2_files == ["prg.s19", "project.json"], (
        f"P2 files after save: {p2_files}"
    )
    assert (
        "Closed the Patch Editor document (1 entries); "
        "unsaved changes were not kept" in log_lines
    ), log_lines


def test_tc_b100_10_reset_leaves_the_patch_editor_clean_for_the_next_load(
    tmp_path: Path,
) -> None:
    """TC-B100-10 (LLR-165.3, LED .55(b), LED .60), hotfix 3b: after a project load
    the reset empties the paste buffer AND leaves the Patch Editor clean, so
    the next Patch Load loads directly — it raises no dirty-load question.

    Why: the reset's buffer clear posted ``TextArea.Changed``, whose panel
    handler (writer w2) set the dirty flag; the deferred ``mark_loaded`` ran
    before that message was handled, so a fresh session asked "unsaved
    changes will be lost" with nothing unsaved and the Load did not happen
    (CI: AT-B97-14[patch] stopped on ``LoadGuardScreen``). RED on 6d8631a:
    the guard modal is on screen and the document never loads.
    """
    from s19_app.tui.screens_directionb import LoadGuardScreen
    from tests.b97_fixtures import calib_hotfix, fx_project, load_change_file, open_patch_editor
    from tests.b97_probes import settle

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            fx_project(app)  # the app's own project load -> the reset
            panel = await open_patch_editor(app, pilot)
            buffer = app.query_one("#patch_paste_text", TextArea)
            assert buffer.text == "", repr(buffer.text)
            # The prevented message is what repaints the gauge and heading;
            # the clear repaints them itself, so the heading no longer names
            # the shipped example the fresh session started with.
            heading = str(app.query_one("#patch_paste_heading", Static).render())
            assert "editable" in heading, heading
            await load_change_file(app, pilot, panel, calib_hotfix(app.base_dir))
            assert not isinstance(app.screen, LoadGuardScreen), (
                "a clean session raised the dirty-load question"
            )
            subtitle = str(
                app.query_one("#patch_win_script", Container).border_subtitle
            )
            assert "6 entries" in subtitle and "●" not in subtitle, subtitle

    asyncio.run(_drive())
