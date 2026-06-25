"""Batch-07 E6 — manifest + batch/per-variant execution (HLR-006).

Coverage map:

- LLR-006.1 default — ``test_manifest_absent_defaults_to_batch_all``: no
  ``project.json`` → ``read_project_manifest`` is ``None`` and the plan is
  batch mode over ALL variants using the fallback file list.
- LLR-006.1 round-trip — ``test_manifest_round_trip``: a written manifest
  reads back with ``schema_version`` / ``active_variant`` / ``batch`` /
  ``assignments`` intact, paths resolved against the project directory.
- LLR-005.6 completion — ``test_load_project_honors_manifest_active_variant``
  / ``test_load_project_unknown_active_variant_falls_back``: the
  manifest-recorded ``active_variant`` is activated on project load when
  valid; an unknown one warns and falls back to the first variant.
- F-S-03 containment — ``test_manifest_containment_skips_unsafe_entries``:
  an escaping relative entry and an absolute entry each yield exactly one
  ERROR ``ValidationIssue`` (``MANIFEST-PATH-ESCAPE``) and are skipped; the
  safe entry survives (collect-don't-abort).
- LLR-006.2 — ``test_double_run_orderings_identical``: two plan+execute
  runs over the same inputs produce identical variant orderings and
  identical per-variant result orderings.
- LLR-006.4 — ``test_failing_variant_never_aborts_the_rest``: an injected
  parse failure on one variant yields exactly one ``"error"`` result while
  ``len(results)`` equals the planned variant count.
- LLR-006.3/006.5 — ``test_batch_execution_stamps_variant_ids``: a
  2-variant batch run produces one ``ChangeSummary`` and one
  ``CheckRunResult`` per variant, each stamped with the right
  ``variant_id`` by the engines (the service computes no verdicts).
- E6 duplicate-id decision — ``test_duplicate_stem_ids_become_filenames``:
  colliding stems make each ``variant_id`` the full filename in
  ``workspace.build_variant_set``.
- LLR-002.7 headless — ``test_save_back_files_land_under_project_dir``:
  per-variant save-back writes ``<variant_id>-patched.s19`` into the
  project directory with no prompt.
- LLR-006.6 — ``test_execute_scope_without_project_is_status_error``: the
  routed ``execute_scope`` action without a project is one status line,
  never a crash (the ninth-action pin itself lives in
  ``tests/test_tui_patch_editor_v2.py``).

The service-level tests build their projects under a real
``.s19tool/workarea/`` root because the save-back engine stages through the
work area (``save_patched_image`` containment).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from s19_app.tui.models import ProjectVariantSet
from s19_app.tui.services import variant_execution_service as ves
from s19_app.tui.services.variant_execution_service import (
    MANIFEST_PATH_ESCAPE,
    SCOPE_ALL,
    execute_variant_plan,
    plan_variant_executions,
    read_project_manifest,
)
from s19_app.tui.workspace import build_variant_set, validate_project_files
from s19_app.validation.model import ValidationSeverity

# Minimal valid S19 images (checksums verified against s19_app.core.S19File).
S19_A = "S107100001020304DE\nS9030000FC\n"  # 4 bytes at 0x1000
S19_B = "S10720000A0B0C0DAA\nS9030000FC\n"  # 4 bytes at 0x2000


def _write_v2_document(path: Path, entries: list[dict], kind: str = "change") -> Path:
    """Write a v2 ``s19app-changeset`` JSON document fixture."""
    path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": kind,
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return path


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _variant_set(project_dir: Path, name: str = "proj") -> ProjectVariantSet:
    data_files, _a2l, error = validate_project_files(project_dir)
    assert error is None
    return build_variant_set(name, data_files)


# ---------------------------------------------------------------------------
# LLR-006.1 — manifest-absent default: batch mode over all variants
# ---------------------------------------------------------------------------


def test_manifest_absent_defaults_to_batch_all(tmp_path: Path) -> None:
    """No manifest → plan covers ALL variants with the fallback batch.

    Intent: LLR-006.1 — the manifest is optional; its absence means batch
    mode over every variant (the default), with the caller-supplied
    fallback file list applied to each.
    """
    project_dir = _make_project(tmp_path, {"a.s19": S19_A, "b.s19": S19_B})
    chg = _write_v2_document(
        project_dir / "chg.json",
        [{"type": "bytes", "address": "0x1000", "bytes": "AA"}],
    )
    vset = _variant_set(project_dir)

    assert read_project_manifest(project_dir) is None

    plan = plan_variant_executions(vset, None, scope=SCOPE_ALL, fallback_batch=[chg])
    assert [variant.variant_id for variant, _files in plan] == ["a", "b"]
    assert all(files == (chg,) for _variant, files in plan)

    results = execute_variant_plan(plan, project_dir)
    assert [result.variant_id for result in results] == ["a", "b"]
    assert all(result.status == "ok" for result in results)


# ---------------------------------------------------------------------------
# LLR-006.1 — manifest round-trip
# ---------------------------------------------------------------------------


def test_manifest_round_trip(tmp_path: Path) -> None:
    """A written manifest reads back field-for-field, paths project-resolved.

    Intent: LLR-006.1 — ``project.json`` carries
    ``{schema_version, active_variant, batch, assignments}``; ``batch`` and
    ``assignments`` entries resolve against the project directory only.
    """
    project_dir = _make_project(tmp_path, {"a.s19": S19_A, "b.s19": S19_B})
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "b",
                "batch": ["doc.json"],
                "assignments": {"b": ["extra.json"]},
            }
        ),
        encoding="utf-8",
    )

    manifest = read_project_manifest(project_dir)

    assert manifest is not None
    assert manifest.schema_version == 1
    assert manifest.active_variant == "b"
    assert manifest.batch == [(project_dir / "doc.json").resolve()]
    assert manifest.assignments == {"b": [(project_dir / "extra.json").resolve()]}
    assert manifest.issues == []


# ---------------------------------------------------------------------------
# LLR-005.6 completion — manifest active_variant override on project load
# ---------------------------------------------------------------------------


def test_load_project_honors_manifest_active_variant(tmp_path: Path) -> None:
    """Project load activates the manifest-recorded variant when valid.

    Intent: LLR-005.6 (completed at E6) — ``_handle_load_project`` reads the
    manifest and activates its ``active_variant`` instead of the first
    deterministic variant.
    """
    from s19_app.tui.app import S19TuiApp

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = app.workarea / "proj"
        project_dir.mkdir(parents=True, exist_ok=True)
        (project_dir / "a.s19").write_text(S19_A, encoding="utf-8")
        (project_dir / "b.s19").write_text(S19_B, encoding="utf-8")
        (project_dir / "project.json").write_text(
            json.dumps({"schema_version": 1, "active_variant": "b"}),
            encoding="utf-8",
        )
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            for _ in range(12):
                await pilot.pause()
            return (
                app._variant_set.active_id,
                app.current_file.variant_id if app.current_file else None,
            )

    active_id, variant_id = asyncio.run(_drive())
    assert active_id == "b"
    assert variant_id == "b"


def test_load_project_unknown_active_variant_falls_back(tmp_path: Path) -> None:
    """An unknown manifest active_variant warns and activates variant 1.

    Intent: LLR-005.6 — a stale ``active_variant`` is a status warning plus
    the first-variant fallback, never a crash or a refused load.
    """
    from s19_app.tui.app import S19TuiApp

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = app.workarea / "proj"
        project_dir.mkdir(parents=True, exist_ok=True)
        (project_dir / "a.s19").write_text(S19_A, encoding="utf-8")
        (project_dir / "b.s19").write_text(S19_B, encoding="utf-8")
        (project_dir / "project.json").write_text(
            json.dumps({"schema_version": 1, "active_variant": "ghost"}),
            encoding="utf-8",
        )
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            for _ in range(12):
                await pilot.pause()
            warned = any(
                "active_variant 'ghost'" in line for line in app.log_lines
            )
            return (app._variant_set.active_id, warned)

    active_id, warned = asyncio.run(_drive())
    assert active_id == "a", "unknown active_variant must fall back to variant 1"
    assert warned, "the fallback must be announced as a status warning"


# ---------------------------------------------------------------------------
# F-S-03 — manifest entry containment (project directory only)
# ---------------------------------------------------------------------------


def test_manifest_containment_skips_unsafe_entries(tmp_path: Path) -> None:
    """Escaping and absolute entries are one ERROR each and skipped.

    Intent: F-S-03 / LLR-006.1 — ``batch``/``assignments`` entries resolve
    against the project directory ONLY: a ``..`` escape and an absolute
    path each produce exactly one ERROR ``MANIFEST-PATH-ESCAPE`` finding
    and are dropped, while the safe relative entry survives — the read
    never aborts.
    """
    project_dir = _make_project(tmp_path, {"a.s19": S19_A})
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": None,
                "batch": [
                    "../escape.json",
                    "C:\\evil\\abs.json",
                    "ok.json",
                ],
                "assignments": {"a": ["../../outside.json"]},
            }
        ),
        encoding="utf-8",
    )

    manifest = read_project_manifest(project_dir)

    assert manifest is not None
    escape_issues = [
        issue for issue in manifest.issues if issue.code == MANIFEST_PATH_ESCAPE
    ]
    assert len(escape_issues) == 3, (
        f"expected one ERROR per unsafe entry, got: "
        f"{[issue.message for issue in manifest.issues]}"
    )
    assert all(
        issue.severity is ValidationSeverity.ERROR for issue in escape_issues
    )
    assert manifest.batch == [(project_dir / "ok.json").resolve()]
    assert manifest.assignments == {"a": []}


# ---------------------------------------------------------------------------
# LLR-006.2 — deterministic double-run equality
# ---------------------------------------------------------------------------


def test_double_run_orderings_identical(tmp_path: Path) -> None:
    """Two runs over the same inputs produce identical orderings.

    Intent: LLR-006.2 — variants execute in ``ProjectVariantSet`` order
    (outer) and per variant in batch-then-assignments order (inner); the
    plan and the result sequence are pure functions of the inputs, so two
    runs compare equal.
    """
    project_dir = _make_project(tmp_path, {"b.s19": S19_B, "a.s19": S19_A})
    chk_batch = _write_v2_document(
        project_dir / "chk1.json",
        [{"type": "bytes", "address": "0x1000", "bytes": "01"}],
        kind="check",
    )
    chk_extra = _write_v2_document(
        project_dir / "chk2.json",
        [{"type": "bytes", "address": "0x2000", "bytes": "0A"}],
        kind="check",
    )
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "a",
                "batch": ["chk1.json"],
                "assignments": {"b": ["chk2.json"]},
            }
        ),
        encoding="utf-8",
    )
    vset = _variant_set(project_dir)

    def _run() -> tuple:
        manifest = read_project_manifest(project_dir)
        plan = plan_variant_executions(vset, manifest, scope=SCOPE_ALL)
        results = execute_variant_plan(plan, project_dir)
        plan_shape = [
            (variant.variant_id, tuple(path.name for path in files))
            for variant, files in plan
        ]
        result_shape = [
            (
                result.variant_id,
                result.status,
                [check.to_dict()["aggregates"] for check in result.check_results],
            )
            for result in results
        ]
        return plan_shape, result_shape

    first_plan, first_results = _run()
    second_plan, second_results = _run()

    assert first_plan == [
        ("a", ("chk1.json",)),
        ("b", ("chk1.json", "chk2.json")),
    ]
    assert first_plan == second_plan
    assert first_results == second_results


# ---------------------------------------------------------------------------
# LLR-006.4 — per-variant isolation under an injected failure
# ---------------------------------------------------------------------------


def test_failing_variant_never_aborts_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One crashing variant yields one "error"; len(results) == N always.

    Intent: LLR-006.4 — an exception inside one variant's execution is
    captured as that variant's ``"error"`` result with a diagnostic; every
    other variant still executes.
    """
    project_dir = _make_project(
        tmp_path, {"a.s19": S19_A, "b.s19": S19_B, "c.s19": S19_A}
    )
    chk = _write_v2_document(
        project_dir / "chk.json",
        [{"type": "bytes", "address": "0x1000", "bytes": "01"}],
        kind="check",
    )
    vset = _variant_set(project_dir)

    real_build = ves.build_loaded_s19

    def _exploding_build(path, s19, a2l_path, a2l_data):
        if path.name == "b.s19":
            raise RuntimeError("injected parse failure")
        return real_build(path, s19, a2l_path, a2l_data)

    monkeypatch.setattr(ves, "build_loaded_s19", _exploding_build)

    plan = plan_variant_executions(vset, None, scope=SCOPE_ALL, fallback_batch=[chk])
    results = execute_variant_plan(plan, project_dir)

    assert len(results) == 3, "isolation: one result per planned variant, always"
    statuses = {result.variant_id: result.status for result in results}
    assert statuses == {"a": "ok", "b": "error", "c": "ok"}
    failing = next(result for result in results if result.variant_id == "b")
    assert any("injected parse failure" in line for line in failing.diagnostics)


# ---------------------------------------------------------------------------
# LLR-006.3/006.5 — 2-variant batch execution with variant_id stamps
# ---------------------------------------------------------------------------


def test_batch_execution_stamps_variant_ids(tmp_path: Path) -> None:
    """Each variant gets one ChangeSummary + one CheckRunResult, stamped.

    Intent: LLR-006.5 — the service consumes ``apply_change_document`` /
    ``run_check_document`` outputs kind-discriminated per file and stamps
    ``variant_id`` through the engines' parameter; the per-variant image is
    parsed inside the call (LLR-006.3), so variant ``a`` applies at 0x1000
    while variant ``b`` skips it as outside.
    """
    project_dir = _make_project(tmp_path, {"a.s19": S19_A, "b.s19": S19_B})
    chg = _write_v2_document(
        project_dir / "chg.json",
        [{"type": "bytes", "address": "0x1000", "bytes": "AA"}],
    )
    chk = _write_v2_document(
        project_dir / "chk.json",
        [{"type": "bytes", "address": "0x2000", "bytes": "0A"}],
        kind="check",
    )
    vset = _variant_set(project_dir)

    plan = plan_variant_executions(
        vset, None, scope=SCOPE_ALL, fallback_batch=[chg, chk]
    )
    results = execute_variant_plan(plan, project_dir)

    assert [result.variant_id for result in results] == ["a", "b"]
    for result in results:
        assert result.status == "ok"
        assert len(result.change_summaries) == 1
        assert len(result.check_results) == 1
        assert result.change_summaries[0].variant_id == result.variant_id
        assert result.check_results[0].variant_id == result.variant_id

    by_id = {result.variant_id: result for result in results}
    assert by_id["a"].change_summaries[0].counts["applied"] == 1
    assert by_id["b"].change_summaries[0].counts["skipped-outside"] == 1
    assert by_id["a"].check_results[0].aggregates["uncheckable"] == 1
    assert by_id["b"].check_results[0].aggregates["passed"] == 1


# ---------------------------------------------------------------------------
# E6 duplicate-id decision — colliding stems become full filenames
# ---------------------------------------------------------------------------


def test_duplicate_stem_ids_become_filenames(tmp_path: Path) -> None:
    """``fw.s19`` + ``fw.hex`` get ids ``fw.s19`` / ``fw.hex``; lone stems stay stems.

    Intent: the operator-ratified E6 duplicate-id decision applied in
    ``workspace.build_variant_set`` — colliding stems make the FULL
    FILENAME the id (deterministic, display-consistent); non-colliding
    variants keep the stem id.
    """
    vset = build_variant_set(
        "proj", [Path("fw.s19"), Path("fw.hex"), Path("other.s19")]
    )

    assert [variant.variant_id for variant in vset.variants] == [
        "fw.hex",
        "fw.s19",
        "other",
    ]
    assert vset.active_id == "fw.hex"


# ---------------------------------------------------------------------------
# AT-017.2 (batch-16, HLR-017) — consumer pickup of saved batch+assignments
# ---------------------------------------------------------------------------


def test_at017_2_consumer_pickup_of_saved_composition(tmp_path: Path) -> None:
    """``plan_variant_executions`` applies saved ``batch + assignments[vid]``.

    Intent (AT-017.2 / LLR-017.4, batch-16): the SCOPE-1 closure is only real
    if the persisted composition is picked up by the consumer. We write a
    ``project.json`` carrying a project-wide ``batch`` and a per-variant
    ``assignments`` entry, read it back through the SAME reader the save path
    uses (``read_project_manifest``), and assert the planned file tuple for the
    assigned variant EXACTLY equals ``tuple(batch) + tuple(assignments[vid])``
    in the LLR-006.2 inner order — exact, not "non-empty". A wrong key or a
    dropped list would change the tuple, so this test fails if the assignment
    silently drops.
    """
    project_dir = _make_project(tmp_path, {"a.s19": S19_A, "b.s19": S19_B})
    _write_v2_document(
        project_dir / "doc.json",
        [{"type": "bytes", "address": "0x1000", "bytes": "AA"}],
    )
    _write_v2_document(
        project_dir / "extra.json",
        [{"type": "bytes", "address": "0x2000", "bytes": "BB"}],
    )
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "b",
                "batch": ["doc.json"],
                "assignments": {"b": ["extra.json"]},
            }
        ),
        encoding="utf-8",
    )

    manifest = read_project_manifest(project_dir)
    assert manifest is not None
    vset = _variant_set(project_dir)

    plan = plan_variant_executions(vset, manifest, scope=SCOPE_ALL)
    files_by_id = {variant.variant_id: files for variant, files in plan}

    expected_b = (
        (project_dir / "doc.json").resolve(),
        (project_dir / "extra.json").resolve(),
    )
    assert files_by_id["b"] == expected_b, (
        "the assigned variant's plan must be exactly batch + assignments[vid] "
        f"in order; got {files_by_id['b']}"
    )
    # The unassigned variant gets only the project-wide batch (no assignment).
    assert files_by_id["a"] == ((project_dir / "doc.json").resolve(),)


# ---------------------------------------------------------------------------
# LLR-002.7 headless — save-back files land under the project directory
# ---------------------------------------------------------------------------


def test_save_back_files_land_under_project_dir(tmp_path: Path) -> None:
    """Applied variants save back as <variant_id>-patched.s19, promptless.

    Intent: LLR-002.7 headless parameter — a change file that applies ≥1
    entry on an S19 variant persists the patched image into the PROJECT
    directory under the default ``<variant_id>-patched.s19`` name with no
    prompt; a variant with zero applied entries writes nothing.
    """
    project_dir = _make_project(tmp_path, {"a.s19": S19_A, "b.s19": S19_B})
    chg = _write_v2_document(
        project_dir / "chg.json",
        [
            {"type": "bytes", "address": "0x1000", "bytes": "AA"},
            {"type": "bytes", "address": "0x2000", "bytes": "BB"},
        ],
    )
    vset = _variant_set(project_dir)

    plan = plan_variant_executions(vset, None, scope=SCOPE_ALL, fallback_batch=[chg])
    results = execute_variant_plan(plan, project_dir)

    assert (project_dir / "a-patched.s19").exists()
    assert (project_dir / "b-patched.s19").exists()
    for result in results:
        saved = result.change_summaries[0].saved_path
        assert saved is not None
        assert saved.parent == project_dir.resolve()
        assert saved.name == f"{result.variant_id}-patched.s19"


# ---------------------------------------------------------------------------
# LLR-006.6 — execute_scope routing guard (no project → status, no crash)
# ---------------------------------------------------------------------------


def test_execute_scope_without_project_is_status_error(tmp_path: Path) -> None:
    """Routing execute_scope with no project is one status line, app alive.

    Intent: LLR-006.6 — ``execute_scope`` is the ninth routed action; with
    no active project / variant set the router answers with a status
    message and stays responsive (the nine-action pin itself is asserted in
    ``tests/test_tui_patch_editor_v2.py``).
    """
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.screens_directionb import PatchEditorPanel

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            panel.request_action("execute_scope")
            await pilot.pause()
            refused = any(
                "Execute: no project variants" in line for line in app.log_lines
            )
            # Responsiveness probe: a follow-up routed action still works.
            panel.request_action("validate_doc")
            await pilot.pause()
            alive = any(line.startswith("Validate:") for line in app.log_lines)
            return refused, alive

    refused, alive = asyncio.run(_drive())
    assert refused, "execute_scope without a project must be a status refusal"
    assert alive, "the app must stay responsive after the refusal"
