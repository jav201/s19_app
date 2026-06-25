"""TUI manifest write+verify-on-save tests (batch-11 I4, HLR-004).

Coverage map (test -> TC -> LLR):

- TC-004a / LLR-004.1 — ``test_project_save_writes_and_verifies_manifest``:
  a project save through ``_handle_save_dialog`` writes ``project.json`` under
  the project dir AND surfaces a quiet "manifest verified" status — the save
  invokes the serialize->write->verify pipeline and binds the result, without
  changing the existing file-copy save behavior.
- TC-D1 / LLR-004.2 (verified branch) — same test asserts the quiet status
  string; the written manifest re-reads through the reader oracle with the
  saved variant as ``active_variant``.
- TC-D1 / LLR-004.2 (mismatch branch) —
  ``test_manifest_mismatch_surfaces_loud_notice_naming_drift``: a verify result
  forced to MISMATCH (a tampered on-disk manifest) surfaces a loud error notice
  whose body names the drifting key, plus a "MISMATCH" status line.
- LLR-004.2 (refusal branch) —
  ``test_manifest_write_refusal_surfaces_error_notice_no_crash``: a write that
  returns ``(None, issues)`` (containment refusal — project dir outside the
  work area) surfaces an error notice with the plain-text issue message and
  does NOT crash; no ``project.json`` is written.
- TC-004b / LLR-004.3 — ``test_manifest_writer_module_is_headless``: the
  serialize/write/verify module imports neither ``textual`` nor ``logging``
  (import-statement form, V-4 probe), keeping the write logic headless.

These tests encode WHY: batch-11 closes the read-only-manifest gap by giving
the TUI save the WRITE side plus a verify-on-write integrity check (the batch-10
verify-on-save discipline, JSON variant). A save that silently fails to persist
``project.json``, or one that "succeeds" with a manifest the reader can't use,
would defeat the whole feature — so the surfacing (quiet verified / loud
mismatch / loud refusal) is the observable contract under test.

Harness: the ``App.run_test()`` pilot pattern of ``tests/test_tui_variants.py``
(``async def _drive()`` wrapped by ``asyncio.run``), driving the real
``_handle_save_dialog`` handler with a ``SaveProjectPayload``.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services.variant_execution_service import (
    PROJECT_MANIFEST_NAME,
    read_project_manifest,
)

# Minimal valid S19 image (checksum verified against s19_app.core.S19File).
S19_A = "S107100001020304DE\nS9030000FC\n"
S19_B = "S10720000A0B0C0DAA\nS9030000FC\n"  # 4 bytes at 0x2000


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so the deferred apply chain runs."""
    for _ in range(count):
        await pilot.pause()


def _notices(app: S19TuiApp) -> list[tuple[str, str]]:
    """Capture ``(title, message)`` for every ``notify`` call on the app.

    Returns the mutable list the patched ``notify`` appends to so a test can
    assert on the loud-notice surface (LLR-004.2) without a real screen.
    """
    captured: list[tuple[str, str]] = []
    original = app.notify

    def _patched(message: str, *, title: str = "", **kwargs):
        captured.append((title, message))
        return original(message, title=title, **kwargs)

    app.notify = _patched  # type: ignore[method-assign]
    return captured


def _statuses(app: S19TuiApp) -> list[str]:
    """Capture every ``set_status`` message into the returned list."""
    captured: list[str] = []
    original = app.set_status
    app.set_status = lambda message: (captured.append(message), original(message))[1]  # type: ignore[method-assign]
    return captured


# --------------------------------------------------------------------------- #
# TC-004a / TC-D1 (verified) / LLR-004.1 + LLR-004.2
# --------------------------------------------------------------------------- #


def test_project_save_writes_and_verifies_manifest(tmp_path: Path) -> None:
    """A project save writes project.json and surfaces a quiet verified status.

    Intent (LLR-004.1/004.2): the save handler invokes the
    serialize->write->verify pipeline; ``project.json`` lands under the project
    dir, re-reads through the reader oracle with the saved variant as
    ``active_variant``, and the operator sees a quiet "manifest verified" line —
    no loud notice on a clean save.
    """
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        statuses = _statuses(app)
        notices = _notices(app)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(external)
            await _flush(pilot)
            payload = app_module.SaveProjectPayload(
                parent_folder=str(app.workarea), project_name="proj"
            )
            app._handle_save_dialog(payload)
            await _flush(pilot)
            project_dir = app.workarea / "proj"
            manifest = read_project_manifest(project_dir)
            return (
                (project_dir / PROJECT_MANIFEST_NAME).exists(),
                manifest.active_variant if manifest else None,
                manifest.issues if manifest else None,
                statuses,
                notices,
                app._variant_set.active_id if app._variant_set else None,
            )

    exists, active, issues, statuses, notices, active_id = asyncio.run(_drive())
    assert exists, "save must write project.json under the project dir"
    assert active == active_id, "manifest active_variant must equal the saved variant"
    assert issues == [], "the written manifest must re-read with zero reader issues"
    assert any("manifest verified" in m.lower() for m in statuses), (
        f"a clean save must surface a quiet verified status; got {statuses}"
    )
    assert not any("mismatch" in title.lower() for title, _ in notices), (
        f"a clean save must NOT raise a mismatch notice; got {notices}"
    )


# --------------------------------------------------------------------------- #
# TC-D1 (mismatch) / LLR-004.2 — loud notice naming the drift
# --------------------------------------------------------------------------- #


def test_manifest_mismatch_surfaces_loud_notice_naming_drift(
    tmp_path: Path,
) -> None:
    """A verify MISMATCH surfaces a loud error notice naming the drifting key.

    Intent (LLR-004.2): on mismatch the operator must get a prominent notice
    that NAMES what drifted, plus a MISMATCH status line. We force the mismatch
    by tampering the on-disk ``project.json`` between write and verify (patching
    ``write_project_manifest`` to flip ``active_variant`` after the real write),
    so the real ``verify_written_manifest`` re-reads a drifted file and the real
    surfacing path runs (Rule 9: the planted fault matches the asserted drift).
    """
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        statuses = _statuses(app)
        notices = _notices(app)

        real_write = app_module.write_project_manifest

        def _tampering_write(variant_set, project_root, base_dir, **kwargs):
            written, issues = real_write(
                variant_set, project_root, base_dir, **kwargs
            )
            if written is not None:
                payload = json.loads(written.read_text(encoding="utf-8"))
                payload["active_variant"] = "tampered-not-a-real-id"
                written.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return written, issues

        app_module.write_project_manifest = _tampering_write
        try:
            async with app.run_test() as pilot:
                await pilot.pause()
                app.load_selected_file(external)
                await _flush(pilot)
                payload = app_module.SaveProjectPayload(
                    parent_folder=str(app.workarea), project_name="proj"
                )
                app._handle_save_dialog(payload)
                await _flush(pilot)
                return statuses, notices
        finally:
            app_module.write_project_manifest = real_write

    statuses, notices = asyncio.run(_drive())
    assert any("mismatch" in m.lower() for m in statuses), (
        f"a tampered manifest must surface a MISMATCH status; got {statuses}"
    )
    mismatch_notices = [
        (title, message)
        for title, message in notices
        if "mismatch" in title.lower()
    ]
    assert mismatch_notices, f"a mismatch must raise a loud notice; got {notices}"
    assert any("active_variant" in message for _, message in mismatch_notices), (
        f"the mismatch notice must name the drifting key; got {mismatch_notices}"
    )


# --------------------------------------------------------------------------- #
# LLR-004.2 — write refusal/containment -> error notice, no crash, no file
# --------------------------------------------------------------------------- #


def test_manifest_write_refusal_surfaces_error_notice_no_crash(
    tmp_path: Path,
) -> None:
    """A write that returns (None, issues) surfaces an error notice, no crash.

    Intent (LLR-004.2): when ``write_project_manifest`` refuses
    (collect-don't-abort: a containment / IO failure returns ``(None, issues)``,
    LLR-002.3), the save handler must surface an error notice carrying the
    plain-text issue message and must NOT crash. The file-copy save into the
    work area still succeeds; only the manifest write is forced to refuse. We
    patch ``write_project_manifest`` to return the documented refusal tuple, so
    the real surfacing branch runs (Rule 9: the planted failure matches the
    asserted "no file / error notice" outcome).
    """
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        statuses = _statuses(app)
        notices = _notices(app)

        from s19_app.tui.services.manifest_writer import (
            _manifest_write_containment_issue,
        )

        real_write = app_module.write_project_manifest

        def _refusing_write(variant_set, project_root, base_dir, **kwargs):
            return None, [
                _manifest_write_containment_issue(
                    "the manifest write target failed work-area containment "
                    "validation - no file was written"
                )
            ]

        app_module.write_project_manifest = _refusing_write
        try:
            async with app.run_test() as pilot:
                await pilot.pause()
                app.load_selected_file(external)
                await _flush(pilot)
                payload = app_module.SaveProjectPayload(
                    parent_folder=str(app.workarea), project_name="proj"
                )
                app._handle_save_dialog(payload)
                await _flush(pilot)
                project_dir = app.workarea / "proj"
                return (
                    (project_dir / PROJECT_MANIFEST_NAME).exists(),
                    statuses,
                    notices,
                )
        finally:
            app_module.write_project_manifest = real_write

    manifest_exists, statuses, notices = asyncio.run(_drive())
    assert not manifest_exists, (
        "a refused write must NOT leave a project.json behind"
    )
    refusal_notices = [
        (title, message)
        for title, message in notices
        if "manifest write failed" in title.lower()
    ]
    assert refusal_notices, (
        f"a write refusal must surface an error notice; got {notices}"
    )
    assert any(
        "containment" in message for _, message in refusal_notices
    ), "the refusal notice must carry the plain-text issue message"


# --------------------------------------------------------------------------- #
# TC-004b / LLR-004.3 — the writer service is headless (no textual, no logging)
# --------------------------------------------------------------------------- #


def test_manifest_writer_module_is_headless() -> None:
    """The serialize/write/verify module imports no textual and no logging.

    Intent (LLR-004.3 / V-4): the manifest writer must stay headless and
    side-effect-quiet so it is reusable and testable without a running app. The
    probe matches IMPORT STATEMENTS (not the bare token, V-4) so a docstring
    mention never trips it.
    """
    source = Path(
        "s19_app/tui/services/manifest_writer.py"
    ).read_text(encoding="utf-8")
    for line in source.splitlines():
        stripped = line.strip()
        assert not stripped.startswith("import textual"), line
        assert not stripped.startswith("from textual"), line
        assert not stripped.startswith("import logging"), line
        assert not stripped.startswith("from logging"), line
        assert "getLogger" not in stripped, line


# --------------------------------------------------------------------------- #
# batch-16 / HLR-017 — per-variant assignments + project-wide batch persist
# through the SHIPPED save handler (the SCOPE-1 closure).
# --------------------------------------------------------------------------- #


def _save_through_handler(
    app: S19TuiApp,
    *,
    primary: Path,
    batch: tuple[str, ...] = (),
    assignments: dict | None = None,
):
    """Drive ``_handle_save_dialog`` with a composed payload; return the pilot fn.

    Builds an ``async`` driver that loads ``primary`` as the active variant and
    invokes the real save handler with ``batch`` / ``assignments`` populated
    programmatically (Inc-1: no UI). The caller wraps it in ``asyncio.run`` and
    reads ``project.json`` off disk — exercising the WHAT through the shipped
    surface, not the writer's direct kwargs (the SCOPE-1 hole).
    """

    async def _drive():
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(primary)
            await _flush(pilot)
            payload = app_module.SaveProjectPayload(
                parent_folder=str(app.workarea),
                project_name="proj",
                batch=batch,
                assignments=assignments or {},
            )
            app._handle_save_dialog(payload)
            await _flush(pilot)
            return app.workarea / "proj"

    return _drive


def test_at017_1_save_persists_and_round_trips_composition(tmp_path: Path) -> None:
    """AT-017.1 — a save through the handler persists batch+assignments, 0-drift.

    Intent (HLR-017 / LLR-017.4): when the payload carries a project-wide
    ``batch`` and a per-variant ``assignments`` entry, the SHIPPED save handler
    writes them into ``project.json`` so that ``read_project_manifest`` re-reads
    them EXACTLY (resolved against the project dir), the verify reports 0 drift
    (clean "manifest verified" status, no mismatch notice), and
    ``active_variant`` is preserved. RED pre-fix: the handler passed no kwargs,
    so the on-disk ``batch`` / ``assignments`` were empty.
    """
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    statuses: list[str] = []
    notices: list[tuple[str, str]] = []

    app = S19TuiApp(base_dir=tmp_path)
    # Pre-seed the project dir with a second variant + the assignable docs so
    # the post-copy variant rebuild yields a >1 variant set and the entries
    # resolve inside the work area.
    project_dir = app.workarea / "proj"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "b.s19").write_text(S19_B, encoding="utf-8")
    (project_dir / "doc.json").write_text("{}", encoding="utf-8")
    (project_dir / "extra.json").write_text("{}", encoding="utf-8")

    statuses = _statuses(app)
    notices = _notices(app)
    asyncio.run(
        _save_through_handler(
            app,
            primary=external,
            batch=("doc.json",),
            assignments={"b": ("extra.json",)},
        )()
    )

    manifest = read_project_manifest(project_dir)
    assert manifest is not None
    assert manifest.issues == [], f"re-read must be clean; got {manifest.issues}"
    assert manifest.batch == [(project_dir / "doc.json").resolve()], (
        f"on-disk batch must equal the assigned file; got {manifest.batch}"
    )
    assert manifest.assignments == {
        "b": [(project_dir / "extra.json").resolve()]
    }, f"on-disk assignments[vid] must equal the assigned file; got {manifest.assignments}"
    assert manifest.active_variant == (
        app._variant_set.active_id if app._variant_set else None
    ), "active_variant must be preserved across the composition save"
    assert any("manifest verified" in m.lower() for m in statuses), (
        f"a faithful composition save must verify 0-drift; got {statuses}"
    )
    assert not any("mismatch" in title.lower() for title, _ in notices), (
        f"a faithful save must NOT raise a mismatch notice; got {notices}"
    )


def test_at017_3_zero_selection_save_no_regression(tmp_path: Path) -> None:
    """AT-017.3 — an empty payload writes empty batch/assignments, preserved.

    Intent (HLR-017 zero-selection / LLR-017.1): a save that selects nothing
    (default empty ``batch`` / ``assignments``) still succeeds, writes
    ``batch == []`` / ``assignments == {}`` on disk, and preserves
    ``active_variant`` — identical to the prior active-variant-only save. This
    is a NO-REGRESSION guard, not a counterfactual.
    """
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    app = S19TuiApp(base_dir=tmp_path)
    statuses = _statuses(app)
    project_dir = asyncio.run(_save_through_handler(app, primary=external)())

    manifest = read_project_manifest(project_dir)
    assert manifest is not None
    assert manifest.issues == []
    assert manifest.batch == []
    assert manifest.assignments == {}
    assert manifest.active_variant == (
        app._variant_set.active_id if app._variant_set else None
    )
    assert any("manifest verified" in m.lower() for m in statuses), statuses


def test_at017_4_escaping_assignment_refused_no_file_written(
    tmp_path: Path,
) -> None:
    """AT-017.4 — an escaping assignment is refused: notice surfaced, no file.

    Intent (HLR-017 security / LLR-017.4, D-SEC): an assignment entry that is
    absolute or ``../``-escaping must drive the writer's ``_reject_unsafe_entry``
    through the SHIPPED handler — surfacing a POSITIVE refusal observable (the
    "Manifest write failed" error notice) AND leaving NO ``project.json`` behind
    (not merely "no escaping entry in the file"). RED pre-fix: the handler
    ignored assignments, so the refusal path never fired and no notice appeared.
    """
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    app = S19TuiApp(base_dir=tmp_path)
    statuses = _statuses(app)
    notices = _notices(app)
    project_dir = asyncio.run(
        _save_through_handler(
            app,
            primary=external,
            assignments={"a": ("../../escape.json",)},
        )()
    )

    assert not (project_dir / PROJECT_MANIFEST_NAME).exists(), (
        "an escaping assignment must refuse the write — no project.json"
    )
    refusal_notices = [
        (title, message)
        for title, message in notices
        if "manifest write failed" in title.lower()
    ]
    assert refusal_notices, (
        f"an escaping assignment must surface a refusal notice; got {notices}"
    )
    assert any("mismatch" not in s.lower() for s in statuses)


def test_at017_5_stem_collision_assignment_keyed_by_full_filename(
    tmp_path: Path,
) -> None:
    """AT-017.5 — a stem-collision assignment round-trips under the full filename.

    Intent (HLR-017 / D-KEY): a project with ``fw.s19`` + ``fw.hex`` collides on
    the stem ``fw``, so each ``variant_id`` is the FULL FILENAME
    (``workspace.build_variant_set``). Assigning to the full-filename id must
    round-trip on disk AND be picked up by ``plan_variant_executions`` under
    that full-filename key — proving the key is sourced from ``variant_id`` and
    never recomputed as ``Path.stem`` (a stem key would silently drop). RED
    pre-fix: empty manifest.
    """
    from s19_app.tui.services.variant_execution_service import (
        SCOPE_ALL,
        plan_variant_executions,
    )
    from s19_app.tui.workspace import build_variant_set, validate_project_files

    external = tmp_path / "fw.s19"
    external.write_text(S19_A, encoding="utf-8")

    app = S19TuiApp(base_dir=tmp_path)
    project_dir = app.workarea / "proj"
    project_dir.mkdir(parents=True, exist_ok=True)
    # The colliding sibling + the assignable doc, pre-seeded in the work area.
    (project_dir / "fw.hex").write_text(":00000001FF\n", encoding="utf-8")
    (project_dir / "extra.json").write_text("{}", encoding="utf-8")

    asyncio.run(
        _save_through_handler(
            app,
            primary=external,
            assignments={"fw.hex": ("extra.json",)},
        )()
    )

    manifest = read_project_manifest(project_dir)
    assert manifest is not None
    assert manifest.issues == []
    assert manifest.assignments == {
        "fw.hex": [(project_dir / "extra.json").resolve()]
    }, f"the assignment must be keyed by the FULL filename id; got {manifest.assignments}"

    data_files, _a2l, error = validate_project_files(project_dir)
    assert error is None
    vset = build_variant_set("proj", data_files)
    assert "fw.hex" in {v.variant_id for v in vset.variants}
    plan = plan_variant_executions(vset, manifest, scope=SCOPE_ALL)
    files_by_id = {v.variant_id: files for v, files in plan}
    assert files_by_id["fw.hex"] == ((project_dir / "extra.json").resolve(),), (
        "consumer must pick up the collision-keyed assignment under the full id"
    )


# --------------------------------------------------------------------------- #
# White-box TC-301/302/303 — payload carries fields; handler threads them.
# --------------------------------------------------------------------------- #


def test_tc301_payload_carries_batch_and_assignments() -> None:
    """TC-301 / LLR-017.1 — the payload deep-equals constructed composition.

    Intent: ``SaveProjectPayload`` carries ``batch`` / ``assignments``; omitted
    ⇒ empty defaults (zero-selection identity).
    """
    payload = app_module.SaveProjectPayload(
        parent_folder="p",
        project_name="proj",
        batch=("doc.json",),
        assignments={"b": ("extra.json",)},
    )
    assert payload.batch == ("doc.json",)
    assert payload.assignments == {"b": ("extra.json",)}

    bare = app_module.SaveProjectPayload(parent_folder="p", project_name="proj")
    assert bare.batch == ()
    assert bare.assignments == {}


def test_tc302_303_handler_threads_batch_assignments_to_write_and_verify(
    tmp_path: Path,
) -> None:
    """TC-302/303 / LLR-017.2 — handler passes batch+assignments to write+verify.

    Intent (R1): the save handler threads the SAME ``batch`` / ``assignments``
    into BOTH ``write_project_manifest`` (TC-302) AND ``verify_written_manifest``
    (TC-303) — mismatched intent would make verify report spurious drift. We
    spy on both substrate functions through ``app_module`` and assert each
    received the payload values.
    """
    external = tmp_path / "a.s19"
    external.write_text(S19_A, encoding="utf-8")

    app = S19TuiApp(base_dir=tmp_path)
    project_dir = app.workarea / "proj"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "b.s19").write_text(S19_B, encoding="utf-8")
    (project_dir / "doc.json").write_text("{}", encoding="utf-8")
    (project_dir / "extra.json").write_text("{}", encoding="utf-8")

    write_calls: list[dict] = []
    verify_calls: list[dict] = []
    real_write = app_module.write_project_manifest
    real_verify = app_module.verify_written_manifest

    def _spy_write(variant_set, project_root, base_dir, **kwargs):
        write_calls.append(kwargs)
        return real_write(variant_set, project_root, base_dir, **kwargs)

    def _spy_verify(project_dir_, variant_set, project_root, **kwargs):
        verify_calls.append(kwargs)
        return real_verify(project_dir_, variant_set, project_root, **kwargs)

    app_module.write_project_manifest = _spy_write
    app_module.verify_written_manifest = _spy_verify
    try:
        asyncio.run(
            _save_through_handler(
                app,
                primary=external,
                batch=("doc.json",),
                assignments={"b": ("extra.json",)},
            )()
        )
    finally:
        app_module.write_project_manifest = real_write
        app_module.verify_written_manifest = real_verify

    assert write_calls, "write_project_manifest must be called"
    assert verify_calls, "verify_written_manifest must be called"
    assert write_calls[-1].get("batch") == ("doc.json",)
    assert write_calls[-1].get("assignments") == {"b": ("extra.json",)}
    # R1: identical intent threaded to verify.
    assert verify_calls[-1].get("batch") == write_calls[-1].get("batch")
    assert verify_calls[-1].get("assignments") == write_calls[-1].get("assignments")
