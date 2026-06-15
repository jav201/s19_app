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
