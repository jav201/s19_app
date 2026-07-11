"""
Before/after save-back report tests — s19_app batch-24, increment I4
(US-034 / HLR-038, LLR-038.2/.3/.4/.5).

Layer B (black-box, Textual Pilot over the shipped chain):

- **AT-038a** (GATE, C-10 + C-12, Q-M1 observation chain) — apply → save-back
  with a COLLIDING typed name → offered trigger (key ``b``) → the surfaced
  status path equals the single new file in the reports-directory diff → that
  file is re-read from disk: ``-``/``+`` bytes at the patched address, linkage
  row, provenance header whose "after" is the pinned dedup literal
  ``img-patched_1.s19`` (never the typed-name echo). The US-034 counterfactual
  carrier: pre-implementation the key is unbound and no file appears.
- **AT-038b/c/d** (GUARD-class, Q-m1) — declined save / missing original /
  stale cross-project summary each surface a POSITIVE refusal diagnostic and
  write 0 files.

Layer A (white-box on the composer seam, ``before_after_service`` imported
lazily so this file COLLECTS on the pre-implementation tree — the AT-038a RED
capture requirement):

- **TC-038.3** — composer happy path, own-filename-regex ownership, symlink
  destination refusal (S-F4), ctl-bearing symbol md/html pair consistency
  (the ``_strip_ctl`` factoring).
- **TC-038.4** — all four LLR-038.4 refusal classes + the no-project D-3
  refusal naming the manual A<->B path; every class writes 0 files.
- **TC-038.5** — inspection: no ``logging``/``textual`` import in the module
  (LLR-038.5 / V-4) and destination construction via ``REPORTS_DIR_NAME``.

Fixtures are synthetic (public data only). No pytest-asyncio: every Pilot AT
is a sync test wrapping ``asyncio.run`` (idiom ``test_tui_patch_layout.py``).
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes import DISPOSITION_DOMAIN, emit_s19_from_mem_map
from s19_app.tui.changes.model import ChangeSummary, ChangeSummaryEntry
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services.load_service import build_loaded_s19

#: Black-box pin of the LLR-038.2 filename scheme (module-independent so the
#: AT never imports the composer; ownership is asserted in TC-038.3).
_MD_NAME = re.compile(r"^\d{8}T\d{6}Z(-\d{2})?-before-after-report\.md$")
_HTML_NAME = re.compile(r"^\d{8}T\d{6}Z(-\d{2})?-before-after-report\.html$")

_PROVENANCE_BEFORE = re.compile(r"- Original image \(before\): `(.*)`")
_PROVENANCE_AFTER = re.compile(r"- Saved patched image \(after\): `(.*)`")


def _bas():
    """Import the composer module lazily (absent on the pre-fix tree)."""
    from s19_app.tui.services import before_after_service

    return before_after_service


def _fixed_clock() -> datetime:
    """Deterministic UTC clock for filename asserts."""
    return datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc)


def _make_s19_image(
    directory: Path, name: str = "img.s19", patched: bool = False
) -> Path:
    """Emit a 16-byte synthetic S19 at 0x100 (``AA BB`` head when patched)."""
    mem_map = {0x100 + offset: 0x00 for offset in range(16)}
    if patched:
        mem_map[0x100] = 0xAA
        mem_map[0x101] = 0xBB
    text = emit_s19_from_mem_map(mem_map, [(0x100, 0x110)])
    path = directory / name
    path.write_text(text, encoding="ascii")
    return path


def _load_image(app: S19TuiApp, s19_path: Path) -> None:
    """Install an S19 ``LoadedFile`` snapshot on the app (ratified shortcut)."""
    s19 = S19File(str(s19_path))
    app.current_file = build_loaded_s19(s19_path, s19, a2l_path=None, a2l_data=None)


def _set_entry_inputs(app: S19TuiApp, address: str, bytes_text: str) -> None:
    """Fill the Patch Editor entry inputs (TC-051 idiom)."""
    from textual.widgets import Input

    app.query_one("#patch_entry_address_input", Input).value = address
    app.query_one("#patch_entry_value_input", Input).value = ""
    app.query_one("#patch_entry_bytes_input", Input).value = bytes_text


def _notices(app: S19TuiApp) -> list[tuple[str, str, str]]:
    """Capture ``(title, message, severity)`` for every ``notify`` call."""
    captured: list[tuple[str, str, str]] = []
    original = app.notify

    def _patched(message: str, *, title: str = "", severity: str = "information", **kwargs):
        captured.append((title, str(message), severity))
        return original(message, title=title, severity=severity, **kwargs)

    app.notify = _patched  # type: ignore[method-assign]
    return captured


def _statuses(app: S19TuiApp) -> list[str]:
    """Capture every ``set_status`` message into the returned list."""
    captured: list[str] = []
    original = app.set_status
    app.set_status = lambda message: (captured.append(message), original(message))[1]  # type: ignore[method-assign]
    return captured


def _report_names(reports_dir: Path) -> set[str]:
    """Directory listing snapshot (empty when the dir does not exist)."""
    if not reports_dir.is_dir():
        return set()
    return {p.name for p in reports_dir.iterdir() if p.is_file()}


def _summary_entry(symbol: str | None = None) -> ChangeSummaryEntry:
    """One applied 2-byte entry at 0x100 (before ``00 00`` -> after ``AA BB``)."""
    return ChangeSummaryEntry(
        entry_type="bytes",
        address_start=0x100,
        address_end=0x102,
        before_bytes=(0x00, 0x00),
        after_bytes=(0xAA, 0xBB),
        disposition="applied",
        linkage="standalone",
        linkage_symbol=symbol,
    )


def _summary(
    saved_path: Path | None,
    source_image_path: Path | None,
    entries: list[ChangeSummaryEntry] | None = None,
) -> ChangeSummary:
    """A minimal applied ``ChangeSummary`` carrying the B-2 provenance stamp."""
    return ChangeSummary(
        source_path=None,
        kind="change",
        encoding="utf-8",
        value_mode="text",
        timestamp_utc="2026-07-02T10:00:00+00:00",
        variant_id=None,
        counts={token: 0 for token in DISPOSITION_DOMAIN},
        entries=list(entries or [_summary_entry()]),
        saved_path=saved_path,
        source_image_path=source_image_path,
    )


async def _drive_apply(app, pilot, address: str = "0x100", bytes_text: str = "AA BB") -> None:
    """Add one entry and apply the document through the shipped panel chain."""
    panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
    _set_entry_inputs(app, address=address, bytes_text=bytes_text)
    panel.request_action("add_entry")
    await pilot.pause()
    panel.request_action("apply_doc")
    await pilot.pause()


# ===========================================================================
# AT-038a — GATE (C-10 + C-12) — save-back -> trigger -> surfaced path ->
# dir-diff -> re-read from disk
# ===========================================================================


def test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path(
    tmp_path: Path,
) -> None:
    """Apply -> collide-save -> key ``b`` -> surfaced path == dir-diff file ->
    re-read shows -/+ bytes, linkage row, pinned dedup "after" identity.

    Intent: HLR-038 acceptance (Q-M1 chain): the AT snapshots the reports
    listing BEFORE the trigger, captures the surfaced status text, asserts the
    surfaced md/html paths equal the exactly-two new files, then re-reads THE
    SURFACED md path for the content asserts. C-10: the typed save-back name
    collides with a pre-planted file so the header's "after" MUST be the
    dedup-suffixed ``img-patched_1.s19`` — a typed-name echo fails.
    Counterfactual: pre-implementation key ``b`` is unbound -> no new file ->
    the dir-diff assert fails (the RED captured in increment-4.md).
    """
    from textual.widgets import Button

    image_path = _make_s19_image(tmp_path)

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
        reports_dir = project_dir / "reports"
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            project_dir.mkdir(parents=True, exist_ok=True)
            app.current_project = "proj"
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            await _drive_apply(app, pilot)

            # C-10 collision drive: plant the suggested name BEFORE confirming.
            (project_dir / "img-patched.s19").write_text(
                "S00600004844521B\nS9030000FC\n", encoding="ascii"
            )
            notices = _notices(app)
            statuses = _statuses(app)
            app.query_one("#patch_saveback_confirm_button", Button).press()
            await pilot.pause()
            outcomes["offer_notices"] = list(notices)
            # Failure DIAGNOSTIC only — never an expected operand (Q-M2):
            outcomes["saved_path_diag"] = app._change_service.last_summary.saved_path

            before = _report_names(reports_dir)
            statuses.clear()
            app.set_focus(None)
            await pilot.press("b")
            await pilot.pause()
            outcomes["new_files"] = sorted(_report_names(reports_dir) - before)
            outcomes["statuses"] = list(statuses)
            outcomes["notices_all"] = list(notices)
            outcomes["reports_dir"] = reports_dir
        return outcomes

    outcomes = asyncio.run(_drive())

    # --- dir-diff: exactly one new md + one new html -----------------------
    new_files = outcomes["new_files"]
    md_new = [n for n in new_files if n.endswith(".md")]
    html_new = [n for n in new_files if n.endswith(".html")]
    assert len(new_files) == 2 and len(md_new) == 1 and len(html_new) == 1, (
        f"AT-038a: expected exactly one new md + one new html under reports/, "
        f"got {new_files}; saved_path diagnostic: {outcomes['saved_path_diag']}; "
        f"statuses: {outcomes['statuses']}"
    )
    assert _MD_NAME.match(md_new[0]), md_new[0]
    assert _HTML_NAME.match(html_new[0]), html_new[0]

    # --- surfaced path equals the dir-diff file (Q-M1) ----------------------
    written = [s for s in outcomes["statuses"] if "Before/after report written" in s]
    assert len(written) == 1, (
        f"AT-038a: expected exactly one surfaced written-status line, "
        f"got {outcomes['statuses']}"
    )
    surfaced = written[0].split("Before/after report written:", 1)[1]
    surfaced_md, surfaced_html = [p.strip() for p in surfaced.split("|")]
    assert Path(surfaced_md).name == md_new[0], (
        f"surfaced md path {surfaced_md!r} != new file {md_new[0]!r}"
    )
    assert Path(surfaced_html).name == html_new[0]

    # --- re-read THE SURFACED path (C-12) -----------------------------------
    text = Path(surfaced_md).read_text(encoding="utf-8")

    # Provenance header: before = the original; after = the PINNED dedup
    # literal (typed-name-echo discriminator, Q-M2).
    before_match = _PROVENANCE_BEFORE.search(text)
    after_match = _PROVENANCE_AFTER.search(text)
    assert before_match is not None and after_match is not None, text[:800]
    assert Path(before_match.group(1)) == image_path
    assert Path(after_match.group(1)).name == "img-patched_1.s19", (
        f"AT-038a C-10: the 'after' identity must be the dedup-suffixed "
        f"saved_path basename, got {after_match.group(1)!r}"
    )

    # Linkage table row for the applied entry.
    assert (
        "| 1 | bytes | 0x00000100 | 0x00000102 | applied | standalone | - "
        "| 00 00 \\|..\\| | AA BB \\|..\\| |" in text
    ), "AT-038a: linkage row for the applied entry missing"

    # Diff fence: pre-patch bytes as '-' lines, after_bytes as '+' lines.
    heading = "### Run 0x00000100-0x00000102 (changed)"
    assert heading in text
    fence = text[text.index("```diff", text.index(heading)) + len("```diff"):]
    fence = fence[: fence.index("```")]
    minus = [ln for ln in fence.splitlines() if ln.startswith("-")]
    plus = [ln for ln in fence.splitlines() if ln.startswith("+")]
    assert any("00 00" in ln for ln in minus), minus
    assert any("AA BB" in ln for ln in plus), plus

    # Offer notify (LLR-038.3): information severity, names action + key b.
    offers = [
        (title, msg, sev)
        for title, msg, sev in outcomes["offer_notices"]
        if "before_after_report" in msg
    ]
    assert offers and offers[0][2] == "information", outcomes["offer_notices"]
    assert "press b" in offers[0][1].lower()

    # S-F5: surfaced text carries paths/diagnostics only — no entry bytes.
    for message in outcomes["statuses"] + [m for _t, m, _s in outcomes["notices_all"]]:
        assert "AA BB" not in message, (
            f"S-F5: entry byte content leaked into a surfaced message: {message!r}"
        )


# ===========================================================================
# AT-038b/c/d — GUARD-class refusals (positive diagnostic + 0 files)
# ===========================================================================


def test_at_038b_declined_saveback_trigger_refuses_and_writes_nothing(
    tmp_path: Path,
) -> None:
    """Decline the save-back, invoke ``b`` -> surfaced refusal, 0 files.

    Intent: LLR-038.4 class 2 (``saved_path`` is ``None``). GUARD-class: the
    positive surfaced-refusal-diagnostic assert is load-bearing (Q-m1) — the
    0-file listing alone would pass vacuously pre-implementation.
    """
    from textual.widgets import Button

    image_path = _make_s19_image(tmp_path)

    async def _drive() -> tuple[list[str], set[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            project_dir.mkdir(parents=True, exist_ok=True)
            app.current_project = "proj"
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            await _drive_apply(app, pilot)
            app.query_one("#patch_saveback_decline_button", Button).press()
            await pilot.pause()
            statuses = _statuses(app)
            app.set_focus(None)
            await pilot.press("b")
            await pilot.pause()
            return list(statuses), _report_names(project_dir / "reports")

    statuses, report_files = asyncio.run(_drive())
    refusals = [s for s in statuses if "Before/after report refused" in s]
    assert refusals, f"AT-038b: no surfaced refusal diagnostic; statuses: {statuses}"
    assert "no saved patched image" in refusals[0].lower()
    assert report_files == set(), "AT-038b: a refusal must write no file"


def test_at_038c_missing_original_trigger_refuses_and_writes_nothing(
    tmp_path: Path,
) -> None:
    """Delete the original between save-back and trigger -> refusal, 0 files.

    Intent: LLR-038.4 class 3 (source path no longer on disk). GUARD-class:
    positive diagnostic assert load-bearing; the app keeps running (the
    follow-up listing read proves no crash).
    """
    from textual.widgets import Button

    image_path = _make_s19_image(tmp_path)

    async def _drive() -> tuple[list[str], set[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            project_dir.mkdir(parents=True, exist_ok=True)
            app.current_project = "proj"
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            await _drive_apply(app, pilot)
            app.query_one("#patch_saveback_confirm_button", Button).press()
            await pilot.pause()
            image_path.unlink()
            statuses = _statuses(app)
            app.set_focus(None)
            await pilot.press("b")
            await pilot.pause()
            return list(statuses), _report_names(project_dir / "reports")

    statuses, report_files = asyncio.run(_drive())
    refusals = [s for s in statuses if "Before/after report refused" in s]
    assert refusals, f"AT-038c: no surfaced refusal diagnostic; statuses: {statuses}"
    assert "img.s19" in refusals[0] and "no longer on disk" in refusals[0].lower()
    assert report_files == set(), "AT-038c: a refusal must write no file"


def test_at_038d_stale_summary_cross_project_refusal_writes_nothing(
    tmp_path: Path,
) -> None:
    """Apply+save in project A, switch to project B -> stale refusal, 0 files.

    Intent: LLR-038.2 preconditions 4-5 / LLR-038.4 class 4 (B-2): a
    ``last_summary`` surviving the project switch must NOT pair B's loaded
    image against A's patched file. The refusal diagnostic names the mismatch
    (both image identities); B's ``reports/`` stays empty by directory
    listing. GUARD-class per Q-m1.
    """
    from textual.widgets import Button

    image_a = _make_s19_image(tmp_path, name="img.s19")
    image_b = _make_s19_image(tmp_path, name="imgB.s19")

    async def _drive() -> tuple[list[str], set[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        workarea = tmp_path / ".s19tool" / "workarea"
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            (workarea / "projA").mkdir(parents=True, exist_ok=True)
            app.current_project = "projA"
            _load_image(app, image_a)
            app.action_show_screen("patch")
            await pilot.pause()
            await _drive_apply(app, pilot)
            app.query_one("#patch_saveback_confirm_button", Button).press()
            await pilot.pause()

            # Switch to project B and load B's image (shipped-state switch).
            (workarea / "projB").mkdir(parents=True, exist_ok=True)
            app.current_project = "projB"
            _load_image(app, image_b)
            await pilot.pause()

            statuses = _statuses(app)
            app.set_focus(None)
            await pilot.press("b")
            await pilot.pause()
            return list(statuses), _report_names(workarea / "projB" / "reports")

    statuses, report_files = asyncio.run(_drive())
    refusals = [s for s in statuses if "Before/after report refused" in s]
    assert refusals, f"AT-038d: no surfaced refusal diagnostic; statuses: {statuses}"
    assert "stale" in refusals[0].lower(), refusals[0]
    assert "imgB.s19" in refusals[0], (
        f"AT-038d: the stale diagnostic must name the mismatch: {refusals[0]!r}"
    )
    assert report_files == set(), (
        "AT-038d: a stale cross-project summary must write nothing into B"
    )


# ===========================================================================
# TC-038.3 — composer happy path + regex ownership + symlink refusal +
# ctl-symbol md/html pair consistency (LLR-038.2, S-F4, S-F2 factoring)
# ===========================================================================


def test_tc_038_3_composer_happy_path_and_regex_ownership(tmp_path: Path) -> None:
    """The composer writes the md+html pair under ``<project>/reports/`` with
    its OWN filename scheme; the shared/diff regexes never match it.

    Intent: LLR-038.2 — preconditions pass, ``compare_images`` over two
    SOURCE_EXTERNAL paths, both generators invoked with provenance/linkage +
    the ``before-after-report`` stem; regex ownership mirrors the diff-report
    precedent.
    """
    bas = _bas()
    from s19_app.tui.services.diff_report_service import (
        DIFF_REPORT_FILENAME_REGEX,
        DIFF_REPORT_HTML_FILENAME_REGEX,
    )
    from s19_app.tui.services.report_service import REPORT_FILENAME_REGEX

    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    original = _make_s19_image(tmp_path)
    patched = _make_s19_image(project_dir, name="img-patched_1.s19", patched=True)

    result = bas.compose_before_after_report(
        _summary(saved_path=patched, source_image_path=original),
        original,
        project_dir=project_dir,
        workarea=tmp_path / "wa",
        now_fn=_fixed_clock,
    )

    assert result.written, result.diagnostics
    assert result.md_path.parent == project_dir / "reports"
    assert result.html_path.parent == project_dir / "reports"
    assert result.md_path.name == "20260702T120000Z-before-after-report.md"
    assert result.html_path.name == "20260702T120000Z-before-after-report.html"
    assert bas.BEFORE_AFTER_REPORT_FILENAME_REGEX.match(result.md_path.name)
    assert bas.BEFORE_AFTER_REPORT_HTML_FILENAME_REGEX.match(result.html_path.name)
    # Ownership: the shared and diff-report schemes never match these names.
    assert not DIFF_REPORT_FILENAME_REGEX.match(result.md_path.name)
    assert not DIFF_REPORT_HTML_FILENAME_REGEX.match(result.html_path.name)
    assert not REPORT_FILENAME_REGEX.match(result.md_path.name)

    text = result.md_path.read_text(encoding="utf-8")
    assert "## Before/after provenance" in text
    assert str(original) in text and str(patched) in text
    assert (
        "| 1 | bytes | 0x00000100 | 0x00000102 | applied | standalone | - "
        "| 00 00 \\|..\\| | AA BB \\|..\\| |" in text
    )
    assert "```diff" in text


def test_tc_038_3_symlink_reports_destination_refused(tmp_path: Path) -> None:
    """A symlinked ``reports/`` destination is refused; nothing is written.

    Intent: LLR-038.2 acceptance (S-F4) — cheap containment hardening on the
    write side.
    """
    bas = _bas()
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    try:
        (project_dir / "reports").symlink_to(elsewhere, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation not permitted on this platform/user")
    original = _make_s19_image(tmp_path)
    patched = _make_s19_image(project_dir, name="p.s19", patched=True)

    result = bas.compose_before_after_report(
        _summary(saved_path=patched, source_image_path=original),
        original,
        project_dir=project_dir,
        workarea=tmp_path / "wa",
    )

    assert not result.written
    assert any("symbolic link" in d.lower() for d in result.diagnostics), (
        result.diagnostics
    )
    assert list(elsewhere.iterdir()) == [], "S-F4: nothing may cross the symlink"


def test_tc_038_3_ctl_symbol_renders_identically_in_md_and_html_pair(
    tmp_path: Path,
) -> None:
    """A ctl-bearing linkage symbol is stripped in BOTH written formats.

    Intent: the increment-3 reviewer recommendation — ``_strip_ctl`` factored
    out of ``_md_cell`` and applied inside the two before/after HTML helpers:
    the md and html files render the same ctl-stripped symbol, and the raw
    control character reaches neither file.
    """
    bas = _bas()
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    original = _make_s19_image(tmp_path)
    patched = _make_s19_image(project_dir, name="p.s19", patched=True)
    summary = _summary(
        saved_path=patched,
        source_image_path=original,
        entries=[_summary_entry(symbol="CTL\x01SYM")],
    )

    result = bas.compose_before_after_report(
        summary,
        original,
        project_dir=project_dir,
        workarea=tmp_path / "wa",
    )

    assert result.written, result.diagnostics
    md_text = result.md_path.read_text(encoding="utf-8")
    html_text = result.html_path.read_text(encoding="utf-8")
    assert "\x01" not in md_text and "\x01" not in html_text
    assert "CTLSYM" in md_text and "CTLSYM" in html_text


# ===========================================================================
# TC-038.4 — refusal classes 1-4 + no-project D-3 (LLR-038.4)
# ===========================================================================


def test_tc_038_4_all_refusal_classes_write_no_files(tmp_path: Path) -> None:
    """Every LLR-038.4 refusal class surfaces one diagnostic and writes 0 files.

    Intent: classes (1) no summary, (2) ``saved_path`` ``None``, (3) either
    source missing on disk, (4) stale summary — provenance mismatch and
    out-of-project containment. Never raises; ``reports/`` stays absent/empty.
    """
    bas = _bas()
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    original = _make_s19_image(tmp_path)
    patched = _make_s19_image(project_dir, name="p.s19", patched=True)
    kwargs = dict(project_dir=project_dir, workarea=tmp_path / "wa")

    cases: list[tuple[str, object, Path | None, str]] = [
        ("class 1", None, original, "no applied change summary"),
        (
            "class 2",
            _summary(saved_path=None, source_image_path=original),
            original,
            "no saved patched image",
        ),
        (
            "class 3 (original gone)",
            _summary(saved_path=patched, source_image_path=tmp_path / "gone.s19"),
            tmp_path / "gone.s19",
            "no longer on disk",
        ),
        (
            "class 3 (saved gone)",
            _summary(
                saved_path=project_dir / "gone-patched.s19",
                source_image_path=original,
            ),
            original,
            "no longer on disk",
        ),
        (
            "class 4 (provenance mismatch)",
            _summary(saved_path=patched, source_image_path=patched),
            original,
            "stale",
        ),
    ]
    for label, summary, loaded_path, needle in cases:
        result = bas.compose_before_after_report(summary, loaded_path, **kwargs)
        assert not result.written, label
        assert result.md_path is None and result.html_path is None, label
        assert any(needle in d.lower() for d in result.diagnostics), (
            f"{label}: expected a diagnostic containing {needle!r}, "
            f"got {result.diagnostics}"
        )
        assert _report_names(project_dir / "reports") == set(), label

    # class 4 (containment): saved_path outside the current project dir.
    outside = _make_s19_image(tmp_path, name="outside-patched.s19", patched=True)
    result = bas.compose_before_after_report(
        _summary(saved_path=outside, source_image_path=original),
        original,
        **kwargs,
    )
    assert not result.written
    assert any("outside" in d.lower() for d in result.diagnostics), result.diagnostics
    assert _report_names(project_dir / "reports") == set()


def test_tc_038_4_no_project_refusal_names_manual_ab_path(tmp_path: Path) -> None:
    """No active project -> refusal naming the manual A<->B report path (D-3).

    Intent: LLR-038.4 acceptance / §6.2 D-3 — the workarea save-back survivor
    refuses (no destination) and points the operator at the manual A<->B Diff
    report; nothing is written anywhere under the workarea.
    """
    bas = _bas()
    workarea = tmp_path / ".s19tool" / "workarea"
    workarea.mkdir(parents=True)
    original = _make_s19_image(tmp_path)
    patched = _make_s19_image(workarea, name="img-patched.s19", patched=True)

    result = bas.compose_before_after_report(
        _summary(saved_path=patched, source_image_path=original),
        original,
        project_dir=None,
        workarea=workarea,
    )

    assert not result.written
    assert any(
        "a<->b" in d.lower() and "no active project" in d.lower()
        for d in result.diagnostics
    ), result.diagnostics
    assert list(workarea.rglob("*-before-after-report.*")) == []


# ===========================================================================
# TC-038.5 — inspection: module purity + destination construction
# (LLR-038.5, V-4, S-F3)
# ===========================================================================


def test_tc_038_5_module_imports_no_textual_and_no_logging() -> None:
    """The composer module imports no Textual symbol and performs no logging.

    Intent: LLR-038.2 service purity (V-4 probe form) + LLR-038.5 (F-S-07
    discipline: report body content can never reach the rotating log); the
    destination is constructed from ``REPORTS_DIR_NAME`` under the project
    dir (S-F3 — construction is asserted, not gitignoredness).
    """
    import inspect

    bas = _bas()
    source = inspect.getsource(bas)
    assert "import textual" not in source
    assert "from textual" not in source
    assert "import logging" not in source
    assert "getLogger" not in source
    assert "REPORTS_DIR_NAME" in source, (
        "S-F3: the reports destination must be constructed from the shared "
        "REPORTS_DIR_NAME constant under the active project dir"
    )


# ===========================================================================
# AT-054b — batch-35 Inc-0 byte-identity guard golden (LLR-054.4 / HLR-054)
# ===========================================================================

#: Golden fixtures for the batch-35 byte-identity guards, captured at the
#: batch base revision ``79699a5`` by driving the shipped ``b``-key flow
#: under the environment pin declared in :func:`_drive_bkey_report_pair`
#: (golden home: ``tests/goldens/batch35/`` — canonical form, see
#: :func:`_canonical_report_bytes`).
_GOLDEN_DIR = Path(__file__).parent / "goldens" / "batch35"
_AT054B_MD_GOLDEN = _GOLDEN_DIR / "at054b-before-after-report.md"
_AT054B_HTML_GOLDEN = _GOLDEN_DIR / "at054b-before-after-report.html"

#: The LLR-054.4 fixed-clock environment-pin instant (UTC).
_FIXED_REPORT_INSTANT = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)

#: Placeholder replacing every spelling of the per-run pytest tmp root
#: inside canonical report bytes.
_RUN_ROOT_TOKEN = b"<RUN-ROOT>"

#: A run-root path span: the token plus its path remainder, stopping at the
#: delimiters the reports place around paths (whitespace, backtick, quote,
#: pipe, closing paren/bracket) — separator normalization applies ONLY
#: inside these spans, never to report content.
_RUN_ROOT_SPAN = re.compile(rb"<RUN-ROOT>[^\s`\"'|)\]]*")


class _FixedApplyDatetime(datetime):
    """
    Summary:
        ``datetime`` stand-in pinning the ``changes.apply`` stamp clock —
        ``apply_change_document`` defaults to an inline
        ``datetime.now(timezone.utc)`` lambda (``changes/apply.py:313-314``)
        with no module-level ``_default_now`` seam, so the environment pin
        monkeypatches the module's ``datetime`` attribute with this subclass
        (instances stay real ``datetime`` objects, so ``isoformat`` and any
        isinstance check behave identically).

    Args:
        None (classmethod override only).

    Returns:
        None: Class definition.

    Data Flow:
        - ``apply.py:359`` ``timestamp_utc=clock().isoformat()`` ->
          ``ChangeSummary.timestamp_utc`` -> ``BeforeAfterProvenance.
          applied_at_utc`` -> the ``Applied (UTC)`` line in both report
          formats (``diff_report_service.py:378`` / ``:1257``).

    Dependencies:
        Used by:
            - _drive_bkey_report_pair
    """

    @classmethod
    def now(cls, tz=None):  # noqa: ANN001 - datetime.now signature
        """Return the pinned instant (tz-aware when ``tz`` is given)."""
        if tz is None:
            return cls(2026, 7, 10, 12, 0, 0)
        return cls(2026, 7, 10, 12, 0, 0, tzinfo=tz)


def _canonical_report_bytes(raw: bytes, run_root: Path | None = None) -> bytes:
    """
    Summary:
        Map report bytes to the canonical golden form of the LLR-054.4/055.3
        byte-identity pin: platform newline translation undone (CRLF -> LF,
        the ``Path.write_text`` seam — generators join with ``"\\n"`` and let
        the platform translate), every spelling of the per-run pytest tmp
        root replaced by ``<RUN-ROOT>``, and path separators normalized to
        ``/`` ONLY inside run-root path spans — content bytes (including the
        batch-34 ``\\|`` linkage-cell escapes) are never rewritten.

    Args:
        raw (bytes): Report bytes as read from disk (a freshly written
            report, or a stored golden).
        run_root (Path | None): The per-run root whose spellings are
            tokenized; ``None`` for stored goldens (already tokenized at
            capture time — only the CRLF undo applies, shielding the golden
            from git working-tree newline translation).

    Returns:
        bytes: The canonical byte form compared by AT-054b / AT-055b.

    Data Flow:
        - written report bytes + ``tmp_path`` -> canonical bytes;
        - golden bytes (``run_root=None``) -> canonical bytes;
        - equality of the two IS the LLR-054.4/055.3 byte-identity gate
          (raw bytes cannot be run/platform-stable: the reports embed the
          absolute run root in their provenance/inventory path lines).

    Dependencies:
        Uses:
            - _RUN_ROOT_TOKEN / _RUN_ROOT_SPAN
        Used by:
            - test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden
            - the batch-35 golden-capture procedure (increment-000)
    """
    data = raw.replace(b"\r\n", b"\n")
    if run_root is not None:
        forms = {str(run_root), str(run_root.resolve())}
        for form in sorted(forms, key=len, reverse=True):
            data = data.replace(form.encode("utf-8"), _RUN_ROOT_TOKEN)
    return _RUN_ROOT_SPAN.sub(
        lambda match: match.group(0).replace(b"\\", b"/"), data
    )


def _drive_bkey_report_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, bytes]:
    """
    Summary:
        Drive the SHIPPED before/after surface (the AT-038a chain: load
        image, apply one entry through the patch panel, confirm the
        save-back, press key ``b``) under the LLR-054.4 environment pin and
        return the written report files' raw bytes keyed by filename.

    Args:
        tmp_path (Path): Per-test root (app ``base_dir``); the project lives
            at ``.s19tool/workarea/proj`` beneath it.
        monkeypatch (pytest.MonkeyPatch): Applies the environment pin on
            SERVICE module attributes (auto-undone per test):
            ``diff_report_service._default_now`` (the default-clock seam
            BOTH generators resolve when the handler passes no ``now_fn`` —
            ``generate_diff_report``/``generate_diff_report_html``) and
            ``changes.apply.datetime`` (:class:`_FixedApplyDatetime`, the
            apply-stamp clock).

    Returns:
        dict[str, bytes]: ``{filename: raw bytes}`` for every file under
        ``<project>/reports/`` after the ``b`` press.

    Data Flow:
        - pin clocks -> pilot drive (patch apply -> save-back confirm ->
          key ``b``) -> handler writes MD+HTML pair -> raw bytes read back
          from disk for the golden comparison.

    Dependencies:
        Uses:
            - _make_s19_image / _load_image / _drive_apply
            - _FixedApplyDatetime / _FIXED_REPORT_INSTANT
        Used by:
            - test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden
            - the batch-35 golden-capture procedure (increment-000)
    """
    import s19_app.tui.changes.apply as apply_module
    from s19_app.tui.services import diff_report_service

    monkeypatch.setattr(
        diff_report_service, "_default_now", lambda: _FIXED_REPORT_INSTANT
    )
    monkeypatch.setattr(apply_module, "datetime", _FixedApplyDatetime)

    from textual.widgets import Button

    image_path = _make_s19_image(tmp_path)

    async def _drive() -> dict[str, bytes]:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
        reports_dir = project_dir / "reports"
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            project_dir.mkdir(parents=True, exist_ok=True)
            app.current_project = "proj"
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            await _drive_apply(app, pilot)
            app.query_one("#patch_saveback_confirm_button", Button).press()
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("b")
            await pilot.pause()
            return {
                p.name: p.read_bytes()
                for p in reports_dir.iterdir()
                if p.is_file()
            }

    return asyncio.run(_drive())


def test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-054b / LLR-054.4 (HLR-054): with NO filter selected, the shipped
    ``b``-key flow writes an MD+HTML pair byte-identical to the goldens
    captured at the batch base revision ``79699a5`` under the declared
    environment pin.

    Intent: the batch-35 guard golden — every later increment must keep the
    unfiltered before/after output byte-for-byte untouched; any generator
    byte drift flips this equality RED.

    Environment pin (test-side monkeypatch on SERVICE module attributes,
    never a shipped-path change):
    - ``s19_app.tui.services.diff_report_service._default_now`` -> fixed
      2026-07-10T12:00:00Z — the default-clock seam BOTH generators resolve
      when the handler passes no ``now_fn`` (``app.py`` passes none;
      ``before_after_service`` forwards ``now_fn=None`` untouched).
    - ``s19_app.tui.changes.apply.datetime`` -> :class:`_FixedApplyDatetime`
      — the apply-stamp clock (inline default at ``apply.py:313-314``, no
      ``_default_now`` symbol exists there) whose stamp is printed as the
      ``Applied (UTC)`` report line.
    Comparison runs on :func:`_canonical_report_bytes` (CRLF undo +
    per-run tmp-root tokenization); all other bytes are compared exact.
    Goldens: ``tests/goldens/batch35/at054b-before-after-report.{md,html}``.
    Double-proof (batch-24 control): a one-byte golden perturbation makes
    this AT RED — captured in increment-000.md.
    """
    written = _drive_bkey_report_pair(tmp_path, monkeypatch)

    md_name = "20260710T120000Z-before-after-report.md"
    html_name = "20260710T120000Z-before-after-report.html"
    assert sorted(written) == [html_name, md_name], (
        f"AT-054b: expected exactly the pinned-clock MD+HTML pair, "
        f"got {sorted(written)}"
    )

    for label, name, golden_path in (
        ("md", md_name, _AT054B_MD_GOLDEN),
        ("html", html_name, _AT054B_HTML_GOLDEN),
    ):
        assert golden_path.is_file(), (
            f"AT-054b: golden fixture missing: {golden_path} (captured in "
            f"batch-35 increment-000 at base revision 79699a5)"
        )
        observed = _canonical_report_bytes(written[name], tmp_path)
        golden = _canonical_report_bytes(golden_path.read_bytes())
        assert observed == golden, (
            f"AT-054b: unfiltered {label} report bytes drifted from golden "
            f"{golden_path.name} (LLR-054.4 byte-identity, canonical form)"
        )


# ===========================================================================
# TC-311 — batch-35 Inc-2 composer plumbing (LLR-054.1)
# ===========================================================================


def _resolved_matcher(symbols=(), addresses=(), name="cal-filter.json"):
    """Resolved ``ReportFilterMatcher`` via the public parse+resolve API.

    ``name`` rides as the duck-typed ``source_name`` display attribute the
    audit header reads (in-cap Inc-2 decision — see increment-002.md).
    """
    import json

    from s19_app.tui.services.report_filter import (
        parse_report_filter,
        resolve_report_filter,
    )

    doc = json.dumps(
        {
            "format": "s19app-report-filter",
            "version": "1.0",
            "include": {
                "symbols": list(symbols),
                "addresses": [
                    {"start": start, "end": end} for start, end in addresses
                ],
            },
        }
    )
    flt, errors = parse_report_filter(doc)
    assert errors == []
    matcher = resolve_report_filter(flt, [], [])
    if name is not None:
        object.__setattr__(matcher, "source_name", name)
    return matcher


def test_tc311_composer_forwards_matcher_filtered_output_both_formats(
    tmp_path: Path,
) -> None:
    """TC-311 / LLR-054.1: ``compose_before_after_report`` forwards the
    resolved matcher into BOTH generators — the written MD and HTML each
    carry the audit header, keep the matching linkage row, and drop the
    non-matching one.

    Threshold: audit header + filter name + matching symbol present in both
    formats; the non-matching symbol absent from both.
    """
    bas = _bas()
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    original = _make_s19_image(tmp_path)
    patched = _make_s19_image(project_dir, name="img-patched_1.s19", patched=True)
    summary = _summary(
        saved_path=patched,
        source_image_path=original,
        entries=[
            _summary_entry(symbol="CAL_KEEP"),
            ChangeSummaryEntry(
                entry_type="bytes",
                address_start=0x900,
                address_end=0x902,
                before_bytes=(0x00, 0x00),
                after_bytes=(0xCC, 0xDD),
                disposition="applied",
                linkage="standalone",
                linkage_symbol="OTHER_DROP",
            ),
        ],
    )
    matcher = _resolved_matcher(
        symbols=["CAL_KEEP"], addresses=[(0x100, 0x102)]
    )

    result = bas.compose_before_after_report(
        summary,
        original,
        project_dir=project_dir,
        workarea=tmp_path / "wa",
        now_fn=_fixed_clock,
        report_filter=matcher,
    )

    assert result.written, result.diagnostics
    md_text = result.md_path.read_text(encoding="utf-8")
    html_text = result.html_path.read_text(encoding="utf-8")
    for text in (md_text, html_text):
        assert "Report filter applied" in text
        assert "cal-filter.json" in text
        assert "CAL_KEEP" in text
        assert "OTHER_DROP" not in text


def test_tc311_no_filter_generator_kwargs_shape_is_todays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-311 / LLR-054.1 (F-01 kwargs pin): without the kwarg the composer
    calls both generators with EXACTLY today's kwargs shape — no
    ``report_filter`` key, no ``a2l_records``/``mac_records`` ever; with a
    matcher, ``report_filter`` is the ONLY added key on both calls.

    Byte-level no-filter arm: AT-054b (the Inc-0 golden) IS the byte pin —
    this node pins the call shape at the composer seam.
    """
    from s19_app.tui.services.diff_report_service import DiffReportResult

    bas = _bas()
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    original = _make_s19_image(tmp_path)
    patched = _make_s19_image(project_dir, name="p.s19", patched=True)
    summary = _summary(saved_path=patched, source_image_path=original)

    captured: list[tuple[str, dict]] = []

    def _fake(fmt: str):
        def _generator(comparison, **kwargs):
            captured.append((fmt, kwargs))
            return DiffReportResult(
                path=project_dir / "reports" / f"fake.{fmt}",
                written=True,
                diagnostics=[],
            )

        return _generator

    monkeypatch.setattr(bas, "generate_diff_report", _fake("md"))
    monkeypatch.setattr(bas, "generate_diff_report_html", _fake("html"))

    todays_keys = {
        "mem_map_a",
        "mem_map_b",
        "project_dir",
        "provenance",
        "linkage_entries",
        "filename_stem",
        "now_fn",
    }

    result = bas.compose_before_after_report(
        summary,
        original,
        project_dir=project_dir,
        workarea=tmp_path / "wa",
    )
    assert result.written
    assert [fmt for fmt, _ in captured] == ["md", "html"]
    for fmt, kwargs in captured:
        assert set(kwargs) == todays_keys, (
            f"no-filter {fmt} kwargs drifted from today's shape: {set(kwargs)}"
        )
        assert kwargs["filename_stem"] == "before-after-report"

    captured.clear()
    matcher = _resolved_matcher(addresses=[(0x100, 0x102)])
    result = bas.compose_before_after_report(
        summary,
        original,
        project_dir=project_dir,
        workarea=tmp_path / "wa",
        report_filter=matcher,
    )
    assert result.written
    for fmt, kwargs in captured:
        assert set(kwargs) == todays_keys | {"report_filter"}, fmt
        assert kwargs["report_filter"] is matcher
