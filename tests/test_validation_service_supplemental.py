"""US-032 / batch-24 I1 — A2L red-row => ERROR-issue reconcile (HLR-036) plus the
LLR-037.4 no-MAC validation-report retention fix (B-1a).

Layer B gates (AT-036a/b/c) drive the SHIPPED load chain under Textual Pilot —
sync ``asyncio.run`` wrappers because pytest-asyncio is not installed (idiom:
``tests/test_tui_patch_layout.py``) — and observe the rendered ``#a2l_tags_list``
DataTable (colour oracle, untouched) plus the grouped ``IssueRow`` issue
read-back (C-14 migration: the retired ``#validation_issues_list``). Row styles are
asserted against ``_severity_style(ValidationSeverity.ERROR)`` (semantic
colour-policy anchor; no raw ``"red"`` literal, QR-1). Fixtures are
deliberately MAC-LESS: pre-fix ``update_mac_view`` wiped ``_validation_issues``
in every no-MAC session, so these ATs also gate LLR-037.4 — adding a MAC to
green them is forbidden (C-12-family masking, HLR-036 Acceptance).

Layer A: TC-036.1-.4 unit-test ``supplemental_a2l_row_issues`` and the
``build_validation_report`` merge (LLR-036.1/.2/.3); TC-037.4 pins the no-MAC
retention + cache-key stability on both load paths (LLR-037.4). Private-attr
reads live only inside the TC-037.4 white-box scope; elsewhere they are
diagnostics only.

``supplemental_a2l_row_issues`` is imported lazily inside the Layer-A tests so
this module collected (and AT-036a ran RED) on the pre-fix tree, where the
symbol did not yet exist.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Awaitable, Callable, Optional

from textual.widgets import DataTable

from s19_app.tui.app import S19TuiApp, _severity_style
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.models import LoadedFile
from s19_app.tui.services.validation_service import build_validation_report
from s19_app.validation import ValidationIssue, ValidationSeverity

SUPPLEMENTAL_CODE = "A2L_TAG_SCHEMA_INCOMPLETE"

# Grouped ``IssueRow.issue`` read-back layout (C-14 migration):
# (severity, code, artifact, symbol, message)
_SEV, _CODE, _SYMBOL, _MESSAGE = 0, 1, 3, 4


# ---------------------------------------------------------------------------
# Fixtures (synthetic, public data only). Raw A2L texts derive from the
# tag-line shape in tests/test_tui_a2l.py:20-43; the schema-bad characteristics
# intentionally have NO ECU_ADDRESS (or no LENGTH) and NO VIRTUAL keyword —
# the exact divergence shape HLR-036 gates (a2l.py:1290-1291 red, zero issues
# pre-fix).
# ---------------------------------------------------------------------------

_RECONCILE_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin MEASUREMENT RPM\n"
    "      ECU_ADDRESS 0x1000\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "    /begin CHARACTERISTIC BROKEN_CHAR\n"
    "      LENGTH 4\n"
    "    /end CHARACTERISTIC\n"
    "    /begin CHARACTERISTIC NOLEN_CHAR\n"
    "      ECU_ADDRESS 0x1008\n"
    "    /end CHARACTERISTIC\n"
    "    /begin CHARACTERISTIC VIRT_CHAR\n"
    "      VIRTUAL\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)

_DUP_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin MEASUREMENT RPM\n"
    "      ECU_ADDRESS 0x1000\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "    /begin MEASUREMENT DUP_RPM\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "    /begin MEASUREMENT DUP_RPM\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)

_CLEAN_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin MEASUREMENT RPM\n"
    "      ECU_ADDRESS 0x1000\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "    /begin CHARACTERISTIC TORQUE\n"
    "      VIRTUAL\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)

_EMPTY_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)


def _write_s19(tmp_path: Path) -> Path:
    """Emit a 16-byte synthetic S19 image at 0x1000 (builder idiom:
    tests/test_tui_patch_editor_v2.py::_make_s19_image)."""
    mem_map = {0x1000 + offset: 0x00 for offset in range(16)}
    text = emit_s19_from_mem_map(mem_map, [(0x1000, 0x1010)])
    path = tmp_path / "img.s19"
    path.write_text(text, encoding="ascii")
    return path


def _write_a2l(tmp_path: Path, text: str, name: str = "tags.a2l") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Shipped-chain drive + widget read-back helpers
# ---------------------------------------------------------------------------


def _drive_load(
    tmp_path: Path,
    s19_path: Path,
    a2l_path: Path,
    observe: Callable[[S19TuiApp, object], Awaitable[None]],
) -> None:
    """Load S19 (+attached A2L) through the shipped worker-path chain
    (``_parse_loaded_file`` -> ``_prepare_load_payload`` ->
    ``_apply_prepared_load``; multi-artifact idiom tests/test_tui_app.py:1178-1201)
    under Pilot, then hand the app to ``observe`` for black-box asserts."""

    async def _run() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        app.current_a2l_path = a2l_path
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            loaded = app._parse_loaded_file(s19_path)
            assert loaded is not None, "shipped parse chain returned no LoadedFile"
            prepared = app._prepare_load_payload(loaded)
            app._apply_prepared_load(prepared, s19_path, 0.0)
            for _ in range(8):
                await pilot.pause()
            await observe(app, pilot)

    asyncio.run(_run())


def _a2l_row_list(app: S19TuiApp) -> list[tuple[str, tuple]]:
    """Rendered ``#a2l_tags_list`` rows as ``(name_cell_text, cells)`` pairs
    (cells are the styled ``rich.text.Text`` objects; name is column 0 per
    ``_build_a2l_table_cells``)."""
    table = app.query_one("#a2l_tags_list", DataTable)
    rows: list[tuple[str, tuple]] = []
    for index in range(table.row_count):
        cells = table.get_row_at(index)
        rows.append((str(cells[0]), tuple(cells)))
    return rows


def _issue_rows(app: S19TuiApp) -> list[tuple]:
    """Grouped-panel issue read-back (C-14 migration): the ``ValidationIssue``
    each mounted ``IssueRow`` carries, as ``(severity, code, artifact, symbol,
    message)`` tuples. Replaces the retired ``#validation_issues_list``
    DataTable read; reading the issue object (not rendered cells) keeps the
    ``_SEV`` comparison on the ``ValidationSeverity`` enum (stronger typing)."""
    from s19_app.tui.issues_view import IssueRow

    return [
        (
            row.issue.severity,
            row.issue.code,
            row.issue.artifact,
            row.issue.symbol,
            row.issue.message,
        )
        for row in app.query(IssueRow)
    ]


def _assert_within_cap(app: S19TuiApp) -> None:
    """C-14 count-guard (v2): ``GroupedIssuesPanel`` caps mounted rows at
    ``_GROUP_DISPLAY_MAX`` regardless of ``page_size``, so a whole-list count
    or absence claim over ``query(IssueRow)`` is faithful only when the whole
    filtered list fits under the cap. These fixtures emit small issue sets;
    this pins that so a future larger fixture cannot satisfy a claim vacuously."""
    from s19_app.tui.issues_view import _GROUP_DISPLAY_MAX

    assert len(app._filtered_validation_issues()) <= _GROUP_DISPLAY_MAX, (
        "fixture exceeds the grouped-panel row cap; the capped IssueRow read "
        "would no longer equal the whole filtered list"
    )


# ---------------------------------------------------------------------------
# Layer B — AT-036a (GATE): missing-address non-virtual tag ->
# red row AND a named ERROR issue on the Issues surface.
# Counterfactual (the reported bug): pre-fix, observable 1 (red row) PASSES and
# observable 2 (issues row) FAILS with zero rendered issue rows — captured
# verbatim in .dev-flow/2026-07-02-batch-24/03-increments/increment-1.md.
# ---------------------------------------------------------------------------


def test_at_036a_missing_schema_red_row_has_matching_error_issue(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _RECONCILE_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        error_style = _severity_style(ValidationSeverity.ERROR)
        rows = dict(_a2l_row_list(app))
        assert {"RPM", "BROKEN_CHAR", "NOLEN_CHAR", "VIRT_CHAR"} <= set(rows), (
            f"A2L table missing expected tag rows; rendered names: {sorted(rows)}"
        )
        # Observable 1 — red rows for both schema_ok=False arms (a2l.py:1290-1291).
        assert all(cell.style == error_style for cell in rows["BROKEN_CHAR"]), (
            "BROKEN_CHAR (missing address, non-virtual) row is not ERROR-styled"
        )
        assert all(cell.style == error_style for cell in rows["NOLEN_CHAR"]), (
            "NOLEN_CHAR (missing length) row is not ERROR-styled"
        )
        # Boundary — virtual/no-address tag is exempt by construction (a2l.py:1288-1289).
        assert all(cell.style != error_style for cell in rows["VIRT_CHAR"]), (
            "VIRT_CHAR (virtual, no address) must NOT render red"
        )
        # Observable 2 — Issues surface (rail screen 5) carries the matching ERRORs.
        app.action_show_screen("issues")
        await pilot.pause()
        # C-14 count-guard: whole filtered list fits under the row cap, so the
        # capped IssueRow read equals the whole list (existence + absence claims
        # below are then faithful).
        _assert_within_cap(app)
        issue_rows = _issue_rows(app)
        supplemental = [row for row in issue_rows if row[_CODE] == SUPPLEMENTAL_CODE]
        broken = [row for row in supplemental if row[_SYMBOL] == "BROKEN_CHAR"]
        nolen = [row for row in supplemental if row[_SYMBOL] == "NOLEN_CHAR"]
        assert broken, (
            f"Issues surface has no {SUPPLEMENTAL_CODE} row naming BROKEN_CHAR "
            f"(red row without an issue — the HLR-036 divergence). "
            f"Rendered issue rows: {issue_rows!r}"
        )
        assert broken[0][_SEV] == ValidationSeverity.ERROR
        assert "missing address/length" in broken[0][_MESSAGE]
        assert nolen, (
            f"missing-length arm produced no {SUPPLEMENTAL_CODE} issue; "
            f"rendered issue rows: {issue_rows!r}"
        )
        assert not any(row[_SYMBOL] == "VIRT_CHAR" for row in supplemental), (
            "virtual-exempt tag must not gain a supplemental issue"
        )

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer B — AT-036b: dedup — a tag already covered by an ERROR-severity a2l
# issue for the same symbol (A2L_DUPLICATE_SYMBOL here) gains NO second ERROR.
# ---------------------------------------------------------------------------


def test_at_036b_already_covered_symbol_gains_no_second_error(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _DUP_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        error_style = _severity_style(ValidationSeverity.ERROR)
        dup_rows = [cells for name, cells in _a2l_row_list(app) if name == "DUP_RPM"]
        assert len(dup_rows) == 2, "expected both DUP_RPM rows rendered"
        for cells in dup_rows:
            assert all(cell.style == error_style for cell in cells), (
                "schema-bad DUP_RPM row must render red"
            )
        app.action_show_screen("issues")
        await pilot.pause()
        # C-14 count-guard: whole filtered list fits under the row cap, so the
        # "exactly one ERROR" and dedup-absence claims below are faithful.
        _assert_within_cap(app)
        issue_rows = _issue_rows(app)
        dup_errors = [
            row
            for row in issue_rows
            if row[_SYMBOL].casefold() == "dup_rpm"
            and row[_SEV] == ValidationSeverity.ERROR
        ]
        assert len(dup_errors) == 1, (
            f"expected exactly ONE ERROR for DUP_RPM (dedup, LLR-036.2); "
            f"got {dup_errors!r} out of {issue_rows!r}"
        )
        assert dup_errors[0][_CODE] == "A2L_DUPLICATE_SYMBOL"
        assert not any(
            row[_CODE] == SUPPLEMENTAL_CODE and row[_SYMBOL].casefold() == "dup_rpm"
            for row in issue_rows
        ), "supplemental issue must be suppressed for an already-covered symbol"

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer B — AT-036c (negative): clean and zero-tag A2Ls produce zero
# supplemental issues; healthy rows never red.
# ---------------------------------------------------------------------------


def test_at_036c_clean_a2l_yields_zero_supplemental_issues(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _CLEAN_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        error_style = _severity_style(ValidationSeverity.ERROR)
        rows = dict(_a2l_row_list(app))
        assert {"RPM", "TORQUE"} <= set(rows)
        for name in ("RPM", "TORQUE"):
            assert all(cell.style != error_style for cell in rows[name]), (
                f"clean tag {name} must not render red"
            )
        app.action_show_screen("issues")
        await pilot.pause()
        # C-14 count-guard: whole filtered list fits under the row cap, so the
        # absence claim below is faithful (not vacuous under the row cap).
        _assert_within_cap(app)
        issue_rows = _issue_rows(app)
        assert not any(row[_CODE] == SUPPLEMENTAL_CODE for row in issue_rows), (
            f"clean A2L produced supplemental issues: {issue_rows!r}"
        )

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


def test_at_036c_empty_tag_set_yields_zero_supplemental_issues(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _EMPTY_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        a2l_table = app.query_one("#a2l_tags_list", DataTable)
        assert a2l_table.row_count == 0, "zero-tag A2L must render no tag rows"
        app.action_show_screen("issues")
        await pilot.pause()
        # C-14 count-guard (test_at_036c: absence claim, no "exactly one" — the
        # guard is still required so the row cap cannot make it vacuous).
        _assert_within_cap(app)
        issue_rows = _issue_rows(app)
        assert not any(row[_CODE] == SUPPLEMENTAL_CODE for row in issue_rows), (
            f"zero-tag A2L produced supplemental issues: {issue_rows!r}"
        )

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer A — TC-036.1 (LLR-036.1): one issue per schema_ok-is-False tag, keyed
# on ``is False`` (absent key / None gain nothing); fields populated; message
# scrubbed by the ValidationIssue constructor.
# ---------------------------------------------------------------------------


def test_tc_036_1_one_error_per_schema_bad_tag_keyed_on_is_false() -> None:
    from s19_app.tui.services.validation_service import supplemental_a2l_row_issues

    tags = [
        {"name": "BAD1", "schema_ok": False, "reason": "missing address/length"},
        {
            "name": "BAD2",
            "schema_ok": False,
            "reason": "missing address/length",
            "address": 0x2000,
        },
        {"name": "GOOD", "schema_ok": True},
        {"name": "RAW_NO_KEY"},
        {"name": "NONE_KEY", "schema_ok": None},
    ]

    issues = supplemental_a2l_row_issues(tags, [])

    assert [issue.symbol for issue in issues] == ["BAD1", "BAD2"]
    for issue in issues:
        assert issue.code == SUPPLEMENTAL_CODE
        assert issue.severity == ValidationSeverity.ERROR
        assert issue.artifact == "a2l"
        assert issue.symbol in issue.message
        assert "missing address/length" in issue.message
    assert issues[0].address is None
    assert issues[1].address == 0x2000

    # Constructor scrub (validation/model.py:137) applies automatically.
    scrubbed = supplemental_a2l_row_issues(
        [{"name": "ESC", "schema_ok": False, "reason": "bad\x1b[31mreason"}], []
    )
    assert len(scrubbed) == 1
    assert "\x1b" not in scrubbed[0].message


# ---------------------------------------------------------------------------
# Layer A — TC-036.2 (LLR-036.2): dedup key = casefolded symbol x artifact
# "a2l" x severity ERROR; WARNING / non-a2l / symbol-less issues never
# suppress.
# ---------------------------------------------------------------------------


def test_tc_036_2_dedup_casefolded_symbol_a2l_error_only() -> None:
    from s19_app.tui.services.validation_service import supplemental_a2l_row_issues

    bad_tag = {"name": "BAD_TAG", "schema_ok": False, "reason": "missing address/length"}

    def _issue(
        code: str,
        severity: ValidationSeverity,
        artifact: str,
        symbol: Optional[str],
    ) -> ValidationIssue:
        return ValidationIssue(
            code=code, severity=severity, message="m", artifact=artifact, symbol=symbol
        )

    # Casefolded symbol match on an a2l ERROR suppresses.
    covered = _issue("A2L_INVALID_ADDRESS", ValidationSeverity.ERROR, "a2l", "Bad_Tag")
    assert supplemental_a2l_row_issues([bad_tag], [covered]) == []

    # WARNING severity does NOT suppress.
    warning = _issue("A2L_BROKEN_REFERENCE", ValidationSeverity.WARNING, "a2l", "BAD_TAG")
    assert len(supplemental_a2l_row_issues([bad_tag], [warning])) == 1

    # Non-a2l artifact does NOT suppress.
    mac_issue = _issue("MAC_ANY", ValidationSeverity.ERROR, "mac", "BAD_TAG")
    assert len(supplemental_a2l_row_issues([bad_tag], [mac_issue])) == 1

    # Symbol-less a2l ERROR (A2L_STRUCTURE_ERROR shape, rules.py:444) never
    # suppresses — neither a named nor a nameless schema-bad tag.
    structural = _issue("A2L_STRUCTURE_ERROR", ValidationSeverity.ERROR, "a2l", None)
    assert len(supplemental_a2l_row_issues([bad_tag], [structural])) == 1
    nameless_tag = {"name": "", "schema_ok": False, "reason": "missing address/length"}
    assert len(supplemental_a2l_row_issues([nameless_tag], [structural])) == 1


# ---------------------------------------------------------------------------
# Layer A — TC-036.3 (LLR-036.3): merged before dedupe in BOTH
# build_validation_report branches, only when the effective tag list is
# non-empty.
# ---------------------------------------------------------------------------


def test_tc_036_3_merge_in_both_report_branches(tmp_path: Path) -> None:
    bad_tags = [
        {"name": "BROKEN", "schema_ok": False, "reason": "missing address/length"}
    ]
    empty_a2l = {"sections": [], "errors": [], "tags": []}

    def identity(issues: list[ValidationIssue]) -> list[ValidationIssue]:
        return issues

    # MAC-only branch (primary_file=None).
    _, mac_only_issues, coverage = build_validation_report(
        records=[],
        primary_file=None,
        a2l_data=empty_a2l,
        a2l_enriched_tags=bad_tags,
        dedupe_issues=identity,
    )
    assert coverage is None
    assert any(issue.code == SUPPLEMENTAL_CODE for issue in mac_only_issues)

    # Primary-backed branch.
    loaded = LoadedFile(
        path=tmp_path / "img.s19",
        file_type="s19",
        mem_map={0x1000: 0x00},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1001)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )
    _, primary_issues, _ = build_validation_report(
        records=[],
        primary_file=loaded,
        a2l_data=empty_a2l,
        a2l_enriched_tags=bad_tags,
        dedupe_issues=identity,
    )
    assert any(issue.code == SUPPLEMENTAL_CODE for issue in primary_issues)

    # Empty effective tag list -> no supplemental merge in either branch.
    for primary in (None, loaded):
        _, issues, _ = build_validation_report(
            records=[],
            primary_file=primary,
            a2l_data=None,
            a2l_enriched_tags=[],
            dedupe_issues=identity,
        )
        assert not any(issue.code == SUPPLEMENTAL_CODE for issue in issues)


# ---------------------------------------------------------------------------
# Layer A — TC-036.4 (LLR-036.1 nameless boundary): symbol=None with the
# message falling back to address/position context.
# ---------------------------------------------------------------------------


def test_tc_036_4_nameless_schema_bad_tag_falls_back_to_context() -> None:
    from s19_app.tui.services.validation_service import supplemental_a2l_row_issues

    with_address = supplemental_a2l_row_issues(
        [{"name": "", "schema_ok": False, "reason": "missing address/length", "address": 0x30}],
        [],
    )
    assert len(with_address) == 1
    assert with_address[0].symbol is None
    assert with_address[0].address == 0x30
    assert "0x30" in with_address[0].message

    without_context = supplemental_a2l_row_issues(
        [{"schema_ok": False, "reason": "missing address/length"}], []
    )
    assert len(without_context) == 1
    assert without_context[0].symbol is None
    assert without_context[0].address is None
    assert "unnamed" in without_context[0].message.casefold()


# ---------------------------------------------------------------------------
# Layer A — TC-037.4 (LLR-037.4): no-MAC sessions with a primary retain the
# validation report on BOTH load paths, routed through the cache key (stable
# empty-records substitute — never wipe-then-recompute); no-primary sessions
# keep the historical clear. White-box scope: private cache/issue members ARE
# the contract under test here.
# ---------------------------------------------------------------------------


def test_tc_037_4_worker_path_retains_report_without_mac(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _RECONCILE_A2L)

    async def _run() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        app.current_a2l_path = a2l_path
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            loaded = app._parse_loaded_file(s19_path)
            assert loaded is not None
            prepared = app._prepare_load_payload(loaded)
            app._apply_prepared_load(prepared, s19_path, 0.0)
            for _ in range(8):
                await pilot.pause()
            issues_after_load = list(app._validation_issues)
            assert issues_after_load, (
                "worker-precomputed report was wiped by the no-MAC branch (B-1a)"
            )
            assert any(i.code == SUPPLEMENTAL_CODE for i in issues_after_load)
            key_after_load = app._mac_view_cache_key
            # Re-render must be a cache-hit no-op: no rebuild, same key, same issues.
            calls = {"n": 0}
            original = app._build_mac_view_cache

            def _counting() -> None:
                calls["n"] += 1
                original()

            app._build_mac_view_cache = _counting  # type: ignore[method-assign]
            app.update_mac_view()
            assert calls["n"] == 0, "no-MAC re-render recomputed instead of cache-hit"
            assert app._mac_view_cache_key == key_after_load
            assert list(app._validation_issues) == issues_after_load

    asyncio.run(_run())


def test_tc_037_4_sync_path_computes_once_and_caches(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _RECONCILE_A2L)

    async def _run() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        app.current_a2l_path = a2l_path
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            loaded = app._parse_loaded_file(s19_path)
            assert loaded is not None
            calls = {"n": 0}
            original = app._build_mac_view_cache

            def _counting() -> None:
                calls["n"] += 1
                original()

            app._build_mac_view_cache = _counting  # type: ignore[method-assign]
            app._apply_loaded_file(loaded, s19_path, 0.0)
            for _ in range(8):
                await pilot.pause()
            assert calls["n"] == 1, (
                f"sync-fallback path built the cache {calls['n']} times (expected 1)"
            )
            issues_after_load = list(app._validation_issues)
            assert any(i.code == SUPPLEMENTAL_CODE for i in issues_after_load)
            key_after_load = app._mac_view_cache_key
            app.update_mac_view()
            assert calls["n"] == 1, "repeat no-MAC render must be a cache hit"
            assert app._mac_view_cache_key == key_after_load
            assert list(app._validation_issues) == issues_after_load

    asyncio.run(_run())


def test_tc_037_4_no_primary_session_keeps_the_clear(tmp_path: Path) -> None:
    async def _run() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            sentinel = ValidationIssue(
                code="SENTINEL",
                severity=ValidationSeverity.ERROR,
                message="stale",
                artifact="a2l",
            )
            app._validation_issues = [sentinel]
            app.update_mac_view()
            await pilot.pause()
            assert app._validation_issues == [], (
                "no-primary session must keep the historical clear (LLR-037.4)"
            )
            assert app._validation_report is None

    asyncio.run(_run())
