"""US-033 / batch-24 I2 — A2L issue => red-row reconcile (HLR-037).

Layer B gates (AT-037a/b) drive the SHIPPED load chain under Textual Pilot —
sync ``asyncio.run`` wrappers (idiom: ``tests/test_tui_patch_layout.py``;
helpers mirror ``tests/test_validation_service_supplemental.py`` — tests/ is
not a package, so the small drive/read-back helpers are duplicated rather than
cross-imported) — and observe only the rendered ``#a2l_tags_list`` /
``#validation_issues_list`` DataTables. Row styles are asserted against
``_severity_style(ValidationSeverity.ERROR)`` (semantic colour-policy anchor;
no raw ``"red"`` literal). Fixtures are deliberately MAC-LESS: AT-037a's map
source (``_validation_issues``) exists in no-MAC sessions only thanks to the
I1 LLR-037.4 retention fix — I1 -> I2 is a STRICT dependency (HLR-037
Acceptance); adding a MAC to green anything here is forbidden.

Layer A: TC-037.1 unit-tests ``_a2l_issue_severity_map`` (LLR-037.1);
TC-037.2 pins the precedence matrix on ``_a2l_tag_row_severity`` including
the WARNING-never-recolours GUARD over CONSTRUCTED issues (A-M1 split, D-2 —
unbuildable black-box, so it lives here, not in an AT); TC-037.3 pins
first-render freshness on the sync-fallback load path (LLR-037.3).

``_a2l_issue_severity_map`` and the re-signatured ``_a2l_tag_row_severity``
are imported lazily inside the Layer-A tests so this module collected (and
AT-037a ran RED) on the pre-fix tree.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Awaitable, Callable, Optional

from textual.widgets import DataTable

from s19_app.tui.app import S19TuiApp, _severity_style
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.validation import ValidationIssue, ValidationSeverity

DUPLICATE_CODE = "A2L_DUPLICATE_SYMBOL"
BROKEN_REF_CODE = "A2L_BROKEN_REFERENCE"
SUPPLEMENTAL_CODE = "A2L_TAG_SCHEMA_INCOMPLETE"

# Issue-row cell layout per ``precompute_issue_datatable_payload``:
# (severity, code, artifact, related, symbol, address, line, message)
_SEV, _CODE, _SYMBOL = 0, 1, 4


# ---------------------------------------------------------------------------
# Fixtures (synthetic, public data only). AT-037a per 01b: the same symbol
# defined twice as a CASE VARIANT (``RPM`` + ``rpm``) — the engine keys
# duplicates on ``name.lower()`` (rules.py:458,470), so BOTH rows must red —
# plus a healthy memory-checked control tag (green candidate) proving
# per-symbol targeting. Both duplicate rows are retained by the parse path
# (a2l.py:912-1068) and carry valid distinct addresses (schema_ok=True), so
# pre-fix they render OK/green: the red is delivered by the issue map alone.
# ---------------------------------------------------------------------------

_DUP_CASE_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin CHARACTERISTIC RPM\n"
    "      ECU_ADDRESS 0x1000\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "    /begin CHARACTERISTIC rpm\n"
    "      ECU_ADDRESS 0x1002\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "    /begin MEASUREMENT TORQUE\n"
    "      ECU_ADDRESS 0x1004\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)

# AT-037b: a GROUP reference to a symbol that never renders as a tag row —
# the shipped chain emits A2L_BROKEN_REFERENCE (WARNING, symbol-bearing,
# rules.py:507), putting an absent-from-table symbol into the severity map.
_BROKEN_REF_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin MEASUREMENT RPM\n"
    "      ECU_ADDRESS 0x1000\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "    /begin GROUP PANEL\n"
    "      REF_MEASUREMENT GHOST_TAG\n"
    "    /end GROUP\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)


def _write_s19(tmp_path: Path) -> Path:
    """Emit a 16-byte synthetic S19 image at 0x1000 covering every fixture
    address (builder idiom: tests/test_tui_patch_editor_v2.py::_make_s19_image)."""
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
# Shipped-chain drive + widget read-back helpers (idiom:
# tests/test_validation_service_supplemental.py; worker path =
# _parse_loaded_file -> _prepare_load_payload -> _apply_prepared_load).
# ---------------------------------------------------------------------------


def _drive_load(
    tmp_path: Path,
    s19_path: Path,
    a2l_path: Path,
    observe: Callable[[S19TuiApp, object], Awaitable[None]],
) -> None:
    """Load S19 (+attached A2L) through the shipped worker-path chain under
    Pilot, then hand the app to ``observe`` for black-box asserts."""

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
    (cells are the styled ``rich.text.Text`` objects; name is column 0)."""
    table = app.query_one("#a2l_tags_list", DataTable)
    rows: list[tuple[str, tuple]] = []
    for index in range(table.row_count):
        cells = table.get_row_at(index)
        rows.append((str(cells[0]), tuple(cells)))
    return rows


def _issue_rows(app: S19TuiApp) -> list[tuple[str, ...]]:
    """Rendered ``#validation_issues_list`` rows as plain-string cell tuples."""
    table = app.query_one("#validation_issues_list", DataTable)
    return [
        tuple(str(cell) for cell in table.get_row_at(index))
        for index in range(table.row_count)
    ]


# ---------------------------------------------------------------------------
# Layer B — AT-037a (GATE): duplicate symbol -> ERROR issue reds BOTH rows;
# control row untouched; issue list content unchanged (render-side-only fix).
# Counterfactual (the reported bug): pre-fix both duplicate rows render
# non-red (schema_ok=True + memory-checked -> OK/green) while the
# A2L_DUPLICATE_SYMBOL ERROR sits on the Issues surface — captured verbatim
# in .dev-flow/2026-07-02-batch-24/03-increments/increment-2.md.
# ---------------------------------------------------------------------------


def test_at_037a_duplicate_symbol_error_issue_reds_both_rows(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _DUP_CASE_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        error_style = _severity_style(ValidationSeverity.ERROR)
        rows = _a2l_row_list(app)
        dup_rows = [cells for name, cells in rows if name.casefold() == "rpm"]
        assert len(dup_rows) == 2, (
            f"expected both case-variant duplicate rows rendered; "
            f"got names: {[name for name, _ in rows]}"
        )
        # Observable 1 — BOTH duplicate rows ERROR-styled (case-folded match,
        # mirroring the engine's name.lower() duplicate grouping).
        for cells in dup_rows:
            assert all(cell.style == error_style for cell in cells), (
                "duplicate-symbol row is not ERROR-styled "
                "(ERROR issue does not recolour its rows — the HLR-037 divergence)"
            )
        # Observable 2 — healthy control row unaffected (per-symbol targeting).
        torque_rows = [cells for name, cells in rows if name == "TORQUE"]
        assert torque_rows, "control tag TORQUE missing from the rendered table"
        assert all(cell.style != error_style for cell in torque_rows[0]), (
            "control tag TORQUE must not be recoloured"
        )
        # Observable 3 — issue list content unchanged (US-033 is render-side
        # only): exactly one A2L_DUPLICATE_SYMBOL ERROR, no supplemental code.
        app.action_show_screen("issues")
        await pilot.pause()
        issue_rows = _issue_rows(app)
        dup_issues = [row for row in issue_rows if row[_CODE] == DUPLICATE_CODE]
        assert len(dup_issues) == 1, (
            f"expected exactly ONE {DUPLICATE_CODE} issue; rows: {issue_rows!r}"
        )
        assert dup_issues[0][_SEV] == ValidationSeverity.ERROR.value.upper()
        assert dup_issues[0][_SYMBOL].casefold() == "rpm"
        assert not any(row[_CODE] == SUPPLEMENTAL_CODE for row in issue_rows), (
            "schema-complete duplicate tags must gain no supplemental issue"
        )

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer B — AT-037b (boundary, A-M1 split): an issue symbol ABSENT from the
# rendered tag set (naturally produced via A2L_BROKEN_REFERENCE) is inert —
# no crash, no row change.
# ---------------------------------------------------------------------------


def test_at_037b_absent_from_table_issue_symbol_is_inert(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _BROKEN_REF_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        error_style = _severity_style(ValidationSeverity.ERROR)
        rows = dict(_a2l_row_list(app))
        assert "RPM" in rows, f"expected RPM rendered; got {sorted(rows)}"
        assert "GHOST_TAG" not in rows, "referenced-only symbol must not render as a tag row"
        # No row change: the healthy tag keeps its non-ERROR style.
        assert all(cell.style != error_style for cell in rows["RPM"]), (
            "absent-from-table issue symbol must not recolour other rows"
        )
        # Load-bearing positive assert: the shipped chain really produced the
        # absent-symbol issue (otherwise this boundary passes vacuously).
        app.action_show_screen("issues")
        await pilot.pause()
        issue_rows = _issue_rows(app)
        ghost = [
            row
            for row in issue_rows
            if row[_CODE] == BROKEN_REF_CODE and row[_SYMBOL] == "GHOST_TAG"
        ]
        assert ghost, (
            f"fixture failed to produce the natural {BROKEN_REF_CODE} issue "
            f"for GHOST_TAG; rows: {issue_rows!r}"
        )

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer A — TC-037.1 (LLR-037.1): map build/filter semantics — a2l-only,
# non-empty symbol only, casefolded keys, max severity order-independent.
# ---------------------------------------------------------------------------


def _issue(
    code: str,
    severity: ValidationSeverity,
    artifact: str,
    symbol: Optional[str],
) -> ValidationIssue:
    return ValidationIssue(
        code=code, severity=severity, message="m", artifact=artifact, symbol=symbol
    )


def test_tc_037_1_issue_severity_map_build_and_filter_semantics() -> None:
    from s19_app.tui.app import _a2l_issue_severity_map

    issues = [
        _issue("A2L_DUPLICATE_SYMBOL", ValidationSeverity.ERROR, "a2l", "Dup_Sym"),
        _issue("A2L_BROKEN_REFERENCE", ValidationSeverity.WARNING, "a2l", "dup_sym"),
        _issue("A2L_BROKEN_REFERENCE", ValidationSeverity.WARNING, "a2l", "WARN_ONLY"),
        _issue("CROSS_MAC_S19_OUT_OF_RANGE", ValidationSeverity.ERROR, "mac", "MAC_SYM"),
        _issue("A2L_STRUCTURE_ERROR", ValidationSeverity.ERROR, "a2l", None),
        _issue("A2L_INVALID_ADDRESS", ValidationSeverity.ERROR, "a2l", ""),
    ]
    severity_map = _a2l_issue_severity_map(issues)
    assert severity_map == {
        "dup_sym": ValidationSeverity.ERROR,  # max wins over the later WARNING
        "warn_only": ValidationSeverity.WARNING,
    }, "map must filter non-a2l + symbol-less issues and casefold keys"

    # Order independence: WARNING first, ERROR second -> still ERROR.
    reordered = _a2l_issue_severity_map(
        [
            _issue("A2L_BROKEN_REFERENCE", ValidationSeverity.WARNING, "a2l", "sym"),
            _issue("A2L_DUPLICATE_SYMBOL", ValidationSeverity.ERROR, "a2l", "SYM"),
        ]
    )
    assert reordered == {"sym": ValidationSeverity.ERROR}

    assert _a2l_issue_severity_map([]) == {}


# ---------------------------------------------------------------------------
# Layer A — TC-037.2 (LLR-037.2): precedence matrix — ERROR-mapped symbol
# beats every ladder outcome (incl. green); empty map reduces to the existing
# ladder; unmapped symbol unchanged; and the WARNING-never-recolours GUARD
# over CONSTRUCTED issues (A-M1 / D-2: the A2L palette is Red/Green/White/
# Grey only — recolouring on WARNING would invent a fifth state).
# ---------------------------------------------------------------------------

_LADDER: list[tuple[dict, ValidationSeverity]] = [
    ({"name": "T", "schema_ok": False}, ValidationSeverity.ERROR),
    (
        {"name": "T", "schema_ok": True, "memory_checked": True, "in_memory": True},
        ValidationSeverity.OK,
    ),
    (
        {"name": "T", "schema_ok": True, "memory_checked": True, "in_memory": False},
        ValidationSeverity.INFO,
    ),
    (
        {"name": "T", "schema_ok": True, "memory_checked": False, "source": "formula"},
        ValidationSeverity.INFO,
    ),
    ({"name": "T", "schema_ok": True, "memory_checked": False}, ValidationSeverity.NEUTRAL),
]


def test_tc_037_2_row_severity_precedence_matrix_and_warning_guard() -> None:
    from s19_app.tui.app import _a2l_tag_row_severity

    # Empty map -> the function reduces to the pre-US-033 ladder exactly.
    for tag, expected in _LADDER:
        assert _a2l_tag_row_severity(tag, {}) == expected, f"empty-map ladder broke for {tag}"

    # ERROR-mapped symbol (casefolded lookup) -> ERROR wins over EVERY ladder
    # outcome, including the green memory-checked-present candidate.
    error_map = {"t": ValidationSeverity.ERROR}
    for tag, _ in _LADDER:
        assert _a2l_tag_row_severity(tag, error_map) == ValidationSeverity.ERROR, (
            f"ERROR issue must recolour {tag}"
        )

    # GUARD (D-2): WARNING-mapped symbol never recolours — ladder unchanged.
    warning_map = {"t": ValidationSeverity.WARNING}
    for tag, expected in _LADDER:
        assert _a2l_tag_row_severity(tag, warning_map) == expected, (
            f"WARNING issue must NOT recolour {tag} (A2L palette has no orange)"
        )

    # Unmapped symbol -> unchanged.
    other_map = {"other": ValidationSeverity.ERROR}
    for tag, expected in _LADDER:
        assert _a2l_tag_row_severity(tag, other_map) == expected

    # Nameless tag never consults the map.
    assert (
        _a2l_tag_row_severity({"schema_ok": True, "memory_checked": False}, {"": ValidationSeverity.ERROR})
        == ValidationSeverity.NEUTRAL
    )


# ---------------------------------------------------------------------------
# Layer A — TC-037.3 (LLR-037.3): first-render freshness on the SYNC-FALLBACK
# load path (no worker precompute): update_a2l_view must install the issue
# list (update_mac_view, post-enrichment) BEFORE tag rows render, so the
# duplicate rows are red on the FIRST rendered frame — the load chain never
# re-renders the tag table afterwards, so a stale first frame would persist.
# ---------------------------------------------------------------------------


def test_tc_037_3_sync_fallback_first_render_is_fresh(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _DUP_CASE_A2L)

    async def _run() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        app.current_a2l_path = a2l_path
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            loaded = app._parse_loaded_file(s19_path)
            assert loaded is not None
            app._apply_loaded_file(loaded, s19_path, 0.0)
            for _ in range(8):
                await pilot.pause()
            error_style = _severity_style(ValidationSeverity.ERROR)
            dup_rows = [
                cells for name, cells in _a2l_row_list(app) if name.casefold() == "rpm"
            ]
            assert len(dup_rows) == 2
            for cells in dup_rows:
                assert all(cell.style == error_style for cell in cells), (
                    "stale first render on the sync-fallback path: issues were "
                    "installed AFTER the tag rows rendered (LLR-037.3 reorder)"
                )

    asyncio.run(_run())
