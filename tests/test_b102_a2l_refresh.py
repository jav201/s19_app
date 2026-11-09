"""Batch-102 Inc 2 — A2L load/reload siempre refresca el viewer (TC-B102-A2L-01..07).

E4 tester tests for the A2L viewer-refresh slice. Oracles come from the Inc 2
design packet: ``.dev-flow/2026-11-03-batch-102/inc-2/01-requirements.md``
(R-B102-A2L-001..006), ``02-test-cases.md`` (TC-B102-A2L-01..07) and
``codewire-graph.md``, plus the E3 addendas in
``.dev-flow/2026-11-03-batch-102/design/E3-rulings-inc1-inc2.md`` (Inc 2:
``_start_load_worker`` generation prediction, hostile-filter literal painting
via ``safe_text``/``Text``, ``Optional[str]`` empty message).

Layer B style (idiom: ``tests/test_tui_a2l_issue_recolor.py``,
``tests/test_b100_busy.py``): the shipped chain is driven under Textual Pilot
and the painted ``#a2l_tags_list`` / ``#a2l_tags_summary`` / ``#a2l_view``
widgets are read back black-box; worker-path loads drain with
``app.workers.wait_for_complete()`` and short settle loops. No ``s19_app``
source is touched; fixtures are synthetic and public.

RED-in-base expectation (per ``02-test-cases.md`` notas de ejecucion):
TC-B102-A2L-02 (sync-path equal-size reload keeps the ``(id, mem_size)``
enrichment key because the A2L parse cache returns the same payload dict),
TC-B102-A2L-04 (base paints the generic ``No A2L tags.`` instead of the
filter-named message) and TC-B102-A2L-05 (forced ``id()`` collision hits the
identity key) fail on the pre-fix tree; TC-B102-A2L-07 fails because base
installs a worker precompute without generation verification. TC-B102-A2L-01,
-03 and -06 pin behaviour the base already has (they exist to kill the named
mutants, not to be red today).
"""

from __future__ import annotations

import builtins
from pathlib import Path

import pytest
from textual.widgets import DataTable, Input, Label, Static

import s19_app.tui.app as app_module
from s19_app.tui.app import (
    A2LAttachRequest,
    A2LAttachResult,
    PreparedLoad,
    S19TuiApp,
    parse_a2l_cached,
)
from s19_app.tui.changes.io import (
    emit_intel_hex_from_mem_map,
    emit_s19_from_mem_map,
)
from s19_app.tui.workspace import WORKAREA_TEMP

from tests.support import b100_projects as projects

SIZE = (120, 40)

#: Fixture A — tags Alpha and Beta, both inside a 16-byte image at 0x1000.
FIXTURE_A_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin CHARACTERISTIC Alpha\n"
    "      ECU_ADDRESS 0x1000\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "    /begin CHARACTERISTIC Beta\n"
    "      ECU_ADDRESS 0x1002\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)

#: Fixture B — tags Alpha and Gamma (the distinto-attach payload).
FIXTURE_B_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin CHARACTERISTIC Alpha\n"
    "      ECU_ADDRESS 0x1000\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "    /begin CHARACTERISTIC Gamma\n"
    "      ECU_ADDRESS 0x1002\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)

#: Hostile filter text (E3 addenda Inc 2 #3): a Rich style token that must be
#: painted literally, never interpreted as markup.
HOSTILE_FILTER = "[red]"


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _write_s19(tmp: Path, name: str, base: int, size: int = 16, fill: int = 0x00) -> Path:
    mem_map = {base + off: fill for off in range(size)}
    path = tmp / name
    path.write_text(
        emit_s19_from_mem_map(mem_map, [(base, base + size)]), encoding="ascii"
    )
    return path


def _write_hex(tmp: Path, name: str, base: int, size: int = 16, fill: int = 0x00) -> Path:
    mem_map = {base + off: fill for off in range(size)}
    path = tmp / name
    path.write_text(
        emit_intel_hex_from_mem_map(mem_map, [(base, base + size)]), encoding="ascii"
    )
    return path


def _write_a2l(tmp: Path, name: str, text: str) -> Path:
    path = tmp / name
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Widget read-back helpers (duplicated per project convention — tests/ is not
# a package for cross-import of drive/read helpers; idiom:
# tests/test_tui_a2l_issue_recolor.py).
# ---------------------------------------------------------------------------


def _strip_glyph(name_cell: str) -> str:
    for glyph in ("✓ ", "· "):
        if name_cell.startswith(glyph):
            return name_cell[len(glyph):]
    return name_cell


def _tag_column_index(table: DataTable) -> int:
    """The Tag column's index in ``ordered_columns`` (Inc 12 re-orders the
    columns to Address, Length, Tag, …; E2-6)."""
    for index, column in enumerate(table.ordered_columns):
        if str(column.label) == "Tag":
            return index
    raise AssertionError(f"no Tag column in {[str(c.label) for c in table.ordered_columns]}")


def _row_names(app: S19TuiApp) -> list[str]:
    table = app.query_one("#a2l_tags_list", DataTable)
    tag_column = _tag_column_index(table)
    return [_strip_glyph(str(table.get_row_at(i)[tag_column])) for i in range(table.row_count)]


def _in_memory_cells(app: S19TuiApp) -> list[str]:
    """Column 6 of the painted rows — the ``yes``/``no``/``n/a`` in-image cell."""
    table = app.query_one("#a2l_tags_list", DataTable)
    return [str(table.get_row_at(i)[6]) for i in range(table.row_count)]


def _row_count(app: S19TuiApp) -> int:
    return app.query_one("#a2l_tags_list", DataTable).row_count


def _summary_text(app: S19TuiApp) -> str:
    return str(app.query_one("#a2l_tags_summary", Label).render())


def _a2l_view_text(app: S19TuiApp) -> str:
    return str(app.query_one("#a2l_view", Static).render())


# ---------------------------------------------------------------------------
# Shipped-chain drive helpers
# ---------------------------------------------------------------------------


async def _settle(pilot, n: int = 10) -> None:
    for _ in range(n):
        await pilot.pause()


async def _drain(app: S19TuiApp, pilot) -> None:
    """Wait for the worker-path attach/load to fully install and repaint."""
    await app.workers.wait_for_complete()
    await _settle(pilot)


def _attach_result(app: S19TuiApp, a2l_path: Path) -> A2LAttachResult:
    """The bundle the A2L attach worker hands back (``_a2l_attach_worker`` tail:
    copy (skipped here) + ``parse_a2l_cached``), without the thread."""
    entry = parse_a2l_cached(a2l_path, None)
    request = A2LAttachRequest(
        source=a2l_path,
        copy=False,
        temp_dir=app.workarea / WORKAREA_TEMP,
        workarea=app.workarea,
        record_recent=False,
        a2l_cache=None,
        gen=0,
    )
    return A2LAttachResult(request, a2l_path, entry, 0.0)


def _attach(app: S19TuiApp, a2l_path: Path) -> None:
    """Drive the one shipped attach install (``_install_attached_a2l``) on the
    main thread — the seam whose order Inc 2 changes (payload -> view -> outcome)."""
    app._install_attached_a2l(_attach_result(app, a2l_path))


def _set_filter(app: S19TuiApp, text: str) -> None:
    app.query_one("#a2l_tags_filter_input", Input).value = text


# ---------------------------------------------------------------------------
# TC-B102-A2L-01 — direct A2L attach refreshes enriched/filtered rows before
# the success outcome. Covers R-B102-A2L-001 over its 3/3 routes: attach
# inicial, attach distinto, re-attach del mismo archivo tras clear.
# Mutant control: remove the install's ``update_a2l_view()`` call -> rows stay
# empty after every route.
# ---------------------------------------------------------------------------


def test_tc_b102_a2l_01_direct_attach_refreshes_viewer(
    tmp_path: Path,
) -> None:
    img = _write_s19(tmp_path, "img.s19", 0x1000)
    a_a2l = _write_a2l(tmp_path, "fixture_a.a2l", FIXTURE_A_A2L)
    b_a2l = _write_a2l(tmp_path, "fixture_b.a2l", FIXTURE_B_A2L)

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        await projects.load_image(pilot, app, img)
        await _settle(pilot)

        # Route 1/3 — attach inicial through the shipped entry point
        # (``load_a2l_from_path`` -> worker -> ``_install_attached_a2l``).
        app.load_a2l_from_path(a_a2l)
        await _drain(app, pilot)
        # The tag rows are already painted at the outcome boundary: no manual
        # refresh action runs between the install and this read-back.
        assert _row_names(app) == ["Alpha", "Beta"]
        assert " / 2 " in _summary_text(app)
        assert set(app._a2l_row_key_to_tag) == {"a2l:0", "a2l:1"}
        assert "A2L loaded" in log.messages[-1]
        assert "fixture_a.a2l" in log.messages[-1]

        # Route 2/3 — attach distinto replaces the rows before its own outcome.
        app.load_a2l_from_path(b_a2l)
        await _drain(app, pilot)
        assert _row_names(app) == ["Alpha", "Gamma"]
        assert "A2L loaded" in log.messages[-1]

        # Route 3/3 — clear/unload, then re-attach of the SAME file refreshes
        # again (no reliance on payload identity having changed).
        app._apply_unload("a2l")
        await _settle(pilot)
        assert _row_count(app) == 0
        app.load_a2l_from_path(a_a2l)
        await _drain(app, pilot)
        assert _row_names(app) == ["Alpha", "Beta"]
        assert " / 2 " in _summary_text(app)
        assert "A2L loaded" in log.messages[-1]

    projects.run_app(tmp_path / "app", scenario, size=SIZE)


# ---------------------------------------------------------------------------
# TC-B102-A2L-02 — reloading an equal-size, different-content primary image
# refreshes A2L memory state automatically. Covers R-B102-A2L-002/.006.
# RED in base: the A2L parse cache returns the same payload dict for the
# re-attached A2L and the new HEX image has the same map size, so the
# ``(id(current_a2l_data), mem_size)`` enrichment key is unchanged and the
# rows keep painting image-1 membership. Mutant control: a fix keying on
# ``(a2l_gen, mem_size)`` without ``_image_generation`` stays red.
# ---------------------------------------------------------------------------


def test_tc_b102_a2l_02_same_size_reload_refreshes_rows(tmp_path: Path) -> None:
    a_a2l = _write_a2l(tmp_path, "fixture_a.a2l", FIXTURE_A_A2L)
    img1 = _write_s19(tmp_path, "img1.s19", 0x1000)
    # Image 2: same address count (16), different mapped addresses AND content.
    img2 = _write_hex(tmp_path, "img2.hex", 0x2000, fill=0xFF)

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        app.load_a2l_from_path(a_a2l)
        await _drain(app, pilot)

        # Image 1 (S19) covers both tag addresses -> rows paint in-image "yes".
        await projects.load_image(pilot, app, img1)
        await _settle(pilot)
        assert _row_names(app) == ["Alpha", "Beta"]
        assert _in_memory_cells(app) == ["yes", "yes"]

        # Reload through the file-load path: same-size HEX over the same A2L.
        await projects.load_image(pilot, app, img2)
        await _settle(pilot)
        # The final painted rows must reflect image-2 membership: neither tag
        # address (0x1000/0x1002) is mapped by the image at 0x2000.
        assert _row_names(app) == ["Alpha", "Beta"]
        assert _in_memory_cells(app) == ["no", "no"], (
            "painted A2L rows still describe the previous image's membership — "
            "the enrichment cache was not invalidated by the equal-size reload"
        )

    projects.run_app(tmp_path / "app", scenario, size=SIZE)


# ---------------------------------------------------------------------------
# TC-B102-A2L-03 — an active filter is applied to a newly attached A2L.
# Covers R-B102-A2L-003 (match arm). Mutant control: ignore the filter after
# attach -> all rows render.
# ---------------------------------------------------------------------------


def test_tc_b102_a2l_03_active_filter_applied_to_new_attach(tmp_path: Path) -> None:
    b_a2l = _write_a2l(tmp_path, "fixture_b.a2l", FIXTURE_B_A2L)

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        _set_filter(app, "Alpha")
        await _settle(pilot)
        _attach(app, b_a2l)
        await _settle(pilot)
        assert _row_names(app) == ["Alpha"]
        assert " / 1 " in _summary_text(app), _summary_text(app)

    projects.run_app(tmp_path / "app", scenario, size=SIZE)


# ---------------------------------------------------------------------------
# TC-B102-A2L-04 — an active filter with no matches names the filter instead
# of the generic empty message, painted literally (E3 addenda Inc 2 #3: a
# hostile filter must reach the screen as inert text via safe_text/Text,
# never as Rich markup). Covers R-B102-A2L-003 (no-match arm).
# RED in base: the summary paints the generic ``No A2L tags.``.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("filt", ["Missing", HOSTILE_FILTER])
def test_tc_b102_a2l_04_no_match_filter_names_filter(tmp_path: Path, filt: str) -> None:
    b_a2l = _write_a2l(tmp_path, "fixture_b.a2l", FIXTURE_B_A2L)

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        _set_filter(app, filt)
        await _settle(pilot)
        _attach(app, b_a2l)
        await _settle(pilot)
        assert _row_count(app) == 0
        label = app.query_one("#a2l_tags_summary", Label)
        rendered = label.render()
        expected = f"No A2L tags match '{filt}'."
        assert str(rendered) == expected, (
            f"expected the exact filter-named empty message {expected!r}; "
            f"got {str(rendered)!r} (a generic message or an interpreted-markup "
            f"render both fail this contract)"
        )
        if filt == HOSTILE_FILTER:
            # Literal-painting proof: the hostile token survives verbatim in
            # the plain text; if markup were interpreted, ``[red]`` would be
            # consumed as a style tag and vanish from the painted string.
            assert filt in getattr(rendered, "plain", str(rendered))

    projects.run_app(tmp_path / "app", scenario, size=SIZE)


# ---------------------------------------------------------------------------
# TC-B102-A2L-05 — forcing the same object identity and memory size cannot
# return stale enrichment (R-B102-A2L-001/.004, robustness). ``id()`` is
# forced to one constant for BOTH payloads (deterministic, GC-independent,
# per 02-test-cases.md notas); every other object falls through to the real
# ``id()`` so Textual internals are untouched. RED in base: the
# ``(id(payload), mem_size)`` key collides and the stale list renders.
# Mutant control: restoring the ``(id(payload), mem_size)`` key stays red.
# ---------------------------------------------------------------------------


def test_tc_b102_a2l_05_forced_id_collision_recomputes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a_a2l = _write_a2l(tmp_path, "fixture_a.a2l", FIXTURE_A_A2L)
    b_a2l = _write_a2l(tmp_path, "fixture_b.a2l", FIXTURE_B_A2L)
    colliding_id = 0xC0111DE
    real_id = builtins.id

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        entry_a = parse_a2l_cached(a_a2l, None)
        entry_b = parse_a2l_cached(b_a2l, None)
        payload_a, payload_b = entry_a[1], entry_b[1]

        def _forced_id(obj: object) -> int:
            if obj is payload_a or obj is payload_b:
                return colliding_id
            return real_id(obj)

        monkeypatch.setattr(builtins, "id", _forced_id)
        try:
            # Attach A at the forced identity: base stores the enrichment key
            # ``(colliding_id, mem_size)``.
            app._install_attached_a2l(
                A2LAttachResult(
                    A2LAttachRequest(
                        source=a_a2l, copy=False,
                        temp_dir=app.workarea / WORKAREA_TEMP,
                        workarea=app.workarea, record_recent=False,
                        a2l_cache=None, gen=0,
                    ),
                    a_a2l, entry_a, 0.0,
                )
            )
            await _settle(pilot)
            assert _row_names(app) == ["Alpha", "Beta"]

            # Attach B: a DIFFERENT payload at the SAME forced object address
            # and the same memory-map size. Fresh tags must be computed.
            app._install_attached_a2l(
                A2LAttachResult(
                    A2LAttachRequest(
                        source=b_a2l, copy=False,
                        temp_dir=app.workarea / WORKAREA_TEMP,
                        workarea=app.workarea, record_recent=False,
                        a2l_cache=None, gen=0,
                    ),
                    b_a2l, entry_b, 0.0,
                )
            )
            await _settle(pilot)
        finally:
            monkeypatch.undo()
        assert _row_names(app) == ["Alpha", "Gamma"], (
            "stale enrichment rendered: the identity-colliding attach returned "
            "the previous payload's tag list (Beta must be gone, Gamma present)"
        )
        assert " / 2 " in _summary_text(app)

    projects.run_app(tmp_path / "app", scenario, size=SIZE)


# ---------------------------------------------------------------------------
# TC-B102-A2L-06 — the no-A2L state after clear/unload (R-B102-A2L-005).
# Mutant control: keep the previous rows after clear -> non-empty table.
# ---------------------------------------------------------------------------


def test_tc_b102_a2l_06_clear_unload_renders_empty_state(tmp_path: Path) -> None:
    a_a2l = _write_a2l(tmp_path, "fixture_a.a2l", FIXTURE_A_A2L)

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        _attach(app, a_a2l)
        await _settle(pilot)
        assert _row_names(app) == ["Alpha", "Beta"]

        app._apply_unload("a2l")
        await _settle(pilot)
        assert _a2l_view_text(app) == "No A2L loaded."
        assert _row_count(app) == 0
        assert app._a2l_row_key_to_tag == {}
        assert app.current_a2l_data is None

    projects.run_app(tmp_path / "app", scenario, size=SIZE)


# ---------------------------------------------------------------------------
# TC-B102-A2L-07 — a stale worker precompute is discarded when generations
# change before apply (R-B102-A2L-006, robustness; umbral 2/2).
#
# Arm 1 (valid snapshot installs): the shipped worker path
# (``load_from_path`` -> ``_start_load_worker`` -> ``_prepare_load_payload`` ->
# ``_apply_prepared_load``) precomputes enrichment for image 1 and the apply
# installs it — the painted rows come from the worker cache.
#
# Arm 2 (stale snapshot discarded): a ``PreparedLoad`` shaped like the
# pre-fix worker bundle carries an A2L enrichment captured against image 1
# (generation N) while the apply installs image 2 (generation N+1, and the
# pre-fix bundle carries no generation stamp at all). The apply must NOT
# install the precomputed cache: ``_compute_a2l_enriched_tags`` recomputes on
# the UI thread and the painted rows describe image 2.
# RED in base: ``_apply_prepared_load`` installs ``prepared.a2l_enriched_*``
# unconditionally and the identity key matches, so image-1 membership paints.
# Mutant control: install ``prepared.a2l_enriched_*`` without generation
# verification -> stale rows paint -> red.
# ---------------------------------------------------------------------------


def test_tc_b102_a2l_07_stale_prepared_load_discarded(tmp_path: Path) -> None:
    a_a2l = _write_a2l(tmp_path, "fixture_a.a2l", FIXTURE_A_A2L)
    img1 = _write_s19(tmp_path, "img1.s19", 0x1000)
    img2 = _write_hex(tmp_path, "img2.hex", 0x2000, fill=0xFF)

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        app.load_a2l_from_path(a_a2l)
        await _drain(app, pilot)

        # Arm 1/2 — valid snapshot: the shipped worker path precomputes
        # against image 1 and the apply installs it (rows in-image "yes").
        app.load_from_path(img1)
        await _drain(app, pilot)
        assert _row_names(app) == ["Alpha", "Beta"]
        assert _in_memory_cells(app) == ["yes", "yes"]

        # Arm 2/2 — stale snapshot: capture image-1 enrichment (generation N)
        # and hand-apply a PreparedLoad for image 2 (generation N+1) carrying
        # that stale cache with the pre-fix key shape.
        stale_tags = list(app._a2l_enriched_tags)
        assert stale_tags and all(t.get("in_memory") for t in stale_tags), (
            "arm-1 setup: the worker precompute must have produced in-image "
            "enrichment for image 1, otherwise the stale arm is vacuous"
        )
        loaded2 = app._parse_loaded_file(img2)
        assert loaded2 is not None
        assert loaded2.a2l_data is not None
        stale_prepared = PreparedLoad(
            loaded=loaded2,
            precomputed=True,
            a2l_enriched_tags=stale_tags,
            a2l_enriched_key=(id(loaded2.a2l_data), len(loaded2.mem_map)),
            a2l_summary_lines=["stale snapshot"],
        )
        app._apply_prepared_load(stale_prepared, img2, 0.0)
        await _settle(pilot)
        assert app._a2l_enriched_tags is not stale_tags, (
            "the stale worker precompute was installed verbatim — apply-time "
            "generation verification is missing"
        )
        assert _row_names(app) == ["Alpha", "Beta"]
        assert _in_memory_cells(app) == ["no", "no"], (
            "painted A2L rows came from the stale worker snapshot instead of "
            "a UI-thread recompute against the applied image"
        )

    projects.run_app(tmp_path / "app", scenario, size=SIZE)
