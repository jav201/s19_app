"""Direction B snapshot + breakpoint-boundary tests — batch-02, increment 12.

Covers the increment-12 LLRs:
  - LLR-007.1 — density layout integrity (no overlap / no clip across the
    fixed {80x24, 120x30, 160x40} size matrix, in both density modes).
  - LLR-007.2 — every snapshot baseline is rendered ONLY against the public
    synthetic fixtures (the ``tests/conftest.py`` generators
    ``make_large_s19`` / ``make_large_a2l`` / ``make_large_mac``); no client
    firmware / A2L / MAC artifact is ever loaded.

Test cases:
  - TC-016-S — the 29-baseline ``pytest-textual-snapshot`` SVG matrix:
    the 4 restyled screens (Workspace, A2L Explorer, MAC View, Issues
    Report) x {compact, comfortable} x {80x24, 120x30, 160x40} = 24
    baselines, plus the additive scaffold screens: the A2B Diff at the 120x30
    primary size (1), the Patch Editor at both 80x24 and 120x30 to lock the
    batch-22 US-030 2x2 four-pane layout (2), and the Memory Map at both 80x24
    and 120x30 to lock the batch-27 minimap redesign + narrow-regime reflow
    (2) = 5 scaffold baselines.
    29 baseline ``.svg`` files total (batch-27 US-037 adds the map 80x24 reflow
    cell; batch-22 US-031 added the patch 80x24 cell).
  - TC-016-S public-fixture sub-case — the snapshot setup loads no client
    artifact; every baseline traces to a ``conftest.py`` generator.
  - TC-016 / CV-04 — the 119/120-column breakpoint boundary check: the
    proportional ``width-narrow`` regime is in effect at terminal width
    119 and the fixed regime at width 120. This is a plain ``run_test()``
    assertion and needs no snapshot library.

Snapshot strategy (requirements section 5.5, OQ-5 / S-2 resolved)
----------------------------------------------------------------
``pytest-textual-snapshot`` is a dev-only optional dependency declared in
``pyproject.toml`` ``[project.optional-dependencies] dev``. The snapshot
tests carry the ``snapshot`` pytest marker so they can be deselected on a
constrained CI (``pytest -m 'not snapshot'``). If the plugin is not
installed the ``snap_compare`` fixture is absent; the snapshot tests are
then skipped (never failed) via ``pytest.importorskip`` at import time.

Public-fixture-only rule (LLR-007.2 / S-2): a ``pytest-textual-snapshot``
SVG baseline embeds the rendered screen content — bytes, addresses, symbol
names, MAC tags — as committed text. Rendering a baseline against a real
client artifact would commit proprietary data to a shared repo. Every
baseline here is rendered against the deterministic ``conftest.py``
generators only, which produce synthetic, non-confidential, in-repo data;
no path under a client directory is ever opened. ``_PUBLIC_FIXTURE_SOURCES``
records the allowed sources and is asserted by the public-fixture sub-case.

The app instance handed to ``snap_compare`` is a real ``S19TuiApp``; the
``run_before`` callable installs a synthetic ``LoadedFile`` (built through
the same load/parse services the real load pipeline uses), sets the
density class, and navigates the rail to the screen under test — the
deterministic, headless analogue of the ``test_tui_directionb.py`` driver.
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

import pytest

from s19_app.tui.app import S19TuiApp

# The conftest.py public synthetic generators — the ONLY allowed snapshot
# fixture source (LLR-007.2). Imported by name so a future client-fixture
# import would be a visible, reviewable change. The ``tests.conftest`` import
# path matches the convention in ``test_tui_app.py`` / ``generate_large_samples.py``.
from tests.conftest import make_large_a2l, make_large_mac, make_large_s19

# pytest-textual-snapshot is a dev-only optional dependency. When absent the
# whole snapshot module is skipped (the CV-04 boundary check lives in its own
# module-free function below and runs regardless via a guarded import).
snapshot_plugin_available = True
try:  # pragma: no cover - import guard
    import pytest_textual_snapshot  # noqa: F401
except ImportError:  # pragma: no cover - constrained CI without the dev extra
    snapshot_plugin_available = False


# ---------------------------------------------------------------------------
# Public-fixture sources (LLR-007.2) — the allow-list every baseline traces to
# ---------------------------------------------------------------------------

# The deterministic generators are the snapshot fixture source. The
# examples/case_00_public/ directory is the other approved public source
# named by LLR-007.2; it is recorded here for the public-fixture sub-case
# even though this module renders only from the generators.
_EXAMPLES_PUBLIC = (
    Path(__file__).resolve().parent.parent / "examples" / "case_00_public"
)
_PUBLIC_FIXTURE_SOURCES = {
    "make_large_s19": make_large_s19,
    "make_large_a2l": make_large_a2l,
    "make_large_mac": make_large_mac,
}


# The fixed size matrix (OQ-1 / OQ-9): 80x24 minimum, 120x30 primary,
# 160x40 — the three terminal sizes LLR-007.1 pins.
_SIZES = {
    "80x24": (80, 24),
    "120x30": (120, 30),
    "160x40": (160, 40),
}

# The 4 restyled screens carry the full {density x size} matrix; the 3
# additive scaffolds, which have no pre-batch behavior to regress, are
# pinned at the 120x30 primary size only (requirements section 5.5).
_RESTYLED_SCREENS = ["workspace", "a2l", "mac", "issues"]
_SCAFFOLD_SCREENS = ["map", "patch", "diff"]


# ---------------------------------------------------------------------------
# Public synthetic fixture — a small deterministic S19 + A2L + MAC triple
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def public_triple(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Build a small deterministic public S19 + A2L + MAC triple.

    Summary:
        Manufacture a synthetic firmware triple via the ``conftest.py``
        generators (``make_large_s19`` / ``make_large_a2l`` / ``make_large_mac``)
        sized small enough to render fast and stable as an SVG snapshot. The
        triple is the ONLY data the snapshot baselines render against
        (LLR-007.2) — it is synthetic, deterministic and non-confidential.

    Args:
        tmp_path_factory (pytest.TempPathFactory): pytest temp-dir factory.

    Returns:
        dict[str, Path]: ``{"s19": path, "a2l": path, "mac": path}``.

    Data Flow:
        - Generators write deterministic content (fixed seed) to a module
          temp dir; the paths are reused by every snapshot test.

    Dependencies:
        Uses:
            - ``conftest.make_large_s19`` / ``make_large_a2l`` / ``make_large_mac``
        Used by:
            - ``_build_loaded_triple`` (snapshot ``run_before`` setup)
    """
    base = tmp_path_factory.mktemp("snapshot_public")
    s19 = make_large_s19(
        base / "snap.s19", num_ranges=4, bytes_per_range=256, seed=0
    )
    a2l = make_large_a2l(
        base / "snap.a2l",
        num_measurements=24,
        num_characteristics=8,
        memory_span_bytes=4 * 4096,
        seed=0,
    )
    mac = make_large_mac(
        base / "snap.mac",
        num_records=24,
        num_diagnostics=4,
        memory_span_bytes=4 * 4096,
        num_a2l_tags=24,
        seed=0,
    )
    return {"s19": s19, "a2l": a2l, "mac": mac}


def _build_loaded_triple(app: S19TuiApp, triple: dict[str, Path]) -> None:
    """Install the public synthetic triple as the app's ``current_file``.

    Summary:
        Parse the synthetic S19 / A2L / MAC fixture through the same
        load/parse services the real load pipeline uses, attach the result
        as ``current_file`` plus the A2L / MAC state, and flip the empty
        state — the deterministic headless analogue of ``_load_case_01`` in
        ``test_tui_directionb.py``, but rendered from the public generators
        (LLR-007.2) rather than a static ``examples/`` file.

    Args:
        app (S19TuiApp): the running app instance.
        triple (dict[str, Path]): the ``public_triple`` fixture paths.

    Returns:
        None

    Data Flow:
        - ``parse_a2l_file`` / ``S19File`` / ``parse_mac_file`` parse the
          synthetic inputs; ``build_loaded_s19`` fuses them into a
          ``LoadedFile``; ``_apply_empty_state`` reveals the panes.

    Dependencies:
        Uses:
            - ``s19_app.core.S19File``
            - ``s19_app.tui.a2l.parse_a2l_file`` / ``mac.parse_mac_file``
            - ``s19_app.tui.services.load_service.build_loaded_s19``
        Used by:
            - ``_snapshot_run_before``
    """
    from s19_app.core import S19File
    from s19_app.tui.a2l import parse_a2l_file
    from s19_app.tui.mac import parse_mac_file
    from s19_app.tui.services.load_service import build_loaded_s19

    a2l_data = parse_a2l_file(triple["a2l"])
    s19 = S19File(str(triple["s19"]))
    loaded = build_loaded_s19(
        triple["s19"], s19, a2l_path=triple["a2l"], a2l_data=a2l_data
    )
    mac = parse_mac_file(triple["mac"])
    loaded.mac_path = triple["mac"]
    loaded.mac_records = mac.get("records", [])
    loaded.mac_diagnostics = mac.get("diagnostics", [])
    app.current_a2l_path = triple["a2l"]
    app.current_a2l_data = a2l_data
    app.current_file = loaded
    app._apply_empty_state()


def _strip_docstrings(source: str) -> str:
    """Return ``source`` with every docstring node removed.

    Summary:
        AST-parse a function source and drop the leading string-literal
        statement of the module / function bodies, so a no-leak inspection
        scans the executable code only — prose mentioning a word like
        "client" in a docstring is not a false positive.

    Args:
        source (str): the source text of one function (``inspect.getsource``).

    Returns:
        str: the source with docstring statements blanked out.

    Dependencies:
        Used by:
            - ``test_tc016s_snapshot_setup_loads_only_public_fixtures``
    """
    import ast

    tree = ast.parse(source.lstrip())
    docstring_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)
        ):
            doc = ast.get_docstring(node, clean=False)
            if doc is None:
                continue
            body0 = node.body[0]
            start = getattr(body0, "lineno", None)
            end = getattr(body0, "end_lineno", start)
            if start is not None and end is not None:
                docstring_lines.update(range(start, end + 1))
    kept = [
        line
        for idx, line in enumerate(source.lstrip().splitlines(), start=1)
        if idx not in docstring_lines
    ]
    return "\n".join(kept)


def _seed_issues(app: S19TuiApp) -> None:
    """Push a small deterministic set of synthetic validation issues.

    Summary:
        The Issues Report screen needs rows to render a representative
        snapshot. The issues are hand-built ``ValidationIssue`` objects (no
        client data) so the Issues baseline has stable, mixed-severity
        content; this mirrors ``test_tui_directionb.py::_make_issues``.

    Args:
        app (S19TuiApp): the running app with a ``current_file`` installed.

    Returns:
        None

    Dependencies:
        Uses:
            - ``s19_app.validation.model.ValidationIssue`` / ``ValidationSeverity``
        Used by:
            - ``_snapshot_run_before`` (Issues screen only)
    """
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    issues = []
    for i in range(9):
        severity = (
            ValidationSeverity.ERROR if i % 3 == 0 else ValidationSeverity.WARNING
        )
        issues.append(
            ValidationIssue(
                code=f"SNAP_CODE_{i}",
                severity=severity,
                message=f"synthetic issue {i}",
                artifact="mac",
                symbol=f"SNAP_SYM_{i}",
                address=0x0800_0000 + i,
                line_number=i + 1,
            )
        )
    app._validation_issues = issues
    app.validation_issue_filter_mode = "all"
    app._validation_issues_window_start = 0
    app.update_validation_issues_view()


def _snapshot_run_before(
    screen: str,
    density: str,
    triple: dict[str, Path],
):
    """Build the ``run_before`` coroutine for one snapshot cell.

    Summary:
        Return an ``async`` callable that ``pytest-textual-snapshot`` runs
        inside the pilot before capturing the SVG: it installs the public
        synthetic ``LoadedFile``, repaints the per-screen renderers, sets the
        requested density, and navigates the rail to ``screen``. Keeping the
        setup in ``run_before`` (rather than a pre-built app) means every
        baseline is captured from the same deterministic state.

    Args:
        screen (str): rail screen key — one of workspace/a2l/mac/issues/
            map/patch/diff.
        density (str): ``"compact"`` or ``"comfortable"``.
        triple (dict[str, Path]): the ``public_triple`` fixture paths.

    Returns:
        Callable: an ``async`` ``run_before(pilot)`` callable.

    Data Flow:
        - ``_build_loaded_triple`` installs the public ``LoadedFile``.
        - The per-screen ``update_*`` renderers repaint from that snapshot.
        - ``action_cycle_density`` flips the density class if ``compact``.
        - ``action_show_screen`` swaps the rail to the target screen.

    Dependencies:
        Used by:
            - the parametrized ``test_tc016s_*`` snapshot tests
    """

    async def run_before(pilot) -> None:
        app = pilot.app
        _build_loaded_triple(app, triple)
        # Repaint the per-screen renderers from the installed snapshot.
        app.update_sections()
        app.update_hex_view()
        app.update_a2l_view()
        app.update_alt_hex_view()
        app.update_mac_view()
        app.update_mac_hex_view()
        app.update_memory_map()
        if screen == "issues":
            _seed_issues(app)
        # Density default is comfortable; flip once for the compact cell.
        if density == "compact":
            app.action_cycle_density()
        app.action_show_screen(screen)
        await pilot.pause()

    return run_before


# ---------------------------------------------------------------------------
# TC-016-S — the 29-baseline snapshot SVG matrix (LLR-007.1 / LLR-007.2)
# ---------------------------------------------------------------------------

# batch-28 (R-TUI-042, US-038): the A2L Explorer tags table gains a compact
# density polish — `#a2l_tags_pane.density-compact` (tightened pane padding) +
# `DataTable(cell_padding=0)` for compact rows (LLR-042.2). That shifts the
# rendered A2L SVG, so all six `a2l-*` baselines must be regenerated in the
# canonical CI env (.github/workflows/snapshot-regen.yml, pinned textual==8.2.8
# — never locally, per the snapshot-regen-env convention). Until that regen
# lands each A2L cell is an expected mismatch, so they carry
# xfail(strict=False) — the same batch-25/27 xfail-until-baseline pattern; a
# follow-up drops these once the canonical-env baselines are committed.
def _restyled_cell_marks(screen: str) -> tuple:
    """Return the pytest marks for a restyled snapshot cell (none — baselines exist).

    The A2L (batch-28 US-038 compact density), Issues (batch-28 US-039 grouped
    dense view + the batch-29 DataTable retirement / restored `.issue-related`
    node) and Workspace (batch-28 US-040 coverage micro-bar + stat pane + memory
    strip) cells were xfail-until-baseline. Their baselines were regenerated in
    the canonical CI env (snapshot-regen.yml, pinned textual==8.2.8) at
    origin/main `117f6b4` (post batch-29/30) and committed here, so the xfail
    marks are retired — all restyled cells are now full green cells.
    """
    return ()


# batch-31 (fast-dev-flow P1 quick strike) geometry drift: AC-5/AC-7 (B-06
# `#files_list` 1fr + B-20 Load-project button) reshaped the Workspace left
# pane and AC-6 (B-15 `MapCell.render` width-fill) repainted the map grid
# band — 8 grid cells (6 workspace + 2 map) plus the entropy-80x24 backdrop
# cell were xfail-until-baseline. The canonical-CI regen (snapshot-regen.yml,
# pinned textual==8.2.8, run at current main `91d884a` post-#58) recommitted
# exactly those 9 baselines (containment verified in the run log: no other
# screen moved), so the `_BATCH31_GEOMETRY_DRIFT` marks are retired — all
# cells are full green oracles again.
def _batch31_drift_marks(screen: str, density: str, size_key: str) -> tuple:
    """Return the pytest marks for a batch-31 drift cell (none — baselines regenerated)."""
    return ()


# batch-33 (R-B02): the extended `#patch_checks_help` label reflowed the patch
# screen at 120x30; its baseline was regenerated in the canonical CI env
# (snapshot-regen.yml, textual 8.2.8, at main f79834e post-#61 — containment
# verified: exactly that one cell moved) and committed here, so the xfail is
# retired — all cells are full green oracles again.
def _batch33_drift_marks(screen: str, density: str, size_key: str) -> tuple:
    """Return the pytest marks for the batch-33 drift cell (none — baseline regenerated)."""
    return ()


# batch-36 (US-058 / LLR-058.4): the change-set paste group was reparented into
# its own weighted full-width cell (`grid-size: 2 4`, `grid-rows: 1fr 2fr 2fr
# auto`), re-rendering BOTH patch cells. The SVG baselines were regenerated in
# the canonical CI env (snapshot-regen.yml, pinned textual==8.2.8 — never
# locally, per the snapshot-regen-env convention; run 29178366588 moved EXACTLY
# these two cells) and committed HERE, so both patch cells are now full green
# oracles and the xfail is RETIRED (this superseded the batch-35 parked patch
# mark, already retired at 7df60dd via #65).
def _batch36_drift_marks(screen: str, density: str, size_key: str) -> tuple:
    """Return the batch-36 patch drift marks (none — baselines regenerated)."""
    return ()


# batch-38 (US-065 change-doc relabel — title "Change document (JSON)" + rewritten
# `#patch_doc_path_input` placeholder — AND US-067 variant info "?" button): both
# patch cells (80x24 + 120x30) re-rendered. The SVG baselines were regenerated in
# the canonical CI env (snapshot-regen.yml, pinned textual==8.2.8; containment
# check confirmed ONLY the two patch cells moved) and committed, so the batch-38
# xfail-until-baseline marks are retired.
def _batch38_drift_marks(screen: str, density: str, size_key: str) -> tuple:
    """Return the batch-38 patch drift marks (none — baselines regenerated)."""
    return ()


# batch-44 (rail item 8 relabel: "Bookmarks"/U+2736 -> "Flow Builder"/U+2726,
# R-TUI-059 Flow Builder tracer): the activity rail is rendered in EVERY snapshot
# cell, so every tc016s cell (and the tc036s entropy modal, which shows the rail
# behind it) drifted by exactly the rail-8 glyph+label. The SVG baselines were
# regenerated in the canonical CI env (snapshot-regen.yml, pinned textual==8.2.8;
# run 29346071860 at main 1fcdca3 — containment confirmed EXACTLY the 20 rail
# cells moved, 40 insertions / 40 deletions, no other screen) and committed HERE,
# so the batch-44 xfail-until-baseline marks are retired — all cells are full
# green oracles again.
def _batch44_drift_marks(screen: str, density: str, size_key: str) -> tuple:
    """Return the batch-44 rail-relabel drift marks (none — baselines regenerated)."""
    return ()


# batch-45 (R-TUI-060, Memory-Map entropy view swap): the map screen's read-only
# ``sev-*`` validity cell grid is REPLACED by the entropy band view (proportional
# band bar + per-region list + band legend). Only the two ``map`` scaffold cells
# (80x24 + 120x30) drift; no other screen renders the map body. The SVG baselines
# must be regenerated in the canonical CI env (snapshot-regen.yml, pinned
# textual==8.2.8) — NOT locally (local regen drifts unrelated baselines). Until
# then the two map cells are marked ``xfail(strict=False)`` so the suite stays
# green mid-batch; a post-merge follow-up regen retires these marks (mirrors the
# retired ``_batch44_drift_marks`` pattern).
def _batch45_map_drift_marks(screen: str, density: str, size_key: str) -> tuple:
    """Return the batch-45 map entropy-view drift marks (none — baselines regenerated).

    The 2 ``map`` cells drifted when R-TUI-060 replaced the validity grid with the
    entropy band bar + region list + legend. The SVG baselines were regenerated in
    the canonical CI env (snapshot-regen.yml, pinned textual==8.2.8; run 29397319797
    at main 4608953 — containment confirmed exactly the 20 batch-45 cells moved) and
    committed, so the xfail is retired — the map cells are full green oracles again.
    """
    return ()


# batch-45 Inc-5 FOOTER drift: retiring the entropy modal removed the
# FOOTER-VISIBLE `Binding("e", "show_entropy", "Entropy", show=True)`. The Footer
# renders on EVERY screen, so dropping the "e Entropy" key drifts the footer row
# of every cell WIDE ENOUGH to have shown it — the 120x30 and 160x40 widths. At
# the 80x24 floor the footer already truncated "e Entropy", so those cells do NOT
# drift. The `map` cells are already fully xfail'd by `_batch45_map_drift_marks`
# (whole-body band-view drift), so they are excluded here to avoid double-marking.
# The affected cells regenerate in the canonical CI env post-merge (batch-44
# pattern); until then each is xfail(strict=False).
_WIDE_FOOTER_SIZES = frozenset({"120x30", "160x40"})


def _batch45_footer_drift_marks(screen: str, density: str, size_key: str) -> tuple:
    """Return the batch-45 footer-drift marks (none — baselines regenerated).

    Retiring the entropy modal removed the footer-visible ``e``/Entropy binding,
    drifting the footer of every wide (120x30 / 160x40) tc016s cell. The 18 SVG
    baselines were regenerated in the canonical CI env (snapshot-regen.yml, run
    29397319797 at main 4608953 — containment confirmed exactly the 20 batch-45
    cells) and committed, so the xfail is retired — all cells are full green oracles.
    """
    return ()


# batch-46 (R-TUI-063/064, US-U8/US-B2): the Patch Editor 2x2 four-pane grid is
# REPLACED by three responsive bordered windows (PATCH SCRIPT / CHECKS / JSON
# EDIT) laid out 3-across @>=120 and stacked @<120 (the width-narrow reflow).
# Only the two ``patch`` scaffold cells (80x24 + 120x30) drift; no other screen
# renders the patch panel. The SVG baselines must be regenerated in the
# canonical CI env (snapshot-regen.yml, pinned textual==8.2.8) — NOT locally
# (local regen drifts unrelated baselines, per reference_snapshot_regen_env).
# Until then the two patch cells ride ``xfail(strict=False)`` (C-22 upper bound)
# so the suite stays green mid-batch; a post-merge follow-up regen retires these
# marks (mirrors the retired ``_batch44`` / ``_batch45_*`` drift-mark pattern).
def _batch46_patch_drift_marks(screen: str, density: str, size_key: str) -> tuple:
    """Return the batch-46 three-window patch-layout drift marks.

    The two ``patch`` cells (80x24 + 120x30) drift when the 2x2 grid becomes the
    three-window responsive layout. Marked ``xfail(strict=False)`` until the
    canonical-CI baseline regen lands, then retired.
    """
    if screen == "patch" and size_key in ("80x24", "120x30"):
        return (
            pytest.mark.xfail(
                reason=(
                    "batch-46 R-TUI-063/064: patch 2x2 grid -> three-window "
                    "responsive layout; SVG baseline regen pending in "
                    "canonical CI (snapshot-regen.yml)"
                ),
                strict=False,
            ),
        )
    return ()


# batch-47 (R-TUI-066/067, US-WS Workspace MID insight layer): the Workspace
# screen gains pane BORDER TITLES (LLR-066.1), a loader-facts line in `#ws_stats`
# (`Loader N err · ⚠K OOO · Entry 0x…`, LLR-066.4), entropy-banded section rows
# with ✓/cyan-address/human_bytes/entropy-glyph (LLR-066.2), and an
# entropy-banded `#ws_memstrip` with `╱` gap glyphs (LLR-067.1/067.2). All four
# repaint the Workspace body, so every `workspace-*` tc016s cell (both densities
# x 3 sizes = 6 cells) drifts. No other screen renders the Workspace body, so
# containment is Workspace-only — the batch-47 Inc-3 snapshot run showed EXACTLY
# the 6 workspace cells mismatched (no a2l/mac/issues/map/patch/diff/flow cell
# moved → C-28 shared-chrome clean; no footer/header/rail binding change this
# increment). The SVG baselines must be regenerated in the canonical CI env
# (snapshot-regen.yml, pinned textual==8.2.8) — NOT locally (local regen drifts
# unrelated baselines, per reference_snapshot_regen_env). Until the batch-47
# theme+regen follow-up (Inc-7) lands, the 6 workspace cells ride
# xfail(strict=False) (C-22 upper bound); the follow-up regen retires these marks.
def _batch47_workspace_drift_marks(screen: str, density: str, size_key: str) -> tuple:
    """Return the batch-47 Workspace insight-layer drift marks.

    The 6 ``workspace`` cells (both densities x 3 sizes) drift when the Workspace
    gains border titles + loader-facts + entropy section rows + entropy memstrip
    (US-WS, HLR-066/067). Marked ``xfail(strict=False)`` until the canonical-CI
    baseline regen lands (batch-47 Inc-7 theme + regen), then retired.
    """
    if screen == "workspace":
        return (
            pytest.mark.xfail(
                reason=(
                    "batch-47 R-TUI-066/067 US-WS: Workspace border titles + "
                    "loader-facts + entropy section rows + entropy memstrip; SVG "
                    "baseline regen pending in canonical CI (snapshot-regen.yml, "
                    "batch-47 Inc-7 theme+regen follow-up)"
                ),
                strict=False,
            ),
        )
    return ()


# 24 cells: the 4 restyled screens x {compact, comfortable} x {3 sizes}.
_RESTYLED_CELLS = [
    pytest.param(
        screen,
        density,
        size_key,
        id=f"{screen}-{density}-{size_key}",
        marks=_restyled_cell_marks(screen)
        + _batch31_drift_marks(screen, density, size_key)
        + _batch44_drift_marks(screen, density, size_key)
        + _batch45_footer_drift_marks(screen, density, size_key)
        + _batch47_workspace_drift_marks(screen, density, size_key),
    )
    for screen in _RESTYLED_SCREENS
    for density in ("compact", "comfortable")
    for size_key in _SIZES
]

# Additive scaffold cells at the 120x30 primary size, comfortable — PLUS the
# patch screen additionally at the 80x24 floor, to lock the batch-22 US-030
# 2x2 four-pane layout at both the tight floor and the primary width
# (HLR-034.1 / US-031). Real baselines for all four were regenerated in the
# canonical CI env (batch-25, .github/workflows/snapshot-regen.yml, pinned
# textual==8.2.8), so the two patch cells are now full green cells — the prior
# xfail (baseline-regen-pending) is retired. map/diff are 120x30 only.
#
# batch-27 (R-TUI-041, US-035/036/037): the map screen's read-only text list
# becomes a colour-coded minimap grid + detail pane + coverage stats strip, and
# the batch-27 Inc-3 two-regime reflow (LLR-041.10) lays the detail beside the
# grid at 120x30 and stacked below it at 80x24 → BOTH the `map-comfortable-120x30`
# baseline AND a NEW `map-comfortable-80x24` narrow-reflow cell must be locked.
# The map baselines (120x30 primary + the 80x24 narrow-reflow floor) were
# regenerated in the canonical CI env (snapshot-regen.yml) and committed, so the
# batch-27 xfail-until-baseline marks are retired — all scaffold cells are green.
def _scaffold_cell_marks(screen: str, size_key: str) -> tuple:
    """Return the pytest marks for a scaffold snapshot cell (none — baselines exist)."""
    return ()


# The map scaffold, like patch, now carries BOTH the 80x24 floor and the 120x30
# primary — the 80x24 cell locks the batch-27 narrow-regime reflow (LLR-041.10),
# added exactly as batch-22 added the patch 80x24 floor cell (qa M-2).
_TWO_SIZE_SCAFFOLDS = ("patch", "map")


_SCAFFOLD_CELLS = [
    pytest.param(
        screen,
        "comfortable",
        size_key,
        id=f"{screen}-comfortable-{size_key}",
        marks=_scaffold_cell_marks(screen, size_key)
        + _batch31_drift_marks(screen, "comfortable", size_key)
        + _batch33_drift_marks(screen, "comfortable", size_key)
        + _batch36_drift_marks(screen, "comfortable", size_key)
        + _batch38_drift_marks(screen, "comfortable", size_key)
        + _batch44_drift_marks(screen, "comfortable", size_key)
        + _batch45_map_drift_marks(screen, "comfortable", size_key)
        + _batch45_footer_drift_marks(screen, "comfortable", size_key)
        + _batch46_patch_drift_marks(screen, "comfortable", size_key),
    )
    for screen in _SCAFFOLD_SCREENS
    for size_key in (
        ("80x24", "120x30") if screen in _TWO_SIZE_SCAFFOLDS else ("120x30",)
    )
]

# 24 + 5 = 29 baseline cells (batch-27 US-037 adds the map 80x24 reflow cell,
# alongside the batch-22 patch 80x24 floor cell).
_ALL_SNAPSHOT_CELLS = _RESTYLED_CELLS + _SCAFFOLD_CELLS


@pytest.mark.skipif(
    not snapshot_plugin_available,
    reason="pytest-textual-snapshot not installed (dev-only optional extra)",
)
@pytest.mark.snapshot
@pytest.mark.parametrize("screen, density, size_key", _ALL_SNAPSHOT_CELLS)
def test_tc016s_density_layout_snapshot(
    snap_compare,
    public_triple: dict[str, Path],
    tmp_path: Path,
    screen: str,
    density: str,
    size_key: str,
) -> None:
    """Each Direction B screen matches its approved layout baseline (TC-016-S).

    Intent: LLR-007.1 — the SVG baseline is the primary verdict that every
    Direction B screen lays out without overlapping or clipped panes in
    both density modes across the fixed {80x24, 120x30, 160x40} matrix. A
    layout-drift regression (a pane resized, a regime mis-toggled, a token
    re-themed) changes the rendered SVG and fails the cell. LLR-007.2 — the
    app renders only the public synthetic ``conftest.py`` generators; no
    client artifact is opened.

    The 29-cell matrix: the 4 restyled screens carry the full
    {density x size} grid (24 cells); the diff scaffold is pinned at 120x30
    comfortable (1 cell); the patch and map scaffolds each carry 80x24 + 120x30
    to lock, respectively, the batch-22 2x2 four-pane layout and the batch-27
    minimap redesign + narrow-regime reflow at both regimes (4 cells).
    """
    width, height = _SIZES[size_key]
    app = S19TuiApp(base_dir=tmp_path)
    assert snap_compare(
        app,
        terminal_size=(width, height),
        run_before=_snapshot_run_before(screen, density, public_triple),
    )


# TC-321 (batch-36 xfail-set guard) was RETIRED alongside the two patch marks:
# the canonical-CI regen (run 29178366588) committed the two `patch-comfortable-*`
# baselines here, so both cells are now green oracles with no batch-36 xfail to
# guard. The one-batch drift-set assertion has served its purpose.


# ---------------------------------------------------------------------------
# TC-016-S public-fixture sub-case — baselines render public fixtures only
#                                    (LLR-007.2 / S-2)
# ---------------------------------------------------------------------------


def test_tc016s_snapshot_setup_loads_only_public_fixtures(
    public_triple: dict[str, Path],
) -> None:
    """The snapshot setup loads only public synthetic fixtures (LLR-007.2).

    Intent: S-2 — a committed SVG baseline embeds the rendered screen
    content. Every baseline must trace to a public synthetic fixture so no
    proprietary client byte / address / symbol is ever committed. This test
    asserts (a) the snapshot fixture source is the ``conftest.py``
    generators, (b) those generators wrote their output under a pytest temp
    directory (never a client path), and (c) the snapshot ``run_before``
    setup code references no static ``examples/`` artifact and no client
    directory — its only data source is the generator-built triple.
    """
    # (a) The recorded fixture sources are exactly the conftest generators.
    assert set(_PUBLIC_FIXTURE_SOURCES) == {
        "make_large_s19",
        "make_large_a2l",
        "make_large_mac",
    }, "snapshot fixture source must be the conftest.py public generators"
    for name, generator in _PUBLIC_FIXTURE_SOURCES.items():
        assert generator.__module__ in ("conftest", "tests.conftest"), (
            f"{name} must be the conftest.py generator (got module "
            f"{generator.__module__})"
        )

    # (b) Every triple file is a synthetic, generator-written file living in
    # a pytest temp directory — never a client artifact path.
    for kind, path in public_triple.items():
        assert path.exists(), f"public {kind} fixture must have been generated"
        parts = {p.lower() for p in path.parts}
        assert "snapshot_public" in parts or "pytest" in " ".join(parts).lower(), (
            f"public {kind} fixture must live in a pytest temp dir, got {path}"
        )

    # (c) The snapshot setup helpers reference no non-public path. The
    # check is over the executable code only — docstrings are stripped so a
    # word like "client" in explanatory prose is not a false positive — and
    # looks for actual path-like tokens (a non-public examples sub-directory
    # or an absolute filesystem path), not bare words.
    setup_code = "\n".join(
        _strip_docstrings(inspect.getsource(fn))
        for fn in (_build_loaded_triple, _snapshot_run_before, _seed_issues)
    )
    for forbidden in (
        "professional_validation",
        "case_01_basic_valid",
        "case_02_",
        "case_03_",
        "case_04_",
        "case_05_",
        "case_06_",
        "C:\\",
        "/home/",
    ):
        assert forbidden not in setup_code, (
            f"snapshot setup code must not reference a non-public path "
            f"({forbidden!r} found)"
        )
    assert _EXAMPLES_PUBLIC.name == "case_00_public", (
        "the only recorded examples source is the public case_00_public dir"
    )


# ---------------------------------------------------------------------------
# TC-016 / CV-04 — 119/120-column breakpoint boundary check
#                  (LLR-007.1 — needs no snapshot library)
# ---------------------------------------------------------------------------


def test_cv04_breakpoint_boundary_119_proportional_120_fixed(
    tmp_path: Path,
) -> None:
    """The width regime flips exactly at the 119/120-column breakpoint (CV-04).

    Intent: LLR-007.1 fixes a 120-column breakpoint between the proportional
    (``< 120``) and fixed (``>= 120``) width regimes. The other layout tests
    exercise the proportional regime only at 80x24, so a width-responsive
    bug right at the boundary would slip through. This check pins the
    boundary itself: at terminal width 119 the proportional ``width-narrow``
    regime must be in effect, and at width 120 the fixed regime must be in
    effect. It is a plain ``run_test()`` assertion and needs no snapshot
    library — it runs on every environment regardless of the ``snapshot``
    marker.
    """

    async def _regime_at(width: int) -> bool:
        """Return whether the ``width-narrow`` (proportional) regime is set."""
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(width, 30)) as pilot:
            await pilot.pause()
            body = app.query_one("#workspace_body")
            return body.has_class("width-narrow")

    narrow_at_119 = asyncio.run(_regime_at(119))
    narrow_at_120 = asyncio.run(_regime_at(120))

    assert narrow_at_119, (
        "at terminal width 119 (< 120) the proportional regime must be "
        "active — #workspace_body must carry width-narrow"
    )
    assert not narrow_at_120, (
        "at terminal width 120 (>= 120) the fixed regime must be active — "
        "#workspace_body must NOT carry width-narrow"
    )


def test_cv04_breakpoint_boundary_on_live_resize(tmp_path: Path) -> None:
    """A live resize across 119<->120 flips the regime in both directions (CV-04).

    Intent: LLR-007.1 — the breakpoint is driven by ``on_resize`` /
    ``_apply_width_regime``. Beyond pinning the static regime per width
    (the test above), this exercises the dynamic path: resizing one running
    app down across the breakpoint must set ``width-narrow`` and resizing
    back up must clear it, so the regime tracks the live terminal width and
    is not frozen at the mount-time size.
    """

    async def _drive() -> tuple[bool, bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            body = app.query_one("#workspace_body")
            at_120 = body.has_class("width-narrow")
            # Resize down across the breakpoint to 119 columns.
            await pilot.resize_terminal(119, 30)
            await pilot.pause()
            at_119 = body.has_class("width-narrow")
            # Resize back up to 120 columns.
            await pilot.resize_terminal(120, 30)
            await pilot.pause()
            back_at_120 = body.has_class("width-narrow")
            return at_120, at_119, back_at_120

    at_120, at_119, back_at_120 = asyncio.run(_drive())
    assert not at_120, "at width 120 the fixed regime must be active"
    assert at_119, (
        "resizing down to width 119 must activate the proportional regime"
    )
    assert not back_at_120, (
        "resizing back up to width 120 must restore the fixed regime"
    )
