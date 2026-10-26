"""Batch-92 Inc-B — import census over the safe_text and format moves.

Coverage map:

- TC-653 — ``test_tc653_safe_text_import_census`` (LLR-003.1 / LLR-003.3):
  AST-walk census over ``s19_app/`` + ``tests/`` DERIVED FROM THE LIVE TREE at
  run time — ``safe_text`` / ``_CONTROL_SCRUB`` are defined exactly once (at
  ``s19_app.utils``, the byte-preserving move verified in the increment
  packet), the measured consumer set imports the ``safe_text`` name from
  ``s19_app.utils``, NO module imports it from the retired
  ``s19_app.tui.screens_directionb`` address, and the 3 measured old-address
  TEST importers now read ``s19_app.utils``.
- TC-654 — ``test_tc654_format_census_and_shim_identity`` (LLR-004.2 /
  LLR-004.3): no ``s19_app/tui/services/*`` module imports
  ``s19_app.tui.insight_style`` (the service-layer importer set is EMPTY —
  set-equality, so a consumer added after the radiography fails the test,
  review F-QA-2), every ``s19_app.render.format`` importer is in the declared
  measured set, ``validation_service`` sources ``GREEN``/``LABEL``/``VALUE``/
  ``microbar`` from ``render.format``, the 8 ``insight_style`` re-exports are
  the IDENTICAL objects (never copies), the moved values are pinned at the new
  address, and the retained palette/helpers stay canonical in ``insight_style``.

Negative controls (executed RED arms are recorded in the increment-002
packet): flipping one ``safe_text`` consumer back to ``screens_directionb``
reddens TC-653; re-adding a ``tui/services/* → insight_style`` edge reddens
TC-654; replacing the shim with literal copies reddens the ``is``-identity
assertion.
"""

from __future__ import annotations

import ast
from pathlib import Path

import s19_app
import s19_app.render.format as render_format
import s19_app.tui.insight_style as insight_style

PRODUCT_ROOT = Path(s19_app.__file__).resolve().parent
TESTS_ROOT = Path(__file__).resolve().parent

SCREENS_MODULE = "s19_app.tui.screens_directionb"
UTILS_MODULE = "s19_app.utils"
FORMAT_MODULE = "s19_app.render.format"
INSIGHT_MODULE = "s19_app.tui.insight_style"
SERVICES_DIR = PRODUCT_ROOT / "tui" / "services"

#: Declared measured safe_text consumer set (LLR-003.3; module-map §5 F-2 —
#: the real set also includes screens_directionb's internal call sites, which
#: become its own import at the new address). batch-94 (Inc-002, the Flow
#: Builder/Execution panels in ``flow_screens.py``) imports the NAME at its
#: module top (the C-17 fold — every file-derived string renders through
#: ``safe_text``); measured in, per the census's own contract. batch-99
#: (Inc-6, LLR-160.2, the Split/Join view rendering raw segment names and
#: refusal messages in ``segment_split_view.py``) imports the NAME at its
#: module top; measured in.
MEASURED_SAFE_TEXT_CONSUMERS = {
    "s19_app.tui.app",
    "s19_app.tui.checks_view",
    "s19_app.tui.flow_screens",
    "s19_app.tui.issues_view",
    "s19_app.tui.screens_directionb",
    "s19_app.tui.segment_split_view",
}

#: The 3 measured old-address TEST importers of safe_text (P2 code lens),
#: repointed to s19_app.utils by Inc-B. batch-94 (Inc-001, the ce_a Check
#: Editor) adds ``test_tui_check_editor`` — the new collector's own battery
#: drives hostile labels through the same escaper (the C-17 fold); measured
#: in, per the census's own contract.
MEASURED_SAFE_TEXT_TEST_IMPORTERS = {
    "test_a2l_multiline_headers",
    "test_tui_check_editor",
    "test_tui_directionb",
    "test_tui_hostile_map",
}

#: Declared measured render.format importer set (LLR-004.3; module-map R4):
#: the moved renderer's constant block, the declared insight_style shim, and
#: the repointed validation_service. Nobody else.
MEASURED_FORMAT_CONSUMERS = {
    "s19_app.render.hexview",
    "s19_app.tui.insight_style",
    "s19_app.tui.services.validation_service",
}

#: The 8 symbols whose canonical ownership moved to render/format and which
#: insight_style re-exports as the identical objects (LLR-004.2).
SHIM_SYMBOLS = (
    "CYAN",
    "DGRAY",
    "GREEN",
    "LABEL",
    "MICROBAR_EMPTY",
    "MICROBAR_FILLED",
    "VALUE",
    "microbar",
)

#: The retained palette + helpers that stay canonical in insight_style
#: (LLR-004.2: YELLOW/RED/HILITE/LBLUE/PURPLE/MAGENTA, DEPTH_*, human_bytes,
#: label_value, threshold_style, cap_gauge_style).
RETAINED_SYMBOLS = (
    "YELLOW",
    "RED",
    "HILITE",
    "LBLUE",
    "PURPLE",
    "MAGENTA",
    "DEPTH_BG",
    "DEPTH_PANEL",
    "DEPTH_ODD_ROW",
    "DEPTH_BORDER",
    "human_bytes",
    "label_value",
    "threshold_style",
    "cap_gauge_style",
)


def _resolve_import_from(node: ast.ImportFrom, owner_package: str) -> str:
    """Resolve an ImportFrom to a dotted absolute module (level-aware)."""
    if node.level == 0:
        return node.module or ""
    package_parts = owner_package.split(".") if owner_package else []
    # A file module's package is its directory; an __init__'s is itself.
    keep = len(package_parts) - (node.level - 1)
    base = package_parts[:keep] if keep > 0 else []
    if node.module:
        base += node.module.split(".")
    return ".".join(base)


def _census(root: Path, package_of, module_of) -> dict:
    """AST import census: resolved module -> set of importing modules."""
    found: dict = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        owner_module = module_of(path)
        owner_package = package_of(path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                resolved = _resolve_import_from(node, owner_package)
                if resolved:
                    hits.add(resolved)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    hits.add(alias.name)
        for mod in hits:
            found.setdefault(mod, set()).add(owner_module)
    return found


def _census_names(root: Path, package_of, module_of) -> dict:
    """AST import census keyed by imported NAME: (module, name) -> importers."""
    found: dict = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        owner_module = module_of(path)
        owner_package = package_of(path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                resolved = _resolve_import_from(node, owner_package)
                for alias in node.names:
                    found.setdefault((resolved, alias.name), set()).add(owner_module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    found.setdefault((alias.name, ""), set()).add(owner_module)
    return found


def _product_package_of(path: Path) -> str:
    rel = path.relative_to(PRODUCT_ROOT)
    return ".".join(["s19_app"] + list(rel.parts[:-1]))


def _product_module_of(path: Path) -> str:
    rel = path.relative_to(PRODUCT_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(["s19_app"] + parts)


def _tests_module_of(path: Path) -> str:
    return path.stem


# ---------------------------------------------------------------------------
# TC-653 — safe_text lives only at s19_app.utils; consumers repointed
# ---------------------------------------------------------------------------


def test_tc653_safe_text_import_census() -> None:
    """TC-653 — live-tree AST census over the safe_text move (LLR-003.1/003.3)."""
    # LLR-003.1: exactly one definition site per symbol in the product tree,
    # and it is s19_app/utils.py.
    def_sites: dict = {}
    scrub_sites: dict = {}
    for path in sorted(PRODUCT_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        module = _product_module_of(path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "safe_text"
            ):
                def_sites.setdefault(module, []).append(node.lineno)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "_CONTROL_SCRUB":
                        scrub_sites.setdefault(module, []).append(node.lineno)
    assert sorted(def_sites) == [UTILS_MODULE], (
        f"safe_text must be defined only at {UTILS_MODULE}, found: {def_sites}"
    )
    assert sorted(scrub_sites) == [UTILS_MODULE], (
        f"_CONTROL_SCRUB must be defined only at {UTILS_MODULE}, found: {scrub_sites}"
    )

    # LLR-003.3: the measured consumer set imports the NAME safe_text from
    # s19_app.utils — set-equality, drift in either direction fails.
    names = _census_names(PRODUCT_ROOT, _product_package_of, _product_module_of)
    importers = names.get((UTILS_MODULE, "safe_text"), set())
    assert importers == MEASURED_SAFE_TEXT_CONSUMERS, (
        f"safe_text importer set drifted from the measured set: "
        f"extra={sorted(importers - MEASURED_SAFE_TEXT_CONSUMERS)} "
        f"missing={sorted(MEASURED_SAFE_TEXT_CONSUMERS - importers)}"
    )

    # ...and NO module imports safe_text from the retired screens address
    # (zero view imports of screens_directionb.safe_text).
    old = names.get((SCREENS_MODULE, "safe_text"), set())
    assert not old, (
        f"safe_text still imported from {SCREENS_MODULE} by {sorted(old)}"
    )

    # screens_directionb references safe_text only as its own import (the
    # ~80 internal call sites became consumer references).
    screens_path = PRODUCT_ROOT / "tui" / "screens_directionb.py"
    screens_src = screens_path.read_text(encoding="utf-8")
    assert "def safe_text" not in screens_src, (
        "screens_directionb must no longer define safe_text"
    )
    assert "_CONTROL_SCRUB" not in screens_src, (
        "screens_directionb must no longer define _CONTROL_SCRUB"
    )
    assert "from ..utils import safe_text" in screens_src

    # Tests-side: the 3 measured old-address test importers read s19_app.utils
    # now; no test imports safe_text from the screens module anymore.
    test_names = _census_names(TESTS_ROOT, _tests_module_of, _tests_module_of)
    test_importers = test_names.get((UTILS_MODULE, "safe_text"), set())
    assert test_importers == MEASURED_SAFE_TEXT_TEST_IMPORTERS, (
        f"test safe_text importers drifted: "
        f"extra={sorted(test_importers - MEASURED_SAFE_TEXT_TEST_IMPORTERS)} "
        f"missing={sorted(MEASURED_SAFE_TEXT_TEST_IMPORTERS - test_importers)}"
    )
    old_tests = test_names.get((SCREENS_MODULE, "safe_text"), set())
    assert not old_tests, (
        f"tests still import safe_text from {SCREENS_MODULE}: {sorted(old_tests)}"
    )


# ---------------------------------------------------------------------------
# TC-654 — service-layer census dead; validation_service repointed; shim identity
# ---------------------------------------------------------------------------


def test_tc654_format_census_and_shim_identity() -> None:
    """TC-654 — render.format census + the 8-symbol shim identity (LLR-004.2/004.3)."""
    census = _census(PRODUCT_ROOT, _product_package_of, _product_module_of)

    # LLR-004.3: the service-layer insight_style importer set is EMPTY — a
    # service consuming the presentation module via the shim fails by
    # set-equality (declared measured set, F-QA-2).
    services_importers = {
        mod
        for mod in census.get(INSIGHT_MODULE, set())
        if mod.startswith("s19_app.tui.services")
    }
    assert services_importers == set(), (
        f"tui/services/* must not import {INSIGHT_MODULE}: "
        f"{sorted(services_importers)}"
    )

    # ...and every render.format importer is in the declared measured set.
    format_importers = census.get(FORMAT_MODULE, set())
    assert format_importers == MEASURED_FORMAT_CONSUMERS, (
        f"render.format importer set drifted from the measured set: "
        f"extra={sorted(format_importers - MEASURED_FORMAT_CONSUMERS)} "
        f"missing={sorted(MEASURED_FORMAT_CONSUMERS - format_importers)}"
    )

    # validation_service sources the 4 symbols from render.format (AST edge +
    # name check, LLR-004.3).
    vs_path = SERVICES_DIR / "validation_service.py"
    vs_tree = ast.parse(vs_path.read_text(encoding="utf-8"), filename=str(vs_path))
    hits = []
    for node in ast.walk(vs_tree):
        if isinstance(node, ast.ImportFrom):
            resolved = _resolve_import_from(node, "s19_app.tui.services")
            if resolved == FORMAT_MODULE:
                hits.append({alias.name for alias in node.names})
    assert any({"GREEN", "LABEL", "VALUE", "microbar"} <= h for h in hits), (
        f"validation_service must import GREEN, LABEL, VALUE, microbar from "
        f"{FORMAT_MODULE}; found edges: {hits}"
    )

    # LLR-004.2: the shim re-exports the IDENTICAL objects (8/8) — a shim that
    # redefines rather than re-imports (copying a constant or re-defining the
    # function) fails the `is` assertion, and microbar's source is gone from
    # insight_style (it is not DEFINED there anymore).
    for name in SHIM_SYMBOLS:
        assert getattr(insight_style, name) is getattr(render_format, name), (
            f"insight_style.{name} must be the identical object from "
            f"{FORMAT_MODULE} (re-export shim, never a copy)"
        )
    insight_src = (PRODUCT_ROOT / "tui" / "insight_style.py").read_text(
        encoding="utf-8"
    )
    assert "def microbar" not in insight_src, (
        "insight_style must re-export microbar, not define it"
    )

    # Value pins at the new address (HLR-004 numeric pass threshold).
    assert render_format.MICROBAR_FILLED == "█"
    assert render_format.MICROBAR_EMPTY == "░"
    assert render_format.GREEN == "#54efae"
    assert render_format.LABEL == "#c5c7d2"
    assert render_format.VALUE == "#e9e9e9"
    assert render_format.CYAN == "#7dd3fc"
    assert render_format.DGRAY == "#969aad"
    assert render_format.microbar(0.5, 8).plain.count("█") == 4
    assert render_format.microbar(1.0, 0).plain == ""

    # The retained palette/helpers stay canonical in insight_style (LLR-004.2).
    for name in RETAINED_SYMBOLS:
        assert hasattr(insight_style, name), (
            f"insight_style lost retained symbol {name}"
        )
    assert insight_style.threshold_style(10.0, 50.0, 80.0) == insight_style.GREEN
    assert insight_style.cap_gauge_style(100.0, 75.0, 100.0) == (
        f"bold {insight_style.MAGENTA}"
    )
