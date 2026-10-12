"""Batch-92 Inc-A — import census over the hexview move (HLR-001 / HLR-002).

Coverage map:

- TC-651 — ``test_tc651_import_census_all_consumers_read_render_hexview``:
  AST-walk import census over ``s19_app/`` DERIVED FROM THE LIVE TREE at run
  time, asserting set-equality against the declared measured consumer set
  (LLR-001.4; review F-QA-2 — radiography-vs-code drift fails the test), the
  retired path absent from disk and from every import, the tui-free render
  rule (zero ``s19_app.tui.*`` imports under ``render/``), zero service-layer
  hits at a ``tui`` hexview address, and the 8 measured old-address TEST
  importers (3 forms) now reading ``s19_app.render.hexview``.
- TC-652 — ``test_tc652_wrapper_absence_and_renderer_surface``: the 3
  ``range_index`` re-export wrappers are absent from ``s19_app.render.hexview``
  and from the ``s19_app.tui`` import surface and ``__all__`` (LLR-002.1 /
  LLR-002.2), the 12-name renderer surface is re-exported 12/12 (closure
  finding N2), and ``app.py`` sources the primitives from the engine
  (LLR-002.3).

Negative controls (executed RED arms are recorded in the increment packet):
restoring one consumer at the old address reddens TC-651; re-adding a wrapper
shim to ``s19_app.tui`` reddens TC-652.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pytest

import s19_app
import s19_app.render.hexview as render_hexview
import s19_app.tui as tui

PRODUCT_ROOT = Path(s19_app.__file__).resolve().parent
TESTS_ROOT = Path(__file__).resolve().parent

HEXVIEW_MODULE = "s19_app.render.hexview"
RETIRED_MODULE = "s19_app.tui.hexview"

#: Declared measured consumer set (LLR-001.4; module-map §5 F-2 — authoritative).
MEASURED_CONSUMERS = {
    "s19_app.tui.app",
    "s19_app.tui",  # tui/__init__.py
    "s19_app.tui.screens",
    "s19_app.tui.screens_directionb",
    "s19_app.tui.services.load_service",
    "s19_app.tui.services.report_service",
    "s19_app.tui.services.diff_report_service",
}

#: The 8 measured old-address TEST importers (LLR-001.4 negative control,
#: LED-…92.7), by module stem.
MEASURED_TEST_IMPORTERS = {
    "test_report_service",
    "test_tui_diff_screen",
    "test_tui_goto_marker",
    "test_tui_hexview",
    "test_tui_hexview_classed",
    "test_tui_operations_view",
    "test_tui_directionb",
    "test_tui_search_pagination",
}

WRAPPER_NAMES = (
    "address_in_sorted_ranges",
    "build_sorted_range_index",
    "range_in_sorted_ranges",
)

#: The 12-name surviving renderer re-export surface (closure finding N2).
RENDERER_SURFACE = (
    "FOCUS_CONTEXT_ROWS",
    "HEX_WIDTH",
    "MAX_HEX_BYTES",
    "MAX_HEX_ROWS",
    "SEARCH_ENCODING",
    "build_mem_map_s19",
    "build_range_validity_hex",
    "build_range_validity_s19",
    "build_row_bases",
    "find_string_in_mem",
    "render_hex_view",
    "render_hex_view_text",
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


def _census(root: Path, package_of, module_of) -> Dict[str, Set[str]]:
    """AST import census: resolved module -> set of importing modules."""
    found: Dict[str, Set[str]] = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        owner_module = module_of(path)
        owner_package = package_of(path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits: Set[str] = set()
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


def _product_package_of(path: Path) -> str:
    rel = path.relative_to(PRODUCT_ROOT)
    return ".".join(["s19_app"] + list(rel.parts[:-1]))


def _product_module_of(path: Path) -> str:
    rel = path.relative_to(PRODUCT_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(["s19_app"] + parts)


def _tests_package_of(path: Path) -> str:
    return path.stem


def _tests_module_of(path: Path) -> str:
    return path.stem


# ---------------------------------------------------------------------------
# TC-651 — import census: every consumer reads s19_app.render.hexview
# ---------------------------------------------------------------------------


def test_tc651_import_census_all_consumers_read_render_hexview() -> None:
    """TC-651 — live-tree AST census over s19_app/ (LLR-001.4, F-QA-2)."""
    census = _census(PRODUCT_ROOT, _product_package_of, _product_module_of)

    importers = census.get(HEXVIEW_MODULE, set())
    assert importers == MEASURED_CONSUMERS, (
        f"hexview importer set drifted from the measured set: "
        f"extra={sorted(importers - MEASURED_CONSUMERS)} "
        f"missing={sorted(MEASURED_CONSUMERS - importers)}"
    )

    # The retired path: absent from every import in the product tree...
    assert RETIRED_MODULE not in census, (
        f"{RETIRED_MODULE} still imported by {sorted(census[RETIRED_MODULE])}"
    )
    # ...absent from every import in the test tree...
    test_census = _census(TESTS_ROOT, _tests_package_of, _tests_module_of)
    assert RETIRED_MODULE not in test_census, (
        f"{RETIRED_MODULE} still imported by tests: "
        f"{sorted(test_census[RETIRED_MODULE])}"
    )
    # ...and absent from disk (LLR-001.1 existence probe).
    assert not (PRODUCT_ROOT / "tui" / "hexview.py").exists(), (
        "s19_app/tui/hexview.py must be deleted by Inc-A"
    )

    # Tui-free render rule (PDR #D3): render/* carries zero s19_app.tui.* edges.
    render_pkg = PRODUCT_ROOT / "render"
    for path in sorted(render_pkg.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                resolved = _resolve_import_from(node, "s19_app.render")
                assert not resolved.startswith("s19_app.tui"), (
                    f"{path.name} imports {resolved} — render/ must be tui-free"
                )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("s19_app.tui"), (
                        f"{path.name} imports {alias.name} — render/ must be tui-free"
                    )

    # Service-layer grep census: 0 hexview hits at a tui address (LLR-001.4).
    services_dir = PRODUCT_ROOT / "tui" / "services"
    for path in sorted(services_dir.glob("*.py")):
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if "hexview" in line and "render.hexview" not in line:
                # Docstring mentions of the renderer name are fine; import lines are not.
                stripped = line.strip()
                assert not stripped.startswith(("import ", "from ")), (
                    f"{path.name}:{lineno} imports hexview at a non-render address: {line}"
                )

    # The 8 measured old-address TEST importers now read the new address.
    # Two of the three forms address the module itself (form 1
    # ``from s19_app.render.hexview import ...``, form 2
    # ``import s19_app.render.hexview as ...``); form 3
    # (``from s19_app.render import hexview``) resolves to the package.
    new_importers = test_census.get(HEXVIEW_MODULE, set()) | test_census.get(
        "s19_app.render", set()
    )
    # test_report_service.py carries the fourth, source-census STRING form
    # (LLR-001.4: it asserts the service's import text) — no AST import.
    report_test_source = (TESTS_ROOT / "test_report_service.py").read_text(
        encoding="utf-8"
    )
    string_form_repointed = (
        '"from ...render.hexview import" in source' in report_test_source
        and '"from ..hexview import"' not in report_test_source
    )
    missing = (MEASURED_TEST_IMPORTERS - {"test_report_service"}) - new_importers
    assert not missing, (
        f"measured test importers not reading {HEXVIEW_MODULE}: {sorted(missing)}"
    )
    assert string_form_repointed, (
        "test_report_service.py source-census string not repointed to the new address"
    )

    # The 3 import forms are all exercised across the 8 files (LED-…92.7).
    forms = {"from_render_hexview": 0, "import_render_hexview_as": 0, "from_render_pkg": 0}
    for path in sorted(TESTS_ROOT.glob("test_*.py")):
        if path.stem not in MEASURED_TEST_IMPORTERS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == HEXVIEW_MODULE:
                    forms["from_render_hexview"] += 1
                elif node.module == "s19_app.render" and any(
                    alias.name == "hexview" for alias in node.names
                ):
                    forms["from_render_pkg"] += 1
            elif isinstance(node, ast.Import):
                if any(alias.name == HEXVIEW_MODULE for alias in node.names):
                    forms["import_render_hexview_as"] += 1
    assert all(count >= 1 for count in forms.values()), (
        f"not all 3 test import forms present in the measured set: {forms}"
    )


# ---------------------------------------------------------------------------
# TC-652 — wrapper absence; renderer surface; app.py engine sourcing
# ---------------------------------------------------------------------------


def test_tc652_wrapper_absence_and_renderer_surface() -> None:
    """AT-289 — black-box node: the 3 wrapper names are not importable from s19_app.tui,
    absent from tui.__all__, and still live at s19_app.range_index (V-5 re-point, LED-…92.14)."""
    """TC-652 — wrappers gone from the render module and the tui namespace."""
    # LLR-002.1: wrappers absent from the moved module.
    for name in WRAPPER_NAMES:
        assert not hasattr(render_hexview, name), (
            f"s19_app.render.hexview must not define {name}"
        )
    import inspect

    source = inspect.getsource(render_hexview)
    for name in WRAPPER_NAMES:
        assert f"def {name}" not in source

    # LLR-002.2: wrappers absent from the tui import surface and __all__.
    for name in WRAPPER_NAMES:
        assert not hasattr(tui, name), f"s19_app.tui must not expose {name}"
        assert name not in tui.__all__, f"{name} must be dropped from tui.__all__"

    # ...and not importable from s19_app.tui (positive-absence probes).
    for name in WRAPPER_NAMES:
        with pytest.raises(ImportError):
            importlib.import_module(f"s19_app.tui.{name}")

    # The 12-name renderer surface is re-exported 12/12, sourced from render.
    for name in RENDERER_SURFACE:
        assert hasattr(tui, name), f"s19_app.tui lost renderer name {name}"
        assert name in tui.__all__, f"{name} missing from tui.__all__"
        assert getattr(tui, name) is getattr(render_hexview, name), (
            f"tui.{name} must be the identical object from s19_app.render.hexview"
        )

    # LLR-002.3: app.py sources the primitives from the engine and the
    # renderer from render.hexview — no edge to any tui hexview address.
    app_path = PRODUCT_ROOT / "tui" / "app.py"
    tree = ast.parse(app_path.read_text(encoding="utf-8"), filename=str(app_path))
    edges: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            edges.add(_resolve_import_from(node, "s19_app.tui"))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                edges.add(alias.name)
    assert "s19_app.range_index" in edges, (
        "app.py must import the range primitives from the engine"
    )
    assert HEXVIEW_MODULE in edges, (
        "app.py must import the renderer from s19_app.render.hexview"
    )
    assert not any(edge.endswith(RETIRED_MODULE) for edge in edges), (
        f"app.py still carries a tui hexview edge: {sorted(edges)}"
    )
    # The two engine primitives land in app.py's namespace.
    import s19_app.tui.app as app_module

    from s19_app.range_index import (
        address_in_sorted_ranges as engine_addr,
        build_sorted_range_index as engine_build,
    )

    assert app_module.address_in_sorted_ranges is engine_addr
    assert app_module.build_sorted_range_index is engine_build
