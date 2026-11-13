"""Guard for ``tests/support/package_source.py`` (batch-modular H-12).

The helper is the shared vocabulary the four source-reading-test workers rely
on (MERGED-CLASS, READ-PACKAGE, PATH-KEY).  These tests encode WHY it must
fail loudly when the modularized package shape changes:

- the file floors hold on the real tree (app >= 23 files with ``core.py``,
  screens_directionb >= 9 files);
- ``merged_class`` fuses the core body and the mixin bodies, so a method from
  ``core.py`` (``compose``) and a method from a mixin (``_land_focus``) sit in
  one body and each resolves back to its own file;
- a too-small synthetic package (one mixin removed, root override) trips the
  floor instead of silently reading a thinner tree.
"""
from __future__ import annotations

import ast
import shutil
from pathlib import Path

import pytest

from tests.support import package_source as ps


def test_tui_dir_resolves_and_exists() -> None:
    path = ps.tui_dir()
    assert path.is_dir()
    assert path.name == "tui"
    assert path.parent.name == "s19_app"


def test_package_modules_floors_hold_on_the_real_tree() -> None:
    app = ps.package_modules("app")
    assert len(app) >= 23
    assert any(path.name == "core.py" for path, _ in app)
    names = [path.name for path, _ in app]
    assert names == sorted(names)
    assert all(isinstance(mod, ast.Module) for _, mod in app)

    sdb = ps.package_modules("screens_directionb")
    assert len(sdb) >= 9
    assert all(isinstance(mod, ast.Module) for _, mod in sdb)


def test_merged_class_contains_core_and_mixin_methods() -> None:
    merged = ps.merged_class()
    methods = {
        node.name: node
        for node in merged.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "compose" in methods, "core-pinned method missing from merged body"
    assert "_land_focus" in methods, "mixin method missing from merged body"
    assert ps.source_file_of(methods["compose"]).name == "core.py"
    assert ps.source_file_of(methods["_land_focus"]).name == "navigation.py"


def test_merged_class_meets_its_floors() -> None:
    merged = ps.merged_class()
    method_count = sum(
        1
        for node in merged.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    assert method_count >= 374
    assert len(merged._contributing_classes) >= 19


def test_package_text_marks_every_file() -> None:
    text = ps.package_text("app")
    assert "# --- s19_app/tui/app/core.py ---" in text
    assert "# --- s19_app/tui/app/navigation.py ---" in text
    assert "# --- s19_app/tui/app/shell.py ---" in text


def test_package_tree_walks_all_files() -> None:
    tree = ps.package_tree("screens_directionb")
    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    assert {"MemoryMapPanel", "PatchEditorPanel", "AbDiffPanel"} <= classes
    # every body node still resolves back to its own file
    panel = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "AbDiffPanel"
    )
    assert ps.source_file_of(panel).name == "ab_diff.py"


def test_too_small_package_trips_the_floor(tmp_path: Path) -> None:
    src = ps.tui_dir() / "app"
    dst = tmp_path / "s19_app" / "tui" / "app"
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)
    (dst / "shell.py").unlink()
    with pytest.raises(AssertionError, match="core.py|expected at least 23"):
        ps.package_modules("app", root=tmp_path)


def test_unknown_package_is_refused() -> None:
    with pytest.raises(AssertionError, match="unknown package"):
        ps.package_modules("no_such_pkg")
