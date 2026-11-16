"""Test-support helper for the modularized ``s19_app/tui`` packages.

Summary:
    ``s19_app/tui/app.py`` and ``s19_app/tui/screens_directionb.py`` were
    split into the packages ``s19_app/tui/app/`` and
    ``s19_app/tui/screens_directionb/`` (batch-modular).  Dozens of tests
    still read the OLD single-file source as text or AST.  This module gives
    the adapting workers one shared vocabulary (hazards.md H-12):

    - ``package_modules`` — parse every ``.py`` of a package SEPARATELY
      (never concatenated for AST work), each package with its file floor.
    - ``merged_class`` — one synthetic ClassDef whose body is the core class
      body followed by every in-package base-class body in header/MRO order
      (MERGED-CLASS), with its method/class floors and a per-node
      source-file attribute.
    - ``package_text`` — concatenated file text, for regex/substring use ONLY.
    - ``package_tree`` — one synthetic Module over the separately parsed
      bodies, for READ-PACKAGE walks.

    Pure functions, stdlib only, no ``s19_app`` import: everything is read
    from files on disk relative to this file (repo root = ``parents[2]``).
"""
from __future__ import annotations

import ast
import inspect
import textwrap
from pathlib import Path

#: Repository root, two levels above ``tests/support/package_source.py``.
_REPO_ROOT = Path(__file__).resolve().parents[2]

#: The two packages this helper reads.
_PACKAGES = ("app", "screens_directionb")

#: Minimum number of ``.py`` files per package (H-12 floors), counted
#: recursively. ``screens_directionb`` is 8 top-level files plus the 9 files
#: of its ``patch_editor/`` subpackage (the P3a split of ``patch_editor.py``).
_MIN_FILES = {"app": 23, "screens_directionb": 17}

#: Floor for :func:`mro_class_tree` on ``PatchEditorPanel``: the thin panel
#: class plus its six zone mixins.
MIN_PATCH_EDITOR_CLASSES = 7

#: MERGED-CLASS floors: minimum FunctionDef/AsyncFunctionDef in the merged
#: body, and minimum contributing classes (S19TuiApp + its 18 mixins).
_MIN_MERGED_METHODS = 374
_MIN_CONTRIBUTING_CLASSES = 19

#: Attribute set on every AST node produced here, naming its source file.
_SOURCE_FILE_ATTR = "_package_source_file"


def _resolve_root(root: Path | None) -> Path:
    """The repository root to read from: ``root`` or this file's repo."""
    return _REPO_ROOT if root is None else root


def tui_dir(root: Path | None = None) -> Path:
    """Summary: the ``s19_app/tui`` directory of ``root``, asserted to exist.

    Args:
        root: repository root to read from; defaults to the repo containing
            this file.

    Returns:
        Path: ``<root>/s19_app/tui``.

    Raises:
        AssertionError: the directory does not exist.
    """
    path = _resolve_root(root) / "s19_app" / "tui"
    if not path.is_dir():
        raise AssertionError(f"tui directory missing: {path}")
    return path


def package_modules(pkg: str, root: Path | None = None) -> list[tuple[Path, ast.Module]]:
    """Summary: parse every ``.py`` of ``s19_app/tui/<pkg>/`` separately.

    Subpackages are read too (recursive), so a class moved from a module into
    a nested package stays in the scan.

    Args:
        pkg: one of ``"app"`` or ``"screens_directionb"``.
        root: repository root to read from; defaults to the repo containing
            this file.

    Returns:
        list[tuple[Path, ast.Module]]: ``(file path, parsed module)`` pairs
        sorted by path relative to the package.  Each module is parsed on its own — files are
        never concatenated before ``ast.parse``.

    Raises:
        AssertionError: unknown package, too few files, or (for ``"app"``)
            ``core.py`` missing.
    """
    if pkg not in _PACKAGES:
        raise AssertionError(f"unknown package {pkg!r}; expected one of {_PACKAGES}")
    pkg_dir = tui_dir(root) / pkg
    files = sorted(
        (p for p in pkg_dir.rglob("*.py") if "__pycache__" not in p.parts),
        key=lambda path: path.relative_to(pkg_dir).as_posix(),
    )
    if len(files) < _MIN_FILES[pkg]:
        raise AssertionError(
            f"package {pkg!r} has {len(files)} .py files; "
            f"expected at least {_MIN_FILES[pkg]}"
        )
    if pkg == "app" and not (pkg_dir / "core.py").is_file():
        raise AssertionError(f"package 'app' is missing core.py in {pkg_dir}")
    modules = []
    for path in files:
        mod = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        _annotate_source(mod, path)
        modules.append((path, mod))
    return modules


def _annotate_source(mod: ast.Module, path: Path) -> ast.Module:
    """Stamp every node of ``mod`` with its source-file attribute; return it."""
    for node in ast.walk(mod):
        setattr(node, _SOURCE_FILE_ATTR, path)
    return mod


def source_file_of(node: ast.AST) -> Path:
    """Summary: the file an AST node produced by this helper came from.

    Args:
        node: a node from ``package_modules``, ``merged_class`` or
            ``package_tree``.

    Returns:
        Path: the ``.py`` file that held ``node``.

    Raises:
        AssertionError: ``node`` carries no source-file attribute (it was not
            produced by this helper).
    """
    path = getattr(node, _SOURCE_FILE_ATTR, None)
    if path is None:
        raise AssertionError(
            f"AST node {type(node).__name__} has no {_SOURCE_FILE_ATTR}; "
            "it was not produced by package_source"
        )
    return path


def _package_classes(
    modules: list[tuple[Path, ast.Module]],
) -> dict[str, tuple[Path, ast.ClassDef]]:
    """Map every app-package class name to its ``(file, ClassDef)`` pair."""
    classes = {}
    for path, mod in modules:
        for node in mod.body:
            if isinstance(node, ast.ClassDef):
                classes[node.name] = (path, node)
    return classes


def _merged_body(
    name: str, core: ast.ClassDef, classes: dict[str, tuple[Path, ast.ClassDef]]
) -> tuple[list[ast.stmt], list[str]]:
    """The core class body followed by each in-package base body (MRO order)."""
    body = list(core.body)
    contributors = [name]
    for base in core.bases:
        if isinstance(base, ast.Name) and base.id in classes:
            body.extend(classes[base.id][1].body)
            contributors.append(base.id)
    return body, contributors


def merged_class(name: str = "S19TuiApp", root: Path | None = None) -> ast.ClassDef:
    """Summary: one synthetic ClassDef over ``name`` and its in-package bases.

    Args:
        name: the app-package class to merge; ``"S19TuiApp"`` by default.
        root: repository root to read from; defaults to this file's repo.

    Returns:
        ast.ClassDef: a new class whose ``body`` is the body of ``name``
        (from ``core.py``) followed by every in-package base body, in
        header/MRO order.  Body nodes keep their original ``lineno`` and the
        source-file attribute read by :func:`source_file_of`; the class also
        exposes ``_source_files`` and ``_contributing_classes``.

    Raises:
        AssertionError: ``name`` absent, or a MERGED-CLASS floor fails.
    """
    modules = package_modules("app", root=root)
    classes = _package_classes(modules)
    if name not in classes:
        raise AssertionError(f"class {name!r} not found in the app package")
    _core_path, core = classes[name]
    body, contributors = _merged_body(name, core, classes)
    method_count = sum(
        1 for node in body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    if method_count < _MIN_MERGED_METHODS:
        raise AssertionError(
            f"merged {name} body has {method_count} methods; "
            f"expected at least {_MIN_MERGED_METHODS}"
        )
    if len(contributors) < _MIN_CONTRIBUTING_CLASSES:
        raise AssertionError(
            f"merged {name} draws from {len(contributors)} classes; "
            f"expected at least {_MIN_CONTRIBUTING_CLASSES}"
        )
    merged = ast.ClassDef(
        name=name,
        bases=list(core.bases),
        keywords=list(core.keywords),
        body=body,
        decorator_list=list(core.decorator_list),
    )
    merged.lineno = core.lineno
    merged.col_offset = core.col_offset
    merged.end_lineno = getattr(core, "end_lineno", None)
    merged.end_col_offset = getattr(core, "end_col_offset", None)
    merged._source_files = {id(node): node._package_source_file for node in body}
    merged._contributing_classes = contributors
    return merged


def package_text(pkg: str, root: Path | None = None) -> str:
    """Summary: concatenated text of a package, for regex/substring use ONLY.

    Args:
        pkg: one of ``"app"`` or ``"screens_directionb"``.
        root: repository root to read from; defaults to the repo containing
            this file.

    Returns:
        str: the files' text in name order; every file is preceded by a
        ``# --- <repo-relative path> ---`` line so a scan can name its file.

    Raises:
        AssertionError: forwarded from :func:`package_modules` (floor).
    """
    base = _resolve_root(root)
    parts: list[str] = []
    for path, _ in package_modules(pkg, root=root):
        rel = path.relative_to(base).as_posix()
        parts.append(f"# --- {rel} ---\n")
        parts.append(path.read_text(encoding="utf-8"))
    return "".join(parts)


def package_tree(pkg: str, root: Path | None = None) -> ast.Module:
    """Summary: one synthetic Module over a package's separately parsed bodies.

    Args:
        pkg: one of ``"app"`` or ``"screens_directionb"``.
        root: repository root to read from; defaults to the repo containing
            this file.

    Returns:
        ast.Module: a new module whose ``body`` is the concatenation of the
        separately parsed bodies (READ-PACKAGE walks); each node keeps its
        source-file attribute.

    Raises:
        AssertionError: forwarded from :func:`package_modules` (floor).
    """
    body: list[ast.stmt] = []
    for _, mod in package_modules(pkg, root=root):
        body.extend(mod.body)
    return ast.Module(body=body, type_ignores=[])


def mro_class_tree(
    cls: type, module_prefix: str, min_classes: int
) -> ast.Module:
    """Summary: one synthetic Module over the source of a class and its mixins.

    ``inspect.getsource(cls)`` returns only the class body written in its own
    file; once a class is split into zone mixins, a whole-class scan must read
    every in-package class of its MRO.

    Args:
        cls: the class to read, e.g. ``PatchEditorPanel``.
        module_prefix: only MRO classes whose ``__module__`` starts with this
            are read (the in-package mixins; never Textual or stdlib bases).
        min_classes: floor on how many classes contribute, so a scan cannot
            quietly shrink back to the thin core class.

    Returns:
        ast.Module: a new module whose ``body`` is one ``ClassDef`` per
        contributing class, in MRO order.

    Raises:
        AssertionError: fewer than ``min_classes`` classes matched.
    """
    body: list[ast.stmt] = []
    for klass in cls.__mro__:
        if klass.__module__.startswith(module_prefix):
            body.extend(ast.parse(textwrap.dedent(inspect.getsource(klass))).body)
    if len(body) < min_classes:
        raise AssertionError(
            f"{cls.__name__} MRO has {len(body)} classes under "
            f"{module_prefix!r}; expected at least {min_classes}"
        )
    return ast.Module(body=body, type_ignores=[])
