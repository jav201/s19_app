"""Permanent law for the ``deps`` test seam of the modularized TUI packages.

Why this file exists (batch-modular, E5 review finding F2):
    ``s19_app/tui/app/`` and ``s19_app/tui/screens_directionb/`` each carry a
    ``deps.py`` module.  The names tests monkeypatch (the "D1 names": ``os``,
    ``parse_a2l_file``, ``compare_images``, ...) are bound there, and every
    product call goes through ``deps.<name>(...)``.  So

        monkeypatch.setattr(app_module.deps, "parse_a2l_file", fake)

    reaches the product.  Two things silently break that, and before this
    file nothing in the suite noticed either:

    - **Product bypass.**  A package module that writes
      ``from ..services.x import parse_a2l_file`` and calls it bare never
      reads ``deps``; every test that patches ``deps.parse_a2l_file`` then
      patches something the product does not call.
    - **Wrong patch target.**  ``app/__init__.py`` still re-exports every D1
      name (the pre-split import surface), so the pre-split idiom
      ``monkeypatch.setattr(app_module, "parse_a2l_file", fake)`` still
      *succeeds* - it rebinds the re-export, which no product code reads.  A
      failure-injection test written that way passes green without ever
      exercising the failure.

The seam set of a package is derived from the code, never listed by hand: the
names ``N`` read as ``deps.N`` by the package's own modules (``deps.py``
excluded).  That keeps the law correct as the seam grows, and the floors below
keep an empty derivation from passing vacuously.

Known approximations (documented, not hidden):
    - Only bare READS of a seam name are flagged, not imports on their own
      (see ``_product_violations``).
    - Bare-load shadowing honours function parameters and names assigned,
      looped over, bound by ``with ... as`` / ``except ... as``, or defined in
      an enclosing function or module scope.  Comprehension variables count as
      bindings of the enclosing scope; ``global``/``nonlocal`` and ``match``
      captures are not modelled.  Annotations are not scanned.
    - Test-side aliases of a package root are recognised in the forms
      ``import s19_app.tui.app as X``, ``from s19_app.tui import app as X``
      and ``X = importlib.import_module("s19_app.tui.app")`` (same for
      ``screens_directionb``), plus the unaliased dotted path.  An alias passed
      through a helper function, or re-bound by assignment from another alias,
      is not followed.
    - ``open`` is deliberately outside the seam set: hazard H-18 patches
      ``deps.open`` (creating the attribute) while product code reads the
      builtin, and no ``deps.open`` load exists, so the derivation never sees
      it.  Nothing here constrains it.
"""
from __future__ import annotations

import ast
from pathlib import Path

from tests.support.package_source import package_modules

_TESTS_DIR = Path(__file__).resolve().parent
_THIS_FILE = Path(__file__).resolve()

#: Package -> dotted import path of its root module.
_ROOTS = {
    "app": "s19_app.tui.app",
    "screens_directionb": "s19_app.tui.screens_directionb",
}

#: Floors for the derived seam sets: an empty or truncated derivation (for
#: example a rename of the ``deps`` alias) must fail, not pass vacuously.
_MIN_SEAM = {"app": 35, "screens_directionb": 1}

#: Floors for the test-side scan: test modules scanned, and how many of them
#: bind an alias of a package root.
_MIN_TEST_FILES = 100
_MIN_ALIAS_MODULES = 15

_PATCH_FUNCS = {"setattr", "delattr"}


def _seam_names(modules: list[tuple[Path, ast.Module]]) -> set[str]:
    """Names ``N`` read as ``deps.N`` by the package modules except ``deps.py``."""
    names: set[str] = set()
    for path, mod in modules:
        if path.name == "deps.py":
            continue
        for node in ast.walk(mod):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "deps"
            ):
                names.add(node.attr)
    return names


def _scope_bindings(scope: ast.AST) -> set[str]:
    """Names bound directly in ``scope`` (not in nested function/class bodies).

    Imports are deliberately NOT bindings: an import of a seam name is a
    violation in its own right and must not hide the later bare use.
    """
    bound: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        args = scope.args
        for arg in args.posonlyargs + args.args + args.kwonlyargs:
            bound.add(arg.arg)
        for arg in (args.vararg, args.kwarg):
            if arg is not None:
                bound.add(arg.arg)
    stack = list(scope.body if not isinstance(scope, ast.Lambda) else [scope.body])
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        stack.extend(ast.iter_child_nodes(node))
    return bound


class _BareLoads(ast.NodeVisitor):
    """Collect bare ``Name`` loads of seam names that no scope shadows."""

    def __init__(self, seam: set[str]) -> None:
        self.seam = seam
        self.scopes: list[tuple[str, set[str]]] = []
        self.found: list[tuple[int, str]] = []

    def _shadowed(self, name: str) -> bool:
        for index in range(len(self.scopes) - 1, -1, -1):
            kind, bound = self.scopes[index]
            if kind == "class" and index != len(self.scopes) - 1:
                continue
            if name in bound:
                return True
        return False

    def visit_Module(self, node: ast.Module) -> None:
        self.scopes.append(("module", _scope_bindings(node)))
        self.generic_visit(node)
        self.scopes.pop()

    def _visit_function(self, node) -> None:
        for expr in node.decorator_list:
            self.visit(expr)
        for expr in node.args.defaults + [d for d in node.args.kw_defaults if d]:
            self.visit(expr)
        self.scopes.append(("function", _scope_bindings(node)))
        for stmt in node.body:
            self.visit(stmt)
        self.scopes.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expr in node.decorator_list + node.bases:
            self.visit(expr)
        self.scopes.append(("class", _scope_bindings(node)))
        for stmt in node.body:
            self.visit(stmt)
        self.scopes.pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.scopes.append(("function", _scope_bindings(node)))
        self.visit(node.body)
        self.scopes.pop()

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.target)
        if node.value is not None:
            self.visit(node.value)

    def visit_Name(self, node: ast.Name) -> None:
        if (
            isinstance(node.ctx, ast.Load)
            and node.id in self.seam
            and not self._shadowed(node.id)
        ):
            self.found.append((node.lineno, node.id))


def _product_violations(rel: str, source: str, seam: set[str]) -> list[str]:
    """Seam bypasses in one package module's source: unshadowed bare loads.

    An import of a seam name is not flagged by itself: four app modules keep
    ``ListItem`` (annotation-only) and ``file_load.py`` keeps ``os`` (unused)
    as dead imports from the move, and neither is read.  What bypasses the
    seam is READING the name bare; an import that is then called, or ``import
    os`` followed by ``os.path...``, is caught here because imports do not
    shadow.
    """
    tree = ast.parse(source, filename=rel)
    visitor = _BareLoads(seam)
    visitor.visit(tree)
    return [
        f"{rel}:{lineno}: bare load of seam name {name!r}"
        for lineno, name in visitor.found
    ]


def _dotted(expr: ast.AST) -> str | None:
    """``a.b.c`` for a Name/Attribute chain, else ``None``."""
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if not isinstance(expr, ast.Name):
        return None
    parts.append(expr.id)
    return ".".join(reversed(parts))


def _root_aliases(tree: ast.AST) -> dict[str, str]:
    """Names bound in a test module to a package root: ``name -> package``."""
    by_path = {path: pkg for pkg, path in _ROOTS.items()}
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.name in by_path:
                    aliases[alias.asname] = by_path[alias.name]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            for alias in node.names:
                full = f"{node.module}.{alias.name}"
                if full in by_path:
                    aliases[alias.asname or alias.name] = by_path[full]
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and (_dotted(node.value.func) or "").split(".")[-1] == "import_module"
            and node.value.args
            and isinstance(node.value.args[0], ast.Constant)
            and node.value.args[0].value in by_path
        ):
            aliases[node.targets[0].id] = by_path[node.value.args[0].value]
    return aliases


def _root_of(expr: ast.AST, aliases: dict[str, str]) -> str | None:
    """The package an expression denotes the root module of, else ``None``."""
    dotted = _dotted(expr)
    if dotted is None:
        return None
    if dotted in aliases:
        return aliases[dotted]
    for pkg, path in _ROOTS.items():
        if dotted == path:
            return pkg
    return None


def _string_target(text: str, seam_by_pkg: dict[str, set[str]]) -> str | None:
    """The seam name a ``"s19_app.tui.<pkg>.<name>"`` string patch targets."""
    for pkg, path in _ROOTS.items():
        prefix = path + "."
        if text.startswith(prefix) and text[len(prefix):] in seam_by_pkg[pkg]:
            return text[len(prefix):]
    return None


def _test_violations(
    rel: str, source: str, seam_by_pkg: dict[str, set[str]]
) -> list[str]:
    """Patches of a seam name on a package root in one test module's source."""
    tree = ast.parse(source, filename=rel)
    aliases = _root_aliases(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args:
            dotted = _dotted(node.func) or ""
            last = dotted.split(".")[-1]
            is_object = dotted.endswith("patch.object")
            is_string_patch = last in _PATCH_FUNCS or dotted.endswith("patch")
            first = node.args[0]
            if (last in _PATCH_FUNCS or is_object) and len(node.args) >= 2:
                pkg = _root_of(first, aliases)
                name = node.args[1]
                if (
                    pkg is not None
                    and isinstance(name, ast.Constant)
                    and name.value in seam_by_pkg[pkg]
                ):
                    found.append(
                        f"{rel}:{node.lineno}: patches seam name {name.value!r} "
                        f"on the {pkg} package root; patch it on the .deps module"
                    )
            if (
                is_string_patch
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
            ):
                hit = _string_target(first.value, seam_by_pkg)
                if hit is not None:
                    found.append(
                        f"{rel}:{node.lineno}: string target {first.value!r} "
                        f"patches seam name {hit!r} on a package root"
                    )
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute):
                    pkg = _root_of(target.value, aliases)
                    if pkg is not None and target.attr in seam_by_pkg[pkg]:
                        found.append(
                            f"{rel}:{node.lineno}: assigns seam name "
                            f"{target.attr!r} on the {pkg} package root"
                        )
    return found


def _real_seams() -> dict[str, set[str]]:
    return {pkg: _seam_names(package_modules(pkg)) for pkg in _ROOTS}


def test_seam_sets_are_derived_and_not_vacuous() -> None:
    """The seam set is read from the code; an empty one would make both laws
    below pass for the wrong reason."""
    seams = _real_seams()
    for pkg, names in seams.items():
        assert len(names) >= _MIN_SEAM[pkg], (pkg, len(names), sorted(names))
    assert "compare_images" in seams["app"], sorted(seams["app"])
    assert "_json_clock" in seams["screens_directionb"], seams["screens_directionb"]


def test_product_modules_reach_seam_names_only_through_deps() -> None:
    """Every product call of a seam name reads ``deps.<name>``.  A bare call
    or a private import would leave ``monkeypatch.setattr(<pkg>.deps, ...)``
    patching something the product never calls."""
    seams = _real_seams()
    violations: list[str] = []
    for pkg in _ROOTS:
        for path, _mod in package_modules(pkg):
            if path.name in ("deps.py", "__init__.py"):
                continue
            rel = f"s19_app/tui/{pkg}/{path.name}"
            violations.extend(
                _product_violations(rel, path.read_text(encoding="utf-8"), seams[pkg])
            )
    assert violations == [], "\n".join(violations)


def test_tests_never_patch_seam_names_on_a_package_root() -> None:
    """No test rebinds a seam name on ``s19_app.tui.app`` /
    ``s19_app.tui.screens_directionb``: the package root re-exports the name
    for import compatibility only, so such a patch succeeds and does nothing.
    Patch ``<pkg>.deps`` instead."""
    seams = _real_seams()
    files = sorted(p for p in _TESTS_DIR.rglob("*.py") if p.resolve() != _THIS_FILE)
    assert len(files) >= _MIN_TEST_FILES, len(files)
    violations: list[str] = []
    alias_modules = 0
    for path in files:
        source = path.read_text(encoding="utf-8")
        rel = path.relative_to(_TESTS_DIR.parent).as_posix()
        if _root_aliases(ast.parse(source, filename=rel)):
            alias_modules += 1
        violations.extend(_test_violations(rel, source, seams))
    assert alias_modules >= _MIN_ALIAS_MODULES, alias_modules
    assert violations == [], "\n".join(violations)


_SEAM = {"parse_a2l_file", "os"}


def test_control_bare_seam_call_is_flagged() -> None:
    """A module that imports a seam name and calls it bare is flagged, and so
    is a bare use with no import; ``deps.X`` and a shadowing parameter are not."""
    src = "\n".join(
        [
            "from ..a2l_parse import parse_a2l_file",
            "from . import deps",
            "def bad(p):",
            "    return parse_a2l_file(p)",
            "def bare_os(p):",
            "    return os.path.join(p)",
            "def good(p):",
            "    return deps.parse_a2l_file(p), deps.os.sep",
            "def shadowed(os):",
            "    return os.sep",
            "",
        ]
    )
    found = _product_violations("s19_app/tui/app/x.py", src, _SEAM)
    assert len(found) == 2, found
    assert any(":4:" in v and "bare load" in v for v in found), found
    assert any(":6:" in v and "'os'" in v for v in found), found


def test_control_import_alone_is_not_flagged_but_its_use_is() -> None:
    """A dead or annotation-only import is harmless; the same import read bare
    is the bypass."""
    dead = "import os\ndef f(item: os.PathLike) -> None:\n    return None\n"
    assert _product_violations("s19_app/tui/app/x.py", dead, _SEAM) == []
    used = "import os\ndef f(p):\n    return os.path.join(p)\n"
    found = _product_violations("s19_app/tui/app/x.py", used, _SEAM)
    assert len(found) == 1 and ":3:" in found[0], found


def test_control_patching_the_package_root_is_flagged() -> None:
    """Every spelling of 'patch a seam name on the package root' is flagged;
    patching ``app_module.deps`` and a non-seam name are not."""
    seams = {"app": _SEAM, "screens_directionb": {"_json_clock"}}
    src = "\n".join(
        [
            "import importlib",
            "import s19_app.tui.app as app_module",
            "from s19_app.tui import screens_directionb as sdb",
            "viaimp = importlib.import_module('s19_app.tui.app')",
            "def t(monkeypatch):",
            "    monkeypatch.setattr(app_module, 'parse_a2l_file', 1)",
            "    monkeypatch.setattr(sdb, '_json_clock', 1)",
            "    monkeypatch.setattr(viaimp, 'os', 1)",
            "    monkeypatch.setattr('s19_app.tui.app.parse_a2l_file', 1)",
            "    app_module.os = 1",
            "    monkeypatch.setattr(app_module.deps, 'parse_a2l_file', 1)",
            "    monkeypatch.setattr('s19_app.tui.app.deps.parse_a2l_file', 1)",
            "    monkeypatch.setattr(app_module, 'S19TuiApp', 1)",
            "",
        ]
    )
    found = _test_violations("tests/test_x.py", src, seams)
    assert len(found) == 5, found
    assert sorted(int(v.split(":")[1]) for v in found) == [6, 7, 8, 9, 10], found
