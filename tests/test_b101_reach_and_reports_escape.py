"""Batch-101 Inc 12 - every dialog and action reachable; Escape closes Reports (group G-T1).

Written by the independent tester (E4) from the approved design only
(``inc-12/01-requirements.md``, ``02-test-cases.md``, ``E1-slice.md``,
``E1-rulings.md``, ``E3-rulings.md``, ``E3-security.md`` and
``codewire/graph-inc12.md``). No line of the Inc 12 implementation was read.

Requirements observed (the case id is in each node's docstring):

- R-DLG.14 - every dialog (a ``ModalScreen`` subclass) has an opener inside a
  reached function (a static census over ``ast``);
- R-SHELL-KEYS.3 - every ``action_<name>`` method has a reach: an exact action
  string in a binding, a palette entry, a literal ``run_action`` argument or an
  ``@click=`` link, a toolkit binding on a toolkit base class, or a call or
  reference from a reached function (I-5 of the graph);
- R-DLG.2 and R-DLG.15 - Escape closes the Reports dialog from every focus
  place as Close does, an open dropdown list closing first and choosing
  nothing (the Reports filter dropdown and the Edit block gating dropdown);
- AT-I12-1 and AT-I12-2 - the same, through the keys, and the rail keys and
  the Issues peek once the three view aliases are gone.

The censuses read the source with ``ast``; they import the toolkit (``textual``)
only for its class bindings. They spell no removed name (I-3 of the graph): a
restored dead dialog or action is the census's own failure, shown here by
synthetic mutants of the same shapes, each cited by its case id. Driven nodes
use the shipped keys, buttons and dialogs, read what is painted or written to
disk, and wait through ``settled`` for the action's own sign. Windows are
switched with the keys or ``action_show_screen``. ``LOCALAPPDATA`` is isolated
by ``tests/conftest.py``; no node touches the OS clipboard.
"""
from __future__ import annotations

import ast
import asyncio
import importlib
import inspect
import re
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pytest
from textual.widgets import Input, Select, TextArea

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.issues_view import IssueRow  # noqa: E402
from s19_app.tui.screens import FlowBlockEditScreen, ReportViewerScreen  # noqa: E402
from s19_app.tui.services import folder_open_service as fos  # noqa: E402
from s19_app.tui.window_help import WindowHelpScreen  # noqa: E402
from tests.b97_fixtures import (  # noqa: E402
    fx_project,
    load_project,
    make_project,
    open_flow_builder,
)
from tests.b97_probes import record_statuses, settle, settled  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402

SIZE = (118, 54)
SEED = 20260001
SIZE_MB = 1.0
#: A key whose effect the app must show quickly; a missing effect fails with
#: the state in the message instead of after the shared 60 s bound.
CLOSE_WAIT_S = 10.0
LOAD_WAIT_S = 60.0

# --------------------------------------------------------------------------- #
# The static census (I-5 of codewire/graph-inc12.md)
# --------------------------------------------------------------------------- #

#: Methods the toolkit runs by their name.
_TOOLKIT_PREFIXES = ("on_", "_on_", "watch_", "validate_", "compute_", "key_")
_TOOLKIT_NAMES = frozenset({"compose", "render", "check_action", "render_line"})
_TOOLKIT_MODULES = (
    "textual.widgets",
    "textual.app",
    "textual.screen",
    "textual.widget",
    "textual.containers",
    "textual.scroll_view",
    "textual.dom",
)
_ACTION_STRING = re.compile(r"(?:(?:app|screen)\.)?([A-Za-z_]\w*)(?:\(.*\))?", re.S)
_CLICK_LINK = re.compile(r"@click=[\"']?((?:app\.|screen\.)?[A-Za-z_]\w*)")


@dataclass
class _Func:
    module: str
    cls: Optional[str]
    name: str
    node: ast.AST
    refs: Set[str] = field(default_factory=set)
    ctors: Set[str] = field(default_factory=set)

    @property
    def label(self) -> str:
        return f"{self.cls}.{self.name}" if self.cls else self.name


@dataclass
class Census:
    dialogs: Set[str]
    dialogs_without_opener: List[str]
    actions: Dict[str, Set[str]]  # "Class.action_x" -> reasons: string, toolkit, reached
    actions_without_reach: List[str]

    def reasons(self, label: str) -> Set[str]:
        return self.actions[label]


def _text_of(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value if isinstance(part, ast.Constant) else "\x00" for part in node.values
        )
    return None


def _action_of(node: Optional[ast.AST]) -> Optional[str]:
    """The action name of an action string, or None when the node is not one."""
    text = _text_of(node) if node is not None else None
    if text is None:
        return None
    match = _ACTION_STRING.fullmatch(text.strip())
    return match.group(1) if match else None


def _callee(call: ast.Call) -> Optional[str]:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _base_names(cls: ast.ClassDef) -> List[str]:
    names = []
    for base in cls.bases:
        target = base.value if isinstance(base, ast.Subscript) else base
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, ast.Attribute):
            names.append(target.attr)
    return names


def _assigned_name(stmt: ast.AST) -> Optional[str]:
    if isinstance(stmt, ast.Assign):
        targets = stmt.targets
    elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        targets = [stmt.target]
    else:
        return None
    for target in targets:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
    return None


@lru_cache(maxsize=None)
def _toolkit_class(name: str):
    for module_name in _TOOLKIT_MODULES:
        found = getattr(importlib.import_module(module_name), name, None)
        if inspect.isclass(found):
            return found
    return None


@lru_cache(maxsize=None)
def _toolkit_binding_actions(name: str) -> frozenset:
    """The simple action names the toolkit class ``name`` binds (own and inherited)."""
    cls = _toolkit_class(name)
    if cls is None:
        return frozenset()
    found = set()
    for klass in cls.__mro__:
        for binding in klass.__dict__.get("BINDINGS", ()):
            action = getattr(binding, "action", None)
            if action is None and isinstance(binding, (tuple, list)) and len(binding) > 1:
                action = binding[1]
            if isinstance(action, str):
                match = _ACTION_STRING.fullmatch(action.strip())
                if match:
                    found.add(match.group(1))
    return frozenset(found)


def _docstring_ids(tree: ast.AST) -> Set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr):
                value = body[0].value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    ids.add(id(value))
    return ids


def _action_strings(tree: ast.AST) -> Set[str]:
    """Every action string of the four positions in one module (never message text)."""
    found: Set[str] = set()
    docstrings = _docstring_ids(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = _callee(node)
            args = node.args
            keywords = {k.arg: k.value for k in node.keywords}
            if callee in ("Binding", "PaletteEntry"):  # a binding / a palette entry
                value = args[1] if len(args) > 1 else keywords.get("action")
                found.add(_action_of(value))
            elif callee == "run_action" and args:  # a literal run_action argument
                found.add(_action_of(args[0]))
        owner = _assigned_name(node)
        if owner == "BINDINGS" or (owner or "").endswith("PALETTE_ENTRIES"):
            for sub in ast.walk(node):  # tuple forms: (key, action, ...) / (label, action)
                if isinstance(sub, (ast.Tuple, ast.List)) and len(sub.elts) >= 2:
                    if _text_of(sub.elts[0]) is not None:
                        found.add(_action_of(sub.elts[1]))
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:  # an @click= link target
                for match in _CLICK_LINK.finditer(node.value):
                    found.add(match.group(1).split(".")[-1])
    found.discard(None)
    return found


def _collect(tree: ast.Module, module: str, funcs: List[_Func], classes: Dict[str, ast.ClassDef],
             scope_nodes: List[ast.AST]) -> None:
    """Outermost functions (a nested closure folds into its owner) and scope code."""

    def block(body, cls_name: Optional[str]) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.append(_Func(module, cls_name, stmt.name, stmt))
            elif isinstance(stmt, ast.ClassDef):
                classes[stmt.name] = stmt
                scope_nodes.extend(stmt.decorator_list)
                block(stmt.body, stmt.name)
            else:
                scope_nodes.append(stmt)
                if isinstance(stmt, ast.If):
                    block(stmt.body + stmt.orelse, cls_name)
                elif isinstance(stmt, ast.Try):
                    block(stmt.body + stmt.orelse + stmt.finalbody, cls_name)

    block(tree.body, None)


def _names_in(node: ast.AST) -> Tuple[Set[str], Set[str]]:
    refs: Set[str] = set()
    ctors: Set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
            refs.add(sub.id)
        elif isinstance(sub, ast.Attribute) and isinstance(sub.ctx, ast.Load):
            refs.add(sub.attr)
        if isinstance(sub, ast.Call):
            callee = _callee(sub)
            if callee:
                ctors.add(callee)
    return refs, ctors


def _is_toolkit_dispatched(func: _Func) -> bool:
    name = func.name
    if name in _TOOLKIT_NAMES or name.startswith(_TOOLKIT_PREFIXES):
        return True
    if name.startswith("__") and name.endswith("__"):
        return True
    for decorator in getattr(func.node, "decorator_list", ()):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if (isinstance(target, ast.Name) and target.id == "on") or (
            isinstance(target, ast.Attribute) and target.attr == "on"
        ):
            return True
    return False


def census_sources(sources: Dict[str, str]) -> Census:
    """The dialog and action census of ``sources`` ({module path: source text})."""
    funcs: List[_Func] = []
    classes: Dict[str, ast.ClassDef] = {}
    strings: Set[str] = set()
    scope_nodes: List[ast.AST] = []
    for module, text in sorted(sources.items()):
        tree = ast.parse(text)
        strings |= _action_strings(tree)
        _collect(tree, module, funcs, classes, scope_nodes)
    for func in funcs:
        func.refs, func.ctors = _names_in(func.node)
    scope = _Func("<scope>", None, "<scope>", ast.Module(body=scope_nodes, type_ignores=[]))
    scope.refs, scope.ctors = _names_in(scope.node)

    # toolkit arm: the toolkit ancestors of each local class
    def ancestors(name: str, seen: Optional[Set[str]] = None) -> Tuple[Set[str], Set[str]]:
        seen = seen if seen is not None else set()
        local, toolkit = set(), set()
        if name in seen:
            return local, toolkit
        seen.add(name)
        for base in _base_names(classes[name]) if name in classes else ():
            if base in classes:
                local.add(base)
                more_local, more_toolkit = ancestors(base, seen)
                local |= more_local
                toolkit |= more_toolkit
            else:
                toolkit.add(base)
        return local, toolkit

    # reach fixpoint over the reached functions
    by_name: Dict[str, List[_Func]] = {}
    for func in funcs:
        by_name.setdefault(func.name, []).append(func)
    reasons: Dict[int, Set[str]] = {}
    for func in funcs:
        if func.cls and func.name.startswith("action_"):
            action = func.name[len("action_"):]
            found: Set[str] = set()
            if action in strings:
                found.add("string")
            _local, toolkit = ancestors(func.cls)
            if any(action in _toolkit_binding_actions(base) for base in toolkit):
                found.add("toolkit")
            if found:
                reasons[id(func)] = found
    reached: Set[int] = set()
    queue: List[_Func] = [scope]
    for func in funcs:
        if id(func) in reasons or _is_toolkit_dispatched(func):
            queue.append(func)
    reached |= {id(f) for f in queue}
    while queue:
        current = queue.pop()
        for name in current.refs:
            for target in by_name.get(name, ()):
                if id(target) not in reached:
                    reached.add(id(target))
                    if target.name.startswith("action_"):
                        reasons.setdefault(id(target), set()).add("reached")
                    queue.append(target)

    actions: Dict[str, Set[str]] = {}
    for func in funcs:
        if func.cls and func.name.startswith("action_"):
            actions[func.label] = set(reasons.get(id(func), set()))

    # dialogs: ModalScreen subclasses; an opener is a construction (of it or of a
    # subclass) inside a reached function outside the dialog's own body
    dialogs: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, node in classes.items():
            if name not in dialogs and ("ModalScreen" in _base_names(node) or set(_base_names(node)) & dialogs):
                dialogs.add(name)
                changed = True
    without = []
    for dialog in sorted(dialogs):
        family = {dialog} | {n for n in dialogs if dialog in ancestors(n)[0]}
        opened = any(
            (f is scope or id(f) in reached) and f.cls != dialog and f.ctors & family
            for f in [scope, *funcs]
        )
        if not opened:
            without.append(dialog)
    return Census(
        dialogs=dialogs,
        dialogs_without_opener=without,
        actions=actions,
        actions_without_reach=sorted(label for label, why in actions.items() if not why),
    )


def _read_tree() -> Dict[str, str]:
    root = REPO_ROOT / "s19_app"
    return {
        path.relative_to(REPO_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*.py"))
        if "__pycache__" not in path.parts
    }


@pytest.fixture(scope="module")
def tree() -> Dict[str, str]:
    return _read_tree()


@pytest.fixture(scope="module")
def tree_census(tree: Dict[str, str]) -> Census:
    return census_sources(tree)


#: Synthetic mutants: each has the shape of a defect the censuses must catch.
#: They are appended to the real tree as one extra module (cited by case id).
_MUTANT_MODULE = "s19_app/_synthetic_mutant.py"
_DEAD_DIALOGS = '''
class OrphanDialog(ModalScreen[None]):
    pass


class DeadOnlyDialog(ModalScreen[None]):
    pass


class LiveDialog(ModalScreen[None]):
    pass


class BaseViaChild(ModalScreen[None]):
    pass


class ChildOfBase(BaseViaChild):
    pass


class _Opener(App):
    def _never_called(self):
        self.push_screen(DeadOnlyDialog())

    def on_mount(self):
        self.push_screen(LiveDialog())
        self.push_screen(ChildOfBase())
'''
_DEAD_ACTIONS = '''
class _DeadChain(App):
    def action_dead_alias(self):
        self.action_show_screen("a2l")

    def _dead_adapter(self, item):
        self._dead_adapter_object(item)

    def _dead_adapter_object(self, issue):
        self.action_dead_alias()


class _DeadAlone(App):
    def action_dead_mac_alias(self):
        self.action_show_screen("mac")


class PlainCard:
    def action_copy(self):
        return None


class _IdOnly(App):
    def compose(self):
        yield Button("Find", id="find_nxt_probe")

    def on_button_pressed(self, event):
        if event.button.id == "find_nxt_probe":
            self._do_find()

    def _do_find(self):
        return None

    def action_find_nxt_probe(self):
        self._do_find()
'''
_LIVE_ACTIONS = '''
class _Live(App):
    BINDINGS = [Binding("f", "bound_probe", "Bound")]
    EXTRA_PALETTE_ENTRIES = (("Palette probe", "palette_probe"),)

    def action_bound_probe(self):
        return None

    def action_palette_probe(self):
        return None

    def action_run_probe(self):
        return None

    def action_link_probe(self):
        return None

    def action_called_probe(self):
        return None

    def action_arg_probe(self):
        return None

    def on_mount(self):
        self.run_action("run_probe")
        self.action_called_probe()
        self.screen.update("[@click=app.link_probe]x[/]")
        self.bind("g", "app.arg_probe('x')")
        self.add_binding(Binding("h", "arg_probe('y')"))


class ToolkitBox(Input):
    def action_paste(self):
        return None


class _FindProbe(App):
    BINDINGS = [Binding("n", "find_nxt_probe", "Find next")]
    def action_find_nxt_probe(self):
        return None
'''


def _with(tree: Dict[str, str], extra: str) -> Dict[str, str]:
    return {**tree, _MUTANT_MODULE: extra}


# --------------------------------------------------------------------------- #
# R-DLG.14 and R-SHELL-KEYS.3
# --------------------------------------------------------------------------- #


def test_r_dlg_14_1_every_dialog_has_an_opener(tree: Dict[str, str], tree_census: Census) -> None:
    """R-DLG.14/1: 0 dialogs without an opener; at least 21 dialogs censused; the
    census finds the dead shapes it must (an orphan dialog, a dialog built only in
    a function no reached function calls, E3A-02) and passes the live ones (a
    dialog opened in a toolkit handler, a base opened through its subclass)."""
    assert len(tree_census.dialogs) >= 21, sorted(tree_census.dialogs)
    assert tree_census.dialogs_without_opener == [], tree_census.dialogs_without_opener
    # negative controls (R-DLG.14/1): the base's defect shape, restored as synthetic mutants
    mutant = census_sources(_with(tree, _DEAD_DIALOGS))
    assert set(mutant.dialogs) - set(tree_census.dialogs) == {
        "OrphanDialog", "DeadOnlyDialog", "LiveDialog", "BaseViaChild", "ChildOfBase",
    }
    assert mutant.dialogs_without_opener == ["DeadOnlyDialog", "OrphanDialog"]


def test_r_shell_keys_3_1_every_action_has_a_reach(tree: Dict[str, str], tree_census: Census) -> None:
    """R-SHELL-KEYS.3/1: 0 actions without a reach; at least 80 actions censused;
    the six clipboard overrides reached through the toolkit's bindings. Negative
    controls (synthetic mutants of the base's shapes): a dead chain (an alias whose
    only call lies in a function no reached function calls), a lone dead alias, an
    unbound ``action_copy`` on a class that is not a toolkit widget, and an action
    whose name is only a widget id and a comparison literal (E3A-R2-1)."""
    assert len(tree_census.actions) >= 80, len(tree_census.actions)
    assert tree_census.actions_without_reach == [], tree_census.actions_without_reach
    clipboard = [
        f"{cls}.action_{name}"
        for cls in ("CappedTextArea", "OsClipboardInput")
        for name in ("cut", "copy", "paste")
    ]
    for label in clipboard:
        assert label in tree_census.actions, f"{label} is not in the census"
        assert "toolkit" in tree_census.reasons(label), (label, tree_census.reasons(label))
    # negative controls
    dead = census_sources(_with(tree, _DEAD_ACTIONS))
    assert dead.actions_without_reach == [
        "PlainCard.action_copy",
        "_DeadAlone.action_dead_mac_alias",
        "_DeadChain.action_dead_alias",
        "_IdOnly.action_find_nxt_probe",
    ]
    # every arm that gives a reach does give one (a census that flags too much is as vacuous)
    live = census_sources(_with(tree, _LIVE_ACTIONS))
    new = {label: why for label, why in live.actions.items() if label.startswith(("_Live.", "ToolkitBox.", "_FindProbe."))}
    assert sorted(new) == [
        "ToolkitBox.action_paste",
        "_FindProbe.action_find_nxt_probe",
        "_Live.action_arg_probe",
        "_Live.action_bound_probe",
        "_Live.action_called_probe",
        "_Live.action_link_probe",
        "_Live.action_palette_probe",
        "_Live.action_run_probe",
    ]
    assert [label for label, why in new.items() if not why] == []
    assert new["ToolkitBox.action_paste"] == {"toolkit"}
    assert new["_Live.action_called_probe"] == {"reached"}
    assert "string" in new["_Live.action_run_probe"]
    assert "string" in new["_Live.action_link_probe"]
    assert "string" in new["_Live.action_palette_probe"]


# --------------------------------------------------------------------------- #
# The Reports dialog (R-DLG.2, R-DLG.15)
# --------------------------------------------------------------------------- #


async def _reports_project(app, pilot, *, name: str = "proj1", with_reports: bool = True) -> Path:
    await settle(pilot)
    make_project(app, name)
    project = await load_project(app, name)
    if with_reports:
        (project / "reports").mkdir(exist_ok=True)
        (project / "reports" / "20261106T100000Z-report.md").write_text(
            "# Report one\n\nbody\n", encoding="utf-8"
        )
        (project / "reports" / "20261106T110000Z-report.md").write_text(
            "# Report two\n", encoding="utf-8"
        )
        (project / "filters").mkdir(exist_ok=True)
        (project / "filters" / "f1.json").write_text("{}", encoding="utf-8")
    return project


def _known(app) -> tuple:
    """The Known focus (U-2): the focused widget and the shown window before ``t``."""
    assert app.focused is not None, "no widget has the focus before the Reports key"
    return app.focused, app._active_screen_key


async def _known_off_default(app, pilot) -> tuple:
    """The Known focus (U-2), placed where Textual's own fallback would not put it.

    A screen that resumes with nothing focused gives the focus to its first
    focusable widget. Start from ``#sections_list``, a non-input control that is
    not that widget, so a restore that is only that fallback cannot pass."""
    target = app.screen.query_one("#sections_list")
    target.focus()
    await settle(pilot)
    assert app.focused is target, f"the precondition focus did not hold: {app.focused!r}"
    first = next(w for w in app.screen.query("*") if w.focusable)
    assert target is not first, "the Known focus is the toolkit's fallback widget"
    assert not isinstance(target, (Input, TextArea)), target
    return _known(app)


def _report_files(project: Path) -> List[str]:
    folder = project / "reports"
    return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


def _closed(app) -> bool:
    return not any(isinstance(s, ReportViewerScreen) for s in app.screen_stack) and (
        app.screen is app.default_screen
    )


def _stack(app) -> List[str]:
    return [type(s).__name__ for s in app.screen_stack]


async def _open_reports(app, pilot) -> ReportViewerScreen:
    await pilot.press("t")
    await settled(
        pilot,
        lambda: isinstance(app.screen, ReportViewerScreen),
        "the Reports dialog opens",
        timeout=CLOSE_WAIT_S,
    )
    await settle(pilot)
    return app.screen


async def _focus(app, pilot, widget_id: str):
    widget = app.screen.query_one(f"#{widget_id}")
    widget.focus()
    await settle(pilot)
    assert app.focused is widget, f"the precondition focus on #{widget_id} did not hold: {app.focused!r}"
    return widget


async def _await_closed(app, pilot, what: str) -> None:
    await settled(
        pilot, lambda: _closed(app), f"the Reports dialog closed ({what}); stack {_stack(app)}",
        timeout=CLOSE_WAIT_S,
    )
    await settle(pilot)


async def _escape_closes(app, pilot, known: tuple, project: Path, before_status: List[str], what: str) -> None:
    await pilot.press("escape")
    await _await_closed(app, pilot, what)
    assert _report_files(project) == [
        "20261106T100000Z-report.md", "20261106T110000Z-report.md",
    ], _report_files(project)
    assert list(app.log_lines) == before_status, list(app.log_lines)
    assert (app.focused, app._active_screen_key) == known


def _run(base: Path, scenario) -> None:
    async def _go() -> None:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await scenario(app, pilot)

    asyncio.run(_go())


def test_r_dlg_2_1_escape_on_the_report_list_closes_reports(tmp_path: Path) -> None:
    """R-DLG.2/1: Escape on the report list closes the dialog, writes nothing, leaves
    the status line and gives the focus and the window back as before ``t``; one
    Close press in place of Escape gives the same (the reference)."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = await _known_off_default(app, pilot)
        await _open_reports(app, pilot)
        status = list(app.log_lines)
        assert app.focused is app.screen.query_one("#report_list")
        await _escape_closes(app, pilot, known, project, status, "escape on the list")
        # the reference: one Close press from the same place
        await _open_reports(app, pilot)
        app.screen.query_one("#report_close").press()
        await _await_closed(app, pilot, "the Close button")
        assert (app.focused, app._active_screen_key) == known

    _run(tmp_path, scenario)


def test_r_dlg_2_2_escape_on_the_report_view_closes_reports(tmp_path: Path) -> None:
    """R-DLG.2/2: Escape on the rendered report view closes the dialog; 2 files."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = _known(app)
        screen = await _open_reports(app, pilot)
        await pilot.press("enter")
        await settled(pilot, lambda: screen.selected_path is not None, "a report rendered", timeout=CLOSE_WAIT_S)
        await _focus(app, pilot, "report_markdown_scroll")
        await _escape_closes(app, pilot, known, project, list(app.log_lines), "escape on the report view")

    _run(tmp_path, scenario)


def test_r_dlg_2_3_escape_in_the_regions_box_closes_and_keeps_nothing(tmp_path: Path) -> None:
    """R-DLG.2/3: Escape in the declared-regions box with typed text closes the
    dialog; reopened, the box holds the project's regions (none: empty), not ``x``."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = _known(app)
        await _open_reports(app, pilot)
        box = await _focus(app, pilot, "report_declared_regions")
        await pilot.press("x")
        await settle(pilot)
        assert box.text == "x", box.text
        await _escape_closes(app, pilot, known, project, list(app.log_lines), "escape in the regions box")
        screen = await _open_reports(app, pilot)
        assert screen.query_one("#report_declared_regions").text == ""

    _run(tmp_path, scenario)


def test_r_dlg_2_4_escape_on_the_closed_dropdown_closes_reports(tmp_path: Path) -> None:
    """R-DLG.2/4: Escape on the closed filter dropdown closes the dialog."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = _known(app)
        await _open_reports(app, pilot)
        select = await _focus(app, pilot, "report_filter_select")
        assert select.expanded is False
        await _escape_closes(app, pilot, known, project, list(app.log_lines), "escape on the closed dropdown")

    _run(tmp_path, scenario)


def test_r_dlg_2_5_escape_in_the_filter_path_box_applies_nothing(tmp_path: Path) -> None:
    """R-DLG.2/5: Escape in the filter path box with ``abc`` typed and not submitted
    closes the dialog; reopened, the path box is empty and the dropdown blank."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = _known(app)
        await _open_reports(app, pilot)
        box = await _focus(app, pilot, "report_filter_path")
        await pilot.press("a", "b", "c")
        await settle(pilot)
        assert box.value == "abc", box.value
        await _escape_closes(app, pilot, known, project, list(app.log_lines), "escape in the path box")
        screen = await _open_reports(app, pilot)
        assert screen.query_one("#report_filter_path").value == ""
        assert screen.query_one("#report_filter_select", Select).value is Select.NULL

    _run(tmp_path, scenario)


def test_r_dlg_2_6_escape_in_the_context_box_closes_reports(tmp_path: Path) -> None:
    """R-DLG.2/6: Escape in the context-bytes box with ``9`` typed closes the dialog;
    2 files in ``reports/``."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = _known(app)
        await _open_reports(app, pilot)
        box = await _focus(app, pilot, "report_context_bytes")
        shipped = box.value
        await pilot.press("9")
        await settle(pilot)
        assert box.value != shipped and "9" in box.value, (shipped, box.value)
        await _escape_closes(app, pilot, known, project, list(app.log_lines), "escape in the context box")

    _run(tmp_path, scenario)


def test_r_dlg_2_7_escape_on_generate_writes_no_report(tmp_path: Path) -> None:
    """R-DLG.2/7: Escape on Generate closes the dialog and generates nothing (a third
    file would be Escape bound to Generate's path)."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = _known(app)
        await _open_reports(app, pilot)
        await _focus(app, pilot, "report_generate")
        await _escape_closes(app, pilot, known, project, list(app.log_lines), "escape on Generate")
        await settle_workers(pilot)
        await settle(pilot, 12)
        assert len(_report_files(project)) == 2, _report_files(project)

    _run(tmp_path, scenario)


def test_r_dlg_2_8_escape_on_close_closes_reports(tmp_path: Path) -> None:
    """R-DLG.2/8: Escape on the Close button closes the dialog."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = _known(app)
        await _open_reports(app, pilot)
        await _focus(app, pilot, "report_close")
        await _escape_closes(app, pilot, known, project, list(app.log_lines), "escape on Close")

    _run(tmp_path, scenario)


def test_r_dlg_2_9_escape_on_the_folder_chip_opens_no_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-DLG.2/9: Escape on the ``Open reports/`` chip closes the dialog and the
    folder spy counts 0 calls (the spy is live: a press of the chip counts 1)."""
    calls: List[Path] = []

    def spy(path, *, set_status=None, label="folder") -> bool:
        calls.append(Path(path))
        return True

    monkeypatch.setattr(fos, "open_folder_in_file_manager", spy)

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = _known(app)
        await _open_reports(app, pilot)
        await _focus(app, pilot, "open_folder_reports")
        await _escape_closes(app, pilot, known, project, list(app.log_lines), "escape on the folder chip")
        await settle(pilot, 8)
        assert calls == [], calls
        # the spy is live: a press of the chip reaches it
        await _open_reports(app, pilot)
        app.screen.query_one("#open_folder_reports").press()
        await settled(pilot, lambda: len(calls) == 1, "the chip press reached the folder spy", timeout=CLOSE_WAIT_S)

    _run(tmp_path, scenario)


def test_r_dlg_2_10_escape_on_the_help_chip_opens_no_help(tmp_path: Path) -> None:
    """R-DLG.2/10: Escape on the ``?`` chip closes the dialog; no help window opens."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = _known(app)
        await _open_reports(app, pilot)
        await _focus(app, pilot, "window_help_reports")
        await _escape_closes(app, pilot, known, project, list(app.log_lines), "escape on the ? chip")
        assert not any(isinstance(s, WindowHelpScreen) for s in app.screen_stack), _stack(app)

    _run(tmp_path, scenario)


def test_r_dlg_2_11_escape_closes_the_empty_reports_dialog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-DLG.2/11: Escape closes the Reports dialog of a project with no report,
    writes no file and sets no status line."""
    statuses = record_statuses(monkeypatch)

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot, name="proj2", with_reports=False)
        known = _known(app)
        screen = await _open_reports(app, pilot)
        assert screen.query("#report_empty_state"), "the dialog does not show the empty text"
        assert app.focused is screen.query_one("#window_help_reports")
        mark = len(statuses)
        await pilot.press("escape")
        await _await_closed(app, pilot, "escape on the empty dialog")
        assert (app.focused, app._active_screen_key) == known
        assert _report_files(project) == [], _report_files(project)
        assert statuses[mark:] == [], statuses[mark:]

    _run(tmp_path, scenario)


def test_r_dlg_2_12_escape_in_its_help_window_keeps_reports_open(tmp_path: Path) -> None:
    """R-DLG.2/12: Escape in the help window opened from the Reports dialog closes
    that window alone (it holds on the base)."""

    async def scenario(app, pilot) -> None:
        await _reports_project(app, pilot)
        await _open_reports(app, pilot)
        await _focus(app, pilot, "report_list")
        await pilot.press("question_mark")
        await settled(
            pilot, lambda: isinstance(app.screen, WindowHelpScreen), "the Reports help window opens",
            timeout=CLOSE_WAIT_S,
        )
        assert _stack(app)[-2:] == ["ReportViewerScreen", "WindowHelpScreen"], _stack(app)
        await pilot.press("escape")
        await settled(
            pilot, lambda: not any(isinstance(s, WindowHelpScreen) for s in app.screen_stack),
            "the help window closed", timeout=CLOSE_WAIT_S,
        )
        await settle(pilot)
        assert isinstance(app.screen, ReportViewerScreen), _stack(app)

    _run(tmp_path, scenario)


def _highlighted_prompt(select) -> str:
    overlay = select.query_one("SelectOverlay")
    assert overlay.highlighted is not None
    return str(overlay.get_option_at_index(overlay.highlighted).prompt)


def test_r_dlg_15_1_escape_with_the_dropdown_open_closes_only_the_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-DLG.15/1: Escape with the Reports filter dropdown open (highlight on
    ``f1.json``) closes only its list: the dialog stays, the dropdown stays blank and
    no ``Report filter:`` status shows; a second Escape closes the dialog and a
    reopening shows the dropdown blank."""
    statuses = record_statuses(monkeypatch)

    async def scenario(app, pilot) -> None:
        await _reports_project(app, pilot)
        screen = await _open_reports(app, pilot)
        select = await _focus(app, pilot, "report_filter_select")
        await pilot.press("enter")
        await settled(pilot, lambda: select.expanded, "the filter list opens", timeout=CLOSE_WAIT_S)
        await pilot.press("down")
        await settle(pilot)
        assert "f1.json" in _highlighted_prompt(select), _highlighted_prompt(select)
        mark = len(statuses)
        await pilot.press("escape")
        await settled(pilot, lambda: not select.expanded, "the filter list closed", timeout=CLOSE_WAIT_S)
        await settle(pilot)
        assert app.screen is screen and isinstance(app.screen, ReportViewerScreen), _stack(app)
        assert select.value is Select.NULL, select.value
        assert [m for m in statuses[mark:] if m.startswith("Report filter:")] == []
        assert [m for m in app.log_lines if m.startswith("Report filter:")] == []
        await pilot.press("escape")
        await _await_closed(app, pilot, "the second escape")
        screen = await _open_reports(app, pilot)
        assert screen.query_one("#report_filter_select", Select).value is Select.NULL

    _run(tmp_path, scenario)


def test_r_dlg_15_2_escape_with_the_gating_dropdown_open_closes_only_the_list(tmp_path: Path) -> None:
    """R-DLG.15/2: Escape with the Edit block gating dropdown of a CHECK block open
    (highlight on ``block-own-op``) closes only its list and leaves the gating
    ``advisory``; a second Escape closes Edit block and the block keeps ``advisory``."""

    async def scenario(app, pilot) -> None:
        await fx_project(app)
        panel = await open_flow_builder(app, pilot)
        panel.query_one("#flow_palette_check").press()
        await settle(pilot)
        panel.query_one("#flow_ref").value = "baseline.chk.json"
        panel.query_one("#flow_add").press()
        await settled(pilot, lambda: len(panel.current_flow.blocks) == 1, "the CHECK block added", timeout=CLOSE_WAIT_S)
        assert panel.current_flow.blocks[0].gating == "advisory"
        panel.query_one("#flow_pick").value = "1"
        panel.query_one("#flow_edit").press()
        await settled(
            pilot, lambda: isinstance(app.screen, FlowBlockEditScreen), "Edit block opens", timeout=CLOSE_WAIT_S
        )
        await settle(pilot)
        gating = await _focus(app, pilot, "flow_edit_gating")
        assert gating.value == "advisory"
        await pilot.press("enter")
        await settled(pilot, lambda: gating.expanded, "the gating list opens", timeout=CLOSE_WAIT_S)
        await pilot.press("down")
        await settle(pilot)
        assert "block-own-op" in _highlighted_prompt(gating), _highlighted_prompt(gating)
        await pilot.press("escape")
        await settled(pilot, lambda: not gating.expanded, "the gating list closed", timeout=CLOSE_WAIT_S)
        await settle(pilot)
        assert isinstance(app.screen, FlowBlockEditScreen), _stack(app)
        assert gating.value == "advisory", gating.value
        await pilot.press("escape")
        await settled(
            pilot, lambda: not isinstance(app.screen, FlowBlockEditScreen), "Edit block closed", timeout=CLOSE_WAIT_S
        )
        await settle(pilot)
        assert panel.current_flow.blocks[0].gating == "advisory"

    _run(tmp_path, scenario)


# --------------------------------------------------------------------------- #
# AT-I12-1 and AT-I12-2
# --------------------------------------------------------------------------- #


async def _tab_to(app, pilot, widget_id: str) -> None:
    """Tab until ``widget_id`` has the focus (bounded)."""
    for _ in range(30):
        if app.focused is not None and app.focused.id == widget_id:
            return
        await pilot.press("tab")
        await settle(pilot, 2)
    raise AssertionError(f"tab never reached #{widget_id}; the focus is {app.focused!r}")


def test_at_i12_1_escape_closes_reports_from_list_box_and_dropdown(tmp_path: Path) -> None:
    """AT-I12-1 (US-I12-3; rows R-DLG.2, R-DLG.15): through the keys, Escape closes
    the dialog from the rendered list and from the path box with ``abc`` typed (the
    focus and window as before ``t``, nothing applied), and with the filter list
    open Escape closes the list alone and the next one the dialog."""

    async def scenario(app, pilot) -> None:
        project = await _reports_project(app, pilot)
        known = await _known_off_default(app, pilot)
        two = ["20261106T100000Z-report.md", "20261106T110000Z-report.md"]
        screen = await _open_reports(app, pilot)
        await pilot.press("enter")
        await settled(pilot, lambda: screen.selected_path is not None, "a report rendered", timeout=CLOSE_WAIT_S)
        await pilot.press("escape")
        await _await_closed(app, pilot, "first escape")
        assert (app.focused, app._active_screen_key) == known
        screen = await _open_reports(app, pilot)
        await _tab_to(app, pilot, "report_filter_path")
        await pilot.press("a", "b", "c")
        await settle(pilot)
        assert screen.query_one("#report_filter_path").value == "abc"
        await pilot.press("escape")
        await _await_closed(app, pilot, "second escape")
        assert (app.focused, app._active_screen_key) == known
        screen = await _open_reports(app, pilot)
        assert screen.query_one("#report_filter_path").value == ""
        select = screen.query_one("#report_filter_select", Select)
        assert select.value is Select.NULL
        await _tab_to(app, pilot, "report_filter_select")
        await pilot.press("enter")
        await settled(pilot, lambda: select.expanded, "the filter list opens", timeout=CLOSE_WAIT_S)
        await pilot.press("down")
        await settle(pilot)
        assert "f1.json" in _highlighted_prompt(select), _highlighted_prompt(select)
        await pilot.press("escape")
        await settled(pilot, lambda: not select.expanded, "the filter list closed", timeout=CLOSE_WAIT_S)
        await settle(pilot)
        assert app.screen is screen and select.value is Select.NULL
        await pilot.press("escape")
        await _await_closed(app, pilot, "last escape")
        assert _report_files(project) == two

    _run(tmp_path, scenario)


@pytest.fixture(scope="module")
def case08(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Case 08 (seed 20260001, 1.0 MB), generated once."""
    folder = tmp_path_factory.mktemp("b101_i12_case08")
    gen.generate(folder, SEED, SIZE_MB)
    return folder


def test_at_i12_2_rail_keys_and_issue_peek_after_the_aliases_go(tmp_path: Path, case08: Path) -> None:
    """AT-I12-2 (US-I12-1; rows R-SHELL-KEYS.3, R-TUI-021.3, R-ISSUES-HEXPANE-001.1):
    keys ``2``, ``3``, ``1`` show the A2L Explorer, the MAC View and the Workspace;
    Enter on the first Issues row whose address lies in the image keeps the Issues
    window shown and paints that address's hex row in the peek."""

    async def scenario(app, pilot) -> None:
        image = case08 / "firmware.s19"
        app.load_selected_file(image)
        await wait_until(
            pilot,
            lambda: app.current_file is not None and app.current_file.path.name == image.name,
            "the image load did not finish", timeout=LOAD_WAIT_S,
        )
        await settle_workers(pilot)
        app.load_a2l_from_path(case08 / "firmware_issues.a2l")
        await wait_until(
            pilot, lambda: app.current_a2l_data is not None, "the A2L load did not finish", timeout=LOAD_WAIT_S
        )
        await settle_workers(pilot)
        await wait_until(
            pilot, lambda: len(app._validation_issues) > 0, "no validation issues after the loads",
            timeout=LOAD_WAIT_S,
        )
        await settle(pilot)
        for key, window in (("2", "a2l"), ("3", "mac"), ("1", "workspace")):
            await pilot.press(key)
            await settled(
                pilot, lambda: app._active_screen_key == window,
                f"key {key} shows {window}; shown {app._active_screen_key}", timeout=CLOSE_WAIT_S,
            )
        await pilot.press("5")
        await settled(
            pilot, lambda: app._active_screen_key == "issues" and bool(list(app.query(IssueRow))),
            "the Issues window lists rows", timeout=CLOSE_WAIT_S,
        )
        mem_map = app.current_file.mem_map
        rows = [r for r in app.query(IssueRow) if isinstance(r.issue.address, int) and r.issue.address in mem_map]
        assert rows, "no listed issue has an address inside the image"
        row = rows[0]
        address = row.issue.address
        pane = app.query_one("#issues_hex_pane")
        before = str(pane.render())
        wanted = f"{address - address % 16:08X}"
        assert wanted not in before, before
        row.focus()
        await settle(pilot)
        await pilot.press("enter")
        await settled(
            pilot, lambda: wanted in str(pane.render()),
            f"the peek paints the row {wanted}; it shows {str(pane.render())!r}", timeout=CLOSE_WAIT_S,
        )
        assert app._active_screen_key == "issues"

    _run(tmp_path, scenario)
