"""Known-good and known-bad controls for the WinCI gate and upload barrier."""

from __future__ import annotations

import ast
import copy
import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import pytest

from tests.support import b103_artifact_safety as safety
from tests.support import b103_winci_gate as gate

TAIL_REQUIRED = (
    "tests/test_b103_clipboard_tail.py::"
    "test_r_tui_043_13_101_no_copied_text_or_prefix_in_logs"
)
QUIT_REQUIRED = (
    "tests/test_b103_copy_quit_dialog.py::"
    "test_r_copy_16_1_button_and_materialized_empty_selection"
)
NON_AT_NODE = (
    "tests/test_b103_copy_views.py::"
    "test_r_copy_1_ctrl_c_writes_each_view[R-COPY.1/1]"
)
P2_NODE = (
    "tests/test_b103_copy_paste_matrix.py::"
    "test_copy_paste_acceptance_cell[AT-I1b-1/2-T1-P2]"
)


def _sync_counts(root: ET.Element) -> None:
    cases = list(root.iter("testcase"))
    root.set("tests", str(len(cases)))
    root.set("skipped", str(sum(case.find("skipped") is not None for case in cases)))
    root.set("failures", str(sum(case.find("failure") is not None for case in cases)))
    root.set("errors", str(sum(case.find("error") is not None for case in cases)))


def _good_tree(manifest: gate.Manifest) -> ET.ElementTree:
    root = ET.Element("testsuite", name="b103-winci")
    for nodeid in manifest.expected_nodeids:
        file_path, name = nodeid.split("::", 1)
        case = ET.SubElement(
            root,
            "testcase",
            classname=manifest.classname_for_file[file_path],
            name=name,
        )
        rule = manifest.skip_rules.get(nodeid)
        if rule is not None:
            ET.SubElement(case, "skipped", message=rule.reason)
    _sync_counts(root)
    return ET.ElementTree(root)


def _write_tree(tmp_path: Path, tree: ET.ElementTree) -> Path:
    path = tmp_path / "junit.xml"
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return path


def _good_junit(tmp_path: Path) -> tuple[gate.Manifest, ET.ElementTree, Path]:
    manifest = gate.load_manifest()
    tree = _good_tree(manifest)
    return manifest, tree, _write_tree(tmp_path, tree)


def _find_case(
    tree: ET.ElementTree,
    manifest: gate.Manifest,
    nodeid: str,
) -> ET.Element:
    file_path, name = nodeid.split("::", 1)
    classname = manifest.classname_for_file[file_path]
    return next(
        case
        for case in tree.iter("testcase")
        if case.get("classname") == classname and case.get("name") == name
    )


def _remove_case(tree: ET.ElementTree, case: ET.Element) -> None:
    tree.getroot().remove(case)
    _sync_counts(tree.getroot())


def _has(audit: gate.Audit, prefix: str) -> bool:
    return any(violation.startswith(prefix) for violation in audit.violations)


def test_manifest_fixes_complete_population_and_obligations() -> None:
    manifest = gate.load_manifest()
    assert manifest.counts == {
        "testcases": 256,
        "obligations": 108,
        "view_obligations": 46,
        "tail_obligations": 25,
        "quit_obligations": 9,
        "at_obligations": 28,
        "at_p1": 14,
        "at_p2": 14,
        "linux_only_skips": 6,
        "legacy_linux_h_skips": 37,
        "manual_skips": 1,
        "winci_passed": 212,
        "winci_skipped": 44,
    }
    assert len(manifest.expected_nodeids) == len(manifest.expected_set) == 256
    assert Counter(item.family for item in manifest.obligations) == {
        "view": 46,
        "tail": 25,
        "quit": 9,
        "at": 28,
    }
    assert all(item.internal_arms for item in manifest.obligations)
    assert not any(item.requirement == "AT-I1b-8" for item in manifest.obligations)


def test_known_good_full_winci_junit_and_exact_skip_population(tmp_path: Path) -> None:
    _manifest, _tree, path = _good_junit(tmp_path)
    audit = gate.audit_junit(path, 0)
    assert audit.violations == []
    assert (audit.total, audit.passed, audit.skipped) == (256, 212, 44)
    assert (audit.failed, audit.errors) == (0, 0)
    assert audit.obligations_passed == 108
    assert (audit.at_passed, audit.at_p1_passed, audit.at_p2_passed) == (28, 14, 14)
    assert Counter(category for category, _node in audit.allowed_skips) == {
        "legacy-linux-h": 37,
        "linux-only": 6,
        "manual": 1,
    }
    manual = [node for category, node in audit.allowed_skips if category == "manual"]
    assert manual == [
        "tests/test_b103_copy_paste_matrix.py::"
        "test_manual_windows_terminal_operator_acceptance"
    ]


@pytest.mark.parametrize("nodeid", [TAIL_REQUIRED, QUIT_REQUIRED], ids=["tail", "quit"])
def test_missing_required_tail_or_quit_node_fails(tmp_path: Path, nodeid: str) -> None:
    manifest, tree, _path = _good_junit(tmp_path)
    _remove_case(tree, _find_case(tree, manifest, nodeid))
    audit = gate.audit_junit(_write_tree(tmp_path, tree), 0)
    assert _has(audit, "MISSING_NODE")
    assert _has(audit, "REQUIRED_NOT_PASSED")


def test_renamed_at_is_missing_and_unexpected(tmp_path: Path) -> None:
    manifest, tree, _path = _good_junit(tmp_path)
    case = _find_case(tree, manifest, P2_NODE)
    case.set("name", case.get("name", "").replace("AT-I1b-1/2", "AT-I1b-99/2"))
    audit = gate.audit_junit(_write_tree(tmp_path, tree), 0)
    assert _has(audit, "MISSING_NODE")
    assert _has(audit, "UNEXPECTED_NODE")
    assert _has(audit, "AT_CENSUS")


def test_absent_p2_fails_partition_and_required_obligation(tmp_path: Path) -> None:
    manifest, tree, _path = _good_junit(tmp_path)
    _remove_case(tree, _find_case(tree, manifest, P2_NODE))
    audit = gate.audit_junit(_write_tree(tmp_path, tree), 0)
    assert _has(audit, "AT_P2_PASSED")
    assert _has(audit, "REQUIRED_NOT_PASSED")
    assert audit.at_p2_passed == 13


def test_duplicate_non_at_node_fails(tmp_path: Path) -> None:
    manifest, tree, _path = _good_junit(tmp_path)
    duplicate = copy.deepcopy(_find_case(tree, manifest, NON_AT_NODE))
    tree.getroot().append(duplicate)
    _sync_counts(tree.getroot())
    audit = gate.audit_junit(_write_tree(tmp_path, tree), 0)
    assert _has(audit, "DUPLICATE_NODEID")
    assert audit.total == 257


def test_linux_prefix_cannot_skip_a_required_obligation(tmp_path: Path) -> None:
    manifest, tree, _path = _good_junit(tmp_path)
    case = _find_case(tree, manifest, TAIL_REQUIRED)
    ET.SubElement(case, "skipped", message="Linux-only forged exemption")
    _sync_counts(tree.getroot())
    audit = gate.audit_junit(_write_tree(tmp_path, tree), 0)
    assert _has(audit, "DISALLOWED_SKIP")
    assert _has(audit, "REQUIRED_NOT_PASSED")


def test_allowed_skip_requires_exact_reason(tmp_path: Path) -> None:
    manifest, tree, _path = _good_junit(tmp_path)
    nodeid = next(
        nodeid
        for nodeid, rule in manifest.skip_rules.items()
        if rule.category == "linux-only"
    )
    case = _find_case(tree, manifest, nodeid)
    skipped = case.find("skipped")
    assert skipped is not None
    skipped.set("message", skipped.get("message", "") + " but different")
    audit = gate.audit_junit(_write_tree(tmp_path, tree), 0)
    assert _has(audit, "SKIP_REASON")


@pytest.mark.parametrize("attribute", ["tests", "skipped", "failures", "errors"])
def test_inconsistent_declared_junit_counts_fail(tmp_path: Path, attribute: str) -> None:
    _manifest, tree, _path = _good_junit(tmp_path)
    root = tree.getroot()
    root.set(attribute, str(int(root.get(attribute, "0")) + 1))
    audit = gate.audit_junit(_write_tree(tmp_path, tree), 0)
    assert _has(audit, f"JUNIT_{attribute.upper()}_COUNT")


def test_empty_and_unreadable_xml_fail_closed(tmp_path: Path, capsys) -> None:
    empty = tmp_path / "empty.xml"
    root = ET.Element("testsuite", tests="0", skipped="0", failures="0", errors="0")
    ET.ElementTree(root).write(empty, encoding="utf-8")
    assert _has(gate.audit_junit(empty, 0), "JUNIT_EMPTY")

    malformed = tmp_path / "malformed.xml"
    malformed.write_text("<testsuite>", encoding="utf-8")
    assert gate.main(["--junit-xml", str(malformed), "--pytest-exit", "0"]) == 2
    assert "JUNIT_UNREADABLE" in capsys.readouterr().out


def test_pytest_exit_is_preserved_for_good_and_unreadable_xml(
    tmp_path: Path,
    capsys,
) -> None:
    _manifest, _tree, path = _good_junit(tmp_path)
    assert gate.main(["--junit-xml", str(path), "--pytest-exit", "7"]) == 7
    output = capsys.readouterr().out
    assert "PYTEST_EXIT code=7" in output
    assert "pytest_exit=7 gate_exit=7" in output

    malformed = tmp_path / "malformed.xml"
    malformed.write_text("not XML", encoding="utf-8")
    assert gate.main(["--junit-xml", str(malformed), "--pytest-exit", "7"]) == 7


def _safe_artifacts(tmp_path: Path) -> tuple[Path, Path, Path]:
    transcript = tmp_path / "pytest.txt"
    transcript.write_text(
        "tests/test_b103_copy_views.py::test_r_copy_12_7_back_to_back_and_reentry PASSED\n",
        encoding="utf-8",
    )
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuite tests="1" skipped="0" failures="0" errors="0">'
        '<testcase classname="tests.test_b103_copy_views" '
        'name="test_r_copy_12_7_back_to_back_and_reentry"/>'
        "</testsuite>",
        encoding="utf-8",
    )
    gate_transcript = tmp_path / "gate.txt"
    gate_transcript.write_text("WINCI_GATE_RESULT PASS violations=0\n", encoding="utf-8")
    return transcript, junit, gate_transcript


def test_artifact_scanner_known_good(tmp_path: Path, capsys) -> None:
    transcript, junit, gate_transcript = _safe_artifacts(tmp_path)
    audit = safety.audit_artifacts(transcript, junit, gate_transcript)
    assert audit.violations == []
    assert safety.main(
        [
            "--transcript",
            str(transcript),
            "--junit-xml",
            str(junit),
            "--gate-transcript",
            str(gate_transcript),
        ]
    ) == 0
    assert "ARTIFACT_SAFETY_RESULT PASS" in capsys.readouterr().out


_CENSUS_UNKNOWN = object()
_CENSUS_CALL_ARGUMENTS = {
    "other_program_write": 0,
    "_assert_log_excludes": 1,
    "_no_secret": 1,
}
_CENSUS_FORMS = ("raw", "prefix", "repr", "escape", "xml")


def _is_payload_name(name: str) -> bool:
    upper = name.upper()
    return upper.startswith(("SEED", "HOSTILE", "SECRET", "P_CTRL")) or (
        upper.startswith("P") and len(upper) > 1 and upper[1].isdigit()
    )


def _assignment_strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, tuple):
        return ()
    if value and all(isinstance(item, tuple) and len(item) >= 2 for item in value):
        return tuple(item[1] for item in value if isinstance(item[1], str))
    return tuple(item for item in value if isinstance(item, str))


class _AstPayloadCensus(ast.NodeVisitor):
    """Resolve literal payloads from source structure, never from the scanner.

    Includes SEED/HOSTILE/SECRET and shared P* constants, payload assignments,
    imports, the three disclosure-sensitive call positions, literal CR values and
    PS-READ/PS-WRITE. Static concatenation, multiplication and tuple loops are
    resolved. Only dynamic expressions, whitespace, strings under four characters
    and generated payloads over 256 characters are excluded.
    """

    def __init__(self, path: Path, inherited: dict[str, object]) -> None:
        self.path = path
        self.globals = dict(inherited)
        self.scopes: list[dict[str, object]] = []
        self.values: dict[str, list[str]] = {}

    @property
    def scope(self) -> dict[str, object]:
        return self.scopes[-1] if self.scopes else self.globals

    def _lookup(self, name: str) -> object:
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return self.globals.get(name, _CENSUS_UNKNOWN)

    def _eval(self, node: ast.AST) -> object:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self._lookup(node.id)
        if isinstance(node, (ast.Tuple, ast.List)):
            values = tuple(self._eval(element) for element in node.elts)
            if any(value is _CENSUS_UNKNOWN for value in values):
                return _CENSUS_UNKNOWN
            return values
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
            left = self._eval(node.left)
            right = self._eval(node.right)
            if left is _CENSUS_UNKNOWN or right is _CENSUS_UNKNOWN:
                return _CENSUS_UNKNOWN
            try:
                if isinstance(node.op, ast.Add):
                    return left + right
                return left * right
            except (TypeError, ValueError):
                return _CENSUS_UNKNOWN
        return _CENSUS_UNKNOWN

    def _bind(self, target: ast.AST, value: object) -> None:
        if isinstance(target, ast.Name):
            self.scope[target.id] = value
        elif isinstance(target, ast.Starred):
            self._bind(target.value, _CENSUS_UNKNOWN)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, tuple) and len(target.elts) == len(value):
                for element, item in zip(target.elts, value):
                    self._bind(element, item)
            else:
                for element in target.elts:
                    self._bind(element, _CENSUS_UNKNOWN)

    def _consider(self, value: object, line: int) -> None:
        if not isinstance(value, str) or not value.strip():
            return
        if not 4 <= len(value) <= 256:
            return
        origin = f"{self.path}:{line}"
        origins = self.values.setdefault(value, [])
        if origin not in origins:
            origins.append(origin)

    def _record_assignment(self, target: ast.AST, value: object, line: int) -> None:
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Attribute):
            name = target.attr
        else:
            return
        upper = name.upper()
        if _is_payload_name(name):
            for item in _assignment_strings(value):
                self._consider(item, line)
        if "PAYLOAD" in upper:
            for item in _assignment_strings(value):
                self._consider(item, line)
        if isinstance(value, str) and (
            value.startswith(("SEED-", "SECRET-", "PS-READ", "PS-WRITE"))
            or "\r" in value
        ):
            self._consider(value, line)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module != "tests.support.b103_clipboard":
            return
        for alias in node.names:
            value = self.globals.get(alias.name, _CENSUS_UNKNOWN)
            self.scope[alias.asname or alias.name] = value
            if _is_payload_name(alias.name):
                self._consider(value, node.lineno)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        local: dict[str, object] = {}
        arguments = (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
        for argument in arguments:
            local[argument.arg] = _CENSUS_UNKNOWN
        for argument in (node.args.vararg, node.args.kwarg):
            if argument is not None:
                local[argument.arg] = _CENSUS_UNKNOWN
        self.scopes.append(local)
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        value = self._eval(node.value)
        for target in node.targets:
            self._bind(target, value)
            self._record_assignment(target, value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            value = self._eval(node.value)
            self._bind(node.target, value)
            self._record_assignment(node.target, value, node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        current = self._eval(node.target)
        increment = self._eval(node.value)
        value = _CENSUS_UNKNOWN
        if (
            isinstance(node.op, ast.Add)
            and current is not _CENSUS_UNKNOWN
            and increment is not _CENSUS_UNKNOWN
        ):
            try:
                value = current + increment
            except TypeError:
                pass
        self._bind(node.target, value)
        self._record_assignment(node.target, value, node.lineno)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        iterable = self._eval(node.iter)
        if isinstance(iterable, tuple):
            for item in iterable:
                self._bind(node.target, item)
                for statement in node.body:
                    self.visit(statement)
        else:
            self._bind(node.target, _CENSUS_UNKNOWN)
            for statement in node.body:
                self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        else:
            name = ""
        if name in _CENSUS_CALL_ARGUMENTS:
            position = _CENSUS_CALL_ARGUMENTS[name]
            if len(node.args) > position:
                self._consider(self._eval(node.args[position]), node.lineno)
        self.generic_visit(node)


def _ast_payload_census(paths) -> dict[str, list[str]]:
    helper_path = Path("tests/support/b103_clipboard.py")
    helper = _AstPayloadCensus(helper_path, {})
    helper.visit(ast.parse(helper_path.read_text(encoding="utf-8")))
    values: dict[str, list[str]] = {}
    for path in paths:
        census = _AstPayloadCensus(path, helper.globals)
        census.visit(ast.parse(path.read_text(encoding="utf-8")))
        for value, origins in census.values.items():
            values.setdefault(value, []).extend(
                origin for origin in origins if origin not in values.get(value, [])
            )
    return values


def _value_form(value: str, form: str) -> str:
    if form == "raw":
        return value
    if form == "prefix":
        return value[:16]
    if form == "repr":
        return repr(value)
    if form == "escape":
        return value.encode("unicode_escape").decode("ascii")
    if form == "xml":
        return "".join(f"&#x{ord(character):X};" for character in value)
    raise AssertionError(form)


def _census_misses(paths) -> tuple[dict[str, list[str]], list[tuple[str, str, list[str]]]]:
    census = _ast_payload_census(paths)
    registered = {
        value for values in safety.CONTROL_CANARIES.values() for value in values
    }
    misses = []
    for value, origins in census.items():
        if value not in registered:
            misses.append((value, "declaration", origins))
            continue
        for form in _CENSUS_FORMS:
            audit = safety.SafetyAudit()
            safety._scan_text("ast-census", _value_form(value, form), audit)
            if not any(
                violation.startswith("CONTROL_CANARY")
                for violation in audit.violations
            ):
                misses.append((value, form, origins))
    return census, misses


def test_artifact_scanner_census_covers_all_six_family_canaries() -> None:
    paths = [Path(path) for path in sorted(gate.EXPECTED_FILES)]
    _census, misses = _census_misses(paths)
    if misses:
        details = [
            f"{form}@{','.join(origins)}:chars={len(value)}"
            for value, form, origins in misses[:12]
        ]
        raise AssertionError(
            f"AST payload census found {len(misses)} uncovered controls: "
            + "; ".join(details)
        )


def test_artifact_scanner_ast_census_known_present_undeclared_payload(
    tmp_path: Path,
) -> None:
    value = "UNDECLARED-FIX3-PAYLOAD-\r\nNEXT"
    source = (
        'payload = "UNDECLARED-FIX3-PAYLOAD-\\r\\nNEXT"\n'
        "other_program_write(payload)\n"
    )
    path = tmp_path / "test_undeclared_payload.py"
    path.write_text(source, encoding="utf-8")
    census, misses = _census_misses((path,))
    if value not in census:
        raise AssertionError("AST census missed a known-present synthetic payload")
    if not any(
        candidate == value and form == "declaration"
        for candidate, form, _origins in misses
    ):
        raise AssertionError("AST census did not flag the undeclared synthetic payload")


def _canary_value(canary_id: str) -> str:
    values = safety.CONTROL_CANARIES[canary_id]
    return next(
        (
            value
            for value in values
            if "\x00" not in value
            and not any(0xD800 <= ord(character) <= 0xDFFF for character in value)
        ),
        values[0],
    )


def _canary_form(canary_id: str, form: str) -> str:
    return _value_form(_canary_value(canary_id), form)


@pytest.mark.parametrize("canary_id", list(safety.CONTROL_CANARIES))
@pytest.mark.parametrize("surface", ["transcript", "junit"])
@pytest.mark.parametrize("form", ["raw", "prefix", "repr", "escape", "xml"])
def test_artifact_scanner_known_bad_canary_forms(
    tmp_path: Path,
    canary_id: str,
    surface: str,
    form: str,
    capsys,
) -> None:
    transcript, junit, gate_transcript = _safe_artifacts(tmp_path)
    value = _canary_value(canary_id)
    payload = _canary_form(canary_id, form)
    if surface == "transcript":
        transcript.write_text(payload, encoding="utf-8")
    else:
        junit.write_text(
            f'<testsuite tests="1" skipped="0" failures="1" errors="0">'
            f'<testcase classname="example" name="failure">'
            f'<failure message="controlled failure">{payload}</failure>'
            "</testcase></testsuite>",
            encoding="utf-8",
        )
    audit = safety.audit_artifacts(transcript, junit, gate_transcript)
    assert any(violation.startswith("CONTROL_CANARY") for violation in audit.violations)
    assert safety.main(
        [
            "--transcript",
            str(transcript),
            "--junit-xml",
            str(junit),
            "--gate-transcript",
            str(gate_transcript),
        ]
    ) == 1
    output = capsys.readouterr().out
    if value in output or payload in output or "SUFFIX" in output:
        raise AssertionError("artifact scanner output reproduced a controlled canary")
    assert "ARTIFACT_SAFETY_RESULT FAIL" in output


@pytest.mark.parametrize(
    "payload",
    [
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
        "ghp_abcdefghijklmnopqrstuvwxyz1234",
        "-----BEGIN PRIVATE KEY-----",
        'api_key = "unit-test-value-123"',
        r"C:\Users\person\private.txt",
        r"C:\\Users\\person\\private.txt",
        "C&#58;&#92;Users&#92;person&#92;private.txt",
        "/mnt/c/Users/person/private.txt",
        "/home/person/private.txt",
        "WindowsPath('C:/Users/person/AppData/Local/Temp/pytest-0')",
        r"C:\Users\runneradmin2\private.txt",
        "C:/Users/runneradmins/private.txt",
    ],
    ids=[
        "bearer",
        "github-token",
        "private-key",
        "secret-assignment",
        "windows-path",
        "repr-windows-path",
        "xml-windows-path",
        "wsl-path",
        "unix-path",
        "forward-slash-windows-path",
        "runner-prefix-account",
        "runner-prefix-account-forward-slash",
    ],
)
def test_artifact_scanner_known_bad_credentials_and_personal_paths(
    tmp_path: Path,
    payload: str,
) -> None:
    transcript, junit, gate_transcript = _safe_artifacts(tmp_path)
    transcript.write_text(payload, encoding="utf-8")
    audit = safety.audit_artifacts(transcript, junit, gate_transcript)
    assert any(
        violation.startswith(("CREDENTIAL", "PERSONAL_PATH"))
        for violation in audit.violations
    )


def test_artifact_scanner_allows_only_the_hosted_runner_account(tmp_path: Path) -> None:
    """WinCI 43438310100: a failing run's tracebacks carry pytest's tmp_path
    under the GitHub-hosted runner account, which names no person. Those
    forms pass; the same text with any other account is still RED."""
    runner_forms = (
        "tmp_path = WindowsPath('C:/Users/runneradmin/AppData/Local/Temp/"
        "pytest-of-runneradmin/pytest-0/test_x0')\n"
        r"INFO base_dir=C:\Users\runneradmin\AppData\Local\Temp\pytest-0\x"
        "\n"
        r"repr C:\\Users\\RUNNERADMIN\\AppData"
        "\n"
        "path end C:\\Users\\runneradmin\n"
    )
    transcript, junit, gate_transcript = _safe_artifacts(tmp_path)
    transcript.write_text(runner_forms, encoding="utf-8")
    junit.write_text(
        '<testsuite tests="1" skipped="0" failures="1" errors="0">'
        '<testcase classname="example" name="failure">'
        '<failure message="controlled failure">'
        "C:&#92;Users&#92;runneradmin&#92;AppData C:/Users/runneradmin/x"
        "</failure></testcase></testsuite>",
        encoding="utf-8",
    )
    audit = safety.audit_artifacts(transcript, junit, gate_transcript)
    assert audit.violations == []

    person = runner_forms.replace("runneradmin", "person").replace("RUNNERADMIN", "person")
    transcript.write_text(person, encoding="utf-8")
    audit = safety.audit_artifacts(transcript, junit, gate_transcript)
    assert "PERSONAL_PATH artifact=transcript id=windows-user-path" in audit.violations
    assert "PERSONAL_PATH artifact=transcript id=macos-user-path" in audit.violations


def test_artifact_scanner_missing_empty_and_malformed_inputs_fail(tmp_path: Path) -> None:
    transcript, junit, gate_transcript = _safe_artifacts(tmp_path)
    transcript.write_bytes(b"")
    junit.write_text("<testsuite>", encoding="utf-8")
    missing = tmp_path / "missing-gate.txt"
    audit = safety.audit_artifacts(transcript, junit, missing)
    assert "ARTIFACT_EMPTY artifact=transcript" in audit.violations
    assert _has_safety(audit, "JUNIT_XML_UNREADABLE")
    assert _has_safety(audit, "ARTIFACT_UNREADABLE artifact=gate-transcript")
    assert gate_transcript.exists()


def _has_safety(audit: safety.SafetyAudit, prefix: str) -> bool:
    return any(violation.startswith(prefix) for violation in audit.violations)


def test_workflow_upload_is_blocked_unless_artifact_scanner_passed() -> None:
    workflow = Path(".github/workflows/clipboard-windows.yml").read_text(encoding="utf-8")
    scan = workflow.index("tests/support/b103_artifact_safety.py")
    upload = workflow.index("uses: actions/upload-artifact@v4")
    assert scan < upload
    assert "if: always() && steps.artifact_safety.outcome == 'success'" in workflow
    assert "if-no-files-found: error" in workflow


def test_gate_does_not_import_test_modules_to_build_manifest() -> None:
    import ast

    source = Path(gate.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert not any(name.startswith("tests.test_") for name in imports)
    assert json.loads(gate.DEFAULT_MANIFEST.read_text(encoding="utf-8"))["counts"]["testcases"] == 256
