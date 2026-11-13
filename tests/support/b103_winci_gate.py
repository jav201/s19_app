"""Audit the complete WinCI JUnit population against a static manifest."""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_MANIFEST = Path(__file__).with_name("b103_winci_manifest.json")
EXPECTED_AT_NODES = 28
AT_TEST_PREFIX = "test_copy_paste_acceptance_cell[AT-I1b-"
MANUAL_TEST = "test_manual_windows_terminal_operator_acceptance"
MATRIX_CLASS = "test_b103_copy_paste_matrix"
EXPECTED_FILES = frozenset(
    {
        "tests/test_b103_clipboard_windows.py",
        "tests/test_b103_clipboard_matrix.py",
        "tests/test_b103_copy_views.py",
        "tests/test_b103_clipboard_tail.py",
        "tests/test_b103_copy_quit_dialog.py",
        "tests/test_b103_copy_paste_matrix.py",
    }
)
AT_ID = re.compile(r"^AT-I1b-([1-7])/([1-4])-T([12])-P([12])$")


class ManifestError(ValueError):
    """The independent WinCI oracle is missing, malformed or inconsistent."""


@dataclass(frozen=True)
class Obligation:
    requirement: str
    nodeid: str
    internal_arms: tuple[str, ...]
    family: str
    at_id: str | None = None
    at_partition: str | None = None


@dataclass(frozen=True)
class SkipRule:
    nodeid: str
    category: str
    reason: str
    manual_id: str | None = None


@dataclass(frozen=True)
class Manifest:
    expected_nodeids: tuple[str, ...]
    expected_set: frozenset[str]
    obligations: tuple[Obligation, ...]
    skip_rules: dict[str, SkipRule]
    class_to_file: dict[str, str]
    classname_for_file: dict[str, str]
    at_nodeids: frozenset[str]
    at_partitions: dict[str, frozenset[str]]
    counts: dict[str, int]


@dataclass
class Audit:
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    obligations_passed: int = 0
    at_passed: int = 0
    at_p1_passed: int = 0
    at_p2_passed: int = 0
    allowed_skips: list[tuple[str, str]] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def _text(value: Any, label: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{label} must be a non-empty string")
    return value


def _node_name(test: dict[str, Any], case_id: str | None) -> str:
    name = _text(test.get("name"), "test name")
    _require(name.startswith("test_"), f"invalid test name: {name}")
    return f"{name}[{case_id}]" if case_id is not None else name


def _skip_rule(nodeid: str, raw: Any) -> SkipRule:
    _require(isinstance(raw, dict), f"skip must be an object: {nodeid}")
    category = _text(raw.get("category"), f"skip category: {nodeid}")
    _require(category in {"linux-only", "legacy-linux-h", "manual"}, f"skip category: {category}")
    reason = _text(raw.get("reason"), f"skip reason: {nodeid}")
    manual_id = raw.get("manual_id")
    if category == "manual":
        _require(manual_id == "AT-I1b-8", "the only manual skip is AT-I1b-8")
        _require("AT-I1b-8" in reason and "manual" in reason.lower(), "invalid manual reason")
    else:
        _require(manual_id is None, f"unexpected manual id: {nodeid}")
    return SkipRule(nodeid, category, reason, manual_id)


def load_manifest(path: Path = DEFAULT_MANIFEST) -> Manifest:
    """Load and cross-check the static oracle without importing test modules."""
    with path.open(encoding="utf-8") as stream:
        raw = json.load(stream)
    _require(isinstance(raw, dict) and raw.get("schema_version") == 1, "schema_version")
    raw_counts = raw.get("counts")
    _require(isinstance(raw_counts, dict), "counts must be an object")
    counts: dict[str, int] = {}
    for key, value in raw_counts.items():
        _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0, key)
        counts[key] = value

    files = raw.get("files")
    _require(isinstance(files, list), "files must be a list")
    expected_nodeids: list[str] = []
    obligations: list[Obligation] = []
    skip_rules: dict[str, SkipRule] = {}
    class_to_file: dict[str, str] = {}
    classname_for_file: dict[str, str] = {}
    seen_files: set[str] = set()
    family_counts: Counter[str] = Counter()

    for file_entry in files:
        _require(isinstance(file_entry, dict), "file entry must be an object")
        file_path = _text(file_entry.get("path"), "file path")
        _require(file_path not in seen_files, f"duplicate file: {file_path}")
        seen_files.add(file_path)
        classnames = file_entry.get("junit_classnames")
        _require(isinstance(classnames, list) and classnames, f"classnames: {file_path}")
        for classname_raw in classnames:
            classname = _text(classname_raw, f"classname: {file_path}")
            _require(classname not in class_to_file, f"duplicate classname: {classname}")
            class_to_file[classname] = file_path
        classname_for_file[file_path] = classnames[0]

        tests = file_entry.get("tests")
        _require(isinstance(tests, list) and tests, f"tests: {file_path}")
        file_nodes: list[str] = []
        file_skip = file_entry.get("skip")
        for test in tests:
            _require(isinstance(test, dict), f"test entry: {file_path}")
            raw_ids = test.get("ids")
            if raw_ids is None:
                case_ids: list[str | None] = [None]
            else:
                _require(isinstance(raw_ids, list) and raw_ids, f"ids: {test.get('name')}")
                _require(all(isinstance(item, str) and item for item in raw_ids), f"ids: {test.get('name')}")
                _require(len(set(raw_ids)) == len(raw_ids), f"duplicate ids: {test.get('name')}")
                case_ids = list(raw_ids)
            test_skip = test.get("skip")
            _require(not (file_skip and test_skip), f"nested skip conflict: {test.get('name')}")
            specific_skips = test.get("skips", [])
            _require(isinstance(specific_skips, list), f"skips: {test.get('name')}")
            _require(not (specific_skips and (file_skip or test_skip)), f"skip conflict: {test.get('name')}")

            nodes_for_test: dict[str | None, str] = {}
            for case_id in case_ids:
                nodeid = f"{file_path}::{_node_name(test, case_id)}"
                nodes_for_test[case_id] = nodeid
                file_nodes.append(nodeid)
                if file_skip or test_skip:
                    rule = _skip_rule(nodeid, test_skip or file_skip)
                    _require(nodeid not in skip_rules, f"duplicate skip: {nodeid}")
                    skip_rules[nodeid] = rule
            for raw_skip in specific_skips:
                _require(isinstance(raw_skip, dict), f"skip entry: {test.get('name')}")
                case_id = raw_skip.get("id")
                _require(case_id in nodes_for_test, f"skip id absent: {case_id}")
                nodeid = nodes_for_test[case_id]
                rule = _skip_rule(nodeid, raw_skip)
                _require(nodeid not in skip_rules, f"duplicate skip: {nodeid}")
                skip_rules[nodeid] = rule

            single = test.get("obligation")
            multiple = test.get("obligations", [])
            _require(isinstance(multiple, list), f"obligations: {test.get('name')}")
            _require(not (single and multiple), f"obligation conflict: {test.get('name')}")
            if single is not None:
                _require(case_ids == [None], f"single obligation needs one node: {test.get('name')}")
                multiple = [dict(single, id=None)]
            for raw_obligation in multiple:
                _require(isinstance(raw_obligation, dict), f"obligation: {test.get('name')}")
                case_id = raw_obligation.get("id")
                _require(case_id in nodes_for_test, f"obligation id absent: {case_id}")
                requirement = _text(raw_obligation.get("requirement"), "requirement")
                arms = raw_obligation.get("internal_arms")
                _require(isinstance(arms, list) and arms, f"internal arms: {requirement}")
                _require(all(isinstance(arm, str) and arm for arm in arms), f"internal arms: {requirement}")
                _require(len(set(arms)) == len(arms), f"duplicate internal arms: {requirement}")
                partition = raw_obligation.get("at_partition")
                at_id = case_id if requirement.startswith("AT-I1b-") else None
                if at_id is None:
                    _require(partition is None, f"unexpected AT partition: {requirement}")
                    family = "at"  # replaced below; keeps family values centralized
                else:
                    match = AT_ID.fullmatch(at_id)
                    _require(match is not None, f"non-canonical AT id: {at_id}")
                    source, cell, target, route = match.groups()
                    expected_cell = (int(target) - 1) * 2 + int(route)
                    _require(int(cell) == expected_cell, f"AT cell/target/route mismatch: {at_id}")
                    _require(requirement == f"AT-I1b-{source}/{cell}", f"AT requirement mismatch: {at_id}")
                    _require(partition == f"P{route}", f"AT partition mismatch: {at_id}")
                    family = "at"
                if file_path == "tests/test_b103_copy_views.py":
                    family = "view"
                elif file_path == "tests/test_b103_clipboard_tail.py":
                    family = "tail"
                elif file_path == "tests/test_b103_copy_quit_dialog.py":
                    family = "quit"
                elif at_id is not None:
                    family = "at"
                else:
                    raise ManifestError(f"obligation outside census families: {requirement}")
                family_counts[family] += 1
                obligations.append(
                    Obligation(
                        requirement=requirement,
                        nodeid=nodes_for_test[case_id],
                        internal_arms=tuple(arms),
                        family=family,
                        at_id=at_id,
                        at_partition=partition,
                    )
                )
        _require(len(file_nodes) == file_entry.get("expected_count"), f"file count: {file_path}")
        expected_nodeids.extend(file_nodes)

    _require(seen_files == EXPECTED_FILES, "the six canonical files are required")
    expected_set = frozenset(expected_nodeids)
    _require(len(expected_nodeids) == len(expected_set), "duplicate expected nodeid")
    _require(len(obligations) == len({item.requirement for item in obligations}), "duplicate requirement")
    _require(len(obligations) == len({item.nodeid for item in obligations}), "duplicate obligation nodeid")
    _require(all(item.nodeid in expected_set for item in obligations), "obligation outside population")
    _require(not any(item.nodeid in skip_rules for item in obligations), "obligation may not be skipped")

    at_obligations = tuple(item for item in obligations if item.family == "at")
    at_nodeids = frozenset(item.nodeid for item in at_obligations)
    raw_partitions = raw.get("at_partitions")
    _require(isinstance(raw_partitions, dict), "at_partitions")
    at_partitions: dict[str, frozenset[str]] = {}
    for partition in ("P1", "P2"):
        values = raw_partitions.get(partition)
        _require(isinstance(values, list) and all(isinstance(item, str) for item in values), partition)
        at_partitions[partition] = frozenset(values)
        actual = frozenset(item.at_id for item in at_obligations if item.at_partition == partition)
        _require(at_partitions[partition] == actual, f"AT partition mismatch: {partition}")
    _require(len(at_nodeids) == EXPECTED_AT_NODES, "AT census")

    manual_rules = [rule for rule in skip_rules.values() if rule.category == "manual"]
    _require(len(manual_rules) == 1, "exactly one manual skip")
    _require(
        manual_rules[0].nodeid == f"tests/test_b103_copy_paste_matrix.py::{MANUAL_TEST}",
        "manual nodeid",
    )
    computed = {
        "testcases": len(expected_nodeids),
        "obligations": len(obligations),
        "view_obligations": family_counts["view"],
        "tail_obligations": family_counts["tail"],
        "quit_obligations": family_counts["quit"],
        "at_obligations": len(at_obligations),
        "at_p1": len(at_partitions["P1"]),
        "at_p2": len(at_partitions["P2"]),
        "linux_only_skips": sum(rule.category == "linux-only" for rule in skip_rules.values()),
        "legacy_linux_h_skips": sum(rule.category == "legacy-linux-h" for rule in skip_rules.values()),
        "manual_skips": len(manual_rules),
        "winci_passed": len(expected_nodeids) - len(skip_rules),
        "winci_skipped": len(skip_rules),
    }
    for key, value in computed.items():
        _require(counts.get(key) == value, f"count mismatch {key}: declared={counts.get(key)} actual={value}")
    _require(computed["testcases"] == 259, "WinCI population must contain 259 testcases")
    _require(computed["obligations"] == 108, "WinCI must contain 108 obligations")
    _require(computed["view_obligations"] == 46, "views census")
    _require(computed["tail_obligations"] == 25, "tail census")
    _require(computed["quit_obligations"] == 9, "quit census")
    _require(computed["linux_only_skips"] == 6, "exactly six Linux-only skips")
    return Manifest(
        expected_nodeids=tuple(expected_nodeids),
        expected_set=expected_set,
        obligations=tuple(obligations),
        skip_rules=skip_rules,
        class_to_file=class_to_file,
        classname_for_file=classname_for_file,
        at_nodeids=at_nodeids,
        at_partitions=at_partitions,
        counts=computed,
    )


def _nodeid(testcase: ET.Element, class_to_file: dict[str, str]) -> str:
    classname = testcase.get("classname", "")
    name = testcase.get("name", "")
    file_path = class_to_file.get(classname)
    if file_path is not None:
        return f"{file_path}::{name}"
    return f"{classname}::{name}" if classname else name


def _nonnegative(raw: str | None) -> int:
    if raw is None:
        return -1
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return -1
    return value if value >= 0 else -1


def _declared_count(root: ET.Element, attribute: str) -> int:
    if root.tag == "testsuite":
        return _nonnegative(root.get(attribute))
    suites = [child for child in root if child.tag == "testsuite"]
    if not suites:
        return -1
    values = [_nonnegative(suite.get(attribute)) for suite in suites]
    return sum(values) if all(value >= 0 for value in values) else -1


def _reconcile_count(audit: Audit, root: ET.Element, attribute: str, actual: int) -> None:
    declared = _declared_count(root, attribute)
    if declared != actual:
        audit.violations.append(f"JUNIT_{attribute.upper()}_COUNT declared={declared} actual={actual}")
    if root.tag == "testsuites" and attribute in root.attrib:
        aggregate = _nonnegative(root.get(attribute))
        if aggregate != actual:
            audit.violations.append(
                f"JUNIT_ROOT_{attribute.upper()}_COUNT declared={aggregate} actual={actual}"
            )


def audit_junit(
    path: Path,
    pytest_exit: int,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> Audit:
    """Audit every expected node, outcome, skip and declared JUnit count."""
    manifest = load_manifest(manifest_path)
    root = ET.parse(path).getroot()
    audit = Audit()
    if pytest_exit:
        audit.violations.append(f"PYTEST_EXIT code={pytest_exit}")

    testcases = list(root.iter("testcase"))
    audit.total = len(testcases)
    if not testcases:
        audit.violations.append("JUNIT_EMPTY")

    observed: Counter[str] = Counter()
    outcomes: dict[str, str] = {}
    for testcase in testcases:
        nodeid = _nodeid(testcase, manifest.class_to_file)
        observed[nodeid] += 1
        failed = testcase.find("failure") is not None
        errored = testcase.find("error") is not None
        skipped = testcase.find("skipped")
        outcome_count = int(failed) + int(errored) + int(skipped is not None)
        if outcome_count > 1:
            audit.violations.append(f"OUTCOME_AMBIGUOUS node={nodeid}")
        if failed:
            audit.failed += 1
            outcome = "failed"
            audit.violations.append(f"FAILURE node={nodeid}")
        elif errored:
            audit.errors += 1
            outcome = "error"
            audit.violations.append(f"ERROR node={nodeid}")
        elif skipped is not None:
            audit.skipped += 1
            outcome = "skipped"
            reason = skipped.get("message") or skipped.text or ""
            rule = manifest.skip_rules.get(nodeid)
            if rule is None:
                audit.violations.append(f"DISALLOWED_SKIP node={nodeid}")
            elif reason != rule.reason:
                audit.violations.append(f"SKIP_REASON node={nodeid}")
            else:
                audit.allowed_skips.append((rule.category, nodeid))
        else:
            audit.passed += 1
            outcome = "passed"
            if nodeid in manifest.skip_rules:
                audit.violations.append(f"EXPECTED_SKIP node={nodeid}")
        outcomes.setdefault(nodeid, outcome)

    for nodeid, count in observed.items():
        if count != 1:
            audit.violations.append(f"DUPLICATE_NODEID node={nodeid} count={count}")
    missing = manifest.expected_set - frozenset(observed)
    unexpected = frozenset(observed) - manifest.expected_set
    for nodeid in sorted(missing):
        audit.violations.append(f"MISSING_NODE node={nodeid}")
    for nodeid in sorted(unexpected):
        audit.violations.append(f"UNEXPECTED_NODE node={nodeid}")
    if missing or unexpected:
        audit.violations.append(
            f"POPULATION_CENSUS expected={len(manifest.expected_set)} unique={len(observed)}"
        )

    at_present = manifest.at_nodeids & frozenset(observed)
    if at_present != manifest.at_nodeids:
        audit.violations.append(f"AT_CENSUS expected=28 unique={len(at_present)}")
    at_passed_partitions = {"P1": set(), "P2": set()}
    for obligation in manifest.obligations:
        if outcomes.get(obligation.nodeid) != "passed":
            audit.violations.append(
                f"REQUIRED_NOT_PASSED requirement={obligation.requirement} "
                f"node={obligation.nodeid} outcome={outcomes.get(obligation.nodeid, 'missing')}"
            )
            continue
        audit.obligations_passed += 1
        if obligation.at_id is not None:
            audit.at_passed += 1
            at_passed_partitions[obligation.at_partition or ""].add(obligation.at_id)
    audit.at_p1_passed = len(at_passed_partitions["P1"])
    audit.at_p2_passed = len(at_passed_partitions["P2"])
    for partition in ("P1", "P2"):
        expected = manifest.at_partitions[partition]
        actual = at_passed_partitions[partition]
        if actual != expected:
            audit.violations.append(
                f"AT_{partition}_PASSED expected={len(expected)} actual={len(actual)}"
            )

    _reconcile_count(audit, root, "tests", audit.total)
    _reconcile_count(audit, root, "skipped", audit.skipped)
    _reconcile_count(audit, root, "failures", audit.failed)
    _reconcile_count(audit, root, "errors", audit.errors)
    return audit


def _print_audit(audit: Audit, manifest: Manifest) -> None:
    print(
        "WINCI_GATE "
        f"tests={audit.total} passed={audit.passed} failed={audit.failed} "
        f"errors={audit.errors} skipped={audit.skipped} "
        f"obligations_passed={audit.obligations_passed}/{len(manifest.obligations)} "
        f"at_passed={audit.at_passed}/28 "
        f"at_p1={audit.at_p1_passed}/14 at_p2={audit.at_p2_passed}/14"
    )
    for category, nodeid in audit.allowed_skips:
        print(f"ALLOWED_SKIP category={category} node={nodeid}")
    for violation in audit.violations:
        print(f"VIOLATION {violation}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit-xml", type=Path)
    parser.add_argument("--pytest-exit", type=int)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--validate-manifest", action="store_true")
    args = parser.parse_args(argv)
    if args.validate_manifest:
        try:
            manifest = load_manifest(args.manifest)
        except (OSError, ValueError) as exc:
            print(f"VIOLATION MANIFEST_UNREADABLE error={type(exc).__name__}")
            return args.pytest_exit or 2
        print(
            "WINCI_MANIFEST_OK "
            f"tests={manifest.counts['testcases']} obligations={manifest.counts['obligations']} "
            f"at_p1={manifest.counts['at_p1']} at_p2={manifest.counts['at_p2']}"
        )
        return args.pytest_exit or 0
    if args.junit_xml is None or args.pytest_exit is None:
        parser.error("--junit-xml and --pytest-exit are required unless --validate-manifest is used")
    try:
        audit = audit_junit(args.junit_xml, args.pytest_exit, args.manifest)
        manifest = load_manifest(args.manifest)
    except (OSError, ET.ParseError, ValueError) as exc:
        print(f"VIOLATION JUNIT_UNREADABLE error={type(exc).__name__}")
        return args.pytest_exit or 2

    _print_audit(audit, manifest)
    exit_code = args.pytest_exit or (1 if audit.violations else 0)
    print(
        f"WINCI_GATE_RESULT {'PASS' if exit_code == 0 else 'FAIL'} "
        f"violations={len(audit.violations)} pytest_exit={args.pytest_exit} "
        f"gate_exit={exit_code}"
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
