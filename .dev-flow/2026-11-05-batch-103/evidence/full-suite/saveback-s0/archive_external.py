from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime
from pathlib import Path
import re
import xml.etree.ElementTree as ET

def redact(text: str, repo: Path, runtime: Path) -> str:
    home = Path.home().resolve()
    for path, label in ((repo, "[WORKTREE]"), (runtime, "[RUNTIME]"), (home, "[USER_HOME]")):
        for value in dict.fromkeys((str(path), path.as_posix(), str(path).replace("\\", "\\\\"))):
            text = text.replace(value, label)
    text = text.replace(home.name, "[ACCOUNT]")
    text = re.sub(r"\s+hostname=\"[^\"]*\"", "", text)
    text = re.sub(r"pytest-of-[^/\\\s]+", "pytest-tmp", text)
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def case_nodeid(case: ET.Element) -> str:
    classname = case.attrib["classname"].replace(".", "/")
    return f"{classname}.py::{case.attrib['name']}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--nodes", nargs="*")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    def clean(text: str) -> str:
        text = redact(text, args.repo.resolve(), args.runtime.resolve())
        for path in (args.junit.parent.resolve(), args.log.parent.resolve()):
            for value in dict.fromkeys((str(path), path.as_posix(), str(path).replace("\\", "\\\\"))):
                text = text.replace(value, "[EVIDENCE_SOURCE]")
        return text

    tree = ET.parse(args.junit)
    source_suite = tree.getroot()
    cases = list(source_suite.iter("testcase"))
    if args.nodes is not None:
        selected = {node: next((case for case in cases if case_nodeid(case) == node), None) for node in args.nodes}
        missing = [node for node, case in selected.items() if case is None]
        if missing:
            raise SystemExit(f"nodes absent from source JUnit: {missing}")
        cases = [selected[node] for node in args.nodes if selected[node] is not None]
    suite = ET.Element("testsuite")
    for key in ("name", "timestamp"):
        if key in source_suite.attrib:
            suite.set(key, source_suite.attrib[key])
    suite.set("tests", str(len(cases)))
    suite.set("failures", str(sum(case.find("failure") is not None for case in cases)))
    suite.set("errors", str(sum(case.find("error") is not None for case in cases)))
    suite.set("skipped", str(sum(case.find("skipped") is not None for case in cases)))
    suite.set("time", f"{sum(float(case.attrib.get('time', '0')) for case in cases):.3f}")
    for case in cases:
        suite.append(deepcopy(case))
    xml = ET.tostring(suite, encoding="unicode", xml_declaration=False)
    (args.out / "junit.xml").write_text(clean(xml) + "\n", encoding="utf-8", newline="\n")

    log_text = args.log.read_bytes().decode("utf-8", errors="replace")
    if args.nodes:
        lines = log_text.splitlines()
        excerpts = []
        for node in args.nodes:
            function = node.rsplit("::", 1)[-1].split("[", 1)[0]
            starts = [
                index for index, line in enumerate(lines)
                if function in line and line.strip("_ ") != line and set(line.strip()) == {"_"}
            ]
            if not starts:
                starts = [index for index, line in enumerate(lines) if function in line and line.startswith("_")]
            if not starts:
                continue
            start = starts[-1]
            end = len(lines)
            for index in range(start + 1, len(lines)):
                line = lines[index]
                if line.startswith("_") and line.endswith("_") and "test_" in line:
                    end = index
                    break
            excerpts.append("\n".join(lines[start:end]))
        if excerpts:
            log_text = "\n\n".join(excerpts)
    (args.out / "pytest.log").write_text(clean(log_text), encoding="utf-8", newline="\n")
    origin = (
        f"archived={datetime.now().astimezone().isoformat(timespec='seconds')}\n"
        f"commit={args.commit}\nsource_junit=[EVIDENCE_SOURCE]/{args.junit.name}\n"
        f"source_log=[EVIDENCE_SOURCE]/{args.log.name}\n"
        f"selection={'all testcases' if args.nodes is None else str(len(args.nodes)) + ' named testcases'}\n"
        "transformation=UTF-8 decode with replacement where needed; selected JUnit testcases when named; "
        "ANSI removed; account, host, repository and runtime paths redacted\n"
    )
    (args.out / "origin.txt").write_text(origin, encoding="utf-8", newline="\n")
    print(f"archived {len(cases)} cases to {args.out}")


if __name__ == "__main__":
    main()
