"""Run the Inc 9b mutant groups sequentially in fresh remote tree copies."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = Path.home() / "work" / "zq-m9b"
sys.path.insert(0, str(ROOT))
from mutation_spec import (  # noqa: E402
    EXPECTED_GROUP_ARMS,
    GROUPS,
    MISSING,
    MutationError,
    apply_group,
    group_nodes,
    mutations_for,
    mutate_file,
    validate_manifest,
)

PYTHON = Path.home() / "miniconda3" / "envs" / "s19ci" / "bin" / "python"
ARCHIVE = ROOT / "source.tar"
OUT = ROOT / "out"
EXPECTED_COMMIT = "2e80b0d68370c0d4c3eebbc5cf6e325b712769d0"


def now():
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()


def sanitize(text):
    isolated = ROOT / "home" / os.environ["RUNNER_HOME_NAME"]
    replacements = (
        (str(isolated), "<runner-home>"),
        (str(Path.home()), "~"),
        (Path.home().name, "<user>"),
        (socket.gethostname(), "<host>"),
    )
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(sanitize(text), encoding="utf-8", newline="\n")


def load_one():
    return float(Path("/proc/loadavg").read_text().split()[0])


def uptime():
    return subprocess.run(["uptime"], check=True, capture_output=True, text=True).stdout.strip()


def other_test_jobs():
    result = subprocess.run(
        ["ps", "-eo", "pid=,args="], check=True, capture_output=True, text=True
    )
    hits = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pid_text, _, args = stripped.partition(" ")
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        if pid in (os.getpid(), os.getppid()):
            continue
        is_pytest = bool(re.search(r"(^|\s)python\S*\s+-m\s+pytest(\s|$)", args))
        is_q9b = bool(re.search(r"(^|/)(run|resume)_q9b\.sh(\s|$)", args))
        if is_pytest or is_q9b:
            hits.append(pid)
    return hits


class HostUnavailable(RuntimeError):
    pass


def require_quiet_exclusive(group_id, phase):
    deadline = time.monotonic() + 1200
    while True:
        load = load_one()
        jobs = other_test_jobs()
        if load < 1.0 and not jobs:
            return {"load_one": load, "other_test_jobs": 0, "uptime": uptime()}
        if time.monotonic() >= deadline:
            raise HostUnavailable(
                f"host preflight did not clear for {group_id} {phase}: "
                f"load={load:.2f} other_test_jobs={len(jobs)}; no test verdict issued"
            )
        time.sleep(15)


def isolated_environment():
    # HT-11: the isolated HOME basename arrives only through this environment variable.
    name = os.environ["RUNNER_HOME_NAME"]
    home = ROOT / "home" / name
    for path in (
        home,
        ROOT / "x" / "config",
        ROOT / "x" / "cache",
        ROOT / "x" / "data",
        ROOT / "tmp",
    ):
        path.mkdir(parents=True, exist_ok=True)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(ROOT / "x" / "config"),
        "XDG_CACHE_HOME": str(ROOT / "x" / "cache"),
        "XDG_DATA_HOME": str(ROOT / "x" / "data"),
        "TMPDIR": str(ROOT / "tmp"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "LANG": "C.UTF-8",
        "PYTHONPATH": ".",
    }


def import_location(tree, env):
    command = [
        "/usr/bin/env",
        "-i",
        *[f"{key}={value}" for key, value in env.items()],
        str(PYTHON),
        "-c",
        "import s19_app; print(s19_app.__file__)",
    ]
    result = subprocess.run(
        command,
        cwd=tree,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"import probe failed: {result.stdout}{result.stderr}")
    location = result.stdout.strip()
    expected = str(tree / "s19_app" / "__init__.py")
    if location != expected:
        raise RuntimeError(f"wrong import location: {location!r} != {expected!r}")
    return location


def terminate_recorded_session(process, sid):
    events = []
    if process.poll() is not None:
        return events
    os.killpg(sid, signal.SIGTERM)
    events.append(f"SIGTERM recorded SID {sid}")
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(sid, signal.SIGKILL)
        events.append(f"SIGKILL recorded SID {sid}")
        process.wait(timeout=5)
    return events


def run_pytest(tree, group_id, phase, nodes, preflight):
    transcript = OUT / f"{group_id}-{phase}.txt"
    xml_path = ROOT / "groups" / group_id / f"{phase}.xml"
    raw_path = ROOT / "groups" / group_id / f"{phase}.raw.txt"
    env = isolated_environment()
    location = import_location(tree, env)
    command = [
        "/usr/bin/env",
        "-i",
        *[f"{key}={value}" for key, value in env.items()],
        "timeout",
        "300",
        str(PYTHON),
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-n",
        "0",
        "-q",
        f"--junitxml={xml_path}",
        *nodes,
    ]
    with raw_path.open("wb") as handle:
        process = subprocess.Popen(
            command,
            cwd=tree,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        sid = os.getsid(process.pid)
        current = {
            "group": group_id,
            "phase": phase,
            "pid": process.pid,
            "sid": sid,
            "started": now(),
        }
        write_text(ROOT / "current.json", json.dumps(current, indent=2) + "\n")
        cleanup_events = []
        try:
            rc = process.wait(timeout=315)
        except subprocess.TimeoutExpired:
            cleanup_events = terminate_recorded_session(process, sid)
            rc = 124
    header = [
        f"DATE {now()}",
        f"GROUP {group_id}",
        f"PHASE {phase}",
        f"COMMIT {EXPECTED_COMMIT}",
        f"UPTIME {preflight['uptime']}",
        f"LOAD_ONE {preflight['load_one']:.2f}",
        f"OTHER_TEST_JOBS {preflight['other_test_jobs']}",
        f"RESOLVED_NODE_INPUTS {len(nodes)}",
        f"S19_APP_FILE {location}",
        f"PID {process.pid}",
        f"SID {sid}",
        "TIMEOUT_S 300",
        "XDIST_N 0",
    ]
    body = raw_path.read_text(encoding="utf-8", errors="replace")
    tail = [f"EXIT_CODE {rc}"]
    tail.extend(f"CLEANUP {event}" for event in cleanup_events)
    write_text(transcript, "\n".join(header) + "\n" + body + "\n".join(tail) + "\n")
    return {
        "rc": rc,
        "xml": xml_path,
        "transcript": transcript.name,
        "pid": process.pid,
        "sid": sid,
        "cleanup": cleanup_events,
    }


def junit_node(case):
    classname = case.attrib.get("classname", "")
    name = case.attrib.get("name", "")
    if not classname or not name:
        return ""
    return classname.replace(".", "/") + ".py::" + name


def first_line(text):
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:500]
    return ""


def classify_xml(xml_path, expected_nodes):
    if not Path(xml_path).exists():
        return None, "missing JUnit XML"
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError) as exc:
        return None, f"unreadable JUnit XML: {exc}"
    cases = list(root.iter("testcase"))
    if not cases:
        return None, "empty test selection"
    by_node = {}
    duplicates = []
    for case in cases:
        node = junit_node(case)
        if node in by_node:
            duplicates.append(node)
        by_node[node] = case
    outcomes = {}
    for expected in expected_nodes:
        if expected not in by_node:
            outcomes[expected] = {
                "verdict": "BAD",
                "detail": "node not resolved in JUnit XML",
            }
            continue
        case = by_node[expected]
        failures = list(case.findall("failure"))
        errors = list(case.findall("error"))
        skipped = list(case.findall("skipped"))
        if errors:
            text = "\n".join((item.text or "") for item in errors)
            outcomes[expected] = {"verdict": "CRASH", "detail": first_line(text) or "pytest error"}
        elif failures:
            text = "\n".join((item.text or "") for item in failures)
            message = "\n".join(item.attrib.get("message", "") for item in failures)
            assertion = re.search(r"(^|\n)\s*(E\s+)?(AssertionError|Failed)(:|\n|$)", text)
            assertion = assertion or re.search(r"(^|\n)\s*(AssertionError|Failed):", message)
            verdict = "KILLED" if assertion else "CRASH"
            outcomes[expected] = {
                "verdict": verdict,
                "detail": first_line(message) or first_line(text) or "pytest failure",
            }
        elif skipped:
            outcomes[expected] = {"verdict": "CRASH", "detail": "selected node skipped"}
        else:
            outcomes[expected] = {"verdict": "SURVIVED", "detail": "selected node stayed green"}
    extras = sorted(set(by_node) - set(expected_nodes))
    if duplicates or extras:
        for expected in expected_nodes:
            outcomes[expected] = {
                "verdict": "BAD",
                "detail": f"selection mismatch: duplicates={len(duplicates)} extras={len(extras)}",
            }
    return outcomes, ""


def baseline_outcomes(xml_path, expected_nodes):
    outcomes, error = classify_xml(xml_path, expected_nodes)
    if outcomes is None:
        return None, error
    result = {}
    for node, outcome in outcomes.items():
        if outcome["verdict"] == "SURVIVED":
            result[node] = {"verdict": "PASS", "detail": "baseline green"}
        elif outcome["verdict"] == "KILLED":
            result[node] = {"verdict": "FAIL", "detail": outcome["detail"]}
        else:
            result[node] = {"verdict": outcome["verdict"], "detail": outcome["detail"]}
    return result, ""


def aggregate(outcomes):
    verdicts = [item["verdict"] for item in outcomes]
    if "BAD" in verdicts:
        return "BAD"
    if "CRASH" in verdicts:
        return "CRASH"
    if "KILLED" in verdicts:
        return "KILLED"
    return "SURVIVED"


def make_control_results(group_id, outcomes):
    results = []
    for item in GROUPS[group_id]["controls"]:
        arms = [
            {"node": node, **outcomes[node]}
            for node in item["nodes"]
        ]
        results.append({**item, "nodes": list(item["nodes"]), "verdict": aggregate(arms), "arms": arms})
    return results


def selftests():
    checks = []

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append((name, "PASS"))

    try:
        mutate_file(b"alpha\n", [("absent-anchor", "x")])
    except MutationError:
        check("ZERO_APPLICATION_REJECTED", True)
    else:
        check("ZERO_APPLICATION_REJECTED", False)

    node = "tests/synthetic.py::test_negative_control"
    green = (
        "<testsuite tests='1'><testcase classname='tests.synthetic' "
        "name='test_negative_control'/></testsuite>"
    )
    assertion = (
        "<testsuite tests='1'><testcase classname='tests.synthetic' "
        "name='test_negative_control'><failure message='AssertionError: deliberate'>"
        "E   AssertionError: deliberate</failure></testcase></testsuite>"
    )
    crash = (
        "<testsuite tests='1'><testcase classname='tests.synthetic' "
        "name='test_negative_control'><failure message='RuntimeError: unintended'>"
        "RuntimeError: unintended</failure></testcase></testsuite>"
    )
    empty = "<testsuite tests='0'></testsuite>"
    fixtures = {
        "green": green,
        "assertion": assertion,
        "crash": crash,
        "empty": empty,
    }
    for name, content in fixtures.items():
        path = ROOT / f"selftest-{name}.xml"
        path.write_text(content, encoding="utf-8")
    outcomes, _ = classify_xml(ROOT / "selftest-assertion.xml", [node])
    check("ASSERTION_NEGATIVE_CONTROL_KILLED", outcomes[node]["verdict"] == "KILLED")
    outcomes, _ = classify_xml(ROOT / "selftest-crash.xml", [node])
    check("UNINTENDED_EXCEPTION_IS_CRASH", outcomes[node]["verdict"] == "CRASH")
    outcomes, _ = classify_xml(ROOT / "selftest-green.xml", [node])
    check("GREEN_MUTANT_IS_SURVIVED", outcomes[node]["verdict"] == "SURVIVED")
    outcomes, error = classify_xml(ROOT / "selftest-empty.xml", [node])
    check("EMPTY_SELECTION_IS_BAD", outcomes is None and error == "empty test selection")
    write_text(
        OUT / "selftest.txt",
        "M9B HARNESS SELFTESTS\n" + "".join(f"{name} {verdict}\n" for name, verdict in checks),
    )


def extract_fresh(destination):
    if destination.exists():
        raise RuntimeError(f"refusing to reuse existing copy: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(ARCHIVE) as archive:
        archive.extractall(destination, filter="data")


def check_anchors(pristine):
    lines = [f"COMMIT {EXPECTED_COMMIT}"]
    for group_id in GROUPS:
        _, receipts = mutations_for(pristine, group_id)
        count = sum(sum(counts) for counts in receipts.values())
        lines.append(f"{group_id} ANCHORS_OK replacements={count}")
    write_text(OUT / "anchor-check.txt", "\n".join(lines) + "\n")


def run_group(group_id):
    nodes = group_nodes(group_id)
    if len(nodes) != EXPECTED_GROUP_ARMS[group_id] or not nodes:
        raise RuntimeError(f"bad manifest arm count for {group_id}")
    group_root = ROOT / "groups" / group_id
    tree = group_root / "tree"
    extract_fresh(tree)
    result = {
        "group": group_id,
        "commit": EXPECTED_COMMIT,
        "expected_arms": len(nodes),
        "nodes": list(nodes),
    }
    preflight = require_quiet_exclusive(group_id, "baseline")
    baseline_run = run_pytest(tree, group_id, "baseline", nodes, preflight)
    baseline, baseline_error = baseline_outcomes(baseline_run["xml"], nodes)
    result["baseline"] = {
        "rc": baseline_run["rc"],
        "transcript": baseline_run["transcript"],
        "preflight": preflight,
        "arms": baseline,
        "error": baseline_error,
    }
    if baseline is None or baseline_run["rc"] != 0 or any(
        item["verdict"] != "PASS" for item in baseline.values()
    ):
        outcomes = {
            node: {"verdict": "BAD", "detail": "baseline was not a complete GREEN selection"}
            for node in nodes
        }
        result["controls"] = make_control_results(group_id, outcomes)
        return result
    receipts = apply_group(tree, group_id)
    result["mutation_receipts"] = receipts
    preflight = require_quiet_exclusive(group_id, "mutant")
    mutant_run = run_pytest(tree, group_id, "mutant", nodes, preflight)
    outcomes, selection_error = classify_xml(mutant_run["xml"], nodes)
    if outcomes is None:
        verdict = "BAD" if selection_error == "empty test selection" else "CRASH"
        outcomes = {
            node: {"verdict": verdict, "detail": selection_error}
            for node in nodes
        }
    result["mutant"] = {
        "rc": mutant_run["rc"],
        "transcript": mutant_run["transcript"],
        "preflight": preflight,
        "selection_error": selection_error,
    }
    result["controls"] = make_control_results(group_id, outcomes)
    return result


def write_summary(results):
    rows = ["group\tcontrol\trequirement\tnode\tverdict\tdetail"]
    for result in results:
        for control_result in result["controls"]:
            for arm in control_result["arms"]:
                detail = arm["detail"].replace("\t", " ").replace("\n", " ")
                rows.append(
                    f"{result['group']}\t{control_result['id']}\t{control_result['requirement']}"
                    f"\t{arm['node']}\t{arm['verdict']}\t{detail}"
                )
    write_text(OUT / "summary.tsv", "\n".join(rows) + "\n")
    payload = {
        "commit": EXPECTED_COMMIT,
        "runnable_controls": 26,
        "groups": 23,
        "resolved_arms": 43,
        "missing": [
            {"id": item[0], "requirement": item[1], "reason": item[2], "verdict": "MISSING"}
            for item in MISSING
        ],
        "results": results,
    }
    write_text(OUT / "results.json", json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def main():
    validate_manifest()
    if not ARCHIVE.exists():
        raise RuntimeError("source archive is absent")
    if OUT.exists():
        raise RuntimeError("output directory already exists; refusing to overwrite evidence")
    OUT.mkdir(parents=True)
    pristine = ROOT / "pristine"
    extract_fresh(pristine)
    check_anchors(pristine)
    selftests()
    results = []
    for group_id in GROUPS:
        try:
            result = run_group(group_id)
        except HostUnavailable:
            write_text(OUT / "HOST-ABORT.txt", f"DATE {now()}\nGROUP {group_id}\nNO_VERDICT\n")
            raise
        except (MutationError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
            verdict = "BAD" if isinstance(exc, MutationError) else "CRASH"
            outcomes = {
                node: {"verdict": verdict, "detail": f"driver failure: {exc}"}
                for node in group_nodes(group_id)
            }
            result = {
                "group": group_id,
                "commit": EXPECTED_COMMIT,
                "expected_arms": len(group_nodes(group_id)),
                "nodes": list(group_nodes(group_id)),
                "controls": make_control_results(group_id, outcomes),
                "driver_error": str(exc),
            }
        results.append(result)
        write_summary(results)
        counts = {}
        for control_result in result["controls"]:
            counts[control_result["verdict"]] = counts.get(control_result["verdict"], 0) + 1
        print(f"GROUP_DONE {group_id} {counts}", flush=True)
    write_summary(results)
    digest = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    write_text(OUT / "DONE", f"DATE {now()}\nCOMMIT {EXPECTED_COMMIT}\nARCHIVE_SHA256 {digest}\nGROUPS {len(results)}\n")


if __name__ == "__main__":
    main()
