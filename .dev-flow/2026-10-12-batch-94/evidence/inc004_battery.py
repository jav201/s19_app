"""Inc-004 mutation battery — batch-94 Issues warnings triage (HLR-012).

Seven arms over the two SOURCE files (``issues_view.py``, ``app.py``) and the
frozen engine constant, each mapped to the minted node(s) it must turn RED.
One clean-tree baseline run of the three minted nodes precedes the arms; every
arm restores the mutated file and proves the restore by SHA-256. The product
files are CRLF — anchors are converted before matching.

Run from the repo root:

    PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B \
        .dev-flow/2026-10-12-batch-94/evidence/inc004_battery.py

Exit 0 = every arm RED (killed); any SURVIVED/CRASH/BAD exits 1.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
VIEW = ROOT / "s19_app" / "tui" / "issues_view.py"
APP = ROOT / "s19_app" / "tui" / "app.py"
RULES = ROOT / "s19_app" / "validation" / "rules.py"

AT = "tests/test_tui_issues_triage_b94.py::test_at_b94_14_fixture_triage_through_surface"
TC18 = "tests/test_tui_issues_triage_b94.py::test_tc_b94_18_curated_set_and_engine_freeze"
TC19 = "tests/test_tui_issues_triage_b94.py::test_tc_b94_19_panel_reclassification_matrix"

ARMS = [
    ("arm01 predicate returns None (the triage never fires)", VIEW,
     b"    return ValidationSeverity.INFO\n",
     b"    return None  # arm01\n", [AT, TC19]),
    ("arm02 justification note dropped from the INFO group", VIEW,
     b"safe_text(A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION),",
     b'safe_text("arm02: justification dropped"),', [AT, TC19]),
    ("arm03 count helper neutralized (delta always zero)", VIEW,
     b"1 for issue in issues if a2l_reclassified_severity(issue) is not None",
     b"0 for issue in issues  # arm03", [AT]),
    ("arm04 row remap dropped (rows keep WARNING)", VIEW,
     b"issue if severity is None else replace(issue, severity=severity)",
     b"issue if severity is None else issue  # arm04", [AT, TC19]),
    ("arm05 FROBNICATE admitted to the curated set", VIEW,
     b'        "XCP_ON_CAN",\n    }',
     b'        "XCP_ON_CAN",\n        "FROBNICATE",\n    }', [AT, TC18, TC19]),
    ("arm06 frozen engine constant touched", RULES,
     b"RECOGNIZED_A2L_BLOCKS = {",
     b"RECOGNIZED_A2L_BLOCKS = {  # arm06: frozen constant touched", [TC18]),
    ("arm07 panel group_counts not triaged (strip/summary triaged)", APP,
     b"            filtered,\n        )\n"
     b"        panel.render_groups(window, group_counts, truncated=(end - start) < total)",
     b"            [],  # arm07: panel counts not triaged\n        )\n"
     b"        panel.render_groups(window, group_counts, truncated=(end - start) < total)",
     [AT]),
]


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_nodes(nodes: list[str]) -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "--color=no", *nodes],
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                 PYTHONIOENCODING="utf-8", PY_COLORS="0"),
        capture_output=True, text=True,
    )
    tail = (result.stdout or "").strip().splitlines()
    print("    baseline tail:", tail[-1] if tail else "(no output)", flush=True)
    return result.returncode


def main() -> int:
    plan = [(arm, node) for arm in ARMS for node in arm[4]]
    print("arms:", len(ARMS), "node-runs:", len(plan), flush=True)
    touched = {VIEW, APP, RULES}
    hashes = {path: sha(path) for path in touched}
    for path, digest in hashes.items():
        print(f"before: {digest}  ({path.relative_to(ROOT)})", flush=True)

    all_nodes = [AT, TC18, TC19]
    print("CLEAN-TREE BASELINE:", *all_nodes, sep="\n  ", flush=True)
    baseline_rc = run_nodes(all_nodes)
    print("baseline exit:", baseline_rc, flush=True)

    bad = 0
    for (name, target, old, new, nodes), node in plan:
        old = old.replace(b"\n", b"\r\n")
        new = new.replace(b"\n", b"\r\n")
        src = target.read_bytes()
        if src.count(old) != 1:
            print(f"{name} [{node}]: BAD (anchor count {src.count(old)})")
            sys.exit(1)
        target.write_bytes(src.replace(old, new, 1))
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                 "--color=no", node],
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                         PYTHONIOENCODING="utf-8", PY_COLORS="0"),
                capture_output=True, text=True,
            )
        finally:
            target.write_bytes(src)
        verdict = {1: "RED (KILLED)", 0: "GREEN (SURVIVED)"}.get(result.returncode)
        if verdict != "RED (KILLED)":
            bad += 1
        tail = (result.stdout or "").strip().splitlines()
        tail = tail[-1] if tail else "(no output)"
        print(f"{name} [{node.rsplit('::', 1)[-1]}]: "
              f"{verdict or 'CRASH/BAD (exit %d)' % result.returncode} :: {tail}",
              flush=True)

    for path, digest in hashes.items():
        assert sha(path) == digest, f"restore failed for {path}"
        print(f"after:  {sha(path)}  ({path.relative_to(ROOT)})", flush=True)
    print("RESTORE PROVEN (hash identical) for every mutated file", flush=True)
    print(f"TOTALS: {len(plan)} node-runs | RED {len(plan) - bad} | "
          f"SURVIVED {bad} | CRASH/BAD {0 if bad == 0 else 'see rows'}", flush=True)
    return 1 if (bad or baseline_rc != 0) else 0


if __name__ == "__main__":
    sys.exit(main())
