"""inc003 mutation battery runner — batch-94 / increment 003 (the fx_a surface).

RED counterfactual + mutation battery, adapted from the canonical pattern in
``dev-flow/stations/p3-implementation.md`` and the inc002 runner beside this
file (hash before, ONE edit per arm, one node per arm-run, restore in
``finally``, hash after, one verdict per node: exit 1 = RED/KILLED,
0 = GREEN/SURVIVED, anything else = CRASH/BAD).

The arms are the PDR's authoring-time RED mutations (design-proposal.md §5,
Inc-003 rows), one edit per family:
  01 land 11 rail entries (the 12th row dropped)          -> AT-B94-02, TC-B94-08
  02 a cancelled import mounts a lane                     -> AT-B94-19, TC-B94-26
  03 one shared bindings dict across lanes                -> AT-B94-20, TC-B94-27
  04 the mode field hard-coded sequential                 -> AT-B94-21, TC-B94-05
  05 parallel-always dispatch (default arm overlaps)      -> AT-B94-22
  06 the inline X line suppressed                         -> AT-B94-23
  07 the all-clean arm emits an X (invented failure)      -> TC-B94-29
  08 the reload silently drops input bindings             -> AT-B94-24
  09 a stale input named after a rebind (bindings ignored)-> AT-B94-20, TC-B94-30
  10 the outputs field omitted from the envelope          -> TC-B94-31

Runner controls (C-40/C-60): node resolution via --collect-only, arm and
node-run counts asserted up front, a CLEAN-TREE baseline in ONE run, the
BAD-anchor guard, and the per-arm sha256 restore proof.

Run from the repo root:
    PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 \
        python -B .dev-flow/2026-10-12-batch-94/evidence/inc003_battery.py

Transcript: ``evidence/inc003_battery.txt`` (tee the run).
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]
os.chdir(REPO)

ENV = dict(
    os.environ,
    PY_COLORS="0",
    PYTHONDONTWRITEBYTECODE="1",
    PYTHONIOENCODING="utf-8",
)
PYTEST_TIMEOUT = 420  # seconds per node run (TUI drives are slow)

TEST_FX = "tests/test_tui_flow_execution_b94.py"
TEST_SET = "tests/test_flow_chainset_b94.py"


def _adapt_eol(relfile: str, text: str) -> bytes:
    """Match the target file's newline style (the sources are CRLF on disk)."""
    raw = pathlib.Path(relfile).read_bytes()
    if b"\r\n" in raw:
        text = text.replace("\n", "\r\n")
    return text.encode("utf-8")


def arm(arm_id, relfile, old, new, nodes, note=""):
    return {
        "id": arm_id,
        "file": relfile,
        "old": _adapt_eol(relfile, old),
        "new": _adapt_eol(relfile, new),
        "nodes": nodes,
        "note": note,
    }


ARMS = [
    arm(
        "01", "s19_app/tui/app.py",
        '    + (RailEntry("flow_execution", "▶", ">", "Flow Execution"),)\n'
        "    + RAIL_ENTRIES[8:]",
        "    + RAIL_ENTRIES[8:]",
        [f"{TEST_FX}::test_at_b94_02_rail_twelve_entries_mount_panels",
         f"{TEST_FX}::test_tc_b94_08_rail_entries_census_and_duplicate_rejection"],
        "land 11 rail entries: the 12th row (and its container/binding census) "
        "is dropped from the shipped rail",
    ),
    arm(
        "02", "s19_app/tui/app.py",
        "            if stem is None:\n"
        "                return  # cancelled — 0 lanes mounted (LLR-017.1 cancel arm)",
        "            if stem is None:\n"
        "                from .services.flow_model import Flow as _CancelledFlow\n"
        "                panel.add_lane(\"cancelled\", _CancelledFlow(name=\"cancelled\", blocks=[]))\n"
        "                return  # cancelled — 0 lanes mounted (LLR-017.1 cancel arm)",
        [f"{TEST_FX}::test_at_b94_19_import_mounts_lanes_side_by_side",
         f"{TEST_FX}::test_tc_b94_26_lane_mounting_and_render_census"],
        "a cancelled import mounts a lane (the cancel arm adds a lane)",
    ),
    arm(
        "03", "s19_app/tui/flow_screens.py",
        "        lane.bindings[src_index] = value\n",
        "        for _lane in self._lanes:\n"
        "            _lane.bindings[src_index] = value\n",
        [f"{TEST_FX}::test_at_b94_20_rebind_run_reads_each_chains_own_inputs",
         f"{TEST_FX}::test_tc_b94_27_lane_binding_isolation_and_noop"],
        "one shared bindings dict across lanes: editing A writes every lane",
    ),
    arm(
        "04", "s19_app/tui/services/flow_execution_service.py",
        '    record = ChainSetRunRecord(mode=mode)',
        '    record = ChainSetRunRecord(mode="sequential")',
        [f"{TEST_FX}::test_at_b94_21_parallel_mode_overlaps_isolates_and_captures",
         f"{TEST_SET}::test_tc_b94_05_mode_capture_in_run_record_and_report"],
        "the mode field hard-coded: the record never changes from the default",
    ),
    arm(
        "05", "s19_app/tui/services/flow_execution_service.py",
        "    if mode == CHAIN_RUN_PARALLEL:",
        "    if True or mode == CHAIN_RUN_PARALLEL:",
        [f"{TEST_FX}::test_at_b94_22_default_run_is_strictly_sequential"],
        "parallel-always dispatch: an untouched default run overlaps chains",
    ),
    arm(
        "06", "s19_app/tui/flow_screens.py",
        '            log.append("✗ ", style=_S_ERR)',
        '            log.append("· ", style=_S_ERR)',
        [f"{TEST_FX}::test_at_b94_23_run_log_inline_failure_and_report_provenance"],
        "the inline X line suppressed: the failure is visible only elsewhere",
    ),
    arm(
        "07", "s19_app/tui/flow_screens.py",
        '                log.append(f"{glyph} ", style=_S_LABEL)',
        '                log.append("✗ ", style=_S_LABEL)',
        [f"{TEST_FX}::test_tc_b94_29_run_log_emission_and_all_clean_arm"],
        "the all-clean arm emits an X: the log invents a failure",
    ),
    arm(
        "08", "s19_app/tui/app.py",
        "            bindings = {index: ref for index, ref in entry.inputs}",
        "            bindings = {}",
        [f"{TEST_FX}::test_at_b94_24_save_reload_rerun_regenerates_and_notices"],
        "the reload silently drops input bindings (a stale run by construction)",
    ),
    arm(
        "09", "s19_app/tui/services/flow_execution_service.py",
        "    for index, ref in bindings.items():",
        "    for index, ref in {}.items():",
        [f"{TEST_FX}::test_at_b94_20_rebind_run_reads_each_chains_own_inputs",
         f"{TEST_SET}::test_tc_b94_30_chain_set_report_provenance_lines"],
        "the runner ignores the bindings: a stale input is named after a rebind",
    ),
    arm(
        "10", "s19_app/tui/services/flow_persistence_service.py",
        '                "outputs": list(entry.outputs),',
        "",
        [f"{TEST_SET}::test_tc_b94_31_chain_set_serializer_round_trip"],
        "the outputs field omitted from the envelope: the round-trip loses it",
    ),
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_pytest(nodes: list[str], label: str) -> int:
    cmd = [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
           "--color=no", *nodes]
    print(f"  $ pytest [{' '.join(nodes)}]", flush=True)
    try:
        proc = subprocess.run(cmd, env=ENV, timeout=PYTEST_TIMEOUT)
        print(f"  [{label}] exit {proc.returncode}", flush=True)
        return proc.returncode
    except subprocess.TimeoutExpired:
        print(f"  !! {label}: TIMEOUT after {PYTEST_TIMEOUT}s", flush=True)
        return 124


def collect_nodes() -> dict[str, set[str]]:
    """Resolve every node id with pytest --collect-only (C-40 rider)."""
    files = sorted({n.split("::")[0] for a in ARMS for n in a["nodes"]})
    resolved: dict[str, set[str]] = {}
    for test_file in files:
        cmd = [sys.executable, "-B", "-m", "pytest", "--collect-only", "-q",
               "-p", "no:cacheprovider", "--color=no", test_file]
        proc = subprocess.run(cmd, env=ENV, capture_output=True, text=True,
                              timeout=PYTEST_TIMEOUT)
        out = proc.stdout + proc.stderr
        if proc.returncode != 0:
            print(f"COLLECT FAILED for {test_file} (exit {proc.returncode}):")
            print(out[-3000:])
            sys.exit(2)
        ids = set()
        for line in out.splitlines():
            line = line.strip()
            if line.startswith(f"{test_file}::"):
                ids.add(line)
        resolved[test_file] = ids
    return resolved


def main() -> int:
    print("=" * 78)
    print("inc003 mutation battery — batch-94 increment 003 (fx_a Flow Execution)")
    print("cwd:", REPO)
    print("=" * 78)

    full_battery = len(sys.argv) == 1
    if not full_battery:
        wanted = set(sys.argv[1].split(","))
        have = {a["id"] for a in ARMS}
        assert wanted <= have, f"unknown arm ids: {sorted(wanted - have)}"
        ARMS[:] = [a for a in ARMS if a["id"] in wanted]
        print(f"subset mode: arms {sorted(a['id'] for a in ARMS)}")

    # -- Phase 0: node resolution (a node that does not resolve is CRASH/BAD)
    print("\n[phase 0] resolving node ids via pytest --collect-only")
    resolved = collect_nodes()
    unresolved = []
    for a in ARMS:
        for node in a["nodes"]:
            test_file, _, _node_id = node.partition("::")
            if test_file not in resolved or node not in resolved[test_file]:
                unresolved.append((a["id"], node))
    if unresolved:
        for arm_id, node in unresolved:
            print(f"  CRASH/BAD (unresolved): arm {arm_id} -> {node}")
        print("resolution failed; battery aborted (nodes must resolve first)")
        return 2
    if full_battery:
        print(f"  resolved OK: {sum(len(v) for v in resolved.values())} "
              f"collectable nodes across {len(resolved)} files")

    # -- Phase 1: arm-count assertion before trusting the harness
    node_runs = [(a, n) for a in ARMS for n in a["nodes"]]
    print(f"\n[phase 1] arms: {len(ARMS)}; node-runs: {len(node_runs)}")
    assert ARMS and node_runs, "no arms selected"
    if full_battery:
        print("  planned: 10 arms / 15 node-runs")
        assert len(ARMS) == 10, "arm count mismatch"
        assert len(node_runs) == 15, "node-run count mismatch"

    # -- Phase 2: CLEAN-tree baseline (the harness can see GREEN)
    print("\n[phase 2] clean-tree baseline (all nodes, ONE pytest run)")
    all_nodes = [n for _, n in node_runs]
    rc = run_pytest(all_nodes, "baseline")
    print(f"  baseline exit: {rc} (expect 0)")
    if rc != 0:
        print("  CRASH/BAD: the clean tree is not green; battery aborted")
        return 2

    # -- Phase 3: the battery
    print("\n[phase 3] mutation battery")
    verdicts = []  # (arm_id, node, edit_desc, verdict, restore_ok, note)
    bad = 0
    for a in ARMS:
        f = pathlib.Path(a["file"])
        src = f.read_bytes()
        h0 = sha256(src)
        print(f"\n--- arm {a['id']}: {a['file']}")
        print(f"    note: {a['note']}")
        print(f"    edit: {a['old'].decode('utf-8')!r}")
        print(f"          -> {a['new'].decode('utf-8')!r}")
        print(f"    before: {h0}", flush=True)
        occurrences = src.count(a["old"])
        if occurrences != 1:
            bad += 1
            verdict = f"CRASH/BAD (anchor count {occurrences}, expected 1)"
            print(f"    !! {verdict}")
            verdicts.append((a["id"], ",".join(a["nodes"]),
                             a["old"].decode("utf-8"), verdict,
                             sha256(f.read_bytes()) == h0, a["note"]))
            continue
        for node in a["nodes"]:
            arm_label = f"arm {a['id']} [{node}]"
            try:
                mutated = src.replace(a["old"], a["new"], 1)
                f.write_bytes(mutated)
                if sha256(f.read_bytes()) == h0:
                    print(f"    {arm_label}: BAD (the edit did not apply)")
                    bad += 1
                    verdicts.append((a["id"], node, a["old"].decode("utf-8"),
                                     "CRASH/BAD (edit did not apply)",
                                     False, a["note"]))
                    continue
                rc = run_pytest([node], arm_label)
            finally:
                f.write_bytes(src)  # restore whatever the run did
            h1 = sha256(f.read_bytes())
            restore_ok = h1 == h0
            assert restore_ok, f"arm {a['id']}: restore is not proven"
            verdict = {1: "RED (KILLED)", 0: "GREEN (SURVIVED)"}.get(rc)
            if verdict is None:
                bad += 1
                verdict = f"CRASH/BAD (exit {rc})"
            print(f"    after:  {h1} restore-ok={restore_ok}")
            print(f"    {arm_label}: {verdict}", flush=True)
            verdicts.append((a["id"], node, a["old"].decode("utf-8"),
                             verdict, restore_ok, a["note"]))

    # -- Phase 4: verdict table
    print("\n" + "=" * 78)
    print("VERDICT TABLE (arm -> node -> edit anchor -> verdict -> restore)")
    print("=" * 78)
    n_red = n_survived = n_crash = 0
    for arm_id, node, edit, verdict, restore_ok, note in verdicts:
        if verdict.startswith("RED"):
            n_red += 1
        elif verdict.startswith("GREEN"):
            n_survived += 1
        else:
            n_crash += 1
        anchor = edit.splitlines()[0] if edit else ""
        print(f"arm {arm_id} | {node}\n"
              f"    edit: {anchor}... | {verdict} | restore-hash {'OK' if restore_ok else 'FAIL'}\n"
              f"    note: {note}")
    print("-" * 78)
    print(f"TOTALS: {len(verdicts)} node-runs | RED {n_red} | "
          f"SURVIVED {n_survived} | CRASH/BAD {n_crash}")
    print(f"runner exit: {'1 (findings present)' if (n_survived or n_crash or bad) else '0 (all arms killed)'}")
    return 1 if (n_survived or n_crash or bad) else 0


if __name__ == "__main__":
    sys.exit(main())
