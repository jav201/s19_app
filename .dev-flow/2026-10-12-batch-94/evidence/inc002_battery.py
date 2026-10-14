"""inc002 mutation battery runner — batch-94 / increment 002 (the fb_a builder).

RED counterfactual + mutation battery, adapted from the canonical pattern in
``dev-flow/stations/p3-implementation.md`` (hash before, ONE edit per arm,
run one node per arm-run, restore in ``finally``, hash after, one verdict per
node: exit 1 = RED/KILLED, 0 = GREEN/SURVIVED, anything else = CRASH/BAD).

Runner controls (C-40/C-60):
  * every node id is resolved with ``pytest --collect-only`` BEFORE the
    battery and asserted to exist (an unresolvable node = CRASH/BAD);
  * the arm count and the node-run count are asserted before any mutation;
  * a CLEAN-TREE baseline run of all nodes in ONE pytest invocation proves
    the harness can see GREEN (the RED counterfactual's companion control);
  * an edit whose anchor does not match exactly once ends that arm BAD;
  * the file's sha256 must return to its pre-mutation value in the same
    transcript for every arm (restore proven, tree ends CLEAN).

Run from the repo root:
    PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 \
        python -B .dev-flow/2026-10-12-batch-94/evidence/inc002_battery.py

Transcript: ``evidence/inc002_battery.txt`` (tee the run).
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

TEST_BUILDER = "tests/test_tui_flow_builder_b94.py"
TEST_A2B = "tests/test_flow_a2b_b94.py"


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
        "01", "s19_app/tui/flow_screens.py",
        '        yield Static(self._canvas_text(), id="flow_canvas", markup=False)',
        '        yield Static("(no canvas)", id="flow_canvas", markup=False)',
        [f"{TEST_BUILDER}::test_at_b94_15_fb_a_surface_and_wired_patch_run",
         f"{TEST_BUILDER}::test_tc_b94_20_fb_a_composition_census"],
        "the fb_a canvas compose replaced by a placeholder (list-only UI)",
    ),
    arm(
        "02", "s19_app/tui/services/flow_model.py",
        "    if flow_count == 0:\n"
        "        reasons.append(",
        "    if False and flow_count == 0:\n"
        "        reasons.append(",
        [f"{TEST_BUILDER}::test_at_b94_16_a2b_wiring_rule_and_report_provenance",
         f"{TEST_A2B}::test_tc_b94_23_binding_validation_matrix"],
        "both-external refusal suppressed: the (file,file) pair is accepted",
    ),
    arm(
        "03", "s19_app/tui/services/flow_persistence_service.py",
        '    target = flows_dir / f"{clean}.json"\n'
        "    if target.exists():",
        '    target = flows_dir / f"{clean}.json"\n'
        "    if False and target.exists():",
        [f"{TEST_BUILDER}::test_at_b94_17_template_save_listing_import_and_dedup",
         f"{TEST_A2B}::test_tc_b94_04_template_save_reload_and_dedup"],
        "collision dedup-suffix suppressed: a second same-name save clobbers",
    ),
    arm(
        "04", "s19_app/tui/flow_screens.py",
        "        scrub = lambda s: safe_text(s).plain  # noqa: E731 - one-line sink guard",
        "        scrub = lambda s: s  # noqa: E731 - one-line sink guard",
        [f"{TEST_BUILDER}::test_at_b94_18_hostile_names_render_literally"],
        "canvas label scrub dropped: control bytes survive into the paint",
    ),
    arm(
        "05", "s19_app/tui/services/flow_execution_service.py",
        "                                md_safe(path.stem, limit=120),",
        "                                path.stem,",
        [f"{TEST_A2B}::test_tc_b94_25_hostile_file_name_in_emitted_report"],
        "the Mode-A label escaper bypassed: raw markup reaches the report",
    ),
    arm(
        "06", "s19_app/tui/services/flow_persistence_service.py",
        '                    "image_a": {\n'
        '                        "source": block.image_a.source,\n'
        '                        "ref": block.image_a.ref,\n'
        "                    },\n"
        '                    "image_b": {\n'
        '                        "source": block.image_b.source,\n'
        '                        "ref": block.image_b.ref,\n'
        "                    },",
        '                    "image_a": {},\n                    "image_b": {},',
        [f"{TEST_A2B}::test_tc_b94_21_roundtrip_one_of_each_kind_incl_a2b"],
        "A2B bindings dropped at serialize: the round-trip loses them",
    ),
    arm(
        "07", "s19_app/tui/services/flow_execution_service.py",
        '                if path is None or not path.exists():\n'
        "                    # LLR-092.1: containment reject (absolute/escape/reparse) or\n"
        "                    # a missing target — fail closed BEFORE opening any file.\n"
        "                    aborted = _record_error(\n"
        '                        result, index, kind, "config unresolved", issues,\n'
        '                        "crc config not found or not inside the project",\n'
        "                    )\n"
        "                    continue",
        '                if path is None or not path.exists():\n'
        "                    result.block_results.append(\n"
        '                        BlockResult(index, kind, BLOCK_STATUS_OK, "crc skipped")\n'
        "                    )\n"
        "                    continue",
        [f"{TEST_A2B}::test_tc_b94_22_upstream_crc_failure_skips_write_out"],
        "C-1 re-arm: a missing CRC config applies anyway (chain proceeds)",
    ),
    arm(
        "08", "s19_app/tui/services/flow_execution_service.py",
        "                                SOURCE_EXTERNAL,",
        "                                A2B_INPUT_FILE,",
        [f"{TEST_A2B}::test_tc_b94_24_a2b_report_states_each_inputs_provenance"],
        "external arm source-kind drifted off the C-42 pasted form",
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
    print("inc002 mutation battery — batch-94 increment 002 (fb_a builder + A2B)")
    print("cwd:", REPO)
    print("=" * 78)

    # Optional arm subset: `python inc002_battery.py 01,04` (fix-round re-runs).
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
        print("  planned: 8 arms / 11 node-runs")
        assert len(ARMS) == 8, "arm count mismatch"
        assert len(node_runs) == 11, "node-run count mismatch"

    # -- Phase 2: CLEAN-tree baseline (the harness can see GREEN)
    print("\n[phase 2] clean-tree baseline (all 11 nodes, ONE pytest run)")
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
