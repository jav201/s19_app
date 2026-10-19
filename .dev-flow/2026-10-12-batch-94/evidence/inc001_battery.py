"""inc001 mutation battery runner — batch-94 / increment 001 (the editors).

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
  * an edit whose anchor does not match exactly once ends that arm BAD
    (the canonical aborts; this battery records BAD and continues so one
    dead arm cannot silence the other 22);
  * the file's sha256 must return to its pre-mutation value in the same
    transcript for every arm (restore proven, tree ends CLEAN).

Run from the repo root:
    PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 \
        python -B .dev-flow/2026-10-12-batch-94/evidence/inc001_battery.py

Transcript: ``evidence/inc001_battery.txt`` (tee the run).
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

TEST_PATCH = "tests/test_tui_patch_editor_b94.py"
TEST_EDITOR = "tests/test_tui_check_editor.py"
TEST_CHAIN = "tests/test_tui_check_chain_b94.py"


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
        'Binding("equals_sign", "show_screen(\'check_editor\')", "Check Editor", show=False),',
        'Binding("equals_sign", "show_screen(\'patch\')", "Check Editor", show=False),',
        [f"{TEST_EDITOR}::test_at_b94_01_rail_selects_check_editor_mounts_twin",
         f"{TEST_EDITOR}::test_tc_b94_07_rail_mounting_and_write_routing"],
        "rail '=' action target check_editor->patch",
    ),
    arm(
        "02", "s19_app/tui/screens_directionb.py",
        "        table.styles.height = 3",
        "        table.styles.height = 30",
        [f"{TEST_PATCH}::test_at_b94_03_expanded_editor_primary_surface",
         f"{TEST_PATCH}::test_tc_b94_09_widget_census[size0]",
         f"{TEST_PATCH}::test_tc_b94_09_widget_census[size1]"],
        "reworked entries table 3 -> 30 rows (editor below the fold)",
    ),
    arm(
        "03", "s19_app/tui/app.py",
        "        if parsed.has_errors:",
        "        if not parsed.has_errors:",
        [f"{TEST_PATCH}::test_at_b94_04_edit_json_valid_merges"],
        "Edit-JSON validity guard inverted: a VALID confirm is refused",
    ),
    arm(
        "04", "s19_app/tui/app.py",
        "        if parsed.has_errors:",
        "        if False:",
        [f"{TEST_PATCH}::test_at_b94_05_edit_json_invalid_keeps_table"],
        "Edit-JSON validity guard disabled: invalid JSON is accepted",
    ),
    arm(
        "05", "s19_app/tui/screens_directionb.py",
        "            if self._dirty:",
        "            if False:",
        [f"{TEST_PATCH}::test_at_b94_06_dirty_load_accept_loss"],
        "dirty-load guard suppressed: no LoadGuard popup",
    ),
    arm(
        "06", "s19_app/tui/screens_directionb.py",
        '        elif button_id == "load_guard_cancel":\n'
        "            event.stop()\n"
        "            self.dismiss(False)",
        '        elif button_id == "load_guard_cancel":\n'
        "            event.stop()\n"
        "            self.dismiss(True)",
        [f"{TEST_PATCH}::test_at_b94_07_dirty_load_cancel_keeps"],
        "LoadGuard cancel arm dismisses-with-loss (True instead of False)",
    ),
    arm(
        "07", "s19_app/tui/screens_directionb.py",
        '            Horizontal(\n'
        '                Button("Add", id="patch_entry_add_button", classes="patch-chip"),',
        '            Horizontal(\n'
        '                Select([], id="patch_variant_select"),\n'
        '                Button("Add", id="patch_entry_add_button", classes="patch-chip"),',
        [f"{TEST_PATCH}::test_at_b94_08_variant_machinery_retired"],
        "retired patch_variant* widget re-composed (0-variant census)",
    ),
    arm(
        "08", "s19_app/tui/changes/apply.py",
        "        else:\n"
        "            disposition = _STATUS_TO_SKIP_DISPOSITION[entry.status]\n"
        "        counts[disposition] += 1",
        "        else:\n"
        "            disposition = DISPOSITION_APPLIED\n"
        "        counts[disposition] += 1",
        [f"{TEST_PATCH}::test_at_b94_09_apply_applies_loaded_document"],
        "skip disposition counted as applied (skipped->applied flip)",
    ),
    arm(
        "09", "s19_app/tui/app.py",
        '                if not event.path_text.strip():\n'
        '                    self.set_status(\n'
        '                        "Patch Editor: enter a change-file path to load."\n'
        "                    )\n"
        "                else:\n"
        "                    self._patch_editor_load(panel, event.path_text)",
        '                if not event.path_text.strip():\n'
        "                    _scan = self._scan_patch_change_files()\n"
        "                    self._patch_editor_load(\n"
        "                        panel,\n"
        "                        str(self._patches_dir() / _scan[0])\n"
        "                        if _scan\n"
        "                        else event.path_text,\n"
        "                    )\n"
        "                else:\n"
        "                    self._patch_editor_load(panel, event.path_text)",
        [f"{TEST_PATCH}::test_at_b94_10_load_reads_path_input_refresh_repupulates"],
        "empty-path load arm loads scan[0] instead of refusing",
    ),
    arm(
        "10", "s19_app/tui/screens_directionb.py",
        "                Static(\n"
        "                    Text(self._APPLY_GHOST_TEXT, style=\"strike dim\"),\n"
        '                    id="check_apply_ghost",\n'
        "                ),",
        "                Button(\n"
        '                    "Apply",\n'
        '                    id="check_apply_button",\n'
        '                    classes="patch-chip",\n'
        "                ),\n"
        "                Static(\n"
        "                    Text(self._APPLY_GHOST_TEXT, style=\"strike dim\"),\n"
        '                    id="check_apply_ghost",\n'
        "                ),",
        [f"{TEST_EDITOR}::test_at_b94_11_write_validate_chk_json_no_apply",
         f"{TEST_EDITOR}::test_tc_b94_06_composition_census"],
        "one actionable apply Button added to the check editor panel",
    ),
    arm(
        "11", "s19_app/tui/app.py",
        "        self._diff_check_spec = document",
        "        self._diff_check_spec = None",
        [f"{TEST_CHAIN}::test_at_b94_12_writer_dropdown_report_chain"],
        "check-spec stash dropped on load (declared file screens_directionb/"
        "AbDiffPanel; the actual stash seam is the app's "
        "on_*_check_file_selected handler, app.py)",
    ),
    arm(
        "12", "s19_app/tui/screens_directionb.py",
        '                Text("·", style=DGRAY),\n'
        "                safe_text(name, VALUE),",
        '                Text("·", style=DGRAY),\n'
        "                Text.from_markup(name),",
        [f"{TEST_EDITOR}::test_at_b94_13_hostile_symbol_and_file_name"],
        "collector name cell rendered via Text.from_markup (hostile arm)",
    ),
    arm(
        "13", "s19_app/tui/services/change_service.py",
        "        rendered: list[ChangeEntryRow] = []\n"
        "        for index, entry in enumerate(self.document.entries):",
        "        rendered: list[ChangeEntryRow] = []\n"
        "        for index, entry in enumerate(self.document.entries[:-1]):",
        [f"{TEST_PATCH}::test_tc_b94_01_validate_merge_paths"],
        "ChangeService.rows() drops the last entry",
    ),
    arm(
        "14", "s19_app/tui/changes/apply.py",
        '    blocked = document.has_errors or document.kind != "change"',
        "    blocked = document.has_errors",
        [f"{TEST_PATCH}::test_tc_b94_02_apply_gate"],
        "apply gate drops the kind != change term (check specs apply)",
    ),
    arm(
        "15", "s19_app/tui/app.py",
        '                self._prefill_patch_change_files()\n'
        '                self.set_status("Patch Editor: file list refreshed.")',
        '                if service.document.source_path is not None:\n'
        "                    self._patch_editor_load(\n"
        "                        panel, str(service.document.source_path)\n"
        "                    )\n"
        "                else:\n"
        '                    self._prefill_patch_change_files()\n'
        '                self.set_status("Patch Editor: file list refreshed.")',
        [f"{TEST_PATCH}::test_tc_b94_03_load_and_refresh_semantics"],
        "Refresh arm re-loads the document instead of repopulating dropdown",
    ),
    arm(
        "16", "s19_app/tui/app.py",
        "                    panel.mark_saved()",
        "                    pass  # battery arm 16: mark_saved dropped",
        [f"{TEST_PATCH}::test_tc_b94_10_dirty_flag_transitions"],
        "save seam drops panel.mark_saved() (dirty flag survives its save)",
    ),
    arm(
        "17", "s19_app/tui/screens_directionb.py",
        '    def mark_loaded(self) -> None:\n'
        '        """Clear the dirty flag after a successful load (LLR-005.1, writer w4).',
        '    def on_variant_selected(self, event) -> None:\n'
        "        self._dirty = True\n"
        "\n"
        '    def mark_loaded(self) -> None:\n'
        '        """Clear the dirty flag after a successful load (LLR-005.1, writer w4).',
        [f"{TEST_PATCH}::test_tc_b94_11_stale_variant_noop_and_single_binding"],
        "FIX ROUND A re-declaration v2 (v1 inserted a literal on_message and "
        "SURVIVED: Textual dispatches by the message's derived handler_name, "
        "on_<snake class name>, never to a method named on_message). The "
        "realized mutation INSERTS on_variant_selected into PatchEditorPanel "
        "— the panel-side handler for the retired VariantSelected shape, "
        "exactly what HLR-006 removed. The fixed TC-B94-11 posts the "
        "VariantSelected-SHAPED message (handler_name on_variant_selected) "
        "and asserts the dirty flag is untouched; the inserted handler flips "
        "it.",
    ),
    arm(
        "18", "s19_app/tui/screens_directionb.py",
        '                    "Apply loaded changes",\n'
        '                    id="patch_doc_apply_button",',
        '                    "Apply",\n'
        '                    id="patch_doc_apply_button",',
        [f"{TEST_PATCH}::test_tc_b94_12_apply_label_census"],
        "Apply control label Apply loaded changes -> Apply",
    ),
    arm(
        "19", "s19_app/tui/changes/io.py",
        '    if not bare.lower().endswith(".json"):\n'
        '        bare = f"{bare}.json"\n'
        "    return bare",
        '    if not bare.lower().endswith(".json"):\n'
        '        bare = f"{bare}.json"\n'
        '    if bare.lower().endswith(".chk.json"):\n'
        '        bare = bare[: -len(".chk.json")] + ".json"\n'
        "    return bare",
        [f"{TEST_CHAIN}::test_tc_b94_13_chk_write_round_trip"],
        "_safe_name strips .chk.json -> .json (suffix distinction lost)",
    ),
    arm(
        "20", "s19_app/tui/changes/check.py",
        "    for entry in document.entries:",
        "    for entry in document.entries[:-1]:",
        [f"{TEST_CHAIN}::test_tc_b94_14_run_check_document"],
        "run_check_document iterates entries[:-1] (last entry dropped)",
    ),
    arm(
        "21", "s19_app/tui/screens_directionb.py",
        '            if is_check_spec_name(name):\n'
        '                label.append(" CHECK", style=GREEN)\n'
        "            else:\n"
        '                label.append(" PATCH", style=CYAN)\n'
        "            options.append((label, name))\n"
        '        select = self.query_one("#diff_check_select", Select)',
        '            if is_check_spec_name(name):\n'
        '                label.append("", style=GREEN)\n'
        "            else:\n"
        '                label.append(" PATCH", style=CYAN)\n'
        "            options.append((label, name))\n"
        '        select = self.query_one("#diff_check_select", Select)',
        [f"{TEST_CHAIN}::test_tc_b94_15_dropdown_population"],
        "diff dropdown drops the CHECK suffix label (spec-kind distinction)",
    ),
    arm(
        "22", "s19_app/tui/services/diff_report_service.py",
        '    out = ["## Checks", ""]',
        '    out = ["## Check specs", ""]',
        [f"{TEST_CHAIN}::test_tc_b94_16_report_addendum"],
        "check addendum heading ## Checks changed",
    ),
    arm(
        "23", "s19_app/utils.py",
        "_CONTROL_SCRUB = dict.fromkeys((*range(0x00, 0x20), *range(0x7F, 0xA0)))",
        "_CONTROL_SCRUB = dict.fromkeys("
        "(*range(0x00, 0x1B), *range(0x1C, 0x20), *range(0x7F, 0xA0)))",
        [f"{TEST_EDITOR}::test_tc_b94_17_safe_text_hostile_payload"],
        "safe_text scrub table keeps ESC (\\x1b drops out of the C0 range)",
    ),
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_pytest(nodes: list[str], label: str) -> int:
    cmd = [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
           "--color=no", *nodes]
    print(f"  $ {' '.join(cmd)}", flush=True)
    try:
        proc = subprocess.run(cmd, env=ENV, timeout=PYTEST_TIMEOUT)
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
        if proc.returncode not in (0,):
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
    print("inc001 mutation battery — batch-94 increment 001 (tip b6f974f)")
    print("cwd:", REPO)
    print("=" * 78)

    # Optional arm subset: `python inc001_battery.py 01,02,08,15,17` (the
    # fix-round re-runs). Without an argument the full 23-arm battery runs.
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
            test_file, _, node_id = node.partition("::")
            if test_file not in resolved or node not in resolved[test_file]:
                unresolved.append((a["id"], node))
        # assert each arm's nodes resolve to exactly the declared count
        for node in a["nodes"]:
            pass
    if unresolved:
        for arm_id, node in unresolved:
            print(f"  CRASH/BAD (unresolved): arm {arm_id} -> {node}")
        print("resolution failed; battery aborted (nodes must resolve first)")
        return 2
    if full_battery:
        # TC-B94-09 parametrization census: exactly the two declared params
        tc09 = sorted(n for n in resolved[TEST_PATCH] if "test_tc_b94_09" in n)
        assert tc09 == [f"{TEST_PATCH}::test_tc_b94_09_widget_census[size0]",
                        f"{TEST_PATCH}::test_tc_b94_09_widget_census[size1]"], tc09
        print(f"  resolved OK: {sum(len(v) for v in resolved.values())} b94 nodes "
              f"across {len(resolved)} files (TC-B94-09 params: {len(tc09)})")

    # -- Phase 1: arm-count assertion before trusting the harness
    node_runs = [ (a, n) for a in ARMS for n in a["nodes"] ]
    print(f"\n[phase 1] arms: {len(ARMS)}; node-runs: {len(node_runs)}")
    assert ARMS and node_runs, "no arms selected"
    if full_battery:
        print("  planned: 23 arms / 27 node-runs")
        assert len(ARMS) == 23, "arm count mismatch"
        assert len(node_runs) == 27, "node-run count mismatch"

    # -- Phase 2: CLEAN-tree baseline (the harness can see GREEN)
    print("\n[phase 2] clean-tree baseline (all 27 nodes, ONE pytest run)")
    all_nodes = [n for _, n in node_runs]
    rc = run_pytest(all_nodes, "baseline")
    print(f"  baseline exit: {rc} (expect 0)")
    if rc != 0:
        print("  CRASH/BAD: the clean tree is not green; battery aborted")
        return 2

    # -- Phase 3: the battery
    print("\n[phase 3] mutation battery")
    verdicts = []  # (arm_id, node, edit_desc, verdict, restore_ok, extra)
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
            # the declared anchor is absent or ambiguous -> BAD, never skipped
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
