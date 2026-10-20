"""Inc-1 mutation battery (p3-implementation.md template, extended to several files).

One edit per mutant, one node per run, restore proven by SHA-256 after every arm.
Run from the repo root: python .dev-flow/2026-10-19-batch-97/evidence/inc-1/mutate.py
"""
import hashlib
import os
import pathlib
import subprocess
import sys

SVC = pathlib.Path("s19_app/tui/services/folder_open_service.py")
CHIP = pathlib.Path("s19_app/tui/open_folder_chip.py")
T = "tests/test_b97_chips_help.py::"

# (id, file, anchor, ONE edit, nodes)
MUTANTS = [
    ("M1-label-constant", SVC, b'return f"\xf0\x9f\x93\x82 Open {folder}/"', b'return "\xf0\x9f\x93\x82 Open folder"',
     [T + "test_tc_b97_65_shipped_chips_labelled_with_folder_and_status_path",
      T + "test_tc_b97_65_no_project_checks_chip_names_the_folder_it_opens",
      T + "test_tc_b97_65_no_project_session_chip_disabled_with_exact_reason"]),
    ("M2-label-not-recomputed", CHIP, b"        self.label = chip_label(self.family, target)\n", b"",
     [T + "test_tc_b97_65_no_project_checks_chip_names_the_folder_it_opens"]),
    ("M3-no-reparse-walk", SVC, b"if _path_traverses_reparse_point(target, stop_at=root.parent):", b"if False:",
     [T + "test_tc_b97_57_guard_unit_arms",
      T + "test_tc_b97_57_chip_press_guarded_in_a_loaded_project[junction-checks]"]),
    ("M4-no-containment", SVC, b"return target.resolve().is_relative_to(root.resolve())", b"return True",
     [T + "test_tc_b97_57_guard_unit_arms"]),
    ("M5-guard-is-exists", CHIP, b"if not is_openable_chip_dir(target, root):", b"if not target.exists():",
     [T + "test_tc_b97_57_chip_press_guarded_in_a_loaded_project[file-checks]",
      T + "test_tc_b97_57_chip_press_guarded_in_a_loaded_project[junction-checks]",
      T + "test_tc_b97_57_chip_press_guarded_in_a_loaded_project[file-flows]",
      T + "test_tc_b97_57_chip_press_guarded_in_a_loaded_project[junction-flows]"]),
    ("M6-chip-reports-reason", CHIP, b"app.set_status(no_project_reason(self.family))", b'app.set_status(no_project_reason("reports"))',
     [T + "test_tc_b97_29_no_project_chips_disabled_with_their_own_reason",
      T + "test_tc_b97_65_no_project_session_chip_disabled_with_exact_reason"]),
    ("M7-service-reports-reason", SVC, b'return f"{chip_label(family, None)}: no active project', b'return f"{chip_label(CHIP_FAMILY_REPORTS, None)}: no active project',
     [T + "test_tc_b97_29_no_project_reason_names_each_family_folder"]),
    ("M8-root-is-workarea", SVC, b"    return base_dir / WORKAREA_DIRNAME\n", b'    return base_dir / WORKAREA_DIRNAME / "workarea"\n',
     [T + "test_tc_b97_57_family_root_is_project_dir_else_tool_root",
      T + "test_tc_b97_57_no_project_patch_common_home_opens"]),
    ("M9-session-creates", CHIP, b" and self.family != CHIP_FAMILY_SESSION", b"",
     [T + "test_tc_b97_28_session_never_creates_a_removed_project_dir"]),
    ("M10-flows-literal", SVC, b"CHIP_FAMILY_FLOWS = FLOWS_SUBDIR", b'CHIP_FAMILY_FLOWS = "flows"',
     [T + "test_tc_b97_27_flows_folder_name_imported_never_redeclared"]),
    # Gate fold (F1, F2), appended 2026-10-20.
    ("M11-stop-at-none", SVC, b"stop_at=root.parent)", b"stop_at=None)",
     [T + "test_tc_b97_57_reparse_point_above_the_root_is_not_the_guards"]),
    ("M12-stop-at-root", SVC, b"stop_at=root.parent)", b"stop_at=root)",
     [T + "test_tc_b97_57_reparse_point_at_the_root_is_refused"]),
    ("M13-session-tooltip", CHIP, b"if missing and self.family == CHIP_FAMILY_SESSION:", b"if False:",
     [T + "test_tc_b97_28_session_never_creates_a_removed_project_dir"]),
]

# Optional selection by mutant id prefix: python mutate.py M11 M12 M13
if len(sys.argv) > 1:
    MUTANTS = [m for m in MUTANTS if m[0].split("-")[0] in sys.argv[1:]]

env = dict(os.environ, PY_COLORS="0", PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
env.pop("NO_COLOR", None)
print("arms:", sum(len(m[4]) for m in MUTANTS), flush=True)
bad = 0
for mid, f, old, new, nodes in MUTANTS:
    src = f.read_bytes()
    h0 = hashlib.sha256(src).hexdigest()
    assert src.count(old) >= 1, f"{mid}: BAD (anchor not found)"
    for node in nodes:
        try:
            f.write_bytes(src.replace(old, new, 1))
            if hashlib.sha256(f.read_bytes()).hexdigest() == h0:
                print(f"{mid} {node}: BAD (the edit did not apply)")
                sys.exit(1)
            r = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--color=no", "--tb=line", node],
                env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
        finally:
            f.write_bytes(src)
        h1 = hashlib.sha256(f.read_bytes()).hexdigest()
        assert h1 == h0, "the restore is not proven"
        verdict = {1: "RED (KILLED)", 0: "GREEN (SURVIVED)"}.get(r.returncode)
        bad += verdict is None
        tail = [ln for ln in r.stdout.splitlines() if "Error" in ln or "passed" in ln or "failed" in ln][-2:]
        print(f"{mid} [{f.name}] {node.split('::')[1]}: {verdict or 'CRASH/BAD (exit %d)' % r.returncode}")
        print(f"    restore sha256 {h1} == before {h0}")
        for ln in tail:
            print("    | " + ln.strip())
        sys.stdout.flush()
sys.exit(1 if bad else 0)
