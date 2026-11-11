from pathlib import Path
import json
import os
import shutil
import subprocess

BASE = Path("/tmp/b103-inc5-e5")
ROOT = Path("/tmp/b103-inc5-mut")
OUT = ROOT / "out"
PYTHON = Path(os.environ["S19CI_PYTHON"])
APP = "s19_app/tui/app.py"
SPLIT = "s19_app/tui/segment_split_view.py"
PYTEST_WRAPPER = (
    "import sys;sys.path.insert(0,'.');import s19_app;"
    "print(s19_app.__file__);import pytest;"
    "raise SystemExit(pytest.main(sys.argv[1:]))"
)

MUTANTS = [
    ("M-001", APP, "self._refresh_a2l_dependent_views()", "pass  # no fanout", "r001", 2),
    ("M-002", APP, "                self._a2l_enriched_tags = prepared.a2l_enriched_tags", "                self._a2l_enriched_tags = self._a2l_enriched_tags", "r002", 1),
    ("M-003", APP, "self._refresh_a2l_dependent_views()", "pass  # no final project fanout", "r003", 1),
    ("M-004", APP, "self._refresh_a2l_dependent_views()", "pass  # no A2L-only fanout", "r004", 1),
    ("M-005", APP, "self._refresh_a2l_dependent_views()", "pass  # no unload fanout", "r005", 3),
    ("M-006", APP, "            button.variant = variant\n        self.update_a2l_view()", "            button.variant = variant\n        pass  # no viewer refresh", "r006", 1),
    ("M-007", APP, "        self.a2l_tags_filter_mode = \"all\"\n", "        self.a2l_tags_filter_mode = \"all\"\n        self.query_one(\"#a2l_tags_filter_input\", Input).value = \"\"\n", "REFRESH.007", 1),
    ("M-008", APP, "        self.a2l_tags_filter_mode = \"all\"\n", "        self.a2l_tags_filter_mode = \"all\"\n        self.a2l_tags_filter_field = \"name\"\n", "REFRESH.008", 1),
    ("M-009", APP, "        self.a2l_tags_filter_mode = \"all\"", "        self.a2l_tags_filter_mode = \"inmem\"", "r009", 1),
    ("M-010", APP, "        if card is not None:\n            card.show_tag(None)", "        if card is not None:\n            card.show_tag = lambda _tag: None", "r010", 1),
    ("M-011", APP, "        self._a2l_tag_hex_highlight = None\n        self.update_alt_hex_view()", "        self._a2l_tag_hex_highlight = None\n        pass  # no repaint", "r011", 1),
    ("M-012", APP, "        self._prefill_check_editor()\n        self._prefill_patch_editor()", "        pass  # no visible picker refresh\n        self._prefill_patch_editor()", "r012", 1),
    ("M-013", APP, "        self._prefill_patch_editor()\n        self.update_memory_map()", "        pass  # no patch refresh\n        self.update_memory_map()", "r013", 1),
    ("M-014", APP, "        self._a2l_view_generation += 1", "        self._a2l_view_generation += 0", "r014", 1),
    ("M-015", APP, "        self.update_memory_map()\n        try:\n            window = self.query_one(\"#screen_split_join\", SplitJoinWindow)", "        pass  # no memory map\n        try:\n            window = self.query_one(\"#screen_split_join\", SplitJoinWindow)", "r015", 1),
    ("M-016", APP, "            window.invalidate_a2l_selection()", "            window.refresh_window()", "r016", 1),
    ("M-017", APP, "        panel.render_slots(", "        return\n        panel.render_slots(", "r017", 1),
    ("M-018", APP, "            button.variant = variant\n        self.update_a2l_view()", "            button.variant = variant\n        self._mac_window_start = 0\n        self.update_a2l_view()", "r018", 1),
    ("M-019", APP, "            button.variant = variant\n        self.update_a2l_view()", "            button.variant = variant\n        self.validation_issue_filter_mode = \"all\"\n        self.update_a2l_view()", "r019", 1),
    ("M-020", APP, "                    self._confirm_project_a2l_replacement(", "                    self.set_status(\"Project already has an A2L file.\")\n                    return\n                    self._confirm_project_a2l_replacement(", "r020", 1),
    ("M-021", APP, "        def _answer(accepted: bool) -> None:\n            if accepted:", "        def _answer(accepted: bool) -> None:\n            if True:", "r021", 1),
    ("M-022", APP, "            if self.current_project != project_name:\n                self.set_status(changed_message)\n                return\n            current_dir = self._active_project_dir()\n            if current_dir is None or os.path.normcase(\n                os.path.abspath(current_dir)\n            ) != os.path.normcase(os.path.abspath(project_dir)):\n                self.set_status(changed_message)\n                return\n            try:\n                _, a2l_files, error = validate_project_files(current_dir)\n            except OSError:\n                reason, step = _TYPED_REFUSAL_TOKENS[\"unreadable\"]\n                self.set_status(\n                    safe_text(\n                        f\"A2L NOT loaded: project \"\n                        f\"'{painted_names([project_name])}' {reason} — {step}.\"\n                    ).plain\n                )\n                self.logger.warning(\n                    \"A2L load refused (project folder could not be read): %r\",\n                    current_dir,\n                )\n                return\n            if error:\n                self.set_status(error)\n                self.logger.warning(\"Project validation failed: %s\", error)\n                return\n            if len(a2l_files) != 1 or os.path.normcase(\n                os.path.abspath(a2l_files[0])\n            ) != os.path.normcase(os.path.abspath(project_a2l)):\n                self.set_status(changed_message)\n                return\n", "            # no project/A2L identity revalidation\n", "r022", 1),
    ("M-023", APP, "                path, normalized, copy=copy, sync_project=False", "                path, normalized, copy=copy, sync_project=True", "r023", 1),
    ("M-024", APP, "    def action_load_file(self) -> None:\n        \"\"\"Open the Load dialog on the typed-path field (``l`` / ``ctrl+l``).\"\"\"\n        if self._refuse_if_busy():", "    def action_load_file(self) -> None:\n        \"\"\"Open the Load dialog on the typed-path field (``l`` / ``ctrl+l``).\"\"\"\n        if False and self._refuse_if_busy():", "r024", 1),
    ("M-025", APP, "        if self._refuse_if_busy():\n            return\n        gen = self._busy_begin_action(\"a2l_load\", normalized.name)", "        if False and self._refuse_if_busy():\n            return\n        gen = self._busy_begin_action(\"a2l_load\", normalized.name)", "r025", 1),
    ("M-026", APP, "            self.call_from_thread(self._on_a2l_attached, result)", "            self._refresh_a2l_dependent_views()\n            self.call_from_thread(self._on_a2l_attached, result)", "r026", 1),
    ("M-027", APP, "        self._a2l_view_generation += 1", "        self._a2l_view_generation += 0", "r027", 1),
    ("M-028", APP, "            if actual != expected:\n                return False", "            if False and actual != expected:\n                return False", "r028", 1),
]

ROOT.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)
baseline_env = dict(os.environ)
baseline_env.update(HOME=str(ROOT / "runner"), XDG_CONFIG_HOME=str(ROOT / "config"), LOCALAPPDATA=str(ROOT / "local"), PYTHONDONTWRITEBYTECODE="1")
baseline = subprocess.run(
    [str(PYTHON), "-I", "-B", "-c", PYTEST_WRAPPER, "-q", "-p", "no:cacheprovider", "tests/test_b103_a2l_refresh.py"],
    cwd=BASE, env=baseline_env, stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=2400,
)
(ROOT / "baseline.txt").write_text(baseline.stdout, encoding="utf-8")
if baseline.returncode:
    raise RuntimeError("baseline is not GREEN; mutant results are not admissible")

results = []
for mid, filename, old, new, selection, occurrence in MUTANTS:
    work = ROOT / mid
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(BASE, work, symlinks=True)
    path = work / filename
    text = path.read_text(encoding="utf-8")
    expected_count = 4 if mid in {"M-001", "M-003", "M-004", "M-005"} else 2 if mid in {"M-007", "M-008", "M-009"} else 1
    assert text.count(old) == expected_count, (mid, text.count(old), expected_count, old)
    parts = text.split(old)
    text = old.join(parts[:occurrence]) + new + old.join(parts[occurrence:])
    path.write_text(text, encoding="utf-8")
    env = dict(os.environ)
    env.update(HOME=str(ROOT / "runner"), XDG_CACHE_HOME=str(ROOT / "cache"), XDG_CONFIG_HOME=str(ROOT / "config"), LOCALAPPDATA=str(ROOT / "local"), PYTHONDONTWRITEBYTECODE="1")
    command = [str(PYTHON), "-I", "-B", "-c", PYTEST_WRAPPER, "-q", "-p", "no:cacheprovider", "tests/test_b103_a2l_refresh.py", "-k", selection]
    try:
        proc = subprocess.run(command, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        output = proc.stdout
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        returncode = 124
    diff = subprocess.run(["git", "diff", "--", filename], cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True).stdout
    (OUT / f"{mid}.txt").write_text(f"{mid}\npytest -k {selection}\nreturncode={returncode}\n\n{diff}\n{output}", encoding="utf-8")
    failures = [line for line in output.splitlines() if line.startswith("FAILED ")]
    errors = [line for line in output.splitlines() if line.startswith("ERROR ")]
    result = "killed" if failures else "SURVIVED" if returncode == 0 else "TIMEOUT" if returncode == 124 else "ERROR"
    results.append({"id": mid, "selection": selection, "result": result, "failures": failures, "errors": errors})
    print(mid, result, *failures, sep="\n  ", flush=True)
    shutil.rmtree(work)
(OUT / "summary.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps({"killed": sum(r["result"] == "killed" for r in results), "survived": [r["id"] for r in results if r["result"] != "killed"]}))
