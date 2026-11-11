from pathlib import Path
import json
import os
import shutil
import subprocess

BASE = Path("/tmp/b103-inc6-final77")
ROOT = Path("/tmp/b103-inc6-mutants")
OUT = ROOT / "out"
PYTHON = Path(os.environ["S19CI_PYTHON"])
PICKER = "s19_app/tui/a2l_parameter_picker.py"
PANEL = "s19_app/tui/screens_directionb.py"
MODAL = "s19_app/tui/screens.py"
TESTS = ["tests/test_b103_picker_model.py", "tests/test_b103_picker_editor.py"]
WRAPPER = (
    "import sys;sys.path.insert(0,'.');import s19_app;"
    "print(s19_app.__file__);import pytest;"
    "raise SystemExit(pytest.main(sys.argv[1:]))"
)

MUTANTS = [
    ("M-001", PICKER, 'length = row.get("length")', 'length = row.get("byte_size")', "r001"),
    ("M-002", PICKER, "            size = (\n                length\n                if isinstance(length, int) and not isinstance(length, bool) and length > 0\n                else None\n            )", "            size = (\n                2\n                if name == \"ARR12\"\n                else length\n                if isinstance(length, int) and not isinstance(length, bool) and length > 0\n                else None\n            )", "r002"),
    ("M-003", PICKER, "            fmt_unit = _format_parameter(definitions.get(name), row)", "            fmt_unit = f\"u{size * 8}\"", "r003"),
    ("M-004", PICKER, "                else None\n            )\n            fmt_unit", "                else 1\n            )\n            fmt_unit", "r004"),
    ("M-005", PANEL, "        if size is None:\n            self.query_one(\"#patch_entry_bytes_input\", Input).value = \"\"", "        if False:\n            self.query_one(\"#patch_entry_bytes_input\", Input).value = \"\"", "r005"),
    ("M-006", PANEL, "                for offset in range(size):", "                for offset in range(min(2, size)):", "r006"),
    ("M-007", PANEL, "                    byte = mem_map.get(address + offset)", "                    byte = mem_map.get(address + offset, 0)", "r007"),
    ("M-008", PANEL, "        if size > MAX_A2L_DECODE_BYTES:", "        if size < MAX_A2L_DECODE_BYTES:", "r008"),
    ("M-009", PANEL, "            if self._param_rows[symbol][:2] == (address, size) and symbol not in taken:", "            if symbol not in taken:", "r009"),
    ("M-010", PANEL, "            if spec is None or self._param_rows.get(name, (None, None, \"\"))[:2] == spec[:2]:", "            if spec is None or True:", "r010"),
    ("M-011", PANEL, '            mode="pick",\n            show_include_button=True,\n            show_bulk_button=True,', '            mode="highlight",\n            show_include_button=False,\n            show_bulk_button=False,', "r011"),
    ("M-012", PANEL, "        self.app.push_screen(\n            BulkParameterAddScreen(self._a2l_picker), self._on_bulk_add_closed\n        )", "        return", "r012"),
    ("M-013", PICKER, "            if not name or name in seen:\n                continue", "            if not name:\n                continue", "r013"),
    ("M-014", MODAL, '            return Text("No listed parameters found.", style=DGRAY)', '            return Text("Wrong no-match text.", style=DGRAY)', "r014"),
    ("M-015", PANEL, "    def _use_highlighted_parameter(self) -> None:", "        self._a2l_picker.rebuild_ledger()\n\n    def _use_highlighted_parameter(self) -> None:", "r015"),
    ("M-016", PANEL, "        parameter = self._a2l_picker.highlighted_parameter", "        parameter = self._a2l_picker.highlighted_parameter\n        if self._a2l_picker.picked_params:\n            parameter = self._a2l_picker.param_rows[self._a2l_picker.picked_params[0]]", "r016"),
    ("M-017", PICKER, '        "\\ufffd" if ord(character) <= 31 or 127 <= ord(character) <= 159 else character', '        "" if ord(character) <= 31 or 127 <= ord(character) <= 159 else character', "r017"),
    ("M-018", PICKER, "        if signature is not None and signature == self._signature:\n            return False", "        if signature is not None:\n            return False", "r018"),
    ("M-019", PICKER, "            describe_definitions(names, a2l_data) if a2l_data is not None else {}", "            [describe_definition(name, a2l_data) for name in names] if a2l_data is not None else {}", "r019"),
    ("M-020", PANEL, "        table.show_header = True", "        table.show_header = False", "r020"),
    ("M-021", PANEL, "            if any(\n                item[\"source\"] == \"param\" and item[\"size\"] is None for item in items\n            ):", "            if False:\n                # no missing-length guard", "r021"),
]

only = {item for item in os.environ.get("MUTANT_IDS", "").split(",") if item}
if only:
    MUTANTS = [item for item in MUTANTS if item[0] in only]

ROOT.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)
env = dict(os.environ)
env.update(
    HOME=str(ROOT / "runner"),
    XDG_CACHE_HOME=str(ROOT / "cache"),
    XDG_CONFIG_HOME=str(ROOT / "config"),
    LOCALAPPDATA=str(ROOT / "local"),
    PYTHONDONTWRITEBYTECODE="1",
    PYTHONIOENCODING="utf-8",
)
if os.environ.get("MUTANT_SKIP_BASELINE") == "1":
    baseline_text = (ROOT / "baseline.txt").read_text(encoding="utf-8")
    if "77 passed" not in baseline_text:
        raise RuntimeError("the saved baseline is not GREEN")
else:
    baseline = subprocess.run(
        [str(PYTHON), "-I", "-B", "-c", WRAPPER, "-q", "-p", "no:cacheprovider", *TESTS],
        cwd=BASE,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=900,
    )
    (ROOT / "baseline.txt").write_text(baseline.stdout, encoding="utf-8")
    if baseline.returncode:
        raise RuntimeError("baseline is not GREEN; mutant results are inadmissible")

results = []
for mid, filename, old, new, selection in MUTANTS:
    work = ROOT / mid
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(BASE, work, symlinks=True)
    path = work / filename
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        results.append({"id": mid, "selection": selection, "result": "BAD", "failures": [], "errors": [f"anchor count {text.count(old)}"]})
        continue
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    try:
        proc = subprocess.run(
            [str(PYTHON), "-I", "-B", "-c", WRAPPER, "-q", "-p", "no:cacheprovider", *TESTS, "-k", selection],
            cwd=work,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=240,
        )
        output = proc.stdout
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        returncode = 124
    diff = subprocess.run(
        ["git", "diff", "--", filename], cwd=work, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True,
    ).stdout
    (OUT / f"{mid}.txt").write_text(
        f"{mid}\npytest -k {selection}\nreturncode={returncode}\n\n{diff}\n{output}",
        encoding="utf-8",
    )
    failures = [line for line in output.splitlines() if line.startswith("FAILED ")]
    errors = [line for line in output.splitlines() if line.startswith("ERROR ")]
    result = "killed" if failures else "SURVIVED" if returncode == 0 else "TIMEOUT" if returncode == 124 else "ERROR"
    results.append({"id": mid, "selection": selection, "result": result, "failures": failures, "errors": errors})
    print(mid, result, *failures, sep="\n  ", flush=True)
    shutil.rmtree(work)

summary = {
    "killed": sum(item["result"] == "killed" for item in results),
    "survived": [item["id"] for item in results if item["result"] == "SURVIVED"],
    "errors": [item["id"] for item in results if item["result"] == "ERROR"],
    "timeouts": [item["id"] for item in results if item["result"] == "TIMEOUT"],
    "bad": [item["id"] for item in results if item["result"] == "BAD"],
}
(OUT / "summary.json").write_text(json.dumps({"results": results, "summary": summary}, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(summary), flush=True)
