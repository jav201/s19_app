from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

HOME = Path(__file__).resolve().parents[1]
ROOT = HOME.parents[2]
REQ = (HOME / "01-requirements.md").read_text(encoding="utf-8")
CASES = (HOME / "02-test-cases.md").read_text(encoding="utf-8")
SLICE = (HOME / "E1-slice.md").read_text(encoding="utf-8")
EXPECTED_IDS = [f"R-A2L-REFRESH.{n:03d}" for n in range(29, 39)]
PRESERVED = {
    "R-A2L-004.10", "R-A2L-004.11", "R-A2L-004.12", "R-BUSY-RUN.1",
    "R-A2L-REFRESH.001", "R-A2L-REFRESH.012", "R-A2L-REFRESH.013",
    "R-A2L-REFRESH.018", "R-A2L-REFRESH.023", "R-A2L-REFRESH.026",
    "R-A2L-REFRESH.027", "R-A2L-REFRESH.028", "R-PICKER-CORRECT.018",
    "R-PICKER-CORRECT.019",
}
SOURCE = {
    "s19_app/tui/app/file_load.py",
    "s19_app/tui/a2l_parameter_picker.py",
    "s19_app/tui/screens_directionb/check_editor.py",
    "s19_app/tui/screens_directionb/patch_editor/a2l_picker.py",
}


def rows(text: str, prefix: str = "R-A2L-REFRESH.") -> list[list[str]]:
    return [
        [cell.strip() for cell in line.split("|")]
        for line in text.splitlines()
        if re.match(rf"^\| {re.escape(prefix)}\d", line)
    ]


def validate(req_text: str, case_text: str) -> list[str]:
    errors: list[str] = []
    req_rows = rows(req_text)
    ids = [row[1] for row in req_rows if row[1] in EXPECTED_IDS]
    if ids != EXPECTED_IDS:
        errors.append(f"new ids {ids}")
    expected_alternatives: dict[str, int] = {}
    for row in req_rows:
        if row[1] not in EXPECTED_IDS:
            continue
        if len(row) != 9:
            errors.append(f"{row[1]} column count {len(row)}")
            continue
        _, rid, form, requirement, threshold, negative, us, status, _ = row
        if requirement.count("shall") != 1 or not re.search(r"\b[Tt]he system shall\b", requirement):
            errors.append(f"{rid} not single-shall system sentence")
        if not requirement.startswith(form + " "):
            errors.append(f"{rid} form mismatch {form}")
        if form == "If" and ", then the system shall" not in requirement:
            errors.append(f"{rid} unwanted form lacks then")
        match = re.match(r"(\d+)/(\d+)\b", threshold)
        if not match or match[1] != match[2]:
            errors.append(f"{rid} threshold {threshold!r}")
        else:
            expected_alternatives[rid] = int(match[1])
        if rid == "R-A2L-REFRESH.030":
            extra = re.search(r"plus (\d+)/(\d+) partial static AST census", threshold)
            if not match or match.groups() != ("2", "2") or not extra or extra.groups() != ("1", "1"):
                errors.append(".030 must be 2/2 full runtime plus 1/1 partial static")
            expected_alternatives[rid] = 3
        if not negative or not us or status != "new":
            errors.append(f"{rid} negative/US/status")
    case_rows = rows(case_text)
    counts: Counter[str] = Counter()
    coverage: Counter[str] = Counter()
    for row in case_rows:
        if "/" not in row[1]:
            continue
        if len(row) != 8:
            errors.append(f"case column count {len(row)}: {row[:2]}")
            continue
        rid = row[1].split("/")[0]
        if rid in EXPECTED_IDS:
            counts[rid] += 1
            coverage[row[5]] += 1
            if row[6] != "not_run":
                errors.append(f"{row[1]} result {row[6]}")
            if row[5] not in {"full", "partial"}:
                errors.append(f"{row[1]} coverage {row[5]}")
    for rid, expected in expected_alternatives.items():
        if counts[rid] != expected:
            errors.append(f"{rid} alternatives {counts[rid]} != {expected}")
    if coverage != Counter({"full": 33, "partial": 1}):
        errors.append(f"coverage split {coverage}")
    return errors


def main() -> None:
    errors = validate(REQ, CASES)
    bad_req = REQ.replace("the system shall", "the system must", 1)
    bad_req_errors = validate(bad_req, CASES)
    print(f"known_bad_requirement={'RED' if bad_req_errors else 'SURVIVED'} {bad_req_errors[:1]}")
    if not bad_req_errors:
        errors.append("known-bad requirement survived")
    bad_cases = CASES.replace("| not_run |", "| verified |", 1)
    bad_case_errors = validate(REQ, bad_cases)
    print(f"known_bad_result={'RED' if bad_case_errors else 'SURVIVED'} {bad_case_errors[:1]}")
    if not bad_case_errors:
        errors.append("known-bad result survived")
    case_map = {row[1]: row for row in rows(CASES) if len(row) == 8}
    alternative_total = sum(
        1 for row in rows(CASES)
        if "/" in row[1] and row[1].split("/")[0] in EXPECTED_IDS
    )
    if alternative_total != 34:
        errors.append(f"alternative total {alternative_total}")
    for rid in PRESERVED:
        if f"| `{rid}` |" not in REQ or f"| {rid} |" not in CASES:
            errors.append(f"preserved row missing {rid}")
    for path in SOURCE:
        if path not in SLICE or not (ROOT / path).is_file():
            errors.append(f"source census {path}")
    for n in (1, 2, 3):
        row = case_map.get(f"R-A2L-REFRESH.031/{n}", [])
        if not row or "(a2l_before + 1, image_before," not in row[3]:
            errors.append(f"F2 literal key missing in .031/{n}")
    if "-1" not in case_map["R-A2L-REFRESH.031/1"][3]:
        errors.append("F2 no-image mem_size is not -1")
    for n in (1, 2):
        row = case_map[f"R-A2L-REFRESH.034/{n}"]
        if "1.5 s" not in row[2] or "every measured" not in row[3]:
            errors.append(f"F3 hold/gap too weak in .034/{n}")
    if "a2l_service.render_a2l_view" not in case_map["R-A2L-REFRESH.038/2"][2]:
        errors.append("F4 summary failure seam missing")
    if "adapter-mismatch" not in case_map["R-A2L-REFRESH.037/4"][4]:
        errors.append("F7 adapter-mismatch arm missing")
    headless = case_map.get("R-A2L-REFRESH.037/5", [])
    if not headless or "a2l_data=None" not in headless[3] or "snapshot identity is unchanged" not in headless[3]:
        errors.append("E3-I2-01 headless legacy/survival oracle missing")
    if headless and "tests/test_b103_picker_editor.py:846-870" not in headless[2]:
        errors.append("E3-I2-01 caller reference missing")
    for n in (1, 2, 3):
        row = case_map[f"R-A2L-REFRESH.038/{n}"]
        body = " ".join(row[2:4])
        if "Workarea Files" not in body or "A2L-dependent" not in body:
            errors.append(f"E3-I2-02 failure preservation/refresh missing in .038/{n}")
    if "all previous A2L-dependent state/views" not in REQ or "Workarea Files refresh" not in REQ:
        errors.append("E3-I2-02 requirement scope missing")
    rulings = (HOME / "E1-rulings.md").read_text(encoding="utf-8")
    for text in (CASES, SLICE, rulings):
        if "_accepted_a2l_picker_snapshots" not in text:
            errors.append("F6 accepted attribute not pinned across ledgers")
    if "Mapping[str, A2LPickerSnapshot]" not in rulings or "empty read-only mapping" not in rulings:
        errors.append("F6 type/invalidation missing")
    if not all(f"E3-I2-0{n}" in rulings for n in (1, 2, 3)):
        errors.append("E3 dispositions missing")
    if "file_load.py:806-841" not in REQ or "file_load.py:806-841" not in SLICE:
        errors.append("F1 decorator range mismatch")
    direct = (HOME / "evidence-e1/direct-census.txt").read_text(encoding="utf-8")
    if "file_load.py:806-841 FunctionDef _a2l_attach_worker" not in direct or "root=<repo>" not in direct:
        errors.append("F1/redacted direct census output")
    if "DeepSeek" not in rulings or "`pi`" not in rulings or "conductor's later Qwen retries also failed" not in rulings:
        errors.append("audit/Qwen provenance missing")
    trace_lines = (HOME / "evidence-e1/trace-check.txt").read_text(encoding="utf-8").splitlines()
    test_gaps = [line for line in trace_lines if line.startswith("TEST ")]
    evid_gaps = [line for line in trace_lines if line.startswith("EVID ")]
    other_gaps = [line for line in trace_lines if line.startswith(("US ", "CASE ", "SLICE "))]
    if len(test_gaps) != 10 or len(evid_gaps) != 1 or other_gaps or not any("11 gap(s)" in line for line in trace_lines):
        errors.append("F8 trace must contain only 10 TEST requirement gaps + 1 EVID")
    graph = json.loads((HOME / "codewire/lint.json").read_text(encoding="utf-8"))
    if graph["unread"] or len(graph["nodes"]) != 6:
        errors.append("Code-Wire lint/unread/node count")
    private_tokens = ("C:" + "/Users/", "C:" + "\\" + "Users\\", "jj" + "gh8")
    for path in HOME.rglob("*"):
        if path.is_file() and path.suffix in {".md", ".py", ".txt", ".json"}:
            content = path.read_text(encoding="utf-8")
            if any(token in content for token in private_tokens):
                errors.append(f"personal path remains in {path.relative_to(HOME)}")
    print(f"new_requirements={len(EXPECTED_IDS)}")
    print(f"preserved_requirements={len(PRESERVED)}")
    print(f"source_files={len(SOURCE)}")
    print("planned_alternatives=34")
    print("full_product_route=33 partial_static=1")
    print(f"planned_black_box_ATs={len(re.findall(r'^\| AT-ALP-I2-[123] ', CASES, re.M))}")
    print("planned_collected_items=37")
    print(f"trace_TEST_requirement_gaps={len(test_gaps)} trace_EVID_gaps={len(evid_gaps)} other_gaps={other_gaps}")
    print(f"codewire_nodes={len(graph['nodes'])} unread={graph['unread']}")
    print(f"errors={errors}")
    if errors:
        raise SystemExit(1)
    print("E1 structural validation=PASS")


if __name__ == "__main__":
    main()
