from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BATCH = ROOT / ".dev-flow" / "2026-11-05-batch-103"
TABLE = BATCH / "inc-2" / "02-test-cases.md"
MAIN = ROOT / "tests" / "test_b103_a2l_definition.py"
SYNTH = ROOT / "tests" / "test_b103_synth_definitions.py"


def functions(path: Path) -> set[str]:
    return {node.name for node in ast.parse(path.read_text(encoding="utf-8")).body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


main_functions = functions(MAIN)
synth_functions = functions(SYNTH)
cases = {
    "R-A2L-DEF.19/6", "R-A2L-DEF.19/7", "R-A2L-DEF.21/3", "R-A2L-DEF.25/2",
    "R-A2L-DEF.26/2", "R-A2L-DEF.26/3", "R-A2L-DEF.26/4",
    "R-A2L-DEF.58.1/1", "R-A2L-DEF.58.1/2", "R-A2L-DEF.151/7",
    "AT-B103-I2-1", "AT-B103-I2-2",
}
for number in range(40, 58):
    cases.add(f"R-A2L-DEF.{number}/1")
for number in range(1, 21):
    cases.add(f"R-A2L-DEF.138/{number}")
for number in range(1, 6):
    cases.add(f"R-A2L-DEF.152/{number}")
for number in (1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17):
    cases.add(f"R-A2L-DEF.58.2/{number}")
cases.update(f"R-A2L-DEF.40/{number}" for number in range(2, 10))
cases.update(f"R-A2L-DEF.41/{number}" for number in range(2, 7))
cases.update(f"R-A2L-DEF.42/{number}" for number in range(2, 12))
cases.update(f"R-A2L-DEF.43/{number}" for number in range(2, 5))
cases.update(f"R-A2L-DEF.44/{number}" for number in range(2, 3))
cases.update(f"R-A2L-DEF.45/{number}" for number in range(2, 4))
cases.update(f"R-A2L-DEF.46/{number}" for number in range(2, 5))
cases.update(f"R-A2L-DEF.47/{number}" for number in range(2, 4))
cases.update(f"R-A2L-DEF.48/{number}" for number in range(2, 4))
cases.update(f"R-A2L-DEF.49/{number}" for number in range(2, 4))
cases.update(f"R-A2L-DEF.50/{number}" for number in range(2, 4))
cases.update(f"R-A2L-DEF.52/{number}" for number in range(2, 4))
cases.update(f"R-A2L-DEF.53/{number}" for number in range(2, 5))
cases.update(f"R-A2L-DEF.54/{number}" for number in range(2, 5))
cases.update(f"R-A2L-DEF.57/{number}" for number in range(2, 6))

synth_cases = {"R-A2L-DEF.46/3", "R-A2L-DEF.138/16", "AT-B103-I2-2"}
updated = 0
seen: set[str] = set()
lines = TABLE.read_text(encoding="utf-8").splitlines(keepends=True)
out: list[str] = []
for line in lines:
    cells = line.split("|")
    case = cells[1].strip() if len(cells) > 2 else ""
    if case not in cases or case in seen:
        out.append(line)
        continue
    seen.add(case)
    if case == "AT-B103-I2-1":
        name = "test_at_b103_i2_1_write_arm_nine_overlap_refusals_and_only_ascii_encodes"
    elif case == "AT-B103-I2-2":
        name = "test_at_b103_i2_2_write_arm_encodes_planned_then_a_second_value"
    else:
        stem = case.replace("R-A2L-DEF.", "").replace(".", "_").replace("/", "_")
        prefix = f"test_r_a2l_def_{stem}_"
        if case == "R-A2L-DEF.21/3":
            matches = ["test_r_a2l_def_21_3_non_finite_words_give_no_extended_limits_encode"]
        elif case in synth_cases:
            matches = sorted(name for name in synth_functions if name.startswith(prefix))
        elif case.startswith("R-A2L-DEF.58.1/"):
            matches = sorted(name for name in main_functions if name.startswith(prefix) and "does_not_mutate" in name)
        elif case.startswith("R-A2L-DEF.58.2/"):
            matches = sorted(name for name in main_functions if name.startswith(prefix) and name.endswith("_encode"))
        else:
            matches = sorted(name for name in main_functions if name.startswith(prefix))
        if len(matches) != 1:
            raise SystemExit(f"Expected one test for {case}, found {matches}")
        name = matches[0]
    path = "tests/test_b103_synth_definitions.py" if case in synth_cases else "tests/test_b103_a2l_definition.py"
    evidence = "int2b-run1-synth.txt" if case in synth_cases else "int2b-run3-main.txt"
    red = "int2b-red-stub-synth.txt" if case in synth_cases else "int2b-red-stub-final-main.txt"
    cells[-4] = f" `{path}::{name}` (full) "
    cells[-3] = " covered "
    cells[-2] = f" executed: RED on cb083d07 ({red}); GREEN on cb083d07 ({evidence}) "
    out.append("|".join(cells))
    updated += 1

if updated != len(cases):
    raise SystemExit(f"Updated {updated} cases, expected {len(cases)}")
TABLE.write_text("".join(out), encoding="utf-8")
print(f"UPDATED {updated} cases full/covered with RED+GREEN evidence")
