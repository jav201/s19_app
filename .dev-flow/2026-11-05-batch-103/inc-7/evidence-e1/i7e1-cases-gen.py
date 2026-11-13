"""i7e1-cases-gen.py -- write Inc 7's 02-test-cases-{L,V,AT}.md from 01-requirements.md (records tool).

One case per alternative of a requirement: the number of alternatives is the `<n>/<n>` count that opens
the row's Threshold cell (a timing row with no count is one case). A case's example id is `X<row>.<k>`:
item k of that row's threshold, whose expected value the test computes from committed data (case 08 from
tools/synth/make_release_case.py --seed 20260001; the P1/P2 transcripts record the values E1 saw). The group
of a row is fixed below; the test file of each group is the planned E4 file. Run from the inc-7 folder:
    python -I -B evidence-e1/i7e1-cases-gen.py
"""
import io
import re

REQ = "01-requirements.md"
ROW = re.compile(r"^\| (R-[A-Za-z0-9.-]+) \| [A-Za-z]+ \| (.*?) \| (.*?) \| (.*?) \| (.*?) \| (\w+)")
COUNT = re.compile(r"^(\d+)/(\d+)")

L_ROWS = {1, 2, 3, 4, 5, 33, 34, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 57, 58, 59, 61, 63, 64, 65, 66,
          67, 68, 69, 70, 71, 73, 76, 77}
L_CANON = {"R-PASTE.1", "R-TUI-043.4", "R-PASTE.29"}
FILES = {"L": "tests/test_b103_label_list.py", "V": "tests/test_b103_a2l_list_view.py"}


def group(rid: str) -> str:
    if rid.startswith("R-A2L-LIST."):
        return "L" if int(rid.rsplit(".", 1)[1]) in L_ROWS else "V"
    return "L" if rid in L_CANON else "V"


def main() -> None:
    rows = {"L": [], "V": []}
    for line in io.open(REQ, encoding="utf-8"):
        m = ROW.match(line)
        if not m:
            continue
        rid, text, threshold, status = m.group(1), m.group(2), m.group(3), m.group(6)
        if status == "retired" or "Withdrawn" in text:
            continue
        c = COUNT.match(threshold.strip())
        n = int(c.group(2)) if c else 1
        rows[group(rid)].append((rid, n, status))
    for g, items in rows.items():
        out = [f"# Inc 7 — test cases, group {'G-L (list module and I-1 hook)' if g == 'L' else 'G-V (the viewer)'}", "",
               f"Format: `roles/tester.md` — `<requirement id>/<n> | example id | test name | full or partial`. "
               f"Example `X<row>.<k>` = item k of the row's Threshold in `01-requirements.md`; the test computes "
               f"its expected value from committed data (never retyped: tester rule 2). Planned test file: "
               f"`{FILES[g]}`. Test names are planned names; the tester may rename them, keeping the id in the "
               f"name. Coverage is the planned mark; E5 re-checks it. Result comes from the run, never from this file.",
               "", "| Case | Example | Test name | Coverage |", "|---|---|---|---|"]
        for rid, n, status in items:
            slug = re.sub(r"[^a-z0-9]+", "_", rid.lower()).strip("_")
            num = rid[len("R-A2L-LIST."):] if rid.startswith("R-A2L-LIST.") else f"({rid})"
            for k in range(1, n + 1):
                out.append(f"| {rid}/{k} | X{num}.{k} | `test_{slug}_{k}` | full |")
        out.append("")
        out.append(f"{sum(n for _, n, _ in items)} cases over {len(items)} requirements.")
        io.open(f"02-test-cases-{g}.md", "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
        print(g, len(items), "requirements", sum(n for _, n, _ in items), "cases")


main()
