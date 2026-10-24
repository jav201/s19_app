"""Inc-7: reconcile the regenerated 29 cells against the named drift sources.

Per cell (the new baseline's painted rows, svg_rows_diff.rows):
  bar    — the last two painted rows are the key bar: row 1 starts with the
           global `^k Palette` token, row 2 with the window's tag (Inc-8, D29);
  rail   — the rail paints `Check Editor` and `Flow Execution` (batch-94
           Inc-001 / Inc-003 rail census 10 -> 12), where the width shows them;
  ctx    — the status bar paints the A2L name `snap.a2l` (the PC-10 harness fix);
  old_bar — the OLD baseline's bottom row was the one-row Footer.
"""
import subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from svg_rows_diff import rows

TAGS = {"workspace": "Workspace", "a2l": "A2L Explorer", "mac": "MAC View", "issues": "Issues Report",
        "map": "Memory Map", "patch": "Patch Editor", "diff": "A2B Diff"}
repo = Path(sys.argv[1]).resolve()
folder = repo / "tests/__snapshots__/test_tui_snapshot"
total = {"bar": 0, "rail": 0, "ctx": 0, "old_footer": 0}
for p in sorted(folder.glob("*.svg")):
    cell = p.stem.split("[", 1)[1].rstrip("]")
    new = [r for r in rows(p.read_text(encoding="utf-8"))]
    old = rows(subprocess.run(["git", "show", "HEAD:" + p.relative_to(repo).as_posix()], cwd=repo, capture_output=True).stdout.decode("utf-8"))
    painted = [r for r in new if r.strip()]
    bar = len(painted) >= 2 and painted[-2].lstrip().startswith("^k Palette") and painted[-1].lstrip().startswith(TAGS[cell.split("-")[0]])
    text = "\n".join(new)
    rail = "Check Editor" in text and "Flow Execution" in text
    ctx = "snap.a2l" in text
    old_painted = [r for r in old if r.strip()]
    old_footer = bool(old_painted) and "^k Palette" in old_painted[-1] and not any(old_painted[-1].lstrip().startswith(t) for t in TAGS.values())
    for k, v in (("bar", bar), ("rail", rail), ("ctx", ctx), ("old_footer", old_footer)):
        total[k] += v
    print(f"{cell:30s} bar={bar} rail={rail} ctx={ctx} old_one_row_footer={old_footer}")
print("TOTAL of 29:", total)
