"""p11b U8: cost of the per-name parts of a plan on a save as (inventory walk of a 2 000-file project)."""
import shutil, sys, time
from pathlib import Path
tree = Path(sys.argv[1]); work = Path(sys.argv[2]); sys.path.insert(0, str(tree))
from s19_app.tui.services.project_gather_service import inventory_project_tree
root = work / "p11b" / "u8" / "P"; shutil.rmtree(root.parent, ignore_errors=True)
for i in range(2000):
    p = root / ("flows" if i % 2 else "reports") / f"f{i:04d}.json"; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b"{}")
best = min((lambda t0: (inventory_project_tree(root), time.perf_counter() - t0)[1])(time.perf_counter()) for _ in range(5))
inv = inventory_project_tree(root)
print(f"== U8 inventory 2000 files: folders={[ (f.name, f.file_count) for f in inv.folders]} best_of_5={best*1000:.1f} ms")
