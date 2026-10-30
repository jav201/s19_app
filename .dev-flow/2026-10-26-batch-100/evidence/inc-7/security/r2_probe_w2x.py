"""R2-W2x: does an entry the walk accepted through the cache confusion (W2c)
reach a consumer that opens it? The execution plan feeds manifest.batch to
read_change_document(path, project_dir), which has no containment check of
its own. Run on the cp1 tree and (PROBE_TREE) on the pre-fix tree."""
import json, os, subprocess
from pathlib import Path
from common import *
from s19_app.tui.services.variant_execution_service import read_project_manifest
from s19_app.tui.changes.io import read_change_document

root = fresh("W2x")
P = wa(root / "app") / "P"; P.mkdir(parents=True)
r = subprocess.run(["fsutil", "file", "setCaseSensitiveInfo", str(P), "enable"], capture_output=True, text=True)
print("fsutil rc:", r.returncode)
out = root / "outside"; out.mkdir()
(out / "secret.json").write_text(json.dumps({"format": "outside-file-marker", "entries": []}))
junction(P / "SUB", out)
try:
    (P / "project.json").write_text(json.dumps({"schema_version": 1,
        "batch": ["sub/missing.json", "SUB/secret.json"]}), encoding="utf-8")
    m = read_project_manifest(P)
    print("reader issues:", [(i.code, i.details.get("entry")) for i in m.issues])
    for p in m.batch:
        doc = read_change_document(str(p), P)
        codes = sorted({i.code for i in doc.issues})
        opened = "MF-PATH-UNRESOLVED" not in codes
        print(f"  batch {str(Path(p).relative_to(P))!r:22} realpath={os.path.realpath(p)}")
        print(f"      read_change_document opened it: {opened} | codes: {codes} | mentions marker: {'outside-file-marker' in ' '.join(i.message for i in doc.issues)}")
finally:
    os.rmdir(P / "SUB")
print("# junction removed:", not os.path.lexists(P / "SUB"))
