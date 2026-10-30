"""F: the files scope (LLR-169.2) and the Load check never walk sub-folders
or follow links out of the project."""
import json, os, shutil
from common import *
from s19_app.tui.services.manifest_writer import project_file_records, check_project_files
from s19_app.tui.services.variant_execution_service import read_project_manifest
root = fresh("F"); P = wa(root / "app") / "P"; P.mkdir(parents=True)
out = root / "outside"; out.mkdir()
(out / "secret.s19").write_bytes(b"S0030000FC\n")
(out / "dir.s19").mkdir()
(P / "firmware.s19").write_bytes(b"S0030000FC\n")
(P / "sub").mkdir(); (P / "sub" / "inner.s19").write_bytes(b"x")
junction(P / "jdir.s19", out)            # a junction whose name has a data suffix
junction(P / "flows", out)               # a junction sub-folder
try:
    os.symlink(out / "secret.s19", P / "link.s19"); sym = True
except OSError as e:
    sym = f"not creatable ({e.winerror})"
os.link(out / "secret.s19", P / "hard.s19")
print("file symlink:", sym)
print("[F1 project_file_records] keys:", sorted(project_file_records(P)))
manifest = {"schema_version": 1, "files": {k: {"size": 11, "sha256": "0" * 64} for k in
            ["firmware.s19", "link.s19", "jdir.s19", "hard.s19", "flows/secret.s19", "sub/inner.s19"]}}
(P / "project.json").write_text(json.dumps(manifest))
m = read_project_manifest(P)
print("[F2 reader] accepted:", sorted(str(p.relative_to(P.resolve())) if p.is_relative_to(P.resolve()) else str(p) for p in m.files))
print("   issues:", [(i.code, i.details.get("entry")) for i in m.issues])
print("[F3 check] problems:", [(p.kind, p.file) for p in check_project_files(P, m)])
for j in (P / "jdir.s19", P / "flows"): rm_junction(j)
