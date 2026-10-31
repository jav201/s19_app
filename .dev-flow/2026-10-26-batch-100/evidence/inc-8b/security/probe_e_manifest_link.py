"""E: P/project.json replaced by a file symlink to an outside manifest after
the load; Save as Q must not carry the outside file's values."""
from __future__ import annotations
import json, os
from pathlib import Path
from common8b import *  # noqa
import common8b as c

root, base, W = c.new_base("E1")
P = W / "P"
c.bp.write_tree(P, {"patches/boost.json": c.bp.change_document_bytes(), "flows/f1.json": b"{}"})
outside = root / "outside"; outside.mkdir()
m = json.loads((P / "project.json").read_text(encoding="utf-8"))
m["batch"] = ["OUTSIDE_BATCH_NAME.s19"]
m["gathered"] = {"patches": ["patches/boost.json"], "flows": ["flows/f1.json"]}
m["active_document"] = "patches/boost.json"
(outside / "project.json").write_text(json.dumps(m), encoding="utf-8")

async def sc(app, pilot, log):
    await c.open_p(pilot, app)
    os.rename(P / "project.json", P / "project.json.orig")
    c.symlink(P / "project.json", outside / "project.json")
    return await c.save(pilot, app, log, "Q")
try:
    lines = c.run(base, sc)
    for l in c.short(lines, 220):
        print("  |", ascii(l))
    q = W / "Q" / "project.json"
    if q.exists():
        qm = json.loads(q.read_text(encoding="utf-8"))
        print("  Q batch:", qm.get("batch"), " gathered:", qm.get("gathered"), " active_document:", qm.get("active_document"))
        print("  Q carried OUTSIDE_BATCH_NAME:", "OUTSIDE_BATCH_NAME" in q.read_text(encoding="utf-8"))
finally:
    print("links removed:", c.remove_links(c.SCRATCH / "E1"))
