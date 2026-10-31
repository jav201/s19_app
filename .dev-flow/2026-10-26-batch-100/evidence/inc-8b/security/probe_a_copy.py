"""A: save-as copy with links at depth, .previous exclusion, hostile manifest
carry, session rebind, painted-name scan."""
from __future__ import annotations

import json
import os
from pathlib import Path

from common8b import *  # noqa: F401,F403
import common8b as c


def case_links_and_carry():
    print("\n== A1 links at depth + .previous + hostile carry + rebind ==")
    root, base, W = c.new_base("A1")
    P = W / "P"
    outside = root / "outside"
    outside.mkdir()
    (outside / "secret.json").write_bytes(b'{"OUTSIDE_MARKER": 1}')
    (outside / "secret.txt").write_bytes(b"OUTSIDE_MARKER")
    other = root / "base2" / ".s19tool" / "workarea" / "R"
    other.mkdir(parents=True)
    (other / "r.json").write_bytes(b'{"OTHER_WA_MARKER": 1}')
    c.bp.write_tree(P, c.bp.SUBFOLDER_FILES)
    (P / "patches" / "x.json").write_bytes(c.bp.change_document_bytes())
    (P / "notes.txt").write_bytes(b"top-level note")
    (P / "project.json.previous-20261030T000000Z").write_bytes(b'{"batch": ["C:/Windows/win.ini"]}')
    (P / "PROJECT.JSON.previous-20261030T000001Z").write_bytes(b"{}")
    # links at depth
    c.junction(P / "linked", outside)
    c.junction(P / "reports" / "j", outside)
    c.junction(P / "reports" / "2026" / "deep" / "j3", other)
    c.symlink(P / "patches" / "l.json", outside / "secret.json")
    c.symlink(P / "flows" / "a" / "b" / "c" / "l2.json", outside / "secret.json")
    c.symlink(P / "top_link.txt", outside / "secret.txt")
    # bidi/control names among the links
    for i in range(12):
        c.junction(P / "splits" / f"j\u202e{i:02d}\u200b", outside)
    # hostile project.json in P
    manifest = json.loads((P / "project.json").read_text(encoding="utf-8"))
    manifest["batch"] = ["C:/Windows/win.ini", "../R/r.json", str(outside / "secret.json"), "ok_name.json"]
    manifest["assignments"] = {"v1": ["..\\..\\x.json", str(outside / "secret.txt")]}
    manifest["gathered"] = {"patches": ["patches/boost.json", "../outside/secret.json", str(outside / "secret.json")],
                            "flows": ["flows/f1.json\u001b[31m"]}
    manifest["active_document"] = "patches/../../R/r.json"
    manifest.setdefault("derived_from", {})
    manifest["derived_from"][str(outside / "x.s19")] = {"base": "firmware.s19"}
    (P / "project.json").write_text(json.dumps(manifest), encoding="utf-8")
    before_outside = c.digests(outside)
    before_other = c.digests(other)

    async def scenario(app, pilot, log):
        await c.open_p(pilot, app, "P")
        # bind a document inside P
        doc = app._change_service.document
        doc.source_path = P / "patches" / "x.json"
        mark = len(log.messages)
        lines = await c.save(pilot, app, log, "Q")
        flows = []
        try:
            from s19_app.tui.app import FlowBuilderPanel
            panel = app.query_one(FlowBuilderPanel)
            flows.append(getattr(panel, "_session_dir", None) or str(getattr(panel, "session_dir", "")))
        except Exception as exc:  # noqa: BLE001
            flows.append(f"n/a {type(exc).__name__}")
        return lines, str(doc.source_path), str(app.current_project_dir), str(app.active_project_dir()), flows

    lines, src, cur, active, flows = c.run(base, scenario)
    Q = W / "Q"
    print("status lines:")
    for l in c.short(lines):
        print("  |", ascii(l))
    qd = c.digests(Q)
    print("Q files:", sorted(qd))
    print("Q links:", c.sweep(Q))
    marker_hits = [k for k in qd if b"MARKER" in (Q / k).read_bytes()]
    print("Q files holding OUTSIDE/OTHER markers:", marker_hits)
    print("Q holds .previous-*:", [k for k in qd if ".previous-" in k.lower()])
    qm = json.loads((Q / "project.json").read_text(encoding="utf-8")) if (Q / "project.json").exists() else None
    if qm:
        text = json.dumps(qm)
        print("Q manifest batch:", qm.get("batch"))
        print("Q manifest assignments:", qm.get("assignments"))
        print("Q manifest gathered:", qm.get("gathered"))
        print("Q manifest active_document:", qm.get("active_document"))
        print("Q manifest derived_from keys:", list((qm.get("derived_from") or {}).keys()))
        print("Q manifest has ':\\\\' or ':/' (absolute):", (":\\\\" in text) or (":/" in text), " has '..':", ".." in text,
              " has ESC:", "\\u001b" in text)
    print("document source_path after:", src)
    print("current_project_dir:", cur, " active:", active, " flow session:", flows)
    print("outside unchanged:", c.digests(outside) == before_outside, " other WA unchanged:", c.digests(other) == before_other)
    print("scan:", c.scan_lines(lines))


def case_rebind_dotdot():
    print("\n== A2 rebind with '..' spelling and skipped-junction document ==")
    root, base, W = c.new_base("A2")
    P = W / "P"
    R = W / "R"
    (R / "patches").mkdir(parents=True)
    (R / "patches" / "x.json").write_bytes(c.bp.change_document_bytes())
    (P / "patches").mkdir(exist_ok=True)
    (P / "patches" / "x.json").write_bytes(c.bp.change_document_bytes())
    outside = root / "outside"
    (outside / "d").mkdir(parents=True)
    (outside / "d" / "y.json").write_bytes(c.bp.change_document_bytes())
    c.junction(P / "patches" / "j", outside / "d")
    results = {}
    for label, spelled in (
        ("dotdot", W / "P" / ".." / "R" / "patches" / "x.json"),
        ("dotdot_into_P", W / "P" / "patches" / ".." / "patches" / "x.json"),
        ("skipped_junction", P / "patches" / "j" / "y.json"),
        ("upper_case", Path(str(W / "p" / "PATCHES" / "X.JSON"))),
    ):
        async def scenario(app, pilot, log, spelled=spelled, label=label):
            await c.open_p(pilot, app, "P")
            doc = app._change_service.document
            doc.source_path = spelled
            lines = await c.save(pilot, app, log, "Q_" + label)
            return lines, str(doc.source_path)
        lines, src = c.run(base, scenario)
        print(f"  {label}: outcome={[l[:90] for l in lines if 'Saved project' in l or 'NOT saved' in l]} source_path -> {src}")


if __name__ == "__main__":
    import sys
    which = sys.argv[1:] or ["1", "2"]
    try:
        if "1" in which:
            case_links_and_carry()
        if "2" in which:
            case_rebind_dotdot()
    finally:
        n = c.remove_links(c.SCRATCH)
        print("\nlinks removed:", n, " reparse points left in scratch:", c.sweep(c.SCRATCH))
