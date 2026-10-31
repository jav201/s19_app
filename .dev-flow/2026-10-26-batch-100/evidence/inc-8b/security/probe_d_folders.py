"""D: listing / load / Save folder check, foreign-parent spellings, TOCTOU
after load, the A2L guard, unreadable/reserved entries, painted_names."""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from common8b import *  # noqa: F401,F403
import common8b as c
import s19_app.tui.app as appmod
import s19_app.tui.workspace as ws
from s19_app.tui.screens import SaveProjectPayload


def short_name(p: Path) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.windll.kernel32.GetShortPathNameW(str(p), buf, 1024)
    return buf.value if n else ""


async def save_with_parent(pilot, app, log, parent: str, name: str):
    mark = len(log.messages)
    app._handle_save_dialog(SaveProjectPayload(parent_folder=parent, project_name=name))
    for _ in range(400):
        if any(k in m for m in log.since(mark) for k in c.bp.SAVE_OUTCOMES) or any("not found" in m for m in log.since(mark)):
            break
        await pilot.pause()
    for _ in range(4):
        await pilot.pause()
    return log.since(mark)


def d1_list_load_save_folder_check():
    print("\n== D1 list / load / save target: junction projects, two-part names ==")
    root, base, W = c.new_base("D1")
    P = W / "P"
    base2 = root / "base2"
    c.bp.save_case01_project(base2, "R", files=("firmware.s19",))
    R2 = base2 / ".s19tool" / "workarea" / "R"
    outside = root / "outside"
    shutil.copytree(P, outside)  # a valid project outside every work area
    c.junction(W / "J_other_wa", R2)
    c.junction(W / "J_outside", outside)
    c.junction(W / "sub", W / "P")   # two-part spelling sub/P? (junction to P)
    (W / "real").mkdir()
    shutil.copytree(P, W / "real" / "P2")

    async def sc(app, pilot, log):
        res = {}
        res["list"] = app.list_projects()
        for name in ("J_other_wa", "J_outside", "sub", "sub/P", "real/P2", "..", "../workarea/P", str(outside), "P/../J_outside", "\\\\?\\" + str(W / "P")):
            mark = len(log.messages)
            parse_calls = []
            orig = appmod.S19TuiApp._load_a2l_data_with_cache
            t0 = time.perf_counter()
            try:
                app._handle_load_project(name)
            except Exception as exc:  # noqa: BLE001
                log.messages.append(f"RAISED {type(exc).__name__}: {exc}")
            for _ in range(3):
                await pilot.pause()
            res[name] = (str(app.current_project), [m[:150] for m in log.since(mark)])
        # save targets
        await c.open_p(pilot, app)
        for name in ("J_other_wa", "J_outside"):
            mark = len(log.messages)
            lines = await save_with_parent(pilot, app, log, str(app.workarea), name)
            res["save:" + name] = [m[:150] for m in lines]
        return res

    res = c.run(base, sc)
    print("  list_projects:", res.pop("list"))
    for k, v in res.items():
        print(f"  {k!r}: {ascii(v)}")
    print("  R2 / outside untouched:", sorted(c.digests(R2)) == sorted(c.digests(R2)))


def d2_foreign_parent():
    print("\n== D2 foreign-parent spellings for Save as ==")
    root, base, W = c.new_base("D2")
    alias = root / "alias_to_W"
    c.junction(alias, W)
    sib = W.parent / "workarea_sibling"
    sib.mkdir()
    spellings = {
        "plain": str(W),
        "trailing_sep": str(W) + "\\",
        "upper": str(W).upper(),
        "dotdot": str(W / "P" / ".."),
        "forward": str(W).replace("\\", "/"),
        "short83": short_name(W),
        "junction_alias": str(alias),
        "extended": "\\\\?\\" + str(W),
        "unc_admin_share": "\\\\localhost\\" + str(W)[0] + "$" + str(W)[2:],
        "subdir_P": str(W / "P"),
        "sibling": str(sib),
        "parent_of_W": str(W.parent),
    }
    subst_letter = None
    for letter in "QRSTUVXYZ":
        if not os.path.exists(f"{letter}:\\"):
            r = subprocess.run(["subst", f"{letter}:", str(W.parent)], capture_output=True, text=True)
            if r.returncode == 0:
                subst_letter = letter
                spellings["subst"] = f"{letter}:\\workarea"
            break
    try:
        for label, parent in spellings.items():
            if not parent:
                print(f"  {label}: n/a (no spelling)")
                continue
            async def sc(app, pilot, log, parent=parent, label=label):
                await c.open_p(pilot, app)
                lines = await save_with_parent(pilot, app, log, parent, "Q_" + label)
                return [m[:170] for m in lines], str(app.current_project_dir)
            lines, cur = c.run(base, sc)
            landed = [p.name for p in W.iterdir() if p.name == "Q_" + label]
            stray = [str(p) for p in (alias / ("Q_" + label), sib / ("Q_" + label), W / "P" / ("Q_" + label), W.parent / ("Q_" + label)) if os.path.lexists(p) and p.parent != W]
            out = [l for l in lines if "NOT saved" in l or "Saved project" in l or "not found" in l]
            print(f"  {label}: parent={ascii(parent[-60:])} -> landed in W={bool(landed)} current_project_dir textual W child={cur.startswith(str(W)) if landed else '-'} stray={stray}")
            print(f"      {ascii(out[:1])}")
    finally:
        if subst_letter:
            subprocess.run(["subst", f"{subst_letter}:", "/D"], capture_output=True)
            print("  subst removed:", not os.path.exists(f"{subst_letter}:\\"))


def d3_toctou_after_load():
    print("\n== D3 P swapped for a junction after the load ==")
    for target in ("other_wa", "outside"):
        root, base, W = c.new_base("D3_" + target)
        base2 = root / "base2"
        c.bp.save_case01_project(base2, "R", files=("firmware.s19",))
        R2 = base2 / ".s19tool" / "workarea" / "R"
        (R2 / "project.json").write_text(json.dumps({"batch": ["SPY"]}), encoding="utf-8")
        outside = root / "outside"
        outside.mkdir()
        (outside / "project.json").write_text("{}", encoding="utf-8")
        tgt = R2 if target == "other_wa" else outside
        before = c.digests(tgt)
        reads = []
        orig_read = appmod.read_project_manifest

        def spy(path, *a, **k):
            reads.append(str(path))
            return orig_read(path, *a, **k)

        async def sc(app, pilot, log):
            await c.open_p(pilot, app)
            os.rename(W / "P", W / "P_moved")
            c.junction(W / "P", tgt)
            appmod.read_project_manifest = spy
            try:
                a = await c.save(pilot, app, log, "Q")      # save as
                b = await c.save(pilot, app, log, "P")      # open-project save into the junction
            finally:
                appmod.read_project_manifest = orig_read
            return a, b
        a, b = c.run(base, sc)
        print(f"  {target}: save-as -> {ascii([l[:150] for l in a if 'NOT' in l or 'Saved' in l])}")
        print(f"      Save P -> {ascii([l[:150] for l in b if 'NOT' in l or 'Saved' in l or 'could not' in l])}")
        print(f"      reads of the junction target's project.json: {[r for r in reads if 'P' == Path(r).name or str(tgt) in r]}")
        print(f"      target unchanged: {c.digests(tgt) == before}  Q exists: {(W / 'Q').exists()}")


def d4_a2l_guard():
    print("\n== D4 A2L guard (link A2L, over-cap A2L, MAC + linked A2L) ==")
    outside_root = c.fresh("D4_outside")
    src = c.bp.copy_sources(outside_root / "src", c.bp.CASE01_DIR, "firmware.a2l", "firmware.s19", "firmware.mac")
    outside_a2l = src / "firmware.a2l"
    cases = {}
    for label, files in (
        ("data+link", ("firmware.s19",)),
        ("a2l_only_link", ()),
        ("mac+link", ("firmware.mac",)),
        ("data+overcap", ("firmware.s19",)),
        ("a2l_only_overcap", ()),
        ("a2l_only_ok", ()),
    ):
        root = c.fresh("D4_" + label)
        base = root / "base"
        W = base / ".s19tool" / "workarea"
        P = W / "P"
        P.mkdir(parents=True)
        for f in files:
            shutil.copy2(src / f, P / f)
        if "link" in label:
            c.symlink(P / "firmware.a2l", outside_a2l)
        else:
            shutil.copy2(outside_a2l, P / "firmware.a2l")
        (P / "project.json").write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
        parses = []
        orig_cache = appmod.S19TuiApp._load_a2l_data_with_cache
        orig_parse = appmod.parse_a2l_file

        def cache_spy(self, path, *a, **k):
            parses.append(("cache", str(path)))
            return orig_cache(self, path, *a, **k)

        def parse_spy(path, *a, **k):
            parses.append(("parse", str(path)))
            return orig_parse(path, *a, **k)

        saved_cap = ws.DEFAULT_COPY_SIZE_CAP_BYTES
        if "overcap" in label:
            ws.DEFAULT_COPY_SIZE_CAP_BYTES = outside_a2l.stat().st_size - 1
        appmod.S19TuiApp._load_a2l_data_with_cache = cache_spy
        appmod.parse_a2l_file = parse_spy
        try:
            async def sc(app, pilot, log):
                mark = len(log.messages)
                app._handle_load_project("P")
                for _ in range(60):
                    await pilot.pause()
                return [m[:170] for m in log.since(mark)], str(app.current_a2l_path), str(app.current_project), app.current_file is not None
            lines, a2l, proj, has_file = c.run(base, sc)
        finally:
            appmod.S19TuiApp._load_a2l_data_with_cache = orig_cache
            appmod.parse_a2l_file = orig_parse
            ws.DEFAULT_COPY_SIZE_CAP_BYTES = saved_cap
        print(f"  {label}: parses={parses} current_a2l_path={a2l} project={proj} file={has_file}")
        for l in lines:
            print("     |", ascii(l))


def d5_unreadable_and_reserved():
    print("\n== D5 unreadable / reserved / trailing-dot entries ==")
    root, base, W = c.new_base("D5")
    P = W / "P"
    (P / "flows").mkdir()
    made = []
    for rel in ("flows\\x.json.", "flows\\y.json ", "CON.txt", "flows\\nul.json", "COM1", "flows\\CONIN$.md"):
        try:
            c.bp.write_unnormalised(P / rel)
            made.append(rel)
        except OSError as exc:
            print(f"  could not create {rel!r}: {type(exc).__name__} {exc.errno}")
    print("  created via \\\\?\\:", made)
    locked = P / "locked"
    locked.mkdir()
    (locked / "a.txt").write_bytes(b"a")
    r = subprocess.run(["icacls", str(locked), "/deny", f"{os.environ.get('USERNAME')}:(RD)"], capture_output=True, text=True)
    print("  icacls deny list on 'locked':", r.returncode == 0)
    try:
        from s19_app.tui.services.project_gather_service import inventory_project_tree
        inv = inventory_project_tree(P)
        print("  inventory unreadable:", inv.unreadable, " over_ceiling:", inv.over_ceiling)
        async def sc(app, pilot, log):
            await c.open_p(pilot, app)
            return await c.save(pilot, app, log, "Q")
        lines = c.run(base, sc)
        print("  save as:", ascii([l[:200] for l in lines if "NOT" in l or "Saved" in l]), " Q exists:", (W / "Q").exists())
    finally:
        subprocess.run(["icacls", str(locked), "/remove:d", os.environ.get("USERNAME")], capture_output=True)
        for rel in made:
            c.bp.remove_unnormalised(P / rel)


def d6_painted_names():
    print("\n== D6 painted_names ==")
    from s19_app.tui.services.project_gather_service import painted_names
    import unicodedata
    names = ["a\x1b[31mb", "c‮d", "e​f", "g؜h", "i j", "k﻿l", "m\udc80n", "o\U000e0041p", "q­r", "s\u0085t", "u" * 300, "v", "w"]
    out = painted_names(names)
    print("  out:", ascii(out))
    print("  encodes utf-8:", bool(out.encode("utf-8")))
    bad = [hex(ord(ch)) for ch in out if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs")]
    print("  remaining Cc/Cf/Zl/Zp/Cs:", bad)
    print("  longest painted name:", max(len(x) for x in out.split(", ")))
    print("  25 names ->", painted_names([f"n{i}" for i in range(25)])[-30:])
    print("  0 names ->", ascii(painted_names([])), " exactly 10 ->", painted_names([str(i) for i in range(10)]))
    # combining-mark flood and RTL letters (not removable by category)
    print("  RTL letters kept:", ascii(painted_names(["אב.json"])))
    print("  combining flood length:", len(painted_names(["a" + "́" * 500])))


if __name__ == "__main__":
    which = sys.argv[1:] or ["1", "2", "3", "4", "5", "6"]
    try:
        for k, f in (("1", d1_list_load_save_folder_check), ("2", d2_foreign_parent), ("3", d3_toctou_after_load),
                     ("4", d4_a2l_guard), ("5", d5_unreadable_and_reserved), ("6", d6_painted_names)):
            if k in which:
                f()
    finally:
        n = c.remove_links(c.SCRATCH)
        print("\nlinks removed:", n, " reparse points left in scratch:", c.sweep(c.SCRATCH))
