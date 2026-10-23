"""T1 threads: load S19 / MAC / A2L into the in-memory image and tags (Code-Wire data audit)."""
import shutil
from pathlib import Path

from cwh import C1, C3, PUB, new_base, new_project, out, run_app, load_path, settle


def test_t1a_case01_s19_service():
    """T1a: case_01 firmware.s19 through the frozen reader and build_loaded_s19."""
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19
    s19 = S19File(str(C1 / "firmware.s19"))
    loaded = build_loaded_s19(C1 / "firmware.s19", s19, None, None)
    out("T1a", ranges=[(hex(a), hex(b)) for a, b in loaded.ranges],
        mem0=bytes(loaded.mem_map.get(i, 0) for i in range(12)),
        s0=loaded.source_s0_header, entry=hex(loaded.entry_point or 0),
        errors=len(loaded.errors))


def test_t1b_case01_truncated():
    """T1b: case_01 cut after line 5 of 9 (no S7 terminator): a failed-transfer shape."""
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19
    base = new_base()
    lines = (C1 / "firmware.s19").read_text().splitlines()
    cut = base / "firmware_cut.s19"
    cut.write_text("\n".join(lines[:5]) + "\n")
    loaded = build_loaded_s19(cut, S19File(str(cut)), None, None)
    out("T1b", lines_kept=5, of=len(lines), ranges=[(hex(a), hex(b)) for a, b in loaded.ranges],
        errors=loaded.errors, entry=loaded.entry_point)


def test_t1c_case03_overlap():
    """T1c: case_03 overlapping records: which byte wins, and is it reported."""
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19
    s19 = S19File(str(C3 / "firmware.s19"))
    loaded = build_loaded_s19(C3 / "firmware.s19", s19, None, None)
    ov = s19.get_overlap_addresses() if hasattr(s19, "get_overlap_addresses") else "n/a"
    out("T1c", ranges=[(hex(a), hex(b)) for a, b in loaded.ranges], errors=len(loaded.errors),
        overlaps=(sorted(ov)[:4] if isinstance(ov, (set, list, dict)) else ov))


def test_t1d_app_s19_mac_a2l_then_new_s19():
    """T1d: app Load-file route: case_01 S19, then its MAC, then its A2L, then case_02 S19.
    Which MAC / A2L does the second image carry?"""
    base = new_base()
    work = base / "src"
    work.mkdir()
    for f in ("firmware.s19", "firmware.mac", "firmware.a2l"):
        shutil.copyfile(C1 / f, work / f)
    c2 = base / "src2"
    c2.mkdir()
    from cwh import C2
    shutil.copyfile(C2 / "firmware.s19", c2 / "other.s19")

    async def body(app, pilot):
        await load_path(app, pilot, work / "firmware.s19")
        await load_path(app, pilot, work / "firmware.mac")
        await load_path(app, pilot, work / "firmware.a2l")
        f = app.current_file
        out("T1d-1", file=f.path.name, mac=getattr(f.mac_path, "name", None), a2l=getattr(app.current_a2l_path, "name", None),
            mac_records=len(f.mac_records), tags=len(app.current_a2l_tags or []) if hasattr(app, "current_a2l_tags") else "?")
        await load_path(app, pilot, c2 / "other.s19")
        f = app.current_file
        out("T1d-2", file=f.path.name, mac=getattr(f.mac_path, "name", None), a2l=getattr(f.a2l_path, "name", None),
            mac_records=[(r.get("name"), hex(r["address"])) for r in f.mac_records if isinstance(r.get("address"), int)],
            status=app._probe_status[-3:], notes=app._probe_notes[-3:])

    run_app(body, base)


def test_t1e_app_mac_only():
    """T1e: a MAC loaded alone: what bytes does the in-memory image hold?"""
    base = new_base()
    src = base / "src"
    src.mkdir()
    shutil.copyfile(C1 / "firmware.mac", src / "firmware.mac")

    async def body(app, pilot):
        await load_path(app, pilot, src / "firmware.mac")
        f = app.current_file
        out("T1e", file_type=f.file_type, mem_map={hex(a): v for a, v in list(f.mem_map.items())[:4]},
            ranges=f.ranges, status=app._probe_status[-2:])

    run_app(body, base)
