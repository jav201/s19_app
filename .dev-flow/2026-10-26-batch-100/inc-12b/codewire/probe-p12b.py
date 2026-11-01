"""Probe p12b (E2 baseline, Inc 12b) on the main checkout 8947666, imported read-only.

U1  LLR-177.1f planned arm: the base session digest of a cold project load, and of the same
    project loaded over an open image (P2-over-P1), for case_01 (fast) and case_06 (cold only).
U2  LLR-177.1e / .1f hazard: _parse_loaded_file of P2's MAC while P1's image is current
    (what a worker that runs before the reset would do), against the same call with no image.
U3  S-f: how build_section_tree's read loop can report consumed bytes. Text-mode lines vs
    handle.buffer.tell() for the CRLF A2L files; distinct positions (= chunks) and the last value.
U4  LLR-177.1d: which app attributes a base project load / A2L attach / Save assign, read by a
    __setattr__ recorder on a test subclass (main thread on base; the list is what a worker must not write).

Usage: python -I probe-p12b.py <repo> <scratch-dir>
Writes only under <scratch-dir>. Never writes the repo.
"""
import asyncio
import hashlib
import shutil
import sys
import time
from pathlib import Path

repo = Path(sys.argv[1])
scratch = Path(sys.argv[2])
sys.path.insert(0, str(repo))

import s19_app  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.screens import SaveProjectPayload  # noqa: E402

print("import:", Path(s19_app.__file__).resolve())
CASE01 = repo / "examples" / "case_01_basic_valid"
CASE06 = repo / "examples" / "case_06_large_nested_a2l"


def fresh(name):
    base = scratch / name
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    return base


def image_sha(mem_map):
    if not mem_map:
        return None
    h = hashlib.sha256()
    for addr, value in sorted(mem_map.items()):
        h.update(addr.to_bytes(8, "big"))
        h.update(bytes([value & 0xFF]))
    return h.hexdigest()[:16]


def digest(app):
    cf = app.current_file
    rel = lambda p: (str(Path(p).relative_to(app.workarea)) if p is not None and Path(p).is_relative_to(app.workarea) else (str(p) if p else None))
    return (
        rel(cf.path) if cf else None,
        image_sha(cf.mem_map) if cf else None,
        app.current_project,
        rel(app.current_a2l_path),
        rel(cf.mac_path) if cf and cf.mac_path else None,
        len(app._change_service.document.entries),
    )


def make_project(app, name, case, files=("firmware.s19", "firmware.mac", "firmware.a2l")):
    project = app.workarea / name
    project.mkdir()
    for f in files:
        shutil.copy2(case / f, project / f)
    return project


async def u1():
    for label, case in (("case_01", CASE01),):
        base = fresh(f"u1-{label}-cold")
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            make_project(app, "P2", case)
            app._handle_load_project("P2")
            await pilot.pause()
            cold = digest(app)
            cold_snap = app._session_snapshot()
            print(f"== U1 {label} cold P2 digest {cold}")
        base = fresh(f"u1-{label}-over")
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            make_project(app, "P2", case)
            other = base / "p1img.s19"
            shutil.copy2(case / "firmware.s19", other)
            app.load_selected_file(other)
            await pilot.pause()
            print(f"== U1 {label} P1 before: {digest(app)}")
            app._handle_load_project("P2")
            await pilot.pause()
            over = digest(app)
            over_snap = app._session_snapshot()
            diff = sorted(k for k in set(cold_snap) | set(over_snap) if cold_snap.get(k) != over_snap.get(k))
            print(f"== U1 {label} P2-over-P1 digest {over} equal_to_cold={over == cold} snapshot names differing {diff}")
    base = fresh("u1-case06-cold")
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        make_project(app, "P6", CASE06)
        t = time.perf_counter()
        app._handle_load_project("P6")
        dt = time.perf_counter() - t
        await pilot.pause()
        print(f"== U1 case_06 cold P6 digest {digest(app)} wall {dt:.2f} s")


async def u2():
    base = fresh("u2")
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        p2 = make_project(app, "P2", CASE01)
        merged_none = app._parse_loaded_file(p2 / "firmware.mac", [p2 / "firmware.a2l"])
        print(f"== U2 no image open: _parse_loaded_file(P2/firmware.mac) -> file_type={merged_none.file_type} path={merged_none.path.name} mac={merged_none.mac_path.name if merged_none.mac_path else None}")
        other = base / "p1img.s19"
        shutil.copy2(CASE01 / "firmware.s19", other)
        app.load_selected_file(other)
        await pilot.pause()
        merged_live = app._parse_loaded_file(p2 / "firmware.mac", [p2 / "firmware.a2l"])
        print(f"== U2 P1 image open: _parse_loaded_file(P2/firmware.mac) -> file_type={merged_live.file_type} path={merged_live.path.name} parent={merged_live.path.parent.name} mac={merged_live.mac_path.name if merged_live.mac_path else None}")
        prim = app._parse_loaded_file(p2 / "firmware.s19", [p2 / "firmware.a2l"])
        print(f"== U2 P1 image open: _parse_loaded_file(P2/firmware.s19) -> mac carried={prim.mac_path.name if prim.mac_path else None}")


def u3():
    for label, path in (("case_01", CASE01 / "firmware.a2l"), ("case_06", CASE06 / "firmware.a2l")):
        size = path.stat().st_size
        text_sum = 0
        positions = []
        lines = 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                lines += 1
                text_sum += len(raw.encode("utf-8"))
                pos = handle.buffer.tell()
                if not positions or positions[-1] != pos:
                    positions.append(pos)
        mono = all(b >= a for a, b in zip(positions, positions[1:]))
        print(f"== U3 {label} size {size} lines {lines} text-mode bytes {text_sum} (short by {size - text_sum}) "
              f"buffer.tell distinct {len(positions)} first {positions[0]} last {positions[-1]} non-decreasing {mono}")
        t = time.perf_counter()
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                pass
        plain = time.perf_counter() - t
        t = time.perf_counter()
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                handle.buffer.tell()
        told = time.perf_counter() - t
        print(f"== U3 {label} loop plain {plain:.3f} s, with tell per line {told:.3f} s")


class RecordingApp(S19TuiApp):
    CSS_PATH = str(repo / "s19_app" / "tui" / "styles.tcss")
    record = None

    def __setattr__(self, name, value):
        rec = type(self).record
        if rec is not None and not name.startswith("_reactive") and name not in rec:
            rec.append(name)
        super().__setattr__(name, value)


async def u4():
    base = fresh("u4")
    app = RecordingApp(base_dir=base)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        make_project(app, "P2", CASE01)
        RecordingApp.record = []
        app._handle_load_project("P2")
        print("== U4 project load assigns", sorted(RecordingApp.record))
        RecordingApp.record = []
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="Q"))
        print("== U4 save assigns", sorted(RecordingApp.record))
        RecordingApp.record = None
    base = fresh("u4a")
    app = RecordingApp(base_dir=base)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        RecordingApp.record = []
        app.load_a2l_from_path(CASE01 / "firmware.a2l")
        print("== U4 A2L attach assigns", sorted(RecordingApp.record))
        RecordingApp.record = None


parts = sys.argv[3].split(',') if len(sys.argv) > 3 else ['u3', 'u2', 'u1', 'u4']
if 'u3' in parts:
    u3()
if 'u2' in parts:
    asyncio.run(u2())
if 'u1' in parts:
    asyncio.run(u1())
if 'u4' in parts:
    asyncio.run(u4())
