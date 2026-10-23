"""T6 threads: Split / Join / Export from the in-memory image (Code-Wire data audit)."""
from pathlib import Path

from cwh import C1, new_base, mini_s19, out


def _case01():
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19
    return build_loaded_s19(C1 / "firmware.s19", S19File(str(C1 / "firmware.s19")), None, None)


def test_t6a_split_by_ranges_case01():
    """T6a: Split tab `ranges` on case_01, every row, S19 out (the rows the window builds)."""
    from s19_app.tui.segment_split_view import SegRow, write_split_join_export
    loaded = _case01()
    rows = [SegRow(f"range_{i:02d}", "ranges", s, e - s) for i, (s, e) in enumerate(loaded.ranges)]
    base = new_base()
    written = write_split_join_export(loaded.mem_map, rows, mode="split", gap="skip", pad_byte=0xFF,
                                      fmt="s19", stem="firmware", dest_dir=base / "splits",
                                      zero_coverage_empty=True)
    for p in written:
        mem, errs, meta = mini_s19(p)
        lines = p.read_text().splitlines()
        out("T6a", file=p.name, first=lines[0], data_bytes=len(mem),
            lo=hex(min(mem)) if mem else None, s0=meta["s0"], term=meta["term"],
            text=bytes(mem[a] for a in sorted(mem))[:12] if mem else b"")


def test_t6b_split_mac_only_manual_row():
    """T6b: MAC-only session (mem_map = the MAC placeholders), one Manual row over BLOCK_A."""
    from s19_app.tui.segment_split_view import SegRow, write_split_join_export, parse_manual
    from s19_app.tui.mac import parse_mac_file
    recs = parse_mac_file(C1 / "firmware.mac")["records"]
    mem_map = {int(r["address"]): 0 for r in recs if r.get("parse_ok") and isinstance(r.get("address"), int)}
    rows, errs = parse_manual("0x80000000-0x8000000F")
    base = new_base()
    written = write_split_join_export(mem_map, rows, mode="split", gap="skip", pad_byte=0xFF,
                                      fmt="s19", stem="firmware", dest_dir=base / "splits",
                                      zero_coverage_empty=True)
    from s19_app.tui.segment_split_view import build_plan
    plan = build_plan(rows, {0}, [], mem_map, mode="split", gap="skip", stem="firmware", ext="s19", pad_byte=0xFF)
    out("T6b-plan", empty_files=plan.empty_files, packed=plan.packed, files=[(f.label, f.packed, f.empty) for f in plan.files])
    for p in written:
        mem, _, _ = mini_s19(p)
        out("T6b", manual_rows=[(r.name, hex(r.base), r.size) for r in rows], parse_errors=errs,
            file=p.name, data={hex(a): v for a, v in mem.items()}, lines=p.read_text().splitlines())


def test_t6c_join_fill_two_real_ranges():
    """T6c: Join fill over the two real case_01 ranges (no S0 row): offsets kept, pad 0xFF."""
    from s19_app.tui.segment_split_view import SegRow, write_split_join_export
    loaded = _case01()
    real = [(s, e) for s, e in loaded.ranges if s >= 0x80000000]
    rows = [SegRow(f"range_{i:02d}", "ranges", s, e - s) for i, (s, e) in enumerate(real)]
    base = new_base()
    written = write_split_join_export(loaded.mem_map, rows, mode="join", gap="fill", pad_byte=0xFF,
                                      fmt="s19", stem="firmware", dest_dir=base / "splits")
    p = written[0]
    mem, _, meta = mini_s19(p)
    out("T6c", file=p.name, bytes=len(mem), pad_0x80000021=hex(mem.get(0x80000021, -1)),
        s0=meta["s0"], term=meta["term"], src_term=hex(loaded.entry_point))
