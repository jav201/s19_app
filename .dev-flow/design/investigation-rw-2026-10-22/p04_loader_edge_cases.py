"""P04: crafted S19 / Intel HEX inputs through the flow SOURCE block: is each
defect an error, a notice, or silent? Reports the SOURCE block status, the
number of notices, and the loaded byte count vs the bytes the file declares."""
from common import *
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, WriteOutBlock
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.changes.io import _s19_record, _intel_hex_record

def s1(addr, data): return _s19_record("S1", 2, addr, tuple(data))
def s3(addr, data): return _s19_record("S3", 4, addr, tuple(data))
def h(t, a, d): return _intel_hex_record(t, a, list(d))
D = list(range(16))
good_s19 = [s1(0x1000, D), s1(0x1010, D), "S9030000FC"]
s19_cases = {
    "s19_good": good_s19,
    "s19_truncated_no_terminator": good_s19[:1],                       # last data line + S9 lost
    "s19_bad_checksum": [s1(0x1000, D)[:-2] + "00", "S9030000FC"],
    "s19_overlap_conflict": [s1(0x1000, D), s1(0x1008, [0xEE] * 8), "S9030000FC"],
    "s19_duplicate_identical": [s1(0x1000, D), s1(0x1000, D), "S9030000FC"],
    "s19_count_S5_mismatch": [s1(0x1000, D), _s19_record("S5", 2, 7, ()), "S9030000FC"],
    "s19_S4_record": [s1(0x1000, D), "S4050000000000", "S9030000FC"],
    "s19_garbage_line": [s1(0x1000, D), "hello world", "S9030000FC"],
    "s19_lowercase": [s1(0x1000, D).lower(), "S9030000FC"],
    "s19_header_only_S0": [_s19_record("S0", 2, 0, b"HDR"), "S9030000FC"],
    "s19_data_after_term": [s1(0x1000, D), "S9030000FC", s1(0x2000, D)],
    "s19_line_cut_midrecord": [s1(0x1000, D), s1(0x1010, D)[:20]],
    "s19_S0_nonzero_addr": [_s19_record("S0", 2, 0x1000, b"HDRHDR"), s1(0x1000, D), "S9030000FC"],
}
good_hex = [h(4, 0, [0, 0]), h(0, 0x1000, D), h(0, 0x1010, D), h(1, 0, [])]
hex_cases = {
    "hex_good": good_hex,
    "hex_no_eof_truncated": good_hex[:2],
    "hex_data_after_eof": good_hex + [h(0, 0x2000, D)],
    "hex_bad_checksum": [good_hex[0], good_hex[1][:-2] + "00", h(1, 0, [])],
    "hex_overlap_conflict": [good_hex[0], h(0, 0x1000, D), h(0, 0x1008, [0xEE] * 8), h(1, 0, [])],
    "hex_unknown_type_06": [good_hex[0], h(0, 0x1000, D), h(6, 0, [1]), h(1, 0, [])],
    "hex_seg_wrap_type02": [h(2, 0, [0x10, 0x00]), h(0, 0xFFF8, D), h(1, 0, [])],
    "hex_missing_colon": [good_hex[0], h(0, 0x1000, D)[1:], h(1, 0, [])],
    "hex_ela_bad_len": [h(4, 0, [0]), h(0, 0x1000, D), h(1, 0, [])],
}
for cases, ext, fmt in ((s19_cases, "s19", "s19"), (hex_cases, "hex", "hex")):
    for name, lines in cases.items():
        proj = new_project(src=None)
        (proj / f"in.{ext}").write_text("\n".join(lines) + "\n")
        flow = Flow(name=name, blocks=[SourceBlock(f"in.{ext}", file_type=fmt), WriteOutBlock(f"o.{ext}", fmt=fmt)])
        r = run_flow(flow, FlowContext(project_dir=proj))
        sb = r.block_results[0]
        out = r.written_paths[0] if r.written_paths else None
        if out:
            mem = mini_s19(out)[0] if ext == "s19" else mini_hex(out)[0]
        else:
            mem = {}
        print(f"{name:30s} run={r.status:22s} source={sb.status:8s} notices={len(sb.findings)} out_bytes={len(mem)} out_ranges={[(hex(a),hex(b)) for a,b in ranges_of(mem)]} {('| ' + sb.findings[0].message[:70]) if sb.findings else ''}")
