"""Validate the CAP9b evidence matrix without launching or modifying the app."""
from pathlib import Path
import re
import struct
import sys

ROOT = Path(sys.argv[1])
COMMIT = "d05b5180e5f48d4a167d13e7fb45b24586293eb6"
FRAMES = "◐◓◑◒"
JOB = ["decode", "preview", "stage-encode", "stage-refused", "stage-refresh"]
HOSTILE = ["name-markup", "name-brackets", "name-esc", "name-c1"]
SEQUENCES = [(scene, size) for scene in JOB for size in ("118x54", "220x60")]
SEQUENCES += [(scene, size) for scene in HOSTILE for size in ("118x54", "220x60")]
SEQUENCES += [("name-long", "80x24"), ("name-long", "118x54"), ("name-long", "220x60"), ("name-short", "80x24")]
EXPECTED_TEXT = {
    "name-markup": "decode [@click=app.quit]X[/] ·",
    "name-brackets": "decode A[b]B ·",
    "name-esc": "decode A" + chr(0xFFFD) + "[2J ·",
    "name-c1": "decode B" + chr(0xFFFD) + "C ·",
}


def sidecar(path):
    text = path.read_text(encoding="utf-8")
    assert "\x1b" not in text and "\x85" not in text, path
    data = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key] = value
    return text, data


count = 0
for scene, size in SEQUENCES:
    phases = ["f1", "f2"] + (["idle"] if scene in JOB else [])
    states = {}
    for phase in phases:
        png = ROOT / f"{scene}.{size}.{phase}.png"
        text, data = sidecar(Path(str(png) + ".txt"))
        raw = png.read_bytes()
        assert raw[:8] == b"\x89PNG\r\n\x1a\n", png
        width, height = struct.unpack(">II", raw[16:24])
        assert data["commit"] == COMMIT and data["surface"] == "ready"
        assert data["requested_size"] == size and data["app_size"] == size
        assert data["png_name"] == png.name and data["phase"] == {"f1": "busy-f1", "f2": "busy-f2"}.get(phase, phase)
        assert (data["png_width"], data["png_height"]) == (str(width), str(height))
        assert data["png_bytes"] == str(len(raw)) and width > 100 and height > 100
        assert data["stub_os_writes"] == "0"
        states[phase] = data
        count += 1
        if phase != "idle":
            assert data["capture_frame_hold"] == "True" and data["frame_hold_painted_stable"] == "True"
            assert data["painted_top_left_border_color"] == "#f5c26b"
            assert data["pill_bold"] == "True" and data["pill_foreground"] == "#0a0e1b"
            assert data["pill_background"] == "#f5c26b" and data["spinner_glyph"] in FRAMES
    first, second = states["f1"], states["f2"]
    assert second["different_from_f1"] == "True" and second["frame_pair_valid"] == "True"
    assert second["same_job_name"] == "True" and second["elapsed_nondecreasing"] == "True"
    assert second["job_word"] == first["job_word"] and second["busy_name"] == first["busy_name"]
    assert FRAMES.index(second["spinner_glyph"]) == (FRAMES.index(first["spinner_glyph"]) + 1) % 4
    assert float(second["pending_seconds"]) >= float(first["pending_seconds"])
    assert second["painted_sheet_top_row"] != first["painted_sheet_top_row"]
    if "idle" in states:
        idle = states["idle"]
        assert idle["idle_title"] == "True" and idle["busy_absent"] == "True" and idle["idle_border_not_busy"] == "True"
        assert idle["record_hold"] == "False"
    if scene == "decode":
        assert states["idle"]["values_present"] == "True"
    elif scene == "preview":
        assert states["idle"]["preview_result_kind"] == "Encoded"
    elif scene == "stage-encode":
        assert states["f1"]["document_entry_count"] == states["f2"]["document_entry_count"] == "0"
        assert states["idle"]["document_entry_count"] == "1" and states["idle"]["ledger_row_count"] == "1"
    elif scene == "stage-refused":
        assert all(states[p]["document_entry_count"] == "0" for p in phases)
        assert "outside the limits -50..50" in sidecar(ROOT / f"{scene}.{size}.idle.png.txt")[0]
    elif scene == "stage-refresh":
        assert states["f1"]["write_landed_before_busy"] == states["f2"]["write_landed_before_busy"] == "True"
        assert states["f1"]["document_entry_count"] == states["f2"]["document_entry_count"] == "1"
        assert states["f1"]["held_refresh_callbacks"] == states["f2"]["held_refresh_callbacks"] == "1"
        assert states["idle"]["held_refresh_callback_invocations"] == "1"
        assert states["idle"]["document_entry_count"] == "1" and states["idle"]["staged_mark"] == "True"
    if scene in EXPECTED_TEXT:
        assert EXPECTED_TEXT[scene] in first["painted_sheet_top_row"], (scene, first["painted_sheet_top_row"])
    if scene == "name-long":
        expected = {"80x24": 6, "118x54": 46, "220x60": 130}[size]
        match = re.search(r"decode (N+)… ·", first["painted_sheet_top_row"])
        assert match and len(match.group(1)) == expected, (size, first["painted_sheet_top_row"])
        assert " keys still work " in first["painted_sheet_top_row"]
    if scene == "name-short":
        assert "decode N ·" in first["painted_sheet_top_row"] and "…" not in first["painted_sheet_top_row"]

assert count == 54, count
print(f"CAP9B_VALIDATION sequences={len(SEQUENCES)} png={count} sidecars={count} verdict=PASS")
print(f"pairs={len(SEQUENCES)} spinner_order=PASS elapsed_nondecreasing=PASS exact_sidecars=PASS")
print("idle=10 hostile=8 long=3 short=1 stage_post_write=2")
