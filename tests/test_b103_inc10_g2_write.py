"""Batch-103 Inc 10, E4 group G2 (app handlers, the write): the file the prompt writes, in the format chosen.

Cases: ``inc-10/02-test-cases.md`` rows R-PE-EXPORT.8/1..2, .13/1, .14/4, .15/1..2, R-HEX-SAVE-001.1/1..4,
R-S19-SAVE-REUSE-001.1/1..4, R-S19-S0HEADER-001.1/1..2, .2/1..4, .3/1..4, R-HEX-VERIFY-001.1/1..4,
R-HEX-VERIFY-002.1/1..2, AT-I10-1 and AT-I10-2.  One scene may carry several cases (the docstring names each).
Not written, by ruling D-6 A (open code changes D8-27, D8-29; ``conflict`` cases): R-S19-S0HEADER-001.1/3,
R-S19-EMIT.11/1, R-S19-EMIT.11/2.  R-S19-S0HEADER-001.2/5 (D8-28, folded in by the P-022 ruling) is in
``test_b103_inc10_s0_written_name.py``.  E4-N2: nothing here asserts an empty S0 for a source
that has S0 data, nor a terminator address.

Expected values: the S0 data of a source is read from the source with ``tests/support/independent_reader.py``;
files written are read back with the same independent reader and, for record types, from the text.
RED on base ``439860c4``: there is no Format control (the click misses) and the file is written in the loaded
image's kind.
"""
from __future__ import annotations

import pytest

from tests.support import b103_inc10 as t
from tests.support.independent_reader import read_hex, read_s19

SAVED_HEAD = "Saved + verified: "
ENTRY_TAIL = " — 1 entry applied before this save (0x8000007C)"


async def press_format(pilot, times: int = 1) -> None:
    for _ in range(times):
        await t.press_button(pilot, "#patch_saveback_format_button")


def format_text(app) -> str:
    return t.painted(app, t.need(app.screen, "#patch_saveback_format_button"))


# ------------------------------------------------------------------ R-PE-EXPORT.8: one press, shown and written


def test_r_pe_export_8_1_one_press_changes_s19_to_intel_hex_shown_and_written(tmp_path):
    """R-PE-EXPORT.8/1: Format, ``Write file`` -> the control shows ``Intel HEX`` and the written file's first
    line starts with ``:``.  Negative control: a press that changes nothing -> RED."""

    async def body(app, pilot):
        await press_format(pilot)
        label = format_text(app)
        await t.write_file(pilot, app)
        return label, t.first_line(t.written(app, "firmware-patched.hex"))

    label, line = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert "Intel HEX" in label and line.startswith(":"), (label, line)


def test_r_pe_export_8_2_a_second_press_changes_back_to_s19(tmp_path):
    """R-PE-EXPORT.8/2: Format, Format, ``Write file`` -> the control shows ``S19``; the written file's first
    line starts with ``S0``.  Negative control: the press only ever sets Intel HEX -> RED."""

    async def body(app, pilot):
        await press_format(pilot, 2)
        label = format_text(app)
        await t.write_file(pilot, app)
        return label, t.first_line(t.written(app, "firmware-patched.s19"))

    label, line = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert "S19" in label and "Intel HEX" not in label and line.startswith("S0"), (label, line)


def test_r_pe_export_13_1_a_format_change_keeps_the_width(tmp_path):
    """R-PE-EXPORT.13/1: Width (16), Format, Format, ``Write file`` -> ``Width: 16 bytes/line`` and every S3
    record of the written file holds at most 16 data bytes (and there are some).  Negative control: the width
    reset to 32 on a format change -> a longer record -> RED."""

    async def body(app, pilot):
        await t.press_button(pilot, "#patch_saveback_width_button")
        await press_format(pilot, 2)
        label = t.painted(app, t.need(app.screen, "#patch_saveback_width_button"))
        await t.write_file(pilot, app)
        return label, t.s19_data_lengths(t.written(app, "firmware-patched.s19"))

    label, lengths = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert "Width: 16 bytes/line" in label, label
    assert lengths and max(lengths) <= 16, lengths


# ------------------------------------------------------------------ R-PE-EXPORT.14/4, .15: names


def test_r_pe_export_14_4_a_trailing_space_does_not_stop_the_replacement(tmp_path):
    """R-PE-EXPORT.14/4: name box ``firmware-patched.s19 `` (one trailing space), Format, ``Write file`` -> the
    name box ``firmware-patched.hex`` and the file ``firmware-patched.hex`` (no ``.s19.hex``).  Negative
    control: the suffix matched only at the very end of the text -> ``firmware-patched.s19.hex`` -> RED."""

    async def body(app, pilot):
        await t.type_into(pilot, "#patch_saveback_name_input", "firmware-patched.s19 ")
        await press_format(pilot)
        name = t.name_value(app)
        await t.write_file(pilot, app)
        return name, t.work_files(app)

    name, files = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert name == "firmware-patched.hex", name
    assert "firmware-patched.hex" in files and "firmware-patched.s19.hex" not in files, files


@pytest.mark.parametrize("case,typed,written_as", [("R-PE-EXPORT.15/1", "release_v2", "release_v2.hex"),
                                                   ("R-PE-EXPORT.15/2", "x.bin", "x.bin.hex")],
                         ids=["R-PE-EXPORT.15/1", "R-PE-EXPORT.15/2"])
def test_r_pe_export_15_a_name_without_a_format_suffix_is_kept_and_the_write_adds_it(tmp_path, case, typed, written_as):
    """R-PE-EXPORT.15/1,/2: the name box ``release_v2`` / ``x.bin``, Format -> the name box is unchanged;
    ``Write file`` as Intel HEX writes ``release_v2.hex`` / ``x.bin.hex`` (R-HEX-SAVE-001.2).  Negative
    control: the suffix appended into the box on a press -> RED."""

    async def body(app, pilot):
        await t.type_into(pilot, "#patch_saveback_name_input", typed)
        await press_format(pilot)
        name = t.name_value(app)
        await t.write_file(pilot, app)
        return name, t.work_files(app)

    name, files = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert name == typed, (case, name)
    assert written_as in files, (case, files)


# ------------------------------------------------------------------ the conversion matrix through the prompt


CONVERT = [
    ("R-HEX-SAVE-001.1/1 R-HEX-VERIFY-001.1/1 R-S19-S0HEADER-001.1/1", "firmware.s19", 0, "firmware-patched.s19"),
    ("R-HEX-SAVE-001.1/2 R-HEX-VERIFY-001.1/2 R-HEX-VERIFY-002.1/1", "firmware.s19", 1, "firmware-patched.hex"),
    ("R-HEX-SAVE-001.1/3 R-HEX-VERIFY-001.1/3", "firmware.hex", 0, "firmware-patched.hex"),
    ("R-HEX-SAVE-001.1/4 R-HEX-VERIFY-001.1/4 R-HEX-VERIFY-002.1/2 R-S19-S0HEADER-001.2/1", "firmware.hex", 1,
     "firmware-patched.s19"),
]


@pytest.mark.parametrize("cases,source,presses,name", CONVERT, ids=[c[0].split()[0] for c in CONVERT])
def test_the_prompt_writes_the_chosen_format_and_verifies_it(tmp_path, cases, source, presses, name):
    """Cases in the parameter: R-HEX-SAVE-001.1/n (the file in the output format: first line ``S0`` / ``:``, the
    name ends with the format suffix), R-HEX-VERIFY-001.1/n and R-HEX-VERIFY-002.1/n (status ``Saved +
    verified: <name> - 1 entry applied before this save (0x8000007C)``), R-S19-S0HEADER-001.1/1 (case01 -> S0
    data of the source, read from the source) and R-S19-S0HEADER-001.2/1 (a HEX source -> S0 data = the written
    name).  The written file is read back with the independent reader: the patched image.  Negative control:
    the file written in the loaded image's kind (the base) -> /2 and /4 RED; the verify read with the loaded
    image's reader -> ``Verify MISMATCH`` -> RED."""

    async def body(app, pilot):
        await press_format(pilot, presses)
        await t.write_file(pilot, app)
        return t.painted_log(app), t.written(app, name)

    log, path = t.run_applied(tmp_path, t.SIZE, source, "patch_tab_inspector", body)
    assert SAVED_HEAD + name + ENTRY_TAIL in log, (cases, log)
    first = t.first_line(path)
    if name.endswith(".hex"):
        assert first.startswith(":"), (cases, first)
        if source == "firmware.hex":
            assert first == ":0200000480007A", first
        image = read_hex(path)
    else:
        assert first.startswith("S0"), (cases, first)
        image = read_s19(path)
        assert image.header == (read_s19(t.CASE01).header if source == "firmware.s19" else name.encode()), image.header
    expected = dict(read_s19(t.CASE01).data)
    expected.update(zip(range(0x8000007C, 0x80000080), t.PATCH_RUN))
    assert image.errors == [] and image.data == expected, (cases, image.errors)


# ------------------------------------------------------------------ R-S19-SAVE-REUSE-001.1: 16-byte HEX records


REUSE = [("R-S19-SAVE-REUSE-001.1/1", "firmware.s19", ("format",)),
         ("R-S19-SAVE-REUSE-001.1/2", "firmware.s19", ("width", "format")),
         ("R-S19-SAVE-REUSE-001.1/3", "firmware.hex", ()),
         ("R-S19-SAVE-REUSE-001.1/4", "firmware.hex", ("format", "width", "format"))]


@pytest.mark.parametrize("case,source,presses", REUSE, ids=[c[0] for c in REUSE])
def test_r_s19_save_reuse_001_1_a_hex_save_back_holds_at_most_16_data_bytes_per_record(tmp_path, case, source, presses):
    """R-S19-SAVE-REUSE-001.1/1..4: written as Intel HEX (width 32 and 16, S19 and HEX sources, through the
    prompt's chips) no type-00 record holds more than 16 data bytes, and there are type-00 records.  Negative
    control: the width handed to the HEX writer (32-byte records) -> RED."""

    async def body(app, pilot):
        for press in presses:
            await (press_format(pilot) if press == "format" else t.press_button(pilot, "#patch_saveback_width_button"))
        await t.write_file(pilot, app)
        return t.hex_records(t.written(app, "firmware-patched.hex"))

    records = t.run_applied(tmp_path, t.SIZE, source, "patch_tab_inspector", body)
    lengths = [length for kind, _offset, length in records if kind == 0]
    assert lengths and max(lengths) <= 16, (case, lengths)


# ------------------------------------------------------------------ the S0 header of an Intel HEX source (handler)


S0_TWINS = [("R-S19-S0HEADER-001.3/1", "firmware.hex", None),
            ("R-S19-S0HEADER-001.2/2 R-S19-S0HEADER-001.3/2", "s19_sample.hex", "s19_sample-patched.s19"),
            ("R-S19-S0HEADER-001.2/3 R-S19-S0HEADER-001.3/3", "s2_source.hex", "s2_source-patched.s19"),
            ("R-S19-S0HEADER-001.2/4 R-S19-S0HEADER-001.3/4", "cross64k.hex", "cross64k-patched.s19")]


@pytest.mark.parametrize("cases,source,name32", S0_TWINS, ids=[c[0].split()[0] for c in S0_TWINS])
def test_r_s19_s0header_001_an_intel_hex_source_written_as_s19_gets_its_header(tmp_path, cases, source, name32):
    """R-S19-S0HEADER-001.2/2..4 (width 32: S0 data = the written name) and R-S19-S0HEADER-001.3/1..4 (width
    16: first line ``S0030000FC``), the four Intel HEX twins, through the app's save-back handler (the confirm
    message the Write file chip posts, with the output format; this is partial: no prompt is clicked, the
    prompt's own route is the conversion test above).  Negative control: empty header data at width 32 / a
    name header at width 16 -> RED; on base the confirm message takes no output format -> RED."""
    stem = source[:-4]

    async def body(app, pilot):
        out = {}
        if name32:
            await t.post_decision(app, pilot, name32, "s19", 32)
            out["w32"] = t.s0_data(t.written(app, name32))
        await t.post_decision(app, pilot, f"{stem}-w16.s19", "s19", 16)
        out["w16"] = t.first_line(t.written(app, f"{stem}-w16.s19"))
        return out

    out = t.run_loaded(tmp_path, t.SIZE, source, body)
    if name32:
        assert out["w32"] == name32.encode(), (cases, out["w32"])
    assert out["w16"] == "S0030000FC", (cases, out["w16"])


def test_r_s19_s0header_001_1_2_the_source_s0_data_is_kept_at_width_32_for_case00(tmp_path):
    """R-S19-S0HEADER-001.1/2: case00 (S0 data ``Debug\\stm8s003.sm8``, read from the source) written as S19 at
    width 32 through the handler keeps that data.  Negative control: the header taken from the file name when
    the source has S0 data -> RED."""
    expected = read_s19(t.CASE00).header
    assert expected, "the source has S0 data (vacuity guard)"

    async def body(app, pilot):
        await t.post_decision(app, pilot, "s19_sample-patched.s19", "s19", 32)
        return t.s0_data(t.written(app, "s19_sample-patched.s19"))

    assert t.run_loaded(tmp_path, t.SIZE, "s19_sample.s19", body) == expected


# ------------------------------------------------------------------ the acceptance cases


def test_at_i10_1_apply_from_the_inspector_tab_and_export_intel_hex(tmp_path):
    """AT-I10-1 (118x54): case01 loaded through the Load dialog; the Inspector chip pressed BEFORE the entry
    (the entry boxes are in the Inspector pane; the default tab is Patch script since Inc 8, finding F-T10-1);
    0x8000007C ``DE AD BE EF`` typed and Add; Apply; Format; ``Write file``.  No chip is pressed after Apply.
    The apply line is shown; after Format the control shows ``Intel HEX``, the name box is
    ``firmware-patched.hex``, no Width control is painted; the status is ``Saved + verified:
    firmware-patched.hex - 1 entry applied before this save (0x8000007C)``; the file reads back (independent
    Intel HEX reader) with ``DE AD BE EF`` at 0x8000007C and case01's bytes elsewhere.  Negative control: a
    prompt hidden after Apply, no Format control, or the file written as S19 -> RED."""

    async def scene(app, pilot):
        t.TYPING["mode"] = "keys"
        path = t.copy_source(tmp_path, "firmware.s19")
        await t.load_via_dialog(pilot, app, path)
        await t.open_patch_editor(pilot, app)
        await t.click_tab(pilot, "patch_tab_inspector")
        await t.add_entry(pilot, app)
        await t.press_apply(pilot, app)
        seen = {"line": t.painted(app, t.need(app.screen, "#patch_saveback_apply_line"))}
        await press_format(pilot)
        seen["format"] = format_text(app)
        seen["name"] = t.name_value(app)
        seen["width"] = t.painted(app, t.need(app.screen, "#patch_saveback_width_button"))
        await t.write_file(pilot, app)
        seen["log"] = t.painted_log(app)
        seen["path"] = t.written(app, "firmware-patched.hex")
        return seen

    try:
        seen = t.run_scene(tmp_path, t.SIZE, scene)
    finally:
        t.TYPING["mode"] = "value"
    assert seen["line"] == t.APPLY_LINE_1, seen["line"]
    assert "Intel HEX" in seen["format"] and seen["name"] == "firmware-patched.hex", seen
    assert "Width" not in seen["width"], seen["width"]
    assert SAVED_HEAD + "firmware-patched.hex" + ENTRY_TAIL in seen["log"], seen["log"]
    expected = dict(read_s19(t.CASE01).data)
    expected.update(zip(range(0x8000007C, 0x80000080), t.PATCH_RUN))
    image = read_hex(seen["path"])
    assert image.errors == [] and image.data == expected


def test_at_i10_2_an_intel_hex_image_exported_as_s19_at_16_bytes_per_line(tmp_path):
    """AT-I10-2 (220x60): ``firmware.hex`` (case01's twin) loaded through the Load dialog; the entry added from
    the Inspector pane, then the Checks tab shown; Apply; Format; Width; ``Write file``.  The Format control
    showed ``Intel HEX`` first, then ``S19``; ``Width: 16 bytes/line``; ``firmware-patched.s19`` written: first
    line ``S0030000FC``, S3 data records of at most 16 data bytes, terminator ``S7``; status ``Saved +
    verified: firmware-patched.s19 - ...``.  Negative control: the Width press ignored, the file written as
    Intel HEX, or a name header at width 16 -> RED."""

    async def scene(app, pilot):
        t.TYPING["mode"] = "keys"
        path = t.copy_source(tmp_path, "firmware.hex")
        await t.applied_scene(pilot, app, path, "patch_tab_checks", dialog=True)
        seen = {"first": format_text(app)}
        await press_format(pilot)
        seen["second"] = format_text(app)
        await t.press_button(pilot, "#patch_saveback_width_button")
        seen["width"] = t.painted(app, t.need(app.screen, "#patch_saveback_width_button"))
        await t.write_file(pilot, app)
        seen["log"] = t.painted_log(app)
        seen["path"] = t.written(app, "firmware-patched.s19")
        return seen

    try:
        seen = t.run_scene(tmp_path, t.WIDE, scene)
    finally:
        t.TYPING["mode"] = "value"
    assert "Intel HEX" in seen["first"] and "S19" in seen["second"] and "Intel HEX" not in seen["second"], seen
    assert "Width: 16 bytes/line" in seen["width"], seen["width"]
    assert SAVED_HEAD + "firmware-patched.s19" in seen["log"], seen["log"]
    path = seen["path"]
    lengths = t.s19_data_lengths(path)
    assert t.first_line(path) == "S0030000FC" and t.last_tag(path) == "S7", (t.first_line(path), t.last_tag(path))
    assert lengths and max(lengths) <= 16, lengths
    assert {l[:2] for l in path.read_text().splitlines() if l[:2] in ("S1", "S2", "S3")} == {"S3"}
