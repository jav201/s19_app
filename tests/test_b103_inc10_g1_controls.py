"""Batch-103 Inc 10, E4 group G1 (panel and dock), part 2: the prompt's controls.

Cases: ``inc-10/02-test-cases.md`` rows R-PE-EXPORT.7/1..3, .9/1..2, .10/1..2, .11/1..2, .12/1..4, .14/1..3,
R-S19-WIDTH-001.1/1, .2/1, R-HEX-VERIFY-002.3/1..2, R-TUI-064.1/1..2, .2/1..2, .4/1 (the placement cases are in
``test_b103_inc10_g1_panel.py``).  Same drivers and same RED premise on base ``439860c4``: no Format control,
no dock, the prompt inside an undisplayed window.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.b97_probes import clipped_overflow, displayed_descendants
from tests.support import b103_inc10 as t

applied = t.run_applied


def loaded(tmp_path: Path, size, source: str, body):
    """``source`` loaded and the Patch Editor open, no apply, then ``body``."""
    return t.run_loaded(tmp_path, size, source, body)


async def format_press(pilot) -> None:
    await t.press_button(pilot, "#patch_saveback_format_button")


# ------------------------------------------------------------------ R-PE-EXPORT.7, .9: the Format control


def test_r_pe_export_7_1_the_format_control_shows_s19_for_an_s19_image(tmp_path):
    """R-PE-EXPORT.7/1 + R-PE-EXPORT.9/1: Applied case01 -> the painted Format control holds ``S19`` and not
    ``Intel HEX``.  Negative control: always Intel HEX, or no control (base) -> RED."""

    async def body(app, pilot):
        return t.painted(app, t.need(app.screen, "#patch_saveback_format_button"))

    text = applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert "S19" in text and "Intel HEX" not in text, text


def test_r_pe_export_7_2_the_format_control_shows_intel_hex_for_an_intel_hex_image(tmp_path):
    """R-PE-EXPORT.7/2: Applied HEX -> ``Intel HEX``.  Negative control: always S19 -> RED."""

    async def body(app, pilot):
        return t.painted(app, t.need(app.screen, "#patch_saveback_format_button"))

    text = applied(tmp_path, t.SIZE, "firmware.hex", "patch_tab_inspector", body)
    assert "Intel HEX" in text, text


def test_r_pe_export_7_3_each_new_prompt_starts_from_the_loaded_images_format(tmp_path):
    """R-PE-EXPORT.7/3: Format (Intel HEX), ``Don't save``, Apply -> the control shows ``S19``, the name box
    ``firmware-patched.s19``.  Negative control: the format kept from the last prompt -> RED."""

    async def body(app, pilot):
        await format_press(pilot)
        await t.press_button(pilot, "#patch_saveback_decline_button")
        await t.press_apply(pilot, app)
        return t.painted(app, t.need(app.screen, "#patch_saveback_format_button")), t.name_value(app)

    text, name = applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert "S19" in text and "Intel HEX" not in text, text
    assert name == "firmware-patched.s19", name


def test_r_pe_export_9_2_the_label_follows_a_press(tmp_path):
    """R-PE-EXPORT.9/2: after one Format press the painted control holds ``Intel HEX``.  Negative control: the
    label not refreshed on a press -> RED."""

    async def body(app, pilot):
        await format_press(pilot)
        return t.painted(app, t.need(app.screen, "#patch_saveback_format_button"))

    text = applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert "Intel HEX" in text and "S19" not in text, text


# ------------------------------------------------------------------ R-PE-EXPORT.10, .11: the Width control


async def width_is_inert(app, pilot, region) -> list:
    """Reasons the Width control at ``region`` is not inert: painted, focusable, or a click that acts."""
    problems = []
    if t.at_its_place(app, t.need(app.screen, "#patch_saveback_name_input")):
        problems.append("the prompt itself is not shown at its place (vacuity guard)")
    width = t.need(app.screen, "#patch_saveback_width_button")
    if "Width" in t.painted(app, width):
        problems.append("the Width control is painted")
    app.screen.set_focus(t.need(app.screen, "#patch_saveback_name_input"))
    seen = []
    for _ in range(12):
        await pilot.press("tab")
        seen.append(getattr(app.focused, "id", None))
    if "patch_saveback_width_button" in seen:
        problems.append(f"Tab focused the Width control: {seen}")
    before = (t.name_value(app), t.width_label(app))
    await pilot.click(offset=region.center)
    await t.settle(pilot, 3)
    if (t.name_value(app), t.width_label(app)) != before:
        problems.append(f"a click at its place changed {before} -> {(t.name_value(app), t.width_label(app))}")
    return problems


def test_r_pe_export_10_1_no_width_control_for_an_intel_hex_image(tmp_path):
    """R-PE-EXPORT.10/1: Applied HEX -> Width not painted, never focused by Tab, a click at its place leaves
    the width and the name box unchanged.  Negative control: Width shown for Intel HEX (base, B) -> RED."""

    async def body(app, pilot):
        region = t.need(app.screen, "#patch_saveback_width_button").region
        return await width_is_inert(app, pilot, region)

    assert applied(tmp_path, t.SIZE, "firmware.hex", "patch_tab_inspector", body) == []


def test_r_pe_export_10_2_no_width_control_after_switching_to_intel_hex(tmp_path):
    """R-PE-EXPORT.10/2: Applied case01, Format -> as /1, the click at the place the control had.
    Negative control: Width shown for Intel HEX -> RED."""

    async def body(app, pilot):
        region = t.need(app.screen, "#patch_saveback_width_button").region
        assert region.width > 0, "the Width control has no place to click before the switch"
        await format_press(pilot)
        return await width_is_inert(app, pilot, region)

    assert applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body) == []


def test_r_pe_export_11_1_the_width_control_is_shown_for_s19(tmp_path):
    """R-PE-EXPORT.11/1: Applied case01 -> ``Width: 32 bytes/line`` shown at its place.  Negative control:
    the control hidden for S19 -> RED (base: shown only in the JSON tab, C)."""

    async def body(app, pilot):
        width = t.need(app.screen, "#patch_saveback_width_button")
        return t.at_its_place(app, width), t.painted(app, width)

    place, text = applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert place == [] and "Width: 32 bytes/line" in text, (place, text)


def test_r_pe_export_11_2_the_width_control_returns_when_switching_intel_hex_to_s19(tmp_path):
    """R-PE-EXPORT.11/2: Applied HEX, Format -> ``Width: 32 bytes/line`` shown.  Negative control: the control
    stays hidden after the switch -> RED."""

    async def body(app, pilot):
        await format_press(pilot)
        width = t.need(app.screen, "#patch_saveback_width_button")
        return t.at_its_place(app, width), t.painted(app, width)

    place, text = applied(tmp_path, t.SIZE, "firmware.hex", "patch_tab_inspector", body)
    assert place == [] and "Width: 32 bytes/line" in text, (place, text)


# ------------------------------------------------------------------ R-PE-EXPORT.12: the chips stay put


EXPORT_12 = [("R-PE-EXPORT.12/1", t.SIZE, "firmware.s19"), ("R-PE-EXPORT.12/2", t.SIZE, "firmware.hex"),
             ("R-PE-EXPORT.12/3", t.WIDE, "firmware.s19"), ("R-PE-EXPORT.12/4", t.WIDE, "firmware.hex")]


@pytest.mark.parametrize("case,size,source", EXPORT_12, ids=[c[0] for c in EXPORT_12])
def test_r_pe_export_12_write_file_and_dont_save_stay_put_on_a_format_change(tmp_path, case, size, source):
    """R-PE-EXPORT.12/1..4: the regions of ``Write file`` and ``Don't save`` equal before and after a Format
    press (/1, /3 S19 -> Intel HEX; /2, /4 Intel HEX -> S19, the source being HEX).  Negative control: the
    Width control collapsed for Intel HEX -> ``Write file`` moves left -> RED."""
    ids = ("patch_saveback_confirm_button", "patch_saveback_decline_button")

    async def body(app, pilot):
        before = t.regions(app, ids)
        await format_press(pilot)
        return before, t.regions(app, ids)

    before, after = applied(tmp_path, size, source, "patch_tab_inspector", body)
    assert all(r.width > 0 for r in before.values()), (case, "no place before the press", before)
    assert before == after, (case, before, after)


# ------------------------------------------------------------------ R-S19-WIDTH-001


def test_r_s19_width_001_1_1_the_width_is_32_on_every_new_prompt(tmp_path):
    """R-S19-WIDTH-001.1/1: Width (16), ``Don't save``, Apply -> ``Width: 32 bytes/line``.  Negative control:
    the width kept across prompts -> RED."""

    async def body(app, pilot):
        await t.press_button(pilot, "#patch_saveback_width_button")
        assert "16" in t.width_label(app), t.width_label(app)
        await t.press_button(pilot, "#patch_saveback_decline_button")
        await t.press_apply(pilot, app)
        return t.width_label(app)

    assert applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body) == "Width: 32 bytes/line"


def test_r_s19_width_001_2_1_width_switches_32_16_in_the_new_placement(tmp_path):
    """R-S19-WIDTH-001.2/1: Width, Width -> ``Width: 16 bytes/line`` then ``Width: 32 bytes/line``, read from
    the painted control at its new place.  Negative control: the press changes nothing -> RED."""

    async def body(app, pilot):
        out = []
        for _ in range(2):
            await t.press_button(pilot, "#patch_saveback_width_button")
            out.append(t.painted(app, t.need(app.screen, "#patch_saveback_width_button")))
        return out

    first, second = applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert "Width: 16 bytes/line" in first and "Width: 32 bytes/line" in second, (first, second)


# ------------------------------------------------------------------ R-PE-EXPORT.14: the suggested name follows


async def retype_name(pilot, text: str) -> None:
    await t.type_into(pilot, "#patch_saveback_name_input", text)


def test_r_pe_export_14_1_the_suggested_name_follows_a_switch_to_intel_hex(tmp_path):
    """R-PE-EXPORT.14/1: Format -> name box ``firmware-patched.hex``.  Negative control: the name box left as
    it was -> RED."""

    async def body(app, pilot):
        await format_press(pilot)
        return t.name_value(app)

    assert applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body) == "firmware-patched.hex"


def test_r_pe_export_14_2_an_upper_case_suffix_is_replaced(tmp_path):
    """R-PE-EXPORT.14/2: name box ``MyImage.S19``, Format -> ``MyImage.hex``.  Negative control: a
    case-sensitive match -> the name stays ``MyImage.S19`` -> RED."""

    async def body(app, pilot):
        await retype_name(pilot, "MyImage.S19")
        await format_press(pilot)
        return t.name_value(app)

    assert applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body) == "MyImage.hex"


def test_r_pe_export_14_3_a_switch_to_s19_replaces_hex(tmp_path):
    """R-PE-EXPORT.14/3: Applied HEX, name box ``a.hex``, Format -> ``a.s19``.  Negative control: only
    ``.s19`` -> ``.hex`` handled -> RED."""

    async def body(app, pilot):
        await retype_name(pilot, "a.hex")
        await format_press(pilot)
        return t.name_value(app)

    assert applied(tmp_path, t.SIZE, "firmware.hex", "patch_tab_inspector", body) == "a.s19"


# ------------------------------------------------------------------ R-HEX-VERIFY-002.3: the suggested name


@pytest.mark.parametrize("case,source,expected", [
    ("R-HEX-VERIFY-002.3/1", "firmware.s19", "firmware-patched.s19"),
    ("R-HEX-VERIFY-002.3/2", "firmware.hex", "firmware-patched.hex")],
    ids=["R-HEX-VERIFY-002.3/1", "R-HEX-VERIFY-002.3/2"])
def test_r_hex_verify_002_3_the_suggested_name_follows_the_image(tmp_path, case, source, expected):
    """R-HEX-VERIFY-002.3/1,/2: the name box holds ``<stem>-patched<format suffix>`` after Apply.  The prompt
    must be a shown widget for the operator to see it (base: same text, in a 0x0 box).  Negative control:
    the suffix taken from the other format -> RED."""

    async def body(app, pilot):
        return t.name_value(app), t.at_its_place(app, t.need(app.screen, "#patch_saveback_name_input"))

    name, place = applied(tmp_path, t.SIZE, source, "patch_tab_inspector", body)
    assert name == expected and place == [], (case, name, place)


# ------------------------------------------------------------------ R-TUI-064: buttons, width, chips


@pytest.mark.parametrize("case,source", [("R-TUI-064.1/1", "firmware.s19"), ("R-TUI-064.1/2", "firmware.hex")],
                         ids=["R-TUI-064.1/1", "R-TUI-064.1/2"])
def test_r_tui_064_1_validate_apply_save_stay_on_screen_with_the_prompt_shown(tmp_path, case, source):
    """R-TUI-064.1/1,/2 (118x54): Validate, Apply loaded changes and Save inside the screen at scroll offset 0
    with the prompt shown.  The prompt must be shown (a hidden prompt would pass vacuously).  Negative
    control: the dock pushing the document row off screen -> RED."""
    ids = ("patch_doc_validate_button", "patch_doc_apply_button", "patch_doc_save_button")

    async def body(app, pilot):
        bad = [r for i in ids for r in t.at_its_place(app, t.need(app.screen, f"#{i}"))]
        return bad, t.scroll_offsets(t.panel_of(app)), t.prompt_is_shown(app)

    bad, offsets, prompt = applied(tmp_path, t.SIZE, source, "patch_tab_inspector", body)
    assert prompt, "the prompt is not a shown widget, so this case would pass vacuously"
    assert bad == [] and offsets == [], (case, bad, offsets)


@pytest.mark.parametrize("case,size", [("R-TUI-064.2/1", t.SIZE), ("R-TUI-064.2/2", t.WIDE)],
                         ids=["R-TUI-064.2/1", "R-TUI-064.2/2"])
def test_r_tui_064_2_no_painted_part_is_wider_than_the_panel_with_the_prompt_shown(tmp_path, case, size):
    """R-TUI-064.2/1,/2: with the prompt shown no displayed part of the Patch Editor leaves the panel on x
    (``clipped_overflow``) and the apply line is painted whole.  Guard: the population is large and the
    prompt is shown.  Negative control: the apply line / a chip row wider than the panel -> RED."""

    async def body(app, pilot):
        panel = t.panel_of(app)
        line = t.painted(app, t.need(app.screen, "#patch_saveback_apply_line"))
        return clipped_overflow(panel), len(displayed_descendants(panel)), line, t.prompt_is_shown(app)

    over, population, line, prompt = applied(tmp_path, size, "firmware.s19", "patch_tab_inspector", body)
    assert prompt and population > 20, (prompt, population)
    assert over == [], (case, [w.id for w in over])
    assert line == t.APPLY_LINE_1, (case, line)


def test_r_tui_064_4_1_the_prompts_chips_are_one_row_high(tmp_path):
    """R-TUI-064.4/1: the Format control, Width, ``Write file`` and ``Don't save`` have height 1 (and are
    shown, so a 0-row hidden chip cannot pass).  Negative control: a two-row chip grid (the base's) -> RED."""
    ids = ("patch_saveback_format_button", "patch_saveback_width_button",
           "patch_saveback_confirm_button", "patch_saveback_decline_button")

    async def body(app, pilot):
        return {i: (t.shown(t.need(app.screen, f"#{i}")), t.need(app.screen, f"#{i}").region.height) for i in ids}

    got = applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert all(shown and height == 1 for shown, height in got.values()), got
