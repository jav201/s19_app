"""Behavioral tests for the CRC Designer rail screen (batch-58 Phase-3 Inc-4).

Drive the SHIPPED surface — the rail key ``0`` / ``action_show_screen`` and the
``#screen_crc_designer`` parameter form — through a Textual ``Pilot`` (the
harness pattern of ``tests/test_tui_directionb.py``).

- ``routing`` (LLR-V1.1 → AT-058 routing gate): navigation is driven through the
  REAL show path (pressing key ``0``), never a ``.focus()`` proxy (C-16). The
  RED counterfactual is temporal — before the scaffold exists ``#screen_crc_designer``
  is absent and this fails; after the scaffold it is GREEN.
- ``form_and_preset`` (LLR-V1.2 / **AT-058-02**, M2): the mounted form presents
  the preset selector plus the seven ``algorithm`` fields and the three
  ``serialization`` fields; selecting the NON-DEFAULT ``CRC-16/MODBUS`` preset
  through the mounted selector TRANSITIONS the fields off the CRC-32/ISO-HDLC
  seed (a measured delta — width ``32→16``, poly ``0x04C11DB7→0x8005``, xorout
  ``0xFFFFFFFF→0x0000`` — C-10, not a hand-list equality), while
  ``crc_kernel.PRESETS`` stays object- and value-identical (no catalogue
  overwrite). The preset set is derived from ``crc_kernel.PRESETS``
  (``len >= 7``; C-31, no hand-typed catalogue).
"""

from __future__ import annotations

import asyncio
import copy
import re
from itertools import permutations
from pathlib import Path

from textual.widgets import Button, Input, Label, Select, Static, Switch

from s19_app.tui import crc_designer_view
from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile
from s19_app.tui.operations import crc_kernel
from s19_app.tui.operations.crc import compute_region_crc
from s19_app.tui.operations.crc_designer_model import (
    CrcTemplate,
    emit_template,
    parse_template,
)
from s19_app.tui.operations.crc_kernel import CrcAlgorithm, SEED_ALGORITHM, preset_by_name
from s19_app.tui.rail import Rail

#: The named form widget ids the scaffold must present (LLR-V1.2): the preset
#: selector, the seven algorithm fields, the three serialization fields.
_FORM_FIELD_IDS = (
    "crc_preset_select",
    "crc_field_width",
    "crc_field_poly",
    "crc_field_init",
    "crc_field_refin",
    "crc_field_refout",
    "crc_field_xorout",
    "crc_field_check",
    "crc_field_output_address",
    "crc_field_store_width",
    "crc_field_store_endianness",
)


def test_routing_key_0_shows_crc_designer_hides_others(tmp_path: Path) -> None:
    """Pressing ``0`` shows ``#screen_crc_designer`` and hides every other screen.

    Intent (LLR-V1.1): the 10th rail screen routes through the EXISTING
    data-driven ``action_show_screen`` — the real key ``0`` binding, not a
    focus proxy (C-16). Exactly the CRC Designer container loses ``.hidden``,
    all other rail screens gain it, and the rail active marker moves to
    ``"crc_designer"``. Before the scaffold this whole path is absent (RED).
    """

    async def _drive() -> tuple[bool, bool, str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            present = app.query("#screen_crc_designer").first() is not None
            await pilot.press("0")
            await pilot.pause()
            screen = app.query_one("#screen_crc_designer")
            visible = "hidden" not in screen.classes
            active = app.query_one(Rail).active_key
            others_hidden = all(
                "hidden" in app.query_one(f"#{container_id}").classes
                for key, container_id in app.SCREEN_CONTAINER_IDS.items()
                if key != "crc_designer"
            )
            return present, visible, active, others_hidden

    present, visible, active, others_hidden = asyncio.run(_drive())
    assert present, "the #screen_crc_designer scaffold must be composed"
    assert visible, "pressing 0 must show #screen_crc_designer"
    assert active == "crc_designer", (
        f"the rail active marker must move to crc_designer, got {active!r}"
    )
    assert others_hidden, "every other rail screen must carry .hidden"


def test_form_and_preset_populates_off_seed_without_mutating_catalogue(
    tmp_path: Path,
) -> None:
    """Selecting a non-default preset moves the form off the seed; catalogue intact.

    AT-058-02 (M2): from the CRC-32/ISO-HDLC seed default, selecting
    ``CRC-16/MODBUS`` through the mounted selector transitions the form fields
    to MODBUS's values — a measured DELTA (width ``32→16``, poly
    ``0x04C11DB7→0x8005``, xorout ``0xFFFFFFFF→0x0000``), not a hand-list
    equality. Every preset in ``crc_kernel.PRESETS`` populates the width field,
    and ``crc_kernel.PRESETS`` is object- and value-unchanged afterward (no
    overwrite of the read-only catalogue).
    """
    # C-31: the preset set is the live catalogue, not a hand-typed list.
    assert len(crc_kernel.PRESETS) >= 7, "the seed catalogue must carry >= 7 presets"
    catalogue_obj = crc_kernel.PRESETS
    catalogue_snapshot = copy.deepcopy(crc_kernel.PRESETS)

    async def _drive() -> tuple[dict[str, bool], dict[str, str], dict[str, str], dict[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()

            present = {
                field_id: app.query(f"#{field_id}").first() is not None
                for field_id in _FORM_FIELD_IDS
            }

            seed = {
                "width": app.query_one("#crc_field_width", Input).value,
                "poly": app.query_one("#crc_field_poly", Input).value,
                "xorout": app.query_one("#crc_field_xorout", Input).value,
            }

            # Every preset populates the width field through the real selector.
            per_preset_width: dict[str, str] = {}
            selector = app.query_one("#crc_preset_select", Select)
            for preset in crc_kernel.PRESETS:
                selector.value = preset.name
                await pilot.pause()
                per_preset_width[preset.name] = app.query_one(
                    "#crc_field_width", Input
                ).value

            # Land on the non-default MODBUS preset for the M2 delta gate.
            selector.value = "CRC-16/MODBUS"
            await pilot.pause()
            after = {
                "width": app.query_one("#crc_field_width", Input).value,
                "poly": app.query_one("#crc_field_poly", Input).value,
                "xorout": app.query_one("#crc_field_xorout", Input).value,
            }
            return present, seed, per_preset_width, after

    present, seed, per_preset_width, after = asyncio.run(_drive())

    assert all(present.values()), f"missing form widgets: {present}"

    # Seed default is the CRC-32/ISO-HDLC algorithm.
    assert seed["width"] == str(SEED_ALGORITHM.width) == "32"
    assert seed["poly"] == "0x04C11DB7"
    assert seed["xorout"] == "0xFFFFFFFF"

    # Every preset populated the width field to its own width (catalogue-derived).
    for preset in catalogue_snapshot:
        assert per_preset_width[preset.name] == str(preset.width), (
            f"preset {preset.name} must set width to {preset.width}"
        )

    # M2 measured delta seed -> MODBUS.
    assert after["width"] == "16" and after["width"] != seed["width"]
    assert after["poly"] == "0x8005" and after["poly"] != seed["poly"]
    assert after["xorout"] == "0x0000" and after["xorout"] != seed["xorout"]

    # The read-only catalogue is untouched: same object, same values.
    assert crc_kernel.PRESETS is catalogue_obj, "PRESETS must not be rebound"
    assert list(crc_kernel.PRESETS) == list(catalogue_snapshot), (
        "PRESETS contents must be unchanged after preset selection"
    )


def _verdict(app: S19TuiApp) -> str:
    """Read the mounted ``#crc_kat_verdict`` widget's rendered content."""
    return str(app.query_one("#crc_kat_verdict", Static).content)


def test_live_verdict_transitions_on_single_field_events(tmp_path: Path) -> None:
    """A single field-change event flips the verdict (AT-CRC-DSN-016, B3).

    Intent (LLR-V2.1): the verdict recomputes WITHIN the change event, no Run.
    Capture the verdict BEFORE and AFTER one real ``Input.Changed`` and assert
    the TRANSITION, not the end state: breaking ``xorout`` moves
    ``MATCH -> MISMATCH``; a second single event clearing ``check`` moves
    ``MISMATCH -> NO-EXPECTED``. An end-state-only assertion is the defect.
    """

    async def _drive() -> tuple[str, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()

            before = _verdict(app)  # seed CRC-32 kat == check -> MATCH

            # Single real event: break xorout (kat changes, check pinned).
            app.query_one("#crc_field_xorout", Input).value = "0x00000000"
            await pilot.pause()
            after_break = _verdict(app)

            # Single real event: clear check -> no expected value to compare.
            app.query_one("#crc_field_check", Input).value = ""
            await pilot.pause()
            after_clear = _verdict(app)
            return before, after_break, after_clear

    before, after_break, after_clear = asyncio.run(_drive())

    # R7: the verdict is glyph-primary (`✓ MATCH` etc.), so assert `.plain`
    # CONTAINS the token — the transition (before != after) is still the teeth.
    assert "MATCH" in before and "MISMATCH" not in before, (
        f"seed verdict must be MATCH, got {before!r}"
    )
    assert "MISMATCH" in after_break, (
        f"breaking xorout must transition to MISMATCH, got {after_break!r}"
    )
    assert before != after_break, "the verdict must TRANSITION, not stay put (B3)"
    assert "NO-EXPECTED" in after_clear, (
        f"clearing check must transition to NO-EXPECTED, got {after_clear!r}"
    )
    assert after_break != after_clear, "second event must also TRANSITION (B3)"


def test_live_verdict_every_preset_reads_match(tmp_path: Path) -> None:
    """Every catalogue preset yields a MATCH verdict (AT-CRC-DSN-011, M1).

    Intent (LLR-V2.1): the preset set is derived from ``crc_kernel.PRESETS``
    (``len >= 7``, no hand-typed list, C-31); selecting each through the mounted
    selector recomputes the verdict to MATCH read from the mounted widget.
    """
    assert len(crc_kernel.PRESETS) >= 7, "the seed catalogue must carry >= 7 presets"

    async def _drive() -> dict[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            selector = app.query_one("#crc_preset_select", Select)
            verdicts: dict[str, str] = {}
            for preset in crc_kernel.PRESETS:
                selector.value = preset.name
                await pilot.pause()
                verdicts[preset.name] = _verdict(app)
            return verdicts

    verdicts = asyncio.run(_drive())
    for preset in crc_kernel.PRESETS:
        # R7: glyph-primary verdict — `.plain` contains the token.
        assert "MATCH" in verdicts[preset.name] and "MISMATCH" not in verdicts[preset.name], (
            f"preset {preset.name} must read MATCH, got {verdicts[preset.name]!r}"
        )


def test_custom_vector_ascii_and_hex_reproduce_kat(tmp_path: Path) -> None:
    """ASCII and hex custom vectors both compute the seed KAT (AT-058-03).

    Intent (LLR-V3.1): the seed algorithm's CRC over the ASCII vector
    ``123456789`` (the default) and over the equivalent hex ``31..39`` both equal
    ``SEED_ALGORITHM.kat()`` (0xCBF43926), read from the mounted result widget.
    """

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()

            ascii_result = str(
                app.query_one("#crc_custom_vector_result", Static).content
            )

            app.query_one("#crc_custom_vector_mode", Select).value = "hex"
            app.query_one("#crc_custom_vector", Input).value = (
                "31 32 33 34 35 36 37 38 39"
            )
            await pilot.pause()
            hex_result = str(
                app.query_one("#crc_custom_vector_result", Static).content
            )
            return ascii_result, hex_result

    ascii_result, hex_result = asyncio.run(_drive())
    expected = SEED_ALGORITHM.kat()
    assert int(ascii_result, 16) == expected, (
        f"ASCII 123456789 must reproduce the KAT, got {ascii_result!r}"
    )
    assert int(hex_result, 16) == expected, (
        f"hex 31..39 must reproduce the KAT, got {hex_result!r}"
    )


def test_json_preview_roundtrips_through_mounted_widget(tmp_path: Path) -> None:
    """The mounted preview text parses back to the current template (AT-058-04, B1).

    Intent (LLR-V4.1): after a representative edit (selecting the CRC-16/MODBUS
    preset), READ the ``#crc_json_preview`` widget's rendered text and assert
    ``parse_template(<that text>)[0] == current_template`` with ``errors == []``
    — NOT ``parse_template(emit_template(t))`` in the test (through-surface gate).
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_preset_select", Select).value = "CRC-16/MODBUS"
            await pilot.pause()
            return str(app.query_one("#crc_json_preview", Static).content)

    rendered = asyncio.run(_drive())
    template, errors = parse_template(rendered)
    assert errors == [], f"mounted preview must parse cleanly, got {errors!r}"
    expected = CrcTemplate(algorithm=preset_by_name("CRC-16/MODBUS"))
    assert template == expected, (
        "the mounted preview must round-trip to the current MODBUS template"
    )


def test_verdict_fault_guard_out_of_range_width(tmp_path: Path) -> None:
    """An out-of-range width warns markup-safely without crashing (LLR-V2.2).

    Intent: entering ``width=4`` (``crc_stream`` would raise ``ValueError``,
    crc_kernel.py:125) renders a markup-safe warning in the verdict widget and
    leaves the app alive — the compute-boundary fault guard.
    """

    async def _drive() -> tuple[str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_field_width", Input).value = "4"
            await pilot.pause()
            verdict_widget = app.query_one("#crc_kat_verdict", Static)
            markup_off = verdict_widget._render_markup is False
            return str(verdict_widget.content), markup_off

    verdict, markup_off = asyncio.run(_drive())
    assert "Cannot compute" in verdict, (
        f"an out-of-range width must warn, not crash; got {verdict!r}"
    )
    assert verdict != "MATCH"
    assert markup_off, "the verdict widget must render markup-safe (C-17)"


# ─────────────────────────────────────────────────────────────────────────────
# Inc-6 — Load/Save + save-time KAT + markup-safety + form warnings
# (LLR-V5.1 / V5.2 / V5.3 / V5.4; AT-058-05, AT-058-06, AT-CRC-DSN-015)
# ─────────────────────────────────────────────────────────────────────────────
#: The fixed template-library directory (batch-58 LLR-V5.2, F3): a single
#: bounded dir under the app base — never name-derived, so a template name can
#: never redirect the write outside it.
_TEMPLATE_LIB_PARTS = (".s19tool", "templates")


def _status(app: S19TuiApp) -> str:
    """Read the mounted ``#crc_loadsave_status`` widget's rendered content."""
    return str(app.query_one("#crc_loadsave_status", Static).content)


def test_save_then_load_roundtrip_through_view(tmp_path: Path) -> None:
    """Save THROUGH the view writes a file that Load restores field-for-field.

    AT-058-05 (B2): from the seed (whose ``check`` matches, so no save-time
    warning), give the template a distinctive ``name`` + ``aliases``, press the
    Save control → a real ``MyVariant.crc.json`` lands in the fixed template-lib
    dir → perturb the form → set the load path and press the Load control → every
    algorithm/template field equals the pre-perturbation originals. The loop is
    driven through the mounted controls, not a headless ``parse(emit(t))``.
    """
    field_ids = (
        "crc_field_name",
        "crc_field_aliases",
        "crc_field_width",
        "crc_field_poly",
        "crc_field_init",
        "crc_field_xorout",
        "crc_field_check",
    )

    async def _drive() -> tuple[bool, str, dict[str, str], dict[str, str], tuple[bool, bool], tuple[bool, bool]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()

            app.query_one("#crc_field_name", Input).value = "MyVariant"
            app.query_one("#crc_field_aliases", Input).value = "zlib, PKZIP"
            await pilot.pause()

            app.query_one("#crc_save_btn", Button).press()
            await pilot.pause()
            saved = tmp_path.joinpath(*_TEMPLATE_LIB_PARTS, "MyVariant.crc.json")
            existed = saved.exists()
            save_status = _status(app)

            originals = {
                fid: app.query_one(f"#{fid}", Input).value for fid in field_ids
            }
            reflects = (
                app.query_one("#crc_field_refin", Switch).value,
                app.query_one("#crc_field_refout", Switch).value,
            )

            # Perturb the form so a successful Load is a measured restore.
            app.query_one("#crc_field_poly", Input).value = "0x00000000"
            app.query_one("#crc_field_name", Input).value = "Scratch"
            app.query_one("#crc_field_aliases", Input).value = ""
            await pilot.pause()

            app.query_one("#crc_load_path", Input).value = str(saved)
            app.query_one("#crc_load_btn", Button).press()
            await pilot.pause()

            restored = {
                fid: app.query_one(f"#{fid}", Input).value for fid in field_ids
            }
            restored_reflects = (
                app.query_one("#crc_field_refin", Switch).value,
                app.query_one("#crc_field_refout", Switch).value,
            )
            return existed, save_status, originals, restored, reflects, restored_reflects

    existed, save_status, originals, restored, reflects, restored_reflects = asyncio.run(
        _drive()
    )
    assert existed, "Save must write MyVariant.crc.json under the template-lib dir"
    assert "Saved template" in save_status, (
        f"a matching-check Save must report success, got {save_status!r}"
    )
    assert restored == originals, (
        f"Load must restore every field through the view: {originals} vs {restored}"
    )
    assert restored_reflects == reflects, "Load must restore the reflect switches"


def test_hostile_template_renders_literally_at_preview(tmp_path: Path) -> None:
    """A loaded hostile name/alias renders literally at the JSON preview (AT-058-06, F1).

    Load a valid template whose ``name`` is ``[bold]x[/]`` and whose ``aliases``
    carry an ANSI escape. After Load, the ``#crc_json_preview`` widget (the
    highest-risk sink — ``emit_template`` embeds ``name``/``aliases`` verbatim)
    must show the bracket payload as LITERAL characters, render ``markup=False``,
    and apply NO style spans — not merely "no crash" (C-17, LLR-V5.3).
    """
    hostile_path = tmp_path / "hostile.crc.json"
    hostile = CrcTemplate(
        algorithm=CrcAlgorithm(
            "[bold]x[/]", 16, 0x1021, 0xFFFF, False, False, 0x0000, 0x29B1
        ),
        aliases=("\x1b[31mRED\x1b[0m",),
    )
    hostile_path.write_text(emit_template(hostile), encoding="utf-8")

    async def _drive() -> tuple[str, list, object, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_load_path", Input).value = str(hostile_path)
            app.query_one("#crc_load_btn", Button).press()
            await pilot.pause()
            preview = app.query_one("#crc_json_preview", Static)
            # ``render()`` is the visual the widget paints: with ``markup=False``
            # it is a ``Content`` built WITHOUT markup interpretation, so an
            # interpreted ``[bold]`` would have produced a style span (F1).
            rendered = preview.render()
            verdict_alive = str(app.query_one("#crc_kat_verdict", Static).content)
            return (
                str(rendered),
                list(rendered.spans),
                preview._render_markup,
                verdict_alive,
            )

    plain, spans, render_markup, verdict_alive = asyncio.run(_drive())
    assert "[bold]x[/]" in plain, (
        f"the hostile template name must render literally, got {plain!r}"
    )
    assert render_markup is False, "the preview widget must render markup=False (C-17)"
    assert spans == [], f"the preview must apply no style spans (F1), got {spans!r}"
    assert verdict_alive != "", "the app must stay alive after loading hostile text"


def test_load_malformed_file_surfaces_one_error(tmp_path: Path) -> None:
    """A malformed load surfaces exactly one error and the app stays alive (AT-CRC-DSN-015).

    Intent (LLR-V5.1): a bad-JSON file read through the ``crc_template`` facade
    returns one collected error; the view shows exactly that error, the form is
    unchanged (verdict still MATCH), and nothing crashes.
    """
    bad = tmp_path / "bad.crc.json"
    bad.write_text("{ this is not valid json", encoding="utf-8")

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_load_path", Input).value = str(bad)
            app.query_one("#crc_load_btn", Button).press()
            await pilot.pause()
            return _status(app), _verdict(app)

    status, verdict = asyncio.run(_drive())
    assert status.startswith("Load failed:"), (
        f"a malformed load must surface one error, got {status!r}"
    )
    assert "MATCH" in verdict and "MISMATCH" not in verdict, (
        "a load fault must leave the form unchanged (app alive)"
    )


def test_save_all_symbol_name_writes_nothing_and_warns(tmp_path: Path) -> None:
    """An all-symbol name warns and writes NO file (F2, LLR-V5.2).

    Intent: ``sanitize_project_name("@@@")`` → ``None``; Save must warn and write
    nothing (no ``None.crc.json``, no crash) — the security F2 branch.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_field_name", Input).value = "@@@"
            await pilot.pause()
            app.query_one("#crc_save_btn", Button).press()
            await pilot.pause()
            return _status(app)

    status = asyncio.run(_drive())
    lib = tmp_path.joinpath(*_TEMPLATE_LIB_PARTS)
    written = list(lib.glob("*.crc.json")) if lib.exists() else []
    assert written == [], f"an all-symbol name must write NO file, found {written}"
    assert "nothing written" in status, (
        f"the None-name Save must warn, got {status!r}"
    )


def test_save_check_mismatch_warns_but_still_writes(tmp_path: Path) -> None:
    """A KAT mismatch on Save warns but still writes (LLR-V5.4c).

    Intent: pinning a wrong ``check`` (``0x00000000``) while the algorithm's real
    KAT is ``0xCBF43926`` makes ``kat_ok()`` False; Save WARNS (obs #3) but still
    writes the file — warn, do not block.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_field_name", Input).value = "Mismatch"
            app.query_one("#crc_field_check", Input).value = "0x00000000"
            await pilot.pause()
            app.query_one("#crc_save_btn", Button).press()
            await pilot.pause()
            return _status(app)

    status = asyncio.run(_drive())
    saved = tmp_path.joinpath(*_TEMPLATE_LIB_PARTS, "Mismatch.crc.json")
    assert saved.exists(), "a KAT mismatch must still write the file (warn, not block)"
    assert "check does not match" in status, (
        f"a KAT mismatch must paint a warning, got {status!r}"
    )


def test_store_width_too_small_warns_live(tmp_path: Path) -> None:
    """A too-small store_width warns live (LLR-V5.4b).

    Intent: the seed CRC-32 needs ``ceil(32/8) == 4`` stored bytes; typing
    ``store_width = 1`` truncates the stored CRC's detection strength, so the
    ``#crc_warnings`` surface must paint a truncation warning WITHIN the edit
    event (no Save needed), markup-safe.
    """

    async def _drive() -> tuple[str, str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            before = str(app.query_one("#crc_warnings", Static).content)
            app.query_one("#crc_field_store_width", Input).value = "1"
            await pilot.pause()
            widget = app.query_one("#crc_warnings", Static)
            return before, str(widget.content), widget._render_markup is False

    before, after, markup_off = asyncio.run(_drive())
    # R7: a clean warnings tile shows a positive `✓ none`, not a blank.
    assert before == "✓ none", "the seed store_width (4) is wide enough; ✓ none"
    assert "truncated" in after, (
        f"a too-small store_width must warn live, got {after!r}"
    )
    assert markup_off, "the warnings widget must render markup-safe (C-17)"


# ─────────────────────────────────────────────────────────────────────────────
# Inc-7 — coverage strip + per-policy preview + gap-conflict + fill-no-pad warn
# + preview-only guard (LLR-V6.1/V6.2, V7.1, V8.1; AT-058-07/08/09/10,
# AT-CRC-DSN-013/013b/017)
# ─────────────────────────────────────────────────────────────────────────────
def _fixture_mem() -> dict[int, int]:
    """The canonical §3.2 image: two ranges with an 8-byte erased gap between.

    ``0x8000-0x8008`` = bytes ``00..07``; ``0x8010-0x8018`` = bytes ``10..17``;
    ``0x8008-0x8010`` is absent (erased). Probe-confirmed oracles under the seed
    CRC-32/ISO-HDLC: ``concat == 0x9C5BCBBD``, ``fill(0xFF) == 0x2A8A3950``.
    """
    mem = {0x8000 + i: i for i in range(8)}
    mem.update({0x8010 + i: 0x10 + i for i in range(8)})
    return mem


def _loaded(mem_map: dict[int, int]) -> LoadedFile:
    """Wrap ``mem_map`` in a minimal loaded-image snapshot for the preview."""
    return LoadedFile(
        path=Path("preview.s19"),
        file_type="s19",
        mem_map=dict(mem_map),
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )


async def _coverage_preview(
    tmp_path: Path,
    mem_map: dict[int, int] | None,
    ranges: str,
    join: str,
    on_conflict: str = "abort",
    pad: str = "0xFF",
    intra: str = "skip",
) -> str:
    """Drive the coverage strip through the mounted view and read the preview.

    Sets ``current_file`` (so the preview digests real bytes; ``None`` leaves the
    empty state), shows the screen, drives the coverage-strip widgets, and
    returns the rendered ``#crc_coverage_preview`` content (M5: through-widget).
    """
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        if mem_map is not None:
            app.current_file = _loaded(mem_map)
        await pilot.press("0")
        await pilot.pause()
        app.query_one("#crc_coverage_ranges", Input).value = ranges
        app.query_one("#crc_coverage_intra_gap", Select).value = intra
        app.query_one("#crc_coverage_join", Select).value = join
        app.query_one("#crc_coverage_pad_byte", Input).value = pad
        app.query_one("#crc_coverage_on_gap_conflict", Select).value = on_conflict
        await pilot.pause()
        return str(app.query_one("#crc_coverage_preview", Static).content)


def test_coverage_preview_shows_both_policy_oracles(tmp_path: Path) -> None:
    """Both §3.2 policy CRCs render in the mounted preview (AT-058-07 / AT-CRC-DSN-013b, M5).

    Intent (LLR-V6.2): over the named §3.2 fixture image, a two-range
    ``join="fill"`` target's preview widget shows BOTH probe-confirmed oracle
    hexes — ``0x9C5BCBBD`` (concat) and ``0x2A8A3950`` (fill(0xFF)) — read from
    the mounted ``#crc_coverage_preview``, not merely "two numbers render". A
    wrong policy/range would drop an oracle and go RED.
    """
    text = asyncio.run(
        _coverage_preview(
            tmp_path,
            _fixture_mem(),
            "0x8000-0x8008, 0x8010-0x8018",
            join="fill",
        )
    )
    assert "0x9C5BCBBD" in text, f"the concat oracle must render, got {text!r}"
    assert "0x2A8A3950" in text, f"the fill(0xFF) oracle must render, got {text!r}"


def test_coverage_single_range_skip_equals_region_crc(tmp_path: Path) -> None:
    """A single-range skip target's preview == the region CRC (AT-CRC-DSN-013).

    Intent (LLR-V6.2): a one-range ``intra_gap="skip"`` target over the fixture
    digests exactly the present bytes, so its previewed CRC equals
    ``crc.compute_region_crc`` over the same span (pinned to ``0x88AA689F``).
    """
    mem = _fixture_mem()
    oracle = compute_region_crc(mem, 0x8000, 0x8008)
    assert oracle == 0x88AA689F, "the region-CRC oracle is pinned (non-vacuous)"
    text = asyncio.run(
        _coverage_preview(tmp_path, mem, "0x8000-0x8008", join="concat")
    )
    assert f"0x{oracle:08X}" in text, (
        f"a single-range skip preview must equal the region CRC, got {text!r}"
    )


def test_coverage_no_image_shows_empty_state(tmp_path: Path) -> None:
    """With no image loaded the preview shows a graceful note (LLR-V6.2 boundary)."""
    text = asyncio.run(
        _coverage_preview(tmp_path, None, "0x8000-0x8008", join="concat")
    )
    assert "Load an image" in text, f"the no-image state must be graceful, got {text!r}"


def test_gap_conflict_clean_previews_dirty_abort_refuses(tmp_path: Path) -> None:
    """Gap-conflict honoring across abort/warn/ignore + concat (AT-058-08 / AT-CRC-DSN-017).

    Intent (LLR-V7.1), asserting painted content (C-32):
    - clean fill gap → CRC shown, no refusal;
    - a stray non-pad byte in the filled span + ``abort`` → refusal notice, the
      conflict address surfaced, and NO CRC value shown;
    - ``warn`` → CRC shown PLUS a diagnostic; ``ignore`` → CRC shown, silent;
    - ``join="concat"`` never conflicts → CRC shown, no refusal.
    """
    ranges = "0x8000-0x8008, 0x8010-0x8018"
    dirty = _fixture_mem()
    dirty[0x800A] = 0x99  # a real byte where the operator promised an erased gap

    clean = asyncio.run(
        _coverage_preview(tmp_path, _fixture_mem(), ranges, join="fill", on_conflict="abort")
    )
    assert "0x2A8A3950" in clean and "refused" not in clean.lower(), (
        f"a clean fill gap must preview the CRC, got {clean!r}"
    )

    abort_text = asyncio.run(
        _coverage_preview(tmp_path, dict(dirty), ranges, join="fill", on_conflict="abort")
    )
    assert "refused" in abort_text.lower(), (
        f"abort + conflict must refuse the preview, got {abort_text!r}"
    )
    assert "0x800A" in abort_text, "the conflicting address must be surfaced"
    assert "0x2A8A3950" not in abort_text and "0x9C5BCBBD" not in abort_text, (
        f"a refused preview must show NO CRC, got {abort_text!r}"
    )

    warn_text = asyncio.run(
        _coverage_preview(tmp_path, dict(dirty), ranges, join="fill", on_conflict="warn")
    )
    assert "0x2A8A3950" in warn_text, "warn must still show the CRC"
    assert "gap-safety" in warn_text, "warn must append the diagnostic"

    ignore_text = asyncio.run(
        _coverage_preview(tmp_path, dict(dirty), ranges, join="fill", on_conflict="ignore")
    )
    assert "0x2A8A3950" in ignore_text, "ignore must show the CRC"
    assert "gap-safety" not in ignore_text, "ignore must proceed silently"

    concat_text = asyncio.run(
        _coverage_preview(tmp_path, dict(dirty), ranges, join="concat", on_conflict="abort")
    )
    assert "refused" not in concat_text.lower(), "concat never conflicts"
    assert "0x9C5BCBBD" in concat_text, "concat must still preview its CRC"


def test_coverage_inverted_range_warns_not_crash(tmp_path: Path) -> None:
    """An inverted range surfaces a markup-safe warning via _build_target (LLR-V6.1)."""
    text = asyncio.run(
        _coverage_preview(tmp_path, _fixture_mem(), "0x8008-0x8000", join="concat")
    )
    assert "Invalid coverage" in text, (
        f"an inverted range must warn, not crash, got {text!r}"
    )


def test_three_warn_conditions_through_view(tmp_path: Path) -> None:
    """All three warn conditions fire through the mounted view (AT-058-10, M4, C-18).

    One session exercising each of the three independent warnings:
    (1) ``join="fill"`` with ``pad_byte`` unset → ``#crc_warnings``;
    (2) ``store_width < ceil(width/8)`` → ``#crc_warnings``;
    (3) ``check != compute("123456789")`` on Save → ``#crc_loadsave_status``.
    """

    async def _drive() -> tuple[str, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()

            # (1) fill policy with no pad byte.
            app.query_one("#crc_coverage_join", Select).value = "fill"
            app.query_one("#crc_coverage_pad_byte", Input).value = ""
            await pilot.pause()
            warn_fill = str(app.query_one("#crc_warnings", Static).content)

            # (2) store_width narrower than ceil(width/8).
            app.query_one("#crc_field_store_width", Input).value = "1"
            await pilot.pause()
            warn_store = str(app.query_one("#crc_warnings", Static).content)

            # (3) a wrong pinned check on Save.
            app.query_one("#crc_field_name", Input).value = "ThreeWarn"
            app.query_one("#crc_field_check", Input).value = "0x00000000"
            await pilot.pause()
            app.query_one("#crc_save_btn", Button).press()
            await pilot.pause()
            save_status = str(app.query_one("#crc_loadsave_status", Static).content)
            return warn_fill, warn_store, save_status

    warn_fill, warn_store, save_status = asyncio.run(_drive())
    assert "pad_byte" in warn_fill and "unset" in warn_fill, (
        f"(1) fill with no pad_byte must warn, got {warn_fill!r}"
    )
    assert "truncated" in warn_store, (
        f"(2) a too-small store_width must warn, got {warn_store!r}"
    )
    assert "check does not match" in save_status, (
        f"(3) a check mismatch on Save must warn, got {save_status!r}"
    )


def test_preview_only_mem_map_unchanged(tmp_path: Path) -> None:
    """No firmware write path and mem_map is unchanged by any action (AT-058-09, LLR-V8.1).

    Structural (inspection): the view module references NO firmware-write symbol.
    Behavioral (C-12): after a full preview interaction — coverage edits, every
    gap policy, Save, a malformed Load — the loaded ``mem_map`` is the SAME object
    with identical contents.
    """
    source = Path(crc_designer_view.__file__).read_text(encoding="utf-8")
    for symbol in (
        "emit_s19_from_mem_map",
        "copy_into_workarea",
        "write_crc_image",
        "inject_crcs",
    ):
        assert symbol not in source, (
            f"the preview-only view must not reference the firmware writer {symbol!r}"
        )

    bad = tmp_path / "bad.crc.json"
    bad.write_text("{ not json", encoding="utf-8")

    async def _drive() -> tuple[bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded(_fixture_mem())
            mem_obj = app.current_file.mem_map
            before = dict(mem_obj)
            await pilot.press("0")
            await pilot.pause()

            # Exercise every coverage control + a conflict + Save + a bad Load.
            app.query_one("#crc_coverage_ranges", Input).value = (
                "0x8000-0x8008, 0x8010-0x8018"
            )
            app.query_one("#crc_coverage_intra_gap", Select).value = "fill"
            app.query_one("#crc_coverage_join", Select).value = "fill"
            app.query_one("#crc_coverage_pad_byte", Input).value = "0x00"
            app.query_one("#crc_coverage_on_gap_conflict", Select).value = "warn"
            await pilot.pause()
            app.query_one("#crc_field_name", Input).value = "Interact"
            await pilot.pause()
            app.query_one("#crc_save_btn", Button).press()
            await pilot.pause()
            app.query_one("#crc_load_path", Input).value = str(bad)
            app.query_one("#crc_load_btn", Button).press()
            await pilot.pause()

            same_object = app.current_file.mem_map is mem_obj
            unchanged = dict(app.current_file.mem_map) == before
            return same_object, unchanged

    same_object, unchanged = asyncio.run(_drive())
    assert same_object, "the loaded mem_map object must not be replaced by the view"
    assert unchanged, "no Designer action may mutate the loaded mem_map"


# ─────────────────────────────────────────────────────────────────────────────
# batch-59 Inc-1 — Variant-B bench layout fidelity (hero row + 3-column bench)
# (HLR-L2/L3, LLR-L2.1/L2.2/L2.3/L2.4/L3.1; AT-B59-03/04/05)
# ─────────────────────────────────────────────────────────────────────────────
#: The three bench columns; a probe's "column ancestor" is the first of these
#: on its ancestor chain (else the panel sentinel — the flat-form collapse).
_BENCH_COLUMN_IDS = ("crc_bench_c1", "crc_bench_c2", "crc_bench_c3")


def _first_ancestor_id(widget, target_ids: tuple[str, ...]) -> str:
    """Return the id of the first ancestor in ``target_ids`` (else the panel).

    Walks the ``.parent`` chain from ``widget``; in the flat form no bench
    column is on the chain, so every probe collapses to the single
    ``crc_designer_panel`` sentinel (the AT-B59-03 teeth: set size 1 vs 3).
    """
    node = widget.parent
    while node is not None:
        if node.id in target_ids:
            return node.id
        node = node.parent
    return "crc_designer_panel"


def _has_ancestor(widget, ancestor_id: str) -> bool:
    """True when ``ancestor_id`` appears on ``widget``'s ``.parent`` chain."""
    node = widget.parent
    while node is not None:
        if node.id == ancestor_id:
            return True
        node = node.parent
    return False


def test_bench_columns_pairwise_distinct_ancestors(tmp_path: Path) -> None:
    """The three bench probes have pairwise-distinct column ancestors (AT-B59-03).

    Structural teeth (LLR-L2.1 / L5.1, C-31): on the mounted screen a
    ``#crc_bench`` container exists, and the three probes ``#crc_field_width``
    (c1 Algorithm), ``#crc_coverage_ranges`` (c2 Coverage), ``#crc_custom_vector``
    (c3 Custom vector) resolve under PAIRWISE-DISTINCT bench columns —
    ``len(distinct) == 3``. (The realign moved ``#crc_json_preview`` out to a
    full-width strip, so a c3-resident field is the c3 probe now.) In the shipped
    flat form none of them has a ``#crc_bench_c*`` ancestor, so all three collapse
    to the ``crc_designer_panel`` sentinel → ``len == 1`` → this assertion is
    FALSE (the RED counterfactual that guards against a revert to the vertical
    form).
    """

    async def _drive() -> tuple[bool, set[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            bench_present = app.query("#crc_bench").first() is not None
            probes = ("crc_field_width", "crc_coverage_ranges", "crc_custom_vector")
            distinct = {
                _first_ancestor_id(app.query_one(f"#{p}"), _BENCH_COLUMN_IDS)
                for p in probes
            }
            return bench_present, distinct

    bench_present, distinct = asyncio.run(_drive())
    assert bench_present, "a #crc_bench container must exist"
    assert len(distinct) == 3, (
        "the three bench probes must live in pairwise-distinct columns "
        f"{set(_BENCH_COLUMN_IDS)}; got {distinct!r} (flat form collapses to 1)"
    )
    assert distinct == set(_BENCH_COLUMN_IDS), (
        f"each probe must map to its own bench column, got {distinct!r}"
    )


def test_bench_reflows_to_vertical_stack_when_narrow(tmp_path: Path) -> None:
    """The bench lays horizontally at width and stacks under width-narrow (AT-B59-04).

    Reflow (LLR-L2.2, C-13/C-16/C-23): driven through a REAL resize so the
    production ``on_resize`` path toggles ``#workspace_body.width-narrow`` (never
    hand-added — that would be a C-16 proxy). At the 80×24 floor the columns
    stack — the GEOMETRIC effect ``c2.region.y >= c1.region.y + c1.region.height``
    (c2 below c1), NOT mere class presence. At the comfortable 130×30 they sit
    side-by-side (same top, c2 to the right of c1).
    """

    async def _measure(size: tuple[int, int]) -> tuple[bool, object, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            narrow = "width-narrow" in app.query_one("#workspace_body").classes
            c1 = app.query_one("#crc_bench_c1").region
            c2 = app.query_one("#crc_bench_c2").region
            return narrow, c1, c2

    narrow, c1, c2 = asyncio.run(_measure((80, 24)))
    assert narrow, "an 80-col terminal must toggle #workspace_body.width-narrow"
    assert c2.y >= c1.y + c1.height, (
        f"under width-narrow the columns must STACK; c1={c1!r} c2={c2!r}"
    )

    wide, wc1, wc2 = asyncio.run(_measure((130, 30)))
    assert not wide, "a 130-col terminal must clear width-narrow"
    assert wc1.y == wc2.y and wc2.x > wc1.x, (
        f"at the comfortable width the columns must sit side-by-side; "
        f"c1={wc1!r} c2={wc2!r}"
    )


# AT-B59-05 (``test_verdict_hero_center_aligned_in_hero_row``) was DELETED by
# batch-72 LLR-072-2.4. Its five assertions are each falsified by design: the
# operator's 2026-07-28 report is that the verdict tile does not earn hero
# placement, so HLR-072-2 demotes it to a ``Self-test`` row annotating the Check
# field it validates. This is a recorded requirement RETIREMENT (01-requirements
# §6.5 A-1, ledger D = 1) — deleted, never edited into passing. The surviving
# obligation (the verdict stays present, correctly parented and reachable) is
# re-derived as AT-215 below.


# ─────────────────────────────────────────────────────────────────────────────
# batch-59 Inc-2 — the LIVE coverage-window hero (block glyphs + oracle-pinned
# policy CRCs) + boundary/empty acceptance (HLR-L1, LLR-L1.1/L1.2/L1.3/L1.4;
# AT-B59-01/02/10/11)
# ─────────────────────────────────────────────────────────────────────────────
async def _window_after(
    tmp_path: Path,
    mem_map: dict[int, int] | None,
    ranges: str,
    join: str = "fill",
    pad: str = "0xFF",
) -> tuple[str, set[str], object, str]:
    """Drive the coverage strip and read the mounted #crc_coverage_window.

    Returns the window's rendered plain text, its distinct span-style set, the
    ``_render_markup`` flag, and the live verdict (a liveness witness). The window
    is read through ``render()`` — the visual the widget actually paints (M5).
    """
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        if mem_map is not None:
            app.current_file = _loaded(mem_map)
        await pilot.press("0")
        await pilot.pause()
        app.query_one("#crc_coverage_ranges", Input).value = ranges
        app.query_one("#crc_coverage_join", Select).value = join
        app.query_one("#crc_coverage_pad_byte", Input).value = pad
        await pilot.pause()
        window = app.query_one("#crc_coverage_window", Static)
        rendered = window.render()
        return (
            str(rendered),
            {str(span.style) for span in rendered.spans},
            window._render_markup,
            _verdict(app),
        )


def test_coverage_window_renders_colored_glyphs_with_live_oracles(
    tmp_path: Path,
) -> None:
    """The window renders colored glyphs + LIVE-computed policy oracles (AT-B59-01).

    Signature fidelity (LLR-L1.1/L1.3, D-1/B2): over the §3.2 fixture with a
    two-range ``join="fill"`` target, the mounted ``#crc_coverage_window``
    renders (a) ≥1 block glyph, (b) ``len({span.style}) >= 2`` DISTINCT colors
    (not a monochrome label — present=accent, pad-fill=warn), (c)
    ``_render_markup is False`` (the one new C-17 sink), and (d) its ``.plain``
    CONTAINS BOTH pinned oracles ``0x9C5BCBBD`` (concat) AND ``0x2A8A3950``
    (fill) — the anti-mock teeth: a hardcoded-hex window would drop the live
    compute and fail this pin (proven RED with a stubbed wrong oracle).
    """
    plain, styles, markup, alive = asyncio.run(
        _window_after(
            tmp_path, _fixture_mem(), "0x8000-0x8008, 0x8010-0x8018", join="fill"
        )
    )
    assert "█" in plain or "░" in plain, f"the window must draw block glyphs, got {plain!r}"
    assert len(styles) >= 2, (
        f"the window must paint >= 2 DISTINCT colors, got {styles!r}"
    )
    assert markup is False, "the coverage window must render markup=False (C-17)"
    assert "0x9C5BCBBD" in plain, f"the LIVE concat oracle must render, got {plain!r}"
    assert "0x2A8A3950" in plain, f"the LIVE fill oracle must render, got {plain!r}"
    assert alive != "", "the app must stay alive with the window mounted"


def test_coverage_window_deltas_and_repins_on_range_edit(tmp_path: Path) -> None:
    """The window content DELTAS and re-pins the live oracle on a range edit (AT-B59-02).

    Live-data fidelity (LLR-L1.1, B2): after narrowing to a SINGLE range the
    window's rendered content DIFFERS from the two-range content (a measured
    delta, not "content present"), AND shows the recomputed single-range oracle
    ``0x88AA689F`` (== ``compute_region_crc`` over the same span) while the
    two-range concat oracle ``0x9C5BCBBD`` is GONE — a range-width-only mock that
    never re-digests ``mem_map`` would delta but keep the stale oracle.
    """

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded(_fixture_mem())
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_coverage_ranges", Input).value = (
                "0x8000-0x8008, 0x8010-0x8018"
            )
            app.query_one("#crc_coverage_join", Select).value = "fill"
            await pilot.pause()
            two_range = str(app.query_one("#crc_coverage_window", Static).render())
            app.query_one("#crc_coverage_ranges", Input).value = "0x8000-0x8008"
            await pilot.pause()
            one_range = str(app.query_one("#crc_coverage_window", Static).render())
            return two_range, one_range

    two_range, one_range = asyncio.run(_drive())
    assert one_range != two_range, "the window must delta on a range edit (not static)"
    assert "0x88AA689F" in one_range, (
        f"the single-range window must re-pin the region oracle, got {one_range!r}"
    )
    assert "0x9C5BCBBD" not in one_range, (
        f"the stale two-range oracle must be gone after the edit, got {one_range!r}"
    )


def test_coverage_window_empty_state_no_image(tmp_path: Path) -> None:
    """No image loaded → the shipped empty-state note, no glyphs, no crash (AT-B59-10).

    Boundary (LLR-L1.4): with ``current_file`` unset the window renders the
    SHIPPED empty-state string (shared with the preview so they never diverge),
    computes no glyphs, and the app stays alive.
    """
    plain, styles, markup, alive = asyncio.run(
        _window_after(tmp_path, None, "0x8000-0x8008", join="concat")
    )
    assert "Load an image" in plain, f"the empty window must be graceful, got {plain!r}"
    assert "█" not in plain and "░" not in plain, "no glyphs without an image"
    assert markup is False, "the empty window must still render markup=False (C-17)"
    assert alive != "", "the app must stay alive with no image loaded"


def test_coverage_window_malformed_range_markup_safe(tmp_path: Path) -> None:
    """A malformed/inverted range → markup-safe note, no crash, mem_map intact (AT-B59-11).

    Boundary (LLR-L1.4): an inverted range surfaces the ``Invalid coverage``
    fault note (reusing the ``_build_coverage_target`` path), renders
    ``markup=False``, does not crash, and never mutates ``mem_map``.
    """

    async def _drive() -> tuple[str, object, bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded(_fixture_mem())
            mem_obj = app.current_file.mem_map
            before = dict(mem_obj)
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_coverage_ranges", Input).value = "0x8010-0x8000"
            await pilot.pause()
            window = app.query_one("#crc_coverage_window", Static)
            plain = str(window.render())
            same = app.current_file.mem_map is mem_obj
            unchanged = dict(app.current_file.mem_map) == before
            return plain, window._render_markup, same, unchanged

    plain, markup, same, unchanged = asyncio.run(_drive())
    assert "Invalid coverage" in plain, (
        f"an inverted range must warn markup-safely, got {plain!r}"
    )
    assert markup is False, "the fault window must render markup=False (C-17)"
    assert same, "the window must not replace the loaded mem_map (preview-only)"
    assert unchanged, "the window must not mutate the loaded mem_map (US-V8)"


# ─────────────────────────────────────────────────────────────────────────────
# batch-59 Inc-3 — F1 abort-contract fix on the window + fidelity/preservation/
# security ATs (HLR-L1/L4/L5, LLR-L1.4/L4.1/L5.1; F1/F2, AT-B59-06/08/09)
# ─────────────────────────────────────────────────────────────────────────────
#: A hex-byte pair, used to detect an EMITTED store word (`store 50 39 8A 2A`)
#: vs the refusal line (`store — refused …`), which carries no hex pair.
_STORE_WORD_BYTES = re.compile(r"store [0-9A-F]{2}")


async def _window_text(
    tmp_path: Path,
    mem_map: dict[int, int],
    ranges: str,
    join: str,
    on_conflict: str,
    pad: str = "0xFF",
) -> str:
    """Drive the coverage strip (incl. on_gap_conflict) and read the window text."""
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.current_file = _loaded(mem_map)
        await pilot.press("0")
        await pilot.pause()
        app.query_one("#crc_coverage_ranges", Input).value = ranges
        app.query_one("#crc_coverage_join", Select).value = join
        app.query_one("#crc_coverage_pad_byte", Input).value = pad
        app.query_one("#crc_coverage_on_gap_conflict", Select).value = on_conflict
        await pilot.pause()
        return str(app.query_one("#crc_coverage_window", Static).render())


def test_coverage_window_dirty_gap_abort_refuses_store(tmp_path: Path) -> None:
    """A dirty fill gap under abort refuses the store word on the window (F1/F2).

    Safety consistency (F1): the window's active-policy store output must honor
    the SAME shipped abort contract as the sibling preview (AT-058-08,
    ``evaluate_target``). A stray non-pad byte in the filled inter-range gap +
    ``join="fill"`` + ``on_gap_conflict="abort"`` refuses the CRC, so the window
    must render the refusal and NOT emit the divergent store word — whereas a
    CLEAN gap DOES emit it. The measured clean→dirty delta pins F1 so a future
    refactor can't silently flip the hero back to a divergent value.
    """
    ranges = "0x8000-0x8008, 0x8010-0x8018"
    dirty = _fixture_mem()
    dirty[0x800A] = 0x99  # real byte where the operator promised an erased gap

    clean_text = asyncio.run(
        _window_text(tmp_path, _fixture_mem(), ranges, join="fill", on_conflict="abort")
    )
    dirty_text = asyncio.run(
        _window_text(tmp_path, dict(dirty), ranges, join="fill", on_conflict="abort")
    )

    # Clean: the store word IS emitted (the actionable output the window shows).
    assert _STORE_WORD_BYTES.search(clean_text), (
        f"a clean fill gap must emit the store word, got {clean_text!r}"
    )
    # Dirty + abort: the window refuses and emits NO divergent store word.
    assert "refused" in dirty_text.lower(), (
        f"a dirty fill gap under abort must refuse on the window, got {dirty_text!r}"
    )
    assert not _STORE_WORD_BYTES.search(dirty_text), (
        f"a refused window must NOT emit the divergent store word, got {dirty_text!r}"
    )


def test_recompute_handler_fires_through_relayout(tmp_path: Path) -> None:
    """A reused field event drives _recompute through the re-nested tree (AT-B59-06).

    Preservation (HLR-L4, C-12): the verdict widget lives in the hero row and the
    ``#crc_field_xorout`` field in bench column c1 — DIFFERENT branches of the
    re-nested tree — yet a single real ``Input.Changed`` still fires the shared
    ``_recompute`` and transitions ``#crc_kat_verdict`` MATCH→MISMATCH. The field's
    bench-column ancestry is asserted so the transition is proven to fire THROUGH
    the new layout, not a flat form.
    """

    async def _drive() -> tuple[bool, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            field_in_bench = _has_ancestor(
                app.query_one("#crc_field_xorout"), "crc_bench_c1"
            )
            before = _verdict(app)
            app.query_one("#crc_field_xorout", Input).value = "0x00000000"
            await pilot.pause()
            after = _verdict(app)
            return field_in_bench, before, after

    field_in_bench, before, after = asyncio.run(_drive())
    assert field_in_bench, "#crc_field_xorout must live in bench column c1 (re-nested)"
    assert "MATCH" in before and "MISMATCH" not in before, (
        f"seed verdict must be MATCH, got {before!r}"
    )
    assert "MISMATCH" in after, (
        f"the reused handler must transition the verdict through the layout, got {after!r}"
    )
    assert before != after, "the verdict must TRANSITION through the re-nested tree"


def test_bench_column_ancestry_teeth_computed(tmp_path: Path) -> None:
    """The distinct-column-ancestor teeth are a COMPUTED comparison (AT-B59-08).

    Fidelity teeth (HLR-L5, LLR-L5.1, C-31): on the live bench tree the three
    probes resolve to exactly 3 distinct bench-column ancestors (``len == 3``).
    The flat-form counterfactual is computed IN-CODE by re-running the SAME
    ancestor walk with an EMPTY bench-column set (simulating "no bench columns
    exist"): every probe then collapses to the single ``crc_designer_panel``
    sentinel → ``len == 1``. The demonstrated teeth is the executed
    ``len(bench) == 3`` vs ``len(flat) == 1`` comparison, not prose.
    """

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            probes = [
                app.query_one("#crc_field_width"),
                app.query_one("#crc_coverage_ranges"),
                app.query_one("#crc_custom_vector"),
            ]
            # Live bench tree: each probe's first bench-column ancestor.
            bench = {_first_ancestor_id(w, _BENCH_COLUMN_IDS) for w in probes}
            # Flat-form algebra, computed: with NO bench columns to match, the
            # same walk collapses every probe to the panel sentinel.
            flat = {_first_ancestor_id(w, ()) for w in probes}
            return len(bench), len(flat)

    live_len, flat_len = asyncio.run(_drive())
    assert live_len == 3, f"the bench must yield 3 distinct column ancestors, got {live_len}"
    assert flat_len == 1, (
        f"a flat single-panel-ancestor compose collapses to 1 (the teeth), got {flat_len}"
    )


def test_coverage_window_hostile_markup_renders_literally(tmp_path: Path) -> None:
    """A hostile markup range renders literally with no injected span (AT-B59-09, F1).

    Markup-sink regression lock (C-17, LLR-L1.4): driving a ``[link=evil]…[/]``
    payload plus a bare ``[`` token into ``#crc_coverage_ranges`` makes the range
    malformed, so the window echoes the raw token through its ``Invalid coverage``
    fault branch. Assert (a) no crash (the app stays alive), (b) the bracket
    payload appears VERBATIM in ``.plain`` (rendered literally, not interpreted),
    (c) ``render().spans`` carry NO input-derived style span (no ``link``) — the
    sink is markup-safe by construction (``Text()``/``append``, never
    ``from_markup``). Crash-only would be insufficient (MEMORY markup-sink rule).
    """

    async def _drive() -> tuple[str, list, object, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded(_fixture_mem())
            await pilot.press("0")
            await pilot.pause()
            app.query_one("#crc_coverage_ranges", Input).value = (
                "[link=evil]0x8000-0x8008[/], ["
            )
            await pilot.pause()
            window = app.query_one("#crc_coverage_window", Static)
            rendered = window.render()
            return (
                str(rendered),
                list(rendered.spans),
                window._render_markup,
                _verdict(app),
            )

    plain, spans, markup, alive = asyncio.run(_drive())
    assert alive != "", "the app must stay alive after a hostile range string"
    assert markup is False, "the window must render markup=False (C-17)"
    assert "[link=evil]" in plain, (
        f"the hostile markup must render literally in the window, got {plain!r}"
    )
    assert all("link" not in str(span.style).lower() for span in spans), (
        f"the window must apply no input-derived (link) style span, got {spans!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# realign — right-column reachability + full-width JSON strip (operator-flagged
# "right sidebar scrollbar pinned / content unreachable"; R6 full-width JSON)
# ─────────────────────────────────────────────────────────────────────────────
#: Every right-hand / lower widget the operator reported as unreachable — the
#: verdict, warnings, the custom-vector result, the template + load/save fields
#: and buttons, and the JSON preview.
_RIGHT_COLUMN_IDS = (
    "crc_kat_verdict",
    "crc_warnings",
    "crc_custom_vector_result",
    "crc_field_name",
    "crc_field_aliases",
    "crc_load_path",
    "crc_save_btn",
    "crc_load_btn",
    "crc_json_preview",
)


def test_right_column_widgets_reachable_and_json_full_width(tmp_path: Path) -> None:
    """Every right-hand widget scrolls into view and the JSON preview is full-width.

    Operator-flagged bug (realign): the right-hand content (verdict, warnings,
    custom-vector result, template + load/save fields and buttons, JSON preview)
    was effectively unreachable behind a scrollbar pinned at the top. After the
    realign the panel allows vertical scrolling and each such widget scrolls into
    a NON-EMPTY on-screen region (``region.area > 0``) — the reachability teeth,
    not mere "widget exists". R6: the Template JSON preview is a full-width strip
    OUTSIDE the 3-column bench (no ``#crc_bench_c*`` ancestor) and wider than a
    single bench column — measured, not asserted by prose.
    """

    async def _drive() -> tuple[dict[str, int], bool, bool, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            panel = app.query_one("#crc_designer_panel")
            scrollable = panel.allow_vertical_scroll
            reach: dict[str, int] = {}
            for wid in _RIGHT_COLUMN_IDS:
                widget = app.query_one(f"#{wid}")
                widget.scroll_visible(animate=False)
                await pilot.pause()
                reach[wid] = widget.region.area
            json_group = app.query_one("#crc_json_preview_group")
            json_group.scroll_visible(animate=False)
            await pilot.pause()
            json_in_bench = any(
                _has_ancestor(app.query_one("#crc_json_preview"), col)
                for col in _BENCH_COLUMN_IDS
            )
            json_width = json_group.region.width
            column_width = app.query_one("#crc_bench_c1").region.width
            return reach, scrollable, json_in_bench, json_width, column_width

    reach, scrollable, json_in_bench, json_width, column_width = asyncio.run(_drive())
    assert scrollable, "the designer panel must allow vertical scroll so lower content is reachable"
    for wid, area in reach.items():
        assert area > 0, (
            f"{wid} must scroll into a non-empty on-screen region (reachable), got area={area}"
        )
    assert not json_in_bench, (
        "R6: the JSON preview must live OUTSIDE the 3-column bench (full-width strip)"
    )
    assert json_width > column_width, (
        f"R6: the JSON strip must be wider than one bench column (full-width); "
        f"got json={json_width} vs column={column_width}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# batch-72 Inc-3 — CRC Designer Variant B: the paired Reflection row + the KAT
# demoted to a Self-test row under Check + the recompute-surface id census
# (HLR-072-1/2/8, LLR-072-1.1/1.2/2.1/2.2/2.3/2.4/8.1; AT-213/215/219,
# TC-510..513)
# ─────────────────────────────────────────────────────────────────────────────
#: The orphaned batch-58 helper LLR-072-1.2 deletes. Assembled from fragments on
#: purpose: the requirement's pass threshold is a REPO-WIDE grep returning zero
#: hits, which a literal in this file would itself falsify.
_ORPHANED_SWITCH_HELPER = "_switch" + "_row"


def _repo_root() -> Path:
    """The worktree root, derived from the module under test (never cwd)."""
    return Path(crc_designer_view.__file__).resolve().parents[2]


def _custom_vector_result(app: S19TuiApp) -> str:
    """Read the mounted ``#crc_custom_vector_result`` widget's rendered content."""
    return str(app.query_one("#crc_custom_vector_result", Static).content)


def test_reflection_pair_row_shares_one_band_and_drives_the_kernel(
    tmp_path: Path,
) -> None:
    """refin/refout share one row band, are label-separated, and drive the CRC (AT-213).

    HLR-072-1 / LLR-072-1.1. Three clauses, driven through the SHIPPED surface
    (rail key ``0``, never a ``.focus()`` proxy — C-16):

    1. **one band** — ``#crc_field_refin.region.y == #crc_field_refout.region.y``.
       On the shipped tree they are stacked (measured ``y=32`` / ``y=33``), so
       this clause is FALSE before the pair row.
    2. **separable** — a ``Label`` renders strictly BETWEEN the two switches'
       x-bands. Co-location alone is not the requirement: the operator's defect
       was that one toggle reads as the other, so the interleaved label is the
       fix and the assertion.
    3. **C-10 non-default drive with measured values** (00-measurements M-7):
       ``#crc_field_refin`` is seeded ``True`` by ``SEED_ALGORITHM``
       (CRC-32/ISO-HDLC); driving it to ``False`` through the real ``Switch``
       reactive path must transition ``#crc_custom_vector_result`` from
       ``0xCBF43926`` (the externally published CRC-32 check value over the
       seeded vector ``123456789``) to ``0x1898913F`` — the EXACT transition, so
       a rewired-to-the-wrong-switch pair row cannot pass on a bare ``!=``.
    """

    async def _drive() -> tuple[int, int, int, bool, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            refin = app.query_one("#crc_field_refin", Switch)
            refout = app.query_one("#crc_field_refout", Switch)
            row = refin.parent
            between = [
                label
                for label in row.query(Label)
                if refin.region.right <= label.region.x
                and label.region.right <= refout.region.x
            ]
            seeded_on = refin.value
            before = _custom_vector_result(app)
            # The real Switch path: the reactive setter posts Switch.Changed,
            # exactly as a click would (the file's Input.value idiom).
            refin.value = False
            await pilot.pause()
            after = _custom_vector_result(app)
            return (
                refin.region.y,
                refout.region.y,
                len(between),
                seeded_on,
                before,
                after,
            )

    refin_y, refout_y, between, seeded_on, before, after = asyncio.run(_drive())
    assert refin_y == refout_y, (
        f"the reflection toggles must share one row band; "
        f"refin.y={refin_y} refout.y={refout_y}"
    )
    assert between == 1, (
        "exactly one Label must render strictly between the two switches' "
        f"x-bands (the separability cue); got {between}"
    )
    assert seeded_on, (
        "SEED_ALGORITHM must seed refin=True, else the drive is not a "
        "non-default transition (C-10)"
    )
    assert before == "0xCBF43926", (
        f"the seeded vector CRC must be the published CRC-32 check value, got {before!r}"
    )
    assert after == "0x1898913F", (
        f"driving refin True->False must move the CRC to 0x1898913F, got {after!r}"
    )


def test_kat_verdict_demoted_to_self_test_row_under_check(tmp_path: Path) -> None:
    """The KAT verdict is a Self-test row inside the Algorithm group (AT-215).

    HLR-072-2 / LLR-072-2.1. The verdict is re-parented, NOT deleted — batch-59's
    hero tile is retired (§6.5 A-1) and the verdict becomes an annotation of the
    ``Check`` field it validates:

    1. ``#crc_kat_verdict`` has ancestor ``#crc_algorithm_fields``;
    2. the reference vector ``123456789`` is named on screen inside that row —
       without it the row reads ``Self-test ✓ MATCH`` and never says WHAT was
       self-tested (the retired hero tile carried the only on-screen naming);
    3. the verdict is still LIVE at its new parent: setting ``#crc_field_check``
       to the measured ``0x00000000`` through the real ``Input.Changed`` path
       transitions MATCH → MISMATCH. **Two near-misses are excluded explicitly**
       (00-measurements M-7): clearing the field yields ``○ NO-EXPECTED`` and a
       non-hex keystroke yields ``Invalid parameters: …`` — both would satisfy a
       lazy "the text changed" assertion, neither satisfies this one;
    4. ``#crc_live_verify`` is gone (the discriminating negative — clause 1 alone
       is true of a tree that kept the wrapper and cloned the verdict).
    """

    async def _drive() -> tuple[bool, str, str, str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            verdict = app.query_one("#crc_kat_verdict", Static)
            in_algorithm = _has_ancestor(verdict, "crc_algorithm_fields")
            row_text = " ".join(
                str(child.render()) for child in verdict.parent.children
            )
            before = _verdict(app)
            app.query_one("#crc_field_check", Input).value = "0x00000000"
            await pilot.pause()
            after = _verdict(app)
            return (
                in_algorithm,
                row_text,
                before,
                after,
                len(app.query("#crc_live_verify")),
            )

    in_algorithm, row_text, before, after, wrappers = asyncio.run(_drive())
    assert in_algorithm, (
        "#crc_kat_verdict must be re-parented under #crc_algorithm_fields"
    )
    assert "123456789" in row_text, (
        f"the Self-test row must name the reference vector on screen, got {row_text!r}"
    )
    assert "MATCH" in before and "MISMATCH" not in before, (
        f"the seed verdict must be MATCH at the new parent, got {before!r}"
    )
    assert "MISMATCH" in after, (
        f"a real Input.Changed on #crc_field_check must reach the demoted "
        f"verdict, got {after!r}"
    )
    assert "NO-EXPECTED" not in after and "Invalid parameters" not in after, (
        f"the excluded near-misses must NOT satisfy this clause, got {after!r}"
    )
    assert wrappers == 0, (
        f"the #crc_live_verify hero wrapper must no longer be composed, got {wrappers}"
    )


def test_recompute_surface_ids_are_the_live_markup_census(
    tmp_path: Path, monkeypatch
) -> None:
    """The recompute id tuple is the markup census AND is actually consumed (AT-219).

    HLR-072-8 / LLR-072-8.1. Two clauses, deliberately different in kind:

    **Clause 1 — the PIN, labelled as such.** Iterate the LIVE module-level
    ``_RECOMPUTE_SURFACE_IDS`` (never a hand-list, C-31) and assert every
    resolved widget reports ``_render_markup is False``. All six sinks are
    already ``markup=False`` today, so this clause is INVARIANT under this batch:
    it is a regression pin protecting the ``compose`` rewrite that echoes
    user-typed text into these sinks (``Invalid parameters: {exc}``), not a gate
    on new behaviour. A seventh surface declared later is covered automatically.

    **Clause 2 — the GATE.** ``len(tuple) >= 6`` admits a tuple that is hoisted,
    asserted, then IGNORED by a ``_recompute`` still carrying hardcoded queries.
    So: monkeypatch the module tuple to carry one bogus id, drive one real
    ``Input.Changed``, and assert ``_recompute`` takes its ``NoMatches`` early
    return — the live surfaces do not move. This is the only clause that is
    FALSE before the hoist.
    """
    surface_ids = crc_designer_view._RECOMPUTE_SURFACE_IDS
    assert len(surface_ids) >= 6, (
        f"the recompute surface census must cover >= 6 sinks, got {len(surface_ids)}"
    )

    async def _census() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            return {
                surface_id: app.query_one(f"#{surface_id}", Static)._render_markup
                for surface_id in surface_ids
            }

    async def _gate() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            before = _verdict(app)
            monkeypatch.setattr(
                crc_designer_view,
                "_RECOMPUTE_SURFACE_IDS",
                surface_ids + ("crc_no_such_surface",),
            )
            app.query_one("#crc_field_xorout", Input).value = "0x00000000"
            await pilot.pause()
            return before, _verdict(app)

    flags = asyncio.run(_census())
    for surface_id, flag in flags.items():
        assert flag is False, (
            f"#{surface_id} is a recompute sink and must render markup=False "
            f"(C-17), got {flag!r}"
        )

    before, after = asyncio.run(_gate())
    assert "MATCH" in before and "MISMATCH" not in before, (
        f"the gate needs a live MATCH baseline, got {before!r}"
    )
    assert after == before, (
        "with a bogus id in the module tuple _recompute must take its NoMatches "
        f"early return; the verdict moved {before!r} -> {after!r}, so the tuple "
        "is declared but not consumed"
    )


def test_reflection_row_structure(tmp_path: Path) -> None:
    """The pair row is ONE .crc-field-row holding both switches (TC-510).

    White-box structure behind AT-213: both switches share a single
    ``.crc-field-row`` parent inside ``#crc_algorithm_fields``, and that row
    carries the row label plus a sub-label per toggle (``Reflection`` / ``in`` /
    ``out``) — the label inventory the geometry clause of AT-213 measures.
    """

    async def _drive() -> tuple[bool, bool, bool, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            refin = app.query_one("#crc_field_refin", Switch)
            refout = app.query_one("#crc_field_refout", Switch)
            row = refin.parent
            return (
                refin.parent is refout.parent,
                "crc-field-row" in row.classes,
                _has_ancestor(refin, "crc_algorithm_fields"),
                [str(label.render()) for label in row.query(Label)],
            )

    shared_row, is_field_row, in_algorithm, labels = asyncio.run(_drive())
    assert shared_row, "both reflection switches must share ONE row container"
    assert is_field_row, "the reflection pair row must be a .crc-field-row"
    assert in_algorithm, "the reflection row must live inside #crc_algorithm_fields"
    assert labels == ["Reflection", "in", "out"], (
        f"the pair row must carry the row label plus one sub-label per toggle, "
        f"got {labels!r}"
    )


def test_orphaned_per_toggle_helper_is_deleted() -> None:
    """The single-toggle row helper is gone from the package and tests (TC-511).

    LLR-072-1.2: the pair row is the only reflection construction site, so the
    per-toggle helper is orphaned — deleted, not left dead. Asserted twice: the
    attribute is absent from the class, and no ``.py`` file under ``s19_app/`` or
    ``tests/`` still names it (the requirement's repo-wide grep threshold).
    """
    assert not hasattr(crc_designer_view.CrcDesignerPanel, _ORPHANED_SWITCH_HELPER), (
        f"CrcDesignerPanel.{_ORPHANED_SWITCH_HELPER} is orphaned and must be deleted"
    )
    root = _repo_root()
    scanned = 0
    hits: list[str] = []
    for tree in ("s19_app", "tests"):
        for path in (root / tree).rglob("*.py"):
            scanned += 1
            if _ORPHANED_SWITCH_HELPER in path.read_text(encoding="utf-8"):
                hits.append(str(path.relative_to(root)))
    assert scanned > 0, f"the source scan resolved no files under {root} (bad root)"
    assert hits == [], f"{_ORPHANED_SWITCH_HELPER} must have 0 hits, found in {hits!r}"


def test_hero_right_column_holds_warnings_only(tmp_path: Path) -> None:
    """#crc_top_right carries exactly one child group: Warnings (TC-512).

    LLR-072-2.2: retiring the verdict tile must LEAVE the right column, not
    empty it — the counterfactual for "the tile was removed" is a column with
    zero children, which would silently drop the Warnings surface that
    ``_recompute`` writes to.
    """

    async def _drive() -> tuple[list[str], bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            top_right = app.query_one("#crc_top_right")
            child_ids = [str(child.id) for child in top_right.children]
            return child_ids, _has_ancestor(
                app.query_one("#crc_warnings"), "crc_top_right"
            )

    child_ids, warnings_inside = asyncio.run(_drive())
    assert child_ids == ["crc_warnings_group"], (
        f"#crc_top_right must hold the Warnings group alone, got {child_ids!r}"
    )
    assert warnings_inside, "#crc_warnings must still resolve under #crc_top_right"


def test_retired_hero_selectors_absent_from_stylesheet() -> None:
    """The .crc-hero and #crc_live_verify selectors are retired (TC-513).

    LLR-072-2.3: the hero rule is dead CSS once the tile is gone. The stylesheet
    is located from the package (never cwd) and a live CRC selector is asserted
    present first, so a mis-resolved path cannot pass this vacuously.
    """
    stylesheet = _repo_root() / "s19_app" / "tui" / "styles.tcss"
    text = stylesheet.read_text(encoding="utf-8")
    assert "#crc_hero_row" in text, (
        f"{stylesheet} does not look like the CRC stylesheet (non-vacuity guard)"
    )
    assert "crc-hero" not in text, "the .crc-hero rule must be retired"
    assert "crc_live_verify" not in text, "no #crc_live_verify rule may remain"


# ─────────────────────────────────────────────────────────────────────────────
# batch-72 Inc-4 — G-1, the Switch separability guard (HLR-072-3; AT-214, TC-514)
#
# G-1 was originally scoped over "every pair of vertically-adjacent focusable
# controls in the CRC form". That rule is FALSE of 16 pairs on the shipped tree
# and Variant B fixes exactly ONE of them; the other 15 abut BY DESIGN
# (`styles.tcss` `.crc-field-input { border: none; height: 1 }`, batch-59's
# approved R9 compact-row decision). A same-widget-class rule was then proposed
# and ALSO rejected on measurement — 7 violations pre-batch, 6 post, so it is RED
# before AND after and proves nothing. The Switch-only rule is the only one of
# the three that is FALSE before (1 pair) and satisfiable after (0 pairs).
# Census: 00-measurements.md M-1.
# ─────────────────────────────────────────────────────────────────────────────
#: A ``Switch`` construction site. Word-bounded so a hypothetical ``MySwitch(``
#: subclass call is not miscounted as one; the scan is scoped to ``s19_app/``, so
#: this file's own occurrences are out of its reach.
_SWITCH_CTOR = re.compile(r"\bSwitch\(")


def _vertically_abutting(upper: Switch, lower: Switch) -> bool:
    """The §1.3 relation: ``lower`` starts on the row ``upper`` ends, x-bands overlapping.

    Verbatim from `01-requirements.md` §1.3 — ``b.region.y == a.region.y +
    a.region.height`` AND ``a.x < b.x + b.width and b.x < a.x + a.width``. The
    x-band clause is what stops two controls in different bench columns from
    counting as stacked merely because their rows line up.
    """
    a, b = upper.region, lower.region
    return (
        b.y == a.y + a.height
        and a.x < b.x + b.width
        and b.x < a.x + a.width
    )


def test_at214_no_two_switches_render_vertically_abutting(tmp_path: Path) -> None:
    """No two ``Switch`` widgets render vertically abutting (AT-214, G-1).

    HLR-072-3. Three clauses in this node; the fourth (the C-40 counterfactual)
    is executed at the gate rather than encoded, because a permanently-reverted
    tree is not a counterfactual — transcript in
    ``.dev-flow/2026-07-30-batch-72/03-increments/increment-004.md``.

    1. the subject set is **DERIVED** from the live DOM — ``screen.query(Switch)``
       filtered ``region.area > 0`` — never hand-listed (C-31). The area filter is
       not cosmetic: zero-area ``SelectOverlay``-style phantoms sit at
       ``Region(0,0,0,0)`` and a naive walk pairs them nonsensically at ``y=0``;
    2. the derived set is **non-empty** (``>= 2``) — a broken walk, a renamed
       widget class or a screen that never mounted would otherwise satisfy
       clause 3 vacuously, which is the whole failure mode this control exists
       to prevent;
    3. **zero** abutting pairs under the §1.3 relation, checked over ordered
       permutations so the relation is evaluated in both directions.

    The guard coincides with AT-213's pair row *today* precisely because those
    two switches are the only ones that exist — stated plainly rather than
    dressed up as a broader property. What makes it a guard rather than a restatement
    is that the subject set is derived: a third ``Switch`` added anywhere on this
    screen tomorrow is policed automatically, and TC-514 carries the argument that
    no ``Switch`` can be constructed outside it.
    """

    async def _drive() -> tuple[list[str], list[tuple[str, str]]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            switches = [
                widget
                for widget in app.screen.query(Switch)
                if widget.region.area > 0
            ]
            abutting = [
                (str(upper.id), str(lower.id))
                for upper, lower in permutations(switches, 2)
                if _vertically_abutting(upper, lower)
            ]
            return [str(widget.id) for widget in switches], abutting

    switch_ids, abutting = asyncio.run(_drive())
    assert len(switch_ids) >= 2, (
        f"the derived Switch set must be non-empty (>= 2), got {switch_ids!r} — "
        "a vacuous pass here would report GREEN on a screen that never mounted"
    )
    assert abutting == [], (
        f"no two Switch widgets may render vertically abutting (G-1); "
        f"abutting pairs: {abutting!r} out of {switch_ids!r}"
    )


def test_tc514_every_switch_construction_site_is_on_the_crc_designer() -> None:
    """Every ``Switch`` in the package is constructed by the CRC Designer (TC-514).

    AT-214 queries ``app.screen``, and ``App.query`` is **screen-scoped**
    (``app._get_dom_base() -> Screen``): the query alone therefore certifies
    "no abutting Switch pair *on the CRC screen*", NOT "anywhere in the app".
    This node carries the completeness half of that argument, and it is the
    load-bearing evidence — a static fact about the source, not a runtime one:

    (a) exactly one module in ``s19_app/`` imports ``Switch`` at all, and
    (b) every ``Switch(`` construction site in the package is in that module,

    so every ``Switch`` that can exist is composed by ``CrcDesignerPanel`` and is
    inside the scope AT-214 walks.

    **Re-derived at Inc-4, not carried.** `01-requirements.md` HLR-072-3 and
    00-measurements M-1 both record the site count as **1**
    (``crc_designer_view.py:467``). That was true of ``origin/main`` and is FALSE
    of this tree: LLR-072-1.2 deleted the per-toggle row helper (see
    ``_ORPHANED_SWITCH_HELPER`` above — one ``Switch(`` call invoked twice) and
    Inc-3 inlined both toggles into the pair row, so the count is now **2**
    (``:325`` and ``:327``). The count was always incidental;
    the property the requirement actually needs is *single-module confinement*,
    which survives unchanged. Asserting the stale ``== 1`` would have shipped a
    RED test; asserting a bare ``== 2`` would re-plant the same brittle number.
    """
    root = _repo_root()
    package = root / "s19_app"
    scanned = 0
    construction_sites: list[str] = []
    importers: list[str] = []
    for path in package.rglob("*.py"):
        scanned += 1
        source = path.read_text(encoding="utf-8")
        relative = path.relative_to(root).as_posix()
        if _SWITCH_CTOR.search(source):
            construction_sites.append(relative)
        if re.search(r"^from textual\.widgets import .*\bSwitch\b", source, re.M):
            importers.append(relative)

    assert scanned > 0, f"the package scan resolved no .py files under {package}"
    assert construction_sites, (
        "the scan found no Switch construction site at all — the CRC Designer "
        "composes two, so this is a broken scan, not a clean package"
    )
    assert set(construction_sites) == {"s19_app/tui/crc_designer_view.py"}, (
        "every Switch construction site must live in the CRC Designer, else "
        "AT-214's screen-scoped query is not a complete subject set; found "
        f"{sorted(set(construction_sites))!r}"
    )
    assert set(importers) == {"s19_app/tui/crc_designer_view.py"}, (
        "only the CRC Designer may import Switch; found "
        f"{sorted(set(importers))!r}"
    )
