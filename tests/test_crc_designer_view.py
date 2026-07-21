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
from pathlib import Path

from textual.widgets import Button, Input, Select, Static, Switch

from s19_app.tui.app import S19TuiApp
from s19_app.tui.operations import crc_kernel
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

    assert before == "MATCH", f"seed verdict must be MATCH, got {before!r}"
    assert after_break == "MISMATCH", (
        f"breaking xorout must transition to MISMATCH, got {after_break!r}"
    )
    assert before != after_break, "the verdict must TRANSITION, not stay put (B3)"
    assert after_clear == "NO-EXPECTED", (
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
        assert verdicts[preset.name] == "MATCH", (
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
    assert verdict == "MATCH", "a load fault must leave the form unchanged (app alive)"


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
    assert before == "", "the seed store_width (4) is wide enough; no warning"
    assert "truncated" in after, (
        f"a too-small store_width must warn live, got {after!r}"
    )
    assert markup_off, "the warnings widget must render markup-safe (C-17)"
