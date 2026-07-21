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

from textual.widgets import Input, Select

from s19_app.tui.app import S19TuiApp
from s19_app.tui.operations import crc_kernel
from s19_app.tui.operations.crc_kernel import SEED_ALGORITHM
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
