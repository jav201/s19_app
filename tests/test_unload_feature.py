"""Unit tests — the unload rebuild functions (inverse of the load merges).

The unload feature rebuilds ``current_file`` clearing ONE artifact's fields
while carrying every surviving derived loader fact forward (``entropy_windows``,
``source_s0_header``, ``out_of_order_count``, ``entry_point`` — the #106 fix set),
via ``dataclasses.replace``. These tests pin the pure state logic directly and
drive ``_apply_unload`` through a light pilot for the app-wiring path:

  AC-1  ``_unload_mac`` on S19+MAC keeps the image + derived facts; MAC cleared.
  AC-2  ``_unload_primary`` on S19+MAC degrades to a MAC-only spine.
  AC-3  unloading the last spine yields ``None`` (empty state everywhere).

Inc-3 adds through-the-shipped-surface pilot acceptance tests
(``test_ac1_*`` .. ``test_ac5_*``). These drive the app's REAL synchronous
loader (``load_selected_file`` — the entry ``_parse_loaded_file`` +
``_apply_loaded_file`` run behind, including the live S19+MAC merge) over the
``examples/case_01_basic_valid`` trio, then assert the OBSERVABLE result: the
mounted ``MemoryMapPanel.rendered_text`` and the ``LoadedArtifactsPanel``
``.loaded-detail`` slot readouts — never the raw ``LoadedFile`` fields alone.
Pilots run at ``size=(120, 40)`` so all three slots render (the panel caps to
two rows under an 80-col width).

Non-frozen test file (touches no engine-frozen module).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from s19_app.tui.app import (
    S19TuiApp,
    _has_a2l,
    _has_mac,
    _has_primary,
    _unload_a2l,
    _unload_mac,
    _unload_primary,
)
from s19_app.tui.models import LoadedFile
from s19_app.tui.screens_directionb import LoadedArtifactsPanel, MemoryMapPanel
from s19_app.tui.services.entropy_service import compute_entropy


def _s19_with_mac_and_a2l(tmp_path: Path, n: int = 600) -> LoadedFile:
    """A full S19 image + overlaid MAC + attached A2L companion, with the
    derived loader facts populated so their survival is observable."""
    mem = {0x1000 + i: (i * 7) & 0xFF for i in range(n)}
    return LoadedFile(
        path=tmp_path / "fw.s19",
        file_type="s19",
        mem_map=mem,
        row_bases=sorted({a - a % 16 for a in mem}),
        ranges=[(0x1000, 0x1000 + n)],
        range_validity=[True],
        errors=[],
        a2l_path=tmp_path / "labels.a2l",
        a2l_data={"characteristics": [{"name": "MAP"}]},
        mac_path=tmp_path / "tags.mac",
        mac_records=[{"parse_ok": True, "name": "RPM", "address": 0x1000}],
        mac_diagnostics=["ok"],
        entropy_windows=compute_entropy(mem),
        source_s0_header=b"S0HDR",
        out_of_order_count=3,
        entry_point=0x1234,
        variant_id="fw",
    )


def _s19_only(tmp_path: Path, n: int = 600) -> LoadedFile:
    mem = {0x1000 + i: (i * 7) & 0xFF for i in range(n)}
    return LoadedFile(
        path=tmp_path / "fw.s19",
        file_type="s19",
        mem_map=mem,
        row_bases=sorted({a - a % 16 for a in mem}),
        ranges=[(0x1000, 0x1000 + n)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        entropy_windows=compute_entropy(mem),
        source_s0_header=b"S0HDR",
    )


def _mac_only(tmp_path: Path) -> LoadedFile:
    return LoadedFile(
        path=tmp_path / "tags.mac",
        file_type="mac",
        mem_map={},
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_path=tmp_path / "tags.mac",
        mac_records=[{"parse_ok": True, "name": "RPM", "address": 0x1000}],
        mac_diagnostics=["ok"],
    )


def test_presence_helpers(tmp_path: Path) -> None:
    """The three presence predicates read the spine/companion state."""
    full = _s19_with_mac_and_a2l(tmp_path)
    assert _has_primary(full) and _has_mac(full) and _has_a2l(full)

    mac_only = _mac_only(tmp_path)
    assert not _has_primary(mac_only)  # MAC owns file_type but has no ranges
    assert _has_mac(mac_only)
    assert not _has_a2l(mac_only)


def test_unload_mac_keeps_image_and_derived_facts(tmp_path: Path) -> None:
    """AC-1 (state level): dropping the MAC off S19+MAC keeps the image, its
    entropy_windows + source_s0_header, and the A2L; MAC fields cleared."""
    loaded = _s19_with_mac_and_a2l(tmp_path)

    result = _unload_mac(loaded)

    assert result is not None
    # Image spine + derived facts survive.
    assert result.file_type == "s19"
    assert result.mem_map == loaded.mem_map
    assert result.ranges == loaded.ranges
    assert result.entropy_windows == loaded.entropy_windows
    assert result.source_s0_header == b"S0HDR"
    assert result.out_of_order_count == 3
    assert result.entry_point == 0x1234
    # A2L companion survives.
    assert result.a2l_path == tmp_path / "labels.a2l"
    assert result.a2l_data == loaded.a2l_data
    # MAC fields cleared.
    assert result.mac_path is None
    assert result.mac_records == []
    assert result.mac_diagnostics == []


def test_unload_primary_degrades_to_mac_only(tmp_path: Path) -> None:
    """AC-2 (state level): dropping the S19/HEX off S19+MAC yields a MAC-only
    spine — no image, image-derived facts cleared, MAC + A2L kept."""
    loaded = _s19_with_mac_and_a2l(tmp_path)

    result = _unload_primary(loaded)

    assert result is not None
    assert result.file_type == "mac"
    # Image + image-derived facts + caches cleared.
    assert result.mem_map == {}
    assert result.row_bases == []
    assert result.ranges == []
    assert result.range_validity == []
    assert result.entropy_windows == []
    assert result.source_s0_header is None
    assert result.out_of_order_count == 0
    assert result.entry_point is None
    assert result.range_index is None
    assert result.bases_set is None
    assert result.variant_id is None
    # MAC + A2L kept.
    assert result.mac_records == loaded.mac_records
    assert result.mac_path == tmp_path / "tags.mac"
    assert result.a2l_data == loaded.a2l_data


def test_unload_primary_on_s19_only_returns_none(tmp_path: Path) -> None:
    """AC-3 (spine rule): with no MAC, dropping the S19/HEX removes the last
    spine — the whole snapshot (and any companion A2L) clears to None."""
    assert _unload_primary(_s19_only(tmp_path)) is None


def test_unload_mac_on_mac_only_returns_none(tmp_path: Path) -> None:
    """The MAC is the spine in a MAC-only load, so unloading it clears all."""
    assert _unload_mac(_mac_only(tmp_path)) is None


def test_unload_a2l_clears_companion_keeps_spine(tmp_path: Path) -> None:
    """A2L is a companion: unloading it clears a2l_path/a2l_data and keeps the
    spine + its ranges + entropy — never returns None."""
    loaded = _s19_with_mac_and_a2l(tmp_path)

    result = _unload_a2l(loaded)

    assert result is not None
    assert result.a2l_path is None
    assert result.a2l_data is None
    assert result.ranges == loaded.ranges
    assert result.entropy_windows == loaded.entropy_windows
    # MAC untouched by an A2L unload.
    assert result.mac_records == loaded.mac_records


def test_apply_unload_all_clears_current_file(tmp_path: Path) -> None:
    """AC-3 (app wiring): _apply_unload("all") sets current_file None and the
    renderer refresh completes without error (empty-state branches reached)."""

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _s19_with_mac_and_a2l(tmp_path)
            app._apply_unload("all")
            await pilot.pause()
            return app.current_file

    assert asyncio.run(_drive()) is None


def test_apply_unload_mac_keeps_image_via_app(tmp_path: Path) -> None:
    """App wiring: _apply_unload("mac") dispatches to _unload_mac and refreshes
    the views without error, leaving the image spine loaded."""

    async def _drive() -> LoadedFile:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _s19_with_mac_and_a2l(tmp_path)
            app._apply_unload("mac")
            await pilot.pause()
            return app.current_file

    result = asyncio.run(_drive())
    assert result is not None
    assert result.file_type == "s19"
    assert result.mac_records == []
    assert result.entropy_windows  # image-derived facts survived the refresh


def test_apply_unload_no_file_is_noop(tmp_path: Path) -> None:
    """Per-artifact unload with nothing loaded is a no-op (stays None)."""

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = None
            app._apply_unload("mac")
            await pilot.pause()
            return app.current_file

    assert asyncio.run(_drive()) is None


# ---------------------------------------------------------------------------
# Inc-3 — through-the-shipped-surface pilot acceptance tests.
#
# Every test below drives the app's REAL synchronous loader over the packaged
# case_01 trio and reads the rendered Memory Map + Loaded panel, so the AC is
# observed exactly where a user would see it.
# ---------------------------------------------------------------------------

_CASE_01 = Path(__file__).resolve().parent.parent / "examples" / "case_01_basic_valid"
_CASE_01_S19 = _CASE_01 / "firmware.s19"
_CASE_01_MAC = _CASE_01 / "firmware.mac"
_CASE_01_A2L = _CASE_01 / "firmware.a2l"


def _detail_texts(app: S19TuiApp) -> list[str]:
    """The three Loaded-panel slot readouts as plain text, in ``_SLOTS`` order
    ``[primary, mac, a2l]``.

    Reads the mounted ``LoadedArtifactsPanel``'s ``.loaded-detail`` cells — the
    through-surface readout a user sees (each is a present name+summary or the
    absent ``(none)``), not the underlying ``LoadedFile`` fields. Must be called
    inside a running pilot (an active app is required to render ``Static``
    content)."""
    panel = app.query_one("#loaded_panel", LoadedArtifactsPanel)
    texts: list[str] = []
    for cell in panel.query(".loaded-detail"):
        content = cell.render()
        texts.append(getattr(content, "plain", str(content)))
    return texts


def test_ac1_unload_mac_keeps_image_and_map_through_surface(tmp_path: Path) -> None:
    """AC-1 (through the surface): load the case_01 trio through the app's real
    loader (``load_selected_file`` — runs the live S19+MAC merge), then unload
    the MAC. The image spine + entropy survive, the mounted Memory Map still
    renders bands (not its empty text), and only the MAC slot flips to
    ``(none)`` while the S19 and A2L slots stay present."""

    async def _drive() -> tuple[object, list[str], str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.load_selected_file(_CASE_01_S19, a2l_files=[_CASE_01_A2L])
            await pilot.pause()
            app.load_selected_file(_CASE_01_MAC)
            await pilot.pause()
            app._apply_unload("mac")
            await pilot.pause()
            mm = app.query_one("#memory_map_panel", MemoryMapPanel)
            return app.current_file, _detail_texts(app), mm.rendered_text

    current, slots, map_text = asyncio.run(_drive())
    assert current is not None
    assert current.file_type in {"s19", "hex"}
    assert current.entropy_windows  # image-derived facts survived the unload
    assert map_text != MemoryMapPanel._EMPTY_TEXT
    assert slots[0].startswith("firmware.s19")
    assert slots[1] == "(none)"
    assert slots[2].startswith("firmware.a2l")


def test_ac2_unload_primary_degrades_to_mac_only_no_image(tmp_path: Path) -> None:
    """AC-2 (through the surface): from the loaded trio, unload the primary
    image. The snapshot degrades to a MAC-only spine (``file_type == "mac"``,
    no ranges), the mounted Memory Map falls back to its no-image (empty) text,
    and the Loaded panel shows the S19 slot ``(none)`` with the MAC slot still
    present. Drives the real loader."""

    async def _drive() -> tuple[object, list[str], str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.load_selected_file(_CASE_01_S19, a2l_files=[_CASE_01_A2L])
            await pilot.pause()
            app.load_selected_file(_CASE_01_MAC)
            await pilot.pause()
            app._apply_unload("primary")
            await pilot.pause()
            mm = app.query_one("#memory_map_panel", MemoryMapPanel)
            return app.current_file, _detail_texts(app), mm.rendered_text

    current, slots, map_text = asyncio.run(_drive())
    assert current is not None
    assert current.file_type == "mac"
    assert current.ranges == []
    assert map_text == MemoryMapPanel._EMPTY_TEXT
    assert slots[0] == "(none)"
    assert slots[1].startswith("firmware.mac")


def test_ac3_unload_all_clears_snapshot_and_every_slot(tmp_path: Path) -> None:
    """AC-3 (through the surface): load the trio through the real loader, then
    unload everything. ``current_file`` clears to ``None`` and all three Loaded
    slots read ``(none)`` — the state reached through every renderer's no-file
    branch without raising (the drive completing is itself the no-raise proof)."""

    async def _drive() -> tuple[object, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.load_selected_file(_CASE_01_S19, a2l_files=[_CASE_01_A2L])
            await pilot.pause()
            app.load_selected_file(_CASE_01_MAC)
            await pilot.pause()
            app._apply_unload("all")
            await pilot.pause()
            return app.current_file, _detail_texts(app)

    current, slots = asyncio.run(_drive())
    assert current is None
    assert slots == ["(none)", "(none)", "(none)"]


def test_ac4_slots_track_each_sequential_unload(tmp_path: Path) -> None:
    """AC-4 (through the surface): after loading the trio all three slots read
    their file names; unloading the MAC flips only the MAC slot; unloading the
    A2L then flips only the A2L slot — the S19 slot stays present throughout.
    Drives the real loader and snapshots the Loaded panel at each step."""

    async def _drive() -> dict[str, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        steps: dict[str, list[str]] = {}
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.load_selected_file(_CASE_01_S19, a2l_files=[_CASE_01_A2L])
            await pilot.pause()
            app.load_selected_file(_CASE_01_MAC)
            await pilot.pause()
            steps["loaded"] = _detail_texts(app)
            app._apply_unload("mac")
            await pilot.pause()
            steps["no_mac"] = _detail_texts(app)
            app._apply_unload("a2l")
            await pilot.pause()
            steps["no_a2l"] = _detail_texts(app)
        return steps

    steps = asyncio.run(_drive())
    prim, mac, a2l = steps["loaded"]
    assert prim.startswith("firmware.s19")
    assert mac.startswith("firmware.mac")
    assert a2l.startswith("firmware.a2l")
    prim, mac, a2l = steps["no_mac"]
    assert prim.startswith("firmware.s19")
    assert mac == "(none)"
    assert a2l.startswith("firmware.a2l")
    prim, mac, a2l = steps["no_a2l"]
    assert prim.startswith("firmware.s19")
    assert mac == "(none)"
    assert a2l == "(none)"


def test_ac5_reload_mac_after_unload_is_reversible(tmp_path: Path) -> None:
    """AC-5 (reversibility, through the surface): load the trio, unload the MAC,
    then RELOAD the MAC through the same real loader (``load_selected_file`` →
    ``_merge_mac_with_existing_primary``). ``mac_records`` / ``mac_path`` are
    restored and the Loaded panel's MAC slot returns — no residual unload state
    blocks the re-merge. The image spine is unaffected by the round-trip."""

    async def _drive() -> tuple[list[str], object, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.load_selected_file(_CASE_01_S19, a2l_files=[_CASE_01_A2L])
            await pilot.pause()
            app.load_selected_file(_CASE_01_MAC)
            await pilot.pause()
            app._apply_unload("mac")
            await pilot.pause()
            after_unload = _detail_texts(app)
            app.load_selected_file(_CASE_01_MAC)
            await pilot.pause()
            return after_unload, app.current_file, _detail_texts(app)

    after_unload, current, slots = asyncio.run(_drive())
    # The MAC was genuinely gone before the reload.
    assert after_unload[1] == "(none)"
    assert current is not None
    assert current.mac_records  # records restored by the re-merge
    assert current.mac_path is not None
    assert current.mac_path.name == "firmware.mac"
    assert slots[1].startswith("firmware.mac")
    # Image spine untouched by the unload/reload round-trip.
    assert current.file_type in {"s19", "hex"}
    assert slots[0].startswith("firmware.s19")
