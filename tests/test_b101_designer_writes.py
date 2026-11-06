"""Batch-101 increment 5 - the CRC Designer's coverage follows bytes written
into the loaded image in place (US-CRC-FRESH-2, canon S13 CTX-DESIGNER).

Written by the independent tester (E4, tester 1) from the approved design only
(``inc-5/01-requirements.md``, ``02-test-cases.md``, ``E1-rulings.md``,
``E3-rulings.md``, ``codewire/graph-inc5.md`` and the E1 pilot). No line of the
Inc 5 implementation was read.

Requirement rows covered: R-CRC-PREVIEW-002.1 (case /6) and
R-CRC-PREVIEW-002.5 (cases /3 ... /8), plus the amended S13 definition *loaded
image changes* (it is the sentence those rows exercise: a Patch Editor apply
ending with its ``Apply:`` status or with a ``Patch Editor: <error>`` status, a
save-back whatever its outcome, a Save project commit that writes the image).

The oracle is ``zlib.crc32`` of the post-write bytes of
``app.current_file.mem_map`` over the fixture ranges, compared with the text
the CRC Designer paints (``#crc_coverage_preview`` and line 2 of
``#crc_coverage_window``). Every case also pins the literal values the case
text states, so a wrong constant here fails loudly on the first GREEN run.

Drive: rail keys (``0``, ``1``, ``6``), the Load file dialog, the typed change
document path, the Patch Editor buttons, the Save project dialog (``ctrl+s``)
and the save-back row. Two seams, both declared on the case:
  - /6 injects a fault (``apply_change_document`` wrapped to raise after it
    wrote) - the node is *partial*;
  - the display used by a setup step is made fresh with an operator edit of the
    Ranges field (a spelling change of the same coverage), which recomputes on
    the base tree and on the fixed tree alike, so that a setup never depends on
    the behaviour under test and the node fails at the case's own assertion.

Waits: the suite's ``wait_until`` / ``wait_designer_recompute`` (yielding,
``pause_first``) and the dialog helpers; a count that must NOT move is read
after several short pauses, never after one.

Base (``c2cba35``): every node of the cases fails there on the stale CRC (the
designer keeps the pre-write value, or the recompute never comes). The two
integrity nodes at the end pass on the base by design (they pin the oracle
constants and the "other actions do not mark the coverage stale" boundary).
"""
from __future__ import annotations

import asyncio
import json
import zlib
from pathlib import Path
from typing import List, Tuple

import pytest
from textual.widgets import Button, Input, Static

import s19_app.tui.services.change_service as change_service_module
from s19_app.tui import crc_designer_view
from tests.support import b100_load_dialog as ld
from tests.support import b100_projects as projects
from tests.support import b100_save_dialog as sd
from tests.support.b100_workers import settle_workers
from tests.support.b101_designer import (  # noqa: F401  (the fixture is used by name)
    designer_pending,
    designer_recompute_counter,
    designer_recomputes,
    wait_designer_recompute,
)
from tests.support.timing import wait_until
from tests.test_b101_check_spec_keep import (  # E5 C-10: the Check Editor drivers
    HINT,
    card,
    click_on,
    type_into,
    validate_by_click,
)

pytestmark = pytest.mark.usefixtures("designer_recompute_counter")

REPS = 3  # the "3/3" of the requirement thresholds: three fresh apps per limb
QUIET_SHORT_S = 0.05  # Q of the cases that wait for a recompute
QUIET_LONG_S = 10.0  # Q of the case that reads "not before the quiet time"
RECOMPUTE_TIMEOUT_S = 20.0  # a recompute that never comes fails here, loudly
SIZE = (160, 54)

# The fixture image: 0x8000-0x8007 = 00..07, 0x8010-0x8017 = 10..17.
RANGES_A = "0x00008000-0x00008008, 0x00008010-0x00008018"
RANGES_B = "0x00008000-0x00008008,0x00008010-0x00008018"

# (concat, fill) per image state, as the cases state them.
PRE = (0x9C5BCBBD, 0x2A8A3950)  # the image as loaded
AFTER_AA = (0x08DAAFB7, 0x35D90BC3)  # 0x8003 = AA
AFTER_BB = (0x614BD0E8, 0xE1E79AB1)  # 0x8003 = BB


# ---------------------------------------------------------------------------
# Oracle
# ---------------------------------------------------------------------------
def _range_bytes(mem: dict) -> Tuple[bytes, bytes]:
    low = bytes(mem[a] for a in range(0x8000, 0x8008))
    high = bytes(mem[a] for a in range(0x8010, 0x8018))
    return low, high


def oracle(mem: dict) -> Tuple[int, int]:
    """(concat, fill) = zlib.crc32 of the 16 range bytes of ``mem`` (fill:
    the erased gap padded with 0xFF)."""
    low, high = _range_bytes(mem)
    return zlib.crc32(low + high), zlib.crc32(low + b"\xff" * 8 + high)


def _fixture_mem() -> dict:
    mem = {0x8000 + i: i for i in range(8)}
    mem.update({0x8010 + i: 0x10 + i for i in range(8)})
    return mem


def _with(**patch: int) -> dict:
    mem = _fixture_mem()
    for key, value in patch.items():
        mem[int(key[1:], 16)] = value
    return mem


def _s1(address: int, data: bytes) -> str:
    body = bytes([len(data) + 3, address >> 8, address & 0xFF]) + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def write_fixture_image(path: Path) -> None:
    lines = [
        "S0030000FC",
        _s1(0x8000, bytes(range(8))),
        _s1(0x8010, bytes(range(0x10, 0x18))),
        "S9030000FC",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def write_change_document(path: Path, entries: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )


AA_ENTRY = {"type": "bytes", "address": "0x8003", "bytes": "AA"}


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------
def _preview_text(app) -> str:
    return str(app.query_one("#crc_coverage_preview", Static).content)


def _preview_lines(app) -> List[str]:
    return _preview_text(app).split("\n")


def _window_lines(app) -> List[str]:
    return str(app.query_one("#crc_coverage_window", Static).render()).split("\n")


def _preview_for(pair: Tuple[int, int]) -> List[str]:
    return [
        "Active policy: join=concat",
        f"concat: 0x{pair[0]:08X}",
        f"fill:   0x{pair[1]:08X}",
    ]


def _set_quiet(monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
    monkeypatch.setattr(crc_designer_view, "CRC_RECOMPUTE_S", seconds, raising=False)


async def _quiet(pilot, rounds: int = 5) -> None:
    """Several short pauses (a count that must not move is read after these,
    never after one)."""
    for _ in range(rounds):
        await pilot.pause(0.1)


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------
async def _load_image_by_dialog(pilot, app, path: Path) -> None:
    """``l``, type the path, click Load (layout settled first), as the operator."""
    await pilot.press("l")
    await ld.wait_for_dialog(pilot, app)
    await wait_until(
        pilot,
        lambda: len(app.screen.query("#load_path")) > 0
        and app.screen.query_one("#load_path").region.width > 0,
        "timed out waiting for the Load dialog layout",
    )
    for _ in range(4):
        await pilot.pause()
    await ld.type_into_path(pilot, app, str(path))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await wait_until(
        pilot,
        lambda: not ld.is_load_dialog(app.screen)
        and app.current_file is not None
        and app.current_file.path.name == path.name,
        f"timed out waiting for the load of {path.name}",
    )
    await settle_workers(pilot)


async def _press_rail(pilot, app, key: str) -> None:
    """A rail key. Focus is released first, as a click on empty space does:
    a rail digit pressed with a text field focused would be typed into it."""
    app.screen.set_focus(None)
    await pilot.pause()
    await pilot.press(key)


async def _show_rail(pilot, app, key: str, widget_id: str) -> None:
    if not (len(app.query(widget_id)) > 0 and app.query_one(widget_id).region.width > 0):
        await _press_rail(pilot, app, key)
    await wait_until(
        pilot,
        lambda: len(app.query(widget_id)) > 0 and app.query_one(widget_id).region.width > 0,
        f"timed out waiting for {widget_id} after key {key!r}",
    )
    for _ in range(3):
        await pilot.pause()


async def _type_into(pilot, app, input_id: str, text: str) -> None:
    """Focus the input by a click, empty it with keys, type ``text`` key by key."""
    field = app.query_one(input_id, Input)
    assert await pilot.click(input_id), f"click missed {input_id}"
    await pilot.press("end", *(["backspace"] * len(field.value)))
    if text:
        await pilot.press(*("space" if ch == " " else ch for ch in text))
    assert field.value == text, (input_id, field.value, text)


async def _status_since(pilot, log, mark: int, predicate, what: str) -> List[str]:
    await wait_until(
        pilot,
        lambda: any(predicate(m) for m in log.since(mark)),
        lambda: f"timed out waiting for {what}; status lines: {log.since(mark)!r}",
    )
    return log.since(mark)


async def _fresh_designer_display(pilot, app, expect: Tuple[int, int]) -> None:
    """Show the CRC Designer (key ``0``) and make its coverage fresh by an
    operator edit of Ranges (a spelling change of the same coverage), which
    recomputes whatever the in-place-write behaviour is; then check the
    precondition ``expect``. A setup, not the behaviour under test."""
    before = designer_recomputes()
    await _press_rail(pilot, app, "0")
    await wait_until(
        pilot,
        lambda: len(app.query("#crc_coverage_ranges")) > 0
        and app.query_one("#crc_coverage_ranges").region.width > 0,
        "timed out waiting for the CRC Designer",
    )
    field = app.query_one("#crc_coverage_ranges", Input)
    field.value = RANGES_B if field.value == RANGES_A else RANGES_A
    await wait_designer_recompute(pilot, app, before, timeout=RECOMPUTE_TIMEOUT_S)
    assert _preview_lines(app) == _preview_for(expect), (
        f"setup: the CRC Designer paints {_preview_text(app)!r}, expected {_preview_for(expect)!r}"
    )


async def _first_display(pilot, app, expect: Tuple[int, int]) -> None:
    """The natural first display of a clean CRC Designer (key ``0``, wait for
    the recompute, check ``expect``)."""
    before = designer_recomputes()
    await _press_rail(pilot, app, "0")
    await wait_designer_recompute(pilot, app, before, timeout=RECOMPUTE_TIMEOUT_S)
    assert _preview_lines(app) == _preview_for(expect), (
        f"setup: the CRC Designer paints {_preview_text(app)!r}, expected {_preview_for(expect)!r}"
    )


async def _load_document(pilot, app, log, base: Path, name: str, entries: List[dict]) -> None:
    """Key ``6``; the document's path typed into the path field; Load clicked."""
    document = app._patches_dir() / name
    write_change_document(document, entries)
    await _show_rail(pilot, app, "6", "#patch_doc_path_input")
    await _type_into(pilot, app, "#patch_doc_path_input", str(document))
    assert await pilot.click("#patch_doc_load_button"), "click missed #patch_doc_load_button"
    await wait_until(
        pilot,
        lambda: app._change_service.document.source_path is not None
        and len(app._change_service.document.entries) == len(entries),
        lambda: f"timed out waiting for the document load; status: {log.messages[-3:]!r}",
    )
    for _ in range(3):
        await pilot.pause()


async def _apply(pilot, app, log, expect_prefix: str) -> str:
    mark = len(log.messages)
    assert await pilot.click("#patch_doc_apply_button"), "click missed #patch_doc_apply_button"
    lines = await _status_since(
        pilot, log, mark, lambda m: m.startswith(expect_prefix), f"a status starting {expect_prefix!r}"
    )
    for _ in range(3):
        await pilot.pause()
    return next(m for m in lines if m.startswith(expect_prefix))


async def _entry_op(pilot, app, log, button: str, address: str, data: str, status: str) -> None:
    await _show_rail(pilot, app, "6", "#patch_entry_address_input")
    mark = len(log.messages)
    await _type_into(pilot, app, "#patch_entry_address_input", address)
    await _type_into(pilot, app, "#patch_entry_bytes_input", data)
    assert await pilot.click(button), f"click missed {button}"
    await _status_since(pilot, log, mark, lambda m: m == status, f"the status {status!r}")


async def _save_back(pilot, app, log, name: str, expect: str) -> List[str]:
    """Show the save-back row (JSON tab), type ``name`` into it, confirm, and
    wait for a status containing ``expect``. The confirm is a press of the
    shipped button (the row sits in the JSON pane below the clip of the
    status bar at this size; the suite's save-back drives press it too)."""
    assert await pilot.click("#patch_tab_json"), "click missed #patch_tab_json"
    await wait_until(
        pilot,
        lambda: app.query_one("#patch_saveback_confirm_button").region.width > 0,
        "timed out waiting for the save-back row",
    )
    field = app.query_one("#patch_saveback_name_input", Input)
    if field.value != name:
        assert await pilot.click("#patch_saveback_name_input"), "click missed the save-back name"
        await pilot.press("end", *(["backspace"] * len(field.value)))
        await pilot.press(*name)
    assert field.value == name, field.value
    mark = len(log.messages)
    app.query_one("#patch_saveback_confirm_button", Button).press()
    lines = await _status_since(pilot, log, mark, lambda m: expect in m, f"a save-back status with {expect!r}")
    for _ in range(3):
        await pilot.pause()
    return lines


async def _save_project(pilot, app, log, name: str = "P") -> None:
    """``ctrl+s``, the Save project dialog confirmed; wait for the commit line."""
    mark = len(log.messages)
    await sd.save_through_dialog(pilot, app, name)
    await _status_since(
        pilot, log, mark, lambda m: m.startswith("Saved project to"), "the Save project commit line"
    )
    await settle_workers(pilot)


async def _open_project(pilot, app, log, name: str = "P") -> None:
    """A project holding the loaded fixture image, open: the image is saved
    as project ``name`` (shipped handler) and the project opened."""
    await projects.save_project(pilot, app, log, name)
    if app.current_project != name:
        await projects.load_project(pilot, app, name)
    assert app.current_project == name, app.current_project


async def _expect_refresh(pilot, app, before: int, expect: Tuple[int, int], what: str) -> None:
    """After the display that follows an in-place write: exactly one recompute,
    the painted CRCs equal ``zlib.crc32`` of the session bytes and the literal
    values the case states, and window line 2 says the same."""
    try:
        await wait_designer_recompute(pilot, app, before, timeout=RECOMPUTE_TIMEOUT_S)
    except AssertionError as exc:
        raise AssertionError(
            f"{what}: the CRC Designer never recomputed (count {designer_recomputes()}, "
            f"snapshot {before}) - stale coverage; it paints {_preview_lines(app)[1:]!r}, "
            f"the session bytes give concat 0x{oracle(app.current_file.mem_map)[0]:08X}"
        ) from exc
    await _quiet(pilot, 4)
    assert designer_recomputes() - before == 1, (
        f"{what}: expected exactly 1 recompute, got {designer_recomputes() - before}"
    )
    concat, fill = oracle(app.current_file.mem_map)
    assert (concat, fill) == expect, (
        f"{what}: the session bytes give 0x{concat:08X}/0x{fill:08X}, the case states "
        f"0x{expect[0]:08X}/0x{expect[1]:08X}"
    )
    assert _preview_lines(app) == _preview_for((concat, fill)), (
        f"{what}: the CRC Designer paints {_preview_lines(app)!r}, zlib.crc32 of the session "
        f"bytes is concat 0x{concat:08X} fill 0x{fill:08X}"
    )
    assert _window_lines(app)[1] == f"concat 0x{concat:08X}   fill 0x{fill:08X}", _window_lines(app)


def _run(base: Path, scenario):
    return projects.run_app(base, scenario, size=SIZE)


def _reps(tmp_path: Path, make_scenario):
    """The 3/3 of the thresholds: three fresh apps, each in its own folder."""
    results = []
    for rep in range(REPS):
        folder = tmp_path / f"rep{rep}"
        base = folder / "app"
        base.mkdir(parents=True)
        image = folder / "fixture.s19"
        write_fixture_image(image)
        results.append(_run(base, make_scenario(folder, image)))
    return results


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.5/3 - apply, then the first display
# ---------------------------------------------------------------------------
def test_r_crc_preview_002_5_3_apply_then_display(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies R-CRC-PREVIEW-002.5/3 (and the S13 *loaded image changes*
    sentence for a Patch Editor apply): the CRC Designer, not displayed during
    the apply of one ``bytes`` entry ``0x8003`` = ``AA``, shows on its first
    display afterwards the CRCs of the applied bytes.

    Why: the operator copies the painted CRC into a release record; a stale
    pre-apply value is a wrong checksum (SEC-3). Observable: 0 recomputes
    before key ``0``, exactly 1 after, concat/fill equal to ``zlib.crc32`` of
    the post-apply session bytes. Base: ``concat: 0x9C5BCBBD`` stays and no
    recompute comes (pilot D4) -> RED. Negative controls: hook absent ->
    RED; hook recomputing while hidden -> 1 recompute before key ``0`` -> RED."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _first_display(pilot, app, PRE)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            before = designer_recomputes()  # E5 C-3: before the trigger
            status = await _apply(pilot, app, log, "Apply:")
            assert status == "Apply: 1 applied, 0 skipped, 0 blocked", status
            assert app.current_file.mem_map[0x8003] == 0xAA
            await _quiet(pilot)
            assert designer_recomputes() == before, "a hidden CRC Designer recomputed"
            await _press_rail(pilot, app, "0")
            await _expect_refresh(pilot, app, before, AFTER_AA, "apply then display")

        return scenario

    _reps(tmp_path, make)


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.5/4 - save-back, then the first display
# ---------------------------------------------------------------------------
def test_r_crc_preview_002_5_4_save_back_then_display(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies R-CRC-PREVIEW-002.5/4: after the apply of ``AA`` and one display
    (``0x08DAAFB7``), the entry edited to ``BB`` (no new apply) and *Save patched
    image as* ``fixture-patched.s19`` confirmed, the first display afterwards
    shows the CRCs of the saved-back bytes (``0x614BD0E8`` / ``0xE1E79AB1``).

    Why: the save-back re-derives the image and writes the BB into the session
    map in place; the earlier painted value (AA) is then wrong. Base: the
    designer keeps ``0x08DAAFB7`` -> RED. Observable: 0 recomputes before key
    ``0``, exactly 1 after, painted = ``zlib.crc32`` of the session bytes."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            assert await _apply(pilot, app, log, "Apply:") == "Apply: 1 applied, 0 skipped, 0 blocked"
            await _fresh_designer_display(pilot, app, AFTER_AA)
            await _entry_op(
                pilot, app, log, "#patch_entry_edit_button", "0x8003", "BB", "Patch Editor: entry updated."
            )
            before = designer_recomputes()  # E5 C-3: before the trigger
            await _save_back(pilot, app, log, "fixture-patched.s19", "Saved + verified")
            assert list((folder / "app").rglob("fixture-patched.s19")), "the save-back wrote no file"
            assert app.current_file.mem_map[0x8003] == 0xBB
            await _quiet(pilot)
            assert designer_recomputes() == before, "a hidden CRC Designer recomputed"
            await _press_rail(pilot, app, "0")
            await _expect_refresh(pilot, app, before, AFTER_BB, "save-back then display")

        return scenario

    _reps(tmp_path, make)


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.5/5 - Save project commit made elsewhere, then the display
# ---------------------------------------------------------------------------
def test_r_crc_preview_002_5_5_save_project_then_display(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies R-CRC-PREVIEW-002.5/5: in an open project, after the apply of
    ``AA``, a display (``0x08DAAFB7``) and the entry edited to ``BB``, a Save
    project commit made while the CRC Designer is hidden (key ``1``) leaves 0
    recomputes until key ``0``; then exactly 1, with ``0x614BD0E8`` /
    ``0xE1E79AB1``.

    Why: the commit re-derives the image and writes BB in place; the painted AA
    value is stale. Base: the designer keeps ``0x08DAAFB7`` -> RED."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _open_project(pilot, app, log)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            assert await _apply(pilot, app, log, "Apply:") == "Apply: 1 applied, 0 skipped, 0 blocked"
            await _fresh_designer_display(pilot, app, AFTER_AA)
            await _entry_op(
                pilot, app, log, "#patch_entry_edit_button", "0x8003", "BB", "Patch Editor: entry updated."
            )
            await _show_rail(pilot, app, "1", "#loaded_slots")
            before = designer_recomputes()
            await _save_project(pilot, app, log)
            assert app.current_file.mem_map[0x8003] == 0xBB, "the commit did not write the BB"
            await _quiet(pilot)
            assert designer_recomputes() == before, "a hidden CRC Designer recomputed"
            await _press_rail(pilot, app, "0")
            await _expect_refresh(pilot, app, before, AFTER_BB, "Save project then display")

        return scenario

    _reps(tmp_path, make)


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.5/6 - an apply that ends with an error status after it wrote
# ---------------------------------------------------------------------------
def test_r_crc_preview_002_5_6_apply_error_still_refreshes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies R-CRC-PREVIEW-002.5/6 (partial: the fault is injected): an apply
    that ends ``Patch Editor: 'probe'`` after the engine wrote ``AA`` still makes
    the coverage stale; the first display afterwards shows ``0x08DAAFB7`` /
    ``0x35D90BC3``, 1 recompute.

    Why: ``ChangeService.apply`` restores and writes in place before the engine
    can raise; an error status does not mean 'nothing written'. Base: the
    designer keeps ``0x9C5BCBBD`` -> RED. Negative control: the hook in the
    success branch only -> RED."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)
    original = change_service_module.apply_change_document

    def wrote_then_failed(*args, **kwargs):
        original(*args, **kwargs)
        raise KeyError("probe")

    monkeypatch.setattr(change_service_module, "apply_change_document", wrote_then_failed)

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _first_display(pilot, app, PRE)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            before = designer_recomputes()  # E5 C-3: before the trigger
            status = await _apply(pilot, app, log, "Patch Editor:")
            assert status == "Patch Editor: 'probe'", status
            assert app.current_file.mem_map[0x8003] == 0xAA, "the engine wrote nothing before it raised"
            await _quiet(pilot)
            assert designer_recomputes() == before, "a hidden CRC Designer recomputed"
            await _press_rail(pilot, app, "0")
            await _expect_refresh(pilot, app, before, AFTER_AA, "apply error then display")

        return scenario

    _reps(tmp_path, make)


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.5/7 - a save-back refused as blocked still reverted the image
# ---------------------------------------------------------------------------
def test_r_crc_preview_002_5_7_blocked_save_back_still_refreshes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies R-CRC-PREVIEW-002.5/7 (E3 SEC5-2): after the apply of ``AA`` and
    one display (``0x08DAAFB7``), a second entry ``0x8002`` = ``11 22`` (it
    overlaps ``0x8003``) and *Save patched image as* ``fixture-blocked.s19``
    confirmed, the save ends ``Patched image not saved - 2 entries blocked - see
    issues``, writes no file, and leaves ``0x8002`` / ``0x8003`` at ``02`` /
    ``03``; the first display afterwards shows ``0x9C5BCBBD`` / ``0x2A8A3950``.

    Why: the refused save-back has already adopted the re-derived bytes (the
    revert), so a hook gated on the save's ``ok`` leaves the designer painting
    the AA value of an image that no longer holds it. Base: the designer keeps
    ``0x08DAAFB7`` -> RED. Negative control: hook under ``if result.ok`` -> RED."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            assert await _apply(pilot, app, log, "Apply:") == "Apply: 1 applied, 0 skipped, 0 blocked"
            await _fresh_designer_display(pilot, app, AFTER_AA)
            await _entry_op(
                pilot, app, log, "#patch_entry_add_button", "0x8002", "11 22", "Patch Editor: entry added."
            )
            before = designer_recomputes()  # E5 C-3: before the trigger
            lines = await _save_back(
                pilot,
                app,
                log,
                "fixture-blocked.s19",
                "Patched image not saved - 2 entries blocked - see issues",
            )
            assert any(m == "Patched image not saved - 2 entries blocked - see issues" for m in lines), lines
            await _quiet(pilot, 3)
            assert not list((folder / "app").rglob("fixture-blocked.s19")), "a blocked save-back wrote a file"
            mem = app.current_file.mem_map
            assert (mem[0x8002], mem[0x8003]) == (0x02, 0x03), (mem[0x8002], mem[0x8003])
            await _quiet(pilot)
            assert designer_recomputes() == before, "a hidden CRC Designer recomputed"
            await _press_rail(pilot, app, "0")
            await _expect_refresh(pilot, app, before, PRE, "blocked save-back then display")

        return scenario

    _reps(tmp_path, make)


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.5/8 - an apply with 0 applied that restores an earlier apply
# ---------------------------------------------------------------------------
def test_r_crc_preview_002_5_8_zero_applied_restore_still_refreshes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies R-CRC-PREVIEW-002.5/8 (E3 A-2): after the apply of ``AA`` and one
    display (``0x08DAAFB7``), the entry moved to ``0x9000`` (outside the image)
    and Apply pressed, the status is ``Apply: 0 applied, 1 skipped, 0 blocked``,
    ``0x8003`` is back at ``03`` (the apply's journal restore), and the first
    display afterwards shows ``0x9C5BCBBD`` / ``0x2A8A3950``.

    Why: an apply that applies nothing has still undone the earlier apply in
    place. Base: the designer keeps ``0x08DAAFB7`` -> RED. Negative control: the
    hook gated on ``applied > 0`` -> RED. Drive note: the entry editor changes
    an entry by its address, so 'the address edited' is the Remove of the
    ``0x8003`` entry and the Add of ``0x9000`` = ``AA`` (same document)."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            assert await _apply(pilot, app, log, "Apply:") == "Apply: 1 applied, 0 skipped, 0 blocked"
            await _fresh_designer_display(pilot, app, AFTER_AA)
            await _entry_op(
                pilot, app, log, "#patch_entry_remove_button", "0x8003", "", "Patch Editor: entry removed."
            )
            await _entry_op(
                pilot, app, log, "#patch_entry_add_button", "0x9000", "AA", "Patch Editor: entry added."
            )
            before = designer_recomputes()  # E5 C-3: before the trigger
            status = await _apply(pilot, app, log, "Apply:")
            assert status == "Apply: 0 applied, 1 skipped, 0 blocked", status
            assert app.current_file.mem_map[0x8003] == 0x03, "the journal restore did not run"
            await _quiet(pilot)
            assert designer_recomputes() == before, "a hidden CRC Designer recomputed"
            await _press_rail(pilot, app, "0")
            await _expect_refresh(pilot, app, before, PRE, "zero-applied apply then display")

        return scenario

    _reps(tmp_path, make)


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.1/6 - a Save project commit while the CRC Designer is displayed
# ---------------------------------------------------------------------------
def _commit_while_displayed(folder: Path, image: Path, quiet_after: float, wait_for_recompute: bool):
    async def scenario(app, pilot, log):
        await _load_image_by_dialog(pilot, app, image)
        await _open_project(pilot, app, log)
        await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
        assert await _apply(pilot, app, log, "Apply:") == "Apply: 1 applied, 0 skipped, 0 blocked"
        await _entry_op(
            pilot, app, log, "#patch_entry_edit_button", "0x8003", "BB", "Patch Editor: entry updated."
        )
        await _fresh_designer_display(pilot, app, AFTER_AA)
        crc_designer_view.CRC_RECOMPUTE_S = quiet_after  # restored by the test's monkeypatch
        before = designer_recomputes()
        await _save_project(pilot, app, log)
        assert app.current_file.mem_map[0x8003] == 0xBB, "the commit did not write the BB"
        if wait_for_recompute:
            await _expect_refresh(pilot, app, before, AFTER_BB, "Save project commit while displayed")
        else:
            await _quiet(pilot, 2)
            return designer_recomputes() - before, designer_pending(app) is not None, _preview_lines(app)

    return scenario


def test_r_crc_preview_002_1_6_save_project_commit_while_displayed_schedules_a_recompute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies R-CRC-PREVIEW-002.1/6 limb (a) (and the S13 *loaded image
    changes* sentence for a Save project commit): a Save project commit that
    writes the image while the CRC Designer is displayed is a pending change of
    the designer. Q = 10 s: after the commit (the real ``ctrl+s`` dialog) and
    two pauses the recompute count is unchanged and a recompute is pending (it
    was scheduled, it has not run). 3/3.

    Why: the displayed designer must be told at once, but must not recompute
    inside the quiet time. Base: no recompute is pending (the designer was
    never told) -> RED. Negative control: a hook that recomputes synchronously
    -> count +1 -> RED."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)
    for rep in range(REPS):
        folder = tmp_path / f"a{rep}"
        (folder / "app").mkdir(parents=True)
        image = folder / "fixture.s19"
        write_fixture_image(image)
        delta, pending, lines = _run(folder / "app", _commit_while_displayed(folder, image, QUIET_LONG_S, False))
        assert delta == 0, f"the quiet time of 10 s had not elapsed, yet {delta} recompute(s) ran"
        assert pending, (
            f"no recompute is pending after the Save project commit: the designer was not told; "
            f"it paints {lines[1:]!r}"
        )
        _set_quiet(monkeypatch, QUIET_SHORT_S)


def test_r_crc_preview_002_1_6_save_project_commit_while_displayed_recomputes_after_the_quiet_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies R-CRC-PREVIEW-002.1/6 limb (b): Q = 0.05 s, the same commit:
    exactly 1 more recompute, then the preview is exactly ``Active policy:
    join=concat`` / ``concat: 0x614BD0E8`` / ``fill:   0xE1E79AB1`` = ``zlib.crc32``
    of the 16 range bytes of the session map after the commit; window line 2
    says the same. 3/3.

    Base: the preview keeps ``0x08DAAFB7`` and the wait for the recompute times
    out -> RED."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)
    for rep in range(REPS):
        folder = tmp_path / f"b{rep}"
        (folder / "app").mkdir(parents=True)
        image = folder / "fixture.s19"
        write_fixture_image(image)
        _run(folder / "app", _commit_while_displayed(folder, image, QUIET_SHORT_S, True))


# ---------------------------------------------------------------------------
# Integrity nodes (pass on the base by design)
# ---------------------------------------------------------------------------
def test_oracle_constants_are_the_crc32_of_the_stated_byte_states() -> None:
    """Fixture integrity for R-CRC-PREVIEW-002.1/6 and -002.5/3 ... /8: the
    literal CRCs of the cases are ``zlib.crc32`` of the fixture bytes with
    ``0x8003`` = 03 (as loaded), AA and BB. A wrong constant here would turn
    every other node's literal pin into a false RED; this node would fail first."""
    assert oracle(_fixture_mem()) == PRE
    assert oracle(_with(x8003=0xAA)) == AFTER_AA
    assert oracle(_with(x8003=0xBB)) == AFTER_BB


def test_control_other_patch_actions_do_not_mark_the_coverage_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Boundary control for R-CRC-PREVIEW-002.5 (graph: 'any other action, e.g.
    add_entry -> no notice'): adding an entry to the document without applying
    it writes no byte, so the next display of a clean CRC Designer recomputes
    nothing and still paints the loaded image's CRCs.

    Why: a hook placed on every Patch Editor action (or on a stale flag that is
    never cleared) would recompute on every visit and could hide the real
    defect behind noise. Passes on the base and must stay green with the fix;
    it is not a RED-on-base node."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _first_display(pilot, app, PRE)
            await _entry_op(
                pilot, app, log, "#patch_entry_add_button", "0x8003", "AA", "Patch Editor: entry added."
            )
            before = designer_recomputes()
            await _press_rail(pilot, app, "0")
            await _quiet(pilot, 6)
            assert designer_recomputes() == before, "an unapplied entry made the coverage stale"
            assert _preview_lines(app) == _preview_for(PRE), _preview_lines(app)
            assert app.current_file.mem_map[0x8003] == 0x03

        return scenario

    _reps(tmp_path, make)


# ---------------------------------------------------------------------------
# E5 corrective additions (rulings C-4, C-6, C-10 of inc-5/E5-rulings.md),
# written by the corrective pass.
# ---------------------------------------------------------------------------


async def _validate_a_session_row(pilot, app, log) -> tuple:
    """Key ``=``; a memory row ``0x8003`` size 1 typed and Add clicked;
    Validate clicked; return ``(status lines, card)``."""
    await _show_rail(pilot, app, "equals_sign", "#check_validate_button")
    await type_into(pilot, app, "#check_mem_address_input", "0x8003")
    await type_into(pilot, app, "#check_mem_size_input", "1")
    await click_on(pilot, app, "#check_mem_add_button")
    await wait_until(
        pilot,
        lambda: len(app.query_one("#check_editor_panel")._memory_rows) == 1,
        "timed out waiting for the memory row 0x8003",
    )
    return await validate_by_click(pilot, app, log)


async def _card_after_return(pilot, app) -> tuple:
    """Key ``=`` and the Check Editor's Fields card as painted."""
    await _show_rail(pilot, app, "equals_sign", "#check_validate_button")
    await _quiet(pilot, 3)
    return card(app)


def _assert_cleared(first, after, row: str) -> None:
    lines, (status, rows) = first
    assert "Checks: 1 passed, 0 failed, 0 uncheckable" in lines, lines
    assert status == "validation complete" and rows == [row], (status, rows)
    assert after == (HINT, []), f"stale validation results after the write: {after!r}"


# ---------------------------------------------------------------------------
# R-CHKED-057/2, /3 - a save-back or a Save project commit clears the
# Check Editor's validation results (E5 C-10)
# ---------------------------------------------------------------------------
def test_r_chked_057_2_save_back_clears_the_validation_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Case R-CHKED-057/2: the fixture image, ``0x8003`` applied as ``AA``, a
    memory row ``0x8003`` size 1 added and Validate clicked (``0x8003-0x8003
    expected [AA] actual [AA] -> pass``); the entry edited to ``BB`` and *Save
    patched image as* confirmed -> key ``=``: 0 verdict rows and the status
    line ``Validate compares fields to the image``.

    Base: the ``-> pass`` row under ``validation complete`` stays -> RED.
    Negative control: the hook not telling the Check Editor -> RED (M29)."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)
    seen = []

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            assert await _apply(pilot, app, log, "Apply:") == "Apply: 1 applied, 0 skipped, 0 blocked"
            first = await _validate_a_session_row(pilot, app, log)
            await _entry_op(
                pilot, app, log, "#patch_entry_edit_button", "0x8003", "BB", "Patch Editor: entry updated."
            )
            await _save_back(pilot, app, log, "fixture-patched.s19", "Saved + verified")
            assert app.current_file.mem_map[0x8003] == 0xBB
            seen.append((first, await _card_after_return(pilot, app)))

        return scenario

    _reps(tmp_path, make)
    for first, after in seen:
        _assert_cleared(first, after, "0x8003-0x8003 expected [AA] actual [AA] -> pass")


def test_r_chked_057_3_save_project_commit_clears_the_validation_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Case R-CHKED-057/3: as /2 inside an open project, then a Save project
    commit by ``ctrl+s`` instead of the save-back -> key ``=``: 0 verdict rows
    and the status line ``Validate compares fields to the image``.

    Base: the stale ``-> pass`` row stays -> RED. Negative control: M29."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)
    seen = []

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _open_project(pilot, app, log)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            assert await _apply(pilot, app, log, "Apply:") == "Apply: 1 applied, 0 skipped, 0 blocked"
            first = await _validate_a_session_row(pilot, app, log)
            await _entry_op(
                pilot, app, log, "#patch_entry_edit_button", "0x8003", "BB", "Patch Editor: entry updated."
            )
            await _show_rail(pilot, app, "1", "#loaded_slots")
            await _save_project(pilot, app, log)
            assert app.current_file.mem_map[0x8003] == 0xBB, "the commit did not write the BB"
            seen.append((first, await _card_after_return(pilot, app)))

        return scenario

    _reps(tmp_path, make)
    for first, after in seen:
        _assert_cleared(first, after, "0x8003-0x8003 expected [AA] actual [AA] -> pass")


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.5/9 - a save-back that raises after the adopt ends the app
# ---------------------------------------------------------------------------
async def _confirm_save_back(pilot, app, name: str, *, by_keys: bool) -> None:
    """The JSON tab clicked, ``name`` typed into the save-back field, then the
    confirm: by ``tab`` to *Write file* and ``enter`` (``by_keys``), or a press
    of the shipped button."""
    assert await pilot.click("#patch_tab_json"), "click missed #patch_tab_json"
    await wait_until(
        pilot,
        lambda: app.query_one("#patch_saveback_confirm_button").region.width > 0,
        "timed out waiting for the save-back row",
    )
    await _type_into(pilot, app, "#patch_saveback_name_input", name)
    confirm = app.query_one("#patch_saveback_confirm_button", Button)
    if not by_keys:
        confirm.press()
        return
    for _ in range(6):
        if app.focused is confirm:
            break
        await pilot.press("tab")
    assert app.focused is confirm, f"tab never reached the save-back confirm: {app.focused!r}"
    await pilot.press("enter")


def test_r_crc_preview_002_5_9_save_back_raising_after_the_adopt_ends_the_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Case R-CRC-PREVIEW-002.5/9 (E5 C-6, robustness; partial: the fault is
    injected): after the apply of ``AA``, a display and the entry edited to
    ``BB``, a save-back whose emit raises after ``save_patched`` adopted the
    re-derived bytes -> ``0x8003`` holds ``BB``, and the app ends with that
    error (return code 1, the error raised out of the run), so the CRC
    Designer can never show the pre-write CRC (E5-S2 ruling: no hook needed).

    Standing guard (passes on the base). Negative control: the save-back
    handler swallowing the error -> the app keeps running -> RED (M30)."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)

    def raise_after_adopt(self, *args, **kwargs):
        raise RuntimeError("probe after adopt")

    monkeypatch.setattr(change_service_module.ChangeService, "emit_and_verify", raise_after_adopt)
    seen = {}

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            seen["app"] = app
            await _load_image_by_dialog(pilot, app, image)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            assert await _apply(pilot, app, log, "Apply:") == "Apply: 1 applied, 0 skipped, 0 blocked"
            await _fresh_designer_display(pilot, app, AFTER_AA)
            await _entry_op(
                pilot, app, log, "#patch_entry_edit_button", "0x8003", "BB", "Patch Editor: entry updated."
            )
            await _confirm_save_back(pilot, app, "fixture-raise.s19", by_keys=False)
            for _ in range(200):
                if app._exception is not None:
                    break
                await asyncio.sleep(0.05)
            seen["byte"] = app.current_file.mem_map[0x8003]
            assert app._exception is not None, "the save-back error was swallowed; the app runs on"

        return scenario

    for rep in range(REPS):
        folder = tmp_path / f"rep{rep}"
        base = folder / "app"
        base.mkdir(parents=True)
        image = folder / "fixture.s19"
        write_fixture_image(image)
        seen.clear()
        with pytest.raises(RuntimeError, match="probe after adopt"):
            _run(base, make(folder, image))
        assert seen["byte"] == 0xBB, "the fault was not injected after the adopt"
        assert seen["app"].return_code == 1, seen["app"].return_code


# ---------------------------------------------------------------------------
# AT-I5-4 - the save-back confirm reached by keys (C-4)
# ---------------------------------------------------------------------------
def test_at_i5_4_save_back_by_keys_then_display(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-I5-4 (US-CRC-FRESH-2; drives R-CRC-PREVIEW-002.5/4 black box): the
    Load dialog, key ``6``, the path typed, Load and Apply clicked (``AA``);
    key ``0`` (``0x08DAAFB7``); the entry edited to ``BB`` by typed fields and
    a click; the save-back name typed and the confirm reached by ``tab`` and
    pressed by ``enter`` -> ``Saved + verified``, the file written; 0
    recomputes before key ``0``; after key ``0`` exactly 1, concat
    ``0x614BD0E8`` / fill ``0xE1E79AB1``."""
    _set_quiet(monkeypatch, QUIET_SHORT_S)

    def make(folder: Path, image: Path):
        async def scenario(app, pilot, log):
            await _load_image_by_dialog(pilot, app, image)
            await _load_document(pilot, app, log, folder, "d.changes.json", [AA_ENTRY])
            assert await _apply(pilot, app, log, "Apply:") == "Apply: 1 applied, 0 skipped, 0 blocked"
            await _fresh_designer_display(pilot, app, AFTER_AA)
            await _entry_op(
                pilot, app, log, "#patch_entry_edit_button", "0x8003", "BB", "Patch Editor: entry updated."
            )
            before = designer_recomputes()
            mark = len(log.messages)
            await _confirm_save_back(pilot, app, "fixture-keys.s19", by_keys=True)
            await _status_since(pilot, log, mark, lambda m: "Saved + verified" in m, "the save-back")
            assert list((folder / "app").rglob("fixture-keys.s19")), "the save-back wrote no file"
            assert app.current_file.mem_map[0x8003] == 0xBB
            await _quiet(pilot)
            assert designer_recomputes() == before, "a hidden CRC Designer recomputed"
            await _press_rail(pilot, app, "0")
            await _expect_refresh(pilot, app, before, AFTER_BB, "save-back by keys then display")

        return scenario

    _reps(tmp_path, make)
