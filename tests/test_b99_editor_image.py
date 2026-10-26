"""Batch-99 HLR-157: the Patch Editor's image is the source plus the document.

TC-B99-21 (LLR-157.1) — the journal restore in place: the p05 sequence
(apply -> undo -> apply -> save) writes the source bytes at the undone
entry's address; the same bytes are seen through an aliased holder of the
same dict; all entries undone + apply leaves the image equal to the source;
a removed entry overlapping a kept one leaves no stale byte.

TC-B99-22 (LLR-157.2) — undo / remove / edit re-derive the image before the
save (0 stale bytes); an entry added after the last apply is written by the
save and NAMED in the save status; the saved summary lists exactly the
entries the image holds; an interactively created span overlap blocks the
save exactly as it blocks the apply (the save re-derive runs the same
collision refresh — review finding F1): the blocked document saves nothing
and the refusal says why.

TC-B99-40 (LLR-157.4) — after apply -> apply on the same entry, the change
record's ``before_bytes`` is the source byte: the before/after strip, the
service summary and a before/after report all show ``20 41 70 70`` as
before, not ``DE AD BE EF``. The strip arm also covers a NEW file loaded
after the apply (review finding F2): the strip's ``was`` line shows the
new file's byte, never the previous image's source byte.

AT-B99-08 (US-146) — black-box Textual pilot: add ``0xEB10 DE AD BE EF``,
Apply, Undo, add ``0xEB40 01 02``, Apply, add ``0xEB60 05 06`` (WITHOUT
applying), save back.  The independent reader shows the source bytes at
``0xEB10``, ``01 02`` at ``0xEB40`` and ``05 06`` at ``0xEB60``, and the
painted status names the applied entry AND the not-applied entry ("1
entry" count) and stays visible after the verify result (PDR-UX-C6,
review finding F3). A second arm forces a verify mismatch and asserts the
mismatch status line still carries the not-applied names (UX-C6 allows no
exception — review finding F5).
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes import (
    CHG_COLLISION,
    DISPOSITION_APPLIED,
    DISPOSITION_BLOCKED,
)
from s19_app.tui.services.before_after_service import compose_before_after_report
from s19_app.tui.services.change_service import ChangeService
from tests.support.independent_reader import read_s19

#: The source bytes the fixture image declares at 0xEB10..0xEB13 (" App").
SOURCE_EB10 = (0x20, 0x41, 0x70, 0x70)


def _s19_line(record_type: str, address: int, data: bytes) -> str:
    """One S-record line, checksum included (test-local fixture writer)."""
    addr_len = {"S0": 2, "S1": 2, "S2": 3, "S3": 4, "S9": 2}[record_type]
    count = addr_len + len(data) + 1
    body = count.to_bytes(1, "big") + address.to_bytes(addr_len, "big") + data
    checksum = (~sum(body)) & 0xFF
    return record_type + (body + checksum.to_bytes(1, "big")).hex().upper()


def _write_fixture_s19(path: Path) -> None:
    """The premise image: source bytes at 0xEB10..0xEB13 and 0xEB40..0xEB41."""
    lines = [
        _s19_line("S1", 0xEB10, bytes(SOURCE_EB10)),
        _s19_line("S1", 0xEB40, b"\x00\x00"),
        _s19_line("S1", 0xEB60, b"\x00\x00"),
        _s19_line("S9", 0x0, b""),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def _write_fixture_b_s19(path: Path) -> None:
    """A SECOND image file: 0x99-run bytes at 0xEB10..0xEB13 (load-B arm)."""
    lines = [
        _s19_line("S1", 0xEB10, b"\x99\x98\x97\x96"),
        _s19_line("S9", 0x0, b""),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def _service_with_image() -> tuple[ChangeService, dict[int, int], list[tuple[int, int]]]:
    """A change service plus the premise image as a map and ranges."""
    service = ChangeService()
    mem_map = {0xEB10 + i: byte for i, byte in enumerate(SOURCE_EB10)}
    mem_map.update({0xEB40 + i: 0x00 for i in range(2)})
    ranges = [(0xEB10, 0xEB14), (0xEB40, 0xEB42)]
    return service, mem_map, ranges


def _save_back(
    service: ChangeService,
    mem_map: dict[int, int],
    ranges: list[tuple[int, int]],
    tmp_path: Path,
    name: str = "tc21-p05.s19",
    *,
    source_image_path: Path | None = None,
):
    """Save-back through the service into a fresh project dir under tmp."""
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True, exist_ok=True)
    result = service.save_patched(
        mem_map,
        ranges,
        project_dir,
        name,
        source_kind="s19",
        source_image_path=source_image_path,
    )
    targets = sorted(project_dir.rglob(name))
    return result, (targets[0] if targets else None)


def _applied_addresses(service: ChangeService) -> list[int]:
    """The addresses the saved summary holds as applied, in document order."""
    assert service.last_summary is not None
    return [
        record.address_start
        for record in service.last_summary.entries
        if record.disposition == DISPOSITION_APPLIED
    ]


def _status_text(app: S19TuiApp) -> str:
    """The painted newest status line (the ``#log_line_4`` label)."""
    from textual.widgets import Label

    return str(app.query_one("#log_line_4", Label).render())


def _painted_text(app: S19TuiApp) -> str:
    """The painted screen as text (the SVG export idiom of AT-B99-02)."""
    svg = app.export_screenshot()
    return "".join(re.findall(r"<text[^>]*>(.*?)</text>", svg, re.S))


def _strip_plain(app: S19TuiApp) -> str:
    """The before/after card's PAINTED plain text ("" before it mounts)."""
    from textual.widgets import Static

    cards = app.query("#patch_before_after_card")
    if not cards:
        return ""
    rendered = cards.first(Static).render()
    return getattr(rendered, "plain", str(rendered))


def _history_plain(app: S19TuiApp) -> str:
    """The history strip's painted plain text (the undo/redo depth line)."""
    from textual.widgets import Static

    rendered = app.query_one("#patch_history_strip", Static).render()
    return getattr(rendered, "plain", str(rendered))


async def _wait_for(pilot, predicate, description: str, attempts: int = 100):
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


async def _load_fixture(app: S19TuiApp, pilot, src: Path, name: str) -> None:
    """Drive the Load file dialog (rail key ``l``) and wait for the status."""
    await pilot.press("l")
    for _ in range(6):
        await pilot.pause()
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press(*str(src))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await _wait_for(
        pilot,
        lambda: f"Loaded {name}" in _status_text(app),
        "load status line",
    )


# --------------------------------------------------------------------------- #
# TC-B99-21 — LLR-157.1: source plus current document, restored in place
# --------------------------------------------------------------------------- #


def test_tc_b99_21_editor_image_is_source_plus_document(tmp_path: Path) -> None:
    """The p05 sequence writes source bytes at the undone entry's address.

    Intent: LLR-157.1 — every apply restores the journaled addresses in
    place in the SAME dict object before applying, so the alias arm (the
    same bytes seen through another holder of the dict) and the save arm
    both observe the source byte at 0xEB10.
    """
    service, mem_map, ranges = _service_with_image()
    alias = mem_map  # a second holder of the same dict (app.py merge aliases)

    service.add_entry("0xEB10", "", "DE AD BE EF")
    service.apply(mem_map, ranges, None, None, variant_id="img")
    assert alias[0xEB10] == 0xDE, "the apply must write through the shared dict"

    service.undo()
    service.add_entry("0xEB40", "", "01 02")
    service.apply(mem_map, ranges, None, None, variant_id="img")

    result, target = _save_back(
        service, mem_map, ranges, tmp_path, name="tc21-p05.s19"
    )
    assert result.ok, result.message
    assert target is not None, "save-back wrote no file"
    written = read_s19(target)
    assert [written.data[0xEB10 + i] for i in range(4)] == list(SOURCE_EB10), (
        f"the undone entry must return to the source bytes, "
        f"got {[written.data.get(0xEB10 + i) for i in range(4)]}"
    )
    assert [written.data[0xEB40 + i] for i in range(2)] == [0x01, 0x02]
    # The restore happened IN PLACE: the aliased holder sees the source byte.
    assert alias[0xEB10] == SOURCE_EB10[0], (
        "the journal restore must write into the same dict object the "
        "alias holds, not a rebound copy"
    )
    # The saved summary lists exactly the entries the image holds.
    assert _applied_addresses(service) == [0xEB40]

    # Arm 2 (empty boundary): every entry undone + apply -> image == source.
    service2, mem_map2, ranges2 = _service_with_image()
    service2.add_entry("0xEB10", "", "DE AD BE EF")
    service2.apply(mem_map2, ranges2, None, None)
    service2.undo()
    summary2 = service2.apply(mem_map2, ranges2, None, None)
    assert all(
        mem_map2[addr] == SOURCE_EB10[i] for i, addr in enumerate(range(0xEB10, 0xEB14))
    ), f"image after undo-all must equal the source: {mem_map2}"
    assert summary2.counts[DISPOSITION_APPLIED] == 0

    # Arm 3 (overlap boundary): a removed entry whose span overlapped a
    # kept one leaves the kept bytes and restores the rest.
    service3, mem_map3, ranges3 = _service_with_image()
    service3.add_entry("0xEB10", "", "DE AD BE EF")  # 0xEB10..0xEB13
    service3.apply(mem_map3, ranges3, None, None)
    service3.remove_entry("0xEB10")
    service3.add_entry("0xEB12", "", "01 02")  # 0xEB12..0xEB13 overlaps
    service3.apply(mem_map3, ranges3, None, None)
    result3, target3 = _save_back(
        service3, mem_map3, ranges3, tmp_path, name="tc21-overlap.s19"
    )
    assert result3.ok, result3.message
    written3 = read_s19(target3)
    assert [written3.data[0xEB10 + i] for i in range(2)] == list(SOURCE_EB10[:2])
    assert [written3.data[0xEB12 + i] for i in range(2)] == [0x01, 0x02]


# --------------------------------------------------------------------------- #
# TC-B99-22 — LLR-157.2: undo, remove and edit revert applied bytes
# --------------------------------------------------------------------------- #


def test_tc_b99_22_save_rederives_and_names_not_applied(tmp_path: Path) -> None:
    """The save re-derives the image from every entry currently in the
    document and names each entry that was not applied before the save.

    Intent: LLR-157.2 — remove-after-apply and edit-after-apply leave 0
    stale bytes; add-after-apply is written by the save AND named in the
    save status; the saved summary lists exactly the entries the image
    holds; redo after undo re-applies the kept entry's bytes.
    """
    # Arm 1: remove-after-apply -> the removed entry's bytes return to source.
    service, mem_map, ranges = _service_with_image()
    service.add_entry("0xEB10", "", "DE AD BE EF")
    service.apply(mem_map, ranges, None, None)
    service.remove_entry("0xEB10")
    result, target = _save_back(
        service, mem_map, ranges, tmp_path, name="tc22-remove.s19"
    )
    assert result.ok, result.message
    written = read_s19(target)
    assert [written.data[0xEB10 + i] for i in range(4)] == list(SOURCE_EB10), (
        "remove-after-apply left stale bytes in the saved image"
    )
    assert _applied_addresses(service) == []

    # Arm 2: edit-after-apply -> the edited value is written, not the stale one.
    service2, mem_map2, ranges2 = _service_with_image()
    service2.add_entry("0xEB10", "", "DE AD BE EF")
    service2.apply(mem_map2, ranges2, None, None)
    service2.edit_entry("0xEB10", "", "01 02 03 04")
    result2, target2 = _save_back(
        service2, mem_map2, ranges2, tmp_path, name="tc22-edit.s19"
    )
    assert result2.ok, result2.message
    written2 = read_s19(target2)
    assert [written2.data[0xEB10 + i] for i in range(4)] == [0x01, 0x02, 0x03, 0x04]

    # Arm 3: add-after-apply -> the save writes the new entry and NAMES it.
    service3, mem_map3, ranges3 = _service_with_image()
    service3.add_entry("0xEB10", "", "DE AD BE EF")
    service3.apply(mem_map3, ranges3, None, None)
    service3.add_entry("0xEB40", "", "01 02")
    result3, target3 = _save_back(
        service3, mem_map3, ranges3, tmp_path, name="tc22-add.s19"
    )
    assert result3.ok, result3.message
    assert "not applied before this save" in result3.message, result3.message
    assert "0x0000EB40" in result3.message, result3.message
    written3 = read_s19(target3)
    assert [written3.data[0xEB40 + i] for i in range(2)] == [0x01, 0x02]
    assert _applied_addresses(service3) == [0xEB10, 0xEB40]

    # Arm 4 (redo boundary): undo then redo -> the kept entry is written.
    service4, mem_map4, ranges4 = _service_with_image()
    service4.add_entry("0xEB10", "", "DE AD BE EF")
    service4.apply(mem_map4, ranges4, None, None)
    service4.undo()
    service4.redo()
    result4, target4 = _save_back(
        service4, mem_map4, ranges4, tmp_path, name="tc22-redo.s19"
    )
    assert result4.ok, result4.message
    written4 = read_s19(target4)
    assert [written4.data[0xEB10 + i] for i in range(4)] == [0xDE, 0xAD, 0xBE, 0xEF]


def test_tc_b99_22_save_blocks_overlapping_entries(tmp_path: Path) -> None:
    """The save re-derive runs the same collision refresh as the apply, so
    an interactively created span overlap blocks the save (review F1).

    Intent: LLR-157.2 — the reviewer's probe: add ``0xEB10 DE AD BE EF``,
    apply, add ``0xEB12 01 02`` (the spans overlap), save. ``apply`` on the
    same document blocks BOTH entries; the save must not write an image the
    apply would refuse: it saves nothing and the refusal says why. Before
    the fix the save returned ``ok`` and the file held ``DE AD 01 02``
    with the summary listing both entries as applied.
    """
    service, mem_map, ranges = _service_with_image()
    service.add_entry("0xEB10", "", "DE AD BE EF")
    first = service.apply(mem_map, ranges, None, None)
    assert first.counts[DISPOSITION_APPLIED] == 1
    service.add_entry("0xEB12", "", "01 02")

    # Arm 1 (the reviewer's probe): save with NO apply after the overlapping
    # add — nothing but the save's own collision refresh can stamp the
    # collision, so this arm is vacuous if the refresh is skipped.
    result, target = _save_back(
        service, mem_map, ranges, tmp_path, name="tc22-overlap-refused.s19"
    )
    assert not result.ok, (
        f"the save must refuse a document the apply blocks: {result.message}"
    )
    assert target is None, "a blocked document must save nothing"
    assert "blocked" in result.message, result.message
    # The refusal carries the collision finding so the operator sees why.
    assert any(
        issue.code == CHG_COLLISION for issue in result.issues
    ), result.issues

    # Arm 2 (the premise): apply on the SAME overlapping document blocks
    # BOTH entries — the gate the save re-derive must present too.
    service2, mem_map2, ranges2 = _service_with_image()
    service2.add_entry("0xEB10", "", "DE AD BE EF")
    service2.apply(mem_map2, ranges2, None, None)
    service2.add_entry("0xEB12", "", "01 02")
    blocked = service2.apply(mem_map2, ranges2, None, None)
    assert blocked.counts[DISPOSITION_BLOCKED] == 2, (
        f"apply must block the overlapping document: {blocked.counts}"
    )


# --------------------------------------------------------------------------- #
# TC-B99-40 — LLR-157.4: before_bytes means the source byte
# --------------------------------------------------------------------------- #


def test_tc_b99_40_before_bytes_is_source(tmp_path: Path) -> None:
    """After apply -> apply on 0xEB10, the record and the report show the
    source byte as before.

    Intent: LLR-157.4 — the change record's ``before_bytes`` is the source
    image's byte even on a repeated apply: the service summary and a
    before/after report both show ``20 41 70 70`` as before, never
    ``DE AD BE EF``.
    """
    src = tmp_path / "img.s19"
    _write_fixture_s19(src)

    service, mem_map, ranges = _service_with_image()
    service.add_entry("0xEB10", "", "DE AD BE EF")
    service.apply(mem_map, ranges, None, None, variant_id="img")
    summary = service.apply(mem_map, ranges, None, None, variant_id="img")
    record = next(r for r in summary.entries if r.address_start == 0xEB10)
    assert record.before_bytes == SOURCE_EB10, (
        f"repeated apply: before_bytes must be the source byte, "
        f"got {record.before_bytes}"
    )

    # The before/after report shows the source byte as before.
    result, _ = _save_back(
        service, mem_map, ranges, tmp_path, source_image_path=src
    )
    assert result.ok, result.message
    report = compose_before_after_report(
        service.last_summary,
        src,
        project_dir=tmp_path / ".s19tool" / "workarea" / "proj",
        workarea=tmp_path / ".s19tool" / "workarea",
    )
    assert report.written, report.diagnostics
    text = report.md_path.read_text(encoding="utf-8")
    row = next(
        (line for line in text.splitlines() if "0x0000EB10" in line),
        None,
    )
    assert row is not None, "the report carries no linkage row for 0xEB10"
    before_part, _, after_part = row.partition("DE AD BE EF")
    assert "20 41 70 70" in before_part, (
        f"the report row's BEFORE cell must show the source byte: {row}"
    )
    assert "DE AD BE EF" in after_part or "DE AD BE EF" in row, (
        f"the report row's AFTER cell must show the entry: {row}"
    )


def test_tc_b99_40_strip_shows_source_byte(tmp_path: Path) -> None:
    """The before/after strip paints the source byte as "was".

    Intent: LLR-157.4 (the strip reader) — after apply -> apply on 0xEB10
    the strip's was-line shows ``20 41 70 70`` (the source byte the change
    record holds as ``before_bytes``), not the applied ``DE AD BE EF``.
    """
    src = tmp_path / "img.s19"
    _write_fixture_s19(src)
    app = S19TuiApp(base_dir=tmp_path)

    async def _drive() -> str:
        async with app.run_test(size=(120, 54)) as pilot:
            await pilot.pause()
            await _load_fixture(app, pilot, src, "img.s19")
            await pilot.press("6")
            for _ in range(6):
                await pilot.pause()
            # White-box seed of the document (a TC arm, not the AT): the
            # apply clicks below drive the app's own action routing.
            app._change_service.add_entry("0xEB10", "", "DE AD BE EF")
            assert await pilot.click(
                "#patch_doc_apply_button"
            ), "click missed #patch_doc_apply_button"
            await _wait_for(
                pilot,
                lambda: "1 applied, 0 skipped, 0 blocked" in _status_text(app),
                "first apply status line",
            )
            assert await pilot.click(
                "#patch_doc_apply_button"
            ), "click missed #patch_doc_apply_button"
            await _wait_for(
                pilot,
                lambda: "20 41 70 70" in _strip_plain(app)
                or "DE AD BE EF" in _strip_plain(app),
                "strip painted after the repeated apply",
            )
            return _strip_plain(app)

    strip = asyncio.run(_drive())
    assert "20 41 70 70" in strip, (
        f"the strip's was-line must show the source byte; got:\n{strip}"
    )
    assert "DE AD BE EF" in strip, "the strip's now-line must show the entry"


def test_tc_b99_40_strip_shows_new_file_source_byte(tmp_path: Path) -> None:
    """After a NEW file loads, the strip's "was" line shows the NEW file's
    byte, not the previous image's source byte (review finding F2).

    Intent: LLR-157.4 (the strip reader) — the journal binds to the image
    DICT; when the strip is refreshed with a different dict (file B loaded
    after an apply on file A), the overlay must not paint file A's source
    bytes over file B's map. The reviewer's probe: byte ``0x99`` at the
    strip address in file B.
    """
    src_a = tmp_path / "img_a.s19"
    _write_fixture_s19(src_a)
    src_b = tmp_path / "img_b.s19"
    _write_fixture_b_s19(src_b)
    app = S19TuiApp(base_dir=tmp_path)

    async def _drive() -> str:
        async with app.run_test(size=(120, 54)) as pilot:
            await pilot.pause()
            await _load_fixture(app, pilot, src_a, "img_a.s19")
            await pilot.press("6")
            for _ in range(6):
                await pilot.pause()
            # White-box seed of the document (a TC arm, not the AT): the
            # apply click below drives the app's own action routing.
            app._change_service.add_entry("0xEB10", "", "DE AD BE EF")
            assert await pilot.click(
                "#patch_doc_apply_button"
            ), "click missed #patch_doc_apply_button"
            await _wait_for(
                pilot,
                lambda: "1 applied, 0 skipped, 0 blocked" in _status_text(app),
                "apply status line on file A",
            )
            # Load file B: the load-triggered strip refresh pushes file B's
            # map through source_image_view while the journal still holds
            # file A's source bytes — the defect this arm pins.
            await _load_fixture(app, pilot, src_b, "img_b.s19")
            await _wait_for(
                pilot,
                lambda: "99 98 97 96" in _strip_plain(app)
                or "20 41 70 70" in _strip_plain(app),
                "strip repainted for file B",
            )
            return _strip_plain(app)

    strip = asyncio.run(_drive())
    assert "99 98 97 96" in strip, (
        f"the strip's was-line must show file B's byte; got:\n{strip}"
    )
    assert "20 41 70 70" not in strip, (
        f"the strip's was-line must not show file A's source byte: {strip}"
    )
    assert "DE AD BE EF" in strip, "the strip's now-line must show the entry"


# --------------------------------------------------------------------------- #
# AT-B99-08 — US-146: black-box pilot through the TUI
# --------------------------------------------------------------------------- #


def test_at_b99_08_save_back_keeps_editor_image(tmp_path: Path) -> None:
    """Add / Apply / Undo / Add / Apply / Add (no apply) / save back: the
    written file holds the source bytes at 0xEB10, 01 02 at 0xEB40 and
    05 06 at 0xEB60, and the final painted status names the applied entry
    AND the not-applied entry (with the "1 entry" count) and stays visible
    after the verify result (PDR-UX-C6, review finding F3).

    RED premise (P-6): on the unmodified tree the save writes the undone
    entry (``deadbeef`` at 0xEB10) and the status is overwritten by the
    verify line, so neither assertion can pass.
    """
    src = tmp_path / "editor_image.s19"
    _write_fixture_s19(src)
    oracle = read_s19(src)

    app = S19TuiApp(base_dir=tmp_path)

    async def _drive() -> str:
        # 160 columns: the log line's width-aware cap (max(50, width)) must
        # not trim the two-clause status this AT asserts — the full line is
        # ~139 cells.
        async with app.run_test(size=(160, 54)) as pilot:
            await pilot.pause()

            async def _type(input_id: str, text: str) -> None:
                assert await pilot.click(f"#{input_id}"), (
                    f"click missed #{input_id}"
                )
                await pilot.press("ctrl+shift+a")
                await pilot.press(*text)

            # 1. Load the premise image through the Load file dialog.
            await _load_fixture(app, pilot, src, "editor_image.s19")

            # 2. Patch Editor (rail key ``6``): add, apply, undo, add, apply.
            await pilot.press("6")
            for _ in range(6):
                await pilot.pause()
            await _type("patch_entry_address_input", "0xEB10")
            await _type("patch_entry_bytes_input", "DE AD BE EF")
            assert await pilot.click(
                "#patch_entry_add_button"
            ), "click missed #patch_entry_add_button"
            await _wait_for(
                pilot,
                lambda: "entry added" in _status_text(app),
                "add status line",
            )
            assert await pilot.click(
                "#patch_doc_apply_button"
            ), "click missed #patch_doc_apply_button"
            await _wait_for(
                pilot,
                lambda: "1 applied, 0 skipped, 0 blocked" in _status_text(app),
                "apply status line",
            )
            # The Undo/Redo controls render in the editor's JSON pane, so the
            # drive uses the shipped ``ctrl+z`` key binding (the same guarded
            # path the Undo button posts to).  The history strip repaints
            # "1 fwd" when the undo lands (a space-free painted signal).
            await pilot.press("ctrl+z")
            await _wait_for(
                pilot,
                lambda: "1 fwd" in _history_plain(app),
                "undo repaints the history strip",
            )
            await _type("patch_entry_address_input", "0xEB40")
            await _type("patch_entry_bytes_input", "01 02")
            assert await pilot.click(
                "#patch_entry_add_button"
            ), "click missed #patch_entry_add_button"
            await _wait_for(
                pilot,
                lambda: "entry added" in _status_text(app),
                "second add status line",
            )
            assert await pilot.click(
                "#patch_doc_apply_button"
            ), "click missed #patch_doc_apply_button"
            await _wait_for(
                pilot,
                lambda: "1 applied, 0 skipped, 0 blocked" in _status_text(app),
                "second apply status line",
            )

            # 2b. Add a THIRD entry WITHOUT applying it: the save must write
            # it AND the painted status must name it as not applied before
            # the save, with the "1 entry" count (review finding F3).
            await _type("patch_entry_address_input", "0xEB60")
            await _type("patch_entry_bytes_input", "05 06")
            assert await pilot.click(
                "#patch_entry_add_button"
            ), "click missed #patch_entry_add_button"
            await _wait_for(
                pilot,
                lambda: "entry added" in _status_text(app),
                "third add status line",
            )

            # 3. Save-back: the prompt renders in the editor's JSON pane.
            assert await pilot.click("#patch_tab_json"), (
                "click missed #patch_tab_json"
            )
            await _wait_for(
                pilot,
                lambda: "patched" in _painted_text(app),
                "save-back prompt painted",
            )
            assert await pilot.click(
                "#patch_saveback_name_input"
            ), "click missed #patch_saveback_name_input"
            await pilot.press("ctrl+shift+a")
            await pilot.press(*"at_b99_08.s19")
            assert await pilot.click(
                "#patch_saveback_confirm_button"
            ), "click missed #patch_saveback_confirm_button"
            await _wait_for(
                pilot,
                lambda: "Saved + verified" in _status_text(app),
                "save-back verify status line",
            )
            final_status = _status_text(app)
            # UX-C6: the status must still name the applied entry AFTER the
            # verify result surfaces — wait, then re-read the painted line.
            for _ in range(10):
                await pilot.pause()
            return final_status if final_status == _status_text(app) else (
                final_status + " || overwritten by: " + _status_text(app)
            )

    status = asyncio.run(_drive())

    target = None
    for candidate in sorted(tmp_path.rglob("at_b99_08.s19")):
        target = candidate
        break
    assert target is not None, "save-back wrote no file"
    written = read_s19(target)
    assert [written.data[0xEB10 + i] for i in range(4)] == [
        oracle.data[0xEB10 + i] for i in range(4)
    ], (
        f"the undone entry reached the file: "
        f"{[written.data.get(0xEB10 + i) for i in range(4)]}"
    )
    assert [written.data[0xEB40 + i] for i in range(2)] == [0x01, 0x02]
    assert [written.data[0xEB60 + i] for i in range(2)] == [0x05, 0x06], (
        f"the never-applied entry must reach the file via the save "
        f"re-derive: {[written.data.get(0xEB60 + i) for i in range(2)]}"
    )

    # UX-C6: one status line carries the verify word AND the applied entry,
    # outcome first, and nothing overwrites it after the handler returns.
    assert " || overwritten by: " not in status, (
        f"the save-back status was overwritten by the verify result: {status}"
    )
    assert "Saved + verified: at_b99_08.s19" in status, status
    assert "0x0000EB40" in status, (
        f"the final status must name the applied entry: {status}"
    )
    # F3: the same line names the entry that was NOT applied before the
    # save, with the singular "1 entry" count.
    assert "includes 1 entry not applied before this save" in status, (
        f"the final status must name the not-applied entry with its "
        f"count: {status}"
    )
    assert "0x0000EB60" in status, (
        f"the final status must name the not-applied entry: {status}"
    )


def test_at_b99_08_verify_mismatch_status_still_names_entries(
    tmp_path: Path, monkeypatch
) -> None:
    """A forced verify mismatch: the mismatch status line carries the SAME
    not-applied names as the verified arm (PDR-UX-C6 allows no exception —
    review finding F5).

    Intent: UX-C6 / HLR-157 statement 3 — the saved image's not-applied
    naming must survive on BOTH verify arms. The verify outcome is forced
    to ``mismatch`` by patching the engine entry point the service module
    resolves (``change_service.verify_written_image``) — the pilot itself
    stays black-box: real keys and clicks, painted status observed.
    """
    from s19_app.compare import DIFF_KIND_DOMAIN, DiffStats
    from s19_app.tui.changes.verify import STATUS_MISMATCH, VerifyResult
    from s19_app.tui.services import change_service as change_service_module

    def _forced_mismatch(written, intended, file_type):
        return VerifyResult(
            status=STATUS_MISMATCH,
            runs=[],
            stats=DiffStats(
                run_counts={kind: 0 for kind in DIFF_KIND_DOMAIN},
                byte_counts={kind: 0 for kind in DIFF_KIND_DOMAIN},
            ),
            written_path=written,
        )

    monkeypatch.setattr(
        change_service_module, "verify_written_image", _forced_mismatch
    )

    src = tmp_path / "editor_image.s19"
    _write_fixture_s19(src)
    app = S19TuiApp(base_dir=tmp_path)

    async def _drive() -> str:
        # 160 columns so the width-aware log cap paints the two-clause
        # mismatch line in full (see the sibling AT's note).
        async with app.run_test(size=(160, 54)) as pilot:
            await pilot.pause()

            async def _type(input_id: str, text: str) -> None:
                assert await pilot.click(f"#{input_id}"), (
                    f"click missed #{input_id}"
                )
                await pilot.press("ctrl+shift+a")
                await pilot.press(*text)

            await _load_fixture(app, pilot, src, "editor_image.s19")
            await pilot.press("6")
            for _ in range(6):
                await pilot.pause()
            await _type("patch_entry_address_input", "0xEB10")
            await _type("patch_entry_bytes_input", "DE AD BE EF")
            assert await pilot.click(
                "#patch_entry_add_button"
            ), "click missed #patch_entry_add_button"
            await _wait_for(
                pilot,
                lambda: "entry added" in _status_text(app),
                "add status line",
            )
            assert await pilot.click(
                "#patch_doc_apply_button"
            ), "click missed #patch_doc_apply_button"
            await _wait_for(
                pilot,
                lambda: "1 applied, 0 skipped, 0 blocked" in _status_text(app),
                "apply status line",
            )
            # Second entry added WITHOUT an apply: it is the not-applied
            # name the mismatch arm must still carry.
            await _type("patch_entry_address_input", "0xEB40")
            await _type("patch_entry_bytes_input", "01 02")
            assert await pilot.click(
                "#patch_entry_add_button"
            ), "click missed #patch_entry_add_button"
            await _wait_for(
                pilot,
                lambda: "entry added" in _status_text(app),
                "second add status line",
            )

            assert await pilot.click("#patch_tab_json"), (
                "click missed #patch_tab_json"
            )
            await _wait_for(
                pilot,
                lambda: "patched" in _painted_text(app),
                "save-back prompt painted",
            )
            assert await pilot.click(
                "#patch_saveback_name_input"
            ), "click missed #patch_saveback_name_input"
            await pilot.press("ctrl+shift+a")
            await pilot.press(*"at_b99_08m.s19")
            assert await pilot.click(
                "#patch_saveback_confirm_button"
            ), "click missed #patch_saveback_confirm_button"
            await _wait_for(
                pilot,
                lambda: "Verify MISMATCH" in _status_text(app),
                "mismatch status line",
            )
            final_status = _status_text(app)
            for _ in range(10):
                await pilot.pause()
            return final_status if final_status == _status_text(app) else (
                final_status + " || overwritten by: " + _status_text(app)
            )

    status = asyncio.run(_drive())
    assert " || overwritten by: " not in status, (
        f"the mismatch status was overwritten after the handler: {status}"
    )
    assert "Verify MISMATCH: at_b99_08m.s19" in status, status
    assert "includes 1 entry not applied before this save" in status, (
        f"the mismatch line must carry the not-applied naming: {status}"
    )
    assert "0x0000EB40" in status, (
        f"the mismatch line must name the not-applied entry: {status}"
    )
