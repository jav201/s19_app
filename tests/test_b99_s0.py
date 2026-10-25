"""Batch-99 HLR-153: an S19 image holds only its data records.

TC-B99-04 (LLR-153.1) — one data-record predicate feeds every S19 record
walk (``get_memory_map`` / ``get_memory_ranges`` /
``get_record_for_address`` / ``_build_overlap_map``).

TC-B99-05 (LLR-153.2) — the hex-view builders (``build_mem_map_s19`` /
``build_range_validity_s19``) use the same predicate.

TC-B99-06 (LLR-153.3) — an image loaded from an S19 and written back (S19
or Intel HEX) carries the source S0 as a header record and no data at any
address the source did not declare in a data record (oracle: the
independent reader).

TC-B99-07 (LLR-153.4) — a change entry at an address covered only by the
S0 payload gets disposition ``skipped-outside``.

AT-B99-02 (US-142) — black-box Textual pilot: Load file dialog (``l``) ->
Patch Editor (``6``) save-back (``#patch_saveback_*``) and the Memory Map
(``4``); the written file is verified with the independent reader.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.render.hexview import build_mem_map_s19, build_range_validity_s19
from s19_app.tui.changes.apply import apply_change_document, save_patched_image
from s19_app.tui.changes.model import ChangeDocument, ChangeEntry
from s19_app.tui.app import S19TuiApp
from tests.support.independent_reader import read_hex, read_s19

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "synth"
CASE01 = ROOT / "examples" / "case_01_basic_valid" / "firmware.s19"
EXAMPLE_S19 = sorted((ROOT / "examples").rglob("*.s19"))


def _manifest() -> dict:
    return json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))


def _expand_runs(runs: dict) -> dict:
    data = {}
    for key, hex_bytes in runs.items():
        addr = int(key, 16)
        for i, b in enumerate(bytes.fromhex(hex_bytes)):
            data[addr + i] = b
    return data


def _s0_record(s19: S19File):
    return next((r for r in s19.records if r.type == "S0"), None)


def _s19_line(record_type: str, address: int, data: bytes) -> str:
    """One S-record line, checksum included (test-local fixture writer)."""
    addr_len = {"S0": 2, "S1": 2, "S2": 3, "S3": 4, "S9": 2}[record_type]
    count = addr_len + len(data) + 1
    body = count.to_bytes(1, "big") + address.to_bytes(addr_len, "big") + data
    checksum = (~sum(body)) & 0xFF
    return record_type + (body + checksum.to_bytes(1, "big")).hex().upper()


def _defective_record_addresses(path: Path) -> set:
    """Addresses declared only by checksum-defective S1/S2/S3 records.

    The independent reader flags the defective lines in ``errors`` but
    records no addresses for them; this parses those same lines straight
    from the file so TC-B99-06 can bound the bytes the writer may carry
    beyond the reader's image (review finding F5).
    """
    addr_len = {"1": 2, "2": 3, "3": 4}
    bad: set = set()
    for raw in path.read_text(encoding="ascii").splitlines():
        line = raw.strip()
        if len(line) < 4 or line[0] != "S" or line[1] not in addr_len:
            continue
        try:
            body = bytes.fromhex(line[2:])
        except ValueError:
            continue
        if (sum(body) & 0xFF) == 0xFF:
            continue
        width = addr_len[line[1]]
        if len(body) < width + 1:
            continue
        addr = int.from_bytes(body[1 : 1 + width], "big")
        payload = body[1 + width : -1]
        bad.update(addr + i for i in range(len(payload)))
    return bad


# --------------------------------------------------------------------------- #
# TC-B99-04 — LLR-153.1: one data-record predicate feeds every record walk
# --------------------------------------------------------------------------- #


def test_tc_b99_04_predicate_feeds_every_walk():
    """Every S0-bearing corpus S19: maps/ranges/lookup/overlap see S1/S2/S3 only."""
    manifest = _manifest()
    checked = 0
    for entry in manifest["files"]:
        if entry["format"] != "s19" or entry["header"] is None:
            continue
        expected = _expand_runs(entry["data"])
        s19 = S19File(str(CORPUS / entry["name"]))
        header = _s0_record(s19)
        assert header is not None, entry["name"]
        s0_only = {
            header.address + i for i in range(len(header.data))
        } - set(expected)

        mem_map = s19.get_memory_map()
        assert mem_map == expected, entry["name"]
        ranges = s19.get_memory_ranges()
        assert not any(start in s0_only for start, _ in ranges), entry["name"]
        overlap = s19._build_overlap_map()
        assert s0_only.isdisjoint(overlap), entry["name"]
        for addr in sorted(s0_only):
            with pytest.raises(ValueError):
                s19.get_record_for_address(addr)
        checked += 1
    # synth_s1 / synth_s2 / synth_s3 / synth_s0_only are S0-bearing.
    assert checked == 4

    oracle = read_s19(CASE01)
    s19 = S19File(str(CASE01))
    assert s19.get_memory_map() == oracle.data
    assert s19.get_memory_ranges()[0][0] != 0x0
    with pytest.raises(ValueError):
        s19.get_record_for_address(0x0)


def test_tc_b99_04_boundary_s0_alongside_data_at_zero(tmp_path):
    """An S0 at 0x0 beside a data record at 0x0: data kept, header not."""
    path = tmp_path / "s0_and_data_at_zero.s19"
    path.write_text(
        "\n".join(
            [
                _s19_line("S0", 0x0, b"HEADER-TEXT"),
                _s19_line("S1", 0x0, b"\x01\x02\x03\x04"),
                _s19_line("S9", 0x0, b""),
            ]
        )
        + "\n",
        encoding="ascii",
    )
    s19 = S19File(str(path))
    assert s19.get_memory_map() == {0x0: 0x01, 0x1: 0x02, 0x2: 0x03, 0x3: 0x04}
    assert s19.get_memory_ranges() == [(0x0, 0x4)]
    assert s19.get_record_for_address(0x2)[1] == 2
    with pytest.raises(ValueError):
        s19.get_record_for_address(0x4)  # header-only address past the data


# --------------------------------------------------------------------------- #
# TC-B99-05 — LLR-153.2: the hex-view builders use the same predicate
# --------------------------------------------------------------------------- #


def test_tc_b99_05_hexview_builders_use_same_predicate():
    """build_mem_map_s19 == get_memory_map == manifest bytes; S0-only excluded."""
    manifest = _manifest()
    checked = 0
    for entry in manifest["files"]:
        if entry["format"] != "s19":
            continue
        expected = _expand_runs(entry["data"])
        s19 = S19File(str(CORPUS / entry["name"]))
        # Both builders walk the same predicate (internal consistency, all files).
        assert build_mem_map_s19(s19) == s19.get_memory_map(), entry["name"]
        # Manifest equality: the defect files' trailing/overlap bytes are the
        # HLR-154 population; here the manifest-declared bytes must be present.
        built = build_mem_map_s19(s19)
        if entry["verdict"] == "ok":
            assert built == expected, entry["name"]
        else:
            assert all(built.get(a) == b for a, b in expected.items()), (
                entry["name"]
            )
        ranges = s19.get_memory_ranges()
        validity = build_range_validity_s19(s19, ranges)
        assert len(validity) == len(ranges), entry["name"]
        # Every corpus record is structurally valid: no range may flag invalid.
        assert validity == [True] * len(ranges), entry["name"]
        checked += 1
    assert checked == 10

    # S0-only file: empty map, empty validity (the empty-image boundary).
    s19 = S19File(str(CORPUS / "synth_s0_only.s19"))
    assert build_mem_map_s19(s19) == {}
    assert build_range_validity_s19(s19, []) == []

    # Checksum-defective example bytes still flag their ranges invalid.
    bad = next(p for p in EXAMPLE_S19 if "bad_checksums" in str(p))
    s19 = S19File(str(bad))
    validity = build_range_validity_s19(s19, s19.get_memory_ranges())
    assert len(validity) == len(s19.get_memory_ranges())
    assert any(v is False for v in validity)


# --------------------------------------------------------------------------- #
# TC-B99-06 — LLR-153.3: written images carry S0 as header only
# --------------------------------------------------------------------------- #


def test_tc_b99_06_written_images_carry_s0_as_header_only(tmp_path):
    """Round-trip every corpus S19 and every example S19 through
    ``save_patched_image`` (S19 and Intel HEX arms) and re-read the written
    file with the independent reader: data bytes identical, zero extra
    addresses, S0 text preserved as a header record."""
    sources = [
        CORPUS / e["name"]
        for e in _manifest()["files"]
        if e["format"] == "s19" and e["verdict"] == "ok"
    ]
    sources += EXAMPLE_S19
    checked = 0
    for src in sources:
        oracle = read_s19(src)
        s19 = S19File(str(src))
        mem_map = s19.get_memory_map()
        ranges = s19.get_memory_ranges()
        header = _s0_record(s19)
        s0_header = bytes(header.data) if header is not None else None

        dest = tmp_path / f"case_{checked}" / ".s19tool" / "workarea" / "proj"
        dest.mkdir(parents=True)

        out, issues = save_patched_image(
            mem_map,
            ranges,
            dest,
            "roundtrip.s19",
            source_kind="s19",
            s0_header=s0_header,
        )
        assert out is not None and not issues, f"{src.name}: {issues}"
        written = read_s19(out)
        # The written image is exactly the loaded image — no address beyond
        # what the source declared in a data record (S0 payload excluded by
        # the LLR-153.1 predicate).  Well-formed sources must round-trip the
        # independent reader's bytes EXACTLY (the LLR-153.3 mutation arm); a
        # checksum-defective data record is carried by the loader but skipped
        # by the reader, so those two sources assert reader bytes as a
        # preserved subset.
        if oracle.errors:
            # The loader carries the checksum-defective record's bytes, the
            # reader skips them: every written byte beyond the reader's image
            # must live inside a defective record's addresses (review finding
            # F5 — without this bound the S0 re-admission mutation regains
            # 0x0..0xB on these two files and this arm stays GREEN).
            defective = _defective_record_addresses(src)
            assert set(written.data) - set(oracle.data) <= defective, (
                src.name
            )
            assert all(written.data.get(a) == b for a, b in oracle.data.items()), (
                src.name
            )
        else:
            assert written.data == oracle.data, src.name
        assert not any(a <= 0xB and a not in mem_map for a in written.data), (
            src.name
        )
        if oracle.header is None:
            # Sources without an S0 keep the emitter's legacy empty header
            # record — never data at an undeclared address.
            assert written.header in (None, b""), src.name
        else:
            assert written.header == oracle.header, src.name
        assert written.eof_seen, src.name

        out_hex, issues = save_patched_image(
            mem_map,
            ranges,
            dest,
            "roundtrip.hex",
            source_kind="hex",
        )
        assert out_hex is not None and not issues, f"{src.name}: {issues}"
        written_hex = read_hex(out_hex)
        assert written_hex.data == mem_map, src.name
        if oracle.errors:
            assert all(
                written_hex.data.get(a) == b for a, b in oracle.data.items()
            ), src.name
        else:
            assert written_hex.data == oracle.data, src.name
        assert written_hex.eof_seen, src.name
        checked += 1
    # 6 well-formed corpus S19 + 16 example S19.
    assert checked == 22


# --------------------------------------------------------------------------- #
# TC-B99-07 — LLR-153.4: a patch at the S0 address is outside the image
# --------------------------------------------------------------------------- #


def _one_entry_document(address: int, run: tuple[int, ...]) -> ChangeDocument:
    return ChangeDocument(
        format="s19app-changeset",
        version="2.0",
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=[ChangeEntry("bytes", address, run)],
    )


def test_tc_b99_07_patch_at_s0_address_is_outside():
    """case_01: an entry at 0x0 (and at the last S0 payload address) is
    ``skipped-outside`` and writes nothing at 0x0."""
    s19 = S19File(str(CASE01))
    header = _s0_record(s19)
    assert header is not None and header.address == 0x0

    for address in (0x0, header.address + len(header.data) - 1):
        mem_map = s19.get_memory_map()
        ranges = s19.get_memory_ranges()
        summary = apply_change_document(
            _one_entry_document(address, (0xAA, 0xBB)),
            mem_map,
            ranges,
            None,
            None,
        )
        assert summary.entries[0].disposition == "skipped-outside", hex(address)
        assert summary.counts["skipped-outside"] == 1, hex(address)
        assert summary.counts["applied"] == 0, hex(address)
        assert address not in mem_map, hex(address)


# --------------------------------------------------------------------------- #
# AT-B99-02 — US-142: black-box pilot through the TUI
# --------------------------------------------------------------------------- #


def _status_text(app: S19TuiApp) -> str:
    """The painted newest status line (the ``#log_line_4`` label)."""
    from textual.widgets import Label

    return str(app.query_one("#log_line_4", Label).render())


def _painted_text(app: S19TuiApp) -> str:
    """The painted screen as text: the SVG export's ``<text>`` elements
    joined (the snapshot idiom).  Entities stay escaped (spaces export as
    ``&#160;``), so match single space-free words such as ``patched``."""
    svg = app.export_screenshot()
    return "".join(re.findall(r"<text[^>]*>(.*?)</text>", svg, re.S))


async def _wait_for(pilot, predicate, description: str, attempts: int = 100):
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


def test_at_b99_02_save_back_excludes_s0(tmp_path):
    """Load case_01 through the dialog, rewrite in-image bytes, save back:
    the independent reader sees no byte at 0x0..0xB and identical data;
    the Memory Map lists no row carrying 0x00000000; a document whose only
    entry is at 0x0 shows that entry as skipped in the status line.

    The whole drive is keys and clicks (review finding F2): inputs are
    focused with ``pilot.click`` and typed with ``pilot.press``, buttons are
    clicked, and every wait observes the painted status line or the painted
    screen (``export_screenshot``) — never an internal attribute.
    """
    from textual.widgets import Button, Input

    src = tmp_path / "firmware.s19"
    shutil.copy(CASE01, src)
    oracle = read_s19(src)

    app = S19TuiApp(base_dir=tmp_path)

    async def _drive():
        # 54 rows: the Patch Editor's docked save-back row sits at the foot
        # of the JSON pane and is only clickable/painted at the taller
        # viewport (the b97 ATs drive the panel at 118x54 for the same row).
        async with app.run_test(size=(120, 54)) as pilot:
            await pilot.pause()

            async def _type(input_id: str, text: str) -> None:
                assert await pilot.click(f"#{input_id}"), (
                    f"click missed #{input_id}"
                )
                await pilot.press(*text)
            # 1. Load through the Load file dialog (rail key ``l``).
            await pilot.press("l")
            for _ in range(6):
                await pilot.pause()
            # The dialog is a pushed screen: click/type inside ``app.screen``.
            await _type("load_path", str(src))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            await _wait_for(
                pilot,
                lambda: "Loaded firmware.s19" in _status_text(app),
                "load status line",
            )

            # 2. Patch Editor (rail key ``6``): one entry rewriting the two
            #    bytes already at the first data address (identity rewrite).
            await pilot.press("6")
            for _ in range(6):
                await pilot.pause()
            addr = min(oracle.data)
            rewritten = [oracle.data[addr], oracle.data[addr + 1]]
            await _type("patch_entry_address_input", f"0x{addr:X}")
            await _type(
                "patch_entry_bytes_input",
                " ".join(f"0x{b:02X}" for b in rewritten),
            )
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
                lambda: "Apply:" in _status_text(app),
                "apply status line",
            )
            assert "1 applied, 0 skipped, 0 blocked" in _status_text(app)

            # 3. Save-back (offered after the applied entry, premise P-23).
            #    The prompt renders in the editor's JSON pane: pick that tab
            #    by clicking its chip, then wait for the prompt's label to be
            #    PAINTED on the screen (the row reveal), instead of reading
            #    a CSS class.
            assert await pilot.click("#patch_tab_json"), (
                "click missed #patch_tab_json"
            )
            await _wait_for(
                pilot,
                lambda: "patched" in _painted_text(app),
                "save-back prompt painted",
            )
            # The prompt pre-fills the name: select all, replace by typing.
            assert await pilot.click(
                "#patch_saveback_name_input"
            ), "click missed #patch_saveback_name_input"
            await pilot.press("ctrl+shift+a")
            await pilot.press(*"at_b99_02.s19")
            assert await pilot.click(
                "#patch_saveback_confirm_button"
            ), "click missed #patch_saveback_confirm_button"
            target = None
            for _ in range(100):
                candidates = sorted(tmp_path.rglob("at_b99_02.s19"))
                if candidates:
                    target = candidates[0]
                    break
                await pilot.pause(0.05)
            assert target is not None, "save-back wrote no file"

            written = read_s19(target)
            assert not any(a <= 0xB for a in written.data), (
                f"bytes at 0x0..0xB: {sorted(a for a in written.data if a <= 0xB)}"
            )
            assert written.data == oracle.data
            assert written.header == oracle.header

            # 4. Memory Map (rail key ``4``): no row carries 0x00000000.
            #    Every row starts with a band glyph (``░ 0x00000000 …``), so
            #    a startswith probe can never fire (review finding F1) — the
            #    address must be matched as a word anywhere in the row.  The
            #    rows fill without an explicit ``update_memory_map()`` call.
            await pilot.press("4")
            rows = []
            for _ in range(100):
                await pilot.pause()
                rows = [
                    str(r.render()).strip()
                    for r in app.query(".map-region-row")
                ]
                if rows:
                    break
            assert rows, "Memory Map lists no regions"
            assert not any(
                re.search(r"\b0x00000000\b", r) for r in rows
            ), rows

            # 5. A document whose only entry is at 0x0: skipped in the
            #    status line.  Reload the Patch Editor and replace the
            #    document with the 0x0-only one through the doc-load path.
            await pilot.press("6")
            for _ in range(6):
                await pilot.pause()
            doc_path = tmp_path / "only_s0_entry.json"
            doc_path.write_text(
                json.dumps(
                    {
                        "format": "s19app-changeset",
                        "version": "2.0",
                        "kind": "change",
                        "encoding": "utf-8",
                        "value_mode": "text",
                        "entries": [
                            {
                                "type": "bytes",
                                "address": "0x0",
                                "bytes": "AA BB",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            await _type("patch_doc_path_input", str(doc_path))
            assert await pilot.click(
                "#patch_doc_load_button"
            ), "click missed #patch_doc_load_button"
            # The added entry left the draft dirty (LLR-005.1 w1): Load asks
            # first — the operator accepts the loss on the guard modal.
            for _ in range(20):
                await pilot.pause()
                if type(app.screen).__name__ == "LoadGuardScreen":
                    break
            assert type(app.screen).__name__ == "LoadGuardScreen"
            # The modal is pushed before it is composed; wait for its accept
            # button to be painted, then click it.
            await _wait_for(
                pilot,
                lambda: "loss" in _painted_text(app),
                "guard modal painted",
            )
            assert await pilot.click(
                "#load_guard_accept"
            ), "click missed #load_guard_accept"
            await _wait_for(
                pilot,
                lambda: "1 entry" in _status_text(app),
                "document load status line",
            )
            previous = _status_text(app)
            assert await pilot.click(
                "#patch_doc_apply_button"
            ), "click missed #patch_doc_apply_button"
            await _wait_for(
                pilot,
                lambda: _status_text(app) != previous,
                "second apply status line",
            )
            status = _status_text(app)
            assert "0 applied, 1 skipped, 0 blocked" in status, status

    asyncio.run(_drive())
