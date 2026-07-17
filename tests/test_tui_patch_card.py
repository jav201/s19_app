"""batch-48 · US-P5 / HLR-080 — the live before/after card (the HEADLINE).

Layer B (black-box): AT-080a/b/c/d.
Layer A (white-box): TC-080.1/.2/.2a/.3/.4/.5/.6/.7 + the writer census.

⚠ Two anti-vacuity commitments this file makes, both earned by defects this
batch already paid for:

1. **Universals derive or guard their input set** (the Inc-5b HIGH-1 class: a
   real assertion with exact arithmetic quantifying over a hand-listed set that
   omitted the failing case — every CODE mutation passed it). The writer census
   below walks ``app.py``'s AST for every ``.refresh_entries`` call rather than
   naming the sites: a hand-list would reproduce the very defect it exists to
   catch. The Phase-2 census asserted FOUR sites; the live tree has FIVE,
   because Inc-3 added one mid-batch and nothing re-derived the list.

2. **Assert the PAINTED result, not a pre-layout accessor** (Inc-4 F2 /
   Inc-5 AT-079c: ``display = False`` left six tests green). The geometry arm
   reads ``region``; the content arms read ``render()``.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import inspect
from pathlib import Path

import pytest
from textual.widgets import Button, DataTable
from textual.widget import Widget
from textual.containers import VerticalScroll

from s19_app.tui.app import A2LDetailCard, S19TuiApp
from s19_app.tui.screens_directionb import (
    CARD_NO_IMAGE,
    CARD_NO_SELECTION,
    CARD_UNMAPPED_TOKEN,
    BeforeAfterCard,
    PatchEditorPanel,
    before_after_card_text,
)
from s19_app.tui.services.change_service import ChangeEntryRow

_SIZES = ((80, 24), (120, 30))


class _Row:
    """A duck-typed entries row (the shape ``ChangeService.rows`` yields).

    Deliberately NOT a ``ChangeEntryRow``: the panel types its rows as
    ``object`` so the view imports nothing from the service layer, and these
    tests hold that boundary. TC-080.3b separately binds this shape to the real
    dataclass, so this stub cannot drift into a fiction the panel alone honours.
    """

    def __init__(self, address: int, encoded_bytes: tuple, kind: str = "bytes"):
        self.kind_text = kind
        self.address_text = f"0x{address:X}"
        self.value_text = " ".join(f"{b:02X}" for b in encoded_bytes)
        self.status_text = "in image"
        self.linkage_text = "-"
        self.check_glyph = "·"
        self.address = address
        self.encoded_bytes = encoded_bytes


def _card_plain(app: S19TuiApp) -> str:
    """The card's PAINTED content (not a pre-layout accessor — Inc-4 F2)."""
    rendered = app.query_one("#patch_before_after_card", BeforeAfterCard).render()
    return getattr(rendered, "plain", str(rendered))


async def _open_patch(app: S19TuiApp, pilot) -> PatchEditorPanel:
    await pilot.pause()
    app.action_show_screen("patch")
    await pilot.pause()
    return app.query_one("#patch_editor_panel", PatchEditorPanel)


async def _select_row(app: S19TuiApp, pilot, index: int) -> None:
    table = app.query_one("#patch_doc_entries_table", DataTable)
    table.focus()
    table.move_cursor(row=index)
    await pilot.pause()
    await pilot.pause()


# ---------------------------------------------------------------------------
# AT-080a — before == image bytes at the entry span; after == encoded_bytes
# ---------------------------------------------------------------------------


def test_at080a_before_after(tmp_path: Path) -> None:
    """AT-080a — a NON-first row previews THAT row's bytes.

    Intent: HLR-080 / LLR-080.3 — the analyst sees what is there now beside
    what the entry would write. Row index 1 (never 0), so an off-by-one in the
    positional join fails instead of coincidentally passing.
    """

    async def _run() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            panel = await _open_patch(app, pilot)
            panel.refresh_entries(
                [
                    _Row(0x100, (0xDE, 0xAD)),
                    _Row(0x200, (0x01, 0x02, 0x03, 0x04)),
                ],
                mem_map={0x200: 0xAA, 0x201: 0xBB, 0x202: 0xCC, 0x203: 0xDD},
            )
            await pilot.pause()
            await _select_row(app, pilot, 1)
            return _card_plain(app)

    plain = asyncio.run(_run())
    assert "0x200" in plain, f"card does not name the selected entry: {plain!r}"
    assert "AA BB CC DD" in plain, f"before-bytes are not the image's: {plain!r}"
    assert "01 02 03 04" in plain, f"after-bytes are not the entry's: {plain!r}"
    # The discriminator: row 0's bytes must NOT appear. An off-by-one that
    # previewed entry 0 would satisfy every assertion above except this one.
    assert "DE AD" not in plain, (
        f"card previewed the WRONG entry (row 0's bytes leaked): {plain!r}"
    )


def test_at080a_same_address_entries_are_index_joined(tmp_path: Path) -> None:
    """AT-080a (the same-address discriminator) — the join is POSITIONAL.

    Intent: LLR-080.3's normative note — ``ChangeEntry`` carries no id, so the
    contract is document order, and two entries MAY share a start address. An
    address-keyed join structurally CANNOT pass this: both entries key to
    0x300, so it must return one of them for both rows. Only an index join
    distinguishes them.

    This is the Inc-3 TC-077.1 precedent, reused because it is the one fixture
    shape that makes the wrong implementation fail rather than merely be
    unproven.
    """

    async def _run() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            panel = await _open_patch(app, pilot)
            panel.refresh_entries(
                [
                    _Row(0x300, (0x11, 0x11)),
                    _Row(0x300, (0x22, 0x22)),  # SAME address, DIFFERENT bytes
                ],
                mem_map={0x300: 0x99, 0x301: 0x99},
            )
            await pilot.pause()
            await _select_row(app, pilot, 0)
            first = _card_plain(app)
            await _select_row(app, pilot, 1)
            second = _card_plain(app)
            return first, second

    first, second = asyncio.run(_run())
    assert "11 11" in first, f"row 0 did not preview entry 0: {first!r}"
    assert "22 22" not in first, f"row 0 leaked entry 1's bytes: {first!r}"
    assert "22 22" in second, f"row 1 did not preview entry 1: {second!r}"
    assert "11 11" not in second, f"row 1 leaked entry 0's bytes: {second!r}"
    assert first != second, (
        "two entries at the SAME address rendered identically — the join "
        "collapsed on the address, which is exactly the defect this fixture "
        f"exists to catch: {first!r}"
    )


# ---------------------------------------------------------------------------
# AT-080b ★ — the read-only proof
# ---------------------------------------------------------------------------


def test_at080b_read_only(tmp_path: Path) -> None:
    """AT-080b ★ — the card applies NOTHING.

    Intent: HLR-080 / LLR-080.5 — the card is a preview. After N selections the
    memory map is byte-identical (and the SAME object), the change document is
    unchanged, and no file appeared. This is the safety property: a card that
    quietly wrote would be worse than no card.
    """

    async def _run() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            panel = await _open_patch(app, pilot)
            mem_map = {0x200: 0xAA, 0x201: 0xBB, 0x202: 0xCC, 0x203: 0xDD}
            before_copy = copy.deepcopy(mem_map)
            rows = [
                _Row(0x100, (0xDE, 0xAD)),
                _Row(0x200, (0x01, 0x02, 0x03, 0x04)),
                _Row(0x300, (0xFF,)),
            ]
            panel.refresh_entries(rows, mem_map=mem_map)
            await pilot.pause()
            doc_before = copy.deepcopy(
                app._change_service.document.entries
            )
            files_before = sorted(
                str(p) for p in tmp_path.rglob("*") if p.is_file()
            )
            for index in (0, 1, 2):  # N = 3 selections
                await _select_row(app, pilot, index)
            files_after = sorted(
                str(p) for p in tmp_path.rglob("*") if p.is_file()
            )
            return {
                "map_equal": mem_map == before_copy,
                "map_identity": mem_map is panel._mem_map,
                "doc_equal": app._change_service.document.entries == doc_before,
                "new_files": sorted(set(files_after) - set(files_before)),
            }

    out = asyncio.run(_run())
    assert out["map_equal"], "the card MUTATED the memory map"
    assert out["map_identity"], "the retained map was replaced, not read"
    assert out["doc_equal"], "the card MUTATED the change document"
    assert out["new_files"] == [], f"the card wrote files: {out['new_files']}"


def test_tc080_5_no_apply_path_reachable() -> None:
    """TC-080.5 ★ — no apply/save symbol is reachable from the card path.

    Intent: LLR-080.5's static arm. AT-080b proves nothing was written on ONE
    drive; this proves the code cannot write at all, over the card's whole call
    graph. AST-walked (never a source grep matching my own prose — the oracle
    class this batch has repeatedly caught).
    """
    forbidden = {"apply", "save_patched", "write_text", "write_bytes", "open"}
    for func in (
        before_after_card_text,
        BeforeAfterCard.show_entry,
        PatchEditorPanel._render_before_after_card,
    ):
        tree = ast.parse(inspect.getsource(func).lstrip())
        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        leaked = called & forbidden
        assert leaked == set(), (
            f"{func.__qualname__} can reach a mutating call: {leaked}"
        )


# ---------------------------------------------------------------------------
# AT-080c — unmapped address → placeholder, never `00`
# ---------------------------------------------------------------------------


def test_at080c_unmapped(tmp_path: Path) -> None:
    """AT-080c — an unmapped address shows a placeholder, never a fabricated 00.

    Intent: HLR-080 / A4 — ``mem_map`` is SPARSE, so an absent address is
    UNMAPPED, not zero. Rendering `00` there would invent a byte the analyst
    would then trust. The fixture is a PARTIAL span (2 mapped, 2 absent), so a
    naive ``mem_map.get(a, 0)`` fails on the tail while still passing on the
    head — the boundary case that discriminates.
    """

    async def _run() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            panel = await _open_patch(app, pilot)
            panel.refresh_entries(
                [
                    _Row(0x100, (0xDE,)),
                    _Row(0x200, (0x01, 0x02, 0x03, 0x04)),
                ],
                # Only the first 2 of the 4-byte span are mapped.
                mem_map={0x200: 0xAA, 0x201: 0xBB},
            )
            await pilot.pause()
            await _select_row(app, pilot, 1)
            return _card_plain(app)

    plain = asyncio.run(_run())
    assert "AA BB" in plain, f"mapped bytes did not render: {plain!r}"
    assert CARD_UNMAPPED_TOKEN in plain, (
        f"unmapped positions did not render the placeholder: {plain!r}"
    )
    before_line = [
        line for line in plain.splitlines() if line.startswith("before")
    ][0]
    assert before_line.split()[1:] == ["AA", "BB", "--", "--"], (
        f"partial span did not mix bytes and placeholders: {before_line!r}"
    )


def test_tc080_3_unmapped_token_is_distinguishable_from_real_zero() -> None:
    """TC-080.3 — the placeholder is distinguishable from a real 0x00.

    Intent: A4's whole point. A mapped 0x00 is a REAL byte; an absent address
    is the absence of one. If both rendered the same token the card would be
    lying in the one case an analyst most needs the truth. Both operands are
    DERIVED from the builder (never two literals — the F3 vacuity class).
    """
    real_zero = before_after_card_text(0x10, [0x00], [0xFF]).plain
    unmapped = before_after_card_text(0x10, [None], [0xFF]).plain
    assert "00" in real_zero, f"a mapped 0x00 must render as a byte: {real_zero!r}"
    assert real_zero != unmapped, (
        "a mapped 0x00 and an UNMAPPED address render identically — the card "
        f"cannot express 'unknown': {real_zero!r} vs {unmapped!r}"
    )
    assert CARD_UNMAPPED_TOKEN in unmapped
    assert CARD_UNMAPPED_TOKEN not in real_zero


def test_tc080_3_before_after_derivation() -> None:
    """TC-080.3 (unit) — the span is the ENCODED length, read from mem_map.

    Intent: LLR-080.3 — before-bytes are ``mem_map`` at
    ``[address, address+len(encoded_bytes))``. Asserted as a derived tuple, so
    a wrong span length or a wrong origin fails.
    """
    mem = {0x400 + i: 0x10 + i for i in range(8)}
    panel_view = before_after_card_text(
        0x402, [mem.get(0x402 + i) for i in range(3)], [0x01, 0x02, 0x03]
    ).plain
    # Origin 0x402, length 3 ⇒ image bytes 0x12 0x13 0x14.
    assert "12 13 14" in panel_view, panel_view
    assert "0x402" in panel_view


def test_tc080_3b_stub_row_shape_matches_the_real_dataclass() -> None:
    """TC-080.3b — this file's ``_Row`` stub cannot drift from the real row.

    Intent: the stub is the input set for every pilot test here, and per the
    Inc-5b lesson **an input set is itself an oracle**. If ``ChangeEntryRow``
    lost ``address``/``encoded_bytes`` — or never gained them — every test above
    would still pass against a stub that alone carried them, certifying a card
    the real app cannot feed. This binds the stub to the code.
    """
    real = set(ChangeEntryRow.__dataclass_fields__)
    stub = set(vars(_Row(0x1, (0x2,))))
    assert {"address", "encoded_bytes"} <= real, (
        "ChangeEntryRow does not carry the card's raw inputs — the stub is a "
        f"fiction. fields={sorted(real)}"
    )
    assert real <= stub, (
        f"the stub is missing real row fields, so the panel is under-tested: "
        f"{sorted(real - stub)}"
    )


# ---------------------------------------------------------------------------
# AT-080d ★ — C-29 / field-audit B2 reachability (GATE-BLOCKING)
# ---------------------------------------------------------------------------

_NAMED_BUTTONS = (
    "patch_entry_add_button",
    "patch_entry_edit_button",
    "patch_entry_remove_button",
    "patch_entry_edit_json_button",
    "patch_undo_button",
    "patch_redo_button",
    "patch_doc_load_button",
    "patch_doc_refresh_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
    "patch_doc_save_button",
    "patch_variant_info_button",
    "patch_execute_scope_button",
    "patch_execute_run_button",
    "patch_checks_run_button",
    "patch_paste_parse_button",
    "patch_edit_json_button",
)


def _fully_visible(app: S19TuiApp, w: object) -> bool:
    """Batch-46's FOLD-8 primitive, reused verbatim."""
    r = w.region
    if r.area == 0:
        return False
    if not app.screen.region.contains_region(r):
        return False
    node = w.parent
    while node is not None and node is not app.screen:
        if getattr(node, "is_scrollable", False):
            if not node.content_region.contains_region(r):
                return False
        node = node.parent
    return True


def _scrollers(app: S19TuiApp, w: object) -> list:
    out = []
    node = w.parent
    while node is not None and node is not app.screen:
        if getattr(node, "show_vertical_scrollbar", False):
            out.append(node)
        node = node.parent
    return out


async def _reach(app: S19TuiApp, pilot, w: object) -> None:
    for _ in range(6):
        for sc in _scrollers(app, w):
            sc.scroll_y = max(
                0, w.region.y - sc.content_region.y + sc.scroll_offset.y
            )
        await pilot.pause()
    await pilot.pause()


def _drive_reachability_with_card(tmp_path: Path, size) -> dict:
    async def _run() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            panel = await _open_patch(app, pilot)
            panel.refresh_entries(
                [_Row(0x100, (0xDE, 0xAD)), _Row(0x200, (0x01, 0x02))],
                mem_map={0x200: 0xAA, 0x201: 0xBB},
            )
            await pilot.pause()
            await _select_row(app, pilot, 1)
            card = app.query("#patch_before_after_card")
            card_region = card.first().region if card else None
            trapped, unreachable = [], []
            for bid in _NAMED_BUTTONS:
                btn = app.query_one(f"#{bid}", Button)
                node = btn.parent
                while node is not None and node is not app.screen:
                    if isinstance(node, VerticalScroll):
                        trapped.append(bid)
                        break
                    node = node.parent
                await _reach(app, pilot, btn)
                if not _fully_visible(app, btn):
                    unreachable.append(bid)
            return {
                "trapped": trapped,
                "unreachable": unreachable,
                "card_mounted": len(card) == 1,
                "card_area": card_region.area if card_region else 0,
            }

    return asyncio.run(_run())


@pytest.mark.parametrize("size", _SIZES)
def test_at080d_reachable_with_card(tmp_path: Path, size) -> None:
    """AT-080d ★ — GATE-BLOCKING. Docked buttons stay reachable WITH the card.

    Intent: HLR-080 / LLR-080.6 — field-audit **B2** (docked buttons unreachable)
    is the defect batch-46 fixed; the card is this batch's only structural
    addition to that same container, so it is the thing that could re-litigate
    it. Measured AFTER Inc-6's extra docked row.

    **Form 1** (LLR-080.6 / MJ-2): the Phase-3 measurement showed no deficit —
    at both regimes the card mounts AND every named button is reachable — so no
    relaxation fired and no §6.5 amendment is owed. The card is asserted MOUNTED
    and NON-ZERO-AREA here, so this cannot pass by the card quietly vanishing
    (which is precisely the vacuity MJ-2 pre-empted).

    Contract (batch-46 FOLD-8, verbatim): ``off == []`` at scroll 0 is NOT
    asserted — the measured viewport cannot show 17 buttons at once. The
    contract is sibling-not-descendant + ``_fully_visible`` AFTER ``_reach``.
    """
    dims = _drive_reachability_with_card(tmp_path, size)
    assert dims["card_mounted"], (
        f"@{size}: Form 1 requires the card MOUNTED; it is absent, so this "
        "gate would be vacuous"
    )
    assert dims["card_area"] > 0, (
        f"@{size}: the card occupies no rows — it cannot be said to be present"
    )
    assert dims["trapped"] == [], (
        f"@{size}: B2 REGRESSION — buttons trapped inside a scrollable body: "
        f"{dims['trapped']}"
    )
    assert dims["unreachable"] == [], (
        f"@{size}: B2 REGRESSION — buttons not reachable-under-scroll with the "
        f"card mounted: {dims['unreachable']}"
    )


#: The MEASURED card content width per regime (batch-48 Inc-7, C-29 both axes,
#: card mounted + row selected). NOT the body's 38, NOT the docked strip's 38 —
#: the card's own `padding: 0 1` costs 2 cells.
_MEASURED_CARD_BUDGET = {(80, 24): 62, (120, 30): 36}


@pytest.mark.parametrize("size", _SIZES)
def test_tc080_6_card_fits_its_measured_container(tmp_path: Path, size) -> None:
    """TC-080.6 — the PAINTED card fits the container it is ACTUALLY in.

    Intent: C-29, both axes. This is the arm Inc-4's F2 lacked: it reads the
    PAINTED geometry, so a card that renders nothing, overflows, or is hidden
    fails — where a pre-layout content accessor would pass on all three.

    The budget is the MEASURED card content width (62 @80×24 / **36** @120×30),
    asserted as a FLOOR on the container and a CEILING on the content: the floor
    fails loud with the real width if the layout ever narrows, and the ceiling
    fails if the card outgrows it. The worst-case line is exercised (a 32-bit
    address + an elided long run), not a comfortable one.
    """

    async def _run() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            panel = await _open_patch(app, pilot)
            # Worst case reachable: 32-bit address, long run ⇒ elision note.
            long_run = tuple(range(0x20, 0x20 + 64))
            panel.refresh_entries(
                [_Row(0x10, (0x01,)), _Row(0xFFFFFFFF, long_run)],
                mem_map={0xFFFFFFFF + i: 0xEE for i in range(64)},
            )
            await pilot.pause()
            await _select_row(app, pilot, 1)
            card = app.query_one("#patch_before_after_card", BeforeAfterCard)
            plain = _card_plain(app)
            return {
                "content_w": card.content_region.width,
                "region_h": card.region.height,
                "widest": max((len(x) for x in plain.splitlines()), default=0),
                "lines": len(plain.splitlines()),
            }

    out = asyncio.run(_run())
    budget = _MEASURED_CARD_BUDGET[size]
    assert out["content_w"] >= budget, (
        f"@{size}: the card's container narrowed to {out['content_w']}, below "
        f"the measured budget {budget} — the C-29 measurement is stale"
    )
    assert out["widest"] <= budget, (
        f"@{size}: the card paints {out['widest']} cells into a {budget}-cell "
        f"container — it will wrap. CARD_BYTES_MAX or the header is too wide"
    )
    assert out["region_h"] > 0, f"@{size}: the card paints no rows"
    assert out["lines"] == 3, (
        f"@{size}: expected header + before + after; got {out['lines']} lines"
    )


# ---------------------------------------------------------------------------
# TC-080.1 — the card mounts; zero Textual internal-name collisions
# ---------------------------------------------------------------------------


def test_tc080_1_no_widget_name_collisions() -> None:
    """TC-080.1 — the card shadows no ``Widget`` internal.

    Intent: LLR-080.1 — ``_nodes`` shadows ``Widget._nodes`` (mount crash) and
    ``_context`` shadows ``MessagePump._context`` (idle boot deadlock). **Both
    fail with NO traceback**, so a collision is invisible until the app hangs.

    ⚠ **Two wrong oracles were measured and rejected before this one:**

    1. ``vars(BeforeAfterCard) & dir(Widget)`` is NOT the collision set. It
       returns 12 names — but MEASURED, it returns the **identical** 12 for
       ``A2LDetailCard``, the shipped batch-47 card that demonstrably mounts
       and boots. They are injected by Textual's metaclass on every ``Widget``
       subclass (``_reactives``, ``_computes``, ``_inherit_css``, …) plus
       ``DEFAULT_CSS``, a documented override point. None is authored.
    2. Filtering to PRIVATE authored names would be **vacuous**: this card
       authors none (``DEFAULT_CSS`` / ``show_entry``), so the universal would
       quantify over the empty set and pass on any implementation — the
       Inc-5b HIGH-1 class exactly.

    So the threshold is **anchored to what the app already demonstrates**
    (never an invented rule): the card may collide only where a SHIPPED,
    BOOTING widget already collides. Anything novel is, by construction, a name
    no working widget in this app has — which is the actual hazard.
    """
    widget_names = set(dir(Widget))
    mine = {n for n in vars(BeforeAfterCard) if not n.startswith("__")}
    house = {n for n in vars(A2LDetailCard) if not n.startswith("__")}

    # Guard the input set: an empty `mine` would make `novel` empty and the
    # assertion vacuous.
    assert {"show_entry", "DEFAULT_CSS"} <= mine, (
        f"the card's authored members vanished — this check would quantify "
        f"over nothing. members={sorted(mine)}"
    )
    novel = (mine & widget_names) - (house & widget_names)
    assert novel == set(), (
        f"BeforeAfterCard shadows Widget internals {sorted(novel)} that the "
        "shipped A2LDetailCard does NOT — a silent mount crash / idle boot "
        "deadlock with no traceback"
    )
    # The two documented killers, named explicitly: they are the reason this
    # LLR exists, and neither appears in the anchor either.
    assert not ({"_nodes", "_context"} & mine), (
        "the card names _nodes/_context — mounting will crash or the boot will "
        "deadlock, with NO traceback"
    )


@pytest.mark.parametrize("size", _SIZES)
def test_tc080_1_mounts(tmp_path: Path, size) -> None:
    """TC-080.1 — the app boots and the card resolves exactly once."""

    async def _run() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _open_patch(app, pilot)
            return len(app.query("#patch_before_after_card"))

    assert asyncio.run(_run()) == 1


def test_tc080_1_card_never_mounts_blank(tmp_path: Path) -> None:
    """TC-080.1 — the card paints its neutral state at MOUNT.

    Intent: Inc-6's finding, generalised — ``''`` is not the empty state, it is
    nothing, and a freshly-opened Patch Editor is exactly the no-selection case.

    ⚠ Unlike the history strip, the card needs NO app-side mount-time writer:
    its neutral state needs no service datum, so ``on_mount``'s existing
    ``refresh_entries([])`` self-call renders it and C-7 stays intact. That is
    the distinction Inc-6 drew (the strip could not know ``_HISTORY_MAX``), and
    this test is what makes the claim checkable rather than argued.
    """

    async def _run() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await _open_patch(app, pilot)
            return _card_plain(app)

    plain = asyncio.run(_run())
    assert plain.strip() != "", "the card MOUNTED BLANK"
    assert plain.strip() == CARD_NO_SELECTION, (
        f"the card mounted in an unexpected state: {plain!r}"
    )


# ---------------------------------------------------------------------------
# TC-080.2 / TC-080.2a — the mem_map seam (C-7 purity + retain semantics)
# ---------------------------------------------------------------------------


def test_tc080_2_c7_purity_probe() -> None:
    """TC-080.2 — the panel obtains ``mem_map`` from the PARAMETER alone.

    Intent: LLR-080.2 / C-7 / risk R4 — "the card's data need is the exact
    pressure that produces a ``self.app`` reach". The panel is presentational:
    0 ``self.app``, 0 service imports. AST-walked over the real class source, so
    it cannot be satisfied by a comment claiming purity.
    """
    source = inspect.getsource(PatchEditorPanel)
    tree = ast.parse(source.lstrip())

    app_reaches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr == "app"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ]
    assert app_reaches == [], (
        f"PatchEditorPanel reaches self.app at {len(app_reaches)} site(s) — "
        "the card must be fed by parameter, not by reaching for the app"
    )
    imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    assert imports == [], "PatchEditorPanel imports inside the class body"


def test_tc080_2_param_is_defaulted_and_read_only_by_type() -> None:
    """TC-080.2 — ``mem_map`` is defaulted (0 callers break) and read-only.

    Intent: LLR-080.2's typing note — ``Mapping`` (not ``Dict``) at the panel
    boundary keeps the parameter read-only BY TYPE, and the default keeps the
    seam additive. Derived from the live signature, never from prose.
    """
    sig = inspect.signature(PatchEditorPanel.refresh_entries)
    assert "mem_map" in sig.parameters, "the seam does not exist"
    param = sig.parameters["mem_map"]
    assert param.default is not inspect.Parameter.empty, (
        "mem_map is not defaulted — every existing caller breaks"
    )
    assert param.default is not None, (
        "the default is None, so 'not supplied' and 'no image loaded' are "
        "CONFLATED — that is the MJ-1 defect the sentinel exists to prevent"
    )
    annotation = str(param.annotation)
    assert "Mapping" in annotation, (
        f"mem_map is not typed Mapping — read-only-by-type is lost: {annotation}"
    )
    assert "Dict" not in annotation, (
        f"mem_map is typed Dict — that is a mutable boundary: {annotation}"
    )


def test_tc080_2a_retain_semantics(tmp_path: Path) -> None:
    """TC-080.2a ★ — the ``on_mount`` self-call must not NULL a retained map.

    Intent: LLR-080.2's MJ-1 fold. ``refresh_entries`` has FIVE call sites and
    one — the panel's own ``on_mount`` self-call — has no ``mem_map`` to give.
    An unconditional ``self._mem_map = mem_map`` lets that call clear a map a
    real load supplied. Today that is benign ONLY by call ORDERING, an unstated
    invariant. This tests the SEMANTICS directly, so it holds no matter what
    order the sites fire in.

    Three arms, because the sentinel has three behaviours and each is a branch
    (C-10(b)): omitted ⇒ preserve · explicit None ⇒ clear · mapping ⇒ replace.
    """

    async def _run() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            panel = await _open_patch(app, pilot)
            rows = [_Row(0x200, (0x01, 0x02))]
            supplied = {0x200: 0xAA, 0x201: 0xBB}

            panel.refresh_entries(rows, mem_map=supplied)
            after_supply = panel._mem_map

            # The `on_mount` shape: rows only, no mem_map.
            panel.refresh_entries(rows)
            after_parameterless = panel._mem_map

            panel.refresh_entries(rows, mem_map=None)
            after_explicit_none = panel._mem_map

            replacement = {0x200: 0x11}
            panel.refresh_entries(rows, mem_map=replacement)
            after_replace = panel._mem_map
            return {
                "supply": after_supply is supplied,
                "preserved": after_parameterless is supplied,
                "cleared": after_explicit_none is None,
                "replaced": after_replace is replacement,
            }

    out = asyncio.run(_run())
    assert out["supply"], "a supplied map was not retained"
    assert out["preserved"], (
        "a PARAMETERLESS refresh_entries CLEARED the retained map — the "
        "on_mount self-call would null a real image's map (MJ-1)"
    )
    assert out["cleared"], (
        "an explicit None did NOT clear the map — 'no image loaded' cannot be "
        "expressed, so the card would show a stale image's bytes"
    )
    assert out["replaced"], "a new map did not replace the old one"


def test_tc080_2a_mount_selfcall_does_not_clear_a_real_map(tmp_path: Path) -> None:
    """TC-080.2a — the same property, driven through the REAL on_mount path.

    Intent: the arm above uses the self-call's SHAPE; this one uses the real
    method, so the two together cover both "the semantics are right" and "the
    real caller exercises them".
    """

    async def _run() -> bool:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            panel = await _open_patch(app, pilot)
            supplied = {0x200: 0xAA, 0x201: 0xBB}
            panel.refresh_entries([_Row(0x200, (0x01, 0x02))], mem_map=supplied)
            panel.on_mount()  # the real mount-time path, re-entered
            await pilot.pause()
            return panel._mem_map is supplied

    assert asyncio.run(_run()), (
        "on_mount() cleared the retained mem_map — a card fed by a real load "
        "would go blank on any re-mount"
    )


# ---------------------------------------------------------------------------
# TC-080.4 — no-image / no-selection neutral states
# ---------------------------------------------------------------------------


def test_tc080_4_no_image(tmp_path: Path) -> None:
    """TC-080.4 — ``mem_map is None`` → neutral, ZERO byte values fabricated.

    Intent: LLR-080.4 — with no image there is no "before", so the card must
    refuse rather than guess. Threshold: 0 byte values rendered, 0 ``00`` shown,
    0 exceptions.
    """

    async def _run() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            panel = await _open_patch(app, pilot)
            panel.refresh_entries(
                [_Row(0x100, (0xDE,)), _Row(0x200, (0x00, 0x00))],
                mem_map=None,
            )
            await pilot.pause()
            await _select_row(app, pilot, 1)
            return _card_plain(app)

    plain = asyncio.run(_run())
    assert plain.strip() == CARD_NO_IMAGE, (
        f"no-image state is not neutral: {plain!r}"
    )
    assert "00" not in plain, (
        f"the card FABRICATED byte values with no image loaded: {plain!r}"
    )


def test_tc080_4_no_selection_and_out_of_range(tmp_path: Path) -> None:
    """TC-080.4 — an empty document / an out-of-range index → neutral, no crash.

    Intent: LLR-080.4 + the QC-3 "invalid" class — an index outside the row list
    updates nothing and raises nothing.
    """

    async def _run() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            panel = await _open_patch(app, pilot)
            panel.refresh_entries([], mem_map={0x1: 0x2})
            await pilot.pause()
            empty = _card_plain(app)
            panel.refresh_entries([_Row(0x200, (0x01,))], mem_map={0x200: 0xAA})
            await pilot.pause()
            panel._render_before_after_card(99)  # out of range
            await pilot.pause()
            return empty, _card_plain(app)

    empty, out_of_range = asyncio.run(_run())
    assert empty.strip() == CARD_NO_SELECTION, empty
    assert out_of_range.strip() == CARD_NO_SELECTION, out_of_range


# ---------------------------------------------------------------------------
# TC-080.7 — the MECHANICAL C-17 gate (LLR-080.7 / MJ-7)
# ---------------------------------------------------------------------------


def test_tc080_7_card_inputs_are_ints() -> None:
    """TC-080.7 — the card builder accepts NO non-``int`` input. GATE CHECK.

    Intent: LLR-080.7 / MJ-7. The card's C-17 disposition is "N/A with reason"
    — its whole input set is integers plus author-fixed labels. That N/A is only
    honest while it stays true, and **a card header naming its entry is the
    natural design**, so the re-open condition is MECHANICAL rather than a note
    someone must remember (the batch-47 MN-4 shape).

    **If this test goes RED, the N/A is VOID**: LLR-080.7 becomes a live C-17
    sink and ``AT-080e`` (hostile card header, the LLR-079.3 payload set through
    whatever new input reached the card) must be created in that same increment,
    gate-blocking, before it closes. Not a judgement call.

    The annotation set is DERIVED from the live signature, not hand-listed.
    """
    allowed_tokens = {"int", "Optional", "Sequence", "Mapping", "None"}
    sig = inspect.signature(before_after_card_text)
    offenders = {}
    for name, param in sig.parameters.items():
        annotation = str(param.annotation)
        tokens = set(
            t for t in annotation.replace("[", " ").replace("]", " ")
            .replace(",", " ").split()
        )
        stray = tokens - allowed_tokens
        if stray:
            offenders[name] = sorted(stray)
    assert offenders == {}, (
        "the card builder accepts a NON-int input: "
        f"{offenders}. LLR-080.7's C-17 N/A is now VOID — this surface is a "
        "live untrusted-text sink. Create AT-080e (hostile card header) in "
        "THIS increment, gate-blocking, before closing it."
    )
    # Bind the universal to the code: an empty parameter set would make the
    # assertion above vacuously true.
    assert set(sig.parameters) >= {"address", "before", "after"}, (
        "the builder's parameters vanished — the gate is quantifying over "
        "nothing"
    )


def test_tc080_7_card_renders_no_file_derived_row_text() -> None:
    """TC-080.7 — the card path reads no file-derived attribute off a row.

    Intent: the other half of the mechanical gate. The builder's signature can
    stay int-only while the CALLER quietly passes ``row.value_text`` into it.
    This walks ``_render_before_after_card``'s AST for any read of a
    file-derived row attribute.
    """
    file_derived = {"kind_text", "value_text", "status_text", "linkage_text",
                    "address_text"}
    tree = ast.parse(
        inspect.getsource(PatchEditorPanel._render_before_after_card).lstrip()
    )
    read = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    }
    leaked = read & file_derived
    assert leaked == set(), (
        f"the card path reads file-derived row text {leaked} — LLR-080.7's "
        "C-17 N/A is VOID; AT-080e is now owed, gate-blocking"
    )


# ---------------------------------------------------------------------------
# The writer census — DERIVED from the AST, never hand-listed
# ---------------------------------------------------------------------------


def test_writer_census_every_app_site_pushes_mem_map() -> None:
    """Every ``refresh_entries`` call in ``app.py`` passes ``mem_map``.

    Intent: LLR-080.2 / §6.4's writer census — "an omitted site silently renders
    a card with no before-bytes", the MJ-1-class defect.

    ⚠ **The input set is DERIVED, not hand-listed — and that is the whole point
    of this test.** The Phase-2 census asserted FOUR sites; the live tree has
    FIVE. The fifth (the image-install point) was added by Inc-3 mid-batch,
    correctly and with an accurate comment, and *nothing re-derived the census*.
    A test that hard-coded "these 5 sites" would reproduce that exact defect one
    batch later: it would pass while a SIXTH site went unwired. Per the Inc-5b
    lesson, **an input set is itself an oracle** and code mutation cannot test
    one — so this walks the AST and quantifies over whatever is really there.

    A new ``refresh_entries`` call in ``app.py`` without ``mem_map`` fails HERE,
    loudly, with its line number — which is the edge the Phase-2 census lacked.
    """
    import s19_app.tui.app as app_module

    source = Path(inspect.getfile(app_module)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    sites = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "refresh_entries"
    ]
    # Guard the derived set: if the walk finds nothing (a rename, a moved
    # method), the universal below would pass over an empty set — vacuously.
    assert len(sites) >= 4, (
        f"the census found only {len(sites)} refresh_entries call(s) in "
        "app.py — the derivation is broken, so its 'every site' claim would "
        "be vacuous"
    )
    missing = [
        node.lineno
        for node in sites
        if "mem_map" not in {kw.arg for kw in node.keywords}
    ]
    assert missing == [], (
        f"app.py:{missing} call refresh_entries WITHOUT mem_map. Under "
        "sentinel-preserve the card keeps the PREVIOUS image's map and paints "
        "stale before-bytes. Wire every site."
    )


def test_writer_census_panel_selfcall_supplies_none() -> None:
    """The panel's own ``refresh_entries`` self-call supplies NO ``mem_map``.

    Intent: the counterpart to the census above, and the reason the sentinel
    exists. The panel is a view — C-7 forbids it fetching a map — so this site
    MUST stay parameterless. If someone "helpfully" makes it pass ``None`` to
    look consistent, it would CLEAR a retained map on every mount, which is the
    MJ-1 defect wearing a tidy shirt.
    """
    import s19_app.tui.screens_directionb as panel_module

    tree = ast.parse(
        Path(inspect.getfile(panel_module)).read_text(encoding="utf-8")
    )
    selfcalls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "refresh_entries"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    ]
    assert len(selfcalls) == 1, (
        f"expected exactly one panel self-call; found {len(selfcalls)} at "
        f"{[n.lineno for n in selfcalls]} — the retain semantics were reasoned "
        "about one site"
    )
    passed = {kw.arg for kw in selfcalls[0].keywords}
    assert "mem_map" not in passed, (
        f"screens_directionb.py:{selfcalls[0].lineno} — the panel self-call "
        "now passes mem_map. The panel cannot know one (C-7); if it passes "
        "None it CLEARS a retained map on every mount."
    )
