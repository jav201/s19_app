"""Patch Editor BIG — the undo/redo history strip (batch-48, Inc-6).

HLR-081 (R-TUI-081, US-P6) through the shipped Patch Editor surface. The SCRIPT
window gains a strip directly ABOVE the Undo/Redo row reading the analyst's
position in the change-set history — steps available backward and forward, the
depth against ``_HISTORY_MAX``, and the ``ctrl+z`` / ``ctrl+y`` hints that move
it. Today the only signal is whether two buttons are greyed out.

**The position is DERIVED, and that is the whole risk of this increment.**
``ChangeService`` keeps two stacks and NO cursor. ``history_depths()`` returns
``len(_undo_stack)`` / ``len(_redo_stack)`` / ``_HISTORY_MAX``. An off-by-one
here does not crash and does not look wrong — it silently misreports where the
analyst is in their own edit history, which is the one thing the strip exists to
answer. Every functional test below therefore binds THREE quantities that are
computed independently of one another:

    the literal the branch constructs  ==  the live stack lengths  ==  the
    numbers the strip PAINTS

The literal↔stacks edge catches a wrong derivation; the stacks↔painted edge
catches a rendering off-by-one. Asserting only the last pair would let a strip
that agrees with a broken accessor pass.

⚠ **THE BRANCH SET IS ITSELF AN ORACLE — so it is DERIVED, not hand-listed.**
This is the batch's ninth-vacuity lesson (Inc-5b HIGH-1: a test certified "≥40°
from EVERY claimed hue" while its census omitted the hue that would fail it —
real assertion, exact arithmetic, mutation-passes, still wrong). A hand-picked
list of "interesting" history states is the same shape. The set here is derived
from the only two branch predicates the code actually has: ``undo`` no-ops iff
``not self._undo_stack`` (``change_service.py:533``) and ``redo`` no-ops iff
``not self._redo_stack`` (``:565``). Those two predicates partition the
``(back, forward)`` space into exactly FOUR quadrants, and the bound adds one
boundary:

    back==0, fwd==0   -> empty         (both no-op)      TC-081.1 / AT-081b
    back> 0, fwd==0   -> newest end    (redo no-ops)     TC-081.1
    back==0, fwd> 0   -> oldest end    (undo no-ops)     TC-081.1
    back> 0, fwd> 0   -> mid-stack     (neither no-ops)  AT-081a
    back==bound       -> saturation    (eviction fires)  AT-081b

``test_tc081_1_derived`` does not trust that prose: it asserts its own fixture
table covers all four quadrants, computing the coverage from the fixtures rather
than from this comment. Delete a quadrant and the test fails — which is the
property a hand-list cannot have.

MEASURED RED LEDGER — every mutation below was APPLIED to the shipped tree, the
file RUN, the output READ, then reverted by inverse edit. Nothing here is
reasoned. ⚠ **My pre-written predictions were wrong on FOUR of the seven, and
the run won every time** — each entry records what actually happened, not what I
expected. (The corrected entries are M-2, M-3, M-4, M-5.)

    M-1  `history_depths` returns `len(self._undo_stack) - 1` for `back` — the
         classic cursor-vs-stack off-by-one this increment exists to avoid
         -> 3 FAILED: AT-081a, AT-081b, TC-081.1. Prediction held. The
            literal<->stacks edge is what catches it.
    M-2  swap the `back` / `forward` keys in `history_depths`
         -> 2 FAILED: AT-081b, TC-081.1. ⚠ **AT-081a PASSED — I predicted it
            would fail and it did not.** Its fixture is 2 adds + 1 undo ->
            `(1, 1)`, a PALINDROME: `back == forward`, so a key swap is
            value-invisible there. That is 01b's prescribed shape, and it is the
            FOURTH time this batch has been handed a degenerate fixture (Inc-3's
            AT-077d palindrome; Inc-4's 2/1/1 where failed == uncheckable; 01b
            prescribing `['✓','✗','✓']` for an ORDER test, twice). AT-081a keeps
            the prescribed shape because the requirement names it; TC-081.1's
            ASYMMETRIC quadrants (3/0, 0/2, 2/1) are what discharge the swap.
            The lesson is not "01b is careless" — it is that a fixture whose two
            operands coincide certifies nothing about their order, and only
            running the mutation reveals which fixtures those are.
    M-3  the strip renders `back` where it should render `back + forward` (the
         depth total)
         -> 3 FAILED: AT-081a, TC-081.1, TC-081.6. I predicted "TC-081.1 at the
            oldest-end + mid-stack quadrants ONLY" and named neither AT-081a nor
            TC-081.6. Both catch it because `_expect_position` spells the total,
            i.e. the format lives in ONE place and every consumer of it inherits
            the discrimination. That is an argument for the shared helper, but it
            also means a broad failure here proves less than it looks: 3 tests
            fail for ONE reason, not three.
    M-4  `_history_strip_text` ignores `enabled` and always renders the position
         -> 2 FAILED: TC-081.3, TC-081.6. The strip would advertise `ctrl+z` for
            a file-backed document where the SAME A-01 guard makes the key inert.
    M-5  drop the `depths` argument at the history site (`_refresh_patch_history_
         view`) — the site that MOVES the history
         -> 3 FAILED: AT-081a, TC-081.1, TC-081.3. ⚠ Unlike Inc-4's M-3 — where
            the same-shaped omission was behaviourally REDUNDANT because the
            defaulted `None` WAS the cleared state — this site is load-bearing:
            the default renders 0/0 while the real depths are non-zero, so the
            omission is VISIBLE at the surface. The census is not a formality
            here, and TC-081.3's AST arm catches it independently.
    M-6  remove the `on_mount` initial-render site (i.e. ship the defect this
         increment FOUND: the strip mounts blank)
         -> 3 FAILED: AT-081b, TC-081.1, TC-081.3. This is the mutation that
            proves the fix has an oracle. Before it, a freshly-opened Patch
            Editor painted `''` — and `''` is not the empty state, it is nothing.
    M-7  delete the `oldest_end` row from `_QUADRANT_FIXTURES` — i.e. mutate the
         INPUT SET rather than the code
         -> 1 FAILED: TC-081.1, at the coverage assertion. ⚠ **This is the
            mutation class M-1..M-6 cannot reach.** Inc-5b's HIGH-1 was exactly
            this: a real assertion with exact arithmetic quantifying over a
            hand-listed set that omitted the case which would fail it — every
            code mutation passes it. The guard is what makes the set falsifiable.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import subprocess
from pathlib import Path

from textual.content import Content
from textual.widget import Widget
from textual.widgets import Button, Static

from s19_app.tui.app import S19TuiApp
from s19_app.tui.insight_style import DGRAY, VALUE
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services.change_service import (
    HISTORY_DEPTH_KEYS,
    ChangeService,
    _HISTORY_MAX,
)
from tests.test_engine_unchanged import _repo_root
from tests.test_tui_patch_editor_v2 import _set_entry_inputs, _write_v2_document

#: The two regimes every geometry / render claim is measured at (C-29).
_SIZES = ((80, 24), (120, 30))


def _expect_position(back: int, forward: int, bound: int) -> str:
    """The strip's expected TWO-LINE plain text for an ENABLED history.

    Spelled once, here, rather than inline at six call sites — the format is a
    contract and a format living in six places belongs to none of them (the
    Inc-5 ``_expect`` precedent in ``test_tui_patch_checks_strip.py``).

    The two lines are a READING-ORDER choice (where you are, then how to move),
    NOT a wrap workaround. That distinction is measured, not assumed: the
    SCRIPT window's strip budget is **38 cells at 120x30** and 64 at 80x24,
    while the widest reachable line 1 is ``↶ 20 back  ↷ 0 fwd  20/20`` = 25.
    ⚠ The CHECKS strip's 14-cell budget (``_CHECK_STRIP_BAR_CELLS``) is a
    DIFFERENT container's figure — at 120x30 the patch layout is a 3-column
    split and the SCRIPT window is nearly 3x wider than the CHECKS window (44
    vs 22). Inheriting that 14 would have been the C-29 error verbatim, and the
    record sits in a sibling constant inviting exactly that.
    """
    return (
        f"↶ {back} back  ↷ {forward} fwd  {back + forward}/{bound}"
        + "\n"
        + PatchEditorPanel._HISTORY_HINT
    )


def _strip(app: S19TuiApp) -> Content:
    """Return the history strip's rendered content, UNSTRINGIFIED.

    ⚠ ``Static`` has NO ``.renderable`` at textual==8.2.8; the accessor is
    ``render()`` and it returns a ``textual.content.Content``, not the
    ``rich.text.Text`` the builder produced (``Static.update`` passes it through
    ``visualize()``). The house recorded this at
    ``test_tui_patch_checks_strip.py:224``; this file reuses the finding rather
    than re-deriving it.
    """
    content = app.query_one("#patch_history_strip", Static).render()
    assert isinstance(content, Content), (
        f"expected a textual Content off render(); got {type(content).__name__}"
    )
    return content


def _add_entry(app: S19TuiApp, address: int) -> None:
    """Add ONE entry through the REAL Add button (C-10(a) — never the service).

    Each press is one ``_push_history`` call, so N presses is N history steps.
    Addresses must differ: ``add_entry`` on an existing address is an EDIT, and
    an edit is still one history step — but a duplicate would make the entry
    count and the history depth disagree and mask a miscount.
    """
    _set_entry_inputs(app, address=f"0x{address:X}", bytes_text="00")
    app.query_one("#patch_entry_add_button", Button).press()


async def _drive_history(
    app: S19TuiApp, pilot: object, adds: int, undos: int
) -> None:
    """Perform ``adds`` real Add presses then ``undos`` real ``ctrl+z`` presses.

    ``ctrl+z`` (not the Undo button) because AT-081a names the batch-40 S2
    binding and C-16 says drive the real key. Both routes share
    ``action_patch_undo``, so this also exercises the A-01 guard.
    """
    app.action_show_screen("patch")
    await pilot.pause()
    for index in range(adds):
        _add_entry(app, 0x100 + index * 4)
        await pilot.pause()
    for _ in range(undos):
        await pilot.press("ctrl+z")
        await pilot.pause()


# ===========================================================================
# AT-081a — 2 edits + 1 undo -> 1 back / 1 forward, with the key hints
# ===========================================================================


def test_at081a_position(tmp_path: Path) -> None:
    """After 2 adds and a real ctrl+z the strip reports 1 back / 1 forward.

    Intent (AT-081a, C-10(a)): the analyst mid-edit must know whether a step
    back exists and how to take it. The assertion is over the strip's PAINTED
    content, driven through the REAL Add button and the REAL ``ctrl+z``
    binding, and cross-bound to the live stack lengths so the strip cannot
    drift into reporting numbers of its own.

    The strip is asserted to have MOVED OFF its default: a fresh strip reads
    ``0 back / 0 fwd``, so "the strip reads 1/1" is only evidence because
    ``(0, 0)`` is a state this same surface really produces (AT-081b's empty
    arm shows it does).

    ⚠ This fixture is a PALINDROME — ``back == forward == 1`` — so it CANNOT
    see a back<->forward key swap (M-2). That is 01b's prescribed shape and the
    requirement names it, so it stays; TC-081.1's asymmetric quadrants carry the
    swap. Recorded rather than quietly "improved", because the same degeneracy
    has now shipped in three of this batch's prescribed fixtures.
    """

    async def _drive() -> tuple[Content, dict[str, int], int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _drive_history(app, pilot, adds=2, undos=1)
            service = app._change_service
            return (
                _strip(app),
                service.history_depths(),
                len(service._undo_stack),
                len(service._redo_stack),
            )

    strip, depths, undo_len, redo_len = asyncio.run(_drive())

    # Edge 1 — the branch really built the state it claims. 2 adds push 2
    # snapshots; 1 undo moves exactly one across. If this fails the fixture
    # rotted and every assertion below is meaningless.
    assert (undo_len, redo_len) == (1, 1), (
        "fixture integrity: 2 adds then 1 undo must leave ONE snapshot on each "
        f"stack; got undo={undo_len} redo={redo_len}"
    )
    # Edge 2 — the accessor derives from those stacks and nothing else.
    assert depths == {"back": 1, "forward": 1, "bound": _HISTORY_MAX}, (
        f"history_depths must derive (1, 1) from the live stacks; got {depths!r}"
    )
    # Edge 3 — the strip paints those numbers.
    assert strip.plain == _expect_position(1, 1, _HISTORY_MAX), (
        f"the strip must report 1 step back and 1 forward; got {strip.plain!r}"
    )

    # Read the numbers back OFF the rendered text, so a strip that renumbered
    # itself cannot pass by agreeing with itself.
    rendered_back = int(strip.plain.split("↶")[1].split()[0])
    rendered_fwd = int(strip.plain.split("↷")[1].split()[0])
    assert (rendered_back, rendered_fwd) == (undo_len, redo_len), (
        f"the strip's counts ({rendered_back}, {rendered_fwd}) must equal the "
        f"live stack depths ({undo_len}, {redo_len}) exactly"
    )

    # The hints: both keys named, on the shipped surface. Without them the
    # strip answers "a step exists" but not "how do I take it" — half of US-P6.
    for key in ("ctrl+z", "ctrl+y"):
        assert key in strip.plain, (
            f"the strip must show the {key!r} hint (the batch-40 S2 binding); "
            f"got {strip.plain!r}"
        )


# ===========================================================================
# AT-081b — BOUNDS: the empty state, and saturation at _HISTORY_MAX
# ===========================================================================


def test_at081b_bounds(tmp_path: Path) -> None:
    """A fresh document reports the empty state; 21 ops saturate at 20, not 21.

    Intent (AT-081b): the two boundary classes through the shipped surface.

    - **Empty** — a fresh document has no history: 0 back, 0 forward, and the
      depth total renders ``0/20`` with no crash and no divide-by-zero.
    - **Saturation** — ``_push_history`` evicts at ``> _HISTORY_MAX``
      (``change_service.py:505-506``), so the 21st operation does NOT grow the
      depth. The 21st op is the discriminator: at 20 ops nothing has been
      evicted yet and a strip that simply counted operations would still agree.

    The bound is READ from ``_HISTORY_MAX`` rather than spelled ``20``: a
    hardcoded copy of a value the code owns keeps passing after the constant
    moves and then certifies the OLD bound (the Inc-5b F3 bind-the-literal
    lesson, applied before it was earned).
    """

    async def _drive(adds: int) -> tuple[Content, dict[str, int], int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _drive_history(app, pilot, adds=adds, undos=0)
            service = app._change_service
            return _strip(app), service.history_depths(), len(service._undo_stack)

    # --- empty ------------------------------------------------------------
    strip, depths, undo_len = asyncio.run(_drive(0))
    assert undo_len == 0, f"fixture integrity: a fresh document has no history; got {undo_len}"
    assert depths == {"back": 0, "forward": 0, "bound": _HISTORY_MAX}
    assert strip.plain == _expect_position(0, 0, _HISTORY_MAX), (
        f"a fresh document must render the empty state; got {strip.plain!r}"
    )

    # A zero count is styled DGRAY ("no step that way"), a non-zero one VALUE.
    # Without this the empty state is just the number 0 in body text, which is
    # what every other count looks like.
    zero_index = strip.plain.index("0")
    zero_style = next(
        (
            span.style.foreground.hex.lower()
            for span in strip.spans
            if span.start == zero_index and span.style.foreground is not None
        ),
        None,
    )
    assert zero_style == DGRAY.lower(), (
        f"a zero step-count must render DGRAY, not as an ordinary value; got "
        f"{zero_style!r}. The strip's spans are {strip.spans!r}"
    )

    # --- saturation -------------------------------------------------------
    over = _HISTORY_MAX + 1
    strip, depths, undo_len = asyncio.run(_drive(over))
    assert undo_len == _HISTORY_MAX, (
        f"fixture integrity: {over} pushes must evict down to {_HISTORY_MAX} "
        f"snapshots; got {undo_len}"
    )
    assert depths["back"] == _HISTORY_MAX, (
        f"after {over} operations the reported depth must SATURATE at the "
        f"bound, not count operations; got {depths!r}"
    )
    assert strip.plain == _expect_position(_HISTORY_MAX, 0, _HISTORY_MAX), (
        f"the strip must read {_HISTORY_MAX}/{_HISTORY_MAX} after {over} ops "
        f"— never {over}; got {strip.plain!r}"
    )
    assert str(over) not in strip.plain, (
        f"the strip must never report {over} steps: only {_HISTORY_MAX} "
        f"snapshots survive eviction; got {strip.plain!r}"
    )


# ===========================================================================
# TC-081.1 — the position is DERIVED, over the code's OWN branch partition
# ===========================================================================

#: The ``(adds, undos)`` fixture per quadrant of the ``(back, forward)`` space.
#: DERIVED from the two no-op predicates in `change_service` (`undo` no-ops iff
#: the undo stack is empty; `redo` iff the redo stack is), NOT hand-picked —
#: see the module docstring. `_quadrant` computes each fixture's cell and the
#: test asserts the table covers all four, so this dict cannot silently lose the
#: case that would fail it.
_QUADRANT_FIXTURES: dict[str, tuple[int, int, int, int]] = {
    # label: (adds, undos, expected_back, expected_forward)
    "empty": (0, 0, 0, 0),
    "newest_end": (3, 0, 3, 0),
    "oldest_end": (2, 2, 0, 2),
    "mid_stack": (3, 1, 2, 1),
}


def _quadrant(back: int, forward: int) -> tuple[bool, bool]:
    """Map a state to its cell in the undo/redo no-op partition."""
    return (back > 0, forward > 0)


def test_tc081_1_derived(tmp_path: Path) -> None:
    """Depths are derived from the two stacks, across every branch quadrant.

    Intent (LLR-081.1): no history cursor exists, so the position must be
    computed from ``len(_undo_stack)`` / ``len(_redo_stack)``. This test owns
    the off-by-one risk that a cursor would otherwise hide.

    ⚠ **The input set is guarded, not asserted in prose.** The first assertion
    below computes the quadrant of every fixture and requires all four cells of
    the ``(undo no-ops?, redo no-ops?)`` partition to be present. Drop a
    fixture and the test fails. This is the Inc-5b HIGH-1 lesson applied
    up-front: a universal ("the derivation holds across every branch") is only
    as true as the set it quantifies over, and code mutation cannot test a set.

    The fixtures are deliberately ASYMMETRIC (3/0, 0/2, 2/1) — a back<->forward
    swap is invisible at AT-081a's prescribed (1, 1) palindrome (M-2), and
    ``back`` vs ``back + forward`` collapse at any (N, 0) state (M-3). Both
    mutations die here.
    """
    covered = {
        _quadrant(back, forward)
        for _, _, back, forward in _QUADRANT_FIXTURES.values()
    }
    assert covered == {(False, False), (True, False), (False, True), (True, True)}, (
        "the fixture table must cover all FOUR cells of the (undo no-ops?, "
        f"redo no-ops?) partition — the code's own branch structure. Covered: "
        f"{sorted(covered)}. A quadrant missing here is a branch this test "
        "silently certifies without ever entering."
    )

    async def _drive(adds: int, undos: int) -> tuple[str, dict[str, int], int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _drive_history(app, pilot, adds=adds, undos=undos)
            service = app._change_service
            return (
                _strip(app).plain,
                service.history_depths(),
                len(service._undo_stack),
                len(service._redo_stack),
            )

    for label, (adds, undos, back, forward) in _QUADRANT_FIXTURES.items():
        painted, depths, undo_len, redo_len = asyncio.run(_drive(adds, undos))

        # literal <-> live stacks: the branch built what it claims.
        assert (undo_len, redo_len) == (back, forward), (
            f"{label}: {adds} adds then {undos} undos must leave stacks "
            f"({back}, {forward}); got ({undo_len}, {redo_len})"
        )
        # live stacks <-> accessor: derived, with no off-by-one.
        assert (depths["back"], depths["forward"]) == (undo_len, redo_len), (
            f"{label}: history_depths must equal the live stack lengths "
            f"exactly; got {depths!r} against ({undo_len}, {redo_len})"
        )
        # accessor <-> painted: the strip renders what was derived.
        assert painted == _expect_position(back, forward, _HISTORY_MAX), (
            f"{label}: got {painted!r}"
        )

    # The accessor's shape is its own contract (the strip cannot tell a missing
    # key from a 0 — both `.get(key, 0)` to 0, the Inc-4 M-4 finding).
    assert tuple(ChangeService().history_depths()) == HISTORY_DEPTH_KEYS, (
        "history_depths must return every key of HISTORY_DEPTH_KEYS in "
        f"canonical order; got {tuple(ChangeService().history_depths())!r}"
    )

    # DERIVED, not stored — the behavioural oracle for "0 new cursor state".
    # Poke the stack directly and the reported depth MUST follow. A cached
    # count or a cursor attribute would not move, which is exactly the drift
    # LLR-081.1 exists to prevent. This asserts the property rather than
    # grepping for attribute names that look cursor-ish (an oracle keyed to a
    # naming hunch reports on vocabulary, not on behaviour).
    service = ChangeService()
    assert service.history_depths()["back"] == 0
    service._undo_stack.append(service.document)
    assert service.history_depths()["back"] == 1, (
        "history_depths must READ the stack, not a stored count: appending a "
        "snapshot did not move the reported depth"
    )


# ===========================================================================
# TC-081.2 — the strip mounts, threads its data as a parameter, stays pure
# ===========================================================================


def test_tc081_2_strip(tmp_path: Path) -> None:
    """The strip resolves once, above its buttons, fed by a defaulted parameter.

    Intent (LLR-081.2, C-7): DOM order is asserted because "the strip labels
    the Undo/Redo row" is a reading-order claim no functional AT can see (the
    Inc-4 M-5 lesson). The panel is a VIEW: it must not import the service layer
    nor reach ``self.app``, or the Patch screen stops being testable without a
    full app.

    The ``_nodes``/``_context`` arm is §2.4-10 — those names shadow Textual
    ``Widget`` internals and produce a silent mount crash / idle boot deadlock
    with NO traceback. The literal is BOUND to the class first (the Inc-4 F3
    fix): a bare ``names & set(dir(Widget))`` check is constant-true and passes
    without importing anything.
    """

    async def _drive() -> tuple[int, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            strips = list(app.query("#patch_history_strip").results())
            window = app.query_one("#patch_win_script")
            order = [
                child.id
                for child in window.children
                if child.id in ("patch_history_strip", "patch_history_controls")
            ]
            return len(strips), order

    count, order = asyncio.run(_drive())

    assert count == 1, f"the strip must resolve EXACTLY once; got {count} nodes"
    assert order == ["patch_history_strip", "patch_history_controls"], (
        "the strip must sit directly ABOVE the Undo/Redo row it describes, as "
        f"a docked sibling (never inside the scrolling body); DOM order is {order!r}"
    )

    signature = inspect.signature(PatchEditorPanel.set_undo_redo_enabled)
    parameter = signature.parameters.get("depths")
    assert parameter is not None, (
        "set_undo_redo_enabled must take a `depths` parameter — the strip and "
        f"the buttons ride ONE seam (LLR-081.3); signature is {signature!r}"
    )
    assert parameter.default is None, (
        "the parameter must be DEFAULTED so no existing caller breaks; its "
        f"default is {parameter.default!r}"
    )

    # C-7 purity over the panel's own AST — 0 `self.app`, 0 service imports.
    # AST, not `"self.app" not in source`: a substring probe matches the phrase
    # inside this batch's own docstrings and reports on prose, not code (the
    # Inc-4 finding, three oracles deep).
    panel_tree = ast.parse(inspect.getsource(PatchEditorPanel))
    self_app = [
        node
        for node in ast.walk(panel_tree)
        if isinstance(node, ast.Attribute)
        and node.attr == "app"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ]
    assert not self_app, (
        "the panel must not reach `self.app` — it is a view widget and its "
        f"data is threaded in (C-7); found {len(self_app)} access(es)"
    )
    imports = [
        node
        for node in ast.walk(panel_tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    assert not imports, (
        f"the panel must import nothing (C-7); found {len(imports)} import(s)"
    )

    # §2.4-10 — bind the literal to the class FIRST, then ask the collision
    # question. `vars()` (not `dir()`) reads the class's OWN namespace, so an
    # inherited attribute of the same name cannot satisfy it.
    new_members = {
        "_history_strip_text",
        "_HISTORY_HINT",
        "_HISTORY_OFF",
        "_HISTORY_STRIP_BUDGET_COLS",
    }
    assert new_members <= set(vars(PatchEditorPanel)), (
        "the strip's members must exist on PatchEditorPanel itself; missing "
        f"{new_members - set(vars(PatchEditorPanel))!r}"
    )
    assert not (new_members & set(dir(Widget))), (
        f"new members collide with Textual Widget internals: "
        f"{new_members & set(dir(Widget))!r}"
    )


# ===========================================================================
# TC-081.3 — all three writer sites push depths; strip and buttons agree
# ===========================================================================


def test_tc081_3_sites(tmp_path: Path) -> None:
    """Every `set_undo_redo_enabled` call site pushes depths; A-01 stays consistent.

    Intent (LLR-081.3): the strip answers "is a step back available?" and the
    buttons' enabled state answers the same question. If one site updated the
    buttons without the depths, the two would disagree on screen — the batch-38
    Inc-4 F1 stale-panel defect that batch-40 S1 fixed.

    ⚠ **The LLR names THREE sites; there are FOUR, and the fourth was a real
    defect.** All three named sites are ACTION sites, so none fires before the
    analyst's first action — a freshly-opened Patch Editor painted a BLANK
    strip, and blank is not the empty state, it is nothing. The empty state is
    exactly the state a fresh screen is in. ``S19TuiApp.on_mount`` is now the
    fourth site. This is the MJ-1 shape verbatim: that census also counted three
    ``refresh_entries`` sites and missed a mount-time fourth. Found by AT-081b's
    empty arm failing with ``''`` — the boundary case earning its keep.

    The census arm walks ``app.py``'s AST rather than grepping: a grep matches
    the method name inside docstrings (this file's own prose names it), and an
    oracle keyed to prose certifies documentation.

    The behavioural arm is the A-01 boundary: a FILE-BACKED document disables
    both buttons, and the strip must render the disabled state rather than
    advertising ``ctrl+z`` — the same guard makes that key inert
    (``_patch_history_action_allowed``), so a hint there is a wrong answer, not
    decoration.
    """
    call_sites = [
        node
        for node in ast.walk(ast.parse(Path("s19_app/tui/app.py").read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "set_undo_redo_enabled"
    ]
    assert len(call_sites) == 4, (
        f"expected the 4 writer sites in app.py — the 3 action sites the LLR "
        f"names PLUS the on_mount initial render; found {len(call_sites)}. "
        "A NEW site is not a failure to silence — it is a site that must also "
        "push the depths, or the strip and the buttons will disagree there."
    )
    for site in call_sites:
        passes_depths = len(site.args) >= 2 or any(
            kw.arg == "depths" for kw in site.keywords
        )
        assert passes_depths, (
            f"app.py:{site.lineno}: this site updates the buttons without "
            "pushing the depths — the strip would freeze at its previous "
            "numbers while the buttons moved around it (LLR-081.3)"
        )

    # A-01 behavioural arm: a file-backed document -> buttons disabled AND the
    # strip in its disabled state. Zero disagreement.
    doc_path = _write_v2_document(
        tmp_path / "doc.json", [{"type": "bytes", "address": "0x100", "bytes": "00"}]
    )

    async def _drive() -> tuple[Content, bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            _set_entry_inputs(app, path_text=str(doc_path))
            app.query_one("#patch_doc_load_button", Button).press()
            await pilot.pause()
            return (
                _strip(app),
                app.query_one("#patch_undo_button", Button).disabled,
                app.query_one("#patch_redo_button", Button).disabled,
            )

    strip, undo_disabled, redo_disabled = asyncio.run(_drive())

    assert (undo_disabled, redo_disabled) == (True, True), (
        "fixture integrity: a file-backed document must disable both history "
        f"controls (the A-01 guard); got undo={undo_disabled} redo={redo_disabled}"
    )
    assert strip.plain == PatchEditorPanel._HISTORY_OFF, (
        "with the controls disabled the strip must render the disabled state, "
        f"not a position; got {strip.plain!r}"
    )
    for key in ("ctrl+z", "ctrl+y"):
        assert key not in strip.plain, (
            f"the disabled strip must NOT advertise {key!r}: the same A-01 "
            f"guard makes the key inert; got {strip.plain!r}"
        )


# ===========================================================================
# TC-081.4 — C-28 disposition: no App-level Binding added
# ===========================================================================


def test_tc081_4_no_binding_diff() -> None:
    """The batch adds no App-level `Binding(` — C-28's census does not fire.

    Intent (LLR-081.4): the key hints are panel-local TEXT. C-28 fires when an
    increment adds/removes/changes an App-level ``Binding(show=True)`` or any
    shared-chrome element, which drifts EVERY screen's snapshot (the batch-45
    F-1 lesson: 18 unexpected cells). Recording the disposition as an executable
    guard keeps the snapshot census bounded to the 2 patch cells instead of
    re-opening it at a gate.

    The ``ctrl+z`` / ``ctrl+y`` bindings already exist (batch-40 S2); this
    increment DISPLAYS them and does not touch them.
    """
    completed = subprocess.run(
        ["git", "diff", "main", "--", "s19_app/tui/app.py"],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
        check=True,
    )
    changed = [
        line
        for line in completed.stdout.splitlines()
        if line.startswith(("+", "-"))
        and not line.startswith(("+++", "---"))
        and "Binding(" in line
    ]
    assert not changed, (
        "this batch must add no App-level Binding — a shared-chrome binding "
        "drifts every screen's snapshot (C-28). Changed lines:\n"
        + "\n".join(changed)
    )


# ===========================================================================
# TC-081.5 — the strip PAINTS, at both regimes (C-29, the F2 lesson)
# ===========================================================================


def test_tc081_5_strip_geometry_painted() -> None:
    """The strip paints its two lines unwrapped at 80x24 AND 120x30.

    Intent (C-29 / the Inc-4 F2 lesson): every other assertion in this file
    reads ``render()`` — the PRE-LAYOUT ``Content``, which is geometry-blind. A
    strip with ``display = False`` renders identical content and would pass all
    of them. The oracle here is ``Static.render_line(y)``: the composited
    ``Strip``, after layout, wrapping, and the ``display`` check.

    **The budget was MEASURED, not inherited** (the C-29 error Inc-4 committed
    and Inc-5 recorded): ``#patch_history_controls``'s content region is **38**
    cells at 120x30 and **64** at 80x24 — the SCRIPT window's, not the CHECKS
    window's 14. The fixture is the WIDEST REACHABLE line 1 (``back=20``, the
    saturated bound at 2 digits), because that is the only state that can wrap;
    the single-digit counts every other test uses would hide it.

    ⚠ **What this CAN and cannot see.** ``render_line`` resolves for a widget
    that is laid out but scrolled out of view, so both sizes assert the same
    painted contract. It does NOT assert on-screen compositing: the docked rows
    sit below the fold at BOTH regimes (measured: the strip lands at y=44 on a
    24-row screen and y=45 on a 30-row one), reachable by scrolling the window
    — batch-46's deliberate FOLD-8 contract, which
    ``test_tui_patch_layout.py::test_at064a/b`` owns. A ``region.height == 1``
    assertion here would have been a false oracle: it reads "fits" for a widget
    that is not on screen at all.
    """

    async def _run(size: tuple[int, int]) -> tuple[int, list[str], int]:
        app = S19TuiApp()
        async with app.run_test(size=size) as pilot:
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            panel.set_undo_redo_enabled(
                True, {"back": _HISTORY_MAX, "forward": 0, "bound": _HISTORY_MAX}
            )
            await pilot.pause()
            strip = app.query_one("#patch_history_strip", Static)
            return (
                strip.region.height,
                [strip.render_line(y).text for y in range(strip.region.height)],
                strip.content_region.width,
            )

    for size in _SIZES:
        height, painted, width = asyncio.run(_run(size))

        assert height == 2, (
            f"{size}: the strip must paint exactly TWO lines — position then "
            f"key hints; got height={height}. height==0 means it painted NOTHING"
        )
        assert width >= PatchEditorPanel._HISTORY_STRIP_BUDGET_COLS, (
            f"{size}: the measured budget "
            f"({PatchEditorPanel._HISTORY_STRIP_BUDGET_COLS}) must be the "
            f"NARROWER regime's; this container is {width} cells. If this "
            "fails the layout moved and the two-line claim needs re-measuring"
        )
        # Line 1 carries the whole position, unwrapped, at the widest reachable
        # counts. A count separated from its glyph reads as a label on the next
        # line — the exact mid-token wrap the CHECKS strip shipped and Inc-5 had
        # to fix.
        assert painted[0].strip() == f"↶ {_HISTORY_MAX} back  ↷ 0 fwd  {_HISTORY_MAX}/{_HISTORY_MAX}", (
            f"{size}: line 1 must carry the full position intact and unwrapped; "
            f"got {painted[0]!r}"
        )
        assert painted[1].strip() == PatchEditorPanel._HISTORY_HINT, (
            f"{size}: line 2 must be the key hints alone; got {painted[1]!r}"
        )


# ===========================================================================
# TC-081.6 — the builder is pure and never markup-parses (C-17 N/A, recorded)
# ===========================================================================


def test_tc081_6_builder_returns_text() -> None:
    """The builder returns a `Text` built by append, on `__new__` — no app needed.

    Intent (LLR-081.2 / C-17): the strip's input set is derived INTEGERS and an
    author-fixed vocabulary — no file-derived text reaches it, which is why
    HLR-081's boundary catalog audits C-17 as N/A. This test is that audit made
    mechanical: if a future edit threads a label through here, the ``int()``
    coercion below stops being total and this test is where it shows.

    Driven on ``PatchEditorPanel.__new__`` — the builder is pure, so it needs no
    mounted app. That is a property worth pinning: a builder that reached for a
    widget could not be tested this way.
    """
    panel = PatchEditorPanel.__new__(PatchEditorPanel)

    text = panel._history_strip_text(True, {"back": 2, "forward": 1, "bound": 20})
    assert text.plain == _expect_position(2, 1, 20)

    # `None` depths render the honest empty state rather than raising — the
    # defaulted-parameter contract from TC-081.2 has to mean something.
    assert panel._history_strip_text(True, None).plain == _expect_position(0, 0, 0)

    # Disabled ignores the depths entirely: there is no step to take.
    assert (
        panel._history_strip_text(False, {"back": 9, "forward": 9, "bound": 20}).plain
        == PatchEditorPanel._HISTORY_OFF
    )

    # No span carries a verdict hue. The panel's hue namespace is FULL and
    # GREEN/YELLOW/RED are RESERVED for verdicts inside `#patch_editor_panel`
    # (the Inc-2b operator ruling). A history strip is chrome/metadata, not a
    # verdict — it must not claim one. The permitted set is derived from the
    # palette constants the builder actually uses, not hand-listed.
    permitted = {DGRAY.lower(), VALUE.lower(), "#c5c7d2"}
    used = {
        span.style.color.lower()
        for span in text.spans
        if getattr(span.style, "color", None) is not None
    }
    assert used <= permitted, (
        f"the strip painted a hue outside LABEL/VALUE/DGRAY: {used - permitted}. "
        "A new hue in this panel is a namespace decision, not an "
        "implementation choice (Inc-2b)"
    )
