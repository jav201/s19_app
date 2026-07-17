"""Patch Editor BIG — the CHECKS pass/fail strip (batch-48, Inc-4).

HLR-078 (R-TUI-078, US-P3) through the shipped Patch Editor surface. The CHECKS
window gains a strip ABOVE the results area reading the run's three aggregates
as ``✓ P  ✗ F  ◐ U`` plus a proportional bar of the PASS rate.

The three counts already exist and are always present (A3 —
``CHECK_AGGREGATE_KEYS`` ``changes/model.py:571`` is a 3-tuple and the engine
emits all three even at zero), but reach the user only inside the
``#patch_checks_status`` sentence. The bar answers "did most of it pass?"
without arithmetic.

**The bar is UNFLOORED and that is the load-bearing design decision.**
``microbar(floor=True)`` guarantees a positive fraction at least one filled
cell — correct for a bar meaning *"this row exists, here is its magnitude"*
(batch-47 Inc-9 restored exactly that floor for the Workspace section rows,
LLR-042.7). This bar means *"this fraction PASSED"*, which inverts the harm: it
must never round a pass rate UP, because overstating passes understates a
failure. Precedent for a proportional, unfloored bar: the MAC coverage strip
(``validation_service.py:75``), which legitimately shows an empty bar for
``0 of 2``.

⚠ **The stated REASON for that choice — in 01b and in the Inc-4 brief alike —
is measurably WRONG, and the correction lives in TC-078.4.** Both say a floored
bar would render a run with **0 passes** as one filled cell. It would not:
``microbar``'s floor is gated on ``clamped > 0.0`` (``insight_style.py:214``),
so a 0-pass run renders an empty bar under BOTH settings. **AT-078b therefore
CANNOT discriminate ``floor=True``** (measured — M-1), and 01b's claim that "a
floored bar would show 1 filled cell and fail" there is false. The real harm is
a small-but-NONZERO rate (1 of 20 → ``round(0.05 * 8) == 0`` honestly, 1 when
floored); that case is TC-078.4's behavioural arm. The conclusion stands, the
reasoning did not.

**The strip CLEARS by riding ``last_check_result``'s EXISTING undo/redo reset**
(``change_service.py:538`` / ``:570``) — not by a new invalidation mechanism
and not by Inc-3's BL-4 provenance stamp. ``check_aggregates()`` reads all-zero
the moment ``last_check_result`` is ``None``, so the strip and ``check_rows()``
can never disagree. The counterfactual is the batch-38 Inc-4 F1 stale-panel
defect that batch-40 S1 fixed: a history call site that omits the aggregates
while the post-run site supplies them leaves a stale count on screen.

⚠ **A cleared strip and a 0-entry run render IDENTICALLY (``0/0/0``, empty
bar), by design.** Both are honestly "nothing passed, nothing failed, nothing
was uncheckable"; LLR-078.2 specifies the accessor return an all-zero mapping
for "no result current". AT-078c therefore asserts the counts CHANGED OFF a
non-zero post-run state (C-10(a)) — "the strip reads 0/0/0" alone would pass on
a strip that never rendered anything.

MEASURED RED LEDGER — every mutation below was APPLIED to the shipped tree, the
suite RUN, the output READ, then reverted. Nothing here is reasoned; where my
prediction disagreed with the run, the run won and the prediction is struck.

    M-1  `floor=True` on the strip's microbar (the batch-47 Inc-9 shape,
         wrong here)
         -> TC-078.4 FAILED. **AT-078b PASSED — my prediction was WRONG and
            the run corrected it.** I predicted the 0-total strip would render
            '█░░░░░░░'; it rendered '░░░░░░░░'. `microbar` floors only when
            `clamped > 0.0` (`insight_style.py:214`), so NO zero-case assertion
            can see the floor — which also makes 01b's stated AT-078b oracle
            ("a floored bar would show 1 filled cell and fail") false. The
            floor's only honest behavioural oracle is a small-but-nonzero rate,
            so TC-078.4 grew one (1 of 20 -> 0 cells unfloored, 1 floored).
            Re-measured against that arm: TC-078.4 FAILED on BOTH the AST arm
            and the behavioural arm.
    M-2  swap the `failed` / `uncheckable` labels in `_check_strip_text`
         -> AT-078a FAILED ('✓ 2  ✗ 3  ◐ 1'). ⚠ **Measured against 01b's OWN
            prescribed fixture (2 pass / 1 fail / 1 uncheckable) this mutation
            PASSES** — `failed == uncheckable == 1` makes the two slots
            indistinguishable, the same degeneracy Inc-3 measured in 01b's
            AT-077d palindrome. This file therefore uses a fully ASYMMETRIC
            2/1/3 fixture; 01b's obligation ("counts equal `aggregates`
            exactly") is discharged more strongly, not weakened.
    M-3  history call site drops the aggregates argument (`refresh_check_results
         (rows, "")` — the defaulted param reads None)
         -> TC-078.3 FAILED (its AST arm). **AT-078c PASSED — my prediction
            was WRONG.** I predicted a stale '✓ 2  ✗ 1  ◐ 4' after ctrl+z; the
            strip CLEARED anyway, because `aggregates=None` renders the SAME
            all-zero strip the accessor would have returned. So at THIS site
            the argument is behaviourally REDUNDANT, and the batch-38 Inc-4 F1
            stale-count defect **cannot recur here** — the default IS the
            cleared state. Passing it explicitly is a contract choice
            (LLR-078.3), and TC-078.3 is its only oracle. The value of that
            census is a FUTURE third site that needs real counts and silently
            renders zeros.
    M-3b `_refresh_patch_history_view` drops the refresh_check_results call
         entirely (the "it's redundant, delete it" cleanup — the batch-47 Inc-3
         failure mode)
         -> AT-078c FAILED, and the pre-existing
            `test_undo_redo_ux.py::test_ac1_checks_panel_clears_after_undo_and
            _redo` FAILED with it. Run AFTER M-3 showed AT-078c has no
            counterfactual: this is the mutation that proves AT-078c is not
            vacuous. It guards the refresh EXISTING, not the argument.
    M-4  `check_aggregates` returns `{}` when `last_check_result` is None
         (instead of the all-zero mapping)
         -> TC-078.2 FAILED (its accessor-contract arm). **No AT moved** —
            the all-zero mapping and `{}` are indistinguishable through the
            strip (`.get(key, 0)` defaults both to 0), which is exactly why
            LLR-078.2's stated return needs an oracle at the accessor rather
            than at the surface. [my first draft of this ledger recorded "0
            failures"; that was measured BEFORE TC-078.2 grew the contract
            arm, and the arm was added because of it]
    M-5  strip mounted BELOW `#patch_checks_results` instead of above
         -> TC-078.1 FAILED (DOM order arm). No AT moved — position is a
            layout claim, so it needs its own oracle.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
from pathlib import Path

from rich.text import Text
from textual.content import Content
from textual.widget import Widget
from textual.widgets import Button, Label, Static

from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.model import CHECK_AGGREGATE_KEYS
from s19_app.tui.insight_style import (
    GREEN,
    MICROBAR_EMPTY,
    MICROBAR_FILLED,
    RED,
    YELLOW,
)
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services.change_service import ChangeService
from tests.test_tui_patch_editor_v2 import (
    _load_image,
    _make_s19_image,
    _seed_via_paste,
    _set_entry_inputs,
)

#: `_make_s19_image` emits 16 bytes of 0x00 at 0x100-0x10F. An entry whose
#: bytes are "00" inside that window PASSES; one whose bytes differ FAILS; one
#: outside the image entirely is UNCHECKABLE.
_ADDRESS_OUTSIDE_IMAGE = 0x9000

#: The fully ASYMMETRIC fixture: 2 passed / 1 failed / 3 uncheckable. All three
#: counts DISTINCT — see M-2. 01b prescribes 2/1/1, under which a failed <->
#: uncheckable swap is invisible.
_ASYMMETRIC_ENTRIES = [
    # inside the image and matching -> passed x2
    {"type": "bytes", "address": "0x100", "bytes": "00"},
    {"type": "bytes", "address": "0x101", "bytes": "00"},
    # inside the image and NOT matching (image holds 00) -> failed x1
    {"type": "bytes", "address": "0x102", "bytes": "FF"},
    # no image coverage at all -> uncheckable x3
    {"type": "bytes", "address": f"0x{_ADDRESS_OUTSIDE_IMAGE:X}", "bytes": "EE"},
    {"type": "bytes", "address": f"0x{_ADDRESS_OUTSIDE_IMAGE + 1:X}", "bytes": "EE"},
    {"type": "bytes", "address": f"0x{_ADDRESS_OUTSIDE_IMAGE + 2:X}", "bytes": "EE"},
]

_EXPECTED_AGGREGATES = {"passed": 2, "failed": 1, "uncheckable": 3}

#: 2 passed of 6 total -> round(2/6 * 8) == 3 filled cells of the 8-cell bar.
_EXPECTED_BAR = MICROBAR_FILLED * 3 + MICROBAR_EMPTY * 5
_EMPTY_BAR = MICROBAR_EMPTY * 8

#: AT-078c adds a 7th (uncheckable) entry to have a history step to undo, so
#: its post-run shape is 2/1/4 -> round(2/7 * 8) == 2 filled cells.
_BAR_2_OF_7 = MICROBAR_FILLED * 2 + MICROBAR_EMPTY * 6


# ---------------------------------------------------------------------------
# Fixtures / drivers
# ---------------------------------------------------------------------------


def _check_paste_text(entries: list[dict]) -> str:
    """Return a paste-authored ``kind="check"`` changeset (``source_path`` None).

    ``kind="check"`` is the only kind checks RUN over — a ``kind="change"``
    document BLOCKS the run and every entry comes back ``uncheckable``, which
    would silently pass a weaker AT-078a while proving nothing about the
    pass/fail branches. The PASTE seam keeps ``source_path`` ``None`` so the
    Undo/Redo binding AT-078c drives stays enabled (the LLR-064b.4 guard).
    """
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "check",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        }
    )


def _strip(app: S19TuiApp) -> Content:
    """Return the strip's rendered content, UNSTRINGIFIED.

    Not stringified: the glyph SPANS carry the verdict colours, and they are
    only readable off the structured content.

    ⚠ ``Static`` has NO ``.renderable`` at textual==8.2.8 (the house already
    recorded this for ``Label`` at ``test_tui_patch_layout.py:606``); the
    accessor is ``render()``, and it returns a ``textual.content.Content`` —
    NOT the ``rich.text.Text`` the builder produced, because ``Static.update``
    passes it through ``visualize()``. The ``Text`` half of the contract is
    therefore asserted on the BUILDER (TC-078.2), and the rendered half here.
    """
    content = app.query_one("#patch_checks_strip", Static).render()
    assert isinstance(content, Content), (
        f"expected a textual Content off render(); got {type(content).__name__}"
    )
    return content


def _glyph_hex(content: Content, index: int) -> str | None:
    """Return the lowercase hex of the span starting at ``index``, or None.

    The rendered span's style is a ``textual.style.Style`` whose ``foreground``
    is a ``Color``; ``.hex`` comes back UPPERCASE, so it is lowered to compare
    against the ``insight_style`` palette constants.
    """
    for span in content.spans:
        if span.start == index and span.style.foreground is not None:
            return span.style.foreground.hex.lower()
    return None


def _run_checks(app: S19TuiApp) -> None:
    """Press the REAL ``#patch_checks_run_button`` (C-10(a) — never the service)."""
    app.query_one("#patch_checks_run_button", Button).press()


def _open_patch_with_paste(app: S19TuiApp, entries: list[dict]) -> None:
    """Open the Patch Editor and paste-author a check document through the real seam."""
    app.action_show_screen("patch")
    _seed_via_paste(app, _check_paste_text(entries))


# ===========================================================================
# AT-078a — the strip's counts ARE the run's aggregates; the bar is proportional
# ===========================================================================


def test_at078a_counts(tmp_path: Path) -> None:
    """A run's strip reads its aggregates exactly, with a proportional bar.

    Intent (AT-078a): the analyst judges a run's outcome at a glance. The
    assertion is over the strip's rendered CONTENT — driven through the REAL
    Run-checks button over a REAL image loaded through the REAL load surface —
    and is cross-bound to ``CheckRunResult.aggregates`` so the strip cannot
    drift into reporting numbers of its own. "A strip exists" would pass on a
    strip rendering zeros.

    The fixture is ASYMMETRIC (2/1/3, all distinct) — see M-2 in the module
    docstring: under 01b's prescribed 2/1/1 a failed<->uncheckable label swap
    is invisible.
    """
    image_path = _make_s19_image(tmp_path)

    async def _drive() -> tuple[Text, dict[str, int]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image_path)
            _open_patch_with_paste(app, _ASYMMETRIC_ENTRIES)
            await pilot.pause()
            _run_checks(app)
            await pilot.pause()
            return _strip(app), app._change_service.check_aggregates()

    strip, aggregates = asyncio.run(_drive())

    # The run really produced the asymmetric shape the fixture intends. If this
    # fails the fixture rotted and every assertion below is meaningless.
    assert aggregates == _EXPECTED_AGGREGATES, (
        "fixture integrity: the run must yield 2 passed / 1 failed / 3 "
        f"uncheckable; got {aggregates!r}"
    )

    assert strip.plain == f"✓ 2  ✗ 1  ◐ 3  {_EXPECTED_BAR}", (
        "the strip must read each verdict's own count and a bar filled to the "
        f"PASS rate (2 of 6 -> 3 of 8 cells); got {strip.plain!r}"
    )

    # Counts == aggregates EXACTLY, read back off the rendered text so a
    # renumbered strip cannot pass by agreeing with itself.
    rendered = {
        "passed": int(strip.plain.split("✓ ")[1].split(" ")[0]),
        "failed": int(strip.plain.split("✗ ")[1].split(" ")[0]),
        "uncheckable": int(strip.plain.split("◐ ")[1].split(" ")[0]),
    }
    assert rendered == aggregates, (
        f"the strip's counts {rendered!r} must equal the run's aggregates "
        f"{aggregates!r} exactly"
    )

    # Each glyph carries its own verdict colour — a count with no styled glyph
    # conveys no verdict. GREEN/RED/YELLOW is the RIGHT claim here: the strip
    # reports VERDICTS, and it reuses Inc-3's `_GLYPH_STYLE` vocabulary rather
    # than minting a parallel one (no new hue).
    for glyph, style in (("✓", GREEN), ("✗", RED), ("◐", YELLOW)):
        index = strip.plain.index(glyph)
        assert _glyph_hex(strip, index) == style.lower(), (
            f"the {glyph!r} glyph must carry a span styled {style!r} "
            f"(_GLYPH_STYLE); got {_glyph_hex(strip, index)!r}. The strip's "
            f"spans are {strip.spans!r}"
        )


# ===========================================================================
# AT-078b — zero-total boundary: no division, and an EMPTY bar
# ===========================================================================


def test_at078b_zero_total(tmp_path: Path) -> None:
    """A 0-entry run renders 0/0/0 with a 0-filled bar and does not crash.

    Intent (AT-078b, C-10(b) fourth branch — the empty class): the strip's bar
    is ``passed / (passed + failed + uncheckable)``, which divides by zero on a
    0-entry run. The guard is a short-circuit to ``frac = 0.0``, asserted here
    through the shipped surface.

    ⚠ **This test does NOT discriminate ``floor=True``, contrary to 01b**,
    which claims "a floored bar would show 1 filled cell and fail" here.
    MEASURED (M-1): it shows 0 and PASSES, because ``microbar``'s floor is
    gated on ``clamped > 0.0``. The floor's real oracle is TC-078.4's
    small-but-nonzero arm. What this test does own is the divide-by-zero
    boundary — ``passed / total`` on a 0-entry run — which is real.
    """
    image_path = _make_s19_image(tmp_path)

    async def _drive() -> tuple[Text, dict[str, int]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image_path)
            _open_patch_with_paste(app, [])
            await pilot.pause()
            _run_checks(app)
            await pilot.pause()
            return _strip(app), app._change_service.check_aggregates()

    strip, aggregates = asyncio.run(_drive())

    assert aggregates == {"passed": 0, "failed": 0, "uncheckable": 0}, (
        f"a 0-entry run must aggregate to all-zero; got {aggregates!r}"
    )
    assert strip.plain == f"✓ 0  ✗ 0  ◐ 0  {_EMPTY_BAR}", (
        "a 0-total run must render 0/0/0 with an EMPTY bar — a floored bar "
        f"would fill one cell and claim a pass that never happened; got "
        f"{strip.plain!r}"
    )
    assert MICROBAR_FILLED not in strip.plain, (
        f"frac=0.0 must yield ZERO filled cells; got {strip.plain!r}"
    )


# ===========================================================================
# AT-078c — post-undo the strip CLEARS off its non-zero post-run state
# ===========================================================================


def test_at078c_cleared(tmp_path: Path) -> None:
    """A real ctrl+z clears the strip — no stale counts.

    Intent (AT-078c, C-10(a) — assert the observed value CHANGED): ``undo``
    resets ``last_check_result`` (``change_service.py:538``), so the restored
    change-set no longer has a current result and the strip must stop
    describing the pre-move run. The counterfactual is the batch-38 Inc-4 F1
    stale-panel defect (M-3, measured).

    The post-run state is captured and asserted NON-ZERO first: "the strip
    reads 0/0/0" is also true of a strip that never rendered, so only a
    measured CHANGE off a live value proves the clear.
    """
    image_path = _make_s19_image(tmp_path)

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image_path)
            _open_patch_with_paste(app, _ASYMMETRIC_ENTRIES)
            await pilot.pause()

            # A history step for ctrl+z to POP: add a 7th (uncheckable) entry
            # through the REAL Add button — the test_undo_redo_ux idiom. Undo
            # against a freshly-pasted document with no subsequent edit has
            # nothing to restore.
            _set_entry_inputs(app, address="0x9003", bytes_text="EE")
            app.query_one("#patch_entry_add_button", Button).press()
            await pilot.pause()

            _run_checks(app)
            await pilot.pause()
            after_run = _strip(app).plain

            # Focus the screen, then drive the REAL ctrl+z binding (C-16).
            app.query_one("#patch_doc_entries_table").focus()
            await pilot.pause()
            await pilot.press("ctrl+z")
            await pilot.pause()
            return after_run, _strip(app).plain

    after_run, after_undo = asyncio.run(_drive())

    assert after_run == f"✓ 2  ✗ 1  ◐ 4  {_BAR_2_OF_7}", (
        f"precondition: the run must leave a NON-ZERO strip; got {after_run!r}"
    )
    assert after_undo != after_run, (
        "the strip must CHANGE off its post-run state on undo — it still reads "
        f"{after_undo!r}, the batch-38 Inc-4 F1 stale-panel defect"
    )
    assert after_undo == f"✓ 0  ✗ 0  ◐ 0  {_EMPTY_BAR}", (
        f"undo must CLEAR the strip to all-zero; got {after_undo!r}"
    )


# ===========================================================================
# TC-078.1 — the strip mounts once, above the results, and displaces nothing
# ===========================================================================


def test_tc078_1_strip_mounted(tmp_path: Path) -> None:
    """The strip resolves exactly once, precedes the results, status retained.

    Intent (LLR-078.1): the strip is an ADDITION inside
    ``#patch_win_checks_body`` — ``#patch_checks_status`` is RETAINED, not
    replaced (it carries the blocked-run reason, the C-17 sink this batch does
    not touch). DOM order is asserted because "above the results" is the whole
    reading order of the window and no AT can see it (M-5).

    The ``_nodes``/``_context`` arm is §2.4-10: those names shadow Textual
    ``Widget`` internals and produce a silent mount crash / idle boot deadlock
    with NO traceback.
    """

    async def _drive() -> tuple[int, list[str], bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            strips = list(app.query("#patch_checks_strip").results())
            body = app.query_one("#patch_win_checks_body")
            order = [
                child.id
                for child in body.children
                if child.id
                in ("patch_checks_status", "patch_checks_strip", "patch_checks_results")
            ]
            status_ok = app.query_one("#patch_checks_status", Label) is not None
            return len(strips), order, status_ok

    count, order, status_ok = asyncio.run(_drive())

    assert count == 1, f"the strip must resolve EXACTLY once; got {count} nodes"
    assert status_ok, "#patch_checks_status must be RETAINED, not replaced"
    assert order == [
        "patch_checks_status",
        "patch_checks_strip",
        "patch_checks_results",
    ], (
        "the strip must sit ABOVE the results area inside "
        f"#patch_win_checks_body; DOM order is {order!r}"
    )

    # §2.4-10: no new member may shadow a Textual Widget internal.
    new_members = {"_check_strip_text", "_CHECK_STRIP_BAR_CELLS"}
    assert not (new_members & set(dir(Widget))), (
        f"new members collide with Textual Widget internals: "
        f"{new_members & set(dir(Widget))!r}"
    )


# ===========================================================================
# TC-078.2 — aggregates threaded as a defaulted parameter; C-7 purity holds
# ===========================================================================


def test_tc078_2_aggregates_param(tmp_path: Path) -> None:
    """The aggregates arrive as a defaulted parameter and the panel stays pure.

    Intent (LLR-078.2, C-7): the panel is a VIEW — it must not import the
    service layer nor reach ``self.app`` to fetch its own data, or the Patch
    screen stops being testable without a full app. The counts are therefore
    threaded IN (the ``MemoryMapPanel.render_ranges(…, mem_map=…)`` precedent),
    duck-typed as a ``Mapping`` so no service type is imported.

    The accessor's all-zero return shape is asserted HERE rather than through
    the strip, because the strip cannot tell an all-zero mapping from ``{}``
    (M-4, measured): both ``.get(key, 0)`` to 0. LLR-078.2 states the mapping,
    so the contract needs its own oracle.

    ⚠ The purity probe walks the AST, NOT ``"self.app" not in source``. My
    first draft did the substring check and FAILED on correct code — it was
    matching the word ``self.app`` inside this very batch's docstrings. Three
    separate oracles in this increment had that bug; a prose-matching probe
    reports on documentation, not on code.
    """
    signature = inspect.signature(PatchEditorPanel.refresh_check_results)
    parameter = signature.parameters.get("aggregates")

    assert parameter is not None, (
        "refresh_check_results must take an `aggregates` parameter; its "
        f"signature is {signature!r}"
    )
    assert parameter.default is None, (
        "the parameter must be DEFAULTED so no existing caller breaks; its "
        f"default is {parameter.default!r}"
    )

    # C-7 purity probe over the panel's own AST — 0 `self.app`, 0 service
    # imports. Scoped by inspect, not pinned line numbers (which drift: this
    # batch's spec coordinates were ~160 lines stale).
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
        f"data is threaded in (C-7); found {len(self_app)} access(es) at "
        f"lines {[node.lineno for node in self_app]}"
    )

    imported: list[str] = []
    for node in ast.walk(panel_tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
        elif isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
    service_imports = [name for name in imported if "service" in name]
    assert not service_imports, (
        f"the panel must not import the service layer (C-7); found "
        f"{service_imports!r}"
    )

    # The accessor's contract: all three keys, canonical order, ints, at zero.
    service = ChangeService()
    cleared = service.check_aggregates()
    assert cleared == {"passed": 0, "failed": 0, "uncheckable": 0}, (
        f"no current result must yield the ALL-ZERO mapping; got {cleared!r}"
    )
    assert tuple(cleared) == CHECK_AGGREGATE_KEYS, (
        f"the accessor must return CHECK_AGGREGATE_KEYS in canonical order; "
        f"got {tuple(cleared)!r}"
    )
    assert all(isinstance(value, int) for value in cleared.values()), (
        f"every aggregate must be an int; got {cleared!r}"
    )

    # The builder returns a rich Text, never a bare str. Asserted HERE because
    # the rendered surface cannot see it: `Static.update` runs the Text through
    # `visualize()` and `render()` hands back a `Content`, so the `Text` half of
    # the C-17 sink contract has no oracle on the pilot side.
    panel = PatchEditorPanel.__new__(PatchEditorPanel)
    built = panel._check_strip_text({"passed": 1, "failed": 0, "uncheckable": 0})
    assert isinstance(built, Text), (
        f"the strip builder must return a rich.text.Text; got {type(built).__name__}"
    )
    # A None mapping is the cleared strip, not a crash (the parameter default).
    assert panel._check_strip_text(None).plain.startswith("✓ 0"), (
        "a None mapping must render the all-zero cleared strip"
    )


# ===========================================================================
# TC-078.3 — BOTH refresh_check_results call sites push the aggregates
# ===========================================================================


def test_tc078_3_both_sites(tmp_path: Path) -> None:
    """Both app.py call sites pass the aggregates (the writer census).

    Intent (LLR-078.3): the post-run site and the history-refresh site are the
    only two writers. If either omits the counts the strip and ``check_rows()``
    read different states — the exact shape of the batch-38 Inc-4 F1 defect.
    This is a SOURCE-level census (the behavioural arms are AT-078a for the
    post-run site and AT-078c for the history site); it exists so a THIRD call
    site added later cannot quietly skip the argument.

    ⚠ The census walks the AST, NOT ``source.count("…")``. My first draft
    counted substrings and read **3** ``check_aggregates()`` sites against 2
    calls — it was matching my own explanatory COMMENT. A prose-matching oracle
    is not a census; it fails on documentation and passes on a renamed call.
    """
    from s19_app.tui import app as app_module

    tree = ast.parse(inspect.getsource(app_module))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "refresh_check_results"
    ]

    assert len(calls) == 2, (
        f"the writer census pins TWO refresh_check_results call sites; found "
        f"{len(calls)}. A new site must pass the aggregates and be recorded here."
    )

    for call in calls:
        positional = len(call.args) >= 3
        keyword = any(kw.arg == "aggregates" for kw in call.keywords)
        assert positional or keyword, (
            f"the refresh_check_results call at line {call.lineno} does not "
            "pass the aggregates — the strip would render its DEFAULT while "
            "check_rows() renders the real state (the batch-38 Inc-4 F1 defect)"
        )
        argument = call.args[2] if positional else next(
            kw.value for kw in call.keywords if kw.arg == "aggregates"
        )
        assert (
            isinstance(argument, ast.Call)
            and isinstance(argument.func, ast.Attribute)
            and argument.func.attr == "check_aggregates"
        ), (
            f"the aggregates argument at line {call.lineno} must be the LIVE "
            "service accessor check_aggregates(), not a literal or a stashed "
            f"value; got {ast.dump(argument)[:80]}"
        )
