"""AC-1.1/1.2/1.3 — batch-39 Inc-1: native-paste cap on the five TextAreas.

These tests exercise ``s19_app.tui.capped_text_area.CappedTextArea`` — the
shared subclass that caps both native paste ingresses (bracketed ``Paste`` and
the ctrl+v ``action_paste``) to ``_CLIPBOARD_READ_CAP_CHARS`` (64 KiB).

The paste is delivered the way the runtime delivers a real bracketed paste:
posted to the ``App``, which forwards it to the focused widget exactly once
(``App`` guards re-forwarding with ``events.Paste.is_forwarded``). Posting the
event straight to the widget would double-count (widget handles it, then it
bubbles to the app which forwards it back), so the app-level post is the
faithful ingress.

Follows the repo's async-test convention: a sync test body wrapping an inner
``async def _run()`` driven by ``asyncio.run`` (see ``test_tui_patch_layout.py``).
"""

from __future__ import annotations

import asyncio

from textual.app import App, ComposeResult
from textual.events import Paste
from textual.widgets import TextArea

from s19_app.tui.capped_text_area import CappedTextArea
from s19_app.tui.os_clipboard_input import _CLIPBOARD_READ_CAP_CHARS

CAP = _CLIPBOARD_READ_CAP_CHARS  # 65536


class _CappedHarness(App):
    """Minimal app hosting a single focused ``CappedTextArea``."""

    def compose(self) -> ComposeResult:
        yield CappedTextArea("", id="ta")


class _PlainHarness(App):
    """Counterfactual app hosting a stock (uncapped) ``TextArea``."""

    def compose(self) -> ComposeResult:
        yield TextArea("", id="ta")


def _paste_len(app: App, payload: str) -> int:
    """Deliver ``payload`` as a real bracketed paste to the focused TextArea and
    return the resulting ``.text`` length."""

    async def _run() -> int:
        async with app.run_test() as pilot:
            ta = app.query_one("#ta", TextArea)
            ta.focus()
            await pilot.pause()
            app.post_message(Paste(text=payload))
            await pilot.pause()
            await pilot.pause()
            return len(ta.text)

    return asyncio.run(_run())


def test_ac_1_1_red_counterfactual_plain_textarea_inserts_full() -> None:
    """RED anchor: a stock ``TextArea`` inserts the WHOLE over-cap paste.

    This is the pre-fix behaviour the cap must eliminate; it must observe a
    length strictly greater than the cap so the GREEN test below is meaningful.
    """
    inserted = _paste_len(_PlainHarness(), "x" * (CAP + 1000))
    assert inserted > CAP


def test_ac_1_1_over_cap_paste_is_truncated() -> None:
    """AC-1.1: an over-cap bracketed paste inserts at most the cap; excess
    dropped."""
    inserted = _paste_len(_CappedHarness(), "x" * (CAP + 1000))
    assert inserted == CAP


def test_ac_1_2_boundary_exact_cap_is_unchanged() -> None:
    """AC-1.2: a paste of EXACTLY the cap inserts unchanged (no off-by-one
    truncation at the boundary)."""
    inserted = _paste_len(_CappedHarness(), "y" * CAP)
    assert inserted == CAP


def test_ac_1_2_small_paste_is_unchanged() -> None:
    """AC-1.2: a small paste is inserted verbatim (no truncation regression)."""
    payload = "hello world"

    async def _run() -> str:
        app = _CappedHarness()
        async with app.run_test() as pilot:
            ta = app.query_one("#ta", CappedTextArea)
            ta.focus()
            await pilot.pause()
            app.post_message(Paste(text=payload))
            await pilot.pause()
            await pilot.pause()
            return ta.text

    assert asyncio.run(_run()) == payload


def test_ac_1_3_ctrl_v_action_paste_is_capped() -> None:
    """AC-1.3: the second ingress — ``action_paste`` reading ``app.clipboard``
    — is also capped to the limit."""

    async def _run() -> int:
        app = _CappedHarness()
        async with app.run_test() as pilot:
            ta = app.query_one("#ta", CappedTextArea)
            ta.focus()
            await pilot.pause()
            app.copy_to_clipboard("z" * (CAP + 5000))
            ta.action_paste()
            await pilot.pause()
            return len(ta.text)

    assert asyncio.run(_run()) == CAP


def test_ac_1_3_ctrl_v_small_clipboard_unchanged() -> None:
    """AC-1.3 boundary: a small clipboard is pasted verbatim via ctrl+v."""

    async def _run() -> str:
        app = _CappedHarness()
        async with app.run_test() as pilot:
            ta = app.query_one("#ta", CappedTextArea)
            ta.focus()
            await pilot.pause()
            app.copy_to_clipboard("clip text")
            ta.action_paste()
            await pilot.pause()
            return ta.text

    assert asyncio.run(_run()) == "clip text"


def test_five_construction_sites_yield_capped_text_area() -> None:
    """The class swap actually landed: every one of the five paste surfaces is
    capped **at its construction site** (static source proof — no app mount
    required).

    ⚠ **The oracle is `issubclass`, not a class-NAME allowlist** (widened at
    batch-48 Inc-5, which is when the old form's flaw became visible). The
    protected property is *"this site is capped"*. The previous form filtered
    construction calls through a hardcoded ``{"TextArea", "CappedTextArea"}``
    name set and demanded the recorded name be exactly ``"CappedTextArea"`` —
    so when Inc-5 swapped ``#patch_paste_text`` to ``JsonHighlightTextArea``
    (a ``CappedTextArea`` SUBCLASS that inherits both capped ingresses
    untouched), the site fell out of the filter entirely and the test failed
    with ``got None`` — reporting an uncapped surface where the cap was in
    fact intact. It was a **false alarm the first time a subclass appeared**,
    and the same shape would have been a **false pass** had a subclass ever
    OVERRIDDEN the cap while keeping the name.

    Resolving each constructor name against its own module and asking
    ``issubclass(cls, CappedTextArea)`` binds the assertion to the class
    HIERARCHY rather than to a spelling. It stays a static source proof — the
    ids and their constructors are still read out of the AST, so a site that
    silently reverts to a bare ``TextArea`` is still caught (mutation-verified
    at Inc-5: reverting ``#patch_paste_text`` to ``TextArea`` turns this RED).
    """
    import ast
    from pathlib import Path

    import s19_app.tui.screens as screens_mod
    import s19_app.tui.screens_directionb as directionb_mod

    ids_by_module = {
        screens_mod: {
            "changeset_json_text",
            "entry_json_text",
            "report_declared_regions",
            "operation_config",
        },
        directionb_mod: {"patch_paste_text"},
    }

    for module, expected_ids in ids_by_module.items():
        path = Path(module.__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found: dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            if name is None:
                continue
            for kw in node.keywords:
                if kw.arg == "id" and isinstance(kw.value, ast.Constant):
                    found[kw.value.value] = name
        for wid in expected_ids:
            constructor = found.get(wid)
            assert constructor is not None, (
                f"{path.name}: no construction site found for #{wid}"
            )
            cls = getattr(module, constructor, None)
            assert cls is not None, (
                f"{path.name}: #{wid} is constructed as {constructor!r}, which "
                f"is not importable from the module — the AST name must "
                f"resolve for the cap to be provable"
            )
            assert isinstance(cls, type) and issubclass(cls, CappedTextArea), (
                f"{path.name}: #{wid} must be constructed as CappedTextArea or "
                f"a subclass of it (the 64 KiB paste cap); got {constructor!r}"
            )
