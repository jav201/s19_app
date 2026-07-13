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
    a ``CappedTextArea`` at its construction site (static source proof — no app
    mount required)."""
    import ast
    from pathlib import Path

    import s19_app.tui.screens as screens_mod
    import s19_app.tui.screens_directionb as directionb_mod

    ids_by_module = {
        Path(screens_mod.__file__): {
            "changeset_json_text",
            "entry_json_text",
            "report_declared_regions",
            "operation_config",
        },
        Path(directionb_mod.__file__): {"patch_paste_text"},
    }

    for path, expected_ids in ids_by_module.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found: dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            if name not in {"TextArea", "CappedTextArea"}:
                continue
            for kw in node.keywords:
                if kw.arg == "id" and isinstance(kw.value, ast.Constant):
                    found[kw.value.value] = name
        for wid in expected_ids:
            assert found.get(wid) == "CappedTextArea", (
                f"{path.name}: #{wid} must be constructed as CappedTextArea, "
                f"got {found.get(wid)!r}"
            )
