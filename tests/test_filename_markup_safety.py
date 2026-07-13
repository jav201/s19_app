"""Batch-39 Inc-3 (S3 / P-3) — filename markup hygiene.

File-derived names (filenames / paths) reach markup-ENABLED render surfaces.
A hostile filename such as ``[red]evil[/].s19`` must NOT leak Rich styling nor
crash the render with a ``MarkupError``. This module pins the two enumerated
sinks:

- **AC-3.1** — the ``#status_text`` ``Label`` (built ``markup=False``): a hostile
  filename driven through ``_format_coexistence_status`` → ``set_file_status``
  renders the brackets LITERALLY (no style strip, no ``MarkupError``). Read
  through the shipped surface (the mounted ``Label``'s rendered visual) under a
  real ``App.run_test()`` pilot.
- **AC-3.2** — the three ``self.notify`` sites that embed file-derived / dynamic
  text (``app.py`` verify-mismatch name, manifest-write issue messages, manifest
  verify drift/messages) pass ``markup=False``. Asserted as a drift-proof
  consumer-contract invariant over ``app.py``'s AST: every ``self.notify`` call
  whose first positional argument is NOT a constant string literal (i.e. it is
  dynamic / file-derived) must pass ``markup=False``. The two static-string
  notifies stay untouched.

C-17 family (markup-injection hardening); mirrors the batch-33 ``#log_line_*``
scrub precedent. textual==8.2.8 pinned — reading ``Label``'s stored visual is a
version-locked white-box read of the shipped render, same footing as Inc-1's
private-symbol dependency.
"""

from __future__ import annotations

import ast
from pathlib import Path

from textual.widgets import Label

from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile

import s19_app.tui.app as app_module


def _make_loaded(path: Path) -> LoadedFile:
    """Minimal primary-only ``LoadedFile`` whose name drives the status line."""
    return LoadedFile(
        path=path,
        file_type="s19",
        mem_map={},
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )


def _status_visual_plain(app: S19TuiApp) -> str:
    """Return the plain text actually rendered into ``#status_text``.

    ``Static.update`` eagerly builds a ``Visual`` via ``visualize(...,
    markup=self._render_markup)`` and stores it on the name-mangled
    ``_Static__visual`` attribute. Its ``.plain`` is the text that reaches the
    screen — under ``markup=True`` a ``[red]`` tag is consumed (styled, brackets
    stripped); under ``markup=False`` the brackets survive literally. Reading it
    is the load-bearing through-surface observation for AC-3.1 (textual==8.2.8
    pinned).
    """
    label = app.query_one("#status_text", Label)
    return getattr(label, "_Static__visual").plain


def test_at_s3_status_text_renders_hostile_filename_literally(tmp_path: Path) -> None:
    """AC-3.1 — a markup-metacharacter filename renders literally in ``#status_text``.

    Threat model: a real filesystem name cannot contain ``/`` (it is a path
    separator), so a Rich *close* tag (``[/]``) is unreachable via a filename;
    the reachable injection is an *open* style tag, e.g. ``[red]evil.s19``. Under
    the markup-ENABLED default Rich consumes ``[red]`` and styles the text —
    the RED counterfactual (pre-fix) is a visual plain of
    ``Loaded evil.s19 (S19 only)`` (brackets stripped, style leaked).

    GREEN (post-fix, ``#status_text`` built ``markup=False``): the brackets
    survive verbatim through ``set_file_status`` → the mounted ``Label``.
    """
    import asyncio

    hostile_name = "[red]evil[bold].s19"

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            hostile_path = tmp_path / hostile_name
            app.set_file_status(
                app._format_coexistence_status(_make_loaded(hostile_path), hostile_path)
            )
            await pilot.pause()
            return _status_visual_plain(app)

    plain = asyncio.run(_drive())

    assert hostile_name in plain, (
        f"hostile filename must render literally in #status_text; got {plain!r} "
        "(style tags consumed / brackets stripped => markup leaked)"
    )


def test_at_s3_dynamic_notify_sites_pass_markup_false() -> None:
    """AC-3.2 — every dynamic-message ``self.notify`` in ``app.py`` passes ``markup=False``.

    Consumer-contract invariant (drift-proof vs line shifts): a ``self.notify``
    whose first positional argument is a constant string literal is
    author-controlled (safe under the ``markup=True`` default); one whose first
    argument is anything else (an f-string or a variable) can embed file-derived
    text and MUST pass ``markup=False``. This targets exactly the three
    enumerated sinks (verify-mismatch name, manifest-write issues, manifest
    verify drift/messages) without pinning line numbers, and leaves the two
    static-string notifies free.
    """
    source = Path(app_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    offenders: list[str] = []
    dynamic_sites = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "notify"
            and isinstance(func.value, ast.Name)
            and func.value.id == "self"
        ):
            continue
        first = node.args[0] if node.args else None
        is_static = isinstance(first, ast.Constant) and isinstance(first.value, str)
        if is_static:
            continue
        dynamic_sites += 1
        markup_false = any(
            kw.arg == "markup"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
            for kw in node.keywords
        )
        if not markup_false:
            offenders.append(f"line {node.lineno}")

    assert dynamic_sites >= 3, (
        f"expected at least the 3 enumerated dynamic-message notify sites; "
        f"found {dynamic_sites} — the guard may be mis-detecting call sites"
    )
    assert offenders == [], (
        "these self.notify() calls embed dynamic (file-derived) text but do not "
        f"pass markup=False (markup injection sink): {offenders}"
    )
