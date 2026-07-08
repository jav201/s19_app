"""Input widget that pastes from the OS clipboard on Ctrl+V.

Textual's stock ``Input`` binds ``ctrl+v`` to an ``action_paste`` that reads
from ``self.app.clipboard`` — an internal string buffer (``App._clipboard``)
that is populated ONLY when the user invokes ``copy_to_clipboard`` from
inside the running app (typically via Ctrl+C on selected input text). Text
copied in another application never reaches that buffer, so pressing
Ctrl+V in a stock ``Input`` after copying externally does nothing.

Bracketed paste (the terminal sending ``\\x1b[200~...\\x1b[201~``) does route
through ``Input._on_paste`` and does use the OS clipboard, but in a
terminal that has negotiated the Kitty keyboard protocol (Windows Terminal
with Textual's Windows driver, which enables it via ``CSI > 1 u`` before
enabling bracketed paste), the terminal forwards Ctrl+V as a plain key
event rather than converting it to a bracketed paste sequence. The key
event fires the Input's ``ctrl+v`` binding, ``action_paste`` reads the
empty internal clipboard, and the paste silently fails.

The user-visible workaround in such terminals is Ctrl+Shift+V (which
Windows Terminal *always* treats as a paste-from-clipboard shortcut and
converts to a bracketed paste sequence), but that is not how users expect
Ctrl+V to behave.

This module supplies :class:`OsClipboardInput`, a drop-in replacement for
``Input`` whose ``action_paste`` reads the OS clipboard via ``tkinter``
(Python stdlib, no extra dependencies). If the read fails for any reason —
no display, Tk unavailable, another process holding the clipboard — we
fall back to the stock behavior so nothing regresses.
"""

from __future__ import annotations

import logging
from typing import Optional

from textual.widgets import Input

logger = logging.getLogger(__name__)


def read_os_clipboard() -> Optional[str]:
    """
    Summary:
        Return the current OS clipboard text, or ``None`` on failure.

    Returns:
        Optional[str]: Clipboard text if it could be read, else ``None``.

    Data Flow:
        - Imports ``tkinter`` lazily so headless environments where Tk is
          missing do not pay the import cost or fail at module load.
        - Instantiates a hidden root, reads ``clipboard_get`` and destroys
          the root. Any exception (empty clipboard, no display, race
          against another process, non-text content) is swallowed and
          logged at debug level; callers get ``None`` and should fall back.

    Dependencies:
        Used by:
            - :class:`OsClipboardInput.action_paste`
    """
    try:
        import tkinter as tk
    except Exception as exc:  # pragma: no cover — Tk is stdlib on Windows.
        logger.debug("read_os_clipboard: tkinter unavailable: %s", exc)
        return None
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        text = root.clipboard_get()
    except Exception as exc:
        logger.debug("read_os_clipboard: clipboard read failed: %s", exc)
        return None
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:  # pragma: no cover — best-effort cleanup.
                pass
    return text if isinstance(text, str) else None


class OsClipboardInput(Input):
    """
    Summary:
        Drop-in ``Input`` replacement whose ``action_paste`` reads from the
        OS clipboard first, then falls back to Textual's internal clipboard
        (``App._clipboard``) when the OS read fails. Uses only ``tkinter``
        from the standard library — no new runtime dependency.

    Data Flow:
        - ``action_paste`` (bound to Ctrl+V by ``Input.BINDINGS``) calls
          :func:`read_os_clipboard`; on ``None`` it falls back to
          ``self.app.clipboard``. In both branches, only the first line of
          the payload is inserted, matching Textual's stock
          ``Input._on_paste`` policy for single-line ``Input`` widgets.
        - The insertion goes through ``self.replace(text, start, end)``
          against the current selection, identical to the stock behaviour,
          so selection replace semantics are preserved.

    Dependencies:
        Uses:
            - :func:`read_os_clipboard`
            - ``self.app.clipboard`` (fallback)
        Used by:
            - :class:`s19_app.tui.screens.LoadFileScreen`
    """

    def action_paste(self) -> None:
        text = read_os_clipboard()
        if text is None:
            text = self.app.clipboard
        if not text:
            return
        first_line = text.splitlines()[0] if text else ""
        start, end = self.selection
        self.replace(first_line, start, end)
