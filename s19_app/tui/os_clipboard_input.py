"""Input widget that pastes from the OS clipboard on Ctrl+V.

Textual's stock ``Input`` binds ``ctrl+v`` to an ``action_paste`` that
reads from ``self.app.clipboard`` — an in-process string buffer only
populated when ``copy_to_clipboard`` runs from inside the app (typically
Ctrl+C on selected input text). Text copied in another application never
reaches that buffer, so pressing Ctrl+V in a stock ``Input`` after copying
externally does nothing.

Bracketed paste (the terminal sending ``\\x1b[200~...\\x1b[201~``) does route
through ``Input._on_paste`` and does use the OS clipboard, but in a
terminal that has negotiated the Kitty keyboard protocol (Windows Terminal
with Textual's Windows driver, which enables it via ``CSI > 1 u`` before
enabling bracketed paste) the terminal forwards Ctrl+V as a plain key
event rather than converting it to a bracketed paste sequence. The key
event fires the Input's ``ctrl+v`` binding, ``action_paste`` reads the
empty internal clipboard, and the paste silently fails.

The user-visible workaround in such terminals is Ctrl+Shift+V (which
Windows Terminal *always* treats as a paste-from-clipboard shortcut and
converts to a bracketed paste sequence), but that is not how users expect
Ctrl+V to behave.

This module supplies :class:`OsClipboardInput`, a drop-in replacement for
``Input`` whose ``action_paste`` reads the OS clipboard through a
**layered cascade**:

    1. ``tkinter.Tk().clipboard_get()`` — Python stdlib, no extra runtime
       dep. Works in the vast majority of cases.
    2. ``ctypes`` against the Win32 clipboard API — no window, no event
       loop, immune to the transient states where Tk's implicit Tcl
       interpreter would raise ``TclError``.
    3. ``subprocess`` shelling out to PowerShell's ``Get-Clipboard -Raw``
       — a fresh process, completely isolated from any in-process
       clipboard grab state. Available on every Windows install (no
       Windows Terminal dependency).

Each layer carries its own short retry loop; the total worst-case budget
is well under one second so the user does not experience a hang. When
every layer fails we fall back to Textual's internal ``App.clipboard`` so
the paste-from-internal path (Ctrl+C then Ctrl+V inside the app) keeps
working, and we surface a warning notification so the user is not left
guessing why the paste did nothing.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
import time
from typing import Callable, Optional

from textual.widgets import Input

logger = logging.getLogger(__name__)

# Total budget across all layers stays under one second in the failure
# case so the user does not perceive a hang. Individual layer budgets:
#   tkinter    : 3 retries × 50 ms = 150 ms
#   ctypes     : 5 retries × 20 ms = 100 ms
#   powershell : one attempt, 500 ms subprocess wall-clock
_TK_RETRIES = 3
_TK_RETRY_DELAY_S = 0.05
_CTYPES_RETRIES = 5
_CTYPES_RETRY_DELAY_S = 0.02
_POWERSHELL_TIMEOUT_S = 0.5

# Bound the clipboard value we hand downstream. 64 Ki chars ≈ 2× the
# largest legal Windows extended path, so a real path never truncates.
_CLIPBOARD_READ_CAP_CHARS = 65536

_PASTE_FAIL_NOTIFICATION = (
    "Clipboard read failed — try Ctrl+Shift+V or type the path manually."
)


def _read_via_tk() -> Optional[str]:
    """Layer 1 — ``tkinter.Tk().clipboard_get()`` with short retries."""
    try:
        import tkinter as tk
    except Exception as exc:  # pragma: no cover — Tk is stdlib on CPython.
        logger.debug("_read_via_tk: tkinter unavailable: %s", exc)
        return None
    for attempt in range(_TK_RETRIES):
        root = None
        try:
            root = tk.Tk()
            root.withdraw()
            text = root.clipboard_get()
        except Exception as exc:
            logger.debug("_read_via_tk attempt %d failed: %s", attempt, exc)
            text = None
        finally:
            if root is not None:
                try:
                    root.destroy()
                except Exception:  # pragma: no cover — best-effort cleanup.
                    pass
        if isinstance(text, str):
            return text
        time.sleep(_TK_RETRY_DELAY_S)
    return None


def _read_via_ctypes() -> Optional[str]:
    """Layer 2 — Win32 clipboard API through ``ctypes`` with short retries.

    Uses ``OpenClipboard(NULL)`` so no window handle is needed. Bypasses
    the Tcl interpreter and any of its window-manager expectations.
    Returns ``None`` on any non-Windows platform.
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes
    except Exception as exc:  # pragma: no cover — ctypes ships with CPython.
        logger.debug("_read_via_ctypes: ctypes unavailable: %s", exc)
        return None

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    CF_UNICODETEXT = 13

    opened = False
    for _ in range(_CTYPES_RETRIES):
        if user32.OpenClipboard(None):
            opened = True
            break
        time.sleep(_CTYPES_RETRY_DELAY_S)
    if not opened:
        logger.debug("_read_via_ctypes: OpenClipboard failed after %d retries",
                     _CTYPES_RETRIES)
        return None
    try:
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            logger.debug("_read_via_ctypes: no CF_UNICODETEXT on clipboard")
            return None
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            logger.debug("_read_via_ctypes: GlobalLock returned null")
            return None
        try:
            return ctypes.wstring_at(pointer)
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _read_via_powershell() -> Optional[str]:
    """Layer 3 — subprocess ``powershell.exe Get-Clipboard -Raw`` fallback.

    A fresh process reads the clipboard, isolating us from any in-process
    lock state. Ships with every Windows install (does not depend on
    Windows Terminal). Returns ``None`` on any non-Windows platform.

    Encoding: ``utf-8`` explicit with ``errors='replace'`` so unicode
    paths (``Ñoño``, cyrillic, CJK, emoji) survive the round-trip
    instead of being corrupted by ``locale.getpreferredencoding()``
    (typically ``cp1252`` on Windows). We ask PowerShell itself to emit
    UTF-8 via ``[Console]::OutputEncoding``.
    """
    if sys.platform != "win32":
        return None
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
                "Get-Clipboard -Raw",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_POWERSHELL_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        logger.debug("_read_via_powershell timed out after %ss", exc.timeout)
        return None
    except FileNotFoundError as exc:
        logger.debug("_read_via_powershell: powershell.exe not on PATH: %s", exc)
        return None
    except OSError as exc:
        logger.debug("_read_via_powershell subprocess OSError: %s", exc)
        return None
    if result.returncode != 0:
        logger.debug(
            "_read_via_powershell exit=%d stderr=%s",
            result.returncode,
            result.stderr[:120],
        )
        return None
    text = result.stdout.rstrip("\r\n")
    return text if text else None


# Ordered cascade of clipboard-reading strategies. Overridable per-call
# (see ``read_os_clipboard(strategies=...)``) so tests can substitute
# fakes without monkeypatching module attributes.
_STRATEGIES: tuple[tuple[str, Callable[[], Optional[str]]], ...] = (
    ("tkinter", _read_via_tk),
    ("ctypes-win32", _read_via_ctypes),
    ("powershell", _read_via_powershell),
)


def _bound_clipboard_text(text: Optional[str]) -> Optional[str]:
    """
    Summary:
        Truncate a clipboard string to ``_CLIPBOARD_READ_CAP_CHARS`` so an
        oversized clipboard cannot flow unbounded into ``splitlines``, the
        Input widget, or the logs. Passes ``None`` and short strings
        through unchanged and never raises.

    Args:
        text (Optional[str]): Raw value returned by a clipboard strategy,
            possibly ``None`` or arbitrarily long.

    Returns:
        Optional[str]: ``None`` unchanged; otherwise ``text`` when its
        length is ``<= _CLIPBOARD_READ_CAP_CHARS``, else the ``CAP``-char
        prefix.

    Data Flow:
        - Called by :func:`read_os_clipboard` at the single non-``None``
          funnel before the success log + return, so every layer and any
          injected ``strategies`` cascade is bounded at one place.

    Dependencies:
        Uses:
            - ``_CLIPBOARD_READ_CAP_CHARS``
        Used by:
            - :func:`read_os_clipboard`
    """
    if text is None:
        return None
    return text[:_CLIPBOARD_READ_CAP_CHARS]


def read_os_clipboard(
    strategies: Optional[tuple[tuple[str, Callable[[], Optional[str]]], ...]] = None,
) -> Optional[str]:
    """
    Summary:
        Return the current OS clipboard text, or ``None`` when every
        layer of the cascade fails.

    Args:
        strategies (Optional[tuple[tuple[str, Callable[[], Optional[str]]], ...]]):
            Ordered cascade to attempt. When ``None`` (default) the
            module-level ``_STRATEGIES`` cascade is used
            (tkinter → ctypes → PowerShell). Tests inject fake cascades
            here to exercise failure and fallback ordering.

    Returns:
        Optional[str]: Clipboard text from the first strategy that
        returns a non-``None`` value, bounded to
        ``_CLIPBOARD_READ_CAP_CHARS``; ``None`` when every strategy fails.

    Data Flow:
        - Iterates ``strategies`` in order, calling each callable and
          returning its result the first time it is not ``None``, after
          bounding it through :func:`_bound_clipboard_text` so an
          oversized clipboard cannot flow unbounded downstream.
        - The default cascade prioritises the cheapest / most reliable
          layer first (``tkinter``); each fallback layer costs more
          latency but is impervious to the failure mode that could kill
          the previous one. Total worst-case wall-clock budget is well
          under one second (150 ms + 100 ms + 500 ms).
        - Each strategy's own exceptions are swallowed inside the
          strategy; this function does not raise.

    Dependencies:
        Uses:
            - :func:`_read_via_tk`
            - :func:`_read_via_ctypes`
            - :func:`_read_via_powershell`
            - :func:`_bound_clipboard_text`
        Used by:
            - :meth:`OsClipboardInput.action_paste`
    """
    cascade = strategies if strategies is not None else _STRATEGIES
    for name, reader in cascade:
        try:
            text = reader()
        except Exception as exc:  # pragma: no cover — defensive.
            logger.debug("read_os_clipboard: %s raised %s", name, exc)
            continue
        if text is not None:
            text = _bound_clipboard_text(text)
            logger.debug(
                "read_os_clipboard succeeded via %s (len=%d)", name, len(text)
            )
            return text
    logger.warning(
        "read_os_clipboard: every strategy failed (cascade=%s)",
        [name for name, _ in cascade],
    )
    return None


class OsClipboardInput(Input):
    """
    Summary:
        Drop-in ``Input`` replacement whose ``action_paste`` reads from
        the OS clipboard through a layered cascade
        (tkinter → ctypes Win32 API → PowerShell ``Get-Clipboard``),
        falling back to Textual's in-process buffer (``App._clipboard``)
        when every OS layer fails. Surfaces a ``notify`` warning on total
        failure so the user knows the paste did nothing and can reach for
        the OS-level workaround (Ctrl+Shift+V on Windows Terminal).

    Data Flow:
        - ``action_paste`` (bound to Ctrl+V by ``Input.BINDINGS``) is
          async so the cascade runs off the UI event loop via
          ``loop.run_in_executor`` — otherwise the worst-case PowerShell
          subprocess (up to 500 ms) would freeze the terminal.
        - The executor call yields to :func:`read_os_clipboard`; on
          ``None`` we fall back to ``self.app.clipboard``. On non-empty
          text, only the first line of the payload is inserted, matching
          Textual's stock ``Input._on_paste`` policy for single-line
          ``Input`` widgets.
        - The insertion goes through ``self.replace(text, start, end)``
          against the current selection, identical to stock behaviour.
        - On total clipboard failure (no OS layer succeeded AND the
          internal buffer is empty) we call ``self.app.notify(...)``
          with severity ``warning`` — the user sees an in-app message
          instead of a silent no-op, and typing / typing-into-selection
          continues to work normally.

    Dependencies:
        Uses:
            - :func:`read_os_clipboard`
            - ``self.app.clipboard`` (fallback)
            - ``self.app.notify`` (UX signal on total failure)
        Used by:
            - :class:`s19_app.tui.screens.LoadFileScreen`
    """

    async def action_paste(self) -> None:
        # Run the cascade off the UI event loop. Even the fast tk layer
        # blocks synchronously (~89 ms measured), and the PowerShell
        # rescue can spend up to 500 ms in a blocking subprocess. Both
        # would freeze the UI if invoked directly from the loop.
        loop = asyncio.get_event_loop()
        text = await loop.run_in_executor(None, read_os_clipboard)
        source = "os"
        if text is None:
            text = self.app.clipboard
            source = "internal"
        if not text:
            # Every source empty — surface a warning so the user knows
            # nothing was pasted and can reach for the OS-level shortcut.
            try:
                self.app.notify(
                    _PASTE_FAIL_NOTIFICATION,
                    severity="warning",
                    timeout=6.0,
                )
            except Exception:  # pragma: no cover — notify is best-effort.
                pass
            logger.warning(
                "action_paste: no clipboard text available (source=%s)", source
            )
            return
        first_line = text.splitlines()[0] if text else ""
        start, end = self.selection
        self.replace(first_line, start, end)
        logger.debug(
            "action_paste inserted %d chars from %s clipboard",
            len(first_line),
            source,
        )
