"""Input widget that pastes from — and copies/cuts to — the OS clipboard.

Textual's stock ``Input`` binds ``ctrl+v`` to an ``action_paste`` that
reads from ``self.app.clipboard`` — an in-process string buffer only
populated when ``copy_to_clipboard`` runs from inside the app (typically
Ctrl+C on selected input text). Text copied in another application never
reaches that buffer, so pressing Ctrl+V in a stock ``Input`` after copying
externally does nothing. The mirror problem affects copy/cut: the stock
actions only write that same in-process buffer (plus an OSC52 escape the
Windows driver does not reliably deliver), so text copied inside the TUI
never reaches other Windows applications.

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
**layered read cascade**:

    1. ``tkinter`` ``clipboard_get()`` through a **process-wide singleton
       root** — Python stdlib, no extra runtime dep. The ``tk.Tk()`` root
       is created exactly once, in the main thread (Tk pins its interpreter
       to the creating thread, and on Windows repeated create/destroy
       cycles in one process can fail persistently after the first — the
       BUG B7 residual root cause), reused for every read, and destroyed
       once at process exit. Works in the vast majority of cases.
    2. ``ctypes`` against the Win32 clipboard API — no window, no event
       loop, immune to the transient states where Tk's implicit Tcl
       interpreter would raise ``TclError``.
    3. ``subprocess`` shelling out to PowerShell's ``Get-Clipboard -Raw``
       — a fresh process, completely isolated from any in-process
       clipboard grab state. Available on every Windows install (no
       Windows Terminal dependency).

and whose ``action_copy`` / ``action_cut`` write the OS clipboard through
a **layered write cascade** (E3 ruling, finding F-B102-3):

    1. ``ctypes`` against the Win32 ``SetClipboardData`` API — the buffer
       ownership passes to the system on success, so the write is
       delivered immediately and survives app exit.
    2. ``tkinter`` ``clipboard_clear()`` + ``clipboard_append()`` on the
       existing process-wide singleton root — rescue layer only: Tk owns
       the clipboard content it writes, and that content can vanish when
       the singleton root is destroyed at process exit.
    3. ``subprocess`` shelling out to PowerShell's ``Set-Clipboard`` with
       the payload passed through stdin as UTF-8 — a fresh isolated
       process, and the copied text is never interpolated into the
       command line.

Each layer carries its own short retry loop; the worst-case budget is
dominated by the PowerShell rescue, capped at 2.0 s per subprocess so a
cold Windows PowerShell start can still succeed (finding F-B102-1), and
every OS access runs in an executor off the UI event loop so that budget
never freezes the interface. All clipboard payloads — read or written, OS
or the Textual internal mirror — are capped at ``_CLIPBOARD_CAP_CHARS``
(65,536 chars). When every OS write strategy fails we retain Textual's
internal clipboard and paint a warning; when every read layer fails we
fall back to the internal clipboard and, when it is also empty, select
the current field text and paint a read warning.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import subprocess
import sys
import threading
import time
from typing import TYPE_CHECKING, Callable, Optional

from textual.actions import SkipAction
from textual.widgets import Input

if TYPE_CHECKING:  # pragma: no cover — typing only.
    from textual.app import App

logger = logging.getLogger(__name__)

# Layer retry budgets. The Tk/ctypes retry loops stay short; the
# PowerShell rescue gets 2.0 s per subprocess (E3 ruling, finding
# F-B102-1: a cold Windows PowerShell start can exceed the old 500 ms cap
# before Get-Clipboard / Set-Clipboard even runs). Every OS access runs in
# an executor, so the 2.0 s worst case never blocks the UI event loop.
#   tkinter    : 3 retries × 50 ms = 150 ms
#   ctypes     : 5 retries × 20 ms = 100 ms
#   powershell : one attempt, 2.0 s subprocess wall-clock
_TK_RETRIES = 3
_TK_RETRY_DELAY_S = 0.05
_CTYPES_RETRIES = 5
_CTYPES_RETRY_DELAY_S = 0.02
_POWERSHELL_TIMEOUT_S = 2.0

# Bound every clipboard payload — read or written, OS or the internal
# mirror — to 64 Ki chars ≈ 2× the largest legal Windows extended path,
# so a real path never truncates.
_CLIPBOARD_CAP_CHARS = 65536
# Historical alias: ``screens_directionb.py`` and the batch-39/batch-67
# test modules import ``_CLIPBOARD_READ_CAP_CHARS``. The value is
# direction-agnostic — writes are capped exactly like reads (E3 addendum).
_CLIPBOARD_READ_CAP_CHARS = _CLIPBOARD_CAP_CHARS

_PASTE_FAIL_NOTIFICATION = (
    "Clipboard read failed — try Ctrl+Shift+V or type the path manually."
)
_WRITE_FAIL_NOTIFICATION = (
    "Clipboard write failed — copied inside the app only."
)

# Serialize every PowerShell clipboard subprocess (read and write) so
# rapid-fire paste/copy key spam cannot spawn concurrent PowerShell
# processes (E3 addendum 4).
_POWERSHELL_SUBPROCESS_LOCK = threading.Lock()

# Static PowerShell write command (E3 ruling): the payload travels through
# stdin (``$input | Set-Clipboard``), never interpolated into ``-Command``,
# so copied text cannot break out of the command line.
_POWERSHELL_WRITE_COMMAND = (
    "powershell",
    "-NoProfile",
    "-Command",
    "$input | Set-Clipboard",
)


def _create_tk_root() -> Optional[object]:
    """Create a single withdrawn ``tkinter.Tk`` root.

    Must be called from the MAIN thread only: Tk binds its interpreter to
    the creating thread, and on Windows repeated create/destroy cycles of
    ``tk.Tk()`` in the same process can fail persistently after the first
    one (BUG B7 residual root cause, 2026-10-18). Returns ``None`` when
    tkinter is unavailable or the root cannot be created (headless / no
    display), in which case the cascade falls through to the ctypes /
    PowerShell layers unchanged.
    """
    try:
        import tkinter as tk
    except Exception as exc:  # pragma: no cover — Tk is stdlib on CPython.
        logger.debug("_create_tk_root: tkinter unavailable: %s", exc)
        return None
    try:
        root = tk.Tk()
        root.withdraw()
    except Exception as exc:
        logger.debug("_create_tk_root: tk.Tk() failed: %s", exc)
        return None
    return root


class _TkRootSingleton:
    """Process-wide lazy singleton for the layer-1 Tk clipboard root.

    Exactly one ``tk.Tk()`` is created per process, in the main thread, and
    it is destroyed exactly once at process exit (``atexit``). Reads via
    ``clipboard_get`` and rescue writes via ``clipboard_clear`` /
    ``clipboard_append`` may run on an executor thread once the root
    exists — the stateful create/destroy lifecycle is what Tk pins to the
    main thread, and that lifecycle lives entirely in this class.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._root: Optional[object] = None
        # Sticky negative: once creation failed (no tkinter / headless) do
        # not pay the import + failure cost on every paste.
        self._unavailable = False
        # Seam for tests / diagnostics: name of the thread that created
        # the root (creation is only ever attempted on the main thread).
        self.creator_thread: Optional[str] = None

    def get_or_create(self) -> Optional[object]:
        """Return the shared root, creating it when called on the main thread.

        Returns ``None`` when tk is unavailable, when creation previously
        failed, or when called off the main thread before the root exists
        (creation is main-thread-only; the executor reader then yields to
        the next cascade layer — ``action_paste`` primes the root from the
        main thread before entering the executor).
        """
        with self._lock:
            if self._root is not None:
                return self._root
            if self._unavailable:
                return None
            if threading.current_thread() is not threading.main_thread():
                return None
            root = _create_tk_root()
            if root is None:
                self._unavailable = True
                return None
            self._root = root
            self.creator_thread = threading.current_thread().name
            atexit.register(_destroy_tk_root_singleton)
            return self._root

    def get_existing(self) -> Optional[object]:
        """Return the shared root if it already exists, else ``None``."""
        with self._lock:
            return self._root


def _destroy_tk_root_singleton() -> None:
    """Destroy the shared root exactly once, at process exit."""
    with _TK_ROOT._lock:
        root = _TK_ROOT._root
        _TK_ROOT._root = None
    if root is not None:
        try:
            root.destroy()
        except Exception:  # pragma: no cover — best-effort at exit.
            pass


_TK_ROOT = _TkRootSingleton()


def _prime_tk_root() -> None:
    """Create the shared Tk root NOW when running on the main thread.

    The clipboard actions prime the root from the app's event loop (the
    main thread, where Tk demands creation) before dispatching the cascade
    to the executor, so the executor thread never attempts a Tk creation.
    Off-main-thread calls are a no-op: the reader/writer will then fall
    through to the next cascade layer.
    """
    if threading.current_thread() is threading.main_thread():
        _TK_ROOT.get_or_create()


def _read_via_tk() -> Optional[str]:
    """Layer 1 — read via the process-wide Tk root with short retries.

    The root is a lazy singleton (see :class:`_TkRootSingleton`): created
    once in the main thread, reused for every read, destroyed once at
    process exit. This function never creates the root off the main thread
    — the pre-fix create/destroy-per-paste cycle killed layer 1 permanently
    mid-session on Windows (BUG B7, 2026-10-18).

    Thread-safety note: ``clipboard_get`` on the already-created root from
    an executor thread is accepted here — the call is a single synchronous
    Win32 clipboard read through the Tcl interpreter and does not touch the
    root's event loop; only root creation/destruction is main-thread-pinned.
    """
    for attempt in range(_TK_RETRIES):
        root = _TK_ROOT.get_or_create()
        if root is None:
            # tk unavailable, creation previously failed, or we are off the
            # main thread before the root exists — let the cascade move on.
            return None
        try:
            text = root.clipboard_get()
        except Exception as exc:
            logger.debug("_read_via_tk attempt %d failed: %s", attempt, exc)
            text = None
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
    Windows Terminal). Serialized with the write layer through
    ``_POWERSHELL_SUBPROCESS_LOCK`` so key spam cannot spawn concurrent
    PowerShell processes. Returns ``None`` on any non-Windows platform.

    Encoding: ``utf-8`` explicit with ``errors='replace'`` so unicode
    paths (``Ñoño``, cyrillic, CJK, emoji) survive the round-trip
    instead of being corrupted by ``locale.getpreferredencoding()``
    (typically ``cp1252`` on Windows). We ask PowerShell itself to emit
    UTF-8 via ``[Console]::OutputEncoding``.
    """
    if sys.platform != "win32":
        return None
    try:
        kwargs: dict = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": _POWERSHELL_TIMEOUT_S,
            "shell": False,
        }
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with _POWERSHELL_SUBPROCESS_LOCK:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
                    "Get-Clipboard -Raw",
                ],
                **kwargs,
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


def _write_via_ctypes(text: str) -> bool:
    """Write layer 1 — Win32 ``SetClipboardData`` through ``ctypes``.

    Allocates a movable UTF-16 buffer, opens the clipboard, empties it and
    sets ``CF_UNICODETEXT``. On success ownership of the global buffer
    passes to the system (per the Win32 contract it must NOT be freed), so
    this layer runs FIRST in the write cascade: the content is handed to
    the OS immediately and survives app exit (E3 ruling, finding F-B102-3).
    Returns ``False`` off Windows or on any Win32 failure, freeing the
    allocated buffer on that failure path only.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes
    except Exception as exc:  # pragma: no cover — ctypes ships with CPython.
        logger.debug("_write_via_ctypes: ctypes unavailable: %s", exc)
        return False

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    data = text.encode("utf-16-le") + b"\x00\x00"
    handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
    if not handle:
        logger.debug("_write_via_ctypes: GlobalAlloc failed")
        return False
    pointer = kernel32.GlobalLock(handle)
    if not pointer:
        kernel32.GlobalFree(handle)
        logger.debug("_write_via_ctypes: GlobalLock failed")
        return False
    try:
        ctypes.memmove(pointer, data, len(data))
    finally:
        kernel32.GlobalUnlock(handle)

    opened = False
    for _ in range(_CTYPES_RETRIES):
        if user32.OpenClipboard(None):
            opened = True
            break
        time.sleep(_CTYPES_RETRY_DELAY_S)
    if not opened:
        kernel32.GlobalFree(handle)
        logger.debug(
            "_write_via_ctypes: OpenClipboard failed after %d retries",
            _CTYPES_RETRIES,
        )
        return False
    try:
        if not user32.EmptyClipboard():
            kernel32.GlobalFree(handle)
            logger.debug("_write_via_ctypes: EmptyClipboard failed")
            return False
        if not user32.SetClipboardData(CF_UNICODETEXT, handle):
            kernel32.GlobalFree(handle)
            logger.debug("_write_via_ctypes: SetClipboardData failed")
            return False
    finally:
        user32.CloseClipboard()
    return True


def _write_via_tk(text: str) -> bool:
    """Write layer 2 — Tk ``clipboard_clear`` + ``clipboard_append`` rescue.

    Runs on the existing process-wide singleton root and deliberately does
    NOT create it: creation is main-thread-pinned (see
    :class:`_TkRootSingleton`) and the copy/cut actions prime the root on
    the UI thread before the cascade enters the executor. Tk owns the
    clipboard content it writes until another application takes ownership
    — and the content can vanish when the singleton root is destroyed at
    process exit — so this layer runs AFTER the Win32 layer. Returns
    ``False`` when Tk is unavailable or the write raises.
    """
    root = _TK_ROOT.get_existing()
    if root is None:
        return False
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
    except Exception as exc:
        logger.debug("_write_via_tk failed: %s", exc)
        return False
    return True


def _write_via_powershell(text: str) -> bool:
    """Write layer 3 — subprocess ``powershell.exe Set-Clipboard`` fallback.

    A fresh, isolated process writes the clipboard — impervious to any
    in-process clipboard grab state. The command is STATIC
    (``_POWERSHELL_WRITE_COMMAND``): the payload travels through stdin as
    UTF-8 (``$input | Set-Clipboard``), never interpolated into
    ``-Command``, so copied text cannot break out of the command line.
    ``shell=False`` is explicit and a hidden console window is requested
    via ``creationflags``. Serialized with the read layer through
    ``_POWERSHELL_SUBPROCESS_LOCK`` so key spam cannot spawn concurrent
    PowerShell processes. Returns ``True`` only for exit code 0; ``False``
    off Windows, on timeout (``_POWERSHELL_TIMEOUT_S``), on missing
    PowerShell or on any non-zero exit.
    """
    if sys.platform != "win32":
        return False
    kwargs: dict = {
        "input": text,
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": _POWERSHELL_TIMEOUT_S,
        "shell": False,
    }
    kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        with _POWERSHELL_SUBPROCESS_LOCK:
            result = subprocess.run(list(_POWERSHELL_WRITE_COMMAND), **kwargs)
    except subprocess.TimeoutExpired:
        logger.debug(
            "_write_via_powershell timed out after %ss", _POWERSHELL_TIMEOUT_S
        )
        return False
    except FileNotFoundError as exc:
        logger.debug("_write_via_powershell: powershell.exe not on PATH: %s", exc)
        return False
    except OSError as exc:
        logger.debug("_write_via_powershell subprocess OSError: %s", exc)
        return False
    if result.returncode != 0:
        logger.debug(
            "_write_via_powershell exit=%d stderr=%s",
            result.returncode,
            result.stderr[:120],
        )
        return False
    return True


# Ordered cascade of clipboard-reading strategies. Overridable per-call
# (see ``read_os_clipboard(strategies=...)``) so tests can substitute
# fakes without monkeypatching module attributes.
_STRATEGIES: tuple[tuple[str, Callable[[], Optional[str]]], ...] = (
    ("tkinter", _read_via_tk),
    ("ctypes-win32", _read_via_ctypes),
    ("powershell", _read_via_powershell),
)

# Ordered cascade of clipboard-writing strategies. Win32 runs first so a
# successful write survives app exit; Tk is the in-process rescue; the
# static-command PowerShell layer is the isolated-process last resort.
# Overridable per-call (see ``write_os_clipboard(strategies=...)``) so
# tests can substitute fakes without monkeypatching module attributes.
_WRITE_STRATEGIES: tuple[tuple[str, Callable[[str], bool]], ...] = (
    ("win32", _write_via_ctypes),
    ("tkinter", _write_via_tk),
    ("powershell", _write_via_powershell),
)


def _bound_clipboard_text(text: Optional[str]) -> Optional[str]:
    """
    Summary:
        Truncate a clipboard string to ``_CLIPBOARD_CAP_CHARS`` so an
        oversized clipboard cannot flow unbounded into ``splitlines``, the
        Input widget, or the logs. Passes ``None`` and short strings
        through unchanged and never raises.

    Args:
        text (Optional[str]): Raw value returned by a clipboard strategy,
            possibly ``None`` or arbitrarily long.

    Returns:
        Optional[str]: ``None`` unchanged; otherwise ``text`` when its
        length is ``<= _CLIPBOARD_CAP_CHARS``, else the ``CAP``-char
        prefix.

    Data Flow:
        - Called by :func:`read_os_clipboard` at the single non-``None``
          funnel before the success log + return, so every layer and any
          injected ``strategies`` cascade is bounded at one place.
        - :func:`write_os_clipboard` applies the same cap directly to its
          payload before the write cascade, so the cap binds the OS write
          and the caller-side internal mirror equally.

    Dependencies:
        Uses:
            - ``_CLIPBOARD_CAP_CHARS``
        Used by:
            - :func:`read_os_clipboard`
    """
    if text is None:
        return None
    return text[:_CLIPBOARD_CAP_CHARS]


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
        ``_CLIPBOARD_CAP_CHARS``; ``None`` when every strategy fails.

    Data Flow:
        - Iterates ``strategies`` in order, calling each callable and
          returning its result the first time it is not ``None``, after
          bounding it through :func:`_bound_clipboard_text` so an
          oversized clipboard cannot flow unbounded downstream.
        - The default cascade prioritises the cheapest / most reliable
          layer first (``tkinter``); each fallback layer costs more
          latency but is impervious to the failure mode that could kill
          the previous one. The worst-case wall-clock budget is dominated
          by the PowerShell rescue (150 ms + 100 ms + 2,000 ms); the
          cascade runs in an executor, off the UI event loop.
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
            - :meth:`s19_app.tui.capped_text_area.CappedTextArea.action_paste`
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


def write_os_clipboard(
    text: str,
    strategies: Optional[tuple[tuple[str, Callable[[str], bool]], ...]] = None,
) -> bool:
    """
    Summary:
        Write ``text`` to the OS clipboard through the ordered
        Win32 → Tk → PowerShell write cascade, returning ``True`` on the
        first successful strategy. The payload is capped at
        ``_CLIPBOARD_CAP_CHARS`` before any strategy runs.

    Args:
        text (str): Text to write; over-cap payloads are truncated to
            ``_CLIPBOARD_CAP_CHARS`` first.
        strategies (Optional[tuple[tuple[str, Callable[[str], bool]], ...]]):
            Ordered cascade to attempt. When ``None`` (default) the
            module-level ``_WRITE_STRATEGIES`` cascade is used
            (win32 → tkinter → powershell). Tests inject fake cascades
            here to exercise failure and fallback ordering.

    Returns:
        bool: ``True`` when a strategy wrote the OS clipboard; ``False``
        when every strategy failed (a strategy exception means failure of
        that layer only — the cascade continues).

    Data Flow:
        - Truncates ``text`` to ``_CLIPBOARD_CAP_CHARS`` once, then
          iterates ``strategies`` in order, returning ``True`` the first
          time a writer returns ``True``.
        - Win32 runs first so a successful write survives app exit;
          Tk rescue writes can vanish when the singleton root is
          destroyed at exit; PowerShell is the isolated-process last
          resort with a 2.0 s budget.

    Dependencies:
        Uses:
            - :func:`_write_via_ctypes`
            - :func:`_write_via_tk`
            - :func:`_write_via_powershell`
            - ``_CLIPBOARD_CAP_CHARS``
        Used by:
            - :func:`_mirror_and_write_os_clipboard`
    """
    text = text[:_CLIPBOARD_CAP_CHARS]
    cascade = strategies if strategies is not None else _WRITE_STRATEGIES
    for name, writer in cascade:
        try:
            if writer(text):
                logger.debug(
                    "write_os_clipboard succeeded via %s (len=%d)", name, len(text)
                )
                return True
        except Exception as exc:  # pragma: no cover — defensive.
            logger.debug("write_os_clipboard: %s raised %s", name, exc)
            continue
    logger.warning(
        "write_os_clipboard: every strategy failed (cascade=%s)",
        [name for name, _ in cascade],
    )
    return False


async def _mirror_and_write_os_clipboard(app: "App", text: str) -> None:
    """
    Summary:
        Shared copy/cut tail for :class:`OsClipboardInput` and
        ``CappedTextArea``: truncate ``text`` to the cap, mirror it to
        Textual's internal clipboard (cheap, synchronous, and retained
        even if every OS layer fails), prime the Tk root on the UI thread,
        then run the write cascade in the executor. On total OS failure
        the internal mirror is kept and the exact write warning
        ``_WRITE_FAIL_NOTIFICATION`` is painted.

    Args:
        app: The running app — mirror target and notification surface.
        text (str): The selected text being copied/cut.

    Returns:
        None.

    Data Flow:
        - ``text[:_CLIPBOARD_CAP_CHARS]`` → ``app.copy_to_clipboard``
          (internal mirror) → :func:`_prime_tk_root` on the UI thread →
          :func:`write_os_clipboard` in the executor →
          ``app.notify(_WRITE_FAIL_NOTIFICATION, severity="warning")``
          when the cascade returns ``False``.

    Dependencies:
        Uses:
            - ``_CLIPBOARD_CAP_CHARS``, :func:`_prime_tk_root`,
              :func:`write_os_clipboard`, ``_WRITE_FAIL_NOTIFICATION``
        Used by:
            - :meth:`OsClipboardInput.action_copy`
            - :meth:`OsClipboardInput.action_cut`
            - :meth:`s19_app.tui.capped_text_area.CappedTextArea.action_copy`
            - :meth:`s19_app.tui.capped_text_area.CappedTextArea.action_cut`
    """
    text = text[:_CLIPBOARD_CAP_CHARS]
    try:
        app.copy_to_clipboard(text)
    except Exception:  # pragma: no cover — mirror is best-effort.
        logger.debug("internal clipboard mirror failed", exc_info=True)
    _prime_tk_root()
    loop = asyncio.get_event_loop()
    written = await loop.run_in_executor(None, write_os_clipboard, text)
    if written:
        return
    try:
        app.notify(
            _WRITE_FAIL_NOTIFICATION,
            severity="warning",
            timeout=6.0,
        )
    except Exception:  # pragma: no cover — notify is best-effort.
        pass
    logger.warning(
        "OS clipboard write failed; retained Textual internal clipboard only"
    )


class OsClipboardInput(Input):
    """
    Summary:
        Drop-in ``Input`` replacement whose ``action_paste`` reads from
        the OS clipboard through a layered cascade
        (tkinter → ctypes Win32 API → PowerShell ``Get-Clipboard``),
        falling back to Textual's in-process buffer (``App._clipboard``)
        when every OS layer fails, and whose ``action_copy`` /
        ``action_cut`` write the selection to the OS clipboard through the
        Win32 → Tk → PowerShell write cascade, keeping Textual's internal
        clipboard as a mirror/fallback. Surfaces ``notify`` warnings on
        total failure so the user knows the paste/copy did nothing and
        can reach for the OS-level workaround (Ctrl+Shift+V on Windows
        Terminal).

    Data Flow:
        - ``action_paste`` (bound to Ctrl+V by ``Input.BINDINGS``) is
          async so the cascade runs off the UI event loop via
          ``loop.run_in_executor`` — otherwise the worst-case PowerShell
          subprocess (up to 2.0 s) would freeze the terminal. Before
          entering the executor it primes the process-wide Tk root on the
          main thread (see :func:`_prime_tk_root`), so the Tk layer is
          only ever *read* from the executor thread.
        - The executor call yields to :func:`read_os_clipboard`; on
          ``None`` we fall back to ``self.app.clipboard``. On non-empty
          text, only the first line of the payload is inserted, matching
          Textual's stock ``Input._on_paste`` policy for single-line
          ``Input`` widgets.
        - The insertion goes through ``self.replace(text, start, end)``
          against the current selection, identical to stock behaviour.
        - On total clipboard failure (no OS layer succeeded AND the
          internal buffer is empty) we call ``self.select_all()`` and
          ``self.app.notify(...)`` with severity ``warning`` — the user
          sees an in-app message instead of a silent no-op, and the
          selected content marks the field as stale (BUG B7, 2026-10-18).
        - ``action_copy`` (Ctrl+C) / ``action_cut`` (Ctrl+X) are async
          overrides: an empty selection raises Textual's ``SkipAction``
          (so other Ctrl+C bindings still run); otherwise the selection
          is mirrored to ``App.clipboard`` and written to the OS
          clipboard via :func:`_mirror_and_write_os_clipboard` — copy
          leaves ``value``/selection unchanged, cut removes the selection
          first, and both keep the internal mirror even when every OS
          layer fails.

    Dependencies:
        Uses:
            - :func:`read_os_clipboard`
            - :func:`_mirror_and_write_os_clipboard`
            - ``self.app.clipboard`` (fallback)
            - ``self.app.notify`` (UX signal on total failure)
        Used by:
            - :class:`s19_app.tui.screens.LoadDialog` (``#load_path``)
    """

    async def action_copy(self) -> None:
        """Copy the current selection to the OS and internal clipboards.

        Summary:
            Async override of ``Input.action_copy``. With a non-empty
            selection the text — capped at ``_CLIPBOARD_CAP_CHARS`` — is
            mirrored to Textual's internal clipboard and written to the OS
            clipboard; neither ``value`` nor the selection is modified.
            With an empty selection raises ``SkipAction`` (stock
            behaviour), so the internal clipboard is NOT erased with an
            empty string and other Ctrl+C bindings still get their turn.

        Returns:
            None.

        Data Flow:
            ``selected_text`` → empty? → ``SkipAction``; else
            :func:`_mirror_and_write_os_clipboard`.

        Dependencies:
            Used by: the widget's ctrl+c key binding.
        """
        selected_text = self.selected_text
        if not selected_text:
            raise SkipAction()
        await _mirror_and_write_os_clipboard(self.app, selected_text)

    async def action_cut(self) -> None:
        """Cut the current selection (copy to clipboards and remove it).

        Summary:
            Async override of ``Input.action_cut``. With a non-empty
            selection the text is captured, removed from the input
            (through Textual's ``delete_selection``), mirrored to the
            internal clipboard and written to the OS clipboard. The local
            cut remains even when every OS write layer fails. With an
            empty selection raises ``SkipAction`` (stock ``action_copy``
            semantics) instead of copying an empty string.

        Returns:
            None.

        Data Flow:
            ``selected_text`` → empty? → ``SkipAction``; else
            ``delete_selection()`` → :func:`_mirror_and_write_os_clipboard`.

        Dependencies:
            Used by: the widget's ctrl+x key binding.
        """
        selected_text = self.selected_text
        if not selected_text:
            raise SkipAction()
        self.delete_selection()
        await _mirror_and_write_os_clipboard(self.app, selected_text)

    async def action_paste(self) -> None:
        # Prime the process-wide Tk root on the UI thread (the main thread,
        # where Tk demands creation) BEFORE the cascade runs in the executor
        # — creating/destroying tk.Tk() from the executor thread is what
        # used to kill layer 1 permanently mid-session (BUG B7 residual,
        # 2026-10-18). Priming is a no-op once the root exists.
        _prime_tk_root()
        # Run the cascade off the UI event loop. Even the fast tk layer
        # blocks synchronously (~89 ms measured), and the PowerShell
        # rescue can spend up to 2.0 s in a blocking subprocess. Both
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
            # Selecting the current content marks the field as "stale —
            # retype or re-paste", so a later compare cannot ride an
            # unnoticed old value (BUG B7, 2026-10-18).
            self.select_all()
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
