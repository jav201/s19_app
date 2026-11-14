"""Input widget that pastes from — and copies/cuts to — the Windows OS clipboard.

Textual's stock ``Input`` binds ``ctrl+v`` to an ``action_paste`` that
reads from ``self.app.clipboard`` — an in-process string buffer only
populated when ``copy_to_clipboard`` runs from inside the app (typically
Ctrl+C on selected input text). Text copied in another application never
reaches that buffer, so pressing Ctrl+V in a stock ``Input`` after copying
externally does nothing. The mirror problem affects copy/cut: the stock
actions only write that same in-process buffer (plus an OSC52 escape the
Windows driver does not reliably deliver), so text copied inside the TUI
never reaches other Windows applications.

Bracketed paste (the terminal sending a bracketed-paste sequence) does
route through ``Input._on_paste`` and does use the OS clipboard, but in a
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
``Input`` whose ``action_paste`` reads the Windows clipboard through a
**layered read cascade**:

    1. ``ctypes`` against the Win32 clipboard API — no window, no event
       loop, immune to the transient states that used to hang the removed
       Tk read layer.
    2. ``subprocess`` shelling out to the **system** PowerShell's
       ``Get-Clipboard -Raw`` — a fresh process, completely isolated from
       any in-process clipboard grab state, resolved by its absolute path
       under the system folder (never a bare name that a planted
       ``powershell.exe`` could hijack).

and whose ``action_copy`` / ``action_cut`` write the OS clipboard through
a **layered write cascade**:

    1. ``ctypes`` against the Win32 ``SetClipboardData`` API — the buffer
       ownership passes to the system on success, so the write is
       delivered immediately and survives app exit.
    2. ``subprocess`` shelling out to the system PowerShell's
       ``[Windows.Clipboard]::SetText()`` — the command is STATIC, loads
       PresentationCore, sets a UTF-8 no-BOM input encoding, receives
       explicitly encoded bytes through binary stdin, reads the payload in
       one shot via ``[Console]::In.ReadToEnd()`` and writes it verbatim
       (CR, CRLF and LF preserved exactly). The payload is never
       interpolated into the command line.

Every OS access runs in an executor off the UI event loop, and every
clipboard payload — read or written, OS or the Textual internal mirror —
is capped at ``_CLIPBOARD_CAP_CHARS`` (65,536 chars). Off Windows there is
no OS clipboard: a read returns ``None`` and a write ``False`` at once, no
process is started, and the app-clipboard / OSC 52 paths carry the text.
Both paste ingresses (the ``ctrl+v`` action and the terminal paste) strip
the *unsafe paste characters* — C0 controls except NUL, C1 controls, lone
surrogates and bidi controls — before insertion; a box with its own
``restrict`` filter is never stripped and refuses a paste that would put
an unsafe character into it. A right-click in the box copies the shown
selection, or pastes at the cursor when there is none. When every OS write
strategy fails we retain Textual's internal clipboard and paint a warning;
when every read layer fails we fall back to the internal clipboard and,
when it is also empty, select the current field text and paint a read
warning.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
import threading
import time
from typing import Callable, Optional

from textual import events
from textual.actions import SkipAction
from textual.app import App
from textual.widgets import Input

from s19_app.utils import _CONTROL_SCRUB

logger = logging.getLogger(__name__)

# Layer retry budgets. The Win32 read/write retry loops stay short; the
# PowerShell rescue gets 2.0 s per subprocess (E3 ruling, finding
# F-B102-1: a cold Windows PowerShell start can exceed the old 500 ms cap
# before the Get-Clipboard read / [Windows.Clipboard]::SetText write even
# runs). Every OS access runs in
# an executor, so the 2.0 s worst case never blocks the UI event loop.
#   ctypes     : 5 retries × 20 ms = 100 ms
#   powershell : one attempt, 2.0 s subprocess wall-clock
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

# Static PowerShell write command (E3 ruling): UTF-8 bytes travel through
# binary stdin, are read in one shot via ``[Console]::In.ReadToEnd()`` into
# a variable and written with ``[Windows.Clipboard]::SetText()`` — never
# interpolated into ``-Command``, so copied text cannot break out of the
# command line and its CR, CRLF and LF endings survive exactly. The program
# itself is resolved at
# call time by :func:`_system_powershell` (R-PASTE.16), so this tuple holds
# the arguments only.
_POWERSHELL_WRITE_COMMAND = (
    "-NoProfile",
    "-Command",
    "$ErrorActionPreference='Stop';"
    "Add-Type -AssemblyName PresentationCore;"
    "[Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false);"
    "$text=[Console]::In.ReadToEnd();"
    "[Windows.Clipboard]::SetText($text)",
)

# The one definition of the CTX-PASTE term *unsafe paste character*: every
# C0 and C1 control of the repository's ``_CONTROL_SCRUB`` (utils.py:41)
# except NUL (U+0000), plus the lone surrogates (U+D800–U+DFFF) and the
# bidi controls (U+202A–U+202E, U+2066–U+2069). NUL is left out (E3A-25):
# it starts no terminal sequence and every path consumer refuses it
# loudly, so stripping it would only turn a refused path into another
# path.
_UNSAFE_PASTE = dict.fromkeys(
    (
        *(c for c in _CONTROL_SCRUB if c != 0x00),
        *range(0xD800, 0xE000),
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
    )
)
# Translate tables derived once: the keep-set differs by box shape. A
# single-line box keeps TAB; a multi-line box keeps TAB, LF and CR.
_UNSAFE_PASTE_SINGLE = _UNSAFE_PASTE.copy()
_UNSAFE_PASTE_SINGLE.pop(0x09, None)
_UNSAFE_PASTE_MULTI = _UNSAFE_PASTE.copy()
for _KEPT_CONTROL in (0x09, 0x0A, 0x0D):
    _UNSAFE_PASTE_MULTI.pop(_KEPT_CONTROL, None)


def _system_directory() -> Optional[str]:
    """Return the Windows system directory, or ``None`` off Windows.

    Calls ``GetSystemDirectoryW`` (kernel32, through ``ctypes``) into a
    260-character buffer. Reads no environment variable (``SystemRoot``,
    ``PATH``), which a caller could set to redirect the PowerShell layer.
    This is the seam R-PASTE.17 points at an empty folder.
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes
    except Exception as exc:  # pragma: no cover — ctypes ships with CPython.
        logger.debug("_system_directory: ctypes unavailable: %s", exc)
        return None
    buffer = ctypes.create_unicode_buffer(260)
    try:
        length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, 260)
    except Exception as exc:  # pragma: no cover — defensive.
        logger.debug("_system_directory: GetSystemDirectoryW failed: %s", exc)
        return None
    if not length or length >= 260:
        logger.debug("_system_directory: GetSystemDirectoryW returned %r", length)
        return None
    return buffer.value


def _system_powershell() -> Optional[str]:
    """Return the system PowerShell's absolute path, or ``None``.

    Joins ``WindowsPowerShell\\v1.0\\powershell.exe`` onto the folder
    :func:`_system_directory` reports, and returns it only when that is an
    existing file. No cache: called at each PowerShell start, so a test can
    point it elsewhere; the cost is one API call and one file check.
    """
    folder = _system_directory()
    if folder is None:
        return None
    path = os.path.join(folder, "WindowsPowerShell", "v1.0", "powershell.exe")
    return path if os.path.isfile(path) else None


def _read_via_ctypes() -> Optional[str]:
    """Layer 1 — Win32 clipboard API through ``ctypes`` with short retries.

    Uses ``OpenClipboard(NULL)`` so no window handle is needed. Bypasses
    the Tcl interpreter and any of its window-manager expectations. The
    read is bounded by ``GlobalSize`` so an unterminated UTF-16 block
    cannot read past the clipboard block. Returns ``None`` on any
    non-Windows platform or when it could not answer (the clipboard is
    held, ``GlobalLock`` fails, or the size is 0); returns ``''`` when the
    clipboard opened but holds no ``CF_UNICODETEXT`` (a file-drop list or
    an image) or an empty text — answered, no text.
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
    kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalSize.restype = ctypes.c_size_t
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
            # The clipboard opened but holds no text format: answered, no
            # text — the cascade ends without starting a rescue process.
            logger.debug("_read_via_ctypes: no CF_UNICODETEXT on clipboard")
            return ""
        size = kernel32.GlobalSize(handle)
        if not size:
            logger.debug("_read_via_ctypes: GlobalSize returned 0")
            return None
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            logger.debug("_read_via_ctypes: GlobalLock returned null")
            return None
        try:
            text = ctypes.wstring_at(
                pointer, min(size // 2, _CLIPBOARD_CAP_CHARS + 1)
            )
            return text.split("\x00", 1)[0]
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _read_via_powershell() -> Optional[str]:
    """Layer 2 — subprocess ``Get-Clipboard -Raw`` rescue, system path only.

    A fresh process reads the clipboard, isolating us from any in-process
    lock state. The program is the system PowerShell's absolute path
    (:func:`_system_powershell`), never a bare name a planted
    ``powershell.exe`` could hijack (R-PASTE.16). Serialized with the write
    layer through ``_POWERSHELL_SUBPROCESS_LOCK`` so key spam cannot spawn
    concurrent PowerShell processes. Returns ``None`` on any non-Windows
    platform, when the system PowerShell is missing, or when the child
    fails, times out or exits non-zero.

    Stdout stays binary and is decoded explicitly as UTF-8 with
    ``errors='replace'``, so unicode paths (``Ñoño``, cyrillic, CJK,
    emoji) survive without locale-dependent decoding or universal-newline
    translation of CR and CRLF. We ask PowerShell itself to emit the
    clipboard text through ``[Console]::Out.Write((Get-Clipboard -Raw))``
    with ``[Console]::OutputEncoding`` set to a UTF-8 no-BOM encoding
    (``UTF8Encoding($false)``), so no BOM or trailing newline is added.
    """
    if sys.platform != "win32":
        return None
    program = _system_powershell()
    if program is None:
        logger.debug("_read_via_powershell: system PowerShell not found")
        return None
    try:
        kwargs: dict = {
            "capture_output": True,
            "timeout": _POWERSHELL_TIMEOUT_S,
            "shell": False,
        }
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with _POWERSHELL_SUBPROCESS_LOCK:
            result = subprocess.run(
                [
                    program,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                    "[Console]::Out.Write((Get-Clipboard -Raw))",
                ],
                cwd=_system_directory(),
                **kwargs,
            )
    except subprocess.TimeoutExpired as exc:
        logger.debug("_read_via_powershell timed out after %ss", exc.timeout)
        return None
    except OSError as exc:
        logger.debug("_read_via_powershell subprocess OSError: %s", exc)
        return None
    if result.returncode != 0:
        logger.debug(
            "_read_via_powershell exit=%d stderr_len=%d",
            result.returncode,
            len(result.stderr),
        )
        return None
    text = result.stdout.decode("utf-8", errors="replace")
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


def _write_via_powershell(text: str) -> bool:
    """Write layer 2 — subprocess WPF ``[Windows.Clipboard]::SetText()``
    rescue, system path only.

    A fresh, isolated process writes the clipboard — impervious to any
    in-process clipboard grab state. The program is the system PowerShell's
    absolute path (:func:`_system_powershell`). The command is STATIC
    (``_POWERSHELL_WRITE_COMMAND``): it loads PresentationCore, sets the
    console input encoding to UTF-8 without a BOM. The payload is encoded
    explicitly as UTF-8 with ``errors='replace'`` and sent through binary
    stdin, avoiding text-mode newline translation. PowerShell reads it in
    one shot into ``$text`` via ``[Console]::In.ReadToEnd()`` and writes it
    with ``[Windows.Clipboard]::SetText($text)`` — never interpolated into
    ``-Command``, so copied text cannot break out of the command line and
    its CR, CRLF and LF endings are preserved exactly. ``shell=False`` is
    explicit and a hidden console window is requested via ``creationflags``.
    Serialized with the read layer through ``_POWERSHELL_SUBPROCESS_LOCK``
    so key spam cannot spawn concurrent PowerShell processes. Returns
    ``True`` only for exit code 0; ``False`` off Windows, on timeout
    (``_POWERSHELL_TIMEOUT_S``), on missing PowerShell, on any non-zero
    exit or on any stderr output (a held clipboard makes WPF
    ``[Windows.Clipboard]::SetText`` throw, and
    ``$ErrorActionPreference='Stop'`` promotes any such error to a
    terminating error; any stderr is treated as failure).
    """
    if sys.platform != "win32":
        return False
    program = _system_powershell()
    if program is None:
        logger.debug("_write_via_powershell: system PowerShell not found")
        return False
    kwargs: dict = {
        "input": text.encode("utf-8", errors="replace"),
        "capture_output": True,
        "timeout": _POWERSHELL_TIMEOUT_S,
        "shell": False,
    }
    kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        with _POWERSHELL_SUBPROCESS_LOCK:
            result = subprocess.run(
                [program, "-NonInteractive", *_POWERSHELL_WRITE_COMMAND],
                cwd=_system_directory(),
                **kwargs,
            )
    except subprocess.TimeoutExpired:
        logger.debug(
            "_write_via_powershell timed out after %ss", _POWERSHELL_TIMEOUT_S
        )
        return False
    except OSError as exc:
        logger.debug("_write_via_powershell subprocess OSError: %s", exc)
        return False
    if result.returncode != 0 or result.stderr:
        logger.debug(
            "_write_via_powershell exit=%d stderr_len=%d",
            result.returncode,
            len(result.stderr),
        )
        return False
    return True


# Ordered cascade of clipboard-reading strategies. Overridable per-call
# (see ``read_os_clipboard(strategies=...)``) so tests can substitute
# fakes without monkeypatching module attributes.
_STRATEGIES: tuple[tuple[str, Callable[[], Optional[str]]], ...] = (
    ("ctypes-win32", _read_via_ctypes),
    ("powershell", _read_via_powershell),
)

# Ordered cascade of clipboard-writing strategies. Win32 runs first so a
# successful write survives app exit; the static-command system PowerShell
# layer is the isolated-process last resort. Overridable per-call (see
# ``write_os_clipboard(strategies=...)``) so tests can substitute fakes
# without monkeypatching module attributes.
_WRITE_STRATEGIES: tuple[tuple[str, Callable[[str], bool]], ...] = (
    ("win32", _write_via_ctypes),
    ("powershell", _write_via_powershell),
)


def _strip_paste_controls(text: str, multiline: bool) -> str:
    """
    Summary:
        Remove every unsafe paste character from ``text``. This is the one
        strip step shared by the four paste entry points (terminal paste
        and ``action_paste`` in each box class).

    Args:
        text (str): The pasted text to strip.
        multiline (bool): ``True`` for a multi-line box (keeps TAB, LF and
            CR); ``False`` for a single-line box (keeps TAB).

    Returns:
        str: ``text`` without its unsafe paste characters — C0 except NUL
        and C1 (``_CONTROL_SCRUB`` without U+0000), the lone surrogates and
        the bidi controls — minus the box's keep-set.

    Data Flow:
        - Uses the table ``_UNSAFE_PASTE_MULTI`` when ``multiline`` is set,
          else ``_UNSAFE_PASTE_SINGLE``. Code points are removed, not whole
          sequences, so an introducer disappears but its payload remains.
        - It never splits lines: a single-line caller takes the first line
          *before* calling this, so the line end that ends the first line
          is still there to split on.

    Dependencies:
        Uses:
            - ``_UNSAFE_PASTE_SINGLE`` / ``_UNSAFE_PASTE_MULTI``
        Used by:
            - :meth:`OsClipboardInput._on_paste`
            - :meth:`OsClipboardInput.action_paste`
            - :meth:`s19_app.tui.capped_text_area.CappedTextArea._on_paste`
            - :meth:`s19_app.tui.capped_text_area.CappedTextArea.action_paste`
    """
    table = _UNSAFE_PASTE_MULTI if multiline else _UNSAFE_PASTE_SINGLE
    return text.translate(table)


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
        Return the current Windows clipboard text, or ``None`` when no
        layer of the cascade answers.

    Args:
        strategies (Optional[tuple[tuple[str, Callable[[], Optional[str]]], ...]]):
            Ordered cascade to attempt. When ``None`` (default) the
            module-level ``_STRATEGIES`` cascade is used
            (ctypes-win32 → powershell). Tests inject fake cascades
            here to exercise failure and fallback ordering.

    Returns:
        Optional[str]: Clipboard text from the first strategy that
        returns a non-empty string, bounded to ``_CLIPBOARD_CAP_CHARS``;
        ``None`` when a strategy answered "no text" (``''``) or when no
        strategy answered.

    Data Flow:
        - Iterates ``strategies`` in order. A ``None`` (could not answer)
          or a raised exception counts as no answer and the next layer
          runs. The first ``str`` ends the cascade: an empty ``''``
          (answered, no text) returns ``None`` with its own WARNING, so
          no rescue process starts and the caller falls back to the app
          clipboard; a non-empty text is bounded through
          :func:`_bound_clipboard_text` and returned with a DEBUG line.
        - The default cascade runs the cheap Win32 read first, then the
          system PowerShell rescue. The worst-case wall-clock budget is
          the Win32 retries (0.1 s) plus one PowerShell subprocess
          (2.0 s); the cascade runs in an executor, off the UI event loop.

    Dependencies:
        Uses:
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
        if text is None:
            continue
        if text == "":
            logger.warning(
                "read_os_clipboard: no text on the OS clipboard (via %s)", name
            )
            return None
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
        Win32 → system PowerShell write cascade, returning ``True`` on the
        first successful strategy. The payload is capped at
        ``_CLIPBOARD_CAP_CHARS`` before any strategy runs.

    Args:
        text (str): Text to write; over-cap payloads are truncated to
            ``_CLIPBOARD_CAP_CHARS`` first.
        strategies (Optional[tuple[tuple[str, Callable[[str], bool]], ...]]):
            Ordered cascade to attempt. When ``None`` (default) the
            module-level ``_WRITE_STRATEGIES`` cascade is used
            (win32 → powershell). Tests inject fake cascades here to
            exercise failure and fallback ordering.

    Returns:
        bool: ``True`` when a strategy wrote the OS clipboard; ``False``
        when every strategy failed (a strategy exception means failure of
        that layer only — the cascade continues).

    Data Flow:
        - Truncates ``text`` to ``_CLIPBOARD_CAP_CHARS`` once, then
          iterates ``strategies`` in order, returning ``True`` the first
          time a writer returns ``True``.
        - Win32 runs first so a successful write survives app exit; the
          system PowerShell layer is the isolated-process last resort with
          a 2.0 s budget.

    Dependencies:
        Uses:
            - :func:`_write_via_ctypes`
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


def _copy_notice_text(text: str) -> str:
    """
    Summary:
        Build the single information notice for a successful copy, using
        the original uncapped text so an over-cap copy reports the true
        character count while a short copy reports its line count.

    Args:
        text (str): The original, uncapped text being copied.

    Returns:
        str: Exactly one of three notices: ``Copied 1 line to the
        clipboard.``, ``Copied <n> lines to the clipboard.`` (``<n>`` is
        ``text.count("\\n") + 1``, minus one when ``text`` ends with a
        line feed), or ``Copied the first 65,536 characters to the
        clipboard (<N> in all).`` (``<N>`` is the original grouped length)
        when ``len(text) > _CLIPBOARD_CAP_CHARS``.

    Data Flow:
        - The over-cap branch takes precedence over line counting.
        - Never slices ``text``: ``<N>`` is always ``len(text)``, never a
          capped length.

    Dependencies:
        Uses:
            - ``_CLIPBOARD_CAP_CHARS``
        Used by:
            - :func:`_mirror_and_write_os_clipboard`
    """
    if len(text) > _CLIPBOARD_CAP_CHARS:
        return (
            f"Copied the first {_CLIPBOARD_CAP_CHARS:,} characters to the "
            f"clipboard ({len(text):,} in all)."
        )
    lines = text.count("\n") + 1
    if text.endswith("\n"):
        lines -= 1
    if lines == 1:
        return "Copied 1 line to the clipboard."
    return f"Copied {lines} lines to the clipboard."


async def _mirror_and_write_os_clipboard(app: App, text: str) -> None:
    """
    Summary:
        Shared copy/cut tail for :class:`OsClipboardInput`,
        ``CappedTextArea`` and the app-level copy override: preserve the
        original text, derive one capped payload, fail closed on a NUL in
        that payload, otherwise mirror the capped payload to Textual's
        internal clipboard through the unbound toolkit base
        ``App.copy_to_clipboard``, run the write cascade in the executor,
        and emit exactly one result notice on success or the existing
        write-failure warning.

    Args:
        app: The running app — mirror target and notification surface.
        text (str): The original selected text being copied/cut.

    Returns:
        None.

    Data Flow:
        - ``original_text = text`` is kept for the whole call, including
          across the await, so the success notice reports the original
          length. ``capped_text = original_text[:_CLIPBOARD_CAP_CHARS]``
          is derived once.
        - NUL refusal (R-COPY.25): if ``"\\x00" in capped_text``, make zero
          base/writer/OSC 52/process/helper calls, emit exactly one
          6-second warning ``Clipboard copy refused — NUL cannot be
          represented in the Windows text clipboard.`` and one fixed
          WARNING ``OS clipboard copy refused; payload contains NUL``,
          leave both clipboards unchanged, and return. Only ``capped_text``
          is tested, so NUL solely beyond the cap takes the normal path.
        - Non-NUL path: exactly one unbound toolkit base
          ``App.copy_to_clipboard(app, capped_text)`` (never an app
          override) writes the app clipboard and one OSC 52 request, then
          exactly one :func:`write_os_clipboard` runs in the default
          executor.
        - On ``True``, exactly one information notice from
          :func:`_copy_notice_text(original_text)` is emitted (the over-cap
          helper substitutes the cut notice). On ``False``, the existing
          6-second ``_WRITE_FAIL_NOTIFICATION`` warning and its WARNING log
          are emitted and no success/cut notice is emitted.

    Dependencies:
        Uses:
            - ``_CLIPBOARD_CAP_CHARS``
            - :func:`write_os_clipboard`
            - :func:`_copy_notice_text`
            - ``_WRITE_FAIL_NOTIFICATION``
            - ``textual.app.App`` (unbound toolkit base)
        Used by:
            - :meth:`OsClipboardInput.action_copy`
            - :meth:`OsClipboardInput.action_cut`
            - :meth:`s19_app.tui.capped_text_area.CappedTextArea.action_copy`
            - :meth:`s19_app.tui.capped_text_area.CappedTextArea.action_cut`
            - ``S19TuiApp.copy_to_clipboard`` (group-A override, schedules
              once)
    """
    original_text = text
    capped_text = original_text[:_CLIPBOARD_CAP_CHARS]
    if "\x00" in capped_text:
        try:
            app.notify(
                "Clipboard copy refused — NUL cannot be represented in the "
                "Windows text clipboard.",
                severity="warning",
                timeout=6.0,
            )
        except Exception:  # pragma: no cover — notify is best-effort.
            pass
        logger.warning("OS clipboard copy refused; payload contains NUL")
        return
    try:
        App.copy_to_clipboard(app, capped_text)
    except Exception:  # pragma: no cover — mirror is best-effort.
        logger.debug("internal clipboard mirror failed", exc_info=True)
    loop = asyncio.get_event_loop()
    written = await loop.run_in_executor(None, write_os_clipboard, capped_text)
    if written:
        try:
            app.notify(
                _copy_notice_text(original_text),
                severity="information",
            )
        except Exception:  # pragma: no cover — notify is best-effort.
            pass
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
        the Windows clipboard through a layered cascade
        (ctypes Win32 API → the system PowerShell ``Get-Clipboard``),
        falling back to Textual's in-process buffer (``App._clipboard``)
        when every OS layer fails, and whose ``action_copy`` /
        ``action_cut`` write the selection to the OS clipboard through the
        Win32 → system PowerShell write cascade, keeping Textual's internal
        clipboard as a mirror/fallback. Surfaces ``notify`` warnings on
        total failure so the user knows the paste/copy did nothing and
        can reach for the OS-level workaround (Ctrl+Shift+V on Windows
        Terminal). A right-click copies the shown selection, or pastes at
        the cursor when there is none.

    Data Flow:
        - ``action_paste`` (bound to Ctrl+V by ``Input.BINDINGS``) is
          async so the cascade runs off the UI event loop via
          ``loop.run_in_executor`` — otherwise the worst-case PowerShell
          subprocess (up to 2.0 s) would freeze the terminal.
        - The executor call yields to :func:`read_os_clipboard`; on
          ``None`` we fall back to ``self.app.clipboard``, cut to the cap.
          On non-empty text, only the first line of the payload is
          inserted, stripped of its unsafe paste characters, matching
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
            - :func:`_strip_paste_controls`
            - ``self.app.clipboard`` (fallback)
            - ``self.app.notify`` (UX signal on total failure)
        Used by:
            - :class:`s19_app.tui.screens.LoadDialog` (``#load_path``)
    """

    # The cursor at a press that gave this box the focus (written by
    # ``focus_on_click``, read and cleared by ``_on_mouse_down``): ``None``
    # when the box already had the focus at the press. A class-level
    # default that each instance overrides; no ``__init__`` is added.
    _press_cursor: Optional[int] = None

    def focus_on_click(self) -> bool:
        """Record the cursor at a press that changes the focus.

        The screen calls this synchronously for every mouse press on the
        box, before it sets the focus and forwards the press. Writes
        ``_press_cursor`` (the cursor position) only when
        ``self.screen.focused is not self`` — this press changes the focus,
        so the cursor must be read before the stock ``Input._on_focus``
        selects the whole text. Returns ``super().focus_on_click()``, so
        which widget gets the focus is unchanged.
        """
        if self.screen.focused is not self:
            self._press_cursor = self.cursor_position
        else:
            self._press_cursor = None
        return super().focus_on_click()

    def _take_paste(self, text: str) -> bool:
        """Hook for a subclass to take a whole, stripped paste.

        Summary:
            Default no-op both paste routes call with the capped, stripped
            paste text before the first-line cut; a subclass override
            returns ``True`` to say it inserted ``text`` itself, so the
            route inserts nothing more.

        Args:
            text (str): The paste text, capped at ``_CLIPBOARD_CAP_CHARS``
                and already stripped through ``_strip_paste_controls(text,
                multiline=True)``, so an override never has to strip.

        Returns:
            bool: ``False`` — the base box does not take the paste, so the
            route falls through to its stock first-line insert. A subclass
            returns ``True`` once it has inserted ``text``.

        Data Flow:
            - Called only when ``self.restrict`` is not set, after the
              65,536-character cap (and, in ``action_paste``, after the
              empty-text check) and before the first-line cut.
            - ``True`` stops the route (``prevent_default``/``stop`` in
              ``_on_paste``, ``return`` in ``action_paste``); ``False``
              continues to the first-line cut and strip.

        Dependencies:
            Used by:
                - :meth:`OsClipboardInput._on_paste`
                - :meth:`OsClipboardInput.action_paste`
        """
        return False

    def _on_paste(self, event: events.Paste) -> None:
        """Cut and strip a terminal paste into a single-line box in place.

        Caps ``event.text`` to the limit, then takes its first line first
        and strips the unsafe paste characters from it. A box with its own
        ``restrict`` filter is never stripped: a first line that holds an
        unsafe paste character is refused whole (``restricted()``,
        ``prevent_default()``, ``stop()``) so the box is unchanged; any
        other line keeps its raw text, so the stock ``Input._on_paste``
        (which runs after this handler through the MRO) inserts the first
        line and its own ``restrict`` check refuses a C0, DEL or NUL line.
        This handler must not call ``super()._on_paste`` or the stock
        handler would insert twice.
        """
        if len(event.text) > _CLIPBOARD_CAP_CHARS:
            event.text = event.text[:_CLIPBOARD_CAP_CHARS]
        if not self.restrict and self._take_paste(
            _strip_paste_controls(event.text, multiline=True)
        ):
            event.prevent_default()
            event.stop()
            return
        if event.text:
            first_line = event.text.splitlines()[0]
            if self.restrict:
                if _strip_paste_controls(first_line, multiline=False) != first_line:
                    self.restricted()
                    event.prevent_default()
                    event.stop()
                    return
            else:
                event.text = _strip_paste_controls(first_line, multiline=False)

    async def _on_mouse_down(self, event: events.MouseDown) -> None:
        """Copy or paste on a button-3 press, before the stock handler.

        Button 3 (Ctrl or Alt held or not) is handled here: the press is
        prevented (no stock ``Input._on_mouse_down`` cursor move) and
        stopped (no ancestor or app handler). With a shown selection and
        ``_press_cursor`` ``None`` (the box had the focus) it copies;
        otherwise it drops the whole-text selection a press-made focus
        made (the cursor goes back to the cursor at the press) and pastes.
        Any other button returns, so the stock press handler runs as today.
        """
        press = self._press_cursor
        self._press_cursor = None
        if event.button != 3:
            return
        event.prevent_default()
        event.stop()
        if press is None and self.selected_text:
            await self.action_copy()
        else:
            if press is not None:
                self.cursor_position = press
            await self.action_paste()

    def _on_click(self, event: events.Click) -> None:
        """Stop a button-3 click before the widget's text select runs."""
        if event.button == 3:
            event.prevent_default()
            event.stop()

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
        """Paste the OS clipboard text at the selection, stripped and capped.

        Summary:
            Async override of ``Input.action_paste``. Runs the read
            cascade in the executor; falls back to the app clipboard
            (cut to ``_CLIPBOARD_CAP_CHARS``) when no OS layer answers;
            inserts the first line — stripped of its unsafe paste
            characters, or refused whole when a ``restrict`` box would
            admit one — at the selection. When the total result is empty
            the field text is selected and the paste failure warning
            painted.

        Returns:
            None.

        Data Flow:
            ``read_os_clipboard`` in the executor → internal fallback →
            empty? → ``select_all()`` + notify; else first line → strip
            (or refuse in a ``restrict`` box) → ``self.replace``.

        Dependencies:
            Uses: ``read_os_clipboard``, ``self.app.clipboard``,
            ``_CLIPBOARD_CAP_CHARS``, ``_strip_paste_controls``,
            ``_PASTE_FAIL_NOTIFICATION``.
            Used by: the widget's ctrl+v key binding.
        """
        # Run the cascade off the UI event loop. The Win32 read blocks
        # synchronously for its short retry window and the PowerShell
        # rescue can spend up to 2.0 s in a blocking subprocess — both
        # would freeze the UI if invoked directly from the loop.
        loop = asyncio.get_event_loop()
        text = await loop.run_in_executor(None, read_os_clipboard)
        source = "os"
        if text is None:
            text = self.app.clipboard[:_CLIPBOARD_CAP_CHARS]
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
        if not self.restrict and self._take_paste(
            _strip_paste_controls(text, multiline=True)
        ):
            return
        first_line = text.splitlines()[0]
        if self.restrict:
            # A box with its own ``restrict`` filter (the Load path box)
            # is never stripped: a first line holding an unsafe paste
            # character is refused whole (R-LOADDLG.20), and any other
            # line goes on raw so ``Input.replace`` refuses a C0, DEL or
            # NUL line itself.
            if _strip_paste_controls(first_line, multiline=False) != first_line:
                self.restricted()
                return
        else:
            first_line = _strip_paste_controls(first_line, multiline=False)
        start, end = self.selection
        self.replace(first_line, start, end)
        logger.debug(
            "action_paste inserted %d chars from %s clipboard",
            len(first_line),
            source,
        )
