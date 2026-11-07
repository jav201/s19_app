"""OS-clipboard copy/cut/paste with a capped payload for TextArea.

Summary:
    ``CappedTextArea`` is a drop-in replacement for Textual's stock
    ``TextArea`` that (a) bounds how much text a *single* paste can insert
    to ``_CLIPBOARD_CAP_CHARS`` (64 KiB = 65,536 chars) and (b) routes the
    clipboard actions through the real OS clipboard — the same cascades
    :class:`s19_app.tui.os_clipboard_input.OsClipboardInput` uses — so
    Ctrl+C/Ctrl+X/Ctrl+V interoperate with other Windows applications.

    Paste ingresses, capped:

    * bracketed paste (terminal), delivered as an ``events.Paste`` message and
      handled by :meth:`TextArea._on_paste`, and
    * the ctrl+v action :meth:`action_paste`, which reads the OS clipboard
      through the Win32 → system PowerShell read cascade (2.0 s
      PowerShell budget) and falls back to ``self.app.clipboard``.

    Copy/cut, OS + internal:

    * the ctrl+c action :meth:`action_copy` writes the selected document
      text to the OS clipboard (Win32 → system PowerShell write cascade) and
      mirrors it to Textual's internal clipboard, without mutating the
      document; an empty selection raises Textual's ``SkipAction``;
    * the ctrl+x action :meth:`action_cut` additionally removes the text:
      the selection through Textual's keyboard path, or — when no
      selection exists — the whole cursor line through
      ``_delete_cursor_line()``, whose replaced text is what gets written
      (Textual's stock line-cut behaviour, preserved).

    Every clipboard payload — pasted, copied, cut, OS or the internal
    mirror — is capped at ``_CLIPBOARD_CAP_CHARS``. On total OS-write
    failure the internal mirror is retained and the warning
    ``Clipboard write failed — copied inside the app only.`` is painted;
    on total read failure the whole buffer is selected and the existing
    read warning is painted. Every other ``TextArea`` behaviour is
    inherited unchanged.

    Note on ``_on_paste``: Textual auto-dispatches every ``_on_*`` handler up
    the MRO (see ``MessagePump._get_dispatch_methods``), calling this subclass's
    handler *then* the base ``TextArea._on_paste``. So this override only
    truncates and strips ``event.text`` in place — it must NOT call ``super()._on_paste``,
    or the base handler would insert twice. ``action_paste`` / ``action_copy``
    / ``action_cut`` are plain actions (not ``_on_*`` handlers), so they
    fully replace the base methods.

Args:
    Constructor arguments are identical to ``textual.widgets.TextArea`` — this
    subclass adds no new parameters.

Returns:
    An instance whose clipboard surfaces are OS-backed and capped; used
    exactly like a ``TextArea`` at any construction site.

Raises:
    Propagates any exception the base ``TextArea`` methods raise; adds none
    (empty-selection copy/cut raise Textual's ``SkipAction``, which the
    action dispatcher treats as "not handled").

Data Flow:
    native bracketed paste → ``events.Paste`` → :meth:`_on_paste` (cap
    ``event.text`` in place) → base ``TextArea._on_paste`` (auto-dispatched by
    the MRO) → ``_replace_via_keyboard``.
    ctrl+v → :meth:`action_paste` (OS read cascade in the executor, cap,
    internal fallback) → ``_replace_via_keyboard``.
    ctrl+c → :meth:`action_copy` (selection → internal mirror + OS write
    cascade in the executor).
    ctrl+x → :meth:`action_cut` (delete selection / cursor line, then the
    same copy tail).

Dependencies:
    Uses: ``textual.widgets.TextArea`` (base), ``textual.events.Paste``,
    ``textual.actions.SkipAction``,
    ``s19_app.tui.os_clipboard_input`` (the shared 64 KiB cap constant, the
    read/write cascades and the unsafe-paste strip — imported, never
    redefined). The private ``_replace_via_keyboard`` /
    ``_delete_via_keyboard`` / ``_delete_cursor_line`` calls are safe only
    because ``textual==8.2.8`` is pinned.
    Used by: the five paste surfaces built in ``tui/screens.py``
    (``#changeset_json_text``, ``#entry_json_text``, ``#report_declared_regions``,
    ``#operation_config``) and ``tui/screens_directionb.py``
    (``#patch_paste_text``).

Example:
    >>> from s19_app.tui.capped_text_area import CappedTextArea
    >>> CappedTextArea("seed", id="patch_paste_text")  # doctest: +SKIP
"""

from __future__ import annotations

import asyncio
import logging

from textual import events
from textual.actions import SkipAction
from textual.widgets import TextArea

from . import os_clipboard_input as _os_clipboard_input
from .os_clipboard_input import (
    _CLIPBOARD_CAP_CHARS,
    _PASTE_FAIL_NOTIFICATION,
    _mirror_and_write_os_clipboard,
    _strip_paste_controls,
)

logger = logging.getLogger(__name__)


class CappedTextArea(TextArea):
    """A ``TextArea`` with OS-clipboard copy/cut/paste, capped to 64 KiB.

    Summary:
        Overrides both native paste ingresses (bracketed paste and the
        ctrl+v action) to truncate the incoming text to
        ``_CLIPBOARD_CAP_CHARS`` before insertion, and the copy/cut
        actions to write the selection (or the cut cursor line) to the OS
        and internal clipboards, deferring to the base widget's edit
        primitives.

    Data Flow:
        See the module docstring — paste overrides converge on the base
        ``_replace_via_keyboard`` primitive with at most the cap's worth
        of text; copy/cut converge on
        ``_mirror_and_write_os_clipboard``.

    Dependencies:
        Uses: base ``TextArea`` edit machinery, the OS clipboard cascades
        and the shared cap constant. Used by: the five paste-surface
        construction sites.
    """

    def _on_paste(self, event: events.Paste) -> None:
        """Cap and strip a bracketed-paste event in place.

        Summary:
            Caps ``event.text`` to the limit, then strips its unsafe paste
            characters (keeping TAB, LF and CR) before the base
            ``TextArea._on_paste`` inserts it. Textual auto-dispatches every
            ``_on_*`` handler up the MRO, so this method runs FIRST and the base
            handler runs immediately after against the (now-capped, stripped)
            text — this override must NOT call ``super()._on_paste`` or the base
            would insert twice.

        Args:
            event (events.Paste): The paste event carrying the pasted text;
                mutated in place when over the cap or holding an unsafe
                paste character.

        Returns:
            None.

        Raises:
            None.

        Data Flow:
            ``event.text`` → cap in place → strip in place → (MRO) base
            ``TextArea._on_paste`` → ``_replace_via_keyboard``.

        Dependencies:
            Uses: ``_CLIPBOARD_CAP_CHARS``, ``_strip_paste_controls``.
            Used by: the Textual message pump on ``events.Paste`` (which then
            calls the base handler in MRO order).

        Example:
            Delivered by the runtime; not called directly.
        """
        if len(event.text) > _CLIPBOARD_CAP_CHARS:
            event.text = event.text[:_CLIPBOARD_CAP_CHARS]
        event.text = _strip_paste_controls(event.text, multiline=True)

    async def action_paste(self) -> None:
        """Paste the OS clipboard text at the selection, capped and stripped.

        Summary:
            Async override of ``TextArea.action_paste``. Returns without
            mutation for a read-only buffer. Runs the same OS-read cascade
            as ``OsClipboardInput.action_paste`` in the executor; caps the
            result at ``_CLIPBOARD_CAP_CHARS`` and strips its unsafe paste
            characters (keeping TAB, LF and CR); falls back to Textual's
            internal ``App.clipboard`` when every OS layer fails; inserts
            via the base ``_replace_via_keyboard`` path. When the total
            result is empty the whole buffer is selected and the exact
            read warning ``_PASTE_FAIL_NOTIFICATION`` is painted.

        Args:
            None.

        Returns:
            None.

        Raises:
            Propagates whatever the base insertion path raises.

        Data Flow:
            read-only? → return; ``read_os_clipboard`` in the executor →
            internal fallback → empty? → ``select_all()`` + notify; else
            cap → strip → ``_replace_via_keyboard`` → ``move_cursor``.

        Dependencies:
            Uses: ``read_os_clipboard``, ``self.app.clipboard``,
            ``_CLIPBOARD_CAP_CHARS``, ``_strip_paste_controls``,
            ``_PASTE_FAIL_NOTIFICATION``, the private
            ``_replace_via_keyboard`` (pinned ``textual==8.2.8``).
            Used by: the widget's ctrl+v key binding.

        Example:
            Invoked by the ctrl+v binding; not called directly.
        """
        if self.read_only:
            return
        # The read goes through the os_clipboard_input module namespace so
        # a single monkeypatch of ``read_os_clipboard`` covers both widget
        # classes (the seam the batch-67 tests use).
        loop = asyncio.get_event_loop()
        text = await loop.run_in_executor(None, _os_clipboard_input.read_os_clipboard)
        source = "os"
        if text is None:
            text = self.app.clipboard
            source = "internal"
        if not text:
            # Selecting the whole buffer marks it as "stale — retype or
            # re-paste", so the user sees the paste did nothing.
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
        if len(text) > _CLIPBOARD_CAP_CHARS:
            text = text[:_CLIPBOARD_CAP_CHARS]
        text = _strip_paste_controls(text, multiline=True)
        if result := self._replace_via_keyboard(text, *self.selection):
            self.move_cursor(result.end_location)

    async def action_copy(self) -> None:
        """Copy the selected document text to the OS and internal clipboards.

        Summary:
            Mirrors ``OsClipboardInput.action_copy`` for the selected
            document text: an empty selection raises ``SkipAction``
            (stock behaviour — the internal clipboard is NOT erased with
            an empty string); otherwise the text — capped at
            ``_CLIPBOARD_CAP_CHARS`` — is mirrored to ``App.clipboard``
            and written to the OS clipboard through the Win32 → system
            PowerShell cascade. The document is not modified.

        Args:
            None.

        Returns:
            None.

        Data Flow:
            ``selected_text`` → empty? → ``SkipAction``; else
            ``_mirror_and_write_os_clipboard``.

        Dependencies:
            Used by: the widget's ctrl+c key binding.
        """
        selected_text = self.selected_text
        if not selected_text:
            raise SkipAction()
        await _mirror_and_write_os_clipboard(self.app, selected_text)

    async def action_cut(self) -> None:
        """Cut the selection — or the cursor line — to the clipboards.

        Summary:
            Returns without mutation for a read-only buffer. Deletes the
            selection through Textual's keyboard path, or — when no
            selection exists — the whole cursor line through
            ``_delete_cursor_line()`` (Textual's stock line-cut
            behaviour); captures the replaced text, mirrors it internally
            and writes it to the OS clipboard. The local cut remains even
            when every OS write layer fails.

        Args:
            None.

        Returns:
            None.

        Data Flow:
            read-only? → return; ``self.selection`` empty? →
            ``_delete_cursor_line()``; else ``_delete_via_keyboard``;
            ``edit_result.replaced_text`` →
            ``_mirror_and_write_os_clipboard``.

        Dependencies:
            Used by: the widget's ctrl+x key binding.
        """
        if self.read_only:
            return
        start, end = self.selection
        if start == end:
            edit_result = self._delete_cursor_line()
        else:
            edit_result = self._delete_via_keyboard(start, end)
        if edit_result is None:
            return
        await _mirror_and_write_os_clipboard(self.app, edit_result.replaced_text)

    async def _on_mouse_down(self, event: events.MouseDown) -> None:
        """Copy or paste on a button-3 press, before the stock handler.

        Button 3 is handled here: the press is prevented (no stock
        ``TextArea._on_mouse_down`` cursor move, mouse capture or undo
        checkpoint) and stopped (no ancestor or app handler). With a shown
        selection it copies; without one it pastes (which returns for a
        read-only box). No focus record: a multi-line box shows its
        selection with or without the focus and does not select on focus,
        so the selection and cursor here are those shown at the press. Any
        other button returns, so the stock press handler runs as today.
        """
        if event.button != 3:
            return
        event.prevent_default()
        event.stop()
        if self.selected_text:
            await self.action_copy()
        else:
            await self.action_paste()

    def _on_click(self, event: events.Click) -> None:
        """Stop a button-3 click before the widget's text select runs."""
        if event.button == 3:
            event.prevent_default()
            event.stop()
