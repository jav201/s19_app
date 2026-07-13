"""Paste-capped :class:`~textual.widgets.TextArea` subclass.

Summary:
    ``CappedTextArea`` is a drop-in replacement for Textual's stock
    ``TextArea`` that bounds how much text a *single* paste can insert to
    ``_CLIPBOARD_READ_CAP_CHARS`` (64 KiB = 65,536 chars). It closes the two
    native paste ingresses that the base widget leaves uncapped:

    * bracketed paste (terminal), delivered as an ``events.Paste`` message and
      handled by :meth:`TextArea._on_paste`, and
    * the ctrl+v action :meth:`TextArea.action_paste`, which reads
      ``self.app.clipboard``.

    Both paths are overridden here to truncate to the cap before the text
    reaches the base widget's insertion primitive, mirroring the ceiling the
    ``OsClipboardInput`` ctrl+v path already enforces on ``Input`` widgets.
    Every other ``TextArea`` behaviour is inherited unchanged.

    Note on ``_on_paste``: Textual auto-dispatches every ``_on_*`` handler up
    the MRO (see ``MessagePump._get_dispatch_methods``), calling this subclass's
    handler *then* the base ``TextArea._on_paste``. So this override only
    truncates ``event.text`` in place — it must NOT call ``super()._on_paste``,
    or the base handler would insert twice. ``action_paste`` is a plain action
    (not an ``_on_*`` handler), so it fully replaces the base method and
    replicates its insertion logic against the capped text.

Args:
    Constructor arguments are identical to ``textual.widgets.TextArea`` — this
    subclass adds no new parameters.

Returns:
    An instance whose paste surfaces are capped; used exactly like a
    ``TextArea`` at any construction site.

Raises:
    Propagates any exception the base ``TextArea`` methods raise; adds none.

Data Flow:
    native bracketed paste → ``events.Paste`` → :meth:`_on_paste` (cap
    ``event.text`` in place) → base ``TextArea._on_paste`` (auto-dispatched by
    the MRO) → ``_replace_via_keyboard``.
    ctrl+v → :meth:`action_paste` (cap ``app.clipboard``) →
    ``_replace_via_keyboard``.

Dependencies:
    Uses: ``textual.widgets.TextArea`` (base), ``textual.events.Paste``,
    ``s19_app.tui.os_clipboard_input._CLIPBOARD_READ_CAP_CHARS`` (the shared
    64 KiB cap constant — imported, never redefined). The private
    ``_replace_via_keyboard`` call in :meth:`action_paste` is safe only because
    ``textual==8.2.8`` is pinned.
    Used by: the five paste surfaces built in ``tui/screens.py``
    (``#changeset_json_text``, ``#entry_json_text``, ``#report_declared_regions``,
    ``#operation_config``) and ``tui/screens_directionb.py``
    (``#patch_paste_text``).

Example:
    >>> from s19_app.tui.capped_text_area import CappedTextArea
    >>> CappedTextArea("seed", id="patch_paste_text")  # doctest: +SKIP
"""

from __future__ import annotations

from textual import events
from textual.widgets import TextArea

from .os_clipboard_input import _CLIPBOARD_READ_CAP_CHARS


class CappedTextArea(TextArea):
    """A ``TextArea`` that caps native paste input to 64 KiB.

    Summary:
        Overrides both native paste ingresses (bracketed paste and the ctrl+v
        action) to truncate the incoming text to ``_CLIPBOARD_READ_CAP_CHARS``
        before insertion, then defers to the base widget's insertion path.

    Data Flow:
        See the module docstring — both overrides converge on the base
        ``_replace_via_keyboard`` primitive with at most the cap's worth of
        text.

    Dependencies:
        Uses: base ``TextArea`` insertion machinery and the shared cap
        constant. Used by: the five paste-surface construction sites.
    """

    def _on_paste(self, event: events.Paste) -> None:
        """Truncate an over-cap bracketed-paste event in place.

        Summary:
            Caps ``event.text`` to the limit before the base
            ``TextArea._on_paste`` inserts it. Textual auto-dispatches every
            ``_on_*`` handler up the MRO, so this method runs FIRST and the base
            handler runs immediately after against the (now-capped) text — this
            override must NOT call ``super()._on_paste`` or the base would insert
            twice.

        Args:
            event (events.Paste): The paste event carrying the pasted text;
                mutated in place when over the cap.

        Returns:
            None.

        Raises:
            None.

        Data Flow:
            ``event.text`` → cap in place → (MRO) base ``TextArea._on_paste`` →
            ``_replace_via_keyboard``.

        Dependencies:
            Uses: ``_CLIPBOARD_READ_CAP_CHARS``.
            Used by: the Textual message pump on ``events.Paste`` (which then
            calls the base handler in MRO order).

        Example:
            Delivered by the runtime; not called directly.
        """
        if len(event.text) > _CLIPBOARD_READ_CAP_CHARS:
            event.text = event.text[:_CLIPBOARD_READ_CAP_CHARS]

    def action_paste(self) -> None:
        """Cap the ctrl+v clipboard text, then insert via the base path.

        Summary:
            Mirrors ``TextArea.action_paste`` exactly — reads
            ``self.app.clipboard`` and inserts it via ``_replace_via_keyboard``
            — but truncates the clipboard text to the cap first, closing the
            second (ctrl+v) paste ingress.

        Args:
            None.

        Returns:
            None.

        Raises:
            Propagates whatever the base insertion path raises.

        Data Flow:
            ``self.app.clipboard`` → cap → ``_replace_via_keyboard`` →
            ``move_cursor``.

        Dependencies:
            Uses: ``self.app.clipboard``, the private
            ``_replace_via_keyboard`` (pinned ``textual==8.2.8``),
            ``_CLIPBOARD_READ_CAP_CHARS``.
            Used by: the widget's ctrl+v key binding.

        Example:
            Invoked by the ctrl+v binding; not called directly.
        """
        if self.read_only:
            return
        clipboard = self.app.clipboard
        if len(clipboard) > _CLIPBOARD_READ_CAP_CHARS:
            clipboard = clipboard[:_CLIPBOARD_READ_CAP_CHARS]
        if result := self._replace_via_keyboard(clipboard, *self.selection):
            self.move_cursor(result.end_location)
