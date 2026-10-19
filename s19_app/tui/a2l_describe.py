"""E9 curve parameter description modal (batch-96 pending E9, TC-1820..1822).

The A2L Explorer's ``d`` action on the selected tag pushes THIS modal: a
parameter description for CHARACTERISTICs of type CURVE/MAP that combines
the A2L metadata (COMPU_METHOD description, unit, limits, conversion type,
axis types) with the current S19/HEX values (axis points + FNC_VALUES
decoded through the R5 RECORD_LAYOUT walk and converted point by point).

The model is built by :func:`s19_app.tui.a2l.describe_curve_tag` and
rendered by :func:`s19_app.tui.a2l.render_curve_description`; this module
only seats them in the shipped ``WindowHelpScreen`` shell (a ``markup=False``
``Static`` inside the shared ``.modal-dialog`` box, Close + Esc dismissal) —
the C-17 voice applies verbatim to the rendered description text.
"""
from __future__ import annotations

import logging
from typing import Dict

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from .a2l import render_curve_description

logger = logging.getLogger(__name__)


class CurveDescriptionScreen(ModalScreen[None]):
    """The E9 parameter-description modal for the selected A2L tag.

    Summary:
        Read-only modal over the A2L Explorer: header (name, unit, limits,
        conversion + COMPU_METHOD description, axis kinds), the decoded
        ``x -> y`` point table in physical units, and — when the layout,
        the axes, or the image bytes do not resolve — the honest status
        line instead of a table. Never crashes and never invents data: an
        unresolved limb renders its ``notes`` entry.

    Data Flow:
        - ``compose`` builds a ``.modal-dialog`` with the tag name as the
          title, the ``#a2l_curve_desc_body`` ``Static`` (``markup=False``)
          seeded from :func:`render_curve_description`, and a Close button.
        - ``on_button_pressed`` / the Esc binding dismiss with ``None``.

    Dependencies:
        Uses:
            - ``render_curve_description`` / the shared ``.modal-dialog``
              classes
        Used by:
            - ``S19TuiApp.action_a2l_describe_tag`` (app.py, the ``d`` key)
    """

    BINDINGS = [
        Binding("escape", "close_curve_description", "Close", show=False),
    ]

    def __init__(self, description: Dict[str, object]) -> None:
        super().__init__()
        #: The E9 description model (``describe_curve_tag`` payload).
        self.description = description

    def compose(self) -> ComposeResult:
        title = str(self.description.get("name") or "A2L tag")
        yield Container(
            Label(f"Parameter: {title}", classes="modal-title"),
            Static(
                render_curve_description(self.description),
                id="a2l_curve_desc_body",
                markup=False,
            ),
            Container(
                Button(
                    "Close",
                    id="a2l_curve_desc_close",
                    classes="modal-confirm",
                ),
                id="a2l_curve_desc_buttons",
                classes="modal-buttons",
            ),
            id="a2l_curve_desc_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#a2l_curve_desc_close", Button).focus()

    def action_close_curve_description(self) -> None:
        logger.info("CurveDescriptionScreen dismissed by escape.")
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "a2l_curve_desc_close":
            logger.info("CurveDescriptionScreen dismissed by close.")
            self.dismiss(None)
