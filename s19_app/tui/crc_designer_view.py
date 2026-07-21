"""CRC Designer rail-screen parameter form (batch-58, Phase-3 Inc-4).

Home of :class:`CrcDesignerPanel` — the editable parameter form composed inside
the ``#screen_crc_designer`` rail screen (HLR-V1 / LLR-V1.1 / LLR-V1.2). This
increment ships the scaffold: a preset selector plus the seven ``algorithm``
fields (``width`` / ``poly`` / ``init`` / ``refin`` / ``refout`` / ``xorout`` /
``check``) and the three ``serialization`` fields (``output_address`` /
``store_width`` / ``store_endianness``), and preset-driven population that reads
the read-only :data:`crc_kernel.PRESETS` catalogue via :func:`preset_by_name`
without mutating it. The live known-answer verdict, custom-vector, JSON preview,
Load/Save and multi-range coverage surfaces are later increments (LLR-V2..V5).

The panel is presentational (s19_app CLAUDE.md TUI architecture): it imports the
headless ``crc_kernel`` / ``crc_designer_model`` primitives for read-only
lookups and vocabulary constants only, and never calls the range/validation
engine or writes firmware (US-V6 preview-only).
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.widgets import Input, Label, Select, Static, Switch

from .operations.crc_designer_model import ENDIANNESS_VALUES
from .operations.crc_kernel import PRESETS, SEED_ALGORITHM, CrcAlgorithm, preset_by_name


def _format_hex(value: int, byte_width: int) -> str:
    """Render ``value`` as a ``0x``-prefixed hex string zero-padded to width.

    Summary:
        Format a CRC parameter as ``0x`` + uppercase hex, zero-padded to the
        algorithm's whole-byte storage width so the seed/preset deltas read
        canonically (e.g. a 16-bit ``xorout`` of ``0`` shows as ``0x0000``).

    Args:
        value (int): The non-negative parameter value.
        byte_width (int): The whole-byte field width (``ceil(width / 8)``);
            drives the zero-pad length (two hex digits per byte).

    Returns:
        str: The ``0x``-prefixed, zero-padded, uppercase hex string.

    Data Flow:
        - Pure formatting; no engine or widget state.

    Dependencies:
        Used by:
            - :meth:`CrcDesignerPanel._apply_algorithm`

    Example:
        >>> _format_hex(0x8005, 2)
        '0x8005'
    """
    return f"0x{value:0{max(byte_width, 1) * 2}X}"


class CrcDesignerPanel(ScrollableContainer):
    """The CRC Designer editable parameter form (HLR-V1 / LLR-V1.1 / LLR-V1.2).

    Summary:
        Composes a preset selector, the seven ``algorithm`` fields and the
        three ``serialization`` fields, seeded from :data:`SEED_ALGORITHM`
        (CRC-32/ISO-HDLC). Selecting a preset from the selector repopulates the
        algorithm fields from :func:`preset_by_name` — a read-only lookup that
        never mutates :data:`PRESETS` (presets are starting points; edits save
        under a new name, LLR-V1.2). Later increments add the live verdict,
        custom vector, JSON preview, Load/Save and coverage strip.

    Args:
        None

    Returns:
        None

    Data Flow:
        - ``compose`` yields the seed-valued form widgets (each carrying a
          stable ``#crc_*`` id the pilot/handlers query).
        - A ``Select.Changed`` on ``#crc_preset_select`` resolves the chosen
          preset via :func:`preset_by_name` and calls :meth:`_apply_algorithm`,
          which sets the field widgets from that :class:`CrcAlgorithm` — reading
          the catalogue, never writing it.

    Dependencies:
        Uses:
            - ``crc_kernel`` (``PRESETS`` / ``SEED_ALGORITHM`` / ``preset_by_name``)
            - ``crc_designer_model.ENDIANNESS_VALUES`` (serialization vocabulary)
        Used by:
            - ``S19TuiApp._compose_screen_crc_designer``

    Example:
        >>> panel = CrcDesignerPanel()
        >>> panel.id
        'crc_designer_panel'
    """

    def __init__(self) -> None:
        super().__init__(id="crc_designer_panel", classes="crc-designer-form")

    def compose(self) -> ComposeResult:
        algo = SEED_ALGORITHM
        byte_width = algo.store_bytes()
        yield Static(
            "CRC Designer (preview-only): pick a preset or edit the "
            "parameters; presets are read-only starting points.",
            id="crc_designer_help",
            markup=False,
        )
        yield Horizontal(
            Label("Preset", classes="crc-field-label"),
            Select(
                [(preset.name, preset.name) for preset in PRESETS],
                value=algo.name,
                allow_blank=False,
                id="crc_preset_select",
            ),
            classes="crc-field-row",
        )
        with Vertical(id="crc_algorithm_fields", classes="crc-field-group"):
            yield Label("Algorithm", classes="crc-group-title")
            yield self._text_row("Width (bits)", "crc_field_width", str(algo.width))
            yield self._text_row(
                "Polynomial", "crc_field_poly", _format_hex(algo.poly, byte_width)
            )
            yield self._text_row(
                "Init", "crc_field_init", _format_hex(algo.init, byte_width)
            )
            yield self._switch_row("Reflect in", "crc_field_refin", algo.refin)
            yield self._switch_row("Reflect out", "crc_field_refout", algo.refout)
            yield self._text_row(
                "XOR out", "crc_field_xorout", _format_hex(algo.xorout, byte_width)
            )
            yield self._text_row(
                "Check",
                "crc_field_check",
                "" if algo.check is None else _format_hex(algo.check, byte_width),
            )
        with Vertical(id="crc_serialization_fields", classes="crc-field-group"):
            yield Label("Serialization", classes="crc-group-title")
            yield self._text_row(
                "Output address", "crc_field_output_address", "0x00000000"
            )
            yield self._text_row("Store width (bytes)", "crc_field_store_width", str(byte_width))
            yield Horizontal(
                Label("Store endianness", classes="crc-field-label"),
                Select(
                    [(value, value) for value in ENDIANNESS_VALUES],
                    value=ENDIANNESS_VALUES[0],
                    allow_blank=False,
                    id="crc_field_store_endianness",
                ),
                classes="crc-field-row",
            )

    @staticmethod
    def _text_row(label: str, field_id: str, value: str) -> Horizontal:
        """Build a labelled single-line ``Input`` row.

        Args:
            label (str): The human-readable field label.
            field_id (str): The ``#crc_field_*`` id the pilot/handlers query.
            value (str): The initial (seed) field value.

        Returns:
            Horizontal: The label + ``Input`` row.
        """
        return Horizontal(
            Label(label, classes="crc-field-label"),
            Input(value=value, id=field_id, classes="crc-field-input"),
            classes="crc-field-row",
        )

    @staticmethod
    def _switch_row(label: str, field_id: str, value: bool) -> Horizontal:
        """Build a labelled boolean ``Switch`` row.

        Args:
            label (str): The human-readable field label.
            field_id (str): The ``#crc_field_*`` id the pilot/handlers query.
            value (bool): The initial (seed) switch state.

        Returns:
            Horizontal: The label + ``Switch`` row.
        """
        return Horizontal(
            Label(label, classes="crc-field-label"),
            Switch(value=value, id=field_id, classes="crc-field-switch"),
            classes="crc-field-row",
        )

    def _apply_algorithm(self, algo: CrcAlgorithm) -> None:
        """Populate the form fields from ``algo`` (read-only; no catalogue write).

        Summary:
            Set the seven algorithm field widgets plus the derived
            ``store_width`` from ``algo``. Hex parameters are zero-padded to the
            algorithm's whole-byte width; a ``None`` ``check`` clears the field.
            Serialization ``output_address`` / ``store_endianness`` are left as
            the operator set them — a preset carries no placement.

        Args:
            algo (CrcAlgorithm): The preset (or seed) to read values from. Never
                mutated.

        Returns:
            None

        Data Flow:
            - Reads ``algo`` fields; writes the matching ``#crc_field_*`` widget
              values. :data:`PRESETS` is never touched.

        Dependencies:
            Used by:
                - :meth:`on_select_changed`
        """
        byte_width = algo.store_bytes()
        self.query_one("#crc_field_width", Input).value = str(algo.width)
        self.query_one("#crc_field_poly", Input).value = _format_hex(algo.poly, byte_width)
        self.query_one("#crc_field_init", Input).value = _format_hex(algo.init, byte_width)
        self.query_one("#crc_field_refin", Switch).value = algo.refin
        self.query_one("#crc_field_refout", Switch).value = algo.refout
        self.query_one("#crc_field_xorout", Input).value = _format_hex(algo.xorout, byte_width)
        self.query_one("#crc_field_check", Input).value = (
            "" if algo.check is None else _format_hex(algo.check, byte_width)
        )
        self.query_one("#crc_field_store_width", Input).value = str(byte_width)

    def on_select_changed(self, event: Select.Changed) -> None:
        """Populate the form when the preset selector changes (LLR-V1.2).

        Summary:
            On a ``#crc_preset_select`` change, resolve the chosen preset via
            :func:`preset_by_name` and repopulate the algorithm fields. Changes
            to the serialization endianness selector are ignored here. The
            mount-time initial event (fired before the sibling fields exist) is
            tolerated as a no-op.

        Args:
            event (Select.Changed): The selection-change message.

        Returns:
            None

        Data Flow:
            - ``#crc_preset_select`` → ``preset_by_name(value)`` →
              :meth:`_apply_algorithm`.

        Dependencies:
            Uses:
                - ``preset_by_name``
        """
        if event.select.id != "crc_preset_select":
            return
        value = event.value
        if value is None or value is Select.BLANK:
            return
        algo = preset_by_name(str(value))
        if algo is None:
            return
        try:
            self._apply_algorithm(algo)
        except NoMatches:
            # Mount-time initial Changed can arrive before the field widgets
            # are queryable; the seed values are already set in compose.
            return
