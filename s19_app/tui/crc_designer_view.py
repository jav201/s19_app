"""CRC Designer rail-screen parameter form (batch-58, Phase-3 Inc-4/Inc-5).

Home of :class:`CrcDesignerPanel` — the editable parameter form composed inside
the ``#screen_crc_designer`` rail screen (HLR-V1 / LLR-V1.1 / LLR-V1.2). Inc-4
shipped the scaffold: a preset selector plus the seven ``algorithm`` fields
(``width`` / ``poly`` / ``init`` / ``refin`` / ``refout`` / ``xorout`` /
``check``) and the three ``serialization`` fields (``output_address`` /
``store_width`` / ``store_endianness``), and preset-driven population that reads
the read-only :data:`crc_kernel.PRESETS` catalogue via :func:`preset_by_name`
without mutating it.

Inc-5 adds the three live-recompute surfaces, all driven off the real Textual
change events (``Input.Changed`` / ``Switch.Changed`` / ``Select.Changed``) —
no Run button (LLR-V2.1 / V2.2 / V3.1 / V4.1):

- ``#crc_kat_verdict`` — the tri-state known-answer verdict (``MATCH`` /
  ``MISMATCH`` / ``NO-EXPECTED``) recomputed from the current fields.
- ``#crc_custom_vector`` (+ mode) — an operator vector (ASCII or hex) whose CRC
  under the current algorithm is shown; ASCII ``123456789`` reproduces the KAT.
- ``#crc_json_preview`` — the live ``emit_template`` render that round-trips
  back through :func:`parse_template` to the same typed template.

The compute boundary is guarded: an out-of-range width / non-hex field renders a
markup-safe warning rather than crashing the screen. Load/Save and multi-range
coverage remain later increments (LLR-V5).

The panel is presentational (s19_app CLAUDE.md TUI architecture): it imports the
headless ``crc_kernel`` / ``crc_designer_model`` primitives for read-only
lookups, vocabulary constants and JSON serialization only, and never calls the
range/validation engine or writes firmware (US-V6 preview-only). Every live
surface renders ``markup=False`` (C-17): file/preset-derived text never reaches
a markup sink.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.widgets import Input, Label, Select, Static, Switch

from .operations.crc_designer_model import (
    ENDIANNESS_VALUES,
    CrcTemplate,
    emit_template,
)
from .operations.crc_kernel import PRESETS, SEED_ALGORITHM, CrcAlgorithm, preset_by_name

#: Custom-vector interpretation modes (LLR-V3.1). ``ascii`` encodes the raw text
#: as UTF-8 bytes (so ``123456789`` reproduces the KAT); ``hex`` reads
#: whitespace-tolerant hex pairs. An explicit mode is required because
#: ``123456789`` is itself valid hex — auto-detect would mis-read the KAT input.
_VECTOR_MODES: tuple[str, ...] = ("ascii", "hex")

#: Tri-state display tokens for the live verdict (LLR-V2.1). The source is the
#: merged :meth:`CrcAlgorithm.kat_ok` ``True`` / ``False`` / ``None``.
_VERDICT_TOKENS: dict[bool | None, str] = {
    True: "MATCH",
    False: "MISMATCH",
    None: "NO-EXPECTED",
}


def _decode_vector(raw: str, mode: str) -> bytes:
    """Decode the custom-vector text under ``mode`` (LLR-V3.1).

    Summary:
        Turn the operator's custom-vector text into the byte stream to digest:
        ``ascii`` UTF-8 encodes it (so ``123456789`` reproduces the KAT), ``hex``
        strips whitespace and reads hex pairs.

    Args:
        raw (str): The raw custom-vector field text.
        mode (str): One of :data:`_VECTOR_MODES` (``"ascii"`` / ``"hex"``).

    Returns:
        bytes: The decoded byte stream.

    Raises:
        ValueError: When ``mode == "hex"`` and ``raw`` is not valid hex — caught
            by the caller and rendered as a markup-safe warning.

    Data Flow:
        - Pure decode; no widget or engine state.

    Dependencies:
        Used by:
            - :meth:`CrcDesignerPanel._custom_vector_text`

    Example:
        >>> _decode_vector("31 32 33", "hex")
        b'123'
    """
    if mode == "hex":
        return bytes.fromhex("".join(raw.split()))
    return raw.encode("utf-8")


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
        with Vertical(id="crc_live_verify", classes="crc-field-group"):
            yield Label(
                "Known-answer verdict (123456789)", classes="crc-group-title"
            )
            yield Static("", id="crc_kat_verdict", markup=False, classes="crc-verdict")
        with Vertical(id="crc_custom_vector_group", classes="crc-field-group"):
            yield Label("Custom test vector", classes="crc-group-title")
            yield Horizontal(
                Label("Mode", classes="crc-field-label"),
                Select(
                    [(mode, mode) for mode in _VECTOR_MODES],
                    value=_VECTOR_MODES[0],
                    allow_blank=False,
                    id="crc_custom_vector_mode",
                ),
                classes="crc-field-row",
            )
            yield self._text_row("Vector", "crc_custom_vector", "123456789")
            yield Horizontal(
                Label("CRC of vector", classes="crc-field-label"),
                Static(
                    "",
                    id="crc_custom_vector_result",
                    markup=False,
                    classes="crc-verdict",
                ),
                classes="crc-field-row",
            )
        with Vertical(id="crc_json_preview_group", classes="crc-field-group"):
            yield Label("Template JSON preview", classes="crc-group-title")
            yield Static(
                "", id="crc_json_preview", markup=False, classes="crc-json-preview"
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
        """Repopulate on a preset change; recompute on any select change.

        Summary:
            On a ``#crc_preset_select`` change, resolve the chosen preset via
            :func:`preset_by_name` and repopulate the algorithm fields
            (LLR-V1.2). For every select change (preset, endianness, custom
            vector mode) the live surfaces are recomputed (LLR-V2.1 / V3.1 /
            V4.1). The mount-time initial event (fired before the sibling fields
            exist) is tolerated as a no-op.

        Args:
            event (Select.Changed): The selection-change message.

        Returns:
            None

        Data Flow:
            - ``#crc_preset_select`` → ``preset_by_name(value)`` →
              :meth:`_apply_algorithm`; then :meth:`_recompute` for any select.

        Dependencies:
            Uses:
                - ``preset_by_name``, :meth:`_apply_algorithm`, :meth:`_recompute`
        """
        if event.select.id == "crc_preset_select":
            value = event.value
            if value is not None and value is not Select.BLANK:
                algo = preset_by_name(str(value))
                if algo is not None:
                    try:
                        self._apply_algorithm(algo)
                    except NoMatches:
                        # Mount-time initial Changed can arrive before the field
                        # widgets are queryable; seed values are set in compose.
                        return
        self._recompute()

    def on_mount(self) -> None:
        """Populate the live surfaces once all fields are mounted (LLR-V2.1).

        Summary:
            Establish the initial verdict / custom-vector / preview state from
            the seed fields so the first ``BEFORE`` capture reads a real verdict
            (``MATCH`` for the seed) — the transition gate (AT-CRC-DSN-016) needs
            a populated pre-edit state.

        Returns:
            None

        Data Flow:
            - :meth:`_recompute` over the composed seed fields.
        """
        self._recompute()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Recompute the live surfaces on any field / vector edit (LLR-V2.1).

        Args:
            event (Input.Changed): The field-change message (unused; the handler
                reads all current field values).

        Returns:
            None
        """
        self._recompute()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Recompute the live surfaces on a reflect-in/out toggle (LLR-V2.1).

        Args:
            event (Switch.Changed): The switch-change message (unused).

        Returns:
            None
        """
        self._recompute()

    def _current_algorithm(self) -> CrcAlgorithm:
        """Build a :class:`CrcAlgorithm` from the current form fields.

        Summary:
            Read the seven algorithm fields plus the preset-selector name into a
            typed :class:`CrcAlgorithm` (LLR-V2.1). Hex fields accept an optional
            ``0x`` prefix; an empty ``check`` field maps to ``None`` (the
            no-expected tri-state). Field values are read live, never cached.

        Returns:
            CrcAlgorithm: The algorithm the form currently describes.

        Raises:
            ValueError: A non-numeric width or non-hex parameter — caught by
                :meth:`_recompute` and rendered as a markup-safe warning
                (LLR-V2.2).

        Data Flow:
            - ``#crc_field_*`` widget values → parsed ints/bools →
              :class:`CrcAlgorithm`.

        Dependencies:
            Used by:
                - :meth:`_recompute`
        """
        width_text = self.query_one("#crc_field_width", Input).value.strip()
        width = int(width_text) if width_text else 0
        check_text = self.query_one("#crc_field_check", Input).value.strip()
        check = int(check_text, 16) if check_text else None
        return CrcAlgorithm(
            name=str(self.query_one("#crc_preset_select", Select).value),
            width=width,
            poly=self._hex_field("#crc_field_poly"),
            init=self._hex_field("#crc_field_init"),
            refin=self.query_one("#crc_field_refin", Switch).value,
            refout=self.query_one("#crc_field_refout", Switch).value,
            xorout=self._hex_field("#crc_field_xorout"),
            check=check,
        )

    def _hex_field(self, selector: str) -> int:
        """Parse a hex ``#crc_field_*`` value (``0x`` optional; empty → ``0``)."""
        text = self.query_one(selector, Input).value.strip()
        return int(text, 16) if text else 0

    def _verdict_text(self, algo: CrcAlgorithm) -> str:
        """Render the tri-state known-answer verdict token (LLR-V2.1 / V2.2).

        Summary:
            Compute :meth:`CrcAlgorithm.kat_ok` and map the ``True`` / ``False``
            / ``None`` tri-state to ``MATCH`` / ``MISMATCH`` / ``NO-EXPECTED``.
            A compute fault (width ∉ [8, 64]) is caught and rendered as a
            markup-safe warning rather than propagated.

        Args:
            algo (CrcAlgorithm): The current algorithm.

        Returns:
            str: The verdict token, or a ``Cannot compute`` warning.

        Dependencies:
            Uses:
                - :meth:`CrcAlgorithm.kat_ok`
            Used by:
                - :meth:`_recompute`
        """
        try:
            return _VERDICT_TOKENS[algo.kat_ok()]
        except ValueError as exc:
            return f"Cannot compute: {exc}"

    def _custom_vector_text(self, algo: CrcAlgorithm) -> str:
        """Render the current algorithm's CRC over the custom vector (LLR-V3.1).

        Summary:
            Decode ``#crc_custom_vector`` under its mode and digest it with
            ``algo`` (:meth:`CrcAlgorithm.compute`); an ASCII ``123456789``
            reproduces the KAT. A malformed vector or compute fault renders a
            markup-safe warning, never a crash.

        Args:
            algo (CrcAlgorithm): The current algorithm.

        Returns:
            str: The ``0x``-prefixed CRC, or a markup-safe warning.

        Dependencies:
            Uses:
                - :func:`_decode_vector`, :meth:`CrcAlgorithm.compute`
            Used by:
                - :meth:`_recompute`
        """
        mode = str(self.query_one("#crc_custom_vector_mode", Select).value)
        raw = self.query_one("#crc_custom_vector", Input).value
        try:
            data = _decode_vector(raw, mode)
        except ValueError as exc:
            return f"Invalid vector: {exc}"
        try:
            return _format_hex(algo.compute(data), algo.store_bytes())
        except ValueError as exc:
            return f"Cannot compute: {exc}"

    def _preview_text(self, algo: CrcAlgorithm) -> str:
        """Render the live template JSON preview (LLR-V4.1).

        Summary:
            Serialize ``CrcTemplate(algo)`` via :func:`emit_template`; the text
            round-trips back through :func:`parse_template` to the same typed
            template (the AT-058-04 gate reads THIS mounted widget's text). The
            output is rendered ``markup=False`` — its ``[]`` array literals never
            reach a markup sink (C-17).

        Args:
            algo (CrcAlgorithm): The current algorithm.

        Returns:
            str: The pretty-printed template JSON, or a markup-safe warning.

        Dependencies:
            Uses:
                - :func:`emit_template`, :class:`CrcTemplate`
            Used by:
                - :meth:`_recompute`
        """
        try:
            return emit_template(CrcTemplate(algorithm=algo))
        except (ValueError, TypeError) as exc:
            return f"Cannot render preview: {exc}"

    def _recompute(self) -> None:
        """Recompute the three live surfaces from the current fields.

        Summary:
            The single recompute entry point wired to every change event
            (LLR-V2.1). Build the current algorithm and refresh the verdict,
            custom-vector CRC and JSON preview. A field that cannot even form an
            algorithm (non-hex parameter) renders one markup-safe warning across
            the surfaces instead of crashing (LLR-V2.2). During mount — before
            all sibling widgets exist — the ``NoMatches`` is swallowed;
            :meth:`on_mount` performs the first full compute.

        Returns:
            None

        Data Flow:
            - :meth:`_current_algorithm` → :meth:`_verdict_text` /
              :meth:`_custom_vector_text` / :meth:`_preview_text` → each
              ``Static.update`` (markup-safe).

        Dependencies:
            Uses:
                - :meth:`_current_algorithm`, :meth:`_verdict_text`,
                  :meth:`_custom_vector_text`, :meth:`_preview_text`
            Used by:
                - :meth:`on_mount`, :meth:`on_input_changed`,
                  :meth:`on_switch_changed`, :meth:`on_select_changed`
        """
        try:
            verdict = self.query_one("#crc_kat_verdict", Static)
            custom_result = self.query_one("#crc_custom_vector_result", Static)
            preview = self.query_one("#crc_json_preview", Static)
        except NoMatches:
            # Mid-mount: a change event arrived before every surface exists.
            return
        try:
            algo = self._current_algorithm()
        except (ValueError, NoMatches) as exc:
            warning = f"Invalid parameters: {exc}"
            verdict.update(warning)
            custom_result.update("—")
            preview.update(warning)
            return
        verdict.update(self._verdict_text(algo))
        custom_result.update(self._custom_vector_text(algo))
        preview.update(self._preview_text(algo))
