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
markup-safe warning rather than crashing the screen.

Inc-6 adds Load/Save through the ``crc_template`` facade plus the form-level
warnings (LLR-V5.1 / V5.2 / V5.3 / V5.4):

- ``#crc_field_name`` / ``#crc_field_aliases`` — the template identity fields
  that become the untrusted, load-derived surface.
- ``#crc_save_btn`` / ``#crc_load_btn`` + ``#crc_load_path`` —
  Save writes ``emit_template`` to ``<template-lib>/<sanitized-name>.crc.json``
  (a bounded write; an all-symbol name warns and writes nothing), Load reads a
  chosen file through :func:`read_template` (collect-don't-abort: a fault
  surfaces exactly one error, never a crash).
- ``#crc_loadsave_status`` — the Save/Load outcome + the save-time known-answer
  (``check == compute("123456789")``) and name warnings.
- ``#crc_warnings`` — the live ``store_width < ceil(width/8)`` truncation warning.

Multi-range coverage + the fill-no-pad warning remain Inc-7 (LLR-V6/V7). Every
sink that shows template/file-derived text — including the JSON preview that
embeds the loaded ``name`` / ``aliases`` verbatim — renders ``markup=False``.

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
from textual.widgets import Button, Input, Label, Select, Static, Switch

from .operations.crc_designer_model import ENDIANNESS_VALUES
from .operations.crc_kernel import PRESETS, SEED_ALGORITHM, CrcAlgorithm, preset_by_name
from .operations.crc_template import CrcTemplate, emit_template, read_template
from .workspace import ensure_template_lib, sanitize_project_name

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
            - ``crc_template`` facade (``read_template`` / ``emit_template`` /
              ``CrcTemplate``) for Load/Save
            - ``workspace`` (``ensure_template_lib`` / ``sanitize_project_name``)
              for the bounded template-library write
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
        with Vertical(id="crc_template_fields", classes="crc-field-group"):
            yield Label("Template", classes="crc-group-title")
            yield self._text_row("Name", "crc_field_name", algo.name)
            yield self._text_row(
                "Aliases (comma-separated)", "crc_field_aliases", ""
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
        with Vertical(id="crc_warnings_group", classes="crc-field-group"):
            yield Label("Warnings", classes="crc-group-title")
            yield Static("", id="crc_warnings", markup=False, classes="crc-warnings")
        with Vertical(id="crc_loadsave_group", classes="crc-field-group"):
            yield Label("Load / Save", classes="crc-group-title")
            yield self._text_row("Template path (load)", "crc_load_path", "")
            yield Horizontal(
                Button("Save template", id="crc_save_btn"),
                Button("Load template", id="crc_load_btn"),
                classes="crc-field-row",
            )
            yield Static(
                "", id="crc_loadsave_status", markup=False, classes="crc-status"
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
            ``store_width`` from ``algo``, the template ``name`` field, and clear
            ``aliases`` (a preset/algorithm carries none; a Load re-sets aliases
            afterwards). Hex parameters are zero-padded to the algorithm's
            whole-byte width; a ``None`` ``check`` clears the field. Serialization
            ``output_address`` / ``store_endianness`` are left as the operator
            set them — a preset carries no placement.

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
        self.query_one("#crc_field_name", Input).value = algo.name
        self.query_one("#crc_field_aliases", Input).value = ""
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
            Read the seven algorithm fields plus the template ``name`` field
            into a typed :class:`CrcAlgorithm` (LLR-V2.1). Hex fields accept an
            optional ``0x`` prefix; an empty ``check`` field maps to ``None``
            (the no-expected tri-state). Field values are read live, never
            cached.

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
            name=self.query_one("#crc_field_name", Input).value.strip(),
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

    def _current_template(self) -> CrcTemplate:
        """Build a :class:`CrcTemplate` from the current form fields (LLR-V4.1).

        Summary:
            Wrap :meth:`_current_algorithm` together with the comma-separated
            ``#crc_field_aliases`` field into a typed :class:`CrcTemplate` — the
            artifact the JSON preview renders and Save writes. Empty alias tokens
            are dropped. The ``name`` / ``aliases`` are file/operator-derived and
            flow only into ``markup=False`` sinks (C-17, LLR-V5.3).

        Returns:
            CrcTemplate: The template the form currently describes.

        Raises:
            ValueError: A non-numeric width or non-hex parameter — caught by
                :meth:`_recompute` / the Save handler and rendered markup-safe.

        Dependencies:
            Uses:
                - :meth:`_current_algorithm`
            Used by:
                - :meth:`_recompute`, :meth:`_save_template`
        """
        aliases_text = self.query_one("#crc_field_aliases", Input).value
        aliases = tuple(a.strip() for a in aliases_text.split(",") if a.strip())
        return CrcTemplate(algorithm=self._current_algorithm(), aliases=aliases)

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

    def _preview_text(self, template: CrcTemplate) -> str:
        """Render the live template JSON preview (LLR-V4.1 / V5.3).

        Summary:
            Serialize ``template`` via :func:`emit_template`; the text
            round-trips back through :func:`parse_template` to the same typed
            template (the AT-058-04 gate reads THIS mounted widget's text). The
            output is rendered ``markup=False`` — its ``[]`` array literals AND
            the embedded (possibly hostile) ``name`` / ``aliases`` never reach a
            markup sink (C-17, LLR-V5.3 F1: this is the highest-risk sink).

        Args:
            template (CrcTemplate): The current template.

        Returns:
            str: The pretty-printed template JSON, or a markup-safe warning.

        Dependencies:
            Uses:
                - :func:`emit_template`
            Used by:
                - :meth:`_recompute`
        """
        try:
            return emit_template(template)
        except (ValueError, TypeError) as exc:
            return f"Cannot render preview: {exc}"

    def _live_warnings_text(self, algo: CrcAlgorithm) -> str:
        """Render the form-computable live warnings (LLR-V5.4b).

        Summary:
            The single form-computable warning that does not need the loaded
            image: ``store_width < ceil(width/8)`` — a stored field too narrow
            for the CRC silently truncates its detection strength, so it is a
            mandatory warn. The fill-no-``pad_byte`` warning needs the coverage
            strip and lands with it in Inc-7. Rendered ``markup=False``.

        Args:
            algo (CrcAlgorithm): The current algorithm.

        Returns:
            str: The warning line, or ``""`` when the stored field is wide enough.

        Dependencies:
            Uses:
                - :meth:`CrcAlgorithm.store_bytes`
            Used by:
                - :meth:`_recompute`
        """
        text = self.query_one("#crc_field_store_width", Input).value.strip()
        try:
            store_width = int(text) if text else None
        except ValueError:
            return ""
        required = algo.store_bytes()
        if store_width is not None and store_width < required:
            return (
                f"store width {store_width} bytes < required {required} bytes "
                "(ceil(width/8)); the stored CRC will be truncated"
            )
        return ""

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
            - :meth:`_current_template` → :meth:`_verdict_text` /
              :meth:`_custom_vector_text` / :meth:`_preview_text` /
              :meth:`_live_warnings_text` → each ``Static.update`` (markup-safe).

        Dependencies:
            Uses:
                - :meth:`_current_template`, :meth:`_verdict_text`,
                  :meth:`_custom_vector_text`, :meth:`_preview_text`,
                  :meth:`_live_warnings_text`
            Used by:
                - :meth:`on_mount`, :meth:`on_input_changed`,
                  :meth:`on_switch_changed`, :meth:`on_select_changed`
        """
        try:
            verdict = self.query_one("#crc_kat_verdict", Static)
            custom_result = self.query_one("#crc_custom_vector_result", Static)
            preview = self.query_one("#crc_json_preview", Static)
            warnings = self.query_one("#crc_warnings", Static)
        except NoMatches:
            # Mid-mount: a change event arrived before every surface exists.
            return
        try:
            template = self._current_template()
        except (ValueError, NoMatches) as exc:
            warning = f"Invalid parameters: {exc}"
            verdict.update(warning)
            custom_result.update("—")
            preview.update(warning)
            warnings.update("")
            return
        algo = template.algorithm
        verdict.update(self._verdict_text(algo))
        custom_result.update(self._custom_vector_text(algo))
        preview.update(self._preview_text(template))
        warnings.update(self._live_warnings_text(algo))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Route the Save / Load button presses (LLR-V5.1 / V5.2).

        Args:
            event (Button.Pressed): The button-press message.

        Returns:
            None

        Dependencies:
            Uses:
                - :meth:`_save_template`, :meth:`_load_template`
        """
        if event.button.id == "crc_save_btn":
            self._save_template()
        elif event.button.id == "crc_load_btn":
            self._load_template()

    def _save_template(self) -> None:
        """Save the current template to the library (LLR-V5.2 / V5.4c, F2/F3).

        Summary:
            Build the current template, normalize its ``name`` through
            :func:`sanitize_project_name`, and write ``emit_template`` to the
            fixed ``<template-lib>/<sanitized-basename>.crc.json`` — a bounded
            write (F3: only the basename is name-derived, the directory is fixed).
            An all-symbol / empty name (``sanitize`` → ``None``) writes NOTHING
            and warns (F2). On Save the known-answer is validated
            (``check == compute("123456789")``, obs #3) and a mismatch WARNS but
            still writes (LLR-V5.4c). Every status/warning renders ``markup=False``
            (C-17). No firmware is ever written (US-V8).

        Returns:
            None

        Dependencies:
            Uses:
                - :meth:`_current_template`, ``sanitize_project_name``,
                  ``ensure_template_lib``, :func:`emit_template`,
                  :meth:`CrcAlgorithm.kat_ok`
            Used by:
                - :meth:`on_button_pressed`
        """
        status = self.query_one("#crc_loadsave_status", Static)
        try:
            template = self._current_template()
        except (ValueError, NoMatches) as exc:
            status.update(f"Cannot save: invalid parameters: {exc}")
            return
        safe_name = sanitize_project_name(template.algorithm.name)
        if safe_name is None:
            status.update(
                "Cannot save: template name is empty after sanitization; "
                "nothing written."
            )
            return
        # Save-time known-answer validation (obs #3): warn, do not block.
        kat_warning = ""
        try:
            if template.algorithm.kat_ok() is False:
                kat_warning = (
                    "check does not match the computed CRC of 123456789 "
                    "(saved anyway)"
                )
        except ValueError as exc:
            kat_warning = f"could not validate the known-answer: {exc} (saved anyway)"
        lib_dir = ensure_template_lib(self.app.base_dir)
        target = lib_dir / f"{safe_name}.crc.json"
        try:
            target.write_text(emit_template(template), encoding="utf-8")
        except OSError as exc:
            status.update(f"Cannot save: {exc}")
            return
        if kat_warning:
            status.update(f"Saved {target.name} with warning: {kat_warning}")
        else:
            status.update(f"Saved template to {target.name}")

    def _load_template(self) -> None:
        """Load a template file through the E5 facade (LLR-V5.1 / V5.3).

        Summary:
            Resolve ``#crc_load_path`` and read it through
            :func:`read_template` (the ``crc_template`` facade — collect-don't
            abort). A fault surfaces EXACTLY ONE markup-safe error and leaves the
            form unchanged (AT-CRC-DSN-015); a valid file populates the form via
            :meth:`_apply_template`, after which the live surfaces recompute so
            the (possibly hostile) ``name`` / ``aliases`` render literally at
            every ``markup=False`` sink incl. the JSON preview (C-17, F1).

        Returns:
            None

        Dependencies:
            Uses:
                - :func:`read_template`, :meth:`_apply_template`
            Used by:
                - :meth:`on_button_pressed`
        """
        status = self.query_one("#crc_loadsave_status", Static)
        raw = self.query_one("#crc_load_path", Input).value.strip()
        if not raw:
            status.update("Cannot load: enter a template path.")
            return
        template, errors = read_template(raw, self.app.base_dir)
        if errors or template is None:
            first = errors[0] if errors else "template could not be read"
            status.update(f"Load failed: {first}")
            return
        self._apply_template(template)
        status.update("Loaded template from file.")

    def _apply_template(self, template: CrcTemplate) -> None:
        """Populate the form from a loaded template, then recompute (LLR-V5.1).

        Summary:
            Set the algorithm fields (via :meth:`_apply_algorithm`), the template
            ``name`` and the comma-joined ``aliases`` from ``template``, then
            recompute the live surfaces. The ``name`` / ``aliases`` are untrusted
            file-derived text; they reach only ``markup=False`` sinks (C-17).

        Args:
            template (CrcTemplate): The loaded template. Never mutated.

        Returns:
            None

        Dependencies:
            Uses:
                - :meth:`_apply_algorithm`, :meth:`_recompute`
            Used by:
                - :meth:`_load_template`
        """
        self._apply_algorithm(template.algorithm)
        self.query_one("#crc_field_name", Input).value = template.algorithm.name
        self.query_one("#crc_field_aliases", Input).value = ", ".join(template.aliases)
        self._recompute()
