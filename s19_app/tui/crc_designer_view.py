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

Inc-7 adds the multi-range coverage strip + per-policy preview (LLR-V6/V7/V8):

- ``#crc_coverage_ranges`` / ``#crc_coverage_intra_gap`` / ``#crc_coverage_join``
  / ``#crc_coverage_pad_byte`` / ``#crc_coverage_on_gap_conflict`` — the coverage
  editor (ordered ranges + the two gap-policy toggles + pad byte + safety policy)
  from which a :class:`CrcTarget` is built (validated through the shared
  ``_build_target`` fault path).
- ``#crc_coverage_preview`` — while an image is loaded, the target's CRC over the
  real ``mem_map`` for BOTH gap policies (concat AND fill) side by side; a
  ``join="fill"`` target honors ``on_gap_conflict`` (``abort`` refuses the
  preview with no CRC, ``warn`` proceeds with a diagnostic, ``ignore`` silent).
  No image loaded → a graceful "load an image" state.
- The ``#crc_warnings`` surface gains the fill-with-no-``pad_byte`` warning (the
  third of the three warn conditions).

The view is preview-only (LLR-V8.1): it reads ``mem_map`` but NEVER mutates it
and never writes firmware bytes — the only file write is the ``*.crc.json``
template on Save. Every sink that shows template/file-derived text — including
the JSON preview that embeds the loaded ``name`` / ``aliases`` verbatim, and the
gap-conflict diagnostics — renders ``markup=False``.

The panel is presentational (s19_app CLAUDE.md TUI architecture): it imports the
headless ``crc_kernel`` / ``crc_designer_model`` primitives for read-only
lookups, vocabulary constants and JSON serialization only, and never calls the
range/validation engine or writes firmware (US-V6 preview-only). Every live
surface renders ``markup=False`` (C-17): file/preset-derived text never reaches
a markup sink.
"""

from __future__ import annotations

from dataclasses import replace

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Input, Label, Select, Static, Switch

from .insight_style import (
    DGRAY,
    GREEN,
    HILITE,
    MICROBAR_EMPTY,
    MICROBAR_FILLED,
    RED,
    YELLOW,
)
from .operations.crc_designer_model import (
    ENDIANNESS_VALUES,
    INTRA_GAP_VALUES,
    JOIN_VALUES,
    ON_GAP_CONFLICT_VALUES,
    CrcTarget,
    _build_target,
    compute_target_crc,
    evaluate_target,
    store_word,
)
from .operations.crc_kernel import PRESETS, SEED_ALGORITHM, CrcAlgorithm, preset_by_name
from .operations.crc_template import CrcTemplate, emit_template, read_template
from .workspace import ensure_template_lib, sanitize_project_name

#: The graceful empty-state note shown when no image is loaded — shared by the
#: coverage preview and the coverage-window hero so the two surfaces never
#: diverge (batch-59 A12; the value is the batch-58 shipped string).
_COVERAGE_EMPTY_STATE = "Load an image to preview coverage CRCs over real bytes."

#: The block-glyph budget for the coverage-window hero line (batch-59 LLR-L1.1,
#: OQ-3/C-23). PILOT-MEASURED: the boxed ``#crc_coverage_window`` usable inner
#: width is 64 cols at the 80x24 floor (100% stacked) and 55 cols at 120x30
#: (the narrower 2fr regime); 48 leaves headroom under the 55-col minimum so the
#: contiguous-span window line never wraps. NOT inherited from the prototype's
#: 150-col line (C-29 non-transfer).
_COVERAGE_WINDOW_GLYPHS = 48

#: Custom-vector interpretation modes (LLR-V3.1). ``ascii`` encodes the raw text
#: as UTF-8 bytes (so ``123456789`` reproduces the KAT); ``hex`` reads
#: whitespace-tolerant hex pairs. An explicit mode is required because
#: ``123456789`` is itself valid hex — auto-detect would mis-read the KAT input.
_VECTOR_MODES: tuple[str, ...] = ("ascii", "hex")

#: Tri-state display tokens for the live verdict (LLR-V2.1; realign R7). The
#: source is the merged :meth:`CrcAlgorithm.kat_ok` ``True`` / ``False`` /
#: ``None``. Each maps to a glyph-primary token (the app's MAC/Issues convention
#: — glyph first, severity colour second, C-10) plus its :mod:`insight_style`
#: colour: ``✓ MATCH`` GREEN, ``✗ MISMATCH`` RED, ``○ NO-EXPECTED`` DGRAY. The
#: ``.plain`` still substring-matches the bare token (``"MATCH" in "✓ MATCH"``).
_VERDICT_TOKENS: dict[bool | None, tuple[str, str]] = {
    True: ("✓ MATCH", GREEN),
    False: ("✗ MISMATCH", RED),
    None: ("○ NO-EXPECTED", DGRAY),
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
        """Compose the realigned "coverage-first bench" (batch-59 + realign R1/R5/R6).

        Summary:
            Re-arrange every batch-58 ``#crc_*`` widget (same ids, same
            ``markup=False`` sinks, same handler wiring) into the realigned
            bench: a full-width help line, then a **hero row** (``#crc_hero_row``)
            holding the live coverage window (``#crc_coverage_window``, 2fr)
            beside ``#crc_top_right`` (the glyph verdict hero above the Warnings
            tile), then a **3-column bench** (``#crc_bench``) regrouped by data
            flow (R5): c1 = Algorithm (preset first, R1), c2 = Coverage + Store
            placement, c3 = Custom vector + Template + Load/Save, and finally the
            Template-JSON preview as a **full-width strip** below the bench (R6).
            No widget id, handler, or behavior changes — only the nesting and
            labels (HLR-L4).

        Returns:
            ComposeResult: the re-nested bench widget tree.

        Data Flow:
            - Each ``.crc-field-group`` is built once, then placed into a column
              ``Vertical`` / the hero row / the full-width strip; ``query_one("#…")``
              resolves any of them anywhere in the subtree, so the shipped
              ``_recompute`` / Load/Save handlers keep firing (LLR-L4.1).
        """
        algo = SEED_ALGORITHM
        byte_width = algo.store_bytes()
        yield Static(
            "CRC Designer (preview-only): pick a preset or edit the "
            "parameters; presets are read-only starting points.",
            id="crc_designer_help",
            markup=False,
        )

        # R1: the preset selector is the first row of the Algorithm group (it
        # populates the algorithm fields) — nothing floats above the hero.
        algorithm_group = Vertical(
            Label("Algorithm", classes="crc-group-title"),
            Horizontal(
                Label("Preset", classes="crc-field-label"),
                Select(
                    [(preset.name, preset.name) for preset in PRESETS],
                    value=algo.name,
                    allow_blank=False,
                    id="crc_preset_select",
                ),
                classes="crc-field-row",
            ),
            self._text_row("Width (bits)", "crc_field_width", str(algo.width)),
            self._text_row(
                "Polynomial", "crc_field_poly", _format_hex(algo.poly, byte_width)
            ),
            self._text_row("Init", "crc_field_init", _format_hex(algo.init, byte_width)),
            self._switch_row("Reflect in", "crc_field_refin", algo.refin),
            self._switch_row("Reflect out", "crc_field_refout", algo.refout),
            self._text_row(
                "XOR out", "crc_field_xorout", _format_hex(algo.xorout, byte_width)
            ),
            self._text_row(
                "Check",
                "crc_field_check",
                "" if algo.check is None else _format_hex(algo.check, byte_width),
            ),
            id="crc_algorithm_fields",
            classes="crc-field-group",
        )
        serialization_group = Vertical(
            Label("Store placement", classes="crc-group-title"),
            self._text_row("Address", "crc_field_output_address", "0x00000000"),
            self._text_row(
                "Bytes", "crc_field_store_width", str(byte_width),
                placeholder="ceil(width/8)",
            ),
            self._select_row(
                "Store endianness", "crc_field_store_endianness", ENDIANNESS_VALUES
            ),
            id="crc_serialization_fields",
            classes="crc-field-group",
        )
        coverage_group = Vertical(
            Label("Coverage · preview-only", classes="crc-group-title"),
            self._text_row(
                "Ranges",
                "crc_coverage_ranges",
                "0x00008000-0x00008008, 0x00008010-0x00008018",
                placeholder="start-end, start-end, …",
            ),
            self._select_row("Intra gap", "crc_coverage_intra_gap", INTRA_GAP_VALUES),
            self._select_row("Join gaps", "crc_coverage_join", JOIN_VALUES),
            self._text_row("Pad byte", "crc_coverage_pad_byte", "0xFF"),
            self._select_row(
                "On conflict", "crc_coverage_on_gap_conflict", ON_GAP_CONFLICT_VALUES
            ),
            Static("", id="crc_coverage_preview", markup=False, classes="crc-verdict"),
            id="crc_coverage_group",
            classes="crc-field-group",
        )
        custom_vector_group = Vertical(
            Label("Custom test vector", classes="crc-group-title"),
            self._select_row("Mode", "crc_custom_vector_mode", _VECTOR_MODES),
            self._text_row("Vector", "crc_custom_vector", "123456789"),
            Horizontal(
                Label("CRC", classes="crc-field-label"),
                Static(
                    "",
                    id="crc_custom_vector_result",
                    markup=False,
                    classes="crc-verdict",
                ),
                classes="crc-field-row",
            ),
            id="crc_custom_vector_group",
            classes="crc-field-group",
        )
        json_preview_group = Vertical(
            Label(
                "Template JSON · round-trips through parse_template",
                classes="crc-group-title",
            ),
            Static("", id="crc_json_preview", markup=False, classes="crc-json-preview"),
            id="crc_json_preview_group",
            classes="crc-field-group",
        )
        template_group = Vertical(
            Label("Template", classes="crc-group-title"),
            self._text_row("Name", "crc_field_name", algo.name),
            self._text_row(
                "Aliases", "crc_field_aliases", "", placeholder="comma-separated"
            ),
            id="crc_template_fields",
            classes="crc-field-group",
        )
        loadsave_group = Vertical(
            Label("Load / Save", classes="crc-group-title"),
            self._text_row(
                "Load path", "crc_load_path", "",
                placeholder="path/to/name.crc.json",
            ),
            Horizontal(
                Button("Save", id="crc_save_btn"),
                Button("Load", id="crc_load_btn"),
                classes="crc-field-row",
            ),
            Static("", id="crc_loadsave_status", markup=False, classes="crc-status"),
            id="crc_loadsave_group",
            classes="crc-field-group",
        )
        verdict_group = Vertical(
            Label("Known answer · 123456789", classes="crc-group-title"),
            Static("", id="crc_kat_verdict", markup=False, classes="crc-verdict"),
            id="crc_live_verify",
            classes="crc-field-group crc-hero",
        )
        warnings_group = Vertical(
            Label("Warnings", classes="crc-group-title"),
            Static("", id="crc_warnings", markup=False, classes="crc-warnings"),
            id="crc_warnings_group",
            classes="crc-field-group",
        )

        # Hero row: the wide live coverage window (2fr) beside the glyph verdict
        # hero + Warnings right column (1fr).
        yield Horizontal(
            Static("", id="crc_coverage_window", markup=False),
            Vertical(verdict_group, warnings_group, id="crc_top_right"),
            id="crc_hero_row",
        )
        # 3-column parameter bench below the hero row, regrouped by data flow (R5).
        yield Horizontal(
            Vertical(algorithm_group, id="crc_bench_c1"),
            Vertical(coverage_group, serialization_group, id="crc_bench_c2"),
            Vertical(custom_vector_group, template_group, loadsave_group, id="crc_bench_c3"),
            id="crc_bench",
        )
        # R6: the flat JSON text gets the wide surface — a full-width strip below
        # the bench instead of wrapping inside the narrow third column.
        yield json_preview_group

    @staticmethod
    def _text_row(
        label: str, field_id: str, value: str, placeholder: str = ""
    ) -> Horizontal:
        """Build a labelled single-line ``Input`` row.

        Args:
            label (str): The human-readable field label.
            field_id (str): The ``#crc_field_*`` id the pilot/handlers query.
            value (str): The initial (seed) field value.
            placeholder (str): The dim syntax hint shown when the field is empty
                (realign R4 — hints move out of the label into the ``Input``).

        Returns:
            Horizontal: The label + ``Input`` row.
        """
        return Horizontal(
            Label(label, classes="crc-field-label"),
            Input(
                value=value,
                id=field_id,
                placeholder=placeholder,
                classes="crc-field-input",
            ),
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

    @staticmethod
    def _select_row(
        label: str, field_id: str, values: tuple[str, ...]
    ) -> Horizontal:
        """Build a labelled vocabulary ``Select`` row seeded to ``values[0]``.

        Args:
            label (str): The human-readable field label.
            field_id (str): The ``#crc_*`` id the pilot/handlers query.
            values (tuple[str, ...]): The allowed vocabulary; the first is the
                seed value (``allow_blank=False``), matching the batch-58 rows.

        Returns:
            Horizontal: The label + ``Select`` row.
        """
        return Horizontal(
            Label(label, classes="crc-field-label"),
            Select(
                [(value, value) for value in values],
                value=values[0],
                allow_blank=False,
                id=field_id,
            ),
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

    def _verdict_text(self, algo: CrcAlgorithm) -> Text:
        """Render the glyph-primary tri-state known-answer verdict (LLR-V2.1 / V2.2; R7).

        Summary:
            Compute :meth:`CrcAlgorithm.kat_ok` and map the ``True`` / ``False``
            / ``None`` tri-state to the glyph-primary tokens ``✓ MATCH`` (GREEN)
            / ``✗ MISMATCH`` (RED) / ``○ NO-EXPECTED`` (DGRAY) — glyph first,
            severity colour second (the app's MAC/Issues convention, C-10). A
            compute fault (width ∉ [8, 64]) renders a ``⚠ Cannot compute`` YELLOW
            warning rather than propagating. Built with :class:`~rich.text.Text`
            ``append`` (never ``Text.from_markup``) so the ``markup=False`` sink
            stays injection-safe (C-17); the ``.plain`` still substring-matches
            the bare token.

        Args:
            algo (CrcAlgorithm): The current algorithm.

        Returns:
            Text: The styled glyph-primary verdict, or a ``⚠ Cannot compute``
            warning.

        Dependencies:
            Uses:
                - :meth:`CrcAlgorithm.kat_ok`
            Used by:
                - :meth:`_recompute`
        """
        try:
            ok = algo.kat_ok()
        except ValueError as exc:
            return Text(f"⚠ Cannot compute: {exc}", style=YELLOW)
        token, color = _VERDICT_TOKENS[ok]
        return Text(token, style=f"bold {color}")

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

    def _live_warnings_text(self, algo: CrcAlgorithm) -> Text:
        """Render the form-computable live warnings (LLR-V5.4b / V5.4a; R7).

        Summary:
            The two form-computable warnings that do not need the loaded image,
            each rendered independently on its own ``⚠``-prefixed YELLOW line
            (LLR-V5.4, M4); when neither holds the tile shows a ``✓ none`` GREEN
            confirmation (realign R7 — a positive clean state, not a blank):

            - ``store_width < ceil(width/8)`` — a stored field too narrow for the
              CRC silently truncates its detection strength (mandatory warn).
            - the coverage strip selects ``intra_gap`` or ``join`` = ``"fill"``
              while ``pad_byte`` is unset — the filled bytes then silently default,
              so the operator is warned to set an explicit pad byte (the third
              warn condition, LLR-V5.4a).

            Built with :class:`~rich.text.Text` ``append`` (never
            ``Text.from_markup``); all lines render at the ``markup=False`` sink
            (C-17).

        Args:
            algo (CrcAlgorithm): The current algorithm.

        Returns:
            Text: The ``⚠``-prefixed warning lines, or a ``✓ none`` confirmation
            when neither condition holds.

        Dependencies:
            Uses:
                - :meth:`CrcAlgorithm.store_bytes`
            Used by:
                - :meth:`_recompute`
        """
        warnings: list[str] = []
        text = self.query_one("#crc_field_store_width", Input).value.strip()
        try:
            store_width = int(text) if text else None
        except ValueError:
            store_width = None
        required = algo.store_bytes()
        if store_width is not None and store_width < required:
            warnings.append(
                f"store width {store_width} bytes < required {required} bytes "
                "(ceil(width/8)); the stored CRC will be truncated"
            )
        intra_gap = str(self.query_one("#crc_coverage_intra_gap", Select).value)
        join = str(self.query_one("#crc_coverage_join", Select).value)
        pad_raw = self.query_one("#crc_coverage_pad_byte", Input).value.strip()
        if (intra_gap == "fill" or join == "fill") and not pad_raw:
            warnings.append(
                "fill policy selected but pad_byte is unset; the filled bytes "
                "default to 0xFF — set an explicit pad byte"
            )
        if not warnings:
            return Text("✓ none", style=GREEN)
        rendered = Text()
        for index, warning in enumerate(warnings):
            if index:
                rendered.append("\n")
            rendered.append(f"⚠ {warning}", style=YELLOW)
        return rendered

    def _parse_ranges(self, raw: str) -> list[tuple[int, int]]:
        """Parse the coverage ``start-end`` range list (LLR-V6.1).

        Summary:
            Read the comma-separated ``#crc_coverage_ranges`` text into an
            ordered list of half-open ``(start, end)`` hex ranges (``0x`` prefix
            optional), preserving DECLARED order. A malformed token or an empty
            list raises :class:`ValueError`, which the caller renders as a
            markup-safe warning.

        Args:
            raw (str): The raw ranges-field text.

        Returns:
            list[tuple[int, int]]: The ranges in declared order.

        Raises:
            ValueError: A token is not ``start-end`` hex, or no range is given.

        Dependencies:
            Used by:
                - :meth:`_build_coverage_target`
        """
        ranges: list[tuple[int, int]] = []
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" not in token:
                raise ValueError(f"range {token!r} must be 'start-end'")
            start_text, _, end_text = token.partition("-")
            ranges.append((int(start_text.strip(), 16), int(end_text.strip(), 16)))
        if not ranges:
            raise ValueError("enter at least one range as 'start-end'")
        return ranges

    def _build_coverage_target(self) -> CrcTarget:
        """Build the coverage :class:`CrcTarget` from the strip + serialization.

        Summary:
            Assemble the coverage-strip fields (ranges + ``intra_gap`` + ``join``
            + ``pad_byte`` + ``on_gap_conflict``) and the serialization fields
            (``output_address`` / ``store_width`` / ``store_endianness``) into a
            raw target dict and validate it through the shared
            :func:`_build_target` fault path (LLR-V6.1) — so an inverted range or
            out-of-range field surfaces the same collected error the loader uses.
            An empty ``pad_byte`` field defaults to ``0xFF`` for the compute (the
            unset state itself drives the fill-no-pad warning, LLR-V5.4a).

        Returns:
            CrcTarget: The validated target the preview digests.

        Raises:
            ValueError: A malformed range/field or a ``_build_target`` rule
                violation — caught by :meth:`_coverage_preview_text`.

        Dependencies:
            Uses:
                - :meth:`_parse_ranges`, :func:`_build_target`
            Used by:
                - :meth:`_coverage_preview_text`
        """
        ranges = self._parse_ranges(
            self.query_one("#crc_coverage_ranges", Input).value
        )
        pad_raw = self.query_one("#crc_coverage_pad_byte", Input).value.strip()
        pad_byte = int(pad_raw, 16) if pad_raw else 0xFF
        store_text = self.query_one("#crc_field_store_width", Input).value.strip()
        raw = {
            "ranges": [{"start": start, "end": end} for start, end in ranges],
            "intra_gap": str(self.query_one("#crc_coverage_intra_gap", Select).value),
            "join": str(self.query_one("#crc_coverage_join", Select).value),
            "pad_byte": pad_byte,
            "output_address": self._hex_field("#crc_field_output_address"),
            "store_width": int(store_text) if store_text else 4,
            "store_endianness": str(
                self.query_one("#crc_field_store_endianness", Select).value
            ),
            "on_gap_conflict": str(
                self.query_one("#crc_coverage_on_gap_conflict", Select).value
            ),
        }
        return _build_target(0, raw)

    def _coverage_preview_text(self, algo: CrcAlgorithm) -> str:
        """Render the per-policy coverage preview over the loaded image (LLR-V6.2 / V7.1).

        Summary:
            While an image is loaded, compute the target's CRC over the real
            ``mem_map`` for BOTH gap policies (``concat`` AND ``fill``) and show
            them side by side, marking the active ``join`` (LLR-V6.2). A
            ``join="fill"`` target is first evaluated under its
            ``on_gap_conflict`` policy (:func:`evaluate_target`, LLR-V7.1):
            ``abort`` refuses the preview (no CRC, a refusal notice), ``warn``
            proceeds and appends the plain-text diagnostic, ``ignore`` proceeds
            silently. No image loaded → a graceful "load an image" note and no
            compute. The view only READS ``mem_map`` — never mutates it, never
            writes firmware (LLR-V8.1). All text renders ``markup=False``.

        Args:
            algo (CrcAlgorithm): The current algorithm.

        Returns:
            str: The per-policy preview, a refusal notice, or the empty-state
            note — all markup-safe.

        Dependencies:
            Uses:
                - :meth:`_build_coverage_target`, :func:`evaluate_target`,
                  :func:`compute_target_crc`
            Used by:
                - :meth:`_recompute`
        """
        loaded = getattr(self.app, "current_file", None)
        mem_map = loaded.mem_map if loaded is not None else None
        if not mem_map:
            return _COVERAGE_EMPTY_STATE
        try:
            target = self._build_coverage_target()
        except (ValueError, KeyError) as exc:
            return f"Invalid coverage: {exc}"
        try:
            evaluation = evaluate_target(mem_map, algo, target)
        except ValueError as exc:
            return f"Cannot preview: {exc}"
        if evaluation.refused:
            shown = ", ".join(f"0x{addr:X}" for addr in evaluation.conflicts[:8])
            return (
                "Preview refused (on_gap_conflict=abort): "
                f"{len(evaluation.conflicts)} present byte(s) at {shown} conflict "
                "with a filled gap; no CRC shown."
            )
        concat_crc = compute_target_crc(mem_map, algo, replace(target, join="concat"))
        fill_crc = compute_target_crc(mem_map, algo, replace(target, join="fill"))
        lines = [
            f"Active policy: join={target.join}",
            f"concat: {_format_hex(concat_crc, target.store_width)}",
            f"fill:   {_format_hex(fill_crc, target.store_width)}",
        ]
        lines.extend(evaluation.diagnostics)
        return "\n".join(lines)

    def _render_coverage_window(self, algo: CrcAlgorithm) -> Text:
        """Render the multi-range coverage window as colored block glyphs (LLR-L1.1).

        Summary:
            The Variant-B signature (HLR-L1): draw the current target's memory
            window as a block-glyph run per range (present bytes, accent hue) and
            per inter-range gap (erased grey when ``join="concat"``, pad-fill in
            the warning hue when ``join="fill"``), then the LIVE concat and fill
            policy CRC hexes and the active-policy store-word bytes. The two CRCs
            are computed over the real ``mem_map`` via the shipped
            :func:`compute_target_crc` (reused verbatim — 0 new engine math), so a
            static mock would fail the oracle pin (D-1 / B2). No image loaded → the
            shipped empty-state note (no glyph compute); a malformed range → a
            markup-safe ``Invalid coverage`` note (reusing the
            :meth:`_build_coverage_target` fault path). Built via
            :class:`~rich.text.Text` ``append`` — NEVER ``Text.from_markup`` — so
            operator range text on the fault branch renders literally (C-17; the
            widget is ``markup=False``, LLR-L1.2). The window only READS
            ``mem_map`` (US-V8 preview-only, R-4).

        Args:
            algo (CrcAlgorithm): The current algorithm the CRCs are computed with.

        Returns:
            Text: The colored block-glyph window (glyphs + concat/fill hexes +
            store bytes), or the empty-state / invalid-coverage note.

        Data Flow:
            - :meth:`_build_coverage_target` → per-range/per-gap glyph runs
              (:data:`insight_style` palette) + :func:`compute_target_crc`
              (``join`` concat/fill) + :func:`store_word` → styled ``Text``.

        Dependencies:
            Uses:
                - :meth:`_build_coverage_target`, :func:`compute_target_crc`,
                  :func:`store_word`, :func:`_format_hex`, the ``insight_style``
                  palette
            Used by:
                - :meth:`_recompute`
        """
        loaded = getattr(self.app, "current_file", None)
        mem_map = loaded.mem_map if loaded is not None else None
        if not mem_map:
            return Text(_COVERAGE_EMPTY_STATE)
        try:
            target = self._build_coverage_target()
        except (ValueError, KeyError) as exc:
            # Markup-safe by construction: Text() (NOT Text.from_markup) renders
            # the echoed raw operator token literally — the sink's safety rests on
            # markup=False, NOT on the source being int-only (this fault branch DOES
            # echo raw operator text; F2-minor / AT-B59-09).
            return Text(f"Invalid coverage: {exc}")

        span = target.ranges[-1][1] - target.ranges[0][0]
        bytes_per_glyph = max(1, -(-span // _COVERAGE_WINDOW_GLYPHS))  # ceil-divide
        text = Text()
        prev_end: int | None = None
        for start, end in target.ranges:
            if prev_end is not None and start > prev_end:
                gap_glyphs = max(1, round((start - prev_end) / bytes_per_glyph))
                if target.join == "fill":
                    text.append(MICROBAR_FILLED * gap_glyphs, style=YELLOW)
                else:
                    text.append(MICROBAR_EMPTY * gap_glyphs, style=DGRAY)
            range_glyphs = max(1, round((end - start) / bytes_per_glyph))
            text.append(MICROBAR_FILLED * range_glyphs, style=HILITE)
            prev_end = end
        text.append("\n")

        try:
            concat_crc = compute_target_crc(mem_map, algo, replace(target, join="concat"))
            fill_crc = compute_target_crc(mem_map, algo, replace(target, join="fill"))
            # F1: gate the ACTIVE-policy store word through the shipped abort
            # contract so the hero agrees with the sibling preview — a dirty fill
            # gap under on_gap_conflict="abort" refuses the CRC (crc=None), and the
            # window must NOT emit that divergent store word (evaluate_target,
            # AT-058-08). Showing both concat+fill hexes for comparison stays fine.
            evaluation = evaluate_target(mem_map, algo, target)
        except ValueError as exc:
            text.append(f"Cannot compute: {exc}", style=DGRAY)
            return text
        text.append("concat ", style=DGRAY)
        text.append(_format_hex(concat_crc, target.store_width), style=HILITE)
        text.append("   fill ", style=DGRAY)
        text.append(_format_hex(fill_crc, target.store_width), style=YELLOW)
        text.append("\n")
        if evaluation.refused:
            text.append("store — refused (on_gap_conflict=abort)", style=YELLOW)
            return text
        store_bytes = store_word(evaluation.crc, target)
        text.append("store ", style=DGRAY)
        text.append(store_bytes.hex(" ").upper(), style=HILITE)
        for diagnostic in evaluation.diagnostics:
            text.append("\n")
            text.append(diagnostic, style=YELLOW)
        return text

    def _recompute(self) -> None:
        """Recompute the live surfaces from the current fields.

        Summary:
            The single recompute entry point wired to every change event
            (LLR-V2.1). Build the current algorithm and refresh the verdict,
            custom-vector CRC, JSON preview, live warnings and coverage preview.
            A field that cannot even form an algorithm (non-hex parameter)
            renders one markup-safe warning across the surfaces instead of
            crashing (LLR-V2.2). During mount — before all sibling widgets exist
            — the ``NoMatches`` is swallowed; :meth:`on_mount` performs the first
            full compute.

        Returns:
            None

        Data Flow:
            - :meth:`_current_template` → :meth:`_verdict_text` /
              :meth:`_custom_vector_text` / :meth:`_preview_text` /
              :meth:`_live_warnings_text` / :meth:`_coverage_preview_text` →
              each ``Static.update`` (markup-safe).

        Dependencies:
            Uses:
                - :meth:`_current_template`, :meth:`_verdict_text`,
                  :meth:`_custom_vector_text`, :meth:`_preview_text`,
                  :meth:`_live_warnings_text`, :meth:`_coverage_preview_text`
            Used by:
                - :meth:`on_mount`, :meth:`on_input_changed`,
                  :meth:`on_switch_changed`, :meth:`on_select_changed`
        """
        try:
            verdict = self.query_one("#crc_kat_verdict", Static)
            custom_result = self.query_one("#crc_custom_vector_result", Static)
            preview = self.query_one("#crc_json_preview", Static)
            warnings = self.query_one("#crc_warnings", Static)
            coverage = self.query_one("#crc_coverage_preview", Static)
            window = self.query_one("#crc_coverage_window", Static)
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
            coverage.update(warning)
            window.update(warning)
            return
        algo = template.algorithm
        verdict.update(self._verdict_text(algo))
        custom_result.update(self._custom_vector_text(algo))
        preview.update(self._preview_text(template))
        warnings.update(self._live_warnings_text(algo))
        coverage.update(self._coverage_preview_text(algo))
        window.update(self._render_coverage_window(algo))

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
