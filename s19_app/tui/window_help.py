"""Per-window usage help — the ``?`` affordance + modal (batch-95 change 3,
HLR-140 / LLR-140.1..140.2).

Each shipped window gains a ``?`` ghost chip beside its title (left side of the
header row, never displacing the ``📂 Open folder`` chip) and a focused-window
``?`` binding: while a widget of that window holds focus, ``?`` opens THIS
window's "how to use this window's functions" section instead of the app-wide
stock ``HelpPanel`` — the global ``question_mark`` binding (action
``show_help_panel``) stays untouched and still opens the panel whenever no
window-focused path claims the key (LLR-140.1).

The modal is the shipped :class:`~s19_app.tui.screens.VariantHelpScreen`
pattern (``screens.py:416``) generalized to the authored sections: the
title + numbered steps render through a ``markup=False`` ``Static`` so the
copy is verbatim — no Rich/console-markup parsing of the file-derived
strings. The copy lives in ONE editable home — :data:`WINDOW_HELP_SECTIONS`
below — a faithful port of the operator-authored ``prototypes/cambios_10_12_2026/
help_sections.md`` (that md stays the source draft for the nine window
sections; the shipped copy lives here, LLR-140.2). The numbering is
generated at render time so the operator can delete/reorder steps freely
(the md's own drafting notes) without ever leaving a gap in the sequence.
A tenth section (``changes_file_notation``, batch-96 / TC-1802) is
code-authored beside the md port — it documents the v2 change-set JSON
notation for hand-editing and is NOT part of the md fidelity census.

The ninth section (``split_join_export``) ships NOW but its window is
change 4 (inc-004) — no placeholder window is invented; a future seat calls
:func:`open_window_help` with that key and gets the modal for free.
"""
from __future__ import annotations

import logging
from typing import Dict, Tuple

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# The data home — one editable dict (LLR-140.2)
# --------------------------------------------------------------------------- #
#
# Keys are the windows' keys: the seven rail screens use their
# SCREEN_CONTAINER_IDS keys (``patch`` / ``checks`` / ``crc_designer`` /
# ``map`` / ``flow`` / ``a2l`` / ``workspace``), the Reports modal uses
# ``reports``, and the ninth authored section (Split / Join / Export) is
# ``split_join_export`` — reserved for the inc-004 window. Every one of
# those nine steps is a verbatim port of help_sections.md (numbers
# stripped; they re-render as ``N.`` at compose time). The tenth key,
# ``changes_file_notation`` (batch-96 / TC-1802), is code-authored next to
# them — NOT an md port — and documents the v2 change-set file notation.

WINDOW_HELP_SECTIONS: Dict[str, Dict[str, object]] = {
    "patch": {
        "title": "Patch Editor",
        "steps": (
            "Load an S19/HEX image first (`^L`) — patching needs bytes in "
            "memory.",
            "Type an address (`0x…`) plus either a string value or a run of "
            "hex bytes, then press **Add** to append a change entry. The "
            "entry list below previews the bytes of whichever row is "
            "selected.",
            "Alternatively paste or load a v2 change-set JSON "
            "(`s19app-changeset`, `\"kind\": \"change\"`) — the JSON EDIT "
            "pane accepts a pasted document and validates it against the v2 "
            "schema.",
            "Press **Run checks** (same screen) to verify every entry "
            "against the loaded image; uncheckable rows name their reason "
            "(declaration fault, partial/outside range, no image) and "
            "healthy entries are still checked.",
            "The variant selector beside the editor picks which firmware "
            "image of the project loads — it appears only when the project "
            "holds at least two images.",
            "**Open folder** (change 2) jumps to where your change-set "
            "files live: the project folder when a project is saved, the "
            "common `workarea\\patches\\` otherwise.",
        ),
    },
    "checks": {
        "title": "Checks",
        "steps": (
            "Checks run from the Patch Editor — this window is the "
            "read-only result view.",
            "The header tallies **Pass / Fail / Uncheck**; the table lists "
            "every entry with its status. Grouped view clusters failures by "
            "reason.",
            "Select a row to peek at its bytes in the Hex Peek pane and see "
            "*why* it failed.",
            "An “Uncheck” entry is not a failure: it means the entry "
            "cannot be verified (no image, outside range, declaration "
            "fault) — fix the change document or load the right image.",
            "Re-run after every edit; a change-set that is not 100 % pass "
            "should not be exported.",
        ),
    },
    "crc_designer": {
        "title": "CRC Designer",
        "steps": (
            "Pick a preset (e.g. CRC-32/ISO-HDC) — presets are read-only "
            "starting points; every parameter (width, polynomial, init, "
            "reflections, XOR-out) stays editable.",
            "The self-test vector (`123456789`) must read **MATCH** before "
            "you trust a custom set.",
            "Coverage computes CRCs over the image's real ranges: choose "
            "how intra-gaps are handled (skip / concat), the pad byte, and "
            "the on-conflict behaviour.",
            "**Store placement** sets where the coverage CRC is written "
            "back (address, byte count, endianness) — preview-only until "
            "an image is loaded.",
            "Save reusable parameter sets as templates — they land in the "
            "template library (`.s19tool\\templates\\`, or the project "
            "folder under change 1) and reload by name.",
            "**Open folder** (change 2) opens exactly that template "
            "library.",
        ),
    },
    "reports": {
        "title": "Reports",
        "steps": (
            "Reports belong to a project — load or save one first (`p` / "
            "`^S`).",
            "The list shows every `reports\\*.md` newest-first; pick one "
            "to view it.",
            "Use **Filter** (dropdown or a filter path) to render only "
            "part of a report — blank means the full report.",
            "**Declared regions** pre-fills from the loaded A2L; add "
            "`name,start,end` lines to annotate region coverage in the "
            "generated report.",
            "**Context bytes** controls how many bytes of surrounding "
            "memory accompany each change in the report.",
            "**Generate new report** writes the `*.md` + `*.html` pair "
            "into the project's `reports\\` folder; **Open folder** "
            "(change 2) opens that folder directly.",
        ),
    },
    "map": {
        "title": "Memory Map",
        "steps": (
            "Load an image, then page through memory with `+` / `-` "
            "(context pages) and `,` / `.` (hex zoom out/in).",
            "The band bar maps which addresses hold data — entropy "
            "colouring separates code-like from fill-like content.",
            "The ruler gives absolute addresses; the region list names "
            "each contiguous run with its span.",
            "The inspector hex peek shows bytes around the cursor — use "
            "`g` to jump to an address.",
        ),
    },
    "flow": {
        "title": "Flow Builder",
        "steps": (
            "Compose an operation chain by adding steps; each step's "
            "parameters validate as you type.",
            "Save the flow as JSON — flows are **project-only** and land "
            "in the project's `flows\\` folder (LLR-003.7); load one back "
            "from the same list.",
            "Run the chain against the loaded image; every step's output "
            "feeds the next.",
            "Keep flows small and named after their intent — they are the "
            "repeatable “macro” of a session.",
        ),
    },
    "a2l": {
        "title": "A2L Explorer",
        "steps": (
            "Load an A2L (`^L`) to browse its section tree — "
            "characteristics, measurements, records, typedefs.",
            "Use find (`/`) to jump to a name; the tree highlights "
            "matches in place.",
            "`j` dumps the parsed A2L to JSON for external tooling.",
            "Memory segments (when the A2L declares `MEMORY_SEGMENT`) "
            "classify addresses as flash/RAM — this is the same table the "
            "Split / Join / Export window offers.",
        ),
    },
    "workspace": {
        "title": "Workspace",
        "steps": (
            "Load files with `^L` / `l` — S19/HEX images, A2L, MAC. "
            "Loaded artifacts appear in the Loaded panel with their "
            "diagnostics.",
            "Save a project (`^S` / `s`) to gather the loaded files into "
            "one project folder; load one back with `p`. Change 1 extends "
            "the gather to the JSON artifacts.",
            "`o` opens the workarea in Explorer; `r` refreshes the file "
            "list.",
            "`U` unloads everything (with per-artifact unload from the "
            "Loaded panel).",
            "Without a project, artifacts stay in the workspace's common "
            "folders — see the folders.html board for the exact layout.",
        ),
    },
    "split_join_export": {
        "title": "Split / Join / Export",
        "steps": (
            "Pick the source image: the loaded file, a project file, or "
            "browse to one.",
            "Choose what to slice by — A2L `MEMORY_SEGMENT`s, the image's "
            "own contiguous ranges, or manual `0xSTART-0xEND` localities "
            "(one per line).",
            "Tick the ranges to export; the coverage column warns when a "
            "range has no bytes in the source image.",
            "Choose the mode. **split** writes one file per selected "
            "range. **join** packs the whole selection into ONE file — "
            "`concat` (ranges back-to-back) or `fill` (ranges stay at "
            "their original offsets, the gaps between them padded) — same "
            "vocabulary as the CRC Designer's coverage editor.",
            "Set the gap policy when more than one range is in play: "
            "`skip` keeps files sparse (today's emitters), `fill` pads "
            "with the configurable pad byte (default `0x00`).",
            "Pick the format — S19 / HEX / BIN — it applies to BOTH "
            "modes; then destination (project or common folder) and the "
            "naming pattern. The sample filename updates live.",
            "Export: split writes `‹stem›_‹segment›.‹ext›` per range; "
            "join writes one `‹stem›_joined.‹ext›`.",
        ),
    },
    #: batch-97 Inc-3 (D10 / D25, LLR-148.6): CODE-authored like the tenth
    #: section below — not an md port, so outside TC-707's md census. One
    #: ``label — effect`` line per label, key and glyph the Check Editor
    #: paints (TC-B97-32 parses this body). The key lines are hand-typed until
    #: Inc-8's generated keys block replaces them (D27).
    "check_editor": {
        "title": "Check Editor",
        "steps": (
            "Collect A2L parameters and memory rows into a check spec "
            "(`.chk.json`) whose fields ride the A2B diff report; a check "
            "spec is never applied.",
            "Filter — narrows the A2L PARAMETERS ledger to the names that "
            "contain the typed text.",
            "Include parameter — adds the highlighted ledger row to the "
            "REPORT FIELDS, or removes it when it is already included; the "
            "line under the ledger shows that row's full name and address.",
            "space — on the ledger, includes or excludes the highlighted row, "
            "like Include parameter; on a tab chip, opens its tab.",
            "enter — on the ledger, includes or excludes the highlighted "
            "row, like space; on a chip or button, presses it.",
            "Fields — shows the included fields, one line each, then the "
            "memory-row form and the Validate verdicts.",
            "JSON — shows the check spec document the fields produce "
            "(read-only).",
            "Addendum — shows what the A2B diff report gains from this spec.",
            "Address — the memory row's start address, `0x…` hex or decimal.",
            "Label — the memory row's name in the report (optional).",
            "Size (bytes) — 1 to 8; the Fmt column shows it as u8 / u16 / "
            "u32 / u64.",
            "Add row — appends the memory row typed above.",
            "Remove row — removes the highlighted memory row.",
            "Spec — loads a check spec from the patches folder into the "
            "collector.",
            "Write as — the file name Write .chk.json saves under.",
            "Validate — checks the fields against the loaded image; the "
            "verdicts show under the memory form.",
            "Write .chk.json — writes the check spec; nothing is applied to "
            "the image.",
            "Open checks/ — opens the project's checks folder, where check "
            "specs are kept.",
            "Open patches/ — without a project, opens the common patches "
            "folder, where check specs are kept.",
            "? — opens this help.",
            "✓ — the ledger row is included in the REPORT FIELDS.",
            "◆ — a REPORT FIELDS line for an included parameter.",
            "▪ — a REPORT FIELDS line for a memory row: its address, its "
            "width (u8 … u64) and its label, or `memory row` when none was "
            "typed.",
        ),
    },
    #: Tenth section (batch-96, TC-1802 — the 2026-10-18 PDF-bug request):
    #: CODE-authored (NOT ported from help_sections.md, so TC-707's md
    #: fidelity census stays scoped to the nine sections above). Documents
    #: the v2 change-set file notation (changes/io.py LLR-001.1/.2) so an
    #: operator can hand-write a change-set JSON in a text editor. Ships
    #: copy-only like ``split_join_export`` — no window key is consumed.
    "changes_file_notation": {
        "title": "Changes file notation",
        "steps": (
            "A change-set file is ONE JSON object (UTF-8) that you can "
            "hand-write in any text editor, then load (`^L`) or paste into "
            "the Patch Editor's JSON EDIT pane. The five envelope fields "
            "are required: `format` = `s19app-changeset`, `version` = "
            "`2.0`, `kind` = `change` (modifications) or `check` "
            "(expected values), `encoding` = a text codec such as `utf-8`, "
            "and `value_mode` = `text` or `codes`.",
            "`entries` is the array of changes, applied in document order. "
            "Each entry carries `type` — `bytes` or `string` — and an "
            "`address`; a `bytes` entry adds `bytes` (uppercase two-hex-"
            "digit tokens separated by spaces, e.g. `DE AD BE EF`), while "
            "a `string` entry adds `value` — the literal text under "
            "`value_mode: text`, or an array of code points under `codes`.",
            "`address` is a `0x…` hex string such as `0x800020` (a plain "
            "non-negative integer also parses). An entry may add the "
            "optional `symbol` with an A2L tag name, but the resolved "
            "address always stays beside it; unknown extra keys are "
            "ignored on load.",
            "The smallest hand-written change-set — one 4-byte patch at "
            "`0x800020`:\n"
            "```json\n"
            "{\n"
            '  "format": "s19app-changeset",\n'
            '  "version": "2.0",\n'
            '  "kind": "change",\n'
            '  "encoding": "utf-8",\n'
            '  "value_mode": "text",\n'
            '  "entries": [\n'
            '    {"type": "bytes", "address": "0x800020", "bytes": '
            '"DE AD BE EF"}\n'
            "  ]\n"
            "}\n"
            "```",
        ),
    },
}

#: The shipped surfaces that seat an affordance (the ninth section,
#: ``split_join_export``, ships copy-only — inc-004 mounts its window);
#: batch-97 adds ``check_editor`` (Inc-3) and ``flow_execution`` (Inc-6).
SHIPPED_WINDOW_KEYS: Tuple[str, ...] = (
    "patch",
    "checks",
    "crc_designer",
    "reports",
    "map",
    "flow",
    "a2l",
    "workspace",
    "check_editor",
)


def section_for(window_key: str) -> Dict[str, object]:
    """Return the authored section for ``window_key`` (raises on a miss)."""
    try:
        return WINDOW_HELP_SECTIONS[window_key]
    except KeyError:
        raise ValueError(f"unknown window-help section key: {window_key!r}") from None


def section_body_text(window_key: str) -> str:
    """Render the section's numbered steps as the modal body text.

    The ``N.`` numbering is generated here (never stored) so an operator
    edit that deletes or reorders steps can never leave a gap in the
    sequence. Joined with blank paragraphs, the VariantHelpScreen voice.
    """
    section = section_for(window_key)
    steps = section["steps"]
    assert isinstance(steps, tuple)
    return "\n\n".join(
        f"{number}. {step}" for number, step in enumerate(steps, start=1)
    )


def open_window_help(app, window_key: str) -> bool:
    """Push the per-window usage-help modal (LLR-140.1's one seam).

    Args:
        app: The running ``S19TuiApp`` (anything with ``push_screen``).
        window_key: One of :data:`WINDOW_HELP_SECTIONS`.

    Returns:
        ``True`` when the modal was pushed. A key with no authored section
        pushes NOTHING (the boundary limb — a window without a section
        keeps the stock help only; a blank modal is never rendered), so
        callers that seat an affordance validate the key at construction
        (see :class:`WindowHelpChip`).
    """
    if window_key not in WINDOW_HELP_SECTIONS:
        return False
    app.push_screen(WindowHelpScreen(window_key))
    return True


class WindowHelpScreen(ModalScreen[None]):
    """Per-window "how to use this window" modal (LLR-140.1).

    Summary:
        Generalizes the shipped :class:`VariantHelpScreen` pattern from
        one fixed paragraph to the authored sections: the body
        renders the section's numbered steps through a ``markup=False``
        ``Static`` — the copy is operator-editable file-derived text, so
        no Rich/console-markup metacharacter (``**`` / backticks /
        brackets) may ever be interpreted (C-17 voice). Reuses the shared
        ``.modal-dialog`` box model. Dismissed by Close (self-handled) or
        Esc (a ``show=False`` binding, the ChangeSetJsonScreen sibling
        idiom) — the same dismissal pair the contract names.

    Data Flow:
        - ``compose`` builds a ``.modal-dialog`` with the section title,
          the ``#window_help_body`` ``Static`` seeded from
          :func:`section_body_text`, and a Close button.
        - ``on_button_pressed`` dismisses with ``None`` on Close.

    Dependencies:
        Uses:
            - ``Static`` / ``Button`` / the shared ``.modal-dialog``
              classes / :data:`WINDOW_HELP_SECTIONS`
        Used by:
            - :func:`open_window_help` (the chips, the WindowSection
              binding, and inc-004's future Split / Join / Export window)
            - tests/test_window_usage_help.py
    """

    BINDINGS = [
        Binding("escape", "close_window_help", "Close", show=False),
    ]

    def __init__(self, section_key: str) -> None:
        if section_key not in WINDOW_HELP_SECTIONS:
            raise ValueError(f"unknown window-help section key: {section_key!r}")
        super().__init__()
        #: The window key whose section this modal renders.
        self.section_key = section_key

    def compose(self) -> ComposeResult:
        section = WINDOW_HELP_SECTIONS[self.section_key]
        yield Container(
            Label(str(section["title"]), classes="modal-title"),
            Static(
                section_body_text(self.section_key),
                id="window_help_body",
                markup=False,
            ),
            Container(
                Button(
                    "Close",
                    id="window_help_close",
                    classes="modal-confirm",
                ),
                id="window_help_buttons",
                classes="modal-buttons",
            ),
            id="window_help_dialog",
            classes="modal-dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#window_help_close", Button).focus()

    def action_close_window_help(self) -> None:
        logger.info("WindowHelpScreen dismissed by escape.")
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "window_help_close":
            logger.info("WindowHelpScreen dismissed by close.")
            self.dismiss(None)


class WindowHelpChip(Button):
    """The ``?`` ghost chip that opens a window's usage-help modal.

    Args:
        window_key: One of :data:`WINDOW_HELP_SECTIONS` — validated at
            construction so an affordance can never be seated for a
            section that does not exist (the no-orphan-seat limb).

    Sits beside the window title (left side of the header row), a no-key
    control like the ``📂 Open folder`` chip — the focused-window ``?``
    binding rides :class:`WindowSection`, not this chip.
    """

    def __init__(self, window_key: str) -> None:
        if window_key not in WINDOW_HELP_SECTIONS:
            raise ValueError(f"unknown window-help section key: {window_key!r}")
        super().__init__(
            "?",
            id=f"window_help_{window_key}",
            classes="window-help-chip",
        )
        self.tooltip = "How to use this window"
        #: The window key whose section the press opens.
        self.window_key = window_key

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle this chip's own press (the message bubbles no further)."""
        if event.button is not self:
            return
        open_window_help(self.app, self.window_key)


class WindowSection(Container):
    """A rail-screen container carrying the focused-window ``?`` binding.

    Textual's binding chain walks ``focused.ancestors_with_self`` (screen,
    then app), so a ``question_mark`` binding on the rail container claims
    the key ONLY while a widget of THIS window is focused — the app-wide
    ``question_mark`` binding (stock ``HelpPanel``) stays untouched and
    fires whenever no window-focused path claims the key. ``show=False``
    keeps the chip out of the Footer and the stock HelpPanel listing.

    Args:
        window_key: One of :data:`WINDOW_HELP_SECTIONS` — the section the
            focused ``?`` opens.
    """

    BINDINGS = [
        Binding("question_mark", "show_window_usage_help", "Window help", show=False),
    ]

    def __init__(self, window_key: str, *children, **kwargs) -> None:
        if window_key not in WINDOW_HELP_SECTIONS:
            raise ValueError(f"unknown window-help section key: {window_key!r}")
        super().__init__(*children, **kwargs)
        self._window_help_key = window_key

    def action_show_window_usage_help(self) -> None:
        open_window_help(self.app, self._window_help_key)
