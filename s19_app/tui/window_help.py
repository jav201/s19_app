"""Per-window usage help — the ``?`` affordance + modal (batch-95 change 3,
HLR-140 / LLR-140.1..140.2).

Each shipped window gains a ``?`` ghost chip beside its title (left side of the
header row, never displacing the ``📂 Open <folder>/`` chip) and a focused-window
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
from dataclasses import dataclass, replace
from typing import Dict, Mapping, NamedTuple, Optional, Sequence, Tuple

from rich.cells import cell_len
from rich.style import Style
from rich.text import Text
from textual import events
from textual.actions import parse as parse_action
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, VerticalScroll
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
    #: batch-97 Inc-4 (D25, LLR-148.6): rewritten and CODE-authored like
    #: ``check_editor`` — no longer an md port, so outside TC-707's md census.
    #: One ``label — effect`` line per label, key and glyph the Patch Editor
    #: paints (TC-B97-32 parses this body). Since Inc-8 the window's keys
    #: (``WINDOW_KEYS["patch"]``) are the generated keys block (D27).
    "patch": {
        "title": "Patch Editor",
        "steps": (
            "Edit a change-set: the PATCH SCRIPT ledger on the left lists its "
            "entries; the inspector on the right shows the highlighted entry "
            "and holds the Inspector, JSON and Checks tabs. Load an S19/HEX "
            "image first (`^L`) to see the bytes an entry replaces.",
            "Inspector — shows the highlighted entry's BEFORE → AFTER bytes, "
            "the entry form and the DOCUMENT tally.",
            "JSON — shows the loaded document as read-only JSON under its "
            "stamp, and the editable paste buffer.",
            "Checks — shows the declaration faults and the check results, "
            "with Run checks.",
            "Address — the entry's start address, `0x…` hex.",
            "String — a text value, written in the document's encoding.",
            "Bytes — every token is a hex byte (1–2 digits, `0x` optional); "
            "decimals are not accepted, e.g. `DE AD BE EF`.",
            "Add — appends the entry typed in the form.",
            "Edit — replaces the entry at the typed address with the form's "
            "value.",
            "Remove — removes the entry at the typed address.",
            "Edit JSON — on the Inspector tab, edits the highlighted entry as "
            "JSON; on the JSON tab, opens the paste buffer full size. Both "
            "are off for a document loaded from a file.",
            "Parse pasted — loads the paste buffer as the document.",
            "Undo — steps the document back one edit (a pasted or typed "
            "document only).",
            "Redo — steps it forward again.",
            "Scope — cycles which variants Execute scope runs over.",
            "Execute scope — applies the document over the chosen variants.",
            "Save patched image as — the file name an applied image is "
            "written under.",
            "Width — cycles the S19 record width of that file (32 or 16 "
            "bytes per line).",
            "Write file — writes the patched image.",
            "Don't save — closes the prompt without writing.",
            "Write before/after report — writes the report of the last "
            "save.",
            "Run checks — runs a check document's entries against the loaded "
            "image; uncheckable rows name their reason.",
            "File — picks a change file in `patches/`, or takes a typed path "
            "for Load.",
            "Load — loads the typed path (a pick in the list loads at once).",
            "Refresh — re-reads the file list of `patches/`.",
            "Validate — checks the document against the loaded image.",
            "Apply loaded changes — writes the entries into the loaded image "
            "and offers to save it.",
            "Save — writes the document as a change-set file.",
            "Open patches/ — opens the folder change-set files live in: the "
            "project's, or the common `workarea\\patches\\` without a "
            "project.",
            "? — opens this help.",
            "space — on a tab chip, opens its tab.",
            "enter — presses the focused chip or button.",
            "arrow keys — move the ledger highlight, and scroll the read-only "
            "JSON view.",
            "✓ — the entry's check passed.",
            "✗ — the entry's check failed.",
            "◐ — the entry could not be checked; Checks names the reason.",
            "· — the entry has not been checked yet.",
            "-- — in the BEFORE → AFTER bytes, an address the image does not "
            "hold.",
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
            "**Open templates/** (change 2) opens exactly that template "
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
            "into the project's `reports\\` folder; **Open reports/** "
            "(change 2) opens that folder directly.",
        ),
    },
    #: batch-97 Inc-8 (operator decision at the Inc-8 gate, LED-…97.41):
    #: CODE-authored — it left the help_sections.md census. The md port named
    #: `+ -`, `, .` and `g`, none of which acts on the Memory Map; the steps
    #: now name no key, and the keys block lists the window's own (`k`).
    "map": {
        "title": "Memory Map",
        "steps": (
            "Load an image (`^L`) to see where its bytes sit in memory.",
            "The band bar maps which addresses hold data — entropy "
            "colouring separates code-like from fill-like content.",
            "The ruler gives absolute addresses; the region list names "
            "each contiguous run with its span. Double-click a region to "
            "open it in the Workspace hex view.",
            "The inspector shows the highlighted region's details.",
        ),
    },
    #: batch-97 Inc-5 (D25, LLR-148.6): rewritten code-authored — one
    #: ``label — effect`` line per chip, field, key and glyph the Flow Builder
    #: paints; it left the ``help_sections.md`` fidelity census.
    "flow": {
        "title": "Flow Builder",
        "steps": (
            "Build a chain of blocks that runs on the loaded image: the "
            "pipeline shows each block as a card, in run order, joined by "
            "cables, and the area under Run lists each block's verdict. "
            "Flows are project-only: Save… and Load… use the project's "
            "`flows\\` folder (LLR-003.7).",
            "LOAD — picks a load block: it reads the image file named beside it.",
            "PATCH — picks a patch block: it applies a change doc to the image.",
            "CHECK — picks a check block: it verifies addresses against a "
            "check doc.",
            "CRC — picks a CRC block: it stamps a CRC from a CRC template.",
            "WRITE-OUT — picks a write-out block: it writes the image to an "
            "output file.",
            "A2B-DIFF — picks an A2B diff block: it compares two images and "
            "writes a diff report.",
            "EXT-STEP — picks an external step: a human runs a command or "
            "follows an instruction outside the app, and the run pauses "
            "there until its log and output file are confirmed in Flow "
            "Execution.",
            "image file — the image a load block reads, relative to the "
            "project.",
            "change doc — the change-set a patch block applies.",
            "check doc — the check spec a check block verifies.",
            "CRC template — the CRC configuration a CRC block stamps.",
            "output file — the file a write-out block writes, or the file an "
            "external step leaves behind (an absolute path is preferred "
            "there).",
            "gating — advisory reports a failed check; block-own-op also "
            "stops the check block's own output.",
            "image A — the first A2B input: a file name, or #n for the output "
            "of block n.",
            "image B — the second A2B input, the same way; at least one input "
            "comes from this chain.",
            "mode — Terminal: a command run outside the app; Manual: an "
            "instruction for a human.",
            "command — the exact command run outside the app (Terminal mode).",
            "instruction — what the human does (Manual mode).",
            "log — the file the external step writes as its record; required.",
            "Add — appends a block of the chosen kind built from the fields "
            "beside it; an empty required field, or one holding a NUL "
            "character, is named on the line above Run and nothing is added.",
            "copy block # — the number of the block Copy takes; empty takes "
            "the last block.",
            "Copy — copies that block to the clipboard.",
            "Paste — appends the clipboard's block to the chain, checked "
            "against this project.",
            "Variables — shows or hides the variables editor; the count is "
            "the number of variables declared.",
            "variable — a placeholder name of capitals, digits and _ (for "
            "example BOOST); a change doc writes it as ${BOOST}.",
            "value — the text the placeholder is replaced with when the chain "
            "runs.",
            "Add var — declares the variable, or replaces its value.",
            "Run — runs the chain on the loaded image; each block's verdict "
            "lands under Run, and a write-out block writes its file.",
            "Clear — empties the chain, its variables and the clipboard.",
            "Save… — saves the chain as `flows\\<name>.json` in the project.",
            "Load… — loads a saved chain; a file with an unsafe ref is refused "
            "and the current chain is kept.",
            "Open flows/ — opens the project's flows folder, where saved "
            "chains are kept.",
            "saved / unsaved — beside the flow name: whether the chain is "
            "saved to its file (unsaved in yellow).",
            "NOTICES — the run finished and some blocks reported notices.",
            "ISSUES — the run finished, but a block failed without stopping "
            "the chain.",
            "? — opens this help.",
            "enter — on a chip or a button, presses it.",
            "space — on a kind chip, picks that kind; on any other chip or "
            "button, presses it.",
            "◉ — a load block.",
            "▣ — a patch block.",
            "✓ — a check block (card and chip).",
            "⊕ — a CRC block.",
            "▼ — a write-out block.",
            "⏚ — an A2B diff block.",
            "» — an external step.",
            "≡ — a report block (only when a loaded flow carries one).",
            "─ — a cable between two blocks.",
            "▶ — the cable feeds the next block.",
            "● — a block that ran ok.",
            "◈ — a block that ran with notices.",
            "✗ — a block that failed.",
            "○ — a block that was skipped.",
            "□ — a block waiting for a human (an external step).",
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
    #: batch-97 Inc-6 (D10 / D25, LLR-148.6): CODE-authored like
    #: ``check_editor`` — one ``label — effect`` line per chip, field, key and
    #: glyph Flow Execution paints (TC-B97-32 parses this body). Since Inc-8
    #: its ``c`` key is in the generated keys block (D27).
    "flow_execution": {
        "title": "Flow Execution",
        "steps": (
            "Run saved flows as a set of lanes, one lane per chain: each lane "
            "shows its blocks as cards joined by cables, and each cable shows "
            "how the block before it ran. A lane that reaches an external "
            "step waits for a human until you confirm it. The run log under "
            "the lanes shows its newest 8 lines; the chain-set report under "
            "`reports\\` keeps every line.",
            "Import… — adds a lane from a saved flow (`flows\\<name>.json`); "
            "a flow with an unsafe ref is refused and the lanes are kept.",
            "sequential — Run runs the lanes one after another, in lane "
            "order (the default). Click a word to choose it; enter or space "
            "switches between the two.",
            "parallel — Run runs every lane at the same time; the run report "
            "records the mode.",
            "Run — runs every lane on its bound inputs and writes one "
            "chain-set report; Run and every Confirm stay disabled until the "
            "run ends.",
            "set name — the name Save Set saves the set under.",
            "Save Set — saves the lanes, their bound inputs and their last "
            "outputs as `flowsets\\<name>.json`.",
            "saved sets — the sets saved in this project; Load Set restores "
            "the one shown.",
            "Load Set — replaces the lanes with the saved set's lanes; an "
            "input whose file moved is named in its lane.",
            "image file — the image a lane's load block reads; type another "
            "file and press Bind.",
            "Bind — binds the typed image file to this lane only; the next "
            "Run reads it.",
            "Confirm — on a lane waiting for a human: you ran the external "
            "step and its log and output file exist, so the lane runs on from "
            "that step (its output file is copied into the session folder).",
            "REQUIRED — the line above the run log while a lane waits: it "
            "names the lane whose Confirm is highlighted, the one c confirms.",
            "Open session — opens the active project's folder, where a "
            "confirmed external step's output file is copied.",
            "saved / unsaved — beside the set name: whether the set is saved "
            "to its file (unsaved in yellow).",
            "? — opens this help.",
            "enter — on a chip or a button, presses it.",
            "space — on a chip or a button, presses it; on the mode switch, "
            "switches the mode.",
            "arrow keys — on the lanes area, scroll the lanes sideways and up "
            "or down.",
            "▓ — done: on a cable, the block before it ran ok; at a lane's head, "
            "the lane is done.",
            "░ — not run / skipped: the block has not run yet, or was skipped.",
            "✗ — on a cable: the block before it failed; at a lane's head: "
            "the lane failed.",
            "◇ — on a cable: the block before it finished with notices; at a "
            "lane's head: the lane finished with notices.",
            "□ — on a cable: it leads into a block waiting for a human; at a "
            "lane's head: the lane waits.",
            "▪ — owed by you before the lane can go on: the external step's "
            "log and output file, or an input whose file moved.",
            "◉ — a load block card.",
            "▣ — a patch block card.",
            "✓ — a check block card.",
            "⊕ — a CRC block card.",
            "▼ — a write-out block card.",
            "⏚ — an A2B diff block card.",
            "» — an external step card.",
            "≡ — a report block card.",
            "─ — a cable between two blocks.",
            "▶ — the cable feeds the next block.",
        ),
    },
    #: batch-97 Inc-3 (D10 / D25, LLR-148.6): CODE-authored like the tenth
    #: section below — not an md port, so outside TC-707's md census. One
    #: ``label — effect`` line per label, key and glyph the Check Editor
    #: paints (TC-B97-32 parses this body). Since Inc-8 its ``space`` key is in
    #: the generated keys block (D27).
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
            "the Patch Editor's paste buffer (JSON tab). The five envelope fields "
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
    "flow_execution",
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
          :func:`section_body_text` (and the generated keys block) inside the
          ``#window_help_scroll`` container, and a Close button.
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
        # batch-97 Inc-7 fix round (ux UX-F1): the body scrolls while Close
        # keeps the focus, so these keys work the moment the modal opens.
        Binding("up", "scroll_help('scroll_up')", "Scroll up", show=False),
        Binding("down", "scroll_help('scroll_down')", "Scroll down", show=False),
        Binding("pageup", "scroll_help('page_up')", "Page up", show=False),
        Binding("pagedown", "scroll_help('page_down')", "Page down", show=False),
        Binding("home", "scroll_help('scroll_home')", "Top", show=False),
        Binding("end", "scroll_help('scroll_end')", "Bottom", show=False),
    ]

    def __init__(self, section_key: str) -> None:
        if section_key not in WINDOW_HELP_SECTIONS:
            raise ValueError(f"unknown window-help section key: {section_key!r}")
        super().__init__()
        #: The window key whose section this modal renders.
        self.section_key = section_key

    def compose(self) -> ComposeResult:
        section = WINDOW_HELP_SECTIONS[self.section_key]
        body = [
            Static(
                section_body_text(self.section_key),
                id="window_help_body",
                markup=False,
            )
        ]
        keys_text = window_keys_text(self.app, self.section_key)
        if keys_text:
            body.append(Static(keys_text, id="window_help_keys", markup=False))
        yield Container(
            Label(str(section["title"]), classes="modal-title"),
            # batch-97 Inc-7: the steps and keys scroll inside the dialog, so a
            # section taller than the terminal keeps its title and Close on
            # screen and every line reachable by key.
            VerticalScroll(*body, id="window_help_scroll"),
            Container(
                Button(
                    "Close  esc",
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

    def action_scroll_help(self, action: str) -> None:
        """Run one of the help body's own scroll actions (``action_<name>``)."""
        getattr(self.query_one("#window_help_scroll", VerticalScroll), f"action_{action}")()

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
    control like the ``📂 Open <folder>/`` chip — the focused-window ``?``
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


# --------------------------------------------------------------------------- #
# batch-97 Inc-8 — the window-key table (I-10) and the two-row key bar (I-11)
# --------------------------------------------------------------------------- #
#
# One table feeds row 2 of the key bar and the help modal's keys block, so the
# two cannot drift (D27). It stores binding KEYS only: every label is the
# description of the binding the key resolves to, read when the bar mounts.
# The app is passed in at runtime — this module imports nothing from app.py.


@dataclass(frozen=True)
class KeyEntry:
    """One row-2 entry: a bound key, its state condition, its owner.

    ``owner`` is ``None`` for a key of ``S19TuiApp.BINDINGS``, else a selector
    naming the widget (inside the window, or the window itself) whose class
    bindings hold the key. ``when`` names a condition the app evaluates on
    each paint (``has_image``, ``patch_history``, ``has_variants``); a false
    condition paints the token dimmed.
    """

    key: str
    when: Optional[str] = None
    owner: Optional[str] = None


#: Row 1, in display order; Textual's command-palette token follows them.
GLOBAL_KEYS: Tuple[str, ...] = (
    "ctrl+k", "ctrl+d", "ctrl+l", "ctrl+s", "x", "question_mark", "q",
)

#: Row 2 per window, in display order. The rows of workspace, patch,
#: check_editor, flow and flow_execution are the ones the prototype round
#: rendered (frozen at the 2026-10-20 delta). The other eight are derived from
#: each action's own guard: a key belongs to a window when its action changes
#: something on that window and it is not global (PC-26; the guards' file:line
#: are held by tests/test_b97_key_bar.py, which asserts each still holds).
WINDOW_KEYS: Mapping[str, Tuple[KeyEntry, ...]] = {
    "workspace": (
        KeyEntry("slash"), KeyEntry("g"),
        KeyEntry("comma", when="has_image"), KeyEntry("period", when="has_image"),
        KeyEntry("k"), KeyEntry("p"), KeyEntry("o"), KeyEntry("r"),
        KeyEntry("U", when="has_image"),
    ),
    "a2l": (
        KeyEntry("slash"), KeyEntry("g"), KeyEntry("plus"), KeyEntry("minus"),
        KeyEntry("d"), KeyEntry("k"),
    ),
    "mac": (
        KeyEntry("slash"), KeyEntry("g"), KeyEntry("plus"), KeyEntry("minus"),
        KeyEntry("k"),
    ),
    "map": (KeyEntry("k"),),
    "issues": (KeyEntry("pagedown"), KeyEntry("pageup"), KeyEntry("k")),
    "patch": (
        KeyEntry("ctrl+z", when="patch_history"), KeyEntry("ctrl+y", when="patch_history"),
        KeyEntry("v", when="has_variants"), KeyEntry("k"),
    ),
    "check_editor": (KeyEntry("space", owner="#check_param_table"),),
    "diff": (
        KeyEntry("k"),
        KeyEntry("f", owner="#ab_diff_panel"),
        KeyEntry("escape", owner="#ab_diff_panel"),
        KeyEntry("right_square_bracket", owner="#ab_diff_panel"),
        KeyEntry("left_square_bracket", owner="#ab_diff_panel"),
    ),
    "flow": (),
    "flow_execution": (KeyEntry("c"),),
    "checks": (KeyEntry("k"),),
    "crc_designer": (),
    "split_join": tuple(
        KeyEntry(key, owner="#screen_split_join")
        for key in ("space", "a", "n", "t", "m", "g", "f", "p", "d", "e", "escape")
    ),
}

#: The rail keys row 2 offers after the window keys — only on the five windows
#: the prototype round rendered (PC-26: no go keys on the derived rows).
WINDOW_GO_KEYS: Mapping[str, Tuple[str, ...]] = {
    "workspace": (),
    "a2l": (),
    "mac": (),
    "map": (),
    "issues": (),
    "patch": ("equals_sign", "9"),
    "check_editor": ("6", "9"),
    "diff": (),
    "flow": ("right_square_bracket", "6", "equals_sign"),
    "flow_execution": ("8", "t"),
    "checks": (),
    "crc_designer": (),
    "split_join": (),
}

#: Help section -> the window whose keys block its modal shows; ``None`` shows
#: none (Reports is a modal, the notation section is copy only).
HELP_KEY_WINDOW: Mapping[str, Optional[str]] = {
    **{key: key for key in WINDOW_HELP_SECTIONS if key in WINDOW_KEYS},
    "split_join_export": "split_join",
    "reports": None,
    "changes_file_notation": None,
}

#: The action that opens a window with no rail binding (its tag reads the
#: palette entry naming that action).
_OPEN_ACTIONS: Mapping[str, str] = {"split_join": "open_split_join_export"}


@dataclass(frozen=True)
class KeyToken:
    """One painted token: the binding's key, display, label, action, owner.

    ``lead`` is painted before the token and is not clickable (the go
    separator). A ``tag`` token is the window name: never clickable. A
    disabled token paints whole in the dim colour and is not clickable.
    """

    key: str
    key_display: str
    label: str
    action: str
    owner: Optional[str] = None
    enabled: bool = True
    when: Optional[str] = None
    lead: str = ""
    tag: bool = False


class PackedRow(NamedTuple):
    """A packed key row: its text, the click ranges of its enabled tokens,
    how many tokens it dropped, and the ranges of its dimmed tokens."""

    text: Text
    hits: Tuple[Tuple[int, int, str], ...]
    dropped: int
    dimmed: Tuple[Tuple[int, int, str], ...] = ()


def _class_bindings(cls) -> list:
    bindings = []
    for klass in cls.__mro__:
        for item in klass.__dict__.get("BINDINGS", ()):
            bindings.append(item if isinstance(item, Binding) else Binding(*item))
    return bindings


def _binding_for(bindings, key: str, where: str) -> Binding:
    for binding in bindings:
        if binding.key == key:
            if not binding.description:
                raise ValueError(f"key {key!r} of {where} has an empty description")
            return binding
    raise KeyError(f"key {key!r} is not bound in {where}")


def _container_id(app, window: str) -> str:
    return app.SCREEN_CONTAINER_IDS.get(window, f"screen_{window}")


def owner_widget(app, window: str, selector: str):
    """The widget ``selector`` names: the window's container or a widget
    inside it."""
    container = app.query_one(f"#{_container_id(app, window)}")
    widget = app.query_one(selector)
    if widget is not container and container not in widget.ancestors:
        raise ValueError(f"{selector!r} is not inside window {window!r}")
    return widget


def _token(app, binding: Binding, **fields) -> KeyToken:
    return KeyToken(
        key=binding.key,
        key_display=app.get_key_display(binding),
        label=fields.pop("label", binding.description),
        action=binding.action,
        **fields,
    )


def resolve_window_tokens(app, window: str) -> Tuple[Tuple[KeyToken, ...], Tuple[KeyToken, ...]]:
    """Resolve ``window``'s entries and go keys against the live bindings.

    Raises ``KeyError`` for an unbound key and ``ValueError`` for an empty
    description, so the table can never paint a key the app lacks.
    """
    app_bindings = _class_bindings(type(app))
    tokens = []
    for entry in WINDOW_KEYS[window]:
        if entry.owner is None:
            binding = _binding_for(app_bindings, entry.key, "S19TuiApp.BINDINGS")
        else:
            widget = owner_widget(app, window, entry.owner)
            binding = _binding_for(_class_bindings(type(widget)), entry.key, entry.owner)
        tokens.append(_token(app, binding, owner=entry.owner, when=entry.when))
    go = tuple(
        _token(app, _binding_for(app_bindings, key, "S19TuiApp.BINDINGS"))
        for key in WINDOW_GO_KEYS[window]
    )
    return tuple(tokens), go


def global_tokens(app) -> Tuple[KeyToken, ...]:
    """Row 1: the global keys, then Textual's command palette (``palette``)."""
    app_bindings = _class_bindings(type(app))
    tokens = [
        _token(app, _binding_for(app_bindings, key, "S19TuiApp.BINDINGS"))
        for key in GLOBAL_KEYS
    ]
    palette = Binding(app.COMMAND_PALETTE_BINDING, "command_palette", "palette")
    tokens.append(_token(app, palette, label="palette"))
    return tuple(tokens)


def more_token(app) -> KeyToken:
    """Row 2's overflow tail: the ``?`` binding relabelled ``more``."""
    binding = _binding_for(_class_bindings(type(app)), "question_mark", "S19TuiApp.BINDINGS")
    return _token(app, binding, label="more")


def window_tag(app, window: str) -> str:
    """The window's name: the description of the binding (or palette entry)
    whose action opens it."""
    action = _OPEN_ACTIONS.get(window, f"show_screen('{window}')")
    for binding in _class_bindings(type(app)):
        if binding.action == action:
            return binding.description
    for label, entry_action in getattr(app, "EXTRA_PALETTE_ENTRIES", ()):
        if entry_action == action:
            return label
    raise KeyError(f"no binding or palette entry opens window {window!r}")


def window_keys_text(app, help_key: str) -> str:
    """The help modal's keys block for ``help_key``: one ``key — label`` line
    per entry of the window it maps to; empty when it maps to none."""
    window = HELP_KEY_WINDOW.get(help_key)
    if window is None:
        return ""
    tokens, _ = resolve_window_tokens(app, window)
    return "\n".join(f"{token.key_display} — {token.label}" for token in tokens)


def _token_text(token: KeyToken) -> str:
    if token.tag:
        return f" {token.label} "
    return f" {token.key_display} {token.label} "


def _token_width(token: KeyToken) -> int:
    return cell_len(token.lead) + cell_len(_token_text(token))


def pack_key_row(
    tokens: Sequence[KeyToken],
    width: int,
    *,
    keep: frozenset = frozenset(),
    more: Optional[KeyToken] = None,
    styles: Optional[Mapping[str, Style]] = None,
) -> PackedRow:
    """Pack whole tokens into ``width`` cells (LLR-150.5).

    When every token fits, all are painted. Otherwise the mandatory tokens
    (indexes in ``keep``) and the ``more`` tail are reserved first, then the
    longest display-order prefix of the others that fits is kept — never a
    greedy skip — and ``more`` ends the row. No token is cut.
    """
    styles = styles or {}
    plain = Style()
    widths = [_token_width(token) for token in tokens]
    if sum(widths) <= width:
        kept = set(range(len(tokens)))
    else:
        budget = width - sum(widths[i] for i in keep) - (_token_width(more) if more else 0)
        kept = set(keep)
        for index, token_width in enumerate(widths):
            if index in kept:
                continue
            if token_width > budget:
                break
            budget -= token_width
            kept.add(index)
    dropped = len(tokens) - len(kept)
    painted = [tokens[i] for i in sorted(kept)]
    if dropped and more is not None:
        painted.append(more)
    text = Text(no_wrap=True, overflow="crop", end="")
    hits, dimmed = [], []
    for token in painted:
        if token.lead:
            text.append(token.lead, styles.get("separator", plain))
        if token.tag:
            text.append(_token_text(token), styles.get("tag", plain))
            continue
        start = text.cell_len
        if token.enabled:
            text.append(f" {token.key_display}", styles.get("key", plain))
            text.append(f" {token.label} ", styles.get("description", plain))
        else:
            dim = styles.get("dim", Style(dim=True))
            text.append(f" {token.key_display} {token.label} ", dim)
        (hits if token.enabled else dimmed).append((start, text.cell_len, token.key))
    if text.cell_len > width:
        text.truncate(width)
        hits = [hit for hit in hits if hit[1] <= width]
        dimmed = [hit for hit in dimmed if hit[1] <= width]
    return PackedRow(text, tuple(hits), dropped, tuple(dimmed))


class KeyRow(Static):
    """One row of the key bar, packed from its tokens on every paint."""

    COMPONENT_CLASSES = {
        "key-bar--key",
        "key-bar--description",
        "key-bar--tag",
        "key-bar--separator",
        "key-bar--dim",
    }

    def __init__(self, row: str, **kwargs) -> None:
        super().__init__("", **kwargs)
        self._row = row
        self._packed = PackedRow(Text(), (), 0)
        self._painted: Dict[str, KeyToken] = {}

    def render(self) -> Text:
        bar = self.parent
        assert isinstance(bar, KeyBar)
        tokens, keep, more = bar.row_tokens(self._row)
        styles = {
            role: self.get_component_rich_style(f"key-bar--{role}")
            for role in ("key", "description", "tag", "separator", "dim")
        }
        self._packed = pack_key_row(tokens, self.size.width, keep=keep, more=more, styles=styles)
        self._painted = {token.key: token for token in (*tokens, *([more] if more else []))}
        return self._packed.text

    async def on_click(self, event: events.Click) -> None:
        """Run the clicked token's action in its own namespace (H-1), never
        through the focused widget, so nothing is typed or pressed there."""
        event.stop()
        for x0, x1, key in self._packed.hits:
            if x0 <= event.x < x1:
                bar = self.parent
                assert isinstance(bar, KeyBar)
                await bar.run_token(self._painted[key])
                return
        for x0, x1, _key in self._packed.dimmed:
            if x0 <= event.x < x1:
                self.app.bell()
                return


class KeyBar(Vertical):
    """The two-row key bar (HLR-150): row 1 the global keys, row 2 the active
    window's tag, keys and go keys.

    Reads the app at runtime: ``_active_screen_key`` (the active window),
    ``key_condition(when)`` (a ``when`` condition) and ``check_action`` (an
    app key answering ``False`` there is left out). An OWNED key acts only
    while the focus is inside its window (the binding sits on a widget of it)
    and its owner's ``check_action`` allows it; otherwise it paints dimmed
    (operator decision at the Inc-8 gate, LED-…97.39). Repaints on the
    screen's bindings signal — focus changes and ``app.refresh_bindings()`` —
    with no timer.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._globals: Tuple[KeyToken, ...] = ()
        self._windows: Dict[str, Tuple[Tuple[KeyToken, ...], Tuple[KeyToken, ...]]] = {}
        self._tags: Dict[str, str] = {}
        self._more: Optional[KeyToken] = None

    def compose(self) -> ComposeResult:
        yield KeyRow("global", id="key_bar_global")
        yield KeyRow("window", id="key_bar_window")

    def on_mount(self) -> None:
        self._globals = global_tokens(self.app)
        self._more = more_token(self.app)
        for window in WINDOW_KEYS:
            self._windows[window] = resolve_window_tokens(self.app, window)
            self._tags[window] = window_tag(self.app, window)
        self.screen.bindings_updated_signal.subscribe(self, self._bindings_changed)

    def on_unmount(self) -> None:
        self.screen.bindings_updated_signal.unsubscribe(self)

    def _bindings_changed(self, _screen) -> None:
        for row in self.query(KeyRow):
            row.refresh()

    def _app_check(self, token: KeyToken) -> Optional[bool]:
        _target, name, params = parse_action(token.action)
        return self.app.check_action(name, params)

    def _owner_live(self, window: str, token: KeyToken) -> bool:
        """An owned key acts only while the focus is inside its window and the
        owner's own ``check_action`` allows the action."""
        container = self.app.query_one(f"#{_container_id(self.app, window)}")
        focused = self.app.focused
        if focused is None or (focused is not container and container not in focused.ancestors):
            return False
        owner = owner_widget(self.app, window, token.owner)
        _target, name, params = parse_action(token.action)
        return owner.check_action(name, params) is True

    def row_tokens(self, row: str):
        """(tokens, mandatory indexes, overflow tail) of ``row`` right now."""
        if row == "global":
            keep = frozenset(i for i, t in enumerate(self._globals) if t.key == "question_mark")
            return list(self._globals), keep, None
        window = self.app._active_screen_key
        entries, go = self._windows[window]
        tokens = []
        for token in entries:
            if token.owner is not None:
                tokens.append(replace(token, enabled=self._owner_live(window, token)))
                continue
            allowed = self._app_check(token)
            if allowed is False:
                continue
            enabled = allowed is True and (
                token.when is None or self.app.key_condition(token.when)
            )
            tokens.append(replace(token, enabled=enabled))
        go_tokens = [token for token in go if self._app_check(token) is not False]
        if go_tokens:
            go_tokens[0] = replace(go_tokens[0], lead=" · go" if tokens else " go")
        tag = KeyToken("", "", self._tags[window], "", tag=True)
        return [tag, *tokens, *go_tokens], frozenset({0}), self._more

    async def run_token(self, token: KeyToken) -> None:
        """Run ``token``'s action: an app key through ``app.run_action``
        (which honours ``check_action``), an owned key on its owner widget."""
        if token.owner is None:
            await self.app.run_action(token.action)
        else:
            widget = owner_widget(self.app, self.app._active_screen_key, token.owner)
            await widget.run_action(token.action)
