# E4 implementation notes — code unit (G1 product text)

Increment 14, batch-101. Unit: `WINDOW_HELP_SECTIONS` (six rewritten sections + six Flow Builder steps, docstring and comments) and the legend constants `MAP_KEYS_LINE`, `MAP_REGION_ROW_FIELD_KEY`.

Files touched (exactly two, within the unit's ownership):

- `s19_app/tui/window_help.py`
- `s19_app/tui/legend.py`

No test file, no document, no `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl` or `tests/test_id_registry.py` was edited. No other file was touched by this unit.

## What changed per file

### `s19_app/tui/window_help.py`

- **Module docstring**: no longer calls the copy a "faithful port of `prototypes/cambios_10_12_2026/help_sections.md`"; the md is not named as the source draft, the "md fidelity census" and "code-authored beside the md port" sentences are gone. It now states every section is code-authored (batch-101 Inc 14). Also removed the stale final paragraph "The ninth section (`split_join_export`) ships NOW but its window is change 4 (inc-004)" — the Split / Join / Export window ships, so the note is false. (The change is confined to the docstring; no behaviour or layout change.)
- **Data-home comment** (the `# The data home` block above the dict): no longer says the sections are a "verbatim port of help_sections.md"; it now lists all twelve keys and states every section is code-authored with numbering re-rendered at compose time.
- **`WINDOW_HELP_SECTIONS`** — six entries rewritten whole to Help copy I14, verbatim:
  - `checks` 5 → 6 steps (R-WHELP.23, removes `**…**` and `*why*`).
  - `crc_designer` 6 steps rewritten (R-WHELP.24, `ISO-HDC` → `ISO-HDLC`, removes `**…**`, `change 1`/`change 2`).
  - `reports` 6 steps rewritten (R-WHELP.18, R-WHELP.19; step 1 kept).
  - `a2l` 4 → 5 steps (R-WHELP.20).
  - `workspace` 5 steps, steps 2/3/5 changed, 1/4 kept (R-WHELP.13).
  - `split_join_export` 7 → 8 steps (R-WHELP.21, R-WHELP.22).
  - Each of the six entries gained the comment `#: batch-101 Inc 14 (D7-26, F-30, F-37, F-41): code-authored; left the help_sections.md census.`
- **`flow` section — six steps changed** (indices 0, 4, 11, 16, 17, 18):
  - Step 1 (index 0): removed ` (LLR-003.7)`.
  - Step 5 (index 4): `CRC — picks a CRC block: it stamps CRCs from a CRC config file.`
  - Step 12 (index 11): `CRC template — the CRC config file a CRC block reads (the same format as the Operations CRC config); a template the CRC Designer saves is not a CRC config and is refused.` (R-WHELP.25, R-WHELP.26)
  - Step 17 (index 16): removed ` (R-B102-FILE-001)`.
  - Step 18 (index 17): removed ` (R-B102-FILE-002/003)` and ` (E3 ruling 1)`; collapsed the double space after the first full stop to one.
  - Step 19 (index 18): removed ` (R-B102-FILE-004..006)`.

### `s19_app/tui/legend.py`

- **`MAP_KEYS_LINE`** → `"↑↓ move · click / ↵ inspect · double-click open hex · Esc close"` (63 cells; was 71). Comment above it no longer says "verbatim from the contract" and now cites R-TUI-062.10.1 and D4-21.
- **`MAP_REGION_ROW_FIELD_KEY`** → `"glyph · start · size · size vs largest · A2L sym · band · ↵ inspect"` (67 cells; was 69, `↵ opens hex` → `↵ inspect`). Comment now notes `↵ inspect` is Enter's action today (R-LEGEND-011) and that the line changes with D4-21.

## Deviations from the graph (and why)

1. **Section comments wrapped to two lines.** The graph gives the per-entry comment as one line (`#: batch-101 Inc 14 (D7-26, F-30, F-37, F-41): code-authored; left the help_sections.md census.`). It is written as two `#:` lines so the text is unchanged while matching the file's existing comment style for the other code-authored sections. No character of the comment text differs.
2. **Docstring rewrite is broader than the single sentence.** The graph asks only that the docstring stop calling the copy a port of the md draft. The stale "ninth section (split_join_export) … its window is change 4 (inc-004)" paragraph was also dropped because it is now false (the window ships); leaving it would keep a design-note reference the increment is removing everywhere else. This is docstring text only — it is never rendered to the operator, so it does not affect any R-WHELP threshold.
3. **Legend comments extended.** The graph only requires the `MAP_KEYS_LINE` comment change; the slice lists "their comments (`:478-488`)" for both constants. A one-line note citing R-LEGEND-011 / D4-21 was added to the `MAP_REGION_ROW_FIELD_KEY` comment to mirror the keys-line note. The constant values are exact.

No deviation in any shipped text: the six rewritten sections and six Flow Builder steps equal Help copy I14 character for character; the two legend constants equal Legend copy I14.

## Verification

- `python -m py_compile s19_app/tui/window_help.py s19_app/tui/legend.py` → **success (exit 0, no output)**.
- Step counts after the change match the pinned counts (R-WHELP.7 (c)): `patch` 43, `checks` 6, `crc_designer` 6, `reports` 6, `map` 4, `flow` 59, `a2l` 5, `workspace` 5, `split_join_export` 8, `flow_execution` 35, `check_editor` 25, `changes_file_notation` 4.
- Stale-phrase census over all sections: 0 hits (`section tree`, `folders.html`, `Change 1`/`change 1`/`change 2`, the five requirement/ruling ids, `**`, `*why*`, `pre-fills from the loaded A2L`, `*.md` + `*.html`, `image's real ranges`, `jump to a name`, `browse to one`, `naming pattern`, `ISO-HDC`, `grouped by reason`, `should not be exported`).
- Both files keep their CRLF line endings (no bare CR, no LF/CRLF mix).
