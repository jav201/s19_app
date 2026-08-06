# Prototype — command-bar ghost inputs · A2B diff · operations binding

**Question:** (1) What are the two near-invisible inputs at the top of the main screen, and which
treatment removes/condenses them? (2) Which A2B diff redesign makes all runs reachable and uses the
full pane? (3) Can the `x` Operations binding go, given the CRC Designer?

**Prototype (runnable, sub-shape A):** [cmdbar_a2bdiff.tui_prototype.py](cmdbar_a2bdiff.tui_prototype.py)
— mounted INSIDE the real `S19TuiApp` (real chrome/rail/footer/styles.tcss); diff runs from the real
`diff_mem_maps`, windows from the real `render_hex_view_text` (incl. highlight path). No writes.
- Live: `python prototypes/cmdbar_a2bdiff.tui_prototype.py cmdbar A|B|C` · `... diff A|B|C`
  (diff A's run list is keyboard/click-live: selection re-renders the windows)
- Capture: `... shot` → `cmdbar_*.120w.svg` + `abdiff_*.132w.svg` (textual==8.2.8, this box)

**Board:** [cmdbar_a2bdiff.prototype.html](cmdbar_a2bdiff.prototype.html) — all 8 captures
(baseline + 3 variants × 2 areas) + decision tables + the operations premise check.
Verified against `origin/main` @ `061a97e`.

## Findings (code facts)

- Ghosts = `#find_input` + `#cmdbar_goto_input` (`command_bar.py:139-149`), landing widgets of
  `/`·`g` (`app.py:5980/5984`); crushed by `#command_bar_row { height: 3 }` + border
  (`styles.tcss:66-71`). Deleting them requires re-homing `/`·`g`.
- A2B diff (`screens_directionb.py`): `#diff_range_list` is a Static — only
  `_render_run_windows(0)` ever runs (runs 1..N unreachable; docstring cites a
  `on_data_table_row_selected` handler that does not exist); `DISPLAY_CONTEXT_BYTES = 16`;
  three rigid `1fr` columns wrap hex rows unreadably.
- **Measured width ceiling** (this box, textual 8.2.8): a full hex+ASCII row = 81 cells. With the
  24-col rail: diff variant A needs ≥ ~130 cols (clean at 132; ascii gutter wraps at 120 → fallback:
  12-col run list or list-as-overlay); variant B fits 120; variant C needs ~190 or an 8-byte row
  mode `render_hex_view_text` doesn't have; the SHIPPED 3-column layout wraps below ~170.
- Textual specificity trap (re-learned): `styles.tcss` id selectors beat subclass `DEFAULT_CSS` on
  the same ids — the variants needed class-scoped selectors + inline styles for the contested boxes.
- Operations premise **partly false**: CRC Designer is preview-only (US-V6 — writes only
  `*.crc.json`, never firmware; kernel wiring into the `crc` op still deferred). The modal's
  **Write CRC** is the only interactive CRC-write path; Flow Builder covers check+inject only via
  flow+config. `extract`/`split_by_segment` are placeholders — no loss.

**Recommended set:** cmdbar **A** (summon line — hex view visibly 2→5 rows at 34-row terminal) ·
diff **A** (master–detail; B strong 120-col alternate) ·
operations **2** (migrate Write CRC into the Designer, then delete modal + `x` + placeholders).

## Verdict (operator, 2026-08-06): RESOLVED

| Area | Direction chosen |
|---|---|
| Command bar | **DELETE outright** — no summon line. Operator observation (confirmed in code): the workspace/A2L/MAC screens already own local find/goto controls wired to the same handlers; the bar inputs are pure duplicates. Re-home the Ctrl+K palette, `/`·`g` (→ active screen's local inputs), and the Project/A2L labels (→ Loaded panel). |
| A2B diff | **Variant A master–detail**, with information accessibility as a first-class requirement (keyboard + mouse selection, visible focus, every run and every byte reachable; 120-col fallback). |
| Operations binding | **Staged.** The modal's CRC is a KNOWN algorithm (crc32_stream: poly 0x04C11DB7, init 0xFFFFFFFF, reverse, final_xor 0xFFFFFFFF) — reproduce it in the CRC Designer by SAVING a `.crc.json` config/template that executes it from the Designer. NO dedicated check/KAT UI in the Designer for it; the batch's full test pass is the equivalence proof. Then delete modal + `x` + placeholder ops. |

**Next:** chartered in [cmdbar_a2bdiff.HANDOFF.md](cmdbar_a2bdiff.HANDOFF.md) for a fresh /dev-flow
session (auth asked at that batch's kickoff, per standing rule); delete this prototype set once
folded in.
