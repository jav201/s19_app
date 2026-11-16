# Inc 10 — E2 rulings: interpretations, extractor list, open items (2026-11-12T22:32:54-06:00, Opus 5.5)

Graph `codewire/graph-inc10.md`: 18 nodes (7 changed, 1 new, 10 context), 12 entities, 31 edges; lint `not read=0`. Extractor (`codewire/evidence-e2/i10e2-extract.sh`, transcript `…/i10e2-extract-transcript.txt`, throwaway clone at `287b9dc3`): run 1 (baseline subset, 17 marks) 3 drifts, all the PROPOSED signatures; run 2 (whole graph) the same plus the one new node without code; run 3 (layered) ruled below. Base `287b9dc3` (`b103-inc10`); the slice is rebased (`E1-slice.md` §5: no function body changed meaning). The G2 verdict is applied in `E1-rulings.md`, section "G2 verdict applied". One agent designed it: 8 module nodes change, at the ~8 threshold, so no split; E4 splits by file (G1 panel = `screens_directionb.py` + `styles.tcss`, G2 app = `app.py`).

## 1. Interpretations made at E2 (no requirement changed)

| Id | Interpretation | Why |
|---|---|---|
| E2-1 | E1's `_switch_saveback_format(self)` becomes `_set_saveback_format(self, output_format, rename)`, called by `show_save_prompt` (no rename) and by the Format press (rename). | One writer of the format, its label and the Width visibility; two writers could disagree after a new prompt (R-PE-EXPORT.7 / .9 / .10 / .11). |
| E2-2 | `show_save_prompt`'s new `output_format` and `apply_line` are keyword-only with no default (I-10.1); since E3-5 `SaveBackDecision.output_format` has no `"s19"` default either (I-10.2). | A default `"s19"` would let a caller show an Intel HEX image as S19. Cost: one test call (`tests/test_tui_patch_layout.py:594`). |
| E2-3 | The Format chip has a fixed width, that of `Format: Intel HEX`. | Its label grows 6 cells on S19 → Intel HEX; at `width: auto` it would move `Write file` / `Don't save` (R-PE-EXPORT.12 RED). E1's slice did not say. |
| E2-5 | The dock has no `patch-docked-group` class and `padding: 0`; the two rows in it get `padding: 0 1`. | R-PE-EXPORT.1's threshold compares the prompt's region with the document row's; the rows' text still starts in the document row's first chip column. |
| E2-12 | The dock has no frame and no title. | No row asks for one (O-5); a frame costs 2 rows of `#patch_main`. |
| E2-13 | `#patch_before_after_row` is one row in the dock (label and button side by side); the apply line is `height: auto` (one row at 118 columns, wraps when narrower). | Saves a row; nothing in the rows fixes either. |
| E2-14 | The save-back handler takes `event.output_format` only when both it and the loaded kind are in `("s19", "hex")`, else the loaded kind. | Keeps R-CHG-003.16's refusal for any other image and ignores a value the panel never sends (E2-8). **Replaced at E3 (E3-5, orchestrator):** no fallback — the handler takes `event.output_format` whenever the loaded kind is `s19` or `hex`, and a value outside the engine's table (`None` included) is refused by the engine (`CHG-HEX-SAVE-UNSUPPORTED`, no file); I-10.2 has no `"s19"` default. |
| E2-15 | The shared CSS rule `:3146-3152` is split: the two prompt rows get their own rule; the history strip, the execute row and the checks controls keep `padding: 0`. | Touch only the moved rows (rule 3: surgical). |
| E2-16 | D8-17's unreachable `<kind> save-back not supported` branch stays. | The orchestrator's D-6 A ruling ("left as is — not in scope"), which E1-slice #8 still offered as optional; the slice now says it stays. |

## 2. Extractor list (ruled)

| Item | Ruling |
|---|---|
| Run 1 / 2: `output_format` not a parameter of `SaveBackDecision.__init__`; `output_format`, `apply_line` not parameters of `show_save_prompt` | **expected** — they are the PROPOSED I-10.2 and I-10.1; E4 makes the code match |
| Run 2: `PatchEditorPanel._set_saveback_format` node without mark | **expected** — the one new node |
| Run 1 (first pass, fixed): constructor nodes `out: None` vs the class | **fixed in the graph** (`out: PatchEditorPanel panel`, `out: SaveBackDecision message`), the extractor's convention; the second pass has no output drift |
| Run 3: 2 nodes replaced by a later graph — `PatchEditorPanel.__init__` (batch-103 Inc 6's node) and `S19TuiApp.on_patch_editor_panel_action_requested` (batch-101 Inc 4 / 5 / 6's) | **accepted**: this graph's nodes state that every other attribute and every other arm is unchanged, so Inc 6's picker statement and batch-101's arms stand |
| Run 3: drift in earlier graphs' nodes outside this slice (`_use_highlighted_parameter`, `_apply_a2l_layout`, `_prefill_check_editor`, `CheckEditorPanel._named_parameter`, `CheckEditorPanel._on_a2l_parameter_picker_bulk_add_requested`: prose in `out:`, `none` read as an input name) | **not this increment's**: older notation in batch-101 / batch-103 Inc 6 graphs; for the batch-end extraction (dev-flow "Batch end") |
| Run 3: 28 nodes "without mark", among them this graph's 6 context nodes in `change_service.py`, `apply.py`, `verify.py` | **artefact of `--path`** (run 3 keeps only the marks of the two Python files of the slice); run 1 marks and checks them (17 of 17) |
| Run 1: call site `on_patch_editor_panel_action_requested → save_patched_image` at `variant_execution_service.py:2584` | **misattribution** (the extractor names the nearest marked node); the real caller is `_execute_one_variant` (`:2478`), as E1 read; unchanged |
| Run 1: `verify_written_image` also called by `_save_project_files`, `operations/crc.py:1524`, `run_flow` | **added** to the graph's baseline table; none changes |
| Code-Wire version | the local clone describes as `v3.1.0-8-gb6cd30d`; `b6cd30d` is the commit of the remote tag `v3.2.0` (`git ls-remote --tags origin` at E2); the tag is not fetched locally |

## 3. Open items for E3 (one reviewer, design + security lens; Inc 10 writes files outside the program)

| Id | Question | Where |
|---|---|---|
| E3-Q1 | No measurement at E2: are R-PE-EXPORT.2/4 and /8 (the A2L tab, taller since batch-103 Inc 6) met with the dock shown at 118×54 and 220×60? The derived rows (R-PE-EXPORT.1/1: document row y 38, prompt 39–41, legend 42) need the same check. A runner probe before E4, or E4's G-T1 first. | graph E2-4 |
| E3-Q2 | Below 118 × 54 the dock can sit below the fold after Apply. Should `show_save_prompt` scroll it into view? It needs a new row (R-PE-EXPORT.17 is free again). | graph E2-7 |
| E3-Q3 | A converted save into an open project makes the `.hex` (or `.s19`) file the active variant beside the source; Save project afterwards still emits the loaded format; the before/after report reads each side by its suffix. Acceptable, or does a row need to say so? | graph E2-6 |
| E3-Q4 (security) | The output format crosses panel → app and is checked against `("s19", "hex")`; the engine refuses any other kind; the suffix rewrite edits only a final `.s19` / `.hex` and the sanitizer F-S-01 still checks the written name; the destination and placement are unchanged; the apply line and the notice hold integers only. Anything missing for hostile names (control characters, reserved device names, a name that is only `.s19`)? | graph E2-8; §1 E2-14 |
| E3-Q5 | `visibility: hidden` on the Width chip: textual 8.2.8 drops it from the focus chain (R: `Widget.focusable`); is a click at its place also inert (the compositor's map)? R-PE-EXPORT.10/1 tests it; a review of the claim avoids an E4 surprise. | node `_set_saveback_format` |
| E3-Q6 | The four `conflict` cases (D8-27 / D8-28 / D8-29, D-6 A) stay untested here; confirm that no Inc 10 test asserts today's empty S0 at width 16 or terminator address 0 as correct. | graph Coverage |
| E3-Q7 | R-PE-110: the Format control, like Width, is selector state and is not refused while a session action runs (E1). Confirm. | `01-requirements.md` "Unchanged" |

## 4. Open operator items (from the G2 page; no G2 answer covers them; the E1 rows stand until the operator decides)

| Id | E1 row (kept) | Prototype px_A (Fig. 7.5 – 7.8) | Cost of switching to px_A |
|---|---|---|---|
| O-1 | apply line `Apply: 1 applied, 0 skipped, 0 blocked · changed in memory only — Write file saves it` (A′) | `✓ APPLIED  1 entry written into firmware.s19 in memory · 0 skipped · not on disk yet` (B′) | R-PE-EXPORT.4's text and 3 cases; B′ paints a file-derived name (R-PE-005 then applies) and `✓` on green, which `styles.tcss:1124-1140` reserves for verdicts in this panel |
| O-2 | Width hidden, its place kept (D-3 A, R-PE-EXPORT.12) | Width removed from the row: `Write file` moves left | drop R-PE-EXPORT.12 and 4 cases; `display` instead of `visibility` |
| O-3 | Format chip `Format: S19` / `Format: Intel HEX`, a click switches | a line `Format (●) S19 ( ) Intel HEX  alt+f switch` above the name | R-PE-EXPORT.8 / .9 cases; a key (O-4) becomes the only switch unless the line is clickable |
| O-4 | no key (E1 §8) | `alt+f`, `alt+b`, `alt+w`, `alt+n` | each key needs the Windows Terminal check (E1 §8) and R-SHELL-KEYS / R-DLG rules for shown keys |
| O-5 | no frame | round frame titled `EXPORT THE CHANGED IMAGE` | 2 rows of `#patch_main`; a new row for the title text |
| O-6 | only a final `.s19` / `.hex` is replaced | any final extension replaced | R-PE-EXPORT.14 / .15 and their 5 cases |

## 5. Overlaps

| Increment | Status at `287b9dc3` | Overlap |
|---|---|---|
| batch-101 Inc 9 / 10a / 12 | merged | none left: Inc 12's `CheckEditorPanel` hunks are disjoint (E1 §7); no dialog, key or action here (R-DLG.14, R-SHELL-KEYS.3 untouched); E1's "E4 integrates after Inc 12 merges" is met |
| batch-103 Inc 6 | merged | `PatchEditorPanel.__init__` and `compose` changed outside the save-back parts; the A2L tab is taller (E3-Q1) |
| batch-103 Inc 1b | its E4 / E5 commits are on this branch above `batch-103` (`app.py` ±14 lines, `os_clipboard_input.py`) | disjoint regions; if `batch-103` integrates Inc 1b differently, Inc 10's `app.py` lines shift and E4 re-reads them |
| batch-103 Inc 8 / Inc 9 (W2, not started) | — | they edit `PatchEditorPanel.compose` (pe-mix staging sheet): they start from I-10.4 (the dock) and keep R-PE-EXPORT.1 / R-TUI-063.1 |
| batch-103 Inc 5 | — | `app.py`, A2L refresh regions; none here |
| canon | — | CTX-SHELL *shown widget* is still not in `REQUIREMENTS.md` at `287b9dc3`; whichever fold comes first adds it (E1 §7) |

Evidence of this stage: `codewire/evidence-e2/i10e2-rebase-census.py` + transcript, `codewire/evidence-e2/i10e2-extract.sh` + transcript. No test ran (operator's PC: static reads only).

## 6. E3 correction and E4 notes (2026-11-12; rulings `E3-rulings.md`)

Graph after the E3 correction: 20 nodes (9 changed, 1 new, 10 context), 13 entities, 36 edges; lint `not read=0`. Source files: 4 (cap 4): E4 splits by file into **G1 panel** = `screens_directionb.py` + `styles.tcss`, **G2 app** = `app.py`, **G3 engine** = `changes/io.py` (E3-2). Rows added: R-PE-EXPORT.17 (E3-1), R-HEX-EMIT-001.11 (E3-2); reworded: R-PE-EXPORT.3's threshold, R-PE-EXPORT.14, .15 (E3-6). Interfaces: I-10.2 loses its `"s19"` default (E3-5); I-10.6 (the HEX emitter's output contract, signature unchanged) is new. I-10.1, I-10.3, I-10.4 and I-10.5 are unchanged.

E4 notes (addenda; each is a brief line for the named worker):

| Id | Note | For |
|---|---|---|
| E4-N1 (E3-3, orchestrator) | Measure every inspector tab with the prompt shown — Inspector, JSON, Checks **and A2L** (taller since batch-103 Inc 6) — at 118×54 and 220×60 before writing the layout assertions: R-PE-EXPORT.2/1 … /10 and R-TUI-063.1/2, /4 as the rows say, and for each tab the last control of the tab lies inside the screen or the tab's own scroll is the documented behaviour. This answers E3-Q1 (E2-4). | G-T1 tester, first |
| E4-N2 (E3-Q6, the reviewer's answer; restates D-6 A) | Check an S19 terminator by its two-character tag only (`S7`, `S8`, `S9`), never a full line such as `S70500000000FA`; never assert an empty S0 for a source that has S0 data. The four `conflict` cases stay untested. | G-T2 tester |
| E4-N3 (E3-1) | R-PE-EXPORT.3's cases re-show the prompt through I-10.1 after their entry change; AT-I10-3 now proves R-PE-EXPORT.17 then .5. Shipped tests that press `Write file` after an entry change with no new Apply now find the prompt hidden: `E1-slice.md` §6 lists the files to read. | G-T1 tester, G2 |
| E4-N4 (E3-2) | The expected HEX lines of *x64u* are data: read `data/x64u.hex`, never retype them; the negative control is the base loop (`data/x64u-base-emitter.hex`) and the cap inside the fixed `range` (bytes lost). Third-party interop (objcopy, srec_cat) is not an E4 check: E5 runs it on the runner. | G3, G-T2 tester, mutant worker |
| E4-N5 (E3-5) | A unit guard: a confirm with `output_format` `None` or `"bin"` on an S19 image writes no file and yields one `CHG-HEX-SAVE-UNSUPPORTED` issue. | G-T2 tester |

## Re-map to a95d0ea9 (relevo-8, 2026-11-13)

The file:line citations above are `287b9dc3`'s. Their `a95d0ea9` places, the census and the row changes of the re-map are in `E1-slice.md` §7 and `E1-rulings.md`, section "Re-map to a95d0ea9 (relevo-8)". Nothing above is rewritten (PP-06).
