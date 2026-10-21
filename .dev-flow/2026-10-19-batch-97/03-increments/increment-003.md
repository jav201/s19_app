# Increment 003 — HLR-145 (+ check arms of HLR-148 / HLR-149) · `Check Editor: ledger + REPORT FIELDS card`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md` (level `full`).
> **Where this lives:** `.dev-flow/2026-10-19-batch-97/03-increments/increment-003.md` (repo, not synced).

| Field | Value |
|---|---|
| Batch | `2026-10-19-batch-97` |
| Increment | `003` |
| Lane (if the batch forked) | `none — one lane (design-proposal §8)` |
| Requirement(s) | `HLR-145 / LLR-145.1–145.10` · check arms of `LLR-148.4, 148.5, 148.6 (check_editor key), 148.7, 148.9` · `LLR-149.1–149.6` (Check arms) |
| Acceptance | AT-B97-04, AT-B97-05, AT-B97-18, AT-B97-21 (layer B) · TC-B97-08..12, 43..46, 61 · TC-B97-30..33, 58 (check arms) · TC-B97-34..38, 59 (Check arms) |
| Agent | `software-dev` (spawned sub-agent) |
| Date | `2026-10-20` (runs finished 2026-10-21) |
| Design refs | `PDR-2026-10-19-batch-97#D6`, `#D9`, `#D10`, `#D12`, `#D16`, `#D19`, `#D21`, `#D23`, `#D25`; PC-5 / PC-8 / PC-14 / PC-19 (discharged, followed), PC-10, PC-11, PC-24 (owed here) |

---

## 1 · What changed

The Check Editor is re-composed as the approved ce_A variant: a full-height A2L PARAMETERS ledger on the left, a REPORT FIELDS card with Fields / JSON / Addendum tabs on the right, then one spec row, one docked action row and a glyph legend.

- **Ledger (LLR-145.1–145.3, D21):** `#check_param_table` is now `IncludeTable(DataTable)`, the panel's growing region. Columns `✓ · Parameter · Address · Fmt` (`Fmt · Unit` from 10 cells). The Address column is never clipped (`max_scroll_x == 0`). Names wider than the column paint first segment + `…` + tail. `#check_full_name_line` (NEW) shows the highlighted row's full name and address, or the empty-state line.
- **Width derivation (D21, PC-8, PC-19):** `check_layout(table_w, card_w, fmt_longest)` is pure. `_apply_layout` runs on mount, resize and show (`call_after_refresh`), returns at once on an equal layout, sets `Column.width` / `auto_width=False` and repaints the width-dependent cells with `update_cell` (first call `update_width=True`). It never adds a column. Measured: Parameter 42 / Fmt 6 / Fields name 24 at 118x54, 89 / 11 / 56 at 220x60 — the design numbers.
- **REPORT FIELDS card (LLR-145.6, 145.7, D19):** three `TabChip`s over one `ContentSwitcher`. Fields: one line per included field (`☑` parameter, `▪` memory row, inclusion order, tail-clipped name), the memory table, its inputs labelled `Address`, `Label`, `Size (bytes)`, `Add row` / `Remove row`, the status line and the verdicts. JSON: a real JSON document (`json.dumps`, `"apply": false`) capped by `cap_json_lines` at `JSON_TAB_LINE_CAP = 5000`. Addendum: `#check_addendum_preview`, always rendered. `#check_preview_toggle_button` stays mounted, hidden; its press opens the Addendum tab.
- **Keys and chips (LLR-145.4, 145.8, 145.9, D16):** every panel button is a one-row chip. `TabChip` binds `space` → press. `IncludeTable` binds `Binding("space", "toggle_include", "Include", show=False)`. `Write .chk.json` is the one filled element (`fill-accent`). Tab chips paint three distinct styles.
- **Header (LLR-148.4/148.5, D9, D10):** `#screen_check_editor` is a `WindowSection("check_editor")` with `titled_header("Check Editor", OpenFolderChip("checks", id_suffix="editor"), help_button=WindowHelpChip("check_editor"))`. No `Binding(` text was added to `app.py` (TC-081.4 guard: 0 lines).
- **Help (LLR-148.6, D25):** `window_help.WINDOW_HELP_SECTIONS["check_editor"]` — one `label — effect` line per label, key and glyph (hand-typed key lines until Inc-8, D27). `SHIPPED_WINDOW_KEYS` gains `check_editor`.
- **Glyphs and legend (LLR-148.7, D6, D7):** `CHECK_GLYPHS = {"✓": included, "☑": parameter field, "▪": memory-row field}`; `#check_legend` is generated from it.
- **Region states (LLR-148.9):** no A2L → one line under the ledger; nothing included → one line on the Fields tab; a refused Write → the app calls the new `CheckEditorPanel.show_status_line("Write refused: MF-WRITE-CONTAINMENT.")`.
- **CSS (D23):** one scoped section `/* batch-97 check_editor */` at the end of `styles.tcss`. It uses only existing tokens and already-claimed hexes; no `.patch-chip` selector.
- **Carry F3/F4 (check part):** the stale `📂 Open folder` docstring at `app.py:2281` (Checks screen) now says `📂 Open checks/`. The others (`app.py:2458, 3028`; `window_help.py:5, 410`; help bodies `:78, :117, :136`) are Patch / CRC / Reports / generic → **left to Inc-4**.

### 1b · Gate fold (2026-10-21) — the gate review and the three operator decisions

Same four source files; no fifth. Each line names the finding, what changed and where it is pinned.

| Finding | What changed | Pinned by |
|---|---|---|
| **Operator 1 — glyph** (LED-…97.12) | `CHECK_GLYPHS` `☑` → `◆` (green) = parameter field; `▪` cyan stays the memory-row field. Fields painter, help line and legend follow (legend generated). Re-captured in Windows Terminal: `◆ 0x00013A00` and `▪ 0x0000EB10` start their addresses in the same column; `◆ parameter field` keeps its space | `test_tc_b97_33_check_glyphs_are_narrow_in_windows_terminal` (`CHECK_GLYPHS` ⊆ `WT_NARROW_GLYPHS = ("✓", "◆", "▪")`, citing `png/impl.check-editor.png`); TC-B97-10/43, AT-B97-18/21 assert `◆`; M31 |
| **Operator 2 — 120–133 band** (LED-…97.13) | LLR-145.3 amended: Parameter ≥ 42 at 118, 119 and ≥ 134; ≥ 28 at 120–133 with painted rows distinct and the full-name line as mitigation. Rail breakpoint added to `BACKLOG-CODE.md` U-17 for the shell batch | the strict xfail became `test_tc_b97_10_parameter_floor_at_the_wide_breakpoint[119, 120, 126, 133, 134]`; M32, M44 |
| **Operator 3 — memory form / UX M2** (LED-…97.14) | three rows (Address · Label · Size (bytes)), labels in a 13-cell column, Address/Label inputs `1fr`, Size 6; spacer row before `MEMORY LOCATIONS` and before the status line. Design §3 tree amended by name. Re-measured: empty rows under the status line 14 · 13 · 20 · 19 (ce_A) and 23 · 22 · 29 · 28 (nothing included) at 118x54 · 118x53 · 220x60 · 220x59; 0 full-width blank panel rows at each (`form-measure-fold.txt`) | TC-B97-44 (form arm) and TC-B97-11 at 118x54 **and** 118x53; TC-B97-38 at 118x54/53/220x60 unchanged; M35, M36 |
| **F1 HIGH** (LED-…97.15) | `_refresh_full_name` paints the address, then the full `Fmt · Unit` (L2), then the name clipped by `clip_param` to the cells left of `CheckLayout.full_name` (NEW field, `table_w − 2`, measured equal to the line's content width at 118 and 220). `_apply_layout` repaints it (PC-19) | `test_tc_b97_10_full_name_line_keeps_address_and_name_tail` (173-cell `LONG_NAME`, 118x54 then 220x60: address whole first, exactly one `…`, ends with the tail, fills the line); M32, M33, M34, M46 |
| F2 | TC-B97-37 runs at the six LLR-149.2 sizes over `long_name_a2l` (its name clips at every size, guarded). At 120 it found that a 4-cell `Fmt` paints `u128` with no `…` (the token fills the column; documented branch of `_clip_fmt_unit`); the oracle now states that branch, the full text is on the full-name line | TC-B97-37 ×6 |
| F3 | no xfail remains in the Inc-3 modules | — |
| F4 | arithmetic reconciled: the first battery is **43 arms** (`mutations.txt` header), not 44; merged with the rerun **40 killed / 3 survived**. With the fold: **62 arms, 60 killed / 2 survived / 0 bad** (§4) | — |
| F5 | the M24 explanation was wrong: `#check_status` echoes the typed address unclipped, so the CSS no-wrap rule IS load-bearing there; M24 retargeted to a new node and killed | `test_tc_b97_37_status_line_stays_one_row_with_a_long_typed_address[118x54, 220x60]` |
| F6 | Fields memory labels keep their head (`_clip_to_cells`); `clip_tail` only for parameters | TC-B97-43 memory node; M38 |
| F7 | `if not self._visible_params: table.clear()` commented (D21 (5): the no-row pass); `border_subtitle` set only in `_refresh_preview` | — (comment / removal) |
| F8 | `clip_param` / `clip_tail` / `_clip_fmt_unit` / `_fmt_longest` measure cells (`cell_len`, `set_cell_size`, new `_tail_cells`) | `test_tc_b97_10_clips_measure_terminal_cells`; M43 |
| F9 | note for Inc-4 in §6 | — |
| F10 | `.tab-chip.chip-selected:focus` adds `underline`, so focused+selected ≠ focused-only (`chip_style` now reads underline) | TC-B97-45: 4 pairwise-distinct tab states; M42 |
| Low (TC-078.3) | comment in `test_tc078_3_both_sites`: the refused Write goes through `panel.show_status_line`, so app.py has no 4th site | — |
| **UX M1** | default label: Fields `▪ 0x0000EB10 u32 memory row` (fmt and `memory row` in DGRAY); real label `▪ <addr> u32 <label, head-kept>`; memory-table Label cell `—`. `.chk.json` unchanged (name `field @ 0x…`). TC-B97-43's parse rule (mark, address, rest) is unaffected | `test_tc_b97_43_memory_lines_name_the_address_once`; M37, M39 |
| UX L1 | `IncludeTable` binds `enter` → `toggle_include` (`show=False`, no `Binding(` in app.py); help line rewritten. Nothing in app.py consumes `RowSelected` for `#check_param_table` (read `app.py:8621-8664`) | `test_tc_b97_45_enter_on_the_ledger_toggles_inclusion`; M40 |
| UX L2 | full `Fmt · Unit` on the full-name line after the address (with F1) | F1 node; M46 |
| UX L3 | `_count()`: `1 field: 1 param · 0 memory rows`, `1 field → report` | `test_tc_b97_43_counts_agree_in_number_and_the_hint_reads_whole`; M41 |
| UX L4 | hint reads `Validate compares fields to the image` — **deviation:** the proposed `Validate compares the fields with the image.` is 44 cells and the status line is 37 at 118 (it would paint with `…`); the chosen text is exactly 37 | same node (no `…`, no ` vs `); M45 |

**For the code-reviewer re-read of F1:** `s19_app/tui/screens_directionb.py` — `CheckEditorPanel._refresh_full_name` (`:7399`), its call in `_apply_layout` (`:7474`), `CheckLayout.full_name` (`:6967`) and its value in `check_layout` (`:6998`), the cell-measured clips `_tail_cells` / `clip_param` (`:6897`, `:6907`).

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens_directionb.py` | source | HLR-145, LLR-148.7, 149.1–149.5 | `JSON_TAB_LINE_CAP`, `CHECK_GLYPHS`, `cap_json_lines`, `clip_param`, `clip_tail`, `CheckLayout`, `check_layout`, `TabChip`, `IncludeTable`; `CheckEditorPanel` re-composed (ids kept) |
| `s19_app/tui/app.py` | source | LLR-148.4, 148.5, 148.9 | Check Editor screen as `WindowSection` with both chips; Write refusal painted in the card; `:2281` docstring |
| `s19_app/tui/styles.tcss` | source | LLR-145.4, 145.9, 149.2–149.6 | one scoped Check Editor section |
| `s19_app/tui/window_help.py` | source | LLR-148.6 | `check_editor` section; `SHIPPED_WINDOW_KEYS` + `check_editor` |
| `tests/test_b97_check_editor.py` | test | HLR-145 | NEW — 36 nodes after the fold (25 at first run; the strict xfail became a 5-size pin; 7 new nodes) |
| `tests/test_b97_width.py` | test | HLR-149 | NEW — 34 nodes after the fold (TC-B97-37 ×6 sizes, status-line node ×2) |
| `tests/test_b97_chips_help.py` | test | HLR-148 | TC-B97-30 rewritten (named supersession); TC-B97-31/32/33/58 check arms added (7 nodes); fold: TC-B97-33 WT-narrow glyph arm (+1) |
| `tests/b97_fixtures.py` | fixture | HLR-145, LLR-145.5, LLR-148.9 (A.5 builders) | `DEMO_A2L`, `SIX_13A00`, `LONGEST_NAME`, `hostile_a2l`, `write_cover_s19`, `staging_block`, `open_check_editor`; fold: `LONG_NAME` (173 cells), `long_name_a2l`, shared `_renamed_a2l` |
| `tests/b97_probes.py` | fixture | LLR-149.2, LLR-149.4, LLR-149.5, LLR-145.8 (§5.1 predicates) | `painted_rows`, `painted_style`, `chip_style`, `is_displayed`, `clipped_overflow`, `displayed_descendants`, `blank_panel_rows`; fold: `chip_style` also returns `underline` |
| `tests/test_window_usage_help.py` | test | LLR-148.6 (I-4) | named supersession: `:250` set equality + `_CODE_AUTHORED_SHIPPED`; `_SEATS` + `check_editor`; seat census expects the suffixed chip |
| `tests/test_changes_file_notation_help.py` | test | LLR-148.6 (I-4) | named supersession: data-home key set + `check_editor` |
| `tests/test_open_folder_chips.py` | test | LLR-148.5 | `_RAIL_CHIPS` + the Check Editor chip; placement asserted for it |
| `tests/test_tui_check_editor.py` | test | LLR-145.3 | AT-B94-13: whole-name sentinel clause moved from the (now clipped) ledger cell to the full-name line (named supersession); fold: second named supersession — at 120x30 the line holds head `b77hostilem`, one `…` and the literal tail `_evil[red]…`; the whole sentinel stays asserted on the addendum emission and the dropdown |
| `tests/test_tui_patch_checks_strip.py` | test | LLR-148.9 (gate Low) | comment only in TC-078.3 (gate fold) |
| `tests/test_id_registry.py` | test | LLR-145.1 (D18 registry re-measure) | `EXPECTED_SCANNED_TEST_FILES` 194 → 196, measured |

| Count | Value |
|---|---|
| **SOURCE files** | **`4` / 4** |
| Test files | `11` (2 new modules, 2 helpers, 7 edits — the fold adds the TC-078.3 comment) |
| Doc / design files | fold: `01-requirements.md` (LLR-145.3, 145.6, 145.7, 148.7 ledger lines and texts), `01-requirements-ledger.md` (LED-…97.12–.15, appended), `design/design-proposal.md` (D6, §3 tree + budget, risk row), `.dev-flow/BACKLOG-CODE.md` (U-17: the rail breakpoint) |

## 3 · How to test

```bash
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1; unset NO_COLOR
python -m pytest tests/test_b97_check_editor.py tests/test_b97_width.py tests/test_b97_chips_help.py \
  tests/test_tui_check_editor.py tests/test_window_usage_help.py tests/test_changes_file_notation_help.py \
  tests/test_open_folder_chips.py tests/test_id_registry.py tests/test_tui_patch_checks_strip.py \
  tests/test_tui_patch_chips.py tests/test_tui_patch_history_strip.py tests/test_tui_snapshot.py -rA -p no:cacheprovider
python -m pytest tests/test_tui_directionb.py -q -p no:cacheprovider          # guard host
python .dev-flow/2026-10-19-batch-97/evidence/inc-3/mutate.py                 # 46 mutants / 62 arms (fold run: M1 M2 M10 M24 M29-M46)
python .dev-flow/2026-10-19-batch-97/evidence/inc-3/measure_fold.py           # Fields pane budget, 4 sizes x 2 scenarios
powershell -File prototypes/b94_polish/capture.ps1 -Scenario check-editor -RealTree -OutPng <out.png> [-Cols 220 -Rows 60]
```

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | `check_layout`, clips, cap, monotonicity, predicate self-check (5) | passed |
| **A · white-box** | `core` · `full` | the remaining TC nodes of the 3 b97 modules + superseded/census files | gate set **175 passed, 30 xfailed** (29 = the batch-94 snapshot envelope; 1 = the strict xfail of §6) — `.dev-flow/2026-10-19-batch-97/evidence/inc-3/green.txt` |
| **B · black-box** | `core` · `full` | AT-B97-04 (×2 sizes + empty arm ×2), AT-B97-05, AT-B97-18, AT-B97-21 | 7 passed (same run) |
| guard host | C-34 | `tests/test_tui_directionb.py` | **184 passed** — `.dev-flow/2026-10-19-batch-97/evidence/inc-3/guard-host.txt` |
| reverse-census run | B1 | 14 files | **188 passed** — `.dev-flow/2026-10-19-batch-97/evidence/inc-3/census-run.txt` |

PC-24 — the 118x53 arms run here: TC-B97-08 (census + docked row), TC-B97-36 (Validate / Write inside at scroll 0), TC-B97-38 height clause (0 blank rows outside the ledger), AT-B97-04 empty arm (docked row inside). All green. Slack restated from the measured tree: spec row, dock and legend 1 row each (slack 0); left chrome 5 (0); ledger 32 rows at H 40 → 31 at H 39 (the hero absorbs the row); card chrome 3 (0); Fields pane with the ce_A scenario (2 params + 4 memory rows) uses 17 of 34 rows → 17 empty at 118x54, 16 at 118x53, matching §3.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none to the source: the new tests ran on the unchanged source (HEAD `f93dadc`, `git diff --stat -- s19_app` empty, in the transcript header) |
| Transcript | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/red.txt` — **46 failed, 37 passed** of 83 nodes |
| Arms resolved at baseline | 83 collected, 83 expected |
| Verdict granularity | per node (`-rfE --tb=line`) |
| Arms that stayed GREEN (37) | 23 Inc-1 chip nodes (unchanged); 14 width nodes that are **pins** on `main` by design: TC-B97-36 ×7, TC-B97-38 height ×3, TC-B97-59 at 100x40 / 220x40, TC-B97-35 predicate self-check, TC-B97-34 hidden arm (then relative only; an absolute clause was added after mutation M4 survived — see below). Their RED is the mutation arm |

**PC-11 classification (by reading each failure line in `red.txt`):** 43 of 46 fail with `AssertionError` at the named clause (e.g. TC-B97-09 `max_scroll_x 25`, TC-B97-08 docked rows y 23 / 26, TC-B97-11 heights 3, TC-B97-61 toggle displayed, TC-B97-59 `(80, 24)` Validate outside the panel after `tab` — a real RED on `main`, not only a pin). Three fail at a `need()` presence assertion of a NEW id: TC-B97-08 tab arm (`#check_card_switcher` — the main-observable "no tab chip"), TC-B97-12 and AT-B97-05 (`#check_fields_lines`). Those are AssertionErrors, not `NoMatches`, but the two hostile rows' contracted RED is the mutation arm (M7, killed). 0 `ImportError`, 0 `NoMatches`, 0 collection errors. Three earlier RED drafts were discarded because they failed at a `NoMatches` or before the named clause; the tests were reordered and the run repeated. `red.txt` is the final run.

| Field | Value |
|---|---|
| **RED counterfactual** | 46 of 83 nodes RED at their named assertion on the unchanged source; `.dev-flow/2026-10-19-batch-97/evidence/inc-3/red.txt` (sha256 `3f98df8d…476051`) |

| Field | Value |
|---|---|
| **Mutation verdicts** | `mutations.txt` + `mutations-rerun.txt`: 30 mutants, **43 arms** (corrected at the gate, F4 — the first packet said 44), every restore proven by sha256. **40 KILLED / 3 SURVIVED-explained / 0 BAD.** After the gate fold: 62 arms, 60 / 2 / 0 (§4c). Killed: head-keeping clip, tail-only clip, 40-cell floor, `refresh(layout=True)` repaint (PC-8's vacuous path), card from the unfiltered list, `Text.from_markup` on the ledger, a second filled button, `space` dropped from `TabChip` and from `IncludeTable`, `can_focus=False` on `TabChip`, toggle displayed, a control dropped from the test's table, chip without `id_suffix`, help line without ` — effect`, glyph `✔` outside the vocabulary, Write refusal not painted (×2), empty lines removed (×3), spec-row margin (×2), columns fixed past the panel (×2), panel `overflow-y: hidden`, Fields name field too wide, predicate counting the region (instrument), Address pushed out, JSON cap removed, dock on two rows, `Size (bytes)` → `Fmt` (×2), 3-row buttons. Two oracles were fixed after the first battery: TC-B97-37 imported `clip_param` (an oracle sharing the implementation — M1 survived; now restated in the test, killed in the rerun) and TC-B97-34's hidden arm was relative only (M4 survived; an absolute clause was added, killed). **Explained survivors:** (1) M1 vs AT-B97-04 — at 42 cells a head clip still leaves the 75 cells distinct; the clip class is TC-B97-10/37's. (2) M5 (no `on_show`) — Textual sends `Resize` when a hidden panel is laid out again, so `on_resize` re-derives; `on_show` is D21's belt-and-braces trigger. (3) M24 (`text-wrap` removed) — **this explanation was wrong (F5):** `#check_status` echoes a typed address unclipped, so the CSS is load-bearing there; the arm targeted TC-B97-37, which never read `#check_status`. Retargeted at the fold and killed (§4c) |

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `tests/test_b97_*.py` (Inc-3 nodes) | unchanged base source | 46 failed (`red.txt`) |
| `b97_probes.clipped_overflow` | a non-scrolling `Horizontal` of six 21-cell cards in an 80-cell panel | ≥ 3 offenders (self-check node); M25 (no intersection) → the `HorizontalScroll` arm RED |
| `snapshot_cells.py` (PC-10) | the same tree twice with a style hash | 3 cells differed between two runs of one tree, so that hash was dropped for the text-frame diff below |
| `mutate.py` | 30 one-edit mutants | per-arm RED lines; asserts each anchor occurs once and the edit applied |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown failing on a known-bad input before its first PASS was believed |

### PC-10 — per-cell C-22 prediction (29 snapshot cells)

**Prediction:** 0 of 29 cells drift from Inc-3. No cell shows the Check Editor (screens workspace, a2l, mac, issues ×24; map ×2, patch ×2, diff ×1). The rail chrome is unchanged, and `space Include` is `show=False`, so the Footer is unchanged. **Verified:** the 29 cells were rendered on a HEAD worktree and on the Inc-3 tree (`snapshot_cells.py`, `cells-head.txt` / `cells-inc3.txt`). The text-frame diff (`cells-diff.txt`) has 3 differing cells (`workspace-compact-120x30`, `a2l-comfortable-120x30`, `issues-compact-160x40`). All three differ only in whether the async A2L load had finished (`snap.a2l` vs `(none)`), and the difference runs in both directions. No Check Editor content and no geometry change. All 29 stay inside the batch-94 `xfail(strict=False)` envelope (green run: 29 xfailed).

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | AT-B97-18 / AT-B97-21 `json.loads` the written `.chk.json` and compare its addresses with the included fields / the JSON tab. The image is `write_cover_s19` (see §6: `prg.s19` covers none of the A2L addresses) |

### Evidence files

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED transcript | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/red.txt` | `3f98df8d14fcfde47b60b56a8ef0dfb9ae7ae12b63921365815ab4a369476051` |
| GREEN transcript (gate set) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/green.txt` | `784e0aa10de678faf94a30598f707e6954cb2f27a9c31eca0b304a913a7dc50f` |
| Guard host | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/guard-host.txt` | `ac58b7a9bcc3332e51a9dcf63a1224c351e4ea2c316f0b7efe1cf9ff5c15c826` |
| Reverse-census greps | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/census.txt` | `1a568a3ea2ea8cb9db942d220cdce5e92939a390e549b232715f2e7c30e312b9` |
| Reverse-census run | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/census-run.txt` | `9df9b0d694f39012ad89aabdaf64caf555b96a62ec5c763d6526c2a5e4995008` |
| Mutation battery | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/mutations.txt` | `fe50dd545a99f0dbfdca84d4ba2d4ff965bfa334e867bde5a4a58ae79426754c` |
| Mutation rerun (M1, M4, M5 after the oracle fixes) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/mutations-rerun.txt` | `f0eed50dacfbb72c03c95e63232619c1d0150fad88af0374fc0879f936048a03` |
| Full suite, fold tree (orchestrator) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/full-suite-fold.txt` | `f46c37f6fd1f25ff1bb3789f4d93861af1961830dd662f779c18b4900b40cc59` |
| Non-baseline isolation re-runs (orchestrator) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/rerun-nonbaseline.txt` | `7fef78f58f21a575efcba3796d82e2b3cd05ffb93965eb20bf0327477a4d0e51` |
| Mutation script (first run `83284d7f…4fbccb`; extended in place at the fold — the digest is the current file) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/mutate.py` | `d5857b58af4ccc5639719c5cdc6aa04ba6b6d7400e025321a18fe5945d1483ae` |
| Snapshot-cell renderer | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/snapshot_cells.py` | `32e690ba9bff890251da19799124c2bc41bb3559e97dc184388d5957fa418dcb` |
| Cells on HEAD / Inc-3 / diff | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/cells-head.txt` · `cells-inc3.txt` · `cells-diff.txt` | `05cb41cb…e755c9` · `f94b31b7…40be12` · `76fddacc…35cb086` |
| Capture 118x54 (first run, kept as copy) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/png/impl.check-editor.pre-fold.png` | `3c7fd2f1d97b4d0520ea0670bb494802f475a60d61b01f38978bafff3395b97f` |
| Capture 118x53 (first run, kept as copy) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/png/impl.check-editor.118x53.pre-fold.png` | `7397124c70cbc0e1a23ff8fcfe78adb417dfc141998830771d9bb6baa16b4206` |
| Capture 220x60 (first run, kept as copy) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/png/impl.check-editor.220.pre-fold.png` | `03519a780164cd4f85ab593966fe2d91cc808b3728de5f3ce3aa207b58a04e17` |

| Field | Value |
|---|---|
| **Evidence files** | 15 artifacts under `.dev-flow/2026-10-19-batch-97/evidence/inc-3/`, each with its SHA-256 in the table above |

Final source digests (first 16): `screens_directionb.py 3b15dd65bace9c43`, `app.py 25e8477984f2fdad`, `styles.tcss 5ad3a1f2a703e12f`, `window_help.py 85975fda11f2e5c8`. Each restore line in `mutations*.txt` shows the same digest before and after the mutant.

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | yes: 0 overflowing descendants (TC-B97-35), 0 blank rows outside the ledger (TC-B97-38), 0 equal Parameter cells, 0 apply actions, 0 snapshot cells drifting, no `Binding(` in `app.py`, no test outside the census reaching a changed id |
| What made the search wide enough | every displayed descendant of the panel (guard ≥ 10); full-width painted panel rows; all 75 painted rows read by scrolling; the 29 cells rendered on both trees; `git grep` over `tests/` and `s19_app/` |
| Positive control | predicate self-check (non-scrolling cards counted); `blank_panel_rows` killed by M20; the snapshot diff's one difference class (load race) shows the instrument sees changes |

### Reverse census — trigger family B, and A3

| Probe | Result |
|---|---|
| B1a ids reached from other tests | `test_tui_check_editor.py`, `test_tui_check_chain_b94.py`, `test_tui_directionb.py`, `test_tui_patch_chips.py`, `test_open_folder_chips.py` — all run, green; AT-B94-13 rewritten (sentinel to the full-name line) |
| B1b changed behaviour | **found:** `test_tui_patch_checks_strip.py::test_tc078_3_both_sites` pins exactly 3 `refresh_check_results` call sites in `app.py`. The first draft of the refusal line added a 4th, so the refusal now goes through the new `show_status_line` (no census change). Removed labels `Add memory row`, `Remove memory row`, `Memory locations`, `A2L parameters`, attribute `_preview_open`: 0 test references |
| B1c hex sweep | new literals in the diff: `#54efae`, `#969aad` only, both already claimed (`test_tc079_5c` green) |
| B1d TC-081.4 | 0 `Binding(` lines in the `app.py` diff |
| B1e chip family | 0 `.patch-chip` selectors added (one comment mention removed); Check buttons still carry the class names, so the AT-076b exemption stays observed (green) |
| B2 / B3 / A3 | no file moved; 0 snapshot baselines paint the Check Editor (control: 19 show the rail label); no source outside `screens_directionb.py` reads the panel's private state |

| Field | Value |
|---|---|
| **Reverse census** | B1a 5 files green (1 rewrite); B1b 1 pinned census respected by design change; B1c/B1d/B1e clean; B2–B3, A3 none; run 188 passed |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | F3/F4 stale `📂 Open folder` prose: 8 sites (A.1 list from Inc-1). 1 corrected here (`app.py:2281`, check-related). 7 routed to Inc-4, enumerated in §1 |

### Signed-balance test ledger

`post = base − deleted + added` over the gate files: 0 nodes deleted; added 25 + 28 + 7 = 60 Inc-3 nodes, plus 1 `_SEATS` parametrization × 2 TC-706 tests = 2 extra nodes in `test_window_usage_help.py`. 5 assertions rewritten in place (TC-B97-30, TC-706 seat census, `:250`, TC-1802 key set, AT-B94-13 sentinel).

### 4c · Gate fold runs (2026-10-21)

| Run | Result | Evidence |
|---|---|---|
| RED, new/changed arms on the pre-fold source (tests edited, `s19_app/` untouched) | **21 failed, 9 passed** of 30; each failure at its named clause (`☑` in the vocabulary; 5-tuple layout; `cell_len` 19 > 12; `☑` marks; name before the address on the full-name line at all five band sizes; `field @ 0x00000100`; `1 fields: 1 params`; `one row per field: [10, 11, 11]`; 3 tab states equal; `enter` 0 → 0; and TC-B97-37 at 120 → `u128 hours` / `u128`, the F2 finding). The 9 GREEN are pins: TC-B97-11 ×2, the status-line node ×2 (its RED is M24), TC-B97-37 at 5 sizes | `red-fold.txt` |
| GREEN gate set (the 12 files of §3) | **193 passed, 29 xfailed, 1 failed — the failure is test_tui_patch_history_strip.py::test_tc081_1_derived (Patch Editor undo depths, a module the fold does not touch; it ran while the WT captures loaded the host); isolated it passes 3/3 and its whole file 8/8 (tc081-1-rerun-fold.txt), and it passed in the first-run green.txt. Recorded as a load-sensitive flake for the orchestrator's full run, not claimed fixed** | `green-fold.txt` |
| Guard host `tests/test_tui_directionb.py` | **184 passed** | `guard-host-fold.txt` |
| Mutation fold run (31 arms) | **30 killed, 1 survived (M1 vs AT-B97-04, explained in §4), 0 bad**; every restore proven by sha256 | `mutations-fold.txt` |
| Pane budget re-measure | §1b operator 3 row | `form-measure-fold.txt`, `measure_fold.py` |
| Real WT captures | `◆` one cell (addresses aligned with `▪`, legend spaced); three rows of the memory form; dock and legend inside at 118x53 | `png/impl.check-editor*.png` (pre-fold copies kept as `*.pre-fold.png`) |

**Mutation totals after the fold (F4):** 62 arms. Old set 43 arms: 41 killed (M24 now killed by its retarget) / 2 survived (M1 vs AT-B97-04; M5 `on_show`, both explained above). New arms M31–M46: 19 / 19 killed. **60 killed / 2 survived / 0 bad.**

**Signed balance (fold):** 0 nodes deleted; the strict xfail node was re-parametrized into 5 pin nodes (−1 xfail, +5); added +7 in `test_b97_check_editor.py` (clips-cells, full-name, memory, counts, enter, TC-B97-11 118x53, TC-B97-44 118x53), +6 in `test_b97_width.py`, +1 in `test_b97_chips_help.py`. Assertions rewritten in place: `☑` → `◆` (6 sites), 5-tuple → 6-tuple layout (2), `1 fields` → `1 field ` (2), TC-B97-45 tab states 3 → 4, TC-B97-37 `Fmt` oracle (the 4-cell branch), AT-B94-13 full-name clause (named).

| Fold evidence | Path | SHA-256 |
|---|---|---|
| RED (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/red-fold.txt` | `efe1f447d18d6f13ee6e374b1c6ea5b16dc567121e86237936d0e2ce0fc0009e` |
| GREEN gate set (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/green-fold.txt` | `fa135113d9d4c67dd0a8d98cc39d2be40855b46ff57b266732fdc6dd98a9eb12` |
| TC-081.1 isolation re-runs | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/tc081-1-rerun-fold.txt` | `81906f721019dfa86af0f0ddcdb099772441d61ca0123c4def473b5d9d6a1c9d` |
| Guard host (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/guard-host-fold.txt` | `78f3909805ae96134870ff0aa2eb588fc3180872499a96029b84074ef1429605` |
| Mutation fold run | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/mutations-fold.txt` | `63203bc788b2463619c27655a253edc2cff9845dd78a95bb90e66993310a8355` |
| Mutation script (46 mutants) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/mutate.py` | `d5857b58af4ccc5639719c5cdc6aa04ba6b6d7400e025321a18fe5945d1483ae` |
| Pane budget | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/form-measure-fold.txt` · `.dev-flow/2026-10-19-batch-97/evidence/inc-3/measure_fold.py` | `3f420664978803422662717a1920ab4c22b012f5cbc361f6bdd5c2d6ba9f1eea` · `259cccacab9b52709945fe5d7722e169628e50a525bdf93ad1e239fa72619c47` |
| Capture 118x54 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/png/impl.check-editor.png` | `209bb6a1ffec81dea5f5d2e3888d4d75137016ea787a91d98b90696dbd1764ce` |
| Capture 118x53 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/png/impl.check-editor.118x53.png` | `e4247f6ab0a0281af23c4fffc3a736a909e42875e88fb7b41d813a9e779e0be2` |
| Capture 220x60 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/png/impl.check-editor.220.png` | `96cd8c56609e59fce14497552eeabcbb477d5103cf45eae9762918034ee9c9ab` |

Fold source digests (first 16): `screens_directionb.py 742023836bd51ff9`, `app.py 25e8477984f2fdad` (unchanged), `styles.tcss 679048f825bdfa5a`, `window_help.py 8773ae3aba325c11`. The first-run evidence rows above are kept as history; the three capture rows above now point at the fold re-captures (first-run copies: `*.pre-fold.png`, same digests as listed).

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a named agent (agents/code-reviewer.md) · OK to advance (round 1 BLOCK-UNTIL F1 HIGH: the full-name line lost the address and the name tail; fold re-read by the same reviewer at `screens_directionb.py:7399-7427`, node `test_tc_b97_10_full_name_line_keeps_address_and_name_tail` green, M32/M33/M34 KILLED; F2–F10 folded; 2 LOW open: `◆` is East-Asian Ambiguous width — narrow in WT western locale only, noted for LED-.12; a very long unit can squeeze the full-name tail — the address stays safe). ux-reviewer — spawned as a named agent (agents/ux-reviewer.md) · approve with conditions (H1 `☑` double-width in WT → operator chose `◆`, LED-.12, re-captured narrow; M1 default label repeats the address → `u32 memory row` / `—`; M2 cramped memory form → operator chose fix now, LED-.14; L1–L4 folded, L4 text shortened to fit 37 cells); conditions discharged by the fold, verified in the re-captured PNGs by the orchestrator. Operator decisions asked at the gate 2026-10-21: glyph `◆`, 120–133 degraded band (LED-.13), memory form now |

## 5 · Risks

- **`☑` double width — closed at the gate:** the operator chose `◆` (LED-…97.12); the WT re-capture shows it one cell. The headless suite still cannot see a wide glyph; the WT-narrow list in TC-B97-33 is the guard, and a new glyph needs a real capture before it joins that list.
- **120–133 columns degraded by decision (LED-…97.13):** Parameter 28–41 cells, clipped twins told apart by the address and the full-name line; the `Fmt` column is 4 cells there, so `u128 hours` paints `u128` (no `…`). Closed only by the shell batch (U-17).
- **AT-B94-13 (batch-94) superseded a second time** (named in the test): at 120x30 the full-name line no longer holds the whole hostile sentinel; it is still asserted whole on the dropdown and the addendum emission.
- **`enter` on the ledger now toggles inclusion** instead of DataTable's row-select; no consumer of `RowSelected` exists for `#check_param_table` (read), but a later feature that wants row-select there must take another key.
- **`#check_param_table` stays a `DataTable` subclass** (`query(DataTable)` still matches, C-38). `_rebuild_memory_table` re-adds rows on add/remove, so the memory table's cursor returns to row 0 after each edit.
- Re-showing the Check Editor re-runs the shipped `_prefill_check_editor`, which clears the inclusions (batch-94 behaviour, not changed).

## 6 · Pending items / spec deviations

- **DECIDED at the gate (LED-…97.13, was OPEN) — LLR-145.3 floor not attainable at 120–133 columns.** The pin replaced the strict xfail; history follows. At ≥ 120 columns the shell widens the rail by 16 cells. The 42-cell card floor (Fields name ≥ 24) and the 42-cell Parameter floor then cannot both fit until 134 columns. Measured: Parameter 28 at 120 (15 equal clipped cells), 34 at 126, 41 at 133, 42 at 134. 118, 119 and ≥ 134 are fine. The design measured only 118 and 220. Encoded as the strict xfail node `test_tc_b97_10_parameter_floor_at_the_wide_breakpoint`. The fix is outside the Check Editor (the shell's rail regime) or a ledger amendment of LLR-145.3's range. Not fixed here.
- **Fixture premise:** `prg.s19` covers 0 of the demo A2L's 75 addresses (measured), so a Write of included parameters declares no entry. AT-B97-18/21 use `write_cover_s19` (an S19 image under every A2L field), not `prg.s19` as A.5 lists.
- **Visible deltas vs ce_A** (for the operator; the captures are in §4):
  - Rows not included show a blank mark instead of `·` (D6 one-meaning; `·` is a separator elsewhere).
  - Only Write is filled (LLR-145.9).
  - No margin rows (LLR-149.5).
  - The Fields head is one line (`6 fields: 2 params · 4 memory rows`), and lines carry no `1B` size column (§3 formula).
  - Fields marks are `◆` / `▪` instead of `✓` (D6, LED-…97.12; first run `☑`).
  - Memory inputs: one row per field with a label column and two spacer rows (LED-…97.14; first run: Label and `Size (bytes)` shared row 2).
  - Memory lines read `▪ <addr> u32 memory row` and the table Label `—` when no label was typed (UX M1).
  - The full-name line reads `address  Fmt · Unit  name` (F1, L2).
  - The new legend row; the WindowSection header with `?` and `📂 Open checks/`.
  - The status hint reads `Validate compares fields to the image` (37 cells; L4's proposed 44-cell wording would clip at 118).
- **Note for Inc-4 (F9):** the Check Editor's rows still carry the Patch Editor classes `patch-docked-row`, `patch-chip-entry`, `patch-chip-apply` and `patch-chip` (kept for the AT-076b exemption and the `.patch-docked-row` census). A rule Inc-4 adds or changes under those classes also restyles the Check Editor's docked rows and chips; Inc-4 should scope its rules to `#patch_editor_panel` or re-run TC-B97-08/11/36/46 and the Check captures.
- **Backlog at close:** the silent `except ValueError: size = 1` in `_add_memory_row` (D19, batch-94 validation).
- **TC-B97-32 Inc-3 parse rule:** one label per line, numbering stripped, split on the first ` — `. Inc-4..6 reuse `_check_help_lines`' shape.
- Capture harness (throwaway, untracked, outside the file count): `prototypes/b94_polish/run_real.py` gained `--real-tree` and `capture.ps1` a `-RealTree` switch (the design said `capture.ps1` "unchanged" — one switch was the least change that passes the flag to a new WT window).

## 7 · Suggested next task

The orchestrator runs the full suite node by node against the baseline (PC-12), `code-reviewer`, and a `ux-reviewer` pass on `png/impl.check-editor*.png` vs `prototypes/b94_polish/png/ce_A*.png`. The two operator items are decided and folded (§1b). Both done (§4b, gate section below). Then Inc-4 (Patch Editor), which also takes the 7 remaining F3/F4 prose sites.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files | all | ✓ | §2: 4 / 4 |
| 2 | Tests written in this same increment | all | ✓ | 60 new nodes |
| 3 | Layer 0 where the criterion applies | `core` · `full` | ✓ | 5 pure nodes |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red.txt` 46/83 RED, PC-11 classified |
| 5 | Reverse census declared | `core` · `full` | ✓ | `census.txt`, `census-run.txt` 188 passed |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | findings folded (§1b); F1 re-read owed (§4b) |
| 7 | No file from another lane touched | all | ✓ | one lane |
| 8 | Frozen interfaces untouched (or returned to trunk) | all | ✓ | I-1 consumed unchanged (`id_suffix`); I-4 membership + `check_editor`; I-9 names as D12 |
| 9 | Coverage claims verified on disk | all | ✓ | `green.txt` `-rA` |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 |
| 11 | Mutation verdicts per arm | all | ✓ | 62 arms: 60 killed / 2 explained / 0 bad (§4c; F4 corrected) |
| 12 | Instrument RED-proof | all | ✓ | §4, 4 instruments |
| 13 | Correction population | all | ✓ | F3/F4 8 sites, 1 here, 7 → Inc-4 |
| 14 | Emitted-form assertion | all | ✓ | `.chk.json` parsed (AT-18/21) |
| 15 | Independent review names somebody | all | ✓ | code-reviewer + ux-reviewer at the gate (§4b); F1 re-read owed |
| 16 | Evidence files with digests | all | ✓ | §4 |

## Gate — full suite, node by node against the baseline (orchestrator, 2026-10-21)

- **Run:** `evidence/inc-3/full-suite-fold.txt` (SHA-256 `f46c37f6fd1f25ff1bb3789f4d93861af1961830dd662f779c18b4900b40cc59`) — 11 failed, 3231 passed, 3 skipped, 32 xfailed in 1:15:13, on the fold tree (after the code-reviewer F1 re-read). An earlier pre-fold run (`full-suite.txt`) and one attempt stopped by the host for low memory at 6 % are superseded.
- **Comparison** (PC-12 command vs `evidence/baseline-pytest-51ee191.txt`):
  - not in the baseline (5): `test_tui_diff_screen.py::test_tc024_report_trigger_surfaces_paths`, `test_tui_flow_builder_b94.py::test_at_b94_17_template_save_listing_import_and_dedup`, `test_tui_patch_big.py::test_at075a_titles`, `test_tui_patch_editor_v2.py::test_at064a_refresh_rereads_edited_file_into_editor`, `::test_save_back_prompt`. Re-run in isolation (`evidence/inc-3/rerun-nonbaseline.txt`, SHA-256 `7fef78f58f21a575efcba3796d82e2b3cd05ffb93965eb20bf0327477a4d0e51`): 4 pass; `test_save_back_prompt` is intermittent — 2/3 on the Inc-3 tree and 1/3 on a clean worktree at HEAD `f93dadc` with no Inc-3 source (removed after use), failing at `test_tui_patch_editor_v2.py:630`. **Verdict: no regression; all five are the order/timing flake class already recorded at Inc-1/Inc-2.**
  - baseline nodes green in this run (4): `at057b`, `at_batch41_escape`, `at077c`, `undo_redo ac1` — recorded, not claimed as fixed.
  - counts reconciled: xfailed 32 = baseline 32 (the 29 snapshot-envelope cells + the baseline's own; the Inc-3 strict xfail became a pin, LED-.13), skipped 3 = 3, XPASS 0.
- **Routed:** the flakes (now incl. `test_save_back_prompt`, `at_b94_17`, `at075a`, `at064a`) → backlog at close (suite hygiene); the silent `except ValueError: size = 1` fallback → backlog at close.
