# Increment 004 — HLR-144 (+ patch arms of HLR-148 / HLR-149) · `Patch Editor: ledger + inspector with a live JSON view`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md` (level `full`).
> **Where this lives:** `.dev-flow/2026-10-19-batch-97/03-increments/increment-004.md` (repo, not synced).

| Field | Value |
|---|---|
| Batch | `2026-10-19-batch-97` |
| Increment | `004` |
| Lane (if the batch forked) | `none — one lane (design-proposal §8)` |
| Requirement(s) | `HLR-144 / LLR-144.1–144.12` · patch arms of `LLR-148.6 (patch key, amended LED-…97.16), 148.7, 148.9` · `LLR-149.1–149.6` (Patch arms) |
| Acceptance | AT-B97-01, AT-B97-02, AT-B97-03, AT-B97-17 (layer B) · TC-B97-01..07, 39..42, 60 · TC-B97-32, 33, 58 (patch arms) · TC-B97-34..38, 59 (Patch arms) |
| Agent | `software-dev` (spawned sub-agent) |
| Date | `2026-10-21` |
| Design refs | `PDR-2026-10-19-batch-97#D1`–`#D5`, `#D12`, `#D20`, `#D21` (item 4), `#D22`, `#D23`, `#D25`; PC-1 / PC-6 / PC-9 / PC-18 / PC-21 (Inc-4 half) discharged on paper and implemented here; PC-10, PC-11, PC-24 (owed here) |

---

## 1 · What changed

The Patch Editor is re-composed as the approved pe_A layout. On the left, a full-height PATCH SCRIPT ledger. On the right, one bordered inspector with Inspector / JSON / Checks tabs over one `ContentSwitcher`. Under the two columns: one file row, one document-controls row and a glyph legend. Every one of the 66 shipped ids is kept (LLR-144.1).

- **Ledger (LLR-144.2, 144.3, D21, D22):** `#patch_doc_entries_table` is the growing region (`height: 1fr`). It shows 6 of 6 rows at 118x54 with 33 data rows (32 at 118x53). Its five columns are added once in `on_mount`. `patch_layout(ledger_w, inspector_w, status_longest, ribbon_w)` is pure. `_apply_layout` runs on mount, resize and show (`call_after_refresh`), returns at once on an equal tuple, and repaints Value / Status / Linkage with `update_cell` (first call `update_width=True`). The geometry pass `_apply_window_geometry`, its forced heights and widths and the app's show-time block are deleted.
- **Identity ribbon (LLR-144.7):** `#patch_identity_ribbon` shows `<file name> · <kind>` (`draft · change` before a save). It is a literal `Text` through `safe_text`. A long name keeps its tail behind one `…` at the ribbon width.
- **Hex strip (LLR-144.8, D5 / PC-1):** `BeforeAfterCard` moved to the top of the Inspector pane and paints the pe_A grid. The rows are aligned to `strip_bytes` (8 at 118 columns, 16 at 220). Each row is an offset header, `was` and `now`. Changed `now` bytes are `bold VALUE`; context and unchanged bytes are `DGRAY`. A summary reads `11 B @ 0x0000EC00 · 11 changed`. At most `STRIP_ROW_CAP = 8` rows are stacked, then `showing N of M bytes`. There are three state lines: no entries, no selection, no image. Builder inputs stay ints (TC-080.7 green).
- **Entry form + chips + tally (LLR-144.9, PC-6):** Address / String / Bytes each sit on one row beside their label. Add / Edit / Remove / Edit JSON sit on one row. `#patch_doc_tally` shows `DOCUMENT`, a 12-cell bar, `N entries · I inside · P partial` and `O outside · F faults`.
- **JSON tab (LLR-144.5, 144.6, D1–D4, PC-18, PC-21):** `LOADED DOCUMENT · read-only` heading, then the stamp, then `#patch_json_view` (`TextArea`, read-only, no soft wrap), then `PASTE BUFFER · editable` with the gauge, then the paste buffer, the paste / history / execute rows and the save-back / report rows while they are offered. The app builds `PatchDocumentView` in ONE helper (`_patch_document_view`, ASCII decode) and passes it at all four `refresh_entries` sites (`app.py:3278, 3468, 5314, 10780`). The panel keeps `_json_shown = (count, HH:MM:SS, json_text)`. The equal-payload rule applies: a byte-equal document leaves view, scroll and stamp untouched. A new payload reloads `cap_json_lines(json_text)` and takes its time from `_json_clock()`. The dirty trigger (`_refresh_dirty_indicator`, all four writers) recomposes the stamp. Fresh start: `No document yet: Load, paste or Add.` and `no document yet`.
- **Keys and chips (LLR-144.10, 144.11):** the tab chips are `TabChip`s (`space` and `enter`) with four distinct states. Save is the one filled element (`fill-accent`). Focus order follows the DOM: header → ledger → tabs → active tab → file row → document controls.
- **Checks tab (LLR-144.12, LLR-148.9):** the issues, the status line (`No check run yet: press Run checks.` before a run and after an undo/redo reset), the strip and the results. A refused load also shows `Refused: <finding>` as the ledger's one state line.
- **Help (LLR-148.6, D25):** `patch` is rewritten code-authored, with one `label — effect` line per label, key and glyph. The `Edit JSON` line names both tabs. **Legend (LLR-148.7):** `PATCH_GLYPHS = {✓, ✗, ◐, ·, --}` generates `#patch_legend`.
- **CSS (D23):** the E-3 pairs, the old Patch geometry rules and the `width-narrow` Patch rules are deleted. One scoped section `/* batch-97 patch_editor */` holds 0 unscoped selectors. `.patch-docked-row, .patch-docked-group` stays byte-equal (F9 guard).
- **F3/F4 carry, 7 prose sites:** `app.py` docstrings (CRC → `📂 Open templates/`, Patch → `📂 Open patches/`); `window_help.py` module and class docstrings (`📂 Open <folder>/`); the `patch` body (rewritten, `Open patches/ — …`), CRC Designer (`**Open templates/**`) and Reports (`**Open reports/**`). Plus one more stale term found by the census: the changes-file-notation body said "JSON EDIT pane" and now says "paste buffer (JSON tab)".

### 1b · Gate fold (2026-10-21) — the gate review and the three operator decisions

Same four source files; no fifth; no `Binding(` in `app.py`. Each line names the finding, what changed and where it is pinned. Operator decisions were asked at the Inc-4 gate on 2026-10-21 and relayed by the orchestrator; each that changes a requirement or design text has a ledger entry.

| Finding | What changed | Pinned by |
|---|---|---|
| **Operator 1 — strip colour** (LED-…97.18) | Changed `now` bytes and a non-zero `N changed` count paint **`bold #56e0d6`** (PATCH teal, new constant `PATCH_TEAL` in `screens_directionb.py` — no existing token held that hex: none in `insight_style.py`, `styles.tcss` or `_CLAIMED_HUES`). `was` bytes stay `VALUE`; unchanged / context bytes and `0 changed` stay `DGRAY`. The teal joins the hue census (`_CLAIMED_HUES`); MAGENTA's optimality test still passes. Design D5 (e) amended | `test_tc_b97_39_changed_bytes_and_count_paint_teal` (layer 0: spans, hue ≤ 4° of the teal, bold); `test_tc_b97_39_strip_follows_the_highlight` reads each painted `now` byte's colour (hue distance, never hex equality — PC-7); `test_tc079_5c` (census); M40, M41 |
| **Operator 2 — memory-entry form** (LED-…97.19) | One spacer row between Address / String / Bytes (`.pe-row { margin-bottom: 1 }`, the last row 0; `#patch_doc_entry_inputs` height 3 → 5); the three inputs paint `$rule` (#1b233a), lighter than the pane's `$bg-base` (the theme's #1e1e1e before). Re-measured empty rows at the pane foot (§3 scenario): **13 · 12 · 22 · 21** (were 15 · 14 · 24 · 23). With the strip at its cap + note (64 B at `0xEB14`), the Add / Edit / Remove chips sit **2 rows below the fold at 118x53, 1 at 118x54**, reached by `tab` and by scrolling the pane (the accepted cost). Design §3 tree, budget and D5 rationale amended | `test_tc_b97_40_labelled_form_and_chips_in_the_inspector[118x54, 118x53]` (rows 2 apart; input bg == `$rule`, lighter than the pane); `test_tc_b97_40_capped_strip_chips_reachable[118x54, 118x53]` (8 rows, exactly 1 / 2 rows below, reachable by tab and scroll); TC-B97-38 height clause green at 118x54 / 118x53 / 220x60; M45, M46, M49 |
| **Operator 3 — help draft** (LED-…97.20) | `crc_designer` and `reports` leave `_EXPECTED_KEYS` (`tests/test_window_usage_help.py`) and `_MD_AUTHORED_KEYS` (`tests/test_changes_file_notation_help.py`) and join `_CODE_AUTHORED_SHIPPED`; the shipped step 6 keeps `Open templates/` / `Open reports/`. The draft's two step-6 lines are restored to the operator's text, byte-equal to HEAD `98f3c84`'s `window_help.py` (`help-draft-restore.diff`, 2 lines, nothing else touched). D25 amended by name | TC-707 / TC-1802 green on the fold key sets; the pre-fold key sets against the restored draft fail at `crc_designer` (`red-fold.txt`) |
| **ux H1 (HIGH)** (LED-…97.21) | Parse pasted now ends in `panel.mark_pasted()` (NEW, sets the dirty flag) instead of `mark_loaded()`: the stamp reads `unsaved changes` beside the ribbon's `draft`, and a Load afterwards raises the dirty-load guard. LLR-144.6 amended | `test_tc_b97_06_paste_parse_marks_the_document_unsaved` (ribbon `draft`, stamp `unsaved changes`, flag set, guard on Load); the paste arm of `test_tc_b97_06_every_writer_refreshes_the_view_at_once` (named supersession `saved` → `unsaved changes`); RED first; M42 |
| ux Obs 5 | `#patch_paste_heading` reads `PASTE BUFFER · example` while the buffer equals `DUMMY_CHANGESET_TEXT`, `PASTE BUFFER · editable` after the first edit (same pass as the gauge). Fits whole with the gauge in the 41-cell pane at 118 (`PASTE BUFFER · example      0.3K / 64.0K`, WT capture) | `test_tc_b97_05_paste_heading_names_the_example`; M43, M48 |
| ux 4a | `#patch_json_view` / `#patch_paste_text`: scrollbar thumb `#969aad` (DGRAY) at 40 % / 70 % hover / 100 % active on `$bg-panel`; the view keeps `soft_wrap=False` (horizontal scroll), the paste buffer its shipped soft wrap | `test_tc_b97_05_text_area_scrollbars_are_muted`; M44 |
| ux backlog items | 4 items routed to `.dev-flow/BACKLOG-CODE.md` (batch-97 section): duplicated Scope / Execute wording (LLR-075.3), clipped File placeholder (LLR-065.1/065.2), `^s` Save Project vs the `Save` chip (note for Inc-8's key bar), `escape` not closing the Save Project modal in Pilot | — |
| code F1 | = operator decision 3 | — |
| code F2 | Deleted the dead / duplicate unscoped rules `#patch_variant_row, #patch_execute_row` and `#patch_variant_select_row` (no `patch_variant_*` id exists; `#patch_execute_row` exists and keeps its `height: auto` in the scoped section, its width is the Container's `1fr`); moved `#patch_doc_issues, #patch_checks_results` into the section as `#patch_editor_panel #…`. `.patch-section-title` / `.patch-field-label` stay (the Check Editor uses `.patch-field-label`, `screens_directionb.py` Check compose). Check Editor frame at 118x54 / 220x60 **identical** to `98f3c84` (`check-frames-diff-fold.txt` empty) | `test_tc_b97_04_no_unscoped_patch_rule_in_the_whole_stylesheet` (whole file, allow-list: the docked-row pair + the two shared label classes); M47 |
| code L1 | TC-B97-58 `ledger_empty` / `json_no_document` compare the painted line with the literals `"No entries yet: Add one, paste a change-set or Load a file."` / `"No document yet: Load, paste or Add."` | M34 now **KILLED** directly (`mutations-fold.txt`) |
| code L4 | one mutation total everywhere (§3, §4, checklist): see §4 | — |

### 1c · Operator decisions (asked 2026-10-21, at the Inc-4 opening) and visible deltas vs pe_A

| Decision | Answer (operator, 2026-10-21) | Where |
|---|---|---|
| Long entries in the hex strip | **8 stacked rows + a `showing N of M bytes` note line**; the whole entry is in the JSON tab | `STRIP_ROW_CAP = 8`; TC-B97-39 builder node, TC-080.6 (64-byte run → 8 rows + note + summary) |
| The three pe_A hints | **removed** | see the visible deltas below |

No ledger entry: no requirement text changes (LLR-144.8 says nothing about a cap; the hints are not contracted).

**Visible deltas vs `prototypes/b94_polish/png/pe_A*.png`** (compare with `png/impl.patch-editor*.png`):
1. Removed: the Inspector hint `Add writes the typed entry · Edit loads…`. It would wrap at 40 cells, and the help has `Add — …` and `Edit — …`.
2. Removed: the foot hint `JSON / Checks → tabs in the inspector`. The tab chips are on screen.
3. Removed: the row identity line `#3 string 0xEC00 · inside · check: …`. The strip paints ints only (TC-080.7), and the highlighted ledger row shows kind and status.
4. Added: the identity ribbon (`calib_hotfix.json · change`) above the two columns (D12, LLR-144.7).
5. Changed `now` bytes and the `N changed` count are bold teal `#56e0d6`, as in pe_A (gate fold, LED-…97.18; the first run painted them bold white). The strip's border-top row carries its `BEFORE → AFTER` title.
6. The ledger's Value column is 22 cells at 118 columns, so the 8-byte `A5` run paints `A5 A5 A5 A5 A5 A5 A5 …` (one cell short; the scrollbar gutter is reserved). At 220 it is whole.
7. Only Save is filled (LLR-144.11). The legend row is new (LLR-148.7). No margin rows outside the inspector; the form's three inputs have one spacer row between them and a `$rule` background (gate fold, LED-…97.19; first run: consecutive rows).
8. The JSON tab (no pe_A capture of it): two headed text areas. The read-only view paints a 1-row horizontal scrollbar band at the foot, in muted DGRAY since the fold. The paste heading reads `PASTE BUFFER · example` until the first edit.

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens_directionb.py` | source | HLR-144, LLR-144.1–144.12, LLR-148.7, 148.9, 149.1–149.6 | `PatchEditorPanel` re-composed (ids kept); `before_after_card_text` grid + `BeforeAfterCard`; `PATCH_GLYPHS`, `PatchDocumentView`, `_json_clock`, `json_stamp_text`, `PatchLayout`, `patch_layout`, `STRIP_ROW_CAP`, `STRIP_ROW_BYTES`, `CARD_NO_ENTRIES`; `_apply_window_geometry` deleted. **Fold:** `PATCH_TEAL` + strip styles; paste heading `example` / `editable`; `mark_pasted()` |
| `s19_app/tui/app.py` | source | LLR-144.3, 144.5, 144.6, 148.10 | `_patch_document_view()`; `document=` at the 4 `refresh_entries` sites; show-time geometry block deleted; 2 docstrings (F3/F4); 0 `Binding(` lines. **Fold:** `parse_paste` → `mark_pasted()` (H1) |
| `s19_app/tui/styles.tcss` | source | LLR-144.4, 144.11, 149.2–149.6 | E-3 pairs + Patch geometry + `width-narrow` Patch rules deleted; one scoped `/* batch-97 patch_editor */` section. **Fold:** 3 dead / duplicate unscoped rules deleted, 1 moved into the section (F2); form spacer rows + `$rule` inputs; muted text-area scrollbars |
| `s19_app/tui/window_help.py` | source | LLR-148.6, 148.10 | `patch` section rewritten (code-authored); F3/F4 prose (2 docstrings, CRC, Reports); notation body "JSON tab". **Fold:** unchanged |
| `tests/test_b97_patch_editor.py` | test | HLR-144, LLR-144.1–144.12 | NEW — 31 nodes; **fold +7** (teal layer 0, paste-parse unsaved, paste heading, muted scrollbars, capped strip ×2, whole-stylesheet scope) and in-place clauses (painted colour in TC-B97-39 highlight, paste arm superseded, TC-B97-40 spacer + background) |
| `tests/test_b97_width.py` | test | HLR-149, LLR-149.1–149.6 | Patch arms of TC-B97-34..38, 59 (30 nodes) |
| `tests/test_b97_chips_help.py` | test | LLR-148.6, 148.7, 148.9 | Patch arms of TC-B97-32, 33, 58 (8 nodes); **fold:** TC-B97-58 two literal clauses (L1) |
| `tests/b97_fixtures.py` | fixture | HLR-144 (A.5 builders) | `CALIB_ENTRIES`, `calib_hotfix`, `empty_changeset`, `legacy_v1`, hostile change-sets, `write_changeset`, `open_patch_editor`, `load_change_file` |
| `tests/test_id_registry.py` | test | LLR-144.1 (D18) | `EXPECTED_SCANNED_TEST_FILES` 196 → 197, measured |
| `tests/test_tui_patch_card.py` | test | LLR-144.8 (D5) | named supersession: AT-080a/TC-080.3 address format, AT-080c `was` line, AT-080d / TC-080.6 home and budget (design item 7), TC-080.1 / TC-080.4 no-entries state |
| `tests/test_tui_patch_layout.py` | test | HLR-144 | named supersession of all 9 tests to the ledger + inspector tree |
| `tests/test_tui_patch_json.py` | test | LLR-144.12 | JSON tab opened before reading; `_FILL_TALL` 120x50 → 118x54; AC-3 rewritten; **fold:** `_CLAIMED_HUES` + the PATCH teal |
| `tests/test_tui_patch_big.py` | test | LLR-144.7, 149.4 | AT-075a inspector chrome per tab; AT-075e head-kept clip; AT-075c opens JSON tab |
| `tests/test_tui_patch_chips.py` | test | LLR-144.10 | tab chips and `#patch_tabs` declared outside the action-chip family; Run checks probed on its tab |
| `tests/test_tui_patch_editor_v2.py` | test | HLR-144 | AT-057a homes; AC-4 (paste on JSON tab); AT-068a click helper opens the control's tab; AT-068a paste step polls with `_settled` instead of one fixed pause (orchestrator, gate suite) |
| `tests/test_tui_patch_editor_b94.py` | test | LLR-149.6 | AT-B94-03: at 80x24 the table is reachable, not whole |
| `tests/test_tui_patch_checks_strip.py` · `tests/test_tui_patch_history_strip.py` · `tests/test_tui_patch_variant.py` | test | LLR-144.12 | geometry nodes open the strip's / row's tab first |
| `tests/test_tui_directionb.py` | test | LLR-144.2 | `PATCH_DOC_SECTION_TITLE` `¹PATCH SCRIPT` → `PATCH SCRIPT` (named supersession) |
| `tests/test_window_usage_help.py` · `tests/test_changes_file_notation_help.py` | test | LLR-148.6 (D25) | `patch` leaves the md-fidelity census (code-authored); **fold:** `crc_designer` and `reports` too (LED-…97.20) |
| `prototypes/cambios_10_12_2026/help_sections.md` | doc | | untracked operator draft (git-excluded): Inc-4 had changed CRC / Reports step 6; **the fold restored both lines** to the operator's text (`help-draft-restore.diff`); net change vs before Inc-4: none |
| `prototypes/b94_polish/run_real.py` | doc | | throwaway harness, untracked: `patch-editor-json` scenario |
| `.dev-flow/BACKLOG-CODE.md` | doc | | fold: 4 ux items routed (batch-97 section) |
| `01-requirements.md` · `01-requirements-appendix.md` · `01-requirements-ledger.md` · `design/design-proposal.md` | doc | | fold: LLR-144.6 amended; A.4 TC-B97-06/39/40; LED-…97.18–.21 appended; D5 (e), D5 rationale, D25, §3 tree / budget / JSON-tab paragraph |

| Count | Value |
|---|---|
| **SOURCE files** | **`4` / 4** — at the cap by design: the design's Inc-4 row names exactly these four files (`screens_directionb.py`, `app.py`, `styles.tcss`, `window_help.py`); the 7 prose carries lie inside them; no fifth was needed |
| Test files | `19` (1 new module, 1 fixture helper, 17 edited); the fold touched 5 of them (no new file) |
| Doc / design files | this packet; evidence under `evidence/inc-4/`; two untracked prototype files (above) |

## 3 · How to test

```bash
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8; unset NO_COLOR
python -m pytest $(cat .dev-flow/2026-10-19-batch-97/evidence/inc-4/gate-files.txt) -q -rfE -p no:cacheprovider
python -m pytest tests/test_tui_directionb.py -q -p no:cacheprovider                 # guard host
python .dev-flow/2026-10-19-batch-97/evidence/inc-4/mutate.py                        # 48 mutants / 63 arms (first run: M1-M39; fold: M40-M49)
python .dev-flow/2026-10-19-batch-97/evidence/inc-4/measure_budget.py               # PC-24 budget, 4 sizes
python .dev-flow/2026-10-19-batch-97/evidence/inc-4/check_frames.py <tree>          # Check Editor frame, per tree
python .dev-flow/2026-10-19-batch-97/evidence/inc-3/snapshot_cells.py <tree>        # PC-10, per tree
powershell -File prototypes/b94_polish/capture.ps1 -Scenario patch-editor[-json] -RealTree -OutPng <out.png> [-Rows 53 | -Cols 220 -Rows 60]
```

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | `patch_layout` monotonic, the strip builder (states, cap, bold), TC-B97-04 ×2 (CSS parse) | passed |
| **A · white-box** | `core` · `full` | the TC nodes of the 3 b97 modules + 17 superseded / census files | gate set **813 passed, 29 xfailed, 9 failed**. The 9 failures: 4 baseline nodes (`at_b78_32`, `at031b`, `at057b`, `at_056e`) and 5 single-pause timing flakes. The 5 flakes fail on a clean HEAD worktree too: **4 of 30 on HEAD vs 3 of 30 on Inc-4** (`rerun-nonbaseline.txt`). See `green.txt`. Files touched after that run were re-run: **94 passed** (`green-after-fixes.txt`) |
| **B · black-box** | `core` · `full` | AT-B97-01, -02, -03 ×2, -17 | 5 passed (same run) |
| guard host | C-34 | `tests/test_tui_directionb.py` | **184 passed** — `guard-host.txt` |
| reverse-census run | B1 | 31 files on HEAD (`census-head-run.txt`) and on the Inc-4 tree (`census-new-first.txt` before the rewrites, `green.txt` after) | §Reverse census |

**PC-24 — the 118x53 arms run here.** These nodes ran at 118x53: TC-B97-02 (ledger ≥ 7 rows, 6 of 6 painted); TC-B97-36 Patch arm (Load / Save / Validate / Apply inside at scroll 0); TC-B97-38 height clause (0 blank rows outside the ledger and the card); TC-B97-40 (form + chips inside the pane); TC-B97-60 at 118x53 with the save-back and report rows offered (every control inside its home and in the chain). All are green.

Slack, measured on the real tree (`budget.txt`), for the design §3 scenario (row #3, 11 B):

| Size | Ledger data rows | Inspector pane rows | Used | Empty at the foot | JSON view · paste | With save-back + report |
|---|---|---|---|---|---|---|
| 118x54 | 33 | 33 | 18 | **15** | 12 · 12 | 10 · 9 |
| 118x53 | 32 | 32 | 18 | **14** | 12 · 11 | 9 · 9 |
| 220x60 | 39 | 39 | 15 | **24** | 15 · 15 | 13 · 12 |
| 220x59 | 38 | 38 | 15 | **23** | 15 · 14 | 12 · 12 |

The ribbon, file row, document controls and legend are 1 row each (slack 0). These numbers equal the design's §3 table (15 · 14 · 24 · 23; 9 · 9 at 118x53 with both rows offered). **After the gate fold** (spacer rows, LED-…97.19): used 20 / 20 / 17 / 17, empty **13 · 12 · 22 · 21** (`budget-fold.txt`); JSON rows unchanged; design §3 amended to these numbers.

### Gate fold results (2026-10-21)

| Run | Result | Evidence |
|---|---|---|
| RED of the new / changed arms on the **pre-fold source** (source digests in the header equal the gate's) | **14 failed, 78 passed**: every new arm RED at its named clause — teal layer 0 `(2, 3, 'bold #e9e9e9')`; highlight colour `['#e9e9e9', …]`; paste-parse `('draft · change', '6 entries · 00:00:02 · saved')`; every-writer paste arm `'saved' == 'unsaved changes'`; heading `PASTE BUFFER · editable      0.3K / 64.0K`; scrollbar `('patch_json_view', '#003054')`; TC-B97-40 rows `[10, 11, 12]` ×2; whole-stylesheet scope `['#patch_variant_row', '#patch_execute_row', '#patch_variant_select_row', '#patch_doc_issues', '#patch_checks_results']`; hue census phantom claimant `#56e0d6`; TC-707 / TC-1802 pre-fold key sets vs the restored draft at `crc_designer`. Capped-strip arm re-run after moving its entry to `0xEB14` (cap + note): 2 failed, `(118x54, -1)`, `(118x53, 0)`. 0 `ImportError` / `NoMatches`. TC-B97-58 L1 literals stay green on both trees (their RED is M34) | `red-fold.txt` |
| GREEN gate set (`gate-files.txt`) on the fold tree | **820 passed, 29 xfailed, 9 failed** (first run: 813 / 29 / 9; +7 nodes). Failed: 3 baseline (`at_b78_32`, `at031b`, `at_056e`; `at057b` passed this time); 2 known single-pause flakes (`tc024`, `tc331`); 4 not failing in the first run — isolated ×2: `test_at_038d` 1/2, `test_at_061a` 2/2, `test_saveback_width_32` 0/2, `test_tc081_1_derived` 0/2. `test_at_061a` measured: **8/20 on clean HEAD `98f3c84`**, 11/20 on the fold tree with the four fold source edits reversed, 5/10 on the fold tree — a single-pause node (one `pause()` after `button.press()`), not caused by the fold. No paste-related node failed | `green-fold.txt`, `rerun-nonbaseline-fold.txt` |
| Non-baseline nodes of the orchestrator's full suite, 3× each on the fold tree | `test_at058b_id_census_and_wiring_survive_reparent` 3/3 passed; `test_at077e_image_generation_invalidates` 3/3 passed (and 3/3 on a clean HEAD worktree, removed after). In its module run another single-pause arm of that module failed instead (`arm (b) remove_entry … expected 2 rows, got 3`). **Verdict: not caused by Inc-4**; same single-pause class; nothing to fix here | `rerun-nonbaseline-fold.txt` |
| Guard host `tests/test_tui_directionb.py` | **184 passed** | `guard-host-fold.txt` |
| Check Editor painted frame 118x54 + 220x60 vs `98f3c84` | **identical** (same SHA-256 as `check-frames-98f3c84.txt`; diff empty) | `check-frames-fold.txt`, `check-frames-diff-fold.txt` |
| Mutations (fold) | M34 re-run + M40–M49: 11 mutants, 15 arms → **14 KILLED / 1 SURVIVED / 0 BAD**. Survivor: M45 (row margins 0) on the capped-strip arm — the chips' row follows the form's fixed height, not the margins; M45's other arm (rows 2 apart) KILLED it, and the retarget **M49** (height 5 → 3) KILLED both capped arms | `mutations-fold.txt`, `mutate.py` |
| Pane budget re-measure | §3 scenario empty rows 13 · 12 · 22 · 21; JSON view · paste unchanged (12 · 12, 12 · 11, 15 · 15, 15 · 14; with save-back + report 10 · 9, 9 · 9) | `budget-fold.txt` |
| Real WT captures (fold) | teal bytes and `11 changed`; spacer rows and `$rule` inputs; at 118x53 the strip, form, chips and tally all inside for row #3; JSON tab `PASTE BUFFER · example` whole beside `0.3K / 64.0K`, grey scrollbars | `png/impl.patch-editor*.png` (first-run copies `*.pre-fold.png`) |

**Mutation totals (L4 — the one number):** **48 mutants, 63 arms: 62 killed / 1 survived-explained / 0 bad.** First run: 38 mutants (M1–M39, with M39 the retarget of M34), 49 arms; M34 survived then and is **killed** since the L1 literal clause. Fold: 10 new mutants (M40–M49), 14 arms, 13 killed, 1 survived (M45's capped-strip arm, retargeted by M49).

**Signed balance (fold):** 0 nodes deleted; +7 nodes in `test_b97_patch_editor.py`; in place: TC-B97-39 highlight (colour clause), TC-B97-06 every-writer (paste arm `saved` → `unsaved changes`, named supersession), TC-B97-40 labelled ×2 (spacer + background), TC-B97-58 ×2 (literals), `_CLAIMED_HUES` (+1 claimant), the two help census key sets (−2 md keys each, +2 code-authored).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none to the source: the new tests ran on the unchanged source (HEAD `98f3c84`, `git diff --stat -- s19_app` empty, in the transcript header) |
| Transcript | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/red.txt` — **59 failed, 10 passed** of 69 nodes (`-k "patch or tc_b97_04"` over the 3 modules) |
| Arms resolved at baseline | 69 collected, 69 expected |
| Verdict granularity | per node (`-rfE --tb=line`) |
| Arms that stayed GREEN (10) | TC-B97-01 ×2: the 66 ids exist on main, and the RED is M1. TC-B97-36 ×7: the actions are inside on main, and the RED is M23. One Inc-1 chip node that `-k patch` also matched (TC-B97-57) |

**PC-11 classification:** 52 of 59 fail with `AssertionError` at the named, main-observable clause. Examples: TC-B97-02 `(3, 6)`; AT-B97-01 2 of 6 rows painted; TC-B97-03 `(5, 3, 30, 28)` at both sizes; TC-B97-04 4 pairs present; TC-B97-05 "no JSON view; the buffer still reads the template: True"; TC-B97-35 `patch_script_section_label` overflowing; TC-B97-38 blank rows `[4, 17, 43]`; TC-B97-58 the empty line wrapping on 2 rows. Five fail at a `need()` presence assertion of a NEW id (TC-B97-02 tab arm, TC-B97-07 ×2, TC-B97-40 ×2). Those are AssertionErrors, not `NoMatches`. **Not RED at first (PC-11), then fixed and re-run:** TC-B97-06 ×3 failed at the `monkeypatch` of the absent `_json_clock` (`AttributeError`). TC-B97-34 painted failed at an `IndexError`. Both were reordered (`raising=False`; a length assertion first). Re-run on the unchanged source: **4 of 4 RED at their clauses** (`red-rerun.txt`). TC-B97-40 was reordered so the inputs' ancestry is asserted before the new pane id. Re-run on a clean HEAD worktree: 2 of 2 RED at the ancestry clause (`red-tc40.txt`). Totals: 0 `ImportError`, 0 `NoMatches`, 0 collection errors in the final readings. Contracted main-REDs (design PC-11 list): TC-B97-02, TC-B97-40 and AT-B97-01 each fail at their main-observable clause.

| Field | Value |
|---|---|
| **RED counterfactual** | 59 of 69 nodes RED on the unchanged source; 52 at the named clause on the first run, 7 re-checked after a PC-11 reorder (`red-rerun.txt` 4/4, `red-tc40.txt` 2/2) |

| Field | Value |
|---|---|
| **Mutation verdicts** | **All runs: 48 mutants, 63 arms, 62 killed / 1 survived-explained / 0 bad** (gate fold above). First run, as recorded then: `mutations.txt` 37 mutants, **48 arms, 47 KILLED / 1 SURVIVED / 0 BAD**, every restore proven by sha256. The survivor is **M34** (the old 110-character ledger line). The ledger state line is held to one row by its CSS no-wrap rule, not by the text length. That rule was retargeted as **M39** (rule removed) and **KILLED** (`mutations-rerun.txt`: the refusal line wrapped onto 3 rows). **First-run totals: 38 mutants, 49 arms, 48 killed / 1 survived-explained / 0 bad** (M34 is killed since the fold). Killed: a shipped id dropped; a 3-row ledger; an unscoped `.patch-docked-row` rule; an E-3 grid back; the JSON cap removed; Parse reading the view; the Undo site without `document=`; the stamp by the document path only (Save + typing arms, AT-B97-02); an equal payload repainted; `Text.from_markup` on the ribbon (×2); the strip bound to row 0 (×2); bold on an unchanged span byte / a context byte; rows elided to one; the strip not recomposed on resize (×2); no row cap; `can_focus=False` on a chip (×2); a second filled chip; the active tab chip filled; a control hidden; the paste buffer read-only; the PC-8 vacuous repaint; the ledger past the panel; the ribbon keeping its head; the Value column fixed; panel `overflow-y: hidden`; an unmapped byte outside the vocabulary; a help line without ` — effect`; the `TextArea` in the D20 tuple (derived 27 ≠ 26); the `Edit JSON` line naming one tab; a blank row before the dock; the strip fixed at 8 bytes; the ledger refusal not painted; the Checks no-run line removed; no fresh-start line (×2); no inspector floor (overflow at 120x54) |

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `tests/test_b97_*.py` (Inc-4 nodes) | unchanged base source | 59 failed (`red.txt`) |
| `check_frames.py` (Check Editor frame diff) | an unscoped `.patch-docked-row { padding: 0; }` appended to `styles.tcss` | 6 differing rows (`check-frames-positive-control.txt`) |
| `snapshot_cells.py` (PC-10) | the two trees | exactly the 2 `patch` cells differ, so the instrument sees a re-composed screen |
| `mutate.py` | 38 one-edit mutants | per-arm RED lines; asserts each anchor occurs once and that the edit applied |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown failing on a known-bad input before its first PASS was believed |

### PC-10 — per-cell C-22 prediction (29 snapshot cells)

**Prediction (stated before Inc-4):** 2 of 29 cells drift, the two `patch` cells. **Verified:** the 29 cells were rendered on a clean HEAD `98f3c84` worktree and on the Inc-4 tree (`cells-head.txt` / `cells-inc4.txt`). The per-cell frame hashes (`cells-diff.txt`) differ in exactly **`patch-comfortable-80x24` and `patch-comfortable-120x30`**; 27 are the same. All 29 stay inside the batch-94 `xfail(strict=False)` envelope (green run: 29 xfailed).

### Check Editor guard (design Inc-4 row item (6), D23 / F9)

`.patch-docked-row, .patch-docked-group` is byte-equal to `98f3c84`. TC-B97-04 scope arm passes, and every selector of the new section starts with `#patch_editor_panel` (M3 KILLED). The Check Editor's painted text frame at 118x54 and 220x60, with the demo A2L and two inclusions, is **identical** on both trees: `check-frames-diff.txt` is empty, and the positive control shows 6 differing rows. `tests/test_b97_check_editor.py` and the Check arms of `tests/test_b97_width.py` are green in `green.txt`.

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | TC-B97-05/06 and AT-B97-01/02 `json.loads` the JSON view and compare it with `serialize_change_document(service.document)` and with the fixture file's addresses; the stamp is parsed with a regex; TC-B97-60 writes the patched image through the shipped Write file control |

### Evidence files

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED transcript | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/red.txt` | `a9d7f6f10d33113814b6dcf563d2e6e254d65f888dc9831eb8990e29dba6a550` |
| RED re-run (PC-11 reorders) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/red-rerun.txt` | `a92335fce045838a17ffcedd24d28a1d57d3052add71adaa4ffe49e52b8b29ed` |
| RED re-run TC-B97-40 (clean HEAD worktree) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/red-tc40.txt` | `7953c48be316dfe09c5115e643f38f8f874bb7bfd622ac4aae39ffb8b8bfa6e2` |
| GREEN gate set | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/green.txt` | `bb2f74518f94427a955916d9ee7a86dfe2ef3c5d6419be0916955a456892c376` |
| GREEN re-run of files touched after it | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/green-after-fixes.txt` | `6f34a690d6e82ccd4468edd6fc8a8bf46cf8a364cbba9838333d4f1714bdb3c7` |
| Gate file list | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/gate-files.txt` | `95b77de9228813056d165f8d0e88c32c24f0e2f2e1685249fc68fb5c5f24c444` |
| Guard host | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/guard-host.txt` | `16453bfbecd0728b84896a65e4bd2452bcd07923e99127afb40ac629153fd8c0` |
| Flake comparison (HEAD vs Inc-4) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/rerun-nonbaseline.txt` | `ab89b63f0b881330d1dad1bba2900f5b9749c0b468859e0b89b5fa87e17c9dfa` |
| Reverse-census file list · greps | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/census-files.txt` · `census.txt` | `49ba336d95034beab598edc907a97cfd9f73b12a49e61cc5243f1606d0e25cbd` · `afbe709a5bc9c2bd8b8207f2389fc67d68bc288e5363a2f408d1f37e44969b31` |
| Census run on HEAD · on the Inc-4 tree before the rewrites | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/census-head-run.txt` · `census-new-first.txt` | `43be508d8b4b1cc11923846d84d3b73ab84802f3a2889668267d575a0c9cc2e2` · `041d0cb8f4bd8a29468fd54e1028e27359bc64d17c57cdd6339f89dd92a31b21` |
| Mutation battery · rerun (M39) · script | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/mutations.txt` · `mutations-rerun.txt` · `mutate.py` | `f8271258c998be4799af87c751bba54ab0f6c52ee46a4003c8f8d70d6372106d` · `09078adf003ad1e6f7fbb9e5f5abc91a09f02ec912816fb20cdb68b375442cf5` · `4bdd04eca4cb9dcf9cb9b96ebd3155e1253c761f1835c42a87806ba853ee26ce` |
| Snapshot cells HEAD · Inc-4 · diff | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/cells-head.txt` · `cells-inc4.txt` · `cells-diff.txt` | `369616a0351679e32fd6afc6b42ef83416ae33841a94335ba5ffc9f0ba4e4b32` · `fd4436dda919bdaa10e0085dd124ed772e3dc5cb167e2e00ccf029b1095ab301` · `e05fdab0a17cb71e9b40f157597d4870ac2977f418527ecf8926550d0e4d16a9` |
| Check Editor frames HEAD · Inc-4 · diff · positive control · script | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/check-frames-98f3c84.txt` · `check-frames-inc4.txt` · `check-frames-diff.txt` · `check-frames-positive-control.txt` · `check_frames.py` | `256b89b991dce10af09252a8576a42436e0e930bc3dd0070b7488bb6f5a176cb` · `256b89b991dce10af09252a8576a42436e0e930bc3dd0070b7488bb6f5a176cb` · `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` · `ac7a1bb42c96e5b7b68203d5a8ec897adb3a56803e2e37dc3eff6038654f090a` · `2d622f13ff24f8097b6fe181bb0c9c3817061e46f6dc17b54c11d842db462b2e` |
| PC-24 budget · script | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/budget.txt` · `measure_budget.py` | `c042193c4eeb8e0c41356c459fe44c79a07ecf7e9d07f07322ba2a62591321fb` · `74267307856d325d31c3def7cc1dbe072afe9a06746b1c292cdc0c4458a71818` |
| Capture 118x54 (Inspector, row #3; fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/png/impl.patch-editor.png` | `97bae1b98e769e236aff2a8d81850856520b65de9873f0f7c70d7da841123767` |
| Capture 118x53 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/png/impl.patch-editor.118x53.png` | `6d58cc26784d6436957312699b5a0b3e4901424f7f93e8d06af93af405d615be` |
| Capture 220x60 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/png/impl.patch-editor.220.png` | `7f72b516cc913d72e50d19bdb69ad529ada556a6b288122149dc8b40aacdbe6f` |
| Capture 118x54 JSON tab | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/png/impl.patch-editor-json.png` | `e69c9d469cfbf3777bb68fda34dcacdec41696964d1a7d425ffd6be69fc0731b` |
| **Fold** RED (pre-fold source) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/red-fold.txt` | `0fd55287562293a3de247875f95447c267a25987ff6e84383df01279513297d5` |
| **Fold** GREEN gate set | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/green-fold.txt` | `c9723f64d046229437347574853e7308451a0f13f9ee701d21a4ba6926e2fe85` |
| **Fold** guard host | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/guard-host-fold.txt` | `c7982fbd4e9f77a3df681af6ee7fb5cc6c4912377f053c419f95c71af1cf8e19` |
| **Fold** non-baseline re-runs (at058b, at077e, at_061a vs HEAD) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/rerun-nonbaseline-fold.txt` | `481642b0054603cbdcdf181339a4bd89fb0a41a5b057745e9d3545eb1174731d` |
| **Fold** mutations · script (48 mutants) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/mutations-fold.txt` · `mutate.py` | `36f5c3eeebc847c1f2ab4b8888e5b8de1df4656df16cad8d97c27bf63590ef65` · `26016be7ff69d6e4d0c37a735a3fe07716e55822321d4627f6122a3244c4915b` |
| **Fold** pane budget | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/budget-fold.txt` | `51d9691e0bc56fdc5828d2ad5f0573f2b1c8b4dabdeaaa5c78924809621b0237` |
| **Fold** Check Editor frames · diff | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/check-frames-fold.txt` · `check-frames-diff-fold.txt` | `256b89b991dce10af09252a8576a42436e0e930bc3dd0070b7488bb6f5a176cb` · `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| **Fold** validator `--brief` (after `--atlas --write`): only V2 blocks (16 AT ids of later increments, as before the fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/validate-brief-fold.txt` | `42f79f6a60e16685c4ce26bb77c7f0e6a9f59aee6f2dba86350f78ce20743c51` |
| **Fold** help-draft restore diff | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/help-draft-restore.diff` | `bbc3601795711243abc14a33e01aa8b8a99f59fed4cd68ce88c3559946b09840` |
| First-run captures kept | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/png/impl.patch-editor.pre-fold.png` · `impl.patch-editor.118x53.pre-fold.png` · `impl.patch-editor.220.pre-fold.png` · `impl.patch-editor-json.pre-fold.png` | `e5427d69…f76a9` · `81498f40…7bd08` · `5c61ac81…7c` · `29378892…6df0` (= the first-run digests) |
| Full suite, fold tree (orchestrator) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/full-suite-fold.txt` | `220b8f1ed1b185d36becba38b192b3a4008875fcb2d682aed4e65bd020811deb` |
| Non-baseline re-runs of the gate suite, at068a hardening (orchestrator) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/rerun-nonbaseline-suite.txt` | `2483995ebcb921f6ee0cd75a794b7402b38ede79331dd230de9892d0a8029e92` |
| `test_tui_patch_editor_v2.py` module after the at068a hardening (orchestrator) | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/patch-v2-module-after-hardening.txt` | `458e98bc174eb60a491d9ab28333d1a0ad6d2a34b18fb1dc72112cf8e2beaf01` |

| Field | Value |
|---|---|
| **Evidence files** | 29 first-run artifacts + 15 fold artifacts (4 re-captures overwrite the first-run PNGs, kept as `*.pre-fold.png`) under `.dev-flow/2026-10-19-batch-97/evidence/inc-4/`, each with its SHA-256 in the table above; the capture rows point at the fold re-captures |

Final source digests after the fold (first 16): `screens_directionb.py 16f059d6a18131c8`, `app.py 6d799e8bb81cefae`, `styles.tcss 478811c37e2dcf74`, `window_help.py cc11018c2c457d25` (unchanged by the fold). First-run digests: `163cbd041347afbf`, `83561794287d3d96`, `8a9e0385f5e903cb`, `cc11018c2c457d25`. Each restore line in `mutations*.txt` shows the same digest before and after the mutant.

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | Yes: 0 overflowing descendants (TC-B97-35, over each of the 3 tabs); 0 blank rows outside the ledger and the card; 0 unscoped selectors in the Patch section; 0 differing Check Editor rows; 0 snapshot cells drifting beyond the 2 predicted; no `Binding(` in the `app.py` diff; no `refresh_entries` site without `document=`; no test outside the census reaching a changed id |
| What made the search wide enough | every displayed descendant of the panel on each tab (guard ≥ 10); full-width painted panel rows; the CSS parsed into blocks (not grepped); both trees rendered for the 29 cells and the Check frame; `git grep` over `tests/` and `s19_app/` |
| Positive control | the M3, M31, M38 mutants (an unscoped rule, a blank row, an overflow) each go RED; the Check frame diff sees M3's padding change (6 rows) |

### Reverse census — trigger family B, and A3

| Probe | Result |
|---|---|
| B1a ids reached from other tests | 31 files (`census-files.txt`). At HEAD: 5 failed, 583 passed (all baseline or flake class). On the Inc-4 tree before the rewrites: 53 failed (`census-new-first.txt`). Each was rewritten by named supersession (§2), or was a baseline / flake node. After: `green.txt` |
| B1b changed behaviour / removed symbols | `CARD_BYTES_MAX`, `_apply_window_geometry`, `_FILL_PANEL_MIN_ROWS`, `_SHORT_BODY_VIEWPORT_ROWS`: 0 code references left (one test message text updated). `¹PATCH SCRIPT` / `JSON EDIT` / `patch-window-body` remain only in comments and docstrings of `test_tui_snapshot.py` / `test_tui_patch_layout.py` (history). The `#patch_checks_help` text and the path placeholder are kept verbatim (AT-032a, AT-052a, AT-065a, TC-332 pins) |
| B1c hex sweep | new literals: `#969aad` (DGRAY), `#b565f3` (PURPLE). Both are already claimed (`test_tc079_5c` green) |
| B1d TC-081.4 | 0 `Binding(` lines in the `app.py` diff |
| B1e chip family | 0 `.patch-chip` / `.tab-chip` selectors outside `#patch_editor_panel`; AT-076b green |
| B2 / B3 / A3 | no file moved; no source outside `screens_directionb.py` reads the panel's new private state; the 4 `refresh_entries` sites all pass `document=` |

| Field | Value |
|---|---|
| **Reverse census** | B1a 31 files, 17 rewritten by named supersession; B1b–B1e clean; B2–B3, A3 none |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | F3/F4 stale `📂 Open folder` prose: 7 sites routed from Inc-3, **7 corrected here** (`app.py` ×2, `window_help.py` ×5). The census found 1 more stale term ("JSON EDIT pane" in the changes-file-notation body), also corrected. 0 left (`git grep "Open folder" -- s19_app` empty) |

### Signed-balance test ledger

`post = base − deleted + added`. **0 nodes deleted.** Added: 31 (`test_b97_patch_editor.py`) + 30 (width Patch arms) + 8 (chips/help Patch arms) = 69. Rewritten in place, all by named supersession, none removed: 9 in `test_tui_patch_layout.py`, 7 in `test_tui_patch_card.py`, 7 in `test_tui_patch_json.py` (6 via the JSON-tab helper, AC-3 restated), 3 in `test_tui_patch_big.py`, 2 in `test_tui_patch_chips.py`, 3 in `test_tui_patch_editor_v2.py`, 1 in `test_tui_patch_editor_b94.py`, 1 each in the two strip modules and in `test_tui_patch_variant.py`, the `PATCH_DOC_SECTION_TITLE` constant (2 nodes), the md-census key sets (2 modules), and the registry bound.

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a named agent (agents/code-reviewer.md) · OK to advance, no HIGH (F1 tests read the untracked operator draft → operator decision 3, LED-.20; F2 dead/unscoped Patch CSS folded with a whole-sheet scope arm; L1 exact literals in TC-B97-58, M34 now killed; L2/L3 noted; L4 counts unified). ux-reviewer — spawned as a named agent (agents/ux-reviewer.md) · approve on re-read (round 1 approve with conditions: H1 HIGH `saved` beside `draft` after Parse pasted → `mark_pasted`, LED-.21, re-walked with Pilot: stamp `unsaved changes`, Load guard focus on Cancel, escape cancels; Obs 5 `example` heading; Obs 1 teal strip, operator, LED-.18; Obs 2 spaced form, operator, LED-.19; 4a muted scrollbars). 2 LOW open: chips abut the Bytes row; stamp stays `unsaved` after undo back to the file's content. Operator decisions asked at the gate 2026-10-21: teal strip, spaced form, help-draft decoupling with the draft's two lines restored |

## 5 · Risks

- **Fold — Load after a parsed paste now asks first** (H1): the parsed document is unsaved, so the dirty-load guard pops on Load. This reverses batch-94 LLR-005.1's w4 for the paste parse only (LED-…97.21); a test or user flow that pastes then loads without accepting the guard now stops at the popup. No gate-set node did.
- **Fold — long entries push the entry chips below the fold** at 118x53 (2 rows) and 118x54 (1 row) when the strip is at its cap; reachable by `tab` / scrolling (operator-accepted, LED-…97.19).
- **Fold — `test_at_061a` / `test_at_038d` are single-pause nodes** that fail 40–55 % of runs on HEAD `98f3c84` and on both Inc-4 trees (`rerun-nonbaseline-fold.txt`); they will keep surfacing in full-suite runs.
- **Single-pause timing tests:** 5 suite nodes that read the screen after one `pilot.pause()` fail intermittently, at the same rate on HEAD and on Inc-4 (4/30 vs 3/30, `rerun-nonbaseline.txt`). Each refresh does a little more work now (serialise + view reload on a new payload), so other single-pause nodes may surface in the full suite.
- **D1 push cost:** the serialiser runs on every `refresh_entries` call (§6.2 cost row: 37 ms at 10 000 entries). The equal-payload rule skips the view reload. The skip of the serialisation itself needs a `ChangeService` revision counter, which would be a fifth file (backlog, as designed).
- **The read-only view's horizontal scrollbar band** costs 1 of its rows (TextArea, `soft_wrap=False`).
- **Below the range:** the JSON and Checks tabs scroll inside themselves (`overflow-y: auto`, paste floor 8 rows, JSON body floor 9). The inspector keeps a 45-cell floor, so at 120–133 columns the ledger is the narrower side: Value 12 cells at 120x54, and its table scrolls sideways when a status is long.
- `#patch_checks_help` keeps its shipped multi-line text (pinned by AT-032a/AT-052a). It wraps under Run checks in the Checks tab's spare rows. The design drew it as 1 row.

## 6 · Pending items / spec deviations

- **Deviation — the stamp's noun is grammatical:** `1 entry · …`, `N entries · …`. The A.4 regex `^(\d+) entries · …` would not match a 1-entry document. The tests accept `entr(?:y|ies)` (precedent: Inc-3 UX L3, `1 field`).
- **Deviation — the strip note reads `showing N of M bytes`.** D5 (c) wrote `first 64 of 200 B shown`. The operator's answer (2026-10-21) used the `showing N of M bytes` form, which is also the JSON cap note's form.
- **Deviation — `patch_layout` takes two more inputs** than D21 names (`status_longest`, `ribbon_w`). The Status column is sized to its longest status (7–20), like the Check Editor's `fmt_longest`, and the ribbon's tail clip needs its width. Both are measured, never the terminal width.
- **Deviation — history strip:** it stays two lines (TC-081.x pins its shape), so the JSON tab's fixed rows are 9, not the design's 8. The measured view / paste heights still equal the §3 table (above).
- **Deviation — the Checks help** stays verbatim (above), not one row.
- **The inspector border subtitle follows the tab:** `v2 schema` on JSON, the run state on Checks (AT-075a restated). The CHECKS and JSON panes themselves have no border.
- **The four baseline `test_tui_patch_editor_v2.py` nodes** (design §6.1) on the re-composed panel: `at031b` and `at057b` still fail as in the baseline; `at064c` and `at_batch41_escape` passed in `green.txt` (`at064c` failed 2 of 4 isolated re-runs of this tree — intermittent, not claimed fixed). All 4 go to the backlog at close.
- Capture harness (throwaway, untracked, outside the count): `run_real.py` gained the `patch-editor-json` scenario.
- Untracked operator draft `prototypes/cambios_10_12_2026/help_sections.md`: CRC / Reports step 6 now name their folder, because TC-707 ports those two sections verbatim. The patch section of the draft is unchanged and no longer ported.
- The full suite was not run here (per instructions). The orchestrator runs it node by node against the baseline (PC-12).
- **Fold — `PATCH_TEAL` lives in `screens_directionb.py`, not `insight_style.py`:** `insight_style.py` is outside this increment's four files; moving the constant there (next to `WAITING_HUMAN` / `CRC_FAMILY`) is a one-line follow-up for a later increment that owns that file.
- **Fold — the shipped draft is untouched in net:** `help_sections.md` is byte-equal to its pre-Inc-4 text for the two restored lines; no test reads `crc_designer` / `reports` from it any more.
- **Fold — single-pause timing class** (`at_061a`, `at_038d`, `at077` arm (b), `tc024`, `tc331`, …): backlog at close, as designed for the class.

## 7 · Suggested next task

The fold is done. The orchestrator re-runs the full suite node by node against the baseline, and asks `code-reviewer` (F2, L1, H1 wiring: `screens_directionb.py` `before_after_card_text`, `_refresh_paste_gauge`, `mark_pasted`; `app.py` `parse_paste` branch; the `styles.tcss` section) and `ux-reviewer` (`png/impl.patch-editor*.png` vs `*.pre-fold.png`) for a re-read. Then Inc-5 (Flow Builder).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files | all | ✓ | §2: 4 / 4 |
| 2 | Tests written in this same increment | all | ✓ | 69 new nodes + 7 at the fold |
| 3 | Layer 0 where the criterion applies | `core` · `full` | ✓ | `patch_layout`, strip builder ×2, CSS parse ×2 |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red.txt` 59/69, PC-11 classified, `red-rerun.txt`, `red-tc40.txt`; fold `red-fold.txt` 14 + 2 RED at the named clause |
| 5 | Reverse census declared | `core` · `full` | ✓ | `census.txt`, `census-head-run.txt`, `census-new-first.txt` |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | findings folded (§1b); re-read of the fold owed (§4b) |
| 7 | No file from another lane touched | all | ✓ | one lane |
| 8 | Frozen interfaces untouched (or returned to trunk) | all | ✓ | I-2/I-3 landed as frozen (`refresh_entries(…, document=)`, `PatchDocumentView`); I-9 names as D12 |
| 9 | Coverage claims verified on disk | all | ✓ | `green.txt` |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 |
| 11 | Mutation verdicts per arm | all | ✓ | 48 mutants, 63 arms: 62 killed / 1 explained / 0 bad (§4, L4) |
| 12 | Instrument RED-proof | all | ✓ | §4, 4 instruments |
| 13 | Correction population | all | ✓ | 7 + 1 sites, 0 left |
| 14 | Emitted-form assertion | all | ✓ | JSON parsed against the serialiser and the file |
| 15 | Independent review names somebody | all | ⚠ | code-reviewer + ux-reviewer at the gate (§4b); fold re-read owed |
| 16 | Evidence files with digests | all | ✓ | §4 |

## Gate — full suite, node by node against the baseline (orchestrator, 2026-10-21)

- **Run:** `evidence/inc-4/full-suite-fold.txt` — 9 failed, 3309 passed, 3 skipped, 32 xfailed in 1:24:25, on the fold tree. The pre-fold run (`full-suite.txt`, 7 failed / 3304 passed) is superseded.
- **Comparison** (PC-12 command vs `evidence/baseline-pytest-51ee191.txt`), not in the baseline (3), re-runs in `evidence/inc-4/rerun-nonbaseline-suite.txt`:
  - `test_before_after_report.py::test_at_038a_…` — 3/3 pass in isolation. Flake.
  - `test_before_after_report.py::test_at_061a_…` — 1/3 on the fold tree, 3/5 on a clean worktree at HEAD `98f3c84` (removed after use). Pre-existing flake (the fold author measured 8/20 failing on HEAD).
  - `test_tui_patch_editor_v2.py::test_at068a_undo_redo_roundtrip_through_surface` — **4/10 failing on the Inc-4 tree vs 5/5 passing on HEAD**: `assert outcomes["after_paste"] == []` at `:3655`, one fixed `pilot.pause()` after Parse pasted. The behaviour is right (the entry renders a tick later): Inc-4's paste refresh also rebuilds the JSON view and the stamp, so the single pause lands before the table re-render more often. **Fixed in the test, not hidden:** the pause is replaced by the repo's bounded `_settled` poll (fails loudly after 50 pauses), `tests/test_tui_patch_editor_v2.py:3634-3641` → 10/10 pass. Module run after the change: 49 passed, 3 failed = `at031b`, `at064c` (baseline) and `test_verify_loud_mismatch_notice` (pre-existing flake, already non-baseline in the Inc-3 pre-fold run; 4/5 in isolation here).
  - baseline nodes green in this run (4): `at057b`, `at064c`, `at_batch41_escape`, `undo_redo ac1` — recorded, not claimed as fixed.
  - counts reconciled: xfailed 32 = baseline 32, skipped 3 = 3, XPASS 0.
- **Routed at close:** the single-pause flake class (`at_061a`, `at_038a`, `verify_loud`, and the earlier ones) → backlog, suite hygiene with the `_settled` idiom as the fix pattern.
