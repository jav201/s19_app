# fast-dev-flow spec — batch-31 P1 quick strike (7 baseline-backlog fixes)

- **Status:** closed 2026-07-09 (AC-1..AC-7 green; full suite 1156 passed / 0 failed; PR pending merge)
- **Created:** 2026-07-09
- **Branch:** worktree `claude/memory-tool-baseline-backlog-30f7df`, merged up to `da1b4c4` (= origin/main after PRs #56/#57 — batch-30 R-043-3 + canonical snapshot regen; renumbered this batch 30→31 accordingly)
- **Route:** /fast-dev-flow (small fixes with pre-verified root causes; Lane A of the 3-lane baseline dispatch)
- **security_required:** true (see §6)

## 1. Objective

Clear the seven small P1 items from the 2026-07-09 baseline backlog (B-01, B-03, B-04, B-05, B-06, B-15, B-20) in one PR: fix Memory-Map→hex navigation, extend OS-clipboard paste to all path/name inputs, bind Issues PgUp/PgDn, and remove three UI-geometry irritants.

## 2. User stories

- As an operator navigating the Memory Map, I want "Open in Hex View" to actually reposition the hex view at the selected cell's region, so map selection is a working navigation tool (B-01).
- As an operator pasting paths from Windows tools, I want Ctrl+V to work in **every** path/name text box (A/B diff paths, change-set path, save-back name, entry inputs, project name), not just the Load dialog, so I stop retyping long paths (B-03).
- As an operator working the Issues and Workspace screens, I want the advertised PgUp/PgDn keys to work (B-04), the JSON paste box to show a useful number of lines (B-05), the work-area file list to use the available space (B-06), the Memory Map cells to render as a contiguous band (B-15), and a visible "Load project" button (B-20), so the advertised surface matches actual behavior.

## 3. Acceptance criteria (observable; one per backlog item)

- [x] **AC-1 (B-01):** When a Memory Map cell is selected whose `cell_start` is NOT itself a present 16-aligned row base and "Open in Hex View" is pressed, the hex view shall reposition so the nearest present row at-or-after the cell start (falling back to at-or-before) is rendered (assert the row's `0x%08X` token appears in `#hex_view` text; today the window provably does not move — RED first).
- [x] **AC-2 (B-03):** When the OS clipboard holds text and `action_paste` fires in each of `diff_path_a`, `diff_path_b`, `diff_report_dest`, `patch_doc_path_input`, the save-back name input, the patch-entry address/value inputs, and the project-name input, the input's value shall contain the clipboard text — same funnel/cap behavior as `#load_path` (inject at the `_STRATEGIES` seam, batch-29 precedent; no monkeypatching the cap away).
- [x] **AC-3 (B-04):** When the Issues screen shows more issues than one page and PgDn / PgUp is pressed, the grouped panel shall advance / retreat one page (rendered row set changes accordingly); the keys named by `TRUNCATION_NOTE` are therefore real.
- [x] **AC-4 (B-05):** When the Patch Editor renders, `TextArea#patch_paste_text` shall have a rendered height of ≥ 6 lines (assert widget content height via Pilot).
- [x] **AC-5 (B-06):** When the Workspace renders in a tall viewport (80×50), `#files_list` shall display more than 8 rows; and at 80×24 both `#files_list` and `#sections_list` shall keep ≥ 1 visible row (fixed `height: 8` replaced by a `1fr` share of the left pane). *(Amended during Inc-1 — measured geometry: at 80×24 the left pane has only 3 content rows, where the old fixed 8 overflowed the pane; at 80×40 a 1:1 share tops out at ~6-7 rows, so the elastic-growth observable lives at 80×50. The original "80×40 → >8 rows" was a pre-measurement estimate.)*
- [x] **AC-6 (B-15):** When the Memory Map grid renders ≥ 2 adjacent same-row cells, the rendered row shall contain consecutive `█` glyphs with no blank gutter column between adjacent cells (kill the `min-width: 2` + centered 1-char glyph artifact).
- [x] **AC-7 (B-20):** When the Workspace renders, a "Load project" button shall be visible, and pressing it shall open the same `LoadProjectScreen` as key `p` (assert modal screen pushed).

## 4. Validation strategy

Pytest + Textual Pilot tests in the same increment as each change, one named test per AC (RED-first where the AC captures a live bug: AC-1, AC-3). Full suite `pytest -q -m "not slow"` green per increment; engine-frozen guards must stay at 0 diffs (no frozen file is touched). **Snapshot suite:** geometry changes (AC-4/5/6/7) will drift SVG baselines — per the standing snapshot-regen convention, affected snapshot cells get `xfail(reason="pending canonical-CI regen batch-31")` and baselines are regenerated ONLY in canonical CI (`snapshot-regen.yml`, textual 8.2.8) after merge; local regen forbidden. Manual smoke: `s19tui --load examples/case_00_public/prg.s19` walking each fixed surface.

## 5. Non-goals (OUT)

- B-02 (uncheckable reasons + info prompts) — next batch; touches the same screens file, sequenced after this lands.
- B-21 CRC multi-region single-CRC — batch-32 (parallel lane, own worktree/PR).
- B-08/09/10 report improvements — batch-33.
- B-07 patch/checks regroup + report filter file — awaiting operator spec.
- Any Memory Map feature work beyond the spacing + navigation fixes (no tooltips, no region names).
- Replacing the transient "press b" toast (B-11, P2).

## 6. Detected security flags

- [ ] Auth / identity
- [ ] Secrets / config
- [ ] External integrations
- [ ] Sensitive data
- [ ] Destructive DB
- [x] Input / attack surface (OS-clipboard **user input** pasted into more path inputs)
- [ ] Network / exposure

**`security_required`:** true

**Risk summary:** B-03 widens the OS-clipboard read surface from one input to ~8. Mitigations already in place from batch-29: every read goes through the single bounded funnel `read_os_clipboard` → `_bound_clipboard_text` (64 KiB functional cap, R-TUI-044) — this batch adds **no new read strategy and no new funnel**, only more consumers of the existing capped path. Pasted paths still pass through the existing resolution/containment (`resolve_input_path`; patches-dir containment guard for the change-file flow). Phase B opens with a focused mini security review confirming: (a) all new consumers are `OsClipboardInput` subclass instances with zero cap bypass, (b) no pasted text reaches a shell/subprocess, (c) markup safety of any pasted text that gets rendered (C-17 lens).

## 7. Increment plan (4 increments, ≤5 files each)

| Inc | Items | Files (est.) |
|---|---|---|
| 1 | AC-4, AC-5, AC-6 (CSS geometry trio) | `styles.tcss`, `tests/test_tui_directionb.py` (+ snapshot xfails) |
| 2 | AC-3, AC-7 (bindings + button) | `app.py`, tests |
| 3 | AC-2 (clipboard swaps) | `screens_directionb.py`, `screens.py`, tests |
| 4 | AC-1 (hex-nav snap) | `app.py`, tests |

## 8. Batch status

| Field | Value |
|-------|-------|
| Current phase | closed |
| Started | 2026-07-09 |
| Closed | 2026-07-09 |
| Promoted to /dev-flow | no |
| Notes | Lane A of 3-lane dispatch; Lane B (batch-32 CRC) requirements drafting in parallel worktree |

## 9. Close (filled in phase C)

### What changed
Seven P1 baseline-backlog fixes in 4 increments: (Inc-1) `#patch_paste_text` pinned to 8 lines, `#files_list` fixed-8 → `1fr` elastic share, `MapCell.render` width-fill for a contiguous minimap band; (Inc-2) PgUp/PgDn bound through new issues-aware context actions + `GroupedIssuesPanel` key rebind, compact Workspace "Load project (p)" button wired to `action_load_project`, empty-state prompt now advertises `p`; (Inc-3) seven inputs swapped to `OsClipboardInput` (patch entry address/value/bytes, change-set path, save-back name, diff A/B paths + report dest, project name); (Inc-4) `update_hex_view` snaps focus to the nearest present row base (`_snapped_focus_row_index`, bisect) instead of the exact-membership guard.

### How it was tested
- 8 new AC-mapped tests (one per AC + the project-name paste case + 2-variant hostile-paste AT), all named `test_ac*`; AC-1/AC-3/AC-7 captured LIVE RED first through the real UI paths.
- Full suite: `pytest -q -m "not slow"` → **1156 passed, 2 skipped, 12 xfailed, 0 failed** (12 xfail = 3 pre-existing + 9 batch-31 snapshot drift cells).
- Snapshot oracle: 25 passed + 9 xfail(strict=False) pending canonical-CI regen (batch-25/27/28 pattern; regen at CURRENT main after merge).
- Engine-frozen guards green (0 frozen diffs).
- Interactive manual smoke NOT performed in this autonomous session; the Pilot ATs drive each fixed surface through the real key/button mechanisms (C-16 discipline).

### Open risks / pending
- Canonical-CI snapshot regen after merge (9 cells), then retire the `_BATCH31_GEOMETRY_DRIFT` / entropy-80x24 xfail marks.
- Goto/search to an ABSENT address now repositions the window near it (previously silently stayed); the full suite pinned no contrary behavior, but flag to operator as a deliberate behavior change.
- AC-5 amended after measurement (elastic observable at 80×50; 80×24 both-lists-visible regression guard) — recorded inline in §3.

### Security flags — handling
`security_required: true` (input surface). Pre-code mini security review: no HIGH findings, verdict OK-to-ship with one MUST — a hostile-paste AT through the real Ctrl+V path — satisfied by `test_ac2h_hostile_paste_renders_literal_and_never_crashes` (balanced `[red]x` + unbalanced-bracket payloads, real downstream echo via the Load action). Conditions honored: class-swap only (funnel/`_STRATEGIES`/cap untouched — 0 diff on `os_clipboard_input.py`), first-line-only insertion preserved, swap scope limited to the reviewed list (`project_parent_path` excluded).

### Suggested commit message
```
fix(tui): batch-31 — P1 quick strike (B-01/03/04/05/06/15/20)
```
