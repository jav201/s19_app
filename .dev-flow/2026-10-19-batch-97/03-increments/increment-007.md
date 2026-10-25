# Increment 007 — HLR-149 · `Width sweep, snapshot regen and the Inc-8 leftovers`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md` (level `full`).
> **Where this lives:** `.dev-flow/2026-10-19-batch-97/03-increments/increment-007.md` (repo, not synced).

| Field | Value |
|---|---|
| Batch | `2026-10-19-batch-97` |
| Increment | `007` (the last; executed after Inc-8 and Inc-9, D29) |
| Lane (if the batch forked) | `none — one lane (design-proposal §8)` |
| Requirement(s) | `HLR-149 / LLR-149.1–149.6` (the sweep; AT-B97-15, -16, -24 realised) · `HLR-150` (AT-B97-25 / -26 and TC-B97-71 re-run; the Diff tokens on a regime switch; the Split / Join export cues) · `LLR-148.6` (help modals scroll) · ledger `LED-2026-10-19-batch-97.43`, `.44`, `.45` (new) |
| Acceptance | AT-B97-15, AT-B97-16, AT-B97-24 (new nodes) · AT-B97-25, AT-B97-26, TC-B97-71 (re-run) · TC-B97-34..38, -59 (the full matrix of `test_b97_width.py`) |
| Agent | `software-dev` (spawned sub-agent) |
| Date | `2026-10-23` |
| Design refs | `PDR-2026-10-19-batch-97#D17` (deviation, LED-…97.45), `#D29`; the Inc-7 row of design §7 (fix set); PC-10, PC-22 (retired by Inc-8's LED-…97.40); Inc-6 §6 item 10 (harness race); Inc-8 §6 item 4, §5 code re-read L2, ux F3 |

---

## 1 · What changed

Five owed items, in the order the orchestrator listed them.

1. **The snapshot harness race (PC-10) is fixed, then the 29 snapshot cells are regenerated.**
   - **The race.** `_build_loaded_triple` set `current_a2l_path` but never repainted the status bar. The A2L name reached the bar only through the startup resize's deferred `update_project_labels` (`app.py` `on_resize`, `call_after_refresh`). When that callback ran before the harness installed the triple, the capture painted `(none)`. Made deterministic by idling the app before `run_before`: `(none)  |  (none)` on 3 of 3 cells (`red.txt`). The fix is one test-side line: the harness calls `app.update_project_labels()`.
   - **The regen.** It ran locally (Windows, Textual 8.2.8, NO_COLOR unset), after a parity probe at `ae0ef4f` (the last commit that wrote the baselines). The local run reproduced 27 of 29 cells byte for byte. The 2 map cells there had been committed greyscale, written with NO_COLOR=1 (`snapshot-env-parity.txt`). **This deviates from D17**, which deferred the regen to the CI workflow after the push (LED-…97.45, §*For the operator* item 1).
   - **Before:** 29 xfailed under the batch-94 envelope. **After:** 33 passed, 0 xfail, 0 xpass, on two consecutive runs. The envelope `_batch94_inc001_drift_marks` is retired as a no-op, following the batch-46/47 precedent.
   - **Cell diff** (`snapshot-cells-diff.txt`, `snapshot-reconcile.txt`):
     - 29 of 29 cells changed.
     - In all 29, the old bottom row was the one-row Footer, and the new last two rows are the key bar (row 1 `^k Palette …`, row 2 the window's tag).
     - All 29 paint `snap.a2l`.
     - 19 of 29 paint the 12-entry rail (`Check Editor`, `Flow Execution`). The 10 cells at 80x24 show the rail as glyphs only.
     - The rows in between moved with the window header rows that batches 94–97 added.
2. **The sweep (HLR-149).**
   - **AT-B97-15, -16 and -24 are real test nodes now**, in `tests/test_b97_width.py`. They are the validator's 3 V2 blocks, and the validator now reports 0 blocks. One session holds the four screens with A.5's widest values: the 47-cell parameter name, a change-set file name wider than the ribbon, a 60-cell change-doc ref on the Builder's chain and on a waiting lane, and a 40-cell set name. Each screen is reached through the rail and read as painted.
   - **The full TC-B97-34..38 / -59 matrix runs green** on the two-row layout, together with AT-B97-25 / -26 and TC-B97-71 (§4).
   - **No layout fix was needed.** 0 of the fix set {`styles.tcss`, `screens_directionb.py`, `flow_screens.py`, `app.py`, `window_help.py`} was touched for the sweep, as the design expected.
3. **Split / Join / Export names `e`** (Inc-8 operator item 4 (a)). The button reads `EXPORT  e`, and the other cues read `ready — e exports`, `— e will ask` / `— e again to confirm`, and the toast `press e again to confirm` (`segment_split_view.py`). The binding was always plain `e`.
4. **Help modals scroll** (Inc-8 ux F3).
   - **The change.** `WindowHelpScreen` wraps the steps and the keys block in `VerticalScroll#window_help_scroll`. A new `/* batch-97 help modal */` CSS section docks the title at the top and caps the scroll at `max-height: 100%`. The title and Close stay on screen, and every line can be reached with `tab` then `pagedown`.
   - **Before**, at 118x54: Patch 105 rows, top at row −48; Flow Builder and Flow Execution keys blocks never painted. At 80x24, every dialog overflowed.
   - **After.** A help that fits keeps its HEAD height (Map 21 rows, Checks 26 rows at 118x54).
5. **Diff tokens on a height-only resize** (Inc-8 code re-read L2).
   - **It reproduced:** 4 of 4 height-only regime switches (wide or fallback ↔ notice at the 29-row floor) left `f ] [` in the old regime's lit or dim state (`red.txt`).
   - **The fix:** `AbDiffPanel.apply_regime` calls `self.app.refresh_bindings()` when the regime changes. That is the regime switch's single site; `on_resize` is the app's, and it delegates here.
   - **Width-only control arm:** wide → fallback was already GREEN on HEAD, because a width change refreshes the bar by another path. It is kept as a control.

### For the operator

1. **The snapshot regen ran locally, not in CI (a deviation from D17, LED-…97.45).**
   - **Why it is safe:** the parity probe reproduced 27 of 29 committed baselines exactly on this machine. The 2 that differed were themselves written under NO_COLOR.
   - **What to check:** the regenerated SVGs carry real colours. For a second opinion, `snapshot-regen.yml` can be run on the pushed branch: its containment step should report 0 changed baselines. The orchestrator decides whether that run is wanted before merge.
2. **`.dev-flow/_derived/ATLAS-*.md` were rewritten by `devflow-validate.py --atlas --write`.** The validator asks for them to be committed (V20 guards them by digest).
3. **`REQUIREMENTS.md` still says `EXPORT ^E` / `^E`** (batch-95 HLR-135, LLR-135.1, LLR-135.5). LED-…97.43 records the supersession for the close-time sync. This batch does not edit `REQUIREMENTS.md`.
4. **Not done: the review-page rebuild** (PLAN item 8, "captures + the single review page"). The orchestrator's Inc-7 brief did not list it. The captures are in `evidence/inc-7/png/`; `prototypes/b94_polish/build_html.py` was not re-run (§6).

### 1c · Fix round after the gate reviews (2026-10-23)

`code-reviewer`: OK to advance, with 4 LOW findings. `ux-reviewer`: changes needed (UX-F1..F4). The orchestrator relayed both; the fold stays inside the same 4 SOURCE files. Record: LED-…97.46.

| Finding | What changed | Pinned by |
|---|---|---|
| **UX-F1** (the keys did nothing until an unhinted `tab`) | `WindowHelpScreen` gets six `show=False` bindings (`up` `down` `pageup` `pagedown` `home` `end`) → `action_scroll_help`, which runs the scroll's own action. Close keeps the focus, `enter` still closes and `esc` still closes. Button binds only `enter`, and the app's `pagedown` / `pageup` are not priority, so the screen binding wins (measured) | NEW `test_help_modal_scrolls_by_key_while_close_keeps_the_focus` (every section at 80x24, plus one arm after `tab`); the first-round help test no longer presses `tab` and asserts Close kept the focus; M17 |
| **UX-F2** (the scroll was not visibly focused) | Resolved by F1. In addition, `#window_help_scroll:focus { background: $bg-base }` tints the body when a `tab` puts the focus there (capture `r2.help-patch-end`) | capture only; no test (a style tint) |
| **UX-F3** (every modal button shows its key) | Close reads `Close  esc`. This follows the `EXPORT  e` form; no other modal button in the app showed its key | NEW `test_help_modal_close_names_its_key_and_the_keys_block_stands_apart`; M18 |
| **UX-F4** (the keys read as part of the last step) | `#window_help_keys { margin-top: 1 }`: one blank row before the keys block | the same test (the keys block's `virtual_region.y` − the body's bottom ≥ 1); M19 |
| CR-F1 | The AT-16 / AT-24 docstrings now say the RED on `51ee191` is structural, and that the clause RED comes from M10–M12, M13, M14 and M16 | — |
| CR-F2 | `^E` → `e` in the prose of `test_segment_split_window.py` (13 lines: module docstring, TC-708 ×2, guard demo, below-thresholds, two comments) and of `test_segment_ops.py:308`. **`styles.tcss:2375` was not changed:** the comment sits inside the b514b07 / 09e44de byte-equal prefix that `test_tc_b97_flow_execution_css_section_is_scoped` and the flow-builder guard check, so editing it would redden two pins for a comment. It is recorded for the close | — |
| CR-F3 | The snapshot module's "regenerate … NEVER locally" comment notes that the batch-97 regen ran locally after a parity probe (LED-…97.45) | — |
| CR-F4 (cheap half) | The help test also matches each line's tail: its last word, which word wrap never splits (a fixed 20-cell tail straddled wraps and gave false misses). It also waits for the animated `page_down` to come to rest before it reads (1 failure in 3 runs before that, 4 / 4 after). **Skipped:** blank-row / no-write mutants for AT-16 / AT-24, recorded (§6) | M5, M6b, M7, M17 re-killed |

**Fix-round RED** on the first-round tree (`window_help.py dabdc14b…`, `styles.tcss ddcd55db…`): **5 failed of 5** help nodes (`red-r2.txt`). They are the first-round help test ×3 (no `tab`, so lines unreachable), the scroll test (`scroll_y` stays 0) and the label / gap test (`Close`, gap 0).
**Fix-round mutations:** M5, M6b, M7, M17 ×2, M18, M19 → **7 of 7 KILLED** (`mutations-r2.txt`).
**Fix-round GREEN:** 9 files (help, width, key bar, split window, segment ops, snapshot, theme, chips help, notation help): **437 passed, 0 failed** in 38:42 (`green-r2.txt`, `window_help.py 92a7ad97…`, `styles.tcss 525d940a…`).
**Re-captures** (real WT, truecolor, one window at a time, each closed):
- `r2.help-patch` and `r2.help-patch-pgdn` at 118x54 and at 80x24 (`pagedown` pressed with the focus on Close, no `tab`);
- `r2.help-patch-end` (the keys block below a blank row; the focus tint).

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens_directionb.py` | source | HLR-150 / LLR-150.4 (LED-…97.39) | `AbDiffPanel.apply_regime`: `self.app.refresh_bindings()` when the regime changes (+6 lines) |
| `s19_app/tui/segment_split_view.py` | source | HLR-150 (LED-…97.43) | 5 painted cues `^E` → `e`; 5 docstring / comment mentions |
| `s19_app/tui/window_help.py` | source | LLR-148.6 (LED-…97.44, .46) | `VerticalScroll#window_help_scroll` around the body and keys block; import; docstring; fix round: six scroll bindings + `action_scroll_help`, Close label `Close  esc` |
| `s19_app/tui/styles.tcss` | source | LLR-148.6 (LED-…97.44, .46) | appended `/* batch-97 help modal */` section (title dock, scroll cap; fix round: keys-block top margin, scroll focus tint); the shipped sheet is a byte-equal prefix |
| `tests/test_tui_snapshot.py` | test | LLR-007.1, LLR-007.2 (TC-016-S), HLR-150 (PC-10, D17, LED-…97.45) | harness `update_project_labels()`; NEW `test_tc016s_harness_paints_the_a2l_context_itself`; `_batch94_inc001_drift_marks` retired |
| `tests/__snapshots__/test_tui_snapshot/*.svg` ×29 | test | LLR-007.1, HLR-150 (D17) | regenerated |
| `tests/test_b97_width.py` | test | HLR-149 | NEW `test_at_b97_15_…[118x54, 160x56]`, `test_at_b97_16_…`, `test_at_b97_24_…` and their helpers |
| `tests/test_b97_key_bar.py` | test | HLR-150 | NEW `test_tc_b97_69_diff_keys_follow_a_height_only_regime_switch` ×5 |
| `tests/test_segment_split_window.py` | test | HLR-150 | NEW `test_export_cues_name_the_bound_export_key` |
| `tests/test_window_usage_help.py` | test | LLR-148.6 | NEW `test_help_modal_fits_and_every_line_is_reachable_by_key` ×3 (fix round: no `tab`, tail match, scroll-rest wait); NEW `test_help_modal_scrolls_by_key_while_close_keeps_the_focus`, `test_help_modal_close_names_its_key_and_the_keys_block_stands_apart` |
| `tests/test_segment_ops.py` | test | HLR-150 (LED-…97.43) | fix round CR-F2: one comment `^E` → `e` |
| `tests/test_id_registry.py` | test | HLR-151 (D18: Inc-9's module) | `EXPECTED_SCANNED_TEST_FILES` 198 → 199: Inc-9's module, measured; Inc-7 adds none |
| `.dev-flow/…/01-requirements-ledger.md`, `01-requirements.md` | doc | LED-…97.43–.45 | 3 entries; back-pointers on HLR-150, LLR-148.6, HLR-149 (V26) |
| `.dev-flow/_derived/ATLAS-*.md` | doc | — | regenerated by the validator |
| `prototypes/keybar/run_keybar.py` | doc | — | untracked harness: `help-<window>[-end]` scenarios |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-160x40].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-160x40].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[diff-comfortable-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-comfortable-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-comfortable-160x40].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-comfortable-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-compact-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-compact-160x40].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[issues-compact-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-comfortable-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-comfortable-160x40].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-comfortable-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-compact-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-compact-160x40].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[mac-compact-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-comfortable-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-comfortable-160x40].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-comfortable-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-compact-120x30].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-compact-160x40].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[workspace-compact-80x24].svg` | test | LLR-007.1, HLR-150 | regenerated baseline (D17, LED-2026-10-19-batch-97.45); close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own (the `*.svg` ×29 row above is a glob) |
| `.fast-dev-flow/archive/2026-07-28-batch-67-spec.md` | doc | — | FB-P2 wording: memory-region extraction; close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own |
| `.fast-dev-flow/archive/2026-07-28-batch-69-fbp2-design-spec.md` | doc | — | FB-P2 wording: memory-region extraction; close-time row (2026-10-25): the file was in this increment's commit but no §2 row named it on its own |

| Count | Value |
|---|---|
| **SOURCE files** | **`4` / 4**: `screens_directionb.py`, `window_help.py` and `styles.tcss` (in the design's Inc-7 fix set), plus **`segment_split_view.py`**, which is not in that set. The orchestrator's Inc-7 scope names it (item 3). The cue strings live only there, so the change could not go anywhere else |
| Test files | 5 modules (4 NEW node groups + the harness fix) + 29 SVG baselines |
| Doc files | ledger, requirements back-pointers, `_derived` atlas, evidence, this packet, the untracked harness |

## 3 · How to test

```bash
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8; unset NO_COLOR
python -m pytest tests/test_b97_width.py -k "at_b97_15 or at_b97_16 or at_b97_24" -q -p no:cacheprovider
python -m pytest tests/test_tui_snapshot.py -q -p no:cacheprovider                   # 33 passed, 0 xfail
python -m pytest $(cat .dev-flow/2026-10-19-batch-97/evidence/inc-7/gate-files.txt) -q -rfE -p no:cacheprovider
python .dev-flow/2026-10-19-batch-97/evidence/inc-7/mutate.py .                     # 16 mutants
python .dev-flow/2026-10-19-batch-97/evidence/inc-7/svg_rows_diff.py . HEAD          # before/after cell rows
python .dev-flow/2026-10-19-batch-97/evidence/inc-7/snapshot_reconcile.py .
powershell -File prototypes/keybar/capture.ps1 -Scenario help-patch-end -OutPng <png>
```

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | n/a — no new pure function; the layer-0 arms of TC-B97-34 / -38 (`check_layout`, `patch_layout`, `pipeline_layout`) re-ran in the gate | passed (`green.txt`) |
| **A · white-box** | `core` · `full` | the gate set (`gate-files.txt`, **26 files**). It is every test module that names a changed symbol: `styles.tcss`, `window_help`, `WindowHelpScreen`, `AbDiffPanel` / `apply_regime` / `refresh_bindings`, `SplitJoinWindow` / `sje_export`, `_build_loaded_triple` and the key bar. It adds `test_b97_width.py` whole (the TC-B97-34..38 / -59 matrix), `test_tui_theme.py`, `test_id_registry.py` and `test_tui_snapshot.py` | **1153 passed, 5 failed** in 1:29:44 (`green.txt`, on `window_help.py dabdc14b…`, `styles.tcss ddcd55db…`, `screens_directionb.py d7d9eba4…`, `segment_split_view.py 910ec87e…`). The 5 failures are below the table |
| **Full suite** | `full` | — | **not run** (orchestrator, per the Inc-7 brief) |
| **B · black-box** | `core` · `full` | AT-B97-15 ×2, AT-B97-16, AT-B97-24 (new); AT-B97-25, AT-B97-26 and TC-B97-71 ×2 (re-run on the final tree, in `test_b97_key_bar.py`) | passed (`green.txt`) |

**The 5 gate failures.**
- **3 baseline nodes:** AT-B78-03, AT-B78-32 and AT-056e (`baseline-pytest-51ee191.txt`).
- **1 pre-existing flake:** `test_tc024_report_trigger_surfaces_paths`, the one Inc-8 recorded. It failed 1 of 5 here (`rerun-nonbaseline.txt`).
- **1 bound Inc-9 left behind:** `test_tc607_scanned_corpus_matches_the_declared_bound` declared 198 and scanned 199. Inc-9 added `test_b97_load_project_dialog.py` without the bump. It is bumped to 199 here, and the module passes, 13 passed (`rerun-nonbaseline.txt`).

**Snapshot regen (D17, PC-10).**
- **Before:** 29 xfailed (`snapshot-before.txt`).
- **Regen:** `--snapshot-update` updated 29 (`snapshot-regen.txt`).
- **After** the mark retired: **33 passed on each of two runs, 0 xfail, 0 xpass** (`snapshot-after.txt`).
- **Reconciliation** (`snapshot-reconcile.txt`): every cell carries the two-row bar (29 / 29) and `snap.a2l` (29 / 29). The 12-entry rail shows in 19 / 29; the ten 80x24 cells paint the rail as glyphs only. The old bottom row was the one-row Footer in 29 / 29.

**Sweep (LLR-149.1–149.6 on the two-row layout).**
- `test_b97_width.py` runs whole in the gate and is green, at 118x54, 119, 120, 160x56, 220x60 and 260x70. Below the range it runs at 80x24, 100x40 and 220x40. The four ATs are in the same module.
- No source fix was needed for the sweep.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none to the source. The new nodes ran first on the unchanged HEAD `5cb7618` working tree (`red.txt`). They ran again in a detached worktree of `5cb7618` with the final test modules copied in (`red-rerun.txt`). The ATs ran in a worktree of the batch base `51ee191` (`red-at.txt`) |
| Transcript | `red.txt`: **9 failed, 1 passed** (harness ×1, Diff height-only ×4, export cues ×1, help ×3). The passing node is the width-only Diff control arm, GREEN on HEAD by design. `red-rerun.txt`: 8 failed, 6 passed, with the same RED nodes. The harness node passes there because its fix is in the copied test module. The 4 AT nodes pass on HEAD, as expected: they realise Inc-3..6 / 8 behaviour. `red-at.txt`: **4 failed, 0 passed** on `51ee191` |
| Instrument | pytest `-rfE --tb=line` |
| Where it ran | the working tree at HEAD source; `scratchpad/wt_5cb7618` and `scratchpad/wt_51ee191` (git worktrees, removed after the runs) |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider` |
| Arms resolved at baseline | 9 + 4 RED |
| Verdict granularity | per node |
| Arms that stayed GREEN | the width-only Diff arm (a control: on HEAD a width change already refreshed the bar) |

| Field | Value |
|---|---|
| **RED counterfactual** | 9 RED on HEAD `5cb7618` (`red.txt`). They were re-confirmed in a clean HEAD worktree (`red-rerun.txt`); that run also exercises the export node's `ready` clause, added after the first run. 4 AT RED on `51ee191` (`red-at.txt`). 0 restores needed: no source edit in the RED runs |

**PC-11 classification.**
- **RED at the main-observable clause:**
  - the harness: `(none)  |  (none)`;
  - Diff ×4: the painted lit / dim map ≠ `check_action` in the new regime;
  - export: `EXPORT  ^E`, plus `^E` in all four cues;
  - help ×3: the dialog off-screen (its top at row −48 at 118x54) and lines never painted;
  - AT-B97-15 ×2: `check_apply_ghost` overflows the Check Editor at 118x54 and 160x56 (P-10's clause).
- **RED structurally on `51ee191`:**
  - AT-B97-16: no `#patch_main`;
  - AT-B97-24: no `#window_help_check_editor` chip.

  Both are also RED by mutation at their clauses: M10–M12 (widths and voids), M13–M14 (reach by key), M16 (overflow at 119).

### Mutation verdicts

| Field | Value |
|---|---|
| **Mutation verdicts** | **First battery: 16 mutants, 17 arms — 15 KILLED / 2 SURVIVED / 0 BAD** (`mutations.txt`). **Fold: 2 arms, 2 KILLED** (`mutations-fold.txt`). Every restore was SHA-256 checked. **Killed:** M1 (no `refresh_bindings` on a regime switch); M2–M4 (one cue back to `^E` each); M5 (body unwrapped from the scroll); M6b (scroll cap removed, fold); M7 (title not docked: the cap runs under Close); M8 (the harness without `update_project_labels`, instrument); M9 (parameter names unclipped → Textual hard clip, AT-15); M10 (Parameter column fixed, AT-16); M11 (Builder cards fixed at 24, AT-16); M12 (lane cards for a fixed 96-cell viewport, AT-16); M13 / M14 (Check / Patch panel `overflow-y: hidden`, AT-24); M16 (a 300-cell Flow Execution ribbon, AT-15 and AT-24). **Survived, M6** (the dialog's own `max-height: 100%` raised): an **equivalent** mutant. The ModalScreen already bounds the dialog: with the rule removed, the measured geometry is identical. The rule was therefore **deleted** from `styles.tcss`, and M6b now mutates the cap that acts. **Survived, M15** (a `.ce-hint` allowed to wrap): AT-15's widest values do not make the hint overflow at 118 or 160, so the AT cannot see it. That clause belongs to TC-B97-37's status-line arm, which killed M24 at Inc-3 **Fix round: 7 arms, 7 KILLED** (`mutations-r2.txt`: M5, M6b, M7, M17 ×2, M18, M19) |

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `race_probe.py` / the harness node | HEAD's harness, the app idle before `run_before` | `(none)  \|  (none)` ×3 (`red.txt`) |
| `_dim` over the Diff tokens | HEAD after a height-only resize | 4 stale maps (`red.txt`) |
| `help_probe.py` / the help node | HEAD's dialog | regions off-screen, unpainted lines (`red.txt`) |
| `_hard_clipped_cells`, `clipped_overflow`, `_wrapped_rows` (AT) | M9; `51ee191`; M16 | cells hard-clipped; `check_apply_ghost` / `fx_ribbon` off the panel (`mutations.txt`, `red-at.txt`) |
| `svg_rows_diff.py` / `snapshot_reconcile.py` | the committed baselines against the regenerated ones | 29 / 29 cells differ; the old Footer row found in 29 / 29 |
| the parity probe | the 2 map baselines written under NO_COLOR | 2 failed (`snapshot-env-parity.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 6 instruments, each shown failing on a known-bad input |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | Each claim is read from what the app paints or emits, never from the code that produces it. The key bar's dim state is read as painted colour (`_dim` over the compositor strips). The help modal is read as painted rows while it is scrolled by key. The export cues are read as the button's painted row, the stats `render()` and the notify payload. The ATs read painted rows, widget regions and DataTable cell text against the column width. The snapshot cells are the emitted SVGs, compared row by row against the committed ones |

### Evidence files

All paths are under `.dev-flow/2026-10-19-batch-97/evidence/inc-7/`.

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED on HEAD (9 failed / 1 passed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/red.txt` | `b4573cd8aae1234e2768ef08b076fc459c49a48a0b74753794406520912b6e69` |
| RED re-run, clean HEAD worktree | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/red-rerun.txt` | `945018c94a6194f0021f2e14417c79c59be0ee0464fd2aa9cdd496713cff67fa` |
| AT RED on `51ee191` (4 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/red-at.txt` | `6925e2e7b38a815c5ec3c5af2b2167c83033a988c7b9fce72a0b3d7ab00b319d` |
| Gate file list (26) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/gate-files.txt` | `41c4c69e82111abf2c1386d90e773610e8088eaa72235fa334e8590db3482d88` |
| GREEN gate (1153 passed / 5 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/green.txt` | `c638915c31b85d58eda2410dd2dbdf2ae7742708ea454f3478a5072cfec9f75f` |
| Non-baseline re-runs | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/rerun-nonbaseline.txt` | `f886d53473e19e9b8acad36a6e5ce9f2d3302706f04ba24dc2f06fec72db947b` |
| Mutations (16 mutants) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/mutations.txt` | `ec7eba0b3ea56037ef4d3bd656827f65496e06204b463e189b37781030119d54` |
| Mutations fold (M6b, M7) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/mutations-fold.txt` | `44c2efe29100cf844dc3c9926452f53b3831d325b3414200b9ed77a579d0fc42` |
| Mutation script (fix round: M17–M19 added) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/mutate.py` | `eed3cf3e9d1e500334b08546c1c305ab50fb478fa120fc55117c011c34d873ff` |
| Snapshot env parity | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/snapshot-env-parity.txt` | `d7a405653bcc23cf35767ec8e9d656fd9e6b2c2a16ee9a1397c8cf5f32fd533a` |
| Snapshot before (29 xfailed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/snapshot-before.txt` | `2b2387faf94aef7e64f8cccd9a0ba7f70b8d5d90758624e9b2822595d75b26c5` |
| Snapshot regen | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/snapshot-regen.txt` | `2ff5b1c0a319a83e501e1805bf9ad3bfa2587ed48d46c9548efe095a04baf2fe` |
| Snapshot cell row diff | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/snapshot-cells-diff.txt` | `d7be11f6ba753413e0f462bbe8687de7922769cb965292feabfd5e7bdf23634e` |
| Snapshot reconciliation | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/snapshot-reconcile.txt` | `e73c02994edbab4b7ec4f4f28ad042ccd264f7d1523bfdbec58810febd77eb3b` |
| Snapshot after (33 passed ×2) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/snapshot-after.txt` | `88fbb58f031ecaac6f4aca2c02e01dd76035d046dcce059d9a91a72ec38777dd` |
| Row-diff script | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/svg_rows_diff.py` | `729ab071ebb037257db8eb46b20cc81976954b1dfebbe367d1c21191009a70ed` |
| Reconcile script | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/snapshot_reconcile.py` | `2578ae43a76a98e5cb060fb0e9fec803a140cbf69dcc401b60716fc3b4beece5` |
| Race probe | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/race_probe.py` | `ab513e63a31877739ca9b6897989e11306709c2015eecac20bdbfda27de5a907` |
| Help probe | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/help_probe.py` | `4c94ef6c70d6be598bd952193d7b3c2589c66c2b10fd83e788bac2dce4ae605e` |
| WT Split / Join / Export (`EXPORT  e`) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.split_join.png` | `6403f98bac8cde793a1b0c8d922a75e6652d02b590153b6fa0c57812d135f97f` |
| WT Patch help, top, 118x54 | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.help-patch.png` | `5b55eae00714acbce0dc27acd853c2ec5451af116b455c99cacdad0560a7f7d0` |
| WT Patch help, scrolled to the keys block | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.help-patch-end.png` | `73fca7a479f920e9f7e7a8d4b6671372f9a183300c9bddcef1debfb6230b33b6` |
| WT Patch help, 80x24 | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.help-patch.80x24.png` | `3ad569a069773b0a026ae4bec837cd650ea19979d4f0621280fa7088debb8a86` |
| WT Map help (fits: auto height kept) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.help-map.png` | `a11dbd882a0f1eddee5fd6018cf43961f2aca324ef1b38112a9f4d07c11ec0b2` |
| Fix-round RED (5 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/red-r2.txt` | `925d4045169229d737eeb0f31bec3495434decb97ffcd10a2c3fca0f577c460e` |
| Fix-round gate file list (9) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/gate-files-r2.txt` | `d39a8f7a832dd40abdc42c6bcb90ee5f79c4e5519511b2515e55299fd094a7d7` |
| Fix-round GREEN (437 passed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/green-r2.txt` | `a41e788e25352cc1e8b9dd1df5808a4372a970e54c4284a04cdf8a5f1a337336` |
| Fix-round mutations (7 / 7 killed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/mutations-r2.txt` | `b6b69336101efb9b7f6358b8010d3ddeb3ed5077d8aba88ec697e88d6453ad68` |
| WT Patch help, top, 118x54 (fix round) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.r2.help-patch.png` | `7d8551da6c1c09d5dc120a85b17a4a41056c304fccbaa6f4009c5fb807c9f3ca` |
| WT Patch help after pagedown, no tab, 118x54 | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.r2.help-patch-pgdn.png` | `2f5b80594be00645086e8b9dfce4563df02de7df42728f74e0100390eda019ab` |
| WT Patch help, top, 80x24 (fix round) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.r2.help-patch.80x24.png` | `2fcbb39915a79ee19ea99ba6cf83661f0e1659a6449cab59c9a08c1d5dc83b82` |
| WT Patch help after pagedown, no tab, 80x24 | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.r2.help-patch-pgdn.80x24.png` | `da1991fc4d3062116813008ee092c8cf9c40a51f9795a3195565e048513b3e27` |
| WT Patch help at its end (blank row, focus tint) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/png/impl.inc7.r2.help-patch-end.png` | `742ad63035d41d8150c69fd00ca40745f2b5e0f33018ef0edbfe120b408f972b` |
| Full suite (11 failed / 3617 passed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/suite-full.txt` | `d0a5813f491c6759f3bf30fccf3d1b030e54c35ea954ff746272521f2bd3a05e` |
| Non-baseline nodes re-run | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/suite-nonbaseline-rerun.txt` | `aa29377d5a2b0725415ccb6b36a34d61dea2c30610c6f4a18f6bc3c475d92563` |
| Post-suite test fixes | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/post-suite-fix.txt` | `b2fb4d63663cd26078197a0f0af06147f707e813b7a673f2f65ce4e20bc21d82` |
| First-round partial suite (stopped) | `.dev-flow/2026-10-19-batch-97/evidence/inc-7/suite-full-partial-r1.txt` | `f7276b31743bd79bd4e5278c0ac9dae91141c8aba6bc83d29076498f533d9704` |

| Field | Value |
|---|---|
| **Evidence files** | The transcripts, scripts and WT captures above (the four full-suite rows added after the fix round), each with its SHA-256. The validator brief (`validate-brief.txt`) is rewritten by every validator run, so it carries no digest. The captures are real Windows Terminal in truecolor (NO_COLOR removed, `SetProcessDPIAware`), taken one window at a time, each window closed (0 `KB-*` windows left). The Diff change has no capture: it shows only across a resize |

**Final source digests:** `window_help.py dabdc14b…`, `styles.tcss ddcd55db…`, `screens_directionb.py d7d9eba4…`, `segment_split_view.py 910ec87e…`. The gate, the fold mutants and the captures ran on these.

The first mutation battery ran on `styles.tcss a566a9f6…`, before the redundant dialog rule was deleted. Its two CSS arms were re-run on the final sheet: M6 as M6b, and M7.

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | Yes, in five places: 0 `^E` left in `segment_split_view.py` (grep: 0); 0 stale Diff tokens after a regime switch (the four height arms and the width arm); 0 help dialogs off-screen over the 12 sections × 3 sizes; 0 hard-clipped cells, overflowing descendants or wrapped rows over the four screens (AT-15); 0 xfail and 0 xpass in the snapshot module |
| What made the search wide enough | every `WINDOW_HELP_SECTIONS` key at 80x24, 118x54 and 220x60; every displayed DataTable cell of each screen; all 29 cells |
| Positive control | M2–M5, M9, M16; `red.txt` |

### Reverse census — trigger family B, and A3

| Probe | Result |
|---|---|
| B1a: tests reaching `styles.tcss`, `window_help`, `WindowHelpScreen`, `AbDiffPanel` / `apply_regime` / `refresh_bindings`, `SplitJoinWindow` / `sje_export`, `_build_loaded_triple`, the key bar | 26 files (`gate-files.txt`), all in the gate set |
| B1b: removed symbols | none removed. Only `^E` strings changed. `#window_help_dialog`'s children were re-parented under `#window_help_scroll`, and no test queries the direct child |
| B1c: hex sweep | no hex added to Python or TCSS |
| B2 · B3 | no file moved; 29 snapshot baselines regenerated and reconciled (above) |
| A3 | no frozen interface touched: I-10 / I-11 unchanged; `section_body_text` unchanged (TC-707 GREEN) |

| Field | Value |
|---|---|
| **Reverse census** | B1a: 26 files, 0 red beyond the baseline, the flake and Inc-9's registry bound. B1b–B1c clean. B3: 29 cells regenerated and reconciled. A3: none |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | **`^E` cues:** 5 painted strings (button, ready, guard ×2, toast) and 5 docstring / comment mentions, enumerated by grep before the edit; 10 corrected, 0 left. `REQUIREMENTS.md` keeps 3 mentions (HLR-135, LLR-135.1, LLR-135.5), recorded for the close-time sync (LED-…97.43). **Help dialogs off-screen:** 4 at 118x54 (Patch, Check, Flow, FlowExec) and 12 at 80x24 (`help_probe.py`); 0 after. **Snapshot drift marks:** 1 live mark (`_batch94_inc001_drift_marks`), retired |

### Signed-balance test ledger

- **Balance:** `post = base − 0 deleted + 14 added`. The 14 are AT-B97-15 ×2, AT-B97-16, AT-B97-24, the Diff arms ×5, the export node, the help node ×3 and the harness node.
- **Rewritten in place:**
  - the snapshot harness (one line);
  - `_batch94_inc001_drift_marks` (retired);
  - `EXPECTED_SCANNED_TEST_FILES` 198 → 199 (Inc-9's module, measured).
- **Regenerated:** 29 SVG baselines.
- **No new test module.**

### Full suite (orchestrator, after the fix round)

- **Run** (`evidence/inc-7/suite-full.txt`, on the r2 source digests in its header): **11 failed, 3617 passed, 3 skipped, 3 xfailed** (2:18:54). The first-round partial run, stopped when the fix round began, is kept as `suite-full-partial-r1.txt`.
- **Against `baseline-pytest-51ee191.txt`** (`comm -23` on sorted FAILED node ids): 6 failures are baseline nodes; 4 baseline nodes now pass; 5 are new.
- **The 5 new nodes, re-run in isolation twice** (`suite-nonbaseline-rerun.txt`):
  - `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` — **real, this increment**: `_show` in `test_b97_width.py` passed `AT_SCREENS[key][0]` (a Subscript) to `query_one`. Fixed by binding the selector to a name first (test file only).
  - `test_window_usage_help.py::test_help_modal_scrolls_by_key_while_close_keeps_the_focus` — **real, this increment, test timing**: under full-suite load `end` was read at 92 of 150, because two consecutive equal reads ended the wait before the scroll animation finished. Fixed with `_scroll_at_rest` (waits for `animator.is_being_animated` to clear and `scroll_y == scroll_target_y`), used by both help tests and the tab arm.
  - `test_tui_patch_editor_v2.py::test_at068b_per_entry_json_popup_edits_only_selected_entry` (passed run 1, failed run 2), `test_verify_quiet_pass_on_faithful_hex_save` and `test_before_after_report.py::test_at_061a_…` (passed both runs) — **pre-existing flakes**, already recorded in `evidence/inc-1/flake-probe.txt` and `evidence/inc-4/rerun-nonbaseline-suite.txt`.
- **After the two fixes** (`post-suite-fix.txt`): the help tests 3 × 5 passed run in parallel to load the box, then 5 passed alone; census + AT-B97-15/-16/-24 27 passed; TC-B97-59 12 passed. The full suite was not run a second time for two test-only edits.


## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — OK to advance, 4 LOW (CR-F1–F4); all folded in §1c except `styles.tcss:2375` (byte-equal prefix guard) and the optional AT-16 / AT-24 mutants · `ux-reviewer` — changes needed (UX-F1–F4), folded in §1c. · fix round re-walked: `ux-reviewer` — OK to advance (F1, F3, F4 resolved on the r2 captures and tests; F2 inspected, not exercised; 2 LOW: about 5 body lines visible at 80x24, scroll keys hinted only by the scrollbar); `code-reviewer` did not re-read the fix round |

## 5 · Risks

- **Local snapshot regen (D17 deviation).** The parity probe covers this machine and Textual 8.2.8. A different CI font or tooling version could still drift. The CI workflow is the second opinion (§*For the operator* item 1).
- **Snapshot cells as an oracle.** Each cell now pins the whole two-row bar and the 12-entry rail. Any later label edit in the bar re-drifts all 29 cells. That is expected.
- **Help scroll by key.** The body is reached by `tab` from Close; `pagedown` then scrolls it. Mouse-wheel scrolling was not tested.
- **`refresh_bindings()` per regime switch.** It runs only when the regime changes, which is rare. On every switch it repaints both bar rows.
- **Pre-existing flake** `test_tc024_report_trigger_surfaces_paths`: 1 of 5 runs here, unchanged from Inc-8.
- **The keys block sits directly under the last step,** with no blank row between them (capture `help-patch-end`). This is Inc-8's layout; it is recorded, not changed.

## 6 · Pending items / spec deviations

1. **D17 deviation:** a local regen instead of the CI regen after the push (LED-…97.45). Optional: a CI containment run on the pushed branch.
2. **Not done: the review-page rebuild** (`prototypes/b94_polish/build_html.py`, PLAN item 8). It was outside the orchestrator's brief, so it is routed to the close or the backlog.
3. **Sync at close:** the `^E` wording of `REQUIREMENTS.md`'s HLR-135, LLR-135.1 and LLR-135.5 (LED-…97.43).
4. **To commit:** `.dev-flow/_derived/ATLAS-*.md` (validator V20) and the 29 SVGs. The harness change in `prototypes/keybar/run_keybar.py` is untracked, like Inc-8's.
5. **AT readings recorded** in LED-…97.45:
   - how "clipped without ellipsis" is read;
   - the void clause runs at 220 and 260 only;
   - the Builder's 3 separator rows are excepted from the blank-row clause;
   - the `tab` walk starts at the help chip.
6. **Gate failures not caused by Inc-7:** AT-B78-03, AT-B78-32 and AT-056e (baseline); tc024 (a flake). The registry bound was Inc-9's; it is bumped here.
7. **Full suite:** owed (orchestrator).
8. **Fix round, skipped (CR-F4's optional half):** no blank-row / no-write mutants for AT-16 / AT-24. `styles.tcss:2375`'s `^E` comment stays inside the byte-equal prefix (CR-F2), for the close.

## 7 · Suggested next task

1. The Inc-7 gate: `code-reviewer` and `ux-reviewer`.
2. ~~The orchestrator's full suite.~~ Done (§4, *Full suite*).
3. The batch close: `05-close.md`, the `REQUIREMENTS.md` sync, and an optional `snapshot-regen.yml` containment run.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files | all | ✓ | 4 / 4 (§2); `segment_split_view.py` is outside the design's fix set, but the orchestrator's scope names it |
| 2 | Tests written in this same increment | all | ✓ | 14 new nodes, 2 rewritten (§4) |
| 3 | Layer 0 where the criterion applies | `core` · `full` | ✓ | n/a: no new pure function; the existing layer-0 arms re-ran |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red.txt` 9; `red-rerun.txt` 8; `red-at.txt` 4 |
| 5 | Reverse census declared | `core` · `full` | ✓ | §4 reverse census |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b: OK to advance (4 LOW, folded) |
| 7 | No file from another lane touched | all | ✓ | one lane |
| 8 | Frozen interfaces untouched | all | ✓ | I-10 / I-11 and `section_body_text` unchanged |
| 9 | Coverage claims verified on disk | all | ✓ | `green.txt`: every failure classified (3 baseline, 1 flake, 1 Inc-9 bound bumped) |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 |
| 11 | Mutation verdicts per arm | all | ✓ | 17 arms: 15 / 2 / 0 (M6 equivalent, rule deleted; M15 owned by TC-B97-37); fold 2 / 0 / 0 |
| 12 | Instrument RED-proof | all | ✓ | 6 instruments |
| 13 | Correction population | all | ✓ | 10 `^E`; 4 + 12 dialogs; 1 mark |
| 14 | Emitted-form assertion | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b: `code-reviewer`, `ux-reviewer` (fix round §1c re-walked by `ux-reviewer`) |
| 16 | Evidence files with digests | all | ✓ | §4 |

**Evidence checklist (software-dev).**
- ✓ **Tests:** the gate set ran 1153 passed and 5 classified failures (`green.txt`); the full suite ran after the fix round (§4, *Full suite*): no new failure left unclassified; two test-timing/convention failures of this increment fixed.
- ✓ **No secrets** in code or output.
- ✓ **No destructive commands:** only the scratch worktrees and the agent's own `__pycache__` were removed; no reset, no push.
- ✓ **File count** 4 / 4.
- ✓ **Review packet:** this file.
