# Increment 004 — HLR-166 / LLR-166.1–166.2 · `The focus lands where you can work (CW-U-2)`

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development
> language — the **prose**, and never a label. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`. The normative RULES below are
> language-independent.

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `004` |
| Lane (if the batch forked) | `main` · `s19_app/tui/app.py` (1 SOURCE file) |
| Requirement(s) | `HLR-166 / LLR-166.1 · LLR-166.2` |
| Acceptance | `AT-B100-04` · white-box `TC-B100-12 · TC-B100-13` |
| Agent | `software-dev` |
| Implementer | Kimi (corrected at close) |
| Date | `2026-10-27` |

---

## 1 · What changed

BLUF: after a load the keyboard focus now lands on the displayed window's focus
target — a named, visible, non-text, **focusable** widget, except on the Map
window, where batch-77 LLR-116.5's auto-selected region row remains the
landing (LED .58 (a), amended by LED .59: that row needs no exemption) — instead of dying on the hidden Split/Join table. `S19TuiApp` carries a per-window **focus-target
table** (`_FOCUS_TARGETS`), declared per window and asserted 1:1 against the
window registry (`SCREEN_CONTAINER_IDS` plus the palette-only Split / Join /
Export window) by TC-B100-12: exactly one target per window, unique ids, **every
target focusable** (`can_focus` — `Screen.set_focus` silently ignores a
non-focusable widget, which is how the first pass left P-16 alive on the Diff
window), and no target naming an `Input` / `TextArea`. The two load tails
re-home the focus: `_step_finalize` (the tail every image install drains
through — Load file, Load project and the Workarea Files pick all funnel into
`_apply_loaded_file`) and the A2L load tail of `load_a2l_from_path`
(LLR-166.2). The rule (LLR-166.1 as gated by LED .57 / LED .58): when the
focused widget **has region area 0**, or **sits in a window that is not displayed**, the
focus moves to the active window's target; a healthy focus is left untouched
(a *visible* Find field keeps its focus and its typed text — LED .58 (c)); a
text input in the persistent chrome (the command palette's `#palette_input`)
is **never** taken — it is where the operator is typing. **No widget type is
exempt from the stale rule** (LED .59, amending LED .58 (a)): the row LLR-116.5
auto-selects in the *displayed* Map window paints a region, so the generic rule
already leaves it alone and it stays the Map landing and the up/down walk's
keyboard subject (HLR-115); a row left holding the focus in a *hidden* Map
window (area 0, still swallowing `up` / `down` / `enter`) is re-homed like any
other stale widget (round-3 finding R3-1, TC-B100-12
`hidden_map_row_is_rehomed`). The separate `Input` / `TextArea` branch is gone:
it repeated the generic stale rule exactly (mutant R2 survived because of it),
and LED .58 (c) holds through the generic rule.

Four facts carry the design. **The Diff and Map targets are focusable widgets**
(LED .57 (a)): Diff names `#diff_compare_button` (always painted, never
disabled, in no hidden regime column); Map names the panel itself,
`#memory_map_panel`, with `can_focus` declared at the `_compose_screen_map`
compose site — the panel is the declared target and the empty-state/fallback
landing, while the post-load landing on Map is LLR-116.5's auto-selected
region row (LED .58 (a)) — an id-less widget, which HLR-166's "named widget"
ledger line covers with "the selected region row". **The empty-state
fallback** (LED .57 (b), widened by R2-4): a declared target that is painted
but cannot take the focus (zero area, or not focusable) lands the focus on
the window's first visible, focusable, non-text widget, else the rail's
`-active` entry — never on an invisible widget. **The rule judges
`default_screen.focused`** (LED
.57 (d)): a widget inside an open modal is never judged or moved — the modal
keeps its focus, and a bad default-screen focus is re-homed behind it. **The
re-home lands synchronously** (`Screen.set_focus`, not `Widget.focus()`):
Textual's `Widget.focus()` only queues a `call_later`, and the callbacks
queued behind the tail would override the queued focus in order; the
synchronous arm of TC-B100-12 (`rehome_lands_synchronously`) pins the
difference — mutant R5, which swaps in `target.focus()`, goes RED on it.

The fix-pass-1 deferred re-assertion (`_reassert_focus_target`) is **gone**
(LED .58 (b)): it re-landed any id-less focus one frame after the tail, which
overrode LLR-116.5's auto-selected row and silenced the Map window's arrow
keys after every load (round-2 finding R2-1, executed by the reviewer's map
arrow probe on three trees). The tail itself lands the panel on Map; the
panel's selection-follow hook runs after the tail and moves the focus onto
the resolved row; the walk works. The interaction needs no re-assertion —
no exemption for a `RegionRow` either (LED .59): a displayed row is healthy
under the generic rule and a hidden one is stale.

The user-visible outcome: after a file load, a project load, a Workarea Files
pick or an A2L load, pressing `p` opens the Load project dialog, `k` opens the
Legend and `t` opens the report viewer — from **whichever of the 13 windows**
is displayed; while the Split / Join / Export window is displayed its table
keeps the focus and keeps owning its own single keys (`p` pads there,
LLR-135); on the Map window the focus is on the auto-selected region row and
`down` walks the regions (HLR-115).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | HLR-166 · LLR-166.1 · LLR-166.2 | `_FOCUS_TARGETS` (the per-window table, 13 windows; Diff → `#diff_compare_button`, Map → `#memory_map_panel`), `_WINDOW_CONTAINER_IDS` (derived frozenset, the C-40 completeness argument), `_focus_needs_rehome` (generic stale rule only — area 0; hidden window; no widget type exempt — LED .59: the `RegionRow` guard and the `Input` / `TextArea` branch are both removed), `_fallback_focus_target` (LED .57 (b): first visible focusable non-text widget, else the rail's `-active` entry), `_resolve_focus_target` (target + fallback when not focusable or zero-area — R2-4), `_rehome_focus_after_load` (reads `default_screen.focused`; synchronous `Screen.set_focus`; `None` focus re-homes like a violation; unmounted tree = documented no-op); `can_focus = True` on the map panel at the `_compose_screen_map` compose site; one call in the load tail `_step_finalize` and one in the A2L load tail of `load_a2l_from_path`; `from textual.widget import Widget` import; **Fix pass 2 (LED .58):** the fix-pass-1 `_reassert_focus_target` and its `call_after_refresh` scheduling are deleted. **Round 3 (LED .59):** the `Input` / `TextArea` branch and the `RegionRow` exemption (with its now-unused `RegionRow` import) are deleted |
| `tests/test_b100_focus.py` | test | HLR-166 · LLR-166.1 · LLR-166.2 | TC-B100-12 (17 functions / 28 nodes: registry census with the focusability assertion · Load file tail · Load project tail · Workarea Files pick · re-home lands on the ACTIVE window's target · Split/Join displayed boundary · every-window load arm parametrized over the 12 registry windows — `map` pins LLR-116.5's row landing · Map load keeps the region row and `down` walks it (LED .58 (a)) · **hidden Map row is re-homed — `hidden_map_row_is_rehomed`, new in round 3 (LED .59, R3-1)** · healthy focus not moved · STALE text input re-homed (LED .58 (c)) · VISIBLE Find input keeps its focus (LED .58 (c)) · empty-state fallback · palette input never taken · modal keeps its focus · bad default focus re-homed behind a modal · synchronous landing), TC-B100-13 (2 arms), AT-B100-04 (2 parametrized size arms) — 32 nodes |
| `tests/test_id_registry.py` | config | HLR-166 (registry hygiene) | `EXPECTED_SCANNED_TEST_FILES` 217 → 218 (round 1: one new scanned file; unchanged in fix pass 1) |

| Count | Value |
|---|---|
| **SOURCE files** | **1 / 4** |
| Test files | 2 (the module + the registry bump from round 1; round 3 adds one function to the module) |
| Doc files | 0 (outside the count) |

---

## 3 · How to test

```bash
# interpreter: <HOME>/anaconda3/envs/s19env/python.exe
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<this worktree>
unset NO_COLOR
python -m pytest -q -p no:cacheprovider tests/test_b100_focus.py
python -m pytest -q -p no:cacheprovider tests/test_b100_focus.py -k tc_b100_12   # LLR-166.1
python -m pytest -q -p no:cacheprovider tests/test_b100_focus.py -k tc_b100_13   # LLR-166.2
python -m pytest -q -p no:cacheprovider tests/test_b100_focus.py -k at_b100_04   # HLR-166 black-box
```

---

## 4 · Test results

Final tree: `s19_app/tui/app.py` sha256 `7168c1c9fb37033131abd91157bc19fbaba4406ab0fc3c17b48c72999be9ff2a` (read-only `sha256sum` at packet time; the 12-char form `7168c1c9fb37` is in the `green-21`, `green-22`, `orch-guards-final` and `orch-guards-census-final` headers). Every transcript is cited by its repo path under `.dev-flow/2026-10-26-batch-100/evidence/inc-4/`.

**Which tree each result ran on.** The tree moved twice after the fix-pass-2 closing pass, both times by deleting code (nothing added):

| Tree (app.py sha256, 12 chars) | What it is | Ran on it |
|---|---|---|
| `77bb9aa6eae8` | fix-pass-2 closing tree | the whole mutant table below (`mut-fix2-*`), the reverse census (`reverse-census-fix2`), `green-14`, `guards`, `guards-census` |
| `79df3ae1c839` | `77bb9aa6` minus the `Input` / `TextArea` branch of `_focus_needs_rehome` (LED .59, orchestrator) | `green-20`, `orch-guards`, `orch-guards-census`, `red-07`; the reviewer's own mutants RG, RT, R1, R7 (round 3) |
| `7168c1c9fb37` | `79df3ae1` minus the `RegionRow` exemption and its import (LED .59, R3-1) — **FINAL** | `green-21`, `orch-guards-final`, `orch-guards-census-final`, `green-22` |

The mutant table and the reverse census were NOT re-run on the final tree; they ran on `77bb9aa6`. What changed since is two deletions: (1) the `Input` / `TextArea` branch, which the reviewer diffed against `77bb9aa6` and found equal to the generic tail; (2) the `RegionRow` exemption, which no test needed (RG survived 31/31). Both deletions were re-verified by the reviewer's own mutants RG / RT / R1 / R7 on `79df3ae1`, and on the final tree by `green-21` (focus module + `test_tui_app.py`), the new test's RED with the exemption (`red-07`) and the final guards / census runs. The carry-over of the other mutant verdicts is argued, not re-executed.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic >=3, or crosses a declared module boundary) | `core` · `full` | `test_tc_b100_12_focus_target_table_matches_the_window_registry` — the registry census (key-set equality both directions, unique ids, every target resolves, is focusable and is not an `Input`/`TextArea`) | 1 passed (inside the 32-node run) |
| **A · white-box** `TC-NNN` <-> LLR | `core` · `full` | `TC-B100-12` (28 nodes = 17 functions, one parametrized over the 12 registry windows: census · three load paths · active-window target · Split/Join boundary · every-window arm · Map keeps the region row and `down` walks it · **hidden Map row re-homed** · healthy focus · STALE text input re-homed · VISIBLE Find input keeps focus · empty-state fallback · palette input never taken · modal keeps focus · bad default behind a modal · synchronous landing) · `TC-B100-13` (2 nodes) | 30 passed |
| **B · black-box** `AT-NNN` <-> story, through the shipped surface | `core` · `full` | `AT-B100-04` at (118x54) and (220x60) | 2 passed |

The module now holds 32 nodes. On the FINAL tree `7168c1c9` the focus module together with `tests/test_tui_app.py` gives **94 passed, 1 xfailed in 254.41 s** (`.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-21-r3-final-focus-tuiapp.txt`); the transcript does not print the module's own count separately. The 31-node module (before the round-3 test) passed on `79df3ae1` (`green-20`: 31 passed in 212.91 s) and on `77bb9aa6` (`green-14`: 31 passed in 223.72 s). The base counterfactual (main `31eb572` archive, the 31-node module, PYTHONPATH and NO_COLOR in the header) fails 24 and passes 7 (`.dev-flow/2026-10-26-batch-100/evidence/inc-4/red-06-fix2-module-at-base.txt`); it was NOT re-captured for the 32nd node. The 7 survivors pin unchanged behaviour (see section 6).

### RED / GREEN / mutation rows

| Kind | Transcript | What ran | Result |
|---|---|---|---|
| RED (fix-2 arms on the fix-pass-1 tree) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/red-05-fix2-arms-on-fix1-tree.txt` | the 4 new/rewritten arms (`-k`) on the pre-fix-pass-2 tree | 3 failed, 12 passed, 16 deselected — `every_window[map]`, `map_load_keeps_the_region_row_and_down_walks_it`, `visible_find_input_keeps_its_focus` |
| RED (final module at base) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/red-06-fix2-module-at-base.txt` | `pytest tests/test_b100_focus.py` on `git archive 31eb572` + the final module | 24 failed, 7 passed in 272.92 s (replaces fix-pass-1 `red-04`) |
| GREEN (focus module, earlier fix-2 tree) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-11-fix2-focus-module.txt` | the module before the NoScreen guard was found | 31 passed in 234.12 s — superseded by `green-14` |
| GREEN (map tests, 21 files) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-12-fix2-map-tests.txt` | `grep -rln "RegionRow\|memory_map" tests/` | 1 failed, 708 passed, 1 xfailed in 1423.12 s — the failure (`test_tui_app.py::test_apply_prepared_load_chains_updates_via_call_later`) was the real NoScreen regression, fixed in `app.py` |
| GREEN (tui_app after the fix) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-13b-fix2-tui-app.txt` | `pytest tests/test_tui_app.py` | 62 passed, 1 xfailed in 37.46 s |
| (interrupted, no verdict) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-13-fix2-focus-module-final.txt` | a focus-module run cut off by the session drop | 12 dots, no summary line — NOT evidence; superseded by `green-14` |
| GREEN (focus module, closing-pass tree `77bb9aa6`) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-14-fix2-focus-module-final.txt` | `pytest tests/test_b100_focus.py` on the restored final `app.py` | 31 passed in 223.72 s |
| GREEN (whole-tree guards, final tree) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/guards.txt` | the six guard files | 75 passed + 29 snapshot cells passed in 151.83 s — no cell changed |
| GREEN (census sweep, final tree) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/guards-census.txt` | `pytest -k census tests` | 87 passed, 3815 deselected in 98.27 s |
| mutation F1-diff-old-target | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-F1_diff_old_target-full.txt` | Diff target reverted to `#ab_diff_panel` | KILLED — 2 failed, 29 passed (census arm, `every_window[diff]`) |
| mutation F1-map-unfocusable | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-F1_map_unfocusable-full.txt` | Map panel loses `can_focus` | KILLED — 1 failed, 30 passed (census arm only; LLR-116.5's hook heals the landing) |
| mutation K1 a2l-tail | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-K1_a2l_tail-full.txt` | re-home removed from the A2L tail (LLR-166.2) | KILLED — 5 failed, 26 passed |
| mutation K2 input-target | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-K2_input_target-full.txt` | table names `search_input` for `workspace` | KILLED — 11 failed, 20 passed |
| mutation K3 drop-mac | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-K3_drop_mac-full.txt` | `mac` dropped from the table | KILLED — 3 failed, 28 passed |
| mutation K4 finalize-tail | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-K4_finalize_tail-full.txt` | re-home removed from `_step_finalize` | KILLED — 18 failed, 13 passed |
| mutation LD self-focused | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-LD_self_focused-full.txt` | reads `self.focused` instead of `default_screen.focused` | KILLED — 1 failed, 30 passed (`bad_default_focus_is_rehomed_behind_a_modal`) |
| mutation R1 always-rehome | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-R1_always_rehome-full.txt` | healthy-focus early return deleted | KILLED — 4 failed, 27 passed (healthy focus, visible Find, palette input, modal) |
| mutation R7 none-no-rehome | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-R7_none_no_rehome-full.txt` | a `None` focus no longer re-homes | KILLED — 3 failed, 28 passed (`empty_state_target_falls_back` + both TC-B100-13 arms) |
| mutation FB no-fallback | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-FB_no_fallback-full.txt` | the R2-4 not-focusable/zero-area fallback block removed | KILLED — 1 failed, 30 passed (`empty_state_target_falls_back`) |
| mutation LC chrome-input-taken | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-LC_chrome_input_taken-full.txt` | text block's final `return False` -> `return True` (every non-stale input taken) | KILLED — 1 failed, 30 passed (`palette_input_is_never_taken`) |
| mutation R2 no-text-clause | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-R2_no_text_clause-full.txt` | the whole text-input block deleted (on `77bb9aa6`) | mutant subject removed (branch deleted, LED .59) — on `77bb9aa6` it SURVIVED, 31 passed in 209.37 s, because the block equalled the generic tail |
| mutation R5 widget-focus | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-R5_widget_focus-full.txt` | landing via `target.focus()` (queued) | KILLED — 3 failed, 28 passed (`rehome_lands_synchronously`, `every_window[map]`, the down-walk arm) |
| GREEN (focus module, tree `79df3ae1`, orchestrator) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-20-orch-focus-module.txt` | `pytest tests/test_b100_focus.py` after the `Input` / `TextArea` branch was removed | 31 passed in 212.91 s |
| GREEN (whole-tree guards, tree `79df3ae1`) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/orch-guards.txt` | the six guard files | 75 passed + 29 snapshots passed in 400.43 s |
| GREEN (census sweep, tree `79df3ae1`) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/orch-guards-census.txt` | `pytest tests -k census` | 87 passed, 3815 deselected in 176.71 s |
| RED (R3-1 hidden Map row, tree `79df3ae1`, exemption PRESENT) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/red-07-r3-1-hidden-map-row.txt` | `pytest tests/test_b100_focus.py -k hidden_map_row` | 1 failed, 31 deselected in 17.51 s — focus left on `RegionRow#None, region Region(x=0, y=0, width=0, height=0)` instead of `#files_list` |
| mutation RG (round 3; = the `red-07` tree) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/red-07-r3-1-hidden-map-row.txt` | the `RegionRow` exemption restored | KILLED by the new `hidden_map_row_is_rehomed` — 1 failed (`red-07`). Before that test existed RG SURVIVED the 31-node module (reviewer's run, 31 passed; `review-increment-004.md` Round 3) |
| GREEN (focus module + `test_tui_app.py`, FINAL tree `7168c1c9`) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-21-r3-final-focus-tuiapp.txt` | `pytest tests/test_b100_focus.py tests/test_tui_app.py` | 94 passed, 1 xfailed in 254.41 s |
| GREEN (whole-tree guards, FINAL tree) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/orch-guards-final.txt` | the six guard files | 75 passed + 29 snapshots passed in 139.43 s |
| GREEN (census sweep, FINAL tree) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/orch-guards-census-final.txt` | `pytest tests -k census` | 87 passed, 3816 deselected in 94.63 s |
| GREEN (map files, FINAL tree) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-22-r3-map-files.txt` | `pytest` over the focus module + 21 map/directionb test files (command in the transcript header) | 710 passed, 1 xfailed in 1443.60 s; 29 snapshots passed (no cell changed) |
| diagnosis tc_b97_55 (change vs base under load) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/tc-b97-55-diagnosis.txt` | 10 rounds, 20 CPU burners per round, 4 CHANGE + 4 BASE pytest at once, plus 5+5 forced-rehome runs on CHANGE | 40 base rc=0 / 40 change rc=0; forced `late_rehome` 5 rc=0; forced `stale_then_rehome` 5 rc=1 (focus moved to `#fx_panel`) — see Reverse census |
| GREEN (tc_b97_55 at base x5) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-19-tc-b97-55-at-base-x5.txt` | `pytest tests/test_b97_flow_execution.py -k tc_b97_55`, five repeats on a `31eb572` archive | 5 x "6 passed, 69 deselected" (28.34-29.32 s each) |
| GREEN/flakes (reverse census, LAST, tree `77bb9aa6`) | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/reverse-census-fix2.txt` | the 32 files of the symbol grep | 976 passed, 1 xfailed, 5 failed in 3314.66 s — see Reverse census |

**Mutant set on `77bb9aa6`: 13 rows (F1-diff, F1-map, K1, K2, K3, K4, LD, R1, R7, FB, LC, R2, R5). 12 KILLED, 1 SURVIVED (R2); R2's subject was removed afterwards (below).** Round 3 adds RG (killed by the new test, row above) and the reviewer's RT (fix-pass-1 Find rule restored: KILLED, 1 failed, `visible_find_input_keeps_its_focus`; reviewer's run on `79df3ae1`, recorded in `review-increment-004.md`, not a packet transcript). The reviewer also re-ran R1 (KILLED, 4) and R7 (KILLED, 3) on `79df3ae1`. RA (no deferred re-assertion) is dropped: the fix deleted `_reassert_focus_target`, so the mutant has no site. Every `mut-fix2-*` transcript ends `RESTORE OK 77bb9aa6eae8`; the four run in this closing pass had their patches parsed (`ast.parse`) and applied exactly once (count 1) before running, so none is a syntax-error "kill". `mut-*-full.txt` files without `fix2` are fix-pass-1 history against a different `app.py` and are not part of this verdict.

**R2 — mutant subject removed (LED .59).** On `77bb9aa6` the stale-only text-input block was identical to the generic tail that follows it, so deleting it could not change any outcome and no test could kill it (the equivalent survivor). The orchestrator deleted the branch (tree `79df3ae1`, ruling LED .59); R2 has no site any more. The reviewer diffed the removed branch against `77bb9aa6` and found it equal to the generic tail, and `green-20` (31 passed) holds on `79df3ae1`.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | base = `git archive 31eb572` + the 31-node `tests/test_b100_focus.py` (`red-06`); round 3: `RegionRow` exemption present vs the new test (`red-07`); fix-2 arms on the fix-1 tree (`red-05`); per-mutant exact-string patches on the final tree by `run_mutants.py` (patch applied once, hash-verified restore) |
| Instrument | project code, own hand via the scratch runner (kept OUTSIDE the evidence home), restore from a pristine byte-copy verified by SHA-256 |
| Where it ran | this worktree for the mutants; a `git archive 31eb572` tree under the session scratch dir for the base RED |
| Transcript | `.dev-flow/2026-10-26-batch-100/evidence/inc-4/red-06-fix2-module-at-base.txt` (24 failed, 7 passed) · `.dev-flow/2026-10-26-batch-100/evidence/inc-4/red-05-fix2-arms-on-fix1-tree.txt` (3 failed, 12 passed) |
| Restore proven by | `RESTORE OK 77bb9aa6eae8` in each `mut-fix2-*`, `app.py` sha re-checked before and after the run, and `green-14` / `guards*` / `reverse-census-fix2` all carry the restored sha in their headers |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1` in every run (C-46) |
| Arms resolved at baseline | 31 nodes at base — 24 failed / 7 passed |
| Verdict granularity | per node id, per transcript |
| Arms that stayed GREEN at base | seven, each pinning unchanged behaviour (section 6) |
| **Mutation verdicts** | `LLR-166.1` — table names an `Input` -> KILLED 11 · window dropped -> KILLED 3 · `_step_finalize` re-home removed -> KILLED 18 · healthy early return removed -> KILLED 4 · text-input block removed (R2) -> subject removed, LED .59 (was SURVIVED 0, equivalent, on `77bb9aa6`) · `RegionRow` exemption restored (RG) -> KILLED 1 (`red-07`) · landing queued via `Widget.focus()` -> KILLED 3 · `None` no longer re-homes -> KILLED 3 · fallback block removed -> KILLED 1 · chrome input taken -> KILLED 1 · `self.focused` read -> KILLED 1 · unfocusable Map target -> KILLED 1 · unfocusable Diff target -> KILLED 2. `LLR-166.2` — A2L-tail re-home removed -> KILLED 5 |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest tests/test_b100_focus.py` at base | the final module on `git archive 31eb572` | 24 failed — `red-06-fix2-module-at-base.txt` |
| the Map down-walk arm and `every_window[map]` | the fix-pass-1 tree (deferred re-assertion on the panel) | both failed, plus the visible-Find arm — `red-05-fix2-arms-on-fix1-tree.txt` |
| the hidden-Map-row arm | the `RegionRow` exemption restored (RG) | 1 failed — `red-07-r3-1-hidden-map-row.txt` |
| the registry census arm | K2, K3, F1-diff, F1-map | each failed — the respective `mut-fix2-*` |
| the load arms | K4, K1 | the three load paths / 12 window params / A2L arms failed — `mut-fix2-K4_finalize_tail-full.txt`, `mut-fix2-K1_a2l_tail-full.txt` |
| healthy / visible-Find / palette / modal arms | R1 | 4 failed — `mut-fix2-R1_always_rehome-full.txt` |
| empty-fallback arm | FB, R7 | `empty_state_target_falls_back` failed in both |
| palette arm | LC | `palette_input_is_never_taken` failed |
| synchronous arm | R5 | `rehome_lands_synchronously` failed |
| bad-default-modal arm | LD | failed — `mut-fix2-LD_self_focused-full.txt` |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 10 instrument groups, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the painted focus (Textual compositor) | `app.focused.id == target and app.focused.region.area > 0 and not isinstance(app.focused, (Input, TextArea))` after each load, observed until settled | every load arm landed on the window's target with a non-zero region — `green-14` |
| the durable file-state line | `#status_text` starts with `"Loaded "` after each load; `"A2L loaded:"` after each A2L load | observed in every arm — `green-14` |
| the screen stack after the single keys | `isinstance(app.screen, LoadProjectScreen)` after `p`, `isinstance(app.screen, LegendScreen)` after `k`, `isinstance(app.screen, ReportViewerScreen)` after `t` | each screen reached at (118, 54) and (220, 60) — `green-14` |
| the painted log tail | `"Loaded project 'P1'" in #log_line_4` after the project load | observed — `green-14` |
| the palette field while a load finishes | `app.focused.id == "palette_input" and palette_input.value == "Spl"` after the A2L tail, then `"Spli"` after pressing `i` | the focus and the typed text stay in the field — `green-14` |
| the modal's focus and the default screen's focus | `app.focused.id == "load_path"` and `app.default_screen.focused.id == "hex_scroll"` after an A2L tail under the Load file dialog | the modal keeps its focus; the default screen's healthy focus is not moved — `green-14` |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 6 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| green-07-tc330-isolation.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-07-tc330-isolation.txt | 3cbe80221bd0da28fbacdea31cef5c68a2c115f7a8f75ff026d482473a26055e |
| green-08-fix1-focus-module.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-08-fix1-focus-module.txt | 1b0e5949aac99776d1aee97e9a71343d772aea0183afad0fb047f7906d39e5e2 |
| green-09-reverse-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-09-reverse-census.txt | 37682ed984a944bf9ea5939206f1367acd834a71a5ea454628eacc27deb786d3 |
| green-10-census-flakes-isolation.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-10-census-flakes-isolation.txt | 617af14671bda29e372f17bf49b6b8a9cc6e1bed7be40d20f997ad3fec0bc65b |
| green-11-fix2-focus-module.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-11-fix2-focus-module.txt | 74c979b8eff4fff8aee62ef4e2e8632c08db61b806fa31279e903659f7d14c4f |
| green-12-fix2-map-tests.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-12-fix2-map-tests.txt | 9975678f39626aca963597b7fdda2cc3b17dd59a69942cdd1bb24f49ee117fbd |
| green-13-fix2-focus-module-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-13-fix2-focus-module-final.txt | bcfde2c2f59cc9a78696f79f6b5905b4bc37f147bdb28d827518d15c1bba2b1a |
| green-13b-fix2-tui-app.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-13b-fix2-tui-app.txt | b8c1c148886436ec57d379ef477eccc509f2adefdc3129ddbd8a506d5dff63f9 |
| green-14-fix2-focus-module-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-14-fix2-focus-module-final.txt | 99d8401149616ce8096ecf39fe2ee3bab7259fe01ce60af5c8d1f7d1c5388324 |
| green-15-fix2-census-flakes-isolation.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-15-fix2-census-flakes-isolation.txt | 6253be4e6321dd7a53f735737f5b144b08c82a8450ea90361ef89250399f5dea |
| green-16-fix2-at061a-isolation-and-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-16-fix2-at061a-isolation-and-base.txt | 206d0f1ae36cdf2eb478400a4c5f42547cbf0cd8344b5a8eb6d720d536248118 |
| green-17-fix2-at061a-flake-rate.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-17-fix2-at061a-flake-rate.txt | d8a730d4ed6c9924db6848130a36663df4a212809e379a1efe27c1263c31821b |
| green-18-fix2-tcb9755-isolation.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-18-fix2-tcb9755-isolation.txt | 7649695dcd1def5fd27a79ecc1d32b2e0066a23843df1a560476409f60b97551 |
| green-19-tc-b97-55-at-base-x5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-19-tc-b97-55-at-base-x5.txt | c207b10448cd5b441ceaa932e6b7c6ba2ca7e63cbf6409adff36af0238640f28 |
| green-20-orch-focus-module.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-20-orch-focus-module.txt | 8919f652fc78ea38dd0204ef807adbfa9f1fc8cd2773fb89d1ad51cfc3da97a6 |
| green-21-r3-final-focus-tuiapp.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-21-r3-final-focus-tuiapp.txt | 09b690b367704d36b256346ab410a355dfe25b7f5b405b836f8452a695f7ff07 |
| guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/guards-census.txt | 3bb8e7887953011ae51ae749f0ca673489f4dec8113c9a1dffcae9933e793f73 |
| guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/guards.txt | 016e2ad7c18f16245fc8ba7770d12fe5ce1d366241be83b9851c9caf2c43302c |
| import-proof.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/import-proof.txt | a9a6f2d4b429b69c682f0dee22add5f807a84a627fd4a6bb07976af34addc490 |
| mut-F1-diff-old-target-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-F1-diff-old-target-full.txt | 9b55ad7b07940d039e76dc26f4673e2eff09dd436aecd338f4a05105786edfdd |
| mut-F1-map-unfocusable-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-F1-map-unfocusable-full.txt | 1f3fe50db40a77d062f36e72a847a6af43ccf1328c23590538ac34a39b0fe5fd |
| mut-FB-no-fallback-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-FB-no-fallback-full.txt | 6145e74eeaa5008ad299b145854c18d3a8865890857f4f188274fb781902c172 |
| mut-fix2-F1_diff_old_target-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-F1_diff_old_target-full.txt | 18d82241cb1e7b21cb1dc5c07dfd4f731fca8dfb112b7b99d383db4ba3c4dad4 |
| mut-fix2-F1_map_unfocusable-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-F1_map_unfocusable-full.txt | 2a782f80c7bb285a758d1a2e4f058cc04b1ef876debf01b059c78bef98b9fdfd |
| mut-fix2-FB_no_fallback-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-FB_no_fallback-full.txt | e5be13f3a5b49b4ce406422020977d64f2b9913ac08af4162677a5d606224169 |
| mut-fix2-K1_a2l_tail-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-K1_a2l_tail-full.txt | 7b9678fc926626fb79b2d285095ce5e5fb7fe897d81323038b0dc22bc787e2cb |
| mut-fix2-K2_input_target-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-K2_input_target-full.txt | 4c4dd4d78fed29fd3f956fea11a630c9bf9e8f59c021e7816cc703d05bf1c93b |
| mut-fix2-K3_drop_mac-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-K3_drop_mac-full.txt | 806f315758c4bd7785587f70d4f7715138bb26cabf7881bedb66ad2c40c2cdd6 |
| mut-fix2-K4_finalize_tail-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-K4_finalize_tail-full.txt | 35dd25503f554c64745a2cd0ab245e05fad9adc223b3a759db537d864d955700 |
| mut-fix2-LC_chrome_input_taken-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-LC_chrome_input_taken-full.txt | e91bc2e1e984d936cd40cfd7dc82e60d8a6d3004bf5411b0108209a017805777 |
| mut-fix2-LD_self_focused-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-LD_self_focused-full.txt | c24f36182404c5581f88e03cea9ae9b0d4c7908fe33ef82b0912d28edec425e3 |
| mut-fix2-R1_always_rehome-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-R1_always_rehome-full.txt | 190653d17eec14c5873702f41bc6c80212af4f7e033e6b22fdf8163492e3e61d |
| mut-fix2-R2_no_text_clause-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-R2_no_text_clause-full.txt | 4fef0b64496983fb36b26f7cdc954e55e6afafd7d97c8217ac817972d6d0065c |
| mut-fix2-R5_widget_focus-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-R5_widget_focus-full.txt | e618b76f260fb1ee99c5d817020805f5dc08f83d887ef9424b64dfd06a944a59 |
| mut-fix2-R7_none_no_rehome-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-fix2-R7_none_no_rehome-full.txt | 999c5dad39ea2e9db8c2d0692f145d5b9d94e5b966276c1c3518a797981de5e6 |
| mut-K1-a2l-tail-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-K1-a2l-tail-full.txt | fd37fbcc6736402cd20df294ea6e86500b943509248f81baa2714f7200b7b745 |
| mut-K2-input-target-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-K2-input-target-full.txt | 4a213c8532f026299debae7b90087eb604713b642f2e9757766b39f1f205d9a9 |
| mut-K3-drop-mac-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-K3-drop-mac-full.txt | b82ceaac34c075114b65a0bb4a24f5b01ff8ce2a5beb0ca98d4859747f7b0781 |
| mut-K4-finalize-tail-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-K4-finalize-tail-full.txt | f45c96b8cc9ae78be97c0300ae2e434ff710a9ca21587ba4d1319b76bd375610 |
| mut-LC-chrome-input-taken-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-LC-chrome-input-taken-full.txt | 1537f266f248fee3080f998056e421d4da346cca2a2c24e0faf8c9d14f21a54e |
| mut-LD-self-focused-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-LD-self-focused-full.txt | b42ad404ee1256c33415d85a80ebd1cabf5a10c97a6180cd1a37fcfa234fd224 |
| mut-R1-always-rehome-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-R1-always-rehome-full.txt | ca988b2ad615383b51a157187df7d8964e4cff39100c68d5bd42938cfdebaa43 |
| mut-R2-no-text-clause-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-R2-no-text-clause-full.txt | de41d2caf11063b477eeb6c725cb6255e357e7d1bf883f9b27c9f2cd5888ba4c |
| mut-R5-widget-focus-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-R5-widget-focus-full.txt | daed1c849b6da7a72c2ea302b791089a58bc017ba6973fe756eddb3c53e4e793 |
| mut-R7-none-no-rehome-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-R7-none-no-rehome-full.txt | 14afbc025c9d91147a602837a3d974e348fe0772a58465d6552a01758529f53b |
| mut-RA-no-reassert-full.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/mut-RA-no-reassert-full.txt | 282f7ef1898907f38e5cac8203210975d7a4605eb36f6f3c9b229f52d3bcedad |
| orch-guards-census-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/orch-guards-census-final.txt | 0a35dadd7f871e01d7c0b686c4abb14786d70c2ea1ae060a19cdad1390df7703 |
| green-22-r3-map-files.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/green-22-r3-map-files.txt | 01971662173a8f828f5ff0d6cf8560473a032d5a6eba2fc207a830393c50f2e5 |
| orch-guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/orch-guards-census.txt | 3fdd3687e897a4921ffdcf854bed98d6aa169ff05e08b075d077c460ac8c0ec1 |
| orch-guards-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/orch-guards-final.txt | 2ab9c74d64b180e3910cee5ebd5b41cfbdace1306e1322d32edb3109d4f65c4f |
| orch-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/orch-guards.txt | ab27e5721fcfd47b395dc6ccf36a9220d171c1fc4b3d5517b9fd40d3cd9db2a5 |
| red-01-focus-module.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/red-01-focus-module.txt | b8c87286907ff5c6bcc420cc78aeb6282fc6a47e809734ba412cf31b6de44dd1 |
| red-02-focus-module.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/red-02-focus-module.txt | 5d3146daf379d47f2a869ac9ebdf46393cdfb9d5e9c26f5e9006fe8982ed6aa7 |
| red-03-census-failures-at-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/red-03-census-failures-at-base.txt | f1795b720741a360833ed1744595059763ccf6544ba73f1fa2de1d57506d7a9b |
| red-04-fix1-module-at-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/red-04-fix1-module-at-base.txt | 798dd92c5b7405d53bed4cc7d593247586c9905a90c4e5f8e07031816c64480a |
| red-05-fix2-arms-on-fix1-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/red-05-fix2-arms-on-fix1-tree.txt | 462a856d1f965116e7b1a37a3553a92e1a0c93f87b43107f12d09b6da64a5c5c |
| red-06-fix2-module-at-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/red-06-fix2-module-at-base.txt | 34d9b88a2448a63edf277cc58cfd03484457b49c61025af71689225df9ef1e76 |
| red-07-r3-1-hidden-map-row.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/red-07-r3-1-hidden-map-row.txt | 91f43efc0bf500fa885251f281d172e33b26fed4e2b4a9a286a5c1c3485d8e50 |
| reverse-census-files.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/reverse-census-files.txt | 23183e15560aeab7fa71ec80b6777b8f4ebd10a4a4a156826028de5fa8a47675 |
| reverse-census-fix2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/reverse-census-fix2.txt | 1493a4e760a5b73f0594da5eb08c703a59ecf98a580c7c3a2814a52bebcd6f32 |
| tc-b97-55-diagnosis.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-4/tc-b97-55-diagnosis.txt | 5a48e41554052bb847e17bd66673f0bb8c491172629ec284929610102285b54b |

| Field | Value |
|---|---|
| **Evidence files** | `61 artifact(s), each at the declared home, with the digest of its bytes on disk` — 51 from the fix-pass-2 closing pass + 10 added in round 3; `green-22-r3-map-files.txt` added by the orchestrator (61 rows) (fix-pass-1 history transcripts — `red-04`, `green-08`, `mut-*-full` without `fix2` — kept, not part of the fix-pass-2 verdict) |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | Yes — one: the registry census asserts the table holds no `Input` / `TextArea` target. That is an ABSENCE claim over the table's value set. |
| If the result is an ABSENCE, what made the search wide enough | the census iterates every entry of `_FOCUS_TARGETS` (itself key-censused against the registry) and isinstance-checks the resolved widget — no hand-listed id set |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b100_12_focus_target_table_matches_the_window_registry` — its docstring says the census is the LLR-166.1 derivation conclusion (one focusable, non-text target per window), not a behaviour pin |
| Conjunctive criteria: one mutation per conjunct | the table's conjuncts each carry their own mutant: completeness vs the registry (`K3-drop-mac`), non-text targets (`K2-input-target`), focusable targets (`F1-map-unfocusable`, `F1-diff-old-target`); the re-home conditions carry the behavioural arms (`R1`, `R5`, `FB`, `LC`, `LD`, `K1`, `K4`, and `RG` for the hidden-row case; `R2` has no site after LED .59) |
| Synthetic instance of the absent case | `K2-input-target` (a table naming `OsClipboardInput#search_input`) is the synthetic re-introduction of the absent case and the census arm goes RED on it (`mut-K2-input-target-full.txt`); the focusability conjunct's synthetic instances are the two F1 reverts |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "_step_finalize\|set_focus\|focus_target\|_SegTable\|RegionRow\|memory_map" tests/ --include=*.py` | 32 files; ALL run on tree `77bb9aa6` (none excluded; NOT re-run on the final tree `7168c1c9` — see "Which tree each result ran on"; `green-22` re-runs the map subset on the final tree: 710 passed, 1 xfailed in 1443.60 s; 29 snapshots passed (no cell changed)) in `.dev-flow/2026-10-26-batch-100/evidence/inc-4/reverse-census-fix2.txt`: 976 passed, 1 xfailed, 5 failed in 3314.66 s. `test_tui_snapshot.py` passed; no cell changed |
| B2 file moved on disk | n/a — no file moved | no readers |
| B3 byte-identical golden captures this source | `guards.txt`: 29 snapshot cells passed | no cell changed |
| B4 artifact produced here is consumed elsewhere | the focus landing is consumed by the operator only | covered by B1 |
| A3 interface consumed by another module changed | no frozen interface touched | n/a |

The 5 failures, classified:
- `test_tui_commandbar.py::test_at_b78_03_...`, `test_tui_diff_screen.py::test_at_b78_32_...`, `test_tui_report_filter_surface.py::test_at_056e_a2b_...` — the 3 pre-existing failures at base (names in `.dev-flow/2026-10-26-batch-100/evidence/inc-4/red-03-census-failures-at-base.txt`); none touches focus.
- `test_before_after_report.py::test_at_061a_...` — flaky at BASE too: `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-17-fix2-at061a-flake-rate.txt` (12 solo runs each: this tree 9 passed / 3 failed, base `31eb572` 10 passed / 2 failed); also `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-15-fix2-census-flakes-isolation.txt` and `.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-16-fix2-at061a-isolation-and-base.txt`. The failure text ("exactly one surfaced written-status line expected, got []") is a status-line timing race, not focus.
- `test_b97_flow_execution.py::test_tc_b97_55_...` ("2 run_chain_set calls for one Run") — a NEW name in the failure set versus fix pass 1. Passed alone 5/5 on this tree (`.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-18-fix2-tcb9755-isolation.txt`) and in the isolation pair of `green-15`. **Disposition (orchestrator diagnosis, round 3):** Inc 4 is mechanically ruled out as the cause — a re-home can only move the focus to `#fx_panel`, which starts no run (`.dev-flow/2026-10-26-batch-100/evidence/inc-4/tc-b97-55-diagnosis.txt`: in the load campaign the re-home fired at least 0.9 s before the run start in all 40 CHANGE runs; the forced `stale_then_rehome` probe fails with `'fx_panel' == 'fx_run'`, a different assertion from the "2 run_chain_set calls" failure). Under CPU load it failed 0 of 40 on each tree (40 base rc=0, 40 change rc=0), and the base ran clean 5 more times (`.dev-flow/2026-10-26-batch-100/evidence/inc-4/green-19-tc-b97-55-at-base-x5.txt`). Routed to the test-race backlog item as a contention flake; the one failure in the 55-minute census run is not reproduced on either tree.

| Field | Value |
|---|---|
| **Reverse census** | 32 files, 976 passed / 5 failed (tree `77bb9aa6`); 3 pre-existing at base, 1 proven flaky at base (at_061a), 1 contention flake routed to the test-race backlog (tc_b97_55, 0/40 failures on each tree under load, Inc 4 ruled out mechanically); snapshot cells unchanged |

**Re-pins recorded (old → new → requirement):** none — no existing test's assertion changed in this increment.

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| every window's focus landing must be declared in one table | every window container id + every re-home call site | `grep -n "SCREEN_CONTAINER_IDS\|_step_finalize\|def load_a2l_from_path" s19_app/tui/app.py` before the edit | 12 registry windows + 1 palette-only window; 2 load tails | 1 table + 2 tail calls | 0 — modal closes (panel/dialog/question) are Inc 6 / 9b / 10 per LLR-166.1's own schedule |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated with its command before the first site was edited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| — none: this increment adds new symbols only; nothing superseded | n/a | n/a | n/a |

### Signed-balance test ledger

Scanned-file ledger (what `EXPECTED_SCANNED_TEST_FILES` pins):
`post = base − deleted + added` → `218 = 217 − 0 + 1` ✓ reconciles
(`tests/test_b100_focus.py` is the one added scanned file;
`tests/test_id_registry.py` bumps the bound by the measured count; nothing
deleted; fix pass 1 added no new file — the count is unchanged.)

Node ledger (test functions collected in the module):
`32 nodes = 28 (TC-B100-12: 17 functions, one parametrized over the 12
registry windows) + 2 (TC-B100-13) + 2 (AT-B100-04 parametrized arms)`
(round 3 adds one function: `hidden_map_row_is_rehomed`).
Windows-only arms: none (no junction/link arms in this increment). Deleted:
none.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · PASS-WITH-NOTES after 3 rounds (r1 BLOCK: F1 unfocusable targets, F2 untestable test; r2 BLOCK-UNTIL R2-1 HIGH: the deferred re-assertion broke the Map arrows against LLR-116.5; r3 PASS-WITH-NOTES, R2-1 discharged on the reviewer's own re-run of the map arrow probe and R7/R1/RT; R3-1 MAJOR the `RegionRow` exemption kept a hidden Map row focused, R3-2 MINOR packet rows) — `review-increment-004.md`. R3-1 fixed exactly as the reviewer specified (exemption deleted + `hidden_map_row_is_rehomed`, RED `red-07`), which the reviewer stated needs no re-read; ruling LED .59. Orchestrator re-run on the final tree `7168c1c9`: focus module + `test_tui_app.py` 94 passed + 1 xfailed (`green-21`), guards 75 passed + 29 snapshots (`orch-guards-final`), census sweep 87 passed (`orch-guards-census-final`), map files 710 passed, 1 xfailed in 1443.60 s; 29 snapshots passed (no cell changed) (`green-22`). `tc_b97_55` (one reverse-census failure) mechanically ruled out and routed to the test-race backlog (`tc-b97-55-diagnosis`). |

---

## 5 · Risks

- `Widget.focus()` defers focus via `call_later`; the re-home therefore calls
  `Screen.set_focus` directly. The difference is now pinned by an arm, not
  asserted from practice: `rehome_lands_synchronously` calls the re-home and
  reads the focus with no pause, and mutant R5 (the landing swapped for
  `target.focus()`) goes RED on it. Any future caller moving the focus inside
  a load tail with `.focus()` re-introduces the ordering hazard this increment
  removed (documented in `_rehome_focus_after_load`'s docstring).
- The re-home fires on the stated conditions ONLY; a focused widget in the
  persistent chrome (rail, command bar) is never re-homed by this rule — and
  the text-input case rides the generic stale rule (LED .58 (c), LED .59): a visible Find field in
  the active window keeps the focus and its typed text through a load
  (`visible_find_input_keeps_its_focus`), only an input in a hidden window or
  of area 0 is re-homed, and a visible chrome input (`#palette_input`) is
  never taken mid-typing (`palette_input_is_never_taken`; mutant LC goes RED
  on it). If a future increment adds a load path that does NOT drain through
  `_step_finalize` or `load_a2l_from_path`, its tail needs its own re-home
  call — the TC-B100-12 call-site shape (one tail, two calls today) is the
  model.
- The Map window's post-load landing is LLR-116.5's auto-selected region row,
  not the declared target (LED .58 (a)): the tail lands the panel, the
  panel's selection-follow hook runs after the tail and moves the focus onto
  the resolved row. `_focus_needs_rehome` has no `RegionRow` exemption (LED
  .59): a displayed row is healthy under the generic rule, a row in a hidden
  Map window is stale and is re-homed (pinned by `hidden_map_row_is_rehomed`).
  Residual risk: the Map landing depends on the selection-follow hook running
  after the tail, which is pinned black-box by
  `map_load_keeps_the_region_row_and_down_walks_it`. The
  fix-pass-1 deferred re-assertion that fought this hook is gone (LED .58
  (b)) — it is what broke the Map's arrow keys (round-2 finding R2-1). Any
  future re-assertion-like pass must not apply to a widget the window's own
  requirement focuses.
- The mutant table and the reverse census ran on `77bb9aa6`, not on the final
  tree `7168c1c9` (two code deletions since; section 4, "Which tree each result
  ran on"). The carry-over is argued and spot-verified (reviewer's RG / RT /
  R1 / R7 on `79df3ae1`, `green-21`, final guards and census), not re-executed.
- The map-file run on the final tree (`green-22`): 710 passed, 1 xfailed in 1443.60 s; 29 snapshots passed (no cell changed).
- The Split / Join / Export window owns its single keys while displayed
  (`p` = pad, LLR-135); the HLR-166 `p`-opens-the-dialog outcome is asserted on
  the rail windows, and the boundary arm pins the window's key ownership
  explicitly so the two requirements cannot silently contradict each other.

## 6 · Pending items / spec deviations

- The modal-close arms of LLR-166.1 (Load-result panel `enter`/`esc` at Inc 6,
  Load dialog `esc` and the cancelled load at Inc 9b, the load question `n` at
  Inc 10) are NOT written here — per the increment brief and the proposal's
  §5.4 schedule; TC-B100-12 is extended at those increments.
- Seven arms are green at base by design (they pin unchanged behaviour):
  `test_tc_b100_12_split_join_window_target_is_its_table` (the boundary
  characterization), `test_tc_b100_12_healthy_focus_is_not_moved`,
  `test_tc_b100_12_every_window_load_lands_on_its_target[map]` and
  `test_tc_b100_12_map_load_keeps_the_region_row_and_down_walks_it` (batch-77
  LLR-116.5 / HLR-115 already worked at base — the fix restores them after the
  fix-pass-1 regression), `test_tc_b100_12_visible_find_input_keeps_its_focus`
  (base has no text-input rule at all), `test_tc_b100_12_palette_input_is_never_taken`
  and `test_tc_b100_12_modal_keeps_its_focus_while_a_load_finishes`. The
  behavioural arms are killed by their declared mutants (§4 mutation rows).
- Mutant RA (no deferred re-assertion) is DISCHARGED BY THE FIX itself — fix
  pass 2 removes `_reassert_focus_target` (LED .58 (b)), so the mutant no
  longer applies and is dropped from the set; the map arms it killed are now
  pinned by `every_window[map]` and the down-walk arm against the shipped
  LLR-116.5 behaviour. Mutant R2 (text-input clause deleted) was an
  EQUIVALENT no-op survivor on `77bb9aa6`; its subject is now deleted (LED .59).
- No contract deviation: the executed verification commands of LLR-166.1/166.2
  and HLR-166 are exactly `pytest tests/test_b100_focus.py -k tc_b100_12 /
  tc_b100_13 / at_b100_04`. HLR-166's "named widget" for the Map window is
  ledgered per LED .58 (a): the landing is LLR-116.5's auto-selected region
  row — an id-less widget by design.
- Fix pass 2 also repaired a latent fix-pass-1 regression found by the map-test
  re-run: `_rehome_focus_after_load` read `default_screen.focused` before any
  mount guard, raising `NoScreen` for `test_tui_app.py::test_apply_prepared_load_chains_updates_via_call_later`
  (which drives `_step_finalize` on an app that never mounted); the focus read
  is now inside the documented unmounted-tree no-op.

- Mutant R2: RESOLVED. The orchestrator deleted the duplicate text-input branch (LED .59, tree `79df3ae1`); R2 has no site and is reported as "mutant subject removed" (section 4).
- R3-1 (code-reviewer round 3, MAJOR): RESOLVED under LED .59 — the `RegionRow` exemption and its import are removed (tree `7168c1c9`), new test `hidden_map_row_is_rehomed` (TC-B100-12) is RED with the exemption (`red-07`) and GREEN without it (`green-21`).
- R3-2 (MINOR, packet hash / rows): addressed in this edit — section 4 names the final tree and the per-tree table, the R2 row is reworded, the 9 evidence files have rows. `green-22` has its digest row (orchestrator).
- Reverse census: 5 failures (section 4) — 3 pre-existing at base, `at_061a` flaky at base, `tc_b97_55` routed to the test-race backlog item as a contention flake (Inc 4 mechanically ruled out; 0/40 failures on each tree under load; base 5 more clean runs).
- Not re-captured: `red-06` (base RED) was taken with the 31-node module; the 32nd node (`hidden_map_row_is_rehomed`) has its own RED in `red-07` on `79df3ae1`, not against base `31eb572`.
- `green-13-fix2-focus-module-final.txt` is an interrupted run (no verdict); superseded by `green-14`. Left in the evidence dir, not deleted.
- Section 4b independent review: written (code-reviewer, PASS-WITH-NOTES, R3-1 fixed).

## 7 · Suggested next task

Increment 5 (HLR-167 — Save project: the split, the emit decision, the plan),
per the proposal's hard order.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 1 source file (`app.py`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b100_focus.py` (32 nodes) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | 1 unit node (the registry census — cyclomatic ≥3 derivation + boundary, focusability included) — `green-14` |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 RED table + `red-06` (24 failed, 7 passed at base 31eb572) + `red-05` (3 failed) + `red-07` (1 failed, R3-1 test with the exemption) + the F1 per-window reverts |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 reverse census — 32 files, all run in `reverse-census-fix2` on `77bb9aa6` (976 passed, 5 failed: 3 pre-existing, 1 flaky at base, 1 contention flake — `tc-b97-55-diagnosis`); map subset on the final tree: `green-22` 710 passed + 1 xfailed |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b: PASS-WITH-NOTES, R3-1 fixed per the reviewer's exact fix |
| 7 | No file from another lane touched | all | ✓ | only `s19_app/tui/app.py` |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | no B100-I row changed; new symbols consumed by `app.py` alone |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | every `N passed` appears in a cited transcript |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 load-bearing emptiness |
| 11 | **Mutation verdicts** declared — **per arm** | all | ✓ | §4 mutation verdicts — 13 mutants on the FULL module (tree `77bb9aa6`), per-arm counts, 12 KILLED + R2 (subject removed, LED .59); round 3: RG KILLED (1, `red-07`) |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 instrument table (10 instrument groups) |
| 13 | **Correction population** declared | all | ✓ | §4 correction population (1 correction) |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 emitted-form table (6 artifacts) |
| 15 | **Independent review** names somebody | all | ✓ | §4b: code-reviewer |
| 16 | **Evidence files** declared | all | ✓ | §4 evidence table (paths + SHA-256) — 61 rows |
