# Code Review — Increment 004 (batch-100, "The focus lands where you can work", CW-U-2)

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`. I am independent of this code: Kimi K2.8 implemented it, not me. |
| Tree reviewed | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc4`, detached at `24d5b7f`, with uncommitted changes. `app.py` sha256 is `af6da521ef2d…`, which equals the packet's `pre-mutation-hashes.txt` and `app-implemented.py.bak`. I never edited the worktree. My only command inside it was a read-only `devflow-evidence.py --root . --check`, and `git status` was unchanged afterwards. |
| Contract | `01-requirements.md`: HLR-166, LLR-166.1 (the load-tail arms only), LLR-166.2, P-16. UX-03 (`design/P2-ux-r1.md`, closed in `P2-ux-r2.md`). `design/design-proposal-b100.md` §5.4. `kimi/BRIEF-inc-4.md`, `BRIEF-COMMON.md`. Precedents: `review-increment-00{1,2,3}.md`. |
| Interpreter proof | s19env Python 3.11, Textual 8.2.8. I built these trees under `…\scratchpad\r4\`:<br>• `base\` = `git archive 24d5b7f` plus the new test file;<br>• `fixed\` = the archive plus the 3 changed files, with `app.py` hash-equal to the worktree;<br>• `mut\<id>\`, one tree per mutant.<br>Every transcript prints `s19_app.__file__` from its own tree. Runs used `PYTHONPATH` set to that tree, `NO_COLOR` unset (`env -u`), `PYTHONDONTWRITEBYTECODE=1` and `-p no:cacheprovider`. |
| **Verdict** | **reject until fixed.** Recorded token: **`BLOCK — BLOCK-UNTIL: F1, F2`** (2 HIGH). This verdict authorises nothing. The increment does not advance until F1 and F2 are fixed and I have re-read the fixes on the diff and re-run the probe and mutant R1. F3–F5 (MAJOR) should land in the same corrective pass. F5 needs an orchestrator ruling first. |

`…\scratchpad` = `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad`.

## BLUF

The mechanism is right and small. The table is checked against the registry, the predicate encodes the three conditions, and the re-home lands synchronously at both tails. A modal that is open when the tail runs keeps its focus. On the windows the tests drive (Workspace, A2L, MAC, Split/Join), P-16 is fixed: I confirmed it RED at base and GREEN now.

Two things block:

- **F1. Two of the 13 declared targets cannot take the focus**, so **P-16 survives on the Diff window**. `#ab_diff_panel` and `#memory_map_panel` are `can_focus=False` containers. `Screen.set_focus` silently ignores a non-focusable widget. I executed this: on Diff, after an image load, the focus is `_SegTable#sje_table area=0` and `p -> Screen`. The census claims to cover "every window", but it never checks that a target can be focused, and no load arm runs on 9 of the 13 windows.
- **F2. Mutant R1, which deletes the healthy-focus early return so every tail always re-homes, leaves all 10 nodes green.** The arm named `healthy_focus_is_not_moved` cannot see it. The product does keep a healthy focus today (probe S4), but nothing pins it.

## Scope reviewed

- `s19_app/tui/app.py`, the whole diff:
  - `_FOCUS_TARGETS` `:7162-7176` and `_WINDOW_CONTAINER_IDS`;
  - `_focus_needs_rehome` `:7628-7667`;
  - `_rehome_focus_after_load` `:7669-7720`;
  - the A2L tail call `:9871-9873`;
  - the `_step_finalize` call `:12207-12210`;
  - `from textual.widget import Widget`.
- Also read, to judge impact:
  - `SCREEN_CONTAINER_IDS` `:7065`, `action_show_screen` `:7241-7300` (the `.hidden` swap) and `action_open_split_join_export` `:7378-7424`;
  - `watch_current_file` `:11950-11983` and `SplitJoinWindow.refresh_window` (`segment_split_view.py:1678-1702`, whose deferred `.focus()` is the P-16 root cause);
  - the whole `_apply_prepared_load` step chain `:12160-12225` and `load_a2l_from_path` `:9790-9880`;
  - in Textual 8.2.8: `App.focused` (the active screen's focus), `App._get_dom_base` (queries resolve on the **default** screen) and `Screen.set_focus` (a no-op on a non-focusable widget).
- `tests/test_b100_focus.py`, all 590 lines, and the `tests/test_id_registry.py` diff (217 → 218).
- The packet `increment-004.md`, `HANDOFF.md`, and all 24 files in `evidence/inc-4/`.

## What I executed (evidence state: `executed`)

| Run (`…\scratchpad\r4\<file>`) | Result |
|---|---|
| **RED at base**: the new module on `git archive 24d5b7f` (`base-red.txt`) | **10 failed.**<br>• 6 behavioural failures name P-16: `last painted focus: _SegTable#sje_table, region Region(x=0, y=0, width=0, height=0)`.<br>• The healthy arm fails at `:329` with `got _SegTable(id='sje_table')`.<br>• The 2 TC-13 arms time out on `last painted focus: None`.<br>• The census arm fails on a missing symbol (`no attribute '_FOCUS_TARGETS'`), not on behaviour. Its behavioural RED comes from K3 and Kimi's input-target mutant.<br>• **The Split/Join boundary arm FAILS at base, at `:361`**, which is the precondition's single read and not the oracle → F4. |
| GREEN, fixed tree (`fixed-green.txt`) | **10 passed** (69 s) |
| Kimi K1, a2l-tail removed, **full module** | KILLED: 2 failed (both TC-13 arms). Matches the packet. |
| Kimi K4, finalize-tail removed, **full module** | KILLED: **7 failed** (3 load arms, healthy, Split/Join, both AT sizes). The packet says the healthy, boundary and AT arms "stay GREEN, named". They do not → F7. |
| Kimi K3, `mac` dropped from the table, **full module** | KILLED: **2 failed** (the census and the healthy arm). The packet says 1 → F7. |
| **R1**: always re-home (the early return deleted) | **SURVIVED, 10 passed** → F2 |
| **R2**: the `Input`/`TextArea` clause deleted | **SURVIVED, 10 passed** → F3 |
| R3: the hidden-window clause deleted | SURVIVED, 10 passed. In the P-16 shape it overlaps the area clause. Note only. |
| R4: the area clause deleted | SURVIVED, 10 passed. It overlaps the hidden-window clause. Note only. |
| **R5**: `target.screen.set_focus(target)` replaced by `target.focus()` | **SURVIVED, 10 passed** → F9 |
| R7: a `None` focus no longer re-homes | KILLED: 2 failed (both TC-13 arms) |
| **Per-window probe** (`probe-perwindow-fixed.txt`). For each of the 12 rail windows: open Split/Join, switch to the window, load an image, then separately an A2L | 10 of 12 windows land on their target and `p` opens `LoadProjectScreen`.<br>**Diff, image load:** `_SegTable#sje_table area=0`, `p -> Screen`.<br>**Diff, A2L load:** focus `None`.<br>**Map:** `RegionRow#None area=57`, an unnamed widget and not the declared target. → F1 |
| Target probe (`probe-targets-out.txt`) | `memory_map_panel` and `ab_diff_panel` have `focusable=False`. In a bare session, `files_list`, `memory_map_panel`, `validation_issues_groups` and `checks_grouped` have area 0 (empty state). → F1, F5 |
| Empty-state probe (`probe-empty-fixed.txt`). Bare session, P-16 shape, A2L-only load | Workspace: `ListView#files_list area=0`. Issues: `GroupedIssuesPanel area=0`. Map: `None`. → F5 |
| Modal and user-focus probe (`probe-modal-user-fixed.txt`, `probe-modal-user-R1.txt`) | **S1:** an A2L tail runs while the Load file dialog is open. The modal keeps `#load_path`; only the default screen's focus moves (to `files_list`). **S2:** a project load finishes under the Legend, which keeps `#legend_close`. **S3:** palette open, `Spl` typed, an A2L tail runs. The palette input loses the focus to `files_list`, and the next typed `i` is dispatched to the app → F6. **S4:** a healthy `#hex_scroll` focus survives an A2L load on the fixed tree; **under R1 it moves to `files_list`** → F2 is a real behaviour with no test. |
| `devflow-evidence.py --root . --check evidence/inc-4/*` (in the worktree, read-only) | All 15 packet rows bind. The only `MISMATCH` limb on them is the index (`not staged`), which is expected before the commit. **9 files on disk have no packet row** → F8. |

## Findings

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **F1** | **HIGH** (correctness + false-confidence census) | `app.py:7166`, `:7170`, `:7715`; tests `:185-216` | **Two targets cannot take the focus, so P-16 survives on the Diff window.** `#ab_diff_panel` (`AbDiffPanel(Container)`) and `#memory_map_panel` are `can_focus=False`. `Screen.set_focus` only acts when `widget.focusable` is true, so on those windows `_rehome_focus_after_load` is a silent no-op.<br>• **Diff:** the hidden table keeps the focus and `p` is dead. This is exactly CW-U-2.<br>• **Map:** the focus ends on an unnamed `RegionRow` by accident, not on the declared target. HLR-166 requires the window's declared target.<br>The census checks key equality and "not an `Input`/`TextArea`". It never checks `can_focus`, and it never checks that the target paints a region when its window is shown. No load arm runs on any window but Workspace, A2L, MAC and Split/Join, so the claim "covers every window" is not tested. | Per-window probe: `image diff … -> focus _SegTable#sje_table area=0  p -> Screen`; `ab_diff_panel focusable=False`, `memory_map_panel focusable=False` | (a) Declare focusable, non-text targets for Map and Diff: a focusable child with an id. For Diff the candidates are `#diff_compare_button`, or `#diff_select_a` if a `Select` is acceptable to UX. **Not** `#diff_range_list`, which has area 0 until a compare runs. Map needs a focusable widget with an id, because today only id-less `RegionRow`s and a `ScrollableContainer` are focusable.<br>(b) Census: for every entry, `widget.can_focus` is true.<br>(c) Add a parametrized arm over **every** key of `_FOCUS_TARGETS`: build the P-16 shape, show the window, load an image, wait for the focus to settle on the target with area > 0, then press `p` (Split/Join keeps its own `p` boundary). Discharge: I re-run the per-window probe and it must show 13 of 13 on target. |
| **F2** | **HIGH** (false-confidence test) | `app.py:7704`; tests `:304-333` | **No test can see the healthy-focus rule. The arm named for it cannot fail when the rule is deleted.** `watch_current_file` re-focuses `#sje_table` on every image install, so by the time `_step_finalize` runs the focus is always bad. The "healthy" arm therefore always takes the re-home branch, and it passes only because the MAC target equals the widget the user had focused. R1 (always re-home) keeps all 10 nodes green. It is still a real behaviour: on an A2L load the user's healthy `#hex_scroll` focus is kept today and moved under R1 (probe S4). The packet's §1 ("a healthy focus is left untouched") and its §4 row cite this arm as the proof. Smaller: the arm reads `app.focused` once after the status predicate, the single-read shape the module's own `_wait_for_focus_on_target` docstring warns against. | R1 → **10 passed**; probe S4 fixed `hex_scroll` → R1 `files_list` | Rename the current arm to what it proves ("the re-home lands on the ACTIVE window's target"), and give it the settled-focus helper. Add a real healthy arm: with an image loaded on Workspace, focus a visible non-target, non-text widget (`#hex_scroll`), run an A2L load (no `current_file` change, so no steal), flush, and assert the focus is still `#hex_scroll`. Discharge: I re-run R1 and it must go RED on that arm. |
| F3 | MAJOR | `app.py:7662`; tests (missing arm) | **The text-input clause, which is UX-03's own example, has no arm.** R2 deletes it and stays 10/10 green. The census pins only the table side ("no target is an `Input`"). LLR-166.1 also requires re-homing *off* a focused `Input`/`TextArea`. That case is reachable on the A2L tail, where nothing steals the focus first (probe S4: `#search_input` → `files_list`). | R2 → 10 passed | Add an arm: on Workspace with an image loaded, focus `#search_input` (or the A2L screen's `#a2l_tag_find_input`), run an A2L load, then assert the focus settled on the target and `p` opens the dialog. R2 must go RED. |
| F4 | MAJOR (test race + false record) | tests `:356-363`; packet §4 RED table "Arms that stayed GREEN", §6 bullet 2 | **The Split/Join boundary arm reads its precondition once, and the packet misstates its base result.** The wait at `:356-360` polls only on `focused.id == "sje_table"`, then `:361` reads `region.area` once. At base the hidden table already holds the focus, so the wait returns before the window is laid out and `:361` sees area 0. On the fixed tree the wait happens to cover one layout pass, so it passes. The packet says this arm "is green at base BY DESIGN". Kimi's own `red-01` and `red-02` show it **FAILED**, and so does my base run, both at `:361`. Neither is a behavioural RED. | `base-red.txt`; `red-02-focus-module.txt:425` (`test_b100_focus.py:361: AssertionError`) | Poll the precondition with `_focus_is_settled_on(app, "sje_table")` (id and area > 0), the same as the oracle. Then re-run at base: the arm should be GREEN (it pins unchanged behaviour) and K4 kills it. Correct the packet's RED table and §6 to match the transcripts. |
| F5 | MAJOR (spec boundary; ruling needed) | `app.py:7708-7715` | **The re-home can land on a zero-area target.** In a bare session the Workspace, Issues, Checks and Map windows show their empty state, and their targets have area 0. An A2L-only load that finds a bad focus (the P-16 shape) moves it onto an invisible widget. That breaks HLR-166's "non-zero visible region" for the A2L-only boundary on the default window. The TC-13 boundary arm avoids this by running on the A2L screen ("owns no empty state"). `p` still works there, because a ListView does not consume `p`, so the impact is the oracle and not dead keys. | Empty-state probe: `workspace: ListView#files_list area=0`; `issues: … area=0` | Orchestrator ruling. Either declare an empty-state target per content-bearing window (a focusable widget in the empty-state panel), or ledger that in an empty state the focus may land on the hidden target (LED + HLR-166 boundary). Add the arm the ruling chooses: an A2L-only load on Workspace in a bare session. |
| F6 | MINOR (ruling) | `app.py:7662`, `:7655-7658` (docstring); packet §5 bullet 2 | **The text-input rule takes the focus from the user's own input in the middle of typing.** If the palette or a Find field is focused when a tail runs (in practice the A2L tail, which nothing steals before), the focus moves to the target, and the next typed character is dispatched as an app key. The rule is written literally in LLR-166.1, but UX-03's concern was the landing spot, not interrupting the user. The docstring and packet §5 also say a widget in the persistent chrome "is never re-homed by this rule". That is wrong for the command bar's `#palette_input`, because the `Input` check runs before the ancestor walk. | Probe S3: `palette_input` → `files_list`; the typed `i` → `Screen` | Ruling for UX: either limit the `Input` clause to inputs in a hidden window or to inputs the load itself focused, or keep the literal rule and ledger the trade-off. Correct the docstring and §5 either way. |
| F7 | MINOR | packet §4 *Mutation verdicts*, RED table | **The mutation verdicts are under-reported and the "stay GREEN" survivors are not evidenced.** `mut-*.txt` ran selected nodes only (`-k …`). My full-module runs give different results: K4 kills 7 nodes, not 3, and the healthy, boundary and AT arms the packet names as GREEN all fail. K3 kills 2, not 1. This is the same record gap as Inc 3's F11(c). | `mut-K4_finalize_tail.txt`, `mut-K3_drop_mac.txt` | Re-run the mutants on the full module and rewrite the rows. Add R1/R2 (killed after F2/F3) and R5 (F9). |
| F8 | MINOR | `evidence/inc-4/`; packet §4 evidence field; worktree root | **Record hygiene.** (a) 9 files on disk have no packet row. These are the instruments `revert_inc4.py` and `apply_mutation.py`, a 642 KB `app-implemented.py.bak`, `probe_focus.py`, `probe_p.py` and `green-01..04`. Either digest the instruments the RED and mutation rows rely on, or delete the scratch files before the commit. (b) The field still says "15+ … (guards.txt / guards-census.txt appended when the runs finish)", which is stale. (c) `HANDOFF.md` is at the worktree root. Move it to `kimi/inc-4-HANDOFF.md` at commit, as for Inc 1–3. | `--check` output | Fix in the corrective pass (`--write` the rows). |
| F9 | MINOR | `app.py:7710-7715`; packet §1 ¶2, §5 bullet 1 | **The packet's load-bearing claim for `Screen.set_focus` has no test.** The packet says `Widget.focus()` would be overridden by the queued load steps, "observed in practice" as the oracle regressing. R5 (`target.focus()`) keeps all 10 nodes green. So either the claim is no longer true or no arm reproduces it. The synchronous form is harmless and I would keep it. | R5 → 10 passed | Either add an arm that R5 turns RED, or reword §1/§5 as a precaution and record R5 as a survivor. |
| F10 | LOW | `app.py:7154-7161` | The comment says the table is "Derived 1:1 from the window registry". It is hand-listed and checked against the registry, which is what the contract means. | code read | Say "declared per window and asserted 1:1 against the registry". |

Notes (no finding):

- **Modals (check 2).** The re-home cannot steal from a modal. `self.query_one` resolves on the default screen and `target.screen.set_focus` acts on the default screen, so the modal keeps its focus (S1, S2). The predicate does judge the *modal's* focused widget, though. When a modal `Input` is focused (S1), the default screen's focus is moved behind it. That is benign today, and it is what Inc 9b wants after `esc`. For Inc 6 ("while the panel is open, the focus stays in it"), the safer form is to evaluate `self.default_screen.focused` and not `self.focused`, or to return early when `self.screen is not self.default_screen`. Then the rule never reads a modal widget. Recommended before Inc 6.
- **R3/R4.** Area 0 and "in a hidden window" overlap in the P-16 shape. The hidden clause still matters when a region is stale between `add_class("hidden")` and the next layout, so keeping both is correct.
- `_step_finalize` calls the re-home inside its `try`, after `update_memory_map` and `_refresh_loaded_panel`. If either raises, the re-home is skipped. That is consistent with "a failed load leaves the focus where it was".

## Checks the brief named

| Check | State |
|---|---|
| 1 · Table derived from the registry, never `Input`/`TextArea`, every window, robust when hidden or unmounted | ✓ The key set equals `SCREEN_CONTAINER_IDS` plus `split_join` (K3 kills it). ✓ No `Input` (Kimi's input-target mutant kills it). ✓ It does not break when a window is hidden: the lookup goes by id, and nothing unmounts. ✓ Before mount, `query_one` raises and the `except` makes it a no-op. **✗ 2 targets are not focusable (F1).** ✗ Targets in the empty state have area 0 (F5). |
| 2 · Re-home conditions; no steal from a modal; no fighting the user's healthy focus | ✓ Exactly the three conditions plus `None`. ✓ No steal from a modal (S1, S2; note above). ✓ A healthy focus is kept (S4), **✗ but no test pins it (F2)**. ✗ The text-input clause has no test (F3) and takes the user's palette or Find input (F6). |
| 3 · Tests, RED, mutants, races | ✓ The AT is black-box: `ctrl+k` palette, rail key `1`, the real Load project and Load file dialogs by key and click, and `p`/`k`/`t` reaching `LoadProjectScreen`/`LegendScreen`/`ReportViewerScreen`. The focus is read through public `app.focused.region`. It runs at 118×54 and 220×60 with notifications on. ✓ The RED at base is behavioural for 8 of 10 nodes; the census node fails on a missing symbol and the boundary node on a race (F4). ✓ I re-ran K1, K3 and K4 on the full module (F7) and 6 mutants of my own. ✓ The oracle polls until settled (`_wait_for_focus_on_target`). ✗ Single reads at `:361` (F4) and `:328` (F2). |
| 4 · Reverse census | ✓ The 3 failures are pre-existing at base (`red-03`, Inc 4 reverted): `test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact`, `test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` and `test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection`. Inc 3 already recorded the first and third as pre-existing. The flake is `test_before_after_report.py::test_tc330_before_after_row_reveal_hide_state_machine`: it passes at base inside `red-03` (`.FFF`) and passes in isolation on the Inc 4 tree (`green-07`). The census list has 14 files (`reverse-census-files.txt`) and the result is 615 passed + 4 failed (`green-06`). I did not re-run the 39-minute census myself. |
| 5 · Inc 1–3 regressions | ✓ The diff adds no `.resolve()`, placement call, `workarea_root` argument or `copy_into_workarea` call (grep of the `+` lines). `_reset_project_session` is untouched: the diff has 4 hunks, all on the focus symbols and the two tail calls. |
| 6 · Hygiene | ✓ 1 SOURCE file. CRLF is consistent: `app.py` 14645/14645, the new test 590/590, `test_id_registry.py` 855/855, with `i/lf w/crlf`. ✓ The §2 Kinds `source`/`test`/`config` are in the closed six. ✓ `Traces to` holds the real ids HLR-166 and LLR-166.1/166.2 (V59). ✓ V56: every figure in the packet appears in its cited transcript (10 failed ×2, 10 passed, 615+4, 3 failed/1 passed, 1 passed, 75 + 29 snapshots, 87, and the mutant counts 2/1/1/3 as selected-node runs). There are no figure images. ✓ The digests of the 15 rows match disk. ✗ 9 files have no row, the field text is stale, and HANDOFF is at the root (F8). |

## Evidence checklist

- [x] Diff read in full: `app.py` `:15-18`, `:7154-7186`, `:7628-7720`, `:9871-9873`, `:12207-12210`; the whole `tests/test_b100_focus.py`; the `test_id_registry.py` diff.
- [x] Correctness pass: non-focusable targets (F1, executed), empty-state area 0 (F5, executed), modals (S1/S2, executed), user inputs (F6, executed), the `None` focus (R7 killed), a raising step skipping the re-home (note).
- [x] Simplicity pass: two small methods and one table, with no premature abstraction. The ancestor walk is the minimum needed to identify the window.
- [x] Reuse checked: it reuses `SCREEN_CONTAINER_IDS` and the `.hidden` mechanism of `action_show_screen`, and mirrors `_focus_local_input`'s pre-mount no-op. No duplicate focus helper.
- [x] Tests reviewed for intent: F2 (the healthy arm cannot fail), F3 (the `Input` clause has no arm), F4 (precondition race), F7 (mutation record), F9 (R5 survives).
- [x] Verdict explicit: `BLOCK — BLOCK-UNTIL: F1, F2`. Both HIGHs are open, with executed evidence: the per-window probe for F1, R1 surviving for F2.

## §4b `Independent review` cell (for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: F1, F2** (2 HIGH, 3 MAJOR, 4 MINOR, 1 LOW) · Both HIGHs are open. **F1:** the declared targets `#ab_diff_panel` and `#memory_map_panel` are not focusable, so `Screen.set_focus` is a silent no-op on those windows. After an image load on Diff the focus stays on `_SegTable#sje_table` (area 0) and `p` does nothing, which is P-16 itself (per-window probe, executed, `review-increment-004.md`). The census never checks `can_focus`, and no arm runs outside Workspace/A2L/MAC/Split-Join. **F2:** mutant R1 (always re-home) leaves `tests/test_b100_focus.py` 10/10 green, so `healthy_focus_is_not_moved` cannot fail. A healthy focus is kept today only by an untested branch (probe S4). Both are discharged only when I re-read the applied fix on the diff, the per-window probe shows 13 of 13 windows on target, and my re-run of R1 goes RED. P-16 is otherwise fixed: RED at base, GREEN now; the AT is black-box at both sizes; no modal loses its focus. Open MAJORs: F3 (the `Input` clause has no arm; R2 survives), F4 (single-read race at `:361`; the packet's "green at base" contradicts `red-01`/`red-02`), F5 (an empty-state target with area 0; ruling).

## Hand-offs

- **Orchestrator:**
  - F5 ruling: an empty-state target per window, or a ledger entry.
  - F6 ruling: scope of the text-input clause.
  - The modal note: evaluate `default_screen.focused` before Inc 6.
  - The pre-existing failures still need owners: `at_b78_03`, `at_b78_32`, `at_056e_a2b`.
- **`qa-reviewer`:** F1(c), the per-window arm; F2/F3, the healthy and `Input` arms; F4, polling the precondition.
- **`ux-reviewer`:** F1(a), choosing the Diff and Map targets; F5; F6.
- **`security-reviewer`:** nothing new. No path, placement or resolution change; LED .50 holds.

---

# Round 2: re-read of corrective pass 1

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as round 1. I did not write the fix. |
| Tree re-read | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc4` at `24d5b7f`, with Inc 4 and fix pass 1 uncommitted. `app.py` sha256 is `ac449a2e411b…` and `tests/test_b100_focus.py` is `ac42b2eb1c6d…`, matching HANDOFF §"Fix pass 1". It is still 1 SOURCE file: `git diff --name-only 24d5b7f` lists `app.py` and `test_id_registry.py`, plus the untracked test module. CRLF is consistent: `app.py` 14822/14822, the test 961/961. I did not edit the worktree. |
| Contract | Main `31eb572`: LED .57 (a)–(d) and `kimi/BRIEF-inc-4-fix1.md`. I also read batch-77 `01-requirements.md` LLR-116.1 and LLR-116.5, and HLR-115 (`RegionRow.on_key`, `screens_directionb.py:1449-1497`). |
| Interpreter proof | `…\scratchpad\r4\fixed2\` = `git archive 24d5b7f` plus the 3 changed files, hash-equal to the worktree. `…\r4\base\` = the archive plus the fix-pass test module. `…\r4\mut2\<id>\` = one tree per mutant. Every transcript prints `s19_app.__file__` from its own tree. `NO_COLOR` unset (`env -u`), s19env 3.11, Textual 8.2.8. |
| **Verdict** | **reject until fixed.** Recorded token: **`BLOCK — BLOCK-UNTIL: R2-1`** (1 HIGH, new in this round). **F1 and F2 are discharged**: I re-read both on the diff, re-ran the per-window probe (13 of 13 windows on target) and re-ran R1 (KILLED, 3 nodes). R2-1 is new. The fix pass's `_reassert_focus_target` breaks batch-77 LLR-116.5 on the Map window: after a load the arrow keys stop walking the regions. R2-2 (MAJOR) puts the code against LED .57 (c). |

## What I executed in round 2 (evidence state: `executed`)

| Run (`…\scratchpad\r4\<file>`) | Result |
|---|---|
| GREEN, fix-pass tree (`r2-fixed2-green.txt`) | **29 passed** (179 s) |
| RED at base: the final module on `git archive 24d5b7f` (`r2-base-red.txt`) | **25 failed, 4 passed** (29 nodes). The 4 passes are split_join, healthy, palette and modal, which pin unchanged behaviour as packet §6 says. All 12 `every_window` cases fail at base, not only Diff. **Kimi's `red-04` shows 24 failed, 4 passed = 28 nodes**, so it was run on an earlier, 28-node version of the module → R2-3. |
| **R1** (always re-home), full module | **KILLED: 3 failed** (`healthy_focus_is_not_moved`, `palette_input_is_never_taken`, `modal_keeps_its_focus…`). Round 1: 10/10 green. **F2 discharged.** |
| R2 (text-input clause deleted) | KILLED: 1 failed (`text_input_in_a_content_window_is_rehomed`). See R2-2 for what that test asserts. |
| R3 (hidden clause) / R4 (area clause) | Both SURVIVED, 29 passed. In the P-16 shape the two clauses overlap, as in round 1. Note only. |
| R5 (`target.focus()` instead of `set_focus`) | KILLED: 1 failed (`rehome_lands_synchronously`). **F9 closed.** |
| **Per-window probe**, image and A2L loads × 12 rail windows (`r2-probes.txt`) | **24 of 24 land on the declared target, and `p` opens `LoadProjectScreen`**. Diff lands on `Button#diff_compare_button`, Map on `MemoryMapPanel#memory_map_panel`. Round 1: Diff was `sje_table area=0`, `p -> Screen`. **F1 discharged.** |
| Target probe | All 13 targets are `focusable=True`. In a bare session, Workspace/Map/Issues/Checks still have area 0, and the fallback covers them (next row). |
| Empty-state probe (bare session, P-16 shape, A2L-only load) | Workspace → `WindowHelpChip#window_help_workspace`, Map → `#window_help_map`, Issues → `RailItem#rail_item_issues`. All have area > 0. **F5 closed per LED .57 (b).** |
| Modal and user-focus probe | **S1** (dialog open): the modal keeps `#load_path`. **S2** (Legend): keeps `#legend_close`. **S3** (palette): keeps `#palette_input`, and the typed `i` stays text. **S4**: a healthy `#hex_scroll` is kept. **S4b**: a visible `#search_input` (Workspace Find) **is taken** and moved to `files_list` → R2-2. |
| **Map arrow probe**, three trees (`probe-map-arrows.txt`). Map window shown, image load (first load and re-load), then `down`, `down` | **Base `24d5b7f` and round-1 tree:** the focus settles on `RegionRow start=0x80010000`, and `down` walks it to `…10080` and then `…10120`. **Fix-pass tree:** the focus settles on `MemoryMapPanel#memory_map_panel` and **`down` does nothing (twice)**. In the re-load case the operator's own `RegionRow` focus is also replaced by the panel. → R2-1 |
| Map suites on the fix-pass tree (`test_map_click_chain.py`, `test_tui_hostile_map.py`, `test_tui_map_big.py`; `r2-map-tests-fixed2.txt`) | 123 passed. None of them loads while the Map window is shown, so they cannot see R2-1. None is in the reverse census either. |
| Census flakes: isolation and file runs (`r2-flakes-iso-*.txt`, `r2-ba-{base,fixed2}-{1,2,3}.txt`) | `test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden`: green in all 8 of my runs on both trees; I could not reproduce it. `test_at_061a_persistent_control_survives_then_writes_pair_and_clears`: **fails at base too** (isolation 1/1, file run 1/3), and on the fix-pass tree in 2/3 file runs, always `writes … got []`. `at_038a` and `at_038c` flake the same way on both trees. These are pre-existing timing flakes in `test_before_after_report.py`, not Inc 4. Kimi's `green-10` (3 passed in isolation) is consistent with that. |
| `devflow-evidence.py --root . --check evidence/inc-4/*` | Every file binds to a packet row. The only mismatch is the index limb (`not staged`), which is expected before the commit. The scratch scripts and the `.bak` are gone. **F8 closed.** |
| Inc 1–3 regressions | `+` lines of the source diff: no `.resolve(`, no `workarea_root`, no `copy_into_workarea`/placement call, no `_reset_project_session`. **None.** |

## Closure table — round 1 findings

| id | State | Evidence |
|---|---|---|
| F1 HIGH | **Discharged** (re-read and re-run) | Diff → `#diff_compare_button` (`app.py:7182`). The Map panel is declared `can_focus` at compose (`:2537`). The census asserts `can_focus` (test `:226-231`). The parametrized `every_window` arm covers all 12 windows (`:405-439`). My probe: 24/24 on target with `p` live. The Map half is superseded by R2-1: in round 1 I called the `RegionRow` landing "by accident". That was wrong. It is LLR-116.5's designed landing, and my wording pushed the fix toward the conflict. |
| F2 HIGH | **Discharged** (re-read and re-run) | The real healthy arm (`:442-479`) uses the probe-S4 shape: an A2L load with no `current_file` change. My R1 re-run is KILLED, with 3 nodes. |
| F3 MAJOR | Mechanically closed (R2 killed); **reopened in substance as R2-2** | The arm asserts the opposite of LED .57 (c) for the Find field. |
| F4 MAJOR | Closed | The precondition now polls (`_focus_is_settled_on`). At base the arm is green in my run (25F/4P), and packet §6 now says so. |
| F5 MAJOR | Closed per LED .57 (b) | `_fallback_focus_target` and `_resolve_focus_target` (`:7747-7778`). Probe: help chip or rail entry, area > 0. |
| F6 MINOR | Closed for the palette; **not for Find** → R2-2 | S3 keeps the palette and the typed text. |
| F7 MINOR | Closed | Full-module transcripts. Kimi's R1, R2 and R5 counts (3/1/1) equal mine. |
| F8 MINOR | Closed | Scratch removed; every file has a row; `--check` binds them all. HANDOFF still sits at the worktree root and moves at commit, as for Inc 1–3. |
| F9 MINOR | Closed | `rehome_lands_synchronously`; R5 is KILLED. |
| F10 LOW | Closed | The comment now says "Declared per window and asserted 1:1 against the window registry". |
| LED .57 (d) / modal note | Closed | `_rehome_focus_after_load` and `_reassert_focus_target` read `default_screen.focused`. Probes S1/S2 and the two modal arms. |

## New findings — round 2

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **R2-1** | **HIGH** (regression of a shipped requirement) | `app.py:7780-7826` (`_reassert_focus_target`), `:7880`; test `:405-439` (`every_window[map]`) | **The re-assertion overrides batch-77 LLR-116.5 and kills the Map's arrow keys after every load.** LLR-116.5 requires that after the selection is resolved, the focus is on the live region row whose `region_start` equals the resolved selection. HLR-115's `up`/`down` walk is implemented on that row (`RegionRow.on_key`) and nowhere else. `_reassert_focus_target` runs one refresh after the tail. It re-lands every *id-less* focus on the declared target, and a `RegionRow` has no id, so the Map window always ends on `#memory_map_panel`, where `up`/`down` do nothing. It also replaces the operator's own `RegionRow` focus (the re-load case), so the rule moves a focus the user chose. The packet frames this as a trade-off ("would leave the focus on an id-less `RegionRow`"), but at base that row is the *required* landing, and `p` already works there (my round-1 probe). `every_window[map]` now asserts the regression as correct behaviour. No map suite loads while the Map is shown, so nothing else catches it. | Map arrow probe: base/round-1 `RegionRow`, `down` walks; fix pass `MemoryMapPanel`, `down` ×2 does nothing | Orchestrator ruling. Recommended: on the Map window the landing is LLR-116.5's auto-selected row. Treat an attached `RegionRow` inside `#memory_map_panel` as the Map's healthy target. Keep the panel only as the empty-state or fallback target. **Remove `_reassert_focus_target`**: it exists only to defeat LLR-116.5. Its "id-less ⇒ re-land" rule would also move any other unnamed widget the operator chose. HLR-166's "named widget" needs a ledger line for the Map ("the selected region row"). Change `every_window[map]` to LLR-116.5's threshold (focused ∈ live `RegionRow`s, `region_start` = the resolved selection) plus `p`, and add `down` → the next row. Discharge: I re-run the map arrow probe on the fix and `down` must walk. Kimi's mutant RA then needs re-recording; and R7 will probably no longer survive (see notes). |
| R2-2 | MAJOR | `app.py:7676-7680` (`_focus_needs_rehome` text clause); test `:482-518`; packet §5 bullet 2 | **The Find field is still taken, which contradicts LED .57 (c), and the new arm asserts the contradiction.** LED .57 (c) says a visible Find field with area > 0 is never taken, and the text-input rule applies only to fields "the load left stale (hidden, or area 0)". The command bar has had no find input since batch-79 (`command_bar.py:223`). So "the Find field" can only mean the per-window Find inputs of `_FIND_GOTO_INPUTS`, all of which live inside content windows. The code re-homes *every* text input inside a content window. `text_input_in_a_content_window_is_rehomed` pins exactly that, with the Workspace Find `#search_input` visible at area 24. Packet §5 says the Find field "is never taken mid-typing", and its own arm shows the opposite. Impact: typing in Find while an A2L load finishes sends the next keys to the app as commands. | Probe S4b: visible `#search_input` → `files_list` | Implement LED .57 (c) as written. A text input is re-homed only when stale, which the area-0 and hidden-window clauses already cover, so the text clause becomes "a visible text input is healthy". Rewrite the arm: a visible `#search_input` keeps the focus and its typed text through an A2L tail. Add a stale-input arm: focus `#alt_search_input`, hide the A2L window with a rail key, run a load, and the focus must be re-homed. Or the orchestrator amends LED .57 (c) to the palette alone and corrects §5. |
| R2-3 | MINOR | `evidence/inc-4/red-04-fix1-module-at-base.txt`; `green-08`, `green-09`, `green-10` headers | `red-04` is 24 failed + 4 passed = 28 nodes, but the final module has 29. The RED was taken on an earlier version of the test file, so it is not the counterfactual of the module under review. My run of the final module at base: 25 failed, 4 passed. The `red-04`, `green-08`, `green-09` and `green-10` headers name the command and the tree but not `PYTHONPATH` or `NO_COLOR`, which is a BRIEF-inc-4 lesson. | node count; my `r2-base-red.txt` | Re-run the base RED on the final module with full headers, and update §4. |
| R2-4 | LOW | `app.py:7776` | `_resolve_focus_target` falls back only on area 0. A target that is painted but not focusable (disabled) would still be a silent `set_focus` no-op. No target can be disabled today (`diff_compare_button` is never disabled). | code read | Fall back when `not target.focusable or target.region.area <= 0`. |

Notes (no finding):

- **R7** (`None` no longer re-homes) survives only because `_reassert_focus_target` lands a `None` focus one frame later. That makes it equivalent, and the explanation is correct for this tree. If R2-1 removes the re-assertion, R7 should be re-run: TC-B100-13 caught it in round 1.
- **R3/R4**: same overlap as round 1. Keep both clauses.
- **Flakes**: `at_061a` (pre-existing at base), `at_054b` (not reproduced), and `at_038a`/`at_038c` (both trees) belong on the test-race backlog item that Inc 3 opened for `at058b`.

## Verdict

**reject until fixed — `BLOCK — BLOCK-UNTIL: R2-1`.**

- F1 and F2 (round 1 HIGHs) are **discharged** by this re-read: the per-window probe shows 13 of 13 windows on target with `p` live, and R1 is KILLED with 3 nodes.
- R2-1 (HIGH) is new and open. It needs an orchestrator ruling on the Map landing, a code fix, and my re-run of the map arrow probe.
- R2-2 (MAJOR) puts the code against LED .57 (c). Fix it in the same pass, or amend the ledger.
- Open MINOR/LOW: R2-3 and R2-4.

## §4b `Independent review` cell (round 2, for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: R2-1** (round 2: 1 HIGH, 1 MAJOR, 1 MINOR, 1 LOW new; round-1 HIGHs F1/F2 discharged) · F1 was resolved by the focusable targets (Diff `#diff_compare_button`, Map panel `can_focus`), the `can_focus` census and the 12-window `every_window` arm. I re-ran the per-window probe: 24/24 loads on target with `p` live (round 1: Diff `sje_table area=0`, `p -> Screen`). F2 was resolved by a real healthy arm (A2L load, no steal), and I re-ran R1 myself: KILLED, 3 failed (round 1: 10/10 green). F3–F10 and LED .57 (b)/(d) are closed, with one exception: **R2-1 (HIGH, open)** — `_reassert_focus_target` re-lands any id-less focus, so after a load on the Map window the focus is taken from LLR-116.5's auto-selected `RegionRow` and put on the panel, and `up`/`down` stop walking the regions. Base and round 1 walk; the fix pass does not (map arrow probe, executed, `review-increment-004.md` round 2). It needs an orchestrator ruling on the Map landing, the re-assertion removed, and my re-run of the arrow probe. Open: **R2-2 (MAJOR)** — a visible Find field (`#search_input`) is still taken, against LED .57 (c), and the new arm asserts that. R2-3 (the RED transcript was run on a 28-node earlier version of the module). R2-4 (fall back when a target is not focusable).

## Hand-offs (round 2)

- **Orchestrator:**
  - R2-1 ruling: the Map landing is the LLR-116.5 row (recommended), plus a ledger line on HLR-166's "named widget" for the Map.
  - R2-2: implement LED .57 (c) as written, or amend it.
  - Add `at_061a`, `at_054b`, `at_038a` and `at_038c` to the test-race backlog item.
- **`qa-reviewer`:** the Map arrow arm (`down` walks after a load), the stale-input arm, and adding the map suites to the focus reverse census.
- **`ux-reviewer`:** R2-1 (the Map's keyboard subject after a load) and R2-2 (typing in Find during a load).
- **`security-reviewer`:** nothing new. LED .50 holds.

---

# Round 3: re-read of corrective pass 2 and the orchestrator's branch removal

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as rounds 1 and 2. I did not write the fix. Kimi K2.8 wrote fix pass 2, a Sonnet agent finished its tail, and the orchestrator deleted one branch. Who implemented is a process fact; I judged the code. |
| Tree re-read | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc4`. `app.py` sha256 is `79df3ae1c839…`, the orchestrator's tree. `tests/test_b100_focus.py` is `f85b49f5e3d3…`. Still 1 SOURCE file. CRLF is consistent: 14800/14800. Main `31eb572` and `24d5b7f` are identical under `s19_app/` and `tests/` (`git diff --stat` is empty), so diffing against either base gives the same result. I did not edit the worktree. |
| Contract | LED .58 (a)–(c) in main `6a1b8ee`; batch-77 LLR-116.5 and HLR-115. |
| Interpreter proof | `…\scratchpad\r4\fixed3\` = `git archive 31eb572` plus the 3 changed files, hash-equal to the worktree. `…\r4\base3\` = the archive plus the final module. `…\r4\mut3\<id>\` = one tree per mutant. Every transcript prints `s19_app.__file__` from its own tree. `NO_COLOR` unset, s19env 3.11, Textual 8.2.8. |
| **Verdict** | **approve-with-fixes.** Recorded token: **`PASS-WITH-NOTES`**. 0 HIGH is open. **R2-1 is discharged**: I re-ran the map arrow probe myself, and after a load on Map the focus is on the region row and `down` walks it. R7 is KILLED again. One MAJOR is new (R3-1). It does not block, but it should land before the commit, because the fix is deleting 2 lines. |

## What I executed in round 3 (evidence state: `executed`)

| Run (`…\scratchpad\r4\<file>`) | Result |
|---|---|
| GREEN, `fixed3` (`r3-fixed3-green.txt`) | **31 passed**, on the orchestrator's `79df3ae1` tree |
| RED at base `31eb572` with the final module (`r3-base-red.txt`) | **24 failed, 7 passed** (31 nodes). This equals Kimi's `red-06`, whose header now names `PYTHONPATH` and `NO_COLOR`, so **R2-3 is closed**. The 7 passes pin unchanged behaviour: Split/Join boundary, healthy focus, `every_window[map]`, the down-walk arm, visible Find, palette and modal. LLR-116.5 already works at base, which is why the two Map arms pass there. |
| **Map arrow probe**, first load and re-load (`r3-probe-map-arrows.txt`) | After the load settles the focus is `RegionRow start=0x80010000`. `down` moves it to `…10080`, and a second `down` to `…10120`. This is identical to base and to the round-1 tree. Round 2 (fix pass 1): `MemoryMapPanel`, and `down` did nothing. **R2-1 discharged.** |
| **R7** (`None` no longer re-homes), full module | **KILLED: 3 failed** (`empty_state_target_falls_back` and both TC-B100-13 arms). Without the re-assertion, a `None` focus is the tail's job again, as in round 1. |
| R1 (always re-home) | KILLED: 4 failed (healthy, visible Find, palette, modal) |
| RT: the fix-pass-1 rule restored, so every text input in a content window is re-homed | KILLED: 1 failed (`visible_find_input_keeps_its_focus`). **R2-2 discharged.** |
| **RG**: the `RegionRow` guard (`app.py:7695`) disabled | **SURVIVED, 31 passed.** Probe on this tree (`r3-probe-RG.txt`): the arrows still walk after a load on Map, and a hidden row is re-homed. → R3-1 |
| **Hidden-row probe** (`r3-probe-hidden-row.txt`). On Map with the row focused, rail key `1`/`2`/`3`, then an A2L load | The rail key leaves the focus on the hidden row (`RegionRow area=0`; Textual does not clear it). **After the A2L tail it is still on `RegionRow area=0`** on Workspace, A2L and MAC. `p` bubbles and opens the dialog, but the hidden row still consumes `up`/`down`/`enter`. Under RG the same steps land on `files_list` / `a2l_tags_list` / `mac_records_list`. → R3-1 |
| Hidden row then an image load (`r3-probe-hidden-row-image.txt`) | The image path is fine: `watch_current_file` moves the focus first, and the tail re-homes it to `files_list` / `mac_records_list` / `validation_issues_groups`. At base the same steps leave the hidden `sje_table`. Only the A2L tail is affected. |
| The orchestrator's branch removal | **I agree with it.** I diffed Kimi's pristine `77bb9aa6` copy (`%TEMP%\kimi-inc4-fix2\app-pristine.py.bak`) against `79df3ae1`. The only code change is the deleted `isinstance(widget, (Input, TextArea))` block. That block tested `area <= 0`, then the first window ancestor's `hidden` class, then fell through, which is exactly the generic tail below it. The block was dead duplication; the behaviour is unchanged, and GREEN on `79df3ae1` shows the same 31 passes. |
| `devflow-evidence.py --check evidence/inc-4/*` | Every row binds; apart from the index limb (`not staged`), the only mismatches are the 3 files with no row yet: the orchestrator's `green-19`, `green-20` and `orch-guards.txt`. `orch-guards.txt` holds only its header so far (the run was still in progress), and `orch-guards-census.txt` does not exist yet. → R3-2 |

## Closure table — round 2 findings

| id | State | Evidence |
|---|---|---|
| **R2-1 HIGH** | **Discharged** (re-read and re-run) | `_reassert_focus_target` and its scheduling are deleted (LED .58 (b)). `every_window[map]` uses LLR-116.5's threshold. The black-box arm `map_load_keeps_the_region_row_and_down_walks_it` (test `:501-548`) uses rail key `4`, the real Load file dialog and `down` ×2, and `red-05` shows it RED on the fix-pass-1 tree. My map arrow probe walks. |
| R2-2 MAJOR | **Closed** | Visible inputs keep their focus (LED .58 (c)). The `visible_find_input_keeps_its_focus` arm is killed by RT. The `stale_text_input…` arm uses a hidden A2L-window input and is RED at base. |
| R2-3 MINOR | Closed | `red-06`: 31 nodes, full header. My base run gives the same counts. |
| R2-4 LOW | Closed | `_resolve_focus_target` falls back when `not target.focusable or area <= 0`, and FB is killed. |

## New findings — round 3

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| R3-1 | MAJOR | `app.py:7695-7700` (the `RegionRow` guard) and its comment | **The `RegionRow` guard exempts a stale row too, so the A2L tail leaves the focus on a hidden window.** LED .58 (a) protects LLR-116.5's row *on Map*. A visible row on a displayed Map already passes the generic rule (area > 0, window not hidden), so the guard only changes the result for a *stale* row: area 0, or in a hidden Map window. That is exactly where HLR-166 requires a re-home. The comment says a stale row's focus "is either cleared by Textual or re-resolved by the panel's selection-follow". The probe shows neither happens: after a rail key, the hidden row keeps the focus through an A2L load and swallows `up`/`down`/`enter`. This is not a regression, because base leaves the same hidden row. But it is the P-16 shape that LLR-166.2 exists to fix, and no test pins the guard (RG survives 31/31). Deleting the guard keeps LLR-116.5 intact (my RG probe: arrows still walk after a load on Map), because the selection-follow hook runs after the tail and re-focuses the resolved row. | Hidden-row probe: `after A2L tail on workspace: RegionRow#None area=0`; RG: `files_list`; RG → 31 passed | Delete the guard and correct the docstring line; that is the smallest change. Or narrow it to `isinstance(widget, RegionRow) and widget.region.area > 0`, which reduces to the generic rule and so also amounts to deleting it. Add an arm: Map with the row focused, rail key `1`, an A2L load, and the focus must land on `#files_list` (area > 0) while `down` does not walk a hidden row. RG then has a killing arm, or there is no guard left to mutate. The map down-walk arm must stay green. |
| R3-2 | MINOR | packet §1/§2/§4/§6; `evidence/inc-4/` | **The packet describes the `77bb9aa6` tree, not the one under review.** The reverse census, guards and every mutant ran on `77bb9aa6`. Only the orchestrator's `green-20` (31 passed) and the in-progress `orch-guards` ran on `79df3ae1`. The R2 row still says "SURVIVED — EQUIVALENT"; it should say "mutant subject removed (branch deleted, LED .58 (c))", as the orchestrator proposes. 3 evidence files have no packet row. | `--check`; packet `:154`, `:160`, `:175` | When the orchestrator's guards and census runs finish, record the `79df3ae1` hash in §1/§4. Reword the R2 row and the verdict line. `--write` the 3 rows, plus `orch-guards-census.txt`. Because the deleted block was dead, the `77bb9aa6` mutant and census results carry over; say so in one line. |

Notes (no finding):

- **Reverse census** (`reverse-census-fix2.txt`): 976 passed, 1 xfailed, 5 failed.
  - Pre-existing at base, confirmed in rounds 1 and 2: `test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact`, `test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` and `test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection`.
  - `test_before_after_report.py::test_at_061a_persistent_control_survives_then_writes_pair_and_clears` flakes at base (my round-2 runs, and `green-16`/`green-17`).
  - `test_b97_flow_execution.py::test_tc_b97_55_input_queued_during_a_run_starts_no_second_run` failed under load with `2 run_chain_set calls for one Run`. It is green solo 5/5 on this tree (`green-18`) and green at base (`green-19`; that transcript prints each `6 passed` line twice, 8 lines for 5 runs, which is cosmetic).
  - Inc 4 touches no flow-execution code. I classify `tc_b97_55` as a contention flake and recommend adding it to the test-race backlog item. It is not proven failing at base, only never failing in isolation on either tree.
- **Inc 1–3 regressions:** none. The source diff adds no `.resolve(`, `workarea_root`, placement call or `_reset_project_session`. The only new import is `RegionRow`.
- **R3/R4** still overlap (round 1 note). The packet's per-arm counts for K1–K4, LD, F1-diff, F1-map, FB, LC and R5 are full-module runs on `77bb9aa6`; I spot-checked R1 and R7 and my counts match (4 and 3).

## Verdict

**approve-with-fixes — `PASS-WITH-NOTES`.**

- R2-1 (round 2 HIGH) is **discharged** by my re-read and re-run: the map arrow probe walks, and the down-walk arm is black-box and was RED on the fix-pass-1 tree.
- R7 is KILLED (3), R1 is KILLED (4), and the R2-2 regression mutant RT is KILLED (1).
- No HIGH is open.
- **R3-1 (MAJOR)** should land before the commit: delete the `RegionRow` guard, which no test needs (RG survives), and add the hidden-row arm. I do not need to re-review it if the corrective change is exactly that deletion plus the arm and the module stays green. Otherwise send it back to me.
- R3-2 (MINOR) is record hygiene for the orchestrator.

## §4b `Independent review` cell (final, for the orchestrator to write)

`code-reviewer` · **PASS-WITH-NOTES** (0 HIGH open; round 3: 1 MAJOR, 1 MINOR new) · R2-1 (HIGH, round 2) was resolved under LED .58 (a)/(b). `_reassert_focus_target` is deleted; Map's post-load landing is LLR-116.5's row, pinned black-box by `map_load_keeps_the_region_row_and_down_walks_it` (rail `4`, the Load file dialog, `down` ×2; RED on the fix-pass-1 tree). I re-ran the map arrow probe myself on `79df3ae1`: the focus is on `RegionRow`, and `down` walks `…10000 → …10080 → …10120`. I also re-ran R7 (KILLED, 3), R1 (KILLED, 4) and RT, the fix-pass-1 Find rule (KILLED, 1). R2-2, R2-3 and R2-4 are closed. The orchestrator's deletion of the `Input`/`TextArea` branch is correct dead-code removal (diffed against `77bb9aa6`: equal to the generic tail). Open: **R3-1 (MAJOR)** — the `RegionRow` guard also exempts a row in a hidden Map, so after a rail key an A2L load leaves the focus on `RegionRow area=0` (probe, executed). The guard is unpinned (RG survives 31/31), and deleting it keeps the Map arrows working (RG probe). Delete it and add the hidden-row arm before the commit. R3-2 (MINOR) — the packet should cite the `79df3ae1` tree and read the R2 row as "mutant subject removed".

## Hand-offs (round 3)

- **Orchestrator:**
  - R3-1: route the 2-line deletion and the hidden-row arm.
  - R3-2: the packet hash, the R2 row, and 4 evidence rows.
  - Add `tc_b97_55` to the test-race backlog with `at_061a`, `at_054b`, `at_038a` and `at_038c`.
- **`qa-reviewer`:** the hidden-row arm (R3-1).
- **`security-reviewer`:** nothing new. LED .50 holds.
