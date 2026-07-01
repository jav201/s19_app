# 04 — Validation — batch-21 (#8 slice-1: US-026/027/029)

> Phase 4. Two-layer validation on the final Inc1+2+3 tree. **VERDICT: PASS.** 3 US / 3 HLR / 7 LLR covered BOTH layers; 0 blocker fails. All provisional AT/TC ids reconciled to real on-disk nodes (V-5). Frozen-engine diff 0; ruff clean.
> Executed directly by the orchestrator (as batch-20 Phase 4): the qa-reviewer agent pattern stalled behind long test runs repeatedly this session; the orchestrator holds the full execution evidence (all 11 nodes run green + full-suite confirmed + per-increment counterfactual REDs captured by the independent code-reviewers). Independent lens was applied per-increment by `code-reviewer` (3×) + Phase-2 `qa-reviewer`.

## V-5 reconciliation — provisional id → real collected node
| Provisional | Real node | Layer | Result |
|---|---|---|---|
| AT-031a (gate) | `tests/test_tui_patch_editor_v2.py::test_at031a_save_doc_lands_in_patches_folder` | B | PASS |
| AT-031b (boundary) | `::test_at031b_two_saves_are_distinct_no_clobber` | B | PASS |
| TC-031 (placement, NET-NEW) | `tests/test_unified_write.py::test_tc031_write_target_resolves_under_patches_folder` | A | PASS |
| AT-030a (C-12 GATE) | `tests/test_tui_patch_editor_v2.py::test_at030a_dropdown_lists_and_loads_selected_change_file` | B | PASS |
| AT-030a-R2 (refresh) | `::test_at030a_r2_save_while_open_appears_without_reactivation` | B | PASS |
| AT-030b (boundary) | `::test_at030b_empty_patches_folder_renders_placeholder_no_crash` | B | PASS |
| AT-030c (guard, NOT the gate) | `::test_at030c_directly_dropped_file_is_listed_and_loadable` | B | PASS |
| F1 (security) | `::test_f1_symlink_entry_is_skipped_by_scan` | B (sec) | PASS |
| TC-030 (scan white-box) | `::test_tc030_scan_returns_sorted_json_set_ignoring_non_change_files` | A | PASS |
| AT-032a (gate) | `::test_at032a_checks_help_states_what_and_which_artifact` | B | PASS |
| AT-032b (regression/wiring) | `::test_at032b_clarity_added_action_wiring_unchanged` | B | PASS |

11 nodes, all PASS (targeted run: `11 passed`).

## Layer A — functional (white-box)
- **HLR-031:** TC-031 pins the final save path `is_relative_to(workarea/"patches")` + folder-creation (net-new — the generic containment tests couldn't detect the root→patches move). PASS.
- **HLR-030:** TC-030 — scan returns the sorted `.json` set, ignores non-change files; empty → placeholder. PASS.
- **HLR-032:** covered by the render assertion in AT-032a (pure-render req, no separate white-box layer needed).
- Folder-creation + no-clobber dedup are inherited from `copy_into_workarea` (workspace.py) — verified by TC-031 (creation) + AT-031b (distinct names).

## Layer B — behavioral (black-box), through the shipped surface
- **US-027 (folder):** AT-031a observes the on-disk `patches/*.json` produced by the real `save_doc`; AT-031b (boundary) asserts two distinct names, no clobber.
- **US-026 (dropdown):** **AT-030a is the C-12 GATE** — two files via the real `save_doc` → dropdown scan lists both → select the SECOND by known filename → assert its distinguishing entry (0x200) loaded (non-default + content). AT-030a-R2 (save-while-open refresh), AT-030b (empty boundary, no crash), AT-030c (direct-drop consumer GUARD — stays green under a reverted save handler, structurally not the gate), F1 (symlink entry skipped / `is_relative_to(patches/)` containment). Representative + boundary + negative + security all present.
- **US-029 (clarity):** AT-032a asserts the rendered token span "runs the loaded change document's checks against the loaded image"; AT-032b confirms clarity added AND the `run_checks` wiring unchanged (drives `button.press()` → the dynamic "Checks:" status line, a different path from the static Label — genuine, not vacuous).

## Bidirectional surface-reachability matrix
| Dimension | Direction | Through handler? | Observed by |
|---|---|---|---|
| Change-doc save (`save_doc`) | input→output | yes | AT-031a/b (on-disk `patches/*.json`) |
| Two distinct saved files | input | yes (real save ×2) | AT-030a (C-12 producer) |
| Dropdown selection | input | yes (`Select.Changed`→load) | AT-030a (loaded doc content) |
| Empty patches folder | input (boundary) | yes | AT-030b (placeholder, no crash) |
| Directly-dropped file | input | yes (scan) | AT-030c (guard) |
| Symlink / escaping entry | input (adversarial) | yes | F1 (skipped/rejected) |
| Save while screen open | input | yes (post-save re-scan) | AT-030a-R2 |
| Checks affordance render | output | yes (composed screen) | AT-032a |
| `run_checks` route | input→output | yes (`button.press`→status) | AT-032b |

Both input dimensions and output/deliverables exercised THROUGH the handler. Complete.

## Counterfactual evidence (QC-2 — one+ per increment, captured at implement/review time)
| Increment | Counterfactual revert | Captured RED |
|---|---|---|
| Inc1 (031) | placement `workarea` (root, not patches/) | TC-031 + AT-031a: file not under `patches/` (`found []`) |
| Inc2 (030) | `_scan_patch_change_files` → `[]` | AT-030a: `InvalidSelectValueError: Illegal select value 'changes_1.json'` (2nd file can't list/load) |
| Inc3 (032) | remove the description Label | AT-032a: `NoMatches on #patch_checks_help` (token span absent) |
Each value-discriminating. Each AT can FAIL.

## Test-count ledger (collected non-slow)
`974 (base ec3a2a7) + 11 = 985`. Inc1 +3 (TC-031, AT-031a/b; 2 e2e globs rewritten-in-place net 0) · Inc2 +6 (AT-030a, AT-030a-R2, AT-030b, AT-030c, TC-030, F1) · Inc3 +2 (AT-032a/b). **Full non-slow (final tree): 953 passed / 29 skipped / 3 xfailed / 0 failed** (985 collected = 953+29+3). Reconciles exactly.

## Quality gates
- ruff: clean (all changed production + test files). **Frozen-engine diff vs origin/main (ec3a2a7): empty**; `test_engine_unchanged` green. No SVG snapshot regen (patch editor has no baseline).
- **F1 self-fold** (orchestrator, from the Inc2 code-review LOW): the load-path symlink check was dead (on the resolved path) → made live (on the unresolved path); re-verified green.

## Blocker check
- US-027: black-box deliverable observed (AT-031a on-disk file). ✓
- US-026: black-box deliverable observed (AT-030a C-12 gate — dropdown lists + loads the right file). ✓
- US-029: black-box deliverable observed (AT-032a rendered clarity + AT-032b live wiring). ✓
- **No story validated by white-box only.** 0 blockers.

## Gaps / carries
- **DEFERRED (later geometry batch):** US-028 (variant dropdown), US-030 (4-pane split — SPIKE, needs host-width measurement + C-13.1 ladder), US-031 (snapshots).
- **Process (→ Phase 5):** (1) the Phase-2 supersession census missed 2 e2e placement globs (keyed on white-box tc018, not e2e save-observers); (2) `software-dev` stalled without a packet on Inc2 (94 tool calls) and the qa-agent pattern stalls behind long suites — reinforces batch-20's "checkpoint-before-long-run" carry.
- N1 (LOW): pre-existing `write_change_document` docstring "later increment" wording — stale, future touch.
- No §6.5 amendment (the temp→root correction was a Phase-2 spec fold, not a Phase-3/4 requirement change).

**VERDICT: PASS.** No `iterate-to-fix` / `iterate-to-refine` — black-box and white-box both green, 0 blocker.
