# Code Review — Increment 003 (batch-100, "A project load starts clean")

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`. Independent: I did not write this code. The implementer was Kimi K2.8. |
| Tree reviewed | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc3`, detached at `dad6423`, with uncommitted changes. `app.py` sha256 `ca8e539b4c8c…`, equal to the HANDOFF's final hash. The worktree was never edited. My only command inside it was a read-only `pytest tests/test_id_registry.py` run with `PYTHONDONTWRITEBYTECODE=1 -p no:cacheprovider`; `git status` was unchanged afterwards. |
| Contract | `01-requirements.md`: HLR-165, LLR-165.1..165.4, P-25, P-26, LED .50 and .51. `design/ARQ-batch-100.md` §2.1–§2.3 (S1–S13, K1/K2, U1, the seam). `design/design-proposal-b100.md` §5.3. `kimi/BRIEF-inc-3.md`, `BRIEF-COMMON.md`. Precedents: `review-increment-001.md`, `review-increment-002.md`. |
| Interpreter proof | s19env Python 3.11.15. `…\scratchpad\base\s19_app\__init__.py` (`git archive dad6423` + the new test file), `…\scratchpad\fixed\s19_app\__init__.py` (archive + the 3 changed files, `app.py` hash equal to the worktree), and one tree per mutant under `…\scratchpad\mut\<id>\`. `PYTHONPATH` = that tree, `NO_COLOR` unset (`env -u`), `PYTHONDONTWRITEBYTECODE=1`. |
| **Verdict** | **approve-with-fixes.** Recorded token: **`BLOCK — BLOCK-UNTIL: F1`** (1 HIGH). This verdict authorises nothing. The increment does not advance until F1 is fixed and I have re-read the fix on the diff and re-run mutant R6. F2–F4 (MAJOR) should land in the same corrective pass. F2 and F3 each need an orchestrator ruling first. |

`…\scratchpad` = `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad`.

## BLUF

The product change is correct and small. One seam is called once, after validation and before the first install. It resets S1–S12 plus the A-07 names, rebinds the change service and re-pushes the generation. Unload now clears the parsed A2L. The P-2 leaks, the contaminating re-save and P-25 are all fixed. I confirmed this at base (RED) and on the fixed tree (GREEN).

What blocks is the test suite. It cannot see 7 of the reset's lines. I deleted all of S7–S11 (the CRC template, the comparison and check spec, the flow run, the execution and the report filter) and the module stayed **16/16 green** (F1). The P1 scenario never sets that state, so neither the relative arm nor the direct arm can detect a leak there. S7 is the latent leak that the ARQ names as the reason for the derived comparison.

The interim notice also has a correctness problem. It reports entries the user already saved or loaded as "unsaved" (F2, executed). After the reset, the Patch panel still carries its dirty marker on an empty ledger (F3, executed).

## Scope reviewed

- `s19_app/tui/app.py`, the whole diff:
  - `_SESSION_SNAPSHOT_NAMES` `:1420-1495`;
  - `_reset_project_session` `:8974-9104`;
  - `_session_snapshot` `:9106-9215`;
  - the call `:9237-9242` and the notice `:9300-9306` in `_handle_load_project`;
  - `_apply_unload` `:11075-11081`;
  - `import hashlib`.
- Also read, to judge impact:
  - `_variant_set` setter `:7318-7327`;
  - `_write_and_verify_manifest` `:8771-8900`, for the Inc 2 `_last_manifest_verify_result`, and its only reader `:8760`;
  - `save_doc` `:3404-3419`;
  - `_invalidate_mac_view_cache` `:11207`;
  - `_mac_view_cache_key_for` `:11236-11286`;
  - the A2L cache `:12335-12356`;
  - `_compute_a2l_enriched_tags` `:13300-13320`;
  - `watch_current_file` `:11769`;
  - `workspace.validate_project_files` and `build_variant_set`;
  - `PatchEditorPanel.refresh_entries`, `_show_document`, `_dirty` and its four writers, `mark_saved` and `mark_loaded` (`screens_directionb.py`).
- `tests/test_b100_session_reset.py` (all of it) and the `tests/test_id_registry.py` diff.
- The packet `increment-003.md`, `HANDOFF.md`, and all 21 files in `evidence/inc-3/`.

## What I executed (evidence state: `executed`)

| Run | Result |
|---|---|
| **Behavioural RED at base.** New module on `git archive dad6423` (`…\scratchpad\base-red.txt`, `base-red-lines.txt`) | **14 failed, 2 passed.** Behavioural failures: `LEAK mac_path` (`:371`); `the reset kept the old ChangeService`; both notice arms (log ends `Loaded project 'P2' -> prg.s19`, with `Loaded prg.s19 (S19+MAC: firmware.mac)` above it, which is P1's MAC re-attached); `unload all kept current_a2l_data (P-25)`; `unload a2l kept current_a2l_data`; `the bare S19 reload re-attached the stale A2L`; both AT sizes; and the order arm (`['install', 'install', 'install', 'install']`). The call-site census shows `[]`, which is structural. **Three TC-B100-09 arms fail on `AttributeError: … no attribute '_session_snapshot'`**, a missing symbol and not a behavioural RED. Their behavioural RED comes from mutants M2, M3 and R10 (F7). The 2 passes are the must-stay-green guards (loose file: no reset; nothing unsaved: no notice). |
| GREEN, fixed tree (`fixed-green.txt`) | **16 passed** (97 s) |
| Kimi M1 re-run, full module (reset moved after the first install) | **KILLED**, 4 failed: the TC-08 order arm, `load_over_leaves_no_p1_state`, and **both AT sizes**. The packet names only the first two. |
| Kimi M4 re-run, full module (old `ChangeService` kept) | **KILLED**, 3 failed: `load_over_matches_cold…`, `load_over_leaves_no_p1_state`, `change_service_is_rebound`. **Both notice arms stay GREEN** (F4). |
| Reviewer R6: the 7 reset lines of S7–S11 deleted | **SURVIVED. 16 passed.** → F1 |
| Reviewer R7: the S12 lines plus the 4 A-07 assignments deleted | KILLED by one node only, `load_over_matches_cold…`. Recorded as a note. |
| Reviewer R8: the `refresh_entries` repaint deleted | **SURVIVED. 16 passed.** The ledger is empty anyway (probe under R8: 0 table rows), because the install's deferred chain repaints it. → F8 |
| Reviewer R9: `current_a2l_data = None` deleted from the reset only | KILLED: `load_over_matches_cold…` and `load_over_leaves_no_p1_state` |
| Reviewer R10: the three keyed-cache reductions bypassed. This is LLR-165.2's third negative control, which the packet did not run. | KILLED: `two_cold_loads_have_equal_snapshots` and `load_over_matches_cold…`. The normaliser is load-bearing. |
| Mutant hashes | Each mutant tree's `app.py` hash is printed in its transcript `…\scratchpad\mut2-<id>.txt`. Every mutant was applied to a copy, so nothing was restored in the worktree. |
| Probe `saved_document_is_reported_as_unsaved` (`…\scratchpad\probe\tests\test_zz_review_probes.py`) | `save ok: True saved files: ['.s19tool\workarea\P1\patches\changes.json']`, then the log reads `Discarded 1 unsaved Patch Editor entries`. → F2 |
| Probe `panel_dirty_marker_after_load_over` (by keys, 220×60) | panel before `(dirty=True, rows=1)`; after the load-over `(dirty=True, rows=0, table rows=0, doc entries=0)` → F3 |
| Census blind-spot probe (`…\scratchpad\probes\census_probe.py`) | 0 tuple-target self-assignments, 0 `setattr`. The 3 aug-assigned names are also plain-assigned. 0 writes of `app.<name> =` from any other `s19_app` module. The census is complete for what it claims. |
| Reverse-census nodes, 3 runs each at base and on the fixed tree (`…\scratchpad\preexist-{base,fixed}.txt`) | Identical on both trees, 3 of 3 runs: `test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact` and `test_at_056e_a2b_diff_report_byte_identical_despite_selection` **fail at base and on the fix: pre-existing.** `test_at078a_counts`, `test_at078b_zero_total`, `test_save_back_prompt`, `test_saveback_width_16_caps_records_and_empties_s0`, `test_paste_parse_then_apply_matches_file_loaded` and `test_at030c_directly_dropped_file_is_listed_and_loadable` pass 3 of 3 on both trees, so they are order or timing flakes and none is caused by this increment. Kimi's `preexisting-at078b-flake.txt` shows `at078b` failing at base. |
| §5.4 population: `tests/test_tui_patch_variant.py` (fixed tree) | 12 passed |
| `tests/test_id_registry.py` (worktree, read-only) | 13 passed (217 holds) |
| `devflow-evidence.py --root . --check evidence/inc-3/*` | Exit 0. All 21 on-disk digests equal the packet's 21 values (compared one by one). The tool reports `packet records no digest for this path` for every row, because the packet's path column holds bare names (F11). The `index blob` MISMATCH lines only mean "not staged". |
| CRLF | `app.py` 14460/14460, `test_b100_session_reset.py` 716/716, `test_id_registry.py` 854/854; `core.autocrlf=true` ✓ |
| Source files touched | `git diff --stat`: `app.py` is the only SOURCE file (1/4). `screens_directionb.py` and `change_service.py` are untouched ✓. No `.resolve()` and no placement call added (LED .50) ✓ |

## Findings

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **F1** | **HIGH** (false-confidence test) | tests `:309-379`; `app.py:9046-9055` | **The reset of S7–S11 is unpinned. The suite stays green when all of it is deleted.** The P1 scenario loads files and adds 1 entry. It never sets `_last_template_path`, `_diff_last_result`, `_diff_check_spec(_name)`, `_last_flow_run`, `_last_execution` or `_report_filter_path`. So the relative arm compares default against default for those names. The direct arm asserts `_last_template_path is None` on a value that was never set, and its docstring says "RED at base: every one of these leaked". That is false for `_last_template_path` and `_declared_regions`. ARQ §2.3 requires the derived comparison precisely because "a hand-listed set would miss the next S7". As written, it misses S7 itself. S7 is user-visible: the next Save project gathers P1's CRC template into P2's `templates/` (ARQ §2.2). The S5/S6 and K1/K2 rows are covered by other paths. | R6 (all 7 lines deleted) → **16 passed**. The code itself is correct today (read). | Before the load-over, give P1's session a non-default value for every S5–S12 name the scenario does not touch. Do it in the relative arm (`load_over_matches_cold…`) and in the direct arm: `_last_template_path` = a file under P1, a `_diff_last_result` object, `_diff_check_spec` / `_diff_check_spec_name = "p1"`, `_last_flow_run`, `_last_execution`, `_report_filter_path`, `_a2l_tag_find_query = "p1"`, `_pending_variant_id`. Direct assignment is fine in a white-box TC. Correct the docstring. Discharge: I re-run R6 and it must go RED, with the S7 name in the `LEAK` line. |
| F2 | MAJOR | `app.py:9025`, `:9300-9306`; packet §5 bullet 4, HANDOFF item 4 | **The interim notice calls saved and loaded entries "unsaved".** N is `len(document.entries)`. The packet justifies it this way: "until [Inc 5] every document entry is unsaved work by construction". That premise is false at this base. `save_doc` writes the document to disk and calls `panel.mark_saved()` (`app.py:3404-3417`), and a document loaded from a file is marked loaded (`:5528`). So a user who saved their entries and then loads another project is told `Discarded 1 unsaved Patch Editor entries`. That is a false alarm about lost work, and LED .51 scopes the line to *unsaved* entries. The brief said: if no app-side way to count unsaved entries exists, STOP and write it in HANDOFF. HANDOFF item 4 raised it, but on the false premise. | Probe: `changes.json` written to `P1\patches\`, then `Discarded 1 unsaved Patch Editor entries` | Orchestrator ruling. Option (a): count N only while the outgoing panel is dirty. The app already holds that signal, because it calls the panel's `mark_saved` / `mark_loaded` itself: track an app-side `_patch_doc_clean` flag at those call sites, which would be a new census name. Option (b): ledger-amend LED .51 to "Discarded N Patch Editor entries", dropping "unsaved" until Inc 5's saved-state record. Either way, add an arm: save the document, load over, no notice (or the amended wording). Correct packet §5 and HANDOFF. |
| F3 | MAJOR | `app.py:9096-9103` | **After the reset, the Patch panel stays dirty over an empty ledger.** The reset discards the entries and repaints the ledger, but the panel's `_dirty` (writer w1, set by entry edits) survives. `refresh_entries` then paints the subtitle `0 entries ●`, and the panel's Load guard (`DirtyLoadRequested`) will ask about unsaved edits on an empty document. At base the entries survived too, so the marker was consistent; this diff introduces the mismatch. Inc 10's load question will read the same flag and so ask on every later load. Caveat: `_dirty` also covers the paste buffer (w2), which the reset does not clear (ARQ U1). A bare `mark_loaded()` would therefore hide genuine buffer edits. | Probe by keys: before `(True, 1)`, after `(True, 0, 0, 0)` | Orchestrator ruling, together with F2. Either the seam also reseeds the paste buffer and calls `panel.mark_loaded()`, which is public, so no edit to `screens_directionb.py` is needed. Or record the stale marker as a known interim state routed to Inc 10 in a ledger entry. Add the arm the ruling chooses: after a load-over with an entry added through the panel, the subtitle is `0 entries` with no `●`. |
| F4 | MAJOR | packet §4 *Mutation verdicts*, m4 | **The m4 verdict claims kills that did not happen.** The packet says the rebind removal kills `test_tc_b100_10_interim_discard_notice` and `…_notice_names_every_discarded_entry` because "the notice reads N=0". Kimi's own `mutations-all.txt` §m4 shows `3 failed, 3 passed`, and the two notice arms are among the passes. My full-module re-run agrees: 3 failed (`load_over_matches_cold…`, `load_over_leaves_no_p1_state`, `change_service_is_rebound`). The count is read *before* the rebind (`:9025`), so no rebind mutation can affect it. The notice arms therefore have no recorded killing mutant. Smaller: §m1 omits the 2 AT kills. | `mutations-all.txt` §m4 tail; `…\scratchpad\mut2-m4_keep_service.txt` | Correct the m4 and m1 rows. Add a mutant aimed at the notice, such as reading N after the rebind, which gives 0 and no line. Record it against both notice arms, executed on the full module. |
| F5 | MINOR | packet §4 reverse census batch C, §6 | **The batch-C dispositions contradict their own transcripts.** (a) The packet says `test_at030c_directly_dropped_file_is_listed_and_loadable` "passes in isolation (`green-06b`)". `green-06b` shows it **FAILED** (`3 failed, 1 passed`; `got -0x1`). (b) `green-06` holds two runs. The first failed `test_at078a_counts`, `test_save_back_prompt` and `test_saveback_width_16_caps_records_and_empties_s0`, and none of the three is dispositioned. The substance holds: my 3+3 runs show all six pass on both trees and the two deterministic ones fail identically at base. | `green-06b` lines 172-175; `green-06` lines 255-259; `…\scratchpad\preexist-*.txt` | Rewrite the dispositions to match the transcripts, cite a base-vs-fix run for all 8 nodes, and name the 3 first-run nodes. |
| F6 | MINOR | tests (missing arm) | **LLR-165.3's boundary arm is missing.** The boundary catalog marks "a worker that captured the old service finishes against it (no exception)". No node exercises it, and the packet does not disposition it. | code read | Add the arm: start the `before_after_report` or `execute_scope` worker on P1, load P2 before it finishes, then assert no exception and that the new service is untouched. Or record a disposition with a reason. |
| F7 | MINOR | packet §4 RED table | **The RED record does not separate missing-symbol REDs from behavioural ones.** Three of the 14 base failures are `AttributeError: _session_snapshot`, and the brief says that is not a RED. Their behavioural RED is M2/M3 plus LLR-165.2's third negative control (the un-normalised snapshot), which the packet did not run. I ran it (R10): KILLED. | `base-red-lines.txt`; `mut2-r10_no_key_normaliser.txt` | Label those 3 nodes in the RED table, and add the R10 row with an executed transcript. |
| F8 | MINOR | tests `:632-716` | **The AT omits HLR-165's observable "the Patch Editor ledger is empty".** LLR-165.1's `refresh_entries` clause is also unpinned (R8 survives). There is no user impact today, because the install repaints the ledger (R8 probe: 0 rows). | R8 → 16 passed | After the load-over, assert in the AT that `#patch_doc_entries_table` has 0 rows and the empty-state line is shown. Keep the seam's repaint: the contract requires it. |
| F9 | MINOR | `app.py:9152-9156`, `:9178-9179` | **The snapshot normaliser is coarse for payloads.** Plain dicts reduce to their key list. `current_a2l_data` is a `dict` with fixed section keys, so two different A2L payloads compare EQUAL, and the same applies to `_a2l_cache_data`. The image digest hashes the bytes in address order but not the addresses. The current scenarios still see the leaks only because P2 has no A2L (`None` vs dict). Inc 8a's threshold reuses this snapshot ("the same final snapshot as a main-thread load"). | code read | For dicts, reduce to `(len, sorted keys, digest of the canonical repr of the values)`, or give the A2L payload a named reduction such as tag count plus a digest of the tag names. Feed `address, byte` into the image digest. |
| F10 | MINOR | `app.py:9066-9068` | **The 8-vs-7 count.** The code clears **eight** `_mac_view_cache_*` names through `_invalidate_mac_view_cache` (`key, rows, meta, summary, coverage_line, widths, cell_rows, cell_styles`). The census holds exactly those eight. That is a correct superset of LLR-165.1's "seven" (the probe predates `widths`). The code comment still says "all seven". Separately, `_last_manifest_verify_result` (Inc 2) is not reset, which is correct, because it is rewritten at `:8864` before its only reader `:8760`. Neither it nor `_variant_set_value` has an ARQ §2.2 row. | code read; census | Change the comment to "eight". The orchestrator should record the 8 and the two unclassified names (install-owned or channel) in the ledger, so the inventory matches the census. |
| F11 | MINOR | packet §4 evidence table; worktree root | **Record hygiene.** (a) The evidence path column holds bare file names, so `devflow-evidence.py --check` cannot bind any row. All 21 digests do match disk (my one-by-one comparison). Use the full `.dev-flow/2026-10-26-batch-100/evidence/inc-3/<file>` paths, as `increment-002.md` does, or write the rows with `--write`. (b) `HANDOFF.md` sits at the worktree root. Move it to `kimi/inc-3-HANDOFF.md` as Inc 1 and Inc 2 did. (c) The mutation transcripts run selected nodes only, so the packet's "arms that stayed GREEN" is not evidenced. F4 is what that hid. | tool output; `ls` | Fix the record in the corrective pass. |

Notes (no finding):

- **R7.** The S12 lines and the 4 A-07 assignments are killed by only one node, the relative arm. F1's seeding should give the direct arm those names too.
- **`_SESSION_SNAPSHOT_NAMES`.** It is a 68-name hand list in product code that the test census must equal. Every later increment that adds a `self.<name> =` must extend it. That is the intended C-31 tripwire (M3 proves it), but Inc 4–11 will pay for it each time.

## Checks the brief named

| Check | State |
|---|---|
| Reset called once, after validation, before the first install | ✓ `:9242`, after `validate_project_files` and the empty check, before `build_variant_set` and the first `load_selected_file`. One call site (AST census). The early return after the reset (`selected_file is None`) cannot be reached: `data_files` ⊆ S19/HEX/MAC, so a primary or the MAC always exists. |
| Resets every inventory row and the A-07 names, rebinds the service, re-pushes the generation | ✓ S1–S12 plus the 4 named S13 assignments plus 8 caches through the invalidator (F10). `ChangeService()` and `set_image_generation(self._image_generation)` are at `:9086-9087`. K1 and K2 are kept. ✗ S7–S11 are untested (F1). |
| Unload clears `current_a2l_data` | ✓ `:11081`, inside `if kind in ("all", "a2l")`. TC-B100-11 is RED at base and GREEN now. |
| Nothing the user needs is lost; Inc 1/2 state | ✓ `current_project_dir` is untouched by the reset and re-set unresolved by the caller (LED .50). `_variant_set` goes through its setter to `None`, then the caller adopts the manifest's set. `_last_manifest_verify_result` is safe (F10). ✗ The notice mislabels saved work (F2). The panel's dirty marker goes stale (F3). |
| `_session_snapshot()` census, normaliser, empty exclusion list | ✓ The empty list is right. The census covers only `S19TuiApp`'s own source, and Textual's attributes are assigned in Textual's source, so none can appear. My probe found no blind syntax form and no external writer. It is not vacuous (M3 kills the domain arm, R10 kills cold-vs-cold) and not flaky (cold-vs-cold green in 9 runs). Its real blind spot is widget-held state (U1), which is where F3 lives. ✗ The normaliser is coarse for payloads (F9). |
| 8 vs 7 `_mac_view_cache_*` | The code says **8**, and all 8 are cleared. The comment says 7 (F10). |
| The relative load-over arm vs order mutations | Acceptable. LLR-165.2 requires a relative comparison, and M1 is killed by the order arm, the direct arm and both AT sizes. The real weakness is scenario coverage, not relativity (F1). |
| LED .51 notice: N, the reader, the wording | Wording ✓ verbatim `Discarded N unsaved Patch Editor entries`, painted as the newest line after `Loaded project …`. Reader ✓ app-held document, `screens_directionb.py` untouched. N ✗ for saved or loaded documents (F2). |
| RED behavioural at base | ✓ 11 of 14 are behavioural; 3 are missing-symbol, covered by M2/M3/R10 (F7) |
| Reverse census and pre-existing failures | ✓ The 2 deterministic failures are pre-existing at base: `test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact` and `test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection`. The flake `test_tui_patch_checks_strip.py::test_at078b_zero_total` is shown failing at base by Kimi and passes 3 of 3 for me on both trees. ✗ The record of the other batch-C nodes is wrong (F5). |
| Hygiene | ✓ 1 SOURCE file, CRLF preserved. ✓ §2 Kinds are `source` / `test` / `config`, all from the closed six. ✓ `Traces to` holds real ids (HLR-165, LLR-165.1..165.4), so V59 is satisfied. ✓ V56: every `N passed/failed` figure in the packet appears in its cited transcript (16; 14/2; 2; 218; 328+1x/1; 221+1s/4; 194; 75; 87). The packet has no figure images. ✓ Digests match. ✗ The `--check` binding and HANDOFF placement (F11). |

## Evidence checklist

- [x] Diff read in full: `app.py` `:1420-1495`, `:8974-9215`, `:9237-9306`, `:11075-11081`; the whole new test file; the `test_id_registry.py` diff.
- [x] Correctness pass: the order and the unreachable early return are checked; the unload works. F2 (N mislabels saved work) and F3 (stale dirty) are executed. The Inc 1/2 state is checked.
- [x] Simplicity pass: the seam is flat assignments plus one rebind, with no premature abstraction. Recorded note: the hand-listed 68-name domain.
- [x] Reuse checked: `_invalidate_mac_view_cache` and the `refresh_entries` call shape of `_refresh_patch_history_view` are reused. No `reset()` was added to the service (P-26 holds).
- [x] Tests reviewed for intent: F1 (S7–S11 vacuous), F4 (notice arms without a killing mutant), F6 (missing boundary arm), F8 (AT omits the ledger observable).
- [x] Verdict explicit: `BLOCK — BLOCK-UNTIL: F1`. The one HIGH is open, with executed evidence (R6 survived).

## §4b `Independent review` cell (for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: F1** (1 HIGH, 3 MAJOR, 7 MINOR) · F1 is open: deleting all seven S7–S11 reset lines leaves `tests/test_b100_session_reset.py` 16/16 green (mutant R6, executed, `review-increment-003.md`). The P1 scenario never sets that state, so the relative and direct TC-B100-09 arms cannot see a leak of the CRC template, the comparison, the flow run, the execution or the report filter. F1 is discharged only when a re-read of the applied fix shows P1 seeded with non-default S5–S12 values in both arms, and my re-run of R6 goes RED naming the S7 attribute. The product reset itself is correct: P-2, P-25 and the AT are RED at base and GREEN now. Open MAJORs: F2 (the notice counts saved or loaded entries as "unsaved"; ruling needed), F3 (the panel stays dirty, `0 entries ●`; ruling needed), F4 (the m4 verdict claims notice kills its own transcript does not show).

## Hand-offs

- **Orchestrator:**
  - F2: a count gated on a clean or dirty signal, or amending LED .51's wording until Inc 5.
  - F3: the seam clears the panel's dirty flag and paste buffer, or the stale marker is ledgered to Inc 10.
  - F10: record the 8 caches and the two unclassified census names in the inventory.
  - The two pre-existing failures need owners: the batch-78 palette artifact and `at_056e_a2b`.
- **`qa-reviewer`:** F1 (seeding design), F6 (worker boundary arm), F8 (AT ledger observable), F9 (normaliser strength before Inc 8a reuses it).
- **`security-reviewer`:** nothing new. No placement call and no path resolution were added. LED .50 holds.

---

# Round 2: re-read of corrective pass 1

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as round 1. I did not write the fix. |
| Tree re-read | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc3` at `dad6423`, with Inc 3 and fix pass 1 uncommitted. `app.py` sha256 `18ee4d450529…`, equal to HANDOFF §"Fix pass 1". Still 1 SOURCE file. CRLF preserved: `app.py` 14508/14508, test file 885/885. The worktree was not edited. |
| Contract | main `3d3cee0`: LED .55 (a) the notice wording `Closed the Patch Editor document (N entries); unsaved changes were not kept`; (b) the seam calls `panel.mark_loaded()`. `kimi/BRIEF-inc-3-fix1.md`. |
| Interpreter proof | `…\scratchpad\fix1\s19_app\__init__.py`, a copy of the worktree's `s19_app` with an identical `app.py` (`cmp`). Mutant trees are under `…\scratchpad\mut1\<id>\`. `NO_COLOR` unset, s19env 3.11. |
| **Verdict** | **approve — PASS-WITH-NOTES.** 0 HIGH open. **F1 is discharged**: I re-read the seeding on the diff and re-ran R6 myself, and it is now RED. F2–F11 are closed, with one exception. **R2-1 (MAJOR)** is new: `mark_loaded()` does not clear the paste buffer, which LED .55(b) and the packet both claim it does. It does not block, but it must be fixed in this increment or the ledger must be corrected before Inc 10. |

## What I executed in round 2 (evidence state: `executed`)

| Run (`…\scratchpad\r2-<id>.txt`) | Result |
|---|---|
| GREEN, the fix-pass tree | **17 passed** (104 s) |
| **R6** (the 7 S7–S11 reset lines deleted), mutant `app.py` `4b958a07…` | **KILLED**, 2 failed. The relative arm prints `LEAK _diff_check_spec: cold=None warm=['p1-check-spec', 2], _diff_check_spec_name …, _diff_last_result …, _last_execution …, _last_flow_run …`. The direct arm prints **`LEAK last_template_path`** (S7). Round 1: 16/16 green. |
| R7 (S12 plus the 4 A-07 assignments deleted) | KILLED by 2 nodes: the relative arm and the direct arm. Round 1: 1 node. |
| M4 (old service kept) | KILLED, 6 failed: both TC-09 load-over arms, `change_service_is_rebound`, the new boundary arm, and both AT sizes. The AT now catches it through `0 entries` and the empty ledger. |
| R12 (the notice is never painted: `if discarded_unsaved:` → `if False:`) | KILLED, 4 failed: both notice arms and both AT sizes. Together with Kimi's m6 (the count read after the rebind), the notice now has killing mutants. **F4 closed.** |
| R11 (`panel.mark_loaded()` deleted from the seam) | KILLED, 2 failed: both AT sizes, on the no-`●` assertion. **F3's arm is non-vacuous.** |
| R8b (the seam's `refresh_entries` call deleted, `mark_loaded` kept) | **SURVIVED**, 17 passed. The ledger is still empty because the install repaints it. → R2-2 |
| Round-1 probes, re-run (`…\scratchpad\probes-r2-out.txt`) | **Saved document:** `changes.json` written, then the line is `Closed the Patch Editor document (1 entries); unsaved changes were not kept`. That is truthful for saved work (F2 ✓). **Dirty marker:** after the load-over by keys, `_dirty=False` and the subtitle is `0 entries`, with no `●` (F3 ✓). **Paste buffer:** `'P1 DRAFT TEXT'` before the load-over and **`'P1 DRAFT TEXT'` after it** → R2-1. |
| Panel-owning reverse census (`test_b97_patch_editor`, `test_tui_patch_editor_b94`, `test_tui_patch_variant`), full tree with the fix-pass files | 66 passed (Kimi: 66) |
| `devflow-evidence.py --root . --check evidence/inc-3/*` | All **32 rows bind**: 0 `packet records no digest` lines, and no disk-vs-packet mismatch. The only `MISMATCH` lines are the index limb (`not staged`), which is expected before the commit. Exit 1 comes from that limb alone. **F11(a) closed.** |

## Closure table — round 1 findings

| id | State | Evidence |
|---|---|---|
| F1 HIGH | **Discharged** (re-read and re-run) | `_seed_p1_derived_state` (test `:161-191`) seeds S5–S12 and the A-07 names in both the load-over relative arm and the direct arm. The direct arm now asserts 20 names. My R6 goes RED and names `last_template_path`. |
| F2 MAJOR | Closed by LED .55(a) | `app.py:9349-9353`. The wording matches LED .55(a) exactly, and the line no longer calls the entries unsaved. The saved-document probe gives a truthful line. |
| F3 MAJOR | Closed for the marker | `app.py:9117-9123` `panel.mark_loaded()`. The AT asserts `●` before the load-over (vacuity guard) and `0 entries` without `●` after it, and R11 kills that assertion. The paste-buffer half of LED .55(b) is not delivered → R2-1. |
| F4 MAJOR | Closed | Packet m1 and m4 rows rewritten from full-module runs. m6 and my R12 kill the notice arms. |
| F5 | Closed | Packet §6 now says `at030c` FAILED in `green-06b` and dispositions the 3 first-run nodes, with my 3+3 runs copied in under provenance headers. |
| F6 | Closed, with a note | `test_tc_b100_10_outgoing_service_finishes_after_rebind`. The "worker" is a test-side asyncio task holding the outgoing service, not one of the app's `@work` threads. That is enough for LLR-165.3's boundary as worded: the old object is still usable, and the rebound one is untouched. M4 kills it. |
| F7 | Closed | The RED table labels 3 base failures as a missing method. R10 is recorded as LLR-165.2's third negative control (`mut-fix1-r10-no-key-normaliser.txt`). |
| F8 | Closed for the observable | The AT asserts 0 ledger rows and the empty-state text. Its comment overstates what that proves → R2-2. |
| F9 | Closed | `app.py:9183-9185` hashes `address:byte`. Dicts reduce to `(len, keys, sha256 of normalised values)` (`:9209-9223`). Cold-vs-cold stays equal (GREEN). |
| F10 | Closed | The comment now says "eight" (`:9079-9083`). The two Inc-era names are classified in the domain comment (`:1426-1432`). Mirroring that into the ARQ §2.2 text is the orchestrator's. |
| F11 | (a) closed; (b) the orchestrator's | (a) full paths, all rows bind. (b) `HANDOFF.md` is still at the worktree root, as the fix brief instructed. The orchestrator moves it to `kimi/inc-3-HANDOFF.md` at commit, as for Inc 1 and Inc 2. |

## New findings — round 2

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **R2-1** | **MAJOR** | `app.py:9117-9123`; LED .55(b); packet §1 line 46 | **`mark_loaded()` does not clear the paste buffer, but LED .55(b), the seam's comment and the packet all say it does.** `PatchEditorPanel.mark_loaded` (`screens_directionb.py:5815-5824`) only sets `_dirty = False` and repaints the marker. Its docstring says the CALLER reseeds the buffer. Consequence: a P1 draft typed in `#patch_paste_text` survives into P2's session, now marked clean, so the panel's Load guard no longer protects it. A later change-file load replaces it without a question, and `Parse pasted` would apply P1's draft onto P2's image. Before this pass the dirty flag at least stayed set. The notice's "unsaved changes were not kept" is also inaccurate for the buffer, which was kept. This is the U1 row of ARQ §2.2. | Probe by keys: buffer `'P1 DRAFT TEXT'` before and after; `_dirty` False after | Either clear the buffer in the seam as LED .55(b) states. `app.py` already writes it at `:3932`. Clear it, then call `mark_loaded()` AFTER the buffer's `TextArea.Changed` has been handled (for example `self.call_after_refresh(panel.mark_loaded)`), because writer w2 re-sets `_dirty` on that message. Add an AT assertion that the buffer is empty after the load-over. Or amend LED .55(b) to say the buffer is kept, and route the buffer to Inc 10's question. |
| R2-2 | MINOR | test `:850-855` (the AT comment) | The AT comment says the ledger assertion is "load-bearing even though today's install chain would repaint it anyway". It is not load-bearing for the seam's repaint: R8b (the `refresh_entries` call deleted) stays 17/17 green. The observable is correctly asserted; only the claim is wrong. | R8b → 17 passed | Reword the comment: it pins HLR-165's observable, not LLR-165.1's repaint clause. Record the R8b survivor in the packet as an equivalent mutant (the install repaints the ledger). |

## Verdict

**approve — PASS-WITH-NOTES.** F1 (HIGH) is discharged by this re-read, with R6 re-run by me. 0 HIGH is open. Open: **R2-1 (MAJOR)**, which LED .55(b) assumed was already done. It needs a code fix in this increment or a ledger correction before Inc 10. **R2-2 (MINOR)**. The F6 note.

## §4b `Independent review` cell (final, for the orchestrator to write)

`code-reviewer` · **PASS-WITH-NOTES** (0 HIGH open; 1 MAJOR, 1 MINOR new in round 2) · F1 (HIGH, round 1) was resolved by seeding P1's S5–S12 and A-07 state in both TC-B100-09 load-over arms (`_seed_p1_derived_state`). I re-read it on the diff and re-ran mutant R6 myself: KILLED, 2 failed, `LEAK last_template_path` plus S8–S11 in the relative arm (round 1: 16/16 green). F2–F11 are closed: the LED .55(a) wording, `mark_loaded` in the seam, killing mutants m6/R12 for the notice, the corrected dispositions, the boundary arm, R10 recorded, the AT ledger and no-`●` checks, the content digest, the "eight" comment, and full-path evidence that binds all 32 rows. Open: R2-1 (MAJOR) — `mark_loaded()` does not clear the paste buffer that LED .55(b) says it clears, so a P1 draft survives into P2 marked clean (probed by keys). Fix it here, or correct the ledger before Inc 10. R2-2 (MINOR) — an AT comment overstates what its ledger check pins (R8b survives).

## Hand-offs (round 2)

- **Orchestrator:** R2-1. Choose between clearing the buffer in the seam (with `mark_loaded` deferred until after the buffer's `Changed` message) and amending LED .55(b) to route the buffer to Inc 10. F10: mirror the 8 caches and the two classifications into the ARQ §2.2 text. F11(b): move `HANDOFF.md` at commit.
- **`qa-reviewer`:** the F6 arm drives a test-side task, not one of the app's `@work` workers. Decide whether Inc 7 or Inc 8a (worker loads) owes a real-worker boundary arm.

---

# Round 3: re-read of corrective pass 2 (bounded to R2-1 and R2-2)

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as rounds 1–2. I did not write the fix. |
| Tree re-read | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc3` at `dad6423`, with Inc 3 and fix passes 1–2 uncommitted. `app.py` sha256 `ddc64e1803ee…`. `git diff --name-only` lists `s19_app/tui/app.py` and `tests/test_id_registry.py` only, so **`screens_directionb.py` is untouched** (`git diff --quiet` ✓). Still 1 SOURCE file. CRLF preserved: 14511/14511. The worktree was not edited. |
| Contract | `kimi/BRIEF-inc-3-fix2.md`; LED .55(b), with the buffer clear now delivered as worded |
| Interpreter proof | `…\scratchpad\fix2\s19_app\__init__.py`, a copy with an `app.py` identical to the worktree (`cmp`). Mutants are in `…\scratchpad\mut2\<id>\`. `NO_COLOR` unset, s19env 3.11. |
| **Verdict** | **approve — PASS.** R2-1 and R2-2 are closed. 0 HIGH and 0 MAJOR are open. |

## The fix as read

At `app.py:9118-9126`, inside the seam's `else:` branch (the panel was found), the seam does two things:

1. It runs `self.query_one("#patch_paste_text", TextArea).text = ""`.
2. It then calls `self.call_after_refresh(panel.mark_loaded)`.

The ordering is right for Textual 8.2.8. `TextArea.text = ""` is `load_text`, which posts `TextArea.Changed`. The panel's writer w2 sets `_dirty` again when it handles that message. `call_after_refresh` posts `InvokeLater` to the app, and its documented contract is to run "after all messages are processed and the screen has been refreshed". So `mark_loaded` runs after w2, never before it.

## What I executed in round 3 (evidence state: `executed`)

| Run (`…\scratchpad\r3-<id>.txt`, `probes-r3-out.txt`) | Result |
|---|---|
| GREEN, the fix-pass-2 tree | **17 passed** (97 s) |
| **The R2-1 key probe re-run**, at both sizes, 5 repetitions each. Each run uses a P1 entry added through the panel plus the draft `'P1 DRAFT TEXT'` in `#patch_paste_text`, then a load of P2 through the dialog. **The FINAL state is read after a 40-pause settle**, not on the first clean frame. | **10 of 10 runs**: before `(dirty=True, 'P1 DRAFT TEXT')`, after `(dirty=False, '', '0 entries')`. The draft is gone and the panel is clean, with no `●`. |
| Stress probe: the draft is written and `_handle_load_project(P2)` is called **in the same tick**, so both the draft's `Changed` and the clear's `Changed` are still pending when the seam runs. 10 repetitions, final state after 40 pauses. | **10 of 10**: `(False, '', '0 entries')` |
| **R13**: `call_after_refresh(panel.mark_loaded)` replaced by an immediate `panel.mark_loaded()` | **KILLED**. Both AT sizes time out on `the clean '0 entries' subtitle after the load-over`. All 10 stress probes end at `(True, '', '0 entries ●')`. The deferral is load-bearing, and the AT's poll is not satisfied by the transient clean frame. |
| R14 = Kimi's m7 (the buffer clear skipped) | **KILLED**. Both AT sizes time out on `the paste buffer cleared by the reset`. This matches the packet's m7 row. |
| `devflow-evidence.py --check` (39 files) | Every row binds. The only `MISMATCH` lines are the index limb (`not staged`). |

## Race and wait check (question 3)

The new AT observables never rely on a single pause. The buffer-cleared check and the clean-subtitle check both use `_wait_for`, which polls up to 150 pauses. Under R13, the transient clean frame (`mark_loaded`, then w2 re-setting the flag) did not satisfy the poll, and both sizes timed out. So the AT catches a broken ordering in practice.

What remains is theoretical. A poll that happens to sample between those two events could pass without the AT re-checking the final state. My 40-pause final-state probes close that gap as evidence, and they found no flake in 20 runs. The single `await pilot.pause()` after returning to the Inspector tab sits before the load-over and gates nothing. The white-box notice arms use `_flush(12)` and read synchronous state that the seam writes, so they have no race. No finding.

Optional hardening, not required: after the clean-subtitle `_wait_for`, `_flush(pilot)` once and re-assert the subtitle and `_dirty`. That would pin the final state in the suite itself.

## Closure table — round 2 findings

| id | State | Evidence |
|---|---|---|
| R2-1 MAJOR | **Closed** (re-read and re-probed) | The buffer is cleared through its widget, and `mark_loaded` is deferred past w2. My key probe gives `'P1 DRAFT TEXT'` → `''` with `_dirty=False` at both sizes. The AT asserts the draft is present before the load-over (vacuity guard) and the empty buffer and no `●` after it. R14/m7 and R13 are both killed. LED .55(b)'s statement and the seam's comment are now accurate. |
| R2-2 MINOR | **Closed** | The AT comment now states that it pins HLR-165's observable, not LLR-165.1's repaint clause, and that R8b is an equivalent mutant. The packet records R8b as equivalent. |
| F6 note | Unchanged | Routed to `qa-reviewer` (round 2) |

## Verdict

**approve — PASS.** 0 HIGH, 0 MAJOR open. F1 (HIGH, round 1) stays discharged: nothing in fix pass 2 touches the seeding or the S5–S12 reset, and the 17/17 GREEN includes both TC-B100-09 arms. Remaining non-blocking items for the orchestrator: the F10 ARQ mirror, the F11(b) `HANDOFF.md` move at commit, and the F6 real-worker question.

## §4b `Independent review` cell (final, for the orchestrator to write)

`code-reviewer` · **PASS** (0 HIGH, 0 MAJOR open) · F1 (HIGH, round 1) was resolved by seeding P1's S5–S12 and A-07 state in both TC-B100-09 load-over arms. I re-read it and re-ran mutant R6 myself: KILLED, `LEAK last_template_path` (round 1: 16/16 green). F2–F11 were closed in round 2. R2-1 (MAJOR, round 2) was resolved by clearing `#patch_paste_text` in the seam and deferring `panel.mark_loaded()` with `call_after_refresh`, past the buffer's `Changed`. I re-read it and re-ran the key probe: `'P1 DRAFT TEXT'` → `''`, `_dirty=False`, `0 entries` with no `●`, 10 of 10 at both sizes plus 10 of 10 same-tick stress runs. Mutants R13 (immediate `mark_loaded`) and m7 (no clear) are both killed by the AT. R2-2 is closed (R8b recorded as equivalent). `screens_directionb.py` is untouched. Notes: the F6 arm uses a test-side task (routed to `qa-reviewer`); ARQ §2.2 mirror (F10); `HANDOFF.md` move (F11b).
