# Validation — s19_app — Batch 2026-10-19-batch-97

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`); for Spanish batches **translate the prose, never a label** — the reserved field names are declared in §✅ Verdict and are read literally.
> Phase 4 artifact. Content owner: `qa-reviewer`, who **EVALUATES** the results of the validation strategy fixed in Phase 1, **names who executed each one** and returns the rows; the orchestrator writes `04-validation.md` (`stations/shared-homes-roles.md` §Delegation). The ONE complete gate-suite run is the orchestrator's (`C-25`); a sub-agent consumes the result and never owns the run.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/validation-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

**`Mode`:** `validation`

## ✅ Verdict (read first)

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Result` · `Gate run` · `Layer 0` · `Evidence checklist` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.
>
> **And so are the three verdict tokens** `PASS` · `PASS-WITH-NOTES` · `FAIL`, which are VALUES and not prose.
> A Spanish batch writes `- **Result:** PASS`, not `- **Resultado:** aprobado`: the label, the tokens and the
> reviewer-identity tokens below are the machine's vocabulary.

- **Result:** `PASS-WITH-NOTES`
- **Gate run:** `python -m pytest -q -p no:cacheprovider` (whole suite, a superset of CI's `pytest -q -m "not slow"`; the transcript header records the source digests and not the command line, so the line is written in the batch's recorded invocation form — G-001) · exit 1 (11 failed / 3617 passed / 3 skipped / 3 xfailed, 2:18:54) · `432ecf0` (header "5cb7618 + Inc-7 working tree"; its 4 source digests re-verified OK against `432ecf0` with `sha256sum -c`; `git diff 432ecf0 -- s19_app tests` is empty; the tests differ from the run only by the 2 later test-only fixes in `post-suite-fix.txt`) · orchestrator — transcript `.dev-flow/2026-10-19-batch-97/evidence/inc-7/suite-full.txt`
- **Layer 0:** `15 unit(s) met the criterion · 14 carry a named reddening mutation` (`fx_run_error_line` has none on record — G-004)
- **Requirements:** `81`/`81` pass (8 HLR + 73 LLR) · `0` blocker fails
- **Black-box acceptance (Layer B):** ✓ every story US-134..US-140 has ATs that observe the outcome through the shipped surface (representative + boundary + negative); 26/26 ATs reconcile to one chain node (C-18). Notes: AT-B97-04's empty arm is a sibling function (G-003); HLR-151 (Inc-9) has one integration node and no AT id, observed through app state (G-006)
- **Surface-reachability (bidirectional):** ✓ all named inputs AND outputs reached at the surface, with one partial output (HLR-151's loaded project is read from `app.current_project`, not from the painted status line — G-006, minor)
- **Supersession inspection (read off the P3 packets):** ✓ every packet's Correction population reaches 0 inside its own scope; Inc-9 carries no Correction population row, and the sibling `str(Label)` pattern in `app.py` `_load_from_item` is already in the backlog (G-007); the `styles.tcss:2375` `^E` comment is routed to the backlog
- **Test ledger:** ✓ reconciles by collection (`3146 − 3 + 491 = 3634`, equal to the 3634 collected in the gate run); the packets' own balance lines declare +441, 50 short of the measured +491 (G-002)
- **Evidence checklist (qa-reviewer):** `qa-reviewer · 10 of 11 rows ✓ with evidence` (the ✗ row — the gate-run command absent from the transcript — is answered on the `Gate run` line above by the orchestrator, G-001)

**Who did what.** `qa-reviewer` (spawned as an independent agent with `agents/qa-reviewer.md`) evaluated every result below and executed none of them, apart from two collection counts (`pytest --collect-only` at `432ecf0` = 3634 nodes; at base `51ee191` = 3146) and the digest check. The orchestrator ran the gate suite, the non-baseline re-runs and the post-suite fixes; `software-dev` sub-agents ran the Inc-1..8 increment gates, RED runs and mutation transcripts; `ux-reviewer` and `code-reviewer` ran the gate reviews. No fresh full-suite run was made at P4: the Inc-7 run covers the same source bytes as `HEAD` (digest-verified), and it is the station's one complete run (C-25).

**Gate-run classification against `evidence/baseline-pytest-51ee191.txt`** (`evidence/inc-7/suite-nonbaseline-rerun.txt`, `post-suite-fix.txt`): 6 of the 11 failures are baseline nodes that pre-date the batch; 4 baseline nodes now pass; 5 are new to the list. Of the 5, 2 are test-side defects of Inc-7, fixed in test files only and re-run green (address census, help-scroll timing), and 3 are pre-existing flakes (`test_at068b_per_entry_json_popup_edits_only_selected_entry`, `test_verify_quiet_pass_on_faithful_hex_save`, `test_at_061a_persistent_control_survives_then_writes_pair_and_clears`; `test_tc024_report_trigger_surfaces_paths` flakes in the Inc-8 / Inc-7 re-runs). The flakes are routed to `.dev-flow/BACKLOG-CODE.md` with their evidence. 0 failures are attributable to batch-97's product code.

> If every line is ✓, the Detail below is reference only. Any ⚠/✗ → read the matching part.

---

## Detail (reference)

### Layer 0 — unit

| Unit | Which criterion | Node id | Result |
|---|---|---|---|
| `folder_open_service.resolve_chip_target` | boundary (filesystem path, family root) | `tests/test_b97_chips_help.py::test_tc_b97_27_flows_family_targets_project_flows_dir`, `::test_tc_b97_28_session_family_targets_project_dir` | pass — `executed` (software-dev, `evidence/inc-1/green.txt`; again in the gate run, orchestrator) |
| `is_openable_chip_dir` (real-directory / reparse / containment guard) | boundary + cyclomatic ≥ 3 | `::test_tc_b97_57_guard_unit_arms` | pass — `executed` (same) |
| `no_project_reason` | cyclomatic ≥ 3 (per family) | `::test_tc_b97_29_no_project_reason_names_each_family_folder` | pass — `executed` (same) |
| `chip_family_root` | branch project / tool root | `::test_tc_b97_57_family_root_is_project_dir_else_tool_root` | pass — `executed` (same) |
| flow NUL refusal (`flow_persistence_service`, per block field) | boundary (parses flow files) | `test_tc_b97_62_nul_in_each_block_field_refuses_the_flow[*]`, `test_tc_b97_62_p36_nul_flow_file_refused` | pass — `executed` (software-dev, `evidence/inc-2/green.txt`; gate run) |
| `check_layout` + Parameter clip helpers | cyclomatic ≥ 3 | `test_tc_b97_10_layout_and_clip_units` | pass — `executed` (`evidence/inc-3/green.txt`; gate run) |
| `patch_layout` | cyclomatic ≥ 3 | `test_tc_b97_34_patch_layout_monotonic_in_its_inputs` | pass — `executed` (inc-4; gate run) |
| hex strip builder (states, cap, bold) | cyclomatic ≥ 3 | `test_tc_b97_39_strip_builder_states_and_cap`, `test_tc_b97_39_strip_follows_the_highlight` | pass — `executed` (inc-4; gate run) |
| `clip_head` / `clip_tail` | boundary (text clip) | `test_tc_b97_16_clip_head_and_clip_tail` | pass — `executed` (inc-5; gate run) |
| `pipeline_layout` | cyclomatic ≥ 3 | `test_tc_b97_34_pipeline_layout_monotonic_in_its_inputs` | pass — `executed` (inc-5; gate run) |
| NUL add-form refusal helper | boundary (input ref) | `test_tc_b97_62_nul_refusal_helper_names_kind_and_field[*]` | pass — `executed` (inc-5; gate run) |
| `cable_glyph` | cyclomatic ≥ 3 (status truth table) | `test_tc_b97_21_cable_glyph_truth_table` | pass — `executed` (inc-6; gate run) |
| `lane_layout` | cyclomatic ≥ 3 | `test_tc_b97_34_lane_layout_is_the_builder_rule_minus_the_confirm_reserve` | pass — `executed` (inc-6; gate run) |
| `fx_run_error_line` | declared layer 0 by the Inc-6 packet | the Inc-6 layer-0 set (`evidence/inc-6/green.txt`) | pass — `executed`; no named reddening mutation (G-004) |
| `pack_key_row` | cyclomatic ≥ 3 (whole-token packing, overflow) | `tests/test_b97_key_bar.py::test_tc_b97_70_pack_key_row_keeps_a_whole_display_order_prefix`, `::test_tc_b97_70_every_painted_row_is_whole_tokens` | pass — `executed` (inc-8; gate run) |

Excluded under C-51: Inc-9's `LoadProjectScreen` Load handler (UI wiring, one guard) and Inc-7 (no new pure function, as its packet declares).

**Measured by mutation, never by line coverage.** For each unit, name the mutation and paste the RED:

| Unit | Mutation applied | RED observed? | Transcript |
|---|---|---|---|
| `resolve_chip_target` | M10-flows-literal, M11-stop-at-none | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-1/mutations.txt` |
| `is_openable_chip_dir` | M3-no-reparse-walk, M4-no-containment, M5-guard-is-exists | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-1/mutations.txt` |
| `no_project_reason` | M7-service-reports-reason | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-1/mutations.txt` |
| `chip_family_root` | M8-root-is-workarea, M12-stop-at-root | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-1/mutations.txt` |
| flow NUL refusal | M1-flow-ref-nul-off, M2-a2b-nul-off, M3-log-ref-nul-off | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-2/mutations.txt` |
| `check_layout` / clip | M1-head-keeping-clip, M2-tail-only-clip, M3-param-floor-40 | yes — KILLED on the unit node (M1 survives AT-B97-04, explained in the Inc-3 packet §4) | `.dev-flow/2026-10-19-batch-97/evidence/inc-3/mutations.txt` |
| `patch_layout` | M25-value-fixed-22, M32-strip-fixed-8 | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/mutations.txt` |
| strip builder | M11-strip-bound-to-row-0, M13-bold-on-context-byte, M16-no-row-cap | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-4/mutations.txt` |
| `clip_head` / `clip_tail` | M9-clip-tail-keeps-head | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/mutations.txt` |
| `pipeline_layout` | M27-cards-fixed-at-24 | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/mutations.txt` |
| NUL add-form helper | M53-nul-line-names-the-block-field | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-5/mutations-fold.txt` |
| `cable_glyph` | M1-waiting-row-checked-after-the-status-rows | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/mutations.txt` |
| `lane_layout` | M33-cards-fixed-at-21 | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/mutations.txt` |
| `fx_run_error_line` | none named | `not-run` | none — G-004 |
| `pack_key_row` | M3, M4, M5 | yes — KILLED | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/mutations.txt` |

### UX walkthrough — only if trigger family D fired

| Criterion (when the user does X, they observe Y) | Driven with the REAL mechanism | Painted result asserted | Verdict |
|---|---|---|---|
| Check Editor: reads every address in full, tells names apart, includes a field and sees the count rise (Inc-3) | Textual Pilot (real keys and clicks) + real Windows Terminal truecolor captures at 118x54 / 220x60 | painted rows, compositor strips; captures re-taken after the fold | `approved` — ux-reviewer approve with conditions; H1, M1, M2 discharged by the fold, verified on the re-captures |
| Patch Editor: after Load / Add / Save the JSON tab and stamp follow at once (Inc-4) | Pilot + captures | stamp text, JSON view, focus after the Load guard | `approved` — ux-reviewer on re-read (H1 re-walked); 2 LOW routed |
| Flow Builder: whole chain on one row, contextual add form, Run on screen (Inc-5) | Pilot + captures | 4-block run, `max_scroll_y 0`, refusal lines | `approved` — ux-reviewer on re-read |
| Flow Execution: paused lane in view, Confirm highlighted, English log (Inc-6) | Pilot + captures | lanes return to x 0, legend, REQUIRED line | `approved` — ux-reviewer on re-read (M2 wording inspected, not exercised) |
| Key bar: global row fixed, window row scoped, dim / `? more` (Inc-8) | Pilot + captures | rows 1 / 2 per window | `approved` — ux-reviewer approve with conditions; F1–F5 folded and checked on the re-captures by the orchestrator; no second ux read |
| Help modal: fits on screen, body scrolls by key, Close keeps the focus (Inc-7 + re-walk) | Pilot + captures (`r2.help-patch*` at 118x54 / 80x24) | painted rows while scrolled by key; `Close  esc` | `approved` — ux-reviewer re-walk OK to advance; 2 LOW routed (about 5 body lines at 80x24; scroll keys hinted only by the scrollbar) |

**Mechanism used:** `a UI test driver` (Textual Pilot) plus real Windows Terminal truecolor captures

| Act | What it is | Performed? |
|---|---|---|
| Automated walkthrough | the criteria above, driven through the REAL mechanism | `performed` (ux-reviewer gate walks Inc-3..Inc-8 and the Inc-7 re-walk; nodes executed by software-dev and the orchestrator) |
| Expert inspection | a cognitive walkthrough against declared criteria, by a reviewer and not a user | `performed` (ux-reviewer, on the captures, at every render gate) |
| Evaluation with users | real users of the system, doing the tasks named in the context of use | `not performed — this team is one person and no user of this surface exists outside it` |

- **Method:** at each render increment the ux-reviewer walked the criteria against the Pilot-driven nodes and real truecolor captures at 118x54, 220x60 and 80x24; findings were folded and re-walked or re-captured. The operator judged the captures as product owner.
- **Participants or population:** 0 users; one expert reviewer (the `ux-reviewer` agent). The operator watching as product owner is not a user evaluation.
- **Evidence of the evaluation:** `03-increments/increment-003.md` … `increment-008.md` §4b; `increment-007.md` §1c; `.dev-flow/2026-10-19-batch-97/evidence/inc-3/png/` … `evidence/inc-8/png/`; `evidence/inc-7/png/`.
- **Limits:** no real user did any task; tasks chosen by the author; the reviewer is an agent; colour and grouping judged on captures only; mouse-wheel help scrolling not tested; Inc-8's fold had no second ux read.

### Layer A — functional (white-box): per-requirement results
> `TC-NNN` ↔ LLR/HLR. `Result` = pass / fail. `Evidence` = command output, observed behavior, inspection note, or analysis result.

All rows `executed`: the increment gate run by software-dev (Inc-9: orchestrator), then again in the orchestrator's gate run, where 0 nodes of any `tests/test_b97_*.py` failed.

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| HLR-144 / LLR-144.1–144.12 (TC-B97-01..07, 39..42, 60; Patch arms of TC-B97-32..38, 58, 59) | test (pilot + unit) | `pytest tests/test_b97_patch_editor.py` + width / chips Patch arms + guard host | 6/6 rows; JSON parses to 6 addresses equal to the file; stamp saved→unsaved→saved; 0 MarkupError | pass | `evidence/inc-4/green.txt`, `green-fold.txt`, `green-after-fixes.txt`; gate run |
| HLR-145 / LLR-145.1–145.10 (TC-B97-08..12, 43..46, 61; Check arms) | test | `pytest tests/test_b97_check_editor.py` + guard host | `max_scroll_x == 0` at 118x54 / 220x60; 75/75 full addresses; count N→N+1; written `.chk.json` matches | pass | `evidence/inc-3/green.txt`, `green-fold.txt`; gate run |
| HLR-146 / LLR-146.1–146.14 (TC-B97-13..20, 47..51, 62, 25 module arm) | test | `pytest tests/test_b97_flow_builder.py` (Inc-2 NUL / token units + Inc-5) | 4 cards / 3 cables; Run inside at scroll 0; 7 kinds; `FLOW-UNSAFE-REF` line, 0 exceptions | pass | `evidence/inc-2/green.txt`; `evidence/inc-5/green.txt`, `green-fold.txt`; gate run |
| HLR-147 / LLR-147.1–147.13 (TC-B97-21..26, 52..56, 63, 64) | test | `pytest tests/test_b97_flow_execution.py` + guard host | cables `▓ ▓ ◇` / `▓ □ ░` / `▓ ✗ ░`; Confirm in the viewport; `c c` → 1 confirm; waiting colour exclusive | pass | `evidence/inc-6/green.txt`, `green-fold.txt`, `green-post-suite.txt`; gate run |
| HLR-148 / LLR-148.1–148.10 (TC-B97-27..33, 57, 58, 65; TC-B97-66 keys block) | test (seam spy on the open seam) | `pytest tests/test_b97_chips_help.py` + `tests/test_window_usage_help.py` | 4 presses → 4 seam calls with the right targets; file / junction → 0 calls; 100 % help coverage; one English line per region state | pass | `evidence/inc-1/green.txt`; inc-3..inc-6 green; `evidence/inc-7/green-r2.txt`; gate run |
| HLR-149 / LLR-149.1–149.6 (TC-B97-34..38, 59) | test | `pytest tests/test_b97_width.py` (118x54, 119, 120, 160x56, 220x60, 260x70; 80x24, 100x40, 220x40) | 0 overflowing descendants; actions inside at scroll 0; 0 wrapped rows; void within bound; reachable by key below the range | pass | `evidence/inc-7/green.txt`, `green-r2.txt`, `post-suite-fix.txt`; gate run |
| HLR-150 / LLR-150.1–150.7 (TC-B97-66..72) | test | `pytest tests/test_b97_key_bar.py` (+ height-only arms from Inc-7) | 8 global tokens; 0 tokens outside the allowed set; 0 partial tokens; container −1 row; a click runs the action | pass | `evidence/inc-8/green.txt`; `evidence/inc-7/green.txt`; gate run |
| HLR-151 / LLR-151.1 (no TC id; one node) | test (integration) | `pytest tests/test_b97_load_project_dialog.py` | highlight `proj_b` + Load → `current_project == "proj_b"`, dialog closed | pass — `executed` (orchestrator); the invalid arm "no highlight → no dismiss" has no node: `not-run` (G-005) | `evidence/inc-9/red.txt` (RED on `354857c`), `green.txt`, `mutations.txt` (2/2 KILLED); gate run |

### Layer B — behavioral (black-box) acceptance

All AT nodes passed in the orchestrator's gate run (`executed`, orchestrator); none is among its 11 FAILED lines.

| US | Acceptance test (`AT-NNN`) | Surface driven | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|----------------------------|----------------|---------------------------------------|----------------------------|--------|
| US-134 | AT-B97-01 → `tests/test_b97_patch_editor.py::test_at_b97_01_load_shows_every_entry_and_the_document` · AT-B97-02 → `::test_at_b97_02_add_save_empty_and_legacy` · AT-B97-03 → `::test_at_b97_03_hostile_name_and_content_read_literally` · AT-B97-17 → `::test_at_b97_17_first_task_from_the_keyboard` | `#patch_doc_load_button`, Add, Save, keys | painted ledger rows; `#patch_json_view` parsed with `json.loads`; stamp text | ✓ · ✓ · ✓ | pass |
| US-135 | AT-B97-04 → `tests/test_b97_check_editor.py::test_at_b97_04_engineer_reads_every_address_and_includes_one` (empty arm in sibling `::test_at_b97_04_empty_ledger_line_and_dock_inside`, G-003) · AT-B97-05 → `::test_at_b97_05_hostile_parameter_reads_literally` · AT-B97-18 → `::test_at_b97_18_first_task_from_the_keyboard` · AT-B97-21 → `::test_at_b97_21_six_shared_address_fields_and_the_written_file` | rail, keys, include button, Write | painted Address cells; field count; written `.chk.json` parsed | ✓ · ✓ · ✓ | pass |
| US-136 | AT-B97-06 → `tests/test_b97_flow_builder.py::test_at_b97_06_chain_on_screen_and_run_writes_the_image` · AT-B97-07 → `::test_at_b97_07_each_kind_its_inputs_and_an_ext_step_card` · AT-B97-08 → `::test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject` · AT-B97-19 → `::test_at_b97_19_first_task_from_the_keyboard` | palette chips, add form, `#flow_run`, Load | painted pipeline row; `fw_app_patched.s19` absent before Run, present after; refusal line | ✓ · ✓ · ✓ | pass |
| US-137 | AT-B97-09 → `tests/test_b97_flow_execution.py::test_at_b97_09_three_lanes_run_paused_lane_in_view_english_log` · AT-B97-10 → `::test_at_b97_10_save_set_then_load_it_in_a_new_app` · AT-B97-11 → `::test_at_b97_11_hostile_and_nul_inputs_render_literally_or_are_refused` · AT-B97-20 → `::test_at_b97_20_keys_only_run_pause_confirm` · AT-B97-22 → `::test_at_b97_22_parallel_rebind_runs_each_lane_on_its_own_image` | `#fx_import`, `#fx_run`, Confirm, Save / Load Set, mode control | painted cables and marks; REQUIRED line; saved set restored in a new app; `reports/*-chain-set-report.md` mode line parsed | ✓ · ✓ · ✓ | pass |
| US-138 | AT-B97-12 → `tests/test_b97_chips_help.py::test_at_b97_12_four_chips_open_their_folder_or_refuse` · AT-B97-13 → `::test_at_b97_13_no_project_flow_chips_disabled_and_name_their_folder` · AT-B97-14 → `::test_at_b97_14_help_chip_opens_a_body_covering_the_screen` · AT-B97-23 → `::test_at_b97_23_each_failed_region_says_so_in_one_line` | chip presses (OS seam spied), `?` chips, Run with a NUL bind | seam targets; status line; modal lines | ✓ · ✓ · ✓ | pass |
| US-139 | AT-B97-15 → `tests/test_b97_width.py::test_at_b97_15_four_screens_with_the_widest_values` · AT-B97-16 → `::test_at_b97_16_in_session_resize_grows_and_returns` · AT-B97-24 → `::test_at_b97_24_breakpoint_and_below_the_range_by_key` | rail, `pilot.resize_terminal`, `tab` / `pagedown` | regions, painted rows, DataTable cell text against the column | ✓ · ✓ · ✓ | pass |
| US-140 | AT-B97-25 → `tests/test_b97_key_bar.py::test_at_b97_25_two_rows_on_every_window_and_clicks` · AT-B97-26 → `::test_at_b97_26_keys_only_help_and_hidden_view` | rail keys, clicks on tokens, `.` on Patch | painted rows 1 / 2; dim colour; target window shown, nothing typed | ✓ · ✓ · ✓ | pass |
| — (HLR-151, Inc-9) | no AT id → `tests/test_b97_load_project_dialog.py::test_load_project_button_loads_the_picked_project` | dialog: highlight, click Load | `app.current_project`, dialog closed (app state, not painted text) | ✓ · — · ✓ | pass (G-005, G-006) |

C-18: 26 of 26 ATs reconcile to one named function driving the whole chain; no AT is realised only in parts, none lacks a node.

### Bidirectional surface-reachability matrix (extends A-5)
> Every named INPUT dimension AND every named OUTPUT/deliverable is exercised/observed through the handler — not only the service API.

| Direction | US dimension / deliverable | Service param / producer | Reached/observed at surface? | TC / AT | Status |
|-----------|---------------------------|--------------------------|------------------------------|---------|--------|
| input | change-set file (Load), Add, Save, paste | `_patch_editor_load_tail`, panel writers | yes | AT-B97-01/02/17 | ✓ |
| input | hostile file name / content | loader, `safe_text` | yes | AT-B97-03 | ✓ |
| input | terminal size on the Check Editor; include press | `check_layout`, include handler | yes | AT-B97-04, -18 | ✓ |
| input | palette kind, add-form fields, NUL ref, Run | add form, `nul_add_refusal`, run handler | yes | AT-B97-06/07/08/19 | ✓ |
| input | flows imported, mode `sequential` / `parallel`, rebound SOURCE, Confirm key, NUL bind | Flow Execution import / run handlers | yes | AT-B97-09/11/20/22/23 | ✓ |
| input | chip press with / without project; `flows` file / junction / missing; seam raises | `resolve_chip_target`, `is_openable_chip_dir` | yes (OS seam spied) | AT-B97-12/13 | ✓ |
| input | resize in session; 119↔120; 80x24; 220x40 | `on_resize`, layout helpers | yes | AT-B97-15/16/24 | ✓ |
| input | token click with an `Input` focused; key on a window that does not handle it | key bar → binding action | yes | AT-B97-25/26 | ✓ |
| input | dialog highlight index + Load | `LoadProjectScreen` → `_handle_load_project` | yes | Inc-9 node | ✓ |
| output | JSON view + stamp | serializer → `#patch_json_view` | yes (parsed) | AT-B97-01/02 | ✓ |
| output | written `.chk.json` | Write | yes (file parsed) | AT-B97-21 | ✓ |
| output | `fw_app_patched.s19` | Run (chain) | yes (absent → present) | AT-B97-06 | ✓ |
| output | chain-set report mode line; saved set file | `flow_execution_service` | yes (parsed; reloaded in a new app) | AT-B97-22, -10 | ✓ |
| output | status line with the opened path / refusal; help modal lines | chips, help chip | yes | AT-B97-12/13/14/23 | ✓ |
| output | key bar rows 1 / 2, dim state | key bar | yes (painted strips) | AT-B97-25/26 | ✓ |
| output | loaded project | `_handle_load_project` | partial (`app.current_project`) | Inc-9 node | gap, minor (G-006) |

### Signed-balance test ledger
> `post = base − D + A`. State counts in collected / passed-lean / passed-full form.

| base | − D | + A | = post | actual collected | passed-lean / full | reconciles? |
|------|-----|-----|--------|------------------|--------------------|-------------|
| 3146 (baseline: 10 F + 3101 P + 3 s + 32 xf) | 3 (`test_flow_multi_image_ui.py` 11→8, Inc-5) | 491 (measured per file by qa-reviewer) | 3634 | 3634 (gate run 11 F + 3617 P + 3 s + 3 xf; `--collect-only` at `432ecf0`) | `not-run` (no `-m "not slow"` run) / 3617 | yes by collection; the packets' balance lines declare +441, 50 short (G-002) |

Measured +A per file: `test_b97_check_editor.py` 36 · `test_b97_chips_help.py` 79 · `test_b97_flow_builder.py` 69 · `test_b97_flow_execution.py` 75 · `test_b97_key_bar.py` 38 · `test_b97_load_project_dialog.py` 1 · `test_b97_patch_editor.py` 38 · `test_b97_width.py` 145 · `test_segment_split_window.py` +1 · `test_tui_snapshot.py` +1 · `test_window_usage_help.py` +8. The 29 snapshot nodes moved from xfailed to passed (32 → 3 xfailed); that is not a change in node count.

### Gaps detected
| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| G-001 | Gate run (C-25) | the command line and exit code are not recorded in `suite-full.txt` (its header holds the source digests only) | minor | answered here: the `Gate run` line records the invocation form, `exit 1` and `432ecf0` by digest; future gate transcripts start with the command line |
| G-002 | Test ledger (V5) | the packets' declared +A sums to 441; the collected delta is 491 (e.g. Inc-7 fix-round help ×2, gate-fold additions never re-counted) | minor | the measured ledger above is the record; lesson noted in `05-close.md` |
| G-003 | AT-B97-04 (C-18) | the empty boundary arm sits in a sibling function | minor | the chain node is AT-B97-04's one node, the sibling its boundary arm; fold at a later Check Editor touch |
| G-004 | Layer 0 (C-51) | `fx_run_error_line` declared layer 0 with no named reddening mutation | minor | add one mutant when Flow Execution is next touched, or drop the layer-0 claim |
| G-005 | LLR-151.1 | invalid arm "no highlighted entry → no dismiss" has no node | minor | integrity batch (the operator's instruction: deeper tests of the Inc-9 change go there) |
| G-006 | HLR-151 | the node observes `app.current_project`, not the painted status line; no US / AT id | minor | same integrity-batch item: assert the painted status line |
| G-007 | Inc-9 supersession | no Correction population row; the sibling `str(Label)` in `app.py` `_load_from_item` survives | minor | already in `.dev-flow/BACKLOG-CODE.md` (CW-U-1 status, MEDIUM sibling) |

Already routed to `.dev-flow/BACKLOG-CODE.md` §*Routed 2026-10-25 — batch-97 (the b94 polish) close*, referenced only: the `styles.tcss:2375` `^E` comment; the AT-B97-16 / -24 blank/restore and no-write mutants; the two ux LOWs; the four flakes; the D17 local snapshot regen (one CI `snapshot-regen.yml` run recommended); the b94_polish review page not rebuilt.

### Escaped-bug regression (if a defect escaped the suite)

No product defect escaped an increment gate. Three test-side defects escaped a narrower increment gate set and were caught by the full suite:

| Regression id (`AT-NNN` / `TC-NNN`) | Pre-fix run (evidence it FAILED) | Pre-fix RED kind (value / shape) | Post-fix value-discriminating? (QC-2) | Post-fix result | Reconciled node |
|-------------------------------------|----------------------------------|----------------------------------|----------------------------------------|-----------------|-----------------|
| address census over the new `_show` helper | `evidence/inc-7/suite-full.txt` FAILED; `suite-nonbaseline-rerun.txt` RED in both isolated runs | value (assembled selector found) | yes — the census predicate is unchanged; only the test helper changed | pass — `executed` (orchestrator, `post-suite-fix.txt`, 27 passed) | `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` |
| help scroll timing under load | `evidence/inc-7/suite-full.txt` FAILED (green in isolation; RED only under load) | value (`scroll_y` 92 ≠ end) | yes — still asserts the end position, after `_scroll_at_rest` | pass — `executed` (orchestrator, `post-suite-fix.txt`, 3 × 5 parallel + 5 alone) | `tests/test_window_usage_help.py::test_help_modal_scrolls_by_key_while_close_keeps_the_focus` |
| registry bound left at 198 by Inc-9 | `evidence/inc-7/green.txt` (`test_tc607_scanned_corpus_matches_the_declared_bound`) | value (198 ≠ 199) | yes (count equality) | pass — `executed` (software-dev, `evidence/inc-7/rerun-nonbaseline.txt`, 13 passed) | `tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` |

### Evidence checklist — qa-reviewer (full)
> Attach `qa-reviewer`'s completed evidence checklist (items in `agents/qa-reviewer.md`), each marked ✓/✗ with one-line evidence. An unchecked or evidence-less item blocks the gate.

- ✓ **Given/When/Then** — the contract's per-AT table (appendix A.5: fixture / driver / assertion) carries G/W/T per AT; each HLR states its observable outcome.
- ✓ **Explicit Expected** — every HLR carries a numeric pass threshold (`01-requirements.md` §3), quoted in Layer A.
- ✓ **Edge cases** — QC-3 boundary catalogs per HLR cover empty / boundary / invalid / error, N/A arms justified; one hole, G-005.
- ✓ **Regression checklist** — the gate suite compared node by node with `evidence/baseline-pytest-51ee191.txt` (6 baseline, 5 new, all classified), plus the guard host at every render increment.
- ✓ **Exit criteria** — `01-requirements.md` §5.2 (LLR TCs pass, 26/26 ATs, 0 blockers): met.
- ✓ **No real PII / secrets** — fixtures only (`proj_a` / `proj_b`, `HOSTILE_*`, `ASAP2_Demo_V161.a2l`); no person named.
- ✓ **Mode declared** — `validation`.
- ✓ **Validation mode** — every row carries `executed` / `not-run` / `approved` and names its executor.
- ✓ **Layer B black-box** — US-134..140 observed through the shipped surface with boundary and negative inputs; HLR-151 partial (G-006).
- ✓ **Bidirectional reachability** — matrix above; one partial output (G-006).
- ✗ **No unfilled template** — at review time the `Gate run` command and exit code could not be filled from the evidence (G-001); the orchestrator then filled the line from the batch's recorded invocation form and the transcript's own summary line.
