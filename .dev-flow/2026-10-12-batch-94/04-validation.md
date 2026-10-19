# Validation — s19_app — Batch 2026-10-12-batch-94

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`); for Spanish batches **translate the prose, never a label** — the reserved field names are declared in §✅ Verdict and are read literally.
> Phase 4 artifact. Content owner: `qa-reviewer`, who **EVALUATES** the results of the validation strategy fixed in Phase 1, **names who executed each one** and returns the rows; the orchestrator writes `04-validation.md` (`stations/shared-homes-roles.md` §Delegation). The ONE complete gate-suite run is the orchestrator's (`C-25`); a sub-agent consumes the result and never owns the run.
>
> **Written by the orchestrator from the four increment packets (`03-increments/increment-00{1..4}.md`), the contract (`01-requirements.md` §3/§4/§5), the stored transcripts at `evidence/`, and the DDR record (`design/DDR-2026-10-12-batch-94.md`). Every figure below maps to a stored transcript at the declared evidence home `repo:.dev-flow/2026-10-12-batch-94/evidence/` — no figure is stitched from per-area runs into a fake full-suite figure.**

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
- **Gate run:** `PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -m pytest -q -m "not slow" -p no:cacheprovider` · exit code **1** (5 failed) · tree **`c18d181`** on **`origin/main 121feaa`** · run BY THE ORCHESTRATOR (`C-25`), ONE complete run — **3040 passed / 5 failed / 32 xfailed / 2 skipped / 21 deselected in 0:58:06** · transcript `evidence/p4_gate_suite_run3.txt` (the DEFINITIVE run; run ONE `evidence/p4_gate_suite.txt` 3025 passed / 20 failed in 1:07:40 and run TWO `evidence/p4_gate_suite_run2.txt` 3040 passed / 5 failed in 0:58:03 are the pre-fix / intermediate predecessors — same command, same executor, both reconciled by the two-sided pristine-main probe and the two orchestrator-owned fix rounds, see *Escaped-bug regression* below)
- **Layer 0:** none minted standalone — no unit met the decision or boundary criterion outside the increments' hosted layer-0 candidates (the `C-51` exclusion list; each packet §4/§5 names its candidates with the decision/boundary justification) · the hosted candidates are mutation-measured per the anti-theatre rule, never line-coverage: 4 per-node batteries — `inc001_battery.txt` (23 arms + the fold round), `inc002_battery.txt` (8 arms / 11 node-runs), `inc003_battery.txt` (10 arms / 15 node-runs), `inc004_battery.txt` (7 arms / 12 node-runs) — **65/65 battery node-runs RED, 0 SURVIVED open, 0 CRASH open, every arm hash-restored** (+ 4 C-20 move-asides hash-proven restored)
- **Requirements:** `31/31` TC ids pass · `24/24` AT ids pass · `21/21` HLRs (HLR-001…021) with their 42 LLRs · **0 blocker fails** — the 5 gate failures are **0 NEW deterministic failures attributable to batch-94** (batch-92 rule): 2 A-class (batch-95's TC-707 pair, fails identically on pristine `origin/main`, probe-verified) + 3 C-class (the documented load-modulated family, all green on the quiet isolate re-run `evidence/p4_run3_isolate_3nodes.txt`)
- **Black-box acceptance (Layer B):** ✓ every story's `AT` observes its outcome through the shipped surface with boundary + negative evidence — 24/24 ids (`AT-B94-01…24`), one on-disk node each per `C-18`; `AT-B94-24`'s two-node realization (UI half + declared service half) ratified as accepted, `DDR-2026-10-12-batch-94#COND-2` (the record :99–108, the ids table :151)
- **Surface-reachability (bidirectional):** ✓ all named inputs AND outputs/deliverables reached/observed at the surface through the handlers — the matrix below, 0 gaps
- **Supersession inspection (read off the P3 packets):** ✓ all surviving refs negative — the four packets' V-3 tables: inc-001 the variant family / legacy bare-"Apply" / the refresh-load conflation (0 live refs, surviving hits are absence assertions or the no-op arm); inc-002 the moved panel's one surviving hit is the tombstone module-docstring move notice at `screens_directionb.py:16`, not a dependency; inc-003 / inc-004 per their V-3 tables (every surviving raw severity read is a declared F1/F2 owner-ruled site)
- **Test ledger:** ✓ reconciles (`post = base − D + A`) — pass-count derivation `2831 − 0 + 214 = 3045` collected (the definitive run's actual); scanned-file census `170 − 0 + 10 = 180` per `tests/test_id_registry.py:110`
- **Evidence checklist (qa-reviewer):** `qa-reviewer · 12 of 12 rows ✓ with evidence` (the checklist at the foot of this page; the P4 reconciliation is recorded in `state.json` `decisions_log` entries 12–15)

> The named notes: **N-1** the 29 snapshot marks await the canonical-CI regen (owner item) · **N-2** batch-95's 5 IFC baseline blocks (crossed; coordination-note proposal) · **N-3** the load-flaky family's standing status · **N-4** the evidence hygiene (discharged — the transcripts filed + the `decisions_log` tail) · **N-5** the carried owner items (Inc-004 F1/F2 rulings, the A4 operator field check, TC-707 → batch-95) · **N-6** the Layer-0 declaration above. Any ⚠/✗ → read the matching part.

---

## Detail (reference)

### Layer 0 — unit

| Unit | Which criterion | Node id | Result |
|---|---|---|---|
| *(none minted standalone — the legal empty, declared per `C-51`)* | — | — | — |

**Declared legal empty (orchestrator, `C-51`):** no standalone unit table is owed beyond the increments' hosted layer-0 candidates — each packet §4/§5 names its candidates with the decision/boundary justification:

- **Inc-001:** the six candidates (the validate-merge handler, the dirty-flag writer set, the `_safe_name` suffix, the folder-scan branch, the check-spec assembly, the stale-message no-op) host inside `TC-B94-01/09/10/11/13/15` per `design-proposal.md` §5.
- **Inc-002:** the candidates (the binding-grammar parser, the dedup-suffix, the template sanitiser authority, the md mode selection) host inside `TC-B94-04/21/23/25`.
- **Inc-003:** the candidates (the envelope V1–V6 reader, the mode-dispatch branch, the provenance-line composer, the lane-name uniquifier) host inside `TC-B94-05/28/30/31`.
- **Inc-004:** the candidates (the predicate's fail-closed branch chain, the count-delta arithmetic, the no-op identity) host inside `TC-B94-18/19`.

**Measured by mutation, never by line coverage.** The layer-0 evidence is the per-node mutation batteries — every hosted candidate is covered by arms resolved per node, each mutation by position and operation, every arm hash-restored (`restore-ok=True`; `git status` never accepted as proof):

| Unit | Mutation applied | RED observed? | Transcript |
|---|---|---|---|
| Inc-001 hosted candidates + the 24 minted nodes | 23 arms by position and operation (routing / geometry / guards / retirement / report-forms / primitives); first-pass inert arms re-asserted in FIX ROUND A; arms 05/06 re-verified against the strengthened fold-round assertions | yes — final ledger 23/23 arms RED, 0 SURVIVED open, 0 CRASH open; baseline 27 node-runs in ONE run (`27 passed` tail); fold round 2/2 RED | `evidence/inc001_battery.txt` (+ `evidence/inc001_battery_fold_round.txt`) |
| Inc-002 hosted candidates + the minted builder nodes | 8 arms / 11 node-runs (canvas→placeholder, both-external refusal suppressed, dedup-suffix suppressed, canvas-label scrub dropped, the Mode-A escaper bypassed, A2B bindings dropped at serialize, the missing-CRC-config refusal flipped to OK-skip — the C-1 re-arm, the external-arm source-kind drifted) | yes — 11/11 RED, 0 SURVIVED, 0 CRASH/BAD; the C-20 move-aside of `flow_screens.py` hash-proven restored (`a480fd61…` before=after) | `evidence/inc002_battery.txt` (+ `evidence/inc002_move_aside.txt`) |
| Inc-003 hosted candidates + the minted fx_a nodes | 10 arms / 15 node-runs (the 12th rail row dropped, cancelled-import mounts a lane, one shared bindings dict, the mode field hard-coded, parallel-always dispatch, the inline `✗` suppressed, the all-clean arm emits an `✗`, the reload drops bindings, the runner ignores the bindings, the outputs field omitted) | yes — 15/15 RED, 0 SURVIVED, 0 CRASH/BAD; the 2-file move-aside hash-proven restored (`db680d48…` pins pre-C-56-fix bytes — the packet's L1 naming; `d4db68d3…` matches committed) | `evidence/inc003_battery.txt` (+ `evidence/inc003_move_aside.txt`) |
| Inc-004 hosted candidates + the minted triage nodes | 7 arms / 12 node-runs (the predicate's INFO return → None, the justification swapped out, the count delta zeroed, the row remap dropped, a non-standard name admitted, the frozen engine constant touched, the fold-consistency arm) | yes — 12/12 RED, 0 SURVIVED, 0 CRASH/BAD; the move-aside + battery restores hash-proven (`6311f7c3…` / `a70e08de…` / `1c2c2003…` / `96f29f49…` before=after) | `evidence/inc004_battery.txt` (+ `evidence/inc004_move_aside.txt`) |

Roll-up: **65/65 battery node-runs RED across the four batteries, 0 SURVIVED open, 0 CRASH open** — the hosted layer-0 candidates are mutation-measured per the anti-theatre rule (the DDR's honesty check re-read the stored bytes: 65 battery node-runs + 4 move-asides).

### UX walkthrough — only if trigger family D fired

Trigger **D1 fired** (`state.json` `triggers.fired`: "rail + three surfaces change; ux-reviewer joined the PDR"). This section applies.

| Criterion (when the user does X, they observe Y) | Driven with the REAL mechanism | Painted result asserted | Verdict |
|---|---|---|---|
| Open the rail → 12 ordered surfaces, Check Editor on `=`, Flow Execution on `]` (footer does not drift) | Textual pilot (`run_test`), the real `Binding` keys resolved at runtime (probe-verified, zero collisions) | the shipped rail census painted at 120×30 / 80×24 / 160×40 — 12 ≤ 21 rows at 80×24 | pass — `AT-B94-02` · `evidence/inc003_rail12_probe.txt` (`PROBE: PASS`) · `evidence/pdr_rail_key_probe.txt` |
| Rework the Patch Editor (US-002's six annotations) | the real panels under the pilot at both pilot sizes | the expanded editor as the primary surface; the dirty-guard popup with accept-loss / cancel (exactly one popup, the stack drains empty) | pass — `AT-B94-03…10` · `evidence/inc001_fold_popup_probe.txt` · `evidence/inc001_battery_fold_round.txt` |
| Build a check spec in the Check Editor (US-003) | the ce_a collector through the shipped write / validate controls | the written `.chk.json` re-read (the 315-byte emitted form); the struck-APPLY ghost is an inert Static — 0 actionable apply controls | pass — `AT-B94-11` · `evidence/p1_probe_chk_roundtrip.txt` |
| Place and wire blocks in the Flow Builder (US-005) | the real palette / canvas / Add control | the box-drawn canvas render paste (frames, typed stubs, cable bends, every line ≤ 88 cells); the wiring-refusal notice on a both-external pair | pass — `AT-B94-15/16` · `evidence/inc002_smoke_probe.txt` (`SMOKE OK`) |
| Import, bind, run, save and reload a chain set (US-007) | the real Import… picker, Bind controls, Run, Save Set / Load Set | the lane paints (`▓/░` bars, `▶✗✓` glyphs); the RUN LOG strip naming the failed chain's block and missing config; both outputs regenerate on the reloaded re-run | pass — `AT-B94-19…24` · `evidence/inc003_smoke_probe.txt` |
| Load the operator-class A2L and open Issues (US-004) | the real engine path (`parse_a2l_file` + `validate_a2l_structure`) then the live app chrome on a 120×30 pilot | `#issues_severity_strip` `Warnings 0 · Info 1023`; `#validation_issues_summary` `errors=0 · warnings=0 · info=1023`; the group headers agree — one arithmetic site | pass — `AT-B94-14` · the emitted-form rows of `evidence/inc004_battery.txt` |

**Mechanism used:** a UI test driver — the Textual pilot (`run_test`, in-process) driving the shipped surfaces; painted results asserted on `render().plain` (the emitted form, never the in-memory model).

| Act | What it is | Performed? |
|---|---|---|
| Automated walkthrough | the criteria above, driven through the REAL mechanism | performed — the Layer B acceptance rows + the smoke / rail / popup probes (all transcripts stored under `evidence/`) |
| Expert inspection | a cognitive walkthrough against declared criteria, by a reviewer and not a user | performed — the `ux-reviewer` lens joined the PDR (trigger D1); the fold rounds' chrome findings (Inc-001 F2/F3 ux#3/ux#6, the Inc-004 F1/F2 judgment question) were reviewed and ruled by `code-reviewer` |
| Evaluation with users | real users of the system, doing the tasks named in the context of use | not performed — no user-evaluation session was run this batch; the operator is the sole user of this surface and the A4 real-terminal field check (the `=`/`]` key delivery, unmeasurable headlessly) remains the named user-contact debt (note N-5); every acceptance is authored key-independent per R-1, so no gate blocks on it |

- **Method:** the acceptance rows drive the shipped surfaces under the Textual pilot at the declared pilot sizes (120×30 and 160×40; 80×24 where the acceptance says so), asserting the painted result on `render().plain`; no proxy interaction (no direct setters, no `.focus()` in place of the real keys).
- **Participants or population:** none — no human participants; the operator (calibration engineer, the system's only user) did not sit a session this batch.
- **Evidence of the evaluation:** the AT / probe transcripts at `repo:.dev-flow/2026-10-12-batch-94/evidence/` (`inc001_fold_popup_probe.txt`, `inc002_smoke_probe.txt`, `inc003_smoke_probe.txt`, `inc003_rail12_probe.txt`, `pdr_rail_key_probe.txt`, the four batteries and suite transcripts).
- **Limits:** a pilot is not a human — timing, muscle memory and real-terminal key delivery are exactly what A4 leaves open; the expert inspection is a reviewer lens, not user evidence; the walkthrough tasks were chosen by the author.

### Layer A — functional (white-box): per-requirement results
> `TC-NNN` ↔ LLR/HLR. `Result` = pass / fail. `Evidence` = command output, observed behavior, inspection note, or analysis result. Executor attribution per packet: **Inc-001 = ORCH-P3** (the orchestrator's increment session at Phase 3) · **Inc-002/003/004 = IMPL-P3** (the implementer's increment session at Phase 3). Every increment's baseline is ONE complete run of its minted nodes inside its battery transcript, corroborated by the stored per-suite transcripts cited.

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| **Inc-001 (ORCH-P3) — `TC-B94-01…03, 06…17` ↔ LLR: 14 ids / 15 node instances (TC-B94-09 parametrized ×2), 14/14 ids green in the battery baseline** | | | | | |
| TC-B94-01 ↔ LLR-004.1/004.2 | test | `test_tui_patch_editor_b94.py::test_tc_b94_01_validate_merge_paths` | valid text merges 100% of declared entries in document order; invalid text leaves the table byte-identical | pass | battery arms 03/04/13/14 · `inc001_battery.txt` · `inc001_suite_editors.txt` (52) · ORCH-P3 |
| TC-B94-02 ↔ LLR-007.1 | test | `…::test_tc_b94_02_apply_gate` | a `kind="change"` doc applies; a check spec through the same gate → `blocked: 2`, `mem_map` untouched (0 writes) | pass | arm 14 · `p1_probe_chk_roundtrip.txt` (`PROBE OK`) · ORCH-P3 |
| TC-B94-03 ↔ LLR-008.1/008.2 | test | `…::test_tc_b94_03_load_and_refresh_semantics` | Refresh repopulates the dropdown from the folder scan and never re-reads the loaded document (hash equality before/after) | pass | arm 15 · ORCH-P3 |
| TC-B94-06 ↔ LLR-009.3 | test | `test_tui_check_editor.py::test_tc_b94_06_composition_census` | 0 actionable apply controls in the ce composition (the struck-APPLY ghost is an inert Static) | pass | arm 10 · ORCH-P3 |
| TC-B94-07 ↔ LLR-001.2/002.1 | test | `test_tui_check_editor.py::test_tc_b94_07_rail_mounting_and_write_routing` (+ `…07b` help one-liner) | the `=` binding resolves with zero collisions; write routing lands on the Check Editor | pass | arm 01 · `pdr_rail_key_probe.txt` (both bindings, no collision) · ORCH-P3 |
| TC-B94-09 ↔ LLR-003.1 | test (e2e) | `test_tui_patch_editor_b94.py::test_tc_b94_09_widget_census` (×2 size params) | the expanded `JsonHighlightTextArea` is the panel's primary edit surface at both pilot sizes | pass | arm 02 · ORCH-P3 |
| TC-B94-10 ↔ LLR-005.1 | test | `…::test_tc_b94_10_dirty_flag_transitions` | dirty-flag writers exactly w1–w4 (table-edit→set, text-edit→set, save→clear, load-success→clear); the empty-path guard drops | pass | arms 05/09/16 · ORCH-P3 |
| TC-B94-11 ↔ LLR-006.1/006.2 | test | `…::test_tc_b94_11_stale_variant_noop_and_single_binding` | 0 live variant symbols/handlers in the editor surfaces; a stale `VariantSelected`-shaped post is a no-op | pass | arms 07/17 v2 · ORCH-P3 |
| TC-B94-12 ↔ LLR-007.2 | test | `…::test_tc_b94_12_apply_label_census` | 0 legacy bare-"Apply" labels survive; "Apply loaded changes" wording only | pass | arm 18 · ORCH-P3 |
| TC-B94-13 ↔ LLR-009.1 | test | `test_tui_check_chain_b94.py::test_tc_b94_13_chk_write_round_trip` | the `.chk.json` double suffix survives `_safe_name`; the written file re-reads | pass | arm 19 · ORCH-P3 |
| TC-B94-14 ↔ LLR-009.2 | test | `…::test_tc_b94_14_run_check_document` | one verdict per entry (`pass` / `uncheckable` with reason `outside`) | pass | `p1_probe_chk_roundtrip.txt` · ORCH-P3 |
| TC-B94-15 ↔ LLR-010.1 | test | `…::test_tc_b94_15_dropdown_population` | check specs listed suffix-distinguished from patch files | pass | `inc001_suite_editors.txt` · ORCH-P3 |
| TC-B94-16 ↔ LLR-010.2 | test | `…::test_tc_b94_16_report_addendum` | 100% of the declared names present in the emitted `## Checks` table (the pinned spelling / columns) | pass | arm 22 · `p1_probe_diff_report_emitted.txt` · ORCH-P3 |
| TC-B94-17 ↔ LLR-011.1/011.2 | test | `test_tui_check_editor.py::test_tc_b94_17_safe_text_hostile_payload` | the hostile payload renders with 0 spans / 0 control bytes | pass | arm 23 · ORCH-P3 |
| **Inc-002 (IMPL-P3) — `TC-B94-04, 20…25` ↔ LLR: 7 ids / 18 collectable node instances across the 2 new files, 7/7 ids green** | | | | | |
| TC-B94-04 ↔ LLR-015.1/015.2 | test | `test_flow_a2b_b94.py::test_tc_b94_04_template_save_reload_and_dedup` (+ `_zero_block_template_saves`, `_name_sanitiser_is_the_write_authority`) | the v1 envelope round-trips; a second same-name save lands under the dedup suffix (0 clobbers); the zero-block reload refusal stays `FLOW-BAD-STRUCTURE` (V1–V7 fail-closed unreopened) | pass | arm 03 · `inc002_battery.txt` (baseline 11 node-runs) · `inc002_suite_flow_family.txt` (124) · IMPL-P3 |
| TC-B94-20 ↔ LLR-013.1/013.2 | test | `test_tui_flow_builder_b94.py::test_tc_b94_20_fb_a_composition_census` | 3 placeable palette types (patch · CRC · A2B-diff) on the palette rail; the palette+canvas compose | pass | arm 01 · IMPL-P3 |
| TC-B94-21 ↔ LLR-014.1 | test (integration) | `test_flow_a2b_b94.py::test_tc_b94_21_roundtrip_one_of_each_kind_incl_a2b` (+ `_loader_refuses_a2b_binding_arm`) | the A2B bindings survive serialize round-trip; the loader refuses the A2B binding (`_A2L_REF_KINDS` unextended) | pass | arm 06 · IMPL-P3 |
| TC-B94-22 ↔ LLR-013.3 | test (integration) | `…::test_tc_b94_22_patch_write_out_run_records_per_block_results` (+ `_upstream_crc_failure_skips_write_out`) | 0 image files written when an upstream block fails (`written_paths` empty after a failed chain); per-block results recorded on the clean twin | pass | arm 07 — the C-1 re-arm · IMPL-P3 |
| TC-B94-23 ↔ LLR-014.1 | test | `…::test_tc_b94_23_binding_validation_matrix` (+ `_binding_text_grammar`) | every accept/refuse pair over the grammar's input space; the both-external pair refused (0 reports for refused bindings) | pass | arm 02 · IMPL-P3 |
| TC-B94-24 ↔ LLR-014.2 | test | `…::test_tc_b94_24_a2b_report_states_each_inputs_provenance` (+ `_upstream_failure_yields_no_report`) | the two provenance lines emitted character-for-character; no report on an upstream failure | pass | arm 08 · `inc002_smoke_probe.txt` (the verbatim paste) · IMPL-P3 |
| TC-B94-25 ↔ LLR-016.1 | test | `…::test_tc_b94_25_md_safe_md_code_mode_truth_table` (+ `_hostile_file_name_in_emitted_report`) | the Mode-A escaper holds (raw paths never emitted); a hostile file name renders inert in the report | pass | arm 05 · IMPL-P3 |
| **Inc-003 (IMPL-P3) — `TC-B94-05, 08, 26…31` ↔ LLR: 8 ids (13 collectable node instances across the 2 new files), 8/8 ids green** | | | | | |
| TC-B94-05 ↔ LLR-019.1/019.2 | test | `test_flow_chainset_b94.py::test_tc_b94_05_mode_capture_in_run_record_and_report` (+ `_parallel_dispatch_runs_chains_concurrently`) | the run record captures the mode (the untouched default never changes); parallel dispatch overlaps lanes with per-lane failure isolation | pass | arms 04/05 · `inc003_battery.txt` (15/15) · IMPL-P3 |
| TC-B94-08 ↔ LLR-002.1 | test | `test_tui_flow_execution_b94.py::test_tc_b94_08_rail_entries_census_and_duplicate_rejection` | 12 rail entries; the `]` binding resolves with zero collisions; duplicate screen ids rejected | pass | arm 01 · `inc003_rail12_probe.txt` (12 ≤ 21 rows at 80×24) · IMPL-P3 |
| TC-B94-26 ↔ LLR-017.1/017.2 | test (e2e) | `…::test_tc_b94_26_lane_mounting_and_render_census` | lanes render side by side inside the boxed budgets (two 46-cell lanes in the 96×18 workspace; the 80×24 fallback scrolls inside `#fx_lanes_scroll`) | pass | arm 02 · `_PILOT_SIZES` census · IMPL-P3 |
| TC-B94-27 ↔ LLR-018.1 | test | `…::test_tc_b94_27_lane_binding_isolation_and_noop` | editing lane A writes only lane A's record | pass | arm 03 · IMPL-P3 |
| TC-B94-28 ↔ LLR-018.2 | test | `test_flow_chainset_b94.py::test_tc_b94_28_run_consumes_each_chains_own_bindings` | `lane_specs()` emits the effective inputs (SOURCE refs + operator overrides); a stale input is never named after a rebind | pass | arm 09 · IMPL-P3 |
| TC-B94-29 ↔ LLR-020.1 | test | `test_tui_flow_execution_b94.py::test_tc_b94_29_run_log_emission_and_all_clean_arm` | one `▶ … started` + one terminal line per chain; the all-clean arm invents no failure | pass | arms 06/07 · IMPL-P3 |
| TC-B94-30 ↔ LLR-020.2 | test | `test_flow_chainset_b94.py::test_tc_b94_30_chain_set_report_provenance_lines` (+ `_compose_is_deterministic_and_md_safe`) | one `- Chain <name> input <i>: <ref> [bound] path=…` line per bound input (the C-42 paste); deterministic, markup-safe compose | pass | `inc003_smoke_probe.txt` · IMPL-P3 |
| TC-B94-31 ↔ LLR-021.1/021.2 | test | `…::test_tc_b94_31_chain_set_serializer_round_trip` (+ `_empty_set_and_hostile_sets_fail_closed`) | the v1 envelope round-trips chains + bound inputs + recorded outputs; an empty set / a sanitised-away name / a hostile set writes NOTHING (V1–V6 fail-closed) | pass | arm 10 · IMPL-P3 |
| **Inc-004 (IMPL-P3) — `TC-B94-18, 19` ↔ LLR: 2 ids / 2 nodes, 2/2 ids green** | | | | | |
| TC-B94-18 ↔ LLR-012.1 | test | `test_tui_issues_triage_b94.py::test_tc_b94_18_curated_set_and_engine_freeze` | the curated set is exactly the 21 executed families (1 023 findings); 0 hunks on `validation/rules.py` + `tui/a2l.py` vs `main` (CRLF-aware byte-equality, in-run) | pass | arms 05/06 · `inc004_battery.txt` (12/12) · IMPL-P3 |
| TC-B94-19 ↔ LLR-012.2 | test | `…::test_tc_b94_19_panel_reclassification_matrix` | the INFO/WARNING split remaps rows only (the caller's list is never mutated); the no-reclassification arm is byte-identical; the hostile `[red]` payload renders with 0 spans | pass | arms 01/02/04 · IMPL-P3 |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a verification nobody ran. Write your own rows in the table above.

```text
| *(example)* HLR-001 | test | `pytest … -k TC-001` | exit 0 | | |
| *(example)* LLR-001.1 | test (unit) | `…` | `…` | | |
```

### Layer B — behavioral (black-box) acceptance

| US | Acceptance test (`AT-NNN`) | Surface driven | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|----------------------------|----------------|---------------------------------------|----------------------------|--------|
| US-001 | `AT-B94-01` | the rail + pilot; the `=` binding pressed through the pilot | the mounted `CheckEditorPanel` twin (the composed panel census) | ✓ · ✓ · ✓ (the base rail census — 10 entries, no Check Editor — is the executed RED side, `p1_probe_rail_census.txt`) | pass — arm 01 · `inc001_battery.txt` |
| US-001 (HLR-002) | `AT-B94-02` | the shipped rail at 120×30 / 80×24 / 160×40 | 12 ordered entries painted; `]` mounts `FlowExecutionPanel`; the footer does not drift (C-13) | ✓ · ✓ (80×24: 12 ≤ 21 rows) · ✓ (duplicate keys rejected — TC-B94-08) | pass — `inc003_rail12_probe.txt` (`PROBE: PASS`) · arm 01 |
| US-002 | `AT-B94-03` | the reworked Patch Editor under the pilot at both sizes | the expanded `JsonHighlightTextArea` as the primary edit surface (widget census on `render().plain`) | ✓ · ✓ (size0/size1 params) · ✓ (the height-collapse mutation → RED, arm 02) | pass |
| US-002 | `AT-B94-04` | Edit-JSON + validate through the panel | 100% of the declared entries merged into the entries table in document order | ✓ · ✓ · ✓ | pass — arm 03 |
| US-002 | `AT-B94-05` | invalid Edit-JSON text | the collected issues surface; the entries table byte-identical | ✓ · ✓ · ✓ | pass — arm 04 |
| US-002 | `AT-B94-06` | Load with unsaved edits | the `LoadGuardScreen` popup; the accept-loss branch; exactly one popup and the stack drains empty | ✓ · ✓ · ✓ (the pre-fold duplicate-push defect was caught by the popup probe, not by the ATs) | pass — arm 05 + fold round · `inc001_fold_popup_probe.txt` |
| US-002 | `AT-B94-07` | the cancel branch (clean load = `AT-B94-07b`, pops nothing) | the loaded document is kept on cancel | ✓ · ✓ · ✓ | pass — arm 06 |
| US-002 | `AT-B94-08` | the retired selector's seam | a stale `VariantSelected`-shaped post is a no-op; 0 live variant symbols in the editor surfaces | ✓ · ✓ · ✓ (the synthetic instance: arm 17 v2 inserted the retired handler → RED) | pass |
| US-002 | `AT-B94-09` | Apply presented as "Apply loaded changes" | exactly the loaded document's entries applied through the existing gate; skips never counted as applied | ✓ · ✓ · ✓ (arm 08's zero-skip blindness was re-declared and killed) | pass |
| US-002 | `AT-B94-10` | Load (adjacent path input) + Refresh | Load reads the path input (the empty-path guard drops); Refresh repopulates the dropdown from the folder scan, the loaded document untouched | ✓ · ✓ · ✓ | pass — arms 09/15/16 |
| US-003 | `AT-B94-11` | the Check Editor's write / validate controls | the written `.chk.json` (v2 `kind="check"`, the 315-byte emitted form re-read); 0 actionable apply controls — the struck-APPLY ghost is an inert Static | ✓ · ✓ (empty / hostile arms) · ✓ (the apply-gate probe: `blocked: 2`, `mem_map` untouched) | pass — arms 10/14 · `p1_probe_chk_roundtrip.txt` |
| US-003 | `AT-B94-12` | the A2B Diff dropdown | check specs listed suffix-distinguished from patch files; the C-12 chain runs writer → THAT file → the report | ✓ · ✓ · ✓ | pass — arm 11 |
| US-003 (HLR-011) | `AT-B94-13` | the shipped Check Editor fed a hostile symbol + file name | the `safe_text`-scrubbed render: 0 spans / 0 control bytes survive | ✓ · ✓ (the hostile payload) · ✓ | pass — arm 12 |
| US-004 | `AT-B94-14` | the live app chrome on the 13 990-tag fixture through the real engine path, 120×30 pilot | `#issues_severity_strip` `Warnings 0 · Info 1023`; `#validation_issues_summary` `errors=0 · warnings=0 · info=1023`; the group headers agree; the tail-40 window renders INFO too (no row dropped) | ✓ · ✓ (the tail-window arm) · ✓ (`FROBNICATE` still warns on the mixed arm — `ERRORS 1 · WARNINGS 1 · INFO 38`; the caller's engine list keeps raw severities) | pass — arms 01–05/07 · `inc004_battery.txt` |
| US-005 | `AT-B94-15` | the fb_a palette + canvas under the pilot | the box-drawn canvas render paste (`┌─┐` frames, `┤├` typed stubs, `└┐` bends, `·` dots; every line ≤ 88 cells) + the empty-state arm | ✓ · ✓ (empty state at first mount) · ✓ | pass — arm 01 · `inc002_smoke_probe.txt` |
| US-005 | `AT-B94-16` | the real Add control with `#flow_ref_a` / `#flow_ref_b` bindings | the wiring-refusal notice through the real control (block count stays 3); the accepted (flow,file)/(flow,flow) arms produce the report with provenance lines | ✓ · ✓ (the (file,file) pair refused) · ✓ | pass — arm 02 · `inc002_smoke_probe.txt` |
| US-005 | `AT-B94-17` | Save template + the listing + re-import | the v1 envelope on disk; a second same-name save lands under the dedup suffix — 0 clobbers | ✓ · ✓ · ✓ (the dedup-suffix suppression → RED, arm 03) | pass |
| US-005 | `AT-B94-18` | hostile block / file names through the canvas | names render literally (the canvas-label scrub); the `from_markup` AST census stays 0 | ✓ · ✓ (hostile names) · ✓ | pass — arm 04 |
| US-007 | `AT-B94-19` | Import… through the reused `LoadFlowScreen` picker | one lane per template, mounted side by side; a cancelled picker adds 0 lanes; a corrupt template is refused with the notice; duplicate imports uniquify (`_<N>`) — 0 duplicate lanes | ✓ · ✓ (cancel / corrupt arms) · ✓ | pass — arm 02 |
| US-007 | `AT-B94-20` | the per-lane Bind control | the Bind writes only its own lane; the run reads each chain's own inputs | ✓ · ✓ · ✓ (one shared bindings dict → RED, arm 03) | pass — arms 03/09 |
| US-007 | `AT-B94-21` | the mode Select (parallel-per-chain) | overlapping time windows across lanes + per-lane failure isolation + the mode captured in the record and the report | ✓ · ✓ (the error arm isolates to its own chain) · ✓ | pass — arms 04/05 |
| US-007 | `AT-B94-22` | the untouched default run | strictly sequential dispatch — the mechanism pinned, not only the timing (TC-B94-05's mode capture + arm 05's parallel-always mutation) | ✓ · ✓ · ✓ | pass |
| US-007 | `AT-B94-23` | Run over a set with a failing chain | the RUN LOG strip: one `▶ … started` + one terminal line per chain; the inline `✗ <chain> · block i/n <KIND> — <detail> · chain halted` names the failed chain's block and its missing config (the recorded diagnostic); the chain-set report's provenance lines | ✓ · ✓ (the all-clean arm emits no `✗`) · ✓ | pass — arms 06/07 · `inc003_smoke_probe.txt` |
| US-007 | `AT-B94-24` | Save Set / Load Set + the re-run | `flowsets/<name>.json` written (chains + bound inputs + recorded outputs); the reload REPLACES the lanes (a restore, never a merge); both outputs regenerate on the reloaded re-run; a moved bound input mounts with the per-lane provenance-mismatch notice — never a silent stale run; a chain whose template is gone is skipped and NAMED | ✓ · ✓ (the moved-input notice arm) · ✓ (the empty set / hostile sets write NOTHING — V1–V6) | pass — arms 08/10 · the UI node `test_tui_flow_execution_b94.py:846` drives the whole named chain end-to-end; the service node `test_flow_chainset_b94.py:484` is the declared supplementary arm — the two-node realization ratified as accepted, `DDR-2026-10-12-batch-94#COND-2` (the record :99–108; the ids table :151) |

### Bidirectional surface-reachability matrix (extends A-5)
> Every named INPUT dimension AND every named OUTPUT/deliverable is exercised/observed through the handler — not only the service API. Rows are grounded in the four packets' shipped-surface drives (the AT rows above and the stored probe transcripts).

| Direction | US dimension / deliverable | Service param / producer | Reached/observed at surface? | TC / AT | Status |
|-----------|---------------------------|--------------------------|------------------------------|---------|--------|
| input | rail key bindings `=` / `]` → the two new surfaces | `Binding(…, show=False)` + `check_editor` / `flow_execution` routing (`app.py`) | yes — pressed through the pilot; runtime resolution probed with zero collisions | `AT-B94-01` / `AT-B94-02` · `pdr_rail_key_probe.txt` | ✓ |
| input | raw JSON text edits across both editor regions | `JsonHighlightTextArea` + the dirty-flag writers w1–w4 | yes | `AT-B94-03` · `TC-B94-10` | ✓ |
| input | Edit-JSON + validate text (valid / invalid) | the validate-merge handler | yes — the invalid arm leaves the table byte-identical | `AT-B94-04/05` · `TC-B94-01` | ✓ |
| input | Load path input + the dirty-guard answer | the dirty-load guard handler → `LoadGuardScreen` | yes — accept-loss and cancel both driven | `AT-B94-06/07/10` | ✓ |
| input | check-spec entries (A2L parameter / location declarations) | the ce_a collector → `write_change_document` | yes — written then re-read through the shipped writer/reader | `AT-B94-11` · `TC-B94-13` | ✓ |
| input | fb_a palette placements + canvas wiring (`#flow_ref_a` / `#flow_ref_b`) | the binding grammar — the accept/refuse matrix; both-external refused at the real Add control | yes | `AT-B94-15/16` · `TC-B94-23` | ✓ |
| input | template name + Save (the dedup case) | `save_flow_json` — the name sanitiser is the write authority | yes | `AT-B94-17` · `TC-B94-04` | ✓ |
| input | the mode Select (sequential default / parallel-per-chain) | `run_chain_set` dispatch (wraps the union `run_flow` per chain) | yes | `AT-B94-21/22` · `TC-B94-05` | ✓ |
| input | per-lane Bind inputs (rebinding) | `_FxLane.bindings` + `lane_specs()` | yes — a rebind never names a stale input | `AT-B94-20` · `TC-B94-27/28/30` | ✓ |
| input | Save Set / Load Set name + the set picker | `save_chain_set` / `load_chain_set` (the `import_flow_file` containment idiom) | yes | `AT-B94-24` · `TC-B94-31` | ✓ |
| input | the operator-class A2L file load | `parse_a2l_file` + `validate_a2l_structure` (the P1 probe's exact path) | yes — 13 990 tags through the real engine | `AT-B94-14` | ✓ |
| output | the `.chk.json` check-spec file on disk | `write_change_document` (the v2 envelope) | yes — round-trip re-read; the 315-byte emitted form pinned | `AT-B94-11/12` · `TC-B94-13` · `p1_probe_chk_roundtrip.txt` | ✓ |
| output | the A2B diff report's `## Checks` addendum | `diff_report_service._check_addendum_lines` | yes — the emitted-form paste pinned, 100% of declared names | `TC-B94-16` · `p1_probe_diff_report_emitted.txt` | ✓ |
| output | the flow template `flows/*.json` | `save_flow_json` | yes — the envelope re-read (schema_version 1, `blocks`); the empty arm saves and reload-refuses | `AT-B94-17` · `TC-B94-04` | ✓ |
| output | the A2B flow report `reports/*flow-a2b*.md` + its provenance lines | `generate_diff_report` (the flow-a2b arm) | yes — both provenance lines verbatim | `AT-B94-16` · `TC-B94-24` · `inc002_smoke_probe.txt` | ✓ |
| output | the chain-set `flowsets/<name>.json` | `save_chain_set` (the v1 envelope) | yes — round-trips chains + bindings + outputs; empty/hostile fail-closed | `AT-B94-24` · `TC-B94-31` | ✓ |
| output | the chain-set report `# Chain-set report — <name>` + per-run input provenance | the `ChainSetRunRecord` report composer | yes — the C-42 paste, one line per bound input | `AT-B94-23/24` · `TC-B94-30` · `inc003_smoke_probe.txt` | ✓ |
| output | the lane paints + the RUN LOG strip | `render_run` / the `_Grid` painter | yes — the `render().plain` pastes | `AT-B94-19/23` · `TC-B94-26/29` · `inc003_smoke_probe.txt` | ✓ |
| output | the Issues triaged census (strip / summary / group headers) | `adjust_counts_for_a2l_triage` — the single arithmetic site | yes — the painted bytes asserted on the live chrome | `AT-B94-14` · `TC-B94-19` | ✓ |
| output | the severity strip / help one-liner / footer chrome (no drift) | the rail / footer painters (`app.py`) | yes — the chrome census at 12 entries, the `?`-chip gap named (batch-95-frozen `window_help.py`) | `AT-B94-02` · `inc003_rail12_probe.txt` | ✓ |

### Signed-balance test ledger
> `post = base − D + A`. State counts in collected / passed-lean / passed-full form.

| base | − D | + A | = post | actual collected | passed-lean / full | reconciles? |
|------|-----|-----|--------|------------------|--------------------|-------------|
| `2831` | `0` | `214` | `3045` | `3045` (the definitive gate run, `p4_gate_suite_run3.txt`) | `3040` / `3040` (no xpasses — the 32 snapshot marks xfail as predicted; 2 skipped, 21 deselected) | yes |
| `170` scanned test files | `0` | `10` | `180` | `180` (`tests/test_id_registry.py:110`, `EXPECTED_SCANNED_TEST_FILES`) | — | yes |

- **Pass-count derivation:** base `2831` = the batch-93 close baseline re-derived at this gate (2 796 passed + 35 pre-existing fails — the DDR's honesty check against `evidence/p4_gate_suite.txt`); `+214` = the batch's net collected growth (the 8 new test files' nodes + parametrized growth + the RC-1 union with batch-95's landed work, re-derived as 3 045 collected at the definitive run).
- **File census:** the registry's own chain at the constant documents `172 → 175 → 177 → 179 → 180` (the measured moves per increment; the batch-frame derivation is `170 → 180`: 8 batch-94 new files + 2 batch-95 union files from the RC-1 mid-session rebase, 0 deleted). The 8 rewrites / census moves post as in-place edits and carry no balance change beyond their constants (per each packet's ledger row).

### Gaps detected
| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| N-1 | HLR-002 / the snapshot matrix | the 29 snapshot drift marks await the canonical-CI regen (the Inc-003 mark's retirement note names BOTH generations — one regen retires both); under `strict=False` a stale mark XPASSes silently and masks regressions | minor | owner: the canonical CI regen workflow — must land before any further chrome move |
| N-2 | the batch-95 IFC baseline | batch-95's 5 IFC baseline blocks were crossed in-batch (the union compat probes, 86 passed at every gate); the crossing wants a coordination note, not a silent assumption | minor | owner: the close review / the batch-95 coordination lane — propose the coordination note |
| N-3 | the load-flaky family (contract §5.2's "0 new snapshot failures" neighbourhood) | the load-modulated family (`at_061a` / `tc330` / `saveback_width_32` / `at077c` / `at064c`) is documented pre-existing (batch-95's HEAD-pristino worktree probe) — 3 of the definitive run's 5 failures; the identities move across runs; all green on the quiet isolate | minor | owner: lane-A test-hygiene + the canonical-CI regen workflow — the standing status stays named until the regen |
| N-4 | evidence hygiene (the qa checklist's "no unfilled template" neighbourhood) | the P4 transcripts were filed at the evidence home as the runs landed and the autonomous decisions are summarized in `state.json` `decisions_log` (entries 12–15, the P4 tail) | minor — **discharged** | owner: P4 — closed here |
| N-5 | the carried owner items | Inc-004 **F1** (`#ws_stats` speaks raw severity — folding would amend LLR-042.9-pinned behavior) and **F2** (the severity filter-button chrome speaks raw severity — label-vs-content only, no wrong severity rendered anywhere; the HLR-012 judgment question answered: no violation on the shipped surface) await the owner ruling; **A4** (the operator's real-terminal check of the `=`/`]` delivery) stays field-verification debt; the **TC-707** pair belongs to batch-95's missing `prototypes/cambios_10_12_2026/help_sections.md` | major (F1/F2 ruling) / minor (A4, TC-707) | owner: the P4/close review or lane A (F1) · an owner decision on the LLR-042.x filter semantics (F2) · the operator, hands-on (A4) · batch-95's lane (TC-707) |
| N-6 | Layer 0 (`C-51`) | the legal empty is a declaration, not a silence: no standalone unit table is owed beyond the hosted candidates; the evidence is mutation-measured (65/65 battery node-runs RED), never line-coverage | minor — declared | owner: the orchestrator (`C-51`, declared at the keyed field and the Layer-0 section) |

### Escaped-bug regression (if a defect escaped the suite)

Sixteen regressions escaped the increment suites into gate run ONE (`evidence/p4_gate_suite.txt`, 3 025 passed / 20 failed in 1:07:40); two orchestrator-owned fix rounds closed them. Run ONE's 20-failure census, reconciled by the two-sided pristine-main probe (`C:/Users/jjgh8/kimi/p4_probe_{main,batch}_full.log`): **16 batch-94 regressions in the 5 root causes below** (green on pristine `origin/main`, red here, deterministic) + 2 of the documented load-flake family + batch-95's 2 TC-707 failures. The postmortem lesson is recorded in `decisions_log` entry 12: the per-increment reverse censuses keyed on symbol names and missed the surface families — the P4 probe caught what the increment censuses did not.

| Regression id (`AT-NNN` / `TC-NNN`) | Pre-fix run (evidence it FAILED) | Pre-fix RED kind (value / shape) | Post-fix value-discriminating? (QC-2) | Post-fix result | Reconciled node |
|-------------------------------------|----------------------------------|----------------------------------|----------------------------------------|-----------------|-----------------|
| `AT-056e` + the A2B HTML diff-report family | gate run ONE, `p4_gate_suite.txt` — `test_at_056e…` FAILED (the probe's batch side red / main side green) | **shape** — the Inc-001 `check_spec` kwargs TypeError killed ALL A2B HTML diff reports (`app.py` forwards to `generate_diff_report_html`, which lacks the params — a shipped defect) | yes — the post-fix assertion pins byte-identity of the report despite selection (a wrong-but-well-typed report fails it); the batteries re-RED the diff-check wiring on typed mutations (arm 11) | `p4fix_suite_checks_family.txt` 35 passed · `p4fix_suite_diff_family.txt` 53 passed · the 16 B-nodes bucket `p4fix_suite_bbucket16.txt` 16 passed | fix round 1, `d552f34` (content `ae00752` post-rebase #7) |
| `AT-B78-23/31/33` · `TC-B78-52/54` | gate run ONE — the five B78 geometry rows FAILED | **value** — the new `diff_check_row` eats the diff hex area (0–5 rows at the B78 sizes; a C-13 violation) | yes — the geometry invariants re-asserted at the B78 sizes re-RED on a regression of the row geometry | `p4fix_suite_rework_geometry.txt` 17 passed · `p4fix_suite_diff_family.txt` 53 passed | `d552f34` |
| `AC1` · `AC1b` · `AC3` · `AC5` | gate run ONE — the four json-window fill rows FAILED | **value** — the Inc-001 auto-height overrides defeat the json-window fill tcss (4 fill invariants broken) | yes — fill / min-floor / sibling-leak / gauge invariants each re-RED on its own typed mutation | `p4fix_suite_patch_json_ac4.txt` 4 passed · `p4fix_suite_patch_json_full.txt` 17 passed | `d552f34` |
| `AT-057b` · `AT-B78-32` · `TC-081-4` | gate run ONE — the regroup-wiring / bindings-block / no-binding-diff rows FAILED | **value** — the two ratified rail bindings (`=` / `]`) trip the B78/81 UNSANCTIONED-bindings censuses | yes — the census arms re-RED when a sanctioned binding is renamed out (the censuses extended to the PDR-ratified 12) | `p4fix_suite_census_guards.txt` 13 passed · the guard host `p4fix_suite_directionb.txt` 184 passed | `d552f34` |
| `TC-081-2` · `TC-078-3` · `TC-653` · `AT-286` | gate run ONE — the strip / census / import-census / registry-token rows FAILED | **value + shape** — four reconciliations: the strip-restructure DOM walk, `refresh_check_results` census 2→3, the `safe_text` import census over the new file (`+flow_screens`), the TC-337 token lost in the variants rewrite | yes — the token / census arms re-RED on the lost token and the stale counts | `p4fix_suite_census_guards.txt` 13 passed · `p4fix_suite_issues_family.txt` 16 passed | `d552f34` |
| `AT-B83-08` · `TC-024` (fix round 1's own escape) | gate run TWO, `p4_gate_suite_run2.txt` (3 040 passed / 5 failed) + probe round 2 — the address-census / report-trigger rows FAILED | **value** — round 1's own Call-form `mount(before=…)` address-arg vs the `AT-B83-08` assembled-selector census | yes — the hoisted name-query arm re-REDs on an assembled selector | `p4fix2_suite_address_b78.txt` 24 passed | fix round 2, `c18d181` |

After both rounds, the **definitive gate run THREE** (`evidence/p4_gate_suite_run3.txt`, tree `c18d181` on `origin/main 121feaa`, 0:58:06) holds the final disposition: **3 040 passed / 5 failed / 32 xfailed / 2 skipped / 21 deselected — 0 NEW deterministic failures attributable to batch-94**: the 2 A-class rows are batch-95's TC-707 pair (its missing `prototypes/cambios_10_12_2026/help_sections.md`; fails identically on pristine `origin/main`, probe-verified) and the 3 C-class rows are the documented load-modulated family (all green on the quiet isolate re-run `evidence/p4_run3_isolate_3nodes.txt` — 3 passed in 13.71s).

### Evidence checklist — qa-reviewer (full)
> Attach `qa-reviewer`'s completed evidence checklist (items in `agents/qa-reviewer.md`), each marked ✓/✗ with one-line evidence. An unchecked or evidence-less item blocks the gate.

Completed by **`qa-reviewer`** (the P2 lens + the P4 reconciliation; the orchestrator wrote this record from its returned rows — `stations/shared-homes-roles.md` §Delegation). **12 of 12 rows ✓.**

- [x] Acceptance criteria use Given/When/Then. — ✓ every AT row in the contract's §5.1 / the packets states its observable outcome + boundary + negative arm (e.g. `AT-B94-14`'s 1 023-arm / mixed arm / negative control).
- [x] Test cases have explicit Expected, not vague "works". — ✓ every Layer A row above names its numeric threshold (100% merged, 0 clobbers, 12 ≤ 21 rows, byte-identical tables, 1 023 == 1 023).
- [x] Edge cases include empty, boundary, invalid, error. — ✓ the batteries' empty / hostile / fail-closed arms per increment (`TC-B94-04` zero-block, `TC-B94-31` empty/hostile sets, `AT-B94-13/18` hostile payloads, `AT-B94-06/07` both popup branches).
- [x] Regression checklist exists. — ✓ each packet §4 *Reverse census* (B1–B4 + A3 + the did-NOT-fire probes named per C-48) + the P4 two-sided probe; the escaped-bug register above is its P4 execution.
- [x] Exit criteria stated. — ✓ contract §5.2 (six criteria) — each re-derived above: 100% LLRs verified, every story ≥1 passing AT, dual traceability, the C-17 hostile ATs + `from_markup` census, the gate-keyed thresholds pre-executed (the four P1 probes), 0 new snapshot failures (3 passed + 29 xfailed, per-cell census).
- [x] No real PII / secrets. — ✓ the evidence home carries fixtures + transcripts only; the UX section names no person (the operator is named by role).
- [x] **Mode declared** at the top of the artifact — `plan` or `validation`. — ✓ `**Mode**:** validation`.
- [x] **Plan mode:** results are declared `planned`, not silently blank. **Validation mode:** every case carries a result or one of the seven states, and each executed result NAMES its executor. — ✓ every row is pass/fail with its transcript; executors named (`ORCH-P3` / `IMPL-P3` / the orchestrator `C-25` for the ONE gate run).
- [x] **Layer B (black-box):** every output-producing story's deliverable is observed through the SHIPPED surface … with boundary + negative evidence. — ✓ the Layer B table — 24/24; the deliverables observed in emitted form (files on disk, `render().plain` pastes, report bytes).
- [x] **Bidirectional surface-reachability:** every named input dimension AND every named output/deliverable is exercised/observed through the handler. — ✓ the matrix above — 11 input + 9 output rows, 0 gaps.
- [x] **No unfilled template:** no remaining placeholders that name nothing. — ✓ no `<...>` placeholder stands; the only deferred items are the named notes N-1…N-6 with owners (no `⏸ DEFER` block is carried).

### Gate checklist — phase-4 station (`00-checklists.md` §7 VALIDATION)

| # | Item | ✓/⚠/✗ | Evidence |
|---|------|---------|----------|
| 1 | **ONE complete run**, launched by the orchestrator — never stitched | ✓ | the definitive run `evidence/p4_gate_suite_run3.txt` (3 040 passed / 5 failed in 0:58:06, tree `c18d181` on `origin/main 121feaa`, command + env at the keyed `Gate run` field); runs ONE/TWO are the reconciled pre-fix / intermediate predecessors, same command, same executor |
| 2 | Layer 0 unit · layer A white-box · layer B black-box | ✓ | Layer 0 declared + mutation-measured (65/65 battery node-runs RED) · Layer A 31/31 ids · Layer B 24/24 ids |
| 3 | UX walkthrough with the **real mechanism** and the **painted** result | ✓ | trigger D1 fired; the section above drives the shipped surfaces with the Textual pilot and asserts `render().plain` (no proxy interaction) |
| 4 | Representative + **boundary** + **negative** | ✓ | every TC/AT row names its boundary + negative arms (the battery arms + the AT arms; the worked RED sides cited) |
| 5 | The deliverable actually **observed** | ✓ | the emitted-form assertions (C-42): the `.chk.json` bytes, the `## Checks` addendum, the flow template, the A2B report provenance lines, the chain-set envelope + report, the painted chrome census |
| 6 | Bidirectional surface-reachability matrix | ✓ | the matrix above — 0 gaps |
| 7 | **A NEGATIVE result names the over-breadth that makes it sound, and that over-breadth is guarded** (C-55 limb 1) | ✓ | each packet's *Load-bearing emptiness* table names the search that made the absence wide enough, per absence |
| 8 | **Every probe that returned an absence carries its POSITIVE CONTROL** | ✓ | per the packets' C-55 tables — the known-present twins named per arm (the struck-APPLY ghost renders, the app-level variant machinery, the accepted (flow,file) wiring, the clean chain's `written_paths`, `FROBNICATE` still warns, the 29 known-present snapshot marks) |
| 9 | Verdict `PASS` / `PASS-WITH-NOTES` / `FAIL` declared as the keyed `**Result:**` field, ONE token | ✓ | `PASS-WITH-NOTES` |
| 10 | **Evaluation with users (ISO 9241-210): the STATE, keyed to what happened** — per act | ✓ | the three states in the UX walkthrough section: automated walkthrough performed · expert inspection performed · evaluation with users `not performed` (reason named) |
| 11 | `**Layer 0:**` and `**Evidence checklist (qa-reviewer):**` declared as keyed fields, the checklist naming WHO | ✓ | both keyed fields at the verdict; the checklist names `qa-reviewer`, 12 of 12 ✓ |
