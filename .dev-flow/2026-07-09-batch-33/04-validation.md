# 04 — Validation · batch-33 · check-result reasons + per-entry taint

**BLUF.** Both layers GREEN. Full suite (gate run): **1234 passed / 1 failed → the single failure is
the anticipated patch-120x30 snapshot drift from the extended help label, now `xfail(strict=False)`
pending canonical-CI regen (standing pattern); post-mark snapshot suite 33 passed + 1 xfailed.**
Engine-frozen guards green inside the run; 0 frozen diffs. All **12 §3 ATs reconcile to exactly ONE
distinct on-disk node** (C-18 table below, incl. two designation notes). RED counterfactual evidence
captured per increment (4 stash captures); one censused pin superseded in place, plus the review-F1
resurrection of the old gate test under the new semantics.

## Layer B — C-18 reconciliation: AT → single node

| AT | Single on-disk node | Notes / counterfactual |
|----|---------------------|------------------------|
| AT-050a | `test_at050a_pilot_mixed_results_via_real_button` (tests/test_tui_patch_editor_v2.py — the REAL Run-checks button, per the US-050 Layer-B fold) | Engine twin `test_at050a_collision_pair_tainted_healthy_entries_checked` is DESIGNATED its white-box TC partner (TC-050.3), not a second AT node. RED: Inc-3 stash (5 failed) + Inc-2 stash (8 failed) |
| AT-050b | `test_at050b_skipped_declarations_taint_nothing` (B-1 same-address pin + CHG-DECL-STRUCTURE) | Inc-2 stash RED |
| AT-050c | `test_at050c_clean_document_negative_control` | Declared negative — passes pre- and post-change; exact aggregates asserted |
| AT-050d | `test_at050d_apply_gate_untouched` | Declared regression guard (apply gate blocks everything, map untouched) |
| AT-051a | `test_at051a_containment_reasons_visible_in_rows` | Inc-3 stash RED (rows ended at the bare token) |
| AT-051b | `test_at051b_doc_kind_loud_status_capped_log_and_not_ok` (full reason on the untruncated status label; prefix-only on ≤50-char log lines; ok=False at the ChangeActionResult return — m-3) | Engine twin `test_at051b_engine_half_doc_kind_run_block` designated its TC partner. Inc-3 stash RED |
| AT-051c | `test_at051c_composed_faulted_envelope_blocks_with_doc_fault` (tests/test_change_service.py — pasted CHG-VALUE-MODE-UNKNOWN envelope + composed BYTES entries per m-1) | R-B02-6 smoke satisfied by the node itself |
| AT-051d | `test_at050c_clean_document_negative_control` (reason_code None on every pass/fail row — one node owns the whole claim; display half re-asserted inside the AT-050a pilot) | Declared boundary-negative |
| AT-051e | `test_at051e_hostile_kind_renders_literal_on_all_surfaces` (three surfaces; token sized to BISECT at the 50-char log cap; rows structurally hostile-free) | render() completion = no-MarkupError verdict |
| AT-051f | `test_at051f_to_dict_additive_through_real_runs` (blocked + runnable; no-consumer state stated) | Inc-4 |
| AT-052a | `test_at052a_checks_help_states_semantics` (three distinct token spans; AT-032a pin untouched) | Inc-4 stash RED (1 failed) |
| AT-052b | `test_at052b_checks_help_survives_screen_cycle` | Wiring regression |

**No AT in parts; no AT without a node; no orphan node** (TC-201-numbering not used this batch — the
TC family is TC-050.1/.2/.3, TC-051.1/.4/.5, and the engine twins; every TC maps to an LLR).

## Layer A — TC ↔ LLR (all GREEN on disk)

| LLR | Nodes |
|---|---|
| 050.1/.2 (two-set gate + attribution) | TC-050.1 (`test_tc050_1_envelope_and_unknown_codes_block` — fail-safe + {0,0,0} boundary), TC-050.2 (`test_tc050_2_taint_boundaries` — address-less + 0x0 falsy), TC-050.3 (engine collision twin), review-F1 resurrection (`test_collision_pair_uncheckable_and_wrong_kind_blocked`) |
| 050.3/.4 (headless / frozen) | existing `test_no_textual_in_static_import_graph` + `test_engine_unchanged` guards (cited, green in the gate run) |
| 051.1/.2 (vocabulary + carriage) | TC-051.1 (`test_tc051_1_reason_vocabulary_and_model_defaults`) |
| 051.3 (template caps) | `test_llr051_3_reason_template_caps` (64-char kind cap; dedup/cap-5/+N more) |
| 051.4/.5 (status/rows) | AT-051b + AT-050a-pilot nodes (+ `check_rows` suffix asserted in both pilots) |
| 051.6/.8 (markup surfaces + funnel scrub) | AT-051e + TC-051.4 (`test_tc051_4_hostile_encoding_sibling_through_load_funnel` — the five-message-class closure on a sibling) |
| 051.7 (log routing) | AT-051b log assertions |
| 052.1/.2 (help) | AT-052a/b |
| TC-051.5 (blocked-run aggregates/report) | `test_tc051_5_blocked_runs_render_checklists` (exact aggregates-line pins — a vacuous draft assertion was caught at authoring and replaced) |

## Bidirectional surface matrix
Inputs: file load (Pilot load_doc), paste (`load_text`), composed entries (`add_entry`), hostile
kind/encoding — all exercised through shipped seams. Outputs: rows, status label, log labels, help
label, `to_dict`, report Checklists — all observed. The apply path re-verified untouched (AT-050d).

## Supersessions (census fully dispositioned)
1. `:406` pinned literal → rewritten-in-place (`Checks: not run` prefix; full reason moved to AT-051b per P1). 2. The apply-gate-mirror engine test → superseded in place at review-F1
(`test_collision_pair_uncheckable_and_wrong_kind_blocked`, same fixtures, new-semantics pins).
3. File-header comment updated. No other consumer moved (aggregates/report/variant re-verified green).

## Full-suite evidence
Gate run: **1234 passed, 2 skipped, 3 xfailed (pre-existing), 21 deselected, 1 failed→xfail'd
(snapshot drift)**; post-mark snapshot suite 33+1. Ledger: touched files 7→17 engine · 21→22 service ·
28→35 patch-editor · 33→34 report (+1 rewrite-in-place, +0 deletions besides the in-place
supersessions); suite total 1241 → 1263 collected.

## Gaps
None open. Deferred by design: Q2 report Reason column (reasons ride `to_dict`, zero consumers —
stated); O-2 filename-markup hygiene on `#status_text`/notify (future candidate, out of scope).
