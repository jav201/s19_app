# Traceability Matrix — batch-33 · check-result reasons + per-entry taint

**Audience:** engineers and reviewers auditing batch-33 (B-02). **Purpose:** prove both traceability
chains (US → HLR → LLR → TC and AT → single on-disk test node) and record the requirement
amendments, operator decisions, adopted defaults, and supersession dispositions.

Totals: **3 US · 3 HLR · 15 LLRs · 12 ATs · 9 TCs.** Every test node name below was grep-verified
against `tests/` on 2026-07-09 (file:line cited per node). Gate run: 1234 passed / 1 anticipated
snapshot drift (xfail'd); 0 engine-frozen diffs.

## 1. Chain A — US → HLR → LLR → TC

| US | HLR | LLRs | White-box TCs |
|----|-----|------|---------------|
| US-050 per-entry taint | HLR-050 (per-entry check gate; amends R-CHK-001 via §6.5) | LLR-050.1 (two-set split: non-blocking vs taint-attribution), LLR-050.2 (gate rewrite in `run_check_document`), LLR-050.3 (purity preserved), LLR-050.4 (0 engine-frozen diff) | TC-050.1, TC-050.2, TC-050.3 |
| US-051 reasons everywhere | HLR-051 (reason carrier + display, markup-safe end to end) | LLR-051.1 (model fields + domain), LLR-051.2 (`to_dict` additive), LLR-051.3 (template text + F2 bounds), LLR-051.4 (blocked-run status message + `ok=False`), LLR-051.5 (row reason suffix), LLR-051.6 (three-surface markup census), LLR-051.7 (reason reaches `ChangeActionResult`), LLR-051.8 (log-funnel scrub — added in-batch, QA P2) | TC-051.1, TC-051.2, TC-051.3, TC-051.4, TC-051.5 |
| US-052 checks info affordance | HLR-052 (help text extension; amends R-PATCH-CHECKS-CLARITY-001 via §6.5) | LLR-052.1 (Option A: extend `#patch_checks_help`), LLR-052.2 (AT-032a token span preserved), LLR-052.3 (80×24 fit — analysis) | TC-052.1 |

### LLR → on-disk node (Layer A, per 04-validation.md, names verified)

| LLR | Verified nodes |
|-----|----------------|
| 050.1 / 050.2 | `test_tc050_1_envelope_and_unknown_codes_block` (tests/test_checks_engine.py:669 — fail-safe + `{0,0,0}` boundary), `test_tc050_2_taint_boundaries` (tests/test_checks_engine.py:718 — address-less + `0x0` falsy + B-1 same-address pin), `test_at050a_collision_pair_tainted_healthy_entries_checked` (tests/test_checks_engine.py:531 — TC-050.3 engine collision twin), review-F1 resurrection `test_collision_pair_uncheckable_and_wrong_kind_blocked` (tests/test_checks_engine.py:202) |
| 050.3 / 050.4 | existing guards, green in the gate run: `test_no_textual_in_static_import_graph` (tests/test_checks_engine.py:410) + the `tests/test_engine_unchanged.py` frozen-set suite |
| 051.1 / 051.2 | `test_tc051_1_reason_vocabulary_and_model_defaults` (tests/test_checks_engine.py:459) |
| 051.3 | `test_llr051_3_reason_template_caps` (tests/test_checks_engine.py:775 — 64-char kind cap; dedup/cap-5/`+N more`) |
| 051.4 / 051.5 | `test_at051b_doc_kind_loud_status_capped_log_and_not_ok` (tests/test_tui_patch_editor_v2.py:2020) + `test_at050a_pilot_mixed_results_via_real_button` (tests/test_tui_patch_editor_v2.py:1923); `check_rows` reason suffix asserted in both pilots |
| 051.6 / 051.8 | `test_at051e_hostile_kind_renders_literal_on_all_surfaces` (tests/test_tui_patch_editor_v2.py:2076) + TC-051.4 = `test_tc051_4_hostile_encoding_sibling_through_load_funnel` (tests/test_tui_patch_editor_v2.py:2194 — five-message-class closure proved on a sibling token) |
| 051.7 | log/return assertions inside `test_at051b_doc_kind_loud_status_capped_log_and_not_ok` |
| 052.1 / 052.2 | `test_at052a_checks_help_states_semantics` (tests/test_tui_patch_editor_v2.py:2148) + `test_at052b_checks_help_survives_screen_cycle` (tests/test_tui_patch_editor_v2.py:2170) |
| TC-051.5 (blocked-run aggregates + report) | `test_tc051_5_blocked_runs_render_checklists` (tests/test_report_service.py:1226 — exact aggregates-line pins; a vacuous draft assertion was caught at authoring and replaced) |

## 2. Chain B — 12 ATs → exactly one on-disk node (C-18 reconciliation)

Copied faithfully from 04-validation.md; every node name grep-verified.

| AT | Single on-disk node (verified file:line) | Notes / counterfactual |
|----|------------------------------------------|------------------------|
| AT-050a | `test_at050a_pilot_mixed_results_via_real_button` — tests/test_tui_patch_editor_v2.py:1923 (the REAL Run-checks button, per the US-050 Layer-B fold) | **Designation note 1:** engine twin `test_at050a_collision_pair_tainted_healthy_entries_checked` (tests/test_checks_engine.py:531) is DESIGNATED its white-box TC partner (TC-050.3), not a second AT node. RED: Inc-3 stash (5 failed) + Inc-2 stash (8 failed) |
| AT-050b | `test_at050b_skipped_declarations_taint_nothing` — tests/test_checks_engine.py:575 (B-1 same-address pin + `CHG-DECL-STRUCTURE`) | Inc-2 stash RED |
| AT-050c | `test_at050c_clean_document_negative_control` — tests/test_checks_engine.py:610 | Declared negative — passes pre- and post-change; exact aggregates asserted |
| AT-050d | `test_at050d_apply_gate_untouched` — tests/test_checks_engine.py:643 | Declared regression guard (apply gate blocks everything, map untouched) |
| AT-051a | `test_at051a_containment_reasons_visible_in_rows` — tests/test_tui_patch_editor_v2.py:1979 | Inc-3 stash RED (rows ended at the bare token) |
| AT-051b | `test_at051b_doc_kind_loud_status_capped_log_and_not_ok` — tests/test_tui_patch_editor_v2.py:2020 (full reason on the untruncated status label; prefix-only on ≤50-char log lines; `ok=False` at the `ChangeActionResult` return — m-3) | **Designation note 2:** engine twin `test_at051b_engine_half_doc_kind_run_block` (tests/test_checks_engine.py:749) designated its TC partner, not a second AT node. Inc-3 stash RED |
| AT-051c | `test_at051c_composed_faulted_envelope_blocks_with_doc_fault` — tests/test_change_service.py:612 (pasted `CHG-VALUE-MODE-UNKNOWN` envelope + composed BYTES entries per m-1) | R-B02-6 composed-path smoke satisfied by the node itself |
| AT-051d | `test_at050c_clean_document_negative_control` — tests/test_checks_engine.py:610 (`reason_code` None on every pass/fail row — one node owns the whole claim; display half re-asserted inside the AT-050a pilot) | Declared boundary-negative |
| AT-051e | `test_at051e_hostile_kind_renders_literal_on_all_surfaces` — tests/test_tui_patch_editor_v2.py:2076 (three surfaces; token sized to BISECT at the 50-char log cap; rows structurally hostile-free) | `render()` completion = no-MarkupError verdict |
| AT-051f | `test_at051f_to_dict_additive_through_real_runs` — tests/test_checks_engine.py:816 (blocked + runnable; no-consumer state stated) | Inc-4 |
| AT-052a | `test_at052a_checks_help_states_semantics` — tests/test_tui_patch_editor_v2.py:2148 (three distinct token spans; AT-032a pin untouched) | Inc-4 stash RED (1 failed) |
| AT-052b | `test_at052b_checks_help_survives_screen_cycle` — tests/test_tui_patch_editor_v2.py:2170 | Wiring regression |

No AT in parts; no AT without a node; no orphan node.

## 3. §6.5 requirement amendments (Before/After)

### R-CHK-001 (REQUIREMENTS.md:1631) — apply-gate mirror RETIRED for checks

- **Before:** "uncheckable covering any entry whose target range is not fully readable" under a
  whole-document not-runnable gate mirroring the apply gate — any document ERROR or wrong `kind`
  made EVERY entry uncheckable, reason-less (`check.py:166` collective taint).
- **After:** per-entry gate. Only document-blocking faults and wrong kind block the run (each with a
  run-level reason); entry-attributable ERRORs taint only their entry; containment uncheckables
  carry reasons; `CheckRunEntry`/`CheckRunResult` carry `reason_code`/`reason`/run-block fields.
- **Rationale:** operator decision B-02-1/2/3 — checks are read-only, so the conservative
  apply-mirror gate hid information without protecting anything. The apply gate (HLR-001 statement
  4 / LLR-002.1) is explicitly NOT amended — apply mutates, so its whole-document gate stays
  (guarded by AT-050d). Companion new row **R-CHK-002** (REQUIREMENTS.md:1672) records the
  self-explaining-uncheckable requirement with full dual trace.

### R-PATCH-CHECKS-CLARITY-001 (REQUIREMENTS.md:3234)

- **Before:** the `#patch_checks_help` label shall read exactly
  `"Checks: runs the loaded change document's checks against the loaded image."`.
- **After:** the label shall contain that sentence verbatim as its first line (AT-032a token span
  preserved, LLR-052.2) plus the kind-requirement and uncheckable-rows-carry-reasons lines.
- **Rationale:** operator decision B-02-4 (info affordance so the topic stops recurring).

## 4. Operator decision record

Source: baseline backlog 2026-07-09, item B-02, operator round-3 decision (recorded at Phase-0,
baked into 01-requirements.md; PLAN.md decision log mirror):

1. **Per-entry taint replaces collective taint** — healthy entries in an error-carrying check
   document are checked normally; only entries that themselves carry an error are uncheckable.
2. **Wrong document kind stays a whole-run block**, but with one loud, specific run-level reason
   (evaluated FIRST, before the blocking-fault check).
3. **Every uncheckable entry carries its reason** (machine-stable code + human sentence).
4. **An info affordance explains check semantics** on the checks surface.

In-batch operator-visible decision: the log-label funnel scrub (LLR-051.8) was fixed **in-batch**
rather than spawned as a separate task (same seam, same hostile AT, one line; overridable at the
gate — not overridden).

## 5. Adopted draft defaults (operator-overridable at the Phase-2 gate; neither overridden)

| Q | Default adopted | Consequence |
|---|-----------------|-------------|
| Q1 — collision taint for checks | **Taint the pair** (conservative): a `CHG-COLLISION` pair taints BOTH partners (`entry-fault`), consistent with the entries-table `" / fault"` marker | `CHG-COLLISION` is the sole member of the taint-attribution set; flipping Q1 later empties the set and forces an AT-050a fixture redesign (interplay recorded at LLR-050.1/§8 Q1) |
| Q2 — report Reason column | **Defer**: the project report's `### Checklists` table keeps its shape; reasons already travel in `to_dict` (zero production consumers today — stated, not faked, in AT-051f) | A later report-focused batch can surface the column with zero engine change; TC-051.5 pins that blocked-run results still render through the report |

## 6. Supersession dispositions (3 — census fully dispositioned)

| # | Superseded item | Disposition |
|---|-----------------|-------------|
| 1 | `tests/test_tui_patch_editor_v2.py:406` pinned literal `"Checks: 0 passed, 0 failed, 2 uncheckable"` on a kind=change run | Rewritten in place to the `Checks: not run` prefix; the full-reason assertion moved to AT-051b (per QA P1 status-vs-log split) — Inc-3 |
| 2 | Pre-batch-33 apply-gate-mirror engine test (census rows 1–2; docstring had become false, passing only because its fixture happened to be a collision pair) | Superseded in place at review-F1 → `test_collision_pair_uncheckable_and_wrong_kind_blocked` (tests/test_checks_engine.py:202), same fixtures, new-semantics pins |
| 3 | `check.py` file-header comment (D-3 "apply-gate mirror" decision text) | Updated to the per-entry-gate decision (Inc-2 docstring rewrite) |

All other censused consumers (aggregates/report/variant, `startswith("Checks:")` pin at :1858)
SURVIVED unmodified and were re-verified green.

## 7. Phase-3 realization notes (fold addendum — recorded, not semantic changes)

- LLR-051.5 realized as the ` ({reason})` row suffix, not the drafted ` — {reason}`.
- Blocked-run rows carry the BOUNDED short pointer `run blocked [{code}]`; the full run-level reason
  lives only on `CheckRunResult` / the status label (F2 no-multiplication).

---

*Assumptions:* line numbers cited are as of the batch-33 worktree at doc time (2026-07-09).
*Next steps:* Q2 report Reason column (deferred, groundwork shipped); canonical-CI snapshot regen
for the xfail'd patch-120x30 cell; postmortem proposals P-1..P-4.
