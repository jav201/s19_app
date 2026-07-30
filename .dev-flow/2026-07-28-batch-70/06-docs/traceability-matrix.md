# batch-70 — traceability matrix

**Audience:** engineers and reviewers auditing coverage of `R-TUI-099`.
**Purpose:** show that both traceability chains close, and name what is *not* covered.

**Scope:** FB-P2 — multi-image flow runs + report fusion. The Patch-Editor variant path, FB-P3's CRC
sub-flow, PKI extraction and the engine-frozen set are explicitly **out** and are not covered here.

**Shipped as** `b457ef8` — squash-merge of **PR #159**, parent `f1f3987`, 2026-07-29. ✅ **This is the
only commit an auditor can check out to reproduce this matrix.**

**Development branch** `claude/fb-p2-batch-70-impl-92b3cd` · pre-squash commits `ebca4cc` (Inc-1),
`4573d43` (Inc-2+3), `2b6c3a5` (Inc-4), `35a7a5e` + `c9a9c8a` (close-out).

> ⚠️ Those five commits are **not reachable from `origin/main` and never will be** — PR #159 was
> squash-merged, so they collapse into `b457ef8`. The branch line above is history, not a checkout
> target. Auditing this matrix means checking out `b457ef8`.
>
> ⚠️ The nine **Phase-0** commits reached the PR only because the Phase-0 branch
> `claude/fb-p2-batch-70-bfc118` was fast-forwarded into the implementation branch. They are in
> `b457ef8` too.

**Source of this mapping:** `REQUIREMENTS.md` §`R-TUI-099` (the shipped entry) and
`.dev-flow/2026-07-28-batch-70/04-validation.md` §1–§3. Node ids were collected from the tree with
`pytest --collect-only`, not recalled.

---

## 1. Chain A — behavioural (black-box): `US → AT → observed outcome → node`

**7/7 GREEN.** Every `AT` drives a shipped surface — `run_flow_over_variants`,
`compose_fused_flow_report`, or the real `#flow_run` button through `S19TuiApp`.

| US | AT | binds | observed outcome | collected node |
|---|---|---|---|---|
| US-FBP2-1 | **AT-205** | LLR-104.2 | an injected **counting iterable** is consumed exactly `3` times for 3 variants; a counting executor records `["a","b","c"]`; `len(variant_outcomes) == 3` | `test_flow_multi_image.py::test_at205_v_variants_produce_v_executions` |
| US-FBP2-1 | **AT-206** | LLR-104.2 | with variant `b`'s image absent: statuses `[ok, error, ok]`, roll-up `error`, counts `(2,0,1)` | `…::test_at206_aborting_variant_does_not_stop_the_remaining_ones` |
| US-FBP2-1 | **AT-211** | LLR-104.1 / .7 | a variant resolving outside the project yields `[ok, error, ok]` with `MANIFEST-PATH-ESCAPE` **recorded in the block's diagnostics** | `…::test_at211_containment_rejected_variant_fails_closed_alone` |
| US-FBP2-1 | **AT-210** (a) | LLR-104.1 | an unscoped run still produces today's block summaries verbatim | `…::test_at210_unscoped_run_is_unchanged_by_the_variant_dimension` |
| US-FBP2-2 | **AT-207** (a) | LLR-104.3 | headings are exactly `### a`, `### b`, `### c`; one summary row per variant | `test_flow_report_fusion.py::test_at207_exactly_one_section_per_executed_variant` |
| US-FBP2-2 | **AT-207** (b) | LLR-104.3 | an id `ev\|il\`x` renders escaped **and no unescaped occurrence survives anywhere in the document** | `…::test_at207_variant_id_with_markdown_metacharacters_renders_escaped` |
| US-FBP2-2 | **AT-208** | LLR-104.4 | header reads `FAILED` + `2 ok / 1 issues / 1 error`, and the three sum to the executed count `4` | `…::test_at208_rolled_up_status_is_the_worst_and_counts_sum_to_executed` |
| US-FBP2-2 | **AT-209** (a) | LLR-104.5 | 3 variants each 25 over cap → all 3 sections present · each cut names `findings: 25 omitted (cap 60 per variant)` · **each counting sequence reports `consumed <= 60`** | `…::test_at209_every_variant_survives_and_each_cut_names_its_dropped_count` |
| US-FBP2-2 | **AT-209** (b) | LLR-104.5 | a 20×-over variant does not evict a 1-finding neighbour; the small one carries **no** cut notice | `…::test_at209_one_pathological_variant_does_not_evict_the_others` |
| US-FBP2-2 | **AT-210** (b) | LLR-104.3 | `compose_flow_report` has no variant parameter, no `variant` token in its source, and `FlowReportState` is unchanged | `…::test_at210_single_image_composer_is_untouched_by_the_fused_path` |

**Both stories have ≥ 1 file-observed AT.** US-FBP2-1 → the `test_d4_*` group reads `reports/` on
disk. US-FBP2-2 → `test_tc503b_fused_report_is_written_under_the_shipped_report_name` reads the
written file and matches it against the shipped `REPORT_FILENAME_REGEX`.

## 2. Chain B — functional (white-box): `HLR → LLR → TC → node`

**HLR-104 → 7 LLRs, 7/7 covered.**

| LLR | TC | collected node |
|---|---|---|
| **104.1** the SOURCE binding is a project-**relative** ref | `TC-500`, `TC-506`, `TC-507` | `test_flow_multi_image.py::test_tc500_source_ref_is_overridden_per_variant_not_by_the_block` · `…::test_tc506_unscoped_binding_is_the_identity` · `…::test_tc507_bound_source_ref_rejects_an_out_of_project_variant` |
| **104.2** fused runner + per-variant isolation | `TC-501`, `TC-501b`, `TC-502` | `…::test_tc501_plan_comes_from_the_projects_own_variant_machinery` · `…::test_tc501b_model_containers_are_well_formed` · `…::test_tc502_an_exception_escaping_run_flow_is_isolated_to_its_variant` |
| **104.3** exactly one section per variant | `TC-503`, `TC-503b` | `test_flow_report_fusion.py::test_tc503_state_projection_preserves_order_and_copies_the_counts` · `…::test_tc503b_fused_report_is_written_under_the_shipped_report_name` |
| **104.4** roll-up **and** its inversion | `TC-504`, `TC-504b` | `…::test_tc504_issues_wins_only_when_no_variant_errored` · `…::test_tc504b_all_clean_rolls_up_clean` |
| **104.5** the bound is charged per variant, in the producer | `TC-505`, `TC-505b`, `TC-505c` | `…::test_tc505_ledger_rows_are_capped_and_the_drop_count_is_named` · `…::test_tc505b_a_variant_under_the_cap_carries_no_cut_notice` · `…::test_tc505c_diagnostics_share_the_variant_budget_with_findings` |
| **104.6** the scope is selectable and wired through one call site | 7 nodes | `test_flow_multi_image_ui.py::test_llr1046_*` — options census · default scope · `assignments` narrowing · the real Run button for both the fused and the single-image path · the no-variants error card · the fused repaint |
| **104.7** a containment rejection fails one variant, not the run | `TC-507`, `TC-508` | `…::test_tc507_…` · `test_flow_multi_image.py::test_tc508_the_variant_rejection_code_is_under_the_existing_census` |

**D-4** — not an LLR but a decision with its own owning nodes, because its second clause had no
owning increment until Inc-4: `test_flow_multi_image_ui.py::test_d4_a_fused_run_writes_exactly_one_report_file`
· `…::test_d4_the_deferred_report_block_still_appears_in_each_variants_ledger` ·
`…::test_d4_a_flow_without_a_report_block_writes_no_report` ·
`…::test_d4_an_unscoped_run_still_writes_its_own_report`.

## 3. Falsifiability

`AT-209` is the only node whose criterion could pass vacuously — a composer that formats everything
and truncates at the writer satisfies "every variant present" and "cuts named" while failing D-7
entirely. It was therefore driven **RED on a copy of the fixed tree** with the three `islice` bounds
reverted, and it fails **on its assertion** (`assert 1200 <= 60`), never on an import error. Full
output in `04-validation.md` §2.

The remaining ATs were genuinely RED before their increment: `run_flow_over_variants`,
`FlowContext.variant` and `flow_fused_report_service` did not exist, so those tests failed at import.
**That is recorded as an import-level RED, which is weaker evidence, and it is not claimed as more.**

## 4. What is NOT covered

| Gap | Why it is stated rather than hidden |
|---|---|
| **AC-6 has no byte-golden** | Carried structurally (the single-image composer is a different module and is not edited). A golden captured from `origin/main` would be strictly stronger. Non-claim in `R-TUI-099`; carried P3 in `BACKLOG-CODE.md`. |
| **The `O(V × ~6 lines)` heading overshoot** | Deliberate — per-variant headings are emitted outside the byte gate so no variant can vanish — but no node drives `V` high enough to observe the document exceeding `FLOW_REPORT_MAX_TOTAL_BYTES`. |
| **Per-variant caps bound rows, not bytes** | A single pathological `summary` string is bounded only by `MAX_REPORT_CELL_CHARS` from the reused `md_safe` path. |
| **No `02-review.md`** | This batch ran the **autonomous** route at the operator's ruling; no separate Phase-2 review artifact was produced. Review evidence lives in the increment commit bodies and `05-postmortem.md` §5 (seven self-catches). Stated so the absence is not read as a lost document. |
