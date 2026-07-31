# Validation — s19_app — Batch 2026-07-31-batch-74

**`R-TUI-101`** · Lane A · 2026-07-31

> ⚠️ **This artifact was written LATE, at the `/dev-flow-sync` gate, and that is itself a finding.**
> Phase 4 ran — the gate suite executed twice, the counterfactual ledger was built, both engine guards
> were checked — but **no `04-validation.md` was produced**, and neither was `06-docs/`. Every prior
> batch in this project ships both. The evidence below is not reconstructed: it is transcribed from
> runs recorded in `state.json`, `03-increments/increment-002.md` and `06-closeout.md` at the time they
> happened. **What was missing was the artifact, not the validation** — but a phase whose record is
> assembled after the merge is a phase nobody could have gated on. Carried as a process defect in §7.

## ✅ Verdict (read first)

**PASS.**

| Axis | Result |
|---|---|
| Gate suite | `pytest -q` **full, `slow` included** — **2436 passed, 2 skipped, 3 xfailed**, 29 snapshots, 30m38s |
| CI, blocking job | `tui-ci` **pass** on the merged head (37m30s) and **pass post-merge on `main`** (28m15s, full suite) |
| CI, advisory job | `snapshot` **pass** (1m50s) — the ONLY job that exercises the 29 snapshot cells |
| Goldens re-baselined | **0** |
| Frozen-engine diff | **0**, both guards |
| Test ledger | `post = base − D + A` → **2441 = 2408 − 0 + 33** |
| LLR coverage | **11 / 11 = 100 %** |
| Counterfactuals | **17 executed**, 16 red-on-target + 1 green-by-design |

## 1. The gate run of record (C-19, C-25)

**Orchestrator-run, never delegated.** The Phase-4 suite exceeds the tool cap and a sub-agent that
launches it exits before it finishes.

| Run | Scope | Result |
|---|---|---|
| Phase-4 gate | `pytest -q` (full, incl. `slow`) | 2434 passed / 2 skipped / 3 xfailed / 29 snapshots · 25m08s |
| Post-discharge re-run | `pytest -q` (full, incl. `slow`) | **2436 passed** / 2 skipped / 3 xfailed / 29 snapshots · 30m38s |
| CI blocking (`tui-ci`, ubuntu/py3.11) | `-m "not slow"` on the PR | **pass**, 37m30s |
| CI post-merge on `main` | **full suite incl. `slow`** | **pass**, 28m15s |

> ⚠️ **Citing "CI green" without this sentence would be false.** The blocking `tui-ci` job installs
> plain `pytest` and never the `[dev]` extra, so its **29 snapshot cells are SKIPPED there**; only the
> advisory `continue-on-error` job exercises them, and it cannot fail the workflow. `tui-ci` also runs
> `ubuntu-latest`, structurally blind to newline-keyed defects.

**Cross-host result, which mattered here.** The three residency gates are ratios against a `≤ 1.15`
threshold and had only ever run on Windows/py3.14. `tui-ci` passed on **both** heads on
ubuntu/py3.11 — the post-discharge run being the first to exercise `AT-241b` off-host. A correct
implementation renders byte-identical work in both measurement windows, so the ratio is **1.000 by
construction rather than by calibration**; that is why the gate is host-invariant, and it is now
executed rather than argued.

## 2. Layer A — white-box nodes reconciled to real tests

| TC | Requirement | Node |
|---|---|---|
| TC-540 | LLR-105.1 | `test_tc540_cap_arms` (parametrised `{CAP−1, CAP, CAP+1}`) |
| TC-541 | LLR-105.3 | `test_tc541_byte_cell_width_arms` |
| TC-542 | LLR-105.4′ | `test_tc542_count_correctness_under_a_filter` |
| TC-543 | LLR-105.5 | `test_tc543_notice_names_the_constant_its_value_and_the_total` |
| TC-544 | LLR-105.6 | `test_tc544_no_bare_cap_literal_in_the_producers_or_in_this_file` |
| TC-545 / TC-545b | oracle discrimination | `test_tc545_…` / `test_tc545b_…` |
| TC-546 / **TC-546b** | LLR-105.2 | `test_tc546_cap_is_summed_over_three_check_files` / `test_tc546b_the_checklist_residency_oracle_discriminates` |
| TC-547 / TC-547b | LLR-105.2 | `test_tc547_saturated_file_omits_the_table_header` (×2 arms) / `test_tc547b_…` |
| TC-548 | LLR-106.1 | `test_tc548_the_address_residency_oracle_discriminates` |
| TC-549 / TC-549b | LLR-106.2 | `test_tc549_elided_count_comes_from_the_value_not_the_raw_string` / `test_tc549b_…` |
| TC-550 | LLR-106.3 | `test_tc550_address_chars_equals_its_own_derivation` |
| TC-551 | LLR-106.4 | `test_tc551_the_address_cue_is_inert_in_markdown` |

## 3. The counterfactual ledger — 17 mutations

All on **copies of the FIXED tree**, never `main`, never a tree another session reads. Every mutation
carries an **apply-check** (anchor present · content changed · hash changed) and a **restore-check**
(hash equals pristine). Baseline and post-restore green in every harness.

| # | Mutation | Result |
|---|---|---|
| M1 | cap per check file instead of per variant | RED |
| M2 | emit the table header even when saturated | RED |
| M3 | notice states the pre-filter population | RED |
| M4 | **the forgery** — truncate without changing the form | RED |
| M5 | state a wrong elided count | RED |
| M6 | **format-then-slice the address** | RED (residency) |
| M7 | `REPORT_ADDRESS_CHARS` derived bottom-up | RED |
| M8 | cue spelled `...` instead of `…` | RED |
| M9 | width bound dropped on the capped path | RED |
| M10 | count perturbed, cue LENGTH held constant | RED |
| **M6b** | **AT-246 under format-then-slice** | **GREEN — by design** |
| F1/M1′ | checklist Address reverted to shipped rendering | RED |
| F2a/M2′ | render the TRAILING kept digits | RED |
| F2b/M9′ | floor division instead of the ceiling | RED |
| F3/M4′ | saturation guard ignores `file_kept` | RED |
| F4/M8′ | drop the sign on a negative address | RED |
| **H-1/M-A** | **full-population-then-slice in `_checklist_lines`** | RED at ratio **9.087** |

**M6b is the load-bearing row.** It is green *on purpose*: under format-then-slice, AT-246's three
conjuncts — width, form, elided count — are **all satisfied**, because they constrain only the emitted
token and the emitted token is byte-identical. That is the executed proof that the residency oracles
are not redundant.

### 3.1 Where this ledger is weaker than it looks

Ten of these seventeen were authored by **reviewers, not by me**, after my own C-40 pass declared the
increment clean. The ledger's completeness is therefore a property of the review process, not of the
author's imagination. Stated plainly because the opposite reading — "seventeen mutations, thorough
batch" — is the one a later reader will reach for.

## 4. Layer B — black-box acceptance through `generate_project_report`

| AT | Story | Observed on the written report |
|---|---|---|
| AT-240 | 1 | `E = CAP+1` → exactly `CAP` rows + one notice |
| AT-241 / **AT-241b** | 1 | cap summed across check files / **checklist residency independent of `E`** |
| AT-242 / AT-242b | 1 | byte-cell width + cue / **width residency independent of `L`** |
| AT-243 | 1 | `Expected`/`Actual` bounded, and the bound survives the cardinality cap |
| AT-244 | 1 | notice counts **kept**, not population |
| AT-245 | 1 | per-file drop counts + saturated file renders no empty table |
| AT-246 | 2 | 100 000-digit address: bounded, **fails** `^-?0x[0-9A-F]+$`, correct elided count, **at both producers** |
| AT-247 | 1+2 | **positive control** — byte-identical to the Inc-0 golden |
| AT-248 | 1 | modifications residency independent of `E` |
| AT-249 | 2 | **Address residency independent of the digit count** |

**C-12 ordering verified by the commit graph, not by prose.** The Inc-0 golden was added at
`07:59:46` in a commit touching only `tests/goldens/batch74/`; the first `report_service.py` commit is
`08:40:07`. The golden cannot have been captured from the rewritten producer.

## 5. Signed-balance test ledger

```
post = base − D + A
2441 = 2408 −  0 + 33
```

`A = 33` is the whole of `tests/test_report_producer_bound.py`. `D = 0` — **nothing was deleted, and
nothing was edited into passing.** `tests/test_report_field_census.py::test_f17` was amended by
**widening** its closed alphabet to `HEX ∪ {" "} ∪ CUE_ALPHABET` and keeping an in-cap arm on the
original narrow alphabet; its node count is unchanged (34 before and after), which is the mechanical
evidence that the amendment did not remove coverage.

## 6. Premise re-check at the validation gate (C-43)

The seven falsified premises (`01-requirements.md` §2.7) all held falsified at this gate. **Four were
written by this batch itself**, not inherited. No premise flipped back.

**One new premise was falsified AT this gate**, by the sync procedure that produced this file:
*"batch-74 produced the artifact set the flow expects."* **FALSE** — see §7.

## 7. Gaps / residual risk

| # | Gap |
|---|---|
| **V-1** | **This artifact and `06-docs/` were not produced at their phases.** Phase 4 and Phase 6 ran and their evidence is real, but the records were assembled at the sync gate, after the merge. A phase whose artifact does not exist at its own gate cannot be gated on — the orchestrator self-approved Phase 4 against runs it had in conversation, not against a document. **The `/dev-flow-sync` template-completeness detect is what caught it**, doing exactly the job it was written for. Carried to `BACKLOG-PROCESS.md`. |
| V-2 | `REPORT_ADDRESS_HEX_DIGITS` has **no in-domain exercise** — every real address is 8 digits. Correctness rests on the executed golden census and on AT-247. |
| V-3 | The `services → changes.io` import is new coupling. |
| V-4 | **`R-TUI-101` is a deliberately bounded claim** — seven non-claims. The document is still not byte-bounded; `V` and `F` are uncapped; `_applied_regions` is unbounded. All chartered to batch-75 with their measurements. |

## Evidence checklist

| # | Item | ✓ | Evidence |
|---|---|---|---|
| 1 | Gate suite run by the orchestrator | ✓ | 2436 passed / 2 skipped / 3 xfailed, 30m38s, full incl. `slow` |
| 2 | CI verdict recorded with its blind spots named | ✓ | `tui-ci` pass ×2 + post-merge on `main`; snapshot-skip caveat stated in §1 |
| 3 | Every AT and TC reconciled to a real node | ✓ | §2 and §4; 33 collected in the batch file |
| 4 | Every gate number executed, not predicted (C-39) | ✓ | §1, §3, §5 — all transcribed from runs |
| 5 | Counterfactual per predicate, red on its OWN assertion (C-40) | ✓ | §3, 17 mutations, apply- and restore-checked |
| 6 | Signed test ledger balances | ✓ | §5, `2441 = 2408 − 0 + 33` |
| 7 | Goldens / frozen engine unchanged | ✓ | 0 and 0, both guards |
| 8 | Residuals stated with their numbers | ✓ | §7 + `BACKLOG-CODE.md` batch-75 charter |
| 9 | Premises re-checked at this gate | ✓ | §6 — and one NEW premise falsified here |
