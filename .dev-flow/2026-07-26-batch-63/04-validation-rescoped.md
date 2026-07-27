# batch-63 (D3-ONLY) — Phase-4 validation

> **BLUF: the three gates were RED before production changed and are GREEN after; the two pins are
> green on BOTH sides by design and are labelled as pins, not as evidence of the fix.** Scope is D3
> alone — D1 and D2 were returned to the backlog at the Phase-2 re-gate.

**Base:** `claude/batch-63-report-table-caps`, cut from `origin/main` @ `031ca8d`.
**Normative spec:** `01-requirements-rescoped-consolidated.md` revision 4 (D3-ONLY).

---

## 1. The counterfactual, captured before any production edit

Run against the unmodified tree, with only the new test file present:

```
FAILED tests/test_report_document_bytes.py::test_at172_replacing_the_encoder_changes_what_the_project_report_writes
FAILED tests/test_report_document_bytes.py::test_at172b_the_unpatched_report_is_exactly_the_encoder_output
FAILED tests/test_report_document_bytes.py::test_at193_no_accounting_module_writes_in_text_mode
FAILED tests/test_report_document_bytes.py::test_at175_written_report_carries_no_cr_on_a_crlf_host
4 failed, 2 passed in 0.64s
```

The two that passed are `AT-174` / `AT-174b`. **That is the specified behaviour, not a gap:** they
pin `_line_bytes`, which the fix deliberately does not change. Presenting them as evidence that D3
was fixed would be the exact defect this batch exists to punish — three vacuous D3 acceptances were
authored before these survived, one of them by the orchestrator.

## 2. Layer B — black-box acceptance

| AT | node | observes | pre-fix | post-fix |
|---|---|---|---|---|
| `AT-172` | `test_at172_replacing_the_encoder_changes_what_the_project_report_writes` | rebinds the encoder, reads **the file** `generate_project_report` wrote | RED | GREEN |
| `AT-172` | `test_at172b_the_unpatched_report_is_exactly_the_encoder_output` | the written bytes equal `document_bytes` of their own text | RED | GREEN |
| `AT-173` | `test_at173_replacing_the_encoder_changes_what_write_flow_report_writes` | the same seam for `write_flow_report`, patching **`flow_report_service.document_bytes`** | RED | GREEN |
| `AT-173` | `test_at173b_flow_report_bytes_equal_the_encoder_output` | the flow report's bytes are the encoder's output | RED | GREEN |
| `AT-193` | `test_at193_no_accounting_module_writes_in_text_mode` | **structural census** — no module sharing the budget writes in text mode; module set derived by import-graph walk and asserted non-empty | RED **on every platform incl. CI** | GREEN |
| `AT-174` | `test_at174_line_bytes_charges_one_byte_per_line` | **PIN** — the `+1`-per-line charge | green | green |
| `AT-174` | `test_at174b_line_bytes_is_partition_invariant` | **PIN** — partition-invariance across 4 partitions | green | green |
| `AT-175` | `test_at175_written_report_carries_no_cr_on_a_crlf_host` | no `\r` on a CRLF host | RED | GREEN (**skipped on CI**) |

Every AT is exactly ONE on-disk node (C-18). No AT is satisfied "in parts".

## 2b. Traceability: LLR → AT → TC → node (closes PR-gate M-1)

`01b-qa-catalog-rescoped.md` is **superseded**, and its §4 semantics for `TC-467..479` are
**retired** — three of those ids were bound there to different observables than the shipped nodes
carry (catalog `TC-473` = the derived census, `TC-475` = report-writer output). A range reservation
is not a catalog, so the shipped per-id semantics are defined here and nowhere else:

| LLR | AT | TC | on-disk node |
|---|---|---|---|
| LLR-102.1 (one encoder; both writers) | AT-172 | TC-470 | `test_report_document_bytes.py::test_at172_replacing_the_encoder_changes_what_the_project_report_writes` |
| LLR-102.3 (platform-independent size) | AT-172 | TC-471 | `…::test_at172b_the_unpatched_report_is_exactly_the_encoder_output` |
| LLR-102.1 (flow writer on the seam) | AT-173 | TC-472 | `test_flow_report_service.py::test_at173_replacing_the_encoder_changes_what_write_flow_report_writes` |
| LLR-102.3 (flow bytes == encoder output) | AT-173 | TC-475 | `test_flow_report_service.py::test_at173b_flow_report_bytes_equal_the_encoder_output` |
| LLR-102.2 (`+1`/line unchanged) | AT-174 **(PIN)** | TC-473 | `…::test_at174_line_bytes_charges_one_byte_per_line` |
| LLR-102.2 (partition invariance) | AT-174 **(PIN)** | TC-474 | `…::test_at174b_line_bytes_is_partition_invariant` |
| LLR-102.1 (no text-mode writer shares the budget) | AT-193 | TC-476 | `…::test_at193_no_accounting_module_writes_in_text_mode` |
| LLR-102.1 (the census detector can fire) | AT-193 | TC-477 | `…::test_at193b_the_text_mode_detector_can_actually_fire` |
| LLR-102.3 (Windows behaviour) | AT-175 | TC-478 | `…::test_at175_written_report_carries_no_cr_on_a_crlf_host` |
| LLR-102.4 (golden neutrality) | — | TC-479 | the 29 snapshot cells + the 6-file derived observer set (§6) |

Recorded plainly: **this is the batch's own OB-2 defect recurring inside the batch** — shipped ids
whose semantics lived only in a superseded artifact. It is a documentation repair, not a code
defect; every LLR already had an executed, mutation-killed verifier.

## 2c. OB-SEC-1 discharged (closes PR-gate m-2)

The Phase-2 security review obliged Phase 3 to paste the cross-module edit's numstat as evidence:

```
$ git diff --numstat origin/main -- s19_app/tui/services/flow_report_service.py
2	1	s19_app/tui/services/flow_report_service.py
```

Two insertions, one deletion — exactly the import line plus the writer swap, and nothing else in the
module batch-62 restored byte-for-byte.

## 3. What CI can and cannot verify — stated, not papered over

`tui-ci.yml:25,:61` and `snapshot-regen.yml:23` all run `ubuntu-latest`. There, the **unpatched**
writer already emits LF, so D3's undercount is **zero** and the pre-/post-fix writers are
byte-identical. Consequences, both accepted deliberately:

- `AT-175` is `skipif os.linesep == LF` — it can only fail on Windows, and it is labelled
  *supplementary, not verified by the merge gate*.
- The load-bearing merge-gate check is **`AT-193`**, which is RED pre-fix everywhere because it
  asserts a *structural* property (`write_text` absent from the accounting-sharing module set) rather
  than a behavioural one.

So CI verifies this requirement's **structure** and **arithmetic**; the platform-dependent
**behaviour** is verified on the operator's host, with the RED transcript in §1. Saying so is a
requirement of this batch, not a nicety.

## 4. Non-vacuity of the census (C-31)

`AT-193`'s input set is produced by `_accounting_modules()`, which AST-parses every module in
`s19_app/tui/services/` and selects those binding `_ByteBudget` or `_line_bytes` from
`report_service`, plus `report_service` itself. A hand-listed census survives every code mutation
while omitting the member that would fail it, so the test additionally asserts the set is
**non-empty and contains both expected members** — an empty or truncated derivation would otherwise
pass trivially.

## 5. Test ledger

`post = base − D + A` → deletions 0, additions 8 (`AT-172` ×2, `AT-173` ×2, `AT-174` ×2, `AT-193`,
`AT-175`), rewrites-in-place 0.

## 6. Gate runs

| run | result |
|---|---|
| New + flow suites | **47 passed** |
| Frozen dual-guard (C-27: source AND test files) | **10 passed**, 165 deselected |
| Report-adjacent suites (6 files, the derived observer set) | **116 passed** in 159.86 s |
| `ruff check` on all 4 touched files | **All checks passed** |
| Full `pytest -q -m "not slow"` | see §7 |

## 7. Full-suite result

Launched and collected by the orchestrator (C-25), evidence read from that one run's own output
(C-19) — not stitched across partial runs:

```
29 snapshots passed.
2200 passed, 2 skipped, 21 deselected, 3 xfailed in 1604.42s (0:26:44)
```

**Ledger reconciles exactly.** The pre-crash baseline recorded in `state.json.resume_checkpoint` was
`2192 passed, 2 skipped, 21 deselected, 3 xfailed`. `2192 + 8 = 2200`, and `skipped` / `deselected` /
`xfailed` are unchanged — so the batch added 8 nodes and moved nothing else. **0 regressions.**

Note `AT-175` **ran** here rather than being skipped, because this host is CRLF; on CI it will be
skipped, which is the documented intent (§3).

## 8. Scope carried, not closed

- **D1** and **D2** returned to `.dev-flow/BACKLOG.md` with every measurement as input.
- **OB-1:** batch-63 closes neither M-2 nor the resident-memory axis; the
  `> TRUNCATED … (report size cap: N bytes)` marker still asserts a bound the document violates.
- **OB-4** (operator-confirmed 2026-07-27): the resident-memory axis is on the backlog with its
  numbers — 988 B/entry, ~99 MB per change document, ~6.3 GB at 8×8, 6 415 B/region at `R=50, K=200`
  — and explicitly noted that the neighbouring bullet's `_ByteBudget` remedy does not close it.
