# Post-mortem — batch-70 · FB-P2 multi-image flow runs + report fusion

**Verdict: shipped, all seven ACs observed, and the two defects that mattered were found by
executing premises rather than by running tests.** Both were in the *inherited design*, not in code —
which is this project's dominant defect class, now confirmed a third time.

## 1. What shipped

| Inc | Commit | Content | Files |
|---|---|---|---|
| 1 | `ebca4cc` | `FlowContext.variant`, `_bound_source_ref`, `run_flow_over_variants` with per-variant isolation | 3 |
| 2+3 | `4573d43` | `flow_fused_report_service` — fused composer, roll-up, **per-variant producer bounding** | 2 |
| 4 | `2b6c3a5` | scope selector, fused rendering, `defer_report` (D-4's missing half) | 5 |

All three increments stayed inside the ≤ 5-file budget.

## 2. Premise evaluation (C-43) — the second batch in a row it paid for itself

Ten premises at Phase 0 (2 failed) and ten at Phase 1 (1 failed). The Phase-1 failure is the one that
would have cost an increment:

**P-2 ❌ — "`VariantDescriptor.path` can be passed to `_resolve_manifest_entry` as the per-variant
`image_ref`".** Executed: the absolute path returns `None` with `MANIFEST-PATH-ESCAPE`; the relative
one resolves. The seam **rejects absolute refs by design**. The inherited D-2 said the ref is
"overridden per variant by the planned image" and never said in what form — so the natural reading
fails every variant, and the natural *fix* is to bypass the seam, which is exactly the containment
fork §7 forbids and which multi-image would multiply.

**The disposition ENLARGED the requirement.** D-2 is untouched; LLR-104.1 now carries the mechanism
(`path.relative_to(project_dir).as_posix()`), and the enlargement paid a second dividend: *a path
that will not relativise **is** the containment rejection*, which is what makes AC-7 observable at
all rather than requiring a hand-built hostile fixture.

> **The rule this hardens.** A design decision that names *what* is bound without naming *how* is not
> a closed question — it is an open one wearing a decision's clothes. Batch-69 closed eight decisions
> and this was the one place a form was left implicit; it was also the only place the implementation
> could have gone wrong silently.

## 3. The defect no test would have caught: D-4 had no owner

The inherited increment table assigned Inc-2 "one fused report, per-variant sections". D-4's actual
text is *"the fused run emits ONE report, with per-variant sections; **no per-variant files**"* — and
**the second clause was assigned to nobody**. With a REPORT block in the flow, each variant's
`run_flow` would have written its own report: V files, the precise manual collation FB-P2 exists to
remove.

**Every composer-level test would still have been green**, because the defect is a *count of files*
on disk, and the composer is correct. It was found by asking what a REPORT block does under the new
loop — not by a test, and not by the spec.

Closed with `FlowContext.defer_report` (the block still reports in every variant's ledger — a silent
skip would be its own defect) plus an artifact-on-disk acceptance that counts `reports/`.

> **The rule.** When an increment table paraphrases a decision, the paraphrase can drop a clause.
> Re-read the DECISION, not the increment row, when checking an increment is complete.

## 4. D-7 — the bound, and its counterfactual

The caps are applied with `itertools.islice` over the source sequences, so a variant with N ≫ cap
findings costs `cap` formatting operations. Drop counts come from `len()`, which is O(1) and
traverses nothing — that is what lets the report *state* N while only *formatting* `cap`.

**The counterfactual was executed on a COPY of the fixed tree**, not on the pre-change tree, and both
AT-209 nodes failed **on their assertion** (`assert 1200 <= 60`; the missing cut notice). Run against
the pre-change tree the tests would have failed at import and proven nothing.

One arithmetic slip was caught while writing it: the first `total_findings` counted only the blocks
inside the ledger slice, so a variant with more blocks than the ledger cap would have **under-stated
its own drop count** — a truncation notice that lies about how much it truncated. Corrected to count
over every block (still O(blocks), formats nothing).

## 5. Self-catches, in order

| # | Caught | Where |
|---|---|---|
| 1 | P-2 — the absolute-path binding fails at the containment seam | Phase 1, before code |
| 2 | D-4's "no per-variant files" clause had no owning increment | Inc-4 |
| 3 | `total_findings` under-counted drops when blocks > ledger cap | Inc-2+3, self-review |
| 4 | `_FLOW_STATUS_SEV_CLASS` did not exist — reused `_FLOW_STATUS_BANNER`'s severity half rather than forking a second status→class map | Inc-4 |
| 5 | TC-505's row predicate was a confusing disjunction; rewritten so the predicate tests what its label claims, plus a contiguity assertion | Inc-2+3 |
| 6 | The `assignments` scope was selectable and **untested** — the import that ruff flagged as unused was the symptom. Added the test instead of deleting the import | Inc-4 |
| 7 | `+36` collected vs `+35` written — attributed to a pre-existing parametrised guard, not published as a guess | Validation |

**On #6:** the lint finding was a *coverage* signal wearing a *hygiene* costume. Removing the import
would have silenced it and shipped a selectable UI option with no test behind it.

**On #7:** the delta was re-derived by diffing collected node ids against the base worktree, per the
project rule *a carried number is re-derived, never copied*. The extra node is
`test_universal_paste.py::test_ac1_no_tui_module_constructs_a_stock_input[flow_fused_report_service.py]`
— a per-module guard that adopted the new module by itself, which is the system working.

## 6. Session-close file reconciliation (C-44)

| File | State |
|---|---|
| `s19_app/tui/services/flow_model.py` | edited — `variant`, `defer_report`, `VariantRunOutcome`, `FusedFlowRunResult`, `FLOW_SCOPE_*` |
| `s19_app/tui/services/flow_execution_service.py` | edited — `_bound_source_ref`, `_roll_up_variants`, `run_flow_over_variants`, the SOURCE binding, the deferred REPORT arm |
| `s19_app/tui/services/flow_fused_report_service.py` | **NEW** |
| `s19_app/tui/screens_directionb.py` | edited — scope `Select`, `RunRequested.scope`, `render_fused_result` |
| `s19_app/tui/app.py` | edited — the single run call site dispatches on scope |
| `tests/test_flow_multi_image.py` · `test_flow_report_fusion.py` · `test_flow_multi_image_ui.py` | **NEW** (11 / 13 / 11) |
| `REQUIREMENTS.md` | edited — **R-TUI-099** appended with its three explicit non-claims |
| `.dev-flow/2026-07-28-batch-70/01-requirements.md` · `04-validation.md` · `05-postmortem.md` | **NEW** |
| `.dev-flow/2026-07-28-batch-70/PLAN.md` · `.dev-flow/BACKLOG-CODE.md` · `.dev-flow/state.json` | edited at close |
| Engine-frozen set | **untouched** — intersection with the planned edit set was ∅ (P-6), both guards green |

## 7. Test ledger

| | |
|---|---|
| Base (`-m "not slow"`, collected) at `244c5d9` | **2319** |
| After | **2355** — `+36`, fully attributed (35 new + 1 auto-parametrised) |
| Full-suite result | **2350 passed, 2 skipped, 21 deselected, 3 xfailed** in 23:40 — zero failures; `2350+2+3 = 2355` reconciles with the collection |
| Snapshots | **29 passed, none re-baselined** — recorded explicitly because `tui-ci` is blind to snapshot drift |
| Post-append re-run | the six doc-reading test files, after `REQUIREMENTS.md` was appended → **102 passed, 2 xfailed** |
| Frozen guards | `test_engine_unchanged.py` **1 passed** · `test_tui_directionb -k tc031/tc032/engine` **7 passed** |
| Lint | 7 ruff findings, **all pre-existing**, none in this batch's files |

## 8. Carried forward

Three P3 items, all recorded in `BACKLOG-CODE.md` and stated as non-claims in R-TUI-099: the missing
byte-golden for AC-6; the `O(V × ~6 lines)` heading overshoot outside the byte budget; and the AST
column-0 guard, which now has a **third** composer to sweep. Plus the pre-existing R-3 (the batch-65
merge-gate docs' prose layer, P3, untouched here).

## 9. What this batch did NOT do

It did not touch the Patch-Editor variant path, FB-P3, PKI extraction (still blocked on the
operator's definition), or the engine-frozen set. It claims no performance number: the bound is
asserted as a **count of formatting operations**, never as wall-clock or RSS.
