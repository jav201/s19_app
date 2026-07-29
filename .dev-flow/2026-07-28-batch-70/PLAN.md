# PLAN — batch-70 · FB-P2 implementation (multi-image runs + report fusion)

> **START HERE.** Phases 0–5 are **CLOSED**. The implementation is complete and the PR is **awaiting the operator's merge**. Nothing is in flight.

## Where we are

| | |
|---|---|
| **Phase** | 0–5 ✅ CLOSED → **6 — awaiting operator merge** |
| **Branch** | `claude/fb-p2-batch-70-impl-92b3cd` — the Phase-0 branch `claude/fb-p2-batch-70-bfc118` was **fast-forwarded into it**, so all nine Phase-0 commits are in the PR. ⚠️ The Phase-0 branch + its worktree are **frozen**; do not push to them. |
| **Base** | cut off `dc6aa71`; `origin/main` `f1f3987` merged in |
| **Approval** | ⚠️ **CHANGED at the second session's kickoff (re-asked, never inherited): AUTONOMOUS UNTIL THE PR.** The previous session's *supervised per-increment* did **not** carry. The operator still merges; nothing was self-merged. |
| **Flow revision** | `2026.07.28-rev1` · `flow_hash 0127a2767ff11c8a` · C-1…C-45 — **verified current (C-45 PULL). Re-verify at session start.** |
| **Ids allocated** | `AT-205+` · `TC-500+` · `R-TUI-099` · `HLR-104` |
| **Language** | English artifacts |

## Objective

Run a saved Flow across **multiple images/variants** and fuse the per-image results into **one** report. This threads the project's **existing** variant machinery (`plan_variant_executions`, `_resolve_manifest_entry`) rather than inventing one — but see F-1 below: the *flow-layer* variant dimension does not exist and **is built here**.

## The two Phase-0 findings — read before writing any code

### ❌ F-1 · the inherited "seam marker" was FALSE (corrected in `b037186`)

The design cited `flow_execution_service.py:343`'s `variant_id=None` as *"the single-variant assumption, explicit in the code"*. The line is real **at that address** — but sits inside the **CRC block handler's** `OperationInput` (`:339-346`), whose `variant_id` is the operations kernel's *reporting metadata* (`s19_app/tui/operations/model.py:44-46`).

| | |
|---|---|
| Genuinely **reused** | `_resolve_manifest_entry` (4 call sites `:135` `:190` `:250` `:309`) · `plan_variant_executions` |
| **Built** by this batch | the flow-layer variant dimension — `run_flow(flow, ctx)` takes no variant; `FlowContext` = `project_dir`/`mac_records`/`a2l_data` (`flow_model.py:226-228`); only 3 "variant" occurrences in 531 lines |
| **Real Inc-1 binding points** | `run_flow`'s signature · `FlowContext` · the SOURCE `image_ref` override at **`:135`** |
| ⚠️ The trap | wiring the variant into the CRC `OperationInput` at `:343` and believing Inc-1 is closed |

### ❓ F-2 · an incompleteness → **AC-7** (operator-approved)

§7 declares the containment constraint **mandatory**, yet none of AC-1…AC-6 observed it. AC-2 covers *"variant k aborts"*, and **an abort is not a containment rejection**. Folding into AC-2 was rejected — a two-subject acceptance is where batch-65's `AT-197` lost its threshold. **AC-7** consumes the *existing* C-31 census `REJECTING_CODES` (`flow_persistence_service.py:117`) instead of building a new oracle.

## Roadmap

| Inc | Content | ACs | Commit | Files |
|---|---|---|---|---|
| 1 | ✅ `FlowContext.variant` + `_bound_source_ref` + `run_flow_over_variants` with per-variant isolation | AC-1, AC-2, **AC-7**, AC-6 | `ebca4cc` | 3 |
| 2+3 | ✅ `flow_fused_report_service` — fused composer, roll-up, 🔒 **per-variant producer bounding** + cut notice | AC-3, AC-4, **AC-5** | `4573d43` | 2 |
| 4 | ✅ scope selector + fused rendering + `defer_report` (**D-4's unassigned half**) | D-4, LLR-104.6 | `2b6c3a5` | 5 |

All three increments stayed inside the ≤ 5-file budget.

### Two findings worth carrying

- **P-2 ❌** — the design said `SourceBlock.image_ref` is "overridden per variant" without saying in what **form**. `VariantDescriptor.path` is absolute and `_resolve_manifest_entry` **rejects absolute refs by design**, so the natural binding fails every variant and the natural fix is to bypass the containment seam. Bound a project-**relative** ref instead — which is also what makes **AC-7** observable, since a path that will not relativise *is* the containment rejection.
- **D-4 had no owner** — its "**no per-variant files**" clause was in no increment row. With a REPORT block each variant would have written its own report, and **every composer-level test would still have passed**, because the defect is a count of FILES.

## 🔒 D-7 — non-negotiable

The fused report is bounded **by construction, per variant, IN THE PRODUCER**. Batches 62, 63 and 65 were each spent on unbounded report producers and one **exhausted the operator's machine**; fusion multiplies row cardinality by the variant count.

- **Per-variant caps** — one pathological variant must not evict the others' content.
- **Charged in the producer, not the writer** — batch-63's Phase-2 result was precisely that *bounding output does not bound traversal*.
- **Name what was cut** (variant, section, dropped count). Silent truncation in an evidentiary document reads as *"covered everything"*.
- **Oracle = an INJECTED COUNTING ITERABLE.** Never wall-clock, never peak-memory — batch-63 proved neither can distinguish cap-and-continue from cap-and-break. **AC-5 must be shown RED against an unbounded implementation.**

## Risks / watch-items

| | Risk |
|---|---|
| ⚠️ | **The inherited design is a HYPOTHESIS, not an axiom** (C-43). batch-69 shipped no code and validated nothing. Every D-* and AC-* must earn its own validation in Phase 1-2. |
| ⚠️ | **Containment fork.** Every per-variant ref resolves through the **reused** `_resolve_manifest_entry`. Multi-image multiplies resolutions per run, so a fork multiplies the escape surface. D-3 must not become a containment bypass. |
| ⚠️ | **`state.json` is a single-batch, last-writer-wins file** with no owner field, and this project runs concurrent batches. Re-read it immediately before any write. |
| ⚠️ | **Engine-frozen set.** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`. Run **both** guards (C-27): `test_engine_unchanged.py` **and** `test_tc032`. |
| ⚠️ | Line numbers in `BACKLOG-CODE.md` are stale in both directions after 2026-07-28. **Re-derive every line number; never copy one.** |

## Conventions honored

C-43 premise evaluation (**fill `req-template` §2.7 at Phase 1**) · C-44 session-close file reconciliation (**fill the post-mortem table**) · C-45 flow currency + push portable controls upstream · C-21 re-cut increments when an AC changes · C-27 dual frozen guard · C-31 input-set-as-oracle · C-40 falsifiability before correctness · RC-1 base currency.

## Out-of-scope / carries

Patch-Editor variant path · FB-P3 CRC sub-flow · PKI extraction (⛔ blocked on operator definition) · the engine-frozen set · **R-3** (P3 — the batch-65 merge-gate docs' *prose* layer; their mechanical layer is verified clean).

## Test ledger

| | |
|---|---|
| Base (`-m "not slow"`, collected) at `244c5d9` | **2319** |
| After | **2355** — `+36`, **fully attributed**: 35 new nodes + 1 auto-parametrised (`test_universal_paste.py::test_ac1_…[flow_fused_report_service.py]`, a pre-existing per-module guard that adopted the new module by itself) |
| Frozen-source guards (C-27, both arms) | ✅ `test_engine_unchanged.py` **1 passed** · `test_tui_directionb -k tc031/tc032/engine` **7 passed** |
| Lint | 7 ruff findings, **all pre-existing**, none in this batch's files |
| **AC-5 counterfactual** | ✅ bounds reverted on a **copy of the fixed tree** → both `AT-209` nodes fail **on their assertion** (`assert 1200 <= 60`), never on an import error |

## Decision log

| # | Date | Decision |
|---|---|---|
| 1 | 2026-07-28 | Scope = FB-P2 implementation only; **supervised per-increment** (asked at this kickoff, not inherited) |
| 2 | 2026-07-28 | Premise evaluation adopted, then **encoded as C-43** — it caught F-1 and F-2 on first use |
| 3 | 2026-07-28 | **AC-7 adopted as a seventh criterion**, not folded into AC-2 |
| 4 | 2026-07-28 | F-1 **corrected in the inherited ADR + spec**, not carried as a note |
| 5 | 2026-07-28 | Phase 0 gate — **APPROVE**; no exit-criteria axis unmet |

## What batch-70 already shipped (before Phase 1)

Documentation and process only — **zero production code**.

| Commit | What |
|---|---|
| `b037186` | F-1 corrected · **AC-7** added · spec §5 re-cut (C-21) · batch-65 SHAs anchored to `b691f21` |
| `14b8285` | batch-65 merge-gate corrective **item 3** |
| `ba19c3d` | merge-gate **item 1** discharged by **re-derivation** (the prescribed text was itself wrong) |
| `1bd4ebf` | **R-2** — batch-65 artifacts map 10 → 21 |
| `ec4d605` | flow-revision block at the head of Lane A |
| `3db49a2` | **R-3** mechanical layer verified clean |
| `f1f3987` | **PR #158** — recovered batch-65's never-merged close-out |

Upstream (portable controls, per C-45): `claude-config` **`061bf93`** · `claude-skills` **`18e499d`**.
