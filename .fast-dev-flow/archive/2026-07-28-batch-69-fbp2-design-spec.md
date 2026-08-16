# Design Spec — s19_app · batch-69 · FB-P2: multi-image flow runs + report fusion

- **Status:** DESIGN ONLY — implementation is a separate batch, deliberately
- **Date:** 2026-07-28
- **Branch:** `claude/batch-69-fbp2-design` (base = `origin/main` tip at cut; RC-1 PASS)
- **Flow mode:** autonomous + self-merge (operator-granted THIS batch at kickoff; per-batch only)
- **security_required:** true (see §7)

> **Why design-only, stated rather than assumed.** The operator picked this batch citing remaining context. FB-P2 is the larger of the two candidates — full `/dev-flow` shape — so running it end-to-end on a narrow window reproduces exactly the failure batch-65 documented: a long context, and the bad self-corrections arrive at the end. This batch therefore produces **decisions and acceptance criteria**, and stops at the implementation boundary. **No production code.**

---

## 1. Objective

Decide — not merely enumerate — how a saved Flow runs across multiple images/variants and how the per-image results fuse into one report, so the implementation batch has no open design questions left.

---

## 2. What already exists (measured, not assumed)

| Asset | State |
|---|---|
| `variant_execution_service.py` (971 lines) | `ProjectManifest`, `plan_variant_executions`, `_execute_one_variant`, `VariantExecutionResult(variant_id, status, change_summaries, check_results, diagnostics, mem_map)` |
| `flow_execution_service.py` (531 lines) | `run_flow` over one image; **already imports `_resolve_manifest_entry` from the variant service** — the containment seam is shared, not forked |
| ~~The seam marker~~ ❌ **WITHDRAWN batch-70** | ~~`flow_execution_service.py:343` passes `variant_id=None` — the single-variant assumption is explicit in the code~~ — **FALSE as characterized.** The line exists at that address but lives in the **CRC block handler**'s `OperationInput` (`:339-346`); `OperationInput.variant_id` is operations-kernel reporting metadata (`operations/model.py:44-46`), not a flow seam. See the corrected row below. |
| The flow layer's variant dimension | **ABSENT — this feature builds it.** `run_flow(flow, ctx)` takes no variant; `FlowContext` = `project_dir` / `mac_records` / `a2l_data` (`flow_model.py:226-228`). Only 3 "variant" occurrences in 531 lines: docstring `:7`, the import `:66`, the CRC line `:343` |
| The containment seam (genuinely reused) | `_resolve_manifest_entry` imported at `:66`, called at **4 sites** — `:135`, `:190`, `:250`, `:309` |
| `FlowContext` | `project_dir`, `mac_records` only — **no variant dimension** |
| `flow_report_service.py` | `compose_flow_report(state, generated_at)` over `FlowReportState(flow_name, block_results, aborted, image_ranges, pre_crc_ranges, written_paths, project_dir)` |
| Status vocabularies | blocks: `ok` / `error` / `skipped` / `notices` · flow: `ok` / `error` / `completed-with-issues` |

**Consequence — corrected batch-70 Phase 0 (executed against disk).** The *variant machinery* (manifest parsing, planning, containment) is shipped and proven, and FB-P2 reuses it. But the **flow layer's variant dimension does not exist and this feature builds it** — the original claim that this is "mostly threading an existing dimension, not building one" understated the work by resting on a mis-read seam marker (row 3 above). D-1..D-8 are unaffected: the correction moves the *effort/risk* premise, not any decision. Practical consequence for Inc-1: the binding points are `run_flow`'s signature, `FlowContext`, and the SOURCE `image_ref` override at `:135` — **not** the CRC `OperationInput` at `:343`.

---

## 3. Design decisions — RESOLVED

**D-1 — the image set comes from the project's variant set, not a new list.**
Reuse `ProjectVariantSet` + `plan_variant_executions`. Rationale: it is already the project's notion of "the same artifact across images", it carries manifest resolution and containment, and a second parallel concept would fork `_resolve_manifest_entry` — the boundary batch-53 hardened and which `run_flow` already reuses. *Rejected:* an explicit path list in `flow.json`, which would let a flow name images outside the project.

**D-2 — `SourceBlock` becomes the per-variant binding point; the block is not rewritten.**
When a run is variant-scoped, the SOURCE block's `image_ref` is **overridden per variant** by the planned image, and the flow file is unchanged on disk. Rationale: a flow stays a reusable recipe; binding it to N images is a property of the *run*, not of the flow. A flow whose SOURCE names a specific file still works unscoped, exactly as today.

**D-3 — per-variant isolation: one variant's abort does NOT abort the run.**
Each variant executes independently and records its own terminal status; the run continues. Rationale: the whole value of multi-image is comparison, and a fused report missing 4 of 5 images because the 1st failed is worse than useless. This matches `_execute_one_variant`'s existing per-variant discipline.

**D-4 — the fused run emits ONE report, with per-variant sections; no per-variant files.**
Rationale: N files re-create the manual collation FB-P2 exists to remove, and the shipped `list_project_reports` / `ReportViewerScreen` surface one file per run. *Rejected:* N+1 files (per-variant plus fused) — it doubles the write surface and every byte-budget question, for a collation the fused document already provides.

**D-5 — the fused status is the WORST across variants, and the count is stated.**
Rollup: any `error` → `error`; else any `completed-with-issues` → `completed-with-issues`; else `ok`. **The header must also carry `n_ok / n_issues / n_error`**, because a single rolled-up word over N images hides exactly what the operator opened the report to see. A rollup that cannot be inverted into per-variant outcomes is a summary that lies by omission.

**D-6 — variant identity is `variant_id`, rendered verbatim and ESCAPED.**
`variant_id` is file-derived, so it enters the markdown composer through the batch-62 `md_safe` path like every other file-derived field. No new escaping mode.

**D-7 (the load-bearing one) — the fused report is BOUNDED BY CONSTRUCTION, per variant, before it is written.**
This project has now spent **three** batches (62, 63, 65) on report producers that were unbounded, and the last one measured `O(V×E)` traversal that exhausted the operator's machine. **Multiplying the row cardinality by the variant count without a bound would be repeating a known, expensive lesson deliberately.** Therefore:
- every per-variant section carries its own cap, so one pathological variant cannot evict the others' content — the *class-selective eviction* finding from batch-63 D1, applied across the variant axis;
- the cap is charged in the **producer**, not at the writer — batch-63's Phase-2 finding was precisely that *bounding output does not bound traversal*;
- when a section is capped, the report **names what was cut** (variant, section, count). A silent truncation in an evidentiary document reads as "covered everything".

**D-8 — no new viewer.** The fused report is written through the existing `write_flow_report` path so it matches `REPORT_FILENAME_REGEX` and `ReportViewerScreen` picks it up unchanged — the same reuse FB-P1b relied on.

---

## 4. Acceptance criteria for the IMPLEMENTATION batch (observable)

**AC-1** — Given a project with V declared variants and a flow with a SOURCE block, running the flow variant-scoped executes the flow **V times**, once per planned image. *Oracle: an injected counting iterable over the planned set, not a wall-clock or peak-memory comparison — batch-63 proved those cannot distinguish cap-and-continue from cap-and-break.*

**AC-2** — When variant *k* aborts, variants *k+1…V* still execute and appear in the report with their own statuses (D-3).

**AC-3** — The fused report contains exactly one section per executed variant, each identified by its `variant_id`, and a `variant_id` containing markdown metacharacters renders escaped (D-6).

**AC-4** — The fused header's rolled-up status is the worst per D-5, **and** the `n_ok / n_issues / n_error` counts sum to the number of executed variants.

**AC-5** — With V variants each producing more findings than the per-section cap, **every** variant is still represented, and the report names each cut section with its dropped count (D-7). *This must be shown failing against an unbounded implementation.*

**AC-6** — Running a flow **unscoped** produces byte-identical output to today's single-image path. The new dimension must be additive.

**AC-7** *(added batch-70 Phase 0 — operator-approved)* — A variant whose `image_ref` **fails containment** fails *that variant* closed, with its rejection code recorded, while the remaining variants still execute and appear in the fused report. The `REJECTING_CODES` completeness census covers the variant path. *Oracle: the existing C-31 census in `flow_persistence_service.py:117` — "every code here is exercised by ≥1 hostile case, so a new reject arm shipped without a battery row goes RED".*

> **Why AC-7 exists — an incompleteness, not a falsehood.** §7 declares the containment constraint **mandatory** ("a variant whose ref fails containment must fail that variant closed without aborting the others — D-3 must not become a containment bypass"), yet **no AC-1..AC-6 observes it**. AC-2 covers *"variant k aborts"*, and an abort is not a containment rejection: one is an execution failure, the other is a ref pointing outside the project. Folding it into AC-2 was rejected — an AC with two distinct subjects is precisely where batch-65's `AT-197` lost its threshold. The disposition ENLARGES the requirement set rather than reinterpreting an existing member, and it consumes infrastructure that already exists rather than building a new oracle.

---

## 5. Increment plan for the implementation batch

| Inc | Content |
|---|---|
| 1 | `FlowContext` gains the variant dimension; `run_flow` loops the planned set with per-variant isolation (D-1..D-3). Binding points are `run_flow`'s signature, `FlowContext`, and the SOURCE `image_ref` override at `flow_execution_service.py:135` — **not** the CRC `OperationInput` at `:343`. AC-1, AC-2, **AC-7**, AC-6. |
| 2 | `FlowReportState` gains per-variant sections; fused composer + rollup (D-4..D-6). AC-3, AC-4. |
| 3 | Per-variant producer bounding + the cut notice (D-7). AC-5. |
| 4 | UI: scope selector in `FlowBuilderPanel`; wire through. |

---

## 6. Out of scope

The Patch-Editor variant path (unchanged), FB-P3 CRC sub-flow, PKI extraction (still blocked on the operator's definition), and the engine-frozen set.

---

## 7. Security flags

`security_required: **true**` — one pattern fires and it is real.

**`file` / untrusted path resolution across N images.** Every per-variant image ref must resolve through the **reused** `_resolve_manifest_entry`, never a fork — that function is the containment boundary batch-53 hardened, and `flow_execution_service` already imports it. The multi-image change multiplies the number of resolutions per run, so a fork here would multiply the escape surface too. **Implementation constraint: the reject-arm census (`REJECTING_CODES`) must cover the variant path, and a variant whose ref fails containment must fail that variant closed without aborting the others (D-3 must not become a containment bypass).**

**Not a flag but recorded:** D-7 is a denial-of-service consideration, not a confidentiality one. It is treated as load-bearing anyway because this project has already had a report producer exhaust host RAM.
