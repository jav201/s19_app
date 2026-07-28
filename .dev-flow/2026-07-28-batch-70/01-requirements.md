# Requirements Document — s19_app — Batch 2026-07-28-batch-70

**FB-P2 — multi-image flow runs + report fusion.** Implementation of the design closed at batch-69 (`.fast-dev-flow/spec.md`, ADR §12), as corrected at this batch's Phase 0.

- **Flow revision:** `2026.07.28-rev1` · `flow_hash 0127a2767ff11c8a` · C-1…C-45 (verified current at session start, C-45 PULL)
- **Ids allocated:** `AT-205+` · `TC-500+` · `R-TUI-099` · `HLR-104`
- **Language:** English
- **security_required:** true

---

## 1. Introduction

### 1.1 Purpose

Define the requirements for running one saved Flow across a project's declared image variants and fusing the per-variant outcomes into **one** report, so an operator stops re-running the same flow by hand per image.

### 1.2 Scope

**In scope.** The flow layer's variant dimension (`FlowContext` + a fused runner), per-variant isolation, the SOURCE `image_ref` override through the *reused* containment seam, the fused report composer (per-variant sections, rollup, inverted counts), per-variant **producer** bounding, and a UI scope selector.

**Out of scope.** The Patch-Editor variant path, FB-P3 CRC sub-flow, PKI extraction (blocked on operator definition), and every module in the engine-frozen set.

### 1.3 Definitions

| Term | Definition |
|------|------------|
| Variant | One S19/HEX image declared in a project, identified by `VariantDescriptor.variant_id` (the filename stem). |
| Variant-scoped run | A run whose SOURCE image is bound per variant at run time; the flow file is unchanged. |
| Unscoped run | Today's single-image run — the SOURCE block's own `image_ref` is used. |
| Fused report | ONE markdown document carrying one section per executed variant plus a rolled-up header. |
| Producer bounding | Charging a cap where the rows are *formatted*, not where they are written (batch-63: bounding output does not bound traversal). |

### 1.4 References

`.fast-dev-flow/spec.md` (batch-69 design, corrected batch-70) · `.fast-dev-flow/ADR-flow-builder-tracer.md` §12 · `.dev-flow/2026-07-28-batch-70/PLAN.md` · REQUIREMENTS.md `R-TUI-059` (Flow Builder) · batch-63 / batch-65 post-mortems (report producer bounding).

### 1.5 Document overview

§2.7 carries the mandatory premise evaluation. §3–4 derive HLR-104 and its LLRs. §5 carries the dual traceability (`US → AT` behavioral, `US → HLR → LLR → TC` functional).

---

## 2. Overall description

### 2.1 Product perspective

The Flow Builder (rail-8, `R-TUI-059`) executes an ordered typed-block pipeline over **one** image. The project already has a *variant* concept (`ProjectVariantSet`, `plan_variant_executions`) with its own containment seam (`_resolve_manifest_entry`), which `flow_execution_service` already imports. This batch joins the two: the variant machinery is reused; the **flow layer's variant dimension is built here** (Phase-0 finding F-1).

### 2.2 Product functions

1. Run a flow across the project's variant set, one execution per planned variant.
2. Isolate variants — one variant's abort or containment rejection does not stop the others.
3. Compose ONE fused report: per-variant sections, worst-across-variants status, inverted counts.
4. Bound the fused report per variant, in the producer, and name what was cut.
5. Offer the scope as a UI selector on the Flow Builder panel.

### 2.3 User characteristics

The operator is a firmware engineer with a saved project holding several image variants and a saved flow.

### 2.4 Constraints

- **Containment.** Every per-variant image ref resolves through the reused `_resolve_manifest_entry` — never a fork. Multi-image multiplies the resolutions per run, so a fork multiplies the escape surface.
- **Engine-frozen set.** No file in `_ENGINE_PATHS` is touched.
- **Additivity.** An unscoped run must be byte-identical to today's output.
- **≤ 5 files per increment.**

### 2.5 Assumptions and dependencies

Depends on `variant_execution_service.plan_variant_executions` / `_resolve_manifest_entry`, `workspace.build_variant_set`, `flow_report_service` (`_ByteBudget`, `_md_safe`, `_report_filename`), and `markdown_safety.md_safe`.

### 2.6 Source user stories

- **US-FBP2-1** — *As an operator with a project holding several image variants, I run a saved Flow once and it executes against every variant, so I stop re-running the same flow by hand per image.*
- **US-FBP2-2** — *As an operator reading the result of a multi-image run, I get ONE report whose per-variant sections and inverted counts let me tell which images passed and which did not, and whose evidence is never silently truncated, so a fused report cannot read as "covered everything" when it was cut.*

### 2.7 Premise evaluation (C-43) — MANDATORY

Every premise below was **executed against this tree** at `244c5d9`. The inherited batch-69 design enters as **hypothesis**, not axiom — it shipped no code and validated nothing.

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| P-1 | `VariantDescriptor` carries `variant_id`, `path`, `file_type` — enough to bind a SOURCE block per variant. | premise | ✅ TRUE | `s19_app/tui/models.py:96-98` — `variant_id: str` / `path: Path` / `file_type: str`. | Used directly by LLR-104.1. |
| P-2 | **`VariantDescriptor.path` can be passed to `_resolve_manifest_entry` as the per-variant `image_ref`.** | hypothesis | ❌ **FALSE** | `_resolve_manifest_entry(d, str((d/'fw_a.s19').resolve()), …)` → `None`, issues `['MANIFEST-PATH-ESCAPE']`. The same call with `'fw_a.s19'` → resolves. The descriptor's path is **absolute**; the seam **rejects absolute refs by design** (`variant_execution_service.py:263-272`). | **BLOCKS the naive binding.** Corrected in LLR-104.1: the override derives a **project-relative** ref (`path.relative_to(project_dir).as_posix()`) and passes *that* through the seam. A path that will not relativise is a containment rejection, which is what makes AC-7 reachable. |
| P-3 | `plan_variant_executions(variant_set, manifest, scope)` yields `(descriptor, files)` in deterministic plan order and accepts `manifest=None`. | premise | ✅ TRUE | `inspect.signature` → `(variant_set, manifest, scope='all', fallback_batch=()) -> list[Tuple[VariantDescriptor, Tuple[Path, ...]]]`; `variant_execution_service.py:666-679`. | D-1 satisfied by reuse; the `files` half is ignored (a flow carries its own refs). |
| P-4 | `MANIFEST-PATH-ESCAPE` is already a member of `REJECTING_CODES`, so AC-7's rejection code is already under the C-31 census. | premise | ✅ TRUE | `MANIFEST_PATH_ESCAPE in REJECTING_CODES` → `True`; `flow_persistence_service.py:127`. | AC-7 consumes the existing census — **no new oracle built**, as specified. |
| P-5 | The shipped flow-report producer **formats every finding row before any budget check**, so fusing V variants multiplies formatting work by V. | premise | ✅ TRUE | `flow_report_service.py:342-376` — `findings_lines` accumulates for **all** blocks, then `put(findings_lines, "Findings")` at `:376` performs the first budget check. Per-block cap `MAX_REPORT_FINDINGS_PER_BLOCK = 200` (`:89`) is the only bound → worst case `200 × blocks × V` formatted rows. | This is D-7's factual basis. LLR-104.5 charges the cap **per variant, in the producer**. |
| P-6 | None of the files this batch must edit is in the engine-frozen set. | premise | ✅ TRUE | `tests/test_engine_unchanged.py:120-130` — `_ENGINE_PATHS` = `core.py`, `hexfile.py`, `range_index.py`, `validation`, `tui/a2l.py`, `tui/mac.py`. Planned edits: `services/flow_model.py`, `services/flow_execution_service.py`, new `services/flow_fused_report_service.py`, `screens_directionb.py`, `app.py`. Intersection = ∅. `pytest tests/test_engine_unchanged.py` → **1 passed**. | No unfreeze needed. Guard re-run at every increment gate (C-27). |
| P-7 | `run_flow` has exactly one production call site, so adding a fused sibling does not fan out. | premise | ✅ TRUE | `grep -rn "run_flow" --include=*.py s19_app/` → one call: `app.py:2324`. | LLR-104.6 wires the scope at that single site. |
| P-8 | `workspace.build_variant_set` produces the `ProjectVariantSet` the runner needs. | premise | ✅ TRUE | `inspect.signature` → `(project_name: str, data_files: Sequence[Path], active_id: Optional[str] = None) -> ProjectVariantSet`. | Used by LLR-104.6. |
| P-9 | The `-m "not slow"` baseline is 2319 collected. | premise | ✅ TRUE | `pytest -q -m "not slow" --collect-only` → `2319/2340 tests collected (21 deselected)`. | The Δ this batch is measured against 2319. |
| P-10 | *(inherited, batch-69 D-4)* One fused file is enough — `list_project_reports` / `ReportViewerScreen` surface one file per run. | hypothesis | ✅ TRUE | `flow_report_service.write_flow_report:452-458` names via the reused `_report_filename`, so the fused document matches `REPORT_FILENAME_REGEX` unchanged. | D-8 satisfied by writing through the same naming seam. |

**Gate rule applied.** One ❌ (P-2). It **blocked and was corrected before any code was written** — the correction is LLR-104.1's relative-ref derivation, and it is what makes AC-7 observable at all. No ❓ remains.

> **§6.5 amendment note.** P-2 does not delete an inherited decision; D-1/D-2 stand. It **enlarges** them with the binding mechanism the design left implicit — see §6.5.

---

## 3. High-level requirements

### HLR-104 — A saved flow runs across a project's variants and fuses into one bounded report

**R-TUI-099.** Given a project with a declared variant set, the Flow Builder shall execute a saved flow once per planned variant with per-variant isolation, and compose exactly one report carrying one section per executed variant, a worst-across-variants status, inverted counts, and a per-variant producer-charged bound that names whatever it cut. An unscoped run shall be byte-identical to the single-image path.

**Acceptance:** AT-205…AT-211 (§5.2).

---

## 4. Low-level requirements

### LLR-104.1 — The SOURCE binding point is the variant's project-**relative** ref

`FlowContext` gains an optional `variant: Optional[VariantDescriptor]` field (additive; `None` = today's behavior). When set, the SOURCE block's `image_ref` **and** `file_type` are overridden by the variant for the duration of that run; the `Flow` object and the flow file are never mutated. The override derives a project-relative POSIX ref from `VariantDescriptor.path` and passes it through the **reused** `_resolve_manifest_entry` — never a fork, and never the absolute path (P-2). A path that does not relativise into the project records one `MANIFEST-PATH-ESCAPE` `ValidationIssue` and fails that block, hence that variant, **closed**.

*Binding points (Phase-0 F-1): `run_flow`'s signature, `FlowContext`, and the SOURCE branch at `flow_execution_service.py:135` — **not** the CRC `OperationInput` at `:343`, which is operations-kernel reporting metadata.*

### LLR-104.2 — A fused runner executes the planned set with per-variant isolation

`run_flow_over_variants(flow, ctx, variant_set, manifest, scope)` derives the planned variant list from `plan_variant_executions` (D-1) and calls `run_flow` once per descriptor with a per-variant `FlowContext`. Each call is wrapped in an isolation boundary: an exception escaping `run_flow` is recorded as that variant's `error` outcome and the loop continues (D-3). `len(variant_outcomes) == len(planned)` always. Two keyword-only seams exist **for observation**: `plan` (an iterable of descriptors, the AC-1 counting oracle) and `run_one` (the per-variant executor).

### LLR-104.3 — The fused report carries exactly one section per executed variant

A new `flow_fused_report_service` composes the fused document. Every variant contributes exactly one `### <variant_id>` section — the heading, its status line and its cut notice are emitted **unconditionally**, so no budget pressure can make a variant vanish. `variant_id` is file-derived and passes the batch-62 `md_safe` path (D-6).

### LLR-104.4 — The header states the rollup **and** its inversion

Rolled-up status: any `error` → `error`; else any `completed-with-issues` → `completed-with-issues`; else `ok` (D-5). The header additionally states `n_ok`, `n_issues`, `n_error`, and these sum to the number of executed variants. A rollup that cannot be inverted is a summary that lies by omission.

### LLR-104.5 — The bound is charged per variant, in the producer

Per-variant caps `MAX_FUSED_LEDGER_ROWS_PER_VARIANT` and `MAX_FUSED_FINDINGS_PER_VARIANT` limit how many rows are **formatted**, via `itertools.islice` over the source sequence — so a variant with N ≫ cap findings costs `cap` formatting operations, not N. The dropped count is `len(source) - cap`, which is O(1) and traverses nothing. Every cut section names the variant, the section and the dropped count. Caps are per variant so one pathological variant cannot evict another's content.

### LLR-104.6 — The scope is selectable and wired through one call site

`FlowBuilderPanel` gains a scope `Select` (*This image* / *All variants* / *Assignments only*). `RunRequested` carries the scope; `S19TuiApp.on_flow_builder_panel_run_requested` resolves the variant set via `workspace.build_variant_set` and dispatches to `run_flow_over_variants` for a variant scope, or to `run_flow` unchanged otherwise.

### LLR-104.7 — A containment rejection fails one variant, not the run

A variant whose derived ref fails containment yields that variant's `error` outcome with the `MANIFEST-PATH-ESCAPE` code recorded in its block diagnostics; variants after it still execute and still appear in the fused report. The code is already a `REJECTING_CODES` member (P-4), so the existing C-31 census covers the variant path.

---

## 5. Validation strategy

### 5.1 Methods

Black-box `AT-*` observe the user-verified outcome through the shipped service surface; white-box `TC-*` validate the LLR mechanism. **AC-5's bounding AT must be shown RED against an unbounded implementation** — the counterfactual is run on a copy of the fixed tree with the `islice` bound reverted, never on the pre-change tree.

### 5.2 Dual-traceability

| Story | AT (behavioral) | Spec AC | HLR → LLR | TC (functional) |
|---|---|---|---|---|
| US-FBP2-1 | **AT-205** V variants → V executions (counting iterable) | AC-1 | HLR-104 → LLR-104.2 | TC-500, TC-501 |
| US-FBP2-1 | **AT-206** variant *k* aborts, *k+1…V* still execute | AC-2 | HLR-104 → LLR-104.2 | TC-502 |
| US-FBP2-1 | **AT-211** a containment-rejected variant fails closed alone | AC-7 | HLR-104 → LLR-104.1/104.7 | TC-507, TC-508 |
| US-FBP2-1 | **AT-210** an unscoped run is byte-identical to today | AC-6 | HLR-104 → LLR-104.1 | TC-506 |
| US-FBP2-2 | **AT-207** exactly one section per variant; metacharacters escaped | AC-3 | HLR-104 → LLR-104.3 | TC-503 |
| US-FBP2-2 | **AT-208** rollup is the worst; counts sum to executed | AC-4 | HLR-104 → LLR-104.4 | TC-504 |
| US-FBP2-2 | **AT-209** every variant represented; each cut names its dropped count; **producer** work is capped | AC-5 | HLR-104 → LLR-104.5 | TC-505 |

### 5.3 Batch acceptance criteria

1. AT-205…AT-211 green.
2. `pytest -q -m "not slow"` ≥ 2319 + the new tests, zero regressions.
3. `tests/test_engine_unchanged.py` and `test_tc032` green at every increment gate (C-27).
4. AT-209 shown **RED** against a bound-reverted copy of the fixed tree, with the output pasted.
5. `REJECTING_CODES - BATTERY_EXPECTED_CODES == ∅` still holds.

---

## 6. Appendices

### 6.3 Open risks

| | Risk |
|---|---|
| ⚠️ | **Containment fork.** The per-variant ref must go through `_resolve_manifest_entry`. P-2 showed the *obvious* binding is rejected by that seam — which is a feature, and the temptation is to "fix" it by bypassing the seam. LLR-104.1 forbids that in writing. |
| ⚠️ | **Bounding the writer instead of the producer.** The existing composer's `put()` budget is a writer bound (P-5). Adding a fused `put()` and calling D-7 done would repeat batch-63's exact Phase-2 finding. |
| ⚠️ | `state.json` is single-batch, last-writer-wins — re-read immediately before any write. |

### 6.5 Requirement amendments (Before / After)

**A-1 — LLR-104.1's binding mechanism (from premise P-2).**

- **Before (batch-69 D-2, as written):** "the SOURCE block's `image_ref` is **overridden per variant** by the planned image" — the *form* of the override left unstated.
- **After (batch-70):** the override binds the variant's **project-relative POSIX ref**, passed through the reused `_resolve_manifest_entry`. The absolute `VariantDescriptor.path` is **rejected by that seam by design**, so the unstated form was not free.
- **Nature:** ENLARGEMENT. D-2 is unchanged and now carries the mechanism that makes it executable — and makes AC-7 reachable, since "does not relativise into the project" *is* the containment rejection AC-7 observes.
