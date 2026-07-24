# 01b — QA catalog · batch-60 (FB-P1b flow-run report generation)

Black-box ATs (WHAT, through the shipped surface) + TCs (HOW). Every AT carries a
**counterfactual** — the concrete break that must turn it RED — so no test can pass
vacuously (C-31). Painted-surface reads follow C-32; markup asserts follow C-17
(literal text **AND** no injected structure — crash-only is insufficient).

## AT-001 — A report-bearing flow writes a report naming every executed block (US-001)
- **Given** a project with a loadable image, and a flow `LOAD → WRITE-OUT → REPORT`
- **When** `run_flow` executes it
- **Then** exactly one `reports/<ts>-report.md` exists, is non-empty, and its Pipeline
  ledger has one row per executed block (count derived from `result.block_results`, not a
  hardcoded 2), each naming its KIND.
- **Type:** integration · **TC-001** (happy path), **TC-002** (row count derived)
- **Counterfactual:** the composer emits a fixed template ignoring `block_results` → the
  derived-count assert goes RED.

## AT-002 — The flow report is surfaced by the existing reports list (US-002)
- **Given** the report written by AT-001
- **When** `list_project_reports(project_dir)` runs
- **Then** the flow report path is included (its name matches `REPORT_FILENAME_REGEX`).
- **Type:** integration · **TC-003**
- **Counterfactual:** the writer invents `flow-report.md` (a name outside the regex) → the
  report is invisible to the shipped viewer → RED. **This is the D-3 discriminator.**

## AT-003 — Hostile file-derived text renders inert (US-003) **[C-17]**
- **Given** a flow whose PATCH `change_doc_ref` is
  `calib[bad].json | # INJECTED ` `` `code` `` ` <script>` and whose finding echoes it
- **When** the report is composed
- **Then** the payload appears **escaped/literal** in the output AND introduces **no live
  markdown structure**: no unescaped `|` inside a ledger row (the row still has exactly its
  declared column count), no new heading line, no live code span, no link.
- **Type:** unit + integration · **TC-004** (per-metacharacter escape), **TC-005** (ledger
  row column-count preserved under the hostile summary), **TC-006** (benign ref stays
  readable — the negative control that proves `_md_safe` is not blanket-mangling)
- **Counterfactual:** `_md_safe` escapes `|` only → the `#`/`` ` ``/`[` cases go RED. Per-
  metacharacter cases prevent a collapsed proxy (the batch-53 qa M-1 lesson).

## AT-004 — The written report path is visible in the panel ledger (D-5) **[C-32]**
- **Given** a report-bearing flow run through the REAL panel surface (`app.run_test`, rail-8)
- **When** the run completes and `render_result` paints
- **Then** the painted ledger text contains `reports/` + the report filename, read off
  `render().plain`; and the painted line injects no markup span (`spans == []`).
- **Type:** e2e pilot · **TC-007**
- **Counterfactual:** the branch writes the file but summarises `"report written"` without
  the path → the filename assert goes RED.

## AT-005 — Positional semantics: the report covers blocks BEFORE it only (D-2)
- **Given** a flow `LOAD → REPORT → WRITE-OUT`
- **When** it runs
- **Then** the report's ledger contains LOAD but **not** WRITE-OUT (which executes after).
- **Type:** integration · **TC-008**
- **Counterfactual:** the implementation composes from the final `FlowRunResult` instead of
  the state-so-far → WRITE-OUT appears → RED. **This is the D-2 discriminator.**

## AT-006 — No REPORT block ⇒ no report written (D-1 explicit trigger)
- **Given** a flow `LOAD → WRITE-OUT` (no REPORT block)
- **When** it runs
- **Then** `reports/` contains no new file (and `list_project_reports` is unchanged).
- **Type:** integration · **TC-009**
- **Counterfactual:** an implicit-always implementation writes a terminal report → RED.
  **This pins the operator's explicit-trigger decision.**

## AT-007 — Two reports in the same second do not overwrite (LLR-002.1)
- **Given** a flow with two REPORT blocks (D-4) and a frozen clock
- **When** it runs
- **Then** two distinct files exist; the second carries the `-01` suffix; neither is empty.
- **Type:** integration · **TC-010**
- **Counterfactual:** the writer builds the name itself instead of reusing
  `_report_filename` → the second write clobbers the first → RED (one file, or equal names).

## AT-008 — A write failure degrades, never aborts the flow (LLR-003.1)
- **Given** a report-bearing flow where the report write raises (unwritable `reports/`)
- **When** it runs
- **Then** the REPORT block result is `error` with a diagnostic, the flow is **not** aborted,
  and the image/threaded state is intact (later blocks still execute).
- **Type:** integration · **TC-011**
- **Counterfactual:** the branch lets the exception propagate into the generic per-block
  handler that sets `aborted = True` → a later block is skipped → RED.

## Boundary catalog
☑ empty (flow whose only block is REPORT → report with an empty ledger + `(none)` written
files — TC-012) ☑ boundary (report after an ERROR block → status FAILED label — TC-013)
☑ invalid (hostile ref — AT-003) ☑ error (unwritable dir — AT-008). None N/A.

## Control coverage
- **C-12 output-then-consume:** AT-002 consumes the report through
  `list_project_reports` — the shipped consumer over the handler-produced artifact.
- **C-17 markup safety:** AT-003 asserts literal text **and** structure preservation; this
  also closes the **batch-53 qa M-3 carry** (the report composer is the new markup sink).
- **C-31 input-set-is-an-oracle:** AT-001 derives its row count from `block_results`;
  AT-003 splits per metacharacter rather than one collapsed payload.
- **C-32 painted result:** AT-004 reads `render().plain` + `spans`, not a pre-layout attr.
- **C-20 RED-verify:** every load-bearing AT (001/002/003/005/006/007/008) is move-aside
  RED-verified at its increment gate.

## Exit criteria
All ATs pass; full non-slow suite shows 0 batch-60 regressions (the known 19 `tc016s`
snapshot failures proven pre-existing by base differential vs `556db0c`); ruff clean;
engine-frozen guards green; final qa + security 0-HIGH.

## Evidence checklist
- [x] Every US owns ≥1 AT — US-001→AT-001, US-002→AT-002, US-003→AT-003.
- [x] Every AT carries a counterfactual that names the concrete break.
- [x] Decision discriminators pinned (D-1→AT-006, D-2→AT-005, D-3→AT-002, D-4→AT-007).
- [x] Boundary catalog complete (empty/boundary/invalid/error).
- [x] Control coverage mapped (C-12/C-17/C-20/C-31/C-32).
