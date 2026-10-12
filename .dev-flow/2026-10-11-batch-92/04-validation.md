# Validation — s19_app — Batch 2026-10-11-batch-92

> Phase 4 artifact. Orchestrator-owned gate runs (C-25); `qa-reviewer` evaluated and returned the
> attributed rows (`review-p4-qa.md`); the orchestrator wrote this artifact.

## ✅ Verdict (read first)

- **Gate:** `approve` (recommended) — both validation layers green under the extended 52-node
  flaky-tolerant rule; the batch's no-functionality-loss claim rests on the deterministic
  evidence set, not on suite timing.
- **Gate run (C-25 — the CI-equivalent command, executed by the orchestrator):**
  `python -m pytest tests/ -q --tb=no -rf` — TWO complete runs in the batch tree
  (`evidence/p4-full-suite.txt`: **36 failed / 2729 passed**, 38 min;
  `evidence/p4-full-suite-run2.txt`: **40 failed / 2725 passed**, 61 min under heavy load),
  plus one complete run at the untouched base (`kimi/batch92/base-full-suite.txt`:
  **39 failed / 2723 passed** — proving the local noise pre-exists the batch).
- **Gate-rule application (§5.2, LED-…92.6/…92.11/…92.15):** every failure of both batch runs
  ⊆ the 52-node known-unstable corpus (`evidence/baseline-failing-set.txt`); the 3 nodes that
  failed outside the original 44-union were dispositioned by execution (both trees, standalone,
  second full run — LED-…92.15), not by eye. **No stable-pass→fail outside the corpus in either
  run. Census TC-651..TC-655 absent from every failing set.**
- **Deterministic no-functionality-loss set (the instrument that is actually sharp on this
  machine):** (1) the move byte-identical — body hash `fe6921c7…` recomputed independently
  three times (implementer, increment reviewer, DDR analyst); (2) AT-288 — report bytes
  byte-identical to the pinned pre-move capture (sha256 `061ee94c…4c39`, re-verified at P4);
  (3) safe_text transfer hash `103da220…2974` recomputed by the Inc-B reviewer; (4) every
  deterministic context (standalone, file subsets, both trees) behaves identically.
- **Flaky corpus is a project defect, not a batch signal:** 36–40 failures per full run on
  identical base code, load-modulated (61-min run under load produced the widest cloud),
  `at064b` failing at BASE. Routed to BACKLOG-CODE.md lane A at close (with tc024, C3, and
  the suite-noise item) — sharpening the local gate is follow-up work this batch deliberately
  does NOT absorb.

---

## Detail (reference)

### Layer 0 — unit

| Unit | Mutation (the RED that proves it) | Result |
|---|---|---|
| `render/hexview.py` body | identity-hash vs base (any drift changes the hash) | ✓ 3 independent recomputations match (`fe6921c7…`) |
| `safe_text` + `_CONTROL_SCRUB` | hostile probe `safe_text("a\x9b31mb[red]")` → `a31mb[red]` (Inc-B reviewer, cold interpreter); `from_markup` at the new address → 5 b77 nodes RED (Inc-B mutation battery) | ✓ both executed |
| `microbar` + glyphs | clamps at frac −0.5/0.5/1.5 → 0/4/8 filled; glyph identity `is render.format.*` (Inc-A sim + TC-654/655 pins) | ✓ |
| census TC-651/653/654 | consumer flip-back → RED by set-value; new consumer → RED by set-size; copy-shim → RED by `is`-identity (both increment reviewers ran their own mutations) | ✓ 4 arms Inc-A + 4 arms Inc-B, restores hash-proven |

Layer-0 closure was judged at the DDR (no new unit tests owed — every moved unit already
carries unit-level nodes; the two unasserted micro-branches are byte-identical inherited code).

### UX walkthrough — only if trigger family D fired

**Not owed — family D did not fire** (behavior-preserving import-move; no user-visible change).

### Layer A — functional (white-box): per-requirement results

| Req | TC(s) | Node(s) | Result | Executed by / evidence |
|---|---|---|---|---|
| LLR-001.1/001.2/001.4 | TC-651 | `tests/test_render_hexview.py` (+ TC-652 co-located) | ✓ absent from all failing sets; qa re-ran 5/5 | software-dev Inc-A; orchestrator P4 runs; qa-reviewer re-run (`review-p4-qa.md`) |
| LLR-002.1–002.3 | TC-652 | `tests/test_render_hexview.py::test_tc652_wrapper_absence_and_renderer_surface` | ✓ 3/3 increment runs; absent from failing sets | software-dev Inc-A; reviewer re-run |
| LLR-003.1–003.3 | TC-653 | `tests/test_import_census.py` | ✓ 5/5 Inc-B; absent from failing sets | software-dev Inc-B; qa re-run |
| LLR-004.1–004.3 | TC-654 | `tests/test_import_census.py` (+ identity arm) | ✓ 5/5 Inc-B; absent from failing sets | software-dev Inc-B; qa re-run |
| LLR-001.1/004.1 pins | TC-655 | `tests/test_render_format.py` | ✓ 3/3; absent from failing sets | software-dev Inc-A; qa re-run |
| LLR-001.2/.3 | repointed suite | `test_tui_hexview.py` / `test_tui_hexview_classed.py` / `test_tui_helpers.py` (43 nodes) | ✓ 43/43 at draft; absent from failing sets | software-dev Inc-A; sample 12/12 re-run by qa |
| LLR-002.3 | engine direct | `test_range_index.py` family (unchanged) | ✓ frozen engine untouched | inspection (frozen dual-guard 0 diff) |

### Layer B — behavioral (black-box) acceptance

| Story | AT | Reconciled node (V-5/C-18) | Result | Evidence |
|---|---|---|---|---|
| US-92-1 | AT-288 | `tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` — **one** node, whole chain through the report surface | ✓ byte-equal to pinned pre-move capture | capture `evidence/at288-pre-move-report.bin` + `.sha256`; re-hash verified at P4 |
| US-92-2 | AT-289 | `tests/test_render_hexview.py::test_tc652_wrapper_absence_and_renderer_surface` (re-pointed at DDR, LED-…92.14 — the chartered name never realized) | ✓ | DDR record §C-2 |
| US-92-3 | AT-290 | **canonical binding** `tests/test_tui_issues_view.py::test_at082f_hostile_issue_tokens_render_literal` (the through-surface driver); `test_c17_…` re-graded mention (qa C-18 judgment) | ✓ both green | `review-p4-qa.md` AT-290 decision; re-binding bookkeeping at close |
| US-92-4 | AT-291 | `tests/test_tui_mac_coverage.py::test_at071_strip` (whole-chain driver; `test_build_mac_coverage_strip_counts`, `test_zero_total_no_divdiv` companions) | ✓ 14/14 family | Inc-B evidence; qa re-run |

### Bidirectional surface-reachability matrix (extends A-5)

No new input dimensions or output deliverables exist in this batch (repoint-only; the contract's
QC-3 boundary catalogs declare `none`/inapplicable per requirement). The moved functions' inputs
(fixture images, ranges, style constants) and outputs (`Text` rows, report bytes) are exercised
through the handler surfaces: hex view via the repointed 43-node suite, reports via AT-288's
end-to-end service path, screens via the guard host (183 tests through the shipped TUI surface).
Declared `n/a — no new surface` with this evidence.

### Signed-balance test ledger

| Run | Executed by | Result | Outcome |
|---|---|---|---|
| Inc-A: TC modules / repointed 8-file set / guard host / AT-288 | software-dev (agents) | 3/3 · 185/1-in-union · 183/0 · 1/1 | green |
| Inc-A independent review | code-reviewer agent | OK to advance, 0 HIGH | green |
| Inc-B: TC modules / repointed set / AT-290/291 family / guard host | software-dev (agents) | 5/5 · 72/0 · 14/14 · 183/0 | green |
| Inc-B independent review | code-reviewer agent | OK to advance, 0 findings | green |
| P4 gate run 1 (batch tree) | **orchestrator** | 36 failed / 2729 passed — all ⊆ 52-corpus | green under rule |
| P4 gate run 2 (batch tree, loaded) | **orchestrator** | 40 failed / 2725 passed — all ⊆ 52-corpus | green under rule |
| Base full run (flake control) | **orchestrator** | 39 failed / 2723 passed — noise pre-exists | control |
| Registry guard / frozen dual-guard / qa re-runs | agents + orchestrator | 13/13 · green · 11/11 + 12/12 | green |

### Gaps detected

None for the batch's scope. Carried (named, not silent): tc024/tc058b/at064b + suite-noise
sharpening → BACKLOG-CODE.md lane A at close; AT-290/AT-291 registry re-binding bookkeeping at
close (ids currently RESERVED); C4 prose mentions (4) → backlog.

### Escaped-bug regression

None — no defect escaped the suite during this batch.

### Evidence checklist — qa-reviewer (full)

✓ complete in `review-p4-qa.md` — Layer A/B rows with per-result attribution (who executed
each result: orchestrator / named agent), AT-290 C-18 judgment, gate-rule application, and the
provisional verdict this artifact finalizes.
