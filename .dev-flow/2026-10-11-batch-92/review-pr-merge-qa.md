# PR-MERGE QA REVIEW — batch-92 (PR #210, the merge gate)

**Mode:** validation (the flow's merge gate; independent of the implementation).
**Reviewed tree:** worktree `C:/Users/jjgh8/Github/s19_app-b92`, branch `kimi/batch-92-layer-inversions` merged with origin/main at `fe03fab` (batch commit `9a87038` + merge resolution).
**Scope:** `git diff origin/main...HEAD` only — main-side carries (batch-91 closes, batch-93 seed/P1) are context, not this batch's diff.
**Every executed result below was executed by me (qa-reviewer, this review) unless it names another executor.**

## VERDICT: CLEAN — no HIGH/MEDIUM finding; merge gate passes.

---

## 1. Dual traceability — INTACT

- Contract `01-requirements.md` (batch-92's) carries US-92-1…US-92-4 (READY) → HLR-001…HLR-004 → **13 LLRs** (`grep -c "^### LLR-"` = 13) → TC-651…TC-655. Chain complete on disk.
- `python -m pytest tests/test_render_hexview.py tests/test_render_format.py tests/test_import_census.py -q` → **5 passed** (all collected nodes; the 3 files mint 5 parametrized census/identity nodes).
- AT-288…AT-291, re-run by me this review, all green (7 nodes):
  - AT-288 → `tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` — 1/1; pinned capture `evidence/at288-pre-move-report.bin` + `.sha256` on disk.
  - AT-289 → `tests/test_render_hexview.py::test_tc652_wrapper_absence_and_renderer_surface` — 1/1 (V-5 re-point per DDR §C-2; the chartered `test_at289_…` name was never realized — recorded, reconciled).
  - AT-290 → canonical binding `tests/test_tui_issues_view.py::test_at082f_hostile_issue_tokens_render_literal` — 1/1 (+ `test_c17_…` mention, the C-18 judgment in `review-p4-qa.md`).
  - AT-291 → `test_at071_strip` + 2 companions in `tests/test_tui_mac_coverage.py` — 3/3.
- Reconciliations read: `04-validation.md:68-73` (one node per AT per V-5/C-18) and `review-p4-qa.md:53-60` (per-AT reconciliation rows). No AT unreconciled, no node serving two ATs (the AT-289↔TC-652 co-pointing is the recorded, qa-accepted single realization).

## 2. Frozen modules — ZERO DIFF

- `git diff origin/main...HEAD --name-only -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py` → **0 entries**; the full-diff grep for any frozen basename → no hit (FROZEN-CLEAN).
- Frozen dual-guard, both arms run by me:
  - TC-027 arm: `pytest tests/test_engine_unchanged.py -q` → **1 passed**.
  - TC-031 arm: `pytest tests/test_tui_directionb.py -q -k tc031` → **3 passed** (no-diff / no-name-only-diff / imports-resolve).

## 3. Cross-increment regression — NONE

- Spot-runs by me across the repointed files: AT family 7/7 · `test_tui_goto_marker`+`test_tui_hexview_classed`+`test_tui_hostile_map`+`test_tui_search_pagination` 37/37 · `test_tui_operations_view`+`test_a2l_multiline_headers` 35/35 · `test_tui_hexview` 26/26 · `test_tui_diff_screen` 52/53.
- The one failure, `test_tui_diff_screen.py::test_tc024_report_trigger_surfaces_paths`, is **line 30 of the pinned `evidence/baseline-failing-set.txt`** (the 52-id known-unstable union) and a named member of the tc024 suite-flakiness carry — a pre-existing race (fails at base; the test's own comment concedes the race). Per contract §5.2 rule 2 it is an in-union flip: **recorded, not counted**. Not a batch-92 regression.
- The increments' evidence and the P4 record (`04-validation.md`, incl. the two orchestrator full-suite runs + base control under the 52-node corpus rule) read consistent with these results; I did not re-run the full suite (not required at this gate).

## 4. Gate carries — ALL DISCHARGED

- **(a) PDR C2** — `docs/architecture.md:341-345` carries the **KILLED by batch-92** rows for the two `render/hexview → tui/…` residuals (P1 amendment, operator-ratified) with the surviving `change_service → color_policy` edge declared US-92-5 OUT; the freeze wording at §7 (`docs/architecture.md:136-148`) names `tui/color_policy.py` "frozen from 2026-10-11-batch-92 (operator-confirmed 2026-10-11)". Read, matches the record.
- **(b) QA-PDR-2** — re-grepped by me: all 7 contract refs now read the anchored `.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt` form (7/7 anchored, zero bare). DDR row claims 7/7 re-written; my independent grep confirms.
- **(c) DDR §C-1** — `tests/test_id_registry.py:70-74` reads `EXPECTED_SCANNED_TEST_FILES = 163` with the narrative intact ("batch-92 merge (2026-10-12): 160 -> 163, measured … MEASURED, not incremented" — batch-91's `test_docs_canon.py` + batch-92's three modules). `pytest tests/test_id_registry.py -q` → **13 passed** (guard green at 163).
- **(d) DDR §C-2 + qa P4** — AT-289/290/291 node bindings present as tokens in the realized files: AT-289 token in the TC-652 node docstring (`tests/test_render_hexview.py:261`); AT-290 canonical node `test_at082f_…` in `tests/test_tui_issues_view.py`; AT-291 `test_at071_strip` in `tests/test_tui_mac_coverage.py`. All re-ran green by me (§1 above). The AT-290 C-18 canonical-binding decision is recorded in `review-p4-qa.md:59`.
- **(e) Backlog carries** — `.dev-flow/BACKLOG-CODE.md` (batch-92 close block): all 6 present — (1) P2 suite-flakiness / gate-not-sharp, (2) P2 US-92-5 (`css_class_for_severity` out of frozen color_policy), (3) P3 TC-027 `_ENGINE_PATHS` never gained `color_policy.py`, (4) P3 C4 stale `tui.hexview` prose mentions, (5) tc024/tc058b/at064b folded into carry 1, (6) P3 AT-290/AT-291 registry re-binding bookkeeping. Named, not silent.
- **(f) Fold-canon** — `REQUIREMENTS.md:6253` carries the `HLR-001 … 2026-10-11-batch-92 | active` row and `:6265` the `LLR-003.2 … 2026-10-11-batch-92 | active` row (fold-canon tokens in the canon file).

## 5. Merge-resolution integrity — SOUND

- `AT-TC-REGISTRY.jsonl` parsed by me: `_meta` line **first**, 1,425 data rows, **zero duplicate ids** — the union is clean.
- `.gitattributes` carries all three evidence `-text` marks: `.dev-flow/2026-10-08-batch-91/evidence/**`, `.dev-flow/2026-10-11-batch-92/evidence/**`, `.dev-flow/2026-10-11-batch-93/evidence/**`.
- `.dev-flow/state.json` is **main's**: `batch_id: 2026-10-11-batch-93`, `current_station: P0`, `phase_status: not-started` — correct for the live checkout (batch-93 is the active batch; a batch-92 state here would be the defect).
- `tests/test_id_registry.py` merge resolution: bound 163, valid syntax (13/13 collected and passed), narrative intact (read :66-76).

## 6. Id-collision note — NO DOUBLE-BOOKED ID ON THIS BRANCH

- The registry rows for the overlapping numbers are **batch-92's**: AT-288/289/290/291 and TC-651/652/653/654/655 all read `batch-92` / `RESERVED` / no node-binding yet (the AT-290/291 re-binding flip is carry (e)6, a close/registry edit on batch-93's side of the house — not a gate defect).
- **Batch-93 has zero rows in the merged registry.** Its contract (`.dev-flow/2026-10-11-batch-93/01-requirements.md:655-673`) declares AT-287…295 / TC-649…684, overlapping batch-92's AT-288…291 / TC-651…655 — but its own text says "P0 writes the RESERVED rows", and its `current_station: P0` means those rows were never written. The reservations live only in its contract text.
- The merged registry therefore has **no double-booked id**; the renumbering/rebase debt belongs to batch-93 (its coordination note, `COORDINATION-batch93-memmap.md:16-17`: batch-93 "holds its source increments (P3+) until batch-92 merges to main. Then batch-93 rebases onto the refactored tree."). Its overlapping ids will collide LOUDLY at its P0 registry write — the append-only design working as intended.

---

## Merge recommendation

**CLEAN — merge PR #210.** All seven gate items verify by execution; the single red node in the spot-runs is inside the pinned known-unstable corpus and is a named, carried pre-existing flake. The batch-93 id overlap is a declared, correctly-sequenced debt on the other lane, not a defect of this merge.
