# PLAN.md — 2026-07-12-batch-38 (living compendium)

> **BLUF:** Batch-38 ships the **P3 backlog set B-16..B-19** (4 stories, US-065..068) — a patch-editor label fix, a defensive A2L >32-bit WARNING, a variant-selector help popup, and patch-editor undo/redo + per-entry JSON editing. Run mode **autonomous + self-merge**, with **one operator gate: plan approval** (this document). RC-1 clean @ `5a6c45b`. No engine-frozen module is edited.

---

## Where we are
- **Phase 0 — Story intake & refinement.** `phase_status: awaiting-gate` (the single operator PLAN-approval gate).
- Awaiting operator approval of this plan → then Phases 1–6 run autonomously, self-merge after final PR-level QA pass.

## Objective
Close the remaining **P3** items from the operator's 2026-07-09 baseline backlog (the P1 set closed in batches 31–35; P2 in batch-37). Four independent, small-to-medium UI/robustness stories. No new external-write surface beyond existing patterns.

## Batch-kickoff authorization (recorded verbatim)
- **Scope:** Full P3 set — B-16, B-17, B-18, B-19.
- **Run mode:** *Autonomous + self-merge.*
- **Operator refinement (verbatim):** "Yes, record all autonomous decisions as your first response states. But only ask me to approve the plan."
  - ⇒ All phase + increment gates run autonomously (full review packets in-conversation, self-approve with a named exit-criteria axis check). **The only stop-for-approval is this Phase-0 plan gate.**
  - ⇒ Self-merge after PR-open + CI-green **only** once the final independent PR-level `qa-reviewer` pass over the whole diff vs `main` comes back clean (dual traceability intact · 0 engine-frozen diffs · no cross-increment regression via C-26 · every gate carry discharged). A HIGH finding blocks the merge and returns to the operator.
- **Per-batch rule:** batch-38-only; NEVER carried to batch-39; re-ask at next kickoff (`feedback_standing_auth_per_batch`).

## RC-1 base-currency gate — PASS
- `git fetch origin` clean; `HEAD == origin/main == merge-base == 5a6c45b`. No rebase needed.
- **Already-shipped check (Phase-0, per-story):** 0 source hits for the B-16..B-19 outcomes — all four proceed. Evidence in §Story intake below.

## Story intake (Definition of Ready)

| US | B-item | Outcome (WHAT, black-box) | Seam | Classify |
|----|--------|---------------------------|------|----------|
| US-065 | B-16 | The free-path field for the change-set reads as an **alternative to the patches/ dropdown for the same primary change-set**, not a second/`v2` file — the placeholder + section copy no longer implies a distinct file. | `screens_directionb.py:1854` section title + `:1904` placeholder on `#patch_doc_path_input` | **READY** |
| US-066 | B-17 | Loading an A2L whose tag address exceeds `0xFFFFFFFF` surfaces a **WARNING-severity issue naming the tag** (code `A2L_ADDRESS_EXCEEDS_32BIT`; turns the unreproducible "two extra chars" into a diagnosable warning); a hostile/oversized address renders safely (no crash, no markup leak). | `services/validation_service.build_validation_report` (**not frozen**; Phase-2 fold M1 — `a2l_service.enrich_tags_and_render` returns tag rows not issues, so it is the wrong sink); `ValidationIssue(WARNING)` constructed TUI-side; `validation/` stays frozen | **READY** |
| US-067 | B-18 | An **info/help affordance** on the variant selector opens a modal explaining what the selector does (which firmware image it picks, when it appears). | new info button beside `Select#patch_variant_select`; `_refresh_patch_variant_select` app.py:3071 | **READY** |
| US-068 | B-19 | The patch editor supports **undo/redo** of change-set edits AND a **per-entry JSON edit popup** (edit one entry's JSON, distinct from batch-37's whole-set popup). | patch editor per-entry `Add/Edit/Remove` (`screens_directionb.py:1885-87`), whole-set `#patch_edit_json_button` (batch-37); undo/redo = history stack in ChangeService/screen | **READY** — flagged **likely SPLIT at Phase 2** (undo/redo vs per-entry popup), precedent US-064 |

**Already-shipped evidence (RC-1 per-story):**
- B-16: placeholder still literally `"path to v2 change-set .json"` (screens_directionb.py:1904). Not fixed.
- B-17: 0 hits for `0xFFFFFFFF`/`4294967295`/>32-bit handling in `a2l.py` or `validation/`. Not present.
- B-18: variant `Select` exists; 0 info/help popup wired to it. Not present.
- B-19: 0 hits for `undo`/`redo`; per-entry `Edit` button exists but opens no JSON popup; batch-37 popup is whole-SET only. Not present.

## Feasibility notes (Phase-0 → carry to Phase 1)
- **B-17 / engine-freeze:** `validation/{engine,model,rules}.py` are engine-frozen (`_ENGINE_PATHS` guards). The >32-bit WARNING must be **produced TUI-side** — in **`services/validation_service.build_validation_report`** (Phase-2 fold M1: a supplemental producer sibling of `supplemental_a2l_row_issues`, merged into both report branches so it reaches `ValidationReport.issues` → `GroupedIssuesPanel`; NOT `a2l_service.enrich_tags_and_render`, which returns tag rows + summary lines, not issues — `a2l_service.py:14`), constructing `ValidationIssue(severity=WARNING, code="A2L_ADDRESS_EXCEEDS_32BIT")` and routing colour through the existing `css_class_for_severity`. `ValidationSeverity.WARNING` confirmed (`model.py:13`). **No frozen file is edited.** Markup-safety (C-17) applies: the tag name is file-derived → render via escaped/explicit `Text`, hostile-input AT mandatory.
- **B-19 split:** undo/redo is a new capability (history stack) with its own ATs; the per-entry JSON popup mirrors batch-37's `ChangeSetJsonScreen` scoped to one entry. Expect an architect-driven split into US-068a (undo/redo) + US-068b (per-entry popup) at Phase 1/2, each with an owning increment (C-21 re-cut if the split lands after the increment plan).
- **B-16:** pure copy/label — cheapest story; still owes a black-box AT asserting the rendered placeholder/section text.
- **B-18:** new modal + info button; geometry pilot-measured (C-23) at 80×24 and 120×30.

## Roadmap / increment plan (provisional — finalized Phase 2)
1. **Inc-1 — US-065 (B-16)** relabel placeholder + section copy. (smallest; no deps)
2. **Inc-2 — US-066 (B-17)** TUI-side >32-bit WARNING + hostile-input AT.
3. **Inc-3 — US-067 (B-18)** variant-selector info button + help modal (geometry pilot-measured).
4. **Inc-4 — US-068a (B-19a)** patch-editor undo/redo history stack. **A-01 guard (M4, LLR-068a.4)** folds here: Undo/Redo DISABLED when `source_path is not None` (batch-37 precedent).
5. **Inc-5 — US-068b (B-19b)** per-entry JSON edit popup (new `#patch_entry_edit_json_button`). **A-01 guard (M4, LLR-068b.4)** folds here: per-entry control DISABLED when `source_path is not None`.
   - **Cut stands after the Phase-2 fold (C-21):** AT-068b was re-pointed (B2), not added; the two A-01 guards fold into the existing Inc-4/Inc-5 owners — no new/split AT lacks an owning increment.

## Key decisions (autonomous, recorded)
- **D-0 (Phase 0):** RC-1 PASS @ 5a6c45b; all 4 stories READY; B-19 flagged split-likely; B-17 routed TUI-side to respect the engine freeze. *(This document is the operator plan-approval gate.)*

## Risks / watch-items
- **R-1 (B-17 engine freeze):** any accidental edit to `validation/` trips the `_ENGINE_PATHS` guard → build the WARNING in a service. **Mitigation:** frozen-diff check every increment + final PR pass.
- **R-2 (B-19 scope):** undo/redo can balloon (unbounded history, snapshot semantics). **Mitigation:** bound the history depth (`_HISTORY_MAX` default 20, verify Phase 3); deep-copy snapshots (no-alias asserted); keep MVP (change-set level undo, not keystroke); split from per-entry popup.
- **R-2b (A-01 data-loss — Phase-2 M4):** undo/redo and per-entry JSON edit could silently mutate/replace a **file-backed** change document. **Mitigation / stance:** DISABLE both control sets when `ChangeService.document.source_path is not None` (batch-37 precedent `set_edit_json_enabled`, `app.py:1743,1907,3264`); LLR-068a.4 / LLR-068b.4 + boundary AT branch (AT-068a/AT-068b, mirroring batch-37 AT-064c).
- **R-3 (C-26 reverse census):** US-065/067/068 touch shared ids/classes (patch controls, variant select). Every touched id/class reverse-grepped across `tests/` before increment close.
- **R-4 (snapshot drift):** new buttons/modals may drift Textual SVG cells → `xfail(strict=False)` predicted per-cell (C-22), canonical-CI regen only (local regen FORBIDDEN).
- **R-5 (C-17 markup safety):** B-17 renders a file-derived tag name in a WARNING message → escape / explicit `Text`, hostile-input AT.

## Conventions honored
- Docstring section order (Summary→Args→Returns→Raises→Data Flow→Dependencies→Example); type hints mandatory; ≤5 files/increment; ≤40-60 logical lines/function.
- Engine-frozen set untouched: `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`.
- Controls in force: C-10/11/12 (AT discipline), C-13/23 (geometry pilot-measure), C-16 (real-interaction ATs), C-17 (markup safety), C-18 (one AT → one node), C-21 (re-cut on AT-amend), C-22 (per-cell drift), C-24/C-26 (reverse/golden census), C-25 (orchestrator owns Phase-4 run).

## Out-of-scope carries (to batch-39+)
- Bookmarks screen (dead rail scaffold — own batch).
- Hygiene carries: S-F7 (linkage_symbol raw), canonicalizer 3-copy consolidation, `object.__setattr__` test-helper, native-paste 64KiB cap on `#patch_paste_text`+popup (batch-37 carry), ~9 LOW carries, P-1/P-2/P-3.
- Deferred polish: coverage-% `.6f`; A2L-symbol region names + tooltips.

## Test ledger
- Base: **1358** (batch-37 gate green, reconciled to 1385 nodes incl. xfails; canonical gate count `pytest -q -m "not slow"` = 1358 passed / 5 xfailed). Will re-confirm the live base at Phase-3 Inc-1.

## Decision log (human-readable mirror of state.json.decisions_log)
- **2026-07-12 · Phase 0:** kickoff authorization recorded (autonomous + self-merge, plan-approval-only gate); Phase-0 intake drafted; 4 stories READY; awaiting operator plan approval.
- **2026-07-12 · Phase-2 fold (reconciliation, no re-derivation):** folded the architect + qa sub-reviews across `01-requirements.md`, `01b`, and PLAN. **B1** — ratified `A2L_ADDRESS_EXCEEDS_32BIT` as the single public issue code (`A2L_ADDRESS_OVER_32BIT` retired). **B2** — AT-068b/TC-341..343 re-pointed to the NEW `#patch_entry_edit_json_button` (not the existing field-edit `#patch_entry_edit_button`). **M1** — US-066 producer sink corrected to `validation_service.build_validation_report` (verified sink-reaching; `a2l_service.enrich_tags_and_render` returns tag rows, not issues). **M2** — TC ids renumbered TC-001..019 → TC-332..345 (14 TCs). **M3** — US-065 copy pinned verbatim (title `"Change document (JSON)"`, placeholder `"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`). **M4** — A-01 data-loss guards added (LLR-068a.4 / LLR-068b.4 + AT branches): DISABLE undo/redo + per-entry JSON edit when `source_path is not None`. Minors: AT-066b ANSI split, AT-067a render/fixture pin, deep-copy no-alias, A-1 int-address flag. Increment cut unchanged (C-21). Recorded Before/After in `01-requirements.md` §6.5.
- **2026-07-12 · Phase 1 approved (autonomous):** 5 US / 5 HLR (R-TUI-054..058) / 16 LLR / 6 AT / 14 TC. All seams verified `file:line`; 0 `should`-as-modal; every LLR non-frozen. Axis check clean.
- **2026-07-12 · Phase 2 iterate-to-refine → re-approved (autonomous):** 2 blockers + 4 majors folded (above), security PASS. Certainty axis closed.
- **2026-07-12 · Phase 3 — all 5 increments APPROVE (autonomous), 0 HIGH batch-wide:**
  - **Inc-1 US-065** relabel (2 pinned strings) — code-review 0 HIGH/0 LOW; C-26 census 0; 2 patch snapshot cells `xfail`.
  - **Inc-2 US-066** A2L >32-bit WARNING in `validation_service` (both branches), boundary + C-17 hostile-input proven — 0 HIGH; 1 LOW (test-helper dup).
  - **Inc-3 US-067** variant info modal, real `pilot.click`, geometry pilot-measured fits 80×24 + 120×30 — 0 HIGH; C-26 sibling sweep clean.
  - **Inc-4 US-068a** undo/redo bounded history + A-01 guard — 0 HIGH; reachability ruled OK (overflow-y scrollbar); 2 LOW carried (F1 checks-panel-stale, F2 discoverability→ctrl+z/y).
  - **Inc-5 US-068b** per-entry JSON popup + A-01 guard, distinctness proven (single-entry seed i≠0, siblings byte-identical) — 0 HIGH; 1 LOW informational (cross-entry collision caught at doc gate).
  - **Freeze fix:** Inc-2's AT-066a had landed in the frozen `test_tui_a2l.py` (`_ENGINE_TEST_FILES`) → `test_tc032` RED; reverted to `main` + relocated AT-066a to non-frozen `test_tui_a2l_issue_recolor.py`. **Control candidate (Phase 5):** per-increment frozen guard must run BOTH `test_engine_unchanged` (source) AND `test_tc032` (engine TEST files).
  - **Ledger:** ~1358 → ~1384 (+~26). Source diff vs `main`: 5 non-frozen files (app/screens/screens_directionb/change_service/validation_service), 0 frozen.
- **2026-07-12 · Phase 4 (in progress):** orchestrator-owned gate run `pytest -q -m "not slow"` launched in background (C-25).
