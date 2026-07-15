# Post-mortem — s19_app — Batch 2026-06-23-batch-14 (US-015)

> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`. Keep section order for cross-batch sweeping.

## 🔑 At a glance (read first)
- **Outcome:** closed clean — PASS-WITH-NOTES, 0 defects, 0 blocker fails.
- **Scope:** US-015 (selectable 16/32 S19 record width + populated S0 header, via TUI save flows). US-016 dropped — already shipped externally (batch-15, main §20).
- **Increments:** 3 (Inc1 emitter+S0 data / Inc2 backend threading / Inc3 selector UI+pilot). **0 engine-frozen edits** throughout.
- **Ledger:** 903 → 922 (+13 / +3 / +2 / +1 Phase-4). Full suite **890 passed / 0 failed**.
- **Iterations:** {0:1, 1:2 (1 iter), 2:1, 3:1, 4:1}. Findings: **0 blocker / 4 major / 9 minor — all closed.** Code-review 3/3 APPROVE (no HIGH/MED).

## Top 3 lessons (BLUF)
1. **Stale-base scaffolding (RC-1, the one real process failure).** Batch-14 was scaffolded in a worktree off a stale `main` (`aeb8da0`) while `origin/main` advanced to `9169130` (US-016 shipped, audit closed). It required a mid-flight rebase + dropping US-016 — a full Phase-1 spec (2 HLR/LLR + AT-016.*) was written for an already-shipped story. Recovery was clean, but detection was late. **A green board hid the upstream waste.** → NEW Phase-0 base-currency gate (below).
2. **The two-layer model earned its keep — but the AT's first cut was the weak link.** Black-box AT caught the C3 class white-box TCs structurally cannot (a wired-but-dead selector passes every service-level TC). Yet the AT's *first cut* had two holes — F1 (asserted on the selector's default value, so it didn't exercise the control) and F2 (the preserve-S0 branch never observed) — both caught by **code-review, not QA**. Lesson: a green AT suite is not proof the AT exercises the shipped surface.
3. **The b12 controls + draft-time verification did their job pre-code.** Consumer-input-contract citation surfaced C1 (polymorphic emit dispatch → would `TypeError` on HEX save) — caught by *both* architect+qa in Phase 2, fixed on paper. A-5 surfaced C2 (CRC third save surface). Amendment B (Inc1) corrected a false spec premise (`get_memory_map` folds all records → "S0 adds 0 addresses" was false) via §6.5, not a silent rewrite.

---

## What worked
- **Engine-frozen invariant held end-to-end** — 0 diffs across all 7 frozen paths (TC-027/031/032 green). Keeping emission in `tui/changes/io.py` (not frozen `core.py`/`hexfile.py`) meant the whole feature lived outside the frozen set by construction.
- **C1 caught pre-code by the input-contract control** — `save_patched_image` dispatches polymorphically through `_SAVE_BACK_EMITTERS` (shared with the HEX emitter, which rejects the new kwargs). Fixed as an S19-branch-only guard + isolation guard TC-220b (a real `TypeError` regression guard outside the try/except).
- **Blast-radius budgeting accurate** — D2 predicted the 16→32 default flip safe (0 row-width tests); Phase-4 confirmed (CRC re-parse equality, 21 CRC tests green).
- **A-5 found the third surface (C2)** — `crc.py:879` inherits the 32 default; disposition (accept-as-uniform, re-parse-backed) was matrix-documented, not discovered post-merge.
- **Amendment B = draft-time verification at implementation time** — software-dev flagged the false premise via §6.5 Before/After; code-reviewer independently confirmed `get_memory_map` (core.py:485) folds all records and that a populated S0@0 can never corrupt the data-record map (the later data record overwrites it).
- **Reader-as-oracle with a non-vacuous negative control** — TC-218 corrupts a *data-record* byte (not inert S0); data-record-map oracle (Amendment B) keeps S0 population and data corruption independently asserted (TC-215 / TC-218).
- **Cross-format integrity multi-directional** — TC-226 (S19↔reparse, HEX→S19@32, S19→HEX) at 0 delta. Boundary discipline on C4 (252 accept / 253 reject).
- **Mid-batch process change absorbed cleanly** — the two-layer AT-<n> model landed in `/dev-flow` mid-flight; Phase-1 iter-2 folded it with no thrash.

## What didn't / scope drift
- **RC-1 stale base** — Phase 0/1 derived against a tree 2 PRs behind `origin/main`; US-016 fully specified then dropped. Wasted Phase-1 effort a `git fetch` would have prevented. The dev-flow assumed a current base with no gate asserting it.
- **RC-2 AT-below-surface** — the C3 finding needed a Phase-2 fix (pilot through the real selector) *and* a Phase-4 F1 hardening (cycle the selector off its default), because the default-32 value was the sole discriminator. Two corrections on the same test-honesty issue. F2 (preserve leg) was likewise code-review-caught, not QA-authored. Engineering-rule-9 in practice: the original AT couldn't fail when the selector→emit wiring broke.
- **RC-3 increment over-budget** — original Inc2 was 6 files; the ≤5 rule (the backstop) caught it and forced the Inc2/Inc3 split. Healthy split, but reactive — Phase-1 under-counted the backend-threading + UI + pilot fan-out (F-A-05 flagged "exactly 5 files, zero slack").
- **C2 CRC width has no explicit width-AT** — only width-agnostic map re-parse equality. Acceptable for an additive batch; named as a known limitation, not silently rubber-stamped.

## Root causes
- **RC-1:** worktree `main` never refreshed against `origin/main`; no phase gate verified base-currency or "already-shipped per story."
- **RC-2:** "an AT subsumes/exercises the surface" was applied by judgment, not a checkable rule — the default-value coincidence and the unobserved policy branch are criterion-level gaps (open carry C-10).
- **RC-3:** Phase-1 increment planning under-counted multi-hop + UI + pilot file fan-out.

## Metrics
| Dimension | Value |
|---|---|
| Iterations/phase | P0:1 · P1:2 (1 iter) · P2:1 · P3:1 · P4:1 |
| Findings | 0 blocker / 4 major / 9 minor — all closed (majors all pre-code design catches) |
| Code review | 3/3 APPROVE (Inc1 2 LOW / Inc2 2 LOW / Inc3 3 LOW); 0 HIGH/MED |
| Test ledger | 903 → 922 (+13/+3/+2/+1), reconciles (890 pass + 29 skip + 3 xfail) |
| Full suite | 890 passed / 0 failed |
| Engine-frozen edits | 0 across all phases |
| ruff debt introduced | 0 (6 app.py + 1 change_service pre-existing, batch-15 C-7) |

## Carries / proposed next-batch items
Reconciled with `.dev-flow/BACKLOG.md`:
- **NEW — RC-1 Phase-0 base-currency gate (propose P0/P1, global `/dev-flow`):** before scaffolding/deriving, `git fetch origin` + assert merge-base == `origin/main` tip (rebase if not); per story, grep `origin/main` for its requirement-id/acceptance surface and reclassify SATISFIED-EXTERNALLY at Phase 0 if shipped. Record the verified tip in PLAN *pre*-derivation. (Cost: 1 fetch + per-story grep.)
- **C-10 (NEW, evidenced) — AT-authoring anti-pattern guidance:** (a) no default-value-reliant pilots (exercise a non-default value or cycle off-and-back, assert the captured value changed); (b) one AT per policy branch through the surface, asserting *content* not just non-empty. Origin: F1/F2.
- **C-11 (NEW) — decide ownership of the C-10 checks:** shift-left to QA at AT-authoring time, or make them an explicit code-review checklist line (both F1/F2 were code-review-caught).
- **CRC-width AT (LOW, latent-gap closer):** one AT asserting `crc.py:879` emits ≤32-byte records (the map oracle is width-agnostic).
- **C-1** dev-flow-sync unfilled-template reject-check (P1, not exercised this batch — Phase-4 was filled). **GAP #2** manifest composition (P1, next feature). **C-9** hex-window AT (P2). **C-7/4a** app.py ruff cleanup (P2, own micro-PR). **C-6** retire TC-230/231 ids (P3). obsidian_synced ride-along (done this batch).
- **N-2 (Phase 6):** align spec engine-guard node name (`test_tc031_engine_modules_unchanged_vs_main` does not exist → live `..._have_no_diff_vs_main`) + provisional TC-<n> ids to reconciled `test_tc*` names, so the next batch doesn't inherit dead citations.
- **Endorse keeping AT + TC as independent layers** (do NOT consolidate "AT-subsumes-TC"): this batch is direct evidence they catch different failure classes (AT caught C3; TC layer stayed solid while the AT layer had the first-cut defects).
