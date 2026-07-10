# PLAN — batch-33 · Check-result reasons + per-entry taint (B-02, P1)

> Living compendium. Updated at every gate + significant checkpoint.

## Where we are
- **Phase 1 — locking.** Draft verified against merged main (R-B02-1 CLOSED: 33/36 citations exact, 3 line-drift-only, 0 content changes); QA strategy delivered; lock agent folding the 4 PROMINENT findings into 01-requirements.md. Next: Phase-1 gate → Phase-2 triple review.

## Objective
Check results explain themselves: per-entry `reason_code` + display reason on every `uncheckable`;
**operator-decided behavior change** — only error-carrying entries are uncheckable, healthy entries
still checked; wrong-kind = whole-run block with one loud reason; checks help affordance extended.
In-batch: scrub the markup-enabled log-label funnel (pre-existing C-17 exposure).

## RC-1
Branch `feat/batch-33-check-reasons` from origin/main tip **`dd91941`** (batch-32 squash). Nothing
shipped: `check.py:166` collective gate intact; `CheckRunEntry` has no reason field.

## Stories (Phase-0: all READY)
| US | What |
|----|------|
| US-050 | Per-entry taint (behavior change, §6.5 before/after; apply gate untouched, AT-050d guard) |
| US-051 | Reasons everywhere: 6-code taxonomy, loud run-block, C-17 across all THREE render surfaces |
| US-052 | Checks help affordance (extend `#patch_checks_help`, AT-032a token preserved) |

## Key decisions
- Operator round-3: **collective taint dropped** (per-entry); wrong-kind stays whole-run with loud reason.
- Reason taxonomy: `doc-kind`, `doc-fault` (run-block) · `entry-fault`, `partial`, `outside`, `no-image` (per-entry); stable `reason_code` + display string on `CheckRunEntry`/`CheckRunResult`.
- Error→entry mapping: entry-scoped-code allowlist × `issue.address == entry.address` (reuses `fault_addresses` idiom); unknown codes fail-safe to run-block.
- Q1 default: collision entries stay uncheckable-with-reason (both PAIR partners). Q2 default: report Reason column deferred; `to_dict` keys land with the no-consumer state named.
- **In-batch**: log-label funnel scrub (`#log_line_1..4` markup-enabled today; pre-existing `CHG-KIND-UNKNOWN` exposure) — one-line seam fix + hostile AT.
- P1 fold: AT-051b asserts the full reason on `#patch_checks_status` (50-char log cap, app.py:8884); log gets prefix-only assertion.
- US-050 realized through the REAL Run-checks button (Pilot idiom :749-816), not engine-direct.

## Increment sketch (firm at Phase-3 entry)
1. Inc-1: model layer — reason fields + domain + `to_dict` (+TCs).
2. Inc-2: engine — per-entry gate + reason assignment in `run_check_document` (+AT-050a-d RED-first; supersede the :406 pinned literal).
3. Inc-3: service/UI — `check_rows` reasons, status line, log-funnel scrub, AT-051a-f incl. 3-surface hostile.
4. Inc-4: help affordance + REQUIREMENTS.md rows (R-CHK-001 §6.5 amendment) + docs sweeps.

## Risks / watch-items
- Supersession census: the pinned `"Checks: 0 passed, 0 failed, 2 uncheckable"` literal (:406) + `startswith("Checks:")` (:1858) + aggregates consumers (report_service reads attributes) — all dispositioned in the draft §6.1, re-verified.
- AT-051c builds on the un-smoked add-entry-onto-faulted-envelope path — Phase-2 smokes it first.
- TC-051.5 owns blocked-run aggregates {0,0,N} + zero-entry {0,0,0}.
- C-17: THREE surfaces (rows markup=False ✓; `#patch_checks_status` markup-enabled; `#log_line_1..4` markup-enabled + truncation-bisected-token vector).

## Ledger
Base @ dd91941: suite 1241 collected; touched files: test_checks_engine 7 · test_change_service 21 · test_tui_patch_editor_v2 28 · test_report_service 33 · test_variant_execution 12.

## Decision log (mirror)
- 2026-07-09 P0 approved (standing auth): 3 stories READY; RC-1 PASS @ dd91941; operator taint decision recorded.
- 2026-07-09 P1 in-progress: R-B02-1 closed; QA folds P1/P2/count/fixture/TC-051.5/no-consumer/Pilot-companion being applied.
