# 02 — Cross-agent review · batch-86 · Phase 2 (round 1)

**Gate verdict: ITERATE-TO-REFINE — 1 blocker · 6 major · 7 minor.** Two independent
reviewers (architect lens, qa lens; security not triggered — family C non-activation
recorded in PLAN.md). Both re-executed rather than re-read: the architect re-ran ≥14 claims
(20+ line citations exact, cross-sums coherent), the qa re-ran 12 thresholds (zero
divergences) and reproduced all four M-9 arms over the REAL parsed record. The record's
substance held everywhere except one emptiness claim — which is the finding.

## Blockers

| id | Finding | Evidence (executed) |
|---|---|---|
| **B86-R2-01** | **"0 genuine undeclared dependants" (G4/§5.6/P-7) is FALSE — the bare-name sweep (M-5) was app.py-only, and tests couple by bare id too.** C-55 exactly: the emptiness carried G4's GREEN with no declared search-width guard; widening by one directory refuted it | `tests/test_tui_commandbar.py:686` (`_B78_SEARCH_SURFACES` drives `search_button`/`goto_button` — a rename breaks it), `:135` (composes `f"#{sid}"` over `screen_workspace`), `:329/:491` (asserts on it); `tests/test_tui_directionb.py:6375` (`assert goto_focus == "goto_input"`); in-app function-granular omissions `app.py:5749/:5789/:7512/:7517` |

## Major

| id | Finding |
|---|---|
| B86-R2-02 | AT-B86-04's oracle command contradicts §2.6(d)/qa-plan AC-d (`main` vs merge-base; `pyproject.toml` dropped) — the N4/N5 internal-contradiction shape |
| B86-R2-03 | P-2/M-1's mention location `:211` contradicted by its own command (real: `:1784`); count and verdict survive |
| B86-QA-F1 | Pre-state contradiction: M-8/P-9 say `2 block` "pre-existing Atlas staleness"; the qa plan's same-day pre-state says `0 block`, Atlas current. The staleness arose AFTER batch open (tripped by the batch's own scaffold edits); P-9's "neither attributable to this document" is not established as worded |
| B86-QA-F2 | Station P3 can pass with zero live gates attributable to its own deliverable (every seeding-sensitive criterion deferred to CLOSE) — defect-#15 one level down. Fix: run G6's per-id greps at the P3 increment gate itself |
| B86-QA-F3 | M1/M5 kill-mutation disposition cites M-9 for parse-path coverage an in-memory arm cannot provide (it feeds pre-parsed dicts), silently deviating from the qa plan's copy protocol. Substance verified independently (qa reproduced all 4 arms over the real parsed record); the citation is wrong. Fold one copy-protocol M5 into Phase 4 beside M4/M7 |
| B86-QA-F4 | AT-B86-01's ☑ error arm cites a "carried" pilot transcript that DOES NOT EXIST (batch-85 has no 00-measurements.md). The real evidence is selftest arm `V14 BLOCK-nofile` — re-cite |

## Minor

R2-04 (LLR-86.8/HLR-86.3 quantifier vs its own table: rows 5/6 carry no M-id) · R2-05 = QA-F1
(same divergence, one fix) · R2-06 (AC-c's expected unowned-LLR enumeration dropped at the
fold: LLR-86.7/86.8 print live, unanticipated by the text) · R2-07 (D-86-A cites M-7 where
the evidence is in M-6; the exclusion itself verified sound) · R2-08 (G4's `∪` invites the
wrong sum: write "pilot's 4 at their lines PLUS this record's 38 at its lines") · QA-F5
(M-9 transcript lacks its invocation snippet — not re-runnable without spelunking) · QA-F6
(ledger pin has no baseline yet — state it as a gate precondition until the s19env run lands).

## What survived (both reviewers, executed)

Every counted threshold verbatim (V10 20 · V11 35 · V12 1 · V14 97 · V19 2 · V21 35 · V13
38+1 with per-row file lists) · every symbol/line citation in §5 exact · normative language
clean (0 `should` in Statements) · derivation chains complete both directions · D-86-A
exclusion and D-86-E quarantine ruled SOUND · pins labelled as pins · selftest citations all
exist (189 arms, exit 0). The three format lessons held under re-execution.

## Disposition

All 14 findings are confined to the batch's own artifacts; 0 product code. Returned to the
Phase-1 author (context intact) with the consolidated fix list; frozen figures that move
(V14, V13 pair set, D-86-D counts, G3/G4) must be RE-MEASURED after the fix, never edited
in place (C-39 rider). Re-gate: orchestrator re-executes the moved figures + spot-checks
each discharged finding; a second full double-review is not owed unless the fix escapes the
record (it does not).
