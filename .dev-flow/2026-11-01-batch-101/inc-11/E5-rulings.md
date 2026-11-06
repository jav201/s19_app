# Inc 11 — E5 rulings (orchestrator, 2026-11-05)

Inputs: E5-code-review.md (PASS-WITH-NOTES: F1, F2 MINOR; F3–F5 NIT), E5-security.md (PASS-WITH-NOTES: E5-1 MEDIUM, E5-2 LOW, E5-3…E5-6 INFO), E5-coverage-audit.md (20/77 cases changed; 3 full → partial), E5-mutants.md (DeepSeek: 32/32 KILLED; every transcript shows a failing run; caveat: the transcripts do not print `s19_app.__file__` and there is no in-copy unmutated run — the integrator's GREEN run int-07/int-15 on the same tree is the baseline).

## Corrective pass (binding)

| Id | Ruling |
|---|---|
| C-1 | F1 (A-8): `docs/architecture.md:39/398/416` updated to the shipped behaviour (the view paints the engine's severity; the re-labelling is gone) — text only. |
| C-2 | F2 (N-1, N-3, N-4, N-2 residuals): R-A2L-036.2 and .4 carry the base + size ≤ 2^32 bound of .13; .5 and .6 lose the stale wording; D-5 records the N-2 (non-ASCII digit skipped) and N-3 (non-digit typo shifts the anchor) residuals and E5-3 (a quoted address shifts the base onto the size word) as accepted. |
| C-3 | F3–F5: the acceptance test docstring names the real wait helper; the S11 test asserts which word the reader anchors on; the fixture uses the shipped quoting. |
| C-4 | Audit marks: R-TUI-042b.4/1 asserts the painted colour `#f6ff8f` (or stays partial with reason); AT-I11-4 asserts each name with its base (`boot` at 0x0), and R-SEG-SRC.6/1 follows it. |
| C-5 | Audit case corrections: AT-I11-1's key (`p`), AT-I11-4/5 real routes, the missing clauses of R-A2L-036.7/1, R-TUI-042b.5/2, R-SEG-SRC.6/2; the 11 non-id Tests entries become real node ids; R-A2L-120/1 gets its G1 test; R-VAL-032.3/3 drops TC-B94-18. |
| C-6 | Audit discrimination: the 21 cases that also pass on base each name the mutant that kills their test (from E5-mutants.md); any case with no killing mutant gets one run on LAN host 2 (or is marked partial with the reason). |
| C-7 | Audit clauses with no case (3) and owed black-box ATs (3): add each or rule it not-testable with the reason. |
| C-8 | E5-6 hostile-name test also asserts control characters are scrubbed. |

## Routed to BACKLOG-CODE (append, batch-101 style)

| Id | Item |
|---|---|
| E5-1 (MEDIUM, pre-existing) | A file can declare a whole-address-space MEMORY_SEGMENT (`0x0 0xFFFFFFFF`); a Split export with fill of that row exhausts memory. A fill-export size cap (with the S-2 note). |
| E5-2 (LOW) | A 4 MiB hostile segment block costs ~1 s per read (base 0.01 s); linear. |
| E5-4, E5-5 | Modal title parses tag names as markup; OK rows not shown (pre-existing). |
| O-4, O-5, O-6 | Iterative parser (deep nesting), `/end` name check, modal title/body scrub — from E3. |

Runs: LAN host 2 (`<USER>@<IP>`, redacted at commit) only (operator rule).
