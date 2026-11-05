# Inc 7 — E5 rulings (orchestrator, 2026-11-05)

Inputs: E5-code-review.md (PASS-WITH-NOTES), E5-security.md (PASS-WITH-NOTES), E5-coverage-audit.md (8/52 changed), E5-mutants.md (23/24, M22 survived).

## Corrective pass (binding)

| Id | Source | Ruling |
|---|---|---|
| C-1 | S5-1 (LOW, impl) | The staging file gets a random name in the report folder (`tempfile.mkstemp(dir=…, prefix=<final stem>, suffix=".part")` or equivalent exclusive create of an unpredictable name), so a planted link at a guessable `<name>.part` is never followed. A leftover `.part` is still never touched. Update the requirement/case text that names `<name>.part` (N-1 and its case) to the new naming, record the change as a design-gap fix, and keep the LLR-155.3 placement census GREEN. RED first: a test that plants a dangling link at the old `<name>.part` and asserts the link target is not created (Windows arm; skip with reason where links cannot be made). |
| C-2 | M22 survivor | Add a test that plants `\|` in a field written by `_md_cell` (linkage Type, Disposition, Linkage, refusal code or Applied) and asserts the escaped cell; prove it kills M22. |
| C-3 | audit: clauses with no case | Add a case and a test for: the loaded MAC forwarded through key `b` (kills a never-forward-MAC mutant); the status text after a failed write (R-CMP-005.16, new row .16/3); the before/after failure status (R-CMP-005.17); image B's path (R-CMP-004.9.2); cite the existing N-1 stale-`.part` node in a case row. |
| C-4 | audit: owed ATs R-1…R-3 | Black-box, through keys with the pilot: key `b` with a MAC loaded; the Diff screen Report control / key 7 with a write failing mid-way; key `b` with the HTML generator failing. Each asserts the painted status text exactly. Where no key route exists, mark `partial` with the reason. |
| C-5 | audit R-4, R-6; TypeError cases | Add the missing AT-B94-18 assertion (R-4); add the MAC-half mutant controls so .35/1 (MAC half) and .24/2 are proven by a test that fails on an output difference, not only on a TypeError; record the kills. |
| C-6 | audit R-CMP-004.14/2 | Compare the HTML hex row text with the Markdown block (`row[:58]` or the whole row) instead of rewording the case. |
| C-7 | CR-6 (NIT) | `test_r_cmp_005_17_1` asserts the reports folder exists before it asserts absence of files, so it cannot pass vacuously. |
| C-8 | records | Repair 02-test-cases.md per the audit's change table and the rows above; update E1-slice.md §4 with SR-1's touched guard node; Count note. |

## Routed, not fixed here

| Id | Route |
|---|---|
| S5-3 (MEDIUM, design-gap) + CR-1: report size/memory (pre-existing; 1 MiB fully changed → ~1.3 GiB peak, 1.13 GiB HTML at 4 MiB) | BACKLOG-CODE, a new increment: an up-front refusal above an estimated output size, then line-by-line writes (CR-1 measured −42 % peak, identical bytes; changes I-6) |
| S5-2 (LOW) only the census can limit `_write_report` callers | BACKLOG-CODE |
| CR-2 … CR-5 (NIT) | BACKLOG-CODE |
| OBS-E5-1 `test_tc024_report_trigger_surfaces_paths` flaky on base and head | BACKLOG-CODE (test hygiene) |
| M12 / M20 killed by a single test each | noted in E5-mutants.md; no action |

Re-review after the pass: the security reviewer checks C-1 only; the coverage auditor re-audits the changed and added cases only.
