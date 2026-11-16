# Inc 8 — validation (E5)

Stage E5, model claude-opus-5-5 (relevo-10, brief X8). Base `d5d48685`. Tip validated: `e88d227d` (code and tests). `c2737944` changed records only; the last run, `s1again.txt`, covers it. Review: `E5-review.md`.

## Verdict: PASS-WITH-NOTES

- The change is proven: the 14 Inc 8 test files, the seam law and the source-scanning laws are GREEN on the runner, and `trace_check` prints no gap (below).
- One review pass. The single MAJOR (F-3) is fixed test first, so no BLOCKER or MAJOR is open. Seven findings were fixed in this pass (F-1 … F-7). Four MINOR findings go to PENDING (F-8 … F-11).
- The notes are the items the operator must still judge. They are listed at the end and are **not** passed.

## Runs (runner, isolated env: HOME basename `<runner-home>`, `-n 2`, `timeout 300`; `s19_app.__file__` and `uptime` at the top of each transcript)

| Run | Tree | Result | Evidence |
|---|---|---|---|
| Probes: decoded texts `287.0` / `175.0`; erased text row; tail at 118; no-editor input; bidi unit | `c743007e` archive + one scratch probe file | 5 passed; values as quoted in `E5-review.md` | `evidence/e5/probe1.txt` |
| F-3 RED on base; F-4 test GREEN on base | `c743007e` archive + the two new tests | `test_r_pe_def_24_4…` failed (New `·`), `test_r_pe_def_36_n…` ×2 passed | `evidence/e5/red1.txt` |
| F-4 negative control (input always enabled) | the same, mutated copy | `test_r_pe_def_36_n…` ×2 failed | `evidence/e5/red2.txt` |
| s1, s1_detail, s2_picker_definitions + `tests/test_deps_seam_law.py` | index tree of `e88d227d` | 173 passed | `evidence/e5/g1.txt` |
| s2_sheet_rows, s2_sheet_formula, s2_sheet_keys (incl. the R-PE-DEF.12 timing nodes, load 2.29: load-sensitive, HT-08) | same | 83 passed | `evidence/e5/g2.txt` |
| p_layout, p_ledger, p_wiring | same | 47 passed | `evidence/e5/g3.txt` |
| a1_service, a2_app, a3_help | same | 55 passed | `evidence/e5/g4.txt` |
| at, at_help | same | 13 passed | `evidence/e5/g5.txt` |
| Laws: docs_canon, b101_doc_hygiene, b101_help_legend_docs, no_private_tokens, filename_markup_safety, report_markup_safety, id_registry, deps_seam_law (they read git, so they ran on a bundle clone) | clone of `b103-inc8` `e88d227d` | 306 passed | `evidence/e5/laws2.txt` |
| R-TUI-064.1 … .3 canon arms (TC-B97-34 … 38, 59; `-k patch`) | same clone | 29 passed | `evidence/e5/w97p.txt` |
| s1 again, after the examples `short` change (`EX.short` is the oracle of `test_r_pe_def_21_short_number_matches_the_examples`) | index tree + new examples file | 118 passed | `evidence/e5/s1again.txt` |

The 14 Inc 8 files total 371 passed (E4 final: 368). The 3 new nodes are F-3's test and F-4's two parameter cases. The first law run on the archive tree (no `.git`) failed in `git ls-files`, an environment fault rather than a product failure, so it was rerun on the clone above.

## Mutant score

E4: 106 of 106 negative controls killed, 89 of 89 rows (`E4-mutants.md`, "Survivor follow-up"). E5: 19#x and 81#x were survivors on dead or redundant code, and that code is now removed (F-1, F-2). The new control 36#a is killed (`evidence/e5/red2.txt`).

## Review verdicts

E5 code + security, one reviewer: no BLOCKER or MAJOR open. MINOR F-8 … F-11 go to PENDING (`E5-review.md`).

## Not run

- The full suite runs at batch end (DF-08).
- `test_engine_unchanged` (it needs a `main` ref).
- No mutant battery beyond 36#a.
- Real captures and the Windows manual checks.

## Awaiting the operator's capture verdict (DF-09): not passed

- **V-1 … V-13** (`E1-rulings.md` §6): the layout, filter row, sheet rows, number detail and formula bar, enum widget (at 118 and 220), bit-mask widget, text widget, no-editor rows, narrow layout, status lines, help section wording, and Inc 9's provisional items. Two items ride on V-4: F-8 (the limits words missing from the tail at 118) and P-045's tail before typing.
- **P-046**: the marks ▶ / ● / ◆ share one column, so a selected pending row has no distinct mark. Also the manual Windows items M-1 key delivery, M-2 bracketed paste and M-3 Escape routing (`E4-test-at.md`).
- **K-1 note**: the key bar shows `? Help` while the filter input holds focus. This is pre-existing, by LLR-150.2 / TC-B97-67 (`E4-integration.md`); it goes to the V-1 page and the backlog.

## trace_check

`python ~/.claude/skills/dev-flow/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-8/01-requirements.md --base d5d48685 --src s19_app`, from the repo root with this record and `evidence/e5/` staged:

```
trace_check: 2 US, 89 active requirements (3 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 0 gap(s)
exit=0
```
