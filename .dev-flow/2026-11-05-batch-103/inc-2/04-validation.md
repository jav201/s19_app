# Inc 2a — A2L definition model I (scalar kinds): validation record (E5)

**Verdict: PASS-WITH-NOTES.** No MAJOR, HIGH or worse is open. All 216 2a cases are `covered` and `verified` on the final code. Code under test: `s19_app/tui/a2l_definition.py` and `tools/synth/make_release_case.py`, at the final fix pass (md5 `7bd4064983dbcefac4523b1792f1838e` / `82fba4c34fb9cad1888a30d06025a725`, as the final GREEN runs it). Written 2026-11-07.

**Platform limit.** Every run below is on <runner>, Python 3.11.18, platform Linux. The perf bounds (R-A2L-DEF.136, .149, .150) are valid on that host only; Windows was not run.

## Runs (evidence copied into the batch evidence folder)

| Run | Result | Evidence |
|---|---|---|
| **Final GREEN main** (model + synth) | 199 passed, 1 deselected (`.59/2`, the slow case, by design) | `../evidence/inc-2/fix-tests-green-main.txt` |
| **Perf (`serial_timing`), 3 runs** | 22 passed in each of 3 runs; 52 timing bounds, 0 under 20 % margin | `../evidence/inc-2/fix-tests-green-perf-1.txt`, `../evidence/inc-2/fix-tests-green-perf-2.txt`, `../evidence/inc-2/fix-tests-green-perf-3.txt` |
| **Mutants on the final code** | 63/63 killed, 0 survived, 1 not realisable (`.58.1`'s encode arm, a 2b arm) | `../evidence/inc-2/mutant-table-A.md`, `../evidence/inc-2/mutant-table-B.md` |
| **Security round 2 — census** | 0 differences (corpus 142,164 pairs; hostile 436,802; fix-eq 152,294; long runs 15,456; also 0 vs `069171cd`) | `../evidence/inc-2/sec-e5r2-census-transcript.txt` |
| **Security round 2 — seeded mutation** | 1,461 mutants, 0 exceptions (round 1: 32) | `../evidence/inc-2/sec-e5r2-hostile-mutate-transcript.txt` |
| **Coverage audit** | 216 agree / 0 partial / 0 gap | `../evidence/inc-2/E5-coverage-audit.md` |

## Review verdicts

| Review | Round 1 | Round 2 |
|---|---|---|
| Code (Opus) | FAIL (CR-1, CR-2 MAJOR) | PASS-WITH-NOTES (0 MAJOR; CR-1 … CR-11 closed, CR-8 recorded only) |
| Security (Opus) | FAIL (E5S-01, E5S-02 MAJOR) | PASS-WITH-NOTES (0 MAJOR; E5S-01 … -05 closed, E5S-06 deferred to BL-I2-18, E5S-07 unchanged; new E5S-08 MINOR, E5S-09 LOW) |
| Coverage audit (qa-reviewer) | n/a | PASS-WITH-NOTES (216 agree / 0 partial / 0 gap) |

E3 (design) closed earlier: architect and security both FAIL in round 1, PASS-WITH-NOTES in round 2 (`E3-rulings.md`); the E5 gap passes added R-A2L-DEF.149, .150 and .151.

## Key design changes made at E5

- **CR-1 = E5S-02:** the TAB_NOINTP walk-back loop becomes one `bisect_left`; decode time no longer grows with a run of equal x (case `.150/10`).
- **The number rule (CR-2 + E5S-01 + E5S-03 + CR-3 + CR-5):** a number the system writes into a refusal message or a kind text is written in decimal when its magnitude is at most 2^64 − 1, else as the `.151` echo of its file word; no message raises and none exceeds 1,024 characters.
- **CR-4 = E5S-05:** conversion type words are compared case-sensitively everywhere.
- **E5S-04:** the walk is iterative (an explicit stack), so deep nesting cannot raise `RecursionError`.
- **CR-6:** the definitions-case enum planned text follows the drawn raw (`.59/4`).
- **CR-7:** the P-2 private fields stay `compare=False, repr=False`, pinned by `.149/5`.
- **E5-3:** the timing measure is one fresh walk — the 399 names after the first, timed through a generator, no two-walk subtraction.

## Models per stage

| Stage | Model |
|---|---|
| Implementation | DeepSeek v4 Pro |
| Tests | Sonnet |
| Code review, security review | Opus (claude-opus-5-5) |
| Records, graph, orchestration | Opus |
| Mutants | DeepSeek v4 Pro |
| Coverage audit | qa-reviewer (deepseek-v4-pro) |

## Not run

- **Windows:** no run; the perf bounds are valid on <runner> only.
- **Full test suite:** batch end.
- **The 2b arms:** the 109 2b cases (encode, the write guards, the `.138` span index) and every encode arm of a mixed 2a case wait for Inc 11 and their own re-review.

## Open notes (backlog)

| Id | Sev | Note |
|---|---|---|
| BL-I2-18 | LOW design-gap | bidi and separator characters stay in display texts (E5S-06); consumers render through `safe_text`, the residue is recorded |
| E5S-08 | MINOR design-gap | Inc 3a's records still call 2a contracts the fix pass changed (`_read_stored_value(name_echo)`, the exact type verdict, `_number_text`) |
| E5S-09 | LOW design-gap | under load the E5-3 measure's 2S ratio approaches the 1.5 bound; judge growth at 8S |
| CR-8 | INFO | the describe section list is closed; decode reads `compu_tabs_by_name` only for a definition built by hand |
| 2b arms | backlog | the 109 2b cases and the encode arms of the mixed 2a cases |
| Windows / full suite | owed | run at the batch end |

## Evidence in the batch evidence folder (trace_check)

Copies of the decisive transcripts, cited above by their path from this record so the trace checker links them; the originals stay under `inc-2/evidence-e4/` and `inc-2/evidence-e5/`:

- `../evidence/inc-2/fix-tests-green-main.txt` — final GREEN main (199 passed, 1 deselected).
- `../evidence/inc-2/fix-tests-green-perf-1.txt`, `../evidence/inc-2/fix-tests-green-perf-2.txt`, `../evidence/inc-2/fix-tests-green-perf-3.txt` — the 3 perf runs (22 passed each).
- `../evidence/inc-2/mutant-table-A.md`, `../evidence/inc-2/mutant-table-B.md` — 63 killed / 0 survived / 1 not realisable on the final code.
- `../evidence/inc-2/sec-e5r2-census-transcript.txt`, `../evidence/inc-2/sec-e5r2-hostile-mutate-transcript.txt` — the security round-2 census and mutation runs.
- `../evidence/inc-2/E5-coverage-audit.md` — the coverage audit (216 agree / 0 partial / 0 gap).

## Trace check (orchestrator)

**Run:** `evidence-e5/trace-check-transcript.txt`, executed on <runner> from a committed `--shared` clone at `0c499784`, with `--base e07fb00 --src s19_app tools`.

**Result:** 1 US, 72 active requirements, 19 gaps.
- **All 19 gaps are `TEST`, on exactly the 19 rows the "Split (amendment A2)" table assigns to 2b: R-A2L-DEF.40 … .57 and .138** (encode messages, write guards). This is by design: these rows are owed by Inc 2b, which waits for Inc 11.
- **0 gaps on any 2a row:** no SLICE, EVID, CASE or TRACE gap.
- The batch-end trace must reach 0 gaps once 2b's tests exist.
