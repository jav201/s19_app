# Inc 1a — Clipboard core: instant paste: validation record (E5)

**Verdict: PASS-WITH-NOTES.** No MAJOR, HIGH or worse is open in the slice's product code. The one MEDIUM (SEC-1, the WinCI test fixture `_own_write` encoding a lone surrogate without `surrogatepass`) and the two LOWs (SEC-2, SEC-3) are resolved in the tests or routed to backlog. The final GREEN holds on all three arms: RUN-A 122 passed, 75 skipped; RUN-B 54 passed; laws 219 passed, 1 failed. The single law failure is the redaction gate, RED by design until the pre-push sweep. 33 of the 34 applied mutants are killed; M-PASTE.6 is the only survivor and is pending the Windows CI arm. Written 2026-11-07.

**Platform limit.** Every run below is on cachyos-rtx (Linux, Python 3.11.18). The 54 WinCI-only cases (`tests/test_b103_clipboard_windows.py`) and the OS-text / right-click behaviours they prove were not run: they wait for the push (R-PASTE.20).

## Runs (evidence under `inc-1a/evidence-e4/`, `inc-1a/evidence-e5/`)

| Run | Result | Evidence |
|---|---|---|
| E4 integration (implementer + tester, on `e07fb00`) | RUN-A 53 failed, 69 passed, 75 skipped (RED); RUN-B 54 passed; laws 3 failed, 215 passed (RED) | `evidence-e4/int-green-a.txt`, `int-green-b.txt`, `int-green-laws.txt` |
| E4 test-fix pass | RUN-A 4 failed, 118 passed, 75 skipped (3 debounce + 1 workspace right-click); RUN-B 54 passed; laws 1 failed (redaction gate) | `evidence-e4/int-green2-a.txt`, `int-green2-b.txt`, `int-green2-laws.txt` |
| **Final GREEN (test-fix pass complete)** | **RUN-A 122 passed, 75 skipped (plus a 2-passed Xvfb arm); RUN-B 54 passed; laws 219 passed, 1 failed, 1 skipped (the redaction gate)** | `../evidence/inc-1a/fix-green-a.txt`, `../evidence/inc-1a/fix-green-b.txt`, `../evidence/inc-1a/fix-green-laws.txt` |
| Mutants (E5) | 34 applied: 32 killed, 2 survived; +10 rows not realisable (Windows CI pending) | `../evidence/inc-1a/mutant-table.md` |
| M-PASTE.10 re-check | now killed (the test pins the exact WARNING line) | `../evidence/inc-1a/fix-green-mut10.txt` |
| Mutant timing control | RED on the delay mutant (the expected Negative-control outcome) | `../evidence/inc-1a/int-mutant-tcl.txt` |

## Review verdicts

| Review | Verdict |
|---|---|
| Code (DeepSeek) | PASS-WITH-NOTES: 1 HIGH (the `[workspace]` right-click copy never fires), 1 MAJOR (three debounce test faults), 2 INFO |
| Security (DeepSeek) | PASS-WITH-NOTES: 1 MEDIUM (SEC-1 `surrogatepass`), 2 LOW (SEC-2 workflow guard asserts, SEC-3 E3S-25(c) marker), 2 INFO |
| Mutants (DeepSeek) | 34 applied: 32 killed, 2 survived (M-PASTE.10 oracle gap; M-PASTE.6 WinCI-only control) |

E5 rulings (orchestrator): SEC-1 and SEC-2 are fixed in the tests; SEC-3 goes to backlog as BL-I1A-1; SEC-4 (the redaction gate) stays RED until the pre-push sweep; SEC-5 is an accepted residual. M-PASTE.10 is fixed by pinning the exact WARNING text; M-PASTE.6 is recorded `pending Windows CI`. The three debounce failures are a test fault on the 1a side (the tests settle the debounce before teardown) and a product defect outside the slice (BD-1A-1) routed to Inc 12; the workspace right-click failure is fixed through the `needs_project` path.

## Open notes

| Id | Note |
|---|---|
| BD-1A-1 | The A2L filter debounce fires after teardown (`NoMatches '#a2l_tags_list'`). Product defect outside the slice, routed to Inc 12 (guard the refresh when the table is absent, add a case, check against the base code). |
| BL-I1A-1 | SEC-3 LOW backlog: the E3S-25(c) marker is missing (exposure 0 today). |
| Windows CI arms (54) | The 54 WinCI-only cases wait for the push; not run on cachyos-rtx. |
| M-PASTE.6 | The cut's OS write is unobservable on LinuxH; the WinCI arm kills it. Pending the Windows CI run. |
| Redaction gate | RED until the pre-push redaction sweep (expected; the only law failure). |
| AT-I1a-10 / AT-I1a-11 | Operator-run checks: Ctrl+V vs Ctrl+Shift+V and a copy into Notepad (AT-I1a-10); the right-click check in Windows Terminal (AT-I1a-11). |

## Not run

- **Windows:** no run; the 54 WinCI-only cases and the OS-text / right-click behaviours wait for the push (R-PASTE.20).
- **Full test suite:** batch end.
- **AT-I1a-10 / AT-I1a-11:** operator-run (see open notes).

## Models per stage

| Stage | Model |
|---|---|
| E1–E3 design, architect, security | Opus 5.5; corrections DeepSeek v4 Pro |
| E4 implementation, test-fix | DeepSeek v4 Pro (tester) |
| E5 code review, security review, mutants | DeepSeek v4 Pro |
| E5 rulings (orchestration) | Opus 5.5 |

## Evidence in the batch evidence folder (trace_check)

Copies of the decisive transcripts, cited here by their path from this record so the trace checker links them; the originals stay under `inc-1a/evidence-e4/` and `inc-1a/evidence-e5/`:
- `../evidence/inc-1a/fix-green-a.txt` — final RUN-A GREEN (122 passed, 75 skipped).
- `../evidence/inc-1a/fix-green-b.txt` — final RUN-B GREEN (54 passed).
- `../evidence/inc-1a/fix-green-laws.txt` — final laws run (219 passed, 1 failed: the redaction gate).
- `../evidence/inc-1a/fix-green-mut10.txt` — M-PASTE.10 re-check, killed (2 failed).
- `../evidence/inc-1a/mutant-table.md` — 34 applied (32 killed, 2 survived) + 10 not realisable.
- `../evidence/inc-1a/int-mutant-tcl.txt` — the timing mutant control, RED as expected.
