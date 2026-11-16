# Inc 9b — validation (E5)

**Verdict: PASS-WITH-NOTES.** No BLOCKER/MAJOR is open. MINOR/backlog items are BL-9b-1…5, O-A and the inherited/base-identical residuals listed in `E5-review.md`.

- Base: `e4485817d7ac3706c77f14a4c2a8cf784fe35038`; E5 start: `3194ccea0840ad22bd12530157c6cabaa123d1ce`.
- Final exact test clone: `6a8cfb0a9bb64b95dd9969fb08e05ae85c1bd6b4`; final captured product archive: `d05b5180e5f48d4a167d13e7fb45b24586293eb6`. CAP9b evidence commit: `05314689ae09643f5e84d8d177251cf01a10cad8`.
- Reviewer X9b, one pass. All E5 fixes and commits/paths are itemized in `E5-review.md`.

## Runs

All pytest runs used Linux rtx, HT-02 isolation, UTF-8, no bytecode/cache, closed stdin, `timeout 300`, full HEAD and imported `s19_app.__file__`; W/S/AT used `-n 0`, with each AT in its own process. Laws used `-n 2` per file after the combined run's 300 s timeout. No dirty overlay is used for final evidence.

| run | exact tree / result | evidence |
|---|---|---|
| Unicode RED → GREEN | `f1161ee7`: 2 RED; `d05b5180`: 6 PASS | `evidence/e5/runs/red-unicode.txt`, `green-unicode.txt` |
| HOLD-MOUNT RED/GREEN | `0acff83a`: baseline 1 PASS; double-super 1 RED | `evidence/e5/runs/control-hold-mount.txt` |
| HOLD-APPLY caller / equivalence | `8539c371`: product 1 PASS; stated control 1 PASS (equivalent); no-hook control 1 RED | `evidence/e5/runs/control-hold-apply.txt` |
| HOLD-LOAD RED/GREEN | `a211b3d6`: product 1 PASS; early-return 1 RED | `evidence/e5/runs/control-hold-load.txt` |
| Residual M9b controls | `a211b3d6`: N-98b RED; N-97b valid-sync RED; I-LATER-RAISE valid RED; I-CHAIN-99 RED; N-99 later-stall not a kill | `evidence/e5/runs/control-m9b-residuals.txt` |
| Corrected .99 / CHAIN scheduler | `a211b3d6`: serialize-stall .99 RED 1.585 s (quiet preflight 0.13); scheduler RED on chain | `evidence/e5/runs/control-corrected.txt` |
| Strengthened .98/.102 controls | `bf486a9d`: title-once RED; real-key baseline PASS; active-job RED | `evidence/e5/runs/control-oracles.txt` |
| Final collection | `6a8cfb0a`: **45 new nodes collected** (W25/S10/AT10); law+caller collection 463 | `evidence/e5/runs/final/collect-new.txt`, `collect-laws.txt` |
| Final W / S | `6a8cfb0a`: **W 25/25 PASS; S 10/10 PASS** | `evidence/e5/runs/final/final-w.txt`, `final-s.txt` |
| Final AT | `6a8cfb0a`: **10/10 PASS**, ten separate processes | `evidence/e5/runs/final/final-at-*.txt` |
| Hue/caller | `6a8cfb0a`: 14 PASS + inherited `ac1/ac3/ac5` FAIL | `evidence/e5/runs/final/final-patch-json.txt` |
| Law guards, base/final | Each exact clone: 13 files, **440 PASS / 3 FAIL / 3 SKIP**; identical failed nodes, no new law failure | `evidence/e5/runs/final/laws/`; combined timeout transcripts `final-laws.txt`, `base-laws.txt` are not completed results |
| CAP9b | `d05b5180`: **22 sequences, 54 PNG + 54 sidecars PASS**, all opened | `E5-captures.md`, `evidence/e5/captures/`, `evidence/e5/runs/capture-validation.txt` |

## Mutants, captures and Q9b

M9b original score remains **19/26 runnable controls KILLED (73.1%)**: 1 SURVIVED, 2 CRASH, 4 BAD; **43 arms = 35 KILLED, 2 SURVIVED, 2 CRASH, 4 BAD**, plus 3 MISSING. Every non-kill is ruled in `E5-review.md`: N-95b equivalent by caller census; N-101a `.101/5` arm non-discriminating by stale early return; CRASH controls corrected to valid mutations; BAD controls split per process; HOLD-APPLY/LOAD/MOUNT now have named executed oracles. No BAD/CRASH is relabelled KILLED.

All 22 busy sequences have distinct next-spinner frames, same job/name and nondecreasing seconds; ten idle frames restore title/border. Hostile markup/brackets/ESC/C1, long cuts (6/46/130 `N` + `…`) and short `N` pass. Both stage-refresh sequences show write-landed BUSY and one later callback. Final lock absent and scratch removed. Three orphan windows from failed attempts remain with dead recorded PIDs; no shared host/title kill was used (`E5-captures.md`).

**Q9b not rerun.** Its 35/35 timing runs passed. `.98/1` maximum-gap worst `.470 s` against `.500 s` leaves only **5.9%** margin; `.97/1` has five assertion passes but no QC-TM margin. Corrected write+refresh block is `1.146 s`; `.29/2` and `.82/1` retain their approved 1.0 s bounds.

## Not run

No full repository suite or snapshot regeneration (batch-end/canonical CI scope); no Q9b/gap/O-E/FX9c/timing distribution; no inherited `w_jobs 26_2` rerun (existing base/product 300 s timeouts); no push. Capture verdicts remain subject to the operator's visible-decision rule.

## trace_check

```text
$ python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-9b/01-requirements.md --base e4485817 --src s19_app
trace_check: 1 US, 13 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 0 gap(s)
```
