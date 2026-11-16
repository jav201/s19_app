# Inc 9 — validation (E5, X9)

**Verdict: PASS-WITH-NOTES since FX9f (see § Update FX9f at the end); as first written: FAIL** — one MAJOR open: F-X9-2 (R-PE-BENCH.29/2 and .82/1 miss 0.5 s at load < 2 once the timer is not
vacuous). Everything else is green or ruled. Review: `E5-review.md`; captures: `E5-captures.md`, index of facts
`evidence/e5/captures/INDEX-facts.md`, e.g. the refused decode `evidence/e5/captures/x-refused-decode.118x54.png`.

Tree `b103-inc9`: start `811198b5`, X9 commits `8d4b5770` (F-X9-1 instrument + 20/1 mark), `54ee7618` (captures), then
this record. Base `6c4fd21f` (= `git merge-base HEAD b103-inc8`). Runner rtx, bundle clone of `8d4b5770`'s content
(`head` = 811198b5 + the X9 test file), HT-02 env, `s19_app.__file__` = `~/work/zq-x9/head/s19_app/__init__.py` atop every
transcript, `-n 2`, `timeout 300` (900 for slow), timing nodes alone at `-n 0` after a 1-min load < 2.

## Runs (`evidence-e5/transcripts/`)
| Set | Result | Evidence |
|---|---|---|
| `tests/test_b103_inc9_*.py` (12 files, `-m "not serial_timing and not slow"`) | **316 passed**, 0 failed | `battery/c-test_b103_inc9_*.txt` |
| Inc 9 slow, not timing, not 26_2 (26_1, 20_2, 28_2) | **3 passed** | `battery/c-slow.txt` |
| `tests/test_b103_inc8_*.py` (14 files) | **371 passed**, 0 failed | `battery/c-test_b103_inc8_*.txt` |
| Laws: `test_id_registry`, `test_suite_hygiene`, `test_requirements_canon`, `test_address_census`, `test_deps_seam_law`, `test_no_private_tokens`, `test_engine_unchanged` | **117 passed, 3 skipped, 2 failed** — both base-identical (`E4-integration-w.md`): `test_canon_rows_hold_the_obligation_word_once`, `test_at_b83_08_tree_holds_no_assembled_selectors`; the third base law, `r_tst_070_2`, is green (no record spells the runner HOME basename) | `battery/c-laws.txt` |
| 20_1 (`timed_press`, decode held) | **GREEN**, load 1.98 before, 0 under 20 % margin | `battery/t-20_1.txt` |
| 29_1 (`timed_press`) | **GREEN**, load 1.83 before, 0 under 20 % margin | `battery/t-29_1.txt` |
| 29_2, repaired instrument, head | **RED 0.561 s** (load 0.42) | `x5-head-29_2.txt` |
| 29_2, arrival mutant / stall mutant | **RED 0.921 s / 1.299 s** (load 1.06 / 1.11) | `x5-marr-29_2.txt`, `x5-mstall-29_2.txt` |
| 82_1, repaired instrument, head | **RED 1.950 s** (load 0.98); probe: 0.05–0.49 s during the encode, 1.907 s behind the ≈ 1.4 s UI-thread record stage | `x5-head-82_1.txt`, `x5-probe82.txt` |
| 29_2 with FX9's `handled_press` + arrival mutant | **GREEN** — the vacuous timer (F-X9-1) | `m292-arrival.txt` |
| 26_2 | not re-run; FX9 GREEN 439 s at load 1.17 cited (`E4-fixes-fx9.md`) | — |

First instrument attempt (keys every 0.1 s from a thread, `x3-*.txt`, `x4-probe.txt`) measured queueing behind earlier keys
(up to 1.06 s from the flood alone) and was replaced by one key in flight; those runs are kept as the record of why.

## Mutant score
MW9: 91 mutants, 87 killed, 4 argued equivalent (accepted, `E5-review.md`). X9 adds 2 controls on the repaired 29_2: the
arrival stand-in (survived FX9's timer, RED now) and FX9's stall mutant (RED).

## Review verdicts
| Item | Provisional verdict |
|---|---|
| F-X9-1 MAJOR (timer vacuous for the arrival case) | fixed test-side, controls RED |
| F-X9-2 MAJOR (product misses .29/2, .82/1) | **open → orchestrator** |
| F-X9-3 … F-X9-9 MINOR | PENDING (`E5-review.md`) |
| F-I9b-1 | accepted |
| F-FX9-1 | "handling" is the measure, not the first frame; the helper was vacuous → F-X9-1 |
| F-FX9-2 | MINOR, 20/1 mark → partial |

**Provisional, awaiting the operator's confirmation on the final page (P-059):** V-1 keep · V-2 change (F-X9-5) · V-3 keep ·
V-4 keep · V-5 change (F-X9-6) · V-6 keep · V-7 keep · V-8 keep · V-9 keep (wording F-X9-7) · V-10 keep · V-11 keep ·
V-12 keep · V-13 keep · V-14 change (F-X9-8) · Inc 8 V-13 keep · **W-8 change** (`✗ refused: <message>` in place of the
decoding line, F-X9-4) · D-2 A, D-3 A, D-6 A, D-7 A, D-9 A keep (captures V-7, V-12, V-4, V-8) · C9's chart / ramp look keep.

## trace_check (from the repo root, before this record existed)
```
$ python ~/.claude/skills/dev-flow/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md --base 6c4fd21f --src s19_app
EVID   no 04-validation.md beside .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md
trace_check: 1 US, 82 active requirements (1 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 1 gap(s)
```
After this record (same command, re-run):
```
trace_check: 1 US, 82 active requirements (1 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 0 gap(s)
```
The SLICE gap for `definition_sheet.py` named in the brief does not
appear with base `6c4fd21f` (Inc 8's file is in the base); ruled: Inc 8's, none for Inc 9.

## Not run
R-PE-BENCH.14's "no image" capture; 26_2 re-run; a lower-load repeat of 29_2 (rtx shared with MU7); a full re-check of all
189 case marks (timing and refusal rows only).

## Re-check X9r (relevo-14) — after FX9b, FX9c, FX9d

**Verdict: FAIL** — F-X9-2 pending the operator (O-A separate process for the encode, O-E stepped shared refresh, or
accept / relax the bound; none applied), plus **F-X9r-2 MAJOR open** (Inc 9 turns `test_tui_patch_json.py::
test_tc079_5c_hue_census_is_complete` RED; GREEN on the pre-Inc-9 base). Review: `E5-review.md` § Re-check X9r.
Tree `b103-inc9` at `ab62093b` (code head) + X9r records; runner rtx, real `git clone`s of a bundle of `b103-inc9` + `main`,
HT-02 env, `s19_app.__file__` = `~/work/zq-x9r/<tree>/s19_app/__init__.py` atop every transcript. Evidence
`evidence-e5/x9r/` (`transcripts/chain-log.txt` is the run log; scripts in `scripts/`).

| Set | Result | Evidence |
|---|---|---|
| 29_1 (alone, `-n 0`) | **GREEN** 0.169 s (66.1 % margin), 1-min load 0.29 before | `t-29_1.txt` |
| 29_2 | **RED** slowest press 0.543 s, load 1.08 | `t-29_2.txt` |
| 82_1 | **RED** slowest press 0.937 s, load 1.06 | `t-82_1.txt` |
| 20_1 | **GREEN** 0.142 s (71.6 % margin), load 0.99 | `t-20_1.txt` |
| `tests/test_b103_inc9_*.py` (13 files, `-m "not serial_timing and not slow"`) | **323 passed**, 0 failed | `c-test_b103_inc9_*.txt` |
| Inc 9 slow, not timing (26_1, 26_2, 20_2, 28_2) | **4 passed** (657 s) | `c-inc9-slow.txt` |
| `tests/test_b103_inc8_*.py` (14 files) | **371 passed**, 0 failed | `c-test_b103_inc8_*.txt` |
| Laws (`id_registry` 12, `suite_hygiene` 67, `requirements_canon` 10 + 1F, `address_census` 22 + 1F, `deps_seam_law` 6, `no_private_tokens` 2, `engine_unchanged` 1) | **120 passed, 2 failed** — the two base-identical: `test_canon_rows_hold_the_obligation_word_once`, `test_at_b83_08_tree_holds_no_assembled_selectors`; `r_tst_070_2` green | `c-test_*.txt` |
| FX9b nodes on `4c891ea9` product + head tests | **8 failed** (RED as claimed) | `b-fx9b-red.txt` |
| FX9d O-B nodes on `b21d5517` product | **1 failed** (`test_ob_1`), 1 passed | `b-fx9d-red.txt` |
| O-C equality probe `card_diff.py` | head = FX9c's pre-O-C digests (md5 equal); mutants `oc1` 395 / `oc2` 554 of 3,001 differ | `cd-*.txt` |
| O-C mutant `oc1` vs `test_tui_patch_card.py` | survives (1 failed = the pre-existing purity probe) — F-X9r-3 | `b-moc1-card.txt` |
| O-D mutants | `od1` RED (`w_stage` 15/16/18); `od2` survives 112 nodes — F-X9r-3 | `b-mod1.txt`, `b-mod2.txt` |
| History strip on real clones with `main` | head, `b21d5517`, `16b00234`, `6c4fd21f`: each 1 failed (`tc081_2`), 7 passed — FX9d's claim upheld | `d-hs-*.txt` |
| FX9c's 28 user failures vs `6c4fd21f` (10 files, same runner) | 27 identical on all three trees; `tui_patch_json` +1 on Inc 9 = F-X9r-2 | `d-*.txt`, `f-*.txt` |

Captures (HT-10): 11 real Windows Terminal PNGs `evidence/e5/captures/r-*` — V-2 keep at 118, change at 220 (F-X9r-1,
MINOR); V-5 keep; W-8 keep; O-B JSON view keep (visible change: no bracket-match highlight in the read-only view;
control `r-ob-json-pre-fx9d`). Provisional, awaiting the operator's confirmation on the final page (P-059).

MINOR for PENDING: F-X9r-1 (strip width from a pre-layout width at 220), F-X9r-3 (O-C/O-D guards without suite nodes),
F-X9r-4 (FX9c's purity-probe attribution is wrong: same failure on `6c4fd21f`, which has no `bench_sheet.py`).

Record change: `01-requirements.md` R-PE-BENCH.82's trace column now names FX9c's `screens_directionb/shared.py`,
`patch_editor/entries.py` and FX9d's `patch_editor/document.py` (F-X9-2 record-stage block), so SLICE traces them.

### trace_check (from the repo root)
Before the trace-column edit:
```
$ python ~/.claude/skills/dev-flow/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md --base 6c4fd21f --src s19_app
SLICE  s19_app/tui/screens_directionb/patch_editor/document.py changed since 6c4fd21f and no requirement file names it
SLICE  s19_app/tui/screens_directionb/patch_editor/entries.py changed since 6c4fd21f and no requirement file names it
SLICE  s19_app/tui/screens_directionb/shared.py changed since 6c4fd21f and no requirement file names it
trace_check: 1 US, 82 active requirements (1 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 3 gap(s)
```
After:
```
$ python ~/.claude/skills/dev-flow/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md --base 6c4fd21f --src s19_app
trace_check: 1 US, 82 active requirements (1 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 0 gap(s)
```

Not run: mutant `od3` (argued); a second run per timing node; `test_b97_width`.

## Update FX9f (relevo-14) — F-X9-2 closed by operator decision

**Verdict: PASS-WITH-NOTES.** Supersedes the FAIL of the X9 and X9r sections above: F-X9-2 is closed by the operator's decision
(2026-11-14, "Relaja el límite pero deja en el backlog el item"; `s19-PENDING.md` P-125/P-126, review-page item F-X9-2) and F-X9r-2
by FX9e. Record change: R-PE-BENCH.29's row states the exception narrowly (while a preview or a record-stage encode of an object of
more than 4,096 elements is running, 1.0 s instead of 0.5 s) and the cases .29/2 and .82/1 carry 1.0 s in `01-requirements.md` and
`02-test-cases.md`; the test constant is `RELAXED_KEY_LIMIT_S = timing_bound(1.0)`, used by those two nodes only (29_1 and 20_1 keep
0.5 s); the two test ids were renamed `...within_half_a_second` -> `...within_one_second` (`02-test-cases.md`, `02-test-cases-W.md`
follow). Tree `b103-inc9` `f60f1dc5`; runner rtx, fresh clone of a bundle, HT-02 env; transcripts `evidence-e5/fx9f/transcripts/`.

| Set | Result | Evidence |
|---|---|---|
| 29_1 (alone, `-n 0`) | **GREEN** 0.173 s / 0.5 s (65.5 %), load 0.19 | `t-29_1.txt` |
| 29_2 | **GREEN** 0.475 s / 1.0 s (52.5 %), load 0.76 | `t-29_2.txt` |
| 82_1 | **GREEN** 0.916 s / 1.0 s, **LOW margin 8.4 %**, load 0.94 | `t-82_1.txt` |
| 20_1 | **GREEN** 0.145 s / 0.5 s (71.1 %), load 0.98 | `t-20_1.txt` |
| Control: paint stall 0.8 s | 29_2 **RED** 1.139 s, 82_1 **RED** 1.807 s | `t-mp08-*.txt` |
| Control: paint stall 1.3 s | 29_2 **RED** 1.670 s, 82_1 **RED** 2.282 s | `t-mp13-*.txt` |
| Control: arrival stall 1.3 s | 29_2 **RED** 1.441 s | `t-ma13-29_2.txt` |
| `tests/test_b103_inc9_*.py` (13 files, not timing, slow included) | **327 passed**, 0 failed | `battery-log.txt` |
| `tests/test_b103_inc8_*.py` (14 files) | **371 passed**, 0 failed | `battery-log.txt` |
| Laws (7 files) | **120 passed, 2 failed** - the two known base failures: `test_canon_rows_hold_the_obligation_word_once`, `test_at_b83_08_tree_holds_no_assembled_selectors` | `battery-log.txt` |

Notes kept: 82_1 passes with an 8.4 % margin (earlier runs 0.937 / 0.988 s) and can flake on a loaded host; O-A (encode in a
separate process) and O-E (stepped shared refresh) stay in the backlog; MINOR F-X9r-1, F-X9r-3, F-X9r-4, F-X9-3 ... F-X9-9 as in
`E5-review.md`. The provisional verdicts of the review page (P-059) stand as listed above.

### trace_check (from the repo root, after the edits)
```
$ python ~/.claude/skills/dev-flow/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md --base 6c4fd21f --src s19_app
trace_check: 1 US, 82 active requirements (1 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 0 gap(s)
```
