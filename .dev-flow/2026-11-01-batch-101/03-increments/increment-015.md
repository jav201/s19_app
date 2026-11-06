# Increment 015 — Inc 15 · R-TST-150…164 · Windows-only test failures: waits through the shared settled helper instead of a single pause

| Field | Value |
|---|---|
| Batch | 2026-11-01-batch-101 |
| Increment | 015 |
| Lane (if the batch forked) | — (no fork) |
| Requirement(s) | R-TST-150 … R-TST-164 (stories US-TST-15, US-TST-16) |
| Acceptance | the 28 cases of `02-test-cases.md` (14 normal, 14 robustness); black-box by keys/holds: R-TST-150/2, 151/2, 152/2, 153/2, 159/2, 160/2, 161/2, 161/3, 162/2, 162/3, 164/1 · white-box: the four changed arms + the static guard node + the R-TST-158 conventions parameter · unit: none (0 product functions change) |
| Agent | `software-dev` |
| Date | 2026-11-06 |

Models per stage (from `steps.log`): Opus — E1 diagnosis, E3 (round 1, correction, round 2), the E4 integration step, the E5 code review, and the E5 corrective pass; DeepSeek v4 Pro — the E4 test edits (1 unit) and this record; qa-reviewer (Opus) — the E5 coverage audit and re-audit.

---

## 1 · What changed

The four Patch Editor / Flow Execution arms that failed on the Windows host now wait for the app to handle a press, a value set or a posted action before they read the state it left — through the shared `tests.b97_probes.settled` helper, never through a single `pilot.pause()`. The defect was a one-pause read: on the Windows host `pilot.pause()` can return before the press is handled (Textual 8.2.8 ends the pause when `time.process_time()` advances by less than 1 ms, and on Windows that clock steps 15.625 ms), so the arm read the state from before the handler ran. Nine waits (D1 … D9, table D of `01-requirements.md`) replace the single pauses: D1/D2 in `test_tc331_disable_guard_predicate_tracks_source_path`, D3/D4/D9 in `test_tc_b94_27_lane_binding_isolation_and_noop`, D5 in `test_at030c_directly_dropped_file_is_listed_and_loadable`, D6/D7/D8 in `test_save_back_prompt`. A new static test in `tests/test_suite_hygiene.py` pins each site's description, predicate, position and shared-wait binding, and the handled-press rule joins `docs/engineering-rules.md` as rule 7 (R-TST-158). **0 files under `s19_app/` change** — the diagnosis found no product defect.

## 2 · Files modified

Committed: `git diff --stat main...HEAD` (224 files, +13 623 / −12). Uncommitted at close: `04-validation.md` and this packet. SOURCE files: **0 / 4**.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `tests/test_tui_patch_editor_v2.py` | test | US-TST-15, US-TST-16 | waits D1, D2 (TC-331), D5 (AT-030c), D6/D7/D8 (save-back); `from tests.b97_probes import settled`; docstrings cite their R-TST ids |
| `tests/test_tui_flow_execution_b94.py` | test | US-TST-15, US-TST-16 | the bind-step call recorder + waits D3, D4, D9; lane B's paint read off the compositor (`painted_rows`, C-6); `from tests.b97_probes import settled` |
| `tests/test_suite_hygiene.py` | test | US-TST-15, US-TST-16 | new test `test_r_tst_154_155_inc15_arms_wait_through_settled` (the 9-site AST guard) + `_CONVENTION_RULES["R-TST-158"]` + the parametrize entry + the `settled`-binding check |
| `docs/engineering-rules.md` | doc |  | "Six rules" → "Seven rules"; rule 7 (Handled press) with the R-TST-158 sentence verbatim and its Origin line |
| `.dev-flow/2026-11-01-batch-101/inc-15/01-requirements.md` | doc |  | EARS requirements R-TST-150 … R-TST-164 (15 rows) + Definitions (one-pause read, handled press, shared wait, Windows host, held-handler probe, table D) + US-TST-15, US-TST-16 |
| `.dev-flow/2026-11-01-batch-101/inc-15/02-test-cases.md` | doc |  | 28 ISO 29119-3 cases over 15 requirements; marks moved to the audited values at E5 and re-audited (RA-1, RA-2) |
| `.dev-flow/2026-11-01-batch-101/inc-15/E1-rulings.md` | doc |  | E1 cause, scope and decisions D-1 … D-6 + orchestrator rulings + the E3/E5 folds (C-3, C-4, C-5) |
| `.dev-flow/2026-11-01-batch-101/inc-15/E1-slice.md` | doc |  | E1 implementation slice: every file and function to change, counted and mapped; 0 source files |
| `.dev-flow/2026-11-01-batch-101/inc-15/E3-architect.md` | doc |  | E3 design review: round 1 FAIL (1 HIGH, 2 MAJOR, 7 MINOR) → round 2 PASS-WITH-NOTES |
| `.dev-flow/2026-11-01-batch-101/inc-15/E3-rulings.md` | doc |  | E3 rulings F1 … F10 and the round-2 scope |
| `.dev-flow/2026-11-01-batch-101/inc-15/E4-impl-notes.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, 1 unit): the tests-only edits, 0 deviations |
| `.dev-flow/2026-11-01-batch-101/inc-15/E4-integration-notes.md` | doc |  | E4 integration (Opus): GREEN for the right reasons; the `77f4553` guard fix; holds/mutants/controls; Windows 80/80 |
| `.dev-flow/2026-11-01-batch-101/inc-15/E5-code-review.md` | doc |  | E5 code review: PASS-WITH-NOTES (security lens carried; no separate security reviewer) |
| `.dev-flow/2026-11-01-batch-101/inc-15/E5-corrective-notes.md` | doc |  | E5 corrective pass C-1 … C-10 (tests and records only): D9, the predicate pins, the `_wait_for` ban, the runs |
| `.dev-flow/2026-11-01-batch-101/inc-15/E5-coverage-audit.md` | doc |  | E5 coverage audit (26 cases, 11.5 % departures) + the re-audit (RA-1, RA-2) |
| `.dev-flow/2026-11-01-batch-101/inc-15/E5-rulings.md` | doc |  | E5 rulings C-1 … C-10 and the re-audit rulings RA-1 … RA-3 |
| `.dev-flow/2026-11-01-batch-101/inc-15/codewire/graph-inc15.md` | doc |  | Code-Wire graph: not applicable (tests-only), the E2 skip record (F10) |
| `.dev-flow/2026-11-01-batch-101/inc-15/steps.log` | doc |  | Stage log, models and UTC stamps (E5 end appended at close) |
| `.dev-flow/2026-11-01-batch-101/inc-15/04-validation.md` | doc |  | This increment's validation record (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-015.md` | doc |  | This packet (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-15/evidence-e1/` probes + `lin/` + `win/` transcripts | generated | US-TST-15, US-TST-16 | E1 diagnosis evidence: the clock probe, 20 Windows runs + traces, 14 Linux runs, the 4 held-handler reproductions, the 7 run/guard/clock probes |
| `.dev-flow/2026-11-01-batch-101/inc-15/evidence-e3/` probes + `lin/` transcripts | generated | US-TST-15, US-TST-16 | E3-correction hold runs (10 base-form RED halves) + the probes and the census script |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-15/int-01.txt` … `int-66.txt`, `int-70.txt` … `int-89.txt`, `int-index-{linux,windows}.txt` | generated | US-TST-15, US-TST-16 | E4 integration runs (LAN Linux int-01 … 66; Windows int-70 … 89) and their indexes |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-01.txt` … `e5c-27.txt`, `e5c-31.txt` … `e5c-50.txt`, `e5c-index-{linux,windows}.txt` | generated | US-TST-15, US-TST-16 | E5 corrective runs (LAN Linux e5c-01 … 27; Windows e5c-31 … 50) and their indexes |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-15/probes/` (11 files) | generated | US-TST-15, US-TST-16 | the E4/E5 run guards, battery scripts and mutator/unparse plugins (`i15int-*`, `i15c-e5-*`, `i15c_e5_*`) |

| Count | Value |
|---|---|
| **SOURCE files** | **0 / 4** |
| Test files | 3 (0 new files; 4 changed test functions, 1 new test function, 1 new parametrize entry) |
| Doc files | 1 product doc + 16 record files (outside the count) |
| Config files | 0 |
| Generated | 4 indexes + 11 probes + 180 transcripts under the three evidence homes |

The increment changes no source file, so it cannot be cut smaller: the subject is the test suite, not the product.

## 3 · How to test

```bash
# the four nodes, serial (LAN Linux host, s19ci Python 3.11.18)
python -m pytest -p i15c_e5_guard -p no:cacheprovider -v \
  tests/test_tui_patch_editor_v2.py::test_tc331_disable_guard_predicate_tracks_source_path \
  tests/test_tui_patch_editor_v2.py::test_at030c_directly_dropped_file_is_listed_and_loadable \
  tests/test_tui_patch_editor_v2.py::test_save_back_prompt \
  tests/test_tui_flow_execution_b94.py::test_tc_b94_27_lane_binding_isolation_and_noop
# the static guard + the R-TST-158 conventions parameter
python -m pytest -p i15c_e5_guard -p no:cacheprovider -v \
  tests/test_suite_hygiene.py::test_r_tst_154_155_inc15_arms_wait_through_settled \
  tests/test_suite_hygiene.py::test_r_tst_007_conventions_hold_each_test_rule
# the three changed test files in the release gate's parallel lane flags
python -m pytest -p i15c_e5_guard -p no:cacheprovider -n 8 -m "not serial_timing" \
  tests/test_tui_patch_editor_v2.py tests/test_tui_flow_execution_b94.py tests/test_suite_hygiene.py
# the Windows serial runs (isolation rules of E1-rulings.md §6)
bash .dev-flow/2026-11-01-batch-101/evidence/inc-15/probes/i15c-e5-win.sh
```

The hold/mutant/never-settle/guard-control runs are the `I15_HOLD` / `I15_NEVER` / mutator battery in `E4-integration-notes.md` §2 and `E5-corrective-notes.md` §3, all on the LAN Linux host in copies of the tree.

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | none — 0 product functions change | n/a |
| **A · white-box** the four arms + the static guard | `core` · `full` | 4 changed arms (names kept) + 1 new guard node + the R-TST-158 parameter | 129 passed in `e5c-01` (parallel, `-n 8`); 12/12 serial in `e5c-03…05`; 8 passed (guard + conventions) in `e5c-06` |
| **B · black-box** holds, mutants, never-settle, Windows serial | `core` · `full` | the 28 cases | 27 `covered` + 1 `partial` (R-TST-157/2); 28 `verified`, 0 `failed`, 0 `not_run` |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | each arm's base form (one `pilot.pause()` at the guarded read, the `c2cba35` form) under its own held-handler probe — the handler runs 1.5 s late, so the single pause ends first |
| Instrument | the held-handler probes `i15int_guard.py` / `i15c_e5_guard.py` (a `-p` plugin; no file in the tree changes) |
| Where it ran | the LAN Linux host, in copies of the worktree (never the branch) |
| Transcript | int-09/10, 14/15, 19/20, 24/25, 29/30, 34/35, 39/40 and e5c-10/11; E3 base halves `evidence-e3/lin/i15c-hold-{paste,select,apply,decline,confirm}-*.txt` |
| Restore proven by | n/a — the RED ran on base-form copies, not a mutated branch file |
| Bytecode cache | n/a (no branch file was mutated) |
| Arms resolved at baseline | 4 node ids (names kept) + 1 new guard node + the R-TST-158 parameter |
| Verdict granularity | per node id in each transcript |
| Arms that stayed GREEN | none of the guarded reads — each base form went RED at the read its wait guards |

| Field | Value |
|---|---|
| **RED counterfactual** | the base (one-pause) form under each hold made the guarded read fail: D1 load step, D2 paste step, D4 `assert {} == {0: 'variant_b.hex'}`, D5 `got -0x1`, D6 `AttributeError … 'saved_path'`, D7 `prompt_hidden_after_decline`, D8 `traversal_path is not None`, D9 `KeyError: 'base_2'` |

| Field | Value |
|---|---|
| **Mutation verdicts** | 6 product mutants (in tree copies, never the branch) each KILLED at the assertion its row names: R-TST-150 (b) int-41, 151 (b) int-42, 153 (b) int-43 + e5c-15, 152 (same-ref early return removed + `fx_bind`) int-44/45 + e5c-16, 161 (b) int-46/47, 162 (b, Linux only) int-48/49. Plus 12 static-guard controls, each RED: int-58 … 63 (D1 removed/moved, f-string, changed text, range loop, local `settled`) and e5c-20 … 24 (predicate → `lambda: True`, swapped predicate, `_wait_for`, `_confirm_with` renamed with 0 skipped, D9 removed); the pre-fix guard stays GREEN on the same edits (int-64, e5c-25/26), which is the hole each fix closes |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the held-handler probes | each base (one-pause) form under its hold | each RED at the guarded read (int-09 … 40, e5c-10/11; E3 base halves) |
| the static guard | a removed/moved/f-string/changed/looped/local `settled`/wrong-predicate/`_wait_for`/renamed-helper site | each RED, naming its site (int-58 … 63, e5c-20 … 24) |
| the mutant harness | 6 product mutants | each RED at the targeted assertion (int-41 … 49, e5c-15/16) |
| the coverage audit | the 26 E1/E3 case marks | 3 of 26 (11.5 %) departures found (`E5-coverage-audit.md`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments (held-handler probes, the static guard, the mutant harness, the coverage audit), each shown RED before its PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| lane B's painted cards (the rendered widget) | `painted_rows` over the compositor, cropped to lane B's scroll-area region, holds `base.s19` and not `variant_b.hex` (C-6; reads the painted text, not the `lane_paint_plain` seam) | GREEN 3/3 (`e5c-03…05`) and 20/20 Windows (`e5c-31…50`) |
| the wait's failure text | each never-settling site fails with `did not settle: <its table-D description>` (R-TST-154/2) | 8/8 at `77f4553` (int-50 … 57) + 3/3 on the changed arm (e5c-17 … 19), each text verbatim |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 2 artifacts (the painted lane-B cards; the wait's `did not settle:` text), each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-06. Homes: `.dev-flow/2026-11-01-batch-101/evidence/inc-15/`, `.dev-flow/2026-11-01-batch-101/inc-15/evidence-e1/`, `.dev-flow/2026-11-01-batch-101/inc-15/evidence-e3/`.

| Evidence artifact | Path (repo-relative) | SHA-256 |
|---|---|---|
| e5c-01.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-01.txt | 2aa3f37577394178da0dbccf331d11f9c4fbc7d20d831c1f57d9cbde8de4cef2 |
| e5c-02.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-02.txt | 94c9ceb7685570f34adc4fe63f68bc49773113121e77025d5ed5e3a639b78990 |
| e5c-03.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-03.txt | 121a764836230d3efa6d61c7e8999261ea0eb2062f1cd4338d4877550a9c442c |
| e5c-04.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-04.txt | e30eefee54562f71dafd18a959963602a7237464dbf1ba27f4c6bdd24009361c |
| e5c-05.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-05.txt | 594906e5b8910b96a9ca936cbaca1a1b303928164ba9ecc7d7d249366d7b3ea5 |
| e5c-06.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-06.txt | e5cb25918c20a7ebd94e378a278e7fe67ffc4dbac94a68c13cc8a9520ddc753a |
| e5c-07.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-07.txt | 9b9cb3cef6429131ef7c3e525050735045977049f959ede0b8381f383098b05a |
| e5c-08.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-08.txt | 21ff8093a5aeb46f463b4a00bc2ca09e6fccbfef22d6e481ee7482c0d738ae2d |
| e5c-09.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-09.txt | 81cf3b531e48b6a3f7fb59e7ca1f1bae20bf8e4c64272049c91f672fc16543ae |
| e5c-10.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-10.txt | 3c712759e636901d3403cce2e25ad7019ece8e5ab4f810574445cf62a2ef8a57 |
| e5c-11.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-11.txt | 4ee06b37f488e5f08dc7d4a052415df8fa7ada679058bfb68982870553b9fa7c |
| e5c-12.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-12.txt | c5c5f8aca308da9df4d5eb1e878ebebcd0db9a6493d8860eb85d41b3435c02dd |
| e5c-13.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-13.txt | f6137dc5c34b9b633a19261382dc10111a6edb68e6f2a4724f755a373d078884 |
| e5c-14.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-14.txt | 4de25bf1a33f15d1ced49cdbf332ee0a4551e6d339fe55a989f331fb545be0c9 |
| e5c-15.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-15.txt | 865047a7c13ed6c6ca21f13afda08864a2cdc51ffeefd9c4e0804f68e91939d3 |
| e5c-16.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-16.txt | 3b234c5f02013ca124856129ce49a003d095c2c1dc6d5a16346f05149cea8dcc |
| e5c-17.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-17.txt | fae147fa91041f89cf2841cf1c3366d05325668b68b2a988fab74a261884aa5a |
| e5c-18.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-18.txt | 8ce510ae7738aefa8e9664dcb651faf1ea93500436d244476af8e159672f9928 |
| e5c-19.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-19.txt | a70a1e398d24f4c94587e04f5e57e931ead680af611b76017ef301fcbf9c26b5 |
| e5c-20.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-20.txt | a1479441b4a0bad8836a1d607e180afc0a6d838be67ef829ee2971867f178fda |
| e5c-21.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-21.txt | 95d30efd8bbdfb2a9b4eed56e879dda536900a3b89fb14c6e9d2f3b5aa42d6cc |
| e5c-22.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-22.txt | 448f11f36f13cc96b5e1cead296bef5bcfedf3e23b39f59d88b6181b5d226271 |
| e5c-23.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-23.txt | c618cefd62cffebd1e4732a25124cb4b508fa8ca89c43d2db89dc51850d69a0c |
| e5c-24.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-24.txt | bf2ef9380a31c6f395468392b1cec7a9a3ca336f4c646f1ca15397280ee1c262 |
| e5c-25.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-25.txt | 965326288f99cb688db8c77819fd552c11d9f2b3b194ace1f0ce01bbca6b62a4 |
| e5c-26.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-26.txt | 3366f0040390619ca047a166d94cd7f12b0b7de69c6894711c196ba3f4fa8f05 |
| e5c-27.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-27.txt | 3d5445cc09e9869ec7d93a55a0c6c3c8fbdf5966c1f85b415b68dcfc3744da88 |
| e5c-31.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-31.txt | d1f18ac0e6ae915af5edb548c29c320af42cc3484d12b9e6e136b2c1d9ece972 |
| e5c-32.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-32.txt | a4ea0397c537e3a73633094123f2b508486772d2eeccb3e0db603635e1352fae |
| e5c-33.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-33.txt | 4830494406c9be10f5d9df0888c4de63faaa541dd0eb7ad4c2c194eabeeefd80 |
| e5c-34.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-34.txt | d27fc973a002165d1dd1bab12a6906241d7786f9aae50e94b6ae0aeb5a60b2eb |
| e5c-35.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-35.txt | e7d256be22991da361e2d13df0b1892dde55118095efd3470c6500ce1b0f99db |
| e5c-36.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-36.txt | 0d5a0041c99d2d277cc682a3e14fe96aeb74ae70d8654492e6f3b24aaf42b696 |
| e5c-37.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-37.txt | 0c63f38393f1c923ad1f864447c48f3caad01b92f2a4cfd45df8a3fbd2f92822 |
| e5c-38.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-38.txt | 36aea550e97e3119a6c46684cb8ee21668081f4e691fd84cb761358f3e1242da |
| e5c-39.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-39.txt | 118b1a3e520faf0121dd483bc77e30cdf0db7ab1ab38ed763623377e5a895312 |
| e5c-40.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-40.txt | 4a832fdf637b87f9aa9898d37a5eaf8667038aec775b95e46773d0d2e5b92e24 |
| e5c-41.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-41.txt | f02ece5ec6a727069bee8df2cdaae0e2b75e2a627d07d9e1eb6295fd3920b1c2 |
| e5c-42.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-42.txt | f845ed49907fcb230b25809741474289e47dcf309c85c003465d4f507621aee3 |
| e5c-43.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-43.txt | 1ca6dad171bc6a1fc99a7c891527f5def8c45665edf3dbc95063aa4546b588a8 |
| e5c-44.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-44.txt | 05082fc31bfc0fed61c2547474f3830d0ff8be9a601037f6acfe3963643b84f0 |
| e5c-45.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-45.txt | e5af937d6382b762176ef29dee6dc52cd921a24523b88bf1aa1adc95784f55b9 |
| e5c-46.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-46.txt | f13f34e2a87a189bf1e488e534fdfd80e683c41b74ca9655d7648caee6589c41 |
| e5c-47.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-47.txt | 9377ea254a014a724568d4fc4907434d34ae021765b536bbbaa4086b64ac682e |
| e5c-48.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-48.txt | d41100756f0d44940120ac7cb2cd24082c8eefc85165a58cf8b91121f604b4a0 |
| e5c-49.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-49.txt | a7e2243623a2d8b96367bb4717bd80932491075223b19804056e018c18547558 |
| e5c-50.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-50.txt | 0fad7e9cbd3ea0e0ec38768e89b77490caa12712b9b4037a7d8c716ae82bec48 |
| e5c-index-linux.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-index-linux.txt | 95af67d6102c81f7bb2839cd0919f5e83d02a353dd2c662893bb0cc65237c43d |
| e5c-index-windows.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/e5c-index-windows.txt | acbc20d67316f13c8505bdb5adcbd1bc0ceb319589aba8c863dc1fcb272472dc |
| int-01.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-01.txt | 9002a596823cd0606ba9f32a7242666ef49724d2234729b0dc61f7ba6883c4c6 |
| int-02.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-02.txt | 3d3ddd76f9b385ed1c67ce15090363adabcf4388bdba20bac77a17211ab4462d |
| int-03.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-03.txt | c8a27846a8d25a0905269d3e7844f94b643ef8e0cd74fcd90ec003bbcfd2012e |
| int-04.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-04.txt | ca5a9412992b627aec7db3f10bf2fbe4bd126f510bccdb85874a93a2cd0f7b34 |
| int-05.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-05.txt | ed58252488745d4a8a42bdcb3f1bccf9137e8b04d6057f27957003a5c36dc84c |
| int-06.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-06.txt | 30f9f0e8f67d818dd5cbb83fe9dd1de9cf97b767fd332f81e9782c9129b6432c |
| int-07.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-07.txt | dc7913edda5d781159fbc65e47095c4ed49872c5dd3f7bbd6c952aa217a9bc45 |
| int-08.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-08.txt | d3474fc0d1c70cd0f8ee2b10afa22f331540a372438ef47482c9db1a59a314e9 |
| int-09.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-09.txt | a6cdc5d22d5852eafb331cc606409f8773819770732ec87ad11624347d75706d |
| int-10.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-10.txt | 86f151e1ec1af8b29f3701e3a7c42ea894ab4f8682b078831a6c4dd340279cc2 |
| int-11.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-11.txt | 0324cc601df5caf58e815feede292f7adc5e5477339ead52ebfc149a4cd61c0b |
| int-12.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-12.txt | 9f87b90b1793b014ac0f60065a3a3b183c8282d52df274cb8dee77785b4322fd |
| int-13.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-13.txt | 4435afa89b202ee19bbf1379e10c2425afbb21e6b3fbe07d8f8237ff5b405f12 |
| int-14.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-14.txt | 09bcc5698764839d88e9c77c5ee2b635674d063b58fec156e8b8805cdaf03447 |
| int-15.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-15.txt | 35ceb9278e21567733f51786b95bf22f1b44ae1f39b8a080c48384f47197523a |
| int-16.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-16.txt | dd261b2d76748c208568bfa96e3450d721b59109f09b63c1c623d722e0ec0a1a |
| int-17.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-17.txt | ea4baf9dc3030df73f5b5050cc8b2f0c38e7c3a26eff53b736fc53bce1800162 |
| int-18.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-18.txt | fecdd1a9c541454978eaa4aa62ab4bbba79ba4cf678a29926f694e8d3cbeb98a |
| int-19.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-19.txt | 675160e9388c44a9dae5c4bcebc09412223b4a87e698435775cdf891121a20f6 |
| int-20.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-20.txt | 57abc43e34fafbda19d833d7059127432955f39ae456224668a79c8ce665995d |
| int-21.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-21.txt | 98105f5d2be17f147a4eb664a74c9fef2ea8185118b0db38424efde08fe14818 |
| int-22.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-22.txt | 70612dfc14d9fd688ff2db6bab4b56ef4beaa1f4a3d39383c100200492369b87 |
| int-23.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-23.txt | cf6f41cc9147f935105fc7bd48d29ac8403b8cab107f209fc4b07504cadcb22b |
| int-24.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-24.txt | f34569fa2d2c299b7519e3f96aab35ecb5c68abb96918b772c3bd2e477ea60dc |
| int-25.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-25.txt | 25c5b7d2d922847ffe5498418462ecd60e5ee6daa4b0760e44ba5c74407d25b4 |
| int-26.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-26.txt | 2e0374cff628babf6f94ec828904825347c9464a6ade28e1dd6a593917da7f10 |
| int-27.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-27.txt | a461feddaa316a5149f60296a29e24c4cda968a200b318891a8f7d5736906dd0 |
| int-28.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-28.txt | 568f4a80762bd1a9920d2488f4f2bd002aabadd08a965c14799d01b71919da99 |
| int-29.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-29.txt | 895dcd2af1344af59563e3f66a41f6a8e65719d07756d84ca40d094f3a853a25 |
| int-30.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-30.txt | 0382352346827cf34e83e848c4f98b53459ada660b338d56d9c3048cea8a02c4 |
| int-31.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-31.txt | 0d8ae3732b560011dc475e3b78c2adfb5a73edc0b9e00c125cdc1e759ed78ab0 |
| int-32.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-32.txt | eaad025a0abd130b207572d5a6248cc2781250ba4d57c0430f309e3dd32aac81 |
| int-33.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-33.txt | 82beea61b10123fdea9014a1f431296a38f57bf57b16a0e4f4dba3b3b7568ba0 |
| int-34.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-34.txt | 79b9484d7a1c2efe54af01594e0f54e6fdb44c3bac95fc361547765725145d4d |
| int-35.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-35.txt | 9d2d6c929cfb599d6d1a74f9c7da330677f9109f1b993b42524f9883bbefa055 |
| int-36.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-36.txt | d8b3315bda6b292285195445b23f2c36c4462a06515aa8a6a5c4f092f48f0d7d |
| int-37.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-37.txt | 0e3d1b5adaa8534836e30f6e1b6e4a3d6e445ddb0e7f6a1f500d65734c253dd2 |
| int-38.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-38.txt | 322019da81a35e2583429813147f13b3a66c05fca904f537d0758390132fef46 |
| int-39.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-39.txt | 71ac86e370b4f510a4fd3581efc7b3bc52a73e04ae5f12ff8806aff17c997a45 |
| int-40.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-40.txt | 0b80b8821832d338148b4b2892b5e761693cbda76b32afb8a250beb66786ef71 |
| int-41.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-41.txt | 603279102e05470a1ad75465297fad13fa6def91c64fb45b5ae35a054ee6b09f |
| int-42.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-42.txt | 9d547777e866b09771f5f90ae56a706cbcd8fc0bae5761d987bb75432c064236 |
| int-43.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-43.txt | dc6ada0fe9f0ff41f21fead0470cfd6968bf286c1966d7c5a596b522d6ae7b02 |
| int-44.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-44.txt | acbff869469b018fcc4728e8a638cf76610efcb34b47d73a3e861eb95c2c11da |
| int-45.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-45.txt | efe8135827e621e4ade550f88e9861c09c6515eb4809b7157369c4cbf40ff677 |
| int-46.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-46.txt | 4292d33caf86671a078ac41bbeb260f75a8ecb28104fcd5d211cbfdfb12142f1 |
| int-47.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-47.txt | 8450d98bd21aba87cb6c61b13a5b3729d88f062f2a58e71998f372fec68102ad |
| int-48.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-48.txt | b5fb500dcc3ba31ce69002638c738b0ea652be29944ecc64942627a19236333f |
| int-49.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-49.txt | e38b69250f50cc106e541b5c4fe123123265407cfe45a589d9a34164bb436efe |
| int-50.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-50.txt | e04bec78af4c4d199afd16b30c07318cd9e92d3e7b76e85c769e6002a2da252d |
| int-51.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-51.txt | 4d0fe9208c843bc133791ac1593a07964d2f8f35397626fd1cbe37684bbdf9dc |
| int-52.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-52.txt | cf6bbb191fa44ff0986e0b7da8d55e8dc92d31d1211655ef48f5e630eb8ffc8d |
| int-53.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-53.txt | 0e498ad806ae0a0b25b3f6f54ad89f8fc1d8f824cfe0b5db539219d672c87fa9 |
| int-54.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-54.txt | ce5d8b3d0d773b85a4c99f8987addaeffe24b0d78d4e72c58eb98ba57fd0dd6f |
| int-55.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-55.txt | 4a781fc47ee5b822ed7c792dba8af9a8c873982040820afa0359f636124844e8 |
| int-56.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-56.txt | b1a96fdfbbf7d59b730b34ea1c07b23ad86e87bef728ab34c014b05a2b3f98b0 |
| int-57.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-57.txt | 7fce9df939fd381a0251ef788e0f8ff6c189175c02af1228b9d8535c9ef7e795 |
| int-58.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-58.txt | d9d381976c4d7f3b4ab394e63bdd73a1ce8092c608a66bd25a5eb82cd5383c99 |
| int-59.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-59.txt | 7a65c2c5c684dd71eec972e2bc4b14c5e07426a79e36ac363e060bc618f976a3 |
| int-60.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-60.txt | b1acc10eea0f58bdd71cdf40ec459319b975e9348039fd76d244f6c7aa05838f |
| int-61.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-61.txt | 33173e583f85698b9e34e06dcb99c1e396b7419f6de43d7d8f542fa8ea1ab946 |
| int-62.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-62.txt | cca6368e7ad59f75d64879a24a21e7c27071979d4fd2e258741ad06ea909ebb9 |
| int-63.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-63.txt | 4a2daa1c29980c8ae88757ba1d83979b2aed9b9ea8bec280fedd70f6f1043c65 |
| int-64.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-64.txt | b860bc01d4d344856a5eb9e712fa6f8dc2bab0daa83babd435dfaec4e56ac1f2 |
| int-65.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-65.txt | dfdc9d55be9b1dfff5ff7436fd89ad134b19493278c9782554b99c82aaf4da77 |
| int-66.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-66.txt | eaffdbe935e199fa5afece3f90ebce0bfaecd7639b871ff55ecf639a046fea67 |
| int-70.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-70.txt | fe569602b316b4e73096355bbf85efbc6e3603f06308899608f8c179297e924f |
| int-71.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-71.txt | c2c6f384661579de1d886c10aaa75c5c6c5382e0ab86b9ed4ad349b9b3ba778a |
| int-72.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-72.txt | 5ecf77b55cedd61586df51830f9aa981d55f93c020c32107b428976aa419beb5 |
| int-73.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-73.txt | c4b7d991dbefbaa3516544545effd6d209541e145f48bff0f704819aeac99049 |
| int-74.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-74.txt | 57be0746232d973e8e1ad77a90d83dacf70f6c54776e67dd219c9cddfeeae0e7 |
| int-75.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-75.txt | be8dd96fe6a935278ebb0be437554bdcdebde8f75bc0462bf1f2d0780eade57b |
| int-76.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-76.txt | 2959f4f48cdb90817b58371281d13a829c7b837f4cfb830776cd6a4c413b8956 |
| int-77.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-77.txt | 7131dae4c28f619df61f041a3a216921305a4fc529889796035a49e62a588bd3 |
| int-78.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-78.txt | a554586baa6d9c45cbd76b44028e2eb473795d9af41dfd37139a648474cc5063 |
| int-79.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-79.txt | 03e432d236fb00161f1299ea9ba618f9f09f147f17a9d558a20ef27590265415 |
| int-80.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-80.txt | 7a50b20f6c62e58bd54fe4fe399f688991da5414311b443c3ff9328078b18a50 |
| int-81.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-81.txt | aee8f9268dcdf29fd3d52050bbe6d481784f0f1a942241ce9f2cd2f5f92c1441 |
| int-82.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-82.txt | 7a89f445c5fa1259ce5d1c5b7b5fe346c7fd788b715b7997861c85dd3f5a3a6a |
| int-83.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-83.txt | 460baa02c2a703a238a1ef8a61f28dda9435bc05f43836a87e0b71e057a983b5 |
| int-84.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-84.txt | 73005101e48761c462a8acb02743ef59d10b3c5bba791abe001f14eb76fd3008 |
| int-85.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-85.txt | 7df5b89b8e09fc91255b2200b43f8fc7eddcfc2261097e047241e3d3ee5fc318 |
| int-86.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-86.txt | f7cbdc504466d090381399d5e7e17c9700851c56ea6bdf2d53b22a2f610706a2 |
| int-87.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-87.txt | a10b8cea05f1abae8df8e567b648086b0306196ed10779e4862b4a344fd85ef3 |
| int-88.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-88.txt | 207e355d53790cde66f5c6ccceb9b7b0cc919b3658d0d0e1c64e212c8e6d4df9 |
| int-89.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-89.txt | 74049dd46dd78041dfae178c00f39e1b2555b9faf43b987d9133a4c963d846d8 |
| int-index-linux.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-index-linux.txt | 14f41bed135ec3a43dedc57efa029c85134e3a91db3cd2941bf3d924a2315838 |
| int-index-windows.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-15/int-index-windows.txt | a6f9c6db0d3a3675fc5759487c5b34f163458142ac5405aa6f8e666d69739066 |

| Field | Value |
|---|---|
| **Evidence files** | 133 transcripts + 4 indexes, each cited with the digest of its stored bytes, under the home `.dev-flow/2026-11-01-batch-101/evidence/inc-15/` |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — "0 files under `s19_app/` change" and "no one-pause read survives in the four arms" |
| If the result is an ABSENCE, what made the search wide enough | `git diff --name-only c2cba35 <head> -- s19_app` (empty) and the static guard's site walk over the four named functions (`test_r_tst_154_155_inc15_arms_wait_through_settled`) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | the static guard node (pins the 9 sites' description/predicate/position/shared-wait binding) |
| Conjunctive criteria: one mutation per conjunct | each guard clause has its own control (position: int-58/59; description: int-60/61; predicate: e5c-20/21; shared-wait/loops: int-62/63, e5c-22; D9: e5c-24) |
| Synthetic instance of the absent case | the guard controls plant the forbidden form (a moved/removed/f-string/predicate-swapped/loop/local-helper site) and turn the guard RED |
| **Positive control for every probe that returned an ABSENCE** | the pre-fix guard stays GREEN on the same planted edits (int-64, e5c-25/26) — the discriminator the fix adds |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl "settled" tests/` | the 2 changed arms import `settled`; the shared helper `tests/b97_probes.settled` is Inc 2's (R-TST-020/021/024); no other test re-pins a wait site |
| B2 file moved on disk | `git diff --name-status c2cba35 <head> -- tests docs` | no rename: the 4 arms keep their names, 1 new node added (the code review's AST comparison found the same top-level test names) |
| B3 byte-identical golden captures this source | `grep -rl "test_tui_flow_execution_b94\|test_tui_patch_editor_v2" tests/goldens/ tests/__snapshots__/` | 0 hits — no golden captures the changed arms |
| B4 artifact produced here is consumed elsewhere | the R-TST-158 sentence in `docs/engineering-rules.md` | consumed by the parametrized conventions guard `test_r_tst_007_conventions_hold_each_test_rule[R-TST-158]` |
| A3 interface consumed by another module changed | `git diff --name-only c2cba35 <head> -- s19_app` | empty — no product interface changed |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and verdict: no product symbol or interface changed, no file moved, no golden re-pinned |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the E5 rulings C-1 … C-10 | every record/test site the rulings name | `E5-corrective-notes.md` §1 enumerates the sites per ruling before the first edit | 10 rulings | all (C-6, C-7, C-10 in tests; C-1 … C-5, C-8, C-9 in records; the D9 case/row move at RA-2) | none — the re-audit (RA-1 … RA-3) confirms |

| Field | Value |
|---|---|
| **Correction population** | 1 correction (the C-1 … C-10 pass, plus the RA-1/RA-2 re-audit), enumerated with its method before the first site was edited |

### Signed-balance test ledger

`post = base − deleted + added` → scanned test modules unchanged (`tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` not re-measured: no test file was added). Test cases `28 = 26 + 2` (E1/E3 26; + R-TST-157/2 split at C-8 and + R-TST-153/3 at C-10, which RA-2 moves to R-TST-164/1). 0 test functions renamed or deleted, 1 added.

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` (E5) **PASS-WITH-NOTES** carrying the security lens — 0 HIGH/MAJOR, 1 MINOR (F1, the predicate pin) + 4 NIT (F2–F5), all folded by the corrective pass; no separate `security-reviewer` ran because the increment changes 0 product files, and the carried lens found evidence redaction clean, Windows isolation and tmp-only writes — `E5-code-review.md`. `qa-reviewer` coverage audit (E5): 26 cases, 3 of 26 = 11.5 % departures → rulings C-1 … C-10 → corrective → **re-audit** 28 cases / 27 covered / 1 partial / 28 verified — `E5-coverage-audit.md`. E3 design (code-free): `architect` round 1 **FAIL** (1 HIGH, 2 MAJOR, 7 MINOR) → round 2 **PASS-WITH-NOTES** (F1–F3 closed; N1–N3) — `E3-architect.md`, `E3-rulings.md`. **There WAS a re-review (E3 round 2 and the E5 re-audit), because each round 1 blocked or found open records.** |

## 5 · Risks

- **Windows-only timing.** The fix is proven on the Windows host only for the four named nodes (80/80 at `77f4553`, TC-B94-27 20/20 at `5edcb3f`); the one-pause pattern remains elsewhere in the suite and can still flake on Windows.
- **The static guard pins the nine sites only** (scope ruling E3 F3): a future arm that adds a one-pause read is bound by the R-TST-158 sentence, which is a convention, not an enforcement.
- **The parallel-lane run is partial** (RA-1): the `-n 8` lane ran over the 3 changed files, not the release gate's whole suite; a serial-vs-parallel interaction outside those files is not ruled out until the merge verification.
- **The D9 trigger keys a repeated import on its last occurrence** (`max(..., default=None)`); if a future arm reorders the two imports, the guard may pin the wrong occurrence.
- **The negative paint assertion has no failing control of its own** (re-audit note R1) and D9's trigger calls `_wait_for` internally (R2) — both routed to the D-6 backlog row, not blocking.

## 6 · Pending items / spec deviations

- **Merge-time full suite** — R-TST-157/2 is `partial` until the batch merge verification runs the release gate's whole-suite parallel lane (`pytest -n 8 -m "not serial_timing"`) plus the serial lane; its record cites that run and flips the case to `covered`.
- **D-6 backlog census row** — the suite-wide census of one-pause reads (146 sites in 28 test files, plus 88 direct reads after the self-pausing `pilot.press`/`pilot.click`, plus `while` loops whose body calls `pilot.pause()`), the retirement of the module-local `_settled` onto `tests.b97_probes.settled`, and the two re-audit notes (R1 negative paint control, R2 `_wait_for` inside `_import_stem`) — no ratchet guard in this increment.
- **Uncommitted records** — this packet and `04-validation.md` are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 15 before Inc 6 reaches E4 (Inc 6 may move `document.source_path` and the load/paste path the new waits read); then close the batch with the full suite + the whole-suite parallel lane, and open the D-6 census backlog row as its own increment.

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 0 source files (`git diff --name-only c2cba35 972ba5b -- s19_app` empty); reason in §2 |
| 2 | Tests written in this same increment | all | ✓ | the 4 changed arms + `test_r_tst_154_155_inc15_arms_wait_through_settled` + the R-TST-158 parameter |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — 0 product functions change (tests-only) |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | the base (one-pause) form under each hold (§4) |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | 5 probes in §4 |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | PASS-WITH-NOTES, 0 HIGH, F1–F5 (§4b) |
| 7 | No file from another lane touched | all | ✓ | no fork; the 3 test files + 1 doc are not in another lane's set |
| 8 | Frozen interfaces untouched | all | ✓ | 0 files under `s19_app/`; the frozen `_ENGINE_PATHS` set is untouched |
| 9 | Coverage claims verified on disk | all | ✓ | the coverage audit read the transcripts (`E5-coverage-audit.md`) |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 Load-bearing emptiness |
| 11 | **Mutation verdicts** declared per arm | all | ✓ | 6 product mutants + 12 guard controls, per node in §4 |
| 12 | **Instrument RED-proof** declared | all | ✓ | 4 instruments (§4) |
| 13 | **Correction population** declared | all | ✓ | 1 correction (§4) |
| 14 | **Emitted-form assertion** declared | all | ✓ | 2 artifacts (§4) |
| 15 | **Independent review** names somebody | all | ✓ | `code-reviewer`, `qa-reviewer`, `architect` (§4b) |
| 16 | **Evidence files** declared | all | ✓ | 133 transcripts + 4 indexes with SHA-256 (§4) |
