# Increment 023 — batch-end fix rounds 1–3 and the release version bump

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `023` |
| Lane | `main` · 3 SOURCE files (`app.py`, `screens.py`, `version.py`), of the 4-file cap |
| Requirement(s) | `LLR-171.1m` · `LLR-173.5a` · `LLR-175.1` · `LLR-167.6` · `LLR-175.5` · `LLR-164.2` · `LLR-168.3` · `LLR-176.1` · `LLR-162.1` · `LLR-162.3` · `LLR-176.2c` · `HLR-177b` · `LLR-176.4` · `LLR-177.4c` · `LLR-177.5` · `LLR-147.13` |
| Acceptance | CI9b-3/4 · CI11-1 … CI11-4 · R-1 … R-3 · A12-51 · SE5-12b-2 · OBS-12b-1/2 · TC-B100-73/51 · AT-B100-18 · TC-B97-64 · AT-B100-17 |
| Agent | `orchestrator` (the three fix rounds, ruled in each `fix-round-*.md`; no sub-agent reviewer spawned) |
| Date | `2026-11-01` (operator release decision 2026-11-01) |

---

## 1 · What changed

Fix round 1 (`fix-round-1.md`, `dee0d96`) closed the Linux-only CI failures: CI9b-3/4 (the Windows trailing-dot arm, LLR-173.5a), CI11-1 (the LLR-171.1m `..` / outside-P rebind gate, one product fix in `app.py`), CI11-2 (the tc47 debounce wait), CI11-3 (the tc65 `normcase` fold) and CI11-4 (the tc59 refused-plan re-pin). Fix round 2 (`fix-round-2.md`, `677435e`) closed the battery's real failures: R-1 (the two Save timing arms; product finding R1-P1), R-2 (the CSS byte-equality supersessions), R-3 (the list-pick oracle), R-4 (environment only), A12-51 (the manifest-mismatch tail), SE5-12b-2 (the two project-sync guards), OBS-12b-1 (the e13 `bz-busy` override) and OBS-12b-2 (the quit question's emphasis), and closed 5 BACKLOG-CODE rows. Fix round 3 (`fix-round-3.md`, `d460190`) closed the 4 new Linux CI failures of run 41338318239 — all test races / platform assumptions, product unchanged — including AT-B100-18 and AT-B100-17. The release bump lands `0.1.0` → `1.0.0rc1` in `pyproject.toml` and `s19_app/version.py` (operator release decision, 2026-11-01: tag `v1.0.0-rc1` at this close; batch-101 "release hardening", then `v1.0.0`).

## 2 · Files modified

Branch history: `dee0d96` (b100-fix1, fix round 1) then `677435e` (b100-fix1, fix round 2) merged on main; `d460190` (b100-fix3, fix round 3) merged on main. The `1.0.0rc1` bump in `pyproject.toml` / `s19_app/version.py` is uncommitted on this branch at the close.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | LLR-171.1m · LLR-176.2c · HLR-177b | CI11-1 (the `..` / outside-P gate on the document-row rebind), SE5-12b-2 (the two project-sync guards), OBS-12b-2 (`_QuitQuestionScreen.PRIMARY_BUTTON`). sha256[:16] `fce707dab6d2945d` |
| `s19_app/tui/screens.py` | source | HLR-177b | OBS-12b-2: `ConfirmQuestionScreen.PRIMARY_BUTTON` and the per-button `modal-confirm`. sha256[:16] `f46d545d9d61aeff` |
| `s19_app/version.py` | source | HLR-168 | the release bump `0.1.0` → `1.0.0rc1` (uncommitted). sha256[:16] `8b00e2d13533e394` |
| `pyproject.toml` | config | HLR-168 | the release bump `0.1.0` → `1.0.0rc1` (uncommitted). sha256[:16] `8c026edb12705950` |
| `tests/test_b100_load_dialog.py` | test | LLR-173.5a | CI9b-3/4: the `TRAILING_DOT_ARM` skipif (dee0d96) |
| `tests/test_b100_project_homes.py` | test | LLR-171.1m | CI11-1: the `outside P` arm (dee0d96) |
| `tests/test_b100_save_dialog.py` | test | LLR-175.1 | CI11-2 (the `debounce` param), CI11-3 (the `normcase` fold), SE5-11-1 docstring (dee0d96, 677435e) |
| `tests/test_b100_save_image.py` | test | LLR-167.6 · LLR-175.5 | CI11-4: the refused-plan re-pin (dee0d96) |
| `tests/test_b100_active_variant.py` | test | LLR-168.3 | R-1 TC-B100-20: the paint-time clock and `_wait_yielding` (677435e) |
| `tests/test_b100_save_guards.py` | test | LLR-164.2 | R-1 TC-B100-05: the commit-end stamp (677435e) |
| `tests/test_b100_busy.py` | test | LLR-176.2c · LLR-176.4 | A12-51 arm; TC-B100-51 size from `stat().st_size` (677435e, d460190) |
| `tests/test_b100_workers.py` | test | LLR-176.2c · LLR-177.4c · LLR-177.5 · HLR-177b | SE5-12b-2 and OBS-12b-2 arms; AT-B100-18 and AT-B100-17 re-pins (677435e, d460190) |
| `tests/test_b97_flow_execution.py` | test | LLR-176.1 · LLR-147.13 | R-2 (the three CSS supersessions); TC-B97-64 (the D15 clock seam) (677435e, d460190) |
| `tests/test_b99_load_project.py` | test | LLR-162.1 · LLR-162.3 | R-3: the list-pick re-load oracle (677435e) |
| `tests/test_b100_a2l_progress.py` | test | LLR-176.4 | TC-B100-73: the size read from the fixture on disk (d460190) |
| `tools/e13/run.py` | test | HLR-177 | OBS-12b-1: the `bz-busy` `_parse_loaded_file` override passes `**kwargs` (677435e) |
| `.dev-flow/2026-10-26-batch-100/fix-round-1.md` | doc |  | fix round 1 record |
| `.dev-flow/2026-10-26-batch-100/fix-round-2.md` | doc |  | fix round 2 record |
| `.dev-flow/2026-10-26-batch-100/fix-round-3.md` | doc |  | fix round 3 record |
| `.dev-flow/BACKLOG-CODE.md` | doc |  | rows closed (5 at Inc 12b, 3 by fix round 2); R1-P1, R2-CI, SR12b-7, SR12b-7b, OBS-F2-1 opened |
| `.dev-flow/2026-10-26-batch-100/evidence/fix-1/*` · `.dev-flow/2026-10-26-batch-100/evidence/fix-2/*` · `.dev-flow/2026-10-26-batch-100/evidence/fix-3/*` | generated | HLR-176 | the fix-round transcripts (§4) |

| Count | Value |
|---|---|
| **SOURCE files** | **`3` / 4** |
| Test files | 11 (uncapped) |
| Doc files | 4 (outside the count) |
| Config files | 1 (outside the count) |

## 3 · How to test

The fix-round runs executed in the `b100-fix1` / `b100-fix3` worktrees and on a WSL Linux host; they are not re-run here. Selections and commands are in each `fix-round-*.md` (§Runs). The `1.0.0rc1` bump is asserted by `git diff` showing `0.1.0` → `1.0.0rc1` in both files.

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/fix-1/`, `fix-2/`, `fix-3/`, `batch-end/`. Counts below are the transcripts' own summary lines.

| Round | Transcript | Result |
|---|---|---|
| fix 1 | `green-project-homes-171-1m-tc31.txt` | 38 passed, 2 failed (fixture setup MAX_PATH; re-run alone 2 passed) |
| fix 1 | `green-load-dialog-tc43-tc63.txt` | 47 passed |
| fix 2 | `green-01-save-guards-and-load.txt` | 83 passed, 1 deselected |
| fix 2 | `green-02a-workers.txt` | 69 passed, 1 xfailed |
| fix 2 | `green-02b-busy.txt` | 116 passed, 1 skipped |
| fix 2 | `green-02c-question-reuse-ids.txt` | 180 passed, 5 deselected |
| fix 3 | `wsl-02-fix-4-nodes-GREEN.txt` | 4 passed |
| fix 3 | `wsl-06-module-workers-after-at17.txt` | 69 passed, 1 xfailed |
| fix 3 | `win-01-fix-4-nodes.txt` | 4 passed |
| batch-end | `linux-gate-f72eef1-summary.txt` | 18 failed, 5027 passed, 205 skipped, 4 xfailed |

### Evidence files

| Artifact | Path | SHA-256 |
|---|---|---|
| green-project-homes-171-1m-tc31.txt | .dev-flow/2026-10-26-batch-100/evidence/fix-1/green-project-homes-171-1m-tc31.txt | 6e4164da5a9a6d8ff18e96373dce0545033bbc2544eb6676a5fdc4a922b8f67f |
| green-load-dialog-tc43-tc63.txt | .dev-flow/2026-10-26-batch-100/evidence/fix-1/green-load-dialog-tc43-tc63.txt | 018b1380cf3a03357f6dc04fa0695f58997991cd5a479b4490b808ef920f57d0 |
| green-01-save-guards-and-load.txt | .dev-flow/2026-10-26-batch-100/evidence/fix-2/green-01-save-guards-and-load.txt | f9f66145efaa0f11b1992bf5a93d70937e7a8b18eaee595ee496e72af390762d |
| green-02a-workers.txt | .dev-flow/2026-10-26-batch-100/evidence/fix-2/green-02a-workers.txt | 3a8b2f902161b6cf171270536331b6acd09960480c61ab216e5c83fc3241e51f |
| green-02b-busy.txt | .dev-flow/2026-10-26-batch-100/evidence/fix-2/green-02b-busy.txt | 1b978e300c5cbb222196b40b8bc5e107480315c49a4eba33613bb1d499746c49 |
| green-02c-question-reuse-ids.txt | .dev-flow/2026-10-26-batch-100/evidence/fix-2/green-02c-question-reuse-ids.txt | d51258bc09847fd8290a3ac34ffe49d2ad0a60b9de7ecbfe1c4008dfdace8c15 |
| wsl-02-fix-4-nodes-GREEN.txt | .dev-flow/2026-10-26-batch-100/evidence/fix-3/wsl-02-fix-4-nodes-GREEN.txt | d755432dd2074e6955b8225ad9f50b7051589a58e79933d8ef126e5434134d26 |
| wsl-06-module-workers-after-at17.txt | .dev-flow/2026-10-26-batch-100/evidence/fix-3/wsl-06-module-workers-after-at17.txt | aa11ded30f1a971136dd0249ad6008c8893faf499cda0b54d1a360420001dbcc |
| win-01-fix-4-nodes.txt | .dev-flow/2026-10-26-batch-100/evidence/fix-3/win-01-fix-4-nodes.txt | 17e583a412912126f8633a748338fb0d920262ab61d12705641b0572f2e00913 |
| linux-gate-f72eef1-summary.txt | .dev-flow/2026-10-26-batch-100/evidence/batch-end/linux-gate-f72eef1-summary.txt | c78f6c8ffda8c60ea6cfc13aaa3904c96d1e15f67ec93976cafa5a3125d8bfad |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | SELF-REVIEW — the batch-end fix rounds were reviewed by the orchestrator's rulings in each `fix-round-*.md` §"Orchestrator rulings" (fix round 1: the CI11-* rulings; fix round 2: the R-* / A12-51 / SE5-12b-2 / OBS-12b-* / SR12b-7 rulings; fix round 3: the TC-B100-73/51, AT-B100-18, TC-B97-64, AT-B100-17 rulings). No independent reviewer was spawned for the batch-end fix rounds; this is a declared self-review, not an independent one. |

## 5 · Risks

- **R1-P1**: Save project sits at the TC-B100-20 bound since Inc 12b (profile owed; BACKLOG-CODE).
- **Posix arms** of CI9b-3, CI11-3 and CI11-1 are proven only by the Linux CI after the merge.
- **No Python 3.11 on the WSL host** for fix round 3; the orchestrator re-ran the nodes on a Linux 3.11 host (`evidence/fix-3/cachy-*.txt`).

## 6 · Pending items / spec deviations

see 05-close.md.

## 7 · Suggested next task

The close commit and the `v1.0.0-rc1` tag; then batch-101 "release hardening".

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 of 4 (`app.py`, `screens.py`, `version.py`) — §2 |
| 2 | Tests written in this same increment | all | ✓ | the fix-round test arms — §2 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | n/a | no new unit logic — test re-pins and two product guards |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `ci11-1-red-base.txt` (2 failed), `ci11-4-negative-control-mutant.txt` (1 failed); `SE5-12b-2-RED.txt`, `OBS-12b-2-RED.txt`, `battery-rerun1-RED.log`; `wsl-01-base-4-nodes-RED.txt` (3 failed, 1 passed) |
| 5 | Reverse census declared | `core` · `full` | ✓ | `SR12b-7-census.txt` (91 loops in 40 files) |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — SELF-REVIEW (orchestrator rulings; not an independent reviewer) |
| 7 | No file from another lane touched | all | ✓ | the named sources/tests/config/docs are this lane's |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `a2l.py` unchanged (fix round 3 mutants restored byte-equal) |
| 9 | Coverage claims verified on disk, not from intent | all | ✓ | the cited transcripts' own summary lines — §4 |
| 10 | Load-bearing emptiness declared | all | n/a | no absence-backed conclusion |
| 11 | Mutation verdicts declared | all | ✓ | M-70, M-dwell, M-quit, M-at17 killed (fix-round-2/3) |
| 12 | Instrument RED-proof declared | all | ✓ | the RED-before-GREEN arms in each fix round |
| 13 | Correction population declared | all | n/a | no correction sweep |
| 14 | Emitted-form assertion declared | all | ✓ | `git diff` `0.1.0` → `1.0.0rc1` in both release files |
| 15 | Independent review names somebody | all | ⚠ | SELF-REVIEW (not independent) — §4b |
| 16 | Evidence files declared | all | ✓ | §4 evidence table with digests |
