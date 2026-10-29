# Increment 015 — LLR-165.3 · `Hotfix 3b: a project load leaves the Patch Editor clean`

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `015` — hotfix "3b" of Increment 003, out of sequence: numbered after the 14 planned units so no planned packet number moves; delivered between Increments 004 and 005 |
| Lane | `main` · `s19_app/tui/app.py`, `s19_app/tui/screens_directionb.py` (2 SOURCE files) |
| Requirement(s) | `LLR-165.1 · LLR-165.3` · LED-2026-10-26-batch-100.55 (b) (outcome unchanged) · LED-2026-10-26-batch-100.60 (this hotfix) |
| Acceptance | `AT-B100-03` (re-run) · white-box `TC-B100-10` (new arm) · regression pins: batch-97 `AT-B97-14[patch]`, `AT-B97-15` ×2, `AT-B97-16`, `AT-B97-24` |
| Agent | `software-dev` (orchestrator-implemented; Kimi out of budget) |
| Date | `2026-10-29` |

---

## 1 · What changed

BLUF: after any project load, the next Patch Load loads directly again. Inc 3's reset
(`_reset_project_session`, `app.py:9257`) emptied `#patch_paste_text` by assigning its text. That
posts `TextArea.Changed`, the panel's handler (writer w2) set the dirty flag, and the
`mark_loaded` deferred with `call_after_refresh` ran before the bubbled message in the
fresh-session path. A session with nothing unsaved then raised the dirty-load question
(`LoadGuardScreen`) and the document did not load. Five batch-97 nodes have been red in CI
since the Inc 3 merge (run 40497466178), and red locally on `6d8631a`.

- `PatchEditorPanel.clear_paste_buffer()` (NEW, public, `screens_directionb.py:5827`): clears the
  buffer under `buffer.prevent(TextArea.Changed)` and repaints the paste gauge and heading itself,
  because the prevented message is what normally repaints them.
- The reset calls `panel.clear_paste_buffer()` and then `panel.mark_loaded()` synchronously. The
  deferral and its comment are gone.
- LED .55 (b)'s outcome (buffer empty, no dirty `●`) is unchanged; only its mechanism changes
  (LED .60). `screens_directionb.py` is touched one increment before Inc 10, for this one method.

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | LLR-165.1 · LLR-165.3 | `_reset_project_session`: the paste-buffer clear goes through `panel.clear_paste_buffer()`; `mark_loaded()` runs synchronously (no `call_after_refresh`) |
| `s19_app/tui/screens_directionb.py` | source | LLR-165.3 | `PatchEditorPanel.clear_paste_buffer()` (NEW); `_refresh_paste_gauge` docstring "Used by" names it |
| `tests/test_b100_session_reset.py` | test | LLR-165.1 · LLR-165.3 | `test_tc_b100_10_reset_leaves_the_patch_editor_clean_for_the_next_load` (NEW, TC-B100-10 arm): the app's own project load, then the Patch Editor's Load control — no `LoadGuardScreen`, 6 entries loaded with no `●`, buffer empty, heading `editable` |

| Count | Value |
|---|---|
| **SOURCE files** | **2 / 4** |

## 3 · How to test

```bash
# interpreter: C:/Users/jjgh8/anaconda3/envs/s19env/python.exe ; NO_COLOR unset ; PYTHONPATH=<tree>
python -m pytest tests/test_b100_session_reset.py -p no:cacheprovider -q
python -m pytest tests/test_b97_chips_help.py tests/test_b97_width.py -p no:cacheprovider -q
```

## 4 · Test results

Final tree: `app.py` sha256 `b148ec156c1d…` (the review's F1/F2 docstring fixes over `f8c5efa0327c…`, on which `green-01`…`green-04`, guards, census and the mutants ran), `screens_directionb.py` sha256 `47fd3bf24826…` (12-char forms in every
transcript header). All transcripts under `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/`.

| Run | Transcript | Result |
|---|---|---|
| RED, new arm at `6d8631a` | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/red-01-hotfix-arm-at-6d8631a.txt` | 1 failed: `a clean session raised the dirty-load question` (`app.screen` is `LoadGuardScreen`) |
| RED, the 5 batch-97 nodes at `6d8631a` | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/red-02-b97-nodes-at-6d8631a.txt` | 5 failed, 144 passed (`NoMatches … on LoadGuardScreen()`, `did not settle: Run focused` ×3, `check_validate_button`) |
| GREEN, Inc 3 file | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-01-session-reset.txt` | 18 passed |
| GREEN, the two batch-97 files | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-02-b97-chips-width.txt` | 224 passed |
| GREEN, Inc 3 file, final test (heading assertion added) | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-03-session-reset-final.txt` | 18 passed |
| Guards (6 files) | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/guards.txt` | 75 passed, 29 snapshots passed |
| Census sweep (`-k census`) | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/guards-census.txt` | 87 passed |
| GREEN, reverse-census files (8) | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-04-reverse-census.txt` | 1 failed, 183 passed — the failure is `test_at057b` (test-race backlog) |
| `test_at057b` ×5 on each tree | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-05-at057b-x5-fix-and-base.txt` | fix tree 2 failed / 3 passed; `main` 6d8631a 3 failed / 2 passed — pre-existing flake, not this hotfix |
| FINAL tree: Inc 3 file + 6 guards | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-06-final-reset-and-guards.txt` | 93 passed, 29 snapshots passed |
| Mutant M1 — clear without `prevent` | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/mut-M1_no_prevent.txt` | KILLED — 3 failed (new arm + AT-B100-03 ×2) |
| Mutant M2 — no gauge/heading repaint | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/mut-M2_no_gauge_refresh.txt` | KILLED — 1 failed (new arm, heading still `example`) |
| Mutant M3 — no `mark_loaded` | `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/mut-M3_no_mark_loaded.txt` | KILLED — 2 failed (AT-B100-03 ×2, the dirty-before-load arm) |

Every mutant transcript ends `RESTORE OK` with the restored file's digest.

### Reverse census

`grep -rln "mark_loaded\|patch_paste_text\|_reset_project_session\|LoadGuardScreen" tests/ --include=*.py`
names 11 files: `b97_fixtures.py` (helpers), `test_b100_session_reset.py` (`green-03`),
`test_tui_snapshot.py` (`guards`), and 8 test files run together in
`.dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-04-reverse-census.txt`: `test_b97_key_bar.py`,
`test_b97_patch_editor.py`, `test_b99_s0.py`, `test_capped_text_area.py`, `test_tui_patch_editor_b94.py`,
`test_tui_patch_editor_v2.py`, `test_tui_patch_json.py`, `test_tui_patch_layout.py` — 1 failed, 183 passed; the failure (`test_at057b`) flakes at the same rate on `main` (`green-05`).
The two batch-97 files that went red in CI are not in the grep (they reach the guard through
`b97_fixtures`) and are re-run in full (`green-02`). Snapshot cells: unchanged (`guards`, 29 passed). The full suite runs in CI
on push; its FAILED-node set is compared with run 40882519921 (11 failed) before the next increment.

### Why it escaped (C-55)

Inc 3's reverse census grep did not reach the batch-97 files, and the post-merge CI runs were not
compared node by node with the run before. Both are recorded in LED .60.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-3b/` | SHA-256 |
|---|---|---|
| green-01-session-reset.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-01-session-reset.txt | f59c4e495e8ee12c6ae2bfce5a39a78a720491f0bdd996415e34a69fb6e0592b |
| green-02-b97-chips-width.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-02-b97-chips-width.txt | 7e044238b2acd0da5d37486b60ec45c954ba91753894f7f1f666b227ef639b97 |
| green-03-session-reset-final.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-03-session-reset-final.txt | 28bb90c4ac73bcfb4ba9425c6aa6c824e16517f2072b73d1399881bd25fb9280 |
| green-04-reverse-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-04-reverse-census.txt | d08e923ca5da973a5ad0881ec2e48b031e89a44d9e40d95689863871f27b42d6 |
| green-05-at057b-x5-fix-and-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-05-at057b-x5-fix-and-base.txt | c67adcbec36a95958d8fefebc08b19b680ad02cc7faed1c4571b2fabd69c26d9 |
| green-06-final-reset-and-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/green-06-final-reset-and-guards.txt | 08cde6ffe6f5c079723c0aa84c8500d2bbb5f0f95a1a498ddba19466cd51d387 |
| guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/guards-census.txt | 84f1ad79a71bdf813b9d6b173f8b1e166472ebf6cfe211b84c9c1eef5f365819 |
| guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/guards.txt | 71b26dc0c62f699684f39a18d7795ed98a5682502b548533b3ee3f4b4bfc874d |
| mut-M1_no_prevent.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/mut-M1_no_prevent.txt | d64ba90dac2b6a2f85906b536229f96ebad98d4ec11199c22c38382c3777c48c |
| mut-M2_no_gauge_refresh.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/mut-M2_no_gauge_refresh.txt | 4124683fbb8fb2a0054cab2b30d50aaf97b00b50c21763b8687b6bf10e64506f |
| mut-M3_no_mark_loaded.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/mut-M3_no_mark_loaded.txt | d49682592628f2dc8e8ad3b1bdb8c266b806f2acdec67e8f151ff9f14f89bf4e |
| red-01-hotfix-arm-at-6d8631a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/red-01-hotfix-arm-at-6d8631a.txt | 7764b8365d094c0e6d8a6af0ceda5607c5ce7d6bc083cba49af5ff6355d0b54a |
| red-02-b97-nodes-at-6d8631a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-3b/red-02-b97-nodes-at-6d8631a.txt | ecefcb629897ad9b80b69afda8bb6b996d389cd47d2cbd93b484ee8700a2521c |

| Field | Value |
|---|---|
| **Evidence files** | `13 artifact(s), each at the declared home, with the digest of its bytes on disk` |

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · **PASS-WITH-NOTES** (0 HIGH, 0 MEDIUM, 3 LOW) — `review-increment-015.md`. Read against LLR-165.3, LED .55 (b) and LED .60; verified by execution on a `6d8631a` scratch tree and the fix tree. The new node is RED on base on `LoadGuardScreen` and GREEN on the fix; a probe ties the 5 batch-97 nodes to this mechanism (base: the guard modal swallows the Patch Load, 0 entries, focus held on `load_guard_cancel`, so "Run focused" never settles; fix: 6 entries, `#fx_run` focused). Mutants M1 (no prevent) and the reviewer's M5 (no clear) killed by the new test; M3 (no `mark_loaded`) by AT-B100-03. `prevent` is context-scoped, harmless here (one synchronous assignment, no `SelectionChanged` handlers); no other `Changed` observer loses anything; no other deferred race. LOW: F1 test docstring cited LLR-165.1 → fixed to LLR-165.3 / LED .60; F2 `_reset_project_session` docstring omitted `clear_paste_buffer` → fixed; F3 AT-B100-03 alone kills M3 → kept in the verification set (`green-06`). Orchestrator re-run on the final tree (`app.py` `b148ec156c1d`, docstrings only since `f8c5efa0327c`): Inc 3 file + 6 guards 93 passed, 29 snapshots (`green-06`). |

## 5 · Risks

- `Widget.prevent(TextArea.Changed)` suppresses the message for every observer, not only writer w2.
  The reset repaints the gauge and heading itself; the review checks for other observers.
- The full-suite verdict is CI's (~2 h 20 min); local evidence covers the Inc 3 file, the two
  batch-97 files, the guards and the census sweep.

## 6 · Pending items / spec deviations

- CI run of the merge: compare its FAILED set with run 40882519921; expected 6 (the known
  `help_sections.md` ×3 from uncommitted `prototypes/`, `at_b78_03`, `at_b78_32`, `at_056e`).

## 7 · Suggested next task

Inc 5 (Save project saves the image you see), Opus implementer.

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 source files |
| 2 | Tests written in this same increment | all | ✓ | `test_tc_b100_10_reset_leaves_the_patch_editor_clean_for_the_next_load` |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | behavioural arm through the app's own load and the Load control |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | `red-01`, `red-02` |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 reverse census |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b: PASS-WITH-NOTES, LOW F1/F2 fixed |
| 7 | No file from another lane touched | all | ✓ | the 2 sources + 1 test |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | B100-I4 / I19 unchanged in signature; a public panel method added |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | every count is in a cited transcript |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | none: the arm sets the dirty-making state (the shipped example in the buffer) itself |
| 11 | **Mutation verdicts** declared — **per arm** | all | ✓ | M1–M3, all KILLED |
| 12 | **Instrument RED-proof** declared | all | ✓ | `red-01` shows the arm fails at base |
| 13 | **Correction population** declared | all | ✓ | 1 correction (the deferred `mark_loaded`) |
| 14 | **Emitted-form assertion** declared | all | ✓ | painted: `app.screen`, the SCRIPT subtitle, the heading |
| 15 | **Independent review** names somebody | all | ✓ | §4b: code-reviewer |
| 16 | **Evidence files** declared | all | ✓ | §4 evidence table (13 rows, paths + SHA-256) |
