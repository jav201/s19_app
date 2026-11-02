# Increment 019 — Inc 10 · HLR-174 … HLR-174d / LLR-174.x · one short question before unsaved work is lost

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `010` |
| Lane | `main` · 3 SOURCE files (`screens.py`, `screens_directionb.py`, `app.py`), at 3 of the 4-file cap; `styles.tcss` is unchanged (ruling Q-6) |
| Requirement(s) | `HLR-174` · `HLR-174a` · `HLR-174b` · `HLR-174c` · `HLR-174d` · `LLR-174.1`–`LLR-174.4` and their suffixes (`LLR-174.1a/.1b/.1c`, `LLR-174.2a`–`.2t`, `LLR-174.3a`–`.3d`, `LLR-174.4a/.4b/.4c`) · `LLR-165.3` (interim line removed) · `LLR-166.1`, `LLR-167.8`, `LLR-173.7` (their Inc 10 arms) |
| Acceptance | `AT-B100-15` (question, keep, replace, items, after-save halves) · `AT-B100-03` (re-pinned: answers `y`) · `TC-B100-44` (LLR-174.1…) · `TC-B100-45` (LLR-174.2…) · `TC-B100-46` (LLR-174.3…) · `TC-B100-72` (LLR-174.4…) · `TC-B100-12` (LLR-166.1 arm) · `TC-B100-70` (LLR-167.8 arm) · `TC-B100-66` (LLR-173.7 arm) · `TC-B100-10` (LLR-165.3 re-pin) — in `tests/test_b100_load_question.py` (NEW), `tests/test_b100_session_reset.py` and `tests/test_b99_editor_image.py` |
| Interfaces | consumes `LoadDialog` / `_handle_load_dialog` / `_load_workarea_file` / `_load_from_item` / `_handle_select_variant` / `_route_load_project` / `_load_path_from_user_input` / `resolve_input_path` / `painted_names` / `check_action`; adds `ConfirmQuestionScreen` to `screens.py`, `PatchEditorPanel.is_dirty` to `screens_directionb.py`, and `QuestionKind` + `UnsavedItem` + `_confirm_then_load` + `_load_would_lose` + `_load_question_text` to `app.py`; reuses `LoadGuardScreen` (unchanged) |
| Agent | design-first experiment (`dev-flow-v3-beta` pipeline): E1 requirements · E2 Code-Wire baseline + prototypes · E3 code-free design review (2 rounds: architect + security) · E4 parallel build (2 DeepSeek implementers + Opus tester, then Opus integration) · E5 validation (83 mutants on DeepSeek v4 Pro via pi, code + security review on Opus, one corrective pass on Opus) · E13 capture. Models per stage in the step table below |
| Date | `2026-10-31` (E1 start 14:32Z through E13 21:11Z, all UTC) |
| Base | `8947666` (Inc 9a final); `b100-inc10` branches from the integrated 9b (`741cc07`), merges the corrected 9b (`1747479`), then merges `main` after 9b closed (`98d521e`). Tree at `1747479` plus uncommitted corrective edits at the time of writing |
| Import proof | `s19_app.__file__` printed in every transcript header (the worktree's `s19_app/__init__.py` for GREEN/guards runs, a scratch copy's for RED/mutant runs) |

---

## 1 · What changed

**The feature (HLR-174 / HLR-174a … HLR-174d).** One short confirm modal — `ConfirmQuestionScreen`, two buttons `#confirm_yes` / `#confirm_no` — asks before an image-replacing route replaces unsaved work. The four routes (the Load dialog, the Workarea Files pick, the variant switch `v`, and a project load) all pass the one seam `_confirm_then_load(kind, go)`; the guard `_load_would_lose` asks over the three unsaved flags (D, the image; W, the Patch Editor; F, the Flow Builder) by load kind; `y` / a click on `#confirm_yes` runs the load that asked, `n` / `escape` / an immediate `enter` (focus on `#confirm_no`) cancel and keep everything.

- **HLR-174 — one question before an image-replacing route replaces unsaved work.** D for an image replacement, D/W/F for a project load; an attach (MAC or A2L) never asks (LLR-174.1, .1a, .1b). The 24-cell trigger table: 11 ask, 13 load.
- **HLR-174a — a load that would replace or move nothing unsaved does not ask**, whether or not a project is open. The `pb_A` prototype asked whenever a project was open; the approved text overrides it.
- **HLR-174b — Replace continues the load.** `y` and a click on `#confirm_yes` run the load that asked (LLR-174.2c, .2e, .2f, .3).
- **HLR-174c — Cancel keeps everything.** `n`, `escape`, `enter` on the initial focus and a click on `#confirm_no` leave the session and the kept work unchanged (LLR-174.2b, .2d, .2e, .3a). The focus after the close follows LLR-166.1.
- **HLR-174d — the question names every unsaved item.** The title (`Replace <current>?`), the image file name, `Patch Editor entries`, `flow <name>`, the target (`Load <target> anyway?`), the labels (`Replace (y)` / `Cancel (n)`), in at most two sentences, every name through `painted_names` (LLR-174.2i, .2k–.2q).
- **The modal's mechanics.** One modal, exactly two buttons (LLR-174.2); built from title/text/labels as parameters (LLR-174.2a, the quit arm Inc 12 reuses); the focus on `#confirm_no` (LLR-174.2b); the priority keys `ctrl+l/s/k/d` inert (LLR-174.2h); any other non-priority key leaves it open (LLR-174.2g); a second answer is ignored (LLR-174.2s); the Patch Editor's own Load button keeps `LoadGuardScreen` (LLR-174.2j) and its change-file dropdown now keeps the same guard (LLR-174.2t).
- **The question sits before the reset, never inside it.** The answer comes before `_reset_project_session` (LLR-174.3); a cancelled project load runs no reset (LLR-174.3a); `_handle_load_project` asks nothing (LLR-174.3b); a confirmed project load that is then refused (a 2-MAC folder, an unreadable A2L-only project) keeps the work (LLR-174.3c); a cancelled variant switch leaves `_pending_variant_id` unchanged (LLR-174.3d).
- **One seam, one question, the right kind.** `_confirm_then_load` is the one seam every image-replacing route passes (LLR-174.4); one question per request even when one request passes two routing functions (LLR-174.4a); the kind of a typed or recent path comes from the **resolved** path, failing closed to image when the typed and resolved suffixes differ (LLR-174.4b, CR10-01); a work-area file's kind comes from its suffix (LLR-174.4c).

**The interim line is gone.** LLR-165.3 loses its interim `Closed the Patch Editor document (N entries); unsaved changes were not kept` sentence (ruling Q2); its two TC-B100-10 arms and AT-B100-03's two assertions are re-pinned (the arms assert 0 closed-document lines; AT-B100-03 waits for the question and answers `y`).

**Corrective pass (E5).** 6 fix rows, one pass (`inc-10/E5-corrective-notes.md`). CR10-01 = SEC10-01 fixed the kind rule in `_load_path_from_user_input`'s data arm (the kind comes from `resolve_input_path`, not the typed suffix, so a relative `cal.mac` symlink to a `.s19` asks); SR-2 added the C60 test (`test_tc_b100_45_refusal_lines_paint_names_literally`) so M63/M64/M70 are killed; CR10-03/CR10-04 fixed two docstrings/comments; CR10-05 moved the `test_id_registry.py` bump into the docstring history; SEC10-02 widened the S10-04 backlog row (no code change). The 14 mutant survivors were re-run in a scratch copy: 13 re-killed and 1 confirmed equivalent (M08), final count **82 killed / 1 equivalent / 0 invalid / 0 non-equivalent survivors of 83**; the corrective-pass mutants MC1/MC2 killed 2 of 2.

**Process decision (operator override 2026-10-31).** Per increment, run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The touched-module run and the full suite are deferred to the batch-end battery (§7). E4's `guards-01-attempt1-failed.txt` is kept: the only failure was the expected `EXPECTED_SCANNED_TEST_FILES` bound (230 → 231, F4), fixed before `guards-01.txt`.

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens.py` | source | HLR-174 · LLR-174.2 … .2i | `ConfirmQuestionScreen(ModalScreen[bool])` (line 1230, after `ConfirmDiscardScreen`): `AUTO_FOCUS = "#confirm_no"`, `BINDINGS` (`y`/`n`/`escape`), `__init__(title, body, yes_label, no_label)`, `on_button_pressed`, `_close` with the `_dismissed` guard on its first line; `Text` labels, `markup=False`. `styles.tcss` unchanged (Q-6), so the layout arms of LLR-174.2r pass at 99/118/220 columns with no new rules. Final sha256[:16] `69a749f331f6d5c1` |
| `s19_app/tui/screens_directionb.py` | source | LLR-174.1c | `PatchEditorPanel.is_dirty` (read-only property over `_dirty`, after `mark_pasted`) and the `_dirty` comment naming its five writers; CR10-03 corrects the comment/docstring to name the three outside readers (the guard, `_handle_save_dialog`, the dropdown guard). Final sha256[:16] `1288d9015c281fe2` |
| `s19_app/tui/app.py` | source | HLR-174 … HLR-174d · LLR-174.1 … .4 | `QuestionKind` / `UnsavedItem` aliases; `_confirm_then_load` (the seam), `_load_would_lose` (the guard), `_load_question_text` (the composer); the four leaves (`_route_load_project`, `_load_workarea_file`, `_load_path_from_user_input`, `_handle_select_variant`) pass the seam; the `_pending_variant_id` stamp moves inside `go`; `check_action` adds `ConfirmQuestionScreen`; `_handle_load_project` runs the reads before the reset (S10-01/S10-05); the dropdown guard (S10-02/A10-R2-3); S10-04's three painted refusal lines; CR10-01's resolved-path kind rule; CR10-04's docstring. Final sha256[:16] `5a9550c493ab6ad1` |
| `s19_app/tui/styles.tcss` | source | LLR-174.2r | **unchanged** (ruling Q-6): the existing `.modal-dialog` and `.modal-buttons` rules (the classes `ConfirmQuestionScreen` carries) already make the layout arms pass at 99/118/220 columns. Final sha256[:16] `5093edc072e03091` |
| `tests/test_b100_load_question.py` | test | HLR-174 … HLR-174d · LLR-174.1…–174.4 · AT-B100-15 · TC-B100-44/45/46/72/12/70/66 | NEW module (55 nodes final; 52 at E4, then C60 + the two CR10-01 arms and the mutation-ruling arms in E5) |
| `tests/test_b100_session_reset.py` | test | LLR-165.3 · AT-B100-03 | re-pinned: `test_tc_b100_10_interim_discard_notice`, `test_tc_b100_10_notice_names_every_discarded_entry` assert 0 closed-document lines; `test_at_b100_03_project_load_over_unsaved_work_saves_only_p2` waits for the question and answers `y`; `test_tc_b100_10_no_discard_notice_when_nothing_unsaved` holds unchanged |
| `tests/test_b99_editor_image.py` | test | LLR-174.4 (TC-B99-40 re-pin) | `test_tc_b99_40_strip_shows_new_file_source_byte` waits for the question and answers `y` (C56) |
| `tests/test_id_registry.py` | config | HLR-174 | `EXPECTED_SCANNED_TEST_FILES` 230 → 231 (measured, F4; the bump line moved into the docstring history, CR10-05) |
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-174 … HLR-174d · LLR-174.x · LLR-165.3 · LLR-166.1 · LLR-167.8 · LLR-173.7 | E1/E3/E5 edits (LED .89–.91) |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-174 … HLR-174d · LLR-174.4b | LED .89 – .91 |
| `.dev-flow/BACKLOG-CODE.md` | doc | HLR-174 | items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/inc-10/*` | doc | HLR-174 … HLR-174d | the experiment records: `E1-scope.md`, `E1-rulings.md`, `E2-rulings.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E4-*.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `E13-notes.md`, `steps.log`, `codewire/*` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-019.md` | doc | HLR-174 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-10/*` | generated | HLR-174 | transcripts (evidence digest table at the end of §4) |
| `tools/e13/run.py` · `tools/e13/capture_all.ps1` | test | HLR-174 | orchestrator-owned: scenario `lq-question` |

## 3 · How to test

```bash
# from the worktree root; interpreter <HOME>/anaconda3/envs/s19env/python.exe
# the new load-question module (every node):
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_load_question.py
# the re-pinned nodes (targeted):
python -m pytest -q -p no:cacheprovider tests/test_b100_session_reset.py -k "tc_b100_10 or at_b100_03"
python -m pytest -q -p no:cacheprovider tests/test_b99_editor_image.py -k "tc_b99_40_strip_shows_new_file_source_byte"
# guards (the frozen-engine guard, the registry, the staging re-pin):
python -m pytest -q -p no:cacheprovider tests/test_id_registry.py tests/test_b99_staging.py tests/test_engine_unchanged.py
# mutants: evidence/inc-10/mutation-summary.md (83 rows) + mut-c-*.txt (the E5 re-runs)
# NOT run per increment (operator override 2026-10-31): the touched-module run and the full suite -> batch-end battery (§7)
```

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-10/`. **Final source hashes** (sha256[:16], verified with `sha256sum` at close): `screens.py` `69a749f331f6d5c1` · `screens_directionb.py` `1288d9015c281fe2` · `app.py` `5a9550c493ab6ad1` · `styles.tcss` `5093edc072e03091` (unchanged). Branch history in §2: `b100-inc10` branched from the integrated 9b (`741cc07`), merged the corrected 9b (`1747479`), then merged `main` after 9b closed (`98d521e`). Import proof in every header; `NO_COLOR` unset.

**Scope (operator override 2026-10-31, stated plainly):** run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. The whole touched modules and the full suite are **deferred to the batch-end battery** (with fix rounds for failures found there). `guards-01-attempt1-failed.txt` is the one kept failure: the `EXPECTED_SCANNED_TEST_FILES` bound, fixed before the final `guards-01.txt`.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` <-> LLR | `core` · `full` | TC-B100-44/45/46/72 (`tests/test_b100_load_question.py`), TC-B100-10 + AT-B100-03 (`tests/test_b100_session_reset.py`), TC-B99-40 (`tests/test_b99_editor_image.py`), TC-B100-12 / TC-B100-70 / TC-B100-66 (`tests/test_b100_load_question.py`) | `executed` — `green-01-new.txt`: **52 passed** (421.6 s); `green-02-repinned.txt`: **5 passed** (56.0 s); `green-03-merged.txt`: **257 passed, 4 skipped** (1472.6 s); `green-04-corrective.txt`: **10 passed** (55.2 s); `guards-01.txt`: **178 passed** (740.5 s) |
| **B · black-box** `AT-NNN` <-> story | `core` · `full` | AT-B100-15 (five halves) | `executed`: `test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route` in `green-01-new.txt` and `green-03-merged.txt`; RED `red-01-vs-base.txt` fails all 57 new-file + re-pinned nodes on `741cc07` (no `ConfirmQuestionScreen`) |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| E4 tester's new tests vs base `741cc07` | `red-01-vs-base.txt` | **57 failed** (573.2 s) — the 52 new-file nodes and the 5 re-pinned nodes all RED on base (no `ConfirmQuestionScreen` / `is_dirty` / seam) |
| E5 corrective arms on the pre-fix source `1747479` | `red-02-corrective.txt` | Part 1 **1 failed, 2 passed** (16.0 s): CR10-01 arm (a) RED, arm (b) and C60 GREEN on `1747479` (expected); Part 2 **1 failed** (4.5 s): C60 RED on `e4bfd6a` (pre-Inc 10, raw names) |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| the one question | `red-01-vs-base.txt`: all 57 nodes fail on `741cc07` (no `ConfirmQuestionScreen` exists); the 9a-tree probe (`work/probe_p10.out.txt`) shows the three key routes replace a patched image with the stack `['Screen']` |
| the one seam | `test_tc_b100_72_every_load_call_passes_the_seam` (AST census: the three loaders and `_handle_load_project` only inside a `go`, inside `_handle_load_project`, or `load_from_path`'s worker start; 0 bypasses); M77/M83 re-killed |
| the kind from the resolved path | CR10-01 arm (a) RED on `1747479` (`AssertionError: (0, None, False, False)` — 0 questions, `b.s19` installed over the patched image, D lost); MC2 (the typed-suffix rule) kills it on the corrected tree |
| the C60 painted refusal lines | RED on `e4bfd6a` (all three lines keep U+202E / U+00AD); M63/M64/M70 KILLED |
| the C08 focus re-home | the SR-1 spy count on `_rehome_focus_after_load` (1 call): M36 KILLED |

### Mutation verdicts (C-40)

**E4/E5 run on `1747479`** (`mutation-summary.md`; every transcript ends `restored = True`): **83 rows total. 69 KILLED, 14 SURVIVED, 0 INVALID.**

| Verdict | Mutants | Disposition |
|---|---|---|
| KILLED | 69 | each failure read for a behavioural assertion, not only the return code |
| SURVIVED, equivalent | M08 (screen-level `enter` binding — dead: the focused `Button` consumes `enter` first) | recorded, no code change; survives all 25 TC-B100-45 nodes |
| SURVIVED, wrong target / gap / weak test | M14, M15, M16, M29, M30, M32, M33, M50, M63, M64, M70, M71, M79 | re-targeted or strengthened arms in E5, all KILLED (`mut-c-*.txt`) |
| SURVIVED, re-derived | M75r / M75s / M76r / M77r (their original target line was CR10-01's rewrite) | re-derived on the corrected line, all KILLED |
| Corrective-pass mutants | MC1, MC2 (CR10-01 over-correction / the 1747479 rule) | 2 of 2 KILLED |

**Final count (E5): 82 KILLED, 1 equivalent (M08), 0 INVALID, 0 non-equivalent survivors of 83.** The 83 E4/E5 mutants ran on the pre-E5 bytes (`1747479`); the E5 re-runs used a scratch copy of the corrected tree (`<scratch>/c10/mutc`, never the worktree).

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| the question | `ConfirmQuestionScreen` is a `ModalScreen[bool]`; 2 `Button` widgets with ids `confirm_yes` / `confirm_no`, 0 other buttons and 0 `Input`/`TextArea`; the `_dismissed` guard is the first line of `_close`; no import from `s19_app.tui.app` / `.services` / `.workspace` (`test_tc_b100_45_modal_imports_nothing_from_the_app`) |
| the reader | `is_dirty` is a read-only property with no setter; 0 attribute reads of `_dirty` on a `PatchEditorPanel` outside `screens_directionb.py` |
| the seam | `_confirm_then_load(kind, go)`; every loader call inside a `go`; `None` treated as cancel by truthiness; no `try/except` in `_load_would_lose` (A10-02) |
| the refusals | `Variant not found` / `Variant file missing` / `No supported files in project` paint through `painted_names`, one call each (C60) |

### Guards and snapshot cells

| Run | Transcript | Result |
|---|---|---|
| guards attempt 1 (kept) | `guards-01-attempt1-failed.txt` | **177 passed, 1 failed** (814.6 s) — `test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` (`231 == 230`, F4) |
| guards on the integrated bytes | `guards-01.txt` | **178 passed** (740.5 s) (`tests/test_id_registry.py`, `tests/test_b99_staging.py`, `tests/test_engine_unchanged.py`, `tests/test_b100_load_dialog.py`) |
| the census sweep (`-k census`) | — | **not run** (operator ruling; batch-end battery) |

### Reviewers' probes

The code reviewer executed `probe_mac_link.py` (the CR10-01 scenario on `1747479`: `D before: True`, `route: ('data', '')`, `pushed: []`, `current file: b.s19`, `patched byte kept: False`), `probe_modal_under.py` (a question over `SaveProjectScreen` raises nothing, same on `1747479` and `e4bfd6a`), and re-ran `tests/test_b100_load_question.py` (52 of 52 with the default temp), `test_b100_load_dialog.py` + `test_b100_project_homes.py` (240 passed, 4 skipped, 2 `WinError 206` under a long basetemp) and the 5 re-pins. The security reviewer executed `probe_symlink_fallback` (SEC10-01), the type-ahead/stack/`ctrl+p` probes, and 8 targeted nodes (all passed). The full suite and the touched modules were `not-run` in both lanes (out of scope; batch-end battery).

### Security probes

`security-increment-019.md`: SEC10-01 (the relative-path kind read from the typed suffix — executed `probe_symlink_fallback`, `classifier=('data', '') questions=0 stack=['Screen'] file=b.s19 D=False digest_same=False`), SEC10-02 (the S10-04 backlog row leaves out the work-area race line — by reading). Re-verification of the E3 mitigations: S10-01/S10-05 (reads before the reset), S10-02/A10-R2-3 (the dropdown guard), S10-04 (painted refusal lines) — all `executed`, `approved`. Full per-question results in `security-increment-019.md`.

### E13 (C-UX-5) evidence

Orchestrator-owned captures, real Windows Terminal: scenario `lq-question` (seeds project P clean plus `workarea/temp/fw2.s19`, patches `firmware.s19` with one entry, starts a project load of P, stops with the question open). Painted text: title `Replace firmware.s19?`, body `There are unsaved changes in firmware.s19 and Patch Editor entries. Load project P anyway?`, buttons `Replace (y)` / `Cancel (n)`. **3 PNGs** in `evidence/inc-10/e13/` (`lq-question.118x54.png`, `lq-question.220x60.png`, `lq-question.99x54.png`), `DONE failures=0` (`E13-notes.md`). At every size the title names the image, the body names both items and the target, both buttons are fully visible with their keys, the focus starts on Cancel, and nothing clips; the body soft-wraps to 2 clean lines at 118 and 99 columns. No OBS.

### Experiment step table (from `inc-10/steps.log`; UTC)

| Start | End | Step | Agents | Outcome |
|---|---|---|---|---|
| 14:32 | 14:51 | E1 | 1 x Opus | 36 single-"shall" requirements (5 HLR + 31 LLR); Q1–Q8 ruled (all as recommended) |
| 16:27 | 16:40 | E2 | 1 x Opus | baseline 37 nodes; prototypes G-A 9 nodes/39 examples, G-B 12 nodes/57 examples; Q-6 (probe: `styles.tcss` unchanged, 3 source files) |
| 17:14 | 17:27 | E3 (2 rounds) | 2 x Opus (architect ∥ security) + 1 design-fix pass by DeepSeek v4 Pro | r1: architect PWN (1 MAJOR), security PWN (2 MAJOR); r2: architect PWN (3 NIT), security PASS (2 NIT); E3 closed; addenda S10-05/S10-06/A10-R2-1…3 |
| 17:59 | 19:31 | E4 | 2 x DeepSeek v4 Pro (G-A + G-B) + 1 x Opus (tester), then 1 x Opus (integration) | 57 new+re-pinned items, 57 RED on `741cc07`; GREEN 52/52 new, 5/5 re-pinned, 178/178 guards; **0 source edits** at integration |
| 20:52 | — | E5 | 1 x Opus (reviews + corrective) + 1 x DeepSeek v4 Pro (mutants) | code-review PWN (1 MINOR), security PWN (1 MINOR, same defect); 69/83 → 82 killed + 1 equivalent; no re-review (nothing blocking) |
| 21:11 | — | E13 | 1 x DeepSeek v4 Pro | `lq-question` 3 PNGs, failures=0, no OBS; close records start |

Note (corrected at close): times in this log are local (UTC−6), not UTC; see 05-postmortem.md Record corrections.

First step start to the last logged step: 14:32Z to 21:11Z = about 6 h 39 min wall. Raw facts for the operator's comparison: **E3 (design, no code) caught 3 MAJOR in round 1 (A10-01, S10-01, S10-02) and 0 in round 2; E5 (code) caught 0 HIGH and 1 MINOR (CR10-01 = SEC10-01, found independently by both reviewers); 1 corrective pass; 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes. The table is filled by the orchestrator.

The digests are the SHA-256 of the staged blobs (`git cat-file blob :<path> | sha256sum`), taken after the close writes.

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-10/` | SHA-256 |
|---|---|---|
| lq-question.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-10/e13/lq-question.118x54.png | 3b4f7dd648d3c03711cffa1a793032113311cbc96edf0ff39490dee0d6cb2794 |
| lq-question.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-10/e13/lq-question.220x60.png | e9a9c94b43a64575188cb26a40247dc3d489f2aecfa79e23a485230f17bf103a |
| lq-question.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-10/e13/lq-question.99x54.png | a0eecb69dc2b574231af33dfb1887fcb30a3606dbf79f5b3ce40f23d09bf276a |
| green-01-new.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/green-01-new.txt | e59631f3a8a7b2956d13976c3af09c99899a74ff781e231da935e2665b960660 |
| green-02-repinned.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/green-02-repinned.txt | 0ddd7ed0352c9c57808a3ad651edef75f50f3fad6a36a64320a7036b032ba1de |
| green-03-merged.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/green-03-merged.txt | 2186e55e53ca686e5e3b4dd23f84167fe4095a63cc90e48d5de340559ef7abf5 |
| green-04-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/green-04-corrective.txt | 33e1ebfc465c9f62b85c6a4496bfb30244cd21ae8b4757a60a8e8d54df889065 |
| guards-01-attempt1-failed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/guards-01-attempt1-failed.txt | ab09a3ff3eb8adaf4643db17537fdb471bc24e571610d7b159e916eb9cdfb7c9 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/guards-01.txt | 601535345332ab4e9375435f8c4fd6062dc314c3459512e0a5a2dbf956ef1a16 |
| mut-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-01.txt | 4720325933f1a0330d030b07db1d8719b57ed079d7670ae5994af269340be29f |
| mut-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-02.txt | c39ddce9e9c9573fd5eba5a8fc2331b56cec03504fd40599238c4d23b7979e8b |
| mut-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-03.txt | c8a02f58f2b026b3ac3497bc35bd6a83564b31b1a94c0c154b771104893d9997 |
| mut-04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-04.txt | f432dcbb0eac3fb5e81b0def635c371e1bc5c58c9a0b1862549c0e2d1d4020ab |
| mut-05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-05.txt | 4295a66072167911b9a79cc00dc36daae7db19350ca425d383e9055fd10877ab |
| mut-06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-06.txt | 254992ac51e4db70ba8567aec8de06c618b1e5e90013e5519cac2d4b9ae0f431 |
| mut-07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-07.txt | aacef3ef16ab10f525662ccef2b1a49b1de3abe044b0452746bfc6310cac365c |
| mut-08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-08.txt | 830b8d46d746893dcfeda530f7dacd1385b09a2df77cdb4cefee0716f50d25bc |
| mut-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-09.txt | cd2659f816a6efb2651e49c3a65c9893e140c35d2278f6643074dcb1735b1eec |
| mut-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-10.txt | 0d0c1a4530a123485242e4be0a7e1f0d2ffdbdc9b96a8e81c57063eece5c4443 |
| mut-11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-11.txt | ef21e9d90fe9a3f5bd347c9c1b074c4d78e9463e590737810e5142531a7d72ed |
| mut-12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-12.txt | 2fa47b2153595303b1586c6dd550e1e9feb92cb3d6a49be3eb7362b5810c9375 |
| mut-13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-13.txt | f9262658b57a0c9c0c00296f544383269e1d8bd2b4eef2593c87cb6e17fb6f11 |
| mut-14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-14.txt | 0b7b5abb8ed496c3cc4c4f3598ec16ba5528cc2a027df24ed445c36e64d54e4c |
| mut-15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-15.txt | 9e049907361a2b38061a827a45a76671633e77af92fa68c1188532e5117c4265 |
| mut-16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-16.txt | 8d7fadb28ffc4be3bc899d4858156f536f9ed520c38a90b76c465fc6bde55092 |
| mut-17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-17.txt | de5375a8ea06f80aa4a1f237d1ea6272bf23be7efa424aabf08cd33476225aaf |
| mut-18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-18.txt | ddd281144dd6c7913cb16502f63157e5faecc894ce5873a3cc08257470bd79bc |
| mut-19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-19.txt | 399751560854391f0f655eda104c004baacb15998a13a0f233acd0d30da11ce6 |
| mut-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-20.txt | 978040737adbd9b766cc47fb9ca98f059ec21dda45db7b82d5fc67487f9a4d16 |
| mut-21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-21.txt | 7c2fd1fe3d30ed6a6e203a2ede50690e810badd6fe31e9b5c09e30d4902edc29 |
| mut-22.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-22.txt | 2795b40f76f3414fc7cf0e7e6015cd12305e69649d69ced7ce087a910ebd2721 |
| mut-23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-23.txt | 96b8ad2276e69ecfeda640a3512bee9c71467506418377d56b24206792b88181 |
| mut-24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-24.txt | 46546bea07befb2775a6cff5f6057d606e332c11d94c9dfb571c5f3b418f65ce |
| mut-25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-25.txt | 538e989b07d99f5d9d48773062fb5ae06c7e6ca94f7598e74400856e8f028147 |
| mut-26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-26.txt | 04e997a2f5bfe242662a6339be74cfd1b8020976642452df43ea2425c8d5f54b |
| mut-27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-27.txt | edfa1e4bf8fdb6b108f0df8f330bc4d93ca43273fd67bd14d44f30dc93401878 |
| mut-28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-28.txt | 3674e893f7a8d0385e1945503d5ef817f926cee88d180d7f31fe14981ab06378 |
| mut-29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-29.txt | 72781f313d453e0bb90988af5b51d89fe42020e121965a67dc8049f522fc0d66 |
| mut-30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-30.txt | 20c3cbc208afaca44fb906e2880863627a512bb779b34962388d9201936eabec |
| mut-31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-31.txt | 5dc84006fdd9d8096072606954c3c65fad77087ef34228380d3c83d3aa670622 |
| mut-32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-32.txt | 394179c36e90c6787f469d207e588f421b81c7cc596c731bb2cf0deac7b50a24 |
| mut-33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-33.txt | 872cadde3cca5578643981fe01515575fc667e3cf5d0efdc06bf98fb39fb04c6 |
| mut-34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-34.txt | b7da66143b111659b755336832fc2ca23bf7ac707761da52e7387653e2b311b0 |
| mut-35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-35.txt | b363df33d81e1d39dc4fb909aeb3e371ea739b385d2d23c0d3bc43397b141f8b |
| mut-36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-36.txt | e43bee05e145f3e25820ddc54be49225fd53232aa3999c594ac04569c27f2caa |
| mut-37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-37.txt | 8588f56686aa3c0b2821b09b67dd38cf79a1c78bbf7617f36c05d34911df50f6 |
| mut-38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-38.txt | d4b7e3ca289099026a731689948cd3eddd728c7e276374e835373ae3889ff22f |
| mut-39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-39.txt | d7f7d39ce8f17b7c1b36132547f77315c4cd49f14c493efd30fc16e78e9bb7fa |
| mut-40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-40.txt | b29f16b9a15d83a68d7a5bfc85ccf3419adce3a6ccba1407daefee4f02408b9d |
| mut-41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-41.txt | 6dee6c022d33ed14b10d7ffc67122c5eb43aa12c71db36a7a226ec235f4ccd06 |
| mut-42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-42.txt | 0f37308cee0947a5de3b16b2d43af56d6cb0c90dd01e2c63393f85fa2a56dd0d |
| mut-43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-43.txt | c92cb419812be9d3366406ad96c01e20f7990ddbbae5fc2ffa95c352ae830554 |
| mut-44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-44.txt | 8d56d7d031e89c806f29751846c1c5a4ff79b6fc9c722f19c68995952555d954 |
| mut-45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-45.txt | b5cdb7259b1379d20dd265a9bb0b15a749bd32b334eb50e91c429cb76f953067 |
| mut-46.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-46.txt | 7f2bdeb9d5e83c9e6437ba45542021b1f4d1fb52856afd4d71fb6fa3534a9dd0 |
| mut-47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-47.txt | 943e5569afcbea98cd933683b7e9b6783cf7e5692b66ea17ec4458965d2bc1de |
| mut-48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-48.txt | fef8d0f4132471b9cb084ebc1afc9b3d884bcc43c360d8e8aadc96c81e3466d1 |
| mut-49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-49.txt | b2668bf740543eb7c0c7b6032ad090e3a29234efc0b82771643533a6f3e69af2 |
| mut-50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-50.txt | c6f3253281786b750a22fdc50682d4dba34a38f17a6b4c13bdde656c164de92b |
| mut-51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-51.txt | 6f02412c5913795440264591e579a1e8e234a45b40d689c06cda151b0b3683f8 |
| mut-52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-52.txt | c264f546c54435cc4863fd2b8970de667186b56f444cdd41ad9e742ed10d64cc |
| mut-53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-53.txt | 25d67d2bbbe98d4b74c1932212d2231e7ba7a01f631d4f820ffd50ae122b4f92 |
| mut-54.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-54.txt | d60da3e46f13471f3268b72543b5643498482f7fe6441a2532bc5b18bd385b5d |
| mut-55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-55.txt | eb8b7b29739970f93da69ee4fcca84beb48fa0baee9ab0ac27ba052dc9171a60 |
| mut-56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-56.txt | 8cb025a05cf55aff261a112bdb32174ccfb9b418f41a4a01a7a2d9f639505f32 |
| mut-57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-57.txt | 5124cc371cbf1c9501edd5a84af46f238228a0a63e3719a67da8ceadd8b88665 |
| mut-58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-58.txt | 26d14551608c1815e550629e9b46d932e4b18a1220e3e44e95e9c2e804e70448 |
| mut-59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-59.txt | 75d0c5065294be900bd88f61da7273c2916015813139c317dc4adba95b9ee33c |
| mut-60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-60.txt | 5b1cb3ee8e630b28283d277281624acdb10e458d821bc02aa31b4285e2b6c946 |
| mut-61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-61.txt | 04a5b0fda049bd157f753a13a4f8a90e38f95e105a2b98f854039474c9cdfe0a |
| mut-62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-62.txt | 194143688f759fa4f36c71a04ce7de0ddd7eef04f9b9e07e98052d1dd91bab87 |
| mut-63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-63.txt | ce9f27eb4ae4476f3bdaa036063849e46d30e59a239c48c354be152a982444cc |
| mut-64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-64.txt | 3d6fdc184adfaa334d52607b169d797771b6a280e466cda2111aa734529cff01 |
| mut-65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-65.txt | aff74c7ba63aab682c6f644bf4f02cc40d1fda3756f91924aff807f1fd9a5794 |
| mut-66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-66.txt | 1b40a6f75d73f4fcc65c5bd96f2778270a4d54b8ccc4c0ac3fb1a2c2fa2eed1d |
| mut-67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-67.txt | 1e15315dcb112b38e731d2803560d5fd1dab5e77108f462bb5b5da1abc23bc4c |
| mut-68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-68.txt | c146f09dbba8880e51179f6b846508c435ff88a72fa66cdfc2c461303937c10e |
| mut-69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-69.txt | 6a2dc8b798ff19a92aa9f567646c577d3e199af59bdb24473d51e079d9a655b0 |
| mut-70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-70.txt | 7f6385ccec74063af61fac210e0012ffac8e67f6b8758760079f2efe8f1655ab |
| mut-71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-71.txt | 5753981f1eb510ebc0fc6a8b17fb42504f196a35d5d47566f4fbc9643d1f0a17 |
| mut-72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-72.txt | ec52206f7f24035231380d1c6a7abfc1506bc65f1c1c21f6a93c56c1f510eee2 |
| mut-73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-73.txt | 823b29d6aa058262d81f74d991ecd68fbfc1a5654a7a9a445253512902721c30 |
| mut-74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-74.txt | 21189654fd087b1b7c7270717305b2f7e4ad8716f548e0592afc8a58119eca4a |
| mut-75.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-75.txt | 87713dd0c1806d6789923f880f6f6a65bd0b69891a104b2e30f0aea54f64953a |
| mut-76.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-76.txt | 2b6ca01f298f46fe955d2209ce09e96925ab63dda8eacdad9e4eb1da36d4c38f |
| mut-77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-77.txt | cc31abaf668f17c9bb4ac5ad7016adcd9d48bbaf9b5d1295ff8a8d94349e1bcc |
| mut-78.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-78.txt | 515f4b323c6c5d8c417d96a5b2ae8c48adaf6778135e816ad3825e938c3eae24 |
| mut-79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-79.txt | 8a26125779e8cb7e49fd7e76a263ec4f2195ee83e279f41b2a1dbf711ce02390 |
| mut-80.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-80.txt | 10f898140a2cccaa40732e29765219d162e3ee3e69d5188d9a9257ea44973cb3 |
| mut-81.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-81.txt | 7091264c764148fd5690cf64326a36cfc2530576e6bc65368578e53265557f41 |
| mut-82.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-82.txt | 2287fb42173ffd9f75ab49ed6bed491e69d3e814596fec84691811264b959262 |
| mut-83.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-83.txt | 764e120ad16e9c91bfb688af1286d07588723f491585e6307ce4d1d4ceb8097e |
| mut-c-M08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M08.txt | f381ebc7f39fe0b5893a890be1440a60baa1e9c9ed4404fe628b778868da3122 |
| mut-c-M14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M14.txt | 5a12ffb23c0cd3605e166fe616ba6d9b170d39f60c983eb5781d565fe042d2ab |
| mut-c-M15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M15.txt | 29afe6beff50ff71cd2a9aef56dac1f247c32b48c6a424ed35fa07aac061a403 |
| mut-c-M16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M16.txt | cdc15698d4b0c029f95b2859c5c7adcdde293f1f76274d406ff340d4682d951c |
| mut-c-M29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M29.txt | 46ffd982ad539757437c9e7efd657f53d984d9816688ccadbe4080b8923e2f1a |
| mut-c-M30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M30.txt | 757690d77bbf3204dbef65f423604d7d05af19db599dd1667acd6ea3ec9b3492 |
| mut-c-M32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M32.txt | f8e2569e13f46ab45c132f5001e9d687d9aca4744c2a5175afcd69a2f2060024 |
| mut-c-M33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M33.txt | 2e7e7dcd14a7826f479f94bc8826645cc0b1fb1a6b38864c54053354053222a5 |
| mut-c-M50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M50.txt | 9d128d9ef0afde6f6eae6d5075255e33c030388387fa9d81b1dca25223062137 |
| mut-c-M63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M63.txt | 9e3d54979960043283f88796cbea29a9554146dd070974597d9f918a94ac2a02 |
| mut-c-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M64.txt | ce58afdea19bee0b425d4a27b6c14d86417a4a3d6df50186696f9f37cb48421c |
| mut-c-M70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M70.txt | ccaafd90d996d9161987aa534d4f5bbeeed6cf812c5064300a60bc1a8eea1c58 |
| mut-c-M71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M71.txt | 164363bce12a7926c51a216d9ccfb23c185fcc0ae29c1996d062e2f2673c5463 |
| mut-c-M75r.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M75r.txt | 8a8a84ec5eb3cef9719dd8884eb3090e933e6825c8af2f92d82291fb07721ea4 |
| mut-c-M75s.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M75s.txt | fb0c806ebc984795eeda5f137110795e17a091fd71e3166d27bfdd5cf58de807 |
| mut-c-M76r.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M76r.txt | 16ed139a743b895d042e5bb08b1fae9b7f5117036c9a5b41dc9d426cd88d1e80 |
| mut-c-M77r.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M77r.txt | ecd79953230bf17ef7f96cc508d3fb0cd8c9aa16b2805093a94f953ef244e34c |
| mut-c-M79.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-M79.txt | dc7a421f3042c12acf7885501b1405e2e1cd6342c94a089e457e0d46c0c8ebaa |
| mut-c-MC1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-MC1.txt | faa6ce8125015250b2eca7a250b729c47489b47b855d487cab43b55008ee611f |
| mut-c-MC2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mut-c-MC2.txt | 61d02960d42326b39cb281609e3528cf6420a616e7b4c45857df79491a09cb07 |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-10/mutation-summary.md | 2dad97a722668d1bc61b233be5fb15b25868b159e9030757324e19a53fa57304 |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/red-01-vs-base.txt | 2b5d9d7aacdc3bac872dd82c43aae322bfc9ef9b80f576f925276741bb80dc20 |
| red-02-corrective.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-10/red-02-corrective.txt | eb922ad16492b37c899498de8d23b19d00199baaf2d9ed8bc94aab1b5d3c4af5 |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · **PASS-WITH-NOTES** (0 HIGH, 0 MAJOR, 1 MINOR, 4 NIT) — "OK to advance, with notes". The MINOR CR10-01 is the resolved-path kind rule; NITs CR10-02 (re-record GREEN on the merged tree), CR10-03 (the `is_dirty` three-reader docstring), CR10-04 (`_confirm_then_load` returns `bool`, never `None`), CR10-05 (the `test_id_registry.py` bump history). Diff read in full. — `review-increment-019.md`. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · **PASS-WITH-NOTES** (0 HIGH, 0 MAJOR, 1 MINOR, 1 NIT) — SEC10-01 (the relative-path kind, the same defect as CR10-01, found independently), SEC10-02 (the S10-04 backlog row widened). Executed probes. — `security-increment-019.md`. **Design reviews (E3, code-free):** `architect` (2 rounds: r1 PASS-WITH-NOTES 1 MAJOR, r2 PASS-WITH-NOTES 0 MAJOR) and `security-reviewer` (2 rounds: r1 PASS-WITH-NOTES 2 MAJOR, r2 PASS 2 NIT) → design approved (`inc-10/E3-architect.md`, `E3-security.md`). **There was no re-review:** nothing was blocking — the E5 reviews left 0 HIGH and 0 MAJOR in the source, and CR10-01 = SEC10-01 (the one MINOR, the same defect found independently) is a recommendation that does not block, so the narrow re-review is satisfied by the corrective pass's RED/GREEN/mutant evidence (`red-02-corrective.txt`, `green-03-merged.txt`, `green-04-corrective.txt`, `mut-c-*.txt`). **Orchestrator (2026-10-31).** Final source hashes `screens.py` `69a749f331f6d5c1`, `screens_directionb.py` `1288d9015c281fe2`, `app.py` `5a9550c493ab6ad1`; `styles.tcss` unchanged (`5093edc072e03091`). Scope ruling in force: per increment, the new and modified requirement tests, the modules that exercise the changed functions and the guards only (LED .75); the touched-module run and the full suite are deferred to the batch-end battery by the 2026-10-31 override. Rulings applied: Q1–Q8 (`inc-10/E1-rulings.md`), the E2 rulings (`inc-10/E2-rulings.md`), A10-* / S10-* / A10-R2-* (`inc-10/E3-rulings.md`), ruling 7 and SR-1/SR-2 (`inc-10/E4-integration-notes.md`), and the E5 rulings CR10-* / SEC10-* (LED .90). |

---

## 5 · Risks

- **The touched-module run and the full suite were not run for Inc 10** (operator override 2026-10-31). A module outside the new-file/re-pinned set that calls one of the changed functions after the corrective pass has not been exercised here. The batch-end full battery is the check (§7).
- **The S10-03 in-flight worker.** A load worker that is already running installs with no check; an image patched during a running parse is replaced with 0 questions. Declared, routed to Inc 12b (its ruling Q3 refuses Patch Editor changes while a session-writing action runs).
- **The C39 race.** A work-area file deleted while the question is open asks 0 questions and the pick then fails (`load_selected_file`'s `Load failed` line, the raw path). The kind check's `exists()` stays before the seam (M79); declared design note, not a test.
- **The `W\temp\x.mac.` residual (Q-4).** A path whose suffix reads `""` after the strip is an image kind, so a work-area MAC-like name ending in a dot asks once for nothing; `load_from_path` then refuses `Unsupported file type`. Nothing is lost.
- **The SEC10-01 reachability.** The kind fix needs a link with a misleading suffix reached only through the relative fallback; on hosts where `os.symlink` raises, the CR10-01 link arm skips with a reason (it ran here).
- **Stacked questions.** Two requests made before any answer stack two questions; `y` on the top one loads, and the lower question then names a patch that no longer exists (stale text, harmless — `n` keeps the loaded file, and no order loses work without a `y`).
- **Declared risks (not backlog).** The A2L-arm typed name (CR10-01's declared deviation: `_load_path_from_user_input`'s `a2l` arm keeps `typed.name` as its target; an A2L attach never asks, so that target is never painted and no test can observe it).
- **Model performance.** DeepSeek v4 Pro implemented G-A and G-B with **0 deviations** (both implementers declared none; the 4 E4 failures were all test-side), ran the **83** mutants (69 killed at first, then the survivors re-run to 82 killed / 1 equivalent), and did **1 design-fix pass** (E3 r1). Opus did E1, E2, E3 (2 rounds), the tester, the integration (0 source edits), the reviews and the corrective pass.

## 6 · Pending items / spec deviations

**Backlog added at the close** (`.dev-flow/BACKLOG-CODE.md`, each with its evidence path and home):
- Q7 (E1-rulings) — unload over a patched image is out of scope for the load question → **Inc 12a sweep**.
- Q8 (E1-rulings) — the Flow Execution panel's unsaved flow sets are out of scope → **Inc 12a sweep**.
- S10-03 (E3-rulings) — an in-flight load worker installs with no check → **Inc 12b**.
- S10-04 + the widened SEC10-02 row (E3-rulings + E5-rulings) — status lines after `y` paint a raw path or exception text (`load_from_path`'s `File not found: {path}`, `load_selected_file`'s / `_handle_load_error`'s `Load failed: {exc}`) → **Inc 12a sweep**.

**Declared (Risks, not backlog).** The A2L-arm typed name (CR10-01's declared deviation — `typed.name` stays the `a2l` target; never painted, no test can observe it).

**Named gaps / observations.** M08 is an equivalent mutant (recorded, no fix). OBS-10-*: none — E13 found no defect. The `mut-c` transcripts name the scratch `--basetemp` paths in their `command:` line (the temp folders themselves were removed).

**Finding → disposition (E3, code-free design review).**

| Finding | Severity | Disposition |
|---|---|---|
| A10-01 (dead `None` arm), A10-02 (guard fails open) | MAJOR / MINOR | E3 r1 rulings A10-01 … A10-11 (LED .89) |
| S10-01 (refusal after the reset), S10-02 (dropdown replaces entries) | MAJOR | E3 r1 rulings S10-01 … S10-04 (LED .89) |
| S10-05, S10-06, A10-R2-1 … A10-R2-3 | NIT | E3 r2 addenda (LED .89) |

**Finding → disposition (E5, code).**

| Finding | Severity / tag | Disposition |
|---|---|---|
| CR10-01 = SEC10-01 the kind read from the typed suffix | MINOR / design-gap | fixed (resolved path, fail closed); `red-02-corrective.txt` + MC1/MC2 |
| SR-2 the C60 test gap | — / test-gap | fixed (`test_tc_b100_45_refusal_lines_paint_names_literally`); M63/M64/M70 KILLED |
| CR10-02 re-record GREEN on the merged tree | NIT / impl | fixed (`green-03-merged.txt`) |
| CR10-03 the three-reader docstring; CR10-04 the `bool` docstring | NIT / impl | fixed (comments/docstrings only) |
| CR10-05 the registry bump history | NIT / impl | fixed (docstring form) |
| SEC10-02 the S10-04 backlog row widened | NIT / design-gap | backlog → Inc 12a sweep |

**Orchestrator rulings Q1–Q8** are in `inc-10/E1-rulings.md`; the **E2 rulings** (Q-1 … Q-7, Undo boundary, `_pending_variant_id`, Census, G-B P-1/P-2/P-3, G-A P-GA10-1/P-GA10-2, Q-6) are in `inc-10/E2-rulings.md`; the **E3 rulings A10-* / S10-* / A10-R2-*** are in `inc-10/E3-rulings.md`; the **seam rulings 7 and SR-1/SR-2** are in `inc-10/E4-integration-notes.md`; the **E5 rulings CR10-* / SEC10-*** are in `inc-10/E5-rulings.md` (LED .90).

**Re-pins (test::node — old -> new — requirement).** The 5 re-pinned nodes move the interim-line expectations to the question: `test_tc_b100_10_interim_discard_notice` / `test_tc_b100_10_notice_names_every_discarded_entry` assert 0 `Closed the Patch Editor document` lines (LLR-165.3, ruling Q2); `test_at_b100_03_project_load_over_unsaved_work_saves_only_p2` waits for the question, asserts it names `Patch Editor entries`, presses `y`, and drops the two interim-line assertions (§C.5); `test_tc_b99_40_strip_shows_new_file_source_byte` waits for the question before answering (C56).

## 7 · Suggested next task

**Inc 11 of batch-100** — the Save dialog (`HLR-175`) — with the `dev-flow-v3-beta` pipeline; its E4 integration is in progress on `b100-inc11`. Carried into it from this increment: the Save-dialog priority-key exposure (Q6, from Inc 9b's close) and the quit question that reuses this increment's `ConfirmQuestionScreen` (Inc 12a+12b).

**Batch-end full battery (owed once, when all increments are done — operator rulings 2026-10-30 and 2026-10-31).**
1. the touched-module run deferred by the 2026-10-31 override, every failure dispositioned against base;
2. the full reverse census / full suite on the final tree;
3. the guards and the census sweep (`-k census`) on the final bytes;
4. the mutants of every increment re-run on the final tree where a later increment touched the same function (the 83 Inc 10 mutants ran on the pre-E5 bytes `1747479`; the E5 re-runs cover what E5 changed);
5. the CI run, comparing the FAILED set with the previous run.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 of the 4-file cap (`screens.py`, `screens_directionb.py`, `app.py`); `styles.tcss` is unchanged (Q-6) — §2 |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_load_question.py` (NEW, 55 nodes) + the re-pins in `test_b100_session_reset.py` / `test_b99_editor_image.py` + `test_id_registry.py` F4 — §2, §4 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | pure units: `_load_would_lose`, `_load_question_text`, `is_dirty`, the modal's verdict providers |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01-vs-base.txt` (57 items RED vs `741cc07`); `red-02-corrective.txt` (CR10-01 arm (a) RED on `1747479`, C60 RED on `e4bfd6a`) |
| 5 | Reverse census declared | `core` · `full` | ⚠ | **not run per increment — operator override 2026-10-31, batch-end full battery** (§7). The new file, the re-pinned nodes and the guards ran |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES (0 HIGH, 0 MAJOR in source); no re-review owed (nothing blocking) |
| 7 | No file from another lane touched | all | ✓ | the 3 named sources + tests / fixtures / config / records; `tools/e13/` is the orchestrator's; `prototypes/` untouched |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `_ENGINE_PATHS` modules untouched (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`); `screens.py` / `screens_directionb.py` / `app.py` changes are additive |
| 9 | Coverage claims verified on disk | all | ✓ | every count cites its transcript; the 83 E4/E5 mutants are stated as run on the pre-E5 bytes `1747479`, the E5 re-runs on the corrected scratch tree |
| 10 | Load-bearing emptiness declared | all | ✓ | the CR10-01 arm (a) and C60 fail on their base trees; the C08 spy count turns M36 RED; M75/M76/M77 re-derived and killed |
| 11 | Mutation verdicts declared — per arm | all | ✓ | 83 run: 69 KILLED, 14 SURVIVED, 0 INVALID; E5 re-runs: 82 KILLED, 1 equivalent (M08), 0 INVALID, 0 surviving — §4 |
| 12 | Instrument RED-proof declared | all | ✓ | §4 Instrument RED-proof |
| 13 | Correction population declared | all | ✓ | writers of the question: `_confirm_then_load`, `_load_would_lose`, `_load_question_text`, the four route leaves, `check_action`, `_handle_load_project` (reads before reset), the dropdown guard, `_load_path_from_user_input` (CR10-01), `ConfirmQuestionScreen`, `PatchEditorPanel.is_dirty` |
| 14 | Emitted-form assertion declared | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b — `code-reviewer`, `security-reviewer`, E3 `architect` and `security-reviewer` |
| 16 | Evidence files declared | all | ✓ | §4 evidence digest placeholder the digest table (filled by the orchestrator from the staged blobs) covers `evidence/inc-10/` |
