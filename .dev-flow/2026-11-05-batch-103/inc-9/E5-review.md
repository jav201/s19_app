# Inc 9 E5 — review (X9, one reviewer, one pass: code + security)

Model claude-opus-5-5. Tree `b103-inc9`, start tip `811198b5`; base `git merge-base HEAD b103-inc8` = `6c4fd21f`. Diff reviewed:
`6c4fd21f..811198b5 -- s19_app tests` (25 files, +6797 / −8; product: `definition_bench.py`, `definition_bench_view.py`,
`bench_sheet.py`, `app/patch.py`, `services/change_service.py`, three one-line Inc 8 seams incl. F-W1 in `sheet.py`).
Runner: rtx, HT-02 env, HOME basename `<runner-home>`, `s19_app.__file__` atop every transcript, scratch `~/work/zq-x9/`.
Evidence: `evidence-e5/` (transcripts, scripts, the arrival mutant), captures `evidence/e5/captures/` (`E5-captures.md`).

## Verdict: FAIL — one MAJOR open (F-X9-2, product), handed back to the orchestrator

## Findings

| Id | Tag | Severity | Finding | Disposition |
|---|---|---|---|---|
| F-X9-1 | impl (test instrument) — the independent review of F-FX9-1 | **MAJOR**, fixed here | FX9's `handled_press` timed a key from `driver.send_message` called by the test coroutine. That coroutine runs on the UI thread's own event loop, so it can only send once any UI-thread work at the preview's arrival is over; R-PE-BENCH.29/2's own negative control ("the diff and lo/hi done on the UI thread when the result arrives") was never run (MW9: ".29/2 uncovered"). Stand-in mutant (`evidence-e5/scripts/mutant-arrival.py`: `_job_done` sleeps 0.8 s on a preview result) **survived**: `transcripts/m292-arrival.txt`, `1 passed in 102.96s`, load 0.69 before. A vacuous timer. | Fixed test-side in `tests/test_b103_inc9_w_jobs.py`: `keys_until` now sends each key from a thread (`_typist`, as a terminal's input thread does; `Driver.send_message` is thread-safe), one key in flight at a time (a flood measured queueing behind earlier keys: probe `x4-probe.txt`, interval 0.1 s → up to 1.06 s from the queue alone), and times send → the sheet's key action returning. Controls on the final helper: arrival mutant **RED 0.921 s** (`x5-marr-29_2.txt`), FX9's stall mutant **RED 1.299 s** (`x5-mstall-29_2.txt`). |
| F-X9-2 | impl (product) — reopens F-MW9-2 | **MAJOR, open** | With the non-vacuous instrument the product misses the 0.5 s bound at load < 2: **29_2 RED, slowest 0.561 s** (load 0.42 before, `x5-head-29_2.txt`; typical 0.05–0.42 s); **82_1 RED, slowest 1.950 s** (load 0.98, `x5-head-82_1.txt`). Probe `x5-probe82.txt` (load 1.07) splits 82_1: during the encode (0–43 s) keys take 0.05–0.49 s (margin < 2 %); after the worker returns, the UI-thread record stage holds the loop ≈ 1.4 s (`_refresh_patch_history_view` 1.369 s incl. `set_document` 0.357 s, `stage_record` 0.021 s) and the key sent then waits 1.907 s. Probe `x4-probe.txt` (keys 0.5 s apart, load ≈ 1): the arrival itself is cheap (`_job_done` 0.019 s); single-key latency during the preview encode up to 0.486 s, with `_paint` taking 0.26–0.28 s at times (GIL contention with the pure-Python encode). | Not small (process model or chunked encode / staging of a 1 M-element record; or a requirement change for the post-encode stage, which .82/1's text "while the encode runs" does not literally cover) → orchestrator: DF-04 (a) product fix by `software-dev` against .29/2 and .82/1, plus a ruling on whether .82/1's window ends at the encode or at the written record (the node waits for the record). The two nodes stay RED on the tree — the honest state. |
| F-X9-3 | test case mark — F-FX9-2 ruling | MINOR | 20_1 holds the decode asleep in `Gate`, so its key is timed against an idle worker, never a computing decode. It still kills its stated negative control (decode on the UI thread). | Mark of R-PE-BENCH.20/1 changed `full` → `partial` in `02-test-cases.md` (reviewer card item 4). A node with `keys_until` against a released decode is not small (each `down`/`up` moves off LARGE and requeues the decode) → PENDING. F-X9-2's probes cover the same GIL mechanism (encode). |
| F-X9-4 | design-gap — W-8 | MINOR (visible, P-059) | After a refused decode (or a job that raised: `_run_job` maps any exception to `None`), `bench_detail` keeps `decoding <n> values …` forever (`x-refused-decode.*`: REF_BLK, Current `--`, bench `decoding 6 values …`), and the tools then report "still decoding". | **W-8 provisional ruling: change, not "keep as built".** Reason: the line states a decode that is not running, so the operator waits for values that never come; R-PE-BENCH.21 is a While-row and the capture shows it outside its state. Proposed: `✗ refused: <message>` in place of the decoding line (W-8's text). New behaviour → DF-04 (c), for the operator's page, not applied here. |
| F-X9-5 | impl vs R-PE-BENCH.18 | MINOR | Strip width: VB1D and LARGE at 118 paint 16 `█` and hide the count (`… `) where .18's formula gives 14 and the count; where the count fits it runs into the New cell (`4·`, `41 cells`). Capture `v2.*`. | PENDING (DF-04 a, small fix in `bench_cells` / `summary_strip`, with a cells test). |
| F-X9-6 | impl | MINOR | VAL_BLK 2-D op-line label loses its closing `]` at 118 and 220 (`VAL_BLK_DEF_0001[x0..1,y0..1 op =`); MAP with the same where keeps it. Capture `v5b.*`. | PENDING (the label is cut before ` op =`; check the name-label width of Inc 8's bar). |
| F-X9-7 | wording | MINOR | `1 notices`, `1 cells` (k = 1) follow the requirement text literally. | PENDING / P-026 wording. |
| F-X9-8 | design-gap (layout) | MINOR (visible) | At 80x24 the op line / formula bar is below the visible screen in five of six scenes (panel scrolls), tool row cut `shi…`. R-PE-BENCH.5 holds by its letter. | V-14 provisional "change"; operator page. |
| F-X9-9 | impl (robustness) | MINOR | Element texts and axis-point texts are cleaned with the unbounded `plain()` and fitted per paint (`definition_bench_view._shown_value`, `axis_labels`), where Inc 8 uses the bounded `clip(…, clean=True)`; a hostile A2L text of MiBs costs O(len) per visible cell per paint. No requirement violated (.90/.91 hold). | PENDING. |

Bidi controls (U+202A–E, U+2066–9) in cells: already backlog P-026 F-9 (Inc 8); not re-raised.

## Security pass (untrusted A2L names / units, escapes, jobs, memory)
- Markup: every bench / op / bytes text is a `rich.Text` (never a markup `str`); R-PE-BENCH.90 nodes green. Controls: `plain()` on element, axis and unit texts and on refusal messages in the bytes line (.91). Status messages go through `name_echo` and the app's status sink (`shell._append_log_line`: `safe_text(...).plain`, markup off, width cap), incl. the raw `event.outcome.message` in `_stage_bench_record`.
- Cell widths: `_fit` / `_cut` use `cell_len` and `Text.truncate`; wide characters cannot widen a line (.5 / .7 nodes).
- Jobs: one worker at a time (`_active_job`), the slot keeps one decode and one preview, stale results dropped by `generation` / view token, a stale record reports and writes nothing; the app re-checks generation, the definition and the encoded span before staging (`_stage_bench_record`). Running jobs are not cancelled — a deselected LARGE decode runs to its end (≈ 11 s) and is dropped; bounded by the one-job rule (R-PE-BENCH.28/2 is an RSS bound, green per MW9).
- Memory: summaries only for rows ≤ 4,096 elements; `BenchValues` stores `array("d")` + shared empty texts (≈ 16 B / element), so a 200-row page of 4,096-element rows is ≈ 13 MiB < 64 MiB; FX9's deselect fix drops `labels` / `strip` / `lo` / `hi` (26_2 GREEN, FX9).

## Rulings asked by the brief
- **F-I9b-1** (MW9's split of 26_2): accepted. Run 1 (untraced, 240 s) RED alone on `t26b` (decode sleeps 300 s); run 2 (traced, ≤ 1 MiB) RED alone on `t26` (12.3 MiB) and on the real defect (4.0 MiB, F-MW9-1); GREEN after FX9 (439 s). Neither bound loosened. F-MW9-3 confirmed by the orchestrator.
- **MW9 survivors** (4 argued equivalent): accepted — `w22e` (requeue order; settled output equal, only latency order differs, no requirement orders the slot), `w25b`, `w51b`, `s07` as argued.
- **F-FX9-1**: (a) the requirement text of .29/2 and .82/1 is "handle the key within 0.5 s" — the key's handling, not the first frame; the sheet's own paint (`_reveal` → `_paint`) runs inside the action, so "action returned" includes the product's paint, and Textual's compositor frame is framework time (FX9 probe 2: ≤ 0.31 s). No change to end at the first frame. (b) The helper itself was vacuous for the arrival case → F-X9-1 (MAJOR, fixed). (c) The stall control is RED with the final helper (1.299 s).
- **F-FX9-2**: F-X9-3 (MINOR, mark → partial).
- **Timing nodes** (all at 1-min load < 2 before each run; rtx shared with MU7): 29_1 and 20_1 keep `timed_press` — see `04-validation.md` (chain 2); 29_2 and 82_1 **decided RED** with the repaired instrument (F-X9-2); FX9's GREEN numbers (0.212 / 0.079 s) were the vacuous instrument's. 26_2: FX9's run cited (GREEN 439 s, load 1.17), not repeated.
- **W-8**: change (F-X9-4), provisional.
- **C9's visual choices** (E4-impl-b D-6: ramp colours, edit colour, canvas line layout): keep, provisional — captures `v3`, `v4`, `v5a/b` read clearly at 118 and 220.
- **W-list**: W-1…W-7 and W-9 applied by I9 (`E4-integration-w.md` step 4b, commit `9a930853`) as wording, meaning unchanged; I checked the rows named there against the requirements and found no meaning change. W-8 not applied (requirement change) → F-X9-4.

## Checks not run, and why
- R-PE-BENCH.14 "no image" capture (only the missing-byte case).
- A probe of 29_2 under the repaired instrument at a lower load than 0.42 (rtx shared with MU7); the verdict uses the brief's < 2 rule.
- A full re-read of all 82 rows' test cases' full/partial marks: only the timing and refusal rows (20/1, 21/1, 29/x, 82/1, 14/x) were re-checked.
- The 26_2 slow node (7 min) was not re-run; FX9's GREEN at load 1.17 is cited.

## Re-check X9r (relevo-14): FX9b + FX9c + FX9d, one reviewer, one pass

Model claude-opus-5-5. Tree `b103-inc9`, start tip `ab62093b`; diff reviewed `4c891ea9..ab62093b -- s19_app tests` (6 product
files +96 / -20, 6 test files). X9r wrote none of the fixes. Runner rtx, HT-02 env (HOME basename `<runner-home>` read from
`RUNNER_HOME_NAME`), `s19_app.__file__` atop every transcript, real `git clone`s of a bundle of `b103-inc9` + `main` (HT-03),
scratch `~/work/zq-x9r/`. Transcripts, scripts and mutants: `evidence-e5/x9r/`. Captures: `E5-captures.md` § Re-check X9r.

### Verdict (X9r, as written): FAIL — F-X9-2 pending the operator (O-A / O-E / accept), and F-X9r-2 (MAJOR, open) for the orchestrator

**Update (FX9f, relevo-14): PASS-WITH-NOTES.** F-X9-2 is closed by the operator's decision (the bound is relaxed to 1.0 s for
R-PE-BENCH.29/2 and .82/1 only; O-A / O-E stay in the backlog) and F-X9r-2 was closed by FX9e (`E4-fixes-fx9e.md`). See
§ Update FX9f at the end of this file.

29_2 (0.543 s) and 82_1 (0.937 s) are not within 0.5 s at load ≈ 1, so the brief's PASS-WITH-NOTES branch does not
apply. Its "FAIL-pending-operator for F-X9-2 only" branch does not apply either: F-X9r-2 below is a MAJOR this re-check
found and could not close with a small fix inside Inc 9's files.

### Findings
| Id | Tag | Severity | Finding | Disposition |
|---|---|---|---|---|
| F-X9-2 | impl (product) | MAJOR, pending operator | 29_2 RED `slowest press 0.543 s` (1-min load 1.08 before), 82_1 RED `0.937 s` (load 1.06); 29_1 GREEN 0.169 s (load 0.29), 20_1 GREEN 0.142 s (load 0.99). FX9b/c/d cut the record-stage block 1.39 → 0.67 s (FX9d); what is left is the encode's GIL tail (29_2) and the rest of the block (82_1). | Operator page: O-A (encode in a separate process), O-E (stepped shared refresh), or accept / relax the bound. None applied; no bound, timer, xfail or skip changed. |
| F-X9r-2 | impl (Inc 9 regression in an existing suite node) | **MAJOR, open** | `tests/test_tui_patch_json.py::test_tc079_5c_hue_census_is_complete` is RED on `ab62093b` and `16b00234`, GREEN on the pre-Inc-9 base `6c4fd21f` (real clones, same runner, `d-test_tui_patch_json-*.txt`): Inc 9's colour literals `#1c2438` (`definition_bench.py:469`, ramp step-0 background), `#101828` (`:477`, dark text on light ramp cells) and `#f5c26b` (`definition_bench_view.py:54`, C9's D-6 edit colour) are in neither `_CLAIMED_HUES` nor `_EXCLUDED_LITERALS`. FX9c and FX9d called it "base-identical" because their bases (`16b00234`, `b21d5517`) already held Inc 9. | Not fixed here: `#f5c26b` paints a foreground cue, so it must be CLAIMED and then meets the census's hue rules against the other cues; that is a visual decision on C9's D-6 colour, in a file outside Inc 9. Orchestrator: one census entry per literal (the two backgrounds / near-black → EXCLUDED with reasons; the edit amber → CLAIMED and checked), or a colour change if it collides. |
| F-X9r-1 | impl (visible) vs CTX-PE-BENCH array row cells | MINOR | At 220×60 VB1D's strip paints 8 blocks + ` 40` (`r-v2-vb1d.220x60`) where the Current cell is 44 wide (strip width 40, k = 1, 16 blocks; X9's pre-FX9b 220 captures painted 16). At 118 it is right (8 blocks). `_start_next` reads `sheet_widths(self._body.content_size.width or 118)`; a page summarised before the sheet is laid out (here the page fills on load, before the Patch screen shows) gets the 118 class, and nothing re-summarises on resize. FX9b's `- count - 2` made the stale width visible (before it, both classes gave k = 1 for 16 columns). | PENDING (DF-04 a): take the width when the strip is painted, or re-queue the summaries when the width class changes; RED node: a 220 variant of `w_select` 11 with the page filled before the screen is shown. Cause inferred from the code and the two captures, not instrumented. |
| F-X9r-3 | test strength | MINOR | Three FX9c guards have no suite node. Mutant `oc1` (drop `+ max(0, span - len(before))` from the card's changed count) passes `test_tui_patch_card.py` (only its pre-existing purity-probe failure) and is killed only by the evidence probe `card_diff.py` (395 of 3,001 digests differ); in the app `before` always has the span's length (`entries.py`), so it is equivalent there. Mutant `od2` (cached max abs Δ used without the identity check) passes 112 nodes of `w_stage`, `b_cells`, `w_select`, `w_mutants`, `w_keys`. Mutant `od3` (a deselected LARGE row keeps `staged_delta`, and with it both value arrays) was not run: 28/2 stages nothing, so it cannot see it (argued survivor). | PENDING: a pure card case with `before` shorter than `after`; a model case where `values` changes under a cached pair; a 28/2-style RSS check over staged LARGE rows. |
| F-X9r-4 | records | MINOR | FX9c attributes `test_tui_patch_card.py::test_tc080_2_c7_purity_probe` ("reaches self.app at 2 site(s)") to Inc 9's `ArrayBenchSheet`. The same node fails with the same 2 sites on `6c4fd21f`, where `bench_sheet.py` does not exist (`git cat-file -e` fails). Base-identical before Inc 9; it touches no code Inc 9 changed. | Record only; the probe's 2 sites → batch end. |

### Checks of the fixes
- **FX9b** (F-X9-5/6/7, W-8): its 8 nodes RED on `4c891ea9`'s product with the head's tests (`b-fx9b-red.txt`: 8 failed), GREEN on head. W-8's line is `Text("✗ refused: " + plain(message))`, cut to the width (markup off, ESC cleaned; the node checks both and the decoding line on a new decode). F-X9-6's 28-cell constant mirrors Inc 8's CSS and its node reads that CSS, so drift is caught.
- **FX9c O-C**: same painted card. `card_diff.py` (committed by FX9c; 3,001 seeded cases incl. 1 MiB) on head prints the digests of FX9c's pre-O-C base `16b00234` exactly (md5 of the two lists equal), and kills `oc1` (395 differ) and `oc2` (one span cell short of the painted rows: 554 differ). The probe exists and fails on a wrong card, but it is evidence, not a suite node (F-X9r-3).
- **FX9c O-D**: `BenchState.staged_delta` is the last field, default `None`, `compare=False, repr=False`: positional construction, equality and repr unchanged, so additive only (I-9.1 addition in `codewire/graph-inc9.md`). The cache is used only while `values` and `staged` are the same objects, else the old computation runs (a "summary" job replaces `values` and leaves a stale pair, which the check refuses). Mutant `od1` (cached value 0.0) RED on `w_stage` 15/16/18 (`b-mod1.txt`). The worker's read of `self.states` is one dict read.
- **FX9d O-B**: `ReadOnlyJsonView` is used once, at `#patch_json_view` (grep); `query_one(..., TextArea)`, the app's `widget.id == "patch_json_view"` copy path and the id CSS rules still apply. `test_ob_1` RED on `b21d5517`'s product (`b-fx9d-red.txt`: 1 failed, 1 passed); `test_ob_2` holds the paste buffer's matching. Captured: head `_matching_bracket_location=None`, the `}` plain; `b21d5517` match `(12, 4)`, highlighted (`r-ob-json*`).
- **FX9d's `test_tui_patch_history_strip` claim: upheld.** Real clones with a local `main` (the binding-diff arm runs): head, `b21d5517`, `16b00234`, `6c4fd21f` each `1 failed, 7 passed`, the same node `test_tc081_2_strip`; `test_tc081_4_no_binding_diff` passes on all four. FX9d's extra failure came from the `git archive` copy (no repository), not from code.
- **FX9c's 28 "base-identical" user failures**, spot-checked against the pre-Inc-9 base `6c4fd21f` (per-file FAILED id lists, `f-*.txt`): `tui_patch_card` 1, `b100_session_reset` 3, `b103_clipboard_core` 2, `b103_copy_paste_matrix` 7, `tui_patch_history_strip` 1, `b97_chips_help` 1, `b99_editor_image` 2, `tui_patch_editor_b94` 1, `tui_snapshot` 6: identical on head, `16b00234` and `6c4fd21f` (0 diff lines). `tui_patch_json`: 4 on head and `16b00234`, 3 on `6c4fd21f`; the extra one is F-X9r-2. So 27 of the 28 predate Inc 9 and touch no code it changed; 1 is Inc 9's (F-X9r-2).
- **Security**: no new untrusted-text path besides W-8's message (plain, `Text`, cut); no new thread work beyond O-D's dict read; no file, process or clipboard surface.

### Not run, and why
- Mutant `od3` (argued above). A second timing run per node (one run each at load ≈ 1; the verdict does not depend on it: 82_1 is 0.44 s over). `test_b97_width` (slow, not in the failing set).

## Update FX9f (relevo-14): F-X9-2 closed by the operator's decision

Software-dev worker FX9f, claude-sonnet-5-5, tree `b103-inc9`, start `7c8bda05`, code/record commit `f60f1dc5`. Not an independent
review: it applies a decision and re-measures. Runner rtx, HT-02 env, fresh clone of a bundle of `f60f1dc5`, `s19_app.__file__` atop
every transcript (`evidence-e5/fx9f/transcripts/`), scratch deleted.

| Id | Disposition now |
|---|---|
| F-X9-2 | **Closed by operator decision** (Javier, 2026-11-14: "Relaja el límite pero deja en el backlog el item"; `s19-PENDING.md` P-125/P-126, review-page item F-X9-2). R-PE-BENCH.29/2 and .82/1 are now bounded at **1.0 s**; no other bound, timer or helper changed. Residual: O-A (encode in a separate process) and O-E (stepped shared refresh) stay in the backlog; 82_1's margin is thin (below). |
| F-X9r-2 | Closed by FX9e (`E4-fixes-fx9e.md`); not re-run here beyond the laws. |
| F-X9r-1, F-X9r-3, F-X9r-4, F-X9-3 ... F-X9-9 | unchanged (PENDING / MINOR). |

Re-measure (each node alone, `-n 0`, after a 1-min load < 2; `evidence-e5/fx9f/transcripts/t-*.txt`): 29_1 0.173 s / 0.5 s (load 0.19),
29_2 **0.475 s / 1.0 s** (load 0.76), 82_1 **0.916 s / 1.0 s, LOW margin 8.4 %** (load 0.94), 20_1 0.145 s / 0.5 s (load 0.98).
The 82_1 pass is thin: earlier runs read 0.937 and 0.988 s at similar load, so it can flake red on a busy host; that is the open
residual, and it is why the verdict carries notes rather than a clean PASS.

Controls (the relaxed timer can still fail): FX9's paint stall (`evidence-e5/fx9f/scripts/mutate.py paint`: `_paint` sleeps while a job
runs) at 0.8 s is still RED because it adds to the base latency: 29_2 RED 1.139 s, 82_1 RED 1.807 s; at 1.3 s: 29_2 RED 1.670 s,
82_1 RED 2.282 s; X9's arrival stall at 1.3 s on 29_2: RED 1.441 s.

Verdict for Inc 9: **PASS-WITH-NOTES** (open notes: 82_1 thin margin / O-A / O-E backlog; the MINORs above).
