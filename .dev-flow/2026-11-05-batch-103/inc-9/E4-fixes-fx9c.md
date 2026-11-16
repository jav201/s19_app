# Inc 9 FX9c: shorten the record-stage block (F-X9-2 options O-B, O-C, O-D; relevo-13)

Model claude-opus-5-5 (software-dev). Tree `b103-inc9`, start tip `16b00234`. Ruling (orchestrator, PENDING P-101):
apply O-B, O-C, O-D (one commit each, measured); not O-A, O-E, O-F; 29_2 / 82_1 stay RED if over 0.5 s (no bound or
timer change, no xfail / skip); stop and report an option that grows past FX9b's line estimate x2 or changes painted
output. Runner scratch `~/work/zq-fx9c/` (HT-02 env, HOME basename `<runner-home>` read from `RUNNER_HOME_NAME`,
`s19_app.__file__` atop every transcript, timed runs alone at `-n 0` after a 1-min load < 2). Probes, scripts and
transcripts: `evidence-e4/fixes-fx9c/` (redacted: `~`, `<user>`, `<runner-home>`).

## State / next step
- **O-C applied** (`8bd07d0c`), **O-D applied** (`f5cb522e`); painted output unchanged (proofs below).
- **O-B: STOP AND REPORT (brief clause), not applied.** The one-line fix does not exist in the installed Textual
  (8.2.8, the `s19ci` env): `TextArea.__init__` has no `match_cursor_bracket` parameter (passing it raises
  `TypeError`), and the reactive `match_cursor_bracket` only gates the DRAWING of the match: `_watch_selection`
  calls `find_matching_bracket` unconditionally (`textual/widgets/_text_area.py:888`), so setting it to False keeps
  the 0.46 s scan. The working fix is a `TextArea` subclass for the read-only JSON view whose `find_matching_bracket`
  returns None (~5 lines and a new class in `patch_editor/document.py`): over the x2 gate of a 1-line estimate and a
  new pattern on a file outside the slice. Its effect was measured as a what-if (probe stub, scratch only): below.
- 29_2 and 82_1 stay **RED** (0.539 s, 1.659 s). The remaining block is 1.18 s (0.71 s with the O-B subclass);
  O-E / O-F (block) and O-A (the encode window) are what is left: §What O-A and O-E would still buy.
- Next (orchestrator): rule on the O-B subclass (DF-04 (a), file outside the slice) and on O-A / O-E (operator page).

## Measurements (one `test_fx9c_probe.py::test_probe_parts` run per tree, scratch only, HT-09)
The probe is FX9b's `test_probe_parts` (same wraps, same typist, 82_1's scenario) plus: 4 s of keys after the stage
(the per-key cost of a staged LARGE row with no edit), a digest (plain + spans) of every before/after card painted, and
the O-B what-if (env `FX9C_NOBRACKET=1`: `find_matching_bracket` stubbed to return None). Trees are `git archive` of each
commit (LF, Linux). Each run started at a 1-min load < 2; another worker's two pytest-xdist processes ran on the host
during these runs (load after 2.2-2.9), so single-part numbers carry +/- ~10 % noise. Transcripts `p-<tree>-nb<0|1>.txt`
(+ `.json`), log `chain1-log.txt`.

| Part (UI thread, seconds) | base `16b00234` | + O-C `8bd07d0c` | + O-D `f5cb522e` | + O-B what-if (stub) |
|---|---|---|---|---|
| load before | 1.94 | 1.94 | 1.98 | 1.88 |
| `_stage_bench_record` (the block) | **1.456** | **1.249** | **1.183** | **0.707** |
| - `stage_record` | 0.021 | 0.019 | 0.031 | 0.027 |
| - `serialize_change_document` | 0.188 | 0.172 | 0.177 | 0.168 |
| - `_render_before_after_card` | 0.246 | 0.072 | 0.066 | 0.072 |
| - `_show_document` (`load_text`; of it `find_matching_bracket`) | 0.612 (0.609; 0.466) | 0.607 (0.605; 0.461) | 0.625 (0.623; 0.480) | 0.148 (0.146; 0.000) |
| - `set_document` (of it `_paint`; `_max_staged_delta` in it) | 0.360 (0.106; 0.098) | 0.348 (0.097; 0.090) | 0.254 (not > 0.05; not called) | 0.264 |
| after the block: card again (RowHighlighted) | 0.511 | 0.099 | 0.106 | 0.096 |
| after the block: `_paint` per key (`_max_staged_delta` in it) | 0.18-0.36 (0.16-0.21) | 0.24-0.70 (0.23-0.67) | <= 0.16 (not called) | <= 0.14 |
| keys after the stage: n / p50 / max (s) | 15 / 0.208 / 0.804 | 9 / 0.457 / 0.730 | 30 / 0.057 / 0.202 | 31 / 0.039 / 0.294 |
| the key sent just before the stage (wait / action) | 1.607 / 0.361 | 1.594 / 0.501 | 1.487 / 0.021 | 1.217 / 0.018 |

Per option (saving on the UI thread, this run's numbers):
- **O-C**: block -0.207 s (card 0.246 -> 0.072 s); the RowHighlighted card after the block -0.412 s (0.511 -> 0.099 s).
- **O-D**: block -0.066 s (`set_document` 0.348 -> 0.254 s: its paint no longer runs `_max_staged_delta`); every later key
  of the staged LARGE row with no edit no longer pays the 0.16-0.67 s scan (keys after the stage p50 0.457 -> 0.057 s,
  max 0.730 -> 0.202 s). `_max_staged_delta` was not called on the UI thread at all in the O-D run.
- **O-B** (not applied; what-if): block -0.476 s (`load_text` 0.623 -> 0.146 s).
- Net applied: block 1.456 -> 1.183 s (-0.27 s); with the O-B subclass 0.707 s (-0.75 s).

### Remaining block on `f5cb522e` (1.183 s)
`_show_document` 0.625 (bracket scan 0.480 + load 0.145) · `set_document` 0.254 (Inc 8 rows over every byte) ·
`serialize_change_document` 0.177 · card 0.066 · `stage_record` 0.031 · rest 0.03. With the O-B subclass the block is
0.71 s: still > 0.5 s, so .82/1 still needs the block split (O-E) or Inc 8's rows off the UI thread (O-F), and the key
sent during the encode tail still waits behind both.

## Painted output unchanged
- **O-C (pure function)**: `probes/card_diff.py` digests (plain + spans) of `before_after_card_text` over 3,000 seeded
  random cases (per_row of `STRIP_ROW_BYTES`; spans 0-400; `before` None / shorter / longer than the span; unmapped bytes;
  random `row_cap` 0-11 incl. 0; addresses past 32 bits; no-selection) and one 1 MiB case: base and O-C trees print the
  same 3,001 digests (`cd-base.txt`, `cd-oc.txt`; `diff` of the two = 0 lines; LARGE `46dbf33d625d8c5c`,
  `1048576 B @ 0x00080000 · 314213 changed` on both).
- **O-C (in the app, LARGE)**: every card painted in the probe runs has digest `6daf5484e8d5bfd6`, 26 lines,
  `1048576 B @ 0x00100000 · 4096 changed`, on base, O-C, O-D and the what-if.
- O-C and O-D are also held by the existing card / bench tests in the fresh clone (§Fresh clone): the card's
  `test_tui_patch_card.py`, the Δ-cell nodes R-PE-BENCH.16/2, 16/4 (pure model, `staged_delta` unset -> computed path)
  and the app nodes `w_stage` 15/16/18 and `w_mutants` (worker path, cached).

## Changes (files and lines)
| Option | Commit | File (lines) | Change |
|---|---|---|---|
| O-C | `8bd07d0c` | `screens_directionb/shared.py` (+14 / -10) | `before_after_card_text`: rows from `len(lead) + span + len(trail)`; cells built for the painted rows only (`shown * per_row` positions); the changed count over the whole span as `sum(map(ne, before, after)) + max(0, span - len(before))` (same rule: `None != byte`, a position past `before` is unmapped) |
| O-C | `8bd07d0c` | `patch_editor/entries.py` (+1 / -1) | the span read as `list(map(mem.get, range(...)))` (still `.get`, LLR-080.5) |
| O-D | `f5cb522e` | `definition_bench.py` (+14 / -2) | additive `BenchState.staged_delta: (values, staged, max \|Δ\|) \| None` (`compare=False, repr=False`); `staged_delta(values, staged)`; `_delta_text` uses it while `values` and `staged` are those same objects, else computes as before |
| O-D | `f5cb522e` | `patch_editor/bench_sheet.py` (+11 / -3) | the worker computes it with a "decode" result (current, staged pair) and a "staged" result (against the row's values read at job time); `_assign_result` stores it with `staged`; a deselected large row drops it with its values (the RSS bound of R-PE-BENCH.28/2) |

Line gate (FX9b estimate x2, counting added code lines): O-C 12 -> 24, actual 11 (+ 4 comment lines); O-D 10 -> 20,
actual 19 (incl. the import, the deselect clear FX9b's estimate did not name, and 2 lines from splitting a long
`replace`) + 4 doc lines. Both within the gate, O-D at its edge. Source files: 4 over two commits (2 each), cap 4; no test file changed.
**I-9.1 addition recorded** in `codewire/graph-inc9.md` (BenchState block, "FX9c O-D").

Decisions (decide and record):
- O-C "reads only the bytes it paints": the card's last line counts changed bytes over the WHOLE span (painted output),
  so every span byte is still read once; it is now one C-level pass (`map`) instead of a Python list comprehension, a
  1 M-tuple cell list and a Python generator. Reading fewer bytes would change the painted count.
- O-D's cache is identity-keyed (not a bare float) because `summary` jobs replace `values` without `staged`; a stale
  pair falls back to the old computation instead of painting a wrong Δ. The worker reads `self.states[name].values`
  for a "staged" job (atomic dict read; a race only costs a cache miss).
- O-B: stopped (above); O-C and O-D were applied because each is independent of O-B and inside its own gate.

## Visible changes (operator)
None. O-B (the bracket highlight in the read-only JSON view) was not applied, so the highlight stays. O-C paints the
same card (digests above); O-D paints the same Δ text (same function on the same values).

## Timing nodes on `f5cb522e` (each alone, `-n 0`, `-m serial_timing`, load < 2 read before each; QC-TM lines)
| Node | Tree | Load before | Result | Transcript |
|---|---|---|---|---|
| 29_1 | head | 1.99 | **GREEN** 0.167 s (66.7 % margin) | `t-od-29_1.txt` |
| 29_2 | head | 1.85 | **RED** `slowest press 0.539 s` (FX9b 0.560 s) | `t-od-29_2.txt` |
| 82_1 | head | 1.99 | **RED** `slowest press 1.659 s` (FX9b 1.872 s) | `t-od-82_1.txt` |
| 20_1 | head | 1.86 | **GREEN** 0.135 s (72.9 % margin) | `t-od-20_1.txt` |
| 29_2 | head + X9 arrival mutant | 1.87 | **RED** 0.886 s | `t-marr-29_2.txt`, `t-marr-diff.txt` |
| 29_2 | head + FX9 stall mutant | 1.86 | **RED** 1.112 s | `t-mstall-29_2.txt`, `t-mstall-diff.txt` |
| 82_1 | head + FX9 stall mutant | 1.10 | **RED** 2.256 s | `t-mstall-82_1.txt` |

Mutants: FX9b's `mutant-arrival.py` / `mutant-stall.py` (`evidence-e4/fixes-fx9b/scripts/`), applied to copies; they
stay RED and above the head's own times (0.886 / 1.112 > 0.539; 2.256 > 1.659). 29_2 is a tail miss during the
encode (GIL contention, FX9b part 1; untouched by O-B/C/D); 82_1 improved by ~0.2 s and stays RED on the block.

## What O-A and O-E would still buy (from FX9b's and these measurements)
- **O-A** (encode / decode in a separate process): the keys during the encode back to ~0.015 s p50 (FX9b `idle` row);
  the only option for 29_2 (0.539 s, a GIL tail) and for 82_1's keys before the encode returns.
- **O-E** (post-stage refresh in steps with the loop turning between them): today's steps would be serialize 0.18,
  card 0.07, JSON view 0.63 (0.15 with the O-B subclass), sheet 0.25: the longest step 0.63 s without O-B, 0.25 s with
  it, so O-B (subclass) + O-E bound every step < 0.5 s; O-E alone does not (the JSON view step).
- **O-F** (Inc 8 rows): -0.1 to -0.25 s of the sheet step; not needed for the bound once O-E splits it out.

## Fresh clone
Bundle clone of `b103-inc9` at `f5cb522e` (the code head; this record adds only records), `scripts/chain2.sh`, one run
per file, `-n 2`, `timeout 300`; `s19_app.__file__` = `~/work/zq-fx9c/clone/s19_app/__init__.py` atop every transcript
(`transcripts/clone/c-*.txt`, summary `chain2-log.txt`; load 1.08 at the start, 1.43 at the end). The user files that
failed were re-run whole on a base clone at `16b00234` with the same runner (`scripts/chain3.sh`,
`transcripts/base/b-*.txt`, `chain3-log.txt`): every failure set is IDENTICAL to base (per-file `FAILED` id lists
compared, 0 differences).

| Set | Result |
|---|---|
| `tests/test_b103_inc9_*.py` (12 files, `-m "not serial_timing and not slow"`; timing nodes ran alone above) | **321 passed**, 0 failed (FX9b: 321) |
| `tests/test_b103_inc8_*.py` (14 files) | **371 passed**, 0 failed |
| Users of the card / JSON view / `patch_editor` entries (grep of `tests/` for `before_after_card_text`, `BeforeAfterCard`, `_render_before_after_card`, `patch_before_after_card`, `patch_json_view`, `patch_editor.entries` / `.document`, `_show_document`, `refresh_entries`: 20 files, `scripts/users.txt`) | **752 passed, 28 failed, 22 skipped, 2 xfailed**; the 28 failures are base-identical (base clone: the same 28 node ids): `b100_session_reset` 3 (`_right_gesture` census), `b103_clipboard_core` 2, `b103_copy_paste_matrix` 7, `b97_chips_help` 1, `b99_editor_image` 2, `tui_patch_card` 1 (`test_tc080_2_c7_purity_probe`, open item), `tui_patch_editor_b94` 1, `tui_patch_history_strip` 1, `tui_patch_json` 4, `tui_snapshot` 6 (`a2l-*` density snapshots). `test_b97_width` timed out at 300 s in chain 2 (rc 124, no failure printed) and passed whole at 900 s on both clones: head 145 passed (596.9 s), base 145 passed (625.9 s) |
| Laws: `test_id_registry`, `test_suite_hygiene`, `test_requirements_canon`, `test_address_census`, `test_deps_seam_law`, `test_no_private_tokens`, `test_engine_unchanged` | **117 passed, 3 skipped, 2 failed** - the two base-identical failures only: `test_canon_rows_hold_the_obligation_word_once`, `test_at_b83_08_tree_holds_no_assembled_selectors`; `test_r_tst_070_2` green |

Per-file user counts (head): session_reset 17/3F, symbol_reads 24, clipboard_core 83/2F/2s, clipboard_tail 27/4s,
copy_paste_matrix 7/7F/15s, copy_quit_dialog 28, copy_views 54, chips_help 78/1F, flow_execution 75, patch_editor 38,
width 145 (900 s run), editor_image 6/2F, patch_big 24, patch_card 25/1F, editor_b94 16/1F, editor_v2 52,
history_strip 6/1F/1s, patch_json 13/4F, patch_layout 9, snapshot 25/6F/2xf.
The base-identical user failures were not run in Inc 9's earlier batteries (FX9b ran only inc9, inc8 and laws); they are
outside FX9c and recorded here for the orchestrator.

## Open items
- O-B subclass (stop-and-report above); O-A / O-E / O-F (operator page); 29_2 / 82_1 RED.
- **Base-identical failure outside FX9c**: `tests/test_tui_patch_card.py::test_tc080_2_c7_purity_probe` fails on base
  `16b00234` too (`prebase.txt`, `PatchEditorPanel reaches self.app at 2 site(s)`): the probe walks the panel's class
  tree, which now includes Inc 9's `ArrayBenchSheet` (`bench_sheet.py`: `getattr(self.app, "set_status", None)` and
  `self.app.call_from_thread`). Not caused by O-C / O-D; not in Inc 9's earlier batteries (the file was not run). Needs
  an orchestrator ruling (the probe's scope vs the bench worker's app reach).
- From FX9b, unchanged: W-8 for a job that raised; the requirement-canon texts (k = 1 plurals, W-8's line).

## Evidence checklist
- [x] Tests: every result is one complete run's own output (`executed`); timing verdicts read at load < 2 before each
  run (`chain1-log.txt`); O-B's fix `not-run` (stop-and-report; what-if probe only).
- [x] No secrets; records redacted (`~`, `<user>`, `<runner-home>`).
- [x] No destructive command on work without a commit; rtx scratch deleted by explicit list (below); no push.
- [x] File count: 4 source files over 2 commits (cap 4), 0 test files.
- [x] 0 CR in the committed diffs.

## Commits
`8bd07d0c` O-C, `f5cb522e` O-D, then this record's commit. No push.

## Scratch deleted (explicit list, only paths I created)
`~/work/zq-fx9c/`: `base baseclone card_diff.py chain1.sh chain2.sh chain3.sh clone fx9c.bundle home launch3.sh
launch.sh marr mstall mutant-arrival.py mutant-stall.py oc od out pre prebase repo run.sh test_fx9b_probe2.py
test_fx9b_probe.py test_fx9c_probe.py tmp users.txt waitload.sh x`, then the empty folder (after this record's commit).
Local: the FX9c work folder outside the repo. The copies of FX9b's `waitload.sh` and mutant scripts used here are the
committed ones under `evidence-e4/fixes-fx9b/scripts/`. `pre` / `prebase` were the pre-launch smoke run
(`transcripts/pre.txt`: card + bench model nodes on the head, 85 run, 1 failed = the base-identical purity probe,
`prebase.txt`).
