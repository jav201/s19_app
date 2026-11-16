# Inc 9 FX9d: O-B as a read-only JSON view without bracket scan (relevo-14)

Model claude-sonnet-5-5 (software-dev). Tree `b103-inc9`, start tip `b21d5517`. Runner scratch `~/work/zq-fx9d/` (HT-02 env,
HOME basename `<runner-home>` read from `RUNNER_HOME_NAME`, `s19_app.__file__` atop every transcript, HT-03). Scripts and
redacted transcripts: `evidence-e4/fixes-fx9d/` (`~`, `<user>`, `<runner-home>`).

## Ruling (orchestrator, relevo-14, DF-04 (a), provisional under P-059)
FX9c found that Textual 8.2.8 always runs `find_matching_bracket` in `_watch_selection`, so `match_cursor_bracket=False`
saves nothing. Apply O-B as a small `TextArea` subclass for the read-only JSON view only (`patch_editor/document.py`)
whose `find_matching_bracket` returns `None`. Scope extension to that file recorded here. Editable text areas keep
Textual's behaviour. Stop if the subclass needs more than ~10 lines or changes any other behaviour: it did not (12 added
lines incl. a 4-line docstring and blank lines; 1 line changed at the compose site; no other behaviour).

## Diff (`0ba56c8c`, `s19_app/tui/screens_directionb/patch_editor/document.py`, +12 / -1)
```
+class ReadOnlyJsonView(TextArea):
+    """... no bracket matching (why: Textual 8.2.8 scans on every selection change ...)"""
+    def find_matching_bracket(self, bracket: str, search_from: tuple[int, int]) -> None:
+        return None
-        yield TextArea(            # _compose_json_view, id="patch_json_view", read_only=True, soft_wrap=False
+        yield ReadOnlyJsonView(
```
`query_one("#patch_json_view", TextArea)` still resolves (subclass); no test asserts the exact class. Source files: 1 (cap 4).
Test files: new `tests/test_b103_inc9_ob_json_view.py` (`68dfccdb`); `tests/test_id_registry.py` bound 343 -> 344 for it
(`92e9794f`, the law's own instruction; the first fresh-clone run failed it: scanned 344, not 343).

## RED / GREEN (`-n 0`, one file each, transcripts `red.txt`, `green.txt`, `mut.txt`)
| Tree | Node 1 (read-only view runs no bracket scan) | Node 2 (editable paste buffer still matches) |
|---|---|---|
| HEAD code `b21d5517` + the test (`68dfccdb`) | **RED** `assert 'patch_json_view' not in ['patch_json_view' x3]` | GREEN |
| fix `0ba56c8c` | **GREEN** | **GREEN** |
| leak mutant (copy of the fix + `TextArea.find_matching_bracket = lambda ...: None` appended) | GREEN | **RED** `assert None == (0, 27)` |

Node 1 counts Textual's own `TextArea.find_matching_bracket` entered, by widget id (a wrapper via `monkeypatch`); a
subclass that does not call `super()` never reaches it. Node 2 asserts the paste buffer still enters it and still finds
the closing `}`.

## Record-stage block, before / after (FX9c probe `test_probe_parts`, 82_1's scenario, `-n 0 -s`, UI thread seconds)
Load read before each run: red 0.50, green 0.94 (1-min). Trees are `git archive` copies (HT-09); probe files only in the copies.

| Part | before (`b21d5517`) | after (`0ba56c8c`) |
|---|---|---|
| `_stage_bench_record` (the block) | **1.251** | **0.674** |
| `stage_record` | 0.019 | 0.020 |
| `serialize_change_document` | 0.173 | 0.166 |
| `_show_document` (`load_text`; of it `find_matching_bracket`) | 0.609 (0.607; 0.467) | 0.143 (0.141; 0.000) |
| `set_document` | 0.258 | 0.252 |
| keys after the stage: n / p50 / max | 30 / 0.044 / 0.357 | 27 / 0.049 / 0.308 |
| painted before/after card digest | `6daf5484e8d5bfd6` x2 | `6daf5484e8d5bfd6` x2 |

Block -0.577 s, all of it the bracket scan (0.467 -> 0.000). The block is still > 0.5 s (0.674): serialize 0.166 +
sheet 0.252 + JSON view load 0.141 + rest; O-E / O-F / O-A remain the open options (FX9c record).

## Timing nodes (each alone, `-n 0`, `-m serial_timing`, on `0ba56c8c`; load = 1-min before the run)
| Node | Load | Result | FX9c (`f5cb522e`) |
|---|---|---|---|
| 29_1 | 1.00 | **GREEN** 0.242 s (51.6 % margin) | 0.167 |
| 29_2 | 0.98 | **RED** slowest press 0.505 s | 0.539 |
| 82_1 | 0.96 | **RED** slowest press 0.988 s | 1.659 |
| 20_1 | 0.97 | **GREEN** 0.152 s (69.6 % margin) | 0.135 |

One run each; no bound, timer, xfail or skip changed. 29_2 is 5 ms over its bound (a GIL tail during the encode, FX9b
part 1); 82_1 improved by 0.67 s and stays RED on the rest of the block. The 29_1 / 20_1 differences vs FX9c are
single-run noise at load ~1; both stay GREEN.

## Visible change (operator)
The read-only JSON view (`LOADED DOCUMENT`) no longer highlights the matching bracket when the cursor is on one.
Editable text areas (paste buffer, JSON popups) keep it. Nothing else paints differently (card digests above).

## Fresh clone (`git clone` of the bundle of `b103-inc9`, `-n 2`, `timeout` 300 / 900, one run per file; transcripts `c-*`)
Clone head `0ba56c8c` for chain 2, `92e9794f` (the final code head, adds the id-registry bound) for chain 4.

| Set | Result |
|---|---|
| `tests/test_b103_inc9_*.py` (13 files, `-m "not serial_timing and not slow"`) | **all pass** (a9 29, b_canvas 42, b_cells 39, b_detail 54, b_model 20, b_tools 59, i 3, ob_json_view 2, w_jobs 2, w_keys 19, w_mutants 29, w_select 14, w_stage 11) |
| `tests/test_b103_inc8_*.py` (14 files) | **all pass** (371 tests, as in FX9c) |
| 27 files that touch `#patch_json_view` / `patch_tab_json` / `_show_document` (grep of `tests/`; no test imports `patch_editor.document` by name) | 15 files have failures; each re-run whole on a `git archive` of `b21d5517` with the same runner: FAILED id lists IDENTICAL (0 diff lines) in 14; `test_tui_patch_history_strip` differs (below) |
| Laws | `test_id_registry` 1 failed in chain 2 = MY new test file (bound 343), fixed in `92e9794f`: 12 passed on a clone at `92e9794f`; `test_suite_hygiene` 65 passed 2 skipped; `test_deps_seam_law` 6 and `test_no_private_tokens` 2 passed; `test_engine_unchanged` 1 skipped; `test_requirements_canon` 1 failed and `test_address_census` 1 failed = the two base-identical failures (`test_canon_rows_hold_the_obligation_word_once`, `test_at_b83_08_tree_holds_no_assembled_selectors`), 0 diff lines vs base |

`test_tui_patch_history_strip`: clone 1 failed + 1 skipped; the `git archive` base (no `.git`) 2 failed, the extra one
`test_tc081_4_no_binding_diff` fails there only because the archive has no git history. Not a regression.
Failing user files and counts (clone = base): active_variant 6, document 4, session_reset 3, designer_writes 11,
inplace_views 4, clipboard_core 2, copy_paste_matrix 7, chips_help 1, b99_editor_image 2, b99_s0 1, b99_staging 1,
patch_card 1, editor_b94 1, patch_json 4, history_strip 1 (`chain2-log.txt`, `chain3-log.txt`). Six of these files
(`b100_active_variant`, `b100_document`, `b101_designer_writes`, `b101_inplace_views`, `b99_s0`, `b99_staging`) were not
in FX9c's 20: base-identical, outside FX9d, for the orchestrator.

## Open items
- 29_2 (0.505 s) and 82_1 (0.988 s) RED: block 0.674 s; O-E (split the post-stage refresh) / O-F / O-A are the options.
- Base-identical failures in files not covered by earlier batteries (list above).
- Scratch note: one 1 KB helper (`parts_fx9d.py`) was piped to the runner's `/tmp` for one command and deleted at once
  (the brief says never `/tmp`).

## Evidence checklist
- [x] Tests: every result is one complete run's own output (`executed`); timing started at 1-min load < 2 (`chain1-log.txt`).
- [x] No secrets; records redacted (`~`, `<user>`, `<runner-home>`); no host, account or HOME basename (scanned).
- [x] No destructive command on work; runner scratch deleted by explicit list; no push; no process kill was needed (PF-01).
- [x] File count: 1 source file (cap 4); tests: 1 new + 1 bound bump.
- [x] 0 CR in the committed diffs (working copies are CRLF by `core.autocrlf`; the index is LF).

## Commits
`68dfccdb` tests (RED on base), `0ba56c8c` subclass, `92e9794f` registry bound, then this record's commit. No push.

## Scratch deleted (explicit list, only paths I created)
`~/work/zq-fx9d/`: `base clone clone2 green red mut home out tmp x run.sh waitload.sh redgreen.sh chain1.sh chain2.sh
chain3.sh chain4.sh launch.sh launch3.sh after2.sh users.txt fx9d.bundle fx9d2.bundle`, then the empty folder. Local: the
work folder `s19-relevo14-work/fx9d`, `s19-relevo14-work/waitload.sh`, `s19-relevo14-work/test_fx9c_probe.py`, two temp tars.
