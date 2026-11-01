# E13 notes — inc-12b capture scenario `qz-quit`

Scenario added: `qz-quit` (tools/e13/run.py, tools/e13/capture_all.ps1). It seeds
project P (the clean manifest, same as `sd-dialog`), loads it, patches
`s19_app.tui.app.place_into_workarea` (run.py only) so the Save worker sleeps
~60 s on its first placement, starts a Save of a new project `P1` via
`_handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea),
project_name="P1"))`, then — once `#status_text` paints the Save progress line —
focuses `#files_list`, presses `q`, and stops with the quit question open and the
Save still running.

## Headless re-run observations (selftest)

The selftest (`tools/e13/run.py --scenario qz-quit --selftest`) reports the same
logical widget state at all three capture sizes — the quit question is a modal
whose title/body/buttons/focus/status are independent of the terminal grid, so
118×54, 220×60 and 99×54 all show:

- Quit question title: `Quit?`
- Quit question text: `still working: Saving project P1 — wait, or quit after it finishes`
- Buttons: `Quit (y)` / `Stay (n)`
- Focused button: `confirm_no` (the `Stay (n)` button — the question's AUTO_FOCUS)
- `#status_text` (under the question): `Saving project P1  ·  step 2/4 Place the files  ·  00:02`
  (the leading glyph is the busy spinner frame and varies run to run; the line
  contains `step ` as required)
- `#progress_bar` value: `25` (step 2 of 4)
- Last log lines: `Loaded firmware.s19 (S19 only)` and
  `Loaded project 'P' -> firmware.s19 - variant 1 of 1, 1 problem - details: p`

The three captures were run through `tools/e13/capture_all.ps1 -Only qz-quit`
and finished `DONE failures=0`, leaving:

- `.dev-flow/2026-10-26-batch-100/evidence/inc-12b/e13/qz-quit.118x54.png`
- `.dev-flow/2026-10-26-batch-100/evidence/inc-12b/e13/qz-quit.220x60.png`
- `.dev-flow/2026-10-26-batch-100/evidence/inc-12b/e13/qz-quit.99x54.png`

I did not view these PNGs (image content is not available to me in this run);
every claim above comes from the headless selftest re-runs, not from the images.

## Selftest exit note

`asyncio.run(_once())` shuts down the default executor, which joins the Save
worker still sleeping in the patched `place_into_workarea` (~60 s), so the
`os._exit(0)` the bz-busy selftest used (placed after `asyncio.run`) only fired
~60 s late. For `qz-quit` the `os._exit(0)` now runs inside `_once`, right after
the `run_test` context teardown and before that executor join, so the selftest
ends ~5 s after reaching the surface. (Same path as bz-busy.)

## Observations

- OBS-12b-1 (pre-existing, out of scope, NOT fixed): `bz-busy`'s
  `_parse_loaded_file(self, path, a2l_files=None)` override is stale — the base
  now calls it with an `a2l_cache_out` keyword, so its selftest reports
  `Load failed: ... unexpected keyword argument 'a2l_cache_out'`. Unrelated to
  `qz-quit`; `qz-quit` does not override `_parse_loaded_file` and is unaffected.
- No defects observed in the `qz-quit` surface itself: title, body, buttons,
  focus, `#status_text` (`step `) and progress bar all match the quit-question
  contract from `test_tc_b100_53_quit_asks_only_while_a_session_action_runs`.

## Orchestrator view of the PNGs (Opus, 2026-11-01)
The orchestrator viewed all three PNGs (118x54, 220x60, 99x54).
- The quit question paints as designed at every size: title `Quit?`, text `still working: Saving project P1 — wait, or quit after it finishes` (wraps to two lines at 99), buttons `Quit (y)` / `Stay (n)`, the focus ring on `Stay (n)`.
- The busy line under it: glyph, `Saving project P1 · step 2/4 Place the files · 00:05` (00:06 at 220); the progress bar at 25% with NO Textual ETA beside it (OBS-12a-1 fixed by `show_eta=False`).
- The key bar says `^l Load` (12a label) and `q Quit`.
- OBS-12b-2 (cosmetic, design): `Quit (y)` carries the primary (filled light-blue) style while the focus is on `Stay (n)`; the eye lands on the destructive answer although Enter would pick Stay. Not fixed; BACKLOG-CODE (button variant of the quit question).
- OBS-12b-3 (pre-existing, check): the newest log row is cut at `… 1 problem - details: p` at all three widths, so the cut is a fixed length, not the window width. Batch-end battery: confirm against main and route.
- OBS-12b-1 (tool, pre-existing): `bz-busy`'s `_parse_loaded_file` override in tools/e13/run.py is stale (`a2l_cache_out`). BACKLOG-CODE.
