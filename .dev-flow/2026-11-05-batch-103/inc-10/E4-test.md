# Inc 10 E4 — tester T10 hand-back

Tester T10 (Sonnet 5.5). Tree `s19_app-b103-inc10-tests`, branch `b103-inc10-tests`, base `439860c4`. Never read the implementer tree. No push. Case map and negative controls: `02-test-cases-T.md`. RED transcripts (sanitised, PP-03): `evidence-e4-t10/`.

## 1. Files

New tests (all under `tests/`): `test_b103_inc10_g1_panel.py` (27 nodes: R-CHG-003.1, R-PE-EXPORT.1, .2, R-TUI-063.1), `test_b103_inc10_g1_controls.py` (24: Format, Width, names, R-TUI-064), `test_b103_inc10_g2_arms.py` (23: apply line, notice, the five hides, AT-I10-3, R-TUI-049.1), `test_b103_inc10_g2_write.py` (21: the files written, the S0 header, AT-I10-1, AT-I10-2), `test_b103_inc10_g3_engine.py` (24: R-HEX-EMIT-001.11 and the cited engine rows). Support `tests/support/b103_inc10.py` (every helper ≤ 40 lines). Data `tests/fixtures/b103_inc10/` (x64u: copies of `inc-10/data/`, derived by the stdlib script there) and one `.gitattributes` line (LF for them). 0 source files edited.

Retargeted shipped tests (I-8.3 (e), `E1-slice.md` §7.2/§8): `tests/test_b97_patch_editor.py` (TC-B97-60: the prompt's home is `#patch_export_dock`; + the Format control and the apply line: 30 controls, 12 read-outs), `tests/test_tui_patch_layout.py` (`_BUTTON_HOMES` + the dock; `show_save_prompt` call with the two I-10.1 arguments; AT-064c wording), `tests/test_tui_patch_editor_v2.py` (:302 and :574 read a shown widget, not the absence of `hidden`), `tests/test_b100_active_variant.py` (:1064 shown-widget wait; no JSON chip), `tests/test_b99_editor_image.py` (AT-B99-08 and TC-B99-22: see F-T10-2).

## 2. Coverage

130 cases: **126 mapped to a test** (table in `02-test-cases-T.md`; `trace_check` below: 0 gaps), **4 not written** — R-S19-S0HEADER-001.1/3, R-S19-S0HEADER-001.2/5, R-S19-EMIT.11/1, R-S19-EMIT.11/2 (`conflict`, D-6 A, owed by D8-27 / D8-28 / D8-29; E4-N2: no test asserts an empty S0 for a source with S0 data or a terminator address).

```
$ python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-10/01-requirements.md --tests tests --ids "R-PE-EXPORT.*" "R-CHG-003.*" "R-TUI-063.*" "R-TUI-049.*" "R-TUI-064.*" "R-HEX-*" "R-S19-*" "R-IMG-WRITE.*"
trace_check: 44 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)
```

## 3. RED on base 439860c4 (rtx, HT-02 env, `-n 2`, `timeout 300`, `s19_app.__file__` = the base tree first line of every transcript)

| File | Result on base | Notes |
|---|---|---|
| `g1_panel` | 25 failed, 2 passed (128 s) | the 2 GREEN: R-TUI-063.1/1 and /3 (prompt hidden: the base order already holds, census C; they guard the shown-prompt cases /2, /4 against a wrong order list) |
| `g1_controls` | 24 failed (116 s) | every case RED: the Format control, apply line and dock do not exist; the prompt is 0×0 in every tab but JSON |
| `g2_arms` | 21 failed, 2 passed (126 s) | the 2 GREEN: R-PE-EXPORT.6/1, /2 (0 notices after a successful apply, base C; they guard R-PE-EXPORT.5's change) |
| `g2_write` | 21 failed (103 s) | every case RED (no Format control; the file is written in the loaded kind) |
| `g3_engine` | 2 failed, 22 passed (1.3 s) | RED: R-HEX-EMIT-001.11/1, /2 (`:10FFF800…` crossing record, the base emitter). GREEN by design: the cited engine rows (R-HEX-SAVE-001.2, R-PE-EXPORT.16, R-HEX-EMIT-001.2/.3, R-S19-EMIT.3/.4/.5, R-IMG-WRITE.2, R-HEX-VERIFY-001.1/5): the engine is unchanged, census C; they are characterisation guards for the new path, and the oracle guard test proves the fixture can fail (the base-emitter file crosses, the expected file does not) |
| shared retargets (8 nodes, 14 params) | 14 failed (58 s) | retargets pin the new home; RED on base is expected, GREEN needs the implementation (not run by me) |

Why each RED is for the right reason (first `E` line, in `evidence-e4-t10/`): R-CHG-003.1 `not a shown widget (region 0×0)`; the format and apply-line cases `expected exactly 1 widget, found 0`; R-PE-EXPORT.5/1..3 `[]` (no notice); R-PE-EXPORT.17/1..3 `(False, 'Patch Editor: entry added.')` (the prompt is offered and not hidden); R-PE-EXPORT.17/4, /5 `the prompt is still a shown widget after …`; R-PE-EXPORT.3 `TypeError … unexpected keyword argument 'output_format'` (I-10.1).

A GREEN-on-base node that turned out vacuous was fixed: R-PE-EXPORT.10/1 passed on base because the prompt was 0×0 (nothing painted, nothing focusable, a click at (0,0) does nothing); it now first asserts the prompt itself is shown at its place.

## 4. What the tests do not prove, and what I could not run

- **No GREEN run.** Tester rule: I never read the implementer tree. Everything that imports the app ran on rtx at the base only. The GREEN of the new tests and of the retargets is the conductor's run on the implemented tree; I wrote them from the requirement, the case rows, the graph examples and the committed data.
- **R-PE-EXPORT.2/11 dock height not measured** (no dock on base). The two tests print `DOCK-HEIGHT 118x54 = n rows` and `DOCK-HEIGHT 220x60 = n rows`; `n > 4` is finding F-R8-1 (not a failure of the test). Read it from the GREEN run (`-s`).
- **Partial routes (declared in `02-test-cases-T.md`):** images load through `app.load_from_path` and boxes are filled by assignment, except AT-I10-1 / AT-I10-2 (Load dialog + keys) and R-CHG-003.1/1, /5 (Load dialog); R-S19-S0HEADER-001.2/2..4, .3/1..4 and .1/2 post the confirm message (with `output_format`) instead of clicking `Write file`; the per-entry JSON popup text is replaced with `load_text`; R-PE-EXPORT.17/5 uses Inc 8's DEFC image, not case01; R-TUI-064.2 reads `clipped_overflow` and the whole apply line (the compositor cannot paint past the screen).
- **Load:** rtx load average 3 to 7 during the runs; no timing is asserted anywhere.
- **Entry change then `Write file` in shipped tests:** a static scan (apply → entry change → confirm inside one test function) found only AT-B99-08 and TC-B99-22, both retargeted. Tests that reach the same sequence through helpers are not found by the scan; the conductor's GREEN run lists them (E1-slice §6 names the candidates).
- Third-party interop (objcopy, srec_cat) is E5's (E3-2), not run.

## 5. Findings (requirement vs graph vs shipped code)

- **F-T10-1 (AT-I10-1 / AT-I10-2 vs Inc 8 final).** The cases say the Inspector tab is "the default". At `439860c4` the landing pane starts on **Patch script** (`layout.py`: `ContentSwitcher(initial="patch_win_script")`; R-TUI-063.3), and the entry boxes live only in the Inspector pane. So the operator story needs one chip press (Inspector) before typing the entry. AT-I10-1 presses it before the entry and none after Apply ("no tab chip pressed" holds as written); the row's "default" wording should be corrected.
- **F-T10-2 (R-PE-EXPORT.17 vs AT-B99-08 / TC-B99-22).** Those two shipped tests add an entry, do not apply it, and press `Write file` to prove the "includes 1 entry not applied before this save" naming (F3). With R-PE-EXPORT.17 the add hides the prompt, so the product no longer reaches that state. I kept their intent as a handler-level guard by showing the prompt through I-10.1 (the route R-PE-EXPORT.3's cases use). Orchestrator choice: keep as is, or retire the two arms (like C-5).
- **F-T10-3 (R-PE-EXPORT.17/1..3 on base).** The base cannot be RED at the hide itself in the Inspector tab (the prompt is not painted there); the nodes read the `hidden` class and the shown state together, so on base they fail at "still offered, not hidden". A dropped hide in one arm turns exactly that arm's test RED after the fix.
- No disagreement found between the requirement rows and the graph's examples beyond F-T10-1.

## 6. Mutants the E4 mutant worker can run (each is a named NC in `02-test-cases-T.md`)

Base loop of `emit_intel_hex_from_mem_map` (R-HEX-EMIT-001.11/1, /2; the second mutant caps inside the fixed `range`); the hide dropped from each of `add_entry`, `edit_entry`, `remove_entry`, `_apply_entry_json_edit`, `on_staging_sheet_stage_requested` (17/1..5); no notice / information severity (5, 6); `Width` collapsed instead of hidden (12); name suffix matched at the very end only (14/4); format not carried on the decision (HEX-SAVE-001.1/2, /4).
