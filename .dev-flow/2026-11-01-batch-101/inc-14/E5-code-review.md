# Inc 14 — E5 code review

Batch 2026-11-01-batch-101, increment 14, stage E5. Reviewer: code-reviewer, independent of the implementers, the tester and the integrator. Read-only, apart from this file. No test was run on this PC (operator rule). I read the integrator's LAN-host transcripts instead.

Scope: `git diff main...HEAD` at head `7d37efa` (merge base `b7b77c4`). `main` is now `f86f415`, and `git diff --stat b7b77c4 main -- s19_app tests README.md` is empty, so every truth check below holds on the current `main` too.

## Verdict

**PASS-WITH-NOTES.** No BLOCKER and no MAJOR finding.

- Every product text matches the binding text, character for character.
- Every sentence I checked is true to the code at this base.
- Each new or re-bodied test can fail when its text is wrong. One test is weaker than its case (F1, MINOR).
- The integrator's two test fixes made nothing weaker.
- The SECURITY.md hold-out group is complete. It is now triggered: `evidence/inc-14/gh-pvr.txt` (2026-11-05T23:42:44Z) reads `{"enabled":false}`.

Evidence state for each check: `executed` (static read and scripted diff on this PC); suite results `executed` on the LAN host per the transcripts. Snapshot SVG tests are `not-run` (29, plugin absent; E4 §5).

## 1. Product texts against the binding texts

- **Help copy I14.** A script parsed `01-requirements.md` §Help copy I14 and read `WINDOW_HELP_SECTIONS` with `ast.literal_eval`, without importing the module. All six rewritten sections (36 steps, titles unchanged) are equal. The six Flow Builder steps are equal to the base text with exactly the named removals. The double space in step 18 is collapsed, and the five other sections are byte-identical to base. `tests/support/help_copy_i14.py` equals both. The step counts match the R-WHELP.7 pins: 43/6/6/6/4/59/5/5/8/35/25/4.
- **Legend copy I14.** `legend.py:497`, `:505` are equal.
- **Documents vs graph.** The README blocks (1)–(15), SECURITY.md, the CHANGELOG subsections (a)–(f) of Reports, the Flows, CRC config and Projects texts, guide passages /1–/11 and the DOSSIER 8 marks all equal the graph texts. Only wrapping or layout differs.
- **CHANGELOG CRC section.** It is verbatim with `inc-8/release-note-crc.md` §What changed … end, `##` → `####` (scripted diff: equal).
- **Declared deviations, all acceptable:**
  - The comment is wrapped over two `#:` lines; the text is unchanged.
  - The dropped docstring paragraph claimed the Split / Join / Export window is "change 4 (inc-004)". That was false, because the window ships, and the docstring is not rendered.
  - The extra `MAP_REGION_ROW_FIELD_KEY` comment.
  - `[A-1]` is omitted from guide /11. It is a trace tag, not prose.
  - SECURITY "Include:" is written as bullets.
  - Also seen: ch06 /1 wraps the key-line code span across a line break. CommonMark renders it as one span, and the test flattens whitespace.

## 2. Truth to the code (sample with file:line)

- **Keys.** The README rows were checked against `S19TuiApp.BINDINGS` (`app.py:2674-2745`):
  - `check_action` (`:9604-9614`): `+ -` A2L/MAC, `, .` Workspace, `c` Flow Execution.
  - `_FIND_GOTO_INPUTS` (`:9351-9364`): `/ g` on Workspace, A2L, MAC.
  - `page_down_context` (`:10474-10504`): Issues, else A2L/MAC.
  - `j` → `workarea/temp/<stem>.a2l.json` (`:9232-9248`).
  - `=`, `]` rail keys (`:2717`, `:2720`).
  - `Ctrl+P` is `ENABLE_COMMAND_PALETTE` (Textual default, not overridden).
- **Key bar row 1.** `GLOBAL_KEYS` and its labels (`window_help.py:841-843`, `:1016-1024`) match README:146.
- **`?` routing.** It claims the window first (`window_help.py:5-10`, `:801`; `screens.py:3170`), else the panel (`app.py:9695`).
- **Split / Join / Export.** The window's keys (`segment_split_view.py:1456-1471`) and these behaviours match:
  - the default tab is `ranges` (`:1480`);
  - `g` cycles skip/fill in split mode and concat/fill in join mode (`:1986-1991`);
  - pad toggles 0x00 ↔ 0xFF (`:1998-2000`);
  - the project destination falls back to common (`:1617-1626`);
  - the two-step confirm (`:2031-2050`);
  - the palette entry (`app.py:9446-9449`).
- **Controls named in the rewritten sections exist in their own window's compose:**
  - A2L (`app.py:8023-8064`, `:8266`);
  - CRC Designer (`crc_designer_view.py:367-428`);
  - Checks: Hex Peek (`app.py:3659`), click / Enter → `Selected` (`checks_view.py:257-266`), 40-row cap and note (`:311`);
  - Patch: Run checks on the Checks tab (`screens_directionb.py:4456`, `:5192`);
  - Reports (`screens.py:3300`, `:3336`, `:3342`).
- **README Patch Editor and Projects.** The labels exist: Apply loaded changes `:5269`, Write file under "Save patched image as:" `:5117-5130`, Execute scope `:5098`. A save into a project becomes a variant (`app.py:4929ff`, LLR-168.2).
- **Operations.** The placeholder text is `placeholder: <id> not yet implemented` (`operations/placeholders.py:8`).
- **CHANGELOG vs merged code:**
  - Inc 3: the status is `Project sync NOT done: … could not be read — check that the folder can be opened, then load again.` (`app.py:14980-14992`), and `iterdir` on a deleted folder raises OSError (`workspace.py:2176`).
  - Inc 8: the reasons (`crc_config.py:97`, `:262`, `:291`, `:542`) and `external step refused` (`flow_execution_service.py:1170-1201`).
  - Inc 7: the title (`diff_report_service.py:1823`, `:2703`), the `.part` name (`:342`), U+FFFD (`_strip_ctl`) and the path code spans (`_md_path`).
  - The release-note values are pinned by RELNOTE 1/2 and 2/2 against `crc32_stream`.
- **SECURITY scope.** `subprocess` appears only in `folder_open_service.py:194` and `os_clipboard_input.py:359`, `:522`. `s19_app/version.py` exists, and the distribution is `s19tool` (`pyproject.toml:30`).

## 3. Tests — can each fail?

- **tc707 numbering** (`test_window_usage_help.py`). (a) It compares the rendered body to `f"{n}. {step}"`, with a gapped-body control. (b) It rejects a stored number prefix. (c) It holds 12 pins. Each arm has a control that reports a defect. Not vacuous.
- **K(w) census** (`test_b101_help_legend_docs.py:162-236`). It models `check_action`, the self-guards, N-1 and the Split widget keys. The controls `h` (unbound), `,` and `d` (bound but inert on Checks) are reported, and `,` on Workspace is accepted.
- **AT-285** (`test_docs_canon.py`). It reads `_merged_bindings`. The `h` control is reported. With the palette monkeypatched off, the unbound set is exactly `{Ctrl+P}`, a discriminating negative.
- **Document substring pins.** These are exact phrases from the graph, with an absent-phrase control per passage or RELNOTE. RED on base: 56/72 (`red-01-tester-base.txt`).
- **Integrator fixes.**
  - SR-1: `_BEFORE` loses its `)`. This is the graph's I-5 form, and each passage still has an absent-phrase arm.
  - SECURITY.1/1: the old negation regex became the exact phrase `not in a public issue`, which is stricter.
  - TC-607 250 → 252 is a measured equality.
  - None of these is weaker.

## 4. SECURITY.md hold-out group

The group is complete. It takes:
- `SECURITY.md`;
- `test_r_doc_security_1_1_policy_names_private_path`, `test_r_doc_security_2_1_supported_versions` and `test_r_doc_security_1_3_readme_links_the_policy` (`test_b101_help_legend_docs.py:1224-1264`);
- the README row `README.md:429`.

No other tracked file names SECURITY.md (`git grep`), apart from the test module's docstring. `test_r_doc_readme_4_2` stays GREEN once the row is gone, because it still needs the CHANGELOG link (F8).

## Findings

### F1 — R-WHELP.12/2 does not scope controls to their window  [MINOR · impl]
- **Where:** `tests/test_b101_help_legend_docs.py:343-352`.
- **What:** `_painted_strings(app.screen)` collects the strings of every mounted rail window, and hidden windows stay mounted (`app.py:9338-9342`, P-10). Several named controls are painted by other windows too: "Hex Peek" by Issues (`app.py:3593`), and "Find Next", "Goto", "Goto 0xADDR" and "Search ASCII text" by Workspace and MAC (`:3490-3493`, `:8145-8149`).
- **Scenario:** remove the Hex Peek pane from Checks, or the find row from A2L Explorer. The test stays GREEN although the help step is then false. The claims hold today; I verified them in §2.
- **Fix:** take the root as `app.query_one(f"#{app.SCREEN_CONTAINER_IDS[screen]}")`, as the Split and Reports arms already do.

### F2 — F-28 "fixed in 1.0.0" reads as "the block now reads Designer templates"  [MINOR · design-gap]
- **Where:** `docs/user-guide/DOSSIER.md` F-28 row.
- **What:** In 1.0.0 the Flow CRC block still refuses a Designer template, now with a named cause (R-CRC-CONFIG-001.16). §17.5 of the guide says so.
- **Fix:** at the batch-end doc pass, word the mark "fixed in 1.0.0: refused with a named cause", or similar. R-DOC-GUIDE.2 pins the set, so this needs a named supersession.

### F3 — CHANGELOG "a line break as one space" is not exact for CRLF  [NIT · design-gap]
- **Where:** `CHANGELOG.md:50`.
- **What:** `_normalise` replaces CR and LF each with a space (`markdown_safety.py:140`), so CRLF becomes two spaces. The test pins `"a b  c"` itself (`test_b101_help_legend_docs.py:1428`).
- **Fix:** "a tab, a carriage return or a line feed each as one space".

### F4 — two spellings of the same keys  [NIT · design-gap]
- **What:** The help steps write `^K`, `^L`, `^S`; README:146 quotes the bar as `^k`, `^l`, `^s`. `^L` and `^S` pre-date this increment, and Inc 14 adds `^K`.
- **Fix:** backlog, so one spelling is chosen across help and README.

### F5 — stale test docstrings  [NIT · impl]
- **Where:** `tests/test_window_usage_help.py:4-34`, and the `test_tc707_boundary_*` docstring and assertion message.
- **What:** They still describe the md fidelity census and "inc-004 mounts its window". The product docstring had the same text removed.

### F6 — a vacuous negative control and a thin guide pin  [NIT · impl]
- `tests/test_changes_file_notation_help.py:159-160` compares sets built inside the test, which is always true and runs no detector.
- Guide passage /7 (`test_b101_help_legend_docs.py:1465-1467`) pins only `(capture taken before 1.0.0`, not "names the work area's common folders".

### F7 — README wrapping  [NIT · impl]
- **What:** The new README paragraphs are single long lines (e.g. `README.md:81`, `:146`, `:166`, `:182`), while the file wraps at about 80 columns. This is declared and is layout only.

### F8 — N-2 wording at merge  [NIT · records]
- **What:** N-2 says "its two tests … plus the README link-check arm". The group is three tests plus the README row.
- **Fix:** hold out the row, not `test_r_doc_readme_4_2`, which keeps the CHANGELOG link check. If SECURITY.md is held out, mark R-DOC-SECURITY.1/.2 as deferred in the trace.

## What I read

- `01-requirements.md`, `E1-slice.md`, `E1-rulings.md` (partly), `E3-rulings.md` (rounds 1 and 2), `codewire/graph-inc14.md`, `E4-impl-notes-{code,guide,top}.md`, `E4-tester-notes.md`, `E4-integration-notes.md`, `../inc-8/release-note-crc.md`.
- Transcripts `int-01`, `int-02`, `red-01`, and `gh-pvr.txt`.
- The full product diff, the full `tests/test_b101_help_legend_docs.py`, `tests/support/help_copy_i14.py`, and the diffs of `test_window_usage_help.py`, `test_changes_file_notation_help.py`, `test_docs_canon.py`, `test_id_registry.py`.
- Code at the file:lines cited above.

## Evidence checklist

- ✓ Diff read in full: the product files, plus the tests listed above.
- ✓ Correctness pass: §2. Every claim sampled holds.
- ✓ Simplicity pass: 0 functions and 3 constants changed. No abstraction.
- ✓ Reuse: the tests reuse the existing harnesses (`test_tui_report_seam`, `test_map_click_chain`, `test_crc_designer_view`).
- ✓ Tests reviewed for intent: §3, F1 and F6.
- ✓ Verdict is explicit: PASS-WITH-NOTES. No HIGH finding is open.
