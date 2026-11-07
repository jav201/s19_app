# Inc 10 — E1 rulings: scope, canon changes, decisions

Base `e07fb00`. Rows: `01-requirements.md`; cases: `02-test-cases.md`; slice: `E1-slice.md`; evidence: `evidence-e1/`. Every decision in §3 is **PROPOSED — awaiting orchestrator ruling** (and, where marked, **awaits G2**: prototype round 2 shows the variants `px_A` docked export bar, `px_B` Inspector card, `px_C` export dialog — `C:\Users\jjgh8\Github\s19_app\prototypes\b103_ux\round2\variants\px_*.py`, read only). The table of `01-requirements.md` carries the recommended option of each decision; the other options' rows are written out here.

## 1. Scope and what the census found

**In scope (US-103-06):** (a) the defect — the save-back prompt is shown in an undisplayed tab; (b) a visible result of every apply; (c) the output-format choice S19 / Intel HEX independent of the source, the Width choice only for S19, the name's extension following the format; (d) the write and the verify for both formats under the existing S8.7 / S8.8 rows.

**Facts (base `e07fb00`):**
- **The defect, per tab** (C, `evidence-e1/i10e1_layout_census_transcript.txt`): after Apply, `#patch_saveback_row` loses `hidden` but stays a child of `#patch_win_json`; its region is 0×0 and the hit test finds nothing in the Inspector, Checks and A2L tabs at both 118×54 and 220×60 (6 of 8 tab cases). It is shown only in the JSON tab, at (74,36) 41×3 and (142,42) 75×3. The Apply button is in the document row, shown in all four tabs. The Patch Editor never scrolls at either size (`max_scroll_y` 0).
- **Why no test caught it** (R): the shipped state walk presses Apply only after showing the JSON tab, `tests/test_b97_patch_editor.py:1418-1426`; `tests/test_tui_patch_editor_v2.py:302`, `:574` and `tests/test_b100_active_variant.py:1064` read the `hidden` class, not the shown region.
- **A stale prompt** (C): an apply that applies nothing (the entry replaced by one outside the image) leaves the prompt shown at both sizes, while the image byte at 0x8000007C is back to 0x3C (R-CHG-002.1 restored it). Pressing `Write file` there would write a copy of the source under a `-patched` name. No canon row covers hiding it → R-PE-EXPORT.3.
- **No cue** (B, C): the status line alone; 0 notices after an apply, successful or not.
- **The engine already converts** (C, `evidence-e1/i10e1_convert_census_transcript.txt`): given the output format as its kind, the save-back writer writes and the verify reads back 32/32 conversions (4 S19 sources with S1 / S2 / S3 records, S0 data and S9 / S8 / S7 terminators, their 4 Intel HEX twins, each to S19 at width 32 and 16 and to Intel HEX), all `verified` and read back to the same image. The flow's WRITE-OUT block already passes a chosen format this way (`flow_execution_service.py:722-729`). Reading a file with the other format's reader gives `mismatch` 8/8 (the negative control of R-HEX-VERIFY-001.1).
- **What a conversion carries** (C): S19 → Intel HEX keeps every byte and drops the S0 data and the terminator address (HEX types 00, 01, 04 only; the reader discards type 03/05 anyway, `hexfile.py:182-184`); Intel HEX → S19 writes S1 / S2 / S3 by the highest address (R-S19-EMIT.3 … .5 hold), an S0 of the written name at width 32 and an empty S0 at width 16 (R-S19-S0HEADER-001.2 / .3), and terminator address 0 (R-S19-EMIT.12). An Intel HEX file keeps 16 data bytes per record at either width (R-S19-SAVE-REUSE-001.1).
- **The name** (C): the writer adds the format suffix to a name that lacks it, so `firmware-patched.s19` written as Intel HEX becomes `firmware-patched.s19.hex` — the reason for R-PE-EXPORT.14.

**Out of scope:** the Execute-scope write (`variant_execution_service.py:2584`, S19 only), Save project's image (`app.py:13264`), the flow WRITE-OUT, the folder rule (§3 D-7), the open code changes of §4 (by D-6 A), the `Save` label (§6).

## 2. Changes to existing canon rows (fixed in place)

| # | Row | Old text (canon) | New text | Reason |
|---|---|---|---|---|
| R-1 | R-CHG-003.1 | When an apply ends with at least one applied entry on an S19 or Intel HEX image, the system shall show the save-back prompt. | … the system shall show the save-back prompt as a shown widget whichever inspector tab was shown when the operator pressed Apply. | Defect: the row was met by un-hiding the prompt inside an undisplayed window (C: 6 of 8 tab cases 0×0). "Show" did not say *where*, so a test of the `hidden` class passed while the operator saw nothing. The fix names the observable: a shown widget (batch-101 Inc 12's CTX-SHELL term) from any tab. Not changed to match code: the code fails the new row. |
| R-2 | R-TUI-063.1 | … the file row, the document row and the legend, top to bottom. | … the file row, the document row, the save-back prompt while it is shown, and the legend, top to bottom. | Follows D-1 A (the prompt docked between the document row and the legend). **PROPOSED — awaits G2.** Under D-1 B or C this row stays as it is. |
| R-3 | R-TUI-049.1 | When a save-back succeeds, the system shall show the before/after control. | … the system shall show the before/after control as a shown widget whichever inspector tab is shown. | The same defect class: the control is revealed inside `#patch_win_json` (`screens_directionb.py:5144-5158`). Today it is seen only because `Write file` is reachable only from the JSON tab; once the prompt moves, the control would appear in a tab the operator is not on. D-5. |
| R-4 | R-HEX-SAVE-001.1 | When the system writes a save-back, the system shall write the file in the kind of the loaded image, S19 or Intel HEX. | … the system shall write the file in the output format. | The new behaviour (US-103-06: a format independent of the source). The output format is set by R-PE-EXPORT.7 / .8. |
| R-5 | R-HEX-SAVE-001.2 | If the save name does not end with the kind suffix in any letter case, then the system shall add the kind suffix. | … the format suffix … the format suffix. | "Kind suffix" was defined by the loaded image's kind (CTX-SAVEBACK); with an independent output format that would name the wrong suffix. The term is replaced by *format suffix*. |
| R-6 | R-S19-SAVE-REUSE-001.1 | When the system writes a save-back of an Intel HEX image, … | When the system writes a save-back as Intel HEX, … | "Of an Intel HEX image" now reads as the source; the 16-byte rule belongs to the written format (an S19 source written as Intel HEX also writes 16 bytes per record, C). |
| R-7 | R-S19-S0HEADER-001.1, .2, .3 | … a save-back of an S19 image whose source has (no) an S0 record with data … | … as S19 a save-back whose source has (no) an S0 record with data … | Same ambiguity: the header rules apply to the written S19 file, whatever the source. An Intel HEX source written as S19 has no S0 record, so .2 (width 32) and .3 (width 16) govern it (C). The width-16 alternative of .1 and the "written name" of .2 keep their open code changes D8-27 and D8-28 (§4). |
| R-8 | R-S19-EMIT.11 | When the system writes a save-back of an S19 image whose source has a terminator, … | When the system writes as S19 a save-back whose source has a terminator, … | Without the change the row would ask an S19 source written as Intel HEX for an S19 terminator. Its code change D8-29 stays open (§4). |
| R-9 | R-HEX-VERIFY-001.1 | … read the file back with the S1 reader of its kind. | … with the S1 reader of the output format. | "Its kind" could be read as the loaded image's kind; the read must follow what was written (C: the wrong reader gives `mismatch`). |

Context notes (`01-requirements.md` Definitions): CTX-SAVEBACK gains *output format*, *Format control*, *apply line*, replaces *kind suffix* with *format suffix* and changes *suggested name* and *save-back prompt*; CTX-PE's *save-back prompt* line loses "It sits in the JSON tab" (PROPOSED — awaits G2), and its JSON-tab list loses the prompt and the before/after control (D-5).

## 3. Decisions — PROPOSED, awaiting orchestrator ruling

### D-1 Where the prompt sits — **awaits G2**
- **A — docked bar under the document row, in every tab (px_A).** Rows as in `01-requirements.md`: R-PE-EXPORT.1, R-TUI-063.1 (changed). The row and the before/after control leave `#patch_win_json` for a container between `#patch_doc_controls` and `#patch_legend`; `#patch_main` gives up the rows (C: 35 rows at 118×54, 41 at 220×60, enough for a 3-row bar). Consequence: the ledger and inspector lose ~3 rows while the prompt is shown; no state change on Apply; no new screen, key or action (R-SHELL-KEYS.3 of batch-101 Inc 12 is untouched).
- **B — card at the top of the Inspector tab (px_B).** R-PE-EXPORT.1 becomes "The system shall show the save-back prompt at the top of the Inspector tab." and one row is added: "R-PE-EXPORT.17 · When an apply ends with at least one applied entry on an S19 or Intel HEX image, the system shall show the Inspector tab." R-TUI-063.1 unchanged. Consequence: **px_B as prototyped (the card waits in the Inspector, the chip dot the only sign) fails R-CHG-003.1 as fixed**; it passes only with R-PE-EXPORT.17, which moves an operator who applied from the JSON or Checks tab away from what they were reading. The inspector's pane is 41 columns wide at 118×54 (C: `#patch_tab_switcher` 41×32), so the 85-column apply line wraps to three lines.
- **C — a dialog after Apply (px_C).** R-PE-EXPORT.1 becomes "When an apply ends with at least one applied entry on an S19 or Intel HEX image, the system shall open the dialog `Export the changed image?` with the save-back prompt." The dialog rules S7.1 then apply (R-DLG.1 no key of the Patch Editor acts; R-DLG.2 Escape = `Don't save`; R-DLG.5 focus in the name box; R-DLG.11 / .12 each button shows its key — the prototype's `Write file  alt+w`, `Don't save  esc`, Format `alt+f`); CTX-DIALOG's table gains the row; R-TUI-063.1 unchanged. Consequences: a new `ModalScreen` class and three keys that need the Windows Terminal evidence of §8; the before/after control still needs a home outside the JSON tab (D-5), so the dock of A is needed anyway; the class must not go into `screens.py`, which batch-101 Inc 12 changes (§7); batch-101 Inc 12's R-DLG.14 (an opener per dialog) and R-SHELL-KEYS.3 (a reach per action) apply.
- **Recommendation: A.** It meets R-CHG-003.1 from every tab with no change of state, keeps the before/after control beside the prompt, adds no screen, key or action, and touches the fewest lines in the two files batch-101 Inc 12 also edits.

### D-2 The format a new prompt starts with — **awaits G2**
- **A — the loaded image's format** (R-PE-EXPORT.7 as written). One press fewer in the common case; `Write file` always works; an operator who exports in the source format sees today's file.
- **B — always ask (px-ask).** R-PE-EXPORT.7 becomes "When the system shows the save-back prompt, the system shall set no output format." and two rows are added: "R-PE-EXPORT.17 · If no output format is set when the operator presses `Write file`, then the system shall write no file." and "R-PE-EXPORT.18 · If no output format is set when the operator presses `Write file`, then the system shall show the status `Patch Editor: choose S19 or Intel HEX before Write file`." R-PE-EXPORT.9 shows no name until a choice; the suggested name has no suffix until then. Consequence: one more press per export, one more refusal path.
- **Recommendation: A.**

### D-3 The Width control for Intel HEX
- **A — hidden, its place kept** (R-PE-EXPORT.10 as written, with R-PE-EXPORT.12: `Write file` and `Don't save` do not move). A hidden control is not painted, takes no focus, and a click at its place does nothing; the reserved place keeps the buttons under the pointer when the format changes (tui-design FEEDBACK: prefer a hidden reserved track to a collapse that moves its neighbours).
- **B — shown disabled.** R-PE-EXPORT.10 becomes "While the output format is Intel HEX, the system shall disable the Width control." Consequence: the operator reads `Width: 32 bytes/line` beside a format that writes 16 bytes per record (R-S19-SAVE-REUSE-001.1) — a label that contradicts the file.
- **C — hidden and collapsed.** R-PE-EXPORT.12 is dropped; `Write file` jumps 22 columns when the format changes (the Width chip is 21 cells, C).
- **Recommendation: A.** This also closes the open item D8-40 / D10-43 ("Width control on an Intel HEX save-back — needs prototype", `s19w/review/CODE-CHANGES.md:222`, `:259`), which G2's px_A / px_C show hidden for HEX.

### D-4 The visible result of an apply (the brief's "decide whether a notice is also needed")
- **A — the apply line in the prompt; a warning notice only when nothing was applied; no notice on success.** Rows R-PE-EXPORT.4, .5, .6. Reasons (tui-design FEEDBACK): a successful apply is a transition the prompt itself now shows where the operator looks, as persistent state rather than a toast that times out (the US-061 precedent of the before/after control, and R-HEX-VERIFY-002.2: a verified save shows no notice); an apply that applies nothing changes nothing else on screen — no prompt (R-PE-EXPORT.3 hides any old one) — so the status line alone repeats today's failure, and "nothing applied" is a consequence the operator could otherwise read as done.
- **B — also an information notice on every successful apply.** Consequence: two cues for one event; the notice overlaps the prompt's area at 118×54 for its lifetime.
- **C — the status line only (today).** Fails US-I10-1.
- **Text of the apply line — awaits G2:** **A′** (in the table) `Apply: <a> applied, <s> skipped, <b> blocked · changed in memory only — Write file saves it` reuses the status text verbatim and adds the side effect and the next step (outcome first; 85 columns with one-digit counts, inside the 112-column document row at 118×54). **B′** the prototype's ` ✓ APPLIED  <a> entr(y|ies) written into <file name> in memory · <s> skipped · not on disk yet`: the `✓` already means "check passed" in the Patch Editor's legend (CTX-PE legend), one glyph with two meanings on one surface; and it puts a file-derived name in the line (R-PE-005 then applies to it). **Recommendation: A, with A′** unless the G2 verdict picks the prototype's words.

### D-5 The before/after control follows the prompt
- **A — it moves with the prompt** (R-TUI-049.1 changed, §2 R-3). Under D-1 A both share the docked bar: after `Write file` the bar holds `Before/after report available:` and `Write before/after report`.
- **B — it stays in the JSON tab.** Consequence: once `Write file` is pressed outside the JSON tab, R-TUI-049.1 is met only by an undisplayed widget — the defect this increment removes, moved one step later.
- **Recommendation: A.**

### D-6 Open code changes on rows this increment rewords (§4)
- **A — leave them open.** The reworded rows (R-S19-S0HEADER-001.1, .2, R-S19-EMIT.11) keep their open alternatives as `conflict` cases (`02-test-cases.md`: R-S19-S0HEADER-001.1/3, .2/5, R-S19-EMIT.11/1, /2), with no test in this increment; the bytes an S19 → S19 save writes today stay identical.
- **B — fold D8-27 and D8-28 here** (both in the save-back handler this increment rewrites, `app.py:5027-5033`; no new file): the source's S0 data kept at width 16 too, and the header built from the written name. Consequence: an S19 → S19 save at 16 bytes per line writes a non-empty S0 from now on — a change to files the operator's tools already take, in an increment the operator asked for urgently for another reason.
- **C — B plus D8-29** (the source's terminator address): needs the S19 writer and the two service functions that carry its arguments (`changes/io.py`, `changes/apply.py`, `services/change_service.py`) — over the 4-file cap with the two UI files; a split.
- **Recommendation: A.** D8-17 (the unreachable `<kind> save-back not supported` branch, `app.py:4877-4880`) sits inside the arm Inc 10 rewrites; removing it is a one-line deletion the orchestrator may fold in with A (no row changes).

### D-7 The destination folder
- **A — unchanged** (R-CHG-003.8: the open project's folder, or the work area; CTX-SAVEBACK *destination*). No reason found to change the rule: the operator asked for the format, not the place.
- **Recommendation: A.** Noted for the backlog, not a decision: the verified status names the file and not its folder (`Saved + verified: firmware-patched.s19 — …`), and the Patch Editor's `📂 Open patches/` chip opens `patches/`, not the folder the image lands in.

## 4. Open code changes that touch this increment's rows (`C:\Users\jjgh8\Github\s19w\review\CODE-CHANGES.md`)

| Code change | Row | Effect here |
|---|---|---|
| D8-17 (`:206`) unreachable `<kind> save-back not supported` | — | inside the apply arm Inc 10 changes; may be removed with D-6 A |
| D8-25 (`:212`) a blocked apply names its reason | R-CHG-002.5, .6 | not changed; R-PE-EXPORT.5's notice uses its own counts text, independent of the status a blocked apply shows |
| D8-27 (`:214`) source S0 kept at width 16 | R-S19-S0HEADER-001.1 | open (D-6 A): case R-S19-S0HEADER-001.1/3 `conflict` |
| D8-28 (`:215`) header from the written name | R-S19-S0HEADER-001.2 | open (D-6 A): case R-S19-S0HEADER-001.2/5 `conflict`; the other cases use a written name equal to the typed one |
| D8-29 (`:216`) the source's terminator address | R-S19-EMIT.11 | open (D-6 A): cases /1, /2 `conflict` |
| D8-33 (`:220`) code `CHG-SAVE-UNSUPPORTED` | R-CHG-003.16 | not touched (the refusal still concerns the loaded image's kind) |
| D8-34 (`:221`) the save suffix names only the saved entries | R-CHG-003.23 | not touched; the cases use one inside entry, where both readings agree |
| D8-40 / D10-43 (`:222`, `:259`) Width on an Intel HEX save-back, needs prototype | R-S19-SAVE-REUSE-001.1 | closed by D-3 A once the G2 verdict confirms (G2 shows it) |

## 5. Id check

`R-PE-EXPORT` (`R-PE-EXPORT.1` … `.16`, and `.17`, `.18` reserved for the D-1 B / D-2 B alternatives) is unused: `git grep -n "R-PE-EXPORT"` on `batch-103` (HEAD `08ad2ae`) finds only the steps.log line that opened this stage; `git grep "R-PE-EXPORT" b101-inc9 b101-inc10 b101-inc12 b101-inc12b` finds nothing; no file under `docs/requirements/review/`, `C:\Users\jjgh8\Github\s19w\review\` or any `.dev-flow/` folder of the worktree names it (grep, 2026-11-06). The changed rows keep their canon ids.

## 6. Observations outside the scope (no change here)

- **The canon lacks the Patch Editor's A2L tab.** CTX-PE and R-TUI-063.3 list Inspector, JSON, Checks; the code has a fourth, A2L (batch-102 Inc 5, `screens_directionb.py:4453-4458`), and no `R-B102-PE-*` row is in `REQUIREMENTS.md`. Inc 10's thresholds count four tabs from the code. The fold belongs to whoever owns batch-102's canon fold.
- **The `Save` label.** The operator pressed `Save` (the one filled button, R-TUI-064.5) expecting the image and got the change document — "only the JSON was saved". With the prompt shown after Apply the path to the image is visible; relabelling `Save` touches R-TUI-064.5, the help texts, the user guide and many tests. Backlog candidate, or a question for the G2 page.
- **Two exports of one apply.** `Write file` hides the prompt (R-CHG-003.5); a second export in the other format needs a second Apply, which is harmless (R-CHG-002.1 restores, then re-applies). Kept as is.
- **R-HEX-VERIFY-001.5** (a diagnostic on read-back means `mismatch`) is open as D8-31; the conversion census found no diagnostic in 32 read-backs, so no conversion case depends on it.

## 7. Overlaps (A1 rule 3 style; the orchestrator rules when E2–E4 start)

| Inc 10 touches | Also touched by | How |
|---|---|---|
| `screens_directionb.py` `PatchEditorPanel.compose` (`:4930-5284`), `.on_button_pressed` (`:5900-6058`), `.show_save_prompt` (`:6448-6469`), `SaveBackDecision` (`:4652-4681`), class constants (`:4585-4590`) | **batch-101 Inc 12**: `CheckEditorPanel.compose` (`:7708-7845`), `CheckEditorPanel.on_button_pressed` (`:7912-7959`) (`b101-inc12:…/inc-12/E1-slice.md` §2) | disjoint hunks in one file. Inc 12 merges into `main` before batch-103 (A1 rule 4); a line shift of Inc 10's citations is possible only if Inc 12's removals above `:4930` — none (its hunks are all below `:7700`). **Recommended:** Inc 10's E2 may start now on the base lines; E4 integrates after Inc 12 merges |
| `app.py` apply arm (`:4854-4880`), `on_patch_editor_panel_save_back_decision` (`:4958-5096`) | **batch-101 Inc 12**: removals at `:10753-10763`, `:11190-11192`, `:16738-16886`, docstrings `:16670`, `:16779`; **Inc 9 / 10a / 12b**: hunks at `:3999-4030`, `:4460-4609` (flow lanes) and, for 10a, at `:45`, `:1833-1885`, `:2616` and above `:10000` | disjoint; the hunks above Inc 10's region add +28 lines (Inc 9) or +39 (`b101-inc10`, which carries Inc 9) before `:4734`, so Inc 10's `app.py` lines shift by that much after they merge; the graph cites base lines and E4 re-reads them |
| batch-101 Inc 12's rows | R-DLG.14 (an opener per dialog), R-SHELL-KEYS.3 (a reach per action), R-DLG.2 (Escape) | none under D-1 A (no dialog, no action); under D-1 C the dialog needs its opener (the apply arm), a binding for every key action, and Escape = `Don't save` |
| CTX-SHELL *shown widget* | batch-101 Inc 12 (new term) | cited unchanged; whichever merges first folds it |
| `screens.py` | batch-101 Inc 12 (`ReportViewerScreen`, `VariantHelpScreen`) | not touched by Inc 10 under any option (a D-1 C dialog goes in `screens_directionb.py`) |
| `styles.tcss` | no batch-101 branch (`git diff --stat e07fb00...<branch>` for Inc 9, 10, 12, 12b) | none |
| batch-103 **Inc 1b** | `app.py` only, other regions (`E1-slice.md` of Inc 1b) | none |
| batch-103 **Inc 6, 8, 9** | `screens_directionb.py` (`PatchEditorPanel`: the picker, the pe-mix staging sheet) | Inc 10 merges first (W1); Inc 8's E1 cites R-PE-EXPORT.1 / R-TUI-063.1 as the prompt's place in the pe-mix layout (the prototype keeps the export placement as a separate decision that carries into the winning layout) |

Tests that pin the prompt's home and must move with D-1 (E4, not capped): `tests/test_b97_patch_editor.py:1418-1426` (the prompt and the before/after control homed in `#patch_win_json`), `tests/test_tui_patch_layout.py:190-197` and the 80×24 reachability AT-064c (`:715-730`, "siblings of the JSON window body"), `tests/test_tui_patch_editor_v2.py:302`, `:574`; the frozen id set `tests/b97_fixtures.py:95-120` keeps every shipped id (Inc 10 adds ids, removes none).

## 8. Inputs and platform

Under D-1 A no requirement depends on a new key: the prompt's controls are buttons and a text box the operator reaches by click or Tab, as today's Width / `Write file` / `Don't save`. Under D-1 C (or if the G2 verdict keeps the prototype's `alt+f` / `alt+b` / `alt+w`), each key needs evidence that it reaches the app in Windows Terminal before a row depends on it: alt+letter dialog keys are shipped for Load (`alt+l`) and Save project (`alt+s`, CTX-DIALOG), but `alt+f`, `alt+b`, `alt+w` have not been checked — a pilot on the operator's terminal (G1 exception rules) or the `windows-latest` job.

## Orchestrator rulings (2026-11-06T19:43:15-06:00, Opus 5.5)

D-1 (placement) and D-2 (default format) **→ operator at G2** (page question 7); the E1 recommendation (docked bar A; same format as the loaded file) is on record. D-3 **A** (Width hidden for HEX, its space kept). D-4 **A** (the apply line in the prompt; a warning notice only when nothing was applied; the line's text waits for G2). D-5 **A** (the before/after control moves with the prompt). D-6 **A** (D8-27/28/29 stay open; the unreachable D8-17 branch is left as is — not in scope). D-7 **A** (folder rule unchanged). New row R-PE-EXPORT.3 (stale prompt after a no-op apply) accepted. **E2 waits for the G2 verdict** (the graph depends on D-1); it is written on base lines and integrated at E4 after batch-101 Inc 12 merges. Backlog: the canon has no A2L tab row though the code has four tabs.
