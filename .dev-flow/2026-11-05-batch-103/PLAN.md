# PLAN — s19_app — batch 2026-11-05-batch-103 (editors + A2L)

- **Status:** G1 approved 2026-11-05; amended 2026-11-06 (amendment A1 below). E1 running for Inc 1a, 1b, 2 and 4.
- **Branch:** `batch-103`, rebased 2026-11-06 onto `main` `e07fb00` (batch-101 Incs 1–8, 11, 13–16 merged); first opened from `9f9f6af`. Worktree `C:/Users/jjgh8/Github/s19_app-b103`.
  - The draft's base was `f11b3f4`, the batch-102 merge.
  - `9f9f6af` is that base plus the batch-101 Inc 2 merge.
- **Process:** `dev-flow-v3-beta` (E0–E5 per increment, batch end once).
- **Method versions (checked 2026-11-05; use only these):**
  - dev-flow v3 beta: `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\SKILL.md` and `trace_check.py`, commit `d858a9a` of the skills repo, working tree clean. Not the public `jav201/dev-flow` (rev94) and not the old `skills\dev-flow\` kit.
  - Code-Wire v3.1.0: tag `v3.1.0` (annotated, 2026-11-05) = commit `e436a08` = `origin/main` (corrected 2026-11-06: the E0 text said `ebc3bb7`, a commit off that line; `tools/` is identical). Local clone `C:\Users\jjgh8\Github\code-wire`. Core only: examples from the requirement, real callers from `tools/codewire_extract.py`, and a test that fails. Lint and recordings are records, not gates.
- **Inputs:**
  - Operator verdict: `prototypes/b103_ux/veredicto-b103.json`.
  - Evidence: `prototypes/b103_ux/findings/{A,B,C}-*.md`.
  - Draft: `prototypes/b103_ux/PLAN-DRAFT.md`.
- **Scope rule (D2):** batch-103 covers the editors and A2L, PLAN-DRAFT Inc 1–7 plus the label matcher. The flows (PLAN-DRAFT Inc 8–11 and the FB/FX merge) are batch-104.

## Commission — user stories

Every story keeps the operator's window and words as its acceptance anchor. A story is never re-routed to another window without a ruling; batch-102 missed this, with story 3 landing in the Check Editor.

| US | Story | Operator source |
|---|---|---|
| US-103-01 | Copy and paste work in every window. Text copied from any part of the TUI can be pasted into any text field of the TUI and into other Windows programs, and a paste lands at once. | Story 1 (Workspace, A2L, Load under Windows 11/PowerShell). Note of 2026-11-05: "escenarios de copiar texto desde varias partes de la TUI y pegado a las ventanas de texto disponibles en la TUI". |
| US-103-02 | After any A2L load or reload, every view that shows A2L labels shows them, with no manual refresh. | Story 2 |
| US-103-03 | The A2L Viewer takes a list of labels: paste it, see which labels were found or are missing, complete names by similarity, and filter the viewer by the list. | Story 3. av verdict: av_A plus av_C's paste modal plus a similarity autocomplete that matches the start, middle or end of a name and judges word similarity. |
| US-103-04 | The Patch Editor uses the same parameter selector as the Check Editor, and the selector reports each parameter's true size and format. | Story 5 (selector parity). PE-D1: arrays are cut to 1 element. PE-D2: wrong format label. |
| US-103-05 | The Patch Editor edits a parameter by its A2L definition: scalars, enums, bit masks, text, curves, maps and value blocks. | Story 5 (edit by definition). pe verdict: `mix`. |
| US-103-06 | From the Patch Editor alone, the operator applies the document's changes to the loaded image, sees that they were applied, and exports the changed image as S19 (16 or 32 data bytes per line) or Intel HEX. | Operator, 2026-11-06: in a real test session small quick changes forced a trip through the Flow Builder and an older version was used instead. "I saw the Apply button, but I did not see the change applied. When I saved the file with the button, only the JSON was saved." "16 or 32" = data bytes per line. |

Story 4 (Check Editor speed) was fixed in batch-102, and the operator confirmed it. It is out of scope.

## Readings confirmed by the operator (2026-11-05)

- **Patch Editor mix.**
  - Base: pe_B's staging sheet, meaning the simple change list, the parameter list and the detail that expands horizontally.
  - CURVE/MAP/VAL_BLK use pe_C's detailed bench views.
  - The simple, medium and advanced view levels are backlog item 1, the first change after this batch.
- **A2L Viewer.**
  - av_A's list-aware filter, plus av_C's paste modal with live found/missing status, plus the similarity autocomplete.
  - The autocomplete helps build the list, and the list then filters the av_A viewer.
  - No named label sets.
- **Clipboard: the `partial` is resolved, not accepted.**
  - A copy→paste matrix runs every copy source against both field classes and both paste routes, plus every window that has a text field once.
  - Linux runs use a private Xvfb display on the CachyOS host.
  - The Win32/PowerShell layer runs in a new `windows-latest` CI job. The runner is disposable, so its clipboard belongs to no one.
- **Testers:** an independent Sonnet tester, launched by the orchestrator, writes the tests. DeepSeek implements only.
- **D6 synth tool** (`tools/synth/make_release_case.py`): it is test-data tooling and does not count toward the 4-source-file cap. This is an orchestrator ruling; the operator did not object.

## Increments

All estimates are orchestrator guesses made before E1. The caps are about 80 requirements and 40 graph nodes. PLAN-DRAFT Inc 2 is split in two because its estimate (about 95 requirements) exceeded the cap. The split follows the boundary the operator sees, Inc 8 versus Inc 9.

| Inc | Draft | Wave | Title | US | Scope | Source files (≤ 4) | Est. req / nodes | Depends / gate |
|---|---|---|---|---|---|---|---|---|
| 1a | 1 (part) | W0 | Clipboard core: instant paste | 01 | Read cascade without the Tk worker-thread penalty (C-D1). Tk write removed or moved to the main thread (C-D2). `powershell.exe` called by absolute path. Copy→paste matrix rows whose source and target are text fields (both field classes, both paste routes, every window with a text field once). | `os_clipboard_input.py`, `capped_text_area.py`; config: `.github/workflows/tui-ci.yml` (Windows job) | ~22 / ~8 | none |
| 1b | 1 (part) | W0 | Clipboard: copy from every view | 01 | Copy reaches the OS clipboard from the read-only Patch document, the hex view, the A2L summaries and the A2L tag table (new copy action). The remaining copy→paste matrix rows (sources that are not text fields). | `app.py`, `screens_directionb.py` | ~15 / ~8 | E1 now; E2–E4 after batch-101 Inc 10a and Inc 12 merge (A1) |
| 2 | 2 (part) | W0 | A2L definition model I: scalar kinds | 05 | Pure model. TAB_VERB/COMPU_VTAB enums, BIT_MASK, ASCII, FORMAT/PHYS_UNIT, EXTENDED_LIMITS. Decode and encode round trip. Synth gains enum and BIT_MASK (D6). | new `a2l_definition.py` | ~50 / ~16 | none (`a2l.py` frozen) |
| 3 | 2 (part) | W0 | A2L definition model II: arrays and axes | 05 | VAL_BLK/MATRIX_DIM, axis conversion, STD/FIX/COM_AXIS with AXIS_PTS. Round trip. Synth gains COM_AXIS (D6). | `a2l_definition.py` | ~45 / ~14 | Inc 2 |
| 4 | new (handoff 2026-11-05) | W0 | Label similarity matcher (pure) | 03 | Tokenise on `_`, camelCase and digit boundaries. Match a substring anywhere, a subsequence, or per-token Damerau-Levenshtein. One deterministic ranking. Tested on case08 names and real A2L name shapes. | new `label_match.py` | ~25 / ~8 | none |
| 5 | 3 | W1 | Every view current after any A2L load | 02 | The viewer's In-memory/Invalid mode is reset or visible after a load. The Check Editor picker refreshes while visible (CE-D1). Replacing the project A2L asks y/n instead of refusing. A busy refusal is visible. | `app.py`, `a2l_parameter_picker.py` | ~30 / ~12 | after batch-101 Inc 4–6 merge (D1) |
| 6 | 4 | W1 | Picker correctness | 04 | Full array length, for Check specs too (PE-D1). Format label (PE-D2). Patch bulk include. Carries from Inc 2 E3 (E3S-04a, E3A-07/E3S-08, E3S-11): render every I-2 string with markup off and control characters replaced; stage masked edits over an overlay and re-encode later fields of a word; shorten a long `<text>` in messages. | `a2l_parameter_picker.py`, `screens_directionb.py` | ~25 / ~10 | Inc 3, 5 |
| 7 | 5 | W2 | A2L Viewer: list of labels | 03 | av_A filter, av_C paste modal with live found/missing status, and the autocomplete from Inc 4. Carries from Inc 4 E3 (E3S-01): the paste modal splits a pasted list into names and ranks each one; never one query for the whole paste (R-A2L-MATCH.38 returns nothing past 256 characters). | `app.py`, `screens.py` (modal), `a2l_parameter_picker.py` (shared list parser) | ~40 / ~16 | G2 verdict; Inc 4, 5 |
| 8 | 6 | W2 | Patch Editor: edit by definition (scalars, enums, bit masks, text) | 05 | pe_B staging sheet: change list, parameter list, horizontal detail. Carries from Inc 2 E3 (E3S-04a, E3A-07/E3S-08, E3S-11): render every I-2 string with markup off and control characters replaced; stage masked edits over an overlay and re-encode later fields of a word; shorten a long `<text>` in messages. | `screens_directionb.py`, new editor widget module, `change_service.py`, `app.py` | ~50 / ~20 | G2 verdict; Inc 2, 6 |
| 9 | 7 | W2 | Patch Editor: CURVE / MAP / VAL_BLK | 05 | pe_C bench views inside the pe_B sheet. Carries from Inc 2 E3 (E3S-04a, E3A-07/E3S-08, E3S-11): render every I-2 string with markup off and control characters replaced; stage masked edits over an overlay and re-encode later fields of a word; shorten a long `<text>` in messages. | editor widget module, `screens_directionb.py` | ~45 / ~18 | Inc 3, 8 |
| 10 | new (operator, 2026-11-06) | W1 (urgent) | Patch Editor: apply visibly, export the changed image | 06 | Probe `design/pe-apply-probe.md`: the apply works, but the save-back prompt is un-hidden inside the JSON tab while the Inspector tab is shown (a defect against R-CHG-003.1). Scope: the export prompt reachable where the apply happens; an output-format choice S19 (16/32 bytes per line) or Intel HEX, independent of the source; Width only for S19; a visible cue that the apply happened. The prompt layout is shown in prototype round 2. | `screens_directionb.py` (`PatchEditorPanel`), `app.py` (apply / save-back handlers), `apply.py` (save-back emitters) | ~25 / ~10 (guess) | probe; G2 scene; same-file rule of A1 with b101 Inc 12 |
| 11 | new (operator, 2026-11-07, A2) | W0 | A2L reader: comments, quoted strings, one-line IF_DATA, INSTANCE/BLOB | 05 (enabler), 02 | The reader stops opening sections inside comments and strings, closes one-line IF_DATA, reads INSTANCE/BLOB spans; commented-out objects are no longer live tags. Defects BL-I2-12, BL-I3-11, Inc 2 E3S-30/35-P2/36/37/38. | `a2l.py` (+ its tag table) | ~30 / ~12 (guess) | none; precedes Inc 2b, 3b, 6, 8 |

Order: Inc 1a, 2 and 4 run in parallel and share no source file; Inc 1b's E1 runs with them (records only), its E2 waits (A1). Inc 3 follows Inc 2, which owns the same file. W1 waits for batch-101. W2 waits for G2.

Differences from PLAN-DRAFT, with their reasons:
- **File lists.** PLAN-DRAFT named an "A2L view module" for its Inc 1, 3 and 5, and `workspace.py` for its Inc 1. Both were wrong.
  - The A2L Explorer is composed in `app.py` (from about :7960).
  - The Workspace views `#hex_view`, `#ws_stats` and `#a2l_view` are composed in `app.py` too (:3497–3508).
  - `workspace.py` has no clipboard code. `app.py` replaces both entries.
- **Dependencies after the split.**
  - Inc 6 needs the array dimensions from Inc 3, to fix PE-D1.
  - Inc 9 needs the array and axis model from Inc 3.
  - Both are already met by schedule, because W0 runs before W1 and W2.

## Shared interfaces (pinned before the E2 of the consumer)

| Id | Interface | Producer → consumers |
|---|---|---|
| I-1 | OS clipboard read/write (Inc 1a) and the copy action for non-input views (Inc 1b) | Inc 1a → Inc 1b, Inc 7 (paste modal), Inc 8/9 (editors) |
| I-2 | Definition model: decode / encode / describe one A2L object | Inc 2/3 → Inc 6 (array length), Inc 8/9 |
| I-3 | Matcher: `build_label_index(names)` once per name list, then `rank(query, index, limit)` → ordered matches, each with the rule that matched and its spans (Inc 4 D-1 B, pinned in `inc-4/codewire/graph-inc4.md`) | Inc 4 → Inc 7 |
| I-4 | A2L refresh contract (load generation reaches every A2L view) | Inc 5 → Inc 6, 7 |
| I-5 | Label-list parser (batch-102 bulk parser in `a2l_parameter_picker.py`) | existing → Inc 6 (Patch bulk include), Inc 7 (modal) |

## Amendment A2 (operator, 2026-11-07, `design/A2-inc2-split.json`)

Inc 2's E3 ran five security rounds without closing: every guard on the write path rested on the frozen reader (`a2l.py`), which mis-reads comments, quoted strings, one-line IF_DATA and INSTANCE/BLOB. The operator chose to split and fix the reader:
- **Inc 2a** — describe, decode and display (the read side of I-2). Goes to E4 now. It inherits today's reader limits, which the A2L views already show; no new write path.
- **Inc 2b** — encode and the merge into the image (the write side of I-2, R-A2L-DEF.138/.139 and the mask guards). Waits for Inc 11; its guards are re-checked against the fixed reader.
- **Inc 11 (new)** — A2L reader: comments, quoted strings, one-line IF_DATA, INSTANCE/BLOB (`a2l.py` unfrozen for this). It also stops commented-out objects from showing as live tags in the A2L views today. Precedes Inc 2b, 3b, 6 and 8.
- Inc 3 splits the same way (3a read side, 3b write side) at its rebase.

## Amendment A1 (operator, 2026-11-06)

Batch-101 runs until 2026-11-07. The operator approved working in parallel under four rules:
1. `batch-103` is rebased onto the current `main` (`e07fb00`). Done 2026-11-06.
2. Inc 2, 3 and 4 run the whole cycle now (new modules only). The D6 synth extension is additive: a new case or an opt-in option, and a test pins case 08's output hash so batch-101's fixtures do not move.
3. Inc 1 is split. Inc 1a (clipboard core, no `app.py`) runs now. Inc 1b (copy from non-input views, `app.py` hex/A2L views and `screens_directionb.py`) writes its E1 now; its E2–E4 wait for batch-101 Inc 10a (hex view in `app.py`) and Inc 12 (`screens_directionb.py`) to merge, so the graph cites lines that no longer move.
4. Nothing from batch-103 merges to `main` before the batch-101 v1.0.0 tag.

Batch-101 work still open on 2026-11-06 (other session; branches not touched here):

| b101 | Source files |
|---|---|
| Inc 9 (E5) | `app.py`, `flow_screens.py`, `flow_execution_service.py`, `flow_persistence_service.py` |
| Inc 10a / 10b | `app.py` (hex view), `segment_split_view.py`, `hexview.py` |
| Inc 12 / 12b | `screens.py`, `app.py`, `screens_directionb.py` (`CheckEditorPanel`), `flow_screens.py` |

None changes `os_clipboard_input.py`, `capped_text_area.py`, `tui-ci.yml` or `tools/synth/make_release_case.py` (Inc 10 and 12 read case 08 as a fixture).

## Parallel safety with batch-101 (checked 2026-11-05; superseded by A1)

Batch-101 branches in flight, owned by another session and not touched here:
- `b101-inc3`: `app.py` (−2 lines near :14937 and :15060) and `project_gather_service.py`.
- `b101-inc7`: `app.py` (diff-report hunks near :5727–5814 and :7893–7960), plus `before_after_service.py`, `diff_report_service.py` and `flow_execution_service.py`.
- `b101-inc8`: `crc.py`, `crc_config.py`, `flow_execution_service.py` and `flow_model.py`.

Inc 1 touches `app.py` in other regions: the copy path and the A2L table action. The hunks are disjoint, and the integrator re-checks at merge. Inc 2–4 add new files only.

Overlap with batch-101 that must not be fixed twice:
- PE-D3 (symbol entries refused) is batch-101 Inc 4.
- Batch-101 Inc 5/6 touch the Check/Patch Editor lifecycle; W1 waits for them.

## Test platform (operator rule, 2026-11-05)

- All test runs and probes run on the CachyOS host `cachyos-rtx` (`ssh javiergr@192.168.1.67`, env `s19ci` at `~/miniconda3/envs/s19ci`, clone `~/work/s19_app`; login shell fish, wrap in `bash -lc`). Nothing runs on the main PC except the G1 exception (real Windows Terminal captures, isolated `LOCALAPPDATA`, no clipboard, every window closed).
- **Test scope (operator, 2026-11-06):** between increments, run only the tests of what the increment modified or added (new and changed requirements, tests the increment changed, the law guards). The full suite runs once, at the batch end, after every increment is implemented.
- Clipboard tests run under a private Xvfb display: real X clipboard, isolated by construction.
- The Win32/PowerShell clipboard layer runs only in the new `windows-latest` CI job.
  - **Open risk:** whether the hosted runner exposes a usable clipboard. Its first run checks this.
  - If it does not, the operator rules on the fallback.
- Every clipboard test asserts it is isolated before it writes:
  - on X: a private `DISPLAY`;
  - on the CI runner: the `CI` environment.
- Latency oracles run the real read path with a fixed payload. No fakes on the measured path.
- Results count only for the commit and platform they ran on.

## Models

| Stage | Model |
|---|---|
| E0–E3, integration, E5 reviews and rulings | Opus (orchestrator, main session) |
| E4 implementation, record-correction passes | DeepSeek v4 Pro, isolated worktree, launched by the orchestrator from the per-increment handoff files (operator, 2026-11-06: no DeepSeek limit). The handoff files stay self-contained so the operator can re-run one. |
| E4 tests | Sonnet tester(s), launched by the orchestrator, one per file group plus one for cross-group ATs |
| Mechanical (mutant runs, captures, records) | Sonnet |

## Gates

- **G1:** E0 approval of this plan. It gates the E1 of every increment in the batch.
- **G2:** prototype round 2, before W2 only.
  - Combined screens: the pe mix, and the av mix with the autocomplete dropdown.
  - Real Windows Terminal captures at 118x54 and 220x60.
  - A verdict page with a general-notes field.
- **G3:** batch end. Full suite, canon fold-in, review page and operator decision.

## Backlog (ordered)

1. Patch Editor view levels (simple, medium, advanced). This is the first change after batch-103, so the feature is not left incomplete (operator, 2026-11-05).
2. Batch-104, flows:
   - PLAN-DRAFT Inc 8–11 with D4/D5.
   - The FB/FX merge prototype round: fb_B plus lanes, with import details boxed in columns.
   - FB-21: `dict_to_flow` overwrites `Flow.name` with the last variable name.
3. Batch-101 Inc 3–15 (another session), then the v1.0.0 tag. Inc 2 is already merged at `9f9f6af`.
4. Batch-102 handoff items:
   - environment snapshots and colour baselines (23 + ~25);
   - LLR-173.6l wording;
   - perf bounds `tc_b100_20/61`;
   - palette freeze AT-B78-03;
   - the 64 KiB bulk notice;
   - the TOCTOU note.
5. A2L Explorer at 118 columns: hex rows wrap and the Length column is empty. This goes into Inc 7 if the chosen layout touches it.
6. CachyOS: remove the s19_app pip install from conda `base` (needs the operator's OK).
7. A probe damaged the operator's recent-files store on 2026-11-05.
   - The incident was disclosed and cleaned.
   - Backup: `%LOCALAPPDATA%\s19_app\recent_sources.json.pre-b103c-cleanup.bak`.
   - No repo action is needed.
