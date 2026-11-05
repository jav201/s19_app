# PLAN — s19_app — batch 2026-11-05-batch-103 (editors + A2L)

- **Status:** E0 draft, awaiting operator approval (gate G1).
- **Branch:** `batch-103` from `main` `9f9f6af`, worktree `C:/Users/jjgh8/Github/s19_app-b103`.
  - The draft's base was `f11b3f4`, the batch-102 merge.
  - `9f9f6af` is that base plus the batch-101 Inc 2 merge.
- **Process:** `dev-flow-v3-beta` (E0–E5 per increment, batch end once).
- **Method versions (checked 2026-11-05; use only these):**
  - dev-flow v3 beta: `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\SKILL.md` and `trace_check.py`, commit `d858a9a` of the skills repo, working tree clean. Not the public `jav201/dev-flow` (rev94) and not the old `skills\dev-flow\` kit.
  - Code-Wire v3.1.0: tag `v3.1.0` = commit `ebc3bb7`, which is also `origin/main`. Local clone `C:\Users\jjgh8\Github\code-wire`. Core only: examples from the requirement, real callers from `tools/codewire_extract.py`, and a test that fails. Lint and recordings are records, not gates.
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
| 1 | 1 | W0 | Clipboard: instant paste, copy from every view | 01 | Read cascade without the Tk worker-thread penalty (C-D1). Tk write removed or moved to the main thread (C-D2). `powershell.exe` called by absolute path. Copy reaches the OS clipboard from the read-only Patch document, the hex view, the A2L summaries and the A2L tag table (new copy action). Copy→paste matrix as ATs. | `os_clipboard_input.py`, `capped_text_area.py`, `app.py`, `screens_directionb.py`; config: `.github/workflows/tui-ci.yml` (Windows job) | ~35 / ~14 | none |
| 2 | 2 (part) | W0 | A2L definition model I: scalar kinds | 05 | Pure model. TAB_VERB/COMPU_VTAB enums, BIT_MASK, ASCII, FORMAT/PHYS_UNIT, EXTENDED_LIMITS. Decode and encode round trip. Synth gains enum and BIT_MASK (D6). | new `a2l_definition.py` | ~50 / ~16 | none (`a2l.py` frozen) |
| 3 | 2 (part) | W0 | A2L definition model II: arrays and axes | 05 | VAL_BLK/MATRIX_DIM, axis conversion, STD/FIX/COM_AXIS with AXIS_PTS. Round trip. Synth gains COM_AXIS (D6). | `a2l_definition.py` | ~45 / ~14 | Inc 2 |
| 4 | new (handoff 2026-11-05) | W0 | Label similarity matcher (pure) | 03 | Tokenise on `_`, camelCase and digit boundaries. Match a substring anywhere, a subsequence, or per-token Damerau-Levenshtein. One deterministic ranking. Tested on case08 names and real A2L name shapes. | new `label_match.py` | ~25 / ~8 | none |
| 5 | 3 | W1 | Every view current after any A2L load | 02 | The viewer's In-memory/Invalid mode is reset or visible after a load. The Check Editor picker refreshes while visible (CE-D1). Replacing the project A2L asks y/n instead of refusing. A busy refusal is visible. | `app.py`, `a2l_parameter_picker.py` | ~30 / ~12 | after batch-101 Inc 4–6 merge (D1) |
| 6 | 4 | W1 | Picker correctness | 04 | Full array length, for Check specs too (PE-D1). Format label (PE-D2). Patch bulk include. | `a2l_parameter_picker.py`, `screens_directionb.py` | ~25 / ~10 | Inc 3, 5 |
| 7 | 5 | W2 | A2L Viewer: list of labels | 03 | av_A filter, av_C paste modal with live found/missing status, and the autocomplete from Inc 4. | `app.py`, `screens.py` (modal), `a2l_parameter_picker.py` (shared list parser) | ~40 / ~16 | G2 verdict; Inc 4, 5 |
| 8 | 6 | W2 | Patch Editor: edit by definition (scalars, enums, bit masks, text) | 05 | pe_B staging sheet: change list, parameter list, horizontal detail. | `screens_directionb.py`, new editor widget module, `change_service.py`, `app.py` | ~50 / ~20 | G2 verdict; Inc 2, 6 |
| 9 | 7 | W2 | Patch Editor: CURVE / MAP / VAL_BLK | 05 | pe_C bench views inside the pe_B sheet. | editor widget module, `screens_directionb.py` | ~45 / ~18 | Inc 3, 8 |

Order: Inc 1, 2 and 4 run in parallel and share no source file. Inc 3 follows Inc 2, which owns the same file. W1 waits for batch-101. W2 waits for G2.

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
| I-1 | OS clipboard read/write and the copy action for non-input views | Inc 1 → Inc 7 (paste modal), Inc 8/9 (editors) |
| I-2 | Definition model: decode / encode / describe one A2L object | Inc 2/3 → Inc 6 (array length), Inc 8/9 |
| I-3 | Matcher: `rank(query, names, limit)` → ordered matches, each with the rule that matched | Inc 4 → Inc 7 |
| I-4 | A2L refresh contract (load generation reaches every A2L view) | Inc 5 → Inc 6, 7 |
| I-5 | Label-list parser (batch-102 bulk parser in `a2l_parameter_picker.py`) | existing → Inc 6 (Patch bulk include), Inc 7 (modal) |

## Parallel safety with batch-101 (checked 2026-11-05)

Batch-101 branches in flight, owned by another session and not touched here:
- `b101-inc3`: `app.py` (−2 lines near :14937 and :15060) and `project_gather_service.py`.
- `b101-inc7`: `app.py` (diff-report hunks near :5727–5814 and :7893–7960), plus `before_after_service.py`, `diff_report_service.py` and `flow_execution_service.py`.
- `b101-inc8`: `crc.py`, `crc_config.py`, `flow_execution_service.py` and `flow_model.py`.

Inc 1 touches `app.py` in other regions: the copy path and the A2L table action. The hunks are disjoint, and the integrator re-checks at merge. Inc 2–4 add new files only.

Overlap with batch-101 that must not be fixed twice:
- PE-D3 (symbol entries refused) is batch-101 Inc 4.
- Batch-101 Inc 5/6 touch the Check/Patch Editor lifecycle; W1 waits for them.

## Test platform (operator rule, 2026-11-05)

- All test runs and probes run on the CachyOS host (`ssh javierg@…`, env `s19ci`). Nothing runs on the main PC.
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
| E4 implementation | DeepSeek v4 Pro via `opencode run`, isolated worktree, launched by the operator from the W0 handoffs |
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
