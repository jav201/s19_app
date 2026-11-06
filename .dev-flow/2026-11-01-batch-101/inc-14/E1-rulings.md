# Inc 14 — E1 rulings: scope, canon changes, decisions

Base `b7b77c4`. Requirements `01-requirements.md`; slice `E1-slice.md`; cases `02-test-cases.md`; graph `codewire/graph-inc14.md`. Every claim below was read in the code at `b7b77c4` (file:line given); no test and no app run (operator rule for this PC). The triage rows used (F-16, F-30, F-37, F-38, F-41) were each re-read in the code and held, with the corrections noted in §1.

## 1. Scope

| Item | Source | In / out | Rows |
|---|---|---|---|
| F-37 A2L "section tree", "`/` jumps to a name", "the same table" | DOSSIER F-37, D7-26; `window_help.py:335-347`; `/` → `#alt_search_input` (`app.py:9353`), an ASCII search of the image (`app.py:20611-20640`) | in | R-WHELP.12, .20 |
| F-37 Workspace "folders.html board", "Change 1" | D7-26; `window_help.py:348-363` | in | R-WHELP.13 |
| F-37 Checks "table", "grouped by reason", `*why*`, "should not be exported" | `window_help.py:145-160`; groups by outcome `checks_view.py:57`; 40-row cap `:53` | in | R-WHELP.12, .14, .23 |
| F-37 CRC Designer "the image's real ranges", "(skip / concat)", "preview-only until an image is loaded", "reload by name", "change 1/2", `ISO-HDC` typo | `window_help.py:162-181`; Ranges field `crc_designer_view.py:374-379`; values `crc_designer_model.py:48-56`; Load path `:427-430` | in | R-WHELP.12, .13, .14, .24 |
| F-30 Reports "Declared regions pre-fills from the loaded A2L" | `window_help.py:192`; seed = manifest only (`app.py:14032-14036`) | in (text; the A2L prefill is not built, PLAN §d) | R-WHELP.19 |
| F-41 Reports "writes the `*.md` + `*.html` pair" | `window_help.py:197-199`; `report_service.py:494`, `:1399-1403` | in (text; the HTML twin is not built, PLAN §d) | R-WHELP.18 |
| F-37 Split / Join "browse", "a project file", settable naming pattern, "configurable pad byte", "today's emitters" | `window_help.py:365-392`; source = `current_file` (`segment_split_view.py:1539-1552`); `_pattern` constant (`:163`, `:1488`); pad toggles 0x00 / 0xFF (`:1998-2000`) | in | R-WHELP.12, .21, .22 |
| Flow Builder: requirement and ruling ids in steps 1, 17, 18, 19 | `window_help.py:227-228`, `:260`, `:263-268`, `:274` | in (found at E1; same file, same defect class as D7-26's "change 1/2") | R-WHELP.13 |
| BL-I8-2, text half: Flow Builder "CRC template — the CRC configuration a CRC block stamps"; step 5 "stamps a CRC from a CRC template" | `../inc-8/E1-rulings.md` §7; `window_help.py:233`, `:246` | in. The field label `CRC template` (UI) stays in BL-I8-2 | R-WHELP.25, .26 |
| F-43 / F-44 help alignment (PLAN §d: "Inc 14 removes any help claim beyond it") | census of all sections for `html`, `verdict`, `template` (B) | in: the only claim beyond the shipped reports is F-41's step; no other line promises HTML or verdicts | R-WHELP.18 |
| F-16 Memory Map key line | DOSSIER F-16; `legend.py:489-491`; `RegionRow.on_key` (`screens_directionb.py:1457-1505`) | in (legend text) | R-TUI-062.10.1 |
| F-16, same sheet: region-row field line `↵ opens hex` | `legend.py:484-486` | in (found at E1: the sheet would contradict itself if only the key line changed) | R-LEGEND-011 |
| F-16, the Memory Map inspector subtitle `↑↓ · ↵ hex` | `screens_directionb.py:2626` | **out**: a screen string, not help text, in a file of the `app.py` chain (Incs 5, 6, 12) → backlog BL-I14-1 with D4-21 | R-TUI-062.10.2 (§2) |
| D4-21: Enter opens hex, arrows select and inspect | S4 R-TUI-062.3, .4, .11 | **out**: behaviour change, not text; not in the plan | — |
| D3-19: the A2L, MAC and Issues legend rows | S3 R-LEGEND-011 | **out** (D-10) | — |
| F-38 README: 10 screens / keys `1`–`0`, footer, missing keys, missing windows | D0-9, D0-10; `README.md:81-125` | in | R-DOC-README.2, .3 |
| D0-11 README: Operations runs all three; `flow.json` | `README.md:186-187`, `:203-207`; `placeholders.py:85`; `flow_persistence_service.py:99`, `:1022-1024` | in | R-DOC-README.4 |
| README stale claims found at E1: `project.toml` (not in the tree; `CLAUDE.md:12`), "Markdown or self-contained HTML" (both are written), "or over every variant … one fused report" (`run_flow_over_variants` has no product caller, grep), `SOURCE` block (the kind is LOAD), "**Save patched**" (the control is Write file) | `README.md` | in | R-DOC-README.4 |
| `SECURITY.md` (P0 ruling, D15-18 thread) | `PLAN.md` orchestrator rulings | in | R-DOC-SECURITY.1, .2 |
| Inc 8 release note (D-3, S-8: a tracked batch-end deliverable) | `../inc-8/release-note-crc.md` | in (D-2: its home) | R-DOC-RELNOTE.1, .2 |
| Inc 7 report title and inputs, escaped Markdown names (F-E3-8), whole hex windows (F6-1); Inc 8 rebind of external copies | `../inc-7/01-requirements.md` US-BAR-1, US-MDESC-1, US-HEXWIN-1; `../inc-8/01-requirements.md` R-FLOW-EXT.9 … .13 | in | R-DOC-RELNOTE.3 … .6 |
| Inc 7 `(screen 7)` → `(key 7)` text | `../inc-7/E1-rulings.md` O-3 | **nothing to change**: no document quotes either text (grep of `README.md`, `docs/`) | — |
| BL-I8-3: ch17.11, ch18.9, ch17:62, DOSSIER :737, :758 | `../inc-8/E1-rulings.md` §7, E3 A-7 | in | R-DOC-GUIDE.1, .2 |
| ch21 (Inc 7 carry: F-42 passages, F-E3-8 escaping consequence) | `../inc-7/E1-rulings.md` line 17, `E3-rulings.md` F-E3-8 | in | R-DOC-GUIDE.1, .2 |
| Guide passages of Inc 14's own findings: ch06.5 (F-16), ch16.1 (F-30), ch16.2 (F-41), ch19.1 (F-37), ch21 intro / 21.5 (F-41); DOSSIER rows F-16, F-30, F-37, F-38, F-41 | `docs/user-guide/` | in | R-DOC-GUIDE.1, .2 |
| Guide passages and DOSSIER rows of the other increments (3, 4, 5, 6, 9, 10, 11, 12, 13) | — | **out**: each increment or the batch-end doc pass (D-8) | — |
| `prototypes/cambios_10_12_2026/help_sections.md` | operator rule | **never edited** (the file is absent from this tree; §3) | — |

## 2. Canon changes, for the requirements session

**New rows (27):** R-WHELP.18, .19, .20, .21, .22, .23, .24, .25, .26 (S7.4); R-DOC-SECURITY.1, .2; R-DOC-RELNOTE.1, .2, .3, .4, .5, .6, and .7 … .14 (E3 round 1, A-14 / S-2 / S-3; each id checked absent from `REQUIREMENTS.md` and every `inc-*/01-requirements.md` on every `b101-*` branch); R-DOC-GUIDE.1, .2 (S0). Each id was checked absent from `REQUIREMENTS.md`, `s19w/review/S*-ears-strict.md` and every `.dev-flow/2026-11-01-batch-101/*` folder at `b7b77c4`. S0 has no section for the security policy, the release notes or the user guide: proposed new subsections S0.4 (security policy), S0.5 (release notes), S0.6 (user guide), with the context terms of `01-requirements.md` §Documents.

**Split (E2, E7):** R-TUI-062.10 ("… in the Memory Map's key line, inspector subtitle and row glyphs …") has three objects in one `shall` (not singular, 29148). It becomes:

| Id | Form | Requirement | Status after Inc 14 |
|---|---|---|---|
| R-TUI-062.10 | — | — Withdrawn: split into .10.1, .10.2, .10.3 | — |
| R-TUI-062.10.1 | U | The system shall name in the Memory Map's key line only keys that the Memory Map handles. | Yes (Inc 14) |
| R-TUI-062.10.2 | U | The system shall name in the Memory Map's inspector subtitle only keys that the Memory Map handles. | No: `↑↓ · ↵ hex` (`screens_directionb.py:2626`); backlog BL-I14-1 with D4-21 |
| R-TUI-062.10.3 | U | The system shall name in the Memory Map's row glyphs only keys that the Memory Map handles. | Yes: the row's `↵` is Enter, which the row handles (inspect) |

**Context changes:**
- S7 CTX-HELP gains two terms: **Markdown mark** and **reference** (wording in `01-requirements.md` §Definitions; D-4, D-7).
- S3 CTX-LEGEND map sheet: the region-row field line becomes `"glyph · start · size · size vs largest · A2L sym · band · ↵ <what Enter does on a region row>"` (today `inspect`), and `Map keys` gains its text `↑↓ move · click / ↵ inspect · double-click open hex · Esc close` (D-6).

**Status changes after Inc 14:** R-WHELP.12, .13, .14 Partly → Yes (except the `changes_file_notation` fence, D-4); R-DOC-README.2, .3, .4 Partly → Yes; R-LEGEND-011 stays Partly (D3-19); R-TUI-062.3, .4, .11 unchanged (No / Partly, D4-21).

**CODE-CHANGES items closed:** D7-26 (all three rows), D0-9, D0-10, D0-11 (the README half; the Operations half of D13-13 stays open), D3-19 for the map-keys line only.

## 3. TC-707 and TC-1802: the help_sections.md guards

**Facts (read at `b7b77c4`):**
- `prototypes/cambios_10_12_2026/help_sections.md` is an untracked draft: the main checkout excludes it (`.git/info/exclude:39`), so it is absent from every clone — this worktree, the LAN host, CI. Three nodes read it and fail with `FileNotFoundError` wherever it is absent: `tests/test_window_usage_help.py::test_tc707_copy_matches_help_sections_md_verbatim`, `::test_tc707_numbering_generated_sequential`, and `tests/test_changes_file_notation_help.py::test_tc1802_nine_md_sections_intact_tenth_section_added`. They are three of Inc 2's five known failures (`../inc-2/01-requirements.md:39`).
- The contract they test (LLR-140.2: the md is the source of the help copy) has no row in the new canon: HLR-140 is absorbed into R-WHELP.1 … .15 (`REQUIREMENTS.md:169`), and no R-WHELP row names the md.
- The four sections still in the md census (`checks`, `a2l`, `workspace`, `split_join_export`) are exactly four of the six F-37 / D7-26 must rewrite. Where the md is present (the operator's checkout), rewriting them turns the census RED; where it is absent, the census is RED already.

**Ruling (proposed; the orchestrator confirms, D-3):** the four sections join the code-authored sections, as batch-97 Inc-3 … Inc-8 did for `patch`, `crc_designer`, `reports`, `flow`, `flow_execution`, `check_editor` and `map` (named supersession). The md-reading arms go; the node names stay (a parallel session keys test-case records on them):

| Node (name unchanged) | Body after Inc 14 | Row |
|---|---|---|
| `test_window_usage_help.py::test_tc707_section_census_nine_sections_min_three_steps` | every section (12): a title, ≥ 3 non-empty steps (base: the 4 md keys only) | R-WHELP.7/1 |
| `::test_tc707_copy_matches_help_sections_md_verbatim` | the six rewritten sections and the six changed Flow Builder steps equal Help copy I14, pinned in the test; no file read | R-WHELP.12/4 |
| `::test_tc707_numbering_generated_sequential` | every section's body is numbered `1.` … `N.` with N = its step count; no file read | R-WHELP.7/1 |
| `::test_tc707_boundary_no_orphan_seats_no_blank_modal` | `_EXPECTED_KEYS` = ∅ and `_CODE_AUTHORED_SHIPPED` gains `checks`, `a2l`, `workspace`; the seat formula is unchanged and still holds | R-WHELP.7/1 (guard) |
| `test_changes_file_notation_help.py::test_tc1802_nine_md_sections_intact_tenth_section_added` | the exact 12-key set of the help sections (all code-authored); no file read | R-WHELP.12/4 (guard) |

**Answer to the brief:** yes — after this increment no test reads `help_sections.md`, and the three known failures turn GREEN by the test changes above, without editing the forbidden file. Without the test changes they cannot turn green: absent the file they fail before any assertion. Consequence for the batch end: Inc 2's known-failure list shrinks from 5 to 2 (`test_at_b78_03_…`, `test_at_056e_…`), and the CI FAILED-set comparison must expect the three to leave it. The node names keep "md" and "nine" in them although they no longer read the md; each docstring says why.

## 4. Decisions for the orchestrator

| Id | Decision | Recommendation and reason |
|---|---|---|
| D-1 | Private reporting path for `SECURITY.md` | GitHub private vulnerability reporting is **disabled** on the repository (`gh api repos/jav201/s19_app/private-vulnerability-reporting` → `{"enabled":false}`, 2026-11-05; the repository is public). **Recommend: the operator enables it** (Settings → Security → Private vulnerability reporting; a repository setting, so it is the operator's action, not an agent's) and `SECURITY.md` points to it. An e-mail address would put personal data in the repository: not recommended. No response-time promise is written unless the operator gives one. Until it is enabled, R-DOC-SECURITY.1/2 stays `failed` |
| D-2 | Home of the 1.0.0 release notes | **Recommend `CHANGELOG.md` at the root**, `## 1.0.0` first: a plain, widely used convention, versioned with the code, and the GitHub release page can quote it. The Inc 8 note asked for "the operator's release page"; this gives that page one source. Alternatives: a README section (the README is also the PyPI long description; release history does not belong there) or `docs/release-notes/` (a new convention) |
| D-3 | TC-707 / TC-1802 re-bodied (§3) | **Recommend accept.** The md contract has no canon row and the file is in no clone; the alternative (leave three nodes RED forever) keeps a known failure that tests nothing |
| D-4 | What counts as a Markdown mark (R-WHELP.14) | **Recommend:** `**`, `__`, `*word*`, `_word_` (the marks D7-26 names); backtick code spans are not marks (8 of 12 sections use them for keys, paths and values, as the key bar does; TC-B99-33 and TC-B97-32 read such lines). The `changes_file_notation` JSON fence stays: no window opens that section (D7-11) and TC-1802 parses the fence; it is reviewed when D7-11 makes the section reachable (backlog BL-I14-2) |
| D-5 | Guide captures that show the old text (ch06-05, ch17-05, ch19-01, ch21-02) | **Recommend:** change the text now, add the note `(capture taken before 1.0.0: <what the capture shows>)` beside each such capture (graph I-5; the `)`-closed form first written here is a records slip, corrected at E5 C-3, SR-1), and re-take them in the batch-end doc pass (needs the app and headless Edge; nothing runs on this PC). A capture that contradicts its text without a note would mislead |
| D-6 | F-16 scope: legend text only | **Recommend** (operator ruling 3): the legend names what the keys do today (Enter inspects). R-TUI-062.3 (Enter opens hex) stays an open requirement (D4-21, backlog); CTX-LEGEND's field line is written as `↵ <what Enter does on a region row>` so the canon does not state "inspect" and R-TUI-062.3 "open hex" at once. When D4-21 lands, the two legend constants change with it |
| D-7 | Requirement and ruling ids in help steps | Treated under R-WHELP.13 with the CTX-HELP term "reference" (no new row); five ids in the Flow Builder steps are removed |
| D-8 | Guide scope | Inc 14 takes BL-I8-3, the ch21 carry of Inc 7 and its own findings' passages and DOSSIER rows. The other increments' guide passages (F-01 … F-51 fixed elsewhere) go to the batch-end doc pass, which applies R-DOC-GUIDE.1/.2 to them |
| D-9 | The README key guard `tests/test_docs_canon.py::test_at285_every_readme_named_key_exists_in_the_seat` | Its `_GLYPH` map has no `=` / `]`, and `_shipped_keys` reads `S19TuiApp.BINDINGS` only, so the README rows `=`, `]` and `Ctrl+P` (bound by Textual's `App`: `App.BINDINGS` holds `ctrl+q`; `App.COMMAND_PALETTE_BINDING` = `ctrl+p`, Textual 8.2.8) would turn it RED. **Recommend:** extend `_GLYPH` with `=` → `equals_sign`, `]` → `right_square_bracket`, and `_shipped_keys` with the inherited `App.BINDINGS` and `App.COMMAND_PALETTE_BINDING`. This makes the guard check more keys, not fewer; it is not a weakening. Node name unchanged. **Amended at E3 [A-5]:** the inherited keys come from `S19TuiApp._merged_bindings` (not `App.BINDINGS`, which misses an override or `inherit_bindings = False`), and `ctrl+p` counts only while `S19TuiApp.ENABLE_COMMAND_PALETTE` is true (Textual binds it only then, `app.py:874-881`); negative control: the flag monkeypatched to `False` → the README `Ctrl+P` row is RED — the drift D-11 predicts |
| D-10 | D3-19 legend rows (A2L red, MAC pale yellow, Issues info) | **Recommend out of Inc 14.** The PLAN scopes Inc 14 to the map-keys line of D3-19; the rows also print in the project report (R-LEGEND-SOURCE-001), so changing them re-pins report goldens (a B3 ripple). Backlog BL-I14-3 |
| D-11 | `Ctrl+P` in the README | CTX-KEYS lists it and the app binds it today; S0 D0-10 says not to list it because S6 D6-13 will remove Textual's palette. D6-13 is not in batch-101, so 1.0.0 ships it. **Recommend: list it** (R-DOC-README.3 and .4 both hold only then); remove the row with D6-13 |

## 5. Backlog rows proposed

- **BL-I14-1** — Memory Map inspector subtitle `↑↓ · ↵ hex` (`screens_directionb.py:2626`): R-TUI-062.10.2. Fix with D4-21 (Enter opens hex) or change the text; a screen string, so with the KF-101-M review.
- **BL-I14-2** — the `changes_file_notation` section's JSON fence shows its Markdown marks as typed if the section is ever shown (R-WHELP.14). Decide with D7-11.
- **BL-I14-3** — D3-19: the A2L, MAC and Issues legend rows describe intentions (R-LEGEND-011); rewrite from CTX-LEGEND with the report goldens re-pinned.
- **BL-I14-4** — README claims not verified in this pass: the test count (`2760 collected tests`, measured 2026-10-11) and "Every one of these has an equivalent in the TUI" (CLI section). Neither names a window, key, command or file (R-DOC-README.4 does not reach them).
- **BL-I14-6** [E3 A-2] — Check Editor home split: **Write .chk.json** writes into the common `.s19tool/workarea/patches/` with or without a project (`app.py:7338`, no `dest_dir`; `tui/changes/io.py:1504`), while the Open checks/ chip opens `<project>/checks/` (`folder_open_service.py:330`) and the Check Editor help says check specs are kept there. A product defect, not Inc 14's to fix (operator ruling 3); an Inc 5 / Inc 6 interface (graph I-9). Inc 14's README says what the code does.
- **BL-I14-5** — re-take the guide captures ch06-05, ch17-05, ch19-01, ch21-02 (D-5), and the other increments' guide passages (D-8): the batch-end doc pass.

## 6. Interfaces with other increments

| Increment | Shared | Interface |
|---|---|---|
| Inc 7, Inc 8 (merged) | their user-visible changes | read only: the release notes and guide text quote their rows' exact texts (R-BEFORE-AFTER-REPORT-001.32, R-CRC-CONFIG-001.16, R-FLOW-CRC.4, read suffix of R-FLOW-EXT.12) |
| Inc 2 (merged) | the known-failure list | the three md nodes leave it (§3) |
| Inc 13 (CRC Designer recompute) | README CRC Designer section | **Corrected at E3 [A-12]:** "after each edit" does not survive Inc 13's own wording ("150 ms after the last keystroke"); the README keeps the base sentence "recomputes on every keystroke" (`crc_designer_view.py:615-625`) and Inc 13 rewrites it when it merges (graph I-14) |
| Inc 9 (F-45) | README Flow Execution section | [A-11] "Each run writes a chain-set report" (not "one"), true at base; Inc 9 updates it (graph I-10) |
| Inc 4, 5, 6, 10, 11, 12; every later merge | help, README, CHANGELOG, DOSSIER text | the full list is the graph's interface table I-8 … I-16 (E3 architect §3) |
| Inc 12 (Reports viewer `esc`, F-51) | Reports help section (this increment's copy) | if Inc 12 makes `esc` close the viewer, it may add a step; it does not own `window_help.py` (PLAN), so it asks the orchestrator |
| Inc 6 (F-06, Patch Editor dropdown) | Patch Editor help `File — picks a change file in patches/` | untouched here; Inc 6 owns the text if its fix changes what the dropdown lists |
| Inc 11 (F-03 Issues filter) | legend Issues rows | untouched here (D-10) |
| D4-21 (backlog) | `legend.MAP_KEYS_LINE`, `legend.MAP_REGION_ROW_FIELD_KEY` | change with D4-21 |
| Batch-end doc pass | user guide | applies R-DOC-GUIDE.1/.2 to the other increments' findings (D-8) |

## Orchestrator rulings (2026-11-05)

- **D-1:** `SECURITY.md` points to GitHub private vulnerability reporting, with no e-mail and no response-time promise. Turning that setting on is the operator's action (repo settings); the orchestrator asks the operator. Until it is on, `SECURITY.md` must not claim it is enabled — its text names the setting as the channel and is checked again at E5 against `gh api` (R-DOC-SECURITY not-testable case).
- **D-2: yes** — root `CHANGELOG.md` holds the 1.0.0 release notes (Inc 8 CRC note; Inc 7/8 changes to written outputs); later increments append to it.
- **D-3: yes** — the four sections still checked against the untracked md become code-authored (as batch-97 did); tc707/tc1802 md-reading parts are re-bodied, same node names, against the exact help copy in 01-requirements.md. Reason: the md is in no clone and LLR-140.2 has no row in the strict canon. The known-failure list is expected to drop by these three nodes; forwarded to the requirements/test-case session.
- **D-4, D-5, D-6, D-7, D-8, D-10, D-11: accepted as recommended** in §4.
- **D-9: yes** — the AT-285 README key guard counts `=`, `]`, `Ctrl+Q`, `Ctrl+P` as bound keys (stricter, not looser).
- Inc 4's stale guide text (ch08 §8.2, ch10 F-01 sentence, ch17 F-01 note, DOSSIER F-01 row and its false "Project Execute scope does resolve them" claim) and S4-8 go to the batch-end doc pass (D-8), since Inc 4 is not merged yet.
- Runs: tests on the LAN Linux host only (operator rule).

## E3 round 1 — rulings folded (`E3-rulings.md`, 2026-11-05)

Architect FAIL (A-1 … A-6 MAJOR, A-7 … A-19 MINOR), security PASS-WITH-NOTES (S-1 MEDIUM, S-2 … S-5 LOW, S-6 … S-8 INFO). Round 2 re-checks A-1 … A-6 and S-1.

| Ruling | Folded into |
|---|---|
| A-1 | R-DOC-RELNOTE.5 statement ("of a name"), threshold and negative control; case R-DOC-RELNOTE.5/1, R-DOC-GUIDE.1/11; graph CHANGELOG (c) and guide /11 |
| A-2 | graph README block (5); R-DOC-README.4 threshold and case /1 (present phrase); backlog BL-I14-6 (§5); graph I-9 |
| A-3 | R-WHELP.7 threshold and negative controls; case R-WHELP.7/1; graph node `test_tc707_numbering_generated_sequential`, `section_body_text` examples, I-15; slice §4 |
| A-4 | Definitions "Key that acts on a window" (K(w)); R-WHELP.12 threshold (a) and negative control; case fixture K(w) and R-WHELP.12/1; graph entity example |
| A-5 | D-9 (amended above); R-DOC-README.3 threshold and negative control; case R-DOC-README.3/2; graph node `test_at285_…`; slice §4 |
| A-6 + S-1 | D-1 (amended at the end of this section); R-DOC-SECURITY.1 threshold; case R-DOC-SECURITY.1/2 (blocking merge precondition); graph `[I/O: SECURITY.md]`; slice §1 |
| A-7, A-8, A-9 | Help copy I14 Reports step 4, Workspace step 5, CRC Designer step 3; R-WHELP.19 statement and threshold; new case R-WHELP.19/3; case R-WHELP.13/2; graph `ReportViewerScreen.compose` |
| A-10, A-18 | graph README blocks (3), (13) |
| A-11, A-12 | graph README blocks (8), (9); graph I-10, I-14; §6 |
| A-13, A-14 + S-2, S-3 | R-DOC-RELNOTE.6; new rows R-DOC-RELNOTE.7 … .14 and cases /1; US-REL-1; graph CHANGELOG; slice §1 |
| A-15 | R-DOC-GUIDE.2 threshold and negative control; case R-DOC-GUIDE.2/2 |
| A-16, A-17 | slice §4; graph test nodes `test_tc707_boundary_…`, `test_tc1802_…` |
| A-19 + S-4, S-5 | graph `[I/O: SECURITY.md]` Scope; graph README block (8) |
| S-6 | R-DOC-SECURITY.2 threshold; graph `[I/O: SECURITY.md]` |

- **D-1 amended [A-6, S-1]:** private vulnerability reporting enabled is a merge precondition for `SECURITY.md`, checked at E5 with the dated `gh api` transcript. If it is still off at merge, `SECURITY.md` is held out of the merge (the rest of Inc 14 merges) and re-checked at the batch end. No public-issue fallback text. Enabling it is the operator's action; the orchestrator has asked.
