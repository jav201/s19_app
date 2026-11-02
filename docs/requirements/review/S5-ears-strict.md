# S5 — Workspace & file I/O: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S5 (lines 2186–2479): R-TUI-029, 001, 002, 005, 006, 008, 011, 015, 066, and three "information contract" blocks (R-TUI-113, 114, 115).
Code: `s19_app/tui/workspace.py` (work-area part), `services/load_service.py`, `services/folder_open_service.py`, `open_folder_chip.py`, `screens_directionb.py::LoadedArtifactsPanel` / `EmptyStatePanel`, the S5 functions of `app.py`, the `#ws_*`, `#sections_*`, `#files_*`, `#loaded_*` rules of `styles.tcss`. Two read-only code readings, every fact with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows and cites in S5.2, S5.3, S5.4, S5.5, S5.6, S5.7, S5.9 and S5.10 verified at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-WORKAREA, CTX-FILES, CTX-WORKSPACE; CTX-RECENT and CTX-LOADQ sit with their sections (S5.9, S5.10).
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first** (TUI rule).
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `review/CODE-CHANGES.md`. Nothing is changed in the code yet.
- **Batch-100** (2026-11-01): HLR-163, HLR-172, HLR-172b and HLR-174 … HLR-174d are written as rows (sub-headings "from batch-100 HLR-<n>"); the record of every change is the block before section 6. No test was run; test names were read in `tests/test_b100_*.py`.

---

## 1. How S5 was written before

- Seven one-line rows from the first batches (R-TUI-001 … 015): short, mostly true, missing the rules that make them testable (where the work area is, what a name collision gives, what happens when a copy is refused).
- R-TUI-066: one paragraph that mixes screen content with data-class field order and merge-site instructions.
- R-TUI-113, 114, 115: ~165 lines that record the dev-flow "information contract" method (validator rules V10–V19, coherence obligations, retrofit cost). They describe the process, not the product.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-113 / 114 / 115 | Process records (IFC method, validator rules, batch decisions) inside the product requirements. No operator behaviour. | Out of the chapter; they stay in their batch records (D5-1). |
| R-TUI-001 | "a work area … at startup": not where. It is `.s19tool/workarea/` under the folder the app starts in; launching from another folder creates another work area. If a folder cannot be created the app stops with a traceback. | Location in CTX-WORKAREA; a clear error (R-TUI-001.5, D5-12). |
| R-TUI-002 / 011 | "Loading must copy into the work area before parsing." Project loads and work-area file picks read files that are already in the work area, in place. | "A file from outside the work area" (R-TUI-002.1, .2). |
| R-TUI-006 | "unique filenames when needed": the rule is not stated, and byte-identical files are reused, not renamed. | Both rules with the exact name pattern (R-TUI-006.1, .2). |
| R-TUI-005 | "against the app working directory and the repo root". The repo-root fallback walks up to 6 parent folders looking for `pyproject.toml`; for an operator it can open a file from an unrelated folder. | Typed path, then the start folder; repo-root fallback removed (D5-8). |
| R-TUI-008 | "open the workarea": no key, no folder named, no failure text; the key has no guard although the folder chips do. | Rows with key, folder, texts; same guard as the chips (D5-13). |
| R-TUI-015 | "maximum size of 5 MB": per file, and one backup is kept, so the log takes up to 10 MiB. | Both values (R-TUI-015.2, .3). |
| R-TUI-066 | Requires dataclass field order and "both merge sites shall carry the two fields forward" — design. The loader-facts line's `N err` counts integrity notices as well as rejected lines. | Observable rows; N defined (CTX-WORKSPACE). |
| R-TUI-029 | "supersedes R-TUI-003 (the pre-batch five-tile Main view)": history. | Layout rows only. |

---

## 3. Context notes (informative)

### CTX-WORKAREA · Folders and copies (S5.1 … S5.3)

```text
start folder     The folder the app is started in.
.s19tool/        <start folder>/.s19tool: the app's own folder.
work area        .s19tool/workarea/. It holds:
  temp/          copies of the files the operator loads
  patches/       change documents and check files when no project is open (S8, S9)
  <project>/     one folder per project (S11)
log folder       .s19tool/logs/ (beside the work area, not in it).
copy             A file the system writes into temp/ from a file outside the work area.
placement        A file the system writes into a folder of the work area: a copy into
                 temp/, a file saved into a project (S11), a save-back (S8), an
                 export (S17).
destination      The folder a placement writes into.
same content     Two files with the same size and the same SHA-256.
numbered name    <stem>_<N><suffix>, N one or more digits (for fw.s19: fw_1.s19,
                 fw_2.s19 …).
name match       Two names are equal; on Windows, equal ignoring case.
reuse candidate  A file of the destination whose name matches the file's name or one
                 of its numbered names, and that is a regular file.
copy limit       256 MiB (268,435,456 bytes).
link             A symbolic link, a junction or another reparse point.
```

### CTX-FILES · File kinds and loading (S5.3, S5.4)

```text
file kind        By extension, ignoring case:
  S19            .s19 .srec
  Intel HEX      .hex .ihex
  MAC            .mac
  A2L            .a2l
data file        An S19, Intel HEX or MAC file.
primary          The S19 or Intel HEX file of the session (one at a time).
companion        The A2L file and the MAC file of the session (one of each at a time).
path input       What the operator types in the load box. Whitespace around it and
                 double quotes are removed; a leading ~ is the home folder.
work-area pick   A pick of a Workarea Files row, or of a work-area row in the Load
                 dialog (S7 R-LOADDLG.27, .61).
painted name     A file name as shown: every character of Unicode category Cc, Cf,
                 Zl or Zp removed, an unpaired surrogate shown as U+FFFD; a result
                 over 120 characters becomes its first 119 characters and "…".
                 In a status text below, <name> is the painted name.
load status      The status line after a load:
  Loaded <name> with integrity notices: <codes>      (any integrity notice, S1)
  Loaded <name> (<S19|HEX>+MAC: <MAC file name>)     (primary + MAC)
  Loaded <name> (<S19|HEX> only)                     (primary, no MAC)
  Loaded <name> (MAC only)                           (MAC, no primary)
load outcome     Loaded <name>
file-load steps  The long action of a file load (S6 CTX-BUSY): label "Loading <name>";
                 steps "Copy into the work area", "Parse", "Install".
session action   As S6 CTX-BUSY.
```

### CTX-WORKSPACE · The Workspace screen (S5.6 … S5.8)

```text
Workspace        Header ("Workspace" and a ? chip), the memory strip (S4), the loaded
                 panel, and three panes:
  left           "Workspace" — Load project (p) button, Workarea Files list,
                 Data Sections list
  middle         "Hex View" — search and go-to boxes, the main hex view (S4)
  right          "Context" — Coverage Stats, then the A2L summary (S2)
section row      Three lines:
                 <validity glyph> 0x<start>
                 – 0x<last>  <size, human-readable, 9 wide> <band glyph>
                 <8-cell micro-bar: size / largest range>
MAC row          MAC out-of-range
                 @ 0x<address>
stats pane       Coverage: <coverage, 2 decimals>%   (— when there is no range)
                 Ranges: <ranges>
                 Errors: <ERROR issues>
                 Warnings: <WARNING issues>
                 Loader <N> err · ⚠<K> OOO · Entry <address or —>
                   N: line diagnostics + integrity notices of the primary (S1)
                   K: out-of-order records (S19; 0 for Intel HEX)
                   Entry: address of the first S7/S8/S9 record; — for Intel HEX or
                          when there is none
loaded panel     Title "Loaded"; rows PROJ, <S19|HEX>, MAC, A2L, then "unload all [U]".
  PROJ           (none) · <project> · <project>:<variant> (<i>/<N>)
  primary slot   <file name>  <mapped bytes, human-readable> · <ranges> rng
  MAC slot       <file name>  <n> record(s)
  A2L slot       <file name>  <n> tag(s)
  empty slot     (none), dim, no button
empty state      No file loaded - press Ctrl+L (or 'l') to load a file, or 'p' to load a
                 saved project.
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested**, **Partly** / **No** with the decision.

### S5.1 · The work area (CTX-WORKAREA)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-001.1 | When | When the system starts, the system shall create the work area under the start folder if it does not exist. | Yes; tested. |
| R-TUI-001.2 | When | When the system starts, the system shall create `workarea/temp/` if it does not exist. | Yes; tested. |
| R-TUI-001.3 | When | When the system starts, the system shall create `workarea/patches/` if it does not exist. | Yes; untested. |
| R-TUI-001.4 | When | When the system starts, the system shall create the log folder if it does not exist. | Yes; tested. |
| R-TUI-001.5 | If | If the system cannot create one of these folders, then the system shall print an error that names the folder and stop with a non-zero exit status. | Partly: stops with a Python traceback (D5-12). |

### S5.2 · Copies

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-002.1 | When | When the operator loads a file from outside the work area, the system shall copy it into `temp/` before reading it. | Yes; tested. |
| R-TUI-002.2 | When | When the operator loads a file that is already in the work area, the system shall read it where it is. | Partly: a project load and a work-area pick read in place (tested, `test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy`); a variant switch and a typed path inside the work area go through the general load, which copies into `temp/` (`app.py:8801`, `app.py:15124`; S11 D11-28). |
| R-TUI-006.1 | If | If the destination holds a reuse candidate with the same content, then the system shall use that file and write nothing. | Yes; tested (`test_tc_b100_01_s7_sequence_reuses_identical_files`, `test_tc_b100_01_deleted_lower_suffix_reuses_existing_suffix`, `test_tc_b100_01_upper_case_suffix_name_is_reused_on_windows`, `test_at_b100_01_repeated_loads_reuse_and_name_existing_variant`). |
| R-TUI-006.2 | If | If the file's name is taken in the destination by a different content, then the system shall name the new file with the lowest free numbered name. | Yes; tested (`test_tc_b100_01_s7_sequence_reuses_identical_files`). |
| R-TUI-011 | U | The system shall keep every copy in `temp/` until the operator deletes it. | Yes. |
| R-TUI-002.3 | If | If the file to copy is a link, then the system shall refuse it with the reason `Refusing to copy: source is a symbolic link or reparse point: <path>`. | Yes; tested. |
| R-TUI-002.4 | If | If the file to copy is larger than the copy limit, then the system shall refuse it with the reason `Refusing to copy: source size <n> bytes exceeds cap <limit> bytes: <path>`. | Yes; tested (also `test_tc_b100_01_direct_calls_refuse_and_write_nothing`). |
| R-TUI-002.5 | If | If a copy would be written outside the work area, then the system shall refuse it with the reason `Refusing to place: destination is not contained inside <work area>: <path>`, where `<work area>` is the work-area folder's path. | Partly: the reason prints the literal text `<base>/.s19tool/workarea/` in place of the path (`workspace.py:747-748`, `:778-779` at e279c8b); no test asserts the reason text (D5-54). |
| R-TUI-002.6 | If | If the target file stays locked after 5 attempts within 1 second, then the system shall refuse the copy with the reason `Not saved: <name> in <folder> is still locked after 5 retries, another program may hold it — close it and retry. Nothing written.` | Yes. |
| R-TUI-002.7 | If | If the system refuses to copy an S19, Intel HEX or MAC file, then the system shall show the status `Cannot load file: <reason>`. | Yes. |
| R-TUI-002.8 | If | If the system refuses to copy an A2L file, then the system shall show the status `Cannot load A2L: <reason>`. | Yes; tested (`test_tc_b100_54_a2l_worker_failure_keeps_the_session`, containment arm). |

#### (from batch-100 HLR-163) Reuse rules and the destination guard

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-006.3 | If | If a file of the destination with the same content is empty, then the system shall not reuse it. | Yes; tested (`test_tc_b100_01_zero_byte_candidate_is_never_reused`). |
| R-TUI-006.4 | If | If a file of the destination with the same content is a link, then the system shall not reuse it. | Yes; tested (`test_tc_b100_01_link_candidate_is_never_reused`). |
| R-TUI-006.5 | If | If more than one reuse candidate has the same content, then the system shall reuse the one under the file's own name, else the one with the lowest number. | Yes; untested (`workspace.py:822-886`). |
| R-TUI-002.9 | If | If the destination, or a folder on its path inside the work area, is a link, then the system shall refuse the placement with the reason `Refusing to place: destination traverses a symbolic link or reparse point: <path>`. | Yes; tested (`test_tc_b100_62_junction_destination_is_refused_nothing_written`; the refusal, not its text). |

### S5.3 · Path input and file kinds (CTX-FILES)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-005.1 | U | The system shall take a file's kind from its extension, ignoring case. | Yes. |
| R-TUI-005.2 | When | When the operator submits a path input, the system shall remove the whitespace around it. | Yes. |
| R-TUI-005.9 | When | When the operator submits a path input, the system shall remove its double quotes. | Yes; untested. |
| R-TUI-005.3 | When | When a path input starts with `~`, the system shall read `~` as the operator's home folder. | Yes; untested. |
| R-TUI-005.4 | If | If a relative path input does not name an existing file from the current folder, then the system shall look for it under the start folder. | Yes; tested. |
| R-TUI-005.5 | U | The system shall not look for a path input in any parent folder of the start folder. | No: up to 6 parent folders are searched for a repository root (D5-8). |
| R-TUI-005.6 | If | If the file of a load can no longer be found when the load starts, then the system shall show the status `File not found: <path>`. | Yes; tested (`test_tc_b100_53_path_gone_under_the_load_question_keeps_the_app`, `test_tc_b100_53_use_time_resolve_error_refuses_and_keeps_the_app`, `test_tc_b100_53_path_refused_between_the_two_looks_keeps_the_app`); `app.py:15109`. A late check: the typed path was classed first (D5-42). The A2L case is S2 R-A2L-004.3. |

R-TUI-005.7 and .8 (status for a typed folder or an unsupported typed path) are retired here: since batch-100 every typed path gets a class in the Load dialog before any load (S7 R-TUI-043.14 … .24, R-LOADDLG.71 … .77; D5-42).

### S5.4 · Loading

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-012L.1 | When | When the operator loads a primary, the system shall replace the session's primary with it. | Yes; tested. |
| R-TUI-012L.2 | When | When the operator loads a primary, the system shall keep the session's A2L and MAC. | Yes; tested. |
| R-TUI-012L.3 | When | When the operator loads a MAC file, the system shall replace the session's MAC with it. | Yes; tested. |
| R-TUI-012L.4 | When | When the operator loads a MAC file, the system shall keep the session's primary and A2L. | Yes; tested. |
| R-TUI-012L.5 | U | The system shall keep the screen responsive while it parses an S19, Intel HEX or MAC file. | Yes; tested (`test_tc_b100_53_workarea_data_pick_parses_on_the_file_load_worker`, `test_tc_b100_53_project_load_reads_every_file_on_a_worker`). The copy into `temp/` is a held step (`app.py:15124`; S6 D6-35, D5-50). |
| R-TUI-012L.6 | When | When the system copies and parses an S19, Intel HEX or MAC file, the system shall show the progress (S6 CTX-BUSY, R-PROGRESS-LINE.1 … .11) with the file-load steps of CTX-FILES. | Yes; tested (`test_tc_b100_50_each_worker_action_begins_with_a_progress_line`). Step 1 cannot show before the copy (S6 D6-46). |
| R-TUI-012L.8 | When | When a load ends, the system shall show the load status of CTX-FILES for the file just loaded. | Partly: a MAC loaded onto a primary with notices is shown with the primary's notice codes (`app.py:17676`, D5-21). |
| R-TUI-012L.12 | When | When a file load ends, the system shall show the status `Loaded <name>` after the load status. | Yes; tested (`test_tc_b100_53_workarea_pick_begins_a_file_load_and_never_syncs_the_project`, `test_tc_b100_51_file_load_ends_once_on_success`) (D5-47). |
| R-TUI-012L.9 | If | If parsing a file fails, then the system shall show the status `Load failed: <reason>`. | Yes (`app.py:18051`). |
| R-TUI-012L.10 | If | If copying or parsing an A2L file fails for a reason other than a refused copy, then the system shall show the status `File NOT loaded: '<name>' could not be read — check that the file can be opened, then load again.` | Yes; tested (`test_tc_b100_54_a2l_worker_failure_keeps_the_session`) (D5-41). |
| R-TUI-012L.11 | If | If copying or parsing an A2L file fails, then the system shall keep the A2L that was loaded before. | Yes; tested (`test_tc_b100_54_a2l_worker_failure_keeps_the_session`, `test_tc_b100_53_every_a2l_attach_route_parses_on_a_worker`). |

R-TUI-012L.7 (a load requested while another runs) is retired here: S6 R-BUSY-REFUSE.1 and .6 state the refusal and that no load question opens (D5-40).

### S5.5 · Files list, open folder, log

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-WS-FILES.1 | When | When the system shows the Workarea Files list, the system shall list the regular files directly in `temp/` whose kind is in CTX-FILES, ordered by name ignoring case. | Yes; tested (`test_tc_b100_37_lister_returns_the_regular_files_sorted`, `test_tc_b100_37_lister_sorts_whatever_order_the_folder_yields`, `test_tc_b100_37_files_list_shows_loadable_suffixes_only`, `test_tc_b100_37_rows_equal_the_lister`). |
| R-WS-FILES.2 | When | When the system starts, ends a load or the operator presses `r`, the system shall refresh the Workarea Files list. | Yes; tested. |
| R-WS-FILES.3 | When | When the operator selects a row in the Workarea Files list, the system shall load the file whose on-disk name the row holds. | Yes; tested (`test_tc_b100_39_picked_row_loads_the_file_as_named`). |
| R-WS-FILES.4 | If | If the selected file no longer exists, then the system shall show the status `File NOT loaded: '<name>' not found — pick another file.` | No: nothing is shown (`app.py:15570`); batch-100 pins the silence (D5-51). |
| R-WS-FILES.5 | U | The system shall show file names in the Workarea Files list as plain text, never as markup. | Yes; tested (`test_tc_b100_39_rows_paint_names_literally`, `test_at_b100_13_workarea_files_show_names_as_named`). |
| R-TUI-008.1 | When | When the operator presses `o`, the system shall open the work area in the system's file manager. | Yes; tested. |
| R-TUI-008.2 | When | When the system has opened the work area, the system shall show the status `Opened workarea: <path>`. | Yes; tested. |
| R-TUI-008.3 | If | If the file manager cannot be started, then the system shall show the status `Failed to open workarea: <reason>`. | Yes; tested. |
| R-TUI-008.4 | If | If the work area is not a real folder inside `.s19tool/`, then the system shall refuse to open it with the status `Refused to open workarea: not a real folder inside <root>/`. | No: only the folder chips check it (D5-13). |
| R-TUI-015.1 | U | The system shall write its log to `.s19tool/logs/s19tui.log`. | Yes; tested. |
| R-TUI-015.2 | If | If the log file reaches 5 MiB, then the system shall start a new log file. | Yes; tested. |
| R-TUI-015.3 | U | The system shall keep one previous log file. | Yes; tested (≥ 1 only). |
| R-TUI-015.4 | When | When a load ends, the system shall write the log line `Load summary: file_type=<kind> path=<path> addresses=<n> range_count=<n> range_bytes=<n> errors=<n>`. | Yes. |

R-WS-FILES.6 (list the loadable files written at the work-area root, `splits/`, `crc/`) is retired: batch-100 keeps the list to `temp/` (D5-43).

#### (from batch-100 HLR-172b) Workarea Files names and picks

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-WS-FILES.7 | If | If an entry of `temp/` is a link, then the system shall leave it out of the Workarea Files list. | Yes; tested (`test_tc_b100_37_file_link_in_temp_is_not_listed`). |
| R-WS-FILES.8 | If | If the name of a file in `temp/` ends in a dot or a space, then the system shall leave the file out of the Workarea Files list. | Yes; tested (`test_tc_b100_37_lister_skips_a_name_ending_in_a_dot_or_space`; Windows only). |
| R-WS-FILES.9 | If | If `temp/` is missing, is a link or cannot be listed, then the system shall show an empty Workarea Files list. | Yes; tested (`test_tc_b100_37_unlistable_temp_gives_an_empty_list`, `test_tc_b100_37_unlistable_temp_shows_no_rows`). |
| R-WS-FILES.10 | U | The system shall show each file name of the Workarea Files list as its painted name. | Yes; tested (`test_tc_b100_39_rows_paint_names_literally`). |
| R-WS-FILES.11 | If | If the picked file no longer exists, then the system shall not ask the load question. | Yes; tested (`test_tc_b100_39_pick_of_a_vanished_entry_asks_nothing`). |
| R-WS-FILES.12 | If | If a work-area pick is not a regular file when the load runs, then the system shall refuse the load with the status `File NOT loaded: '<name>' is not a regular file — pick another file.` | Yes; tested (`test_tc_b100_39_pick_rechecks_the_entry`, `test_tc_b100_39_pick_rechecks_the_entry_after_the_question`, `test_tc_b100_39_pick_rechecks_the_entry_and_fails_closed`, `test_tc_b100_39_pick_of_a_reparse_point_file_is_refused`, `test_tc_b100_39_pick_survives_an_error_at_the_first_look`, `test_tc_b100_66_pick_refusal_tokens_carry_no_decision_id`). |
| R-WS-FILES.13 | If | If a work-area pick is larger than the copy limit when the load runs, then the system shall refuse the load with the status `File NOT loaded: '<name>' is too large to open — load a smaller file.` | Yes; tested (`test_tc_b100_39_pick_over_cap_is_refused`). |
| R-WS-FILES.14 | When | When the operator makes a work-area pick while a project is open, the system shall leave the project unchanged. | Yes; tested (`test_tc_b100_53_workarea_pick_begins_a_file_load_and_never_syncs_the_project`). |
| R-WS-FILES.15 | If | If a work-area pick of an A2L file fails, then the system shall keep the rows and the cursor of the Workarea Files list. | Yes; tested (`test_tc_b100_54_failed_in_place_a2l_pick_keeps_the_files_list_cursor`); `app.py:15371`. |

The busy refusal of a work-area pick, `U` and the Loaded panel's unload is S6's (R-BUSY-REFUSE.1, .6; CTX-BUSY refused list).

### S5.6 · The Workspace screen (CTX-WORKSPACE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-029.1 | While | While the Workspace is shown at 120 columns or more, the system shall make the left pane 22 columns wide. | Yes; tested. |
| R-TUI-029.6 | While | While the Workspace is shown at 120 columns or more, the system shall make the right pane 40 columns wide. | Yes; tested. |
| R-TUI-029.2 | While | While the Workspace is shown at less than 120 columns, the system shall make the left pane 24 % of the width. | Yes; tested. |
| R-TUI-029.7 | While | While the Workspace is shown at less than 120 columns, the system shall make the right pane 30 % of the width. | Yes; tested. |
| R-TUI-029.3 | While | While the Workspace is shown, the system shall give the middle pane the rest of the width. | Yes; tested. |
| R-TUI-029.4 | If | If no file is loaded, then the system shall show the empty state on the Workspace, Issues, Memory Map and Checks screens. | Yes; tested. |
| R-TUI-066.1 | When | When the system shows the primary's ranges, the system shall show one section row per range, in address order. | Yes; tested. |
| R-TUI-066.2 | When | When the system shows a section row, the system shall colour it green for a valid range and red for an invalid one. | Yes; tested. |
| R-TUI-066.3 | When | When the system shows a section row, the system shall show a validity glyph that matches the range's validity. | No: `✓` also on invalid ranges (D5-23, prototype first). |
| R-TUI-066.4 | If | If the primary has more than 200 ranges, then the system shall show the first 200 and the row `... <n> more ranges (see log) ...`. | Yes; tested. |
| R-TUI-066.5 | When | When a valid MAC record's address is outside the primary image, the system shall add a MAC row for it after the section rows, in address order. | Yes; tested. |
| R-TUI-066.6 | If | If there are more than 50 MAC rows, then the system shall show the first 50 and the row `... <n> more MAC out-of-range (see Issues panel) ...`. | Yes; tested. |
| R-TUI-066.7 | When | When the operator selects a MAC row, the system shall jump the main hex view to its address. | Yes. |
| R-TUI-066.8 | When | When a primary is loaded, the system shall show the stats pane of CTX-WORKSPACE. | Yes; tested. |
| R-TUI-066.9 | If | If no file is loaded, then the system shall show the stats pane with `Coverage: —` and zero counts. | Yes; tested. |
| R-TUI-066.11 | If | If no file is loaded, then the system shall leave out the loader line. | Yes; tested. |
| R-TUI-066.10 | When | When the issue list changes, the system shall update the stats pane's error and warning counts. | Partly: one step behind after a load or unload; an A2L load never updates it (D5-20). |

R-TUI-029.5 (keep the left pane visible with no file loaded) is retired: the Load dialog lists the work-area files in the empty state (D5-44).

### S5.7 · The loaded panel and unloading

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-WS-LOADED.1 | U | The system shall show the loaded panel of CTX-WORKSPACE above the Workspace panes. | Yes; tested. |
| R-WS-LOADED.2 | U | The system shall label the primary slot `S19` or `HEX` after the primary's kind. | No: always `S19` (D5-22). |
| R-WS-LOADED.3 | While | While an A2L file is loaded, the system shall show its A2L slot, with or without a primary. | Yes; tested for an A2L-only project (`test_at_b100_10_a2l_only_project_saves_and_reopens`); `screens_directionb.py:2063-2070` (D5-18 done). |
| R-WS-LOADED.4 | While | While a slot holds a file, the system shall show a `[u]` button on it. | Yes; tested. |
| R-WS-LOADED.5 | When | When the operator presses `[u]` on a slot, the system shall unload that slot's file. | Yes; tested (also the A2L of an A2L-only session, `test_tc_b100_32_unload_of_an_a2l_only_session_clears_the_a2l`). |
| R-WS-LOADED.6 | When | When the operator presses `U` or `[U]`, the system shall unload the primary, the A2L and the MAC. | Yes; tested. The parsed A2L tags go too (S2 R-A2L-004.13). |
| R-WS-LOADED.7 | When | When the system unloads the primary, the system shall keep the A2L and the MAC loaded. | Yes: with no MAC the A2L stays loaded and its slot now shows (`app.py:16825`, `:16843`, `screens_directionb.py:2063-2070`); the no-MAC arm is untested (D5-18 done). |
| R-WS-LOADED.8 | When | When the system unloads the primary, the system shall drop the primary's image, ranges and entropy windows. | Yes; tested. |
| R-WS-LOADED.16 | When | When the system unloads the primary, the system shall drop the primary's line diagnostics and integrity notices. | Partly: with a MAC loaded, they stay, with the old path (D5-19). |
| R-WS-LOADED.9 | When | When the system unloads the MAC, the system shall keep the primary and the A2L loaded. | Yes; tested. |
| R-WS-LOADED.10 | When | When the system unloads the A2L, the system shall keep the primary and the MAC loaded. | Yes; tested. The parsed A2L tags go with the file (S2 R-A2L-004.13). |
| R-WS-LOADED.11 | When | When the system unloads files, the system shall keep the open project. | Yes; tested. |
| R-WS-LOADED.12 | When | When the system unloads files, the system shall keep their copies in `temp/`. | Yes. |
| R-WS-LOADED.13 | When | When the system unloads files, the system shall show the status `Unloaded primary image.`, `Unloaded MAC.`, `Unloaded A2L.` or `Unloaded all artifacts.` | Partly: the message is added (`app.py:16866`), but the status line keeps the unloaded file's `Loaded …` (D5-17). |
| R-WS-LOADED.14 | If | If nothing is loaded when the operator asks to unload, then the system shall show the status `Nothing to unload.` | Partly: unload-all says `Unloaded all artifacts.` (`app.py:16801-16803`, D5-27). |
| R-WS-LOADED.15 | U | The system shall show file names in the status line and the loaded panel without control characters. | Yes; tested (`test_tc_b100_50_control_bytes_never_reach_the_status_log`) (D5-32 partly done). |
| R-WS-LOADED.17 | U | The system shall show file names in the status line and the loaded panel as plain text, never as markup. | Yes; tested. |

### S5.8 · Open-folder chips (CTX-CHIPS; from S0 HLR-139, LLR-139.x, LLR-148.x)

```text
CTX-CHIPS  Open-folder chips
  chip           A 📂 button in a window header that opens one folder in the
                 system file manager (explorer on Windows, open on macOS,
                 xdg-open elsewhere).
  chip target    Patch Editor:   <project>/patches/, else workarea/patches/
                 Checks:         <project>/checks/,  else workarea/patches/
                 CRC Designer:   <project>/templates/, else .s19tool/templates/
                 Reports:        <project>/reports/;  none with no project
                 Flow Builder:   <project>/flows/;    none with no project
                 Flow Execution: the project folder;  none with no project
  chip folder    The last name of the chip target; with no target, the name
                 the table above gives (patches, checks, templates, reports,
                 flows).
  chip root      The project folder; with no project, .s19tool/.
```

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHIP-001.1 | U | The system shall label each chip other than the Flow Execution chip `📂 Open <chip folder>/`. | Yes; tested (`test_tc703_patch_editor_chip_resolves_change_set_home_both_modes`). |
| R-CHIP-001.2 | U | The system shall label the Flow Execution chip `📂 Open session`. | Yes. |
| R-CHIP-001.3 | When | When the operator presses an enabled chip, the system shall open its chip target in the system file manager. | Yes; tested (`test_tc705_seam_popen_argv_list_per_platform_arm`). |
| R-CHIP-001.4 | While | While a chip has no chip target, the system shall show the chip disabled. | Yes; tested (`test_tc704_reports_without_project_disabled_status_reason_zero_opens`). |
| R-CHIP-001.5 | When | When a chip becomes disabled, the system shall show the status `<label>: no active project — load a project first.` | Yes; tested (same test). |
| R-CHIP-001.6 | While | While a project is open and the target of a chip other than the Flow Execution chip does not exist, the system shall show the chip dimmed with the tooltip `folder does not exist yet`. | Yes; tested (`test_tc704_missing_project_folder_dimmed_create_offer_opens`). |
| R-CHIP-001.12 | While | While no project is open and a chip's target does not exist, the system shall show the chip dimmed with the tooltip `no project — files are in the common folders`. | Yes; tested (`test_tc704_missing_common_home_no_project_dimmed_and_recreated`). |
| R-CHIP-001.13 | While | While the Flow Execution chip's target does not exist, the system shall show the chip dimmed with the tooltip `project folder is missing`. | Yes; tested (`test_tc_b97_28_session_never_creates_a_removed_project_dir`). |
| R-CHIP-001.14 | While | While a chip has no chip target, the system shall show the tooltip `no project — files are in the common folders` on the disabled chip. | Yes; tested (`test_tc704_reports_without_project_disabled_status_reason_zero_opens`). |
| R-CHIP-001.7 | When | When the operator presses a chip other than the Flow Execution chip whose chip target does not exist, the system shall create the chip target before opening it. | Yes; tested (`test_tc704_missing_common_home_no_project_dimmed_and_recreated`). |
| R-CHIP-001.8 | If | If the system cannot create a chip target, then the system shall show the status `Failed to create folder: <reason>`. | Yes; untested. |
| R-CHIP-001.9 | If | If a chip target is not a folder, has a link on its path, or resolves outside the chip root, then the system shall refuse to open it with the status `Refused to open <target>: not a real folder inside <chip root name>/`. | Yes. |
| R-CHIP-001.10 | When | When the system opens a chip target, the system shall show the status `Opened folder: <path>`. | Yes. |
| R-CHIP-001.11 | If | If the system file manager cannot be started, then the system shall show the status `Failed to open folder: <reason>`. | Yes; tested (`test_tc705_seam_failure_lands_on_status_line_no_escape`). |

### S5.9 · Recent sources (CTX-RECENT; from batch-100 HLR-172)

```text
CTX-RECENT  Recent sources
  recent-sources store  The file <LOCALAPPDATA>\s19_app\recent_sources.json: one per
                        user, in the local (not roaming) profile, outside every work
                        area and every start folder.
  store folder          <LOCALAPPDATA>\s19_app
  usable LOCALAPPDATA   The variable is set, starts with a drive letter, a colon and
                        \ or /, and names a folder that exists.
  store format          JSON {"schema_version": 1, "sources": [{"path": <absolute
                        path>, "kind": <kind>}, ...]}, newest first, ASCII only.
  kind                  s19 (.s19 .srec), hex (.hex .ihex), mac (.mac), a2l (.a2l);
                        the suffix compared ignoring case.
  absolute path         The source path made absolute by text only: . and .. folded,
                        no link followed, the drive letter as typed (a mapped network
                        drive keeps its letter).
  same source           Two absolute paths that are equal (on Windows, ignoring case).
  accepted entry        An object with a text "path" and a text "kind", where the path
                        starts with a drive letter, a colon and \ or /,
                        holds no control character (U+0000-U+001F, U+007F-U+009F),
                        holds none of < > : " | ? * after its first two characters,
                        holds no character of Unicode category Cf, Zl, Zp or Cs,
                        has no component that is a device name (S11 CTX-SAVE),
                        and the kind is the kind of the path's suffix.
  store problem         too large, or could not be read (the Load dialog shows it, S7).
```

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-RECENT-001.1 | U | The system shall keep each user's recent sources in the recent-sources store. | Yes; tested (`test_tc_b100_34_store_lives_under_localappdata`). |
| R-RECENT-001.2 | When | When a load copies a data file from outside the work area into `temp/`, the system shall record the file's absolute path and kind first in the recent-sources store. | Yes; tested (`test_tc_b100_34_record_puts_newest_first_with_its_kind`, `test_tc_b100_34_recent_kind_follows_the_loaders_suffix_sets`, `test_tc_b100_34_outside_load_records_the_source_not_the_work_copy`, `test_tc_b100_34_source_that_copies_then_fails_to_parse_is_recorded`, `test_at_b100_12_outside_load_is_remembered_and_typed_project_path_opens`). Recorded before the parse (`app.py:15151`; D5-53). |
| R-RECENT-001.19 | When | When an A2L file from outside the work area has been copied and parsed, the system shall record the file's absolute path and kind first in the recent-sources store. | Yes; tested (`test_tc_b100_34_record_puts_newest_first_with_its_kind`, its `.a2l` arm); `app.py:15320-15321`. |
| R-RECENT-001.20 | If | If copying or parsing an A2L file fails, then the system shall leave the recent-sources store unchanged. | Yes; untested (`app.py:15320-15321`, ruling P2-9; D5-53). |
| R-RECENT-001.3 | U | The system shall record the absolute path of a source without following links. | Yes; tested (`test_tc_b100_34_record_stores_the_lexical_absolute_path`, `test_tc_b100_34_record_does_not_resolve_a_junction`). |
| R-RECENT-001.4 | When | When the system records a source that is already in the store, the system shall keep one entry for it, in first place. | Yes; tested (`test_tc_b100_34_same_source_keeps_one_entry_in_first_place`, `test_tc_b100_34_case_spelling_of_one_source_keeps_one_entry`). |
| R-RECENT-001.5 | U | The system shall keep at most 20 entries in the recent-sources store, dropping the oldest first. | Yes; tested (`test_tc_b100_34_store_holds_at_most_twenty_entries`, `test_tc_b100_34_twenty_five_outside_loads_keep_twenty_newest_first`). |
| R-RECENT-001.6 | U | The system shall keep the store file at most 65,536 bytes long, dropping the oldest entries first. | Yes; tested (`test_tc_b100_34_written_store_fits_the_read_cap`). |
| R-RECENT-001.7 | If | If the new entry alone would make the store file longer than 65,536 bytes, then the system shall leave the store unchanged. | Yes; tested (same test). |
| R-RECENT-001.8 | When | When the system writes the store, the system shall carry over only the existing entries that are accepted entries. | Yes; tested (`test_tc_b100_34_record_writes_back_only_accepted_entries`). |
| R-RECENT-001.9 | When | When the system writes the store, the system shall replace the previous store file in one step. | Yes; tested (`test_tc_b100_34_store_is_replaced_through_unique_staging_files`). |
| R-RECENT-001.10 | If | If a load fails before its copy into `temp/` completes, then the system shall leave the store unchanged. | Yes; tested (`test_tc_b100_34_load_failing_before_its_copy_records_nothing`). |
| R-RECENT-001.11 | If | If the source lies inside the work area, then the system shall not record it. | Yes; tested (`test_tc_b100_34_source_inside_the_work_area_is_not_recorded`). |
| R-RECENT-001.12 | If | If the path input was found only under the start folder or a repository root (R-TUI-005.4, .5), then the system shall not record the source. | Yes; tested (`test_tc_b100_34_source_found_only_in_the_base_folder_is_not_recorded`, `test_tc_b100_34_source_found_through_a_junction_fallback_is_not_recorded`, `test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded`). |
| R-RECENT-001.13 | If | If the absolute path of the source would not be an accepted entry, then the system shall not record it. | Yes; tested (`test_tc_b100_34_source_the_read_would_drop_is_not_recorded`, `test_tc_b100_34_source_with_a_win32_forbidden_character_is_not_recorded`, `test_tc_b100_34_record_with_an_embedded_nul_never_raises`). |
| R-RECENT-001.14 | If | If `LOCALAPPDATA` is not usable, then the system shall write no store file. | Yes; tested (`test_tc_b100_34_no_usable_localappdata_writes_no_store`, `test_tc_b100_34_unusable_localappdata_gives_no_store_path`) (D5-45). |
| R-RECENT-001.15 | If | If the store folder is a link, then the system shall not write the store. | Yes; tested (`test_tc_b100_34_linked_store_folder_is_not_written`). |
| R-RECENT-001.16 | If | If the store has the store problem `could not be read` when the system records a source, then the system shall leave the store unchanged. | Yes; tested (`test_tc_b100_34_unreadable_store_is_left_unchanged`). |
| R-RECENT-001.17 | If | If writing the store fails, then the system shall leave the store unchanged. | Yes; tested (`test_tc_b100_34_failed_store_write_returns_false_and_keeps_the_store`). |
| R-RECENT-001.18 | If | If the system does not record a source, then the system shall complete the load with no status about the store. | Yes; tested (`test_tc_b100_34_failed_store_write_never_fails_the_load`). |
| R-RECENT-002.1 | When | When the system reads the store, the system shall take at most the first 20 accepted entries, in stored order. | Yes; tested (`test_tc_b100_35_read_returns_the_first_twenty_accepted_in_order`). |
| R-RECENT-002.2 | If | If a store entry is not an accepted entry, then the system shall drop it. | Yes; tested (`test_tc_b100_35_entry_path_checks_drop_entries`, `test_tc_b100_35_entry_whose_kind_does_not_match_its_suffix_is_dropped`, `test_tc_b100_35_entry_with_a_win32_forbidden_character_is_dropped`, `test_tc_b100_35_malformed_entry_is_dropped`). |
| R-RECENT-002.3 | If | If the store file is larger than 65,536 bytes, then the system shall read the store as empty with the store problem `too large`. | Yes; tested (`test_tc_b100_35_oversized_store_reads_as_too_large`). |
| R-RECENT-002.4 | If | If the store file or the store folder is a link, or the store file cannot be opened or read, then the system shall read the store as empty with the store problem `could not be read`. | Yes; tested (`test_tc_b100_35_unreadable_store_reads_as_could_not_be_read`). |
| R-RECENT-002.5 | If | If the store file is not a JSON object holding `schema_version` 1 and a `sources` list, then the system shall read the store as empty with no store problem. | Yes; tested (`test_tc_b100_35_store_of_the_wrong_shape_reads_as_empty`). |
| R-RECENT-002.6 | If | If the store file does not exist or `LOCALAPPDATA` is not usable, then the system shall read the store as empty with no store problem. | Yes; tested (`test_tc_b100_35_missing_store_reads_as_empty_with_no_problem`). |
| R-RECENT-002.7 | U | The system shall read any store file content without stopping on an error. | Yes; tested (`test_tc_b100_35_store_read_never_raises`). |
| R-RECENT-002.8 | When | When the system reads the store, the system shall write no file. | Yes; tested (`test_tc_b100_35_read_logs_no_entry_and_writes_nothing`). |
| R-RECENT-002.9 | When | When the system reads the store, the system shall write no store entry to the log. | Yes; tested (same test). |
| R-RECENT-003.1 | U | The system shall not copy an entry of the recent-sources store into any file under the start folder. | Yes; tested (`test_tc_b100_36_seeded_recent_entries_never_reach_the_base_folder`, `test_tc_b100_36_loaded_source_path_stays_out_of_project_files`). |

The Load dialog's Recent section, its store-problem line and a refused recent row (which keeps its entry, R-LOADDLG.81) are S7's.

### S5.10 · The load question (CTX-LOADQ; from batch-100 HLR-174, HLR-174a, HLR-174b, HLR-174c, HLR-174d)

```text
CTX-LOADQ  The load question
  load route         A request that loads into the session: the Load dialog (a typed
                     path, a recent source, a project row, a work-area row; S7
                     R-LOADDLG.60 … .62, R-TUI-043.2, .15), a
                     Workarea Files pick, a variant switch (v, and the v of the
                     Load-result panel, S11).
  load kind          image replacement   an S19 or Intel HEX file, or a variant
                     attach              a MAC or A2L file
                     project load        a project
  unsaved image      The loaded image holds a byte other than the byte last loaded,
                     saved by Save project (S11) or saved back (S8).
  unsaved entries    The Patch Editor's dirty flag is set (S10 CTX-PE-DOC; when Save
                     project clears it: S10 R-PE-038, R-PE-039.1 … .4).
  unsaved flow       The Flow Builder holds edits not yet saved (S16).
  unsaved work       For an image replacement: an unsaved image. For a project load:
                     an unsaved image, unsaved entries or an unsaved flow. For an
                     attach: none.
  load question      A dialog, top to bottom:
    title            Replace <current>?
                       <current>: the open project's name; else the loaded image's
                       file name; else "the current session".
    body             There are unsaved changes in <items>. Load <target> anyway?
                       <items>: the unsaved work, in the order image, entries, flow,
                       as "A", "A and B" or "A, B and C".
                       image: the loaded image's file name. entries: "Patch Editor
                       entries". flow: "flow <flow name>".
                       <target>: "project <name>" for a project load; else the
                       file name of the requested file.
    buttons          Replace (y)   Cancel (n)
  answer             replace or cancel.
  Every <name> in the question is a painted name (CTX-FILES).
```

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-LOADQ-001.1 | When | When a load route requests an image replacement while the loaded image is unsaved, the system shall ask the load question before the session changes. | Yes; tested (`test_tc_b100_44_twenty_four_cells_ask_by_kind`, `test_tc_b100_44_undo_alone_and_repatch_after_save_ask`, `test_tc_b100_72_every_route_asks_and_cancel_keeps_the_session`, `test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route`). |
| R-LOADQ-001.2 | When | When a load route requests an image replacement while the loaded image is not unsaved, the system shall load without the load question. | Yes; tested (`test_tc_b100_44_saved_states_load_without_asking`: after Save project and after a save-back, which records the saved image, `app.py:4743`). |
| R-LOADQ-001.3 | When | When a load route requests an attach, the system shall attach the file without the load question. | Yes; tested (`test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch`). |
| R-LOADQ-001.4 | When | When a load route requests a project load while the loaded image is unsaved, the Patch Editor holds unsaved entries or the Flow Builder holds an unsaved flow, the system shall ask the load question before the session changes. | Yes; tested (`test_tc_b100_44_project_load_asks_iff_a_flag_is_set`, `test_tc_b100_44_patch_editor_reader_follows_its_writers`). |
| R-LOADQ-001.5 | When | When a load route requests a project load while there is no unsaved work, the system shall load without the load question. | Yes; tested (`test_tc_b100_44_project_load_asks_iff_a_flag_is_set`). |
| R-LOADQ-001.6 | U | The system shall ask the load question at most once per load request. | Yes; tested (`test_tc_b100_72_one_question_per_request`). |
| R-LOADQ-002.1 | When | When the operator makes a work-area pick, the system shall take the load kind from the file's suffix. | Yes; tested (`test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix`). |
| R-LOADQ-002.2 | When | When the operator loads a typed path or a recent source, the system shall take the load kind from the suffix of the file the path resolves to. | Yes; tested (`test_tc_b100_72_typed_path_takes_its_kind_from_the_classification`). |
| R-LOADQ-002.3 | If | If a typed path or a recent source ends in a MAC suffix and resolves to a file with another suffix, then the system shall treat the load as an image replacement. | Yes; tested (`test_tc_b100_72_relative_mac_takes_its_kind_from_the_resolved_path`). |
| R-LOADQ-003.1 | When | When the operator answers the load question with replace, the system shall run the load that asked. | Yes; tested (`test_tc_b100_72_replace_runs_the_load_on_every_route`, `test_tc_b100_46_go_runs_at_once_when_clean_and_after_the_question_on_replace`). |
| R-LOADQ-003.2 | When | When the operator cancels the load question, the system shall leave the session and the unsaved work unchanged. | Yes; tested (`test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset`, `test_tc_b100_72_every_route_asks_and_cancel_keeps_the_session`). |
| R-LOADQ-003.3 | When | When the operator cancels the load question, the system shall show no status. | Yes; tested (`test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset`). |
| R-LOADQ-003.4 | If | If the operator cancels the load question of a variant switch, then the system shall not apply that variant to a later load. | Yes; tested (`test_tc_b100_46_cancelled_variant_switch_keeps_the_pending_selection`). |
| R-LOADQ-003.5 | If | If a project load the operator confirmed is refused before the project opens, then the system shall keep the unsaved work. | Yes; tested (`test_tc_b100_46_refused_project_after_yes_keeps_the_work`, `test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work`). |
| R-LOADQ-004.1 | When | When the load question opens, the system shall put the focus on `Cancel (n)`. | Yes; tested (`test_tc_b100_45_focus_starts_on_cancel_on_every_route`). |
| R-LOADQ-004.2 | When | When the operator presses `y` in the load question, the system shall answer replace. | Yes; tested (`test_tc_b100_45_y_replaces_with_the_focus_on_either_button`). |
| R-LOADQ-004.3 | When | When the operator presses `n` or `escape` in the load question, the system shall answer cancel. | Yes; tested (`test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button`). |
| R-LOADQ-004.4 | When | When the operator presses `enter` in the load question, the system shall give the answer of the focused button. | Yes; tested (`test_tc_b100_45_enter_answers_with_the_focused_button`). |
| R-LOADQ-004.5 | When | When the operator clicks a button of the load question, the system shall give that button's answer. | Yes; tested (`test_tc_b100_45_click_answers_with_the_clicked_button`). |
| R-LOADQ-004.6 | If | If the operator presses a key other than `y`, `n`, `escape`, `enter`, `tab`, `shift+tab` or a priority key while the load question is open, then the system shall keep the question open with the session unchanged. | Yes; tested (`test_tc_b100_45_other_keys_leave_the_question_open`). |
| R-LOADQ-004.7 | If | If the operator presses `ctrl+l`, `ctrl+s`, `ctrl+k` or `ctrl+d` while the load question is open, then the system shall ignore the key. | Yes; tested (`test_tc_b100_45_priority_keys_are_inert_under_the_question`). |
| R-LOADQ-004.8 | If | If a second answer reaches the load question after the first, then the system shall ignore the second answer. | Yes; tested (`test_tc_b100_45_a_second_answer_is_ignored`). |
| R-LOADQ-005.1 | U | The system shall title the load question `Replace <current>?`. | Yes; tested (`test_tc_b100_45_title_names_what_is_replaced`). |
| R-LOADQ-005.2 | U | The system shall show the body `There are unsaved changes in <items>. Load <target> anyway?` in the load question. | Yes; tested (`test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences`, `test_tc_b100_45_load_target_named_per_route`, `test_tc_b100_66_question_text_holds_no_decision_ids`). |
| R-LOADQ-005.3 | U | The system shall name in `<items>` every kind of unsaved work that made the system ask. | Yes; tested (`test_tc_b100_45_unsaved_image_is_named_by_its_file_name`, `test_tc_b100_45_patch_editor_entries_named_only_when_w`, `test_tc_b100_45_flow_item_named_with_its_flow_name`). |
| R-LOADQ-005.4 | U | The system shall show the load question with the two buttons `Replace (y)` and `Cancel (n)` and no other button or text box. | Yes; tested (`test_tc_b100_45_one_modal_with_replace_and_cancel`). |
| R-LOADQ-005.5 | U | The system shall show every name in the load question as its painted name, never as markup. | Yes; tested (`test_tc_b100_45_names_paint_literally`). |
| R-LOADQ-006.1 | U | The system shall show the title of the load question above its body, and the body above the buttons. | Yes; untested (`screens.py:1523-1544`). |
| R-LOADQ-006.2 | U | The system shall show the buttons of the load question on one right-aligned row, `Replace (y)` first. | Yes; untested (`screens.py:1531-1544`, `styles.tcss:1751-1757`). |
| R-LOADQ-006.3 | While | While the load question is shown at 99 columns or more, the system shall keep its body and both buttons fully on screen. | Yes; tested (`test_tc_b100_45_buttons_and_body_stay_fully_visible`: 99, 118 and 220 columns). |
| R-LOADQ-006.4 | U | The system shall give the confirm accent of the load question to `Cancel (n)`. | No: `Replace (y)` carries it (`screens.py:1501`) (D5-52, prototype first). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D5-1 | R-TUI-113, 114, 115 record the dev-flow information-contract method. | Out of the requirements; they stay in the batch records. |
| D5-2 | R-TUI-066 prescribes dataclass field order and merge-site code. | Observable rows; the field rules go to the design notes. |
| D5-3 | R-TUI-029 carries the history of the replaced five-tile view. | Layout rows only. |
| D5-5 | The work area is created under the folder the app starts in, so starting it elsewhere gives another work area (and other projects). | Keep: each folder has its own work area. CTX-WORKAREA states it, so it is no longer a surprise. |
| D5-6 | Project loads and work-area picks read files in place. | Rows say "from outside the work area" (R-TUI-002.1, .2). |
| D5-7 | Byte-identical files are reused, not renamed. | Row R-TUI-006.1. |
| D5-11 | `temp/` is never cleaned; it grows with every new file. | Keep (copies are the evidence of what was loaded). A clean-up command would be a new feature; not proposed. |
| D5-34 | "5 MB" log limit. | 5 MiB per file, one backup (R-TUI-015.2, .3). |
| D5-38 | Batch-100 HLR-163 (LLR-163.1, .2) widens reuse to every placement into the work area: any `<stem>_<digits><suffix>` qualifies, names match ignoring case on Windows, an empty file or a link is never reused, and a link on the destination path is refused (`workspace.py:822-998`, `:663-781`). The function names, the one claim loop per placement kind, the `workarea_root` keyword and "size before bytes" (LLR-163.2) are design. The variant-append status (LLR-163.5) and the save-plan prediction (LLR-163.7) are S11's; the export's reuse word (LLR-163.6) and the test re-pins (LLR-163.3, .4) belong to the files of the export and the change documents. | R-TUI-006.1, .2 changed (destination, reuse candidate in CTX-WORKAREA); R-TUI-006.3 … .5 and R-TUI-002.9 added. Design text out. |
| D5-39 | Since Inc 12a (`d7b427d`) a file load shows its progress as a long action of S6 CTX-BUSY, not the progress lines `Copying into workarea temp... (10 %)` … `Loaded <name> (100 %)` that R-TUI-012L.6 named (`app.py:366-370`); no step line reaches the message lines (S6 R-PROGRESS-END.5). | R-TUI-012L.6 cites S6's progress rows (R-PROGRESS-LINE.1 … .11); S5 keeps the file-load steps and the outcome text (CTX-FILES), as S6 CTX-BUSY assigns them. CTX-FILES "progress line" retired. |
| D5-40 | R-TUI-012L.7 asked that a newer load win over a running one (D5-16). Batch-100 HLR-177a (Inc 12b) refuses any load while a session action runs, before the load question (`app.py:8166`, `:20440-20460`). Both describe the same case; the batch decided after an operator verdict (P-D, VS-PD-3). | Batch wins: R-TUI-012L.7 retired; S6 R-BUSY-REFUSE.1 and .6 state the refusal and that no load question opens. D5-16 superseded. |
| D5-41 | R-TUI-012L.10 asked for `Cannot load A2L: <reason>` when an A2L parse fails (D5-15). Batch-100 LLR-177.2b (Inc 12b) catches the failure on the worker and shows `File NOT loaded: '<name>' could not be read — check that the file can be opened, then load again.` (`app.py:15361-15378`), keeping the previous A2L; a refused copy keeps `Cannot load A2L: <reason>`. | Batch wins: R-TUI-012L.10 takes the batch text; R-TUI-012L.11 added. D5-15 superseded (fixed). |
| D5-42 | R-TUI-005.6, .7, .8 gave status lines for a typed path that is missing, a folder, or of an unsupported kind (D5-14 asked `Not a file: <path>`). Since Inc 9a/9b the Load dialog checks the typed path before it closes and paints the refusal inside the dialog (`app.py` `_load_dialog_verdict`, `_typed_load_route` `:14770`): `not found` / `not a supported file` / `outside the work area` / `not a project`, each with `check the path` or its next step (HLR-173d, LLR-173.5, LLR-172.5e/f/h). The old texts stay only as late checks inside the load (`app.py:15109`, `:15114`), reached when the file changes after the class check; `Unsupported file type` is then unreachable in practice (the class already read the resolved suffix). | R-TUI-005.7, .8 retired; R-TUI-005.6 restated as the late check. The dialog's typed-path classes and refusals are S7's (R-TUI-043.14 … .24, R-LOADDLG.71 … .77). D5-14 superseded. |
| D5-43 | R-WS-FILES.6 (D5-37) asked the Workarea Files list to show loadable files written at the work-area root, `splits/` and `crc/`. Batch-100 LLR-172.4a and HLR-162 keep it to `temp/` on purpose (`app.py:7931-7957`; tested, `test_tc_b100_37_lister_returns_the_regular_files_sorted`). Not a defect: a written file loads by its typed path in the Load dialog. | Batch wins: R-WS-FILES.6 retired. D5-37 superseded. Listing more folders would be a new Load-dialog feature, prototype first if wanted. |
| D5-44 | R-TUI-029.5 (D5-26) asked to keep the left pane visible with no file loaded, so that a copy in the work area can be picked. Since Inc 9b the Load dialog (P-A verdict) lists projects, work-area files and recent sources with no file loaded. | Obsolete: R-TUI-029.5 retired; D5-26 superseded. The empty state still hides the panes (R-TUI-029.4). |
| D5-45 | Batch-100 HLR-172 adds a per-user recent-sources store (LLR-172.1 … 172.3). Design and test mechanics leave: the staging-file naming, the ASCII JSON encoder and the 32 + k × (33 + n) size arithmetic, `os.path.abspath` / `normcase`, the drive regex, "every record runs on the UI thread", the test fixture that points `LOCALAPPDATA` at a temporary folder. The store needs a drive-rooted `LOCALAPPDATA` (`workspace.py:2134`), so on Linux and macOS no store is written and the Recent section stays empty. | Rows S5.9 (CTX-RECENT). Kept as the batch decided (S-16): the store is a Windows convenience. The store problem's text in the dialog is S7's. |
| D5-46 | Batch-100 HLR-174 … 174d add one question before a load replaces unsaved work. The 24-cell table becomes CTX-LOADQ's "unsaved work". Design leaves: the modal built from parameters (LLR-174.2a; S6's quit question reuses it), the public dirty reader (LLR-174.1c), the one-seam census (LLR-174.4), "the handler asks nothing" (LLR-174.3b) and the reset order (LLR-174.3; its observable part is R-LOADQ-003.2). The Patch Editor's own load guard and its change-file dropdown (LLR-174.2j, .2t; `test_tc_b100_45_patch_editor_load_keeps_its_own_guard`, `test_tc_b100_45_change_file_dropdown_keeps_the_guard`) are S10's rows R-PE-016, R-PE-019a (S10 D10-45) and settle S10 D10-20; the "Patch Editor entries" item reads S10's dirty flag (R-PE-038, R-PE-039.1 … .4), with no second row here. The route refusal lines `Variant not found`, `Variant file missing`, `No supported files in project` (`test_tc_b100_45_refusal_lines_paint_names_literally`) and the declared regions a confirmed project load installs (`test_tc_b100_46_project_load_adopts_declared_regions_after_the_reset`) are S11's. The focus after a cancel is S6's (LLR-166.1, `test_tc_b100_12_cancelled_question_rehomes_the_focus`). | Rows S5.10 (CTX-LOADQ). The layout settled by the P-B verdict (VS-PB-1 … 3) is written as rows R-LOADQ-006.1 … .3. |
| D5-47 | Since Inc 12a a file load ends with the outcome `Loaded <name>` (S6 R-PROGRESS-END.1) after its load status (`app.py:18016`); AT-B100-01 was re-pinned to read it (ruling CI12a-1). The message lines then hold the load status and the shorter outcome. | Requirement follows the code: R-TUI-012L.12 (S6 CTX-BUSY leaves the outcome text to the action's chapter). The repeat is accepted by that ruling. |
| D5-48 | Tests that verify implementation only (AST censuses, call counts, read counts, call order): `test_tc_b100_01_one_claim_loop_per_placement_kind`, `test_tc_b100_01_wrapper_is_the_one_line_path_return`, `test_tc_b100_01_app_placements_name_the_workarea_root`, `test_tc_b100_02_size_check_runs_before_any_candidate_read` (TC-B100-02, all of it), `test_tc_b100_37_one_function_enumerates_the_temp_folder`, `test_tc_b100_37_widened_census_and_one_enumeration_at_dialog_open`, `test_tc_b100_37_files_list_shows_loadable_suffixes_only_through_one_predicate`, `test_tc_b100_44_guard_reads_the_public_reader`, `test_tc_b100_44_no_private_dirty_read_outside_the_panel`, `test_tc_b100_45_modal_builds_from_its_parameters`, `test_tc_b100_45_modal_imports_nothing_from_the_app`, `test_tc_b100_46_project_load_handler_asks_nothing`, `test_tc_b100_46_reset_runs_after_the_answer`, `test_tc_b100_72_every_load_call_passes_the_seam`. | Listed here, cited by no row. The project-list arm of TC-B100-37 (`test_tc_b100_37_project_list_skips_a_trailing_dot_on_every_platform`, LLR-172.4e) is S11's project list. |
| D5-53 | The two kinds record a recent source at different times: a data file once its copy into `temp/` succeeds, even if the parse then fails (LLR-172.1a, LLR-172.1d, declared Q1; `app.py:15151`); an A2L file only after its parse, so a failed A2L load records nothing (Inc 12b, ruling P2-9; `app.py:15320-15321`). | Requirement follows the code: R-RECENT-001.2 (data file), R-RECENT-001.19, .20 (A2L). Both are batch rulings; not changed here. |
| D5-50 | The copy of a data file from outside the work area, with the reuse check's hashing, runs on the screen's thread (`app.py:15124`), so a large copy holds the screen. Batch-100 declared this held step (LLR-177.1k note, ruling P2-8; S6 D6-35); its workers cover the parse (HLR-177), and the A2L copy already runs on its worker. | Requirement follows the code: R-TUI-012L.5 now covers the parse only. Defer the copy: a later batch may move it to the worker, as S6 D6-35 says. |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D5-8 | The repository-root fallback for relative paths (6 parent folders, `pyproject.toml`) serves development, and can open a file from an unrelated folder. | Remove it (R-TUI-005.5). Since batch-100 a source found this way is also not recorded as recent (R-RECENT-001.12). |
| D5-9 | `_has_a2l` (tests only), `ScreenScaffold` (never built), the unreachable bare `Loaded <name>` branch of the load status (`app.py:17792`). `walk_tree_no_links` left this list: since Inc 8b save as uses it (`project_gather_service.py:1269`). | Remove. |
| D5-49 | `load_selected_file` (`app.py:17335`) has no product caller since Inc 12b: the work-area pick now starts the file-load worker (`app.py:15620`). Only tests call it, as a synchronous loader. | Remove it from the app; tests load through the shipped route or a support helper. |
| D5-55 | R-CHIP-001.6 named one tooltip, `folder does not exist yet`, for every missing chip target. The code shows three, by case (`open_folder_chip.py:130-148`, `folder_open_service.py:91-95` at e279c8b): no project open, the Flow Execution chip, and the others. Found by the S5 test-case pilot (2026-11-01). | R-CHIP-001.6 narrowed to its case; R-CHIP-001.12, .13, .14 state the other tooltips. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D5-54 | R-TUI-002.5's refusal reason prints the literal text `<base>/.s19tool/workarea/` instead of the work-area path (`workspace.py:747-748`, `:778-779` at e279c8b), and no test asserts the text. Found by the S5 test-case pilot (2026-11-01). | The reason names the real work-area path (R-TUI-002.5); a test asserts the text. Code change. |
| D5-10 | The Workarea Files list builds labels that read markup. | Plain text (R-WS-FILES.5); add the list to S1's safe-text views. Done: batch-100 Inc 9a (`f1b8960`). |
| D5-12 | If the work-area or log folder cannot be created, the app dies with a traceback. | An error naming the folder, non-zero exit (R-TUI-001.5). |
| D5-13 | `o` opens the work area with no check; the 📂 chips check that the target is a real folder inside `.s19tool/`. | Same check (R-TUI-008.4). |
| D5-14 | A folder typed as a path gives `Unsupported file type: ` or a copy error. | `Not a file: <path>` (R-TUI-005.7). **Superseded by D5-42.** |
| D5-15 | An exception while parsing an A2L is not caught. | `Cannot load A2L: <reason>` (R-TUI-012L.10). **Superseded by D5-41** (fixed in Inc 12b with the batch text). |
| D5-16 | A load started while another runs does not cancel the older one, so it may still be installed last. Not reproduced. | Reproduce in the batch; newer load wins (R-TUI-012L.7). **Superseded by D5-40.** |
| D5-17 | Unload messages go only to the log; the status line still says `Loaded …`. | Show them on the status line (R-WS-LOADED.13). Re-checked at 570b4b5: the message is added, the status line still keeps `Loaded …`. |
| D5-18 | Unloading the primary with no MAC hides the A2L slot but leaves the A2L in the Explorer, and re-attaches it to the next primary; an A2L loaded with no primary never shows in the panel. | Every slot is independent: unloading the primary keeps the A2L, and the panel shows it (R-WS-LOADED.3, .7). Done: batch-100 Inc 8b (`3a4a309`). |
| D5-19 | Unloading the primary while a MAC is loaded keeps the primary's diagnostics, integrity notices and path, so `Loader N err` and the issues still describe a file that is gone. | Drop them (R-WS-LOADED.8). |
| D5-20 | Error and warning counts are computed before the issue list is rebuilt, so they lag one step; an A2L load never updates them. | Update after the issue list (R-TUI-066.10). |
| D5-21 | A MAC loaded onto a primary with integrity notices shows `Loaded <mac> with integrity notices: S19-…`. | The status describes the file just loaded (R-TUI-012L.8). |
| D5-22 | The primary slot says `S19` for Intel HEX files. | `HEX` (R-WS-LOADED.2). |
| D5-27 | Unload-all with nothing loaded says `Unloaded all artifacts.` | `Nothing to unload.` (R-WS-LOADED.14). |
| D5-28 | Picking a file that no longer exists does nothing. | `File not found: <name>` (R-WS-FILES.4). **Superseded by D5-51** (text). |
| D5-32 | The status line, the log lines and the A2L summary keep control characters from file names. | Remove them (R-WS-LOADED.15); add the status line to S1's safe-text views. Partly done: the status line and the message lines scrub them since Inc 12a (`4cedb23`); the log file and the A2L summary (S2) were not re-checked. |
| D5-33 | The files list shows every file of `temp/`, including the A2L JSON exports; picking one gives `Unsupported file type: .json`. | List only loadable kinds (R-WS-FILES.1). Done: batch-100 Inc 9b (`12d0f81`). |
| D5-51 | A work-area pick of a file that is gone shows nothing (`app.py:15570`). Batch-100 pins that silence (`test_tc_b100_39_pick_of_a_vanished_entry_asks_nothing`: 0 status lines), but the test's stated reason covers only "no question". A pick with no answer is a defect. | Show `File NOT loaded: '<name>' not found — pick another file.` (batch refusal style), still with no question (R-WS-FILES.4, .11); re-pin the status arm of that test. |

**Prototype first** (visual; prototype round with real captures and your verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D5-23 | `✓` (green) on every section row, invalid ranges too. | A glyph per validity that reads at a glance and matches the legend. |
| D5-24 | The band glyph in section rows has no band colour. | Colour it, or drop it (the memory strip shows bands already). |
| D5-25 | Below 120 columns the loaded panel shows 2 rows; with the PROJ row first, only PROJ and the primary are visible. | Which rows show at narrow widths. |
| D5-26 | With no file loaded, the left pane (files list, `Load project`) is hidden with the rest, so a copy in the work area cannot be picked. | Keep the left pane while the empty state shows (R-TUI-029.5). **Superseded by D5-44.** |
| D5-52 | The load question gives the confirm accent to `Replace (y)` (`screens.py:1501`, `styles.tcss:1765`); the quit question gives it to the safe answer after ruling OBS-12b-2 (`app.py:450`). The focus already starts on Cancel. | Which button carries the accent; recommendation `Cancel (n)`, as OBS-12b-2 (R-LOADQ-006.4). |

**Passed to other groups**

- **S1**: the Workarea Files list and the status line join the safe-text views (D5-10, D5-32).
- **S2**: R-A2L-004 (A2L load) now also follows S5.2 / S5.4; R-A2L-003 (JSON export) keeps writing into `temp/`, and S5 hides it from the files list.
- **S4**: R-TUI-009 (selecting a section row jumps the hex view) and the memory strip (R-TUI-067) — the hex classes of R-TUI-066 are S4 R-TUI-004.5.
- **S7**: the load dialog (R-TUI-043).
- **S11**: projects, variants, project save and `validate_project_files` (R-TUI-012, 014, R-PROJ-002).
- Batch-100 items for S1, S2, S6, S7, S8, S10, S11, S13, S16 and S17 are in the record below and in the side file of this reconciliation.

---

**Received from later groups** (after S6–S17 were written)

| # | The situation | Recommendation (applied) |
|---|---|---|
| D5-35 | The 📂 chips had no rows anywhere: their rules sat in S0's table (HLR-139, LLR-139.1, .2, LLR-148.x); S9, S10, S12, S13 and S16 each pointed here. | Shared chip rows in S5.8 (CTX-CHIPS); each window's owner cites them and keeps only its target. Read from `open_folder_chip.py`, `services/folder_open_service.py`. |
| D5-36 | S11 found R-TUI-002.2 and R-TUI-012L.5 false for variant activation (copies into `temp/`) and for project loads and Workarea Files picks (parse on the main thread). | Rows kept; "Code today" reads Partly; the fix is S11 D11-28. At 570b4b5 the parse half is fixed (Inc 12b) and R-TUI-012L.5 reads Yes; the copy on the screen's thread is a batch-declared held step (D5-50); the variant switch's copy into `temp/` stays S11 D11-28. |
| D5-37 | With no project, a save-back lands at the work-area root (S8 D8-1), an export in `splits/` (S17), a CRC write in `crc/` (S13). The Workarea Files list shows `temp/` only, so a written image can be loaded again only by typing its path. | The list also shows the loadable files in those folders (R-WS-FILES.6). Code change. **Superseded by D5-43.** |

- **S8, S13, S17**: written files use the same-content and numbered-name rules (R-TUI-006.1, .2) and S5.3's path rules (D5-8 applies to the CRC config and template paths and to the report filter path box).
- **S17**: the BIN pair is reused only under its own names (S17 D17-35).
- **S6**: R-TUI-029.4 keeps the empty state of the four windows; the loaded panel's project row is S5's and uses S11's variant id.

**Reconciled with batch-100 (s19_app 570b4b5)**

- Rows added (76): R-TUI-006.3, .4, .5, R-TUI-002.9 (HLR-163); R-TUI-012L.11, .12; R-WS-FILES.7 … .15 (HLR-172b; .15 from the S6 agent's items); R-RECENT-001.1 … .20, R-RECENT-002.1 … .9, R-RECENT-003.1 (HLR-172); R-LOADQ-001.1 … .6, R-LOADQ-002.1 … .3, R-LOADQ-003.1 … .5, R-LOADQ-004.1 … .8, R-LOADQ-005.1 … .5, R-LOADQ-006.1 … .4 (HLR-174 … 174d).
- Rows changed in text: R-TUI-005.6 (now the late check, after the S7 agent's items), R-TUI-006.1, .2 (any destination, reuse candidate), R-TUI-012L.5 (the parse only), R-TUI-012L.6 (progress of S6 CTX-BUSY), R-TUI-012L.10 (batch text), R-WS-FILES.1 (regular files, case-blind order), R-WS-FILES.3 (on-disk name), R-WS-FILES.4 (batch refusal style).
- "Code today" changed: R-TUI-002.2 (reason), R-TUI-012L.5 (Partly → Yes, after narrowing to the parse, D5-50), R-WS-FILES.1, .5, R-WS-LOADED.3, .7, .15 (Partly or No → Yes); R-WS-LOADED.13 (reason); cites added to R-TUI-002.4, .8, R-WS-LOADED.5, .6, .10 (S2 R-A2L-004.13, from the sweep).
- Rows retired (5): R-TUI-005.7, .8 (D5-42), R-TUI-012L.7 (D5-40, now S6 R-BUSY-REFUSE.1, .6), R-WS-FILES.6 (D5-43), R-TUI-029.5 (D5-44). Context term retired: "progress line" (D5-39).
- Decisions added: D5-38 … D5-53. Decisions superseded: D5-14 (by D5-42), D5-15 (D5-41), D5-16 (D5-40), D5-26 (D5-44), D5-28 (D5-51), D5-37 (D5-43). Decisions marked done or partly done: D5-10, D5-18, D5-33; D5-32. D5-9 lost `walk_tree_no_links`.
- Context notes: CTX-WORKAREA (placement, destination, name match, reuse candidate), CTX-FILES (data file, work-area pick, painted name, load outcome, file-load steps, session action), CTX-RECENT and CTX-LOADQ new. CTX-LOADQ cites S10 (dirty flag, R-PE-038, R-PE-039.1 … .4) and S8 (save-back records the image) after the sweep agent's items; CTX-FILES "session action" and "file-load steps" now point to S6 CTX-BUSY after the S6 agent's items. D5-50 moved from "Code change" to "Requirement follows the code" (batch-declared held step).
- Not verified: no test was run. For about 25 cited nodes the docstring or body was read; the others were matched by name to the LLR whose threshold they implement (the `-k` selectors of `01-requirements.md`). The Windows-only arms (junctions, case, trailing dots) were not run here. Lint before: 95 rows (14/42/9/30/0); after: 166 rows (29/67/10/60/0).


**Delta to s19_app e279c8b and the test-case pilot (2026-11-01)**

- R-TUI-002.5: the placeholder is the work-area path; the code prints a literal text (D5-54, code change).
- R-CHIP-001.6 narrowed; R-CHIP-001.12, .13, .14 added (D5-55).
- e279c8b changed no S5 code since 570b4b5 (only tests, the version and the canon fold).

## 6. Counts

| | Old S5 | Strict |
|---|---:|---:|
| Requirement statements | 9 rows + 3 process records | 169 rows (incl. 14 chip rows, 30 recent-source rows, 31 load-question rows) |
| Statements the code contradicts or that are not product behaviour | 6 (113/114/115 process; 002/011 copy scope; 006 reuse; 005 repo root) | 0 |
| Rows by form: U / When / While / If / Where | — | 29 / 67 / 13 / 60 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 51 (21 follow the code or move, 4 remove, 18 code change, 5 prototype first, 3 received; numbers not contiguous; 6 superseded) |

Checked by script: one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id.
