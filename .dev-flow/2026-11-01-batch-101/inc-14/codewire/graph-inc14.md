# Code-Wire graph — Inc 14 (help, legend and README describe the shipped app), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `b7b77c4`. Requirements `../01-requirements.md` (28 rows), slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (`<HOME>/Github/code-wire/docs/Notation-Grammar.md`), as in `../../inc-2/codewire/graph-inc2.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** ("was: … / now: …") or **new**. Context nodes are unchanged; they are here because a changed constant flows into them or because they are the behaviour a text must describe.
- This increment changes **no function**: the product changes are three constants (`WINDOW_HELP_SECTIONS`, `MAP_KEYS_LINE`, `MAP_REGION_ROW_FIELD_KEY`) and documents. They are written as `[Data: …]` and `[I/O: …]` entities with the examples their rows need; the context function nodes carry the examples that tie each text to the behaviour it describes.
- Example sources are case ids of `02-test-cases.md` (`R-WHELP.18/2`); `B` = read in the base tree at E1. "Help copy I14" and "Legend copy I14" are the exact texts of `../01-requirements.md` §Definitions — the single source; this graph does not repeat the help copy.

Groups for E4 (file ownership) and the interfaces they share — pinned here, changed only by an orchestrator ruling:

| Group | Files | Owns |
|---|---|---|
| G1 product text | `s19_app/tui/window_help.py`, `s19_app/tui/legend.py` | `[Data: WINDOW_HELP_SECTIONS]`, `[Data: MAP_KEYS_LINE]`, `[Data: MAP_REGION_ROW_FIELD_KEY]` and their comments / module docstring |
| G2 documents | `README.md`, `SECURITY.md` (new), `CHANGELOG.md` (new), `docs/user-guide/ch06-memory-map.md`, `ch16-reports.md`, `ch17-flow-builder.md`, `ch18-flow-execution.md`, `ch19-help-palettes-settings.md`, `ch21-html-reports.md`, `DOSSIER.md` | the `[I/O: …]` document entities |
| G3 tests (tester, independent) | `tests/test_b101_help_legend_docs.py` (new), `tests/test_window_usage_help.py`, `tests/test_changes_file_notation_help.py`, `tests/test_docs_canon.py` | the test nodes of `../E1-slice.md` §4, §5 |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 help copy | Help copy I14 (`../01-requirements.md`), character for character; in Python source each shown backslash is `\\`, `‹` `›` are U+2039 / U+203A | requirements → G1 (data), G3 (pinned in `test_tc707_copy_matches_help_sections_md_verbatim`) |
| I-2 legend copy | `MAP_KEYS_LINE = "↑↓ move · click / ↵ inspect · double-click open hex · Esc close"`; `MAP_REGION_ROW_FIELD_KEY = "glyph · start · size · size vs largest · A2L sym · band · ↵ inspect"` | requirements → G1, G3, G2 (ch06 quotes the key line) |
| I-3 README key cells | every key table cell that holds one key is `` `<key>` `` alone (`` `=` ``, `` `]` ``, `` `Ctrl+P` ``…); two keys in one cell are written `` `a` / `b` `` (not checked by AT-285, checked by R-DOC-README.3/1); every `.s19tool` path is written with forward slashes (AT-285 arm 2) | G2 → G3 |
| I-4 release notes | `CHANGELOG.md`, first section heading exactly `## 1.0.0` | G2 → G3 |
| I-5 capture note | the exact text `(capture taken before 1.0.0` opening a parenthesis under or after a changed passage | G2 → G3 |
| I-6 fixed mark | the Kind cell of a DOSSIER §5 row ends ` · fixed in 1.0.0` | G2 → G3 |
| I-7 test-file census | `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` 250 → 251 | G3 → integration (re-measured there) |

Order inside E4: G1 and G2 in parallel; G3 writes its cases first from this graph and `../02-test-cases.md`, proves the new tests RED on base (`b7b77c4`), then GREEN on the integrated tree. G3 never edits product text; G1 and G2 never edit tests.

## Nodes

section_body_text
req: R-WHELP.7, R-WHELP.12
in: str window_key
out: str body
func: unchanged. `"\n\n".join(f"{n}. {step}" for n, step in enumerate(steps, start=1))` over `WINDOW_HELP_SECTIONS[window_key]["steps"]`; numbers are generated, never stored.
module: s19_app/tui/window_help.py
examples: (R-WHELP.7/1) `"checks"` with Help copy I14 Checks (6 steps) → 6 paragraphs, the first starts `1. Checks run in the Patch Editor`, the last `6. Run checks again after every edit.`
examples: (R-WHELP.7/1) `"split_join_export"` → 8 paragraphs `1. ` … `8. ` (base: 7)
examples: (R-WHELP.7/1) each of the 12 keys → paragraph `k` starts `f"{k}. "` for k = 1 … N, 12/12
examples: (R-WHELP.12/4) `"a2l"` → paragraph 3 = ``3. `/` puts the cursor in Search ASCII text, the search box of the hex pane: Find Next finds that text in the loaded image's bytes. `g` puts it in Goto 0xADDR: Goto shows that address.`` (base paragraph 2 = ``2. Use find (`/`) to jump to a name; the tree highlights matches in place.``)

WindowHelpScreen.compose
req: R-WHELP.7, R-WHELP.12, R-WHELP.14
in: str section_key
out: ComposeResult
func: unchanged. Title `Label`, body `Static(section_body_text(key), markup=False)` (`#window_help_body`), then the generated keys block (`#window_help_keys`, from `HELP_KEY_WINDOW` → `WINDOW_KEYS`), then `Close  esc`. `markup=False` is why `**` shows as typed (R-WHELP.14's defect) and why `<time>`, `[`, `‹›` render literally.
module: s19_app/tui/window_help.py
call: section_body_text, window_keys_text
examples: (R-WHELP.18/1) section `reports` → body paragraph 6 = ``6. Generate new report writes one Markdown file, `<time>-report.md`, into the project's `reports\` folder; Open reports/ opens that folder.``; no keys block (`HELP_KEY_WINDOW["reports"] is None`, unchanged)
examples: (R-WHELP.14/1) section `checks`, base → body shows `**Pass / Fail / Uncheck**` as typed; Inc 14 → `Pass / Fail / Uncheck`, 0 `*`
examples: (R-WHELP.12/1) section `split_join_export` → keys block lists `space a n t m g f p d e esc` (unchanged, from `WINDOW_KEYS["split_join"]`); no step's label before ` — ` equals one of them (TC-B97-66 holds: the new steps have no ` — ` label at all)

_focus_local_input
req: R-WHELP.20
in: str kind
out: None
func: unchanged — the behaviour R-WHELP.20 describes. `_FIND_GOTO_INPUTS[self._active_screen_key]` → `("alt_search_input", "alt_goto_input")` on `a2l`; focuses `targets[0]` for `find`.
module: s19_app/tui/app.py
examples: (R-WHELP.20/2) A2L Explorer shown, `/` → focused id `alt_search_input`, placeholder `Search ASCII text`
examples: (R-WHELP.20/2) then type `CAL`, press `Find Next` (`_handle_search_alt`, `app.py:20611`) → status `Found at 0x<8 hex>` or `Search text not found.` — a search of the image's bytes, not of tag names (the base help's "jump to a name" is false)

ReportViewerScreen.compose
req: R-WHELP.19
in: str project_name; list[Path] reports; tuple[DeclaredRegion, ...] declared_regions
out: ComposeResult
func: unchanged — the behaviour R-WHELP.19 describes. `#report_declared_regions` text = one line `f"{name},{start},{end}"` per declared region (integers, decimal), from `declared_regions`, which the app takes from `_declared_regions` (manifest-seeded at project install, `app.py:14032-14036`; replaced by the typed regions on Generate, `:6354`). No A2L input exists.
module: s19_app/tui/screens.py
examples: (R-WHELP.19/2) Project P loaded (regions `cal` 0x00800000–0x0080FFFF, `cfg` 0x00C00000–0x00C00FFF) → box text `cal,8388608,8454143\ncfg,12582912,12586999`
examples: (R-WHELP.19/2) Project P0 with A2L F loaded → box text `""` (F-30's observation, now what the help states)

generate_project_report → _report_filename
req: R-WHELP.18
in: Path project_dir; …
out: Path written
func: unchanged — the behaviour R-WHELP.18 describes. Writes one Markdown file named by `REPORT_FILENAME_REGEX` (`report_service.py:494`, `_report_filename` `:1369-1404`), `<YYYYMMDD>T<HHMMSS>Z[-NN]-report.md`; no HTML writer exists.
module: s19_app/tui/services/report_service.py
examples: (R-WHELP.18/2) Project P0, `t`, `Generate new report` → `reports\` before: 0 files; after: 1 file matching `^\d{8}T\d{6}Z(-\d{2})?-report\.md$`, 0 `.html`

SplitJoinWindow._sample
req: R-WHELP.21, R-WHELP.22
in: list[SegRow] rows
out: str sample
func: unchanged — the behaviour R-WHELP.21/.22 describe. Rows come from `current_file` (ranges tab: `current_file.ranges`); stem = `Path(current_file.path).stem`, else `output`; `resolve_sample(stem, seg, fmt, DEFAULT_PATTERN)` with `seg` = the first ticked row's name in split, `joined` in join. `_pattern` is never reassigned (no setter).
module: s19_app/tui/segment_split_view.py
examples: (R-WHELP.22/2) loaded `firmware.s19`, tab ranges, `range_00` ticked, mode split, format s19 → NAMING line `‹stem›_‹segment› → firmware_range_00.s19`
examples: (R-WHELP.22/2) then `m` (join) → `… → firmware_joined.s19`
examples: (R-WHELP.21/2) loaded image with ranges [(0x1000, 0x1100), (0x2000, 0x2010)] → ranges rows `range_00` (0x1000, size 0x100), `range_01` (0x2000, size 0x10)

GroupedChecksPanel.render_groups
req: R-WHELP.23
in: Sequence[CheckDisplayRow] rows; Mapping[str, int] group_counts
out: None
func: unchanged — the behaviour R-WHELP.23 describes. One header per present outcome in `CHECK_GROUP_ORDER = ("fail", "uncheckable", "pass")` (`checks_view.py:57`), labels `FAILED`, `UNCHECKABLE`, `PASSED`; at most `_CHECK_DISPLAY_MAX = 40` rows, then `TRUNCATION_NOTE`.
module: s19_app/tui/checks_view.py
examples: (R-WHELP.23/2) rows pass, fail, uncheckable (in that input order) → headers in order `FAILED`, `UNCHECKABLE`, `PASSED`
examples: (R-WHELP.12/2) 41 rows → 40 `CheckRow`s and the last line `More check entries than shown — see the Patch Editor.` (Checks step 5: "its last line says so")

CrcDesignerPanel._parse_ranges
req: R-WHELP.24
in: str text
out: list[tuple[int, int]]
func: unchanged — the behaviour R-WHELP.24 describes. Half-open `start-end` hex ranges from the Ranges field (`crc_designer_view.py:868-897`); coverage is computed over these, in the loaded image.
module: s19_app/tui/crc_designer_view.py
examples: (R-WHELP.24/2) `"0x00008000-0x00008008"` → `[(0x8000, 0x8008)]`; image bytes `31 32 33 34 35 36 37 38` there, CRC-32/ISO-HDLC → concat result `0x9AE0DAAF` (= `zlib.crc32(b"12345678")`)

RegionRow.on_key
req: R-TUI-062.10.1, R-LEGEND-011
in: events.Key event
out: None
func: unchanged — the behaviour the legend lines describe. `enter` → stop, post `Activated(start, end, chain=1)` (inspect); `up`/`down` → stop, focus the previous / next `RegionRow` of the same list, no wrap; every other key bubbles (so `j` → `dump_a2l_json`, `k` → `show_legend`).
module: s19_app/tui/screens_directionb.py
emit: RegionRow.Activated(chain=1)
examples: (R-TUI-062.10.1/2) focus on row 0 of 3, `down` → focus row 1; the inspector still shows row 0's region
examples: (R-TUI-062.10.1/2) focus on row 0, `up` → focus stays on row 0
examples: (R-TUI-062.10.1/2) `enter` on row 1 → one `Activated(chain=1)`; inspector shows row 1's region; the Memory Map stays shown
examples: (R-TUI-062.10.1/2) `j` on a row → not consumed; with A2L F loaded the status reads `A2L JSON saved: <stem>.a2l.json` (why `j k select` is false)

MemoryMapPanel.on_region_row_activated
req: R-TUI-062.10.1
in: RegionRow.Activated message
out: None
func: unchanged. `chain == 1` → select and inspect; `chain >= 2` → open the Workspace hex view at the region start (R-TUI-062.2, R-TUI-062.8).
module: s19_app/tui/screens_directionb.py
examples: (R-TUI-062.10.1/2) a double click on row 1 (chain 2) → Workspace shown, hex view at row 1's start

LegendScreen.compose (map branch)
req: R-LEGEND-011, R-TUI-062.10.1
in: str scope = "map"
out: ComposeResult
func: unchanged. Four boxes; the `Region row` box holds `MAP_REGION_ROW_SAMPLE` then `MAP_REGION_ROW_FIELD_KEY`; the `Map keys` box holds `MAP_KEYS_LINE`; every line `markup=False` (`screens.py:2905-2914`).
module: s19_app/tui/screens.py
examples: (R-TUI-062.10.1/1) `4`, `k` → `Map keys` box line = `↑↓ move · click / ↵ inspect · double-click open hex · Esc close` (base `↑↓ / j k select · click inspect · double-click / ↵ open hex · Esc close`)
examples: (R-LEGEND-011/1) `Region row` box line 2 = `glyph · start · size · size vs largest · A2L sym · band · ↵ inspect` (base `… · ↵ opens hex`)
examples: (R-LEGEND-011/2) at 80×24 → each of the two lines on one row of a 72-cell interior (63 and 67 cells)

test_at285_every_readme_named_key_exists_in_the_seat
req: R-DOC-README.3
in: README.md text
out: None (assert)
func: changed (helpers only; node name kept). was: `_GLYPH` = `/ ? , . + -`; `_shipped_keys` = `S19TuiApp.BINDINGS` keys and key_displays. / now: `_GLYPH` adds `"=": "equals_sign"`, `"]": "right_square_bracket"`; `_shipped_keys` also adds every key of the inherited `textual.app.App.BINDINGS` (`ctrl+q`, `ctrl+c`) and `App.COMMAND_PALETTE_BINDING` (`ctrl+p`). The assertion is unchanged.
module: tests/test_docs_canon.py
examples: (R-DOC-README.3/2) README cell `` `=` `` → `equals_sign` ∈ shipped → passes (base helper: `=` ∉ shipped → RED)
examples: (R-DOC-README.3/2) cell `` `Ctrl+P` `` → `ctrl+p` ∈ shipped (from `COMMAND_PALETTE_BINDING`) → passes
examples: (R-DOC-README.3/2, negative control) a README row `` `h` `` → `h` ∉ shipped → RED

test_tc707_copy_matches_help_sections_md_verbatim
req: R-WHELP.12
in: WINDOW_HELP_SECTIONS
out: None (assert)
func: changed (body; node name kept, `../E1-rulings.md` §3). was: reads `prototypes/cambios_10_12_2026/help_sections.md` (absent from every clone → `FileNotFoundError`) and checks the 4 md keys' steps are substrings. / now: a module-level `_HELP_COPY_I14: dict[str, tuple[str, tuple[str, ...]]]` holds the title and steps of the 6 rewritten sections and the 6 changed Flow Builder steps (by index 0, 4, 11, 16, 17, 18), copied from Help copy I14; asserts equality, no file read. The docstring says the md contract was retired at the canon swap (LLR-140.2 → R-WHELP.1 … .15).
module: tests/test_window_usage_help.py
examples: (R-WHELP.12/4) Inc 14 tree → passes (6/6 sections, 6/6 Flow Builder steps)
examples: (R-WHELP.12/4) base tree → RED (`a2l` step 1 differs: `Load an A2L (`^L`) to browse its section tree — …`)
examples: (R-WHELP.12/4, negative control) Inc 14 tree with the CRC Designer step 3 reverted → RED

test_tc707_numbering_generated_sequential
req: R-WHELP.7
in: WINDOW_HELP_SECTIONS
out: None (assert)
func: changed (body; name kept). was: reads the md, matches md headings to titles, compares counts. / now: for every key, `section_body_text(key).split("\n\n")` paragraphs start `1. ` … `N. ` with N = `len(steps)`; no file read.
module: tests/test_window_usage_help.py
examples: (R-WHELP.7/1) 12 keys → 12/12 pass on base and on Inc 14 (base fails only for the absent md)

test_tc707_section_census_nine_sections_min_three_steps
req: R-WHELP.7
in: WINDOW_HELP_SECTIONS
out: None (assert)
func: changed (body; name kept). was: iterates `_EXPECTED_KEYS` (4 md keys). / now: iterates every key; title non-empty, ≥ 3 non-empty steps.
module: tests/test_window_usage_help.py
examples: (R-WHELP.7/1) Inc 14 → 12/12 (smallest: `changes_file_notation` 4 steps, `map` 4 steps)

test_tc707_boundary_no_orphan_seats_no_blank_modal
req: R-WHELP.7
in: SHIPPED_WINDOW_KEYS
out: None (assert)
func: changed (module constants only). was: `_EXPECTED_KEYS = {checks, a2l, workspace, split_join_export}`, `_CODE_AUTHORED_SHIPPED` = 7 keys. / now: `_EXPECTED_KEYS = frozenset()`, `_CODE_AUTHORED_SHIPPED` += `checks`, `a2l`, `workspace` (10 keys). The formula `(_EXPECTED_KEYS - {"split_join_export"}) | _CODE_AUTHORED_SHIPPED == set(SHIPPED_WINDOW_KEYS)` still holds: both sides are the 10 shipped seats.
module: tests/test_window_usage_help.py
examples: (R-WHELP.7/1) Inc 14 → `set() | {10 keys} == {patch, checks, crc_designer, reports, map, flow, a2l, workspace, check_editor, flow_execution}` → passes

test_tc1802_nine_md_sections_intact_tenth_section_added
req: R-WHELP.12
in: WINDOW_HELP_SECTIONS
out: None (assert)
func: changed (body; name kept). was: key-set equality with `_MD_AUTHORED_KEYS` (4) plus 8 named keys, then reads the md. / now: `_MD_AUTHORED_KEYS = frozenset()`; the equality lists all 12 keys; the md read and loop are removed; the docstring says why.
module: tests/test_changes_file_notation_help.py
examples: (R-WHELP.12/4) Inc 14 → `set(WINDOW_HELP_SECTIONS) == {12 keys}` → passes; base on a clone → RED (`FileNotFoundError`)

## Entities

[Data: window_help.WINDOW_HELP_SECTIONS]
req: R-WHELP.12, R-WHELP.13, R-WHELP.14, R-WHELP.18, R-WHELP.19, R-WHELP.20, R-WHELP.21, R-WHELP.22, R-WHELP.23, R-WHELP.24, R-WHELP.25, R-WHELP.26
in: dict[str, dict[str, object]] — 12 keys, each `{"title": str, "steps": tuple[str, ...]}`
desc: changed. was (B): `checks` 5 steps, `crc_designer` 6, `reports` 6, `a2l` 4, `workspace` 5, `split_join_export` 7, as at `window_help.py:145-204`, `:335-392`; Flow Builder steps 1, 5, 12, 17, 18, 19 as at `:227-274`. / now: those six sections = Help copy I14 (5 + 5 + 6 + 6 + 6 + 8 = 36 steps; titles unchanged); Flow Builder steps per Help copy I14; the other five sections, every title, the key set and the key order unchanged. The module docstring (`:1-28`) and the data-home comment (`:50-61`) say the sections are code-authored; the draft md is history. Each of the six rewritten entries gets the comment `#: batch-101 Inc 14 (D7-26, F-30, F-37, F-41): code-authored; left the help_sections.md census.`
examples: (R-WHELP.12/3) base: 18 stale phrases; Inc 14: 0
examples: (R-WHELP.13/1) base: 10 references (`Change 1`, `folders.html`, `change 1`, `change 2` ×2, `LLR-003.7`, `R-B102-FILE-001`, `R-B102-FILE-002/003`, `E3 ruling 1`, `R-B102-FILE-004..006`); Inc 14: 0
examples: (R-WHELP.14/1) base: 22 `**`, 1 `*why*`; Inc 14: 0 (the `changes_file_notation` fence excluded, D-4)
examples: (R-WHELP.12/1) Inc 14 key tokens: `a2l` {`^L`, `/`, `g`, `d`, `j`} ⊂ app keys; `workspace` {`^L`, `l`, `^S`, `s`, `p`, `o`, `r`, `U`} ⊂ app keys; `crc_designer` {`x`}; `reports` {`p`, `^S`}; `split_join_export` {`^L`, `^K`, `esc`, `t`, `space`, `a`, `n`, `m`, `g`, `p`, `f`, `d`, `e`} ⊂ app keys ∪ window keys; 0 outside
examples: (R-WHELP.25/1) Flow Builder step 12 = ``CRC template — the CRC config file a CRC block reads (the same format as the Operations CRC config); a template the CRC Designer saves is not a CRC config and is refused.``; `_help_lines("flow")["CRC template"]` (TC-B97-32 parser) = the text after ` — ` (label kept)
examples: (R-WHELP.26/1) the same step contains `a template the CRC Designer saves is not a CRC config and is refused`

[Data: legend.MAP_KEYS_LINE]
req: R-TUI-062.10.1
in: str
desc: changed. was: `"↑↓ / j k select · click inspect · double-click / ↵ open hex · Esc close"` (71 cells). / now: Legend copy I14 (63 cells). The comment above it stops saying "verbatim from the contract" and cites R-TUI-062.10.1 and D4-21 (the line changes when Enter opens hex).
examples: (R-TUI-062.10.1/1) Inc 14 → `"↑↓ move · click / ↵ inspect · double-click open hex · Esc close"`; contains neither `j k` nor `select` nor `↵ open hex`

[Data: legend.MAP_REGION_ROW_FIELD_KEY]
req: R-LEGEND-011
in: str
desc: changed. was: `"glyph · start · size · size vs largest · A2L sym · band · ↵ opens hex"` (69 cells). / now: `"glyph · start · size · size vs largest · A2L sym · band · ↵ inspect"` (67 cells). `MAP_REGION_ROW_SAMPLE` (the row with its trailing `↵`) is unchanged.
examples: (R-LEGEND-011/1) Inc 14 → the sheet's `Region row` line 2 ends `↵ inspect`; 0 `opens hex` in the sheet

[I/O: README.md]
req: R-DOC-README.2, R-DOC-README.3, R-DOC-README.4
desc: changed, by block (G2 writes these texts; line numbers on base):
  (1) `:81-95` → the paragraph "A left activity rail switches between twelve windows, one key each. Split / Join / Export has no rail item and no key: open it from the command palette (`Ctrl+K`)." and a `| Key | Window |` table, rail order: `1` Workspace — sections · hex · context; `2` A2L Explorer — tag table + hex pane; `3` MAC View — record table + hex pane; `4` Memory Map — coverage + entropy bands; `5` Issues Report — validation findings; `6` Patch Editor — change-set authoring, checks, patched-image write; `=` Check Editor — check specs for the A2B diff report; `7` A2B Diff — compare two images, write a diff report; `8` Flow Builder — chains of blocks run on the loaded image; `]` Flow Execution — saved flows run as lanes; `9` Checks — the last check run, grouped by outcome; `0` CRC Designer — parametric CRC authoring + known-answer proof.
  (2) `:97-122` → intro "The global keys (the full set lives in `S19TuiApp.BINDINGS`, `s19_app/tui/app.py`; `Ctrl+Q` and `Ctrl+P` come from Textual):" and a `| Key | Action |` table: `Ctrl+K` command palette · `Ctrl+P` Textual's own command palette · `Ctrl+D` cycle layout density · `Ctrl+L` / `l` load a file · `Ctrl+S` / `s` save project · `p` load project · `U` unload everything (images, A2L, MAC) · `r` refresh the workarea file list · `o` open the workarea folder · `v` select the active variant · `x` Operations dialog · `j` write the parsed A2L as JSON into `.s19tool/workarea/temp/` · `d` describe the highlighted A2L tag (A2L Explorer) · `t` report viewer · `b` before/after report for the applied change-set · `c` confirm the lane waiting at an external step (Flow Execution) · `/` the window's find box (Workspace, A2L Explorer, MAC View) · `g` the window's go-to box (Workspace, A2L Explorer, MAC View) · `k` legend (scoped to the shown window) · `?` help (see below) · `+` / `-` page the A2L or MAC table forward / back · `PgDn` / `PgUp` page forward / back (Issues Report, A2L Explorer, MAC View) · `,` / `.` page the Workspace hex view back / forward · `Ctrl+Z` / `Ctrl+Y` undo / redo the Patch Editor change-set · `q` / `Ctrl+Q` quit.
  (3) `:124-125` → "Two rows at the bottom of every window show the keys: row 1 the global keys (`^k` Palette · `^d` Density · `^l` Load · `^s` Save project · `x` Operations · `?` Help · `q` Quit), row 2 the shown window's own keys. `?` opens the help of the window that has the focus — its numbered steps, then its keys; with the focus outside a window that has help, it opens the panel that lists every active key."
  (4) `### Patch Editor` (`:164-174`): its last two sentences → "**Apply loaded changes** writes the entries into the loaded image, and **Write file** (under **Save patched image as**) writes the result as a new `.s19` / `.hex` file; in a project the file becomes a new variant. The change-set JSON and the written image are the shipped hand-off."
  (5) new `### Check Editor` after Patch Editor: "Collects A2L parameters and memory rows into a **check spec** (`.chk.json`): addresses with their expected bytes. A check spec is never applied; the A2B Diff report lists its fields in a `## Checks` section. Check specs live in the project's `checks/` folder, or without a project in the common `.s19tool/workarea/patches/`."
  (6) `### A↔B Diff` (`:176-180`) → `### A2B Diff`: "Compares two images (project variants or files) into classified runs (`changed` / `only_a` / `only_b`), then writes a diff report as a Markdown file and a self-contained HTML file side by side, with a `## Checks` section when a check spec is chosen."
  (7) `### Flow Builder` (`:182-187`): "Composes an ordered chain of typed blocks — LOAD, PATCH, CHECK, CRC, WRITE-OUT, A2B-DIFF and EXT-STEP (a step a human runs outside the app) — and runs it on the loaded image. Flows belong to a project and are saved as `flows/<name>.json` in the project folder."
  (8) new `### Flow Execution` after Flow Builder: "Runs saved flows as lanes, one lane per flow, one after another or in parallel. A lane that reaches an external step waits until you confirm it (`c`). Each run writes one chain-set report, `reports/<time>-chain-set-report.md`, in the project; a set of lanes saves as `flowsets/<name>.json`."
  (9) `### CRC Designer`: "recomputes on every keystroke" → "recomputes after each edit".
  (10) new `### Split / Join / Export` after CRC Designer: "No rail item and no key: open it from the command palette (`Ctrl+K`, Split / Join / Export). It exports ranges of the loaded image — the A2L's memory segments, the image's own ranges, or ranges you type — as one file per range (split) or one file holding them all (join), in S19, Intel HEX or binary, into the project's `splits/` folder or the common `.s19tool/workarea/splits/`."
  (11) `### Operations modal` (`:203-207`): "`x` opens the Operations dialog, which lists the registered operations (`s19_app/tui/operations/registry.py`). `crc` checks or writes CRCs over the loaded image from a CRC config. `extract` and `split_by_segment` are listed but not implemented yet: they answer `placeholder: <name> not yet implemented` and change nothing."
  (12) `### Projects and variants` (`:209-216`), last two sentences → "The Patch Editor's **Execute scope** applies a change-set over the chosen variants: each variant's image is parsed in isolation, one failing variant never aborts the rest, and Reports → **Generate new report** writes the project report of that run."
  (13) `### Workarea` table (`:218-226`) rows: `.s19tool/workarea/temp/` transient loads, and the A2L JSON that `j` writes · `.s19tool/workarea/patches/` change-sets and check specs saved without a project · `.s19tool/workarea/splits/` Split / Join / Export output without a project · `.s19tool/workarea/<project>/` saved projects — a `project.json` manifest plus the image / MAC / A2L artefacts it references, optionally per-variant, and the `patches/`, `checks/`, `templates/`, `flows/`, `flowsets/`, `reports/`, `splits/`, `external/` folders as they are used · `.s19tool/templates/` CRC Designer templates saved without a project · `.s19tool/logs/s19tui.log` TUI log, 5 MB rotating.
  (14) `## Known rough edges` (`:399-400`): delete the `project.toml` bullet (the file is not in the tree; `CLAUDE.md:12`).
  (15) `## Documentation` table (`:417-428`): add `[SECURITY.md](SECURITY.md)` — how to report a vulnerability, supported versions; `[CHANGELOG.md](CHANGELOG.md)` — release notes.
examples: (R-DOC-README.2/1) Inc 14 → `### ` headings include the 13 window names; base → 10 (no Check Editor, Flow Execution, Split / Join / Export; `A↔B Diff` instead of `A2B Diff`)
examples: (R-DOC-README.2/2) Inc 14 window table keys in order `1 2 3 4 5 6 = 7 8 ] 9 0`
examples: (R-DOC-README.3/1) Inc 14 → 26/26 CTX-KEYS rows present; base → 21/26 (missing: the rail-keys row (`=`, `]`), `q`/`Ctrl+Q` as a pair, `Ctrl+P`, `d`, `c`)
examples: (R-DOC-README.4/1) base → 11/11 stale claims present; Inc 14 → 0
examples: (R-DOC-README.4/2) Inc 14 → every repository link target exists, `SECURITY.md` and `CHANGELOG.md` included

[I/O: SECURITY.md]
req: R-DOC-SECURITY.1, R-DOC-SECURITY.2
desc: new, at the repository root. Text (G2 writes it as given; D-1):
  `# Security policy` / `## Supported versions`: a `| Version | Security fixes |` table, rows `1.0.x` → yes, `0.x and the 1.0.0 release candidates` → no. / `## Reporting a vulnerability`: "Please report a vulnerability privately, not in a public issue: open the repository's **Security** tab on GitHub and choose **Report a vulnerability** (GitHub private vulnerability reporting)." Then "Include:" — the version (`s19_app/version.py`, or `pip show s19tool`); what the vulnerability lets someone do; the steps, or a small input file, that show it — synthetic files only, never firmware, A2L or MAC files you are not free to share. / `## Scope`: "s19_app is an offline terminal tool: it opens no network connection. What it must withstand is the content of the files it reads — S19, Intel HEX, A2L, MAC, and the change-set, check, CRC and flow JSON files — and where it writes, under its work area (`.s19tool/`). Examples of a vulnerability: a crafted input file that makes the app write outside its work area, run a command, or paint escape sequences or markup taken from the file; a small file that makes it use unbounded memory or time." No response-time promise (D-1).
examples: (R-DOC-SECURITY.1/1) file present; contains `Security`, `Report a vulnerability`, `not in a public issue`
examples: (R-DOC-SECURITY.1/2) E5, after the operator enables the setting: `gh api repos/jav201/s19_app/private-vulnerability-reporting` → `{"enabled":true}` (2026-11-05: `{"enabled":false}`)
examples: (R-DOC-SECURITY.2/1) table rows `1.0.x` / yes and `0.x and the 1.0.0 release candidates` / no

[I/O: CHANGELOG.md]
req: R-DOC-RELNOTE.1, R-DOC-RELNOTE.2, R-DOC-RELNOTE.3, R-DOC-RELNOTE.4, R-DOC-RELNOTE.5, R-DOC-RELNOTE.6
desc: new, at the repository root (D-2). `# Changelog`, one line "Changes that alter what s19_app computes or writes, newest release first.", then `## 1.0.0` with:
  `### CRC: init is taken as written when reverse is true` — the four sections of `../../inc-8/release-note-crc.md` ("What changed", "Am I affected?", "What an affected config does now", "How to keep the earlier value") copied verbatim as `####` headings, without that file's first line ("Batch-101 Inc 8 …", process text).
  `### Reports` — (a) "The before/after report (Patch Editor → Write before/after report, `b`) is titled `Before/after report` in both files; earlier versions titled it `Diff report`. Its header computes the artifact lines against the loaded A2L and MAC (`a2l=used (<covered>/<total>)` where it read `a2l=absent`), and its Runs table fills the Symbols column from the loaded A2L and MAC." (b) "Diff and before/after report files hold every hex window whole; earlier versions cut each window at 512 rows." (c) "In the Markdown file of a diff or before/after report, names and paths carry a backslash before each Markdown character (`CAL\_A`, `img\.s19`), so a Markdown reader shows them exactly. A plain-text search of the `.md` file for `CAL_A` no longer matches; search the HTML file instead."
  `### Flows` — "When a confirmed external step copies an output that differs from the file already under its name, the copy gets a numbered name (`<name>_1.<ext>`) as before, and a later block of the same run that names the output now reads this run's copy; its summary ends ` · read <copy file name> in place of <ref>`. Earlier versions read the first copy."
examples: (R-DOC-RELNOTE.1/2) `crc32_stream(b"123456789", polynomial=0x04C11DB7, init=0x12345678, reverse=True, final_xor=0xFFFFFFFF)` → `0x0F8B7431` (the stated 1.0.0 value)
examples: (R-DOC-RELNOTE.2/2) bit-reverse(`0x12345678`) → `0x1E6A2C48`; the same call with init `0x1E6A2C48` → `0x18026B2A` (the stated earlier value)
examples: (R-DOC-RELNOTE.3/1) section text contains `Before/after report`, `a2l=used`, `Symbols column`
examples: (R-DOC-RELNOTE.6/1) section text contains `every hex window whole` and `512 rows`

[I/O: docs/user-guide passages]
req: R-DOC-GUIDE.1
desc: changed, eleven passages (G2 writes these texts; base line numbers):
  /1 `ch06-memory-map.md:54-56` → "`k` explains the bands and their entropy ranges, the parts of the map, a region row, and the keys. The "Map keys" line says what each key does: `↑↓ move · click / ↵ inspect · double-click open hex · Esc close`. (capture taken before 1.0.0: it shows the earlier line `↑↓ / j k select · … double-click / ↵ open hex`, finding F-16)"
  /2 `ch16-reports.md:20-22` → "- **Declared regions** — `name,start,end` lines that the generated report uses to annotate coverage. It holds the regions saved with the project; the demo project has none, so it is empty."
  /3 `ch16-reports.md:33-36` → "… and writes `reports\<time>-report.md`. It writes Markdown only: no `.html` copy is produced, as the window's help says. The reports that do have an HTML copy are shown in Chapter 21."
  /4 `ch17-flow-builder.md:59-64` → "**Run** runs the chain on the project and lists each block's verdict: `source ok`, `patch ok — applied 5 entries`, `check notices — passed=3 failed=1 uncheckable=1`; then the CRC block stops: it names the template the CRC Designer saved, and a CRC block reads a CRC config, not a Designer template. Its cause is `crc config invalid: CRC config is structurally invalid: a CRC Designer template is not a CRC config - it has no regions or groups` (finding F-28), and the chain ends **FAILED** there. (capture taken before 1.0.0: it shows the earlier cause `… 'reverse'`)"
  /5 `ch17-flow-builder.md:175-179` → "… as any other ref (finding F-48). When a later run produces a different output, the copy is stored as `<name>_1…`, and a later block of the same run that names the output reads this run's copy; its summary ends ` · read <copy> in place of <ref>` (finding F-49, fixed in 1.0.0)."
  /6 `ch18-flow-execution.md:178-182` → "**If the output changes on the next run.** In the same session the command was run again with `BENCH=V2`, then Run and Confirm. The new output was copied as `step_patch.changes_1.json`. In 1.0.0 the PATCH block reads that copy — its summary ends ` · read step_patch.changes_1.json in place of step_patch.changes.json` — and `terminal_out.s19` holds `BENCH=V2`. (This run was recorded before 1.0.0, when the PATCH block still read `step_patch.changes.json` and the image kept `BENCH=OK`; finding F-49.)"
  /7 `ch19-help-palettes-settings.md:17-19` → "… Flow Builder, Flow Execution, Reports, Split / Join / Export. (capture taken before 1.0.0: its step 5 names a "folders.html board"; 1.0.0 names the work area's common folders, finding F-37)"
  /8 `ch21-html-reports.md:40-44` → "- **Header** — when, with which tool version, and which two files were compared: A is the image as loaded (`firmware.s19`), B the written file (`firmware-patched.s19`), with artifact lines computed against the loaded A2L and MAC (`a2l=used (…)`). The page is titled "Before/after report". (capture taken before 1.0.0: it shows the title "Diff report" and `a2l=absent; mac=absent`, finding F-42)"
  /9 `ch21-html-reports.md:53-55` → "- **Runs** — each differing address run with its length and class. The *Symbols* column names the A2L and MAC symbols whose address lies in the run, from the loaded A2L and MAC (the capture, taken before 1.0.0, shows `-`)."
  /10 `ch21-html-reports.md:23-24` → "… are Markdown only (finding F-44)."; `:141` "Markdown only (finding F-41)." → "Markdown only."
  /11 `ch21-html-reports.md`, a new paragraph at the end of 21.2: "In the `.md` file, names and paths carry a backslash before each Markdown character (`CAL\_A`, `img\.s19`), so a Markdown reader shows them exactly; a plain-text search of the `.md` file for `CAL_A` finds nothing — search the `.html` file, or open the `.md` in a Markdown reader."
examples: (R-DOC-GUIDE.1/4) Inc 14 → `ch17-flow-builder.md` contains `a CRC Designer template is not a CRC config - it has no regions or groups` and `(capture taken before 1.0.0`; not ``then `crc error — CRC config is structurally invalid: 'reverse'` ``
examples: (R-DOC-GUIDE.1/6) Inc 14 → `ch18-flow-execution.md` contains `in place of step_patch.changes.json`; not `To use a new output, delete or rename the old copy`
examples: (R-DOC-GUIDE.1, all) the claims quoted are the merged rows' exact texts: R-CRC-CONFIG-001.16 / R-FLOW-CRC.4 (Inc 8), the read suffix of R-FLOW-EXT.12 (Inc 8), R-BEFORE-AFTER-REPORT-001.32 … .35 and R-BEFORE-AFTER-REPORT-001.24 (Inc 7), US-MDESC-1 (Inc 7)

[I/O: docs/user-guide/DOSSIER.md §5]
req: R-DOC-GUIDE.2
desc: changed. The Kind cell of rows F-16 (`:725`), F-28 (`:737`), F-30 (`:739`), F-37 (`:746`), F-38 (`:747`), F-41 (`:750`), F-42 (`:751`), F-49 (`:758`) gains ` · fixed in 1.0.0`; the Finding and Evidence cells stay (they record what was seen). No other row changes.
examples: (R-DOC-GUIDE.2/1) `| F-16 | help mismatch, live + code · fixed in 1.0.0 | …` (8/8)
examples: (R-DOC-GUIDE.2/2) `| F-43 | limitation, live | …` unchanged; 0 other rows with `fixed in 1.0.0`

[Outside: prototypes/cambios_10_12_2026/help_sections.md]
desc: the operator's untracked draft; never edited (operator rule); after Inc 14 no test reads it (`../E1-rulings.md` §3)

[Outside: screens_directionb.py:2626 inspector subtitle "↑↓ · ↵ hex"]
desc: unchanged; R-TUI-062.10.2, backlog BL-I14-1 (a screen string; D-6)
