# Inc 14 — E1 slice: every file and function to change, counted and mapped

Base `b7b77c4`. Line numbers are on the base tree. Graph: `codewire/graph-inc14.md`. Rows: `01-requirements.md`. Rulings: `E1-rulings.md`.

## 1. Summary

| File | Changes | Rows |
|---|---|---|
| `s19_app/tui/window_help.py` | **0 functions.** 1 constant changed: `WINDOW_HELP_SECTIONS` — 6 entries rewritten whole (`checks` `:145-160`, `crc_designer` `:162-181`, `reports` `:183-204`, `a2l` `:335-347`, `workspace` `:348-363`, `split_join_export` `:365-392`) and 6 steps of `flow` (`:227-228`, `:233`, `:246`, `:260`, `:263-268`, `:274`). Text only: the module docstring (`:1-28`) and the data-home comment (`:50-61`) stop calling the sections a port of `help_sections.md`; the comments above the six rewritten entries say "code-authored, batch-101 Inc 14" | R-WHELP.7, .12, .13, .14, .18 … .26 |
| `s19_app/tui/legend.py` | **0 functions.** 2 constants changed: `MAP_KEYS_LINE` (`:489-491`), `MAP_REGION_ROW_FIELD_KEY` (`:484-486`); their comments (`:478-488`) | R-TUI-062.10.1, R-LEGEND-011 |

**Totals:** **2 source files** under `s19_app/` (cap 4). 0 changed functions, 3 changed constants, 0 new symbols. No signature, no import, no widget, no CSS changes. Unchanged and only read: `section_body_text`, `open_window_help`, `WindowHelpScreen`, `HELP_KEY_WINDOW`, `WINDOW_KEYS`, `window_keys_text` (`window_help.py`); `LegendScreen` map branch (`screens.py:2840-2920`); `RegionRow.on_key` (`screens_directionb.py:1457`).

**Documents (outside `s19_app/`, no cap):**

| File | Change | Rows |
|---|---|---|
| `README.md` | rail paragraph and window table (`:81-95`); key table (`:97-122`); footer paragraph (`:124-125`); sections Patch Editor (`:164-174`), A↔B Diff → A2B Diff (`:176-180`), Flow Builder (`:182-187`), Operations modal (`:203-207`), Projects and variants (`:209-216`), Workarea table (`:218-226`); new sections Check Editor, Flow Execution, Split / Join / Export; Known rough edges (`project.toml` bullet, `:399-400`); Documentation table (`:417-428`) gains `SECURITY.md`, `CHANGELOG.md` | R-DOC-README.2, .3, .4 |
| `SECURITY.md` (new) | supported versions; private reporting path; scope (inputs, the processes the app starts on purpose) [A-19, S-4, S-5]. Merge precondition: private vulnerability reporting enabled (E5 transcript), else held out of the merge [A-6, S-1] | R-DOC-SECURITY.1, .2 |
| `CHANGELOG.md` (new) | `## 1.0.0`: the CRC note of `../inc-8/release-note-crc.md`; the before/after report title and inputs, escaped Markdown names, whole hex windows, failed writes, visible replacements, leftover `.part` files (Inc 7); external-step copies, relative paths, copy names in reports, CRC config reasons (Inc 8); deleted project folder (Inc 3) [A-13, A-14, S-2, S-3] | R-DOC-RELNOTE.1 … .14 |
| `docs/user-guide/ch06-memory-map.md` | 6.5 (`:54-56`) + capture note | R-DOC-GUIDE.1 |
| `docs/user-guide/ch16-reports.md` | 16.1 Declared regions (`:20-22`); 16.2 (`:33-36`) | R-DOC-GUIDE.1 |
| `docs/user-guide/ch17-flow-builder.md` | 17.5 (`:59-64`) + capture note; 17.11 later block (`:175-179`) | R-DOC-GUIDE.1 |
| `docs/user-guide/ch18-flow-execution.md` | 18.9 "If the output changes on the next run" (`:178-182`) | R-DOC-GUIDE.1 |
| `docs/user-guide/ch19-help-palettes-settings.md` | 19.1 (`:16-19`) + capture note | R-DOC-GUIDE.1 |
| `docs/user-guide/ch21-html-reports.md` | intro (`:23-24`); 21.1 header and Runs bullets (`:40-44`, `:53-55`) + capture notes; 21.2 escaping sentence (new); 21.5 (`:141`) | R-DOC-GUIDE.1 |
| `docs/user-guide/DOSSIER.md` | §5 rows F-16 (`:725`), F-28 (`:737`), F-30 (`:739`), F-37 (`:746`), F-38 (`:747`), F-41 (`:750`), F-42 (`:751`), F-49 (`:758`): fixed mark | R-DOC-GUIDE.2 |

Never edited: `prototypes/cambios_10_12_2026/help_sections.md` (operator rule; absent from this tree).

## 2. Function and constant map

| Symbol | File:line (base) | Change | Rows |
|---|---|---|---|
| `WINDOW_HELP_SECTIONS["a2l"]` | `window_help.py:335-347` | 4 steps → 5 steps, Help copy I14 | R-WHELP.12, .20 |
| `WINDOW_HELP_SECTIONS["workspace"]` | `:348-363` | steps 2, 3, 5 changed; 1, 4 kept | R-WHELP.12, .13 |
| `WINDOW_HELP_SECTIONS["checks"]` | `:145-160` | 5 steps → 6 steps | R-WHELP.12, .14, .23 |
| `WINDOW_HELP_SECTIONS["crc_designer"]` | `:162-181` | 6 steps rewritten | R-WHELP.12, .13, .14, .24 |
| `WINDOW_HELP_SECTIONS["reports"]` | `:183-204` | steps 2 … 6 changed; 1 kept | R-WHELP.12, .13, .14, .18, .19 |
| `WINDOW_HELP_SECTIONS["split_join_export"]` | `:365-392` | 7 steps → 8 steps | R-WHELP.12, .14, .21, .22 |
| `WINDOW_HELP_SECTIONS["flow"]` steps 1, 5, 12, 17, 18, 19 | `:227-228`, `:233`, `:246`, `:260`, `:263-268`, `:274` | ids removed (1, 17, 18, 19); CRC lines (5, 12) | R-WHELP.13, .25, .26 |
| `MAP_KEYS_LINE` | `legend.py:489-491` | Legend copy I14 | R-TUI-062.10.1 |
| `MAP_REGION_ROW_FIELD_KEY` | `legend.py:484-486` | Legend copy I14 | R-LEGEND-011 |

Not changed, by decision: the `patch`, `map`, `flow_execution`, `check_editor`, `changes_file_notation` sections (they already meet R-WHELP.12 … .14 except the fence, D-4); `SHIPPED_WINDOW_KEYS`, `HELP_KEY_WINDOW`, the keys blocks (generated from `WINDOW_KEYS`, R-WHELP.8); `LEGEND_TABLE` (D-10); `screens_directionb.py:2626` (BL-I14-1).

## 3. Callers and readers read (rule 8)

- `WINDOW_HELP_SECTIONS` ← `section_for` / `section_body_text` (`window_help.py:582-602`) ← `WindowHelpScreen.compose` (`:675`), `HELP_KEY_WINDOW` (`:880-885`, keys only). Tests that read it: `test_window_usage_help.py`, `test_changes_file_notation_help.py`, `test_b97_chips_help.py` (label-effect census of `patch`, `flow`, `flow_execution`, `check_editor`: Inc 14 keeps every Flow Builder label, `CRC template` included), `test_b97_key_bar.py` (TC-B97-66: no step whose label before ` — ` equals one of the window's keys — the new copy has no such step; the Memory Map arm is unchanged), `test_b99_bytes_field.py` (`patch` only), `test_b97_flow_execution.py` (`flow_execution` only).
- `MAP_KEYS_LINE`, `MAP_REGION_ROW_FIELD_KEY` ← `LegendScreen` map branch (`screens.py:2910-2914`, rendered `markup=False`). Tests: `test_legend_map_sheet.py:144-145`, `test_legend_n8.py:152-153`, `:174-175`, `:559` — all compare against the constant, none against a literal (grep `j k select`, `opens hex` in `tests/`: 0 hits). No SVG snapshot renders the legend sheet or a help window (grep of `tests/__snapshots__`).
- `README.md` ← `tests/test_docs_canon.py` (AT-285: every single-key cell of a README key table is a bound key; no live `s19tool` token outside `.s19tool/` paths). New README text writes `.s19tool/…` with forward slashes so the second arm stays green.
- `help_sections.md` ← the three md nodes only (`E1-rulings.md` §3); after Inc 14, no reader.

## 4. Nodes touched (existing test node names; none renamed)

| Node | Change | Why |
|---|---|---|
| `tests/test_window_usage_help.py::test_tc707_section_census_nine_sections_min_three_steps` | body: iterates every section | md contract retired (`E1-rulings.md` §3, D-3) |
| `tests/test_window_usage_help.py::test_tc707_copy_matches_help_sections_md_verbatim` | body: the 6 sections and 6 Flow Builder steps (indices 0, 4, 11, 16, 17, 18) equal Help copy I14 (pinned in the test); no file read [A-16] | D-3 |
| `tests/test_window_usage_help.py::test_tc707_numbering_generated_sequential` | body [A-3]: every section's paragraph n equals `f"{n}. {steps[n-1]}"`; no stored step matches `^\s*\d+[.)]\s`; each section's step count equals a pinned count (all 12; graph I-15); no file read | D-3, E3 A-3 |
| `tests/test_window_usage_help.py::test_tc707_boundary_no_orphan_seats_no_blank_modal` | module constants `_EXPECTED_KEYS` = ∅, `_CODE_AUTHORED_SHIPPED` += `checks`, `a2l`, `workspace`; the dead constant `_HELP_SECTIONS_MD` (`:86-91`) deleted [A-17]; body unchanged | D-3 |
| `tests/test_changes_file_notation_help.py::test_tc1802_nine_md_sections_intact_tenth_section_added` | `_MD_AUTHORED_KEYS` = ∅; the key-set equality lists all 12 keys; the md read and the constant `_HELP_SECTIONS_MD` (`:44`) removed [A-17] | D-3 |
| `tests/test_docs_canon.py::test_at285_every_readme_named_key_exists_in_the_seat` | helpers [A-5]: `_GLYPH` += `=`, `]`; `_shipped_keys` reads `S19TuiApp._merged_bindings` (inherited keys included) and adds `S19TuiApp.COMMAND_PALETTE_BINDING` only while `S19TuiApp.ENABLE_COMMAND_PALETTE` is true; negative control by monkeypatch | D-9 as amended by E3 A-5 |

Expected outcome on these 6 nodes: the three md nodes go from FAILED (known, `FileNotFoundError`) to PASSED; the other three stay PASSED. The `test_tc706_*` parametrised nodes (9 seats each) read `section_body_text`, so they keep passing with the new copy (they compare the modal body to the same function).

## 5. New tests (E4 proposal)

One new file, `tests/test_b101_help_legend_docs.py`; test names start `test_r_<row id>_…` so `trace_check.py` binds them. `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` grows by 1 (250 → 251), re-measured at integration. The R-DOC-SECURITY.1/2 "path is open" arm is an E5 evidence transcript (`gh api …`), not a test: a test must not call the network.
