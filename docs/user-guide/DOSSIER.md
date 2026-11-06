# s19tui user guide — dossier

Status: **Phase C done — chapter text and real captures, for review** (Phase C added the funnel and parallel-lanes demo to Chapters 17 and 18 and Chapter 21 on the reports; Phase D added the external step in Terminal mode, 17.11 and 18.9). No slides yet:
slides are built only after this dossier is approved.

- Product state: branch `b100-release-assets` at `9fd3638` (main `570b4b5` plus the
  synthetic demo case). No product code was changed.
- Language: English (the app and its UI are English). No person's name appears in the
  text or the captures.
- Every capture is a real Windows Terminal window, true colour, 118×54 unless the file
  name ends in `-99` (99×54) or `-wide` / `wide` (220×60). Each PNG was opened and
  checked after capture.
- Demo inputs: `examples/case_08_release_demo/` (synthetic, generated; see its
  `README.txt`), copied into a scratch work area at `C:\Users\Public\s19demo` for the
  runs (that is the path visible in some captures). Documents written only for this
  guide are named `guide_*` and are described where they are used.

## 1. Totals

| Count | What |
|---|---|
| **21** | chapters (one file each, `ch01-…md` to `ch21-…md`) |
| **181** | captures in `img/` (175 Windows Terminal, 6 headless Microsoft Edge renders of HTML reports) |
| **32** | user-reachable windows (1 app shell, 13 views, 18 modal dialogs) |
| **372** | features inventoried from the code (§4) |
| **51** | findings for the release fix (§5) |

## 2. Chapters

| Ch | File | Windows | Captures |
|---|---|---|---|
| 1 | [ch01-start.md](ch01-start.md) — Start the app and find your way | the app shell (W00): header, activity rail, window body, status bar, key bar | 3 |
| 2 | [ch02-load.md](ch02-load.md) — Load files and projects | Load dialog (W01), Load result panel (W02), Replace question (W03) | 9 |
| 3 | [ch03-workspace.md](ch03-workspace.md) — Workspace | Workspace (W04) | 7 |
| 4 | [ch04-a2l-explorer.md](ch04-a2l-explorer.md) — A2L Explorer | A2L Explorer (W05), Parameter description (W06) | 11 |
| 5 | [ch05-mac-view.md](ch05-mac-view.md) — MAC View | MAC View (W07) | 5 |
| 6 | [ch06-memory-map.md](ch06-memory-map.md) — Memory Map | Memory Map (W08) | 6 |
| 7 | [ch07-issues.md](ch07-issues.md) — Issues Report and the legend | Issues Report (W09), Classification legend (W10) | 7 |
| 8 | [ch08-patch-editor.md](ch08-patch-editor.md) — Patch Editor | Patch Editor (W11), Edit entry JSON (W13), Edit change-set JSON (W12), Unsaved changes will be lost (W14), Select variant (W23) | 22 |
| 9 | [ch09-a2b-diff.md](ch09-a2b-diff.md) — A2B Diff | A2B Diff (W17) | 8 |
| 10 | [ch10-check-editor.md](ch10-check-editor.md) — Check Editor | Check Editor (W15) | 8 |
| 11 | [ch11-checks.md](ch11-checks.md) — Checks | Checks (W16) | 3 |
| 12 | [ch12-crc-designer.md](ch12-crc-designer.md) — CRC Designer | CRC Designer (W18) | 7 |
| 13 | [ch13-operations.md](ch13-operations.md) — Operations: compute and write a CRC | Operations (W19), Confirm CRC write (W20) | 5 |
| 14 | [ch14-split-join-export.md](ch14-split-join-export.md) — Split / Join / Export | Split / Join / Export (W21) | 12 |
| 15 | [ch15-save-project.md](ch15-save-project.md) — Save the project and switch variants | Save project (W22), Select variant (W23) | 5 |
| 16 | [ch16-reports.md](ch16-reports.md) — Reports | Reports viewer (W24) | 3 |
| 17 | [ch17-flow-builder.md](ch17-flow-builder.md) — Flow Builder | Flow Builder (W25), Save flow as (W26), Load flow (W27), Discard unsaved flow edits? (W28) | 18 |
| 18 | [ch18-flow-execution.md](ch18-flow-execution.md) — Flow Execution | Flow Execution (W29) | 18 |
| 19 | [ch19-help-palettes-settings.md](ch19-help-palettes-settings.md) — Help, palettes and settings | app shell (W00): help panel, command palette, Textual palette, Viewer settings, density; Window help (W30) | 9 |
| 20 | [ch20-quit.md](ch20-quit.md) — Quit | app shell (`q`), Quit? question (W31) | 2 |
| 21 | [ch21-html-reports.md](ch21-html-reports.md) — HTML reports: review what was modified, checked and compared | Patch Editor (W11), A2B Diff (W17), Flow Builder (W25), Reports viewer (W24); the report files | 13 |

## 3. How the captures were made

- **Tool.** The project's E13 mechanism (`tools/e13/capture.ps1` + `run.py`), not
  modified, copied into a guide driver outside the repo: `guide_run.py` (one scripted
  scenario per chapter, real `S19TuiApp` on a scratch work area, keys sent through the
  same path as Textual's `Pilot.press`, clicks through `Pilot.click`) and
  `guide_capture.ps1` (opens one new Windows Terminal window per chapter with a unique
  title, `NO_COLOR` unset, saves a PNG with `PrintWindow` each time the driver signals
  a shot, then closes that window with `WM_CLOSE` and checks it is gone).
- **Environment.** `LOCALAPPDATA` pointed at a scratch folder, so the real
  `%LOCALAPPDATA%\s19_app` was never created (checked after the runs). The scratch
  work area was deleted after each window closed.
- **Where the driver set values instead of typing.** Long paths, multi-character
  field values and dropdown picks were set on the widget (the same value a user types
  or picks); keys such as `^l`, `p`, `/`, `g`, Tab, Enter, `space`, `^z`, `]`, `c`,
  `q` were real key presses. Mouse actions (band click, double click on a Map region)
  were real pointer events. The hex panes in Chapter 3 were scrolled programmatically
  to show the target row, as a user does with the wheel (finding F-07).
- **Window hygiene.** Every terminal window opened for the guide was closed; a
  final scan found no window titled `GUIDE-…` open.
- **HTML reports (Chapter 21).** The `.html` files the app wrote during the Chapter 21
  run were rendered with **Microsoft Edge in headless mode** (`msedge --headless=new
  --screenshot`, 1280 px wide, a throw-away profile, no window), full page, cut into
  1400 px slices; the slices shown are named `ch21-…-html-…png`. No report was edited.
  For Chapter 21.4 one line (`{"kind": "report"}`) was added to a saved *flow* file,
  because the builder cannot add a REPORT block (F-36).
- **Not captured, on purpose:** the "📂 Open …" chips and `o` (they open the system
  file manager) and Flow **Import…** (system file dialog); their effect is described
  from the code.

## 4. Window inventory (from the code)

Conventions: **Reach** = how the user gets there. Keys are written as the key
bar paints them (`^K` = Ctrl+K). "palette" = the app's own command palette
(`^K`), whose entries are built 1:1 from `S19TuiApp.BINDINGS` plus two extra
entries (`app.py:_build_palette_entries`, `EXTRA_PALETTE_ENTRIES`). Every rail
screen is also reachable by clicking its rail row (`rail.py:RailItem` →
`app.py:on_rail_selected` → `app.py:action_show_screen`).

### W00 — App shell (on every screen) · 30 features

Reach: always present. Startup: `s19tui` or `s19tui --load <path>`
(`app.py:main`, startup load in `app.py:on_mount` → `_load_path_from_user_input`).

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Start with nothing loaded; empty-state prompt "No file loaded - press Ctrl+L (or 'l') …" | `s19tui` | `screens_directionb.py:EmptyStatePanel`, `app.py:_apply_empty_state` |
| 2 | Start and load a file at once | `s19tui --load firmware.s19` | `app.py:main`, `app.py:on_mount` |
| 3 | Header title "Hex Edit Tool" | — | `app.py:S19TuiApp.TITLE`, `compose` |
| 4 | Activity rail, 12 rows, glyph + label, active marker | click a row | `app.py:RAIL_ENTRIES_B94`, `rail.py:Rail.set_active` |
| 5 | Rail keys `1`–`6`, `=`, `7`, `8`, `]`, `9`, `0` | key | `app.py:S19TuiApp.BINDINGS` (`show_screen(...)`), `action_show_screen` |
| 6 | Command palette: open, type to filter, Enter/click runs | `^K` | `command_bar.py:CommandBar.open_palette/on_input_changed/on_input_submitted/on_list_view_selected`, `app.py:action_focus_palette`, `on_command_bar_palette_action` |
| 7 | Palette entry "Viewer settings" | `^K` → Viewer settings | `app.py:EXTRA_PALETTE_ENTRIES`, `action_open_settings_menu` |
| 8 | Palette entry "Split / Join / Export" | `^K` → Split / Join / Export | `app.py:EXTRA_PALETTE_ENTRIES`, `action_open_split_join_export` |
| 9 | Viewer settings menu: page size 25/50/100/150/200 for Hex rows, A2L tags, MAC rows | pick a row | `app.py:_update_settings_menu`, `on_list_view_selected`, `_apply_viewer_setting` |
| 10 | Layout density compact ⇄ comfortable | `^D` | `app.py:action_cycle_density` |
| 11 | Find: focus the active screen's ASCII search (Workspace, A2L, MAC only; elsewhere one status line) | `/` | `app.py:action_focus_find`, `_focus_local_input`, `_FIND_GOTO_INPUTS` |
| 12 | Go-to: focus the active screen's address field (same three screens) | `g` | `app.py:action_focus_goto`, `_focus_local_input` |
| 13 | Escape releases a find/go-to field | `esc` | `app.py:on_key` |
| 14 | Single-key bindings are typed as text while a command-bar field has focus | — | `app.py:on_key` (`_COMMAND_BAR_SUPPRESSED_KEYS`) |
| 15 | Status line (`#status_text`) + context label | — | `app.py:compose` (`#status_line`), `set_status`, `set_file_status` |
| 16 | Progress bar with step and elapsed time during load/save | — | `app.py:set_progress`, `_busy_begin_action`, `step_busy`, `end_busy` |
| 17 | Log tail, last 4 lines | — | `app.py:compose` (`#log_line_1..4`), `_append_log_line` |
| 18 | A second load/save is refused while one runs | — | `app.py:_refuse_if_busy` |
| 19 | Two-row key bar: row 1 global keys + Textual palette; row 2 the active window's keys | — | `window_help.py:KeyBar`, `GLOBAL_KEYS`, `WINDOW_KEYS`, `WINDOW_GO_KEYS` |
| 20 | Key bar tokens are clickable; disabled tokens dim | click | `window_help.py:KeyRow.on_click`, `KeyBar.run_token`, `pack_key_row` |
| 21 | Help panel (every active binding, incl. hidden ones), toggle | `?` (when no window claims it) | `app.py:action_show_help_panel` |
| 22 | Per-window help (`?` chip in a window title, or `?` with focus in that window) | `?` / click `?` | `window_help.py:WindowHelpChip`, `WindowSection.action_show_window_usage_help`, `open_window_help` → W30 |
| 23 | Legend for the active screen | `k` | `app.py:action_show_legend` → W10 |
| 24 | Operations modal | `x` | `app.py:action_operations_view` → W19 |
| 25 | Load (typed path first) | `^L` / `l` | `app.py:action_load_file` → W01 |
| 26 | Load project (list first) | `p` | `app.py:action_load_project` → W01 |
| 27 | Save project | `^S` / `s` | `app.py:action_save_project` → W22 |
| 28 | Reports viewer | `t` | `app.py:action_view_reports` → W24 |
| 29 | Textual command palette (theme, keys, screenshot, quit …) | `^P` (key bar "palette") | Textual `App.COMMAND_PALETTE_BINDING` = `ctrl+p` (textual 8.2.8), painted by `window_help.py:global_tokens` |
| 30 | Quit | `q` (also Textual `^Q`) | `app.py:action_quit` (asks W31 only while a load/save runs) |

### W01 — Load dialog · 14 features

Reach: `^L` / `l` (opens with the path field focused), `p` or the Workspace
"Load project (p)" button (opens with the list focused). `screens.py:LoadDialog`,
rows/verdict/preview from `app.py:_load_dialog_rows/_load_dialog_verdict/_load_dialog_preview`,
routed by `app.py:_handle_load_dialog`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Path field: S19, HEX, MAC, A2L or a project folder | type, Enter | `screens.py:LoadDialog.on_input_submitted`, `_path_choice` |
| 2 | Section "Projects" (folders in the workarea) | arrows | `app.py:_load_dialog_rows` (`list_projects`) |
| 3 | Section "Work area" (files already copied into `workarea\temp`) | arrows | `app.py:_load_dialog_rows` (`list_workarea_files`) |
| 4 | Section "Recent" (recorded recent sources, file name + kind) | arrows | `app.py:_load_dialog_rows` (`read_recent_sources`) |
| 5 | Empty/problem lines per section ("no projects — ctrl+s saves a project", "no recent sources", …) | — | `app.py:_load_dialog_rows` |
| 6 | Preview pane: project → variants, A2L, marks `●`; work-area file → marks; recent → full path, kind | highlight | `app.py:_load_dialog_preview`, `screens.py:LoadDialog.show_preview` |
| 7 | Typing while the list has focus moves the text into the path field | type | `screens.py:LoadDialog.on_key` |
| 8 | Load (Enter on list/preview, `alt+l`, button) | `enter` / `alt+l` | `screens.py:LoadDialog.action_load`, `BINDINGS` |
| 9 | Refusal reason line keeps the dialog open ("nothing selected — pick a row or type a path", unsupported/missing path) | — | `screens.py:LoadDialog._say`, `app.py:_load_dialog_verdict` |
| 10 | Cancel (`esc`, button) | `esc` | `screens.py:LoadDialog.action_cancel` |
| 11 | Stacked layout under 100 columns | resize | `screens.py:LoadDialog._apply_stack` |
| 12 | Project load → W02 result panel | — | `app.py:_route_load_project`, `LoadResultScreen` push |
| 13 | File load copies into `workarea\temp`, parses off-thread with progress | — | `app.py:load_from_path`, `_start_load_worker` |
| 14 | Load over unsaved work asks first → W03 | — | `app.py:_confirm_then_load`, `_load_would_lose` |

### W02 — Load result panel · 4 features

Reach: automatic after a project load (`app.py`, push of `LoadResultScreen` in the project-install tail). `screens.py:LoadResultScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Title "Project <name> opened [with N problems]" + summary table | — | `screens.py:LoadResultScreen.compose`, `_summary` |
| 2 | Problems list ("Problems found (the rest loaded)") or "No problems found." | — | `screens.py:LoadResultScreen._problem_row` |
| 3 | Select variant → W23 | `v` / button | `screens.py:LoadResultScreen.BINDINGS`, `app.py:_handle_load_result` |
| 4 | Close | `esc` / button | `screens.py:LoadResultScreen.BINDINGS` |

### W03 — Replace question · 3 features

Reach: any load that would replace unsaved work (patched image, unsaved Patch
Editor entries, unsaved flow). `app.py:_confirm_then_load` →
`screens.py:ConfirmQuestionScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Names what would be lost (image / document / flow) | — | `app.py:_load_would_lose`, `_load_question_text` |
| 2 | Replace | `y` / button | `screens.py:ConfirmQuestionScreen.BINDINGS` |
| 3 | Cancel | `n` / `esc` / button | `screens.py:ConfirmQuestionScreen.BINDINGS` |

### W04 — Workspace · 20 features

Reach: `1`, rail, startup screen. `app.py:_compose_screen_workspace`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `window_help.py:WindowHelpChip("workspace")` |
| 2 | Memory strip: whole-image one-row minimap | — | `app.py:update_memory_strip` |
| 3 | Loaded panel: three slots S19/HEX, MAC, A2L with name and counts | — | `screens_directionb.py:LoadedArtifactsPanel.render_slots` |
| 4 | Unload one artifact `[u]` | click | `screens_directionb.py:LoadedArtifactsPanel.on_button_pressed`, `app.py:on_loaded_artifacts_panel_unload_requested`, `_apply_unload` |
| 5 | Unload all `[U]` | click / `U` | `app.py:action_unload_all` |
| 6 | "Load project (p)" button | click | `app.py:on_button_pressed` (`ws_load_project_button`) |
| 7 | Workarea Files list; pick loads the file | Enter / click | `app.py:on_list_view_selected` → `_load_from_item` |
| 8 | Refresh the list | `r` | `app.py:action_refresh_files`, `refresh_files` |
| 9 | Open the workarea in the file manager | `o` | `app.py:action_open_workarea` |
| 10 | Data Sections list; pick jumps the hex view | Enter / click | `app.py:_jump_to_section` |
| 11 | Hex view | — | `app.py:update_hex_view` |
| 12 | Search ASCII text + Find Next | `/`, type, button | `app.py:_handle_search` |
| 13 | Goto 0xADDR + Goto (focus marker `>`) | `g`, type, button | `app.py:_handle_goto` |
| 14 | Hex page back / forward | `,` / `.` | `app.py:action_hex_page_prev/next` |
| 15 | Coverage Stats pane (coverage %, ranges, errors, warnings) | — | `app.py` (`#ws_stats`) |
| 16 | Context pane: A2L summary | — | `app.py:update_a2l_view` |
| 17 | Legend (example card only) | `k` | `app.py:action_show_legend`, `_SCREEN_LEGEND_SECTIONS` |
| 18 | Empty state with no file | — | `app.py:_apply_empty_state` |
| 19 | Focus lands on Workarea Files after a load | — | `app.py:_FOCUS_TARGETS`, `_rehome_focus_after_load` |
| 20 | Status line names the loaded image (and MAC/A2L coexistence) | — | `app.py:set_file_status`, `_format_coexistence_status` |

### W05 — A2L Explorer · 21 features

Reach: `2`, rail. `app.py:_compose_screen_a2l`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `window_help.py:WindowHelpChip("a2l")` |
| 2 | Tag table (Tag, Address, Length, Source, Raw, Physical, InMem, Region, Limits, Unit, Bits, Endian, Virt, Func, Access, …) with per-row severity colour | — | `app.py:_setup_datatable_columns`, `update_a2l_tags_view` |
| 3 | Filter tags (text, debounced) | type | `app.py:on_input_changed` → `_schedule_a2l_filter_refresh` |
| 4 | "Field: <name>" opens the filter-field menu (all, name, address, length, raw/physical value, source, in_memory, limits, unit, bits, endian, virtual, function_group, access, datatype, description, memory_region) | click | `app.py:_toggle_a2l_filter_menu`, `_set_a2l_filter_field` |
| 5 | Filter All | button | `app.py:on_button_pressed` (`a2l_filter_all`) |
| 6 | Filter Invalid | button | `app.py:on_button_pressed` (`a2l_filter_invalid`) |
| 7 | Filter In-Memory | button | `app.py:on_button_pressed` (`a2l_filter_inmem`) |
| 8 | Find in tag table + Find next | type, button | `app.py:_handle_a2l_tag_find_next`, `action_a2l_tag_find_next` |
| 9 | Page Prev / Page Next | buttons, `-` / `+`, PgUp/PgDn | `app.py:action_a2l_tags_page_prev/next`, `action_page_*_context` |
| 10 | Summary line under the table | — | `app.py` (`#a2l_tags_summary`) |
| 11 | Detail card follows the highlighted row | arrows | `app.py:on_data_table_row_highlighted` → `A2LDetailCard.show_tag` |
| 12 | Enter/click on a row jumps the hex pane and highlights the tag's bytes | Enter | `app.py:on_data_table_row_selected` → `_jump_to_tag_by_data` |
| 13 | Hex pane search ASCII + Find Next | `/` | `app.py:_handle_search_alt` |
| 14 | Hex pane Goto | `g` | `app.py:_handle_goto_alt` |
| 15 | Describe tag (CURVE/MAP point table) → W06 | `d` | `app.py:action_a2l_describe_tag` |
| 16 | Dump parsed A2L to `workarea\temp\<stem>.a2l.json` | `j` | `app.py:action_dump_a2l_json` |
| 17 | Legend (A2L rows) | `k` | `app.py:action_show_legend` |
| 18 | Large-A2L warning / slow-parse notice | — | `app.py:large_a2l_warn_bytes`, `slow_parse_warn_seconds` |
| 19 | Region column from A2L `MEMORY_SEGMENT` (flash/ram/unknown) | — | `a2l.py:extract_memory_segments`, `classify_address` |
| 20 | Hex paging of the pane | `,` / `.` | `app.py:action_hex_page_prev/next` |
| 21 | Focus lands on the tag table after a load | — | `app.py:_FOCUS_TARGETS` |

### W06 — Parameter description · 2 features

Reach: `d` on a highlighted A2L row. `a2l_describe.py:CurveDescriptionScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | "Parameter: <name>" — A2L metadata + decoded CURVE/MAP points from the image (scalar → honest "not a curve" header) | — | `a2l_describe.py:CurveDescriptionScreen.compose`, `app.py:describe_curve_tag` call |
| 2 | Close | `esc` / button | `a2l_describe.py:CurveDescriptionScreen.BINDINGS`, `on_button_pressed` |

### W07 — MAC View · 11 features

Reach: `3`, rail. `app.py:_compose_screen_mac`. (Not a `WindowSection`: no `?` chip; `?` opens the help panel.)

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Records table (Tag, Address, InA2L, InMem, Status, SourceLine, ParseErr, A2LMatch) | — | `app.py:_setup_datatable_columns`, `update_mac_view` |
| 2 | Coverage strip | — | `app.py:update_mac_view` (`#mac_coverage_strip`) |
| 3 | Page Prev / Page Next | buttons, `-` / `+` | `app.py:action_mac_records_page_prev/next` |
| 4 | Legend button | click / `k` | `app.py:on_button_pressed` (`mac_legend_button`) |
| 5 | Summary line | — | `app.py` (`#mac_records_summary`) |
| 6 | Enter/click a record jumps the hex pane | Enter | `app.py:_jump_to_mac_address` |
| 7 | MAC overlay highlight in the hex pane | — | `app.py:update_mac_hex_view` |
| 8 | Hex search ASCII + Find Next | `/` | `app.py:_handle_search_mac` |
| 9 | Hex Goto | `g` | `app.py:_handle_goto_mac` |
| 10 | Hex paging | `,` / `.` | `app.py:action_hex_page_prev/next` |
| 11 | Focus lands on the records table after a load | — | `app.py:_FOCUS_TARGETS` |

### W08 — Memory Map · 9 features

Reach: `4`, rail. `app.py:_compose_screen_map`, `screens_directionb.py:MemoryMapPanel`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `window_help.py:WindowHelpChip("map")` |
| 2 | Entropy band bar (code-like vs fill-like colouring) | — | `screens_directionb.py:MemoryMapPanel.render_ranges`, `BandBar` |
| 3 | Click a band run → inspect that region | click | `screens_directionb.py:BandSegment.on_click` |
| 4 | Ruler with absolute addresses | — | `screens_directionb.py:MapRuler` |
| 5 | Region list (address · size · band), arrows move focus | ↑ ↓ | `screens_directionb.py:RegionRow.on_key` |
| 6 | Single click / Enter → inspector (fields + 8-byte peek) | click / Enter | `screens_directionb.py:MemoryMapPanel.on_region_row_activated` |
| 7 | Double click → open the region in the Workspace hex view | double click | `MemoryMapPanel.OpenInHexRequested`, `app.py:on_memory_map_panel_open_in_hex_requested` |
| 8 | One-line stats strip | — | `screens_directionb.py:MemoryMapPanel` (stats strip) |
| 9 | Legend = entropy band key | `k` | `app.py:action_show_legend` (`view_key="map"`) |

### W09 — Issues Report · 10 features

Reach: `5`, rail. `app.py:_compose_screen_issues`, `issues_view.py:GroupedIssuesPanel`. (No `?` chip.)

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Filter "Issues: All" | button | `app.py:on_button_pressed` (`issues_filter_all`) |
| 2 | Filter Errors | button | `app.py:on_button_pressed` (`issues_filter_error`) |
| 3 | Filter Warnings | button | `app.py:on_button_pressed` (`issues_filter_warning`) |
| 4 | Legend button | click / `k` | `app.py:on_button_pressed` (`issues_legend_button`) |
| 5 | Severity strip | — | `app.py:update_validation_issues_view` |
| 6 | Grouped-by-severity list | — | `issues_view.py:GroupedIssuesPanel` |
| 7 | Click/Enter on an issue → Hex Peek pane | click / Enter | `issues_view.py:IssueRow.on_click/on_key`, `app.py:on_issue_row_selected` → `_update_issues_hex_pane` |
| 8 | Page | PgUp / PgDn | `issues_view.py:GroupedIssuesPanel.BINDINGS`, `app.py:action_validation_issues_page_prev/next` |
| 9 | Summary line | — | `app.py` (`#validation_issues_summary`) |
| 10 | Empty state | — | `app.py:_apply_empty_state` |

### W10 — Classification legend · 3 features

Reach: `k` anywhere; MAC and Issues "Legend" buttons. `screens.py:LegendScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Rows scoped to the active screen (A2L / MAC / Issues / Hex; full table where unmapped) | — | `app.py:_SCREEN_LEGEND_SECTIONS`, `action_show_legend` |
| 2 | Per-view example card; entropy band key on Map | — | `screens.py:LegendScreen.compose` (`view_key`) |
| 3 | Close | `esc` / button | `screens.py:LegendScreen.BINDINGS` |

### W11 — Patch Editor · 45 features

Reach: `6`, rail. `app.py:_compose_screen_patch`, `screens_directionb.py:PatchEditorPanel`;
actions routed by `app.py:on_patch_editor_panel_action_requested` (set `PATCH_ACTIONS_V2`).

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `WindowHelpChip("patch")` |
| 2 | "📂 Open patches/" chip (project `patches\` or common `workarea\patches\`; create-on-press when missing) | click | `open_folder_chip.py:OpenFolderChip("patch")` |
| 3 | Identity ribbon | — | `PatchEditorPanel._refresh_ribbon` |
| 4 | PATCH SCRIPT ledger (Kind, Address, Value / bytes, Status, Linkage) | arrows | `PatchEditorPanel._ENTRIES_COLUMNS`, `on_data_table_row_highlighted` |
| 5 | Tab chips Inspector / JSON / Checks | click, `space`, `enter` | `PatchEditorPanel._TABS`, `TabChip.BINDINGS` |
| 6 | BEFORE → AFTER bytes card (`--` = address not in image) | — | `screens_directionb.py:BeforeAfterCard` |
| 7 | Address field | type | `#patch_entry_address_input` |
| 8 | String field (document encoding) | type | `#patch_entry_value_input` |
| 9 | Bytes field (hex tokens) | type | `#patch_entry_bytes_input` |
| 10 | Add | button | `add_entry` |
| 11 | Edit | button | `edit_entry` |
| 12 | Remove | button | `remove_entry` |
| 13 | Edit JSON (Inspector tab) → W13 | button | `app.py:on_patch_editor_panel_entry_edit_json_requested` |
| 14 | DOCUMENT tally | — | `#patch_doc_tally` |
| 15 | JSON tab: loaded document read-only + stamp | — | `#patch_json_view`, `#patch_json_stamp` |
| 16 | Paste buffer with JSON highlighting + size gauge | type / paste | `json_highlight.py:JsonHighlightTextArea`, `#patch_paste_gauge` |
| 17 | Parse pasted | button | `parse_paste` |
| 18 | Edit JSON (JSON tab) → W12 | button | `app.py:on_patch_editor_panel_edit_json_requested` |
| 19 | History strip | — | `#patch_history_strip` |
| 20 | Undo | button / `^Z` | `app.py:action_patch_undo`, `on_patch_editor_panel_undo_requested` |
| 21 | Redo | button / `^Y` | `app.py:action_patch_redo`, `on_patch_editor_panel_redo_requested` |
| 22 | Scope: cycle variants for Execute scope | button | `#patch_execute_scope_button` |
| 23 | Execute scope (apply over chosen variants) + scope line | button | `execute_scope` → `app.py:_trigger_execute_scope` |
| 24 | Select variant | `v` (key bar, when variants exist) | `app.py:action_select_variant` → W23 |
| 25 | File dropdown "Change files in patches/" (pick loads at once) | select | `PatchEditorPanel.on_select_changed`, `app.py:on_patch_editor_panel_change_file_selected` |
| 26 | Typed path field | type | `#patch_doc_path_input` |
| 27 | Load (typed path) | button | `load_doc` → `app.py:_patch_editor_load` |
| 28 | Load over unsaved edits → W14 | — | `app.py:on_patch_editor_panel_dirty_load_requested` |
| 29 | Refresh file list | button | `refresh_doc` → `_prefill_patch_change_files` |
| 30 | Validate document against the image | button | `validate_doc` |
| 31 | Apply loaded changes | button | `apply_doc` |
| 32 | Save document as change-set file (project `patches\`/`checks\`, else common) | button | `save_doc`, `app.py:_change_doc_save_home` |
| 33 | Save patched image as: name field (suggested `<variant>-patched.s19/.hex`) | after Apply | `PatchEditorPanel.show_save_prompt` |
| 34 | Width 32 ⇄ 16 bytes/line | button | `#patch_saveback_width_button` |
| 35 | Write file | button | `app.py:on_patch_editor_panel_save_back_decision` |
| 36 | Don't save | button | same handler |
| 37 | Write before/after report (after a save) | button / `b` | `app.py:on_patch_editor_panel_before_after_report_requested`, `action_before_after_report` |
| 38 | Checks tab: declaration faults count + list | — | `#patch_doc_issue_count`, `#patch_doc_issues` |
| 39 | Run checks (needs a `kind: check` document) | button | `run_checks`, `PatchEditorPanel.refresh_check_results` |
| 40 | Check status + strip + result rows | — | `#patch_checks_status`, `#patch_checks_strip`, `#patch_checks_results` |
| 41 | Per-entry glyphs ✓ ✗ ◐ · | — | `PATCH_GLYPHS`, `#patch_legend` |
| 42 | Unsaved (dirty) flag tracked; cleared by Save | — | `PatchEditorPanel.mark_saved` |
| 43 | Status line for every result | — | `app.py:_report_change_result` |
| 44 | Legend (Hex rows) | `k` | `_SCREEN_LEGEND_SECTIONS["patch"]` |
| 45 | Unsupported save-back for MAC/A2L-only images named on the status line | — | `app.py:on_patch_editor_panel_action_requested` (`apply_doc` branch) |

### W12 — Edit change-set JSON · 3 features

Reach: Patch Editor JSON tab → "Edit JSON" (off for a document loaded from a file). `screens.py:ChangeSetJsonScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Full-size capped text editor seeded with the paste buffer | type | `capped_text_area.py:CappedTextArea` |
| 2 | Confirm | button | `screens.py:ChangeSetJsonScreen` (`changeset_json_confirm`) |
| 3 | Cancel | button / `esc` | `screens.py:ChangeSetJsonScreen.BINDINGS` |

### W13 — Edit entry JSON · 3 features

Reach: Patch Editor Inspector tab → "Edit JSON". `screens.py:EntryJsonScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Editor seeded with the highlighted entry as JSON | type | `screens.py:EntryJsonScreen.compose` |
| 2 | Confirm | button | `entry_json_confirm` |
| 3 | Cancel | button | `entry_json_cancel` |

### W14 — Unsaved changes will be lost · 3 features

Reach: Patch Editor Load while either editor region is dirty. `screens_directionb.py:LoadGuardScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Warning text | — | `LoadGuardScreen.compose` |
| 2 | Accept loss and load | button | `LoadGuardScreen.on_button_pressed` |
| 3 | Cancel (default focus) | button / `esc` | `LoadGuardScreen.action_cancel` |

### W15 — Check Editor · 24 features

Reach: `=`, rail. `app.py:_compose_screen_check_editor`, `screens_directionb.py:CheckEditorPanel`;
routed by `app.py:on_check_editor_panel_action_requested`, `on_check_editor_panel_spec_file_selected`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `WindowHelpChip("check_editor")` |
| 2 | "📂 Open checks/" chip (no project: common patches folder) | click | `OpenFolderChip("checks", id_suffix="editor")` |
| 3 | A2L PARAMETERS ledger | arrows | `#check_param_table` (`IncludeTable`) |
| 4 | Filter parameters | type | `#check_param_filter` |
| 5 | Include / exclude highlighted parameter | `space` / `enter` / button | `IncludeTable.BINDINGS`, `CheckEditorPanel.action_toggle_include` |
| 6 | Full name + address line of the highlighted row | — | `#check_full_name_line` |
| 7 | Tab chip Fields | click | `CheckEditorPanel._CARD_TABS` |
| 8 | Tab chip JSON (the spec document, read-only) | click | `#check_preview` |
| 9 | Tab chip Addendum (what the A2B diff report gains) | click | `#check_addendum_preview` |
| 10 | REPORT FIELDS lines (◆ parameter, ▪ memory row) | — | `#check_fields_lines` |
| 11 | MEMORY LOCATIONS table | — | `#check_mem_table` |
| 12 | Address field | type | `#check_mem_address_input` |
| 13 | Label field | type | `#check_mem_label_input` |
| 14 | Size (bytes) 1–8 | type | `#check_mem_size_input` |
| 15 | Add row | button | `#check_mem_add_button` |
| 16 | Remove row | button | `#check_mem_remove_button` |
| 17 | Spec dropdown "Check specs in patches/" | select | `CheckEditorPanel.on_select_changed` |
| 18 | Write as (file name) | type | `#check_file_name_input` |
| 19 | Validate against the image (verdicts under the form) | button | `validate_doc` |
| 20 | Write .chk.json | button | `write_doc` (`CHECK_EDITOR_ACTIONS`) |
| 21 | Apply ghost (struck through) + "never applied" hint | — | `#check_apply_ghost`, `#check_apply_hint` |
| 22 | Fields count | — | `#check_fields_count` |
| 23 | Glyph legend ✓ ◆ ▪ | — | `CHECK_GLYPHS`, `#check_legend` |
| 24 | Status line / hint | — | `#check_status` |

### W16 — Checks · 7 features

Reach: `9`, rail. `app.py:_compose_screen_checks`, `checks_view.py:GroupedChecksPanel`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `WindowHelpChip("checks")` |
| 2 | "📂 Open checks/" chip | click | `OpenFolderChip("checks")` |
| 3 | Aggregate strip Pass / Fail / Uncheckable | — | `app.py:update_checks_view` |
| 4 | Grouped-by-outcome list | — | `checks_view.py:GroupedChecksPanel`, `CheckGroupHeader` |
| 5 | Click/Enter a row → Hex Peek | click / Enter | `checks_view.py:CheckRow`, `app.py:on_check_row_selected` |
| 6 | Legend | `k` | `_SCREEN_LEGEND_SECTIONS["checks"]` |
| 7 | Empty state | — | `app.py:_apply_empty_state` |

### W17 — A2B Diff · 16 features

Reach: `7`, rail. `app.py:_compose_screen_diff`, `screens_directionb.py:AbDiffPanel`;
routed by `app.py:on_ab_diff_panel_compare_requested/report_requested/check_file_selected`. (No `?` chip.)

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | A: project variant dropdown or "(external path below)" | select | `#diff_select_a`, `app.py:_prefill_diff_variants` |
| 2 | External path A | type | `#diff_path_a` |
| 3 | B: dropdown | select | `#diff_select_b` |
| 4 | External path B | type | `#diff_path_b` |
| 5 | Check spec dropdown (appears when check specs exist) | select | `AbDiffPanel._make_check_row`, `app.py:on_ab_diff_panel_check_file_selected` |
| 6 | Compare | button | `app.py:on_ab_diff_panel_compare_requested` |
| 7 | Report (diff report; `## Checks` addendum when a spec is selected) | button | `app.py:on_ab_diff_panel_report_requested` |
| 8 | Report destination dir (no-project only) | type | `#diff_report_dest` |
| 9 | Status line | — | `#diff_status` |
| 10 | Run list of differing ranges | arrows | `#diff_range_list`, `AbDiffPanel.on_list_view_highlighted` |
| 11 | Image A / Image B hex windows | — | `#diff_hex_a`, `#diff_hex_b` |
| 12 | Window page + / − | `]` / `[` (focus in panel) | `AbDiffPanel.action_page_window_down/up` |
| 13 | Run-list overlay (fallback regime) | `f` | `AbDiffPanel.action_toggle_run_overlay` |
| 14 | Close overlay | `esc` | `AbDiffPanel.action_close_run_overlay` |
| 15 | Width/height regimes + size notice | resize | `AbDiffPanel.apply_regime`, `#diff_size_notice` |
| 16 | Legend (Hex rows) | `k` | `_SCREEN_LEGEND_SECTIONS["diff"]` |

### W18 — CRC Designer · 26 features

Reach: `0`, rail. `app.py:_compose_screen_crc_designer`, `crc_designer_view.py:CrcDesignerPanel`
(handlers `on_select_changed`, `on_input_changed`, `on_switch_changed`, `on_button_pressed`).
Preview-only: it never writes firmware (`CrcDesignerPanel._save_template` docstring, US-V8).

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `WindowHelpChip("crc_designer")` |
| 2 | "📂 Open templates/" chip | click | `OpenFolderChip("templates")` |
| 3 | Preset dropdown | select | `#crc_preset_select` |
| 4 | Width (bits) | type | `#crc_field_width` |
| 5 | Polynomial | type | `#crc_field_poly` |
| 6 | Init | type | `#crc_field_init` |
| 7 | Reflection in (switch) | toggle | `#crc_field_refin` |
| 8 | Reflection out (switch) | toggle | `#crc_field_refout` |
| 9 | XOR out | type | `#crc_field_xorout` |
| 10 | Check value | type | `#crc_field_check` |
| 11 | Self-test `123456789` verdict MATCH / mismatch | — | `#crc_kat_verdict` |
| 12 | Coverage ranges | type | `#crc_coverage_ranges` |
| 13 | Intra gap | select | `#crc_coverage_intra_gap` |
| 14 | Join gaps | select | `#crc_coverage_join` |
| 15 | Pad byte | type | `#crc_coverage_pad_byte` |
| 16 | On conflict | select | `#crc_coverage_on_gap_conflict` |
| 17 | Coverage preview + live coverage window | — | `#crc_coverage_preview`, `#crc_coverage_window` |
| 18 | Store placement: Address | type | `#crc_field_output_address` |
| 19 | Store placement: Bytes | type | `#crc_field_store_width` |
| 20 | Store endianness | select | `#crc_field_store_endianness` |
| 21 | Custom test vector: mode, vector, CRC result | select / type | `#crc_custom_vector_mode`, `#crc_custom_vector`, `#crc_custom_vector_result` |
| 22 | Template name + aliases | type | `#crc_field_name`, `#crc_field_aliases` |
| 23 | Template JSON preview | — | `#crc_json_preview` |
| 24 | Save template (`<project>\templates\` or common `.s19tool\templates\`) | button | `CrcDesignerPanel._save_template` |
| 25 | Load path + Load | type, button | `CrcDesignerPanel._load_template` |
| 26 | Warnings tile + load/save status | — | `#crc_warnings`, `#crc_loadsave_status` |

### W19 — Operations · 8 features

Reach: `x` (needs a loaded file; else one status line). `app.py:action_operations_view`, `screens.py:OperationsScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Operations list: `crc`, `extract`, `split_by_segment` | arrows | `operations/registry.py:_REGISTRY` |
| 2 | Config file path field | type | `#operation_config_path` |
| 3 | Load config | button | `#operation_config_load` |
| 4 | CRC config editable JSON (prefilled example) | type | `#operation_config` (`DUMMY_CONFIG_TEXT`) |
| 5 | Execute (computes, shows status + result hex) | button | `#operations_execute`, `OperationsScreen._present_result` |
| 6 | Write CRC (enabled only after a real check) → W20 | button | `OperationsScreen._on_write_pressed` |
| 7 | Close | button | `#operations_close` |
| 8 | `extract` / `split_by_segment` are placeholders (no real effect) | select | `operations/placeholders.py` |

### W20 — Confirm CRC write · 3 features

Reach: Operations → Write CRC. `screens.py:ConfirmWriteScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Width 32 ⇄ 16 bytes/line | button | `#confirm_write_width` |
| 2 | Confirm (writes a new modified S19 under the work area) | button | `screens.py:OperationsScreen._on_confirm_write` → `_run_crc_write_worker` |
| 3 | Cancel | button | `#confirm_write_cancel` |

### W21 — Split / Join / Export · 17 features

Reach: palette only — `^K` → "Split / Join / Export" (no rail key). `app.py:action_open_split_join_export`,
`segment_split_view.py:SplitJoinWindow`. Window keys work while focus is inside it.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `WindowHelpChip("split_join_export")` |
| 2 | Source tabs A2L segments / image ranges / manual | `t` | `SplitJoinWindow.action_cycle_tab`, `TABS` |
| 3 | Range table with cursor | ↑ ↓ / `k` `j` | `SplitJoinWindow.action_move`, `_SegTable.BINDINGS` |
| 4 | Tick / untick a range | `space` | `SplitJoinWindow.action_toggle_row` |
| 5 | Tick all | `a` | `SplitJoinWindow.action_select_all` |
| 6 | Tick none | `n` | `SplitJoinWindow.action_select_none` |
| 7 | Manual localities editor (`0xSTART-0xEND` per line) | type | `#sje_manual`, `on_text_area_changed` |
| 8 | Mode split ⇄ join | `m` | `SplitJoinWindow.action_toggle_mode` |
| 9 | Gap policy (split: skip/fill; join: concat/fill) | `g` | `SplitJoinWindow.action_cycle_gap` |
| 10 | Format S19 / HEX / BIN | `f` | `SplitJoinWindow.action_cycle_format` |
| 11 | Pad byte 0x00 ⇄ 0xFF | `p` | `SplitJoinWindow.action_cycle_pad` |
| 12 | Destination project ⇄ common | `d` | `SplitJoinWindow.action_cycle_dest` |
| 13 | Naming pattern + live sample filename | — | `segment_split_view.py:_chips_naming` |
| 14 | Output band, per-file gantt, legend, ruler, stats, summary | — | `_BandBar`, `_GanttBar`, `_RulerBar` |
| 15 | Export (refuses on conflicts; two-step confirm for span guard / empty files) | `e` / button | `SplitJoinWindow.action_export` |
| 16 | Close back to the previous screen | `esc` | `SplitJoinWindow.action_close_window` |
| 17 | Coverage column warns when a range has no source bytes | — | `segment_split_view.py` (`∅ empty — 0 B of source in span`) |

### W22 — Save project · 7 features

Reach: `^S` / `s` (needs a loaded file or A2L; else one status line). `app.py:action_save_project`, `screens.py:SaveProjectScreen`, `app.py:_handle_save_dialog`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Project name (prefilled with the open project) | type | `#project_name` |
| 2 | Where line (target folder or refusal reason) | — | `#save_where`, `app.py:_save_dialog_preview` |
| 3 | Plan summary (what will be gathered into the folder) | — | `#save_summary` |
| 4 | Project-wide batch files selection (multi-variant re-save) | toggle | `#assign_batch` |
| 5 | Per-variant file assignment | toggle | `#assign_<n>` |
| 6 | Save | `alt+s` / button | `SaveProjectScreen.BINDINGS`, `app.py:_confirm_project_save` |
| 7 | Cancel | `esc` / button | `SaveProjectScreen.BINDINGS` |

### W23 — Select variant · 3 features

Reach: `v` (with a multi-variant project), or W02 "Select variant (v)". `app.py:action_select_variant`, `screens.py:SelectVariantScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Variant list, "(active)" marker | arrows | `SelectVariantScreen.compose` |
| 2 | Activate (switch the loaded image; asks W03 over unsaved work) | button | `app.py:_handle_select_variant` |
| 3 | Cancel | button | `#variant_cancel` |

### W24 — Reports viewer · 10 features

Reach: `t` (needs an active project; else one status line). `app.py:action_view_reports`, `screens.py:ReportViewerScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `WindowHelpChip("reports")` |
| 2 | "📂 Open reports/" chip | click | `OpenFolderChip("reports")` |
| 3 | Report list `reports\*.md`, newest first (or empty state) | arrows | `list_project_reports` |
| 4 | Markdown view of the picked report | pick | `#report_markdown` |
| 5 | Declared regions (`name,start,end` per line), prefilled from the A2L | type | `#report_declared_regions` |
| 6 | Filter dropdown (`filters\*.json`) | select | `app.py:on_report_viewer_screen_filter_selected` |
| 7 | Filter path (blank = full report) | type | `app.py:on_report_viewer_screen_filter_path_typed` |
| 8 | Context bytes | type | `#report_context_bytes` |
| 9 | Generate new report (`.md` + `.html` pair) | button | `app.py:on_report_viewer_screen_generate_requested` |
| 10 | Close | button | `#report_close` |

### W25 — Flow Builder · 37 features

Reach: `8`, rail. `app.py:_compose_screen_flow`, `flow_screens.py:FlowBuilderPanel`;
routed by `app.py:on_flow_builder_panel_run_requested/save_requested/load_requested`.
Project-only for Run, Save and Load.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `WindowHelpChip("flow")` |
| 2 | "📂 Open flows/" chip | click | `OpenFolderChip("flows")` |
| 3 | Pipeline of block cards joined by cables | — | `flow_screens.py:pipeline_text` |
| 4–10 | Kind chips LOAD ◉, PATCH ▣, CHECK ✓, CRC ⊕, WRITE-OUT ▼, A2B-DIFF ⏚, EXT-STEP » (7) | click / `space` | `FlowBuilderPanel._KIND_OPTIONS`, `KindChip` |
| 11 | Kind dropdown (mounted but hidden; the kind chips replace it) | — | `#flow_kind`, `FlowBuilderPanel.on_mount` (`display = False`) |
| 12 | Ref field (image file / change doc / check doc / CRC template / output file) | type | `#flow_ref` |
| 13 | Gating advisory ⇄ block-own-op (CHECK) | select | `#flow_gating`, `_GATING_OPTIONS` |
| 14 | Image A (file or `#n`) | type | `#flow_ref_a` |
| 15 | Image B | type | `#flow_ref_b` |
| 16 | External mode Terminal ⇄ Manual | select | `#flow_ext_mode` |
| 17 | Command / instruction | type | `#flow_ext_instruction` |
| 18 | Log file (required) | type | `#flow_ext_log` |
| 19 | Output file | type | `#flow_ext_output` |
| 20 | + Add (errors named above Run) | button | `FlowBuilderPanel.on_button_pressed` |
| 21 | Copy block # field | type | `#flow_pick` |
| 22 | Copy | button | `#flow_copy` |
| 23 | Paste | button | `#flow_paste` |
| 24 | Clipboard status | — | `#flow_clip_status` |
| 25 | Variables (N) toggle | button | `#flow_funnel_toggle` |
| 26 | Variable name | type | `#flow_funnel_name` |
| 27 | Variable value | type | `#flow_funnel_value` |
| 28 | + Add var | button | `#flow_funnel_add` |
| 29 | Variables list | — | `#flow_funnel_list` |
| 30 | Wiring notice | — | `#flow_wiring_notice` |
| 31 | Run (single loaded image; needs a project) | button | `app.py:on_flow_builder_panel_run_requested` |
| 32 | Clear | button | `#flow_clear` |
| 33 | Save… → W26 | button | `app.py:on_flow_builder_panel_save_requested` |
| 34 | Load… → W27 (W28 first if unsaved) | button | `app.py:on_flow_builder_panel_load_requested` |
| 35 | Result area: per-block verdict ● ◈ ✗ ○ □, NOTICES / ISSUES | — | `#flow_result` |
| 36 | saved / unsaved marker | — | ribbon |
| 37 | Glyph legend | — | `flow_legend_text` |

### W26 — Save flow as · 4 features

Reach: Flow Builder Save…. `screens.py:SaveFlowScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Name field (letters, numbers, - _) | type | `#flow_save_name` |
| 2 | Overwrite notice | — | `#flow_overwrite_notice` |
| 3 | Save (`flows\<name>.json`) | button | `flow_save_ok` |
| 4 | Cancel | button | `flow_save_cancel` |

### W27 — Load flow · 5 features

Reach: Flow Builder Load…, Flow Execution Import…. `screens.py:LoadFlowScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | List of saved flows | arrows | `#flow_list` |
| 2 | Import… (native file dialog; copies into `flows\`) | button | `LoadFlowScreen._import_external` |
| 3 | Import status line | — | `#flow_import_status` |
| 4 | Load | button | `flow_load_ok` |
| 5 | Cancel | button | `flow_load_cancel` |

### W28 — Discard unsaved flow edits? · 2 features

Reach: Flow Builder Load… with unsaved blocks. `screens.py:ConfirmDiscardScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Discard | button | `flow_discard_ok` |
| 2 | Cancel | button | `flow_discard_cancel` |

### W29 — Flow Execution · 17 features

Reach: `]`, rail. `app.py:_compose_screen_flow_execution`, `flow_screens.py:FlowExecutionPanel`;
routed by `app.py:on_flow_execution_panel_*`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | `?` help chip | click / `?` | `WindowHelpChip("flow_execution")` |
| 2 | "📂 Open session" chip | click | `OpenFolderChip("session")` |
| 3 | Name strip (set name, saved / unsaved) | — | `#fx_name_strip` |
| 4 | Import… a lane from a saved flow → W27 | button | `app.py:on_flow_execution_panel_import_requested` |
| 5 | Mode sequential ⇄ parallel | click / `enter` / `space` | `flow_screens.py:ModeToggle` |
| 6 | Run all lanes, one chain-set report | button | `app.py:on_flow_execution_panel_run_requested` |
| 7 | Set name | type | `#fx_set_name` |
| 8 | Save Set (`flowsets\<name>.json`) | button | `app.py:on_flow_execution_panel_save_requested` |
| 9 | Saved sets dropdown | select | `#fx_set_select` |
| 10 | Load Set | button | `app.py:on_flow_execution_panel_load_set_requested` |
| 11 | Lanes: cards + cables with state glyphs ▓ ░ ✗ ◇ □ ▪ | arrows scroll | `#fx_lanes` |
| 12 | Per-lane image file field | type | `fx_bind_<lane>_<n>` input |
| 13 | Bind | button | `fx_bind_<lane>_<n>` |
| 14 | Confirm an external step | button / `c` | `app.py:on_flow_execution_panel_external_step_confirmed`, `action_confirm_attention` |
| 15 | REQUIRED line naming the waiting lane | — | `#fx_required` |
| 16 | Run log (newest 8 lines) | — | `#fx_log` |
| 17 | Glyph legend | — | `fx_legend_text` |

### W30 — Window help · 3 features

Reach: `?` chip or `?` with focus in a window that has a section (workspace, a2l, map, patch, check_editor, checks, crc_designer, flow, flow_execution, reports, split_join_export). `window_help.py:WindowHelpScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Numbered steps for the window + that window's keys block | — | `window_help.py:section_body_text`, `window_keys_text` |
| 2 | Scroll | ↑ ↓ PgUp PgDn Home End | `WindowHelpScreen.BINDINGS` |
| 3 | Close | `esc` / button | `WindowHelpScreen.action_close_window_help` |

### W31 — Quit? · 2 features

Reach: `q` while a load or save runs (otherwise `q` quits at once). `app.py:action_quit` → `_QuitQuestionScreen`.

| # | Feature | How | Code proof |
|---|---|---|---|
| 1 | Quit after the action ends | `y` / button | `app.py:_answer_quit`, `_exit_if_quit_pending` |
| 2 | Keep working | `n` / `esc` / button | `screens.py:ConfirmQuestionScreen.BINDINGS` |

Feature total: 30+14+4+3+20+21+2+11+9+10+3+45+3+3+3+24+7+16+26+8+3+17+7+3+10+37+4+5+2+17+3+2 = **372** (counted from the table rows).

---


## 5. Findings for the release fix

Queued for a fix increment; no product code was edited. "Live" = seen in the running
app during the captures; "code" = read in the code.

| ID | Kind | Finding | Evidence |
|---|---|---|---|
| F-01 | defect, live + code | The Patch Editor (dropdown or typed Load) and the Check Editor (Spec dropdown) parse change/check documents without the loaded A2L, so every entry with a `symbol` is refused (`CHG-SYMBOL-UNRESOLVED … no A2L context is declared`) even with the A2L loaded. The case documents `demo_patch.changes.json`, `demo_check.chk.json`, `demo_check_fails.chk.json` cannot be used as delivered. Project Execute scope does resolve them. | `app.py:_patch_editor_load` calls `service.load(path_text, self.base_dir)` with no `a2l_context`; ch08-02, ch08-03 |
| F-02 | known defect, live | Clean A2L reports 102 `A2L_UNRECOGNIZED_BLOCK` for `MOD_PAR`, `MOD_COMMON`, `AXIS_DESCR` (shown as Info); the Info heading cites an internal "Cambio4 triage". | ch07-01 |
| F-03 | defect, live | Issues **Warnings** filter also lists the 102 Info rows (379 rows); the legend says Info rows appear only under All. | ch07-05, ch07-07 |
| F-04 | usability, live | After **Apply loaded changes** on the Inspector tab, the "Save patched image as" prompt appears only on the JSON tab; nothing on the visible tab says so. | ch08-07, ch08-08 |
| F-05 | usability, live · fixed in 1.0.0 | The "Before/after report ready — press b" notice appears without a project; `b` then refuses (needs a project). | ch08-09, ch08-10 |
| F-06 | defect, code · fixed in 1.0.0 | The Patch Editor file dropdown always lists the common `workarea\patches\`, while Save writes into the project's `patches\` / `checks\` when a project is open, so a saved document does not appear in the dropdown. | `app.py:_patches_dir`, `_change_doc_save_home` |
| F-07 | usability, live | Data-section jump, Find Next and Goto load the right window but do not scroll the hex pane to the target row; at 118×54 the target is often below the visible rows (Workspace, MAC). | ch03-02…04 (scrolled by the driver), ch05-04 |
| F-08 | layout, live | At 118 columns the Workspace, A2L and MAC-less hex search/goto fields and the A2L filter field are 1–3 cells wide; typed text is not readable. | ch03-01, ch04-01 |
| F-09 | layout, live | A2L tag table columns run together (`cell_padding=0`): `0x00803DE064` is address + length. | ch04-01 |
| F-10 | layout, live | A2L filter row overflows at 118 columns: In-Memory, the find field and the page buttons are cut off. | ch04-01 |
| F-11 | layout, live | MAC View at 118 columns: the record table shows only Tag and a clipped Address, and the Page Prev / Page Next / Legend buttons collapse to an invisible bar; the window has no title bar or `?` chip. | ch05-01 |
| F-12 | layout, live | Workspace Loaded panel shows only the PROJ and S19 lines at 118×54; the MAC and A2L slots and `[U]` are clipped. | ch03-01 |
| F-13 | defect, live | The status line keeps "Loaded firmware.mac (S19+MAC)" after `[u]` and `U`. | ch03-06, ch03-07 |
| F-14 | defect, live | After an unload and after closing Split / Join, keyboard focus is left on a hidden Split / Join widget (`sje_table`, `sje_manual`). | driver log of Chapters 3 and 14 |
| F-15 | defect / performance, live | Memory Map: on first show the region list (118 cols) or band bar and list (220 cols) are blank until a key is pressed; the demo image builds 6365 band and region widgets and each keypress took several seconds. | ch06-01, ch06-01-map-wide |
| F-16 | help mismatch, live + code · fixed in 1.0.0 | Map legend "Map keys: ↑↓ / j k select · ↵ open hex": `j`/`k` are not handled by region rows and Enter only inspects. | ch06-05; `screens_directionb.py:RegionRow.on_key` |
| F-17 | layout, live | "Unsaved changes will be lost" dialog: buttons squeezed top-left in an oversized box. | ch08-18 |
| F-18 | defect, live | Split / Join: the `t` that switches to the manual tab is also typed into the manual box. | driver log (`manual box after t: 't'`) |
| F-19 | defect, live | **Viewer settings cannot be closed**: open from the palette, then pick a row, `esc`, open the entry again, switch windows, change density — the menu stays on screen in all cases (`_toggle_settings_menu` is never called). | ch19-06…09; driver log |
| F-20 | key conflict, live | `]` with the focus inside the A2B Diff panel pages the hex windows (screen stays on Diff); with the focus outside the panel `]` opens Flow Execution. The panel's code comment still says `]` is not an app binding. | ch09-05; driver log |
| F-21 | cosmetic, live | Describe CURVE prints `(index (axis points unavailable))` on every row. | ch04-06 |
| F-22 | usability, live | Patch Editor **Save** writes `changes.json` without asking for a name. | ch08-17 |
| F-23 | performance, live | With the 10 MB image: each CRC Designer field edit took about 10 s; loading a template with a 1.2 MiB coverage took about 2 min; Split / Join join-fill previews took about 25 s; the UI does not respond meanwhile. | driver timestamps |
| F-24 | defect, live | CRC Designer says "Load an image to preview coverage CRCs over real bytes" with an image loaded, until a field changes. | ch12-01 |
| F-25 | defect, live | A2B Diff: the A and B variant dropdowns are not painted at 118 or 220 columns; only the external-path fields are visible (the captures set the dropdown value directly). | ch09-01, ch09-08 |
| F-26 | defect, live | Check Editor: after **Write .chk.json** the collector shows `1 field: 0 params` and the ledger loses its ✓ marks, though the file holds all fields. | ch10-07 |
| F-27 | defect, live | Check Editor: reloading a written spec brings parameters back as unlabelled memory rows; parameter names and labels are lost. | ch10-08 |
| F-28 | defect, live · fixed in 1.0.0: the block names the cause when it refuses a Designer template; it does not read Designer templates | Flow CRC block cannot read a template saved by the CRC Designer: `crc config invalid: CRC config is structurally invalid: 'reverse'`. | ch17-05 |
| F-29 | defect, live | Split / Join A2L source shows `a2l(0)` although the loaded A2L declares four `MEMORY_SEGMENT`s. | ch14-02 |
| F-30 | help mismatch, live · fixed in 1.0.0 | Reports "Declared regions" stays empty with the A2L loaded; the help says it pre-fills from the A2L. | ch16-01 |
| F-31 | placeholder, live + code | Operations `extract` and `split_by_segment` are listed but return "placeholder — not yet implemented". | ch13-06; `operations/placeholders.py` |
| F-32 | layout, live | CRC Designer bench is taller than 54 rows; Store placement, Custom vector, Template and Load / Save are below the fold. | ch12-04, ch12-05 |
| F-33 | unreachable, code | `screens.py:VariantHelpScreen` is never opened. | no call site |
| F-34 | unreachable, code | `app.py:action_view_main`, `action_view_mac` have no key and no palette entry (`action_view_alt` only internal). | `app.py` |
| F-35 | dead widget, code | Hidden widgets kept mounted: Check Editor "Addendum preview" button, Flow Builder kind dropdown `#flow_kind`. | `CheckEditorPanel.compose`, `FlowBuilderPanel.on_mount` |
| F-36 | limitation, code | Flow "report" block cannot be added from the builder; it appears only if a loaded flow file carries one. | `FlowBuilderPanel._KIND_OPTIONS` |
| F-37 | help mismatch, code + live · fixed in 1.0.0 | In-app help text that the app does not do: Split / Join "pick the source image … or browse" and an editable naming pattern; A2L "section tree" and "`/` jumps to a name"; Checks "table" and "grouped by reason"; CRC Designer "coverage over the image's real ranges"; Workspace "folders.html board"; Reports pre-filled regions (F-30); Map keys (F-16). | `window_help.py:WINDOW_HELP_SECTIONS`; ch19-01 |
| F-38 | doc mismatch, code · fixed in 1.0.0 | README says 10 screens on keys 1–0 and a one-row footer; the app has 12 rail windows (`=` Check Editor, `]` Flow Execution), the palette-only Split / Join / Export and a two-row key bar. | `README.md` |
| F-39 | defect, live | Issues grouped list shows the INFO group before the WARNING group (clean and faulty files); the legend states error → warning → info. | ch07-01, ch07-02 |
| F-40 | defect, live · fixed in 1.0.0 | Patch Editor Checks tab keeps the results of an earlier check run after another document or a project is loaded. | ch08-20 |
| F-41 | help mismatch, live + code · fixed in 1.0.0 | Reports → **Generate new report** writes Markdown only (`<time>-report.md`); the Reports help says it writes the `*.md` + `*.html` pair. | ch21-12; `report_service.py` (`-report.md` only) |
| F-42 | defect, live · fixed in 1.0.0 | The before/after report is titled "Diff report" in both `.md` and `.html`; its header shows `a2l=absent; mac=absent` and the Runs *Symbols* column stays `-` although the A2L is loaded and the linkage table names the symbols. | ch21-02 |
| F-43 | limitation, live | The diff report's `## Checks` addendum lists the declared fields with expected bytes only — no actual value and no pass/fail verdict. | ch21-06 |
| F-44 | limitation, code + live | The flow report (REPORT block, FB-P1b), the fused flow report and the chain-set report are Markdown only; the only HTML reports are the before/after and diff reports. | `flow_report_service.py`, `flow_execution_service.py:write_chain_set_report`; ch21-11 |
| F-45 | defect, live · fixed in 1.0.0 | After **Confirm** of an external step in a parallel run, the re-run writes a second chain-set report for that lane alone that records *Mode: sequential*, *Chains: 1*. | `reports\<time>-chain-set-report.md` of the Chapter 18.8 run |
| F-46 | defect, live · fixed in 1.0.0 | A flow saved after **Clear** keeps the previous flow's name inside its file (`flows\tune_b.json` holds `"name": "tune_a"`, `tune_c.json` holds `tune_b`); lanes use the file name, so the stale name is only cosmetic so far. | saved flow files of the Chapter 17.10 run |
| F-47 | to investigate, live · carried to backlog (not reproduced on the base) | In the Chapter 17.10 / 18.8 run the log tail shows *Before/after report refused: No applied change summary…* right after start, before any key the driver sent that maps to `b`; the trigger is not identified. | ch17-13 … ch18-09 |
| F-48 | gap, code + live | A later block cannot reference an external step's output: there is no `#n` reference, binding or `${NAME}` for it. The only way is to type the copy's file name as an ordinary project-relative ref (17.11). The block's docstring says "downstream blocks reference THAT copy". | `flow_model.ExternalStepBlock`, `flow_execution_service.run_flow` (`ExternalStepBlock` branch); ch18-17 |
| F-49 | defect, live · fixed in 1.0.0 | When a later run's external output differs, the copy is stored as `<name>_1.<ext>` (no overwrite) but a later block that names the copy still reads the first file: `terminal_out.s19` kept `BENCH=OK` after the step produced `BENCH=V2`. | driver log of the 18.9 run (`step_patch.changes_1.json` written, `terminal_out.s19` unchanged) |
| F-50 | limitation, live + code | The Flow Builder pauses at an external step (*PAUSED – WAITING FOR A HUMAN*) but offers no Confirm; the run can only continue from Flow Execution. In Terminal mode the app never runs the command and does not see its exit code — only the existence of the log and output files is checked. | `app.py:on_flow_builder_panel_run_requested` (`FlowContext` without confirmations); ch17-18, ch18-16 |
| F-51 | usability, live | `esc` does not close the Reports viewer; only **Close** does (its bindings hold `?` only). | `screens.py:ReportViewerScreen.BINDINGS`; driver log of the 18.9 run |

## 6. Live checks requested

| Check | Result |
|---|---|
| `]` in A2B Diff | Focus on the Compare button (inside the panel): `]` paged both hex windows, active window stayed `diff`. Focus on the rail: `]` switched to `flow_execution`. Both from the same live run (driver log, 15:49:35 and 15:49:38). The panel binding wins inside the panel; the app binding wins elsewhere. |
| Viewer settings close | Opened from `^k` → Viewer settings. After picking *Hex rows: 50* the menu stayed open; after `esc` it stayed open with the focus on the list; opening the palette entry again and switching to another window (`1`) left it open; it was still open after `^d`. No way to close it was found (F-19). |

## 7. Inputs used

| Input | From | Used in |
|---|---|---|
| `firmware.s19`, `firmware.hex`, `firmware_v2.s19`, `firmware.a2l`, `firmware.mac` | case 08 | all chapters |
| `firmware_issues.a2l`, `firmware_issues.mac` (faulty variant) | case 08 | Chapter 7 only |
| `demo_patch.changes.json`, `demo_check.chk.json`, `demo_check_fails.chk.json` | case 08 | Chapter 8 (refused, F-01), Chapter 9 (dropdown), project batch assignment |
| `guide_patch_nosym.changes.json` | written for the guide: `demo_patch.changes.json` without its two `symbol` entries | Chapters 8, 17, 18 |
| `guide_check_mixed.chk.json` | written for the guide: the case check entries without `symbol`, plus `BUILD_ID=SYNTH_9999` at `0x00C00118` (fails) and 2 bytes at `0x00500000` (outside the image) | Chapters 8, 9, 11, 17 |
| project `demo` | assembled for the guide: the four case files plus a minimal `project.json` (Chapter 8 adds a batch assignment) | Chapters 2, 8, 9, 15–18 |
| CRC config in Operations | typed for the guide (CRC-32 over `0x00C00000–0x00C00FF0`, stored at `0x00C00FFC`) | Chapter 13 |
| flows `demo_flow`, `bench_a`, `bench_b`, set `bench_set` | built in the app during the captures | Chapters 17, 18 |
