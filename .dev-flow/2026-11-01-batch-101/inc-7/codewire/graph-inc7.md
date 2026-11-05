# Code-Wire graph — Inc 7 (before/after report names itself; whole hex windows; inert Markdown text), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`), corrected after E3 round 1 (`../E3-rulings.md`; changed lines carry the finding id in brackets). Graph only: no stub, mark or declaration in any tree. Base `e266395`. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1, as in `../../inc-2/codewire/graph-inc2.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …") or **new**. Context nodes (unchanged) are here because a changed node calls them or a row depends on them staying as they are.
- Example sources are the test-case ids of `02-test-cases.md` (`R-CMP-004.14/1`); `B` = a probe of the base tree run at E1 from the session scratchpad (read-only, the worktree's package imported by path). Every example states the Inc 7 target unless it says "holds on base" or "base:".
- `«…»` shows a Markdown string exactly, backslashes included. `·` stands for U+0001, `¤` stands in for U+0085 (C1) and `<RLO>` for U+202E (right-to-left override); neither real character is written in this file. `�` is U+FFFD.

Groups for E4 (file ownership) and the interfaces they share — pinned here, changed only by an orchestrator ruling:

| Group | File | Owns nodes |
|---|---|---|
| G1 report generators | `s19_app/tui/services/diff_report_service.py` | `_md_text`, `_md_path`, `_run_symbol_names`, `_annotate_run`, `_window_rows`, `_image_line`, `_header_lines`, `_run_table_lines`, `_provenance_lines`, `_linkage_table_lines`, `_flow_change_attribution_lines`, `flow_change_census_complete`, `_audit_header_lines`, `_html_header`, `generate_diff_report`, `generate_diff_report_html`, `_strip_ctl`, `_html_run_rows`, `_write_report` [S-2, S-3] |
| G2 composer | `s19_app/tui/services/before_after_service.py` | `compose_before_after_report` |
| G3 app (O-1) | `s19_app/tui/app.py` | `action_before_after_report`, `_start_before_after_worker`, `_start_diff_report_worker` [S-3] |
| G4 flow-A2B producer (O-2) | `s19_app/tui/services/flow_execution_service.py` | `run_flow` (A2B external arm only) |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 composer inputs | `compose_before_after_report(summary, loaded_path, *, project_dir, workarea, now_fn=None, report_filter=None, a2l_data: Optional[dict] = None, a2l_records: Optional[Sequence[dict]] = None, mac_records: Optional[Sequence[dict]] = None) -> BeforeAfterReportResult`. `a2l_data` and `mac_records` always go to `compare_images` (its own `None` defaults = today); `a2l_records` and `mac_records` join the generator kwargs only when not `None` | G3 → G2 |
| I-2 generator signatures | `generate_diff_report` / `generate_diff_report_html`: **unchanged**. The title is `"Before/after report"` when `provenance is not None`, else `"Diff report"` (D-1) | G1 → G2, `app.py` A↔B report, G4 |
| I-3 raw values in, escaping at the sink | `ImageRef.label`, `.variant_id`, `.path`, every linkage / flow-attribution symbol and document reference, and the filter display name reach the generators **raw**; the generators alone write them as report-safe text / path text (D-5). Producers must not pre-escape | G2, G4, `app.py` A↔B → G1 |
| I-4 app → worker | gathered on the UI thread in `action_before_after_report`: `a2l_data = self.current_a2l_data`; `a2l_records = self._compute_a2l_enriched_tags() or None`; `mac_records = loaded.mac_records if loaded is not None and loaded.mac_path is not None else None`; passed to `_start_before_after_worker(..., a2l_data=, a2l_records=, mac_records=)` (keyword-only, after `gen`) | G3 internal |
| I-5 row format | `0x{base:08X}  {16 cells joined by " "}  \|{16 ASCII cells}\|`, cell `{b:02X}` or two spaces; ASCII `chr(b)` for 0x20 … 0x7E else `.` — byte-identical to `render_hex_view`'s rows | G1 internal (`_window_rows`: the rows `render_hex_view` writes, `hexview.py:273-276`; not `_html_hex_row`'s, which shows an unmapped ASCII cell as a space) [F-E3-5] |

Interfaces with other increments:

| With | What | Rule |
|---|---|---|
| Inc 2 (PR #212) | the batch35 goldens get `Tool version: <TOOL-VERSION>` | Inc 7 rebases on main after Inc 2 merges; its golden lines (title, labels) differ from Inc 2's |
| Inc 6 | `app.py:action_before_after_report` (F-47 breadcrumb, F-05); D14-14 string in `before_after_service.py:318` | O-1, O-3: Inc 7 merges first, or Inc 6 rebases; the string goes with whichever owner the orchestrator names |
| Inc 8, Inc 9 | `flow_execution_service.run_flow` (CRC block, external outputs, re-run) | O-2: Inc 7 touches only lines `:981-988` of the A2B arm |
| Inc 3 … 5 | other `app.py` functions | disjoint functions |
| Inc 14 | guide ch21 text describing F-42 | docs follow after the fix |
| I-6 report file write [S-3] | `_write_report(target: Path, text: str) -> None`: `<target>.<16 random hex>.part` created exclusively (E5 C-1), written UTF-8, `os.replace` onto `<target>`; on any exception the `.part` file is removed and the exception re-raised | G1 → both generators |
| I-7 visible text [S-2] | `_strip_ctl(value) -> str` = `markdown_safety._normalise(str(value))`: tab/CR/LF → space; Cc, Cf, Cs, Zl, Zp → `�`. Every HTML sink of a label field, path field, refusal message, provenance or linkage value calls it before `_esc`; `md_safe`/`md_code` apply the same steps on the Markdown side | G1 internal |
| D16-15 (open) | `run_flow` runs on the UI thread; the flow-A2B report's whole windows cost ~1.3 s per MiB there | OBS-7-5, admitted limit [F-E3-3] |

## Nodes — G1 `diff_report_service.py`

_md_text
req: R-CMP-004.9.1, R-BEFORE-AFTER-REPORT-001.21, R-BEFORE-AFTER-REPORT-001.22
in: object value; int limit = REPORT_CELL_CHARS
out: str text
func: new. `return md_safe(value, limit=limit)` — S12 report-safe text: visible-text steps, cut at the field limit (512; 500 for a refusal message), escape. No separate strip first [S-2]; `md_safe` slices its input at 8 × limit before any scan, so a multi-megabyte name is never walked whole [S-5].
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.9.1/1) "A*b_[x].s19" → «A\*b\_\[x\]\.s19»
examples: (R-CMP-004.9.1/8) "img.s19" → «img\.s19»; "img-patched.s19" → «img-patched\.s19» (interior `-` kept)
examples: (R-CMP-004.9.1/4) "EVIL|SYM<b>·END" → «EVIL\|SYM\<b\>�END» [S-2]
examples: (R-BEFORE-AFTER-REPORT-001.21/1) "CTL·SYM" → «CTL�SYM» [S-2]
examples: (R-CMP-004.9.1/12) "a¤b" → «a�b»; "S<RLO>T" → «S�T» [S-2]
examples: (R-CMP-004.15/2) "a\tb.s19" → «a b\.s19» [S-2]
examples: (R-CMP-004.9.1/10) message "the symbol '<img src=https://h/p>[x](http://b)' is not declared", limit 500 → «the symbol '\<img src=https:\/\/h\/p\>\[x\](http:\/\/b)' is not declared» [S-1]
examples: (R-CMP-004.9.1/7) 600 × "A" → 512 × "A" + «… (truncated)» (525 characters, B)
examples: (B) "cal-filter.json" → «cal-filter\.json»; "(unnamed filter)" → «(unnamed filter)»

_md_path
req: R-CMP-004.9.2, R-BEFORE-AFTER-REPORT-001.21
in: object value
out: str text
func: new. `return md_code(value)` — S12 path text: visible-text steps, backtick → `�`, nothing escaped, never cut [S-2]. The caller writes the two backticks.
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.9.2/1) "/tmp/a`b.s19" → «/tmp/a�b.s19»
examples: (R-CMP-004.9.2/4) "/tmp/my_img*.s19" → «/tmp/my_img*.s19» (unchanged, B)
examples: (R-CMP-004.9.2/3) "<RUN-ROOT>/img.s19" → the same bytes (the golden canonicaliser still matches)
examples: (R-BEFORE-AFTER-REPORT-001.21/2) "C:/p/doc·.json" → «C:/p/doc�.json» [S-2]
examples: (R-CMP-004.9.2/4) `str(tmp_path / "my_img.s19")` → the same string exactly [F-E3-9]

_run_symbol_names
req: R-CMP-004.5, R-BEFORE-AFTER-REPORT-001.24
in: DiffRun run; Sequence[tuple[int, str]] symbol_addresses
out: list[str] names
func: new. The names whose address lies in `[run.start, run.end)`, in `symbol_addresses` order (A2L pairs first, then MAC — the order `generate_diff_report` builds). Same membership as today's `_annotate_run` (`build_sorted_range_index` + `address_in_sorted_ranges`). Empty list when none.
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.5/1) run 0x100–0x102, pairs [(0x0F0, "WIDE")] → [] ; pairs [(0x100, "HERE")] → ["HERE"]
examples: (R-BEFORE-AFTER-REPORT-001.24/2) run 0x100–0x102, pairs [(0x100, "CAL_A"), (0x101, "CAL_M")] → ["CAL_A", "CAL_M"]

_annotate_run
req: R-CMP-004.5
in: DiffRun run; Sequence[tuple[int, str]] symbol_addresses
out: str annotation
func: changed. was: builds the name list inline and joins it / now: `", ".join(_run_symbol_names(run, symbol_addresses)) or "-"`. Output unchanged; its one caller left is `_html_run_rows` (the HTML cell, escaped there by `_esc`).
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.8/1) run 0x100–0x102, pairs [(0x100, "CAL_A")] → "CAL_A" (HTML `<td>CAL_A</td>`, holds on base for the same input)

_window_rows
req: R-CMP-004.14
in: dict[int, int] mem_map; int low; int high
out: list[str] rows
func: changed. was: `render_hex_view(mem_map, row_bases=list(range(low, high, 16)), max_rows=MAX_HEX_ROWS).splitlines()` — at most 512 rows plus the cap line / now: one I-5 row per base in `range(low, high, HEX_WIDTH)`, built here; no cap, no header line. Callers unchanged: `_diff_block_lines`, `_hex_windows_lines._block`, `_html_hex_windows`.
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.14/1) A = {0x1000 … 0x37FF: 0xAA}, low 0x0FC0, high 0x3800 → 644 rows, rows[0] «0x00000FC0                                                   |................|», rows[-1] starts «0x000037F0  AA AA»; 0 cap lines (base: 513 lines, the first «... window limited to 512 rows ...», B)
examples: (R-CMP-004.14/3) B = {0x0 … 0xF, 0x10000 … 0x20FFF: 0x22}, low 0xFFC0, high 0x21000 → 4,356 rows, rows[-1] starts «0x00020FF0  22 22»; 0 «output truncated» (mutant M2 gives 4,100 rows + «... output truncated at 65536 bytes ...»)
examples: (R-CMP-004.14/6) the `_PRE_CHANGE` A map {0x100 … 0x103: 0xAA}, low 0xC0, high 0x110 → the 5 rows of `_PRE_CHANGE_MD_TEMPLATE`'s A block, byte for byte (holds on base)

_image_line
req: R-CMP-004.9.1, R-CMP-004.9.2
in: str label; ImageRef image
out: str line
func: changed. was: `f"- Image {label}: {image.label or '(unnamed)'} [{image.source_kind}{variant}] path=`{image.path}` parse-errors={n}"`, all raw / now: label → `_md_text(image.label)` (or `(unnamed)` when empty), variant id → `_md_text(image.variant_id)`, path → `` `{_md_path(image.path)}` ``; `source_kind` and the count are the system's own tokens, unchanged.
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.9.1/1) label "A*b_[x].s19", kind "external", path "/tmp/a.s19", 0 errors → «- Image A: A\*b\_\[x\]\.s19 [external] path=`/tmp/a.s19` parse-errors=0»
examples: (R-CMP-004.9.1/2) label "v_1<b>", kind "project-variant", variant "v_1<b>" → «- Image A: v\_1\<b\> [project-variant variant=v\_1\<b\>] path=`…` parse-errors=0»
examples: (R-CMP-004.9.2/1) path "/tmp/a`b.s19" → «path=`/tmp/a�b.s19`» (2 backticks on the line)
examples: (R-CMP-004.9.1/9) flow arm label "patch.out", kind "flow", path "block 2 (patch).out" → «- Image A: patch\.out [flow] path=`block 2 (patch).out` parse-errors=0» (TC-B94-24 re-pinned)

_header_lines
req: R-BEFORE-AFTER-REPORT-001.32, R-CMP-004.1
in: ComparisonResult comparison; datetime generated_at; str title
out: list[str] lines
func: changed. was: line 0 the constant «# Diff report» / now: line 0 `f"# {title}"`; the rest unchanged (blank, Generated, Tool version, 2 image lines, 2 artifact lines, blank). `generate_diff_report` still slices `[:2]` / `[2:]` around the audit block.
module: s19_app/tui/services/diff_report_service.py
examples: (R-BEFORE-AFTER-REPORT-001.32/1) title "Before/after report" → lines[0] «# Before/after report»
examples: (R-CMP-004.1/1) title "Diff report" → lines[0] «# Diff report» (holds on base)

_run_table_lines
req: R-CMP-004.9.1, R-BEFORE-AFTER-REPORT-001.24, R-CMP-004.5
in: ComparisonResult comparison; Sequence[tuple[int, str]] symbol_addresses; Optional[Sequence[DiffRun]] runs
out: list[str] lines
func: changed. was: Symbols cell `_annotate_run(...)`, raw / now: `", ".join(_md_text(n) for n in _run_symbol_names(run, symbol_addresses)) or "-"` — escaped name by name, so the 512 limit applies per name.
module: s19_app/tui/services/diff_report_service.py
examples: (R-BEFORE-AFTER-REPORT-001.24/1) run 0x100–0x102 changed, pairs [(0x100, "CAL_A")] → «| 0x00000100 | 0x00000102 | 2 | changed | CAL\_A |»
examples: (R-CMP-004.9.1/3) run 0x100–0x104, pairs [(0x100, "A_B"), (0x101, "x|y")] → cell «A\_B, x\|y»; the row splits on unescaped pipes into 5 cells
examples: (B) test `test_symbol_annotation_only_intersecting_run`: «| 0x00000100 | 0x00000104 | 4 | changed | INSIDE\_SYM |» (base: «INSIDE_SYM»)

_provenance_lines
req: R-CMP-004.9.2, R-BEFORE-AFTER-REPORT-001.21
in: BeforeAfterProvenance provenance
out: list[str] lines
func: changed. was: original, saved and change-document paths as `` `{_md_cell(p)}` `` (pipe escaped inside the code span, a backtick closes it) / now: `` `{_md_path(p)}` ``. Applied (UTC) stays `_md_cell` (D-7); `(in-memory document)` unchanged.
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.9.2/3) paths under the run root, no special character → the lines of today's golden, byte for byte
examples: (R-CMP-004.9.2/2) original "/p/o`.s19", saved "/p/s`.s19", document "/p/d`.json" → «- Original image (before): `/p/o�.s19`», «- Saved patched image (after): `/p/s�.s19`», «- Change document: `/p/d�.json`»

_linkage_table_lines
req: R-CMP-004.9.1, R-BEFORE-AFTER-REPORT-001.21, R-BEFORE-AFTER-REPORT-001.22
in: Sequence[ChangeSummaryEntry] entries
out: list[str] lines
func: changed. was: Symbol cell `_md_cell(entry.symbol or entry.linkage_symbol)` / now: `_md_text(...)`; `-` when none. Type, Disposition, Linkage stay `_md_cell`; Before/After stay `_md_table_cell` (D-7).
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.9.1/4) symbol "EVIL|SYM<b>·END" → cell «EVIL\|SYM\<b\>�END»; 10 unescaped pipes [S-2] (base: «EVIL\|SYM<b>END»)
examples: (B) symbol "CAL_SYM", mac-linked → «| 1 | bytes | 0x00000100 | 0x00000102 | applied | mac-linked | CAL\_SYM | AA AA \|..\| | 01 02 \|..\| |»

_flow_change_attribution_lines
req: R-CMP-004.9.1
in: FlowChangeAttribution attribution; Sequence[DiffRun] runs
out: list[str] lines
func: changed. was: change-document reference, symbol and refusal message through `_md_cell` / now: reference and symbol through `_md_text`, in the table rows and the refusal bullets; the refusal message through `_md_text(message, limit=500)` [S-1]. Disposition and code stay `_md_cell` (D-7, the system's own tokens). Section text otherwise unchanged (R-DIFF-FLOWCHG.3 … .7).
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.9.1/5) record (doc "patches/c_1.json", symbol "S*1", 0x1000–0x1002, applied), run 0x1000–0x1002 → «| patches\/c\_1\.json | S\*1 | 0x00001000 | 2 | applied | 0x00001000–0x00001002 |»
examples: (R-CMP-004.9.1/5) refusal (doc "patches/c_1.json", symbol "S*1", address 0x1000, code "CHG-X", message "m") → «- refused: patches\/c\_1\.json symbol 'S\*1' @ 0x00001000 [CHG-X] m»
examples: (R-CMP-004.9.1/10) refusal (doc "c.json", symbol "<img src=https://h/p>[x](http://b)", code "CHG-SYMBOL-UNRESOLVED", message "the symbol '<img src=https://h/p>[x](http://b)' is not declared") → «- refused: c\.json symbol '\<img src=https:\/\/h\/p\>\[x\](http:\/\/b)' [CHG-SYMBOL-UNRESOLVED] the symbol '\<img src=https:\/\/h\/p\>\[x\](http:\/\/b)' is not declared» — 0 `image` / `link_open` / `html_inline` tokens under markdown-it [S-1] (base: the message raw, a live `<img>`)
examples: (B) TC-717's refusal on "c2.json" → «- refused: c2\.json symbol 'Ghost' …» (base: «c2.json»)

flow_change_census_complete
req: R-CMP-004.9.1
in: FlowChangeAttribution attribution; Sequence[str] lines
out: bool complete
func: changed. was: matches each record's document cell and each refusal's document as `_md_cell(ref)` / now: as `_md_text(ref)` — the spelling the section now writes. Refusal code stays `[_md_cell(code)]`. Everything else unchanged (F6-4 stays on the backlog).
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.9.1/5) the section of the example above → True; the same section with the record's row removed → False
examples: (B) TC-718 battery: complete section → True, one change dropped → False (holds after the change; mutant M14 makes the complete section False)

_audit_header_lines
req: R-CMP-004.9.1
in: str filter_name; Optional[tuple[int, int]] linkage_counts; tuple[int, int] run_counts
out: list[str] lines
func: changed. was: `f"- Filter file: {_strip_ctl(filter_name)}"` / now: `f"- Filter file: {_md_text(filter_name)}"` (O-5). Other lines unchanged.
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.9.1/6) "a|b`c<b>d.json" → «- Filter file: a\|b\`c\<b\>d\.json» (base: «a|b`c<b>d.json»)
examples: (B) "cal-filter.json" → «- Filter file: cal-filter\.json»; "(unnamed filter)" unchanged

_html_header
req: R-BEFORE-AFTER-REPORT-001.34, R-CMP-004.1, R-CMP-004.8, R-CMP-004.15
in: ComparisonResult comparison; datetime generated_at; str title
out: list[str] lines
func: changed. was: line 0 the constant `<h1>Diff report</h1>`; label, variant id and path through `_esc` alone / now: `f"<h1>{_esc(title)}</h1>"`; label, variant id and path through `_esc(_strip_ctl(…))` [S-2]. Artifact items unchanged. No Markdown escaping (R-CMP-004.8).
module: s19_app/tui/services/diff_report_service.py
examples: (R-BEFORE-AFTER-REPORT-001.34/1) title "Before/after report" → lines[0] `<h1>Before/after report</h1>`
examples: (R-CMP-004.8/1) label "A_b.s19" → `<li>Image A: A_b.s19 [external] …` (no backslash)
examples: (R-CMP-004.15/1) label "a¤b", path "/p/<RLO>x.s19" → `<li>Image A: a�b [external] path=<code>/p/�x.s19</code> …` (base: both characters raw) [S-2]

generate_diff_report
req: R-BEFORE-AFTER-REPORT-001.32, R-CMP-004.1, R-CMP-004.14, R-CMP-004.9.1, R-CMP-004.9.2
in: ComparisonResult comparison; keyword inputs unchanged (I-2)
out: DiffReportResult result
func: changed. was: `_header_lines(comparison, generated_at)`; `target.write_text(...)` / now: `title = "Before/after report" if provenance is not None else "Diff report"`; `_header_lines(comparison, generated_at, title)`; the file through `_write_report(target, text)` (I-6) [S-3]. The audit block still goes at index 2 (S-F6). Everything else unchanged; the escaping and the whole windows come from the helpers above.
module: s19_app/tui/services/diff_report_service.py
modify: [File: <dest>/<ts>-<stem>.md] (create)
examples: (R-BEFORE-AFTER-REPORT-001.32/3) provenance given, filter given → lines[0] «# Before/after report», lines[2] «## Report filter applied»
examples: (R-CMP-004.1/2) provenance None, `linkage_entries=[entry]` → lines[0] «# Diff report»
examples: (R-CMP-005.16/1) the text write raises `OSError("disk full")` after half the text → the error propagates; `reports/` holds no `<ts>-diff-report.md` and no `.part` file (base: a partial `.md`) [S-3]

generate_diff_report_html
req: R-BEFORE-AFTER-REPORT-001.33, R-BEFORE-AFTER-REPORT-001.34, R-CMP-004.1, R-CMP-004.14
in: ComparisonResult comparison; keyword inputs unchanged (I-2)
out: DiffReportResult result
func: changed. was: `<title>Diff report</title>` constant; `write_text` / now: `<title>{_esc(title)}</title>` [F-E3-10] with the same rule as `generate_diff_report`; `_html_header(..., title)`; the file through `_write_report` (I-6) [S-3].
module: s19_app/tui/services/diff_report_service.py
modify: [File: <dest>/<ts>-<stem>.html] (create)
examples: (R-BEFORE-AFTER-REPORT-001.33/1) provenance given → exactly one `<title>Before/after report</title>`
examples: (R-CMP-004.14/4) the 69,632-byte only-B fixture → the B `<pre>` holds 4,356 rows (base: 512 + the cap line, B)

_hex_windows_lines, _diff_block_lines, _html_hex_windows, _html_side_by_side_pane
req: R-CMP-004.14
func: unchanged. They call `_window_rows` (the first three) or render their own rows (`_html_side_by_side_pane` via `_html_hex_row`, already uncapped). Windows, merging and clamping are unchanged.
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.14/1, B) 10,240-byte changed run → base Markdown: diff block 1,026 lines (2 × (512 rows + 1 cap line)), A 513, B 513; HTML panes 644 each (already whole). Target: 1,288 / 644 / 644 / 644 + 644
examples: (R-CMP-004.14/5) the before/after composer fixture of 8,960 changed bytes → window 0xC0–0x2400, 564 rows in every block and pane

_strip_ctl
req: R-CMP-004.15, R-BEFORE-AFTER-REPORT-001.21
in: object value
out: str text
func: changed [S-2]. was: removes U+0000 … U+001F and U+007F / now: `_normalise(str(value))` from `markdown_safety` (I-7): tab, CR, LF → one space; each character of category Cc, Cf, Cs, Zl, Zp → `�`; nothing trimmed. Name kept (`tests/test_tui_report_filter_surface.py:1390-1391` calls it; no U+0001 and no LF in its output still hold). Callers that follow with no code change: `_md_cell`, `_md_table_cell`, `_html_provenance`, `_html_linkage`, `_html_flow_change_attribution`, `_html_audit_header`.
module: s19_app/tui/services/diff_report_service.py
examples: (R-BEFORE-AFTER-REPORT-001.21/1) "CTL·SYM" → "CTL�SYM" (base: "CTLSYM")
examples: (R-CMP-004.15/1) "S<RLO>T" → "S�T"; "a¤b" → "a�b" (base: unchanged, raw)
examples: (B) "a·b\r\nc" → "a�b  c" (two spaces: CR and LF each become one)

_html_run_rows
req: R-CMP-004.15, R-CMP-004.8
in: ComparisonResult comparison; Sequence[tuple[int, str]] symbol_addresses; Optional[Sequence[DiffRun]] runs
out: list[str] lines
func: changed [S-2]. was: Symbols cell `_esc(_annotate_run(...))` / now: `_esc(_strip_ctl(_annotate_run(...)))`. Colours and other cells unchanged.
module: s19_app/tui/services/diff_report_service.py
examples: (R-CMP-004.15/1) pairs [(0x100, "S<RLO>T")] → `<td>S�T</td>` (Markdown cell «S�T»)

_write_report
req: R-CMP-005.16
in: Path target; str text
out: None
func: new [S-3] (I-6). `part = target.with_name(f"{target.name}.{secrets.token_hex(8)}.part")` (E5 C-1, design-gap fix: an unpredictable staging name, so a link planted at a guessable `<name>.part` is never followed; Windows exclusive create follows a dangling link, S5-1); open `part` with mode `"x"`, encoding UTF-8, write `text`; `os.replace(part, target)`. On any exception: `part.unlink(missing_ok=True)`, then re-raise. The `.part` name never matches `DIFF_REPORT_FILENAME_REGEX` and is not a `.md`, so `list_diff_reports` and the Reports listing never show it. The final name was chosen free by `_diff_report_filename`; the replace does not add an overwrite the old `write_text` did not have (D14-11, exclusive create of the final name, stays on the backlog).
module: s19_app/tui/services/diff_report_service.py
modify: [File: <dest>/<name>.<random>.part] (create, then rename); [File: <dest>/<name>] (create)
examples: (R-CMP-005.16/1) write raises after half the text → no `<name>`, no `<name>.part`; the `OSError` reaches the caller (status `Diff report failed: OSError: disk full`)
examples: (R-CMP-005.16/2) success → `<name>` holds the whole text, no `.part` left
examples: (R-CMP-005.16/4) a stale `<name>.part` holding `ANOTHER WRITER` → `<name>` written whole beside it; the stale file keeps its bytes (N-1; before E5 C-1: `FileExistsError`)
examples: (R-CMP-005.16/5) a dangling link at `<name>.part` → its target is not created, the link is unchanged, `<name>` is a regular file (E5 C-1; base and head `90ea8ae` on Windows: target created, `<name>` became the link)

_md_cell, _md_table_cell, md_safe, md_code, _normalise
req: R-BEFORE-AFTER-REPORT-001.21, R-BEFORE-AFTER-REPORT-001.22, R-CMP-004.9.1, R-CMP-004.9.2
func: unchanged. `md_safe` / `md_code` are S12's report-safe text / path text (`markdown_safety.py`), both starting with `_normalise`. `_md_cell` stays for the system's own tokens only (D-7).
module: s19_app/tui/services/diff_report_service.py, s19_app/tui/services/markdown_safety.py

## Nodes — G2 `before_after_service.py`

compose_before_after_report
req: R-BEFORE-AFTER-REPORT-001.35, R-BEFORE-AFTER-REPORT-001.24, R-CMP-003.2, R-BEFORE-AFTER-REPORT-001.11, R-CMP-005.17
in: Optional[ChangeSummary] summary; Optional[Path] loaded_path; Optional[Path] project_dir; Path workarea; Optional[NowFn] now_fn = None; Optional[ReportFilterMatcher] report_filter = None; Optional[dict] a2l_data = None; Optional[Sequence[dict]] a2l_records = None; Optional[Sequence[dict]] mac_records = None
out: BeforeAfterReportResult result
func: changed. was: `compare_images(source_a, source_b)` with no artifact; generator kwargs = the 7 keys (+ `report_filter`); no-project reason `… (screen 7) …`; an HTML failure leaves the Markdown file / now: `compare_images(source_a, source_b, a2l_data=a2l_data, mac_records=mac_records)`; after the 7 keys, `kwargs["a2l_records"] = a2l_records` when not `None`, `kwargs["mac_records"] = mac_records` when not `None` (I-1). The no-project reason reads `(key 7)` [F-E3-1]. When `generate_diff_report_html` raises or returns `written=False` after the Markdown file was written: `md.path.unlink(missing_ok=True)` (an `OSError` from it suppressed — the module does no logging), then re-raise / return the refusal as today [S-3]. Preconditions and their order unchanged.
module: s19_app/tui/services/before_after_service.py
modify: [File: <project>/reports/<ts>-before-after-report.md|.html] (create)
examples: (R-BEFORE-AFTER-REPORT-001.35/1) fixtures + `a2l_data` (tags CAL_A 0x100, CAL_B 0x9000) + `mac_records` [CAL_M 0x102] → both files, both images: «- Image A artifacts: summary=both; a2l=used (1/2); mac=used (1/1)» and the same for B
examples: (R-CMP-003.2/2) fixtures, no artifact input → «summary=none; a2l=absent; mac=absent» on both lines (holds on base)
examples: (R-BEFORE-AFTER-REPORT-001.24/1) fixtures + `a2l_records` [CAL_A 0x100] → Markdown run row ends «| changed | CAL\_A |», HTML `<td>CAL_A</td>`
examples: (R-BEFORE-AFTER-REPORT-001.24/4) no artifact input, generators monkeypatched → each generator gets exactly {mem_map_a, mem_map_b, project_dir, provenance, linkage_entries, filename_stem, now_fn} (TC-311, holds on base)
examples: (R-BEFORE-AFTER-REPORT-001.32/1) fixtures → Markdown line 1 «# Before/after report» (base: «# Diff report»)
examples: (R-BEFORE-AFTER-REPORT-001.11/1) `project_dir=None`, preconditions 1-5 met → `written` False, `diagnostics == ["No active project - the before/after report needs a project reports/ destination; use the manual A<->B Diff report (key 7) with an explicit destination instead."]` (base: `(screen 7)`) [F-E3-1]
examples: (R-CMP-005.17/2) `generate_diff_report_html` raises `RuntimeError("x")` → `RuntimeError` propagates; `reports/` holds no `-before-after-report.md` (base: the `.md` stays) [S-3]

compare_images
req: R-CMP-003.2, R-BEFORE-AFTER-REPORT-001.35
func: unchanged. `a2l_present = a2l_data is not None`, `mac_present = mac_records is not None` (`compare_service.py`); status `absent` / `used` / `unused`. Hence D-3: `[]` must not stand for "no MAC".
module: s19_app/tui/services/compare_service.py
examples: (R-CMP-003.2/1, B) `mac_records=[]` → `mac=unused (0/0)`; `mac_records=None` → `mac=absent`

## Nodes — G3 `app.py`

action_before_after_report
req: R-BEFORE-AFTER-REPORT-001.35, R-BEFORE-AFTER-REPORT-001.24, R-CMP-003.2
in: self
out: None
func: changed. was: dispatches `_start_before_after_worker(loaded_path, project_dir, report_filter, source_name, gen=gen)` / now: before the busy begin, on the UI thread (I-4), reads `a2l_data = self.current_a2l_data`, `a2l_records = self._compute_a2l_enriched_tags() or None`, `mac_records = loaded.mac_records if loaded is not None and loaded.mac_path is not None else None`, and passes the three to the worker. The filter branch (`:5420-5440`) keeps its own reads; nothing that can raise moves between the busy begin and the dispatch (F-10).
module: s19_app/tui/app.py
examples: (R-BEFORE-AFTER-REPORT-001.35/2) A2L loaded with tags at 0x100 …, MAC none → worker gets `a2l_data` = that payload, `a2l_records` = its enriched tags, `mac_records = None`
examples: (R-CMP-003.2/1) loaded image with `mac_path=None`, `mac_records=[]` → `mac_records=None` → report lines «mac=absent» (mutant M7 forwards `[]` → «mac=unused (0/0)»)
examples: (R-CMP-003.2/2) no A2L (`current_a2l_data` None) → `a2l_data=None`, `a2l_records=None` (`[] or None`) → AT-054b golden lines 7-8 unchanged

_start_before_after_worker
req: R-BEFORE-AFTER-REPORT-001.35, R-BEFORE-AFTER-REPORT-001.24
in: Optional[Path] loaded_path; Optional[Path] project_dir; Optional[ReportFilterMatcher] report_filter; str source_name; int gen (kw); Optional[dict] a2l_data = None (kw); Optional[Sequence[dict]] a2l_records = None (kw); Optional[Sequence[dict]] mac_records = None (kw)
out: None
func: changed. was: `compose_before_after_report(last_summary, loaded_path, project_dir=, workarea=, report_filter=)` / now: also `a2l_data=`, `a2l_records=`, `mac_records=`. Status, log and busy handling unchanged.
module: s19_app/tui/app.py
examples: (R-BEFORE-AFTER-REPORT-001.24/3) key `b` after apply + save-back, A2L with a tag at the patched address → the written Markdown's run row names the tag (escaped); status «Before/after report written: <md> | <html>»

_start_diff_report_worker
req: R-CMP-005.17
in: (unchanged signature)
out: None
func: changed [S-3]. was: after `md` is written, an HTML exception or refusal ends the run with its status and leaves `md.path` on disk ("markdown already written") / now: in both arms, `md.path.unlink(missing_ok=True)` before the status; an `OSError` from the removal is logged at WARNING `report kind=diff orphan not removed: <error type>` (no content, R-CMP-004.10). Status and log texts of R-CMP-005.10, R-CMP-004.13 and `HTML report refused: <reason>` unchanged. A Markdown refusal or exception (no `md` file) removes nothing.
module: s19_app/tui/app.py
examples: (R-CMP-005.17/1) HTML generator raises `RuntimeError("x")` → status `Diff report failed: RuntimeError: x`; `reports/` holds 0 `-diff-report.md` (base: 1 orphan `.md`)
examples: (B) `test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome` "html raises" arm: stubbed `md` path → `unlink(missing_ok=True)` does not raise; outcome unchanged

_compute_a2l_enriched_tags
func: unchanged. Cached by `(id(current_a2l_data), len(mem_map))`; already called on the UI thread by the A↔B report and the before/after filter path.
module: s19_app/tui/app.py

## Nodes — G4 `flow_execution_service.py`

run_flow
req: R-CMP-004.9.1, R-CMP-004.9.2
in: Flow flow; FlowContext ctx
out: FlowRunResult result
func: changed, A2B external arm only (`:981-988`). was: the side tuple carries `md_safe(path.stem, limit=120)` and `md_code(str(path))` / now: `path.stem` and `str(path)` (I-3, D-6); the comment above names the generator as the one escaper. The flow arm (`f"{producer.kind}.out"`, `block N (kind).out`) is unchanged.
module: s19_app/tui/services/flow_execution_service.py
examples: (R-CMP-004.9.1/9) external input stem with `[red]` → report label holds «\[red\]» once, never «\\[» (AT-B94-18 unchanged; mutant M12 gives the double escape)
examples: (R-CMP-004.9.1/9) external input `base.s19` → «- Image B: base [external] path=`…/base.s19` parse-errors=0» (TC-B94-24 external-arm regex unchanged)

## Findings

finding F-1 a pre-escaping producer
anchor: s19_app/tui/services/flow_execution_service.py:984, :986
seen: the flow-A2B arm escapes its label (Mode A, limit 120) and path (Mode B) before the generator, so the generator escaping its labels would write the label twice escaped.
effect: AT-B94-18 RED, flow-A2B labels with `\\`.
decision: D-6 — remove the pre-escape; I-3 pins "raw in, escape at the sink". Needs O-2.

finding F-2 the composer cannot see the session's A2L
anchor: s19_app/tui/services/before_after_service.py:183-191 (signature), :328-357
seen: F-42's header and Symbols halves need the app's A2L payload, its enriched tags and the MAC records; the composer gets only paths and the change summary.
effect: the fix spans `app.py` (2 functions).
decision: D-2, I-1, I-4. Needs O-1.

finding F-3 an empty MAC list is not "no MAC"
anchor: s19_app/tui/services/load_service.py:80; s19_app/tui/services/compare_service.py (`mac_present = mac_records is not None`)
seen: an image without a MAC file holds `mac_records=[]`; forwarding it reports `mac=unused (0/0)`.
decision: D-3 (`mac_path is None` → `None`). The A↔B path keeps the defect (OBS-7-1).

finding F-4 the screen's hex view has a second cap
anchor: s19_app/render/hexview.py:231, :243-244
seen: besides 512 rows, `render_hex_view` stops at 65,536 mapped bytes. A fix that only raises `max_rows` leaves windows over 64 KiB cut.
decision: D-4 — `_window_rows` renders its own rows (I-5); mutant M2 guards the trap.

finding F-5 negative assertions on raw symbol names turn vacuous
anchor: tests/test_diff_report_service.py:434, :1268, :1323, :1347
seen: after D-5 a leaked name is written `OUTSIDE\_SYM`, so `"OUTSIDE_SYM" not in text` stays true whether or not it leaked.
decision: E4 re-pins each to the escaped spelling (`E1-rulings.md` §3).

finding F-6 the title follows the provenance input
anchor: s19_app/tui/services/diff_report_service.py:922, :1821, :2576
seen: `provenance=` has one caller (the composer); the before/after report is defined as the diff report carrying it.
decision: D-1; mutants M4, M5 guard that only provenance switches the title.

finding F-7 E3 round 1 corrections [E3]
anchor: ../E3-architect.md, ../E3-security.md, ../E3-rulings.md
seen: architect PASS-WITH-NOTES (F-E3-1 … 3 MAJOR), security PASS-WITH-NOTES (S-1 … S-3 MAJOR)
decision: the six MAJORs are corrected in this graph and the E1 records: `(key 7)` text (F-E3-1); two more re-pinned nodes and both-spelling negatives (F-E3-2); the flow-A2B UI-thread cost admitted as OBS-7-5 with D16-15 as its fix (F-E3-3); refusal message as report-safe text, limit 500 (S-1); visible text in both files through `_strip_ctl` = `_normalise` (S-2, also F-E3-6); `_write_report` and the orphan removal (S-3). Minor items are E4 addenda in `../E3-rulings.md`. The slice stays at 4 files.
