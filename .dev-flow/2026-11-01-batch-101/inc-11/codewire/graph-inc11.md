# Code-Wire graph — Inc 11 (A2L validation and parsing), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `b7b77c4`. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (`<HOME>/Github/code-wire/docs/Notation-Grammar.md`), as in `../../inc-2/codewire/graph-inc2.md` and `../../inc-8/codewire/graph-inc8.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first), **new** or **removed**. Context nodes (unchanged) are here because a changed node calls them or reads their output.
- Example sources are the case ids of `02-test-cases.md` (`R-A2L-036.2/3`); `B` = a probe of the base tree run at E1 from the session scratchpad (read-only on the worktree); `P` = the E1 model of the changed rule run on the shipped fixtures in the scratchpad. Every example states the Inc 11 target unless it says "holds on base".
- Nodes marked **[OR-1]** / **[OR-2]** exist in this form only if the orchestrator rules so (`../E1-rulings.md` §4).
- A2L text in examples: `/` separates lines; `A2L(…)` wraps the body in `/begin PROJECT P ""` / `/begin MODULE M ""` … `/end MODULE` / `/end PROJECT` (line 1 = `/begin PROJECT`).

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns nodes |
|---|---|---|
| G1 engine | `s19_app/validation/rules.py`, `s19_app/tui/a2l.py`; tests `tests/test_b101_a2l_blocks_and_segments.py`, the rewrite of `tests/test_tui_issues_triage_b94.py::test_tc_b94_18_*`, `tests/test_synth_release_case.py::test_a2l_zero_issues`, the comment in `tests/test_engine_unchanged.py` | `[Data: RECOGNIZED_A2L_BLOCKS]`, `[Data: INTERFACE_DATA_BLOCK]`, `_iter_sections`, `validate_a2l_structure`, `[Data: PROGRAM_TYPE_WORDS]`, `[Data: MEMORY_TYPE_WORDS]`, `_memory_segment_record_words`, `extract_memory_segments`, `render_curve_description` |
| G2 Issues view | `s19_app/tui/issues_view.py`, `s19_app/tui/app.py` [OR-1]; tests `tests/test_b101_issues_severity_view.py`, the rewrites of `tests/test_tui_issues_triage_b94.py::test_at_b94_14_*`, `::test_tc_b94_19_*` and its imports | `a2l_reclassified_severity` (removed), `adjust_counts_for_a2l_triage` (removed), `render_groups`, `update_validation_issues_view`, `_render_validation_issues_groups`, `_filtered_validation_issues` [OR-2] |
| G3 acceptance | tests `tests/test_b101_inc11_acceptance.py` (no source) | AT-I11-1 … AT-I11-6 |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 the unknown-block issue | `ValidationIssue(code="A2L_UNRECOGNIZED_BLOCK", severity=WARNING, message=f"Unrecognized A2L block '{NAME}'.", artifact="a2l", line_number=<start_line or None>)` — unchanged shape; only **when** it is raised changes (R-VAL-032.1 … .3) | G1 → `validate_a2l_internal_issues` → `build_validation_report` → G2 (`_validation_issues`) |
| I-2 issue severity is final | the severity an issue carries in `S19TuiApp._validation_issues` is the one every Issues surface paints and counts; no presentation layer re-labels it. `issues_view` exports no `a2l_reclassified_severity`, `adjust_counts_for_a2l_triage`, `CURATED_STANDARD_A2L_BLOCKS`, `A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION` | G1/engine → G2 |
| I-3 the segment entry | `extract_memory_segments(sections: list[dict]) -> list[dict]`, signature unchanged; each entry has exactly the keys `block_name: str \| None`, `raw_first_line: str`, `usage: str \| None`, `kind: str \| None`, `base: int \| None`, `size: int \| None`, `offset: int \| None`, in this order, one entry per MEMORY_SEGMENT in pre-order. `block_name` may now be `None` (was `"UNKNOWN"`); `base is None` ⇔ `size is None`; `usage`/`kind` are `None` whenever `base` is | G1 → `extract_a2l_tags` (`memory_region`), `parse_a2l_file` (log), `segment_split_view._a2l_rows` (Inc 10 / Inc 13 edit that file, not this function's reader: `_a2l_rows` keeps reading `base`, `size`, `block_name`), re-export `a2l_parse` |
| I-4 the description text | `render_curve_description(description: dict) -> str`, signature unchanged; `describe_curve_tag` output unchanged (`points[i]["x_note"]` kept) | G1 → the description window (`d`), tests |
| I-5 the filtered list [OR-2] | `S19TuiApp._filtered_validation_issues() -> list[ValidationIssue]`: the filter mode's issues, stably sorted by severity rank (ERROR 0, WARNING 1, INFO 2) | G2 → summary line, panel window, paging, `action_validation_issues_page_next` |

Interfaces with other increments:
- **Inc 1 (canon):** rows to fold at integration — changed R-VAL-032 (split .1/.2/.3), R-A2L-036.1 … .4, .6 (reworded), R-A2L-036.5 (withdrawn); new R-A2L-036.7 … .12, R-A2L-120 … 123, R-TUI-042b.5 [OR-2], R-TUI-042b.6; new context terms (`../E1-rulings.md` C-3, C-4); S0's HLR-012 map row cites R-VAL-032.1 … .3.
- **Inc 12 (unreachable code, `app.py`):** if OR-1 is declined, Inc 12 receives the removal of the identity `adjust_counts_for_a2l_triage` and its two calls.
- **Inc 10 / Inc 13 (`segment_split_view.py`):** read I-3 through `_a2l_rows`; nothing in their slices depends on `block_name == "UNKNOWN"`.
- **Inc 14 (legend, help):** the legend lines `— Info rows appear only under All` and `Grouped list (order ERROR → WARNING → INFO)` (`legend.py:778-781`) become true as written with OR-2; no text change asked of Inc 14. The user guide ch07 / ch04 / ch14 sentences that name F-02, F-03, F-21, F-29, F-39 are documentation outside `s19_app/` (batch end).
- **Inc 2 (test hygiene):** G3 loads a 10 MB image through the app; the tester generates the release demo once per module (`scope="module"` fixture, as `tests/test_synth_release_case.py`) and asserts no wall-clock bound, so no `serial_timing` mark is needed.

## Nodes

RECOGNIZED_A2L_BLOCKS
req: R-VAL-032.2
in: —
out: set[str]
func: changed. was: 15 names (PROJECT, MODULE, CHARACTERISTIC, MEASUREMENT, GROUP, FUNCTION, MEMORY_SEGMENT, RECORD_LAYOUT, COMPU_METHOD, COMPU_TAB, COMPU_VTAB, TYPEDEF_CHARACTERISTIC, TYPEDEF_MEASUREMENT, AXIS_PTS, IF_DATA). / now: the 61 ASAM block names of `01-requirements.md` Definitions (the 15 are a subset). Name kept (one reader).
module: s19_app/validation/rules.py
examples: (R-VAL-032.2/1) `"AXIS_DESCR" in RECOGNIZED_A2L_BLOCKS` → `True` (base `False`)
examples: (R-VAL-032.2/1) `len(RECOGNIZED_A2L_BLOCKS)` → `61` (base `15`)
examples: (R-VAL-032.1/3) `"PAGE" in RECOGNIZED_A2L_BLOCKS` → `False` (holds on base; PAGE is an XCP name)
examples: (R-VAL-032.2/1 neg) mutant: drop `AXIS_DESCR` → the release demo gives 100 issues → RED

_iter_sections
req: R-VAL-032.3
in: list[dict] sections
out: list[tuple[dict, bool]] scoped
func: changed. was: returns `list[dict]`, every node of the tree in pre-order (recursive `walk`). / now: returns `(section, inside_if_data)` pairs in the same pre-order; `inside_if_data` is `True` when any enclosing section's `str(name).strip().upper()` is `INTERFACE_DATA_BLOCK`; the IF_DATA node itself gets the flag of its own parents. Recursion kept (O-4).
module: s19_app/validation/rules.py
examples: (R-VAL-032.3/1) tree PROJECT › MODULE › IF_DATA › SEGMENT › PAGE → `[(PROJECT, False), (MODULE, False), (IF_DATA, False), (SEGMENT, True), (PAGE, True)]`
examples: (R-VAL-032.3/3) IF_DATA › A › B › FROBNICATE → FROBNICATE `True`
examples: (R-VAL-032.1/4) MODULE › CHARACTERISTIC › FROBNICATE → FROBNICATE `False`
examples: (R-VAL-032.3/3 neg) mutant: flag only direct children of IF_DATA → B, FROBNICATE `False` → RED

validate_a2l_structure
req: R-VAL-032.1, R-VAL-032.2, R-VAL-032.3
in: dict a2l_data; list[dict] tags = None
out: list[ValidationIssue] issues
func: changed. was: for every section of `_iter_sections`, `section_name not in RECOGNIZED_A2L_BLOCKS` → I-1 issue; then the GROUP/FUNCTION reference pass. / now: the loop unpacks `(section, inside_if_data)`; the I-1 issue is raised when `section_name and not inside_if_data and section_name not in RECOGNIZED_A2L_BLOCKS`; the reference pass, the structure errors, the address and duplicate checks are unchanged.
module: s19_app/validation/rules.py
oracle: REQUIREMENTS.md R-VAL-032.1 … .3 (this increment); D3-12
examples: (R-VAL-032.1/1) A2L(`/begin FROBNICATE x` / `/end FROBNICATE`) → `[WARNING A2L_UNRECOGNIZED_BLOCK "Unrecognized A2L block 'FROBNICATE'." line 3]` (holds on base)
examples: (R-VAL-032.1/2) A2L(`/begin frobnicate x` / `/end frobnicate`) → one WARNING, message `Unrecognized A2L block 'FROBNICATE'.` (holds on base)
examples: (R-VAL-032.1/3) A2L(`/begin PAGE` / `0x0` / `/end PAGE`) → one WARNING `… 'PAGE'.` line 3 (holds on base)
examples: (R-VAL-032.1/4) A2L(CHARACTERISTIC C … / `/begin FROBNICATE` / `/end FROBNICATE` / `/end CHARACTERISTIC`) → one WARNING `… 'FROBNICATE'.` line 4 (holds on base)
examples: (R-VAL-032.2/1) A2L(`/begin MOD_PAR ""` / `/end MOD_PAR`) → `[]` (base: one WARNING `… 'MOD_PAR'.`)
examples: (R-VAL-032.2/2) release demo `firmware.a2l` → 0 `A2L_UNRECOGNIZED_BLOCK` (base 102: MOD_PAR 1, MOD_COMMON 1, AXIS_DESCR 100, B)
examples: (R-VAL-032.2/3) each of 34 `examples/**/*.a2l` → 0 (P; base e.g. V171 169, `memorysegment.a2l` 7)
examples: (R-VAL-032.3/1) A2L(IF_DATA XCP › SEGMENT › PAGE) → `[]` (base: SEGMENT and PAGE raised)
examples: (R-VAL-032.3/3) `software_a.a2l` → 0 `A2L_UNRECOGNIZED_BLOCK` (base 1 023, B)
examples: (R-VAL-032.1/4 neg) mutant: only top-level sections checked → the nested FROBNICATE gives `[]` → RED

a2l_reclassified_severity
req: R-TUI-042b.1, R-TUI-042b.4
in: ValidationIssue issue
out: ValidationSeverity | None
func: removed. was: INFO for a WARNING `A2L_UNRECOGNIZED_BLOCK` whose message matches `^Unrecognized A2L block '([A-Z0-9_]+)'\.$` and whose name is in the 21-name curated set, else `None`. / now: does not exist (D3-12); the engine no longer raises the names it re-labelled (R-VAL-032.2, .3) and a name it still raises is a real WARNING (R-VAL-032.1).
module: s19_app/tui/issues_view.py
examples: (R-TUI-042b.1/2) base: `PAGE` WARNING → INFO, so the row sat under INFO; target: no remap, the row sits under WARNINGS
examples: (R-TUI-042b.1/2 neg) mutant: re-introduce the remap → the `PAGE` row under INFO → RED

adjust_counts_for_a2l_triage
req: R-TUI-025.2, R-TUI-042b.2
in: dict counts; Iterable[ValidationIssue] issues
out: dict counts
func: removed. was: moves the count of re-labelled issues from WARNING to INFO (the strip, the summary, the panel's `group_counts`). / now: does not exist; the painters count `issue.severity` directly [OR-1]. If OR-1 is declined: kept as `return counts` (identity) until Inc 12 removes it, with no curated set.
module: s19_app/tui/issues_view.py
examples: (R-TUI-042b.2/1) base: List L4 → `{WARNING: 1, INFO: 3}`; target: the painters' plain counts `{ERROR: 0, WARNING: 3, INFO: 1}`
examples: (R-TUI-042b.2/1 neg) mutant: re-introduce the delta → `⚠ WARNINGS  (1)` → RED

render_groups
req: R-TUI-042b.1, R-TUI-042b.2, R-TUI-042b.4, R-TUI-042b.6
in: Sequence[ValidationIssue] window_issues; dict group_counts; bool truncated = False
out: None (mounts header, row and note widgets)
func: changed. was: classifies each windowed issue with `a2l_reclassified_severity`, groups the remapped copies (`dataclasses.replace`) in `SEVERITY_ORDER`, mounts the justification `Static` (`issue-reclassify-note`) after the INFO header when any row was remapped, caps rows at `_GROUP_DISPLAY_MAX`, appends the truncation note. / now: the same without classification: groups `window_issues` by `issue.severity` as given, never mounts the justification. Header counts stay `group_counts` verbatim; the empty note, the cap and the truncation note are unchanged.
module: s19_app/tui/issues_view.py
examples: (R-TUI-042b.1/1) window I_0, W_0, E_0 with counts `{E:1, W:1, I:1}` → headers `✗ ERRORS  (1)`, `⚠ WARNINGS  (1)`, `• INFO  (1)`, each followed by its one row (holds on base)
examples: (R-TUI-042b.1/2) List L4, counts `{W:3, I:1}` → `⚠ WARNINGS  (3)`, rows PAGE, MOD_PAR, FROBNICATE (`sev-warning`), `• INFO  (1)`, row MAC_DUPLICATE_ADDRESS (base: `⚠ WARNINGS  (…)` row FROBNICATE; `• INFO  (…)`, the justification, rows PAGE, MOD_PAR, MAC_DUPLICATE_ADDRESS)
examples: (R-TUI-042b.6/1) List L4 → the child after `• INFO  (1)` is the MAC_DUPLICATE_ADDRESS `IssueRow`; `query(".issue-reclassify-note")` → empty (base: the note `Standard ASAP2 keyword (curated set) — reclassified WARNING → INFO per the Cambio4 triage: …`)
examples: (R-TUI-042b.4/1) the PAGE row's classes include `sev-warning`, not `sev-info`
examples: (R-TUI-042b.6/1 neg) mutant: restore the note → the child after the INFO header is a `Static` → RED

update_validation_issues_view
req: R-TUI-025.2
in: self (S19TuiApp)
out: None (paints the strip and the summary line, then calls `_render_validation_issues_groups`)
func: changed [OR-1]. was: `severity_counts = adjust_counts_for_a2l_triage({ERROR: …, WARNING: …, INFO: …}, self._validation_issues)`. / now: `severity_counts` = the plain per-severity count dict of `self._validation_issues`; everything else unchanged (paging bounds, summary format, logging).
module: s19_app/tui/app.py
examples: (R-TUI-025.2/1) List L4 → strip `Errors 0 … Warnings 3 … Info 1`; summary `total=4 | errors=0 | warnings=3 | info=1 | filter=all | page 1/1 rows 1-4/4` (base: `warnings=1 | info=3`)
examples: (AT-I11-1) clean release demo → `total=262 | errors=0 | warnings=262 | info=0 | filter=all | page 1/7 rows 1-40/262` (base `total=364 | errors=0 | warnings=262 | info=102 | … page 1/10 rows 1-40/364`)

_render_validation_issues_groups
req: R-TUI-042b.2
in: self (S19TuiApp)
out: None (calls `GroupedIssuesPanel.render_groups`)
func: changed [OR-1]. was: `group_counts = adjust_counts_for_a2l_triage({…}, filtered)`. / now: `group_counts` = the plain per-severity count dict of `filtered`; the window slice and the `truncated` flag unchanged.
module: s19_app/tui/app.py
examples: (R-TUI-042b.2/1) List L4 → `render_groups(window, {ERROR: 0, WARNING: 3, INFO: 1}, truncated=False)`
examples: (R-TUI-025.6/1) List L4, filter `warning` → `render_groups([PAGE, MOD_PAR, FROBNICATE], {ERROR: 0, WARNING: 3, INFO: 0}, truncated=False)` → no INFO header

_filtered_validation_issues
req: R-TUI-042b.5, R-TUI-025.6
in: self (S19TuiApp)
out: list[ValidationIssue] filtered
func: changed [OR-2]. was: the issues of the filter mode in list order (`error` → ERROR only, `warning` → WARNING only, else all). / now: the same selection, then `sorted(…, key=lambda issue: _SEVERITY_RANK[issue.severity])` (stable; `_SEVERITY_RANK` built from `issues_view.SEVERITY_ORDER`, so one order everywhere).
module: s19_app/tui/app.py
examples: (R-TUI-042b.5/2) list W_a, E_b, W_c, E_d, mode `all` → E_b, E_d, W_a, W_c (base: W_a, E_b, W_c, E_d)
examples: (R-TUI-042b.5/1) List L45 → indexes 0–2 = E_0 … E_2, 3–42 = W_0 … W_39, 43–44 = I_0, I_1; page 1 = items 0–39
examples: (R-TUI-025.6/1) List L4, mode `warning` → PAGE, MOD_PAR, FROBNICATE (holds on base)
examples: (AT-I11-2) faulty release demo, mode `all` → items 0–7 are the 8 ERRORs (base after F-02: ERRORs at 0–4 and 107–109, P)
examples: (R-TUI-042b.5/1 neg) mutant: no sort → page 1 of L45 holds W_0 … W_39 and no ERROR → RED

_memory_segment_record_words
req: R-A2L-036.1, R-A2L-036.2, R-A2L-036.7
in: dict sec (a MEMORY_SEGMENT node: `meta`, `lines`)
out: tuple[list[tuple[str, int]], list[str]] (words with their text index; the comment-free texts)
func: new. `texts = _strip_a2l_comments("\n".join([sec.get("meta") or "", *(sec.get("lines") or [])])).split("\n")`; `words = [(w, i) for i, t in enumerate(texts) for w in _split_line_respecting_quotes(t)]`; returns `(words, texts)`. Lines of nested blocks (IF_DATA …) are children, never in `lines`, so they give no word.
module: s19_app/tui/a2l.py
examples: (R-A2L-036.1/2) `software_a.a2l` first segment: meta `""`, lines [`SystemCalFLash "" DATA FLASH INTERN 0xA001C000 0x1000 -1 -1 -1 -1 -1`] → words `SystemCalFLash, "", DATA, FLASH, INTERN, 0xA001C000, 0x1000, -1, -1, -1, -1, -1` (text 1); texts[0] = `""`
examples: (R-A2L-036.1/3) meta `boot CODE FLASH INTERN FLASH 0x00000000 0x010000`, lines [] → words `boot, CODE, FLASH, INTERN, FLASH, 0x00000000, 0x010000` (text 0)
examples: (R-A2L-036.1/1) V161 `ECU_Code`: meta `ECU_Code`, lines [`        "Memory segment for code part of the ECU"`, `        DATA FLASH EXTERN 0x16000 0x86C -1 -1 -1 -1 -1`] (the parser keeps a line's indent and strips its end) → words `ECU_Code` (0), `Memory segment for code part of the ECU` (1), `DATA, FLASH, EXTERN, 0x16000, 0x86C, -1 …` (2)
examples: (R-A2L-036.2/4) lines [`/* 0x10 0x20 */`, `DATA FLASH INTERN 0x1000 0x200 -1`] → the comment gives no word
examples: (R-A2L-036.7/1) meta `""`, lines [] → `([], [""])`

extract_memory_segments
req: R-A2L-036.1, R-A2L-036.2, R-A2L-036.3, R-A2L-036.4, R-A2L-036.6, R-A2L-036.7, R-A2L-036.8, R-A2L-036.9, R-A2L-036.10, R-A2L-036.11, R-A2L-036.12, R-A2L-034, R-SEG-SRC.6
in: list[dict] sections
out: list[dict] segments (I-3)
func: changed. was: `block_name = parse_begin_meta(meta)[0]` (`"UNKNOWN"` when the meta is empty); the record is the first line of ≥ 5 quote-aware words; usage/kind = words 0/1; base/size = `int(words[3], 0)` / `int(words[4], 0)` (a `ValueError` leaves them `None`); offset = word 5 when present. / now: words from `_memory_segment_record_words`; `block_name` = words[0] or `None`; the first `k ≥ 1` where words `k` and `k+1` both pass `int(w, 0)` gives `base`, `size`, `raw_first_line = texts[line of word k].strip()`, `offset` = `int(words[k+2], 0)` when present and a number, else `None`; `usage` / `kind` = the last word of words `1 … k-1` in `PROGRAM_TYPE_WORDS` / `MEMORY_TYPE_WORDS`, else `None`; no such `k` → base, size, offset, usage, kind `None` and `raw_first_line` `""`. The walk (MEMORY_SEGMENT nodes in pre-order, recursing into other nodes' children) is unchanged.
module: s19_app/tui/a2l.py
oracle: ASAM MCD-2 MC MEMORY_SEGMENT record (Name LongIdentifier PrgType MemoryType Attribute Address Size Offset×5); the shipped fixtures (P)
examples: (R-A2L-036.2/1, R-A2L-036.3/1, R-A2L-036.8/1, R-A2L-036.9/1, R-A2L-036.6/1) V161 → `[{block_name: "ECU_Code", raw_first_line: "DATA FLASH EXTERN 0x16000 0x86C -1 -1 -1 -1 -1", usage: "DATA", kind: "FLASH", base: 0x16000, size: 0x86C, offset: -1}, {"ECU_Data", …, "DATA", "FLASH", 0x810000, 0x10000, -1}]` (holds on base)
examples: (R-A2L-036.9/1) V171 `TRANSFORMER_CALIBRATION` → usage `DATA`, kind `NOT_IN_ECU`, base 0x7FFF0000, size 0x1000 (holds on base); `memorysegment.a2l` → (`AscetCode`, `CODE`, `FLASH`, 0x08000000, 0xF800, −1), (`AscetCalibrationRom`, `DATA`, `ROM`, 0x0800F800, 0x800, −1), (`Variables`, `DATA`, `RAM`, 0x20000000, 0x2800, −1) (holds on base)
examples: (R-A2L-036.1/2, .2/2, .3/2, .6/3, .8/1, .9/1) `software_a.a2l` → (`SystemCalFLash`, `DATA`, `FLASH`, 0xA001C000, 0x1000, −1), (`SafetyCalFlash`, …, 0xA0038000, 0x1000, −1), (`PerformanceCalFlash`, …, 0xA0050000, 0x1000, −1) (base: (`UNKNOWN`, usage `SystemCalFLash`, kind `""`, base `None`, size `None`, offset 0xA001C000) …, B)
examples: (R-A2L-036.2/3, .3/3, .8/2, .9/2) release demo → (`boot`, `CODE`, `FLASH`, 0x0, 0x10000, `None`), (`app`, `CODE`, `FLASH`, 0x40000, 0x2C9FA0, `None`), (`cal`, `DATA`, `FLASH`, 0x800000, 0x131FC0, `None`), (`config`, `DATA`, `FLASH`, 0xC00000, 0x1000, `None`) (base: names only, all else `None`, B)
examples: (R-A2L-036.10/1) `case_07_stress_smoke/firmware.a2l` → (`main`, usage `None`, kind `FLASH`, 0x08000000, 0x400, `None`) (base: (`main`, `None` ×5))
examples: (R-A2L-036.4/1) `S1 "" DATA FLASH INTERN 0x1000 BAD` → base `None`, size `None`, usage `None`, kind `None` (base: base 0x1000, size `None`)
examples: (R-A2L-036.4/3) `S3 "" 0x10 DATA 0x20` → base `None`, size `None`
examples: (R-A2L-036.8/3) `M3 "CODE" DATA FLASH INTERN 0x100 0x10` → usage `DATA`, kind `FLASH`
examples: (R-A2L-036.9/3) `M2 "FLASH" DATA RAM INTERN 0x100 0x10` → usage `DATA`, kind `RAM`
examples: (R-A2L-036.11/1) `M1 "" CODE INTERN 0x100 0x10` → usage `CODE`, kind `None`, base 0x100, size 0x10
examples: (R-A2L-036.12/1) `S2 "" DATA FLASH INTERN` → usage `None`, kind `None`
examples: (R-A2L-036.7/1) `/begin MEMORY_SEGMENT` / `/end MEMORY_SEGMENT` → `{block_name: None, raw_first_line: "", usage: None, kind: None, base: None, size: None, offset: None}` (base: `block_name` `"UNKNOWN"`)
examples: (R-A2L-036.6/2) TC-682 `Calib Vars Rom` → offset 0x400; `Plain` → offset `None` (holds on base)
examples: (R-A2L-036.2/1 neg) mutant: the base's fixed indexes 3/4 → `software_a.a2l` and the release demo give base `None` → RED
examples: (R-A2L-036.9/3 neg) mutant: the first memory-type word → `M2` kind `FLASH` → RED

render_curve_description
req: R-A2L-120, R-A2L-121, R-A2L-122, R-A2L-123
in: dict description (from `describe_curve_tag`)
out: str text
func: changed. was: when `points` exist: blank line, header `  {'x':>xw}   {'y':>yw}`, one line per point ending with `   ({x_note})` when the point has `x_note`. / now: `all_index = all(p.get("x_note") for p in points)`; when `all_index`: blank line, the line `  x: point index (axis points unavailable)`, the header, point lines with no suffix; otherwise as before (mixed case keeps the per-row suffix). Header, widths, `(!)` marks, `y shape:` and notes unchanged.
module: s19_app/tui/a2l.py
examples: (R-A2L-120/1, R-A2L-121/1, R-A2L-122/1) Curve C1 → lines `` (blank), `  x: point index (axis points unavailable)`, `  x     y`, `  0   210`, `  1   410`, `  2   610`, `` , `  y shape: ▁▄█` … (base: no note line; `  0   210   (index (axis points unavailable))` ×3, B)
examples: (R-A2L-123/1) points (10, 210, no note), (20, 410, no note), (2, 610, `index (axis points unavailable)`) → `   x     y`, `  10   210`, `  20   410`, `   2   610   (index (axis points unavailable))`; no `x: point index` line (holds on base)
examples: (R-A2L-121/1 neg) mutant: emit the note line inside the point loop → 3 occurrences → RED
examples: (R-A2L-122/1 neg) mutant: keep the per-row suffix when `all_index` → `  0   210   (index …)` → RED

parse_a2l_file
req: R-A2L-034
in: Path path; A2LProgress progress = None
out: dict {path, sections, errors, tags, record_layouts_by_name, compu_methods_by_name, compu_tabs_by_name}
func: unchanged. Builds the section tree (`_parse_a2l_sections`: `name` = the word after `/begin` as written, `meta` = the rest of that line, `start_line`, `lines` = the node's own lines only, `children`), then `extract_a2l_tags`; logs the segment distribution through `extract_memory_segments` + `classify_address`.
module: s19_app/tui/a2l.py
examples: (R-A2L-036.1/3) `/begin MEMORY_SEGMENT boot CODE FLASH INTERN FLASH 0x00000000 0x010000` → node `{name: "MEMORY_SEGMENT", meta: "boot CODE FLASH INTERN FLASH 0x00000000 0x010000", lines: []}` (holds on base)

_strip_a2l_comments
req: R-A2L-036.2
in: str text
out: str text
func: unchanged. Removes `/* … */` and `// …` (to the next newline) outside quoted strings.
module: s19_app/tui/a2l.py
examples: (R-A2L-036.2/4) `"\n/* 0x10 0x20 */\nDATA FLASH INTERN 0x1000 0x200 -1"` → the middle text holds no word (holds on base)

_split_line_respecting_quotes
req: R-A2L-036.1
in: str line
out: list[str] words
func: unchanged. Whitespace split; a `"…"` span is one word without its quotes.
module: s19_app/tui/a2l.py
examples: (R-A2L-036.1/2) `SystemCalFLash "" DATA` → `["SystemCalFLash", "", "DATA"]` (holds on base)

classify_address
req: R-A2L-034
in: int | None address; list[dict] segments
out: str region ("flash" | "ram" | "unknown")
func: unchanged. First segment holding the address with base and size: kind RAM or usage VARIABLE → ram; kind FLASH/ROM or usage CODE → flash; DATA/ROM → flash; DATA/RAM → ram (O-1: `VARIABLE` vs `VARIABLES`, not changed).
module: s19_app/tui/a2l.py
examples: (R-A2L-034/1) address 0x00800010 with the release demo segments → `flash` (base `unknown`: no segment had a base)

extract_a2l_tags
req: R-A2L-034
in: list[dict] sections; dict record_layouts_by_name = None; dict compu_methods_by_name = None
out: list[dict] tags
func: unchanged. `memory_region = classify_address(tag address, extract_memory_segments(sections))` (`a2l.py:2431`, `:2620`).
module: s19_app/tui/a2l.py
examples: (R-A2L-034/1) release demo → 462/462 `memory_region == "flash"` (base 462 `unknown`, B)
examples: (R-A2L-034/2) `case_07_stress_smoke/firmware.a2l` → 8 `flash`, 4 `unknown` (base 12 `unknown`, P)

SplitJoinWindow._a2l_rows
req: R-SEG-SRC.6
in: self
out: list[SegRow] rows
func: unchanged. `extract_memory_segments(data["sections"])`; skips `base is None or size is None`; `SegRow(str(block_name or f"segment_{i:02d}"), "a2l", base, size)`; cached per A2L data object (O-2: size 0 still listed).
module: s19_app/tui/segment_split_view.py
examples: (AT-I11-4) release demo → `[SegRow("boot", "a2l", 0x0, 0x10000), SegRow("app", "a2l", 0x40000, 0x2C9FA0), SegRow("cal", "a2l", 0x800000, 0x131FC0), SegRow("config", "a2l", 0xC00000, 0x1000)]`; chip `a2l(4)` (base `[]`, `a2l(0)`)
examples: (R-SEG-SRC.6/2) `software_a.a2l` → 3 rows, `a2l(3)` (base `a2l(0)`)

describe_curve_tag
req: R-A2L-120
in: dict tag; dict a2l_data; dict mem_map
out: dict description
func: unchanged. For a single-axis CURVE, point `i` gets `x = x_run[i]`, `x_note = None` when the axis run decoded and covers `i`; else `x = i`, `x_note = "index (axis points unavailable)"` (`a2l.py:3071-3079`).
module: s19_app/tui/a2l.py
examples: (R-A2L-120/1) Curve C1 → points `[(0, 210.0, note), (1, 410.0, note), (2, 610.0, note)]` (holds on base)

## Entities

[Data: RECOGNIZED_A2L_BLOCKS]
in: set[str]
desc: see the node above; 61 names; read only by `validate_a2l_structure`.

[Data: INTERFACE_DATA_BLOCK]
in: str
desc: new constant `"IF_DATA"` in `rules.py`; the block whose descendants `_iter_sections` flags.

[Data: PROGRAM_TYPE_WORDS]
in: frozenset[str]
desc: new in `a2l.py`: CALIBRATION_VARIABLES, CODE, DATA, EXCLUDE_FROM_FLASH, OFFLINE_DATA, RESERVED, SERAM, VARIABLES.

[Data: MEMORY_TYPE_WORDS]
in: frozenset[str]
desc: new in `a2l.py`: EEPROM, EPROM, FLASH, NOT_IN_ECU, RAM, REGISTER, ROM.

[Data: S19TuiApp._validation_issues]
in: list[ValidationIssue]
desc: the session's issue list (`build_validation_report` + integrity notices, `app.py:17635-17660`); the severity each issue carries is final (I-2).

[I/O: A2L file]
desc: untrusted input. Section names reach the issue message (rendered through `safe_text`, C-17, unchanged); MEMORY_SEGMENT words reach `int(w, 0)` (a word of more than 4 300 digits raises `ValueError` → not a number; one pass per block, stops at the first pair).

[Interface: Issues screen]
desc: strip, summary line, grouped panel, paging (CTX-ISSUES-SCREEN). Painted from `_validation_issues` and `_filtered_validation_issues()`.

[Interface: Split / Join a2l source]
desc: the `a2l(<n>)` chip and the a2l rows (S17 CTX).

[Interface: description window]
desc: `d` on the A2L Explorer; a `markup=False` modal showing `render_curve_description`'s text.

[Interface: A2L Explorer Region column]
desc: `memory_region` per tag row (`app.py:19893`); also `mem=<region>` in the A2L summary of project reports (R-A2L-077).

## Edges

[I/O: A2L file] ──▶ parse_a2l_file
parse_a2l_file ──▶ extract_a2l_tags
extract_a2l_tags ──▶ extract_memory_segments
extract_memory_segments ──▶ _memory_segment_record_words
_memory_segment_record_words ──▶ _strip_a2l_comments
_memory_segment_record_words ──▶ _split_line_respecting_quotes
extract_memory_segments ──▶ [Data: PROGRAM_TYPE_WORDS]
extract_memory_segments ──▶ [Data: MEMORY_TYPE_WORDS]
extract_a2l_tags ──▶ classify_address
extract_a2l_tags ──▶ [Interface: A2L Explorer Region column]
SplitJoinWindow._a2l_rows ──▶ extract_memory_segments
SplitJoinWindow._a2l_rows ──▶ [Interface: Split / Join a2l source]
validate_a2l_structure ──▶ _iter_sections
_iter_sections ──▶ [Data: INTERFACE_DATA_BLOCK]
validate_a2l_structure ──▶ [Data: RECOGNIZED_A2L_BLOCKS]
validate_a2l_structure ──▶ [Data: S19TuiApp._validation_issues]
when: through `validate_a2l_internal_issues` → `build_validation_report` (unchanged)
[Data: S19TuiApp._validation_issues] ──▶ update_validation_issues_view
[Data: S19TuiApp._validation_issues] ──▶ _filtered_validation_issues
_filtered_validation_issues ──▶ _render_validation_issues_groups
_render_validation_issues_groups ──▶ render_groups
render_groups ──▶ [Interface: Issues screen]
update_validation_issues_view ──▶ [Interface: Issues screen]
describe_curve_tag ──▶ render_curve_description
render_curve_description ──▶ [Interface: description window]

Removed edges: `render_groups ──▶ a2l_reclassified_severity`; `update_validation_issues_view ──▶ adjust_counts_for_a2l_triage`; `_render_validation_issues_groups ──▶ adjust_counts_for_a2l_triage`; `adjust_counts_for_a2l_triage ──▶ a2l_reclassified_severity`.

## Findings

> E2-1 (for E3). Requirement → node coverage: every active row of `01-requirements.md` has at least one example above — R-VAL-032.1 … .3: `validate_a2l_structure`, `_iter_sections`, `RECOGNIZED_A2L_BLOCKS`; R-TUI-042b.1, .2, .4, .6: `render_groups`, `_render_validation_issues_groups`; R-TUI-025.2: `update_validation_issues_view`; R-TUI-025.6: `_filtered_validation_issues`, `_render_validation_issues_groups`; R-TUI-042b.5: `_filtered_validation_issues`; R-A2L-036.1 … .4, .6 … .12: `extract_memory_segments`, `_memory_segment_record_words`; R-A2L-034: `extract_a2l_tags`, `classify_address`; R-SEG-SRC.6: `_a2l_rows`; R-A2L-120 … 123: `render_curve_description`, `describe_curve_tag`.
> E2-2 (for E3, security). Hostile input: (a) a section name with markup reaches only the I-1 message, rendered through `safe_text` (C-17 arm of TC-B94-19 kept in its rewrite); (b) a MEMORY_SEGMENT of N words costs one pass of at most N `int()` calls, each bounded by Python's 4 300-digit limit; (c) deep nesting: the walkers recurse (O-4, pre-existing, not widened).
> E2-3 (for E3). D-9's 61-name list is the one claim no fixture can fully check (a name the standard lacks would only silence a warning). The architect lens should compare it with the ASAM MCD-2 MC 1.7 keyword index if one is at hand.
> E2-4. The prototype changes 11 nodes (8 changed, 1 new, 2 removed) and keeps 7 context nodes — under the 40-node cap; no group split beyond G1/G2/G3 is needed.
