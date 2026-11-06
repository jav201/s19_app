# Code-Wire graph — Inc 4 (documents resolve symbols through the loaded A2L), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `b7b77c4`. Requirements `../01-requirements.md` (R-CHG-SYM.9 … .13, R-TUI-058.9), slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (`<HOME>/Github/code-wire/docs/Notation-Grammar.md`), as in `../../inc-2/codewire/graph-inc2.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first), **new** or **deleted**. Context nodes (unchanged) are here because a changed node calls them, or because a requirement is observed through them.
- Example sources are the test-case ids of `02-test-cases.md`; `B` = read from the base tree at E1; `P` = the E1 probe (`parse_change_document` timing, Windows host, `b7b77c4`: 1 000 × 20 000 → 3.12 s; historical, it sets no threshold: timings run on the LAN Linux host, E3 A-3). Every example states the Inc 4 target unless it says "holds on base".
- `CTX` = the case-08 A2L payload (`parse_a2l_file(firmware.a2l)`, a dict with `tags`); `<tag 2>`, `<tag 3>`, `<check tag>` = the generated names (01 Definitions). The slice assumes D-1 "delete" and D-2 "add `io.py`"; nodes that depend on a decision say so.

Groups for E4 (file ownership) and the interfaces they share — pinned here, changed only by an orchestrator ruling:

| Group | Files | Owns nodes |
|---|---|---|
| G1 reader | `s19_app/tui/changes/io.py` | `_symbol_name_index`, `SYMBOL_NO_A2L_CONTEXT_TEXT`, `_parse_entries`, `_parse_entry`, `_resolve_symbol_tag` |
| G2 services | `s19_app/tui/services/change_service.py`, `s19_app/tui/services/variant_execution_service.py` | `ChangeService.edit_entry_json`, `run_checks_for_project` (deleted), `_execute_one_variant` |
| G3 app | `s19_app/tui/app.py`; the two spies in `tests/test_tui_patch_editor_v2.py` (E1-slice §3) | the six `S19TuiApp` nodes |

The slice is 13 units, 9 of them functions with behaviour; one implementer can take all three groups in order G1 → G2 → G3 (G3 imports G1's constant). Testers: one for G1 + G2 (service level), one for G3 and the black-box cases.

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 the no-context text | `SYMBOL_NO_A2L_CONTEXT_TEXT: str = "no A2L context is declared for this change-set"` in `s19_app/tui/changes/io.py`; R-CHG-SYM.2's message embeds it unchanged | G1 → G1 (`_resolve_symbol_tag`), G3 (`_apply_entry_json_edit`) |
| I-2 the per-entry edit seam | `ChangeService.edit_entry_json(self, index: int, text: str, a2l_context: Optional[dict] = None) -> ChangeActionResult` | G2 → G3 |
| I-3 Check Editor spec read (Inc 5) | `on_check_editor_panel_spec_file_selected` reads with `a2l_context=self.current_a2l_data`; a resolved entry's `ChangeEntry.symbol` is the tag's spelling. Inc 5 edits the item-building lines after the read, not the read. Name source (E3 A-9): Inc 5 uses `entry.symbol` when it is set, looks up by address only for address-only entries, and adds no third name index | Inc 4 → Inc 5 |
| I-4 variant run files (Inc 9) | `_execute_one_variant(variant, files, project_dir, mac_records, a2l_data, capture_mem_map=False)` unchanged; `files` arrive resolved by the plan (`plan_variant_executions` / `_resolve_manifest_entry`, Inc 9's); this increment adds only `a2l_context=a2l_data` to the read | Inc 9 → Inc 4 (no change to the signature) |
| I-5 the session's A2L | `S19TuiApp.current_a2l_data: Optional[dict]`, written only by `_replace_current_a2l` (`app.py:19507`); read on the screen thread | existing → G3 |

## Nodes

### G1 — reader (`io.py`)

_symbol_name_index
req: R-CHG-SYM.13, R-CHG-SYM.7
in: dict? a2l_context
out: dict[str, dict]? index
func: new (D-2). `None` when `a2l_context` is not a dict. Else the loop moved from `_resolve_symbol_tag` (`io.py:1102-1108`) unchanged: for each item of `a2l_context.get("tags") or []` that is a dict, `name = str(tag.get("name") or "").strip()`; a non-empty name → `index.setdefault(name.lower(), tag)` (first match wins). Pure.
module: s19_app/tui/changes/io.py
examples: (B) `None` → `None`; `{}` → `{}`; `{"tags": [{"name": " Speed ", "address": 16, "length": 2}, {"name": "SPEED", "address": 32, "length": 2}, "x", {"name": ""}]}` → `{"speed": <the first tag, address 16>}` (1 key)
examples: (R-CHG-SYM.13/1) the planted 220 040-tag context → 220 040 keys, built at most once per read (E3 A-2, A-3)

_resolve_symbol_tag
req: R-CHG-SYM.2, R-CHG-SYM.3, R-CHG-SYM.4, R-CHG-SYM.7, R-CHG-SYM.13
in: str symbol; dict[str, dict]? symbol_index
out: tuple(dict? tag, str reason)
func: changed (D-2). was: takes `a2l_context`, rebuilds the name index from all tags on every call (cost O(tags) per symbol entry, P). now: takes the prebuilt `symbol_index`; `None` → `(None, f"the symbol {symbol!r} cannot be resolved — {SYMBOL_NO_A2L_CONTEXT_TEXT}")`; `index.get(symbol.strip().lower())` miss → the R-CHG-SYM.3 reason; a tag without `address` or `length` → the R-CHG-SYM.4 reason; else `(tag, "")`. Reason texts unchanged byte for byte.
module: s19_app/tui/changes/io.py
examples: (R-CHG-SYM.10/1) symbol `"<tag 2>"`, index `None` → `(None, "the symbol '<tag 2>' cannot be resolved — no A2L context is declared for this change-set")` (holds on base)
examples: (R-CHG-SYM.9/1) symbol `"<tag 2>"` in lower case, index of CTX → `(<tag 2>'s row, "")`
examples: (R-TUI-058.9/3) `"NO_SUCH_TAG"`, index of CTX → `(None, "the symbol 'NO_SUCH_TAG' resolves to no tag in the declared A2L")` (holds on base)

_parse_entry
req: R-CHG-SYM.1, R-CHG-SYM.2, R-CHG-SYM.13
in: int index; object element; str encoding; str value_mode; list[ValidationIssue] issues; dict[str, dict]? symbol_index = None
out: ChangeEntry? entry
func: changed (D-2). was: keyword `a2l_context`, forwarded to `_resolve_symbol_tag`. now: keyword `symbol_index`, forwarded. Every other limb (C-4, C-6, drift C-14, the address and value parses, the symbol stamp) unchanged.
module: s19_app/tui/changes/io.py
modify: issues (append)
examples: (R-TUI-058.9/2) element `{"type": "bytes", "address": "0x100", "bytes": "01", "symbol": 7}`, index `None` → `None`; issues gets `CHG-SYMBOL-UNRESOLVED` `entry 0 declares a 'symbol' that is not a tag name string — the entry was skipped` (holds on base)
examples: (R-CHG-SYM.9/2) entry 2 of `demo_patch`, index of CTX → a `ChangeEntry` with `symbol == "<tag 2>"`, 0 issues

_parse_entries
req: R-CHG-SYM.13, R-CHG-SYM.9, R-CHG-SYM.10
in: list raw_entries; str encoding; str value_mode; list[ValidationIssue] issues; dict? a2l_context = None
out: list[ChangeEntry] entries
func: changed (D-2, E3 A-2). was: forwards `a2l_context` to every `_parse_entry`. now: lazy index — no index until the first raw entry that is a dict whose `symbol` is a `str`; at that entry `symbol_index = _symbol_name_index(a2l_context)` (once per read) and `symbol_index=symbol_index` goes to that and every later `_parse_entry`; earlier entries carry no string symbol, so they never consult it. A document with no such entry builds no index (the base's cost for address-only documents). Signature unchanged (its caller `parse_change_document` is unchanged). The entry-count ceiling is unchanged.
module: s19_app/tui/changes/io.py
examples: (R-CHG-SYM.13/1) 1 000 symbol entries, the 220 040-tag context → 1 000 entries, 0 issues, `_symbol_name_index` called `1` time; wall time < `1.0` s on the LAN Linux host — base: per-entry rebuild (10.46–11.03 s at 20 000 tags on the Linux host, E3 probe)
examples: (R-CHG-SYM.13/2) 1 address-only entry, the 220 040-tag context → 1 entry, 0 issues, `_symbol_name_index` called `0` times; `demo_patch`, CTX → called `1` time
examples: (R-CHG-SYM.10/1) `demo_patch` entries, `a2l_context=None` → 5 entries, 2 R-CHG-SYM.2 issues (holds on base)

parse_change_document
req: R-CHG-SYM.9, R-CHG-SYM.10, R-CHG-SYM.13
in: str text; dict? a2l_context = None
out: ChangeDocument document
func: unchanged (context). Decodes, validates the envelope, calls `_parse_entries(…, a2l_context=a2l_context)`, adds collision issues. Never re-reads the context after `_parse_entries`.
module: s19_app/tui/changes/io.py
examples: (R-CHG-SYM.9/3) `demo_patch` text, CTX → 7 entries, `has_errors` `False`

read_change_document
req: R-CHG-SYM.9, R-CHG-SYM.11
in: str path_text; Path base_dir; SizeProbe? size_probe = None; dict? a2l_context = None
out: ChangeDocument document
func: unchanged (context). Resolves the path, applies the read cap, reads the bytes, calls `parse_change_document(payload, a2l_context=a2l_context)`, stamps `source_path`.
module: s19_app/tui/changes/io.py
examples: (R-CHG-SYM.9/5) `demo_check.chk.json`, CTX → 3 entries, entry 2 `symbol == "<check tag>"`, 0 issues

### G2 — services

ChangeService.edit_entry_json
req: R-CHG-SYM.9, R-CHG-SYM.10, R-TUI-058.9
in: int index; str text; dict? a2l_context = None
out: ChangeActionResult result
func: changed. was: `probe = parse_change_document(envelope_text)` — no declared A2L, so an unchanged symbol entry is refused (T-12). now: `probe = parse_change_document(envelope_text, a2l_context=a2l_context)`. The envelope, the one-entry rule, the history push, the replace and the message texts are unchanged (I-2).
module: s19_app/tui/services/change_service.py
modify: [Data: ChangeService.document] (replace one entry); [Data: ChangeService._history] (append)
examples: (R-CHG-SYM.9/4) draft with entry 2 = `<tag 2>` symbol entry; index `2`; text = `entry_seed_json(2)`; `a2l_context=CTX` → `ok` `True`, `issues` `[]`, entry 2 equal to before — base: `ok` `False`, message `Patch Editor: entry edit rejected - see findings.`, 1 issue `CHG-SYMBOL-UNRESOLVED`
examples: (R-CHG-SYM.10/4) the same, `a2l_context=None` → `ok` `False`; message `Patch Editor: entry edit rejected - see findings.`; issues = [the R-CHG-SYM.2 finding for entry `0`] (holds on base)

ChangeService.load
req: R-CHG-SYM.9
in: str path_text; Path base_dir; dict? a2l_context = None
out: ChangeActionResult result
func: unchanged (context). Forwards `a2l_context` to `read_change_document`; message `Loaded <kind>: <n> entr(y|ies), <e> error(s)`.
module: s19_app/tui/services/change_service.py
examples: (R-CHG-SYM.9/1) `demo_patch.changes.json`, CTX → message `Loaded change: 7 entries, 0 error(s)`, `ok` `True`

ChangeService.load_text
req: R-CHG-SYM.9
in: str text; dict? a2l_context = None
out: ChangeActionResult result
func: unchanged (context). As `load`, from text.
module: s19_app/tui/services/change_service.py
examples: (R-CHG-SYM.9/2) `demo_patch` text, CTX → `Loaded change: 7 entries, 0 error(s)`

run_checks_for_project
req: (none — canon S9 review "Removed (D9-7)")
in: Path check_path; Path image_path; Path? mac_path = None; Path? a2l_path = None
out: CheckRunResult
func: deleted (D-1). was: reads the check document with no `a2l_context` (T-03), then parses `a2l_path` for linkage only. now: gone, with its module-docstring paragraph and the imports only it used. Test node `tests/test_checks_engine.py::test_headless_project_run` and its import go with it; TC-023's registry `nodes` drop it at integration and E4 runs `tests/test_id_registry.py` (E3 A-1). Fallback if D-1 is ruled "keep": `changed`, `a2l_data = parse_a2l_file(a2l_path) if a2l_path is not None else None` moved above the read and passed as `a2l_context=a2l_data` (row `R-CHK-HEADLESS.1`).
module: s19_app/tui/services/change_service.py
examples: (B) `grep -rn "run_checks_for_project(" s19_app` after the change → 0 hits

_execute_one_variant
req: R-CHG-SYM.11, R-CHG-SYM.12
in: VariantDescriptor variant; Sequence[Path] files; Path project_dir; Sequence[dict]? mac_records; dict? a2l_data; bool capture_mem_map = False
out: VariantExecutionResult result
func: changed. was: `document = read_change_document(str(file_path), project_dir)` — no declared A2L, although `a2l_data` (the project's A2L file, parsed once by `execute_variant_plan`) is in hand and used for linkage (T-04). now: `read_change_document(str(file_path), project_dir, a2l_context=a2l_data)`. Nothing else changes: the image parse, the per-kind dispatch, the save-back, the isolation `except` (I-4).
module: s19_app/tui/services/variant_execution_service.py
modify: result (append summaries / check results / diagnostics)
examples: (R-CHG-SYM.11/1) files `[demo_patch]`, `a2l_data` = CTX → 1 change summary, 0 `CHG-SYMBOL-UNRESOLVED` issues, no entry `blocked`, the entries at `<tag 2>`'s and `<tag 3>`'s addresses `applied` — base: every entry `blocked`
examples: (R-CHG-SYM.11/1b) files `[demo_check]`, CTX → aggregates `{"passed": 3, "failed": 0, "uncheckable": 0}`; files `[demo_check_fails]` → `{"passed": 0, "failed": 3, "uncheckable": 0}` — base: both blocked `doc-fault`, 3 uncheckable
examples: (R-CHG-SYM.12/1) files `[demo_patch]`, `a2l_data` `None` → 2 R-CHG-SYM.2 issues, every entry `blocked` (holds on base)

execute_variant_plan
req: R-CHG-SYM.11, R-CHG-SYM.12
in: Sequence plan; Path project_dir; Path? mac_path; Path? a2l_path; StatusCallback? status_callback; bool capture_mem_maps
out: list[VariantExecutionResult]
func: unchanged (context). `a2l_data = parse_a2l_file(a2l_path) if a2l_path is not None else None` once (`:2662`), passed to each `_execute_one_variant`.
module: s19_app/tui/services/variant_execution_service.py
examples: (R-CHG-SYM.12/1) `a2l_path=None` → every call gets `a2l_data=None` (holds on base)

execute_project_variants
req: R-CHG-SYM.11, R-CHG-SYM.12
in: Path project_dir; ProjectVariantSet variant_set; str scope; Sequence[Path] fallback_batch; StatusCallback? status_callback; bool capture_mem_maps
out: tuple(list[VariantExecutionResult], list[ValidationIssue])
func: unchanged (context). The A2L is `validate_project_files(project_dir)`'s one A2L file, or `None` (`:2743-2755`) — the project's A2L file; no session state reaches it.
module: s19_app/tui/services/variant_execution_service.py
examples: (R-CHG-SYM.11/1) project with `firmware.a2l` → `a2l_path` = that file; without → `None`
examples: (R-CHG-SYM.11/3, E3 A-4) the report run (`app.py:6566`) calls it as Execute scope does: batch `[demo_patch]`, project with `firmware.a2l` → `firmware-patched.s19` written, both symbol entries applied — base: every entry `blocked`, no file
examples: (R-CHG-SYM.11/2 arm b, R-CHG-SYM.12/2, E3 S4-2) the session A2L unloaded (project with `firmware.a2l`) → still applied; the session A2L attached (project without an A2L file) → `a2l_path` `None`, no patched file

### G3 — app (`app.py`)

S19TuiApp._patch_editor_load
req: R-CHG-SYM.9, R-CHG-SYM.10
in: S19TuiApp self; PatchEditorPanel panel; str path_text
out: None
func: changed. was: `service.load(path_text, self.base_dir)`. now: `service.load(path_text, self.base_dir, a2l_context=self.current_a2l_data)`. Report, `mark_loaded` on `ok`, and the shared tail unchanged.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.status] (append)
examples: (R-CHG-SYM.9/1) `current_a2l_data` = CTX; `demo_patch.changes.json` → status lines `Loaded change: 7 entries, 0 error(s)` then none; `panel.mark_loaded()` called — base: `Loaded change: 5 entries, 2 error(s)` + 2 finding lines, no `mark_loaded`
examples: (R-CHG-SYM.10/1) `current_a2l_data` `None` → `Loaded change: 5 entries, 2 error(s)` + 2 R-CHG-SYM.2 lines (holds on base)

S19TuiApp.on_patch_editor_panel_action_requested
req: R-CHG-SYM.9, R-CHG-SYM.10
in: S19TuiApp self; PatchEditorPanel.ActionRequested event
out: None
func: changed, `parse_paste` arm only. was: `service.load_text(event.paste_text)`. now: `service.load_text(event.paste_text, a2l_context=self.current_a2l_data)`. Every other arm unchanged.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.status] (append)
examples: (R-CHG-SYM.9/2) CTX loaded, paste `demo_patch` text → `Loaded change: 7 entries, 0 error(s)`; `mark_pasted` called — base: 5 entries, 2 errors, no `mark_pasted`
examples: (R-CHG-SYM.10/2) no A2L → 5 entries, 2 R-CHG-SYM.2 lines (holds on base)

S19TuiApp._apply_changeset_json_edit
req: R-CHG-SYM.9, R-CHG-SYM.10
in: S19TuiApp self; str? edited
out: None
func: changed. was: pre-check `parse_change_document(edited)`. now: `parse_change_document(edited, a2l_context=self.current_a2l_data)`; on a clean pre-check it posts `parse_paste` as before, which reads with the same A2L (previous node).
module: s19_app/tui/app.py
examples: (R-CHG-SYM.9/3) CTX loaded; draft of `demo_patch` (7 entries); `edited` = the seed → no `Edit JSON refused` line; then `Loaded change: 7 entries, 0 error(s)` — base: `Edit JSON refused: change text carries 2 error(s) — the document is unchanged.`
examples: (R-CHG-SYM.10/3) the A2L unloaded after the paste → `Edit JSON refused: change text carries 2 error(s) — the document is unchanged.` (holds on base); draft keeps 7 entries

S19TuiApp._apply_entry_json_edit
req: R-CHG-SYM.9, R-CHG-SYM.10, R-TUI-058.9
in: S19TuiApp self; int index; str? edited
out: None
func: changed. was: `result = self._change_service.edit_entry_json(index, edited)`, report, refresh. now: `edit_entry_json(index, edited, a2l_context=self.current_a2l_data)`; `_report_change_result(result)`; then, when `not result.ok` and `self.current_a2l_data is None` and any `issue.code == "CHG-SYMBOL-UNRESOLVED" and SYMBOL_NO_A2L_CONTEXT_TEXT in issue.message` (I-1) → `self.set_status("Patch Editor: the entry names an A2L symbol and no A2L is loaded - load the A2L, then edit the entry again.")`; then `_refresh_patch_history_view()` as before. The busy refusal and the Cancel no-op are unchanged.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.status] (append)
examples: (R-CHG-SYM.9/4) CTX loaded; draft row 2 = `<tag 2>`; seed unchanged → 0 `entry edit rejected` lines, 0 finding lines; entry 2 unchanged
examples: (R-TUI-058.9/1) the A2L unloaded after the paste; row 2; seed unchanged → lines in order: `Patch Editor: entry edit rejected - see findings.`; `[CHG-SYMBOL-UNRESOLVED] error: entry 0: the symbol '<tag 2>' cannot be resolved — no A2L context is declared for this change-set — the entry was skipped`; `Patch Editor: the entry names an A2L symbol and no A2L is loaded - load the A2L, then edit the entry again.` — base: the first two lines only
examples: (R-TUI-058.9/2) no A2L; confirmed entry `{"type": "bytes", "address": "0x100", "bytes": "01", "symbol": 7}` → `entry edit rejected - see findings.` + `[CHG-SYMBOL-UNRESOLVED] error: entry 0 declares a 'symbol' that is not a tag name string — the entry was skipped`; `0` plain lines
examples: (R-TUI-058.9/3) CTX loaded; `"symbol": "NO_SUCH_TAG"` → the R-CHG-SYM.3 line; `0` plain lines
examples: (R-TUI-058.9/3 arm b, E3 A-5) CTX loaded; `"symbol": "no A2L context is declared for this change-set"` → the R-CHG-SYM.3 line, whose message contains the I-1 text; `0` plain lines (the `current_a2l_data is None` guard decides)

S19TuiApp.on_check_editor_panel_spec_file_selected
req: R-CHG-SYM.9, R-CHG-SYM.10
in: S19TuiApp self; CheckEditorPanel.SpecFileSelected event
out: None
func: changed. was: `read_change_document(str(candidate), self.base_dir)`. now: `read_change_document(str(candidate), self.base_dir, a2l_context=self.current_a2l_data)`. The containment guard before it and the kind gate, item building and `load_spec` after it are unchanged (I-3: Inc 5 owns the item building).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.status] (append)
examples: (R-CHG-SYM.9/5) CTX loaded; `demo_check.chk.json` → `Check Editor: loaded 'demo_check.chk.json' (3 fields).`; `load_spec` gets 3 items — base: the finding line then `Check Editor: spec NOT loaded.`
examples: (R-CHG-SYM.10/5) no A2L → `[CHG-SYMBOL-UNRESOLVED] error: entry 2: the symbol '<check tag>' cannot be resolved — no A2L context is declared for this change-set — the entry was skipped`, then `Check Editor: spec NOT loaded.` (holds on base)

S19TuiApp.on_ab_diff_panel_check_file_selected
req: R-CHG-SYM.9, R-CHG-SYM.10
in: S19TuiApp self; AbDiffPanel.CheckFileSelected event
out: None
func: changed. was: `read_change_document(str(candidate), self.base_dir)`. now: `…, a2l_context=self.current_a2l_data)`. Blank-pick clear, containment guard, error and kind refusals, stash and status texts unchanged.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._diff_check_spec] (replace)
examples: (R-CHG-SYM.9/6) CTX loaded; `demo_check.chk.json` → panel status `Check spec 'demo_check.chk.json' loaded — 3 declared field(s) will ride the report.`; `_diff_check_spec` has 3 entries — base: `Check spec not loaded — [CHG-SYMBOL-UNRESOLVED] error: entry 2: …`, `_diff_check_spec` `None`
examples: (R-CHG-SYM.10/6) project open with `firmware.a2l` in its folder, session A2L unloaded → status starts `Check spec not loaded — [CHG-SYMBOL-UNRESOLVED] error: entry 2:` (holds on base; the project's file is not used)

S19TuiApp._report_change_result
req: R-TUI-058.9
in: S19TuiApp self; ChangeActionResult result
out: None
func: unchanged (context). `set_status(result.message)`, then one `[<code>] <severity>: <message>` line per issue. The R-TUI-058.9 line is painted after it, so it is the last.
module: s19_app/tui/app.py
examples: (R-TUI-058.9/1) a rejected result with 1 issue → 2 lines, message first (holds on base)

## Entities

[Data: io.SYMBOL_NO_A2L_CONTEXT_TEXT]
in: str
desc: new (D-2, I-1). Module constant `"no A2L context is declared for this change-set"`, the tail of R-CHG-SYM.2's reason, one string for the reader (`_resolve_symbol_tag`) and the app (`_apply_entry_json_edit`). R-CHG-SYM.2's message text is unchanged byte for byte. (R-CHG-SYM.10/1) entry 2 of `demo_patch` with no context → `entry 2: the symbol '<tag 2>' cannot be resolved — no A2L context is declared for this change-set — the entry was skipped` (holds on base).

[Data: S19TuiApp.current_a2l_data]
in: dict?
desc: unchanged (I-5). The session's loaded A2L; written only by `_replace_current_a2l` (`app.py:19507`) on attach, project install, file-load install and clear; read by the six G3 nodes on the screen thread. Never read by the variant run.

[Data: S19TuiApp.status]
in: list[str]
desc: unchanged. The status lines (`set_status`); cases read the lines painted since the trigger.

### Notes

> - **Threads.** All six G3 nodes run on the screen thread; `_execute_one_variant` runs in the Execute-scope worker and never reads `current_a2l_data` (R-CHG-SYM.12: the session cannot leak into a variant run).
> - **Untrusted input (trigger C6, C8).** Documents and A2L files are untrusted. The new code paints no new file-derived text: the R-TUI-058.9 line is a fixed string; finding lines keep their existing `repr` quoting and plain-text rendering. `_symbol_name_index` keeps the base's type checks (non-dict tags skipped, names coerced with `str`), so a hostile A2L cannot raise where the base did not. Cost: one index of at most the A2L's tag count per read, held only for the read.
> - **Escaping (E3 S4-6, binds E4).** Any new paint of `ChangeEntry.symbol` goes through the existing escapers (`safe_text`, `md_safe`, `_md_text`, `_esc(_strip_ctl(...))`).
> - **Not changed:** the reader's refusal texts (R-CHG-SYM.1 … .6), `recorded_document_state`, the flow reads, `_resolve_manifest_entry`, `plan_variant_executions`.
