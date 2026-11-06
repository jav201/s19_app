# Code-Wire graph — Inc 5 (Check Editor keeps picks, names and expected bytes; CRC Designer after an in-place write), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `c2cba35`. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. E3 round-1 corrections (`../E3-rulings.md`, applied as listed in `../E1-rulings.md` §6) are folded into the nodes below. Notation: Code-Wire v3.1, as in `../../inc-2/codewire/graph-inc2.md` and `../../inc-13/codewire/graph-inc13.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Context nodes (unchanged) are here because a changed node calls them or relies on their contract.
- Example sources are the case ids of `02-test-cases.md` (`R-CHKED-026/2`); `P` = the E1 pilot on `c2cba35` (`../evidence-e1/i5e1-pilot-transcript.txt`). Every example states the Inc 5 target unless it says "base".
- Values: the fixture image and case-08 values of `../01-requirements.md` Definitions (`VALUE_0001` @ `0x00000000` u8 `6C`, `VALUE_0002` @ `0x00000014` u16 `A0 BE`, memory row `0x00C00FFC` u32 `FF FF FF FF`).

## Groups and interfaces

The slice has 17 functions in 3 files; the groups follow file ownership. The interfaces below are pinned; an E4 agent proposes a change here and never changes one alone.

| Group | File | Owns nodes |
|---|---|---|
| G1 app | `s19_app/tui/app.py` | `_note_image_bytes_written`, `on_patch_editor_panel_action_requested`, `on_patch_editor_panel_save_back_decision`, `_on_project_saved`, `on_check_editor_panel_spec_file_selected`, `_check_items_to_document` |
| G2 designer | `s19_app/tui/crc_designer_view.py` | `CrcDesignerPanel.note_image_bytes_written` |
| G3 check editor | `s19_app/tui/screens_directionb.py` | `CheckEditorPanel.__init__`, `.set_a2l_parameters`, `.load_spec`, `._named_parameter`, `._collected_items`, `._rebuild_memory_table`, `._add_memory_row`, `._on_a2l_parameter_picker_selection_changed`, `._prune_spec_bytes`, `._demote_moved_spec_params` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 in-place write notice | `CrcDesignerPanel.note_image_bytes_written(self) -> None`: public, no argument, no return, never computes synchronously | G2 → G1 |
| I-2 collected item | `{"source": "param" \| "memory", "name": str, "address": int \| None, "size": int, "expected": tuple[int, ...] \| None}` in `CheckEditorPanel.ActionRequested.items`; the first four keys as on base; `expected` is the spec's bytes for a field loaded from a spec — for a parameter only while its current ledger range is its spec entry's (E3 SEC5-1) — else `None` | G3 → G1 (`_check_items_to_document`) |
| I-3 spec-load item | `load_spec(items, source_name)` with each item `{"address": int, "size": int, "expected": tuple[int, ...], "symbol": str \| None}`; signature of `load_spec` unchanged | G1 → G3 |
| I-5 validation results cleared (E5 C-10) | `CheckEditorPanel.clear_check_results(self) -> None`: public, no argument, no return; `#check_status` back to `_STATUS_HINT`, `#check_results` emptied; no tab switch, no focus move | G3 → G1 |
| I-4 memory row | `CheckEditorPanel._memory_rows: list[tuple[int, str, int, tuple[int, ...] \| None]]` — `(address, label, size, expected)`; internal to G3 | G3 only |

Interfaces with other increments:

| With | What is shared | Rule |
|---|---|---|
| Inc 13 (merged) | `CrcDesignerPanel._on_image_changed`, `on_show`, `_coverage_dirty`, `CRC_RECOMPUTE_S`; the S13 term *loaded image changes* | reused unchanged; the term is amended (`../E1-rulings.md` §2) |
| Inc 4 (merged) | `read_change_document(…, a2l_context=self.current_a2l_data)` at the spec pick sets `ChangeEntry.symbol` to the tag spelling (R-CHG-SYM.9) | consumed by I-3 `symbol` |
| batch-102 picker (merged) | `A2LParameterPicker.set_parameters(rows, signature) -> bool`, `clear_picks()`, `include_names(names) -> dict`, `picked_params`, `param_rows`, `SelectionChanged(names)` | used as they are; `a2l_parameter_picker.py` not edited |
| Inc 6 (next in the `app.py` chain) | it edits `on_patch_editor_panel_action_requested` (load arm, F-40) and `on_patch_editor_panel_save_back_decision` (F-05); it also carries D9-15 (one check home, `docs/requirements/review/CODE-CHANGES.md`), which re-roots the containment guard of `on_check_editor_panel_spec_file_selected` (E3 A-4) | rebase on Inc 5; keep both I-1 call sites ungated (/7, /8); keep the I-3 item shape `{address, size, expected, symbol}` |
| Inc 12 | deletes the `check_preview_toggle_button` branch of `CheckEditorPanel.on_button_pressed` (D9-8) | same class, disjoint function; Remove row's `pop(cursor)` keeps working with I-4 |
| Backlog (D-4 of the rulings) | the A2L enriched-tag cache and the Split / Join window after an in-place write | would extend `_note_image_bytes_written`; not in Inc 5. For Inc 10 (E3 A-4): the extension must not call `SplitJoinWindow.refresh_window` from the helper — it focuses `#sje_table` (`segment_split_view.py:1744`), the focus move E1-D2 rejected; it marks the window stale instead |

## Nodes — G1 app

S19TuiApp._note_image_bytes_written
req: R-CRC-PREVIEW-002.1, R-CRC-PREVIEW-002.5, R-CHKED-057
in: —
out: None
func: new. **Changed at E5 (C-10):** the CRC Designer and the Check Editor are queried separately, each in its own `try` (a missing panel skips only its own notice); the designer delegate as below, then `checks.clear_check_results()` (I-5), also outside its `try`. No focus move, no tab switch, no `refresh_window`. E2 text: `try: panel = self.query_one(CrcDesignerPanel)` / `except Exception: return` around the query only — the app's idiom for a not-yet-mounted tree (`watch_current_file`, `_prefill_check_editor`; `app.py` imports no `NoMatches`); then, outside the `try`, `panel.note_image_bytes_written()`, so a fault in the panel is not swallowed. Called only by the three in-place-write sites below; never on a load (the `current_file` watcher already covers loads).
module: s19_app/tui/app.py
calls: DOMNode.query_one, CrcDesignerPanel.note_image_bytes_written, CheckEditorPanel.clear_check_results
examples: (R-CRC-PREVIEW-002.5/3) CRC Designer hidden → the panel's `_coverage_dirty` becomes True, recompute count +0
examples: (R-CRC-PREVIEW-002.1/6) CRC Designer displayed, Q = 10 s → a recompute pending, count +0 after two pauses
examples: (no panel mounted) → returns None, nothing raised
examples: (R-CHKED-057/1) case 08, pilot spec picked, Validate painted `0x0-0x0 expected [6C] actual [6C] -> pass` under `validation complete`; the apply of `0x0` = `93` → the Check Editor shows 0 verdict rows and `Validate compares fields to the image` (base: the stale `-> pass` row stays)

S19TuiApp.on_patch_editor_panel_action_requested
req: R-CRC-PREVIEW-002.5
in: PatchEditorPanel.ActionRequested event
out: None
func: changed. was: the `apply_doc` arm calls `service.apply(mem_map, …)` and sets `Apply: <a> applied, <s> skipped, <b> blocked`; a `ValueError`/`KeyError` anywhere in the `try` ends as `Patch Editor: <exc>`; nothing tells the CRC Designer. / now: identical, plus, right after the `try`/`except` and before the panel refresh: `if event.action == "apply_doc": self._note_image_bytes_written()` — on both outcomes, because `ChangeService.apply` restores the journal in place before the engine runs, so a raise after that point has still written. Never inside the arm's `if counts["applied"] > 0` (E3 SEC5-2 / A-2): an apply with 0 applied has still restored an earlier apply through the journal.
module: s19_app/tui/app.py
calls: ChangeService.apply, S19TuiApp._note_image_bytes_written
examples: (R-CRC-PREVIEW-002.5/3) fixture image, document `0x8003` = `AA`, Apply → status `Apply: 1 applied, 0 skipped, 0 blocked`; key `0` → preview `concat: 0x08DAAFB7` / `fill:   0x35D90BC3` (base P: `concat: 0x9C5BCBBD`, 0 recomputes)
examples: (R-CRC-PREVIEW-002.5/6) engine wrapped to raise `KeyError("probe")` after writing → status `Patch Editor: 'probe'`; key `0` → `concat: 0x08DAAFB7`, 1 recompute
examples: (R-CRC-PREVIEW-002.5/8) after an apply of `AA` and a display (`0x08DAAFB7`), the entry's address edited to `0x9000`, Apply → status `Apply: 0 applied, 1 skipped, 0 blocked`; `mem_map[0x8003]` = `0x03`; key `0` → `concat: 0x9C5BCBBD` / `fill:   0x2A8A3950`, 1 recompute (a hook under `applied > 0`: `0x08DAAFB7` stays)
examples: (any other action, e.g. `add_entry`) → no notice (recompute count +0 on the next display of a clean CRC Designer)

S19TuiApp.on_patch_editor_panel_save_back_decision
req: R-CRC-PREVIEW-002.5
in: PatchEditorPanel.SaveBackDecision event
out: None
func: changed. was: declined (`filename is None`) or no image → status and return; else `result = self._change_service.save_patched(loaded.mem_map, …)` (which calls `adopt_rederived`, writing the re-derived bytes in place, also when it then refuses a blocked save), then the result handling. / now: identical, plus `self._note_image_bytes_written()` right after `save_patched` returns, before `_report_change_result`, whatever `result.ok` (E3 SEC5-2: a save-back refused as blocked has already adopted the re-derived bytes). Declined and no-image paths unchanged (no write, no notice).
module: s19_app/tui/app.py
calls: ChangeService.save_patched, S19TuiApp._note_image_bytes_written
examples: (R-CRC-PREVIEW-002.5/4) after an apply of `AA` and a display of the CRC Designer, entry edited to `BB`, *Save patched image as* `fixture-patched.s19` → key `0` → `concat: 0x614BD0E8` / `fill:   0xE1E79AB1`, 1 recompute (base: `0x08DAAFB7` stays)
examples: (R-CRC-PREVIEW-002.5/7) after an apply of `AA` and a display (`0x08DAAFB7`), entry `0x8002` = `11 22` added, *Save patched image as* `fixture-blocked.s19` → `result.ok` False, status `Patched image not saved - 2 entries blocked - see issues`, no file; session `0x8002` / `0x8003` = `02` / `03`; key `0` → `concat: 0x9C5BCBBD` / `fill:   0x2A8A3950`, 1 recompute (a hook under `if result.ok:`: `0x08DAAFB7` stays)
examples: (declined) `filename is None` → status `Patch Editor: save-back declined`; no notice

S19TuiApp._on_project_saved
req: R-CRC-PREVIEW-002.1, R-CRC-PREVIEW-002.5
in: SaveOutcome outcome
out: None
func: changed. was: on a committed save with `request.image is not None`, `self._change_service.adopt_rederived(mem_map, request.image.derived, summary)` writes the re-derived bytes in place, then `_surface_verify_result()`. / now: identical, plus `self._note_image_bytes_written()` right after `adopt_rederived`, inside the same `if`. An uncommitted save or a commit with no image step: unchanged, no notice.
module: s19_app/tui/app.py
calls: ChangeService.adopt_rederived, S19TuiApp._note_image_bytes_written
examples: (R-CRC-PREVIEW-002.1/6) CRC Designer displayed showing `0x08DAAFB7`, document edited to `BB`, `ctrl+s` committed → after Q: `concat: 0x614BD0E8`, 1 recompute
examples: (R-CRC-PREVIEW-002.5/5) the same commit from key `1` → 0 recomputes until key `0`; then `concat: 0x614BD0E8`

S19TuiApp.on_check_editor_panel_spec_file_selected
req: R-CHKED-041.2, R-CHKED-026
in: CheckEditorPanel.SpecFileSelected event
out: None
func: changed. was: containment guard, `read_change_document(str(candidate), self.base_dir, a2l_context=self.current_a2l_data)`, refusals (errors, non-check kind), then `items = [{"address": e.address, "size": max(1, len(e.encoded_bytes))} …]`, `panel.load_spec(items, event.filename)`, status `Check Editor: loaded '<name>' (<n> fields).`. / now: identical, except each item is `{"address": e.address, "size": max(1, len(e.encoded_bytes)), "expected": tuple(e.encoded_bytes), "symbol": e.symbol}` (I-3). Status text and count unchanged.
module: s19_app/tui/app.py
calls: read_change_document, CheckEditorPanel.load_spec
examples: (R-CHKED-041.2/1) pilot spec with case 08 and its A2L → items `[{0x0, 1, (0x6C,), None}, {0x14, 2, (0xA0, 0xBE), None}, {0xC00FFC, 4, (0xFF,)*4, None}]`; status `Check Editor: loaded 'pilot_fields.chk.json' (3 fields).`
examples: (R-CHKED-041.2/2) `demo_check.chk.json` → the symbol entry's item carries `symbol` = the tag's spelling; status `… (3 fields).`

S19TuiApp._check_items_to_document
req: R-CHKED-025, R-CHKED-026, R-CHKED-027
in: Sequence[dict] items (I-2)
out: tuple[ChangeDocument, int] (document, skipped)
func: changed. was: for each item, `address` not an int ≥ 0 or `size` ≤ 0 → skipped; else read `size` bytes from the loaded image at `address`; any missing byte (or no image) → skipped; else one `ChangeEntry("bytes", address, expected)`. / now: same, except: when `item.get("expected")` is a tuple of exactly `size` ints, those are the expected bytes and the image is not read (a field loaded from a spec is declared without the image, amended *declared field*); otherwise the base path. The skipped count and the status `Check Editor: <k> field(s) outside the loaded image — not declared.` are unchanged.
module: s19_app/tui/app.py
calls: ChangeEntry, ChangeDocument
examples: (R-CHKED-026/1) image `0x0` = `93`; items `VALUE_0001` with `expected=(0x6C,)`, `VALUE_0002` with `(0xA0, 0xBE)`, memory `0xC00FFC` with `(0xFF,)*4` → entries `0x0 6C`, `0x14 A0 BE`, `0xC00FFC FF FF FF FF`; skipped 0 (base: `0x0 93`)
examples: (R-CHKED-026/2) the same document through Validate → `Checks: 2 passed, 1 failed, 0 uncheckable`; row `0x0-0x0 expected [6C] actual [93] -> fail` (base P: `Checks: 3 passed, 0 failed, 0 uncheckable`)
examples: (R-CHKED-025/1) item `VALUE_0003` with `expected=None` → its bytes read from the image
examples: (R-CHKED-027/1) memory item `0x0F000000`, size 4, `expected=None` → skipped 1
examples: (R-CHKED-027/2) no image; the three pilot-spec items with `expected` → 3 entries, skipped 0 (base: 0 entries, skipped 3)
examples: (E1-D6 backstop) item with `size=2`, `expected=(0x6C,)` → image path (length mismatch; since E3, G3 hands bytes only at their spec entry's range, so only a fault reaches this)

## Nodes — G2 designer

CrcDesignerPanel.note_image_bytes_written
req: R-CRC-PREVIEW-002.1, R-CRC-PREVIEW-002.5
in: —
out: None
func: new, public (I-1). One statement: `self._on_image_changed()`. The app calls it after it wrote bytes into the loaded image in place; the `current_file` reactive does not fire for that, so this is the in-place twin of the watcher (amended *loaded image changes*).
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._on_image_changed
examples: (R-CRC-PREVIEW-002.5/3) not on screen → `_coverage_dirty = True`, nothing scheduled
examples: (R-CRC-PREVIEW-002.1/6) on screen → `_pending_recompute` set (Q later: one `_recompute`)

CrcDesignerPanel._on_image_changed
req: R-CRC-PREVIEW-002.1, R-CRC-PREVIEW-002.5
in: —
out: None
func: unchanged (Inc 13). `if self.is_on_screen: self._schedule_recompute()` else `self._coverage_dirty = True`.
module: s19_app/tui/crc_designer_view.py
calls: Widget.is_on_screen, CrcDesignerPanel._schedule_recompute
examples: (R-CRC-PREVIEW-002.5/3) via `note_image_bytes_written` while key `6` is shown → dirty

CrcDesignerPanel.on_show
req: R-CRC-PREVIEW-002.5
in: events.Show
out: None
func: unchanged (Inc 13). `if self._coverage_dirty: self._schedule_recompute()`; `_recompute` clears the flag.
module: s19_app/tui/crc_designer_view.py
calls: CrcDesignerPanel._schedule_recompute
examples: (R-CRC-PREVIEW-002.5/3) key `0` after the apply → exactly 1 recompute; a second clean display → 0

## Nodes — G3 check editor

CheckEditorPanel.__init__
req: R-CHKED-026, R-CHKED-056
in: —
out: None
func: changed. was: `self._picker = A2LParameterPicker(layout_provider=self._widths)`, `self._memory_rows: list = []` of `(address, label, size)`, `self._layout = None`. / now: the same, `_memory_rows` holds I-4 4-tuples, and `self._spec_bytes: dict[str, tuple[int, int, tuple[int, ...]]] = {}` (included parameter name → its spec entry `(address, size, bytes)` from the last picked spec; E3 SEC5-1: the bytes belong to that range).
module: s19_app/tui/screens_directionb.py
examples: (R-CHKED-026/1) a fresh panel → `_spec_bytes == {}`, `_memory_rows == []`

CheckEditorPanel.set_a2l_parameters
req: R-CHKED-010, R-CHKED-054, R-CHKED-055, R-CHKED-056, R-CHKED-026
in: Sequence[dict] rows; object signature = None
out: None
func: changed. was: `if not self._picker.set_parameters(rows, signature): return` (unchanged signature: nothing changes, R-B102-SEL-004); else the picker cleared every pick; then layout reset and `_refresh_preview()`. / now (E3 SEC5-1): `kept = list(self._picker.picked_params)` first; `if not self._picker.set_parameters(rows, signature): return` (same no-op); then `rows_before = len(self._memory_rows)`; `kept = self._demote_moved_spec_params(kept)` (a pick loaded from a spec that the new ledger no longer lists at its spec entry's range becomes a memory row — R-CHKED-056); `if kept: self._picker.include_names(kept)` (re-includes, in the earlier order, every remaining earlier pick the new ledger lists; unknown names are not included — R-CHKED-055) and `self._prune_spec_bytes()`; `if len(self._memory_rows) != rows_before: self._rebuild_memory_table()`; then the base layout reset and `_refresh_preview()`. Memory rows otherwise untouched (as base).
module: s19_app/tui/screens_directionb.py
calls: A2LParameterPicker.set_parameters, CheckEditorPanel._demote_moved_spec_params, A2LParameterPicker.include_names, CheckEditorPanel._prune_spec_bytes, CheckEditorPanel._rebuild_memory_table, CheckEditorPanel._refresh_preview
examples: (R-CHKED-010/2) picks `[VALUE_0001, VALUE_0002]`, the same A2L loaded again (new signature) → picks `[VALUE_0001, VALUE_0002]`; head line `3 fields: 2 params · 1 memory row` (base P: `[]`)
examples: (R-CHKED-010/1) same signature → returns at the no-op; picks unchanged
examples: (R-CHKED-055/1) session picks, new rows list `VALUE_0002` only → picks `[VALUE_0002]`; `VALUE_0001` (no spec entry) dropped, no memory row added
examples: (R-CHKED-056/1) after the pilot-spec pick, the planted moved A2L (`VALUE_0001` at *A*) → `_demote_moved_spec_params` returns `[VALUE_0002]`; picks `[VALUE_0002]`; `_memory_rows[-1] == (0x0, "field @ 0x00000000", 1, (0x6C,))`; head line `3 fields: 1 param · 2 memory rows` (E1 design: picks `[VALUE_0001, VALUE_0002]`, Write `A 6C`)
examples: (R-CHKED-026/4) after the pilot-spec pick and an apply of `93` at `0x0`, the same A2L loaded again → nothing demoted; picks `[VALUE_0001, VALUE_0002]`; `_spec_bytes` unchanged; Write `0x0 6C`
examples: (R-CHKED-054/1) the post-Write refresh with an unchanged signature → no-op; field set unchanged (holds on base, P)

CheckEditorPanel.load_spec
req: R-CHKED-041.1, R-CHKED-041.2, R-CHKED-041.3, R-CHKED-026, R-CHKED-056
in: Sequence[dict] items (I-3); str source_name
out: None
func: changed. was: `self._picker.clear_picks()`; `self._memory_rows = []`; every item with an address → `(address, self._default_label(address), size)`; rebuild memory table and ledger; Write as := `<base>.chk.json`; `_refresh_preview()`. / now: `self._picker.clear_picks()`; `self._spec_bytes = {}`; `self._memory_rows = []`; `by_key: dict[tuple[int, int], list[str]]` built once from `self._param_rows` (`(address, size) → names` for integer addresses, ledger order); `taken: set = set()`; `named: list = []`; for each item with an address: `size = int(item.get("size") or 1)`, `expected = item.get("expected")`, `name = self._named_parameter(address, size, item.get("symbol"), by_key, taken)`; a name → `named.append(name)`, `taken.add(name)`, `self._spec_bytes[name] = (address, size, expected)` (E3: the spec entry's range with its bytes); no name → `self._memory_rows.append((address, self._default_label(address), size, expected))`. Then `if named: self._picker.include_names(named)`; then the base tail (rebuild memory table and ledger, Write as, `_refresh_preview()`). Cost O(parameters + entries) per pick (one dict over the ledger rows; about 0.1 s estimated for a 220 040-tag A2L, not measured).
module: s19_app/tui/screens_directionb.py
calls: A2LParameterPicker.clear_picks, CheckEditorPanel._named_parameter, A2LParameterPicker.include_names, CheckEditorPanel._rebuild_memory_table, CheckEditorPanel._rebuild_ledger, CheckEditorPanel._refresh_preview
examples: (R-CHKED-041.2/1) pilot-spec items, case-08 ledger → picks `[VALUE_0001, VALUE_0002]`; `_memory_rows == [(0xC00FFC, "field @ 0x00C00FFC", 4, (0xFF,)*4)]`; `_spec_bytes == {"VALUE_0001": (0x0, 1, (0x6C,)), "VALUE_0002": (0x14, 2, (0xA0, 0xBE))}`; head line `3 fields: 2 params · 1 memory row` (base P: `3 fields: 0 params · 3 memory rows`)
examples: (R-CHKED-041.1/1) earlier field set `VALUE_0003` + 2 memory rows → after the pick only the 3 pilot-spec fields
examples: (R-CHKED-041.3/1) empty ledger (no A2L) → 0 picks, 3 memory rows, each label `field @ 0x…` (painted `—`)
examples: (R-CHKED-041.3/5) two items `{0x0, 1, (0x6C,)}` → picks `[VALUE_0001]`, memory rows `[(0x0, "field @ 0x00000000", 1, (0x6C,))]`

CheckEditorPanel._named_parameter
req: R-CHKED-041.2, R-CHKED-041.3
in: int address; int size; str|None symbol; dict by_key; set taken
out: str|None name
func: new, pure over `self._param_rows`. (1) `symbol` is a non-empty `str` and `symbol in self._param_rows` → `symbol` when `self._param_rows[symbol][:2] == (address, size)` and `symbol not in taken`, else `None`: the address rule is not tried (E3 A-6). (2) else (no symbol, or one the ledger does not list) `names = by_key.get((address, size), [])`; `len(names) == 1 and names[0] not in taken` → `names[0]`. (3) else `None`.
module: s19_app/tui/screens_directionb.py
examples: (R-CHKED-041.2/1) `(0x0, 1, None)`, case-08 ledger → `"VALUE_0001"`
examples: (R-CHKED-041.2/3) planted twin, `(0x14, 2, "BETA")` → `"BETA"`
examples: (R-CHKED-041.3/4) planted twin, `(0x14, 2, None)` → `None` (two names)
examples: (R-CHKED-041.3/3) case 08, `(0x14, 1, None)` → `None` (`VALUE_0002` is 2 bytes)
examples: (R-CHKED-041.3/2) `(0xC00FFC, 4, None)` → `None`
examples: (R-CHKED-041.3/5) `(0x0, 1, None)` with `taken = {"VALUE_0001"}` → `None`
examples: (R-CHKED-041.3/6) ledger `{ALPHA: (0x14, 2), GAMMA: (0x14, 1)}`, `(0x14, 1, "ALPHA")` → `None` (E1 form: `"GAMMA"` by the address rule)
examples: (R-CHKED-041.2/2) case 08, the demo-check symbol entry → the tag's spelling

CheckEditorPanel._collected_items
req: R-CHKED-025, R-CHKED-026, R-CHKED-056
in: —
out: tuple[dict, …] (I-2)
func: changed. was: one `{"source", "name", "address", "size"}` per picked name (address/size from `_param_rows`, `(None, 1)` when unknown), then one per memory row. / now: the same four keys and order, plus `"expected"`: for a parameter, `spec = self._spec_bytes.get(name)` and `spec[2]` only when `spec[:2]` equals the `(address, size)` of its current ledger row, else `None` (E3 SEC5-1: the bytes never move to another range); for a memory row, the row's fourth element.
module: s19_app/tui/screens_directionb.py
examples: (R-CHKED-026/1) after the pilot-spec pick → `({param, VALUE_0001, 0x0, 1, (0x6C,)}, {param, VALUE_0002, 0x14, 2, (0xA0, 0xBE)}, {memory, "field @ 0x00C00FFC", 0xC00FFC, 4, (0xFF,)*4})`
examples: (R-CHKED-025/1) `VALUE_0003` included afterwards → its item has `expected=None`
examples: (R-CHKED-025/3) after R-CHKED-056/1, `VALUE_0001` included again at *A* → its item `{param, VALUE_0001, A, 1, None}` (no spec entry left); the memory row's item `{memory, "field @ 0x00000000", 0x0, 1, (0x6C,)}`; Write → `0x14 A0 BE`, `A <image byte>`, `0xC00FFC FF FF FF FF`, `0x0 6C`
examples: (backstop) `_spec_bytes["VALUE_0001"] == (0x0, 1, (0x6C,))` while its ledger row is `(A, 1)` → `expected=None`

CheckEditorPanel._rebuild_memory_table
req: R-CHKED-041.3, R-CHKED-056
in: —
out: None
func: changed. was: `for address, label, size in self._memory_rows:` add the Address / Label (`—` when the label is the default) / Fmt cells. / now: `for address, label, size, _expected in self._memory_rows:` — cells unchanged.
module: s19_app/tui/screens_directionb.py
examples: (R-CHKED-041.3/2) row `(0xC00FFC, "field @ 0x00C00FFC", 4, (0xFF,)*4)` → cells `0x00C00FFC`, `—`, `u32`
examples: (R-CHKED-056/1) the appended row `(0x0, "field @ 0x00000000", 1, (0x6C,))` → cells `0x00000000`, `—`, `u8`, after the `0x00C00FFC` row

CheckEditorPanel._add_memory_row
req: R-CHKED-025
in: —
out: None
func: changed. was: validate the inputs, then `self._memory_rows.append((address, label, size))`. / now: `…append((address, label, size, None))`; validation and messages unchanged.
module: s19_app/tui/screens_directionb.py
examples: (R-CHKED-027/1) Address `0x0F000000`, Size `4` → row `(0x0F000000, "field @ 0x0F000000", 4, None)`

CheckEditorPanel._on_a2l_parameter_picker_selection_changed
req: R-CHKED-025, R-CHKED-026
in: A2LParameterPicker.SelectionChanged event
out: None
func: changed. was: `event.stop()`; `self._refresh_preview()`. / now: `event.stop()`; `self._prune_spec_bytes()`; `self._refresh_preview()`. The prune reads the current picks, not `event.names`, so a queued message older than a spec pick never removes the pick's fresh entries.
module: s19_app/tui/screens_directionb.py
calls: CheckEditorPanel._prune_spec_bytes, CheckEditorPanel._refresh_preview
examples: (R-CHKED-025/2) `VALUE_0001` excluded → message handled → `_spec_bytes` loses `VALUE_0001`; included again → `expected=None` → Write takes the image's `93`

CheckEditorPanel._prune_spec_bytes
req: R-CHKED-025, R-CHKED-026, R-CHKED-055
in: —
out: None
func: new. `picked = set(self._picker.picked_params)`; `self._spec_bytes = {n: s for n, s in self._spec_bytes.items() if n in picked and self._param_rows.get(n, (None, None, ""))[:2] == s[:2]}` — a name still picked but off its spec entry's range loses its bytes (backstop to `_demote_moved_spec_params`, E3 SEC5-1).
module: s19_app/tui/screens_directionb.py
examples: (R-CHKED-025/2) `_spec_bytes = {VALUE_0001: (0x0, 1, (0x6C,)), VALUE_0002: (0x14, 2, (0xA0, 0xBE))}`, picks `[VALUE_0002]` → `{VALUE_0002: (0x14, 2, (0xA0, 0xBE))}`
examples: (R-CHKED-026/1) picks equal the keys, ranges unchanged → unchanged

CheckEditorPanel._demote_moved_spec_params
req: R-CHKED-056, R-CHKED-010
in: list[str] kept (the picks before the repopulation, in order)
out: list[str] (the picks to re-include, in order)
func: new (E3, SEC5-1 = A-1). Runs after `set_parameters` replaced the ledger. For each `name` in `kept` with `spec = self._spec_bytes.get(name)` not `None` and `self._param_rows.get(name, (None, None, ""))[:2] != spec[:2]` (listed at another address, with another byte count, or not listed): `self._memory_rows.append((spec[0], self._default_label(spec[0]), spec[1], spec[2]))` in `kept` order, `del self._spec_bytes[name]`, and `name` is left out of the result. Every other name is returned in `kept` order (a session pick the ledger no longer lists is returned too; `include_names` ignores it — R-CHKED-055). Never reads the image; never changes a spec entry's address, size or bytes.
module: s19_app/tui/screens_directionb.py
calls: CheckEditorPanel._default_label
examples: (R-CHKED-056/1) `kept = [VALUE_0001, VALUE_0002]`, spec entries `(0x0, 1, (0x6C,))`, `(0x14, 2, (0xA0, 0xBE))`; new ledger `VALUE_0001 → (A, 1)`, `VALUE_0002 → (0x14, 2)` → returns `[VALUE_0002]`; appends `(0x0, "field @ 0x00000000", 1, (0x6C,))`; `_spec_bytes == {VALUE_0002: (0x14, 2, (0xA0, 0xBE))}`; Write → `0x14 A0 BE`, `0xC00FFC FF FF FF FF`, `0x0 6C`, none at *A* (E1 design: `A 6C`)
examples: (R-CHKED-056/2) new ledger lists `VALUE_0001_R → (0x0, 1)` and not `VALUE_0001` → the same return and appended row; `VALUE_0001_R` not included (names are resolved at the spec pick only)
examples: (R-CHKED-056/3) new ledger `VALUE_0001 → (0x0, 2)` → the same; the row keeps size 1 and `(0x6C,)`, so Write has no 2-byte entry at `0x0`
examples: (R-CHKED-026/4) the same A2L again (`VALUE_0001 → (0x0, 1)`) → returns `kept` unchanged; nothing appended
examples: (R-CHKED-055/1) session picks with no spec entry, ledger `{VALUE_0002}` → returns `[VALUE_0001, VALUE_0002]`; nothing appended (`include_names` then leaves `VALUE_0001` out)

CheckEditorPanel.clear_check_results
req: R-CHKED-057
in: —
out: None
func: new, public (I-5, E5 C-10). `#check_status` ← `_STATUS_HINT` (`Validate compares fields to the image`, the mount text); `#check_results` children removed. Unlike `refresh_check_results` it does not call `_show_tab`, so the card's tab and the focus stay as they are. The app calls it after an in-place write; the verdict rows judged the old bytes.
module: s19_app/tui/screens_directionb.py
calls: DOMNode.query_one, Label.update, Widget.remove_children
examples: (R-CHKED-057/1) after Validate (`Checks: 3 passed, 0 failed, 0 uncheckable`, one row `-> pass`) and the apply of `0x0` = `93` → 0 rows, status `Validate compares fields to the image`; Validate again → `Checks: 2 passed, 1 failed, 0 uncheckable`, `0x0-0x0 expected [6C] actual [93] -> fail`
examples: (R-CHKED-057/2, /3) a save-back or a Save project commit after Validate → 0 rows, the mount status line
examples: (nothing validated yet) → the card already in its mount state; stays so

## Context (unchanged)

A2LParameterPicker.include_names
req: R-CHKED-010, R-CHKED-041.2, R-CHKED-055
in: Sequence[str] names
out: dict counts
func: unchanged (batch-102 Inc 4). Appends, in list order, each name of the ledger not already picked; ignores unknown names; repaints visible marks; posts `SelectionChanged` when ≥ 1 was included.
module: s19_app/tui/a2l_parameter_picker.py
examples: (R-CHKED-055/1) ledger `{VALUE_0002}`, names `[VALUE_0001, VALUE_0002]` after a clear → picks `[VALUE_0002]`, `not_found` 1

ChangeService.apply / save_patched / adopt_rederived
req: R-CRC-PREVIEW-002.5
func: unchanged. The three writers of the session map in place (`../E1-rulings.md` §1 census); flow and variant runs write their own maps.
module: s19_app/tui/services/change_service.py

## Coverage of the rows by examples

R-CRC-PREVIEW-002.1 (`_note_image_bytes_written`, `_on_project_saved`, `note_image_bytes_written`); R-CRC-PREVIEW-002.5 (`on_patch_editor_panel_action_requested`, `on_patch_editor_panel_save_back_decision`, `_on_project_saved`, `note_image_bytes_written`, `on_show`); R-CHKED-010 (`set_a2l_parameters`, `_demote_moved_spec_params`); R-CHKED-054 (`set_a2l_parameters`); R-CHKED-055 (`set_a2l_parameters`, `include_names`, `_prune_spec_bytes`, `_demote_moved_spec_params`); R-CHKED-056 (`__init__`, `load_spec`, `set_a2l_parameters`, `_demote_moved_spec_params`, `_collected_items`, `_rebuild_memory_table`); R-CHKED-041.1 (`load_spec`); R-CHKED-041.2 (`load_spec`, `_named_parameter`, `on_check_editor_panel_spec_file_selected`); R-CHKED-041.3 (`load_spec`, `_named_parameter`, `_rebuild_memory_table`); R-CHKED-025 (`_check_items_to_document`, `_collected_items`, `_on_a2l_parameter_picker_selection_changed`, `_prune_spec_bytes`); R-CHKED-026 (`_check_items_to_document`, `_collected_items`, `load_spec`, `__init__`); R-CHKED-027 (`_check_items_to_document`, `_add_memory_row`); R-CHKED-057 (`_note_image_bytes_written`, `clear_check_results`; E5 C-10). Nodes: 18 slice nodes + 4 context nodes.
