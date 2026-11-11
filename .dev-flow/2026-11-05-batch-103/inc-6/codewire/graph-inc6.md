# Code-Wire graph — Inc 6 (Picker correctness), batch-103

Stage E2, 2026-11-10, model Kimi. **Graph only:** no stub, extractor mark or declaration was added to product source. No application, test or runtime probe is claimed. Authority: `../01-requirements.md` (20 rows), `../02-test-cases.md` (75 cases), `../E1-rulings.md`, and `../E1-slice.md`. Code-Wire v3.1.0 (`e436a08`).

### 1. Delta, ownership and pinned interfaces

**11 implementation nodes (7 changed + 4 new) + 8 unchanged context groups = 19 nodes**, across the two permitted product files. No deviation from E1's source boundary. Future tests are independent of product implementation and derive expected values from the requirement fixtures.

| Group | Files | Owns |
|---|---|---|
| G1 picker | `s19_app/tui/a2l_parameter_picker.py` | N1-N5; declared length, one-batch I-2 describe, format/literal normalization |
| G2 panels | `s19_app/tui/screens_directionb.py` | N6-N11; Patch pick/bulk host, panel A2L-data handoff, Use guard |
| Read-only producers | `a2l_definition.py`, `app.py`, `a2l.py`, `screens.py`, `utils.py` | C1-C8; no edits |

### I-2 — definition model (CONSUMED, unchanged)

`describe_definitions(names: Iterable[str], a2l_data: dict) -> dict[str, Definition]` is called at most once per real picker population. `Definition.datatype` and `kind` drive element format; `byte_length` is an independent expected-value oracle. No encode/decode/display call, global cache or I-2 signature change. A refused definition can still supply datatype/kind; it never revives missing `length`.

### I-4 — refresh contract (CONSUMED, unchanged)

Inc 5 still owns generation/signature and both app prefills. Equal non-`None` signatures no-op; `None` repopulates. The panel shims additionally pass the app's existing `current_a2l_data` into the picker. No `app.py` edit, new generation, worker or second event bus. Changed generation → one describe per picker before current cells paint.

### I-5 — bulk list parser (CONSUMED, unchanged)

`parse_parameter_list(text: str) -> list` and `include_names(names: Sequence[str]) -> dict` retain exact parsing, order, unique counts and `SelectionChanged`. Patch uses pick mode and the same `BulkParameterAddScreen`; no Patch-specific parser, modal or summary.

### Internal seam (additive change authorized by E1 D-2)

```text
A2LParameterPicker.set_parameters(
    self,
    rows: Sequence[dict],
    signature: object = None,
    *,
    a2l_data: Optional[dict] = None,
) -> bool

A2LParameterPicker.highlighted_parameter -> Optional[dict]
# returned size: Optional[int]
```

Existing positional callers remain valid. `length` is the sole size source. Enriched `byte_size` is never read for size. `a2l_data=None` permits direct component fixtures with `length` and `datatype`/`char_type`; it does not restore `byte_size` fallback.

### 2. Baseline and real callers (static census)

The throwaway extractor copy is outside the product worktree. `extractor-baseline/diff-report.md` records **13 marks / 13 graph nodes / 7 real marked calls / 0 drift / 0 parse failures**. Its five ambiguous resolutions are the same-named Check/Patch panel methods; the direct static app-prefill citations below disambiguate them. Current static callers:

| Node | Current file:line | Real caller / baseline |
|---|---|---|
| N1 `A2LParameterPicker.set_parameters` | `a2l_parameter_picker.py:526` | Patch shim `screens_directionb.py:5388`; Check shim `:7303`; direct component tests |
| N4 `_row_cells` / `_refresh_full_name` | `a2l_parameter_picker.py:776`, `:831` | ledger rebuild `:793-829`; public row/rebuild wrappers `:585-595`; Patch/Check layout passes |
| N5 `highlighted_parameter` | `a2l_parameter_picker.py:481` | Patch Use `screens_directionb.py:5472`; tests |
| N6 `PatchEditorPanel.__init__` | `screens_directionb.py:4811` | app screen composition; constructs highlight-only picker at `:4821-4827` |
| N7 `PatchEditorPanel.set_a2l_parameters` | `screens_directionb.py:5375` | Inc 5 app prefill `app.py:7935`; direct tests |
| N8 `CheckEditorPanel.set_a2l_parameters` | `screens_directionb.py:7285` | Inc 5 app prefill `app.py:7914`; direct tests |
| N9 `_use_highlighted_parameter` | `screens_directionb.py:5454` | real Patch button route `:5922-5927` |
| C3 `parse_parameter_list` / `include_names` | `a2l_parameter_picker.py:75`, `:920` | shared modal `screens.py:1009`; Check spec restore `screens_directionb.py:7308`, `:7353` |
| C7 Check bulk host | `screens_directionb.py:7875-7903` | picker `BulkAddRequested`; existing modal dismiss callback |

## Nodes
A2LParameterPicker.set_parameters
req: R-PICKER-CORRECT.001, R-PICKER-CORRECT.002, R-PICKER-CORRECT.003, R-PICKER-CORRECT.004, R-PICKER-CORRECT.009, R-PICKER-CORRECT.010, R-PICKER-CORRECT.017, R-PICKER-CORRECT.018, R-PICKER-CORRECT.019
in: Sequence[dict] rows; object signature = None; Optional[dict] a2l_data = None (keyword-only)
out: bool repopulated
module: s19_app/tui/a2l_parameter_picker.py
modify: [Data: A2LParameterPicker._param_rows] (replace); [Data: A2LParameterPicker._signature] (replace)
func: **changed.** Return `False` without any describe or widget work for an equal non-`None` signature. Otherwise clear old rows/picks and normalize each row: name/address as today; `size = row["length"]` only when it is a positive non-boolean integer, else `None`; never read `byte_size` for size. With A2L data, call `describe_definitions` once for all names. N2 computes each format from optional definition/tag fields; N3 is applied before dynamic cells paint. Cache longest format, reset filter/page and rebuild one page. `None` always repopulates.
examples: (R-PICKER-CORRECT.001/4) ARR12 `length=12`, `byte_size=2` → repopulated `True`, size `12`, never `2`
examples: (R-PICKER-CORRECT.003/15) ARR12 UWORD length 12 → `u16`, never `u96`
examples: (R-PICKER-CORRECT.004/1) R1 `length=None`, `byte_size=None` → size `None`, never `1`
examples: (R-PICKER-CORRECT.018/1) equal signature with DESCRIBE armed → `False`, `0` describes and unchanged filter/page/picks
examples: (R-PICKER-CORRECT.018/3) two signature=`None` calls with real A2L data and filter/page/picks reseeded before each → both return `True`, defaults/empty picks after each, one describe per call
examples: (R-PICKER-CORRECT.019/1) 13,990 names → one batch call, median ≤ `2.0` seconds and 13,990 normalized rows

_format_parameter
req: R-PICKER-CORRECT.003, R-PICKER-CORRECT.017
in: Optional[Definition] definition; dict row
out: str fmt_unit
module: s19_app/tui/a2l_parameter_picker.py
func: **new pure helper.** ASCII kind → `text`. Otherwise map the element datatype to unsigned/signed/float width (`u8`…`u64`, `s8`…`s64`, `f16`…`f64`); BYTE/WORD/LONG are unsigned; unknown → exactly `?`. Append one space and unit when non-empty. Never read total length or enriched `byte_size` to choose format.
examples: (R-PICKER-CORRECT.003/2) SBYTE → `s8`
examples: (R-PICKER-CORRECT.003/13) FLOAT32_IEEE → `f32`
examples: (R-PICKER-CORRECT.003/16) ASCII length 5 → `text`
examples: (R-PICKER-CORRECT.003/17) UWORD unit `%` → `u16 %`
examples: (R-PICKER-CORRECT.003/18) unknown datatype length 3 → exactly `?`, never `u24`
examples: (R-PICKER-CORRECT.017/3) UWORD + 400-cell hostile unit → `u16 ` + literal unit, never `?`; N4 clips it on both surfaces at 80/118

_literal_parameter_text
req: R-PICKER-CORRECT.017
in: str value; str style = ""
out: Text literal
module: s19_app/tui/a2l_parameter_picker.py
func: **new pure renderer.** Replace each U+0000–001F, U+007F and U+0080–009F with U+FFFD, then return `Text(transformed, style=style)`. No markup parsing and no exception for brackets. Clipping remains N4's cell-width operation.
examples: (R-PICKER-CORRECT.017/1) name `A[red]` + ESC + NUL → literal `A[red]` with two U+FFFD, zero markup spans and zero raw controls
examples: (R-PICKER-CORRECT.017/2) unit `[link=e]` + DEL → literal `u16 [link=e]` plus U+FFFD, no link span

A2LParameterPicker._row_cells
req: R-PICKER-CORRECT.003, R-PICKER-CORRECT.017, R-PICKER-CORRECT.020
in: str name; PickerLayout layout
out: tuple cells; full-name Static updated separately
module: s19_app/tui/a2l_parameter_picker.py
func: **changed render group.** Keep mark/address/layout behavior. Paint N1's normalized format through N3, with existing `_clip_fmt_unit` and `clip_param`; optional size does not invent `u8`. For the full-name line, clip format/unit to the remaining full-name cell budget with visible ellipsis before fitting the name; use the same literal rule and existing empty texts.
examples: (R-PICKER-CORRECT.003/15) ARR12 → fourth cell `u16`; full-name line agrees
examples: (R-PICKER-CORRECT.017/3) UWORD + 400-cell hostile unit at 80 and 118 → exact literal clipped `u16 ` + unit with visible `…` in BOTH ledger cell and full-name line; no overflow
examples: (R-PICKER-CORRECT.020/1) 80×24 → every visible ledger/control region remains inside Patch panel

A2LParameterPicker.highlighted_parameter
req: R-PICKER-CORRECT.004, R-PICKER-CORRECT.005, R-PICKER-CORRECT.006, R-PICKER-CORRECT.007, R-PICKER-CORRECT.008, R-PICKER-CORRECT.016
in: none; reads mounted cursor and normalized rows
out: Optional[dict] parameter
module: s19_app/tui/a2l_parameter_picker.py
func: **changed type/semantics.** Preserve no-row/out-of-range `None`. Otherwise return name, address, `size: Optional[int]`, fmt_unit exactly as normalized. Missing declared length stays `None`.
examples: (R-PICKER-CORRECT.004/2) R2 highlighted → `size=None`, never `1`/`2`
examples: (R-PICKER-CORRECT.006/2) ARR12 highlighted → `size=12`, address `0x1000`

PatchEditorPanel.__init__
req: R-PICKER-CORRECT.011, R-PICKER-CORRECT.020
in: none
out: None
module: s19_app/tui/screens_directionb.py
modify: [Data: PatchEditorPanel._a2l_picker] (replace)
func: **changed.** Construct the shared picker with `id_prefix="patch_param"`, `mode="pick"`, include and bulk enabled, and the existing layout provider. Preserve every unrelated panel field and id.
examples: (R-PICKER-CORRECT.011/2) Patch tab → exactly one enabled `#patch_param_bulk_button`
examples: (R-PICKER-CORRECT.011/3) both panels mounted → disjoint `check_param_*` and `patch_param_*` ids and independent picks

PatchEditorPanel.set_a2l_parameters
req: R-PICKER-CORRECT.001, R-PICKER-CORRECT.002, R-PICKER-CORRECT.003, R-PICKER-CORRECT.004, R-PICKER-CORRECT.018, R-PICKER-CORRECT.019
in: Sequence[dict] rows; object signature = None
out: None
module: s19_app/tui/screens_directionb.py
func: **changed.** Call N1 with rows, signature and keyword `a2l_data=self.app.current_a2l_data`. Keep unchanged-signature early return, layout invalidation and deferred layout pass. No document/history writes.
examples: (R-PICKER-CORRECT.018/4) Inc 5 reload ARR12 length 12→8 while Patch stays visible → one describe and size 8 before outcome, no re-entry

CheckEditorPanel.set_a2l_parameters
req: R-PICKER-CORRECT.001, R-PICKER-CORRECT.002, R-PICKER-CORRECT.003, R-PICKER-CORRECT.004, R-PICKER-CORRECT.009, R-PICKER-CORRECT.010, R-PICKER-CORRECT.018, R-PICKER-CORRECT.019
in: Sequence[dict] rows; object signature = None
out: None
module: s19_app/tui/screens_directionb.py
func: **changed.** Same A2L-data handoff as N7. Preserve kept-pick capture, C5 demotion/reinclude, spec-byte pruning, memory rebuild, layout invalidation and preview refresh. Corrected N1 size is the only changed input to those rules.
examples: (R-PICKER-CORRECT.009/2) ARR12 spec address 0x1000/size 12 → ARR12 included at 12, no memory row
examples: (R-PICKER-CORRECT.010/2) generation length 12→8 → original spec 12 bytes demoted to memory, not re-included at 2

PatchEditorPanel._use_highlighted_parameter
req: R-PICKER-CORRECT.005, R-PICKER-CORRECT.006, R-PICKER-CORRECT.007, R-PICKER-CORRECT.008, R-PICKER-CORRECT.016
in: none; reads N5, current image and entry inputs
out: None
module: s19_app/tui/screens_directionb.py
modify: [Data: Patch entry Address/Bytes/Use status] (replace); [Data: Patch document/history] (unchanged)
func: **changed.** If N5 has no usable address, preserve `No parameter highlighted.`. If `size is None`, set Bytes empty and exact `Parameter has no length — Bytes not prefilled.`, perform zero image lookups and post no document action. Otherwise populate Address and preserve existing over-cap guard, all-or-nothing ascending read and statuses. Bulk picks do not alter the single highlighted-row transfer.
examples: (R-PICKER-CORRECT.005/5) R5 → Bytes empty, exact missing-length status, `0` reads and DOC unchanged
examples: (R-PICKER-CORRECT.006/2) ARR12 full image → Bytes `00 01 02 03 04 05 06 07 08 09 0A 0B`
examples: (R-PICKER-CORRECT.007/2) missing byte at 0x1005 → Bytes empty and `Parameter address loaded; image bytes unavailable.`
examples: (R-PICKER-CORRECT.008/1) cap+1 with full coverage spy → `0` lookups and existing over-cap text

PatchEditorPanel._on_a2l_parameter_picker_bulk_add_requested
req: R-PICKER-CORRECT.012, R-PICKER-CORRECT.013, R-PICKER-CORRECT.014, R-PICKER-CORRECT.015
in: A2LParameterPicker.BulkAddRequested event
out: None; one shared modal pushed
module: s19_app/tui/screens_directionb.py
func: **new host group.** Stop the event and push `BulkParameterAddScreen(self._a2l_picker)` with N11 as dismiss callback. No Check picker, second parser/modal or document action.
examples: (R-PICKER-CORRECT.012/1) Patch Add list → one modal with `Separate names with new lines, commas, semicolons or spaces.`, focused multiline and Include/Close

PatchEditorPanel._on_bulk_add_closed
req: R-PICKER-CORRECT.013, R-PICKER-CORRECT.014, R-PICKER-CORRECT.015, R-PICKER-CORRECT.016
in: Optional[dict] summary
out: None
module: s19_app/tui/screens_directionb.py
func: **new.** No ledger rebuild, preview substitution, document/dirty/undo/redo write or selection change on cancel. Successful C3 selection remains; C4 owns the summary before dismissal.
examples: (R-PICKER-CORRECT.015/1) successful Beta include then close → Beta remains picked, REBUILD `0`, DOC unchanged
examples: (R-PICKER-CORRECT.015/3) Escape after typing Beta → picks unchanged, REBUILD `0`, DOC unchanged

describe_definitions
req: to trace
in: Iterable[str] names; dict a2l_data
out: dict[str, Definition] definitions
module: s19_app/tui/a2l_definition.py
func: unchanged one-walk I-2 producer. N1 consumes datatype/kind only; tests independently compare expected full lengths with byte_length where useful.
examples: (I2 context) ARR12 UWORD shape 2×3 → byte_length `12`, datatype `UWORD`

S19TuiApp._prefill_check_editor
req: to trace
in: current enriched tags and generation signature
out: None; calls N7/N8 on UI
module: s19_app/tui/app.py
func: unchanged. Both editors receive current rows/signature without re-entry; panels now supply current A2L data to N1.
examples: (R-PICKER-CORRECT.018/4) reload with both visible → one N1 describe per picker and current values before outcome

parse_parameter_list
req: to trace
in: str text; Sequence[str] names
out: list tokens; dict summary
module: s19_app/tui/a2l_parameter_picker.py
func: unchanged I-5. Exact case-sensitive unique-name selection in pick mode, ordered picks, existing picks preserved and SelectionChanged only on new inclusion.
examples: (R-PICKER-CORRECT.013/1) Alpha picked; `Beta, Missing; Alpha` → picks Alpha,Beta and counts `1/1/1`, first Missing

BulkParameterAddScreen
req: to trace
in: A2LParameterPicker picker; operator text/actions
out: Optional[dict] summary
module: s19_app/tui/screens.py
func: unchanged shared capped modal, exact instruction/summaries and inert cancel/Escape. First-missing operator text retains R-B102-BULK-006 literal/control-removal semantics and existing clipping, not N3/.017 U+FFFD replacement.
examples: (R-PICKER-CORRECT.014/1) Beta,Alpha,Gamma with Alpha picked → `Included 1 · already included 1 · not found 1 — first missing: Gamma`

CheckEditorPanel._named_parameter
req: to trace
in: spec entries; normalized picker rows
out: named inclusions and memory rows
module: s19_app/tui/screens_directionb.py
func: unchanged `(address,size)` equality and original-spec-byte demotion. N1's full declared length is the new input.
examples: (R-PICKER-CORRECT.009/3) ARR12 with spec size 2 → no ARR12 inclusion; memory row size `2` with original bytes

PatchEditorPanel._apply_a2l_layout
req: to trace
in: actual table/panel regions; normalized visible rows
out: None; columns/cells repainted
module: s19_app/tui/screens_directionb.py
func: unchanged width derivation. New pick controls use existing docked row and are measured at 80/118.
examples: (R-PICKER-CORRECT.020/2) 118×54 → include/bulk/Use/status/page regions non-zero and contained

CheckEditorPanel._on_a2l_parameter_picker_bulk_add_requested
req: to trace
in: A2LParameterPicker.BulkAddRequested event; Optional[dict] summary
out: None
module: s19_app/tui/screens_directionb.py
func: unchanged reference host for N10/N11; Check retains preview refresh and no-rebuild behavior.
examples: (context) Check Add list opens C4 for Check picker; N10 mirrors only modal ownership, not Check preview

safe_text
req: to trace
in: str value; str style = ""
out: Text literal
module: s19_app/utils.py
func: unchanged shared utility outside I-2's replacement rule. N3 locally implements U+FFFD replacement instead of changing this global behavior.
examples: (context) existing non-I-2 callers retain control deletion; picker N3 uses replacement
## Entities

[Data: A2LParameterPicker._param_rows]
in: dict[str, tuple[Optional[int], Optional[int], str]]
desc: name → (address, declared size or None, literal format/unit); never enriched byte_size
sequence:
  equal_signature: A2LParameterPicker.set_parameters
  changed_generation: S19TuiApp._prefill_check_editor → PatchEditorPanel.set_a2l_parameters → describe_definitions → A2LParameterPicker.set_parameters wins → A2LParameterPicker._row_cells
  filter_page: A2LParameterPicker._row_cells

[Data: Patch document/history]
desc: entries, dirty and undo/redo; N9/N10/N11 never write it
sequence:
  bulk_include: PatchEditorPanel._on_a2l_parameter_picker_bulk_add_requested → BulkParameterAddScreen → parse_parameter_list → PatchEditorPanel._on_bulk_add_closed
  use: PatchEditorPanel._use_highlighted_parameter

[Interface: Patch A2L controls]
desc: shared pick/include/bulk/Use controls under patch_param prefix
offers: (R-PICKER-CORRECT.012/1) "Add list" → PatchEditorPanel._open_parameter_bulk_add
offers: (R-PICKER-CORRECT.006/2) "Use parameter" → PatchEditorPanel._use_highlighted_parameter

## Findings

finding R-PICKER-CORRECT.001
anchor: N1, N7, N8
seen: ARR12 length 12 vs byte_size 2 in both editors
decision: covered by a concrete design example

finding R-PICKER-CORRECT.002
anchor: N1, C1
seen: ARR12=12, VB4=4, MAP10=10, TXT5=5
decision: covered by a concrete design example

finding R-PICKER-CORRECT.003
anchor: N1-N4
seen: 14 datatypes; ARR12 u16; ASCII text; unit %; unknown ?
decision: covered by a concrete design example

finding R-PICKER-CORRECT.004
anchor: N1, N5
seen: R1-R4 all size None, no 1/2
decision: covered by a concrete design example

finding R-PICKER-CORRECT.005
anchor: N5, N9
seen: R1-R5 exact missing-length refusal, zero reads
decision: covered by a concrete design example

finding R-PICKER-CORRECT.006
anchor: N5, N9
seen: VB4/ARR12/TXT5 exact non-uniform full bytes
decision: covered by a concrete design example

finding R-PICKER-CORRECT.007
anchor: N9
seen: no image and missing middle byte → exact unavailable status, no fill
decision: covered by a concrete design example

finding R-PICKER-CORRECT.008
anchor: N9
seen: cap+1 zero reads; exact cap full read
decision: covered by a concrete design example

finding R-PICKER-CORRECT.009
anchor: N8, C5
seen: ARR12 spec 12 named; spec 2 memory; scalar 2 named
decision: covered by a concrete design example

finding R-PICKER-CORRECT.010
anchor: N8, C5
seen: 12→12 retained; 12→8 demoted with original bytes
decision: covered by a concrete design example

finding R-PICKER-CORRECT.011
anchor: N6
seen: Patch pick/include/bulk, unique ids, independent picks
decision: covered by a concrete design example

finding R-PICKER-CORRECT.012
anchor: N10, C4
seen: shared modal with exact instruction and focused multiline
decision: covered by a concrete design example

finding R-PICKER-CORRECT.013
anchor: N10, C3
seen: mixed/duplicate/case-variant exact picks and counts
decision: covered by a concrete design example

finding R-PICKER-CORRECT.014
anchor: N10, C4
seen: mixed summary, zero-parsed and parsed-no-match
decision: covered by a concrete design example

finding R-PICKER-CORRECT.015
anchor: N10, N11
seen: include/cancel/Escape preserve ledger and DOC
decision: covered by a concrete design example

finding R-PICKER-CORRECT.016
anchor: N5, N9, N11
seen: after bulk, only highlighted ARR12/VB4 transfers
decision: covered by a concrete design example

finding R-PICKER-CORRECT.017
anchor: N2-N4
seen: hostile name/unit; UWORD + 400-cell hostile unit clipped with visible ellipsis in ledger/full-name at 80/118
decision: covered by a concrete design example

finding R-PICKER-CORRECT.018
anchor: N1, N7, N8, C2
seen: equal 0 describe; changed 1/picker; None twice returns True and resets filter/page/picks after each; live reload
decision: covered by a concrete design example

finding R-PICKER-CORRECT.019
anchor: N1, N4, C1
seen: 13,990 ≤2.0 s; 20 rebuilds, 0 describes, ≤200 rows
decision: covered by a concrete design example

finding R-PICKER-CORRECT.020
anchor: N4, N6, C6
seen: actual 80×24 and 118×54 containment/operability
decision: covered by a concrete design example

finding COVERAGE
anchor: 20 requirements and 19 nodes
seen: 20/20 requirements have concrete examples; no product/source stubs
decision: no split required
