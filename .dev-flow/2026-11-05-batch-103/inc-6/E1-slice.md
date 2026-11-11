# Inc 6 — E1 slice

Date 2026-11-10; model Kimi. Base: static worktree `802c3ee0`. No product/test file was edited and no runtime probe was run. Names marked **new** are design proposals only.

## 1. Count and source boundary

| File | Planned change | Implementation nodes |
|---|---|---:|
| `s19_app/tui/a2l_parameter_picker.py` | 2 existing functions changed, 1 property type adjusted, 2 private helpers new | 5 |
| `s19_app/tui/screens_directionb.py` | 3 existing functions changed, Patch constructor adjusted, 2 new Patch host groups (3 functions) | 6 |
| Every other source file | Read-only reuse; no edit authorized | 0 |

**Total: 2 source files, 11 implementation nodes, including two new Patch host groups (three functions); plus 8 unchanged context nodes = 19 graph nodes.** This is below the 40-node cap and preserves PLAN's two-file limit.

## 2. Implementation map

| # | Function and current file:line | Planned change | Requirements |
|---:|---|---|---|
| 1 | `A2LParameterPicker.set_parameters` — `a2l_parameter_picker.py:526-574` | Add keyword-only `a2l_data=None`; normalize positive non-boolean `length`, never `byte_size`; one batch `describe_definitions` on real population; derive normalized format and cache longest cell; preserve signature semantics. | .001-.004, .009-.010, .017-.019 |
| 2 | `_format_parameter` — **new private** beside population helpers | Pure mapping from optional I-2 definition/tag fields to `text`, `u<N>`, `s<N>`, `f<N>` or exactly `?`, plus unit. No total-length-derived format; a UWORD with a long unit remains `u16` plus that unit. | .003, .017 |
| 3 | `_literal_parameter_text` — **new private** beside cell helpers | Replace C0/C1 with U+FFFD and return literal Rich `Text`; use for A2L/I-2 names, datatypes and units before clipping/painting. | .017 |
| 4 | `A2LParameterPicker._row_cells` / `_refresh_full_name` — `:776-855` (one graph group) | Consume the new normalized optional size/format and literal renderer; preserve existing layout/empty states. Clip full-name format/unit to the remaining full-name cell budget with visible ellipsis before fitting the name. | .003, .017, .020 |
| 5 | `A2LParameterPicker.highlighted_parameter` — `:481-519` | Return `size: Optional[int]`; no behavior change for no row/cursor. | .004-.008, .016 |
| 6 | `PatchEditorPanel.__init__` — `screens_directionb.py:4811-4827` | Use shared pick mode and enable include/bulk with `patch_param` prefix and existing layout provider. | .011, .020 |
| 7 | `PatchEditorPanel.set_a2l_parameters` — `:5375-5391` | Pass current app A2L data into #1; preserve unchanged-signature early return and layout invalidation. | .001-.004, .018-.019 |
| 8 | `CheckEditorPanel.set_a2l_parameters` — `:7285-7314` | Same A2L-data handoff; preserve spec reinclude/demotion/preview behavior. | .001-.004, .009-.010, .018-.019 |
| 9 | `PatchEditorPanel._use_highlighted_parameter` — `:5454-5508` | Refuse missing size with exact text before byte reads; retain full-length all-or-nothing transfer and over-cap boundary. | .004-.008, .016 |
| 10 | `PatchEditorPanel._on_a2l_parameter_picker_bulk_add_requested` / `_open_parameter_bulk_add` — **new host group**, mirroring Check at `:7875-7889` | Stop event and open shared modal bound to Patch picker; no document action. | .012-.015 |
| 11 | `PatchEditorPanel._on_bulk_add_closed` — **new**, mirroring Check `:7891-7903` without Check preview | No ledger rebuild or document/dirty/history mutation; successful selection remains in picker, cancellation inert. | .013-.016 |

## 3. Unchanged context and reuse points

| Id | Function/interface | Role |
|---|---|---|
| C1 | `describe_definitions` / `Definition` — `a2l_definition.py:610`, `:168-208` | One-walk I-2 producer of datatype/kind/full byte-length oracle; no edits. |
| C2 | `S19TuiApp._prefill_check_editor` / `_prefill_patch_editor` — `app.py:7892-7935` | Inc 5 live fan-out and unchanged-signature producer; supplies enriched tag dictionaries but no app edit. |
| C3 | `A2LParameterPicker.include_names` / `parse_parameter_list` — `a2l_parameter_picker.py:75-106`, `:920-1006` | I-5 parser and unique exact-match selection; reused unchanged in pick mode. |
| C4 | `BulkParameterAddScreen` — `screens.py:877-1053` | Shared capped multiline modal and exact summaries; first-missing operator text retains R-B102-BULK-006 literal/control-removal semantics and clipping, outside .017's U+FFFD rule; no edit. |
| C5 | `CheckEditorPanel._named_parameter` / `_demote_moved_spec_params` — `screens_directionb.py:7379-7456` | Existing spec range equality/demotion consumes corrected picker size; no direct edit. |
| C6 | `PatchEditorPanel._apply_a2l_layout` — `:5416-5452` | Existing measured ledger layout; new controls are checked by real geometry at 80/118. |
| C7 | `CheckEditorPanel._on_a2l_parameter_picker_bulk_add_requested` / `_open_parameter_bulk_add` — `:7875-7889` | Host pattern to mirror without changing Check's preview behavior. |
| C8 | `safe_text` — `utils.py:44-99` | Existing literal renderer elsewhere; new picker helper changes only the I-2 control-replacement obligation, not this shared utility. |

## 4. Route-to-slice matrix

| Product route | Path | Distinguishing proof |
|---|---|---|
| Load/reload A2L → visible Check/Patch | C2 → #7/#8 → #1 → C1 once | equal signature 0 describes; changed generation 1 per picker; fresh full length/format without screen re-entry |
| Check spec load/refresh | #8 → C5 using #1 size | 12-byte array spec 12 stays named; spec 2 becomes memory row; demotion preserves original spec bytes |
| Patch Add list | #6 → #10 → C4 → C3 | exact shared parsing/counts/summaries, unique Patch ids, no ledger rebuild/document write |
| Patch Use parameter | #5 → #9 | full non-uniform bytes, missing-length exact refusal, partial-map no-fill, cap guard, only highlighted row |
| Hostile/long picker-owned A2L/I-2 text | #1/#2 → #3 → #4 | markup off, U+FFFD controls, bounded clipped ledger/full-name output, no exception; C4 remains outside this route |

## 5. Explicit exclusions

- No edits to `app.py`, `a2l.py`, `a2l_definition.py`, `screens.py`, styles, services or parser modules.
- No per-row/per-page `describe_definition`, global cache, new worker, or change to Inc 5's generation/signature ownership.
- No document-entry creation from bulk include, no physical-value editor, no I-2 encode or masked staging, and no new long-message surface.
- No weakening of existing over-cap, partial-map, signature, spec demotion, id uniqueness, paging or literal-summary contracts.
