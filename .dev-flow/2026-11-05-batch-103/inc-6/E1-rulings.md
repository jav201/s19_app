# Inc 6 — E1 rulings

Date 2026-11-10; model Kimi. Authority: `../PLAN.md:61`, US-103-04, I-2/I-4/I-5, and I-11.8(g). These are design rulings; no runtime result or operator approval is claimed.

## D-1 — Declared `length` is the only picker size source

`A2LParameterPicker.set_parameters` will normalize a positive non-boolean `row["length"]`; all other values remain `None`. It will never read enriched `byte_size` for size. This discharges both halves of I-11.8(g): removal of `or 1`, and the round-2 widening that forbids layout/enriched element size for arrays or refused lengths.

Existing direct test fixtures that provide only `byte_size` must be ported to `length` without deleting their assertions. That is a fixture correction required by the new contract, not permission to preserve a production fallback.

## D-2 — I-2 supplies element datatype/kind in one batch

The picker gains an optional keyword-only `a2l_data` on `set_parameters`; existing positional `rows, signature` remains unchanged. Check/Patch panel shims pass their app's already loaded `current_a2l_data`; `app.py` and Inc 5's fan-out stay unchanged. On a real population with A2L data, the picker calls `describe_definitions` once for all row names and uses `Definition.datatype`/`kind` for format. Direct unit rows without A2L data use their tag `datatype`/`char_type` only; neither path uses `byte_size`.

The format is an element datatype label, not the A2L display precision string. This follows I-2's Inc 6 note naming `byte_length`, `datatype` and `kind`; `display_format` remains editor/display-value concern. Normalization: unsigned `u<N>`, signed `s<N>`, IEEE float `f<N>`, ASCII `text`, unknown `?`; unit follows verbatim after literal-control replacement.

One call per picker per changed generation preserves R-A2L-DEF.136's 2.0 s budget. Filter/page rendering reuses normalized rows and never describes again. No module-global mutable definition cache is introduced.

## D-3 — Missing length refuses Bytes prefill

`highlighted_parameter` returns `size: Optional[int]`. Patch `Use parameter` checks `None` before any byte lookup: Bytes becomes empty, the exact line is `Parameter has no length — Bytes not prefilled.`, and document/dirty/undo/redo state remains unchanged. Address may be populated, matching the existing over-cap path; no image byte is read and no write action is posted.

Full lengths drive the existing all-or-nothing loop and over-cap guard. Partial maps never zero-fill. The `>` cap boundary remains unchanged.

## D-4 — Patch gains picker-local bulk selection, not document writes

Patch changes from `highlight` to `pick` mode and enables include/bulk controls. It hosts the existing `BulkParameterAddScreen` for `#patch_param_bulk_button`, reusing `parse_parameter_list` and `include_names`. Include, space/enter, duplicate handling, exact summary and no-match behavior are the shared contract.

Bulk inclusion changes only the pick set and visible marks. It never adds change entries or alters dirty/undo/redo state. `Use parameter` still transfers only the highlighted row. This is the smallest interpretation of “Patch bulk include” that supplies parity without inventing an undocumented document-write operation.

Patch adds a host bulk-message route mirroring Check and a close tail that does not rebuild the ledger. Any future bulk document creation belongs to a separately specified increment.

## D-5 — Check specs inherit corrected full lengths

No new spec matching rule is introduced. Existing `(address, size)` equality, demotion and spec-byte preservation consume the corrected picker size. Tests must include a discriminating 12-byte array whose enriched `byte_size` is 2 and whose spec size alternates 12 and 2.

## D-6 — Literal I-2 rendering replaces controls; non-applicable carries stay out

Picker-owned A2L/I-2 strings use literal `Text`, markup off, U+FFFD for C0/C1, and existing cell clipping. This deliberately narrows current `safe_text` deletion to the new I-2 consumer obligation. The shared modal remains unchanged and already provides literal, clipped first-missing text.

Inc 6 does not call I-2 encode, stage masked edits, display refusal messages or accept operator values for encoding. E3A-07/E3S-08 (overlay/re-encode) and E3S-11 (long operator `<text>` in encode messages) are recorded for Inc 8/9, not implemented as unrelated new features here. Long picker strings are bounded by the cell clipping required in .017.

## D-7 — Existing UI grammar, no new visual system

Reuse the shipped ledger, docked chip row, focus order, modal, colors and static feedback. No new motion, palette, glyph language, widget library or visual signature is introduced. The visible delta is limited to full/correct formats and Patch include/bulk controls. Geometry is measured at 80×24 and 118×54 through Textual, not inferred.

## D-8 — Canon/follow-up at batch end

The new R-PICKER-CORRECT rows refine R-B102-SEL-001/007, R-B102-PE-001/003/006 and the Patch application of R-B102-BULK-001…007. They supersede the old `byte_size` normalization and Patch highlight-only mode. Canon is untouched at E1; batch-end folding must remove that contradiction and record the optional `a2l_data` keyword plus `size: Optional[int]` interface.

No new AT/TC registry ids are allocated in E1. Tests will use requirement-keyed cases and batch-scoped acceptance ids only if the tester needs them.
