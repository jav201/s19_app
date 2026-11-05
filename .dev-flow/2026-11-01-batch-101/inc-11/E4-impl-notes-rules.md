# Inc 11 — E4 implementation notes (unit: `s19_app/validation/rules.py`, G1 engine)

Stage E4 of the design-first flow (`dev-flow-v3-beta`). Implementer: E4 unit. Graph: `codewire/graph-inc11.md`. Slice: `E1-slice.md`. Rulings: `E1-rulings.md`, `E3-rulings.md` (round 1, addendum, round 2 addenda N-1…N-4, all binding).

## Functions / constants changed per file

File: `s19_app/validation/rules.py` (the only file edited by this unit)

- `s19_app/validation/rules.py:RECOGNIZED_A2L_BLOCKS`
  - Changed: 15 → 62 ASAM MCD-2 MC block names (the Definitions list of `01-requirements.md`; `AR_COMPONENT` included, E3 A-4). The original 15 names are a strict subset.
  - Interface `[Data: RECOGNIZED_A2L_BLOCKS]` (R-VAL-032.2).
- `s19_app/validation/rules.py:INTERFACE_DATA_BLOCK`
  - New constant `INTERFACE_DATA_BLOCK = "IF_DATA"` (graph `[Data: INTERFACE_DATA_BLOCK]`).
- `s19_app/validation/rules.py:_iter_sections`
  - Changed: return type `list[dict]` → `list[tuple[dict, bool]]`; each element is `(section, inside_if_data)` in the same pre-order. `inside_if_data` is `True` when any enclosing section's `str(name).strip().upper()` equals `INTERFACE_DATA_BLOCK`; the IF_DATA node itself carries its own parents' flag. The flag is passed down as a walk argument (one frame per level) and never recomputed from ancestors (E3 S-3). Recursion kept (O-4, BACKLOG).
- `s19_app/validation/rules.py:validate_a2l_structure`
  - Changed: the section loop unpacks `(section, inside_if_data)`; the `A2L_UNRECOGNIZED_BLOCK` issue is raised only when `section_name and not inside_if_data and section_name not in RECOGNIZED_A2L_BLOCKS`. Message, severity, line number and the GROUP/FUNCTION reference pass are unchanged (interface I-1).

## Deviations from the graph

None. The four node changes match the graph (`RECOGNIZED_A2L_BLOCKS`, `INTERFACE_DATA_BLOCK`, `_iter_sections`, `validate_a2l_structure`) exactly as specified; no function renamed, moved or removed; no other file edited.

## Verification

- `python -m py_compile s19_app/validation/rules.py` → **OK** (exit code 0).
- `RECOGNIZED_A2L_BLOCKS` re-checked statically: 62 entries, 62 unique, order-insensitive equal to the 62-name Definitions list (`A2ML` … `VIRTUAL_CHARACTERISTIC`), with `IF_DATA` and `AR_COMPONENT` present.
- Callers checked: `_iter_sections` is referenced only by `validate_a2l_structure` (both in this file); `RECOGNIZED_A2L_BLOCKS` is read only by `validate_a2l_structure` plus one comment in a test; `INTERFACE_DATA_BLOCK` is referenced only in this file. No test imports these names.
- Line endings preserved: file is clean CRLF (565 CRLF, 0 bare LF, 0 stray CR) after the patch.
