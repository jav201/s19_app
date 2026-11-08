# E3 correction unit C1 — Inc 2 graph: interface and describe path (`inc-2/codewire/graph-inc2.md` only)

Rules: `design/E3-corr-2-common.md` (read it first). Unit C2 edits the decode / encode / display nodes after you; do not touch those.

## Apply, in `graph-inc2.md`
- E3A-01 + E3A-13: I-2 gains `describe_definitions(names: Iterable[str], a2l_data: dict) -> dict[str, Definition]`, over one walk that maps the first MEASUREMENT/CHARACTERISTIC section of each name and every COMPU_METHOD, COMPU_VTAB and COMPU_VTAB_RANGE by name. `describe_definition` delegates to it. `_find_tag` becomes a lookup in that map (its sort and fallback go). Node, contract and an example for R-A2L-DEF.136.
- E3A-03: `Definition` gains the method record's coefficients and table reference (fields with defaults, before `refusal`), so decode and encode never walk `sections`. Write the field list; C2 updates the decode / encode nodes to read them.
- E3S-01: in `describe_definition` / `_read_object_lines`: an unreadable BIT_MASK word, a text object with a BIT_MASK line, or a tag `bit_org` set while the definition has no mask → the `A2L-DEF-MASK` refusal (fail closed). Examples for .19/4 and the text-with-mask case.
- E3S-02: the span check (`MAX_A2L_DECODE_BYTES` reused and added to the D-9 import list), the .7.2 refusal and its examples.
- E3A-17: the signature pin adds `encode_physical_to_raw_bytes` and `parse_begin_meta`.
- E3A-07 + E3S-08 + E3S-04 (a): the I-2 consumer notes exactly as E3-rulings.md states them.
- E3A-09: `<kind>` = `(none)`, and its example (case_07 `CHAR_000000`).
- E3S-12: the definitions case writes `definitions.s19` and `definitions.a2l` (I-D and the generator node).
- Update the coverage-table rows for the ids you touched and the node count. Append to `inc-2/steps.log`: `<ISO timestamp> E3 correction unit C1 (graph: interface, describe) — deepseek-v4-pro via pi — <n> findings applied`.
