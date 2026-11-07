# E3 correction unit C2 — Inc 2 graph: decode, encode and display path (`inc-2/codewire/graph-inc2.md` only)

Rules: `design/E3-corr-2-common.md` (read it first). Unit C1 already changed the interface, `Definition`'s fields (the method record carried) and the describe path: read its result first and keep it.

## Apply, in `graph-inc2.md`, to the decode, encode, display and helper nodes
- E3A-03: decode and encode read the method record from `Definition`'s new fields, never `sections`.
- E3A-02 + E3S-07: `_agrees_at_display_precision` exactly as the CTX term in E3-rulings.md (the 15-significant-digit clause for every datatype; 6 digits for FLOAT32_IEEE only). Examples for .54/3 and the `%.15` grid.
- E3A-04 (.35 / .38 order) and E3A-06 (d ≥ 15: round to 15 significant digits, then d decimals; .36/1 → `0.10000000000000000`).
- E3S-04 (b): the U+FFFD replacement in `Decoded.text` and in every message built from a file or operator word (R-A2L-DEF.137), with examples.
- E3S-05: the image-holds-the-span check at the encode order's image step, for every kind (.26/3 example).
- E3S-06: step 7 checks the written value `p` against the extended limits, else the limits; the .44 notice only when `p` is outside the limits; FLOAT32 limits packed as FLOAT32 (.45/3 example).
- E3A-14 (signed mask with bit 0 and the sign bit → refused), E3A-16 (count-driven table read), E3S-03 (every raise path the fix column lists is guarded: table counts `1e400`, `nan`, `-3`, `2.5`; a 5,000-digit decimal; an eager `DATATYPE_SIZES[None]`; …; .58.2 examples), E3S-09 (`Decimal` exact-integer check, .54/4), E3S-10 (non-finite words are not numbers, .21/3), E3S-11 (ASCII digits only, `strip(" ")`, .40/8–9), E3A-11 (.46/4 masked enum encode example).
- Update the coverage-table rows for the ids you touched and the node count. Append to `inc-2/steps.log`: `<ISO timestamp> E3 correction unit C2 (graph: decode, encode, display) — deepseek-v4-pro via pi — <n> findings applied`.
