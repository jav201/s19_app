# E3 round-2 correction unit G — Inc 2 graph (`inc-2/codewire/graph-inc2.md` only)

Rules: `design/E3-corr-2-common.md` (read it first). No new row id.

Authority: the section "## Round 2 rulings" at the end of `inc-2/E3-rulings.md`. Then the "## Round 2" sections of `inc-2/E3-architect.md` and `inc-2/E3-security.md`: for each finding the rulings accept, apply its fix column to the graph (`grep -n "^| E3A-2[1-9] \|^| E3A-3[0-2] \|^| E3S-1[4-9] \|^| E3S-2[0-1] "`).

## Apply (graph only — rows and cases are another unit's; use their ids as the rulings fix them: .19/7, .19/8 keyword cases, .19/9 SBYTE case, .24/4, .26/4, .58.2/16, .58.2/17)
- E3S-14: `describe_definitions` / `_read_object_lines` record a BIT_MASK keyword even when no mask word is read; such an object gets `A2L-DEF-MASK` at its place in the refusal order (E3A-28). Examples for .19/7 and .19/8 (the two shapes of the fix column: BIT_MASK on a one-word-short header line; BIT_MASK behind a comment on its own line).
- E3A-25 / E3S-19: U+FFFD only in the display text of a decoded value and in every refusal message and notice; the I-2 consumer note adds that every other `str` field is a raw file word and a consumer that renders one replaces control characters as R-A2L-DEF.137 does.
- E3A-22: `Definition`'s three conversion fields lose their defaults (every construction states them).
- E3A-32: the I-2 extension bullet for Inc 3 (its lookups are maps built in `describe_definitions`'s one walk), as the fix column words it.
- E3A-12 (the CONVERSION wording in the `describe_definitions` func), E3A-29 (cost text, `req:` list copied, the edge, "a repeated name maps once"), E3A-30 / E3S-21 (example ids, names and inputs aligned with the cases), E3A-31 / E3S-18 (span boundary example, `<address>` format), E3S-16 (text encode: `_encode_ascii`, then the image-span check, then `Encoded`; .26/4 example), E3S-17 ("integral = finite and `float.is_integer()`"; .58.2/16–17 examples), E3S-20 (at most one notice: the limit value's notice, else the written value's).
- Update the coverage-table rows for the ids you touched and the node count. Append to `inc-2/steps.log`: `<ISO timestamp> E3 round-2 correction unit G (graph) — deepseek-v4-pro via pi — <n> findings applied`.
