# E3 correction unit A — Inc 2 requirement rows (`inc-2/01-requirements.md` only)

Rules: `design/E3-corr-2-common.md` (read it first).

## Apply, in `01-requirements.md`
- E3S-01: R-A2L-DEF.19's condition and the text-object-with-mask refusal (a new alternative in the same row only if it shares the response; else split .19 into .19.1 / .19.2).
- E3S-02: split R-A2L-DEF.7 into .7.1 / .7.2 with the exact text in E3-rulings.md.
- E3S-03: split R-A2L-DEF.58 into .58.1 / .58.2 with the exact text, threshold and negative control in E3-rulings.md.
- E3A-01: new row **R-A2L-DEF.136**: `When the system describes every object of an A2L file of 13,990 objects, the system shall finish within 2.0 s.` Threshold: median of 3 runs on the software_a fixture, <runner>, Python 3.11.18, `serial_timing`; negative control: one walk per name (about 67 s) → RED. Status `new (E3A-01)`.
- E3S-04 (b): new row **R-A2L-DEF.137**: `If a word that the system takes from the A2L file or from the operator holds a control character (U+0000–U+001F, U+007F or U+0080–U+009F), then the system shall give U+FFFD in its place in every text and message it returns.` Threshold 4/4 (a NUL and an ESC, in an enum text and in a name); negative control: no replacement → RED. Status `new (E3S-04)`.
- E3A-02 + E3S-07: the CTX term *agree at the display precision* exactly as E3-rulings.md states it.
- E3A-04 (.35 narrowed, .38 becomes a `When` row), E3A-05 (.56 restated as the fix column words it), E3A-06 (the d ≥ 15 display rule, in the display row or CTX term it belongs to), E3A-09 (`<kind>` placeholder gains `(none)`), E3A-12 (CONVERSION wording), E3A-14 (signed datatype whose mask holds bit 0 and the sign bit → refused, in the mask row), E3A-18 (CTX line: the inclusive range rule holds for every datatype), E3S-05 (.26 "decodes or encodes"), E3S-06 (limit rows .43–.45: the written value also checked, as E3-rulings.md says), E3S-09 (.54: the exact-integer check), E3S-10 (.21 and the `<lower>` placeholder rule: a non-finite word is not a number), E3S-11 (.40: ASCII digits only, spaces trimmed).
- Update the count / summary lines (count the active rows after the splits and the two new rows) and append to `inc-2/steps.log`: `<ISO timestamp> E3 correction unit A (rows) — deepseek-v4-pro via pi — <n> findings applied`.
