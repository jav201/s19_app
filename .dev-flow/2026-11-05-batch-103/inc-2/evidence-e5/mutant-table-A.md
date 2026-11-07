# E5 mutant table — unit A (R-A2L-DEF.1 … .58.x, Inc 2a)

Base: HEAD `26d3e309`, read-only copy `/tmp/b103-e5-2-mutA/base` on cachyos-rtx. Each mutant is a
`cp -a` of the base with the smallest edit to `s19_app/tui/a2l_definition.py` that realises the
row's Negative control. Tests run with `/home/javiergr/miniconda3/envs/s19ci/bin/python -I -m
pytest -q -p no:cacheprovider tests/test_b103_a2l_definition.py -k "<ids>"` under an isolated
HOME/XDG/LOCALAPPDATA (`zq_iso_user`) and `PYTHONDONTWRITEBYTECODE=1`. Evidence (diff + pytest tail)
in `evidence-e5/mutants-A/out/M-*.txt`.

| Mutant | Row | Control (as written) | Edit made | Tests run | Result | Failing test(s) |
|---|---|---|---|---|---|---|
| M-.1 | R-A2L-DEF.1 | kind chosen by the section (every MEASUREMENT → enum) | `_object_kind`: MEASUREMENT branch returns `"enum"` unconditionally | .1/1 … /4 | killed | .1/2, .1/3 |
| M-.2 | R-A2L-DEF.2 | the kind read from `a2l.py`'s `conversion_type` (None for all three) | `_object_kind`: VALUE and MEASUREMENT branches return `"number"` (never enum) | .2/1 … /3 | killed | .2/1, .2/2, .2/3 |
| M-.3 | R-A2L-DEF.3 | ASCII built as a number of its UBYTE layout | `_object_kind`: ASCII branch returns `"number"` | .3/1 … /2 | killed | .3/1, .3/2 |
| M-.4 | R-A2L-DEF.4 | a VAL_BLK defined as a number of its first element | `_object_kind`: `char_type == "VAL_BLK"` returns `"number"` | .4/1 … /8 | killed | .4/1 |
| M-.5 | R-A2L-DEF.5 | the tag matched ignoring case → /1 finds two tags | name map keyed lower-cased; `_find_tag` looks up the lower-cased name | .5/1 … /2 | killed | .5/1 |
| M-.6 | R-A2L-DEF.6 | a name matched ignoring case → /2 gives a definition | (same case-insensitive edit as M-.5) | .6/1 … /2 | killed | .6/2 |
| M-.7.1 | R-A2L-DEF.7.1 | a missing length taken as the datatype size | `byte_length = DATATYPE_SIZES[datatype]` when it is None | .7.1/1 … /2 | killed | .7.1/2 |
| M-.7.2 | R-A2L-DEF.7.2 | the bound removed → `NUMBER 1048577` gives a definition | drop `byte_length > MAX_A2L_DECODE_BYTES` from the span check | .7.2/1 … /6 | killed | .7.2/3 |
| M-.8 | R-A2L-DEF.8 | a missing datatype read as UBYTE | `datatype = _resolve_datatype(...) or "UBYTE"` | .8/1 … /2 | killed | .8/1, .8/2 |
| M-.9 | R-A2L-DEF.9 | the declared length ignored | delete the `A2L-DEF-LENGTH` refusal | .9/1 | killed | .9/1 |
| M-.10 | R-A2L-DEF.10 | a per-line read of the first word (`a2l.py`'s) | type = first a2l.py conversion keyword in tokens (TAB_VERB excluded) | .10/1 … /4 | killed | .10/1, .10/3, .10/4 |
| M-.11 | R-A2L-DEF.11 | the identity fallback of the tag table → a definition | drop the `A2L-DEF-METHOD` refusal (record None) | .11/1 | killed | .11/1 |
| M-.12 | R-A2L-DEF.12 | FORM treated as identity | add `FORM` to `_SUPPORTED_CONVERSION_TYPES` | .12/1 … /4 | killed | .12/1 |
| M-.12b | R-A2L-DEF.12 | the type word upper-cased before the test (Inc 2a at `069171cd`, CR-4) | `conversion_type.upper()` before the supported-type test | .12/1 … /4 | killed | .12/4 |
| M-.13 | R-A2L-DEF.13 | a missing table read as an empty enum (no refusal) | drop the two `A2L-DEF-TABLE` refusals (keep TABLE-EMPTY) | .13/1 … /2 | killed | .13/1, .13/2 |
| M-.14 | R-A2L-DEF.14 | `a2l.py`'s side table (sorted by raw, numeric texts as floats) | sort `entries` by raw before building the form | .14/1 … /3 | killed | .14/3 |
| M-.15 | R-A2L-DEF.15 | the range table not read (base) | COMPU_VTAB_RANGE count forced to None | .15/1 … /2 | killed | .15/1, .15/2 |
| M-.16 | R-A2L-DEF.16 | DEFAULT_VALUE skipped (base) | delete the DEFAULT_VALUE read | .16/1 … /2 | killed | .16/1, .16/2 |
| M-.17 | R-A2L-DEF.17 | an empty table accepted (every text refused at encode) | delete the `A2L-DEF-TABLE-EMPTY` refusal | .17/1 … /2 | killed | .17/1, .17/2 |
| M-.18 | R-A2L-DEF.18 | the mask read as decimal digits only | drop the `0x` branch of `_parse_bit_mask` | .18/1 … /3 | killed | .18/1, .18/3 |
| M-.19 | R-A2L-DEF.19 | the out-of-width bits dropped silently | drop `mask >= (1 << (8*size))` from `_check_bit_mask` | .19/1 … /5, /9 | killed | .19/2 |
| M-.20 | R-A2L-DEF.20 | EXTENDED_LIMITS ignored (base) | delete the EXTENDED_LIMITS read in `_read_object_lines` | .20/1 … /2 | killed | .20/1, .20/2 |
| M-.21 | R-A2L-DEF.21 | the one number taken as both limits | one finite EXTENDED_LIMITS word becomes both bounds | .21/1 … /3 | killed | .21/1 |
| M-.22 | R-A2L-DEF.22 | the method's format kept over the FORMAT line | `display_format = record_format` (object format ignored) | .22/1 … /2 | killed | .22/1, .22/2 |
| M-.23 | R-A2L-DEF.23 | `a2l.py`'s method format (None for the commented header) | `fmt` read only when the type is an a2l.py keyword (TAB_VERB excluded) | .23/1 … /2 | killed | .23/2 |
| M-.24 | R-A2L-DEF.24 | the checks run in another order → /2 gives A2L-DEF-METHOD | METHOD refusal inserted before the address check | .24/1 … /4 | killed | .24/2 |
| M-.25 | R-A2L-DEF.25 | the decode of a refused definition falls back to identity | delete the refusal short-circuit in `decode_definition` | .25/1 | killed | .25/1 |
| M-.26 | R-A2L-DEF.26 | the missing byte read as 0 (the decode's placeholder) | missing bytes appended as 0; BYTES refusal removed | .26/1 | killed | .26/1 |
| M-.27 | R-A2L-DEF.27 | mask ignored (base) → /1 gives 4660 | delete the masked-field extraction in `_read_stored_value` | .27/1 … /3 | killed | .27/1, .27/2, .27/3 |
| M-.27b | R-A2L-DEF.27 | shift by the highest mask bit | `_mask_shift` returns `mask.bit_length() - 1` | .27/1 … /3 | killed | .27/1, .27/3 |
| M-.28 | R-A2L-DEF.28 | the stored value shown as the value | on decode error set `value = stored` | .28/1 … /3 | killed | .28/1, .28/2, .28/3 |
| M-.29 | R-A2L-DEF.29 | last entry wins (a dict built in file order) | `first_of[raw] = pos` unconditionally | .29/1 | killed | .29/1 |
| M-.30 | R-A2L-DEF.30 | max excluded | range heap pops `<= end` (max end dropped) | .30/1 … /4 | killed | .30/2, .30/3, .30/4 |
| M-.31 | R-A2L-DEF.31 | the stored value shown | default text replaced by `_raw_text(stored)` | .31/1 … /2 | killed | .31/1, .31/2 |
| M-.32 | R-A2L-DEF.32 | the empty text | `(no text)` fallback returns `""` | .32/1 … /2 | killed | .32/1, .32/2 |
| M-.33 | R-A2L-DEF.33 | one byte decoded (base) | `_ascii_text` loops over `raw[:1]` | .33/1 … /3 | killed | .33/1, .33/2, .33/3 |
| M-.33b | R-A2L-DEF.33 | the 0x00 bytes kept | remove the `break` on 0x00 | .33/1 … /3 | killed | .33/1, .33/2 |
| M-.34 | R-A2L-DEF.34 | the byte decoded as Latin-1 → /2 gives `Ã©` | non-ASCII byte → `chr(byte)` (Latin-1) | .34/1 … /2 | killed | .34/1, .34/2 |
| M-.35 | R-A2L-DEF.35 | the format's length applied as padding | width parsed from display_format, applied as field width | .35/1 … /6 | killed | .35/3 |
| M-.35b | R-A2L-DEF.35 | `%g` used → /1 `12.3` | `return f"{value:g}"` | .35/1 … /6 | killed | .35/1, .35/2, .35/3, .35/4 |
| M-.36 | R-A2L-DEF.36 | 40 decimals | `min(int(digits), 17)` → `int(digits)` | .36/1 | killed | .36/1 |
| M-.37 | R-A2L-DEF.37 | `repr` used → /1 `0.30000000000000004` | `%.15g` → `repr(value)` | .37/1 … /4 | killed | .37/1, .37/2 |
| M-.38 | R-A2L-DEF.38 | the 15 decimals applied → /1 `-5.000000000000000` | drop the integer short-cut and the conversion guard in the decimals branch | .38/1 … /2 | killed | .38/1 |
| M-.39 | R-A2L-DEF.39 | a non-finite value refused as a decode error | non-finite value → `A2L-DEF-DECODE` refusal | .39/1 … /3 | killed | .39/1, .39/2, .39/3 |
| M-.39b | R-A2L-DEF.39 | `NaN` / `Infinity` spellings | `"NaN"` / `"Infinity"` / `"-Infinity"` | .39/1 … /3 | killed | .39/1, .39/2, .39/3 |
| M-.58.2 | R-A2L-DEF.58.2 | the count read as `int(_to_float(n))` → `1e400` raises | `_read_count` → `int(_to_float(word))` | .58.2/1 … /24 | killed | .58.2/1, .58.2/2, .58.2/4 |
| M-.58.2b | R-A2L-DEF.58.2 | Inc 2a at `eb750c6f` → /18 raises TypeError in `display_text` | remove the fail-closed "not a number" check | .58.2/18 | killed | .58.2/18 |
| M-.58.2c | R-A2L-DEF.58.2 | the NaN-x verdict left out → /19 decodes through an unordered table | remove the `x_nan` refusal in `decode_definition` | .58.2/19 | killed | .58.2/19 |
| M-.58.2d | R-A2L-DEF.58.2 | a number written by `str(n)` → /20 … /23 raise ValueError | `_number_text` → `str(number)` / `_fmt_address` (no hex-echo fallback) | .58.2/20 … /23 | killed | .58.2/20, .58.2/21, .58.2/22, .58.2/23 |
| M-.58.2e | R-A2L-DEF.58.2 | the recursive walk → /24 raises RecursionError | iterative stack → recursive `_walk` | .58.2/24 | killed | .58.2/24 |
| — | R-A2L-DEF.58.1 | an encode that writes its bytes into the image | **not realisable**: the encode/merge that writes bytes into the image is a 2b arm; the 2a module (`a2l_definition.py`) is the read side and has no write path to mutate. | .58.1/1 … /2 | not realisable | — |

## Summary

- **killed**: 50
- **survived**: 0
- **not realisable**: 1 (R-A2L-DEF.58.1 — its Negative control is the encode arm, which is 2b)
