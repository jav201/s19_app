# E5 mutant table B — Inc 2a (rows R-A2L-DEF.59 … .151), HEAD `26d3e309`

Role `mutB` (N=2). Rows from `inc-2/01-requirements.md` "Split (amendment A2)" 2a side, ids ≥ .59: **.59, .60, .61, .62, .63, .136, .137, .139, .149, .150, .151** (11 rows). Two rows have a second control named by `E5-rulings.md` / `E5-code-review.md` → both taken: **M-59b** (CR-6 `planned_text`) and **M-149b** (CR-7 `compare=True`). 13 mutants total.

All runs on <runner> (`<user>@<runner-ip>`), Python 3.11.18 (`~/miniconda3/envs/s19ci/bin/python`), base tree `/tmp/b103-e5-2-mutB/base` = read-only copy of `~/work/b103-int2a` (HEAD `26d3e309`), HOME/XDG_*/LOCALAPPDATA isolated to `<user>`, `PYTHONDONTWRITEBYTECODE=1`. Synth rows edit `tools/synth/make_release_case.py`; the rest edit `s19_app/tui/a2l_definition.py`. Evidence (unified diff + pytest tail) in `mutants-B/out/<id>.txt`.

| Id | Requirement row | Control as written | Edit made (one line) | Tests run | Result | Failing test id(s) |
|---|---|---|---|---|---|---|
| M-59 | R-A2L-DEF.59 | one object added to the release case's inventory → the S19, HEX, A2L and MAC digests change → RED | `_push_scalars("app", 180, False)` → `181` (one extra VALUE in the app region) | `test_b103_synth_definitions.py -k a2l_def_59` (4) | killed | `.59/1`, `.59/2`, `.59/3` |
| M-59b | R-A2L-DEF.59 (2nd control, CR-6) | `planned_text` fixed to `IDLE` → seed 2 decodes `OFF` against `IDLE` → RED | `"planned_text": DEFINITIONS_ENUM_TEXTS[enum_raw]` → `"planned_text": "IDLE"` | `test_b103_synth_definitions.py -k a2l_def_59` (4) | killed | `.59/4` |
| M-60 | R-A2L-DEF.60 | the TAB_VERB method of the case written like case 08's COMPU_VTAB for a TAB_NOINTP method → the kind is number → RED | `TAB_VERB "%.0"` → `TAB_NOINTP "%.0"` in CM_DEF_ENUM | `test_b103_synth_definitions.py -k a2l_def_60` (1) | killed | `.60/1` |
| M-61 | R-A2L-DEF.61 | the two masks overlapping → RED | `"bit_mask": 0x0FF0` → `0x0FF1` (MASK_FIELD_0001 now shares bit 0) | `test_b103_synth_definitions.py -k a2l_def_61` (1) | killed | `.61/1` |
| M-62 | R-A2L-DEF.62 | the PHYS_UNIT written as a UNIT line → RED | `'PHYS_UNIT "deg C"'` → `'UNIT "deg C"'` in DEFINITIONS_EXTRA_LINES | `test_b103_synth_definitions.py -k a2l_def_62` (1) | killed | `.62/1` |
| M-63 | R-A2L-DEF.63 | a wall-clock value written into the case → RED | append `+ f"/* {time.time()} */\n"` to the definitions.a2l text (+ `import time`) | `test_b103_synth_definitions.py -k a2l_def_63` (1) | killed | `.63/1` |
| M-136 | R-A2L-DEF.136 | one walk per name (about 67 s) → RED | move the name/method/table map build inside the per-name loop (one walk per name) | `test_b103_a2l_definition.py` + `test_b103_a2l_definition_perf.py -k a2l_def_136` (2) | killed | perf `.136/1` (`_describing_every_object_is_fast`: killed at 150 s; one-walk-per-name ≈ 25 min for one run ≫ 2.0 s) |
| M-137 | R-A2L-DEF.137 | no replacement → RED | `_clean` returns `text` unchanged (drop the U+FFFD replacement) | `test_b103_a2l_definition.py -k a2l_def_137` (4) | killed | `.137/1`, `.137/2` |
| M-139 | R-A2L-DEF.139 | the first tag of the name used (the round-3 rule) → /3 gives the address 0x10 of the commented-out copy → RED | `_find_tag` returns `tags[0]` instead of the duplicate-name refusal | `test_b103_a2l_definition.py -k a2l_def_139` (3) | killed | `.139/1`, `.139/2`, `.139/3` |
| M-149 | R-A2L-DEF.149 | a shared section read per object at describe → RED | pass a fresh `{}` `reads` map per name (drop the once-per-walk memo) | `test_b103_a2l_definition.py` + `test_b103_a2l_definition_perf.py -k a2l_def_149` (14) | killed | `.149/1`, `/2`, `/3`, `/4`, `/1..4` scaling, `/6`, `/7`, `/8`, `/9`, `/10`, `/5` |
| M-149b | R-A2L-DEF.149 (2nd control, CR-7) | `compare=True` on either field → RED | `compare=False` → `compare=True` on `_name_echo` and `_table_form` | `test_b103_a2l_definition.py -k a2l_def_149_5` (1) | killed | `.149/5` |
| M-150 | R-A2L-DEF.150 | a scan of `enum_entries`, a `_clean` of the text, per element → RED | drop the `_EnumForm` fast path in `_enum_entry_text` and `_enum_text` (linear scan per element) | `test_b103_a2l_definition.py` + `test_b103_a2l_definition_perf.py -k a2l_def_150` (10) | killed | `.150/1`, `/2`, `/3`, `/4`, `/5` |
| M-151 | R-A2L-DEF.151 | Inc 2a at `eb750c6f` (`_clean` only) → /2 gives 257 chars no `…`, /3 keeps `É` → RED | `_echo` returns `_clean(word) or ""` (drop the 256-char cap and the U+0021–U+007E → U+FFFD rule) | `test_b103_a2l_definition.py -k a2l_def_151` (6) | killed | `.151/2`, `/3`, `/4`, `/5`, `/6` |

Counts: **13 killed / 0 survived / 0 not realisable.**

Notes (what each second control's source says):
- **M-59b** — `E5-rulings.md` "Fix-pass records": CR-6's seeds test sits under R-A2L-DEF.59's synth cases with a negative control; `E5-code-review.md` CR-6 names it (`planned_text`).
- **M-149b** — `E5-rulings.md` CR-7 ("add the missing test the review names"); `E5-code-review.md` CR-7 names the control "Negative control: `compare=True` → RED" for `.149/5` (P-2: the two private fields are `compare=False`).
- **M-137** — only `.137/1` and `.137/2` (enum text) fail: the name cases `.137/3`, `/4` are echoed through `_echo` (R-A2L-DEF.151), not `_clean`, so the `_clean`-only mutant leaves them green. The control ("no replacement") is realised on the `_clean` path.
- **M-150** — the edit realises the enum-scan arm of the cell; the TAB arm (frozen `_table_lookup` per element, /7 /8 /10) is left intact, so those stay green; `.150/6` and `.150/9` (equality vs the linear/oracle) also stay green by construction.
