# Inc 11 — E4 impl notes (unit: `s19_app/tui/a2l.py` only)

Base `b7b77c4`, branch `b101-inc11`. Graph `codewire/graph-inc11.md`, rulings
`E1-rulings.md` + `E3-rulings.md` (round 1, addendum, round-2 addenda N-1 … N-4).

## Functions / constants changed (file: name)

- `s19_app/tui/a2l.py:PROGRAM_TYPE_WORDS` — new frozenset of the 8 program-type
  words (CALIBRATION_VARIABLES, CODE, DATA, EXCLUDE_FROM_FLASH, OFFLINE_DATA,
  RESERVED, SERAM, VARIABLES).
- `s19_app/tui/a2l.py:MEMORY_TYPE_WORDS` — new frozenset of the 7 memory-type
  words (EEPROM, EPROM, FLASH, NOT_IN_ECU, RAM, REGISTER, ROM).
- `s19_app/tui/a2l.py:_a2l_number` — new helper. Returns the value when `word`
  fully matches the ASCII pattern `[+-]?(0[xX][0-9A-Fa-f]{1,8}|[0-9]{1,10})`,
  else `None`; decimal in base 10 (so `0400` is 400), hex in base 16, sign
  applied. Rejects `0o`/`0b`, `_`, non-ASCII digits, and longer digit runs.
- `s19_app/tui/a2l.py:_memory_segment_record_words` — new helper. One linear
  scan over `meta` then each own `line`; returns `(words, texts)` where each
  word is `(text, text_index, quoted)` and `texts` are the comment-stripped
  texts. Quote state resets per text (a `"` left open ends at the line); block
  comments `/* … */` may span texts; `//` comments end at the text. Does not
  call `_strip_a2l_comments` or `_split_line_respecting_quotes` (both unchanged).
- `s19_app/tui/a2l.py:extract_memory_segments` — changed to the anchored rule:
  `block_name` = first record word or `None`; address word = first unquoted word
  after the name starting with an ASCII digit or sign; base/size = that word and
  the word after it as ASCII Numbers, kept only when base ≥ 0, size > 0 and
  base + size ≤ 2**32; offset = the word after the size; usage/kind = last
  program-type / memory-type word before the address word. No address word or a
  failed check leaves every numeric field `None` (no further scan). Entry keys
  and order unchanged; recursive walk unchanged.
- `s19_app/tui/a2l.py:render_curve_description` — changed for F-21: when every
  point has `x_note`, emit the line `  x: point index (axis points unavailable)`
  once directly above the header and print no per-row suffix; otherwise keep the
  per-row `   (<x_note>)` suffix (mixed case). Header, widths, `(!)` marks,
  `y shape:` and notes unchanged.

## Deviations from the graph

None. The constants, helpers and both changed functions are implemented exactly
as the graph states their `func:` forms, the I-3 entry contract, and the E3
anchored-rule folds (A-1, S-1, S-2, A-7, N-1 … N-4). The `_a2l_number` ASCII
pattern is enforced with explicit string scans (no `re` import added), which is
byte-equivalent to the pinned regex and adds no new module dependency.

## Verification (no pytest, no `s19_app` import — operator rule)

- `python -m py_compile s19_app/tui/a2l.py` → OK (exit 0).
- Standalone AST extraction of the five new/changed symbols executed the graph
  examples: all `_a2l_number` cases, the four MEMORY_SEGMENT shapes (V161,
  `software_a.a2l`, release demo `boot`, `Calib Vars Rom`-style quoted name),
  S1 … S13 (including S13 = 2^32 kept, S12 > 2^32 rejected), M1/M2/M3, the
  `case_07` record, the empty block, the comment + open-quote record, and the
  F-21 all-index / mixed / zero-point description cases → all OK.

Line endings: `s19_app/tui/a2l.py` stays CRLF on disk (3716 CRLF, no bare CR).
