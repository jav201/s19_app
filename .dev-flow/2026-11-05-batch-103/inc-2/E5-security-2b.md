# Inc 2b E5 security review — `b103-inc2b-code` @ `cb083d07`

**Verdict: PASS-WITH-NOTES.** No MAJOR or HIGH open; nothing blocks integration.
The encode surface (`encode_definition` + its helpers in
`s19_app/tui/a2l_definition.py`) is bounded and control-safe on every new
message string, the overlap guard's span-index identity and cross-kind order
are correct, CLEAN masks / duplicate names / byte-order residuals behave as
ruled in `E3-rulings.md` "Inc 2b re-review against the fixed reader", and the
encode order (definition refusal → parse errors → operator-value checks →
limits → encode → image → mask → precision → shared bytes) matches R-A2L-DEF.57
and R-A2L-DEF.152. Three non-blocking notes remain (two LOW, one INFO).

## What was executed

**Nothing by this reviewer.** Per the brief ("do not run pytest/probes on
Windows"), this is a read-only static review over the integrated tree at
`cb083d07`: the product diff `git diff b73fb886..cb083d07 --
s19_app/tui/a2l_definition.py`, the full new functions in that file, the frozen
encode direction in `s19_app/tui/a2l.py`
(`encode_physical_to_raw_bytes`, `_invert_physical_to_raw`,
`_reverse_table_lookup`, `extract_declared_spans`, `_echo_word`, `_to_float`,
`_number_word`), and the current tests
`tests/test_b103_a2l_definition.py` (`.40`–`.57`, `.138/1`–`.138/20`,
`.151/7`, `.152/1`–`.152/5`, `.58.2` encode arms, `.58.1` encode arm,
`AT-B103-I2-1` write arm) and `tests/test_b103_synth_definitions.py`
(`.138/16`, `.46/3`). No pytest, no probes, no git mutations.

## Confirmations (read-only)

- **Caps / control handling on every new string.** All new refusal/notice
  strings route operator text through `_operator_echo` (`a2l_definition.py:3241`,
  256-char cap + C0/C1 → U+FFFD via `_clean`, spaces and other Unicode
  preserved), file words through `_echo` (`:316`), numbers through
  `_number_text` (`:346`), addresses through `_fmt_address` (`:338`), and the
  parse-error word through the parser's `_echo_word` (`a2l.py:328`, capped and
  C0/C1-replaced). The `A2L-DEF-PARSE` message interpolates `errors[0]`
  (`a2l_definition.py:3684`), which is safe because every parser error embeds
  file words only through `_echo_word` (verified over `a2l.py:505–3890` error
  sink). `A2L-DEF-ENCODE` reasons are bounded (`str(float)` reprs, known
  datatype/conversion-type words). `A2L-DEF-ELEMENTS` interpolates
  `element_count`, bounded because `_read_count` caps each MATRIX_DIM word at 9
  digits (`_matrix_shape`, `:443`). R-A2L-DEF.151 / .137 hold.
- **Span-index identity & cross-kind order.** `describe_definitions.walk`
  (`a2l_definition.py:600–669`) and `extract_declared_spans.walk`
  (`a2l.py:3968–4010`) are the same pre-order DFS over the same `sections`
  tree, so `declared_spans` (BLOB/INSTANCE) aligns 1:1 with the walk's
  BLOB/INSTANCE nodes via the `ds_index` cursor — no mis-pairing, including an
  unclosed BLOB/INSTANCE (which still consumes a `declared_spans` slot with
  `address=None`). The own-entry skip in `_shared_with` (`:3565–3577`) keys on
  `(name, section, address, byte_length, byte_order)`, all of which derive from
  the same tag the definition was built from, so a clean definition never
  matches itself as an overlap. `id(entry)` dedup (`:3560`) is stable because
  `span_entries` tuples stay alive through the index. R-A2L-DEF.138 holds.
- **CLEAN masks / duplicate names / byte-order residual.** `mask_of`
  (`:700–719`) returns `other.bit_mask` only when `other.refusal is None and
  other.byte_length is not None`; a duplicate name or length/byte-order-refused
  neighbour therefore yields no mask and the pair is never exempt — matching
  E3S-41/E3S-36 and cases `.138/10`, `.138/11`, `.138/12`. `.19/7` residual
  (`_mask_byte_order_ambiguous`, `:3629`) counts live BYTE_ORDER in the
  object / record layout / MOD_COMMON and is non-vacuous (the reader alone
  last-wins and refuses nothing — premise `e3-2b-residual-premise.txt`).
- **No `byte_length is None` reaches the image/mask merge.** `byte_length` is
  `None` only when `tag_length is None` or the MATRIX-on-VALUE `value_145`
  flag is set (`:944`), and both force a non-`None` refusal (ADDRESS / MATRIX),
  which `encode_definition` returns at its first step (`:3677`). Array kinds are
  refused at `:3688` before any span arithmetic. So `_image_span_refusal`
  (`range(definition.byte_length)`) and `_merge_bit_mask` cannot raise on
  `None`.
- **Immutable input.** `encode_definition` reads `image` and builds new
  `data`/`written_image` dicts; `_encode_number` builds a fresh mask-free tag
  view and does not mutate `a2l_data`; the frozen encoder only `.get()`s its
  inputs. Covered by `.58.1` encode arm (`test_r_a2l_def_58_1_1/2_encode_*`).
- **Encode-direction hostile content is refusal-safe.** `_reverse_table_lookup`
  (`a2l.py:2870`) sees only float `raw_x` (non-numeric x is dropped in
  `extract_compu_tables`, `a2l.py:1768–1770`), and nan/inf raw degrades to a
  "not finite"/"not invertible" reason, never an exception; `_merge_bit_mask`
  cannot overflow `to_bytes` because `_check_bit_mask` (`:2610`) bounds the mask
  to the datatype width.

## Findings

### F-1 (LOW · design-gap · coverage) — no hostile BLOB/INSTANCE header case

Ref: R-A2L-DEF.138 (BLOB/INSTANCE in the index) and R-A2L-DEF.58.2 (hostile
content → refusal, never an exception); impl at `a2l.py:3894`
(`extract_declared_spans`) and `a2l_definition.py:634–651` (index).

The implementation degrades safely — a BLOB address/length that `_number_word`
cannot read (e.g. `0x` + 5,000 hex digits, a 5,000-digit decimal) yields
`None` and the span is either not indexed (no address) or a fail-closed
declared-address point (address read, length unreadable), and a dangling or
hostile TYPEDEF behind an INSTANCE yields `length=None` through
`_instance_length` (`a2l.py:3921`). But the `.58.2` 24-shape hostile corpus and
the `.138` 20 cases never exercise a hostile BLOB/INSTANCE header — `.138/2`,
`/3`, `/4` use clean/dangling-but-benign headers only. The path is therefore
correct-but-unproven against the one host-shaped body the brief calls out.

Bounded correction: add one `.138`-adjacent INLINE case — a BLOB at `0x10` whose
address word is `0x` + 5,000 hex digits (assert the neighbour at `0x10` encodes,
BLOB not indexed) and an INSTANCE whose TYPEDEF is undeclared and whose address
word is a 5,000-digit decimal (assert the neighbour refuses OVERLAP at the
fail-closed point), each under `_no_exception_encode`. No source change.

### F-2 (LOW · design-gap · render surface) — operator echo preserves Unicode bidi/format controls

Ref: R-A2L-DEF.137 and R-A2L-DEF.151/7; impl at `a2l_definition.py:3241`
(`_operator_echo`) → `:294` (`_clean`).

`_clean` replaces only C0/C1 controls (U+0000–U+001F, U+007F, U+0080–U+009F),
exactly as R-A2L-DEF.137 defines "control character". Operator text that
reaches a rendered refusal/notice therefore still carries U+202A–U+202E,
U+2066–U+2069, U+200E/U+200F and zero-width characters (R-A2L-DEF.151/7 says
"all other Unicode characters are preserved"). A hostile operator text can
visually reorder or spoof the TUI's refusal message even though the cap and the
C0/C1 replacement are correct. This is *by design* per the frozen requirement —
not an implementation defect and not a blocker — but the Inc 8/9 renderer is
the right place to harden it.

Bounded correction: when Inc 8/9 renders an `Encoded`/`Refusal` produced here,
wrap echoed operator text in U+2068/U+2069 (FSI/PDI) or strip bidi controls
before display; do not change `_operator_echo` in this increment (R-A2L-DEF.151
is frozen). Log the note against Inc 8/9.

### F-3 (INFO · impl · clarity) — image-span check runs twice for masked writes

Ref: `a2l_definition.py:3743` (`_image_span_refusal`, step 6) and
`:3749` → `:3388` (`_merge_bit_mask`, which re-checks the same bytes at
`:3395–3404`). The second check is dead after the first passes; harmless and
order-preserving (`.57/3` pins bytes-before-mask), noted only for clarity. No
correction required.

## Summary

- **Blocking: none.** Every MAJOR/HIGH from the E3 security rounds (E3S-36 …
  E3S-44, F1 … F4) is closed by Inc 11 or the correction pass and holds against
  this tree.
- **Non-blocking:** F-1 (hostile BLOB/INSTANCE coverage, LOW), F-2 (bidi
  render-surface hardening for Inc 8/9, LOW), F-3 (redundant span check, INFO).
- All new message strings are capped and control-replaced; the persisted bytes
  are strictly printable-ASCII (text) or numeric (number/enum), so no control
  content reaches disk; the overlap guard's identity and cross-kind order are
  correct; duplicate-name and byte-order residuals behave as ruled.
