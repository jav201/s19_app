# Increment 001 — E4 word codec (LLR-E4.1/E4.2/E4.3)

**Gate: APPROVED (self, autonomous)** · code-reviewer: APPROVE (0 HIGH/MED, 1 LOW non-blocking) · 2026-07-21

## 1. What changed
Added the big-endian / wider-field word codec to non-frozen `s19_app/tui/operations/crc.py`:
- `encode_word(value, *, store_width, endianness="little")` — strict: `big`=MSB-first, `little`=byte-identical to old `encode_le`, wider `store_width` zero-extends at the high end; rejects overflow/negative/unknown-endianness (`ValueError`).
- `decode_word(data, *, endianness="little")` — inverse.
- `encode_le`/`decode_le` reworked into thin wrappers. **Conflict resolved (not averaged):** `encode_le` must keep its documented lenient truncation (`test_crc_engine.py:306` pins `encode_le(…,2)==b"\x01\x02"`), while `encode_word` must reject overflow → `encode_le` masks-then-delegates, so both LLR-E4.1 (reject) and LLR-E4.3 (byte-identical) hold.

## 2. Files modified (frozen census: 0 frozen diffs)
- `s19_app/tui/operations/crc.py` (encode_word/decode_word added ~:480; wrappers `encode_le` :566 / `decode_le` :601)
- `tests/test_crc_word_codec.py` — NEW (6 funcs / 13 cases)
- `git diff --name-only 1e3125b` (source) = `crc.py` only. New test untracked. 2 files ≤ 5.

## 3. How to test
```
python -m pytest -q tests/test_crc_word_codec.py
python -m pytest -q tests/test_crc_engine.py tests/test_crc_operation.py tests/test_crc_designer_model.py tests/test_crc_kernel.py
python -m ruff check s19_app/tui/operations/crc.py tests/test_crc_word_codec.py
```

## 4. Test results
- RED (C-20): `ImportError: cannot import name 'decode_word'` → whole file RED before impl.
- GREEN: `test_crc_word_codec.py 13 passed` (exit 0).
- Byte-identity regression: `108 passed` (engine+operation+designer_model+kernel+word_codec).
- Ruff: All checks passed.
- **code-reviewer independent verify:** byte-identity confirmed vs HEAD stdlib expressions across values×widths; RED genuine + discriminating (opposite-endianness bytes, end-placement, exact overflow); frozen-set clean; boundary/negative covered.

## 5. Risks
Low. Negative `store_width` naturally raises (unreachable via bounded callers); one extra call-hop on the inject path (negligible, output byte-identical per regression).

## 6. Pending
None. `store_width >= ceil(width/8)` enforcement + too-small warning are caller-layer (US-V5 view), correctly out of scope.

## 7. Suggested next
Inc-2 — E5 template-loader facade `crc_template.py` (LLR-E5.1/.2; AT-CRC-DSN-015).

## code-reviewer LOW finding (carry, non-blocking)
- F1: RED is import-level (collapses file), not per-assertion; assertions are individually discriminating so intent is encoded — noted, no action.
