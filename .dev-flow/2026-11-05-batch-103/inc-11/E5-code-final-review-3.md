## Verdict: PASS

**Verification of the committed tree**

- `tests/support/b103_a2l_ref.py:1076-1086` — the `BYTE_ORDER` branch assigns `byte_order_arg = args[0]` (line 1078) with **no** `_unquote`. `_normalize_byte_order` (lines 192-198) does `.strip().upper()` only and matches against the literal tokens `MSB_FIRST/BIG_ENDIAN/MSB_LAST/LITTLE_ENDIAN`. A quoted `"MSB_FIRST"` therefore normalizes to `'"MSB_FIRST"'` (quotes retained) → `None` → `byte_order_invalid = True` → error appended and `no_address = True` (line 1146). The quoted case is **refused**, exactly as `test_cov_read_68_byte_order_error_exact` asserts (`_tag(ref_data, "X")["address"] is None`).
- `tests/test_b103_a2l_reader_coverage.py:1157-1169` — the focused test loops over `("MSB_FRIST", "MSB_LAST_MSW_FIRST", '"MSB_FIRST"', "1")` and requires the reference reader to reject each with `address is None`. This matches the current committed REF behavior.

**Evidence**

- `ref-byte-order-green.txt` → `1 passed in 0.99s` (focused case green).
- `int-green12-a.txt` → `332 passed in 73.25s` (group A green).

**Cause of the prior FAIL**

The red transcript (`ref-byte-order-red.txt`) ran from `/tmp/b103-e5-11-int9-laptop/tree`, a **stale scratch copy** distinct from the committed tree. It failed with `assert 16 is None` — i.e., that scratch REF accepted the quoted `"MSB_FIRST"` (normalizing it to a valid byte order and yielding address 16 = `0x10`). The committed REF at `tests/support/b103_a2l_ref.py` does **not** do this; it preserves `args[0]` verbatim and refuses the quoted case.

**Conclusion:** The prior FAIL was caused by stale scratch state, not by the committed tree.
