## Independent final security re-review — batch-103 Inc 11 (P18/P19)

**Verdict: PASS-WITH-NOTES** — no fail-open found in `s19_app/tui/a2l.py` on any of the seven axes; one low-severity oracle divergence (test support, product side is the conservative one).

### Security findings

**F1 — LOW / design-gap (test oracle, not product).** The reference oracle unquotes the tag's own `BYTE_ORDER` argument, so it would *accept* a quoted byte-order word, while the product reader and the direct test refuse it.
- `tests/support/b103_a2l_ref.py:1078` — `byte_order_arg = _unquote(args[0])` → `"MSB_FIRST"` normalizes to `big`, no address refusal.
- Product: `s19_app/tui/a2l.py:3681-3682` — `own_bo_order = _normalize_byte_order(own_bo_word)` with **no** unquote → quoted word → `None` → `address_invalid`.
- `tests/test_b103_a2l_reader_coverage.py:1159-1165` asserts `"MSB_FIRST"` is refused (`address is None`), per P6 "byte-order words keep their quoted status".
- Impact: product is fail-closed (correct); the oracle is fail-open on this one edge and is **not** covered by the 160-shape differential (no quoted `BYTE_ORDER` shape in `_corpus()`). Latent, no current false-green.

No other findings. The seven specified fail-open guards all hold.

### Guard-by-guard confirmation (static, product code)

1. **Quote-free fast paths don't bypass quoted/extended-kind handling** — PASS.
   - MEASUREMENT fast path `a2l.py:3510` requires `not any('"' in word for word in header)`; else falls to `parse_measurement_header` (quote-aware).
   - CHARACTERISTIC fast path `a2l.py:3524` requires quote-free **and** `header[0] in CHARACTERISTIC_KINDS`; else `_characteristic_from_tokens` (which anchors on kinds, then `_extended_kind_anchor` for CUBE_4/CUBE_5/vendor kinds). Header address is re-validated via `_number_word`/`_MAX_ADDRESS` regardless of path.
   - Lexer Tier-0/0a/1 fast paths (`a2l.py:700+`) gate on `'"' not in …`, `"\x00" not in …`, and drop to the NUL/slow path otherwise — NUL refusal (READ.55) and quote-span handling are never skipped.

2. **DATA_SIZE/LENGTH disagreement and no-number refusal** — PASS. `_tag_sizes` (`a2l.py:529`) sets `no_number=True` for any non-number arg (incl. surplus hex-like words, which arrive as `len(args)>1`), and the family branch compares byte sizes vs span. Gate `a2l.py:3771-3772` (`if no_number or not agree: refused_length_ids.add(...)`) refuses both.

3. **External spans resolved and agreeing** — PASS. Post-pass (`a2l.py:3855+`) skips `refused_length_ids`; only a fully-resolved `_axis_counts_resolving_external` + `_record_layout_full_span` assigns a span; standing-size tags re-run `_tag_sizes` against the resolved span and refuse on disagreement (`a2l.py:3923`).

4. **Final refusals stay final** — PASS. `a2l.py:3855` `continue`s refused ids; the inline-span pass is subordinate to the `no_number or not agree` gate (`a2l.py:3771`); `_bounded_length` is the final backstop (`a2l.py:3803`).

5. **TAB_VERB must not reopen** — PASS. `TAB_VERB` in `COMPU_CONVERSION_KEYWORDS` (`a2l.py:92`); `_apply_compu_method` (`a2l.py:2746`) does an exact-entry lookup with missing-table/missing-entry → `("error", …)` — never identity fallback for a defined TAB_VERB method.

6. **4096-entry cache bounded** — PASS. `@lru_cache(maxsize=4096)` on `_number_word` (`a2l.py:343`); number-word keys are ≤22 chars, non-number keys are references to already-live strings; bound is hard.

7. **Direct length shortcuts preserve unknown/invalid cases** — PASS. `_infer_length_measurement` (`a2l.py:1957`) / `_infer_length_characteristic` (`a2l.py:1994`) are only reached after the agreement/no-number gate; their `explicit` shortcut returns the DATA_SIZE/LENGTH value (P18 fix: no LENGTH-only helper), unknown datatype/`char_type` → `None` (honest grey), never an invented length. Family branch `a2l.py:3781-3783` takes resolved `span` first, else standing DATA_SIZE/LENGTH, else `None` (P16/P18 precedence).

### Non-security report (separate, per request)

- READ.52 memory arms: **green** — case_06 peak-minus-before 519.2 MB, software_a 37.2 MB, string 27.3 MB, words 73.1 MB; all under bound (45–48 % margin). 7 passed, 1 deselected (`coverage-perf-laptop-green.txt`).
- **case_06 timing margin is 0.2 %** (9.296 s / 9.313 s) — flagged LOW; software_a 10.3 %. This is a validation/perf note, not a security finding, and it is the one narrow remaining risk on the performance arm.

### Scope of this review

- **Static:** full read of `a2l.py`, `b103_a2l_ref.py`, both test modules, `E5-rulings.md`, `graph-inc11.md`, and the three evidence transcripts. No files edited, no tests run, no git/clipboard/corpus access.
- **Integration:** evidence transcripts only — `p18-red.txt` (1 RED `None == 4` on baseline, now fixed), `p18-e5-coverage-green-2.txt` (148 passed), `coverage-perf-laptop-green.txt` (7 passed / 1 deselected). Not independently re-run.
- **Mutants still pending:** M10 (CR/CRLF normalisation) is provisionally "not realisable" pending Linux confirmation; Unit A Windows arms must be re-run on Linux; Unit B platform compliance unverified. These are open process items, not product findings.
