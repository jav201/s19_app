## Verdict: PASS

Static review of P18 and its guards. All four behavioral checks hold, and the test names/evidence agree with the ruling. Two non-blocking notes at the end.

### 1. Standing DATA_SIZE and LENGTH — consistent acceptance and precedence

- Impl `_infer_length_characteristic` accepts both keywords: `if parts[0] in ("DATA_SIZE", "LENGTH") and len(parts) == 2:` — `s19_app/tui/a2l.py:1991`. `_infer_length_measurement` mirrors it at the same condition (a2l.py ~1946).
- The family fallback is keyed off `has_standing_size`, which is set for both `DATA_SIZE` and `LENGTH` — `a2l.py:3567-3568` (`if kw in ("DATA_SIZE", "LENGTH"): has_standing_size = True`), and routes through `_infer_length_characteristic` at `a2l.py:3740-3742`.
- REF side matches: `_infer_characteristic_length` returns `length_word if length_word is not None else data_size` — `tests/support/b103_a2l_ref.py:891`; family fallback `_standing_length` accepts both — `b103_a2l_ref.py:1253-1260`.

### 2. External full spans assigned only when resolved and agreeing

- Resolution is fail-closed: `counts` (a2l.py:3814), `layout` (3816), and `span` (3820) each `continue` on `None`.
- Standing-size tags re-run the agreement gate against the resolved span and refuse on disagreement — `a2l.py:3826-3837`.
- The `tag.get("length") is None` direct assignment (`a2l.py:3824-3825`) is only reachable for family tags with no standing size (a standing-size tag always has a non-None length from `a2l.py:3740-3742`), so there is nothing to disagree against. Vacuously correct.

### 3. Final length refusals remain final

- `refused_length_ids` is populated on disagreement/no-number (`a2l.py:3732`), out-of-bounds (`a2l.py:3757`), and post-pass disagreement (`a2l.py:3835`).
- The post-pass skips every refused id up front — `a2l.py:3809-3810` (`if tid in refused_length_ids: continue`). No refused length can be re-derived.

### 4. P16 / P17 not reopened

- P16 (full-span precedence): `if span is not None: tag["length"] = span` precedes the standing-size fallback — `a2l.py:3738-3739`; the family branch never falls back to scalar inference (`else: tag["length"] = None`, `a2l.py:3745-3746`). Test `test_e5_p16_curve_declared_uword_two_axis_points_full_span` still asserts `== 4`.
- P17 (TAB_VERB): `TAB_VERB` remains in `COMPU_CONVERSION_KEYWORDS` — `a2l.py:91` — and the decode route handles it at `a2l.py:2729-2732`; coverage test `tests/test_b103_a2l_reader_coverage.py:1965-1978` asserts `conversion_type == "TAB_VERB"`.

### 5. Test names and evidence agree

- Both P18 nodes exist in `tests/test_b103_a2l_reader_e5.py` under the exact current names: `test_e5_p18_data_size_only_unresolved_span_uses_standing_size` and `test_e5_p18_external_full_span_agrees_with_standing_data_size`; both assert `length == 4`.
- `p18-red.txt` shows `assert None == 4` on the unresolved test only, "1 failed, 1 passed" — matching "external case passed pre-fix". `p18-green.txt` = 2 passed; `p18-e5-coverage-green-2.txt` = 148 passed.

### Notes (non-blocking)

- **INFO (impl asymmetry, no behavior gap):** impl inference helpers are last-wins (`a2l.py:1989-1994`) while REF `_infer_characteristic_length`/`_infer_measurement_length` prefer LENGTH (`b103_a2l_ref.py:891`). This is unreachable: any disagreeing DATA_SIZE/LENGTH pair is refused by `_tag_sizes` first (`a2l.py:3725-3732`; ref `719-786`), and an agreeing pair yields the same value under either ordering.
- **INFO (rename history):** the "renamed without changing fixture or assertion" claim cannot be independently verified without git (permitted tools exclude it); the current name and the RED transcript are fully consistent with the ruling.

**Out of scope (pending, not part of this static verdict):** integration run, the READ.52 protocol, and the two mutant-unit gates — none are adjudicated here.
