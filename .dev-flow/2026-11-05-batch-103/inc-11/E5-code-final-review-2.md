## Verdict: FAIL

One HIGH-severity test-oracle gap contradicts an accepted ruling and leaves a coverage test RED; everything else on the checklist is implemented as ruled.

---

### HIGH — F1 oracle correction not present (test RED)

**Finding:** `E5-rulings.md` (LOW F1) states the REF was corrected to *preserve the quoted token for normalization and diagnostics* so quoted `BYTE_ORDER "MSB_FIRST"` is refused (the RED was `16 is not None`). The committed oracle does not carry that fix.

- `tests/support/b103_a2l_ref.py:1078` — `byte_order_arg = _unquote(args[0])` still strips quotes; `_normalize_byte_order("MSB_FIRST")` → `"big"`, so `byte_order_invalid` stays `False` and `address` stays `0x10` (line ~1130–1131, ~1190).
- `tests/test_b103_a2l_reader_coverage.py:1157-1167` — `test_cov_read_68_byte_order_error_exact` iterates `("MSB_FRIST", "MSB_LAST_MSW_FIRST", '"MSB_FIRST"', "1")` and asserts `_tag(ref_data, "X")["address"] is None`; for `"MSB_FIRST"` the REF returns `16`, so the assertion fails (`16 is not None`).

**Classification:** impl gap (test oracle), not a product defect — `s19_app/tui/a2l.py` correctly refuses the quoted token (`_tag_keyword_lines` keeps quotes → `_normalize_byte_order('"MSB_FIRST"')` → `None` → `address_invalid`, with the `BYTE_ORDER "MSB_FIRST" is not a byte order` diagnostic). The fix is to pass `args[0]` (raw) to normalization/diagnostics in `_read_tag`.

---

### Checked and correct (PASS items)

- **Quote-free direct headers** — `a2l.py:~3520-3560`: MEASUREMENT and CHARACTERISTIC build header dicts directly when `'"' not in word`, avoiding `parse_measurement_header`/`_characteristic_from_tokens` re-parses; short-header semantics preserved.
- **Deferred keyword_texts** — `a2l.py:~3780-3805`: `[text for ... in keyword_lines]` is materialized only inside the branches that call `_infer_length_measurement/_characteristic`, not eagerly.
- **Alias-free keyword handling** — `_tag_sizes` (`a2l.py:529-575`) early-continues on non-size keywords before building `args`; consumers re-derive fresh `args` lists; `_tag_keyword_lines` returns fresh `item_words` per keyword.
- **Childless LINK_MAP skip** — `a2l.py:~3753`: `collect_link_maps(section) if section.get("children") else []`.
- **tag_template.copy + fresh axis_meta** — `a2l.py:3508-3512`: `tag = tag_template.copy()`; template holds only immutables; `tag["axis_meta"] = []` is assigned fresh (no shared list).
- **Bounded caches** — `_number_word` `@lru_cache(maxsize=4096)` (`a2l.py:343`); `_record_layout_decode_metadata` `@lru_cache(maxsize=256)` (`a2l.py:2057`, hashable tuple key, read-only dict consumers).
- **Element-size reuse** — `a2l.py:~3763-3766`: `element_size` resolved once and passed to both `_tag_sizes` and `_infer_length_characteristic` (`el = element_size` with fallback at `a2l.py:2025-2028`).
- **P16** — `_CURVE_MAP_FAMILY` uses resolved `span` first; on unresolved span accepts only standing DATA_SIZE/LENGTH (via `explicit`), never scalar inference (`a2l.py:~3774-3785`).
- **P17** — `TAB_VERB` in `COMPU_CONVERSION_KEYWORDS` (`a2l.py:92`); `_apply_compu_method` TAB_VERB branch with missing-table / missing-entry refusals (`a2l.py:2754-2761`); table `kind` set from first line (`a2l.py:~1770-1780`).
- **P18 / final refusals** — `refused_length_ids` gates the external-axis post-pass; standing-size re-check re-runs `_tag_sizes(..., span)` and refuses on disagreement (`a2l.py:3880-3910`).
- **Near-TAB_VERB negative test** — `test_cov_read_54_tab_verb_near_keyword_is_not_enum` (`coverage.py:1990-2013`) asserts `TAB_VERB_RANGE` → `conversion_type None` then `unknown_method`.
- **RTX margin** — `coverage-perf-rtx-final.txt`: case_06 `8.411 / 8.843 s = 4.9 %` (software_a `11.6 %`), `7 passed, 1 deselected`; `int-green12-a.txt`: `332 passed`.

Net: the product-side READ.52/P16/P17/P18 work is sound; the gate fails only on the un-landed F1 REF correction.
