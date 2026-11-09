## Verdict: PASS-WITH-NOTES

No HIGH or MEDIUM findings. All fail-closed behaviors the review targeted are implemented correctly and the READ.52 correction holds within its bounds (case_06 **8.411/8.843 s, 4.9% margin**; software_a 11.6%; all memory arms green — `coverage-perf-rtx-final.txt`).

### Checklist (all PASS)

| Item | Result | Evidence |
|---|---|---|
| Quoted/extended headers fail-closed (P1) | PASS | `_number_word` regex `_NUMBER_WORD_RE` (a2l.py:268) rejects any quoted word; `_tag_header` (a2l.py:423) and the CHARACTERISTIC header branch (a2l.py:3530-3547) route quoted headers to `_characteristic_from_tokens`, which leaves `address=None`. |
| Numeric/size refusals | PASS | `_bounded_length` (a2l.py:329), `_tag_sizes` disagreement → `no_number`/refusal (a2l.py:530-598), surplus hex-like words → `address_invalid`/`no_number` (a2l.py:350, 563-567). |
| External spans fail-closed | PASS | `_axis_counts_resolving_external` degrades to `None` on any dangling/non-numeric ref (a2l.py:2172-2260); `_record_layout_full_span`/`_walk_record_layout_components` return `None` on unclassifiable component, unknown datatype, non-positive alignment, or >1 MiB total (a2l.py:2456-2517). |
| DATA_SIZE/LENGTH precedence | PASS | `_infer_length_measurement`/`_infer_length_characteristic` return the explicit standing word first (a2l.py:2357, 2382). |
| P16/P18 (span beats scalar; DATA_SIZE survives) | PASS | Family branch assigns `span` first, else standing size only, else `None` (a2l.py:3786-3796); external post-pass skips `refused_length_ids` and only replaces a standing provisional with a resolved, agreeing span (a2l.py:3865-3897). |
| Unknown methods / near-TAB_VERB (P17) | PASS | `COMPU_CONVERSION_KEYWORDS` set membership is exact; `_apply_compu_method` TAB_VERB returns error on missing table / unmatched raw (a2l.py:2815-2824), `unknown_method` otherwise. `TAB_VERB_RANGE` → `conversion_type=None` → `unknown_method` (test `test_cov_read_54_tab_verb_near_keyword_is_not_enum`). |
| Fresh axis_meta per tag | PASS | `tag = tag_template.copy()` then `tag["axis_meta"] = []` (a2l.py:3510-3512); per-tag list, no shared mutable state. |
| Shared cached layout metadata read-only | PASS | `_record_layout_decode_metadata` (a2l.py:2057) returns a dict; all consumers (`_resolve_record_layout`, enrich, encode) only `.get()` it — no writes anywhere. |
| Bounded caches | PASS | `@lru_cache(maxsize=4096)` on `_number_word` (a2l.py:325), `@lru_cache(maxsize=256)` on `_record_layout_decode_metadata` (a2l.py:2055); `_CappedErrors` caps at 100+1; `_echo_word` 256-char cap; `MAX_A2L_DECODE_BYTES`=1 MiB caps `_extract_raw_bytes` and span walks; `_MAX_NESTING`=32. |

### Findings

- **LOW — impl leniency (not fail-open)** · a2l.py:1352, 3518-3521. A quoted positional MEASUREMENT header datatype (`"UWORD"`) is silently unquoted by `parse_measurement_header` and accepted, yielding `length=2`; the oracle (`tests/support/b103_a2l_ref.py`) keeps the quote and yields `None`. P1 only covers quoted *numeric* words, and the inferred length is still bounded by `DATATYPE_SIZES`, so there is no memory-safety impact — but the product is one notch more permissive than the oracle on this shape. Consider aligning the MEASUREMENT header path with the CHARACTERISTIC path's `any('"' in word)` rejection.

- **INFO — dead constant** · a2l.py:290. `_WORD_JOIN_BLOCK = 4096` is defined but never referenced (the lexer joins per canonical line, not in blocks). Harmless.

- **INFO — oracle-only divergence, not a product defect** · a2l.py:241. Product `_HEADER_WORDS` omits `TYPEDEF_AXIS` (the REF has it `=6`). `TYPEDEF_AXIS` is never consumed for span sizing in either reader and is absent from the hostile corpus; `_HEADER_WORDS.get(..., 0)` prevents any KeyError. No action required unless TYPEDEF_AXIS sizing is ever added.

No product edits, test runs, git, or clipboard access were performed.
