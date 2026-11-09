## Verdict: PASS-WITH-NOTES

P18 and P19 are correctly implemented; the product code is sound and the provided evidence (148 passed; READ.52 7/1 green) is consistent with the rulings. All findings below are latent reference-oracle sync gaps or risk notes — none fail the current gate.

## P18/P19 correction — verified correct (static)

- **Full-span/refusal precedence** — `extract_a2l_tags` family branch `if span is not None: span; elif has_standing_size: infer; else None` (a2l.py:3779‑3789); refusals recorded at a2l.py:3765‑3768 and honored by `if tid in refused_length_ids: continue` (a2l.py:3855). P15/P16 precedence preserved.
- **P18 DATA_SIZE/LENGTH consistency** — `_infer_length_characteristic` reads `parts[0] in ("DATA_SIZE", "LENGTH")` (a2l.py:1994+), matching REF `_infer_characteristic_length` (b103_a2l_ref.py:850). External post-pass re-runs `_tag_sizes` with the resolved span and assigns only an agreeing span (a2l.py:3849‑3880). Matches `test_e5_p18_*`.
- **P19 optimizations** — quote-free direct header paths (a2l.py:3510‑3536) are exactly equivalent to their `parse_measurement_header`/`_characteristic_from_tokens` fallbacks (round-trip through the already-tokenized `header` list; fallback still reachable for quoted/extended-kind headers, incl. `_extended_kind_anchor` B6). `@lru_cache(maxsize=4096)` on `_number_word` (a2l.py:343‑344). Element size computed once (a2l.py:3746‑3751) and reused in both `_tag_sizes` and `_infer_length_characteristic`. Direct no-dimensional-keyword length paths (a2l.py:3774‑3776, 3790‑3796) are value-equivalent to `_infer_length_*`. `_tag_sizes` early `if kw not in (...) continue` (a2l.py:543‑544).
- **P16/P17 non-regression** — full-span 4 (not scalar 2) for the two-axis-point CURVE; `TAB_VERB` present in `COMPU_CONVERSION_KEYWORDS` and handled in `_apply_compu_method` (a2l.py:2777+).

## Findings

1. **[NOTE / design-gap]** Reference `_characteristic_element_size` (b103_a2l_ref.py:913‑929) resolves `_deposit_size` before the layout's `decode_type`; product resolves layout-first per P12 (a2l.py:597‑609). A deposit name carrying a contradicting size marker (e.g. `__UBYTE_Z` → FNC_VALUES ULONG) would give length 1 in REF vs 4 in the product. Latent — no such shape in the 35 tracked files or 160-shape corpus, so the differential stays green.

2. **[NOTE / design-gap]** `_tag_sizes` count units diverge. Product converts counts to bytes whenever `element_size` is known (a2l.py:578‑579); REF compares counts raw and only converts for the byte-size cross-pair, and only when `byte_sizes` is non-empty (b103_a2l_ref.py:771‑776). VAL_BLK + declared layout + `MATRIX_DIM 4` + `NUMBER 5` → product "declares the sizes 8 and 10" (matches `test_cov_read_59_all_five_size_shapes`), REF would emit "4 and 5". Both refuse `length`, but the `.59` public error text (I-11.6) diverges. Latent — shape not in the differential corpus.

3. **[NOTE / design-gap]** REF `_axis_counts` is inline-only and returns `None` on `AXIS_PTS_REF` (b103_a2l_ref.py:1381‑1400); it has no external-axis post-pass. Product resolves external axes (`_axis_counts_resolving_external`, a2l.py:2163; post-pass a2l.py:3849‑3880). A resolvable external-axis CURVE/MAP with no standing DATA_SIZE/LENGTH would yield a span in the product but `None` in REF. Latent — no external-axis shape in the corpus.

4. **[NOTE / risk]** READ.52 case_06 time margin is 0.2% (9.296 s vs 9.313 s, ≈17 ms headroom) per `coverage-perf-laptop-green.txt`. Per the ruling this is a declared note, not a threshold change; it remains a CI-flakiness risk on any slower host/lane.

## Pending (not verifiable statically)

Per `E5-rulings.md` corrective order: integration re-run, code/security/coverage re-reviews, and both mutant units on Linux are still outstanding; Unit A's Windows transcripts are non-canonical and must be re-run on Linux; M10 needs Linux confirmation of "not realisable". These are execution items, not defects found in this static review.
