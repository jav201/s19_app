# 02 — Cross-agent review · batch-54 (Multi-line A2L header parsing)

**BLUF — PASS with folds, 0 blockers.** All three reviewers (architect + qa + security) independently cleared the design; the architect disproved both candidate-blockers by execution (no kind-anchor false-positive in the real corpus — anchor-index dist `{1:49, 2:1}`, all land on the true Type; no comment-bleed into other line-scans — 0 interspersed comments in the corpus), qa confirmed **every pinned oracle value is correct (zero typos)** and all counterfactuals genuine, security ruled the comment-stripper crash-free + **linear-time** with no new external surface / dormant markup sink. 6 MAJOR + 9 MINOR/LOW folds, all AT/LLR tightenings.

## Findings + folds (all applied to 01-requirements.md §4.9 / LLRs)

### MAJOR
- **[arch-M3] AT-097 truthiness trap (correctness):** 5/50 chars have `address==0` (falsy, e.g. VIRTUAL.ASCII @0x0). AT-097 MUST assert `address is not None`, never `all(t.get("address"))`. → **Fold:** AT-097 pinned to `is not None`; cite the 5 zero-address chars.
- **[qa-M1] AT-099 not gate-blocking but is the sole guard** for MEASUREMENT no-regression (25/25 datatype) AND the synthetic-`char_type=None` snapshot sentinel. → **Fold:** AT-099 → gate-blocking.
- **[qa-M2] AT-099 synthetic-None universal lacks a count guard (C-31 vacuity):** `all(char_type is None)` passes vacuously on an empty synthetic set. → **Fold:** pin exact synthetic count `len(synthetic_chars)==N ∧ all(None)`.
- **[qa-M3] AT-101 needs an in-test positive control:** a "strip-everything" impl satisfies "all malformed → None" trivially. → **Fold:** add a clean well-formed multi-line block to AT-101's corpus asserting a non-None char_type.
- **[arch-M1] anchor is unbounded (latent, spec-illegal → MAJOR not blocker):** a bare unquoted kind-word token before the real Type would mis-anchor (degrades to `address=None`, no crash; absent from corpus since LongId is always quoted / dotted). → **Fold:** AT pins the real index-2 `NUMBER_42` case; a negative TC asserts the bare-kind-word `address=None` degradation; LLR-ML1-1.3 documents bare-kind-word-name as a non-goal.
- **[arch-M2] `//` scope ambiguous (impl-correctness):** Phase-1 `probe.py`/`probe2.py` treat `//` as break over the WHOLE joined body (drops later mandatory params); only `probe3.py` (newline-sentinel, `//`→next `\n`) is correct and is what LLR-ML1-1.2 implies. → **Fold:** LLR-ML1-1.1 states `//` truncates to the next newline sentinel; TC-097 adds an early-line `//` case asserting all 7 params recovered.

### MINOR / LOW
- **[qa-m1] AT-097 `>=50` → `==50`** (exact; fixture has exactly 50 begins; matches `test_at094:98`).
- **[qa-m2]** enumerate all 8 AT-101 hostile cases with per-case expected (None vs parse).
- **[qa-m3] AT-102** name specific tags (`ASAM.C.CURVE.STD_AXIS`, `ASAM.C.MAP.STD_AXIS.STD_AXIS`); consider gate-blocking (batch-55 scope boundary).
- **[qa-m4 / sec]** clarify AT-101 = behavioral through `parse_a2l_file`; TC-101 = white-box on `_strip_a2l_comments`.
- **[sec-F1] DoS/perf case** in AT-101 corpus (MB-scale unterminated `/*` / quoted span; assert completes under a wall-clock bound — locks the O(n) contract for the gate-blocking SAFE req). May go under the `slow` marker.
- **[sec-F2] render-level C-17 assertion:** a CHARACTERISTIC whose now-live `deposit`/`record_layout_name` contains markup metacharacters renders verbatim (`.plain` eq, `spans==[]`) through `_build_a2l_table_cells` (`app.py:~9995`) + `_a2l_detail_card_text` (`~679`). (Path is safe by construction — literal `Text(...)` sinks, no `from_markup` — but closes the traceability nit on the newly-live field.)
- **[sec-F3] quote-convention parity:** the stripper's escape rule must match `_split_line_respecting_quotes` (`a2l.py:256`); TC-098 adds an escaped-quote-in-string case.
- **[arch-m1] C-26 census under-named:** add `test_tui_snapshot.py` (synthetic no-kind → 0 drift) + `test_examples_pilot_gifs.py` (`@slow`, frame-count only, no A2L text) with why-immune; positively spot-check `test_a2l_enriched.py`.
- **[arch-m2] line-scan comment fragility (OUT OF SCOPE):** the raw-`split()` scan (`a2l.py:994-1047`) isn't comment-stripped but is safe for the corpus (0 interspersed `KEYWORD /* c */ value`; all inline comments trailing → `parts[2:]`). Note as a known limitation; do NOT fix this batch.
- **[arch-m3] dict-shape:** implementer returns the SHIPPED keys (`address_inline`/`lower_limit`/`upper_limit`/`datatype`), not the probe keys (`address`/`lower`/`upper`) — call-site `a2l.py:989` reads `header_char.get("address_inline")`.

## Scope confirmations (all 3 reviewers)
- **MEASUREMENT multi-line deferral is SOUND** (not a gap) — shipped code already parses 25/25 datatype + 24 length single-line; no demo MEASUREMENT is mis-parsed. AT-099 is an adequate regression sentinel. → autonomous adoption CONFIRMED, no operator escalation.
- **HEADER-only / length stays None (batch-55)** — AT-102 guards the boundary.
- **a2l.py re-freeze = post-merge follow-up PR** (batch-50 P-2 pattern).

## Gate verdict
0 blockers on all three axes. Unmet-axis check: none — Coverage (chains complete), Certainty (counterfactuals execution-verified, folds harden the C-31 universals + no-regression + hostile-comment), Evidence (every oracle value + edge case verified against disk/execution). → **APPROVE** after folds applied. C-36 applied (oracle values folded against on-disk vocabulary — all confirmed).
