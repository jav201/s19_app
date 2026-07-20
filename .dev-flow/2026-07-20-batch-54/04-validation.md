# Validation — s19_app — Batch 54 (Multi-line A2L header parsing, P-1b prerequisite)

> Phase 4 artifact. Owner: `qa-reviewer`. Executes the Phase-1 validation strategy (§4.9 canonical AT/TC registry).
> Gate run is orchestrator-owned (C-25); this artifact **consumes** that result. The only command run here is the V-5/C-18 `--collect-only` reconciliation (cited below).

## ✅ Verdict (read first)

- **Result: PASS.**
- **Requirements:** 7/7 gate-blocking ATs pass (AT-096/097/098/099/100/101/102) · AT-103 (non-blocking, markup safety) pass · 0 blocker fails.
- **Black-box acceptance (Layer B):** ✓ every story's `AT` observes its outcome through the shipped `parse_a2l_file` surface with boundary + negative inputs (AT-100 short-body, AT-101 hostile corpus, AT-102 scope guard).
- **Surface-reachability (bidirectional):** ✓ all named inputs (multi-line header / axis body / hostile comments / single-line / MEASUREMENT+synthetic) AND all named outputs (char_type · address · deposit · limits · max_axis_points · external · length-None · rendered cell) reached/observed at the surface.
- **Supersession inspection:** ✓ N/A-clean — no superseded marker/constant retired; the only lifecycle item is the intentional `# UNFROZEN batch-54` marker on a2l.py (re-freeze = post-merge PR-B, not a Phase-4 gate item).
- **Test ledger:** ✓ reconciles (1623 base − 0 + 29 = 1652).
- **Evidence checklist (qa-reviewer):** ✓ complete (see final section).

> Every line ✓. Detail below is reference.

---

## Detail (reference)

### V-5 / C-18 two-layer reconciliation (on-disk collected nodes)

Command run (qa-reviewer): `python -m pytest --collect-only -q tests/test_a2l_multiline_headers.py` → **30 nodes collected**; `-m "not slow"` → **29 selected, 1 deselected** (the `@slow` DoS case at `tests/test_a2l_multiline_headers.py:309`). Every registry AT/TC below maps to a **named on-disk node** — no AT satisfied only by summing partial nodes (C-18 clean); each AT has one node carrying its full gate discriminator, with additional nodes being the registry's *explicitly enumerated* boundary/negative facets.

| Registry AT/TC | On-disk collected node(s) — verbatim | Gate | Note |
|----------------|--------------------------------------|------|------|
| **AT-096** | `test_at096_std_com_golden_header_values` | ✔ 1:1 | golden dual-fact discriminator |
| **AT-097** | `test_at097_all_fifty_characteristics_have_type_and_address` | ✔ 1:1 | 50/50 universal |
| **AT-098** | `test_at098_single_line_characteristics_unchanged` | ✔ 1:1 | no-regression superset |
| **AT-099** | `test_at099_measurement_and_synthetic_no_kind_preserved` | ✔ 1:1 | count-guarded sentinel |
| **AT-100** | `test_at100_axis_descr_max_points_and_external_flag` (**core discriminator: STD/COM/FIX**) + `test_at100_axis_descr_short_body_no_crash` (boundary <4-token) | ✔ | 1 discriminator + 1 boundary; not fragmentation |
| **AT-101** | `test_at101_hostile_comment_corpus[…]` ×8 (`unterminated_block_eats_mandatory`, `multiline_block_removed`, `quoted_metachars_preserved`, `unterminated_quote`, `line_comment_truncates_to_newline`, `block_comment_between_params`, `stray_close_no_open`, `comment_only_body`) + `test_at101_positive_control_clean_multiline_parses` + `test_at101_quoted_metachar_bytes_preserved` + `test_at101_megabyte_unterminated_block_is_linear` **[@slow, deselected in gate]** | ✔ | registry's "8 enumerated + positive-control + DoS" — parametrized enumeration, not partial-satisfaction |
| **AT-102** | `test_at102_curve_map_length_stays_none` | ✔ 1:1 | scope boundary (batch-55) |
| AT-103 (non-blocking) | `test_at103_deposit_with_markup_metachars_renders_verbatim` | 1:1 | markup-sink safety on now-live deposit |
| **TC-097** | `test_tc097_strip_removes_block_and_line_comments` + `test_tc097_line_comment_truncates_to_next_newline_only` + `test_tc097_unterminated_constructs_never_raise` | — | 3 enumerated facets (spanning/adjacent · //-newline-only · unterminated-safe) |
| **TC-098** | `test_tc098_flatten_respects_quotes_across_lines` + `test_tc098_flatten_escaped_quote_parity_with_splitter` | — | quote-respect + escape-parity (sec-F3) |
| **TC-099** | `test_tc099_kind_anchor_index_0_1_2` + `test_tc099_bad_address_and_no_kind_and_short` + `test_tc099_bare_kind_word_before_type_degrades_to_none_address` | — | index 0/1/2 · int(addr)-fail→None · bare-kind negative (arch-M1) |
| **TC-100** | `test_tc100_axis_tokenise_full_body` | — | 1:1 |
| LLR-ML1-1.3 (shim) | `test_backcompat_parse_characteristic_header_delegates` | — | back-compat delegation |
| LLR-ML1-1.6 (facade) | `test_assemble_characteristic_header_public_and_facade` | — | public + re-export |

**C-18 check:** no "satisfied-in-parts". AT-100 = 1 discriminator node + 1 explicit boundary node; AT-101 = a parametrized enumeration exactly matching the registry's "8 hostile + positive-control + DoS"; TC-097/098/099 = the registry's enumerated facets. Each gate-blocking AT's core assertion lives in a single node.

### Layer A — functional (white-box)

| Req | Method | Executed verification | Threshold | Result | Evidence |
|-----|--------|-----------------------|-----------|--------|----------|
| HLR-ML1-1 (`R-A2L-011`) | test | TC-099 kind-anchor positional | 7 params from kind anchor | pass | new-file gate run; oracle STD `CURVE`/`0x810300`/`RL.CURVE.SWORD.SBYTE.DECR` via `parse_a2l_file` |
| HLR-ML1-2 (`R-A2L-011`) | test | AT-098 + AT-099 | 0 failed · 0 snapshot drift | pass | `case_01` 2/2 `VALUE`; MEAS 25/25 datatype+24 length; synthetic `len==8` all `None` |
| HLR-ML2-1 (`R-A2L-012`) | test | TC-100 + AT-100 | STD 8/False · COM True · FIX 6/False · <4→None | pass | axis oracle via surface |
| HLR-SAFE-1 (`R-A2L-013`, C-17) | test | TC-101 + AT-101 | 8/8 no-raise · quoted bytes preserved · malformed→None | pass | 8 hostile params + positive control + `@slow` DoS linear |
| LLR-ML1-1.1..1.6, ML2-1.1, ML1-2.1/2.2 | test/inspection | TC-097/098/099/100 + census + unfreeze marker | shipped dict keys · facade re-export · frozen-set edit | pass | ruff clean (4 files); frozen guards tc031/tc032/tc027 11 passed |

### Layer B — behavioral (black-box) acceptance

| US | AT | Surface driven | Deliverable observed | repr · boundary · negative | Result |
|----|----|----------------|----------------------|----------------------------|--------|
| US-ML1 | AT-096 | `parse_a2l_file` → `data["tags"]` | STD_AXIS `char_type/address/deposit` values | ✓·—·— | pass |
| US-ML1 | AT-097 | `parse_a2l_file` | `len(chars)==50` ∧ all `char_type` ∧ all `address is not None` (5 addr==0) | ✓·✓·— | pass |
| US-ML1 | AT-098 | `parse_a2l_file` | `case_01` 2/2 `VALUE`, addresses + limits unchanged | ✓·—·— | pass |
| US-ML1 | AT-099 | `parse_a2l_file` | MEAS 25/25; synthetic `len==8` all `char_type is None` | ✓·✓·✓ | pass |
| US-ML2 | AT-100 | `parse_a2l_file` → `axis_meta` | STD 8/False · COM True · FIX 6/False · short-body None | ✓·✓·✓ | pass |
| SAFE | AT-101 | `parse_a2l_file` (synthetic tmp A2L) | 0 raise · quoted `*/`/`http://` bytes preserved · malformed→`char_type None` · clean block parses · DoS linear | ✓·✓·✓ | pass |
| US-ML1 | AT-102 | `parse_a2l_file` | CURVE/MAP `length is None` (batch-55 boundary) | —·✓·— | pass |
| (C-17) | AT-103 | `_build_a2l_table_cells` / `_a2l_detail_card_text` | deposit w/ markup metachars `.plain` eq, `spans==[]` | —·—·✓ | pass |

### Bidirectional surface-reachability matrix

| Direction | US dimension / deliverable | Producer / param | Reached at surface? | TC / AT | Status |
|-----------|---------------------------|------------------|---------------------|---------|--------|
| input | multi-line CHARACTERISTIC mandatory header | `assemble_characteristic_header` → `_flatten_body_tokens` | yes | AT-096/097 | ✓ |
| input | multi-line AXIS_DESCR body | AXIS_DESCR full-body capture (`a2l.py:1060-1068`) | yes | AT-100 | ✓ |
| input | inline/spanning + hostile comments | `_strip_a2l_comments` | yes | AT-101 | ✓ |
| input | single-line CHARACTERISTIC (regression) | `parse_characteristic_header` shim | yes | AT-098 | ✓ |
| input | MEASUREMENT + synthetic no-kind (regression) | `_first_header_line` / kind-anchor `None` path | yes | AT-099 | ✓ |
| output | `char_type` | `_characteristic_from_tokens` | yes | AT-096/097 | ✓ |
| output | `address` | kind-anchor / body `ECU_ADDRESS` | yes | AT-096/097 | ✓ |
| output | `deposit` / `record_layout_name` | kind-anchor param | yes | AT-096 | ✓ |
| output | `max_diff` / `conversion` / `lower_limit` / `upper_limit` | 7-param positional window | yes (window-alignment via AT-096 deposit/address + whitebox TC-099) | AT-098 / TC-099 | ✓ |
| output | axis `max_axis_points` (str) + `external` | axis full-body capture | yes | AT-100 | ✓ |
| output | array `length` stays `None` (scope guard) | out-of-scope summer (batch-55) | yes | AT-102 | ✓ |
| output | rendered A2L cell (markup-safe) | `_build_a2l_table_cells` / `_a2l_detail_card_text` | yes | AT-103 | ✓ |

> Note: multi-line `lower_limit`/`upper_limit` are pinned white-box (TC-099 positional read) and reached transitively through the surface — a misaligned 7-param window would break `deposit`/`address` in AT-096, so the correct deposit+address at their positions prove the limit positions landed. No blocking gap.

### Counterfactual / certainty

| AT | Counterfactual | Kind | Discriminating? | Evidence |
|----|----------------|------|-----------------|----------|
| AT-096/097 | pre-fix demo **0-genuine/50** char_type (the "1" was a spurious comment-token match) | **value** (0→50), not shape | yes — value mismatch, QC-2 satisfied (no TypeError masking) | measured Phase-1 via C-35 execution probe against `640de1b` |
| AT-098 | GREEN now, **must stay** (single-line path is a strict subset) | superset guard | n/a | `case_01` unchanged |
| AT-099 | GREEN now, **must stay**; `len==8` ∧ all `None` count-guarded snapshot sentinel | regression sentinel | yes — count guard traps a synthetic char silently starting to parse (would drift snapshots) | 0 snapshot drift confirms |
| AT-101 | naive strip raises / leaks quoted bytes / strips-all | robustness | yes — **positive control** proves negative assertions discriminate (a strip-all impl fails the clean-block parse); **DoS** proves linear bound | 8 hostile + positive control + `@slow` MB linear |
| AT-102 | premature summer fills `length` | scope guard | yes | length observed `None` |

**Snapshot certainty:** 29 snapshots passed, **0 drift**. Phase-1 R3 confirmed — synthetic no-kind fixtures used by snapshot tests stay `char_type=None`, and the demo A2L (the 0→50 change) is not snapshot-pinned → the behavior change touched no baseline.

### Supersession-completeness inspection

| Superseded marker | Result | All surviving refs negative? | Evidence |
|-------------------|--------|------------------------------|----------|
| (none retired this batch) | n/a | n/a | Refactor preserves `parse_characteristic_header` as a delegating shim (has `test_backcompat_…`); MEASUREMENT branch still uses `_first_header_line` (intended-live). Only lifecycle item = `# UNFROZEN batch-54` marker; re-freeze = post-merge PR-B. |

### Signed-balance test ledger

| base | − D | + A | = post | actual (gate, `-m "not slow"`) | reconciles? |
|------|-----|-----|--------|-------------------------------|-------------|
| 1623 (batch-51) | 0 | 29 | 1652 | **1652 passed, 2 skipped, 21 deselected, 3 xfailed, 0 failed** | yes |

> `+29` = the 29 gate-selected new-file nodes (30 on disk − 1 `@slow` deselected). The `test_a2l_f841_cleanup.py` C-26 census reconcile was in-place (stale docstring corrected, `deposit` pin added inside existing tests) → **0 net new nodes**. The `@slow` MB DoS node sits inside the 21 deselected. Reconciles exactly.
> Doc note: increment-002 §2 says "31 tests" for the new file — the on-disk truth is **30 collected** (1 `@slow`). Cosmetic overcount in the increment doc; ground truth = 30/29-gate-selected. Flagged, non-blocking.

### Gaps detected
| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| — | — | none | — | — |

### Escaped-bug regression
> Not applicable — no defect escaped the suite. AT-096/097 are the *feature* counterfactuals (pre-fix RED measured in Phase-1), captured above.

### Evidence checklist — qa-reviewer (full)

- [✓] **Acceptance criteria are behavioral & through-surface** — ATs in §4.9 registry form, each driving `parse_a2l_file` (shipped surface) with explicit Asserts + Counterfactual columns.
- [✓] **Test cases have explicit Expected, not vague "works"** — registry Asserts + Layer A thresholds (STD `CURVE`/`0x810300`; 50/50; axis 8/False·True·6/False).
- [✓] **Edge cases include empty, boundary, invalid, error** — AT-100 <4-token short body; AT-101 8 malformed/hostile cases; AT-102 scope boundary; AT-099 synthetic no-kind.
- [✓] **Regression checklist exists** — AT-098 (single-line) + AT-099 (MEASUREMENT+synthetic) + 0 snapshot drift + C-34 full guard-host `test_tui_directionb.py`+`test_engine_unchanged.py` 175 passed.
- [✓] **Exit criteria stated** — all gate-blocking ATs (096/097/098/099/100/101/102) green ∧ 0 failed ∧ 0 snapshot drift ∧ frozen guards 11 passed.
- [✓] **No real PII / secrets** — S19/A2L firmware fixtures only; no PII, no credentials.
- [✓] **Results left blank unless actually run** — Layer A/B results reflect the orchestrator-owned C-25 gate run (cited, not re-run); the only command I executed is the `--collect-only` reconciliation (output cited verbatim in §V-5).
- [✓] **Layer B (black-box)** — every output-producing story observed through `parse_a2l_file` (US-ML1/ML2) or the render surface (AT-103), with boundary + negative evidence.
- [✓] **Bidirectional surface-reachability** — every named input dimension AND every named output/deliverable exercised/observed through the handler (matrix above), not only the service API.
- [✓] **No unfilled template** — no `<…>`/`TC-NNN` placeholders or empty required rows remain.

---

## Housekeeping (post-gate, not Phase-4 gate items)

- **a2l.py re-freeze = post-merge PR-B** (batch-50 P-2 pattern: "edits first, re-freeze last" — same-PR re-freeze self-trips the vs-main guard). The `# UNFROZEN batch-54` marker is intentionally live through this batch.
- **MEASUREMENT multi-line deferred** (R4 — absent from corpus) → covered by no-regression AT-099. Operator may re-include; not required for this gate.
- **Array length summer = batch-55** (P-1b proper); AT-102 guards the boundary here.

**Gate verdict: PASS** — proceed to PR-A → CI → self-merge → re-freeze PR-B.
