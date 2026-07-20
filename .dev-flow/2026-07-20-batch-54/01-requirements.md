# 01 — Requirements · batch-54 (Multi-line A2L header parsing — P-1b prerequisite)

**BLUF:** Make the A2L parser assemble CHARACTERISTIC mandatory headers + AXIS_DESCR bodies that span multiple lines (the real ASAM convention), so `char_type`/`address`/`deposit`/limits and axis `MaxAxisPoints`+external-flag populate instead of `None`. Execution-verified design (C-35, against `640de1b`): a quote-aware comment-stripper + body-flatten + CHARACTERISTIC_KIND anchor reaches **50/50** demo CHARACTERISTICs (from a genuine 0, the current "1" being a spurious comment-token match), with the single-line path a strict subset (no regression) and 8/8 hostile-comment cases safe. **HEADER fields only — array length stays `None` (batch-55).** a2l.py UNFROZEN this batch (operator-approved); re-freeze at close. New req ids `R-A2L-011/012/013`.

Assembled + reconciled by the orchestrator from parallel Phase-1 architect (HLR/LLR) + qa-reviewer (validation/AT) outputs into one canonical AT/TC registry.

## 1. Scope
- **In:** `s19_app/tui/a2l.py` header/axis assembly (+ new helpers), its facade `a2l_parse.py`, the C-26 census test + a NEW test file. a2l.py source unfrozen (sanctioned).
- **Out:** the inline-axis length summer (batch-55, P-1b proper); multi-line-mandatory MEASUREMENT (absent from corpus — deferred, covered by a no-regression AT; operator may re-include at Phase-2); the a2l.py re-freeze (post-merge follow-up PR).
- **Normative keyword:** `shall` in HLR/LLR only.

---
## 2.6 Source user stories — Definition of Ready  *(Phase-0 gate APPROVED)*

| ID | User story | Class |
|----|-----------|-------|
| US-ML1 | As a firmware engineer loading a real-world A2L, I want multi-line CHARACTERISTIC headers parsed so char_type/deposit/address/limits populate — demo 1→50/50 chars, no single-line regression. | READY |
| US-ML2 | As the same engineer, I want multi-line comment-stripped AXIS_DESCR bodies parsed → MaxAxisPoints + external-axis flag in axis_meta (the batch-55 inputs). | READY |

---
## 3. High-level requirements

### HLR-ML1-1 — CHARACTERISTIC multi-line mandatory-header assembly (`R-A2L-011`)
- **Trace:** US-ML1
- **Statement:** When a CHARACTERISTIC block's mandatory header params (`<Type> <Address> <Deposit> <MaxDiff> <Conversion> <LowerLimit> <UpperLimit>`) span multiple body lines, the parser **shall** assemble them into the tag's `char_type`, `address`, `deposit`/`record_layout_name`, `max_diff`, `conversion`, `lower_limit`, `upper_limit`.
- **Validation:** test · **Priority:** high
- **Threshold:** demo CHARACTERISTICs with `char_type` == 50/50 (from ~0 genuine); with `address` == 50/50; STD_AXIS oracle `char_type="CURVE"`/`address==0x810300`/`deposit=="RL.CURVE.SWORD.SBYTE.DECR"`.
- **Acceptance:** surface `parse_a2l_file` (`a2l.py:1093`) → `data["tags"]`; ATs **AT-096** (golden dual-fact), **AT-097** (50/50 derived universal).

### HLR-ML1-2 — No regression: single-line CHARACTERISTIC, MEASUREMENT, non-kind synthetic blocks (`R-A2L-011`)
- **Trace:** US-ML1
- **Statement:** The parser **shall** parse single-line CHARACTERISTIC headers, MEASUREMENT headers, and CHARACTERISTIC blocks with no mandatory-kind token identically before/after this batch.
- **Validation:** test · **Priority:** high
- **Threshold:** `case_01` 2/2 `char_type="VALUE"` + addresses unchanged; demo MEASUREMENTs 25/25 datatype + 24 length; synthetic `_a2l_characteristic_block` stays `char_type=None`; full suite 0 failed; **0 snapshot drift**.
- **Acceptance:** ATs **AT-098** (single-line), **AT-099** (MEASUREMENT + synthetic).

### HLR-ML2-1 — AXIS_DESCR multi-line → MaxAxisPoints + external flag (`R-A2L-012`)
- **Trace:** US-ML2
- **Statement:** When an AXIS_DESCR body spans multiple lines, the parser **shall** capture `MaxAxisPoints` (4th positional token) and an external-axis flag (true iff `AXIS_PTS_REF` present) into the parent tag's `axis_meta` entry (additive to existing `name`/`header_tokens`).
- **Validation:** test · **Priority:** high
- **Threshold:** STD_AXIS → `max_axis_points=="8"`, `external is False`; COM_AXIS (`AXIS_PTS_REF` @3354) → `external is True`; FIX_AXIS (@3380) → `max_axis_points=="6"`, `external is False`; body <4 tokens → `max_axis_points is None`, no crash.
- **Acceptance:** AT **AT-100**.

### HLR-SAFE-1 — Comment-stripping over untrusted A2L is crash-free + content-preserving (`R-A2L-013`, C-17)
- **Trace:** US-ML1 (introduces the stripper; guards US-ML2 too)
- **Statement:** Given malformed/hostile comment syntax (unterminated `/*`; `*/`//`//`/`/*` inside a quoted span; unterminated `"`), the comment-strip step **shall** neither raise nor alter any quoted-string token's bytes, and **shall** degrade to a `None` header rather than a corrupted one.
- **Validation:** test · **Priority:** high
- **Threshold:** 8/8 hostile → no exception; quoted `*/`/`http://` byte-preserved; malformed-mandatory → header `None`.
- **Acceptance:** AT **AT-101**.

---
## 4. Low-level requirements

- **LLR-ML1-1.1 — `_strip_a2l_comments(text)->str` (NEW).** Remove `/* … */` (incl. spanning the joined body) + `//` comments; treat `/`,`*` inside `"…"` as literal; unterminated `/*`/`"` consume-to-end, never raise. Near `_split_line_respecting_quotes` (`a2l.py:256`). Trace HLR-ML1-1/SAFE-1 · TC-097/TC-101.
- **LLR-ML1-1.2 — `_flatten_body_tokens(lines)->list[str]` (NEW).** Join body lines w/ newline sentinel → `_strip_a2l_comments` → `_split_line_respecting_quotes`. Trace HLR-ML1-1 · TC-098.
- **LLR-ML1-1.3 — kind-anchored `_characteristic_from_tokens(tokens)` (NEW) + refactor `parse_characteristic_header` (`a2l.py:324-345`).** Find first token ∈ `CHARACTERISTIC_KINDS` (`a2l.py:59-69`); read 7 mandatory params from there; `None` if no kind or <7 follow. `parse_characteristic_header(line)` keeps signature, delegates `_characteristic_from_tokens(_split_line_respecting_quotes(line))` (single-line back-compat). Dict shape byte-identical (`a2l.py:336-345`); call-site `a2l.py:980-991` unchanged. Trace HLR-ML1-1 · TC-099.
- **LLR-ML1-1.4 — `assemble_characteristic_header(lines)` (NEW) wired at extract call-site.** For CHARACTERISTIC branch, header = `_characteristic_from_tokens(_flatten_body_tokens(lines))`, replacing `_first_header_line`+`parse_characteristic_header` at `a2l.py:935,939-941` (CHARACTERISTIC only; MEASUREMENT branch `:936-938` retains `_first_header_line`). Trace HLR-ML1-1 · TC-099.
- **LLR-ML2-1.1 — AXIS_DESCR full-body capture (refactor `a2l.py:1060-1068`).** Replace `_find_first_non_empty_line(child.lines)` with `_flatten_body_tokens(child["lines"])`; add `max_axis_points = tokens[3] if len(tokens)>3 else None`, `external = "AXIS_PTS_REF" in tokens`; keep `name`/`header_tokens` (additive). Trace HLR-ML2-1 · TC-100.
- **LLR-ML1-2.1 — MEASUREMENT + single-line + non-kind preserved.** MEASUREMENT keeps `_first_header_line`+`parse_measurement_header` (`a2l.py:306-321,936-938`); no-kind CHARACTERISTIC → `char_type=None` (address still from body `ECU_ADDRESS`, `:997-1001`). Trace HLR-ML1-2 · TC (AT-099).
- **LLR-SAFE-1.1 — malformed-comment corpus through the surface.** NEW test drives the 8-case corpus via `_strip_a2l_comments`/`assemble_characteristic_header`: no raise + quoted byte-preserve + `None`-on-malformed; positive control in-module. Trace HLR-SAFE-1 · TC-101.
- **LLR-ML1-1.5 — C-26 reverse-census + reconcile `test_at094`.** `tests/test_a2l_f841_cleanup.py::test_at094_*` (`:74-109`): its docstring "demo parses only one CHARACTERISTIC" (`:85-87`) is now FALSE → correct it; `len==50` (`:98`) survives; `ASAM.C.VIRTUAL.ASCII`→ASCII/100 (`:107-109`) survives but is now a real parse (was a comment artifact). The 1→50 assertion lives in the NEW module. Confirm `test_a2l_record_layout_length.py`/`test_a2l_enriched.py`/`test_tui_directionb.py:863-892` (path-string only) unaffected. Trace HLR-ML1-1/2.
- **LLR-ML1-1.6 — facade re-export.** New public `assemble_characteristic_header` in `a2l.py` + re-export from `a2l_parse.py`; helpers stay private (`_`). Trace HLR-ML1-1.
- **LLR-ML1-2.2 — C-27 unfreeze this batch (enabling guard).** Remove `s19_app/tui/a2l.py` from the frozen set (`test_engine_unchanged.py:129` + `test_tui_directionb.py` tc031) with an `# UNFROZEN batch-54` marker; re-freeze = post-merge follow-up PR. Other frozen paths unchanged. Trace HLR-ML1-1/2 · inspection.

---
## 4.9 Canonical AT/TC registry (PINNED — C-21; reconciles qa AT-096.. + architect AT-ML*)

| AT | Story | Asserts (through `parse_a2l_file`) | Counterfactual (RED) | Gate |
|----|-------|-----------------------------------|----------------------|------|
| AT-096 | ML1 | STD_AXIS: `char_type=="CURVE"` ∧ `address==0x810300` ∧ `deposit=="RL.CURVE.SWORD.SBYTE.DECR"` (+ index-2 `ASAM.C.ASCII.UBYTE.NUMBER_42` anchors on bare `ASCII`, arch-M1); COM_AXIS deposit=="RL.FNC.SWORD.ROW_DIR" | pre-fix None | ✔ |
| AT-097 | ML1 | `chars=[t…CHARACTERISTIC]`; **`len(chars)==50`** ∧ all have `char_type` (truthy ok) ∧ all have **`address is not None`** (NOT `all(t.get('address'))` — 5/50 have addr==0, arch-M3) | pre-fix 0-genuine/50 | ✔ |
| AT-098 | ML1 | `case_01` 2/2 `char_type=="VALUE"`, addresses `0x80000010`/`0x80000040`, `length`/limits unchanged; `tags==3` | GREEN now, must stay (superset) | ✔ |
| AT-099 | ML1 | demo MEAS 25/25 datatype + ≥24 length; synthetic `make_large_a2l` chars: **`len(synth)==8` ∧ all `char_type is None`** (count-guarded, qa-M2 — snapshot sentinel) | GREEN now, must stay | ✔ |
| AT-100 | ML2 | STD `max_axis_points=="8"`/`external False`; COM `external True`; FIX `"6"`/False; <4-token body → None no-crash | pre-fix first-line-only | ✔ |
| AT-101 | SAFE | **8 enumerated** hostile cases (synthetic tmp A2L via `parse_a2l_file`): 0 raise ∧ quoted `*/`/`http://` bytes preserved ∧ malformed→`char_type None` **+ 1 clean positive-control block → char_type non-None** (qa-M3) **+ 1 MB-scale DoS case completes under bound** (sec-F1, may be `@slow`) | naive strip raises/leaks/strips-all | ✔ |
| AT-102 | scope | `ASAM.C.CURVE.STD_AXIS` + `ASAM.C.MAP.STD_AXIS.STD_AXIS` `length is None` (batch-55 boundary) | premature summer fills length | ✔ |
| AT-103 | C-17 | now-live `deposit`/`record_layout_name` with markup metachars renders verbatim (`.plain` eq, `spans==[]`) via `_build_a2l_table_cells` + `_a2l_detail_card_text` (sec-F2) | markup sink leak | |

**TC (white-box, NEW `tests/test_a2l_multiline_headers.py` unless noted):** TC-097 `_strip_a2l_comments` (spanning; adjacent-token; **`//` truncates to next newline sentinel — early-line `//` with mandatory params on later lines → all 7 recovered**, arch-M2); TC-098 `_flatten_body_tokens` quote-respecting (**+ escaped-quote-in-string parity with `_split_line_respecting_quotes`**, sec-F3); TC-099 kind-anchor positional (index 0/1/2; int(addr) fail→None; **+ negative: bare-kind-word-before-Type → `address=None` degradation**, arch-M1); TC-100 axis full-body tokenize; TC-101 comment-strip robustness corpus (white-box on `_strip_a2l_comments`); TC-102 freeze/census (a2l.py unfrozen; new tests not in tc032-frozen file; C-26 fields re-baselined **incl. `test_tui_snapshot.py`/`test_examples_pilot_gifs.py` why-immune + spot-check `test_a2l_enriched.py`**, arch-m1).

**Gate-blocking:** AT-096, AT-097, AT-098, **AT-099** (qa-M1), AT-100, AT-101, AT-102.

**Impl watch-items (folded):** (a) `_characteristic_from_tokens` returns the SHIPPED dict keys `address_inline`/`lower_limit`/`upper_limit`/`datatype` (call-site `a2l.py:989`), NOT the probe keys (arch-m3). (b) `//` in `_strip_a2l_comments` truncates to the next newline sentinel, never end-of-body (arch-M2). (c) bare-kind-word-as-name is a documented non-goal (arch-M1). (d) line-scan comment fragility (`a2l.py:994-1047`) is a KNOWN LIMITATION out of scope (0 interspersed comments in corpus; arch-m2).

---
## 5.2 Dual traceability (0 gaps)
- **Behavioral:** US-ML1 → {AT-096, AT-097, AT-098, AT-099, AT-102}; US-ML2 → AT-100; SAFE → AT-101.
- **Functional:** HLR-ML1-1 → TC-099 (+ LLR-ML1-1.1/1.2/1.3/1.4 → TC-097/098/099); HLR-ML1-2 → AT-099/AT-098; HLR-ML2-1 → TC-100; HLR-SAFE-1 → TC-101. Every US has an AT; every LLR a TC/inspection.

## 6.3 Risks
- **R1 regression surface:** all 50 chars/25 meas re-parse. Full guard-host + snapshot check + C-26 reverse-census on every touched field.
- **R2 comment grammar (C-17):** join-first strip + quote-state machine; 8/8 hostile verified. AT-101 gate-blocking.
- **R3 no-kind blocks:** synthetic conftest chars have no kind → stay None → no snapshot drift (verified).
- **R4 MEASUREMENT scope:** multi-line-mandatory MEASUREMENT deferred (absent from corpus); covered by no-regression AT-099. Confirm at Phase-2 if operator wants it now.
- **R5 file budget:** ~5 files + 1 new → split guard-file edits into a 2nd increment (Phase 3).

## 6.5 Amendments / 6.4 reconciliation
- New ids `R-A2L-011` (char multi-line + no-regression), `R-A2L-012` (axis), `R-A2L-013` (comment safety). Canonical AT registry pinned (§4.9) reconciling the two agents' schemes.
- Scope: HEADER-only; array length stays None (batch-55). MEASUREMENT multi-line deferred (R4).
- a2l.py re-freeze = post-merge follow-up (batch-50 P-2 pattern).
