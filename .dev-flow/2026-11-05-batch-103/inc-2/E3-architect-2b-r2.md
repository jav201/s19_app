# Inc 2b E3 — ARCHITECT re-review (round 2, against the fixed reader)

**Verdict: PASS-WITH-NOTES.** The two round-1 blockers are closed; every E3S-36 … E3S-44
disposition is confirmed against the corrected records, cases and graph; the two executed
premise transcripts both PASS and cover the residual guards. Five LOW record-sync/trace
findings remain (none MAJOR/HIGH, none a design gap, none blocking E4).

## Executed vs read

- **Executed:** nothing by this reviewer. Read-only review on Windows; no pytest, no probes,
  no git mutations, per the brief.
- **Read (documents):** `E3-rulings.md` ("Inc 2b re-review against the fixed reader",
  "Inc 2b correction completion addendum"); `01-requirements.md` (full); `02-test-cases.md`
  (full); `codewire/graph-inc2.md` (full, incl. nodes `describe_definitions`, `_read_object_lines`,
  `_check_bit_mask`, `_shared_with`, `_selected_bits`, `encode_definition`, `_parse_number_text`,
  `_check_limits`, `_encode_number`, `_merge_bit_mask`, `_encode_enum`, `_encode_ascii`,
  `_agrees_at_display_precision`, the Entities/Edges/Findings sections and the split table);
  `E1-rulings.md` §4 (I-2); `E1-slice.md` §7.
- **Read (evidence):** `evidence-e3/e3-2b-reader-premise-transcript.txt` (PASS),
  `evidence-e3/e3-2b-residual-premise-transcript.txt` (PASS).
- **Read (my prior review):** `E3-architect-2b.md`.

## Closure of the former blockers (round-1 B-1 / B-2)

- **B-1 (E3S-37 `/include` had no machine-checkable signal) — CLOSED.** The ruling chose
  R-A2L-DEF.152, keyed on the structured `a2l_data["errors"]` list (any entry → `A2L-DEF-PARSE`),
  not on parsing the frozen message text. `encode_definition` step (1a) implements it
  (`graph-inc2.md:598`, edge `[Data: a2l_data].errors ──▶ encode_definition` `:952`). The
  premise proves the `/include` error string is present (`e3-2b-reader-premise-transcript.txt`,
  "parse error include"). No unfreeze of `a2l.py` is needed.
- **B-2 (E3S-41 CLEAN `mask_of` not pinned) — CLOSED.** `describe_definitions`
  (`graph-inc2.md:286`) pins `mask_of(other) = other.bit_mask` only when the other's definition
  has **no refusal and a readable length**, else `None`, built on demand and cached by name —
  explicitly "so CLEAN needs no whole-file second describe" (the ruling's rejection of the
  reviewer's second full pass, which would have re-opened `.136`). `_shared_with` (`:439`)
  states the same rule at the pair level. Cases `.138/10` (length-refused neighbour) and
  `.138/11` (duplicate-named neighbour) are discriminating.

## E3S-36 … E3S-44 dispositions — confirmed

| Id | Sev | Confirmed disposition |
|---|---|---|
| E3S-36 | MAJOR | Closed by Inc 11 for C1/C2/C3 (premise: C1/C2/C3 read `little`/`little`/`big`). One residual guard: >1 live BYTE_ORDER keyword → `A2L-DEF-MASK` `its byte order cannot be read` (`.19/7`, `graph-inc2.md:411`; premise: "duplicate MOD_COMMON BYTE_ORDER is currently last-wins", so the guard discriminates). |
| E3S-37 | MAJOR | Option (a): index `declared_spans` (BLOB/INSTANCE + declared-address fail-closed point) — `.138/2 … /9`; `/include` → R-A2L-DEF.152; AXIS_PTS stays R-A2L-DEF.140 in Inc 3b. V171 ULONG/REF_1 and SBYTE/UBYTE arms re-anchored (`.138/5 … /8`; AT-B103-I2-1 applies only UNKNOWN). |
| E3S-38 | MAJOR | Closed by Inc 11 (comment-aware tag read); no C-rule cross-check. |
| E3S-39 | MAJOR | Closed by Inc 11 (`_bounded_length`); hostile unknown-length tag joins as a fail-closed point (`.138/9`, `.138/4`); premise H1–H4 refuse, describe time 0.0016 s. |
| E3S-40 | MEDIUM | Closed by Inc 11 (MATRIX_DIM bounded product). |
| E3S-41 | MINOR | CLEAN `mask_of`, no whole-file second describe (see B-2 closure). |
| E3S-42 | MINOR | Text kind runs the overlap step before `Encoded`: `.138/20`; `encode_definition` step (2) → step 9 (`graph-inc2.md:598`). |
| E3S-43 | LOW | Closed by Inc 11 (comment is a word break; `0x000F`, surplus word → tag invalid → R-A2L-DEF.152). Premise: "commented mask word is read but the tag fails closed". |
| E3S-44 | LOW | `_shared_with` scans to "the first overlapping entry not left out" (`graph-inc2.md:439`). |

## Scope items confirmed

- **BLOB/INSTANCE + unknown-length index.** `describe_definitions` files BLOB/INSTANCE from
  `a2l_data["declared_spans"]` with `_bounded_length`; unreadable length → fail-closed point at
  the declared address. Premise: "unsized INSTANCE keeps declared address {IU, 16, None}".
- **Cross-kind file order.** Positions from one pre-order section walk; BLOB/INSTANCE aligned
  with `declared_spans` in that order, never concatenated as two groups. Premise:
  "declared_spans keeps section order" and "section walk supplies cross-kind file order
  ['CHARACTERISTIC', 'BLOB', 'INSTANCE']".
- **CLEAN without a whole-file second describe.** On-demand, cached-by-name neighbour build; a
  duplicate name yields its NAME refusal and therefore no mask (`.138/11`).
- **Two live residual `.19` guards.** `.19/6` (two live BIT_MASK lines, message `the bit mask
  0x000F cannot be applied to UWORD`) and `.19/7` (ambiguous byte-order source, message `its
  byte order cannot be read`). Withdrawn: `/8`, `/10 … /23` (ids retained). Premise proves both
  guards are reachable and discriminating.
- **R-A2L-DEF.152 and fixtures.** Five cases `/include`, stray `*/`, unclosed comment, unclosed
  quote, capped marker. Error texts /1 … /4 match the premise verbatim (see finding F-5 for /5).
  The object is closed before each defect so its own refusal cannot mask PARSE; describe and
  decode unchanged. Order: definition's own refusal → PARSE → operator-value checks → … → OVERLAP.
- **Exact expected values.** `.138/5 … /8` names match the premise spans
  (`ASAM_I_SCALAR_VALUE_UWORD_SINGLE (0x810000, 2)`, `ASAM_I_SCALAR_VALUE_UWORD_ARRAY_5
  (0x810002, 10)`); `.152/1 … /4` first-error texts match the premise strings. V171 encode cases
  (`.41/2`, `.43/4`, `.44/1,/2`, `.45/1,/2`, `.46/1,/2`, `.48/1,/2`, `.53/4`, `.56/1`) each
  assert the overlap then clear `shared_with` as a test device — verified in `02-test-cases.md`.
- **Text-kind overlap.** `.138/20` present, discriminating (`mutant: return after _encode_ascii → RED`).
- **256-character operator echo.** `.151/7` uses 252 `x` + ` é ` + ESC + `y`; `_operator_echo`
  preserves the space and `é`, replaces ESC with U+FFFD, caps at 256 and adds `…` (y cut). The
  `é`-preservation makes it discriminating against `_echo` (which would map `é` to U+FFFD).
- **Inc 3a fields.** Present in `E1-rulings.md` §4 (shape, element_count, index_mode,
  values_offset, record_layout, axes after `refusal`, before the private fields); all five
  `Definition(...)` construction sites owed at E4 (ruling F-1).
- **Active counts.** 73 requirements (2a 53 + 2b 20); 318 cases = 216 (2a) + 102 (2b) — both
  reconcile mechanically (S2.7a 30, S2.7b 16, S2.7c 22, S2.7d 5; `.19` active 8 of 8).

## No vacuous new cases / no order conflicts

- `.19/6`, `.19/7`, `.151/7`, `.152/1 … /5`, `.57/5`, `.138/10`, `.138/11`, `.138/13`,
  `.138/20` each have a discriminating negative control or isolation device and exact expected
  text; none is smoke.
- PARSE vs definition-refusal vs OVERLAP is a strict, documented order (definition's refusal →
  PARSE → value checks → OVERLAP). `.57/5` (PARSE over NUMBER), `.57/4` (NUMBER over OVERLAP) and
  `.138/13` (PARSE on the original, OVERLAP on the error-cleared copy) pin it without ambiguity.
  The `.152` objects are closed before the defect so their own refusal never masks PARSE.

## Findings (all LOW, record-sync/trace; none blocks E4)

- **F-1 (LOW, record-sync).** The graph's coverage table is stale: `.19/1 … /23`
  (`graph-inc2.md:147`) should be the active 8 (`.19/1 … /7, /9`); `.57/1 … /4` (`:164`) should
  be `.57/1 … /5`; `.138/1 … /19` (`:165`) should be `.138/1 … /20`; `.151` (`:173`) omits
  `.151/7`; and **R-A2L-DEF.152 has no coverage row at all**. The node bodies are correct; the
  summary table was not updated by the correction pass. Fix mechanically before/at E4 so the
  trace stays honest (the `.152` row belongs to `encode_definition` with `.152/1 … /5`).
- **F-2 (LOW, record-sync).** CTX-A2L-DEF's *encode order* term (`01-requirements.md`,
  Definitions block) lists "the definition's refusal, number text, …, shared bytes" and omits the
  R-A2L-DEF.152 parse step, which the graph (`encode_definition` step 1a) and R-A2L-DEF.152
  itself place between the definition's refusal and the operator-value checks. R-A2L-DEF.57
  references "the encode order", so the term should gain the parse step.
- **F-3 (LOW, record-sync).** The graph's P-2 note says "Inc 3's defaulted fields come after
  these two" (`_name_echo`, `_table_form`), but `E1-rulings.md` §4 — the synced authority per the
  addendum — places the Inc 3a fields after `refusal` and *before* the two private fields. All
  are defaulted and keyword-constructed, so there is no functional impact; the note is stale.
- **F-4 (LOW, trace).** AT-B103-I2-1's rows list still names `.44` and `.55` (`02-test-cases.md`
  AT-B103-I2-1; the graph AT example likewise), but the re-anchored AT encodes only `UNKNOWN`:
  the `.44` notice is now exercised by `.44/1,/2` (which clear `shared_with`), and `.55` (number
  round trip) is reached nowhere in the AT. `.46`/`.48` are already acknowledged as deferred to
  AT-B103-I2-2. The rows column should drop `.44`/`.55` (or annotate them as cleared-device cases).
- **F-5 (LOW, coverage).** `.152/5`'s first-error text "Line 20: /end without /begin" is not
  evidenced by the reader premise (which shows only the cap marker `['… 3 more parse errors']`).
  The cap marker is proven reachable; the specific first-error text is the case's own INLINE
  fixture and is pinned at E4. Non-blocking, recorded for the tester.

## What blocks E4

Nothing. No MAJOR/HIGH, no design gap, no implementation defect against the current records.
F-1 … F-5 are LOW and can land in the same correction pass or be carried as E4 addenda.
