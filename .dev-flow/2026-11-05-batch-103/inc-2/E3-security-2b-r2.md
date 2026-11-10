# Inc 2b — E3 security re-review, round 2 (narrow, against the fixed reader)

**Verdict: PASS-WITH-NOTES.** No MAJOR or HIGH open. Both former MAJOR blockers
(E3S-37 span-index scope / F2; F1 stale `.19`/`.138` mask cases) are closed by
the correction pass recorded in `E3-rulings.md` "Inc 2b re-review against the
fixed reader" + "Inc 2b correction completion addendum". The residual `.19`
guards and R-A2L-DEF.152 are **non-vacuous** — the executed premise transcripts
prove the fixed reader alone does not refuse them. Two MINOR record-sync gaps
and three INFO verification items remain; none blocks E4.

**What was read (not executed):** `E3-rulings.md` (final "Inc 2b re-review" and
"correction completion addendum" sections), `01-requirements.md` (S2.7, Split,
Counts), `02-test-cases.md` (`.19`, `.57`, `.138`, `.151`, `.152`, `.139`,
AT-B103-I2-1, Split/Counts), `codewire/graph-inc2.md` (I-2 block, coverage
table, Split, `describe_definitions`, `_find_tag`, `_read_object_lines`,
`_check_bit_mask`, `_shared_with`, `_selected_bits`, `encode_definition`, the
`[Data: a2l_data]`/edges), `E1-rulings.md` §4 (I-2 field order), my previous
`E3-security-2b.md`, and the two executed premise scripts+transcripts
(`evidence-e3/e3-2b-reader-premise.{py,txt}`,
`evidence-e3/e3-2b-residual-premise.{py,txt}`).

**What was executed:** nothing by this reviewer. Read-only; no pytest, no
probes, no git mutations, per the brief. The only executed evidence is the two
premise transcripts (PASS on `<runner>`, Python 3.11.18, over the integrated
tree), which I read rather than re-ran. Their `FAIL SELFTEST` red-proof lines
show the instruments can report failure.

## Closure of the former blockers (E3S-36 … E3S-44, F1 … F4)

| Id | Sev | Disposition confirmed | Evidence |
|---|---|---|---|
| E3S-36 | MAJOR | closed by Inc 11 for C1/C2/C3; residual guard `.19/7` (masked def whose object / record layout / MOD_COMMON holds >1 live BYTE_ORDER keyword → `A2L-DEF-MASK` "its byte order cannot be read") | `01-requirements.md` `.19` row; case `.19/7` (`02-test-cases.md:78`); graph `_read_object_lines` `byte_order_count` + example (`.19/7`); premise `e3-2b-residual-premise.txt` "duplicate MOD_COMMON BYTE_ORDER is currently last-wins ('little', None, [])" — reader alone refuses nothing, so the guard is real, not vacuous |
| E3S-37 | MAJOR | closed by option (a): BLOB/INSTANCE join the index from `a2l_data["declared_spans"]`; unreadable length → declared-address fail-closed point (never exempt); `/include` → R-A2L-DEF.152; AXIS_PTS stays Inc 3b R-A2L-DEF.140 (before Inc 8/9); AT-B103-I2-1 applies only ASCII | CTX *span* (`01-requirements.md`); `.138` row "MEASUREMENT, CHARACTERISTIC, BLOB and INSTANCE"; cases `.138/2-/4, /9`; graph `describe_definitions` + `_shared_with` + `[Data: a2l_data].declared_spans` edge; premise V171 spans `ASAM_I_SCALAR_VALUE_UWORD_SINGLE (0x810000, 2)` / `_ARRAY_5 (0x810002, 10)`, `ASAM_S_EXAMPLE` address, "unsized INSTANCE keeps declared address" |
| E3S-38 | MAJOR | closed by Inc 11; no C-rule cross-check added (as ruled) | `.7.1` unchanged; no cross-check in graph `describe_definitions` |
| E3S-39 | MAJOR | closed by Inc 11 for bounded lengths; only bounded spans filed as intervals; unreadable length → declared-address point | cases `.138/4, /9`; premise H1–H4 hostile lengths → `tag length None` + refusal, 0.0016 s |
| E3S-40 | MEDIUM | closed by Inc 11 (MATRIX_DIM bounded product) | premise H2 `MATRIX_DIM 4294967296` → `A2L-DEF-MATRIX` |
| E3S-41 | MINOR | CLEAN applied without a whole-file second describe: `mask_of(other)` = `other.bit_mask` only when the other's definition has no refusal (else None); candidates built on demand, cached by name; duplicate name → NAME refusal → no mask | graph `_shared_with` ("computed on demand and cached by name"); cases `.138/10, /11`; premise "duplicate neighbour has no clean mask" |
| E3S-42 | MINOR | text kind runs the overlap step before `Encoded`; `.138/20` added | graph `encode_definition` step (2) "…step-6 image-span check, step 9, then `Encoded`"; case `.138/20` |
| E3S-43 | LOW | closed by Inc 11; no glued-token guard restored | graph examples `BIT_MASK 0x000F/* nibble */0` → mask word `0x000F`, surplus word invalidates tag, `.152` refuses the write; premise "commented mask word is read but the tag fails closed" |
| E3S-44 | LOW | applied: scan stops at "the first overlapping entry not left out" | graph `_shared_with` func text |
| F1 | MAJOR | closed: obsolete text-of-object clauses (letters / open-comment-quote / `/begin`) removed; only two live residuals (`.19/6`, `.19/7`); old cases `.19/8`, `.19/10 … /23` withdrawn (ids kept as history); `.138/1 … /13` re-anchored | `.19` row "8/8"; cases `.19/6-/7, /9` + withdrawn markers; `.138/1 … /13`; graph `_read_object_lines` ("old text-of-object pass is withdrawn"), `describe_definitions` |
| F2 | MAJOR | closed = E3S-37 above | — |
| F3 | MINOR | applied (`mask_of` keying, step-9-in-step-2, scan sentence) | graph `_shared_with`, `encode_definition` step (2) |
| F4 | LOW | applied: operator text capped at 256 chars, spaces and non-control Unicode preserved, controls → U+FFFD | `.151` row + case `.151/7`; graph `_operator_echo`; addendum clarifies operator text does not use `_echo` |

## Confirmations requested by the brief

- **E3S-36 … E3S-44 dispositions** — confirmed as above; all inherit either a
  reader fix (closed by Inc 11) or a landed design fix.
- **Completed BLOB/INSTANCE index and unknown-length index** — `.138` row names
  MEASUREMENT, CHARACTERISTIC, BLOB and INSTANCE; unreadable length contributes
  the declared address as a fail-closed point (0x0 a declared address like any
  other). Cases `.138/2-/4, /9`. Premise confirms the reader supplies
  `declared_spans` with section order and unsized-INSTANCE declared address.
- **Cross-kind file order** — `describe_definitions` files BLOB/INSTANCE at
  their section-walk positions, not appended after tags. Premise
  "declared_spans keeps section order" + "section walk supplies cross-kind file
  order ['CHARACTERISTIC','BLOB','INSTANCE']".
- **CLEAN without a whole-file second describe** — `mask_of` on demand, cached
  by name; duplicate name → no mask; the requested definitions and the on-demand
  neighbours carry their actual refusals. Cases `.138/10, /11`.
- **Two live residual `.19` guards** — `.19/6` (duplicate live BIT_MASK →
  `A2L-DEF-MASK`) and `.19/7` (ambiguous BYTE_ORDER source → `A2L-DEF-MASK`
  "its byte order cannot be read"). Both are non-vacuous: premise shows the
  reader alone returns `(refusal None, bit_mask 0x000F)` for the duplicate
  BIT_MASK and `('little', None, [])` for the duplicate BYTE_ORDER.
- **R-A2L-DEF.152 and reachable fixtures** — 5 cases (`/include`, stray `*/`,
  unclosed comment, unclosed quote, capped marker) each with the object closed
  before the defect, so its own refusal cannot mask the PARSE refusal; `<error>`
  = the payload's first error; describe/decode unchanged; check after the
  definition's refusal, before all operator-value checks. Premise confirms the
  four structural error texts and the `… <k> more parse errors` cap.
- **Exact expected values** — the four `.152` error texts match the premise
  transcript verbatim (`/include x.a2l is not read`, `*/ without /*`, `comment
  not closed`, `quoted string not closed`); the cap marker form matches.
- **Text-kind overlap** — `.138/20` exists and step (2) names step 9.
- **256-character operator echo** — `.151/7` (252 `x` + ` é ` + ESC + `y` = 257)
  discriminates both preservation (space, `é`) and the cut (`y` dropped, `…`).
  `_operator_echo` is distinct from `_echo` (addendum).
- **Current Inc 3a fields** — `E1-rulings.md` §4 lists them in real order after
  `refusal` (`shape`, `element_count`, `index_mode`, `values_offset`,
  `record_layout`, `axes`) then the two private P-2 fields; `shared_with` sits
  after `compu_tab_ref`, before `refusal`. See MINOR-2 below for a graph-elision
  note.
- **Active counts** — **73 requirements** (2a 53 + 2b 20) and **318 cases**
  (**216** in 2a + **102** in 2b) reconcile: 2b = S2.7a 4 (`.19/6,/7`, `.25/2`,
  `.151/7`) + S2.7b 3 (`.26/2-/4`) + S2.7c 95 (`.40-.56` 65, `.57` 5, `.138`
  20, `.152` 5). No arithmetic drift.
- **Vacuous cases / PARSE ↔ definition ↔ OVERLAP conflicts** — none found.
  `.138/13` is deliberately split: the original duplicate-mask payload gives
  `A2L-DEF-PARSE` (the reader's "BIT_MASK is declared twice" error) and the
  overlap oracle is isolated on a copy with its error list cleared, so the two
  refusals cannot mask each other. `AT-B103-I2-1` applies only `UNKNOWN`;
  the nine overlap refusals are asserted. The encode order
  (definition refusal → parse → text kind → number → limits → encode → image →
  mask → precision → shared bytes) keeps every earlier refusal speaking before
  `.152` and before `A2L-DEF-OVERLAP`, matching `.57/5` and `.138/13`.

## Findings

### MINOR-1 (design-gap · record sync) — graph coverage table is stale for the 2b re-review

Ref: `codewire/graph-inc2.md` coverage table rows `.19`, `.57`, `.138`, `.151`.

The "Coverage — every requirement → nodes and examples" table was not updated by
the correction pass: it still reads `.19/1 … /23` (withdrawn cases listed as
active), `.57/1 … /4` (missing the new `/5`), `.138/1 … /19` (missing the new
`/20`), `.151/1 … /3` + `/4 … /6` (missing the new `/7`), and it has **no row for
R-A2L-DEF.152**. The node-level trace is complete and correct — `encode_definition`
lists R-A2L-DEF.152, .151, .138 and .57 in its `req:` line, and its `examples:`
lines carry `.152/1 … /5`, `.57/5`, `.138/20`, `.151/7` — so this is a summary-table
sync defect, not a missing trace. Fix: add a `.152` row and refresh the four
stale case ranges before or at E4 so the machine trace stays complete.

### MINOR-2 (design-gap · record sync) — graph I-2 `Definition` block elides the Inc 3a fields

Ref: `graph-inc2.md:30-45` vs `E1-rulings.md:113-131` (§4).

The graph's literal `Definition(...)` field block lists `…, compu_tab_ref,
shared_with, refusal, _name_echo, _table_form` and omits the Inc 3a fields that
§4 places between `refusal` and the private fields (`shape`, `element_count`,
`index_mode`, `values_offset`, `record_layout`, `axes`). The addendum's claim
"I-2 carries the actual Inc 3a fields in their real order" is true of §4 but not
of this block, and the graph's "How Inc 3 extends I-2" prose still names them
"`elements`, `axes`, `shape`" (vs §4's `element_count`). No security impact —
the order of `shared_with` (before `refusal`) is pinned identically in both —
but the graph block should be brought into line with §4.

### INFO-1 — `.152/5` exact first-error text is not in the premise transcripts

The four structural texts are evidenced verbatim; the `/end without /begin`
first error of `.152/5` (`02-test-cases.md:310`) is not shown in either premise
transcript (which shows `Unclosed /begin sections detected.` for a different
shape). Pin the exact reader text at E4 against `parse_a2l_file` before the case
is written.

### INFO-2 — `.138/9` assumes the hostile-length ASCII keeps its declared address

`.138/9` (`02-test-cases.md:294`) needs `H1` (`ASCII` at 0x10, `NUMBER
1000000000000`) to contribute a fail-closed point at 0x10. The reader premise
confirms `tag length None` and the describe refusal, but checks `t["length"]`,
not `t["address"]`; the analogous INSTANCE premise ("unsized INSTANCE keeps
declared address") supports the model, but E4 should assert `address == 0x10`
for the H1 tag before relying on `.138/9`.

### INFO-3 — `.19/7` case coverage is MOD_COMMON only

The row's byte-order residual covers "object, record layout or MOD_COMMON", but
the single case `.19/7` exercises only MOD_COMMON; the record-layout and
object-record sources have no dedicated case. Acceptable as representative
coverage (the negative control "last-wins, no source count" exercises the shared
mechanism), noted for E4 if the record-layout path is non-trivial to implement.

## Summary

- **Blocking: none.** E3S-37/F2 and F1 are closed and evidenced; every other
  round-5 finding is closed by Inc 11 or landed.
- **Non-blocking:** MINOR-1 and MINOR-2 (graph record sync), INFO-1 … INFO-3
  (E4 pin-verifications and one representative-coverage note).
- **No vacuous new cases** among the residual `.19` guards or `.152` (premise
  proves the reader alone does not refuse them), and **no conflict** between
  PARSE, definition refusals and OVERLAP (`.138/13` and `.57/5` pin the order
  and the isolation).
