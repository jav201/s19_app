# Requirements ledger — s19_app — 2026-08-28-batch-89

> **Append-only.** Entries are added in chronological order and never rewritten, never
> renumbered, never deleted. An entry that turns out wrong is superseded by a NEW entry that
> names it. The live contract is `01-requirements.md`; this file records how it came to say
> what it says. Every entry names the requirement it amends; every requirement names its
> entries. `V26` compares the two sets of pairs in both directions and BLOCKs on any pair
> present on one side only.
>
> This file lives under `.dev-flow/` deliberately: writing an id here DECLARES it to the
> corpus scanner, so traceability survives the split (C-56).

### LED-89.1 — the split alone is not the fix, and the pairing is what makes it safe
- **Requirement:** HLR-89.1, LLR-89.1.3
- **Date:** 2026-08-28
- **What changed:** the requirements record became two documents — an editable live contract
  and this append-only ledger — and `V26` was written to enforce the split, the current-state
  check and the both-ways link.
- **Why:** moving the findings table and the forensic prose out of batch-88's record is a
  **35% cut and not a fix**: the remaining 65.3% is normative text written in the forensic
  register, requirements whose justification sits inside the normative sentence. Splitting
  files does not separate a sentence from its reason; splitting the sentence does. And a
  naive split into two EDITABLE files does not reduce the defect surface — it adds one,
  because the two disagree. That is `R-88-17`, batch-88's most repeated defect at 8+
  instances, rehoused rather than closed. What closes it is that the population **is**
  enumerated: every (requirement, entry) pair is declared on both sides and compared as a
  PAIRING. A count, a membership test, or "every id in the ledger exists" each discards the
  pairing, which is exactly where the failure lives — the argument `V15` already makes about
  the bundle.
- **Evidence:** batch-88 record decomposition (findings 8.1% · forensic prose 26.6% ·
  normative remainder 65.3%, operator's measurement); arm `V26 PAIR-crossed`, whose fixture
  holds identical requirement-id and entry-id sets on both sides and swaps only the pairs —
  every membership oracle reports a clean pass on it.

### LED-89.2 — the citations anchor on symbols, because this increment moved the lines
- **Requirement:** HLR-89.4
- **Date:** 2026-08-28
- **What changed:** the environment contract's two binding citations are written as SYMBOLS
  rather than as `file:line`.
- **Why:** the operator's brief cited `git init -b` at `devflow-validate.py:5299`. That
  citation was **correct when it was written and stale by the time it was checked**, because
  this increment inserted the `V26` rule and its arms above it. Measured 2026-08-28: the
  construct now sits at `:5527`, exactly 228 lines lower, inside the V25 fixture builder in
  `selftest()`. This is `R-88-9` — a `file:line` citation into a file the batch itself EDITS
  is stale by construction — reproduced by the very brief that registered it.
- **Evidence:** `grep -n '"init"'` returns `3988` and `5527`; the `-b main` form is the
  second. `capture_output=` with `text=` resolves at `:572-573`, inside `v8_module_map`, and
  is unmoved because this increment inserted below it.

### LED-89.3 — the budget's number is chosen from the corpus and lives only in the code
- **Requirement:** HLR-89.1, LLR-89.1.1
- **Date:** 2026-08-28
- **What changed:** `_LEAN_MAX_CHARS` was set to 55,000 and both budget sentences render it.
- **Why:** `R-88-19` — a measurement written into the record is not a constraint unless
  something checks the implementation against it. A figure restated in a record is a second
  copy that can drift silently, so the record cites the SYMBOL and holds no copy of the value.
  The number itself is chosen from evidence rather than taste: the 65 `01-requirements.md`
  records under `.dev-flow/`, measured 2026-08-28, have a MEDIAN of 55,367 chars, and the
  budget is that median rounded down to 55,000. Half the records this flow has ever produced
  already sit under it, so the budget cannot be accused of demanding a shape the flow has
  never reached. It is NOTICE and never BLOCK: a long record is a fact about a batch's week,
  not a defect in its content.
- **Evidence:** `n=65 median=55367`, p25 37,789 · p75 89,790 · max 322,289, `python` over
  `glob('*/01-requirements.md')`, 2026-08-28. Arms `V26 BUDGET-renders-const` (the sentences
  render the threshold PASSED IN, never a literal) and `V26 BUDGET-constant` (the constant is
  55000). Mutant `M5-constant-widened` (55000 → 550000) killed by 3 arms.

### LED-89.4 — the register is not policed, and that is a ruling rather than an omission
- **Requirement:** LLR-89.1.2
- **Date:** 2026-08-28
- **What changed:** `V26`'s current-state check is Markdown strikethrough and nothing else. It
  does not forbid the warning glyph, nor the words "superseded", "amended" or "measured".
- **Why:** `R-88-16` — a token stream has a grammar to derive a class from and prose does not,
  so a prose claim is pinnable by typed equality and never by forbidding what it may not say.
  `~~x~~` is a Markdown DELIMITER and therefore has a grammar; text that is present and void
  at once is exactly the two-states-at-once shape the lean contract removes. A vocabulary
  guard, by contrast, would kill the wordings someone thought of and no others — and would
  false-fail correct work, which is C-53's expensive failure.
- **Evidence:** measured over all 65 records, 2026-08-28: **16 carry the warning glyph, 10
  carry strikethrough**. Inspection of the glyph's sites shows it marking warnings that ARE
  current state at least as often as amendments. Whether a normative sentence carries its own
  justification therefore remains a reviewer's judgement and a Phase-2 blocker class, stated
  in the template rather than mechanised badly.

### LED-89.5 — the budget was derived in BYTES and enforced in CHARACTERS
- **Requirement:** HLR-89.1, LLR-89.1.1
- **Date:** 2026-08-28
- **Supersedes:** `LED-89.3`, whose figures and whose 55,000 floor are wrong. **That entry is
  left standing exactly as written** — this ledger is append-only, so a wrong entry is
  corrected by a new one that names it, never by a rewrite. Read `LED-89.3` as history and
  this entry as current state.
- **What changed:** `_LEAN_MAX_CHARS` moved from 55,000 to **54,000**, and it is no longer
  typed: it is computed by `_lean_budget_from(...)` from a recorded median, with the flooring
  rule expressed in code rather than in prose.
- **Why:** the four quantiles justifying 55,000 were computed with `os.path.getsize` — BYTES —
  while `_v26_outcome` measures `len(text)` — CHARACTERS. The corpus is UTF-8 with multi-byte
  punctuation throughout, so the two disagree by ~1,000 at the median, which is a whole
  flooring step: the honest floor was 54,000 and the shipped one was 55,000. **This is
  `R-88-19` in its purest form** — four figures written into a record with nothing comparing
  them to the implementation — and the arm that should have caught it, `BUDGET-constant`,
  compared the literal `55000` against the literal `55000`. It was flagged as vacuous in the
  first draft and kept anyway; **flagging an arm as vacuous is not the same as replacing it,
  and there was a real defect behind this one.**
- **Evidence:** measured 2026-08-28 over the 65 records predating batch-89 —
  CHARS median 54,367 (p25 37,006 · p75 87,505 · max 314,621); BYTES median 55,367 (p25
  37,789 · p75 89,790 · max 322,289); 32 of 65 sit at or under 54,000. The population
  self-excludes batch-89's own record, the 66th, because including the subject would let the
  rule move its own threshold — stated here rather than left silent. Arms
  `V26 BUDGET-derivation` (re-derives the median-floor over five supplied size lists) and
  `V26 BUDGET-chars-not-bytes` (pins the unit).

### LED-89.6 — the strikethrough span may not cross a blank line
- **Requirement:** LLR-89.1.2
- **Date:** 2026-08-28
- **What changed:** `_LEAN_STRIKE` gained a blank-line bound —
  `~~(?=\S)(?:(?!\n[ \t]*\n).)+?(?<=\S)~~`.
- **Why:** the first cut was unbounded `re.S`, so the opening `~~` of one span paired with a
  closing `~~` paragraphs away. Two consequences, and the second is worse than the first:
  the BLOCK quoted innocent prose from a different section, and **any record that merely
  SHOWS the canonical `~~this~~` as an example BLOCKed outright** — the rule eating its own
  documentation as a delimiter. batch-89's own record escaped only by the accident of a space
  inside its example.
- **Evidence:** measured over all 66 records, 2026-08-28: **81 spans before and 81 after**,
  zero of them crossing a blank line; batch-88's 47 spans all retained, 2 of which are
  genuinely multi-line, so the wrap case is still exercised by the real corpus and not only by
  a fixture. Arm `V26 STRIKE-blank-line` asserts both halves — a span never crosses a blank
  line, and an intra-paragraph wrap still matches.

### LED-89.7 — six fields ruled, three returned and three retired
- **Requirement:** HLR-89.1
- **Date:** 2026-08-28
- **What changed:** `req-template.md`'s requirement field set. **Returned as live and
  mandatory:** `Boundary catalog` (scoped, explicitly, to every requirement whose `Validation`
  is `test`/`analysis` — HLR or LLR alike, because the catalog exists to generate cases for an
  arm and an `inspection` requirement has no arm to generate them for), `Acceptance test(s)`
  (with `owed at <increment>` as the declared empty), and `Negative control` (its own named
  slot). **Retired:** `Acceptance criteria (informative, complementary)`, `Deliverable +
  observation`, and the §5.2 dual-traceability TABLES.
- **Why:** the operator's criterion, measured: **of the six fields, only two change what gets
  TESTED.** The other four describe or justify, and their home is this ledger. `Boundary
  catalog` is the most load-bearing of the six because it is GENERATIVE rather than descriptive
  — each ticked class is an arm somebody owes — at 9 instances and 6,182 chars in batch-88.
  `Acceptance test(s)` is 896 chars for 9 ids, 0.5% of that record, and buys traceability.
  `Negative control` was inline in **9 of 10** thresholds, meaning exactly one requirement had
  no RED side **and nothing said so**; *a test that cannot fail is vacuous* is this flow's
  central doctrine, and a doctrine carried by convention is carried by nobody. Against that:
  `Acceptance criteria` was **5.6% of batch-88's record** and self-declared informative;
  `Deliverable + observation` restated `Validation` plus `Executed verification`; and the
  traceability tables transcribed the `Traceability` field, populated in **10 of 10** measured
  — a second copy of one truth, which is the shape this flow has paid for repeatedly.
- **Evidence:** the retirement reasons are written INTO `req-template.md` at the point of
  removal, never silently deleted, so a reader meeting the gap finds the argument. **The three
  returned fields are mandatory and enforced by no rule — `R-89-8` says so rather than letting
  the word "mandatory" imply a check that does not exist.**
