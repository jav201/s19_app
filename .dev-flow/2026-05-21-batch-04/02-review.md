# Review — s19_app — 2026-05-21-batch-04

**Phase:** 2 — Cross-agent review
**Iteration:** 1
**Date:** 2026-05-21
**Source artifact under review:** [`.dev-flow/2026-05-21-batch-04/01-requirements.md`](01-requirements.md)
**Batch:** batch-04 — memory-field change kind + unified change-set + selective export
**Reviewers:** `architect`, `qa-reviewer`, `security-reviewer` (parallel)

---

## Aggregate summary

| Reviewer | Blockers | Majors | Minors | Informational | Verdict |
|---|---|---|---|---|---|
| architect | 1 | 4 | 2 | 0 | pass-with-fixes |
| qa-reviewer | 0 | 2 | 7 | 0 | pass-with-fixes |
| security-reviewer | 0 | 3 | 4 | 1 | OK-with-mitigations |
| **Total** | **1** | **7** | **14** | **1** | **blockers-present** |

> The per-reviewer counts overlap by design — A-4 and Q-02 are the same defect
> seen from two angles, and several minors couple to a major. The
> de-duplicated **finding ledger is 22 distinct findings** (A-1..A-6,
> Q-02..Q-12, S-001..S-007): **1 blocker · 7 majors · 14 minors** plus the
> S-007 informational. Q-01, Q-05 and Q-10 were checked clean and are recorded
> in the qa section without a finding row.

### Consolidated verdict

**blockers-present — the dev-flow Phase 2 spec forces a rollback to Phase 1.**

One blocker-severity finding is open — **A-1**. The dev-flow workflow forces a
rollback to Phase 1 whenever **any** blocker is open, so `01-requirements.md`
cannot advance to Phase 3 in its current state — it must be revised in a
**Phase 1 iteration 2** and re-reviewed.

Per-reviewer verdicts: architect `pass-with-fixes`, qa-reviewer
`pass-with-fixes` (0 blockers), security-reviewer `OK-with-mitigations`
(0 blockers). The single blocker is the architect's **A-1** — a callability
defect, not an implementation impossibility:

- **A-1** — LLR-007.1 tells the export coordinator to call the **unchanged**
  batch-03 writer `write_cdfx_to_workarea(...)`, but that writer's signature
  takes a **mandatory `resolution: ResolutionResult` positional argument**. The
  unified change-set (per A-7 / LLR-004.1 / LLR-005.2) models the parameter
  half as a plain `ChangeList` with **no `ResolutionResult`** attached. As
  written, the "reuse the batch-03 writer unchanged" contract (C-1, the central
  reuse decision of the batch) is **not callable** — the requirement specifies
  an export path that cannot be invoked. This is a specification defect that
  makes HLR-007 unimplementable as worded.

The 7 majors are requirement-text and test-case-text defects: an
underspecified on-disk encoding, an underspecified validation status, a
compound LLR bundling two opposite-semantics rules, two missing resource /
nesting bounds, and a missing write-path safety clause for one of the three
files the batch produces. All 7 majors and all 14 minors are closable inside a
single Phase 1 iteration once the A-1 resolution is taken — and the A-1
resolution is **already chosen** (option (a), see Recommended Disposition), so
no further product decision is pending.

### `shall` / `should` discipline check

- **Clean.** No `should` modal appears inside any HLR or LLR `Statement:`
  bullet in Sections 3 and 4. The strict IEEE 830 + EARS convention declared in
  the document preamble — `shall` only inside HLR/LLR statements, `should` only
  in informative voice — is honored throughout the requirements body.
- `should` appears only where the convention permits it: inside
  `Rationale (informative)` / `Acceptance criteria (informative)` blocks and
  appendix prose. No stray normative `shall` / `shall not` was found in
  informative voice.
- See the dedicated discipline-result section below.

---

## Findings table — 22 findings

> Severity: BLOCKER gates the batch; major must be fixed in the Phase 1
> iteration; minor folds into the same iteration; informational = no action.

| ID | Severity | Area | One-line |
|----|----------|------|----------|
| A-1 | **BLOCKER** | LLR-007.1 / HLR-007 / C-1 | `write_cdfx_to_workarea` needs a mandatory `resolution: ResolutionResult`; the unified set models the parameter half as a bare `ChangeList` — the "reuse unchanged" export is not callable. |
| A-2 | major | OQ-V1 / LLR-001.3 / LLR-005.3 | On-disk encoding of the memory-field half is unpinned — `address` as a JSON object key forces a hex/decimal ambiguity; resolve OQ-V1 normatively. |
| A-3 | major | LLR-002.1 / OQ-V2 | `partial` underspecified for an entry spanning a gap that touches two ranges; resolve OQ-V2 — one `partial` status, exactly one issue. |
| A-4 | major | LLR-002.4 | LLR-002.4 bundles two opposite-semantics concerns — inter-entry overlap (collect-don't-abort) and malformed-byte-run rejection (`ValueError`) — into one LLR. |
| A-5 | minor | LLR-007.4 | Add a one-line note that `ValidationIssue.artifact` is the per-half origin-tagging mechanism (so Phase 3 does not reach for a model change — C-5 forbids it). |
| A-6 | minor | §1.5 / §3 / §5.7 | "33 active TC / 34 IDs (TC-014 reserved)" wording is not uniform across the document. |
| Q-02 | major | LLR-002.4 / TC-008 | Same defect as A-4 — split the compound LLR; TC-008's negative-byte assertion must trace to explicit normative wording. |
| Q-03 | major | §5.4 / TC-008 | The `memory_change_factory` overlap variant is underspecified — name concrete distinct start addresses with intersecting runs. |
| Q-04 | minor | §5.2 | Stale `TC-014?` cross-reference on the §5.2 HLR-004 row — remove it. |
| Q-06 | minor | TC-025 | The round-trip equality predicate does not state whether the validation/resolution-status field is included — pin it. |
| Q-07 | minor | TC-020 / LLR-006.2 | A well-formed-JSON-but-wrong-shape document (`[]`, `42`, `{"foo":1}`) trips neither `MF-JSON-PARSE` nor a per-entry rule — add a TC + an `MF-BAD-STRUCTURE` code. |
| Q-08 | minor | §5.4 | Once OQ-V2 is resolved, add a `memory_change_factory` gap-spanning fixture variant for the multi-range `partial` case. |
| Q-09 | minor | §5.4 | Note that `unified_changeset_factory`'s adversarial floats are inherited from the batch-03 `change_list_factory`. |
| Q-11 | minor | TC-018 / LLR-005.4 | The reparse-point rejection arm needs a deterministic mechanism (injectable probe / explicit recorded skip), not a silent CI skip. |
| Q-12 | minor | LLR-003.2 | The non-printable-byte ASCII placeholder character is unpinned ("for example `.`") — pin it; add to the §5.8 Phase-3 to-pin list. |
| S-001 | major | LLR-001.1 / LLR-006.4 / LLR-008.1 | The 256 MB cap bounds the FILE, not the decoded structure — a small well-formed file can declare hundreds of millions of `new_bytes` ints → multi-GB in memory. |
| S-002 | major | §5.5 / OQ-V3 / LLR-006.2 | `RecursionError` on deeply-nested JSON is deferred to a non-normative "checkpoint"; it is a `RuntimeError`, not a `JSONDecodeError`, so it escapes a `JSONDecodeError`-only catch. |
| S-003 | major | LLR-007.2 | LLR-007.2 specifies only the memory-field file CONTENT, no write-path safety clause — the same shape as the batch-03 S-001 blocker, for one of the three files this batch writes. |
| S-004 | minor | LLR-005.4 / C-10 | `copy_into_workarea` is a file-COPY primitive; the unified writer has in-memory JSON — state the serialize-to-temp-then-copy adaptation. |
| S-005 | minor | LLR-006.3 / A-6 | `resolve_input_path` does NOT reject reparse points; A-6 / §5.5 wording overstates it — correct it and state the read-through-symlink threat-model decision. |
| S-006 | minor | LLR-002.2 / LLR-008.1 / LLR-008.3 | No clause forbids `ValidationIssue` messages echoing raw firmware `new_bytes` content into the 5 MB rotating log. |
| S-007 | informational | — | Auth / authz N/A (local single-user TUI) — verified, no action. |

**Counts: 1 blocker · 7 majors · 14 minors · 1 informational = 22 entries.**

---

## Architect findings

### Summary
- blockers: 1
- majors: 4
- minors: 2
- one-line verdict: pass-with-fixes

### Findings

#### A-1 — The "reuse the batch-03 writer unchanged" export path is not callable [BLOCKER]
- **Target:** LLR-007.1 / HLR-007 / C-1
- **Observation:** The batch-03 CDFX writer's entry point — the one C-1 and
  LLR-007.1 mandate be reused unchanged — has the signature
  `write_cdfx_to_workarea(change_list, resolution: ResolutionResult, base_dir,
  file_name)`: `resolution` is a **mandatory positional argument**, a typed
  `ResolutionResult` carrying the parameter entries resolved against the loaded
  A2L. The batch-04 unified change-set, per A-7 / LLR-004.1 / LLR-005.2, models
  the parameter half as a **plain `ChangeList`** — a serialization of
  `ChangeListEntry` fields with **no `ResolutionResult`** attached. The unified
  file format (LLR-005.2) deliberately does not carry resolution state. So at
  selective-export time the coordinator holds a bare `ChangeList` and has
  nothing to pass as the writer's mandatory second argument.
- **Why it matters:** This is not a style nit — it makes HLR-007's central
  deliverable **unimplementable as worded**. C-1 forbids modifying the writer
  signature; LLR-007.1 requires calling it; the unified set does not have the
  argument it requires. An implementer following the requirements literally
  would hit a `TypeError` at the export call and have no in-spec way to resolve
  it. The reuse contract — the load-bearing decision of the whole batch — is
  broken at the seam.
- **Recommended fix (RESOLUTION CHOSEN — option (a)):** The export coordinator
  **re-resolves the parameter `ChangeList` against the currently loaded A2L
  just before calling the writer**, using the batch-03 `resolve_against_a2l`
  path (mirroring how `cdfx_service` resolves before a CDFX write), producing a
  proper typed `ResolutionResult` / resolved CDFX. Concretely:
  - **Amend LLR-007.1** so it states the coordinator re-resolves the parameter
    half against the loaded A2L immediately before invoking
    `write_cdfx_to_workarea`, then passes the resulting `ResolutionResult` —
    the writer is still called unchanged (C-1 honored), it is simply fed a
    freshly-resolved argument.
  - **Add a new LLR under HLR-007** for the export-time re-resolution step (its
    inputs: the parameter `ChangeList` + the loaded A2L; its output: a
    `ResolutionResult`; its no-A2L behaviour: mirror `unresolved-no-a2l`,
    collect-don't-abort, no raise).
  - **Widen LLR-004.1 / A-7** so the parameter half is described as "a
    `ChangeList` that is re-resolved at export time" — not a bare list with
    nothing else around it. The unified file still stores only the
    `ChangeList`; resolution is a transient, export-time computation.
  - This keeps the batch-03 writer literally unchanged (C-1), keeps the unified
    file format resolution-free (LLR-005.2), and reuses the existing
    `resolve_against_a2l` / `cdfx_service` machinery rather than inventing a
    new path.

#### A-2 — On-disk encoding of the memory-field half is unpinned (OQ-V1) [major]
- **Target:** OQ-V1 / LLR-001.3 / LLR-005.3
- **Observation:** LLR-001.3 keys a memory-change entry by its integer
  `address`; LLR-005.3 requires the address "represented so a reader recovers
  the exact integer address" but does **not pin the on-disk shape**. §5.8 OQ-V1
  flags this as non-blocking and only *recommends* a shape. JSON object keys are
  strings — if a writer serialises the memory-field half as a `{address: bytes}`
  object, every address becomes a string key and the reader must re-parse it,
  forcing an undocumented hex-vs-decimal ambiguity between writer and reader.
- **Why it matters:** An unpinned wire format is a specification gap, not a
  Phase-3 detail — the round-trip TC-025 would catch a *mismatch* but cannot
  catch an *ambiguity that both sides happen to agree on by accident*. The
  contract must fix the encoding now.
- **Recommended fix:** Resolve OQ-V1 **normatively** in LLR-005.3: the
  memory-field half SHALL be a **JSON array of objects**, each object carrying
  `address` as an **integer-valued field** (a JSON number), **not** as a JSON
  object key. In-app dict-keying by address (LLR-001.3 identity) stays fine —
  it is the *on-disk* shape being pinned. Update §5.8 to record OQ-V1 as
  resolved.

#### A-3 — `partial` underspecified for a gap-spanning entry (OQ-V2) [major]
- **Target:** LLR-002.1 / OQ-V2
- **Observation:** LLR-002.1 defines `partial` as "overlaps but is not
  contained" in *one* range. An entry whose byte run spans a gap and touches
  **two** loaded ranges is, read strictly, `partial` against each — the LLR
  does not say whether that yields one status or two, one issue or two. §5.8
  OQ-V2 flags it as non-blocking and notes TC-005 / TC-006 *assume* one status
  / one warning.
- **Why it matters:** A test that depends on an unstated assumption is not
  traceable. The status field and the issue count for this case must be
  normative, or TC-005 / TC-006 cannot be reviewed in Phase 4.
- **Recommended fix:** Resolve OQ-V2 in LLR-002.1: an entry whose addressed
  byte range touches **more than one** loaded range (spanning a gap) SHALL
  receive the **single status `partial`** and SHALL produce **exactly one**
  `ValidationIssue` — one entry, one status, one issue. Update §5.8 to record
  OQ-V2 as resolved.

#### A-4 — LLR-002.4 bundles two opposite-semantics concerns [major]
- **Target:** LLR-002.4
- **Observation:** LLR-002.4's single `shall` statement carries two rules with
  **opposite failure semantics**: (1) inter-entry **overlap** between two
  distinct start addresses → append one warning `ValidationIssue`,
  collect-don't-abort, never raise; (2) a **malformed `new_bytes` run** (a value
  outside 0–255, or an empty run) → the model **rejects construction by raising
  `ValueError`**. One LLR cannot cleanly trace to a TC when half of it forbids
  raising and the other half mandates raising.
- **Why it matters:** Compound LLRs break one-LLR-one-intent traceability; a
  Phase-4 reviewer cannot record a single pass/fail verdict against
  LLR-002.4 because the two halves are verified by opposite assertions
  (`pytest.raises` vs. a no-raise + issue-present check). This is the same
  defect qa-reviewer raises as Q-02.
- **Recommended fix:** **Split LLR-002.4 into two LLRs:**
  - **LLR-002.4** — inter-entry overlap → append one warning `ValidationIssue`,
    collect-don't-abort (the §6.2.1 OQ-8 "flagged, never merged/rejected"
    policy).
  - **LLR-002.5 (new)** — malformed `new_bytes` (a byte value negative, a byte
    value `> 255`, or an empty run) → the model rejects construction by raising
    `ValueError`.
  The LLR total moves **34 → 35**; the §1.5, §3, §4 and §5 tallies
  (`4+4+3+5+4+4+4+3+3 = 34` → the LLR-002.x group `4 → 5`, total `35`) and the
  §5.9 acceptance-gate denominator must all be updated.

#### A-5 — `ValidationIssue.artifact` as the per-half origin tag is not stated [minor]
- **Target:** LLR-007.4
- **Observation:** LLR-007.4 requires the export coordinator to "report which
  half each issue came from", and LLR-008.3 already says every issue's
  `artifact` field "identifies the producing concern". But LLR-007.4 does not
  name `artifact` as *the* mechanism — leaving a Phase-3 implementer free to
  reach for a new field or a `ValidationIssue` model change, which C-5 forbids.
- **Recommended fix:** Add a one-line note to LLR-007.4 that the per-half origin
  tagging SHALL be carried on the existing `ValidationIssue.artifact` field
  (e.g. `artifact="param-half"` / `artifact="memory-half"`) — no model change,
  consistent with C-5 and LLR-008.3.

#### A-6 — "33 active TC / 34 IDs (TC-014 reserved)" wording is not uniform [minor]
- **Target:** §1.5 / §3 / §5.7
- **Observation:** The document describes the test-case catalogue
  inconsistently — §5.7 says "33 active test cases ... plus TC-014
  reserved/unallocated", §5.2 still carries a `TC-014?` marker in the HLR-004
  row, and §1.5 / §3 do not mention the reserved slot at all. A reader
  reconciling the counts must cross-reference three sections.
- **Recommended fix:** Make the phrasing uniform — "**33 active test cases over
  34 IDs (TC-001…TC-034); TC-014 is a reserved/unallocated slot**" — and use
  that exact wording everywhere the catalogue size is stated. (Couples with
  Q-04, which removes the stale `TC-014?` marker.)

---

## QA-reviewer findings

### Summary
- blockers: 0
- majors: 2
- minors: 7
- one-line verdict: pass-with-fixes

> Q-01, Q-05 and Q-10 were checked and found **clean** — recorded at the end of
> this section, no finding row.

### Findings

#### Q-02 — LLR-002.4 compound LLR / TC-008 negative-byte traceability [major]
- **Target:** LLR-002.4 / TC-008
- **Observation:** Same root defect as A-4 — LLR-002.4 bundles the
  collect-don't-abort overlap rule and the `ValueError`-raising malformed-byte
  rule into one statement, so TC-008 (which covers LLR-002.4) is asked to
  verify two opposite behaviours under one TC. Separately, **TC-008's
  assertion** exercises a **negative** byte value (`constructing an entry with
  a negative byte value ... raises ValueError`) but the LLR-002.4 text only
  says "a value outside 0–255" — the negative case is implied, not explicit, so
  the TC assertion does not trace cleanly to normative wording.
- **Why it matters:** A TC must trace to an explicit normative clause; "outside
  0–255" is arguably ambiguous about negatives (a reader could read it as
  "> 255"). The test asserting on negatives without a clause that names them is
  an untraceable assertion.
- **Recommended fix:** Split LLR-002.4 per A-4 (→ LLR-002.4 overlap +
  LLR-002.5 malformed). In the new **LLR-002.5**, state the rejected cases
  **explicitly**: "a byte value that is **negative**, **greater than 255**, or
  an **empty** `new_bytes` run". TC-008's three `ValueError` arms then each
  trace to an explicit phrase.

#### Q-03 — `memory_change_factory` overlap variant is underspecified [major]
- **Target:** §5.4 / TC-008
- **Observation:** §5.4's `memory_change_factory` lists "two entries whose
  addressed ranges overlap" as a variant, but does not name concrete start
  addresses. LLR-001.3 keys entry **identity on `address`** — two entries built
  at the *same* start address would **collapse into one** (in-place update), so
  a naively-built "overlap" fixture could silently produce a single entry and
  TC-008's overlap assertion would test nothing.
- **Why it matters:** An overlap test needs two **distinct** start addresses
  whose byte runs **intersect** — otherwise the identity rule eats the second
  entry and the overlap warning is never provoked. The fixture spec must pin
  this.
- **Recommended fix:** Specify the overlap variant with concrete distinct
  start addresses and intersecting runs — e.g. **`address 0x100 len 8` +
  `address 0x104 len 8`** (distinct identities, ranges `[0x100,0x108)` and
  `[0x104,0x10C)` intersect). State explicitly in §5.4 that the two entries
  have distinct `address` keys so the LLR-001.3 identity rule does not collapse
  them.

#### Q-04 — Stale `TC-014?` cross-reference on the §5.2 HLR-004 row [minor]
- **Target:** §5.2
- **Observation:** The §5.2 per-HLR table's HLR-004 row lists
  "TC-012, TC-013, TC-014?, TC-026, TC-027". TC-014 is a reserved/unallocated
  slot (§5.7) — the `TC-014?` marker is a leftover. HLR-004 is **fully
  covered** by TC-012 / TC-013 / TC-026 / TC-027 without it.
- **Recommended fix:** Remove the `TC-014?` token from the §5.2 HLR-004 row.
  (Couples with A-6 — the uniform wording.)

#### Q-06 — TC-025 round-trip equality predicate omits the status field [minor]
- **Target:** TC-025
- **Observation:** TC-025 asserts structural equality of the parameter
  `(parameter_name, array_index)` keys and values and the memory-field
  `address` keys and `new_bytes`, but does **not state** whether the
  validation/resolution-status field is part of the equality predicate. The
  unified file may or may not persist status (per A-2 and LLR-005.2 it carries
  resolution-status on parameter entries; the memory half carries a validation
  status).
- **Recommended fix:** Pin the predicate explicitly in TC-025 — **recommended:
  the validation/resolution status is re-derived on read (not part of the
  equality assertion), and is asserted separately** (a freshly-read entry
  re-validates against the loaded image / re-resolves against the A2L). State
  this so the round-trip predicate is unambiguous.

#### Q-07 — Well-formed-but-wrong-shape JSON trips no rule [minor]
- **Target:** TC-020 / LLR-006.2
- **Observation:** LLR-006.2 / TC-020 cover **non-well-formed** JSON
  (`MF-JSON-PARSE`); LLR-008.1 covers **per-entry** structural rules. A document
  that is **valid JSON but the wrong shape** — `[]`, `42`, `"foo"`,
  `{"foo": 1}` with no parameter/memory halves — falls between them: `json.load`
  succeeds (no `MF-JSON-PARSE`) and there are no entries to fail a per-entry
  rule. A reader indexing `doc["memory"]` would raise an uncaught `KeyError`.
- **Recommended fix:** Add a TC (use the **reserved TC-014 slot** — fills it
  meaningfully) and an **`MF-BAD-STRUCTURE`** rule code: a well-formed JSON
  document missing the expected top-level halves SHALL emit one
  `MF-BAD-STRUCTURE` issue and return an empty unified change-set — the reader
  SHALL NOT raise `KeyError`. Add a clause to LLR-006.2 (or LLR-008.1) for the
  shape check.

#### Q-08 — Missing gap-spanning fixture variant for the multi-range `partial` case [minor]
- **Target:** §5.4
- **Observation:** Once OQ-V2 is resolved (A-3) the multi-range-spanning
  `partial` case becomes a normative behaviour, but `memory_change_factory`
  has no fixture variant that produces an entry spanning a gap and touching two
  ranges.
- **Recommended fix:** After A-3 lands, add a `memory_change_factory` variant —
  an entry whose run starts inside range 1, crosses the gap, and ends inside
  range 2 — and cover it in TC-005 / TC-006.

#### Q-09 — Adversarial-float inheritance not noted on `unified_changeset_factory` [minor]
- **Target:** §5.4
- **Observation:** §5.5 relies on the three adversarial IEEE floats (`0.1`, the
  `5e-324` denormal, a 17-significant-digit value) for the TC-025 exact-`==`
  round-trip. §5.4's `unified_changeset_factory` says it composes a
  `change_list_factory` parameter half but does not state the adversarial
  floats are **inherited** from the batch-03 `change_list_factory` — leaving it
  unclear whether the factory must add them.
- **Recommended fix:** Add a note to the §5.4 `unified_changeset_factory` row
  that the adversarial floats are **inherited from the batch-03
  `change_list_factory`** (precondition A-1 / RK-2 — batch-03 must be merged and
  green). No new fixture work; just record the dependency.

#### Q-11 — TC-018 reparse-point arm needs a deterministic mechanism [minor]
- **Target:** TC-018 / LLR-005.4
- **Observation:** TC-018's reparse-point rejection arm asserts a symlink /
  NTFS-reparse-point write target is rejected — but creating a symlink on a CI
  image without the privilege fails, and a silent `pytest` skip would let the
  arm pass **without exercising the rejection path**. The batch-03 closure
  finding CV-03 raised the identical issue for TC-036.
- **Recommended fix:** Give the reparse-point arm a **deterministic
  mechanism** — either an injectable reparse-point probe the test can stub
  (mirroring the §5.4 size-probe seam), or an explicit `skipif` / `xfail` with
  a **recorded reason** so a skip is visible, never silent. Reuse the batch-03
  approach.

#### Q-12 — Non-printable-byte ASCII placeholder character is unpinned [minor]
- **Target:** LLR-003.2
- **Observation:** LLR-003.2 says a non-printable byte is shown as "a single
  fixed placeholder character" and the rationale gives "for example `.`" — the
  character is **not pinned**. TC-010 asserts "renders as the fixed placeholder
  character" without naming it, so two implementations could disagree (`.` vs
  `?` vs `·`) and both pass.
- **Recommended fix:** Pin the placeholder character in LLR-003.2 (recommend
  `.` — `0x2E`, the conventional hex-dump placeholder) and have TC-010 assert
  on that exact character. Add the placeholder to the **§5.8 "to pin in
  Phase 3" list** alongside the `MF-*` code spellings.

### Clean — no finding (recorded)

- **Q-01 — LLR / TC arithmetic.** The §1.5 / §3 / §4 LLR tally
  (`4+4+3+5+4+4+4+3+3 = 34`) and the §5.7 / §5.9 TC tally (33 active + TC-014
  reserved over 34 IDs) were re-summed and are **internally consistent as
  written**. (Note: A-4 will *change* the LLR total to 35 — that is a
  consequence of the split, not a pre-existing arithmetic error.)
- **Q-05 — collect-don't-abort coverage.** §5.9 item 6 plus TC-006 / TC-007 /
  TC-020 / TC-023 / TC-034 cover the no-raise contract for both the
  memory-change validator and the unified reader — no gap.
- **Q-10 — round-trip strength.** TC-025's exact-`==` predicate plus the
  adversarial-float fixtures (subject to Q-09's inheritance note) is a genuine,
  non-tautological correctness check — no weakness of the batch-03 Q-03 kind.

---

## Security-reviewer findings

### Summary
- blockers: 0
- majors: 3
- minors: 3
- informational: 1
- one-line verdict: OK-with-mitigations

### Findings

#### S-001 — The 256 MB cap bounds the file, not the decoded structure [major]
- **Target:** LLR-001.1 / LLR-006.4 / LLR-008.1
- **Observation:** LLR-006.4's 256 MB pre-parse size cap
  (`DEFAULT_COPY_SIZE_CAP_BYTES`) bounds the **on-disk file**. It does **not**
  bound the **decoded in-memory structure**. A well-formed unified file
  comfortably under 256 MB can declare a memory-field entry whose `new_bytes`
  array holds **hundreds of millions of integers**, or declare millions of
  memory-field entries — JSON integers and array overhead expand several-fold
  once parsed into Python `int` objects and lists, reaching **multiple GB in
  memory** from a sub-cap file. LLR-001.1 puts no ceiling on `new_bytes` length;
  no LLR caps the entry count.
- **Why it matters:** A resource-exhaustion vector that the existing size cap
  does **not** catch — the file passes the LLR-006.4 gate, then the reader
  builds a multi-GB structure. The unified reader is an external-input surface
  (§5.5 hand-off acknowledges this).
- **Recommended fix:** Add an LLR (under HLR-006 / HLR-008) mandating a
  **documented ceiling on the memory-field entry count** AND on **any single
  `new_bytes` run length**, enforced **during reader reconstruction**, emitting
  one `MF-*` issue (e.g. **`MF-ENTRY-LIMIT`**) per breach,
  **collect-don't-abort** (truncate / drop the offending entry, keep the rest,
  never raise). Add a TC exercising an over-ceiling entry count and an
  over-ceiling `new_bytes` run.

#### S-002 — `RecursionError` on deeply-nested JSON is non-normative and escapes the catch [major]
- **Target:** §5.5 / OQ-V3 / LLR-006.2
- **Observation:** §5.5 and §5.8 OQ-V3 defer deeply-nested-JSON handling to a
  "Phase-2 review checkpoint" with **no normative LLR and no TC**. Two facts
  make this insufficient: (1) the 256 MB size cap does **not** bound nesting
  depth — roughly 100,000 nesting levels is only ~200 KB on disk, far under the
  cap; (2) stdlib `json` parses nesting by C recursion and raises
  **`RecursionError`**, which is a **`RuntimeError`** — it is **not** a
  `json.JSONDecodeError`. A reader whose `except` clause catches only
  `json.JSONDecodeError` (the natural reading of LLR-006.2) lets `RecursionError`
  **escape uncaught**, crashing the load and **violating the collect-don't-abort
  contract** (HLR-006, C-5).
- **Why it matters:** A documented external-input surface with a known crash
  vector and no normative requirement. "Confirm at a checkpoint" is not a
  verifiable contract — Phase 4 has nothing to assert against.
- **Recommended fix:** **Promote OQ-V3 to a normative clause.** Amend LLR-006.2
  (or add **LLR-006.5**): the unified reader SHALL treat a deep-nesting parse
  failure / `RecursionError` as **one `MF-JSON-PARSE` issue** (or a dedicated
  **`MF-NESTING`** code), return an **empty unified change-set**, and **not
  raise** — the reader's exception handling SHALL catch `RecursionError` (a
  `RuntimeError`), not only `json.JSONDecodeError`. Add a TC with a small,
  deeply-nested fixture (programmatically generated, a few hundred KB) asserting
  the issue + no-raise. Update §5.8 to record OQ-V3 as resolved.

#### S-003 — LLR-007.2 specifies the memory-field file content but no write-path safety [major]
- **Target:** LLR-007.2
- **Observation:** LLR-007.2 (selective export produces the memory-field JSON
  file) specifies only the file **content** — format-id, version, the
  memory-change entries. It carries **no write-path safety clause** — no
  containment, no reparse-point rejection, no collision handling. This is
  exactly the shape of the **batch-03 S-001 blocker** (a file written to disk
  with no path-safety LLR), reproduced here for **one of the three files this
  batch writes**. LLR-005.4 hardens the unified-file write and LLR-007.3
  mentions containment for the export pair, but LLR-007.2 — the LLR that
  *specifies the memory-field file* — has no such clause of its own.
- **Why it matters:** A file artifact written to disk with no path-safety
  specification is an unscoped write surface. C-10 mandates the `workspace.py`
  containment path; LLR-007.2 must say so explicitly rather than leaving it to
  LLR-007.3's looser wording.
- **Recommended fix:** Add an explicit clause to LLR-007.2: the memory-field
  file write SHALL resolve under `.s19tool/workarea/` via the `workspace.py`
  containment path, SHALL reject reparse-point traversal, and SHALL dedup-suffix
  on a name collision — **mirroring LLR-005.4 verbatim**. Extend **TC-029** to
  assert the produced file's resolved path is under `.s19tool/workarea/`.

#### S-004 — `copy_into_workarea` is a file-copy primitive; the writer has in-memory JSON [minor]
- **Target:** LLR-005.4 / C-10
- **Observation:** LLR-005.4 (and the LLR-007.2 fix above) tell the writer to
  reuse `copy_into_workarea` for containment. But `copy_into_workarea` is a
  **file-COPY** primitive — it takes an **existing source file** and copies it
  into the work area. The unified writer and the memory-field writer hold
  **in-memory JSON**, not a source file. The requirement names the primitive
  without stating the adaptation.
- **Recommended fix:** State the adaptation in LLR-005.4 / LLR-007.2: the writer
  **serialises the JSON to a transient file under `.s19tool/workarea/temp/`**,
  then calls `copy_into_workarea` to place it at the target — reusing the
  hardened primitive **unchanged**. Do **not** re-inline containment / reparse
  checks into a fresh write path — **C-10 forbids a new write path**.

#### S-005 — `resolve_input_path` does not reject reparse points; A-6/§5.5 overstate it [minor]
- **Target:** LLR-006.3 / A-6
- **Observation:** Assumption A-6 and the §5.5 security hand-off describe
  `resolve_input_path` as providing "reparse-point / traversal handling" on the
  **read** path. In fact `resolve_input_path` only **resolves** a user-typed
  path (cwd + repo-root walk) and checks `exists()` — it does **not** reject
  symbolic links or NTFS reparse points. The requirements wording **overstates**
  the read-side guarantee.
- **Recommended fix:** Correct the A-6 and §5.5 wording — `resolve_input_path`
  is path **resolution**, not reparse-point rejection. Then **decide the
  read-through-symlink question explicitly**: recommended — **accept
  read-through-symlink as in-threat-model** for a local single-user tool, and
  *state that decision*. The real security boundary is the **write side**
  (LLR-005.4 / LLR-007.2 containment) plus the **S-001 / S-002 input bounds** —
  a read-side symlink on a single-user offline machine is not a meaningful
  escalation. (This mirrors the batch-03 closure note CV-01 — "resolution" not
  "containment".)

#### S-006 — No clause forbids issue messages echoing raw `new_bytes` content [minor]
- **Target:** LLR-002.2 / LLR-008.1 / LLR-008.3
- **Observation:** LLR-002.2, LLR-008.1 and LLR-008.3 describe
  `ValidationIssue` messages for memory-field findings but **no clause forbids
  the message string echoing the raw `new_bytes` content verbatim**. A
  memory-change entry's `new_bytes` is raw firmware bytes the engineer intends
  to write; an issue message that inlines them would carry proprietary firmware
  content into the **5 MB rotating log** (`.s19tool/logs/s19tui.log`).
- **Recommended fix:** Add a constraint (fold into **C-9**, or add a clause to
  LLR-008.3): a `ValidationIssue` message for a memory-field finding SHALL
  reference the entry's **`address` and a count / summary** of the byte run
  (e.g. "8 bytes"), **NOT the raw byte content verbatim**. This mirrors the
  batch-03 S-007 reinforcement.

#### S-007 — Auth / authorization out of scope, verified [informational — no action]
- **Target:** —
- **Observation:** Authentication and authorization are **N/A** — `s19_app` is
  a **local, single-user, offline desktop TUI**; this batch adds no network
  surface, no multi-user surface, no credential handling. The unified file and
  memory-field file are local work-area artifacts. **Verified — no action
  required.**
- **Recommended fix:** None.

### Out-of-scope confirmation (per this app's threat model)
- **Auth / authorization:** N/A — single-user offline desktop TUI (S-007).
- **Network egress / DNS / TLS:** N/A — no network surface; the batch adds
  none. Unlike batch-03's XML path, stdlib `json` has **no entity-expansion /
  DOCTYPE / external-entity** attack surface — the billion-laughs / `SYSTEM`
  vectors of batch-03 have **no batch-04 equivalent** (correctly noted in §5.5).
- **Secrets / credentials:** N/A — no keys, tokens or `.env` are read/written.
- **Residual external-input surface:** the unified-file / memory-field-file
  **read path** — bounded by LLR-006.4 (file size), and *to be* bounded by
  S-001 (decoded-structure size) and S-002 (nesting depth). With S-001 and
  S-002 closed, the read-path resource surface is fully bounded.

---

## Normative `shall` / `should` discipline — result

**Clean.** No `should` modal appears inside any HLR or LLR `Statement:` bullet
in Sections 3 and 4. The strict IEEE 830 + EARS convention declared in the
document preamble — `shall` only inside HLR/LLR statements, `should` only in
informative voice — is honored throughout the requirements body.

`should` appears only where the convention permits it: inside
`Rationale (informative)` and `Acceptance criteria (informative)` blocks, the
§5 validation-strategy prose, the §6.2.1 decision table, and the §6.3 risk
table. No stray normative `shall` / `shall not` was found in informative voice.

No discipline finding is raised. The blocker and majors above are about the
**content** of the normative statements — an uncallable reuse contract, an
unpinned wire format, an underspecified status, a compound LLR, two missing
bounds, a missing write-path clause — **not** about `shall` / `should` modal
discipline, which is clean.

---

## Verdict

**blockers-present — the dev-flow workflow forces a rollback to Phase 1.**

The aggregate is **1 blocker · 7 majors · 14 minors · 1 informational**. The
dev-flow Phase 2 spec forces a rollback to Phase 1 whenever **any**
blocker-severity finding is open. One is open — **A-1** (the "reuse the
batch-03 CDFX writer unchanged" export path is not callable: the writer needs a
mandatory `resolution: ResolutionResult` argument the unified change-set does
not carry). Per-reviewer verdicts: architect `pass-with-fixes`, qa-reviewer
`pass-with-fixes` (0 blockers), security-reviewer `OK-with-mitigations`
(0 blockers).

`01-requirements.md` therefore **cannot advance to Phase 3**. It returns to
**Phase 1 for an iteration 2** that closes the A-1 blocker, all 7 majors, and
all 14 minors, after which a closure re-review confirms the fixes.

A-1 is **not** an implementation-impossibility of the kind that would force a
re-scope — it is a specification defect with a clean fix, and the fix is
**already chosen** (option (a): re-resolve the parameter `ChangeList` against
the loaded A2L at export time, via the batch-03 `resolve_against_a2l` path).
**No product-owner decision is pending** — unlike batch-03's S-001, the A-1
resolution does not change a user-facing contract; it is an internal
export-coordinator step. Iteration 2 is therefore a single focused editorial
pass with no decision gate ahead of it.

---

## Recommended Disposition

The 22 findings resolve into: a single Phase 1 iteration-2 pass that closes the
1 blocker + all 7 majors + all 14 minors, no product decision pending, and one
no-action item.

### The A-1 blocker — resolution fixed as option (a)

**A-1 needs no product decision** — the resolution is already chosen.
**Option (a):** the **export coordinator re-resolves the parameter
`ChangeList` against the currently loaded A2L immediately before calling
`write_cdfx_to_workarea`**, using the batch-03 `resolve_against_a2l` path
(mirroring how `cdfx_service` resolves before a CDFX write), producing the
typed `ResolutionResult` the writer's mandatory argument requires.

This is the lowest-risk resolution: the batch-03 CDFX writer stays **literally
unchanged** (C-1 honored), the unified file format stays
**resolution-free** (LLR-005.2 unchanged — the unified file still stores only
the `ChangeList`), and the re-resolution reuses **existing batch-03 machinery**
rather than introducing new serialization. The iteration-2 edits for A-1:

- **Amend LLR-007.1** — the coordinator re-resolves the parameter half against
  the loaded A2L immediately before invoking `write_cdfx_to_workarea`, then
  passes the resulting `ResolutionResult`; the writer is still called unchanged.
- **Add a new LLR under HLR-007** for the export-time re-resolution step
  (inputs: parameter `ChangeList` + loaded A2L; output: `ResolutionResult`;
  no-A2L behaviour: mirror `unresolved-no-a2l`, collect-don't-abort, no raise).
- **Widen LLR-004.1 / A-7** — the parameter half is a `ChangeList`
  **re-resolved at export time**, not a bare list with nothing else.

### Fix in Phase 1 iteration 2 — all 7 majors

All majors are closable in the **same focused iteration** as A-1:

- **A-2** — resolve OQ-V1 normatively in LLR-005.3: the memory-field half is a
  JSON array of objects with `address` as an integer-valued field, never a JSON
  object key.
- **A-3** — resolve OQ-V2 in LLR-002.1: a gap-spanning entry touching two
  ranges gets the single status `partial` and exactly one `ValidationIssue`.
- **A-4 / Q-02** (one defect) — split LLR-002.4 into **LLR-002.4** (inter-entry
  overlap → collect-don't-abort) + **LLR-002.5** (malformed `new_bytes` —
  negative, `> 255`, or empty → `ValueError`); update every LLR tally
  **34 → 35** (§1.5, §3, §4, §5.9).
- **Q-03** — pin the `memory_change_factory` overlap variant with concrete
  distinct start addresses and intersecting runs (e.g. `0x100 len 8` +
  `0x104 len 8`).
- **S-001** — add an LLR capping memory-field entry count and single
  `new_bytes` run length, enforced during reader reconstruction, emitting an
  `MF-ENTRY-LIMIT` issue collect-don't-abort; add a TC.
- **S-002** — promote OQ-V3 to a normative clause (amend LLR-006.2 or add
  LLR-006.5): a deep-nesting / `RecursionError` failure is one
  `MF-JSON-PARSE` / `MF-NESTING` issue, empty change-set, no raise; the
  exception handling catches `RecursionError`; add a small deeply-nested TC.
- **S-003** — add an explicit write-path safety clause to LLR-007.2 (containment
  under `.s19tool/workarea/`, reparse-point rejection, dedup-suffix), mirroring
  LLR-005.4; extend TC-029 to assert the path.

### Fold into the same iteration — all 14 minors

The minors are one-to-few-line edits with no design uncertainty and fold into
iteration 2 alongside the majors: **A-5, A-6, Q-04, Q-06, Q-07, Q-08, Q-09,
Q-11, Q-12, S-004, S-005, S-006**. Several couple to a major or to each other
and are closed by the same edit:

- **A-6 ↔ Q-04** — the uniform "33 active TC / 34 IDs (TC-014 reserved)"
  wording, and the removal of the stale §5.2 `TC-014?` marker.
- **Q-07** — fills the reserved **TC-014** slot meaningfully (the
  well-formed-but-wrong-shape `MF-BAD-STRUCTURE` case).
- **Q-08 ↔ A-3** — the gap-spanning fixture variant becomes addable once OQ-V2
  is resolved.
- **S-004 ↔ S-003 / LLR-005.4** — the serialize-to-temp-then-`copy_into_workarea`
  adaptation applies to both write-path LLRs.
- **Q-11** — the deterministic reparse-point mechanism (mirrors batch-03 CV-03).
- **Q-12** — pinning the ASCII placeholder character, added to the §5.8
  Phase-3 to-pin list alongside the `MF-*` code spellings.

### No action — S-007

**S-007** confirms auth / authorization is N/A for a local single-user offline
TUI — verified, recorded only, no edit required.

### Suggested sequencing

1. **No product decision needed** — the A-1 resolution is fixed as option (a);
   iteration 2 can start immediately.
2. One **Phase 1 iteration 2** applies the A-1 edits (amend LLR-007.1, add the
   re-resolution LLR, widen LLR-004.1 / A-7) plus all 7 majors and all 14
   minors to `01-requirements.md`. The LLR total moves **34 → 35** (A-4 split;
   the new HLR-007 re-resolution LLR may push it further — re-tally on edit).
3. A **closure re-review** (parallel light pass — architect + qa-reviewer +
   security-reviewer) confirms every finding is closed, re-checks the corrected
   LLR / TC tallies, and verifies OQ-V1 / OQ-V2 / OQ-V3 are recorded as
   resolved in §5.8.
4. Only after the closure pass returns **0 blockers / 0 majors** does the batch
   advance to Phase 3.

---

*Generated by parallel review pass: `architect` + `qa-reviewer` +
`security-reviewer`. Consolidated by `architect`.*

---

## Phase 2 — Iteration 2: Closure Verification

**Phase:** 2 — Cross-agent review
**Iteration:** 2 (closure pass)
**Date:** 2026-05-21
**Source artifact under review:** [`.dev-flow/2026-05-21-batch-04/01-requirements.md`](01-requirements.md) — as revised in **Phase 1 iteration 2**
**Reviewers:** `architect`, `qa-reviewer`, `security-reviewer` (parallel closure pass)

### Result

All **22** Phase-2 iteration-1 findings (`A-1` blocker, `A-2`..`A-6`,
`Q-02`..`Q-12`, `S-001`..`S-007`) were re-checked against `01-requirements.md`
as revised in Phase 1 iteration 2 and are **CLOSED**.

Three reviewers ran a parallel closure pass. Closure verdicts:

| Reviewer | Closure verdict |
|---|---|
| architect | `all-closed-clean` |
| security-reviewer | `all-closed-clean` |
| qa-reviewer | `all-closed-new-issues` |

The **A-1 blocker** — the batch-03 CDFX writer `write_cdfx_to_workarea`
requires a mandatory `resolution: ResolutionResult` argument that the unified
change-set does not carry — is **confirmed resolved**. The new
**LLR-007.5** (export-time re-resolution of the parameter `ChangeList` against
the loaded A2L) makes `write_cdfx_to_workarea` callable with the batch-03
writer **literally unchanged** (C-1 honored): the coordinator re-resolves and
feeds the writer a freshly-built `ResolutionResult`.

### Consolidated Phase 2 verdict

**pass — 0 blockers, 0 majors.**

With every iteration-1 finding closed and the A-1 blocker confirmed resolved,
`01-requirements.md` clears the dev-flow Phase 2 gate. **Final requirement
set: 5 US / 9 HLR / 37 LLR / 37 TC.**

### New observations from the closure scan

All three are **minor** — none gates the Phase 2 → Phase 3 advance.

#### CV-01 — TC-010 does not assert the exact placeholder character [minor]
- **Target:** NF-1 / TC-010 / LLR-003.2
- **Observation:** LLR-003.2 now pins the non-printable-byte placeholder
  character to `.` (`0x2E`), but **TC-010's expected result still reads
  "renders as the fixed placeholder character"** without naming the literal
  `.`. TC-010 therefore does not assert the pinned character — an engineering
  rule-9 weakness: the test cannot fail if the placeholder character drifts
  (`.` → `?` → `·` would still pass).
- **Recommended fix:** In Phase 3 increment 1, amend TC-010's expected result
  so it asserts the **exact character `.`** (`0x2E`), tracing to the pinned
  LLR-003.2 wording.

#### CV-02 — §5.2 HLR-008 row omits TC-020 [minor]
- **Target:** NF-3 / §5.2 HLR-008 row
- **Observation:** TC-020 covers LLR-006.2, which is parented to **both**
  HLR-006 and HLR-008. The §5.2 per-HLR coverage table's **HLR-008 row omits
  TC-020**. HLR-008 is still covered by its other test cases — the defect is a
  per-HLR table that **under-reports**, not a genuine coverage gap.
- **Recommended fix:** Add **TC-020** to the §5.2 HLR-008 row.

### NF-2 — already resolved (recorded closed)

The qa-reviewer closure pass raised **NF-2** — a stale TC count in §1.5 / §3
(the iteration-1 catalogue wording "33 active TC / 34 IDs"). This is
**already resolved**: the architect closure pass corrected §1.5 and §3 to
**"37 active TC / 37 IDs"** in parallel, consistent with the final
5 US / 9 HLR / 37 LLR / 37 TC set. **Recorded closed — no further action.**

### Disposition

`CV-01` and `CV-02` are **minor / editorial** — fold both into **Phase 3
increment 1**. **Neither blocks** advancing to Phase 3. `NF-2` is closed.
The batch advances to **Phase 3**.

---

*Closure verification by parallel pass: `architect` + `qa-reviewer` +
`security-reviewer`. Consolidated by `architect`.*
