# Review — s19_app — 2026-05-21-batch-03

**Phase:** 2 — Cross-agent review
**Iteration:** 1
**Date:** 2026-05-21
**Source artifact under review:** [`.dev-flow/2026-05-21-batch-03/01-requirements.md`](01-requirements.md)
**Batch:** batch-03 — functional Patch Editor + ASAM CDFX (`.cdfx`) read/write
**Reviewers:** `architect`, `qa-reviewer`, `security-reviewer` (parallel)

---

## Aggregate summary

| Reviewer | Blockers | Majors | Minors | Informational | Verdict |
|---|---|---|---|---|---|
| architect | 0 | 3 | 6 | 0 | pass-with-fixes |
| qa-reviewer | 2 | 4 | 6 | 0 | CHANGES-REQUESTED |
| security-reviewer | 1 | 3 | 3 | 1 | BLOCK |
| **Total** | **3** | **10** | **15** | **1** | **blockers-present** |

### Consolidated verdict

**blockers-present — the dev-flow Phase 2 spec forces a rollback to Phase 1.**
Three blocker-severity findings are open (**Q-01**, **Q-02**, **S-001**). The
dev-flow workflow forces a rollback to Phase 1 whenever **any** blocker is
open, so `01-requirements.md` cannot advance to Phase 3 in its current state —
it must be revised in a **Phase 1 iteration 3** and re-reviewed.

The three blockers are not implementation-impossibility findings of the
A-03-batch-02 kind; they are **specification defects that make the artifact
unverifiable or unsafe as written**:

- **Q-01** — the document's own LLR count (`34 LLRs`) is arithmetically wrong;
  the real count is **39 LLRs**. The §5.7 reverse-traceability claim and the
  §5.9 acceptance-gate denominator are therefore both wrong — the coverage
  contract cannot be evaluated against a wrong total.
- **Q-02** — the security test case TC-027 is **non-executable**: one fixture is
  asked to carry two distinct attack payloads while the assertion expects a
  single issue, and the "no external file is read" clause has no stated
  detection mechanism.
- **S-001** — the `.cdfx` **write path has no path-containment / traversal /
  symlink / overwrite requirement**, and A-6 / OQ-3 scoped `.cdfx` out of
  `validate_project_files` without replacing the guarantees that scoping
  removed. A view-plus-data batch that writes a file to disk with no
  path-safety LLR is a real, unscoped attack/defect surface.

The 10 majors are requirement-text and test-case-text defects (wrong field
lists, missing display arms, internal value-model inconsistencies, tests that
cannot fail, missing load-path and size-bound LLRs). All 13 substantive
findings — 3 blockers + 10 majors — plus the ~15 minors are closable inside a
single Phase 1 iteration once the S-001 product decision is taken.

### `shall` / `should` discipline check

- **Clean.** No `should` modal appears inside any HLR or LLR `Statement:`
  bullet in Sections 3 and 4 — the strict IEEE 830 + EARS convention declared
  in the document preamble is honored throughout. `should` is used only in
  `Rationale (informative)` / `Acceptance criteria (informative)` blocks and
  appendix prose, where the convention permits it.
- No stray normative `shall` / `shall not` was found in informative voice.
- See the dedicated discipline-result section below.

---

## Findings table — 28 findings

> Severity: BLOCKER gates the batch; major must be fixed in the Phase 1
> iteration; minor folds into the same iteration; informational = no action.

| ID | Severity | Area | One-line |
|----|----------|------|----------|
| A-01 | major | LLR-002.1 / C-1 | "Reuse A2L parsing" field list is wrong — bare `extract_a2l_tags` has `datatype=None`; decode fields exist only post-enrichment. |
| A-02 | major | LLR-003.1 / HLR-002 | A2L `ASCII` is a `char_type`, not a `datatype` token — LLR-003.1's display-form selection has no ASCII arm. |
| A-03 | major | HLR-003 / LLR-003.1 | Internal inconsistency — "store physical value + show hex-of-unsigned-int" is undefined for non-IDENTICAL COMPU_METHODs. |
| A-04 | minor | LLR-004.2 / LLR-006.5 | `BOOLEAN` is editable + in W-INSTANCE-CATEGORY but missing from the LLR-004.2 writer category enumeration. |
| A-05 | minor | LLR-004.6 | `W-EMPTY-CHANGELIST` vs the all-unresolved case is unspecified — a 2-entry all-unresolved list emits 3 warnings. |
| A-06 | minor | LLR-005.3 | XML namespace handling — a default `xmlns` makes ElementTree return `{uri}Local` tags; literal tag match fails. |
| A-07 | minor | LLR-005.4 / TC-018 | `0b`-prefixed binary `V` notation is a Python-literal assumption not pinned by the research. |
| A-08 | minor | LLR-007.6 | Empty-state normative statement leans on external batch-02 id `R-TUI-030`; not self-contained. |
| A-09 | minor | LLR-004.3 / DD-4 | Naming collision — change-list `array_index` vs CDFX `SW-ARRAY-INDEX` are different concepts. |
| Q-01 | **BLOCKER** | §5.7 / §5.9 / header | "34 LLRs" is wrong everywhere — the real count is 39; §5.7 arithmetic and §5.9 gate denominator self-contradict. |
| Q-02 | **BLOCKER** | §5.4 `make_entity_bomb_cdfx` / TC-027 | Security oracle non-executable — one fixture carries two payloads; "no external file read" has no detection mechanism. |
| Q-03 | major | TC-024 / LLR-004.8 | Exact float `==` round-trip is tautological without an adversarial float fixture; in-memory float type unpinned. |
| Q-04 | major | TC-020 / LLR-006.2 | TC-020 never asserts a sibling valid instance still parses — an instance-tree-aborting reader would pass. |
| Q-05 | major | TC-019 | TC-019 overloaded — one TC provokes all 8 `W-*` codes; several have no stated fault-injection mechanism. |
| Q-06 | major | §5.2 HLR-007 | §5.2 introduces a "TC-027 sub-case" notion that exists nowhere else (§5.3 has no sub-case). |
| Q-07 | minor | LLR-005.4 / TC-018 | LLR-005.4 acceptance criteria omits the `0b` example TC-018 uses. |
| Q-08 | minor | TC-022 / §5.7 | TC-022's "Covers LLR" spuriously lists LLR-006.1 (already covered by TC-019). |
| Q-09 | minor | §5.4 fixtures | "Used by" column wrong — TC-024 consumes `change_list_factory`; TC-017 needs `make_variant_cdfx`/`make_tool_note_cdfx`. |
| Q-10 | minor | TC-008 / LLR-003.1 | `FLOAT16_IEEE` and large `A_UINT64` (>2^53) display unverified — no boundary case. |
| Q-11 | minor | TC-019 / W-CATEGORY-VALUE-CONSISTENT | This `W-*` rule has no negative test distinct from the always-correct writer (same root cause as Q-05). |
| Q-12 | minor | §5.9 #10 | "engine/validation test files byte-unmodified" is too strict — adding `artifact="cdfx"` may touch `validation/`. |
| S-001 | **BLOCKER** | LLR-007.3 / A-6 / OQ-3 | `.cdfx` WRITE path has no path-containment / traversal / symlink / overwrite requirement. |
| S-002 | major | LLR-007.4 / HLR-005 | `.cdfx` LOAD path has no path-resolution requirement — symlink/junction read, arbitrary location. |
| S-003 | major | LLR-006.6 | No size/complexity bound on the read path — a huge well-formed `.cdfx` exhausts memory. |
| S-004 | major | LLR-006.6 / §5.5 | Entity mitigation named only by example; stdlib `xml.etree` still expands INTERNAL entities — billion-laughs amplifies. |
| S-005 | minor | TC-027 | Timeout / memory-ceiling acceptance is non-deterministic. |
| S-006 | minor | LLR-005.3 | Tolerant "find SW-INSTANCE anywhere" + namespace-stripping lets a crafted file inject entries anywhere. |
| S-007 | informational | C-9 / C-10 | Data-exposure surface confirmed well-controlled — no action; one reinforcement noted. |

**Counts: 3 blockers · 10 majors · 15 minors · 1 informational = 29 entries**
(28 actionable findings + S-007 informational; the task brief's "~15 minors"
is the 15 minor rows above).

---

## Architect findings

### Summary
- blockers: 0
- majors: 3
- minors: 6
- one-line verdict: pass-with-fixes

### Findings

#### A-01 — "Reuse A2L parsing" field list does not match the A2L module's actual shape [major]
- **Target:** LLR-002.1 / C-1
- **Observation:** C-1 and LLR-002.1 say resolution reuses `tui/a2l.py` and
  reads the tag fields `datatype`, `element_count`/`length`, section/category.
  But a tag produced by a bare `extract_a2l_tags` call for a `CHARACTERISTIC`
  has `datatype = None` — the decode-relevant fields (`decode_type`,
  `element_count`) only exist *after* `enrich_a2l_tags_with_values` /
  `_resolve_record_layout` has resolved the RECORD_LAYOUT and COMPU_METHOD. As
  worded, the requirement points the resolver at fields that are not populated
  on the object it names.
- **Why it matters:** An implementer following LLR-002.1 literally would read
  `datatype=None` for every characteristic and conclude every entry is
  unresolved. The reuse contract names the wrong stage of the A2L pipeline.
- **Recommended fix:** Require resolution to run through
  `enrich_a2l_tags_with_values` (not bare `extract_a2l_tags`); C-1 must be
  amended to add `record_layouts_by_name`, `compu_methods_by_name`, and the
  enriched `decode_type` / `element_count` fields to the named reuse surface.

#### A-02 — A2L `ASCII` is a `char_type`, not a `datatype` — LLR-003.1 has no ASCII arm [major]
- **Target:** LLR-003.1 / HLR-002
- **Observation:** LLR-003.1 says the value-formatting function selects the
  display form "from the resolved A2L data type" and enumerates unsigned /
  signed / float datatype tokens. There is no `ASCII` datatype token in A2L —
  `ASCII` is a `char_type` / characteristic-kind attribute, orthogonal to the
  numeric datatype. LLR-003.1's enumeration therefore has no arm that selects
  the quoted-string form, even though HLR-003 and LLR-004.2 both require it.
- **Why it matters:** The string display path (and the `ASCII` `SW-INSTANCE`
  `CATEGORY`) has no source in the stated selection rule — it cannot be
  implemented or tested against LLR-003.1 as written.
- **Recommended fix:** Restate LLR-003.1 to select the display form / CATEGORY
  from the **pair** (`datatype`, `char_type`): `char_type == ASCII` selects the
  quoted-string form; otherwise the datatype token selects decimal / hex /
  signed / float.

#### A-03 — Internal inconsistency: physical value stored vs. hex-of-unsigned-int shown [major]
- **Target:** HLR-003 / LLR-003.1
- **Observation:** A-4 / DD-3 / LLR-003.3 mandate that the change-list stores
  the **physical** value. HLR-003 / LLR-003.1 mandate that unsigned-integer
  parameters are displayed "as decimal accompanied by hexadecimal." Hex of a
  physical value is **undefined** when the parameter's COMPU_METHOD is
  non-IDENTICAL — a non-IDENTICAL conversion yields a fractional physical
  value, and `hex()` of a fraction has no meaning. The two requirements
  contradict for every scaled unsigned parameter.
- **Why it matters:** A genuine logical inconsistency inside the requirements:
  an implementer cannot show "the hex of the physical value" when that value
  is fractional, and a Phase 4 reviewer cannot say whether TC-008 passed.
- **Recommended fix:** Show the hex companion **only when the physical value is
  integral** (equivalently, only for IDENTICAL-conversion parameters), and
  state that condition explicitly in LLR-003.1.

#### A-04 — `BOOLEAN` missing from the LLR-004.2 writer category enumeration [minor]
- **Target:** LLR-004.2 / LLR-006.5
- **Observation:** `BOOLEAN` is in the §6.1 editable category set and in the
  `W-INSTANCE-CATEGORY` / LLR-006.5 supported set, but the LLR-004.2 writer
  category enumeration lists only `VALUE` / `VAL_BLK` / `ASCII`. The writer
  has no stated `CATEGORY` for a `BOOLEAN` entry.
- **Recommended fix:** Add `BOOLEAN` to the LLR-004.2 category enumeration, or
  remove `BOOLEAN` from the editable set everywhere if it is genuinely out of
  scope this batch — pick one and apply it consistently.

#### A-05 — `W-EMPTY-CHANGELIST` vs the all-unresolved case is unspecified [minor]
- **Target:** LLR-004.6
- **Observation:** LLR-004.5 emits one warning per excluded unresolved entry;
  LLR-004.6 emits `W-EMPTY-CHANGELIST` when there are "zero writable entries."
  A change-list of two all-unresolved entries has zero writable entries — so it
  emits two LLR-004.5 warnings *plus* one `W-EMPTY-CHANGELIST`, three warnings
  total. Whether that is intended is not stated.
- **Recommended fix:** State explicitly whether `W-EMPTY-CHANGELIST` fires on
  the zero-*writable* condition or only on a literally-empty change-list; cover
  the all-unresolved case in TC-019.

#### A-06 — XML namespace handling breaks literal tag matching [minor]
- **Target:** LLR-005.3
- **Observation:** A default `xmlns` on the `MSRSW` root makes
  `xml.etree.ElementTree` return every tag as `{uri}LocalName`. A reader that
  matches `MSRSW`, `SW-INSTANCE`, `V`, etc. by literal string would then fail
  on a perfectly valid namespaced `.cdfx` — and RK-3 already flags namespaces
  as a live risk, while TC-017 explicitly feeds a file with a declared
  `xmlns`. LLR-005.3 does not contain a `shall` clause that pins the
  local-name-match behavior the test depends on.
- **Recommended fix:** Add a `shall` clause to LLR-005.3 requiring the reader
  to match elements by **local name regardless of namespace**.

#### A-07 — `0b`-prefixed binary `V` notation is an unpinned assumption [minor]
- **Target:** LLR-005.4 / TC-018
- **Observation:** LLR-005.4 and TC-018 require decoding `0b`-prefixed binary
  `V` text. `0b` is the **Python** integer-literal prefix; the research summary
  does not establish that CDF `V` elements use that form. This is a
  Python-implementation assumption leaking into a format requirement.
- **Recommended fix:** Cite the exact CDF binary-notation form from the
  research, or soften LLR-005.4 to "binary notation as defined by CDF" and
  drop the `0b` literal unless the research confirms it.

#### A-08 — Empty-state normative statement is not self-contained [minor]
- **Target:** LLR-007.6
- **Observation:** LLR-007.6's `shall` statement defines the Patch Editor
  empty state only by reference to external batch-02 id `R-TUI-030`. A reader
  of this document alone cannot tell what the empty-state bar must contain.
- **Recommended fix:** Restate LLR-007.6 self-containedly — describe the
  neutral empty-state prompt inline — keeping the `R-TUI-030` reference as an
  informative cross-link only.

#### A-09 — `array_index` vs `SW-ARRAY-INDEX` naming collision [minor]
- **Target:** LLR-004.3 / DD-4
- **Observation:** The change-list field `array_index` and the CDFX element
  `SW-ARRAY-INDEX` are different concepts: `array_index` is the change-list
  entry's positional key; `SW-ARRAY-INDEX` is an unrelated CDFX construct. The
  similar names invite an implementer to serialize one as the other.
- **Recommended fix:** Add a note to LLR-004.3 / DD-4 that `array_index` is
  **not** serialized as `SW-ARRAY-INDEX` — it maps only to positional `V`
  order inside the `VG`.

---

## QA-reviewer findings

### Summary
- blockers: 2
- majors: 4
- minors: 6
- one-line verdict: CHANGES-REQUESTED

### Findings

#### Q-01 — "34 LLRs" is arithmetically wrong; the real count is 39 [BLOCKER]
- **Target:** §5.7 / §5.9 / document header
- **Observation:** The document states "34 LLRs" in §5.7's reverse-traceability
  paragraph, in the §5.9 acceptance-gate item #1, and in the header framing.
  The actual LLR count, summed by HLR group, is **39**:
  4 (LLR-001.x) + 4 (LLR-002.x) + 3 (LLR-003.x) + 8 (LLR-004.x) +
  4 (LLR-005.x) + 7 (LLR-006.x) + 6 (LLR-007.x) + 3 (LLR-008.x) = **39**.
  The §5.7 iteration-2 arithmetic ("34 … including the four added in
  iteration 2") self-contradicts — 35 base + 4 added = 39, not 34. The §5.9
  sign-off gate ("100% of … 34 LLRs map to at least one TC") therefore
  measures coverage against a denominator that is wrong by five requirements.
- **Why it matters:** The coverage contract — the central Phase 4 acceptance
  gate — cannot be evaluated against a wrong total. A reviewer checking "all
  LLRs covered" against `34` would declare full coverage while five LLRs go
  unaccounted. This is a self-inconsistent specification, the strongest class
  of doc defect.
- **Recommended fix:** Correct "34 LLRs" → "39 LLRs" everywhere it appears
  (§5.7 reverse-traceability paragraph, §5.9 item #1, the header framing, and
  anywhere else). Fix the §5.7 iteration-2 arithmetic to "35 base + 4 = 39."
  Re-verify the reverse-traceability claim against the corrected total.

#### Q-02 — TC-027 security oracle is non-executable as written [BLOCKER]
- **Target:** §5.4 `make_entity_bomb_cdfx` / TC-027
- **Observation:** `make_entity_bomb_cdfx` is specified to produce a single
  `.cdfx` carrying **both** a billion-laughs nested-entity payload **and** a
  separate external-entity (`SYSTEM`) reference. TC-027 then asserts the reader
  surfaces "**one** `R-XML-PARSE` issue" — but a single file with two distinct
  attack vectors cannot deterministically yield exactly one issue, and the two
  vectors have different failure signatures. Separately, the clause "no
  external file is read" has **no stated detection mechanism** — nothing in the
  TC describes how a test would observe whether an external file was read.
- **Why it matters:** A security test whose fixture and assertion are mutually
  inconsistent, and whose key safety claim has no observable check, cannot
  produce a meaningful verdict. The §5.9 security gate (#6) depends on TC-027 —
  the gate is currently un-evaluable.
- **Recommended fix:** Split `make_entity_bomb_cdfx` into
  `make_billion_laughs_cdfx` and `make_external_entity_cdfx`, one attack vector
  per fixture. Specify the no-read detection concretely — e.g. the `SYSTEM`
  reference points at a sentinel temp file with known content and the test
  asserts that content is **absent** from the parsed result. State the
  expected issue count **per fixture**.

#### Q-03 — Exact float `==` round-trip is tautological without adversarial fixtures [major]
- **Target:** TC-024 / LLR-004.8
- **Observation:** LLR-004.8 / DD-8 require `repr()`-precision float text;
  TC-024 / TC-033 then assert exact `==` on the round-tripped float. `repr()`
  does round-trip a Python binary64 exactly — but so does `str()` for "nice"
  values like `12.5`. With only well-behaved fixtures the test is **tautological**:
  it would pass even if the writer used a lossy representation, because the
  chosen test values do not exercise the lossy path. The in-memory value type
  is also never pinned as binary64.
- **Recommended fix:** Pin the in-memory value type as Python `float`
  (binary64) in LLR-004.8 / DD-8. Add **adversarial** float fixtures to
  TC-024 / TC-033 — `0.1`, a denormal, and a 17-significant-digit value —
  whose round-trip fails under a lossy representation and passes only under
  true `repr()` precision.

#### Q-04 — TC-020 does not verify collect-don't-abort recovery [major]
- **Target:** TC-020 / LLR-006.2
- **Observation:** TC-020 asserts each `R-*` rule code is emitted and "the load
  does not abort." But it never asserts that a **valid sibling instance** in
  the same file still parses. A reader that, on hitting a violating instance,
  aborts the rest of the instance-tree (but returns the issue and does not
  raise) would pass TC-020 while silently violating the collect-don't-abort
  contract (HLR-005, C-5).
- **Recommended fix:** Each `make_rule_violation_cdfx` fixture must include a
  **valid `SW-INSTANCE` alongside** the violating one; TC-020 must assert the
  valid instance is recovered into the change-list.

#### Q-05 — TC-019 is overloaded and several W-* codes have no fault-injection path [major]
- **Target:** TC-019
- **Observation:** TC-019 is a single test case asked to provoke **all eight**
  `W-*` codes. Several of those codes (`W-XML-WELLFORMED`, `W-ROOT-MSRSW`,
  `W-BACKBONE`) are **invariants of a correct writer** — a correct writer
  cannot emit a non-well-formed root or a missing backbone — so there is no
  stated mechanism by which TC-019 could provoke them at all. As written the
  TC mixes genuinely provokable rules with un-provokable writer invariants.
- **Recommended fix:** Split TC-019 into per-rule sub-cases. State that the
  `W-*` validator is tested as a **standalone function on crafted element
  trees** (so the invariant rules can be exercised by feeding the validator a
  deliberately-broken tree). Mark genuinely-unprovokable invariants as
  `analysis` / `inspection` rather than `test`.

#### Q-06 — §5.2 references a "TC-027 sub-case" that exists nowhere else [major]
- **Target:** §5.2 HLR-007 row
- **Observation:** The §5.2 per-HLR table lists HLR-007's test cases as
  "TC-025, TC-026, **TC-027 sub-case**, TC-028." No "sub-case" of TC-027 is
  defined anywhere — §5.3 lists TC-027 plain, and §5.7 has a single TC-027 row
  with no a/b split. The traceability table refers to an artifact that does
  not exist.
- **Recommended fix:** Either formally split TC-027 into TC-027a / TC-027b with
  their own §5.7 rows (which also helps Q-02's two-vector split), or drop the
  "sub-case" wording and list plain `TC-027`.

#### Q-07 — LLR-005.4 acceptance criteria omits the `0b` example [minor]
- **Target:** LLR-005.4 / TC-018
- **Observation:** TC-018 asserts `0b101` → 5, but LLR-005.4's acceptance
  criteria only give the `0x17` and `1.5e1` examples — the binary example is
  in the TC but not the LLR.
- **Recommended fix:** Align LLR-005.4's acceptance criteria with TC-018 (add
  the binary example), consistent with whatever A-07 decides about `0b`.

#### Q-08 — TC-022 spuriously lists LLR-006.1 [minor]
- **Target:** TC-022 / §5.7
- **Observation:** TC-022's "Covers LLR" column lists `LLR-006.1, LLR-006.3`.
  LLR-006.1 (the write-time rule set) is already covered by TC-019 / TC-022 is
  about the `ValidationIssue` model reuse — the LLR-006.1 link is spurious.
- **Recommended fix:** Remove LLR-006.1 from TC-022's "Covers LLR" column;
  leave it as LLR-006.3 only.

#### Q-09 — §5.4 fixture "Used by" column is wrong [minor]
- **Target:** §5.4 fixture table
- **Observation:** The "Used by" column is inaccurate: TC-024 (round-trip)
  consumes `change_list_factory`, not `make_minimal_cdfx`; TC-017
  (producer-variation + tool-note) needs `make_variant_cdfx` and
  `make_tool_note_cdfx`, not only `make_minimal_cdfx`.
- **Recommended fix:** Correct the "Used by" entries so they match the actual
  TC-to-fixture dependencies.

#### Q-10 — `FLOAT16_IEEE` and large `A_UINT64` display unverified [minor]
- **Target:** TC-008 / LLR-003.1
- **Observation:** TC-008 exercises `UBYTE`, `SWORD` and `FLOAT32_IEEE`, but
  not `FLOAT16_IEEE` (half-precision, narrowest float) nor a large `A_UINT64`
  above 2^53 (where binary64 loses integer exactness). Both are display
  boundary cases for LLR-003.1.
- **Recommended fix:** Add a `FLOAT16_IEEE` case and a large-`A_UINT64`
  (>2^53) case to TC-008.

#### Q-11 — `W-CATEGORY-VALUE-CONSISTENT` has no negative test [minor]
- **Target:** TC-019 / `W-CATEGORY-VALUE-CONSISTENT`
- **Observation:** Same root cause as Q-05: `W-CATEGORY-VALUE-CONSISTENT` is a
  writer-output invariant; with TC-019 as a single overloaded case there is no
  negative test distinct from the always-correct writer.
- **Recommended fix:** Covered by Q-05's standalone-validator fix — the
  validator is exercised on a crafted inconsistent tree.

#### Q-12 — §5.9 #10 "byte-unmodified" is over-strict [minor]
- **Target:** §5.9 item #10
- **Observation:** §5.9 #10 requires the "engine/validation test files
  unmodified versus the batch start." But LLR-006.3 adds `artifact = "cdfx"`
  to the `ValidationIssue` model — a legitimate change that may require
  touching `validation/` and its tests. A byte-unmodified gate would fail a
  correct implementation.
- **Recommended fix:** Soften §5.9 #10 to "no **regression** in the
  engine / parser / validation suites" — the suites still pass — rather than
  byte-identical files.

---

## Security-reviewer findings

### Summary
- blockers: 1
- majors: 3
- minors: 2
- informational: 1
- one-line verdict: BLOCK

### Findings

#### S-001 — `.cdfx` WRITE path has no path-containment / traversal / overwrite requirement [BLOCKER]
- **Target:** LLR-007.3 / A-6 / OQ-3
- **Observation:** LLR-007.3 says the save action "invokes the CDFX writer to
  produce a `.cdfx` file in the work area" — but **no LLR pins where that file
  lands, nor any safety constraint on the target path**. A-6 / OQ-3 explicitly
  scoped `.cdfx` files **out** of `validate_project_files`, removing the
  containment guarantee that gate provided, **without replacing it**. There is
  no `shall` requiring the write target to resolve inside the work area, no
  reparse-point (symlink / junction) traversal rejection, and no
  existing-file-overwrite handling. The batch writes an attacker-or-user-named
  file to disk with zero path-safety specification.
- **Why it matters:** This is a real, unscoped write surface. A `.cdfx` path
  containing `..\..` segments, or pointing through a junction, would let the
  save action write outside the intended area or clobber an unrelated file —
  and nothing in the requirements forbids it. A view-plus-data batch that
  produces a file artifact must specify its write-path safety; this one does
  not. It gates the batch.
- **Recommended fix:** Add an LLR (and a matching TC) mandating that the
  `.cdfx` write target **resolves under `.s19tool/workarea/`**, **rejects
  reparse-point traversal**, and either **dedup-suffixes** or **confirms** an
  existing-file target before overwrite — reusing the `workspace.py` helpers
  (`copy_into_workarea`, `_path_traverses_reparse_point`).
  **Recommended product resolution (see Disposition):** `.cdfx` files are
  saved into `.s19tool/workarea/` under the existing `workspace.py`
  containment guards — consistent with the app's model (an "open work area"
  action already exists). If the owner instead intends free-path export, that
  must be stated explicitly **and still carry** the traversal + symlink +
  overwrite requirements.

#### S-002 — `.cdfx` LOAD path has no path-resolution requirement [major]
- **Target:** LLR-007.4 / HLR-005
- **Observation:** LLR-007.4 says the load action "invokes the CDFX reader with
  a `.cdfx` path" but specifies no path-resolution discipline. A user-typed
  path that is a symlink / junction, or that points to an arbitrary location
  off the work area, is read without any stated guard.
- **Recommended fix:** Require the load path to resolve through
  `resolve_input_path` (or a documented helper), consistent with how every
  other user-typed input path is handled in the app. State explicitly whether
  reading a `.cdfx` from **outside** the work area is permitted.

#### S-003 — No size / complexity bound on the read path [major]
- **Target:** LLR-006.6
- **Observation:** LLR-006.6 covers entity-expansion payloads but says nothing
  about a plain, well-formed but **huge** `.cdfx`. `ElementTree.parse` builds
  the entire DOM in memory — a multi-gigabyte well-formed `.cdfx` exhausts
  memory with no malformed XML and no entity payload, so LLR-006.6 does not
  catch it.
- **Recommended fix:** Add an LLR requiring the reader to **reject** (as
  `R-XML-PARSE`, collect-don't-abort) any `.cdfx` exceeding a documented byte
  cap **before parsing**, and to bound nesting depth. Reuse the
  `DEFAULT_COPY_SIZE_CAP_BYTES` (256 MB) rationale from `workspace.py`. Add a
  `make_oversized_cdfx` fixture.

#### S-004 — Entity mitigation is named only by example; stdlib still expands internal entities [major]
- **Target:** LLR-006.6 / §5.5
- **Observation:** LLR-006.6 / DD-9 specify the entity defense only by example
  ("disabled OR safely bounded"). Stdlib `xml.etree.ElementTree` has **no
  expansion-count bound** and **still expands INTERNAL general entities** — so
  a billion-laughs payload with no `SYSTEM` reference still amplifies
  unboundedly. "Or safely bounded" describes a mitigation the stdlib does not
  provide.
- **Recommended fix:** Mandate the concrete stdlib-only mitigation: the reader
  **shall reject any `.cdfx` containing a `DOCTYPE` / `<!ENTITY>` declaration**
  (a conformant CDF 2.0 `.cdfx` needs none) — via a parser whose DTD / entity
  handler raises. Drop the "or safely bounded" wording. Record the
  C-2-vs-security tradeoff as an explicit decision: **no `defusedxml`
  dependency** — DOCTYPE-rejection is the stdlib-only answer that satisfies
  C-2.

#### S-005 — TC-027 timeout / memory-ceiling acceptance is non-deterministic [minor]
- **Target:** TC-027
- **Observation:** TC-027 currently asserts safety via a bounded `pytest`
  timeout and a process-memory ceiling — both environment-dependent and
  flaky.
- **Recommended fix:** Once S-004 commits to `DOCTYPE` rejection, restate
  TC-027 to assert the **deterministic** outcome: a `DOCTYPE` present → exactly
  one `R-XML-PARSE` issue, the parser never expands an entity. Keep the
  timeout only as defense-in-depth, not the primary assertion.

#### S-006 — Tolerant "find SW-INSTANCE anywhere" allows entry injection [minor]
- **Target:** LLR-005.3
- **Observation:** LLR-005.3 combined with A-06's namespace-stripping makes the
  reader locate `SW-INSTANCE` elements **anywhere** in the document. A crafted
  `.cdfx` could place `SW-INSTANCE` elements outside the legitimate
  instance-tree (e.g. inside `ADMIN-DATA` or a comment-adjacent region) and
  have them silently absorbed as real entries.
- **Recommended fix:** Constrain the reader to locate `SW-INSTANCE` elements
  **only under the `SW-INSTANCE-TREE` backbone**, not anywhere in the tree.

#### S-007 — Data-exposure surface confirmed well-controlled [informational — no action]
- **Target:** C-9 / C-10
- **Observation:** Verified: C-9 (synthetic fixtures only) and C-10 (no logging
  of user-typed values or file content beyond `set_status`) correctly control
  the data-exposure surface. No client artifact and no value-logging path is
  introduced. **Recorded as verified — no action required.**
- **Recommended fix:** None. One optional reinforcement: `ValidationIssue`
  messages for `.cdfx` findings should reference the **element / location**,
  not echo proprietary value text into the message string.

### Out-of-scope confirmation (per this app's threat model)
- **Auth / authorization:** N/A — single-user offline desktop TUI.
- **Network egress / DNS / TLS:** N/A — no network surface; the batch adds
  none. (The external-entity case is a *file-read* vector, addressed by S-004,
  not a network vector.)
- **Secrets / credentials:** N/A — no keys, tokens or `.env` are read/written.

---

## Normative `shall` / `should` discipline — result

**Clean.** No `should` modal appears inside any HLR or LLR `Statement:` bullet
in Sections 3 and 4. The strict IEEE 830 + EARS convention declared in the
document preamble — `shall` only inside HLR/LLR statements, `should` only in
informative voice — is honored throughout the requirements body.

`should` appears only where the convention permits it: inside
`Rationale (informative)` and `Acceptance criteria (informative)` blocks and in
appendix prose. No stray normative `shall` / `shall not` was found in
informative voice.

No discipline finding is raised. (The blockers and majors above are about the
*content* of the normative statements — wrong field lists, missing arms,
absent safety clauses — not about the `shall` / `should` modal discipline,
which is clean.)

---

## Verdict

**blockers-present — the dev-flow workflow forces a rollback to Phase 1.**

The aggregate is **3 blockers · 10 majors · 15 minors · 1 informational**. The
dev-flow Phase 2 spec forces a rollback to Phase 1 whenever **any**
blocker-severity finding is open. Three are open — **Q-01** (the LLR count is
arithmetically wrong, breaking the coverage contract), **Q-02** (the security
test oracle TC-027 is non-executable), and **S-001** (the `.cdfx` write path
has no path-safety requirement). Per-reviewer verdicts: architect
`pass-with-fixes`, qa-reviewer `CHANGES-REQUESTED`, security-reviewer `BLOCK`.

`01-requirements.md` therefore **cannot advance to Phase 3**. It returns to
**Phase 1 for an iteration 3** that closes all three blockers, all ten majors,
and the minors, after which a closure re-review confirms the fixes.

None of the three blockers is an implementation-impossibility of the
batch-02 A-03 kind — they are specification defects (a wrong self-reported
count, an inconsistent test fixture/oracle pair, and a missing safety LLR).
All are closable with focused edits to `01-requirements.md`; **S-001 needs a
product-owner decision first** (where `.cdfx` files are written), which is the
only non-editorial item.

---

## Recommended Disposition

The 28 findings resolve into: a single Phase 1 iteration-3 pass that closes all
3 blockers + all 10 majors + all 15 minors, one product-owner decision needed
before that pass starts, and one no-action item.

### One product decision needed first — S-001

**S-001 requires a product-owner decision before the iteration-3 edit can be
written**, because the fix changes the `.cdfx` write contract.

**Recommended resolution:** `.cdfx` files are **saved into `.s19tool/workarea/`**
and protected by the **existing `workspace.py` containment guards**
(`copy_into_workarea`, `_path_traverses_reparse_point`), and **loaded via
`resolve_input_path`**. This is consistent with the app's established model —
the work area is already the home of every other on-disk artifact, and an
"open work area" action already exists, so an engineer can still reach the
produced `.cdfx`. It is the lowest-risk, lowest-new-code resolution: it reuses
hardened helpers rather than introducing a fresh write path.

**Flagged alternative:** the owner may instead opt for **free-path export**
(the engineer chooses an arbitrary save location, closer to a "Save As"
experience). That is a legitimate product choice — but it would **still require
the traversal + symlink + overwrite guards of S-001**; free-path export does
not remove the path-safety obligation, it only moves it. The owner picks; the
guards are mandatory either way.

A-6 / OQ-3 must be amended to record whichever choice is made and to state that
the containment guarantee removed from `validate_project_files` is **replaced**
by the new LLR — not simply dropped.

### Fix in Phase 1 iteration 3 — all 3 blockers + all 10 majors

All blockers and majors are closable in **one focused Phase 1 iteration**:

- **Blockers** — Q-01 (correct "34 LLRs" → "39 LLRs" everywhere; fix the §5.7
  arithmetic and the §5.9 gate denominator; re-verify reverse traceability),
  Q-02 (split `make_entity_bomb_cdfx` into two single-vector fixtures, specify
  the no-read sentinel-file detection, state issue-count per fixture), S-001
  (add the `.cdfx` write-path LLR + TC per the product decision above).
- **Majors** — A-01 (require enrichment via `enrich_a2l_tags_with_values`;
  amend C-1's reuse field list), A-02 (LLR-003.1 selects on the
  `datatype` × `char_type` pair), A-03 (hex companion only when the physical
  value is integral), Q-03 (pin the float type as binary64, add adversarial
  float fixtures), Q-04 (each violation fixture carries a valid sibling
  instance; assert recovery), Q-05 + Q-11 (split TC-019 per-rule, test the
  `W-*` validator as a standalone function on crafted trees, mark
  un-provokable invariants as analysis/inspection), Q-06 (split TC-027 into
  a/b or drop "sub-case" — pairs naturally with Q-02), S-002 (load path
  through `resolve_input_path`), S-003 (add a size-cap LLR + `make_oversized_cdfx`
  fixture), S-004 (mandate `DOCTYPE`/`<!ENTITY>` rejection as the concrete
  stdlib-only mitigation; record the no-`defusedxml` decision).

### Fold into the same iteration — all 15 minors

The minors are one-to-few-line edits with no design uncertainty and fold into
iteration 3 alongside the majors: A-04, A-05, A-06, A-07, A-08, A-09, Q-07,
Q-08, Q-09, Q-10, Q-12, S-005, S-006. Several couple to a major and are closed
by the same edit — A-07 ↔ Q-07 (the `0b` notation), Q-11 ↔ Q-05 (the standalone
validator), S-005 ↔ S-004 (the deterministic `DOCTYPE`-rejection assertion),
A-06 ↔ S-006 (namespace handling and the instance-tree-scoped lookup).

### No action — S-007

**S-007** confirms the data-exposure surface (synthetic fixtures, no value
logging) is well-controlled; recorded only. The optional reinforcement —
`ValidationIssue` messages reference element/location, not value text — may be
folded in opportunistically while editing LLR-006.x but is not required.

### Suggested sequencing

1. Product owner takes the S-001 decision (work-area save vs. free-path
   export). Recommended: work-area save under `workspace.py` guards.
2. One Phase 1 iteration 3 applies the S-001 LLR plus all 3 blockers, 10
   majors and 15 minors to `01-requirements.md`.
3. A closure re-review (parallel light pass — architect + qa-reviewer +
   security-reviewer) confirms every finding is closed and re-checks the
   corrected reverse-traceability against the 39-LLR total.
4. Only after the closure pass returns 0 blockers / 0 majors does the batch
   advance to Phase 3.

---

*Generated by parallel review pass: `architect` + `qa-reviewer` +
`security-reviewer`. Consolidated by `architect`.*

---

## Phase 2 — Iteration 2: Closure Verification

**Phase:** 2 — Cross-agent review
**Iteration:** 2 (closure verification)
**Date:** 2026-05-21
**Source artifact under review:** [`.dev-flow/2026-05-21-batch-03/01-requirements.md`](01-requirements.md) — after **Phase 1 iteration 3**
**Reviewers:** `architect`, `qa-reviewer`, `security-reviewer` (parallel closure pass)

### Result

All **28** Phase-2 iteration-1 findings (A-01..A-09, Q-01..Q-12,
S-001..S-006; S-007 informational) were re-checked after **Phase 1
iteration 3** and are **CLOSED**.

Three reviewers ran a parallel closure pass — verdicts:

| Reviewer | Closure verdict |
|---|---|
| architect | `all-closed-clean` |
| qa-reviewer | `all-closed-clean` |
| security-reviewer | `all-closed-clean` |

Both **Q-blockers** and the **S-001 blocker** are confirmed closed:

- **Q-01** (LLR count) — closed. The corrected total reconciles across §5.7,
  §5.9, and the header.
- **Q-02** (entity-bomb fixture) — closed. The single overloaded fixture was
  split into single-vector fixtures with per-fixture issue counts and a
  concrete no-read detection mechanism.
- **S-001** (write-path containment) — closed. **LLR-007.7** brings the
  `.cdfx` write path to full `copy_into_workarea` containment parity;
  **LLR-006.6** mandates concrete `DOCTYPE` / `<!ENTITY>` rejection.

The **OQ-3 stale cross-reference** (`LLR-007.8` → `LLR-005.5`) was corrected.

**Final requirement set:** 7 US · 8 HLR · 42 LLR · 45 TC.

### Consolidated Phase 2 verdict

**pass** — **0 blockers · 0 majors.** The artifact `01-requirements.md` is
cleared to advance to **Phase 3**.

### New observations from the closure scan

> All four are minor / cosmetic / informational — **none gating**. They do not
> reopen any iteration-1 finding and do not affect the consolidated `pass`
> verdict.

#### CV-01 — §6.3 OQ-3 wording loosely calls LLR-005.5 a "containment" replacement [minor]
- **Target:** §6.3 OQ-3
- **Observation:** §6.3 OQ-3 wording loosely describes LLR-005.5 as a
  "containment" replacement; LLR-005.5 is a path-*resolution* requirement, not
  a containment requirement. A-6 phrases the same relationship correctly.
- **Disposition:** One-line editorial tightening — align OQ-3 wording with
  A-6 ("path resolution", not "containment"). Deferred; non-gating.

#### CV-02 — TC-019a/b/c/g method `U, analysis` could be misread [minor]
- **Target:** TC-019a / TC-019b / TC-019c / TC-019g
- **Observation:** TC-019a/b/c/g carry method `U, analysis`. The `U`
  standalone-validator arm is the pass/fail verdict; the `analysis` arm only
  records the writer-cannot-provoke fact. A Phase-4 reviewer could misread
  `analysis` as the verdict method.
- **Disposition:** Recommend a one-line clarifier on those TC rows so the
  verdict method (`U`) is unambiguous. Minor; non-gating.

#### CV-03 — TC-036 reparse-point arm needs an explicit visible skip guard [minor]
- **Target:** TC-036
- **Observation:** TC-036's reparse-point arm needs an explicit, visible
  `skipif` / `xfail` (with a recorded reason) on CI images that lack the
  symlink-creation privilege — otherwise it can silently pass without
  exercising the rejection path.
- **Disposition:** Add a recorded-reason `skipif` / `xfail` to the
  reparse-point arm. Minor; non-gating.

#### CV-04 — LLR-006.6 DOCTYPE rejection hook ordering [informational — Phase 3 hand-off to `software-dev`]
- **Target:** LLR-006.6
- **Observation:** The LLR-006.6 `DOCTYPE` rejection must be wired to an
  `expat`-level handler that fires **before** entity expansion. The hook
  ordering is an implementation concern, not a requirements defect.
- **Disposition:** Carried into Phase 3 as an implementation note — the
  implementer (`software-dev`) confirms the chosen hook ordering. No
  requirements edit needed.

### Disposition

- **CV-01..CV-03** — minor / cosmetic. Fold into **Phase 3 increment 1** as
  opportunistic pickups, or accept as-is. None blocks anything.
- **CV-04** — implementation note carried into **Phase 3**; hand-off to
  `software-dev`.
- **None of CV-01..CV-04 blocks advancing to Phase 3.** The batch advances
  to Phase 3 with the consolidated Phase 2 verdict **pass**.

---

*Closure verification by parallel pass: `architect` + `qa-reviewer` +
`security-reviewer`. Consolidated by `architect`.*
