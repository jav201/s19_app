# batch-64 — Requirements

**Status:** Phase 0 complete (§2.6 below). §3 Acceptance / §4 HLR-LLR derivation pending the
Definition-of-Ready gate. Do not derive from any story not marked READY.

---

## 2.6 — Story intake & refinement (INVEST + Definition of Ready)

**Source:** `.dev-flow/BACKLOG.md`, the P1 bullet *"OPERATOR DECISION 2026-07-27 — batch-63 control
candidates RESOLVED; this is the spec for the encoding batch."*

**Evaluability convention for this batch.** Every story below produces a *documentation* deliverable
(control text in a named file), not code. The Testable axis is therefore held to the standard set in
`PLAN.md` §6: a presence check is NOT sufficient acceptance. Each story's black-box criterion is
stated at the level of *what the rule must discriminate*, so it can genuinely go RED.

---

### US-B64-1 — P-5 encoded as a new global control (C-40)

> **As** an agent running `/dev-flow` on any project, **I want** the flow to require that every
> acceptance criterion names — and executes — the mutation that turns it RED, **so that** a
> predicate which is correct but does not reference the component under test is caught at the
> authoring gate instead of shipping as false coverage.

- **Functionality.** User = the agent + the operator reading the gate packet. Outcome = a gate
  question that no existing control asks. Out of scope: changing C-10/C-31/C-39; re-encoding P-6 or
  P-7 as separate controls (operator ruled ABSORB).
- **Feasibility.** Path known and narrow: one control block appended to the controls region of
  `~/.claude/commands/dev-flow.md`, in the Phase-1 section per the operator's ruling. Id **C-40**
  derived free. Dependency: none. Size: small.
- **Evaluability (black-box).** *When* the encoded C-40 is applied as written to batch-63's five
  documented vacuous acceptance criteria, *the reader observes* all five FLAGGED; *and when* applied
  to a control group of sound predicates from the same batch, *the reader observes* none flagged;
  *and* for each of C-10 / C-31 / C-39, a stated case C-40 catches that it does not. A control
  flagging 0 of 5 is inert; a control flagging the control group is a false-positive machine. Both
  arms can fail. → `AT-B64-01`, `AT-B64-02`, `AT-B64-03`.
- **Absorption content (operator-ruled, must appear as named examples INSIDE C-40, not as siblings):**
  - **P-6** — a positive control must be shaped to the RULE, never to the implementation it
    certifies. (`AT-193b` was built only from cases its detector already caught, so it certified a
    completeness the detector lacked — authored while the author was actively hunting vacuity.)
  - **P-7** — consolidating artifacts must preserve the union or explicitly retire what it drops.
    (Revision 3 collapsed a 40-row TC layer into three id ranges and silently dropped 8 of ~18 union
    observables, including the one both Phase-1 lanes had independently agreed on.)
- **Independent?** Yes. **Verdict: READY.**

---

### US-B64-2 — P-3 leg 1: the portable principle encoded as a new global control (C-41)

> **As** an agent authoring an assertion about produced output on any project, **I want** the flow
> to require the predicate be written against the bytes/tokens the PRODUCER emits — never a
> character list, a human-readable rendering, or the spec's own vocabulary — **so that** a predicate
> that false-fails a correct implementation (or false-passes a broken one) is caught before it
> becomes a gate.

- **Functionality.** Discharge is mechanical and must be stated as such: *run the producer, paste
  its actual emitted form, then write the predicate against that.* Out of scope: every
  stack-specific mechanic (markdown-it, SVG entities, Rich spans) — those are US-B64-3 and
  US-B64-4 by the operator's decomposition.
- **Feasibility.** One control block, same region as C-40. Id **C-41** derived free. Placement policy
  satisfied: the principle is stack-free, therefore global.
- **Evaluability (black-box).** *When* C-41 is applied to the ~9 recorded occurrences across
  batches 61–63, *the reader observes* each one flagged, **and** the destination-boundary holds: the
  encoded global text contains **no** stack-specific identifier (no `markdown-it`, `&#160;`, `Rich`,
  `Textual`, `SVG`, `AST`), which is a mechanically checkable predicate that goes RED if
  stack-bound content leaks into the global leg. → `AT-B64-04`, `AT-B64-05`.
- **Independent?** Yes, though it shares an increment naturally with US-B64-1 (same file, same
  region). **Verdict: READY.**

---

### US-B64-3 — P-3 leg 2: stack-bound mechanics encoded in the project rules (C-42)

> **As** an agent working on s19_app's Textual + markdown-it + snapshot stack, **I want** the
> project's engineering rules to carry the concrete emitted-form traps for this stack, **so that**
> the general principle in C-41 becomes actionable without polluting the project-agnostic command.

- **Functionality.** New control in `docs/engineering-rules.md`, extending C-32/C-37 (both present,
  verified). Content fixed by the operator's ruling: markdown-it token streams (assert token TYPES,
  not substring presence; `&` entity spoofing — `&vert;` forges a table fragment with every token
  still `text`); **the escaped form of a character is not the character** (`'](' not in note` passed
  against a CORRECT implementation because the emitted form is `\](`); Mode-B code spans (a heading
  emitted as ``#### Checklist: `chk.json` `` is unfindable by its bare form — the batch-63 Phase-0
  probe returned an impossible `-1`, the only reason it was caught); SVG snapshot text carrying
  `&#160;` entities (a literal grep for a rail label returned 0/19); **AST over regex** for
  source-line predicates (an implicitly-concatenated f-string is one assembled template, not two
  lines).
- **Feasibility.** Id **C-42** derived free. This is the ONLY leg inside version control, so it is
  the only one the PR and CI can see. Size: small.
- **Evaluability (black-box).** *When* C-42 is applied to the four recorded s19_app instances, *the
  reader observes* each flagged with the specific mechanic named; *and* the complement of
  US-B64-2's boundary check holds — the traps that belong here are **absent** from the global leg.
  The two boundary predicates together are falsifiable in both directions. → `AT-B64-06`,
  `AT-B64-07`.
- **Independent?** Yes. **Verdict: READY.**

---

### US-B64-4 — P-3 leg 3: extend the `tui-design` skill's existing section

> **As** anyone building a TUI in any Textual/terminal project, **I want** `VERIFY.md`'s "Pin the
> truth, not a string" rule taken one step deeper — pin the truth in the form the producer EMITS it
> — **so that** an assertion that satisfies the existing rule completely can still be recognised as
> unable to fail.

- **Functionality.** **EXTEND the existing `## Pin the truth, not a string  [travels]` section
  (verified present at `VERIFY.md:34`); do NOT add a new section** — operator ruling. The
  counterexample that motivates it: a substring search over SVG source **is** a runtime value, it
  satisfies the existing rule completely, and it returned 0/19 against a correct implementation.
- **CONSTRAINT (operator, 2026-07-27): GENERAL knowledge ONLY.** Test: *is this true of ANY
  Textual/terminal project?* The mechanism qualifies (a Textual SVG export emits `&#160;` entities
  for spaces regardless of whose app it is; Rich colour lives in spans, not in the string). The
  illustrating example **must be de-identified** — write it as *a rail label* or *a menu entry*,
  never as the s19_app string `"CRC Designer"`.
- **Feasibility.** One section extension in a file outside version control. Size: small. Risk: the
  section is tagged `[travels]`; the extension must earn that tag or the tag is dropped.
- **Evaluability (black-box).** *When* the extended section is scanned, *the reader observes* zero
  s19_app-specific identifiers (`CRC Designer`, `s19`, `a2l`, `mac`, any repo path) — a predicate
  that goes RED the moment the de-identification constraint is violated; **and** the added text
  states the emitted-vs-rendered distinction in a form that discriminates the 0/19 counterexample
  from a predicate the existing rule already covers. → `AT-B64-08`, `AT-B64-09`.
- **Independent?** Yes. **Verdict: READY.**

---

### US-B64-5 — P-3 leg 4: execute the TUI-course content plan

> **As** a learner of the course, **I want** M13 to cover assertions that pass wrongly (not only
> tests that fail flakily), **so that** the testing module teaches the failure mode that does not
> announce itself.

- **Functionality.** Plan already written and durable at `G:/My Drive/Courses/textual/PENDING-UPDATES.md`
  (verified on disk, status **NOT STARTED**): M13 second pitfalls block + extended exercise
  (PRIMARY), M14 one paragraph (the WHY, at the compositor), M17 **check first — do not assume**.
- **Feasibility — this is where it fails the axis.** Different medium (HTML lesson authoring across
  a 67-file course), different skill from encoding a control paragraph. M17 is explicitly unscoped
  by its own plan. And the plan records a structural question it itself calls *"a separate call"*:
  `verify_m*.js` harnesses exist for M0–M6 and M15–M20 but **not M7–M14 — including M13, the
  testing module itself**, so the module that would teach *"prove your assertion can fail"* is one
  of the eight with no mechanism proving its own content holds.
- **Evaluability.** Adequate in principle (the course has a verification-harness idiom) but
  **unavailable for M13 specifically**, which is precisely the module in scope.
- **Verdict: RECOMMEND `OUT` — deferred, plan intact.** Deferring costs nothing: `PENDING-UPDATES.md`
  is self-contained and cross-references the other three legs. **Raised at the gate rather than
  decided**, because the operator's ruling named four destinations and narrowing that is the
  operator's call. If the operator says IN, it is `SPIKE` first (resolve the M13 harness question),
  not `READY`.

---

### US-B64-6 — canonical lineage record updated

> **As** the operator or a future agent asking "what controls exist and why", **I want** the
> canonical lineage record to carry C-40/C-41/C-42 with their origins, and to record P-6/P-7 as
> ABSORBED and P-3 as DECOMPOSED, **so that** the control history does not develop the same
> registry gap OB-2 measured for AT/TC ids.

- **Functionality.** Update `project_devflow_control_lineage.md` (the canonical cross-project
  record, 36 401 B, verified present). Also fix `BACKLOG.md`'s stale "Controls encoded" footer,
  which reads `C-1..C-36` while C-37/C-38/C-39 exist — a live instance of the registry-drift
  problem, inside the batch about it.
- **Feasibility.** Small, mechanical, depends on US-B64-1..3 landing first (it records their ids).
- **Evaluability (black-box).** *When* the union-grep census used at RC-1 is re-run after the batch,
  *the reader observes* every encoded control id present in the lineage record and zero id
  registered with no encoded text (both directions — the same bidirectional guard shape OB-2 asks
  for). Goes RED if a control is encoded and not registered, or registered and not encoded.
  → `AT-B64-10`.
- **Independent?** No — depends on 1/2/3. Implement last. **Verdict: READY.**

---

## 2.7 — Definition-of-Ready summary

| story | verdict | next action |
|---|---|---|
| US-B64-1 | **READY** | derive HLR/LLR in Phase 1 |
| US-B64-2 | **READY** | derive HLR/LLR in Phase 1 |
| US-B64-3 | **READY** | derive HLR/LLR in Phase 1 |
| US-B64-4 | **READY** | derive HLR/LLR in Phase 1 |
| US-B64-5 | **RECOMMEND OUT** | operator confirms at the gate; if IN → `SPIKE` on the M13 harness question first |
| US-B64-6 | **READY** (dependent) | derive last; sequence after 1/2/3 |

**Exit-criteria self-assessment for the Phase-0 gate:**

- **Coverage** — every candidate in the operator's ruling has a story; P-6 and P-7 are represented
  as absorbed content inside US-B64-1 rather than dropped. One story (US-B64-5) is proposed OUT with
  a stated reason and a durable plan, not silently narrowed. **Met, pending the US-B64-5 ruling.**
- **Certainty** — each READY story carries a black-box criterion stated so it can go RED, and the
  batch's central vacuity risk is named and answered in `PLAN.md` §6 rather than deferred.
  **Met.**
- **Evidence** — all four destinations verified on disk with size/line counts; the extension anchor
  in `VERIFY.md` confirmed at line 34; the control-id space derived by boundary-correct union-grep
  with two false positives caught and recorded. **Met.**
