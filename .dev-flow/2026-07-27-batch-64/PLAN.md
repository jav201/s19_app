# batch-64 — PLAN (living compendium)

> Updated at every gate and significant checkpoint. Presented in-conversation at each gate,
> not merely linked. Human-readable mirror of `state.json`.

**Batch id:** `2026-07-27-batch-64`
**Route:** full `/dev-flow` (operator-invoked)
**Language:** English (inherited from `state.json`, unchanged)
**Status:** ✅ **MERGED + CLOSED OUT** — PR [#144](https://github.com/jav201/s19_app/pull/144), squash `71126c9`, 2026-07-28. Awaiting `/dev-flow-sync`.

---

## 1. Where we are

**Done.** All five in-scope stories shipped; the TUI-course leg was ruled OUT by the operator with its
plan left durable. `main`: `082ada9 → 71126c9`. CI green on the merged head (`tui-ci` 33m8s,
`snapshot` 1m49s). Both merge gates BLOCKED first and cleared at **0 HIGH** after folds. Zero
production code at any point — the suite is unchanged at **2 201 passing**, re-derived not carried.

Encoded: **C-40** + the **C-35 rider** (global), **C-42** (project rules), the **`VERIFY.md`**
extension, and the lineage registrations including **C-29 back-registered**. `C-41` cancelled on
measured evidence; its id remains free.

**The batch's primary output is not the text — it is that the control caught its own authors twelve
times while being written**, including a vacuous check inside the anti-vacuity clause itself, and two
tautological assertions found **live on `main`** that all three pre-existing controls miss.

## 2. Objective

Encode the control candidates the operator RESOLVED at batch-63's postmortem (ruling recorded
2026-07-27 in `.dev-flow/BACKLOG.md`). Two candidates become new controls; two are absorbed as
named examples; one is decomposed across four destinations.

| candidate | operator ruling | destination |
|---|---|---|
| **P-5** — *"can it go RED?" is a gate question distinct from "is it correct?"* | **ENCODE** as a new global control | global `/dev-flow` |
| **P-6** — a positive control must be shaped to the RULE, not the implementation it certifies | **ABSORB** into P-5 as a named example | (inside P-5) |
| **P-7** — consolidation must preserve the union or explicitly retire what it drops | **ABSORB** into P-5 as a named example | (inside P-5) |
| **P-3** — assert against the emitted encoding, never a character list or the rendered form | **DECOMPOSE across four destinations** | global · project · skill · course |

Operator's reasoning for absorbing P-6/P-7 rather than encoding them separately: all three fail
from one cause — *the predicate does not touch what it claims to touch* — and three controls where
one suffices is the friction that makes controls get ignored.

## 3. Authorization (per-batch — NEVER carried from batch-63)

Asked and answered 2026-07-27 at kickoff:

- **Autonomy + merge authority:** **AUTONOMOUS end-to-end + SELF-MERGE.** Each gate self-approved
  with a named Coverage/Certainty/Evidence axis; packets presented in-conversation. Merge only
  after green CI **and** an independent `qa-reviewer` **and** `security-reviewer` pass 0-HIGH over
  the whole diff vs `main`.
- **Decision recording:** **Confirmed, plus per-ruling pings** — every normative ruling is surfaced
  in-conversation as it is made, not only at the gate. All un-asked decisions land in this PLAN's
  decision log, `state.json.decisions_log`, `05-postmortem.md`, and the vault at sync.

**Encode-approval rule** (`feedback_devflow_control_encode_approval`, "always AskUserQuestion
before encoding a control") is **discharged on the record** by the 2026-07-27 operator ruling in
`BACKLOG.md`, which names each candidate and its destination. Not re-asked.

## 4. RC-1 — base currency (run BEFORE deriving anything)

```
git fetch origin --prune
origin/main tip   = c779e3d
HEAD              = c779e3d
merge-base        = c779e3d
rev-list L/R      = 0 / 0   (neither ahead nor behind)
branch            = claude/next-batch-backlog-8a6c43
git status --porcelain -- s19_app tests examples pyproject.toml  -> 0 lines
```

**Already-shipped check, per destination, executed not assumed:**

| # | destination | on disk | pre-state verified |
|---|---|---|---|
| A | `~/.claude/commands/dev-flow.md` | 275 lines, 59 259 B | max control = **C-39**; no P-5-equivalent present |
| B | `docs/engineering-rules.md` (in repo) | 125 lines | max control = **C-38**; C-32/C-37 present as the extension anchors |
| C | `~/.claude/skills/tui-design/VERIFY.md` | 10 142 B | `## Pin the truth, not a string  [travels]` **present at line 34** — the ruling's "EXTEND, do not add" premise HOLDS |
| D | `G:/My Drive/Courses/textual/PENDING-UPDATES.md` | 7 546 B | exists, **status NOT STARTED**; M13/M14/M17 plan + the M7–M14 harness gap recorded |

**Control-id space DERIVED, not assumed** (this batch's own subject matter, so it is measured).
**`C-40`/`C-41`/`C-42` return 0 boundary-correct hits** — that part holds.

> ~~`C-1 … C-39` contiguous across the union of `~/.claude/commands/`,
> `~/.claude/skills/tui-design/`, `docs/`, `.dev-flow/`, `CLAUDE.md`, and the lineage memory.~~
>
> **REFUTED at the Phase-1 gate, by the qa lane, and re-verified by the orchestrator against disk.
> The ENCODED space is `C-10 … C-39`.** `C-1 … C-9` have **no id-bearing encoded text** anywhere —
> the union-grep hits resolved to architecture-diagram node labels and a ruff rule code. **My census
> counted MENTIONS, not ENCODINGS** — a predicate asserting a property of the *encoded* set while
> quantifying over *any occurrence*. That is this batch's own defect class, committed in its own
> RC-1, and it is left struck through rather than edited away.

Two further false positives, recorded because they are instances of the same subject: the first
census pattern matched `TC-401` for lacking a real boundary, and a stray `C-54` proved to be
batch-37 shorthand for the `AT-054b` golden. The qa lane independently reproduced the
missing-word-boundary defect in its own first harness (phantom `Rich`/`AST` hits) and recorded it
rather than quietly fixing it.

**Registry gap found while measuring:** `C-29` is encoded at `docs/engineering-rules.md:64` but is
**unregistered** in the lineage memory (verified 1 vs 0). Folded into US-B64-6 — cheap, in scope,
and a live instance of the drift this batch is about.

## 5. Stories (Phase 0 — see `01-requirements.md` §2.6 for the full refinement block)

| id | story | INVEST verdict |
|---|---|---|
| **US-B64-1** | P-5 encoded as **C-40** in the global `/dev-flow`, absorbing P-6 + P-7 as named examples | READY |
| **US-B64-2** | P-3 leg 1 (portable principle) as a **RIDER on the existing C-35** in the global `/dev-flow` — **`C-41` CANCELLED as a control, id stays free** (operator ruling D-7) | READY, re-scoped |
| **US-B64-3** | P-3 leg 2 (stack-bound mechanics) encoded as **C-42** in `docs/engineering-rules.md`, extending C-32/C-37 | READY |
| **US-B64-4** | P-3 leg 3 — **EXTEND** `VERIFY.md`'s existing "Pin the truth, not a string" section; general knowledge only, examples de-identified | READY |
| ~~US-B64-5~~ | P-3 leg 4 — TUI-course content plan | **OUT — operator ruling 2026-07-27.** Plan stays durable at `PENDING-UPDATES.md`; carried to `BACKLOG.md` at close |
| **US-B64-6** | Canonical lineage record updated: C-40/C-41/C-42 registered, P-6/P-7 recorded as ABSORBED, P-3 as DECOMPOSED | READY |

## 6. The batch's central design problem (identified at Phase 0, resolved in Phase 1)

**What is a non-vacuous acceptance test for a *documentation* deliverable?**

This is not academic. The naive AT — *"the string `can it go RED` appears in `dev-flow.md`"* — is
precisely the check `VERIFY.md:36` condemns: *"A green check that only goes red when you delete
prose is not evidence."* A batch encoding *"prove your acceptance can fail"* whose own acceptances
cannot fail would be self-refuting, and it would be the sixth instance of the exact defect class
batch-63 measured.

**Proposed acceptance shape — the rule must DISCRIMINATE, not merely exist.** batch-63 documented
**five** acceptance criteria that verified nothing, with their exact predicates preserved in
`.dev-flow/2026-07-26-batch-63/`. That is a labelled corpus. The acceptance therefore is:

1. **Positive arm** — the encoded control, applied as written, FLAGS each of the 5 known-vacuous
   predicates. A control that flags 0 of 5 is inert; that arm can genuinely go RED.
2. **Negative arm (this is P-6 applied to itself)** — the corpus MUST also contain predicates the
   rule should NOT flag, and the control must leave them alone. Shaping the corpus only from cases
   the rule already catches is exactly the defect P-6 names, committed while encoding P-6.
3. **Discrimination arm** — for each of C-10 / C-31 / C-39, show what P-5 catches that it does not.
   batch-63 already measured the answer: all five predicates survived all three, because each
   related two pure functions of the same input while the component under test never appeared in
   the expression. A new control that is a restatement of an existing one is a Coverage failure.
4. **Self-application** — every acceptance in THIS batch names and EXECUTES the mutation that
   reddens it. If C-40 cannot be applied to its own encoding batch, it is not operable.

Carried into Phase 1 as the primary derivation constraint, not left implicit.

## 7. Risks / watch-items

| # | risk | mitigation |
|---|---|---|
| R-a | **Three of four legs are OUTSIDE version control** (`~/.claude/commands/`, `~/.claude/skills/`, `G:/`). The PR carries only `docs/engineering-rules.md` + `.dev-flow/`. No git history, no CI, no diff review for the other legs. | Batch artifacts carry an explicit **before/after record + a byte/line-count and SHA256 pre and post** for every out-of-repo file. Back up each file before edit. Already flagged in `BACKLOG.md` for the global-command leg; extended here to the skill leg. |
| R-b | Prose-presence acceptances are weak by construction | §6 discrimination corpus is the answer; do not settle for presence checks |
| R-c | **Control bloat** — the global command is already 59 KB / 275 lines and consulted every batch. Two more controls raise the cost of reading it. | The operator's own absorption reasoning applies: prefer one control over three. Watch total added length; the discrimination arm justifies inclusion or it does not go in. |
| R-d | Editing the global `/dev-flow` command mid-batch changes the very command this batch is executing under | Edit as the LAST increment, or accept that the running instance holds the pre-edit text in context. Sequencing ruled in Phase 1. |
| R-e | `VERIFY.md`'s target section is tagged `[travels]` — the ruling says the extension must earn that tag or drop it | Explicit acceptance: the added text contains no framework-specific or project-specific identifier |

## 8. Scope call to confirm at the Phase-0 gate — the course leg (US-B64-5)

**Recommendation: OUT of batch-64, deferred with its plan intact.** Reasons: it is
instructional-content authoring in HTML across a 67-file course — a different medium and a
different skill from encoding a control paragraph; its own plan leaves M17 explicitly unscoped
(*"CHECK FIRST, do not assume"*); and it carries an unresolved structural question the plan itself
says is *"a separate call"* (harnesses exist for M0–M6 and M15–M20 but **not M7–M14, including M13,
the testing module itself**). Deferring costs nothing because `PENDING-UPDATES.md` is already
written, durable, and self-contained.

**Counter-argument, stated because it is real:** the operator's ruling named four destinations, and
closing three leaves the fourth NOT STARTED indefinitely. Narrowing a scope the operator set is the
operator's call, not mine — so this is raised at the gate rather than decided here.

## 9. Out-of-scope carries (recorded, not dropped)

- **NEW, found at Phase 1 — a vacuous test is LIVE on `main`.**
  `tests/test_report_document_bytes.py:208` (`test_at172b_…`) asserts
  `raw == rs.document_bytes(raw.decode("utf-8"))`, and `document_bytes` is `text.encode("utf-8")`
  (`report_service.py:440`) — so the clause reduces to `raw == raw.decode().encode()`, **a tautology
  for any valid UTF-8**. Executed across {pre-fix, post-fix} × {LF, CRLF}: **0 RED cases.** Its own
  docstring claims *"This is the clause that fails on a text-mode writer wherever
  `os.linesep != LF`"* — false. Precisely: the function's **second** assert
  (`CR.encode() not in raw or os.linesep == LF`) IS sound, so the test is not wholly inert — its
  **named, documented** clause is. Shipped as part of batch-63's own D3 fix, past three 0-HIGH
  gates. **Carry, not a fix** — D-5 forbids touching `tests/` this batch. It is also the single
  strongest piece of evidence that C-40 discriminates: it was found by *executing the candidate
  control against batch-63's corpus*, and C-10/C-31/C-39 all miss it.
- **NEW — the P-3 occurrence count disagrees across three registers**: the lineage memory says
  "~7th", `BACKLOG.md:35` says "~9", `MEMORY.md` says "8+"; the qa lane enumerated **8 across
  batches 60–63**. Encoded control text therefore carries **no total** — enumerate, never total.
- **NEW — `AT-B64-11` is bookkeeping, not acceptance.** A hash proves *a* change, never the *right*
  one. Labelled as such rather than counted as load-bearing.

- `BACKLOG.md`'s "Controls encoded" footer is **STALE** — it reads `C-1..C-36` while C-37/C-38
  (project) and C-39 (global) exist. Fix during the Phase-6 backlog reconciliation.
- **OB-2 (the missing AT/TC registry)** is a sibling problem to this batch's control-id allocation
  and is NOT in scope here. This batch derived its own ids by union-grep across six destinations —
  the same manual procedure OB-2 says does not scale. Stays a separate batch.
- The document-bounding redesign (F4/OB-4 + both REV-5 designs) stays queued.

## 10. Decision log

| # | date | decision | rationale |
|---|---|---|---|
| D-1 | 2026-07-27 | **This batch takes the id `batch-64`.** | batch-63's artifacts repeatedly forward-reference "batch-64" as the document-bounding redesign. That was a reference to *the next batch*, not a reservation. Bounding work is now un-numbered backlog (batch-65+). Flagged so a reader of batch-63's spec does not expect batch-64 to be the bounding batch. |
| D-2 | 2026-07-27 | Encode-approval AskUserQuestion **not re-asked** | Discharged by the recorded 2026-07-27 operator ruling in `BACKLOG.md`, which names every candidate and its destination. |
| D-3 | 2026-07-27 | Control ids **derived by union-grep across six destinations**, not taken from the lineage memory alone | The lineage memory is canonical but is one subset; batch-63's OB-2 measured a 134-id spread between subsets for TC ids. Applying that lesson to control ids. |
| D-4 | 2026-07-27 | Route kept as full `/dev-flow` | Flagged at intake that `/fast-dev-flow` fits a no-code batch better; operator selected the scope under `/dev-flow` without changing route. Full record is also the point for control lineage. |
| D-5 | 2026-07-27 | **batch-64 adds NOTHING to `tests/` or `s19_app/`** | Two independent reasons that agree. Engineering: a CI test asserting *"the string `C-42` appears in `docs/engineering-rules.md`"* is a prose-presence check — exactly what `VERIFY.md:36` condemns and what §6 exists to avoid; institutionalising it in the app's CI suite would embed the defect class this batch encodes against. Operational: it keeps the write surface disjoint from parallel app work. Acceptance evidence lives in the batch artifacts as executed transcripts. |
| D-6 | 2026-07-27 | The id registry was fixed before dispatch **with per-id SEMANTICS**, not merely as ranges | batch-63's orchestrator fixed ranges, claimed the collision was "removed by construction", and was falsified — both lanes filled the same range with different content and 9–10 of 12 AT ids bound to different observables. Ranges are necessary and not sufficient. **Result this batch: zero id collisions, and the two lanes converged on the C-40 draft independently.** |
| **D-7** | 2026-07-27 | **OPERATOR RULING: P-3 leg 1 becomes a RIDER on the existing C-35, not a new control. `C-41` is cancelled; the id stays free.** | The architect measured the proposed C-41 as **~70 % C-35** and surfaced the cheaper alternative (~600 B vs ~2 000 B, no new id) precisely so the ruling would stand against a known option rather than a default. The genuine delta is one sentence — *executing the producer is not sufficient if the assertion is then written against the RENDERED form.* Consistent with the operator's own absorption reasoning (one control beats three) and with risk R-c (control bloat in a 59 KB command read every batch). **Encoded controls this batch are now exactly {C-40, C-42} plus the C-35 rider.** |
| D-8 | 2026-07-27 | Phase-1 fold done as **ONE consolidated document by the architect lane**, not by re-dispatching both lanes | batch-63's finding: parallel authorship *was* the root cause of its id collision, so fixing a two-lane defect with two lanes reproduces it. Here the lanes did not collide, so the fold is 6 mechanical corrections with measured answers plus one ruling — single-author work. Both lane artifacts stay on disk so the reversal is traceable. |
| **D-9** | 2026-07-27 | **OPERATOR RULING: C-40 ships as V-FULL (5 015 B, 2.07× C-39). The R-c size-gate breach is ACCEPTED on arm 2 (explicit justification).** | Converted from taste to measurement before being asked: three variants + a reference floor were executed, which dissolved the framing — *"accept 2.07× or lose a member"* was a **false dilemma**, since V-TRIM-1 holds 6/6 at 82 % of the bytes. Decomposing the `(Origin: …)` to answer the operator's request for detail **changed my recommendation from hybrid to V-FULL**: S4/S5 are the concrete cases behind the two instances the operator ruled *absorbed*, and S6 is the measured 4/6-vs-6/6 that keeps the two-limb structure from being "simplified" away. Deciding argument: every trim still measures 6/6 **because the arms test the RULE, not the Origin** — so a trim's cost is structurally invisible to the measurement, which is instance (ii) ("a green count over the survivors cannot see the casualties") committed on the control that states instance (ii). Context for any re-litigation: the 1× cap is **not an external standard** — the qa lane invented it in its own run 1, in two arms, and later self-reported (B-2) that arm 1 is not like-for-like, since it caps a three-candidate absorbing control against a one-candidate one and prices narrative identically with rule text. |
| D-9a | 2026-07-27 | **Orchestrator error, found by the Phase-2 architect and recorded rather than quietly fixed** | D-9 was written to `state.json.decisions_log` but **never added to this table**, so the living plan's log ended at D-8 while the ruling existed. The reviewer greps `*.md`, found `D-9` → 0 hits, and correctly reported the spec as presenting an already-settled ruling as open. The living `PLAN.md` is what the operator reads; a decision recorded only in `state.json` is not recorded. Row added above; the omission is left visible here. |

## 11. Test ledger — and the ZERO-CODE constraint (D-5)

Base suite at `c779e3d`: **2201 passed** (batch-63 close). **Expected post: 2201, `A = 0`, `D = 0`.**

**D-5 (ruling, 2026-07-27): batch-64 adds NOTHING to `tests/` or `s19_app/`.** Acceptance evidence
lives in the batch artifacts as executed transcripts, not as CI tests. Two independent reasons, and
they agree:

1. **Engineering.** A guard test asserting *"the string `C-42` appears in `docs/engineering-rules.md`"*
   is a prose-presence check — precisely what `VERIFY.md:36` condemns and what §6 exists to avoid.
   Putting it in the app's CI suite would institutionalise the defect this batch encodes against.
2. **Operational.** It keeps the batch's write surface disjoint from any parallel app work.

### Declared write surface (complete)

| path | in VCS? | is it app code? |
|---|---|---|
| `docs/engineering-rules.md` | ✅ yes | ❌ documentation |
| `.dev-flow/state.json` | ✅ yes | ❌ flow state |
| `.dev-flow/BACKLOG.md` | ✅ yes | ❌ shared queue — **the one real collision point** |
| `.dev-flow/2026-07-27-batch-64/**` | ✅ yes | ❌ new dir, no collision possible |
| `~/.claude/commands/dev-flow.md` | ❌ outside | ❌ |
| `~/.claude/skills/tui-design/VERIFY.md` | ❌ outside | ❌ |
| lineage memory `project_devflow_control_lineage.md` | ❌ outside | ❌ |

**NEVER touched:** `s19_app/`, `tests/`, `examples/`, `pyproject.toml`, `REQUIREMENTS.md`,
`PROJECT_RULES.md`, `CLAUDE.md`. Note in particular that **no `R-TUI-*` entry is added to
`REQUIREMENTS.md`** — this batch changes no application requirement, which is itself confirmation
that the surface is disjoint.

### Concurrency map for parallel app work

| resource | risk | mitigation |
|---|---|---|
| `.dev-flow/state.json` | **CRITICAL if the parallel agent runs full `/dev-flow`** — the file holds ONE batch's state; two concurrent `/dev-flow` batches overwrite each other | **Verified:** `/fast-dev-flow` maintains **no `state.json`** (`fast-dev-flow.md:82`, `:137`) — it uses `.fast-dev-flow/spec.md`. Running the parallel agent on `/fast-dev-flow` removes this collision entirely. |
| `.dev-flow/BACKLOG.md` | **HIGH** — BOTH flows reconcile it as a mandatory close step (`fast-dev-flow.md:102`) | batch-64 is small and merges first; the parallel batch rebases and reconciles after. Whoever merges second re-reads rather than re-applies. |
| `docs/engineering-rules.md` | LOW | only collides if the parallel batch also encodes a project control — flag it if so |
| `.fast-dev-flow/spec.md` | LOW | a live `spec.md` (12 167 B) already exists; the command's own step 2 archives it to `.fast-dev-flow/archive/` before starting fresh |
