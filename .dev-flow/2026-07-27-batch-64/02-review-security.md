# Security Review — batch-64 (control encoding: C-40, C-42, C-35 rider, VERIFY.md extension)

> **VERDICT: OK to ship with one mitigation applied first.** 0 blockers · 1 major · 2 minor.
> The major is **F1** — C-40 mandates routine mutation *execution* and does not bound where the
> mutation runs or require it be reverted, in a project with a recorded incident of exactly that
> (`BACKLOG.md:50`). Fix is ~2 lines appended to C-40's DISCHARGE sentence, landing in the same
> increment (Inc-3). Everything else clears.

---

## Scope reviewed

| item | read |
|---|---|
| `01-requirements-consolidated.md` (normative) | full, 399 lines |
| `PLAN.md`, `01-requirements.md`, `01-requirements-architect.md`, `01b-qa-catalog.md`, `01c-arms-measurement.md` | scanned for the four lanes below |
| `~/.claude/commands/dev-flow.md` | C-10/C-31/C-35/C-39 bodies + full grep for mutation-hygiene language |
| `docs/engineering-rules.md` | C-32 discharge (`:105-115`) as comparator |
| `.dev-flow/BACKLOG.md` | the batch-62 worktree-mutation incident (`:50`) + the M13 mutation-loop draft (`:40`) |

Four lanes: **S-1** reversibility/evidence · **S-2** the text being installed into the agent's own
instructions · **S-3** data exposure via `/dev-flow-sync` · **S-4** instruction-integrity of the
quoted adversarial examples.

**No code surface.** Zero `s19_app/` or `tests/` files in scope (D-5 forbids `tests/`). No new
dependency, no new MCP/Composio/external integration, no auth surface, no network egress, no deploy
path. Sections 2, 3, 5 and 6 of my standing checklist are **N/A by construction** and I am not
manufacturing findings against them.

---

## S-1 — Baseline integrity: VERIFIED UNMODIFIED

Per the discipline note (batch-63's grep-based "unchanged" claim that only a blob-sha settled), this
is a content-hash comparison, not a grep. Executed this session against the live out-of-VCS files:

| file | lines | bytes | SHA256 measured now | vs `§6` PRE |
|---|---|---|---|---|
| `~/.claude/commands/dev-flow.md` | 275 | 59259 | `44660d7cfede148746ac27dcbb8cccabd11c9a420de94b6351b2c7e7ad10b883` | **MATCH** |
| `~/.claude/skills/tui-design/VERIFY.md` | 182 | 10142 | `23cf75e6ae8d0a2c04489f99954ab7d6e976ae3eb93846cba9c8fb25ca9588ed` | **MATCH** |
| `…/memory/project_devflow_control_lineage.md` | 89 | 36401 | `d9f84f9e614100d2dddf612b65ec8a2c156c3679efbfe7b75a1f41b28a0386ee` | **MATCH** |

All three still at baseline. **Nothing has been written yet** — Phase 1/2 discipline held. The three
byte counts and line counts also match `§6`'s table exactly, so `§6` is not merely internally
consistent, it is true of disk.

**On the record's adequacy.** I concur with A-10 / QA: `AT-B64-11` is bookkeeping, not acceptance —
"a hash proves *a* change, never the *right* one." Judged as a *detect-and-reverse* mechanism rather
than as acceptance, it is **adequate on three of four properties**:

- **change proof** — ✓ `LLR-B64-6.3` blocks the gate on POST == PRE for a claimed edit. This is the
  right predicate and it is stated as blocking.
- **restorability** — ✓ backups to `.dev-flow/2026-07-27-batch-64/backup-pre/` with backup SHA = PRE
  SHA, taken at Inc-0 *before the first write* (`LLR-B64-6.1`, `§5` Inc-0). Correct ordering.
- **bounded delta** — ✓ `§6` predicts `dev-flow.md` gains 1 line + an in-place lengthening; an
  order-of-magnitude miss catches a truncation or reformat that a hash-changed check cannot.
- **timeliness** — ✗ see **F3**.

---

## Findings

### F1 — C-40 mandates mutation EXECUTION with no blast-radius bound  [Severity: MAJOR]

- **What.** C-40's discharge clause reads, in full: *"**DISCHARGE for both limbs:** name the mutation
  that reddens the predicate, **execute it, and paste the transcript**, including confirmation that
  the mutation actually applied (a typo'd mutation also "fails", for the wrong reason)."* It does not
  state **where** the mutation runs, that it must be **reverted**, or that it must not run in a tree
  another session is reading. This is the one genuinely new *behavioural* instruction in the batch —
  every other clause governs how a predicate is *written*; this one instructs an agent to *modify a
  tree* as a routine, mandatory gate step.

- **Where.** `.dev-flow/2026-07-27-batch-64/01-requirements-consolidated.md:146` (the C-40 paste
  block, DISCHARGE sentence). Destination per `LLR-B64-1.1`: `~/.claude/commands/dev-flow.md`,
  `### Phase 1 — Requirements engineering`, between the pre-edit `:147` and `:148` bullets. Restated
  normatively at `:83` (`HLR-B64-1`: *"**shall** require the reddening mutation for both limbs to be
  executed"*).

- **Why it matters.** Three compounding reasons, in order of weight:

  1. **The project has a recorded incident of precisely this failure.** `.dev-flow/BACKLOG.md:50`:
     *"do not run counterfactuals in a worktree a reviewer is reading. batch-62 mutated
     `report_service.py` in the live worktree while the independent security review was in progress,
     costing it four spurious failures and forcing a re-run against a pristine `git archive` export.
     The committed tip was always clean, but gate evidence must never be taken from a tree another
     session is editing. Run mutation experiments in an export."* That entry is a **raised process
     candidate, not encoded**. I grepped the whole of `dev-flow.md` for
     `restore|revert|git archive|pristine|worktree|clean tree|scratch` — the only hits are the
     `worktree-not-editor-root` paste protocol (`:41`), C-20's move-aside-never-stash rule (`:178`,
     which *does* say "restore" but only for the net-new-file case), and the C-27/RC-1 bullets. **No
     control body bounds where a mutation runs.** So C-40 will be the first control to mandate
     mutation at scale, into a command that has never stated the hygiene rule.

  2. **C-40 materially escalates the exposure over the existing precedent.** `docs/engineering-rules.md:109`
     (C-32) has the same unbounded phrasing — *"apply the mutation to your OWN new oracle and watch it
     fail"* — so C-40 is not uniquely careless. But C-32 is **project-local** and scoped to *an oracle
     the author is currently writing*. C-40 is **global** (it travels to every project `/dev-flow`
     serves), applies to *"every acceptance-bearing predicate — a black-box `AT`, an `LLR` acceptance
     clause, a `TC`, **and any measurement probe whose number a gate is keyed on**"*, and fires at
     **Phase-1 authoring time** — i.e. before an implementation exists, which means the tree being
     mutated is the **base tree**, not the author's own new code. That is the batch-62 configuration
     exactly, made routine and mandatory.

  3. **The batch's own source text contained the missing step and dropped it.** `BACKLOG.md:40` (the
     M13 draft that seeded P-5, C-40's parent candidate) states the loop as four steps: *"inject the
     falsehood, confirm RED, **verify the mutation actually applied** (a typo'd mutation also "fails",
     for the wrong reason), **restore**"*. C-40 carries the parenthetical verbatim and encodes three
     of the four steps. **`restore` is the one that did not survive the draft.** This is a
     transcription loss, not a design decision — nothing in `§1`'s fourteen amendments, `§10`'s two
     undischarged items, or either lane artifact argues for dropping it.

  I verified the absence mechanically rather than by reading: over the four paste blocks
  (`:145-207`), a scan for `restore|revert|undo|archive|scratch|worktree|clean|read-only|another
  session|in place` returns **zero** matches. The five `export` hits are all the noun *"snapshot
  export"* in C-42 mechanic 4 and the `VERIFY.md` extension, not `git archive` export. A scan across
  **all six** batch-64 artifacts for `run mutation|mutation experiments|pristine|git archive|another
  session|reviewer is reading` returns **zero**.

- **Blast radius, stated honestly.** For an in-VCS file a stray mutation is git-recoverable, so this
  is not a data-loss risk. The realistic cost is the one batch-62 actually paid: **corrupted gate
  evidence and spurious findings in a concurrent reviewer's run** — detection failure, not
  destruction. That is why this is MAJOR and not HIGH. It is *not* LOW because C-40 is the batch's
  flagship control, it is global and permanent, and once encoded every subsequent batch is instructed
  to mutate while being instructed nothing about restoring.

- **Recommendation.** Append to the DISCHARGE sentence, immediately after *"…for the wrong reason)"*.
  No design change, no relation-clause change, ~200 B — which also does not worsen the `§9.1` R-c
  length breach in any meaningful way (5 015 B → ~5 215 B; still the same ruling, the same second
  arm):

  ```markdown
  Run the mutation where **no other session is reading** — your own increment tree or a `git archive`/worktree export, never a tree a concurrent review or a parallel batch is measuring — and **RESTORE it before the next gate**, confirming the restore in the same transcript (`git status` clean, or the file's hash back at its pre-mutation value). A mutation left applied contaminates every later measurement in that tree and is indistinguishable, to anyone else reading it, from a real defect.
  ```

  Land it in **Inc-3**, in the same atomic write as C-40 — not as a Phase-6 carry. The rationale for
  Inc-3's atomicity in `§5` (*"a partial application would leave the rider referencing a C-42 that
  exists while C-40 does not"*) applies with equal force here: shipping C-40's mandate without its
  bound is the half-state.

  Secondary, optional: `§7` already carries five items; adding *"`BACKLOG.md:50`'s F5 process rule is
  now discharged by C-40's discharge clause — close it"* would let this batch retire a raised
  candidate instead of leaving it orphaned beside a control that supersedes it.

---

### F2 — Host-path and account-name disclosure in artifacts bound for the Drive vault  [Severity: MINOR]

- **What.** Batch artifacts sync to the Obsidian vault on Google Drive via `/dev-flow-sync`. Two
  categories of local-environment disclosure are present.

- **Where.**
  - `01-requirements-architect.md:399` — a shell snippet containing
    `$HOME/.claude/projects/C--Users-jjgh8-OneDrive-Documents-Github-s19-app/memory/…`, which
    discloses the **Windows account name** and the OneDrive/GitHub folder layout. This is the only
    occurrence of the account name across all six artifacts.
  - `PLAN.md:70`, `01-requirements.md:134`, `01-requirements-consolidated.md:254` — the absolute path
    `G:/My Drive/Courses/textual/PENDING-UPDATES.md` (the parked US-B64-5 course leg).

- **Why it matters — and why it is MINOR and not more.** The sync destination is the operator's own
  vault on the operator's own Drive; no third party receives these artifacts, and no LFPDPPP-relevant
  *client* data is present. The `G:` paths are being synced *to* `G:` — a Drive path landing in a
  Drive vault is not exfiltration. The prior art cuts the same way: batch-62's D-11 host-path
  redaction for project *reports* was **withdrawn after three integrity defects**, so the project's
  settled position is that byte-substitution redaction costs more integrity than the disclosure costs
  privacy. Re-litigating that here would buy less (these are internal engineering artifacts, not a
  client deliverable) at the same cost.

- **Recommendation.** **No change required for this batch.** Two things worth recording rather than
  fixing: (a) if any batch artifact is ever routed to a client or a public repo, `jjgh8` and the `G:`
  paths are the two strings to strip; (b) **the text that actually travels is clean** — see the
  clearance below.

- **Cleared explicitly and this is the load-bearing half of the lane:** the four blocks that leave
  this batch and install into other contexts — C-40 (`:146`), the C-35 rider (`:152`), C-42
  (`:169-179`), the `VERIFY.md` extension (`:188-206`) — carry **zero** absolute host paths, zero
  account names, and zero credentials. Every path inside them is repo-relative (`.dev-flow/…`,
  `docs/engineering-rules.md`, `tests/…`). C-40 and the rider go into a **global** command that
  serves every project on this machine, and `VERIFY.md` into a skill loaded into **every future
  session**; those are the two destinations where a leaked host path would genuinely propagate, and
  both are clean.

---

### F3 — POST-hash verification is deferred to Inc-4, three increments after the first out-of-VCS write  [Severity: MINOR]

- **What.** `§5` schedules POST rows in **Inc-4** only. Inc-2 writes `VERIFY.md` and Inc-3 writes
  `dev-flow.md`; neither has a hash check at its own increment boundary. `LLR-B64-6.3`'s blocking
  predicate therefore cannot fire until after all three out-of-VCS files have been written.

- **Where.** `01-requirements-consolidated.md:264-266` (`§5` Inc-2/Inc-3/Inc-4 rows) against
  `:136-137` (`LLR-B64-6.2`/`6.3`).

- **Why it matters.** It converts the evidence record from a **per-increment gate** into an
  **end-of-batch audit**. A truncating or misplaced Inc-2 write is not detected until two increments
  of further edits have landed on top of it, at which point attributing the damage is harder and the
  restore is coarser (roll back to Inc-0 backups, losing Inc-3 too). `§5`'s own R-d reasoning names
  the half-edited-window hazard as the reason Inc-3 must be atomic — the same reasoning argues for
  checking the window closed before opening the next one. Low impact because backups exist and the
  files are small, but it is a free strengthening.

- **Recommendation.** Amend `LLR-B64-6.2` to require the POST row for a file to be taken **in the
  increment that edits it** — Inc-2 records `VERIFY.md`'s POST, Inc-3 records `dev-flow.md`'s, Inc-4
  records the lineage memory's and consolidates the table. Same three rows, moved earlier; no new
  work. Optional, non-blocking.

---

## S-2 — Judgment on the mandated-mutation clause (the question asked)

**The clause is NOT adequately bounded, and the gap is the specific one this project has already been
burned by.** Detail and remedy in **F1**. In summary, against the three sub-questions:

| does C-40 say… | answer | evidence |
|---|---|---|
| **where** mutations run? | **No** | zero `worktree`/`export`/`scratch`/`in place` in the paste blocks (`:145-207`) |
| that they are **reverted**? | **No** | zero `restore`/`revert`/`undo`; and `BACKLOG.md:40`'s source draft *did* say `restore` |
| that they are not run in a tree **another session is reading**? | **No** | zero `another session`/`reviewer is reading`/`pristine` in **any** batch-64 artifact |

Everything *else* about the clause is well-formed and I want to be clear that the objection is
narrow. The requirement to execute rather than assert the counterfactual is the right call, is the
batch's strongest contribution, and is measured rather than argued (`4/6` one-limb vs `6/6`/`0/6`
two-limb). The clause even anticipates a subtle failure mode of its own instruction — *"including
confirmation that the mutation actually applied (a typo'd mutation also "fails", for the wrong
reason)"* — which is a sign of care, and makes the dropped `restore` read as transcription loss
rather than a considered omission. **The fix is additive, ~200 B, and changes no relation, no limb,
and no measured arm.**

---

## S-4 — Instruction-integrity of the quoted adversarial examples: CLEARED

The concern is real — C-40 and C-42 quote hostile and vacuous constructs verbatim, and once pasted
into a command file and a project rules file, that text is loaded as *instructions* by future agents.
I checked three ways and found nothing.

1. **No markup breakout.** I parsed the four fenced paste blocks and enumerated every line matching
   column-0 markdown structure (`#{1,6}`, `---`, `***`, `___`, fences, list bullets). Result: C-40 is
   **one** line, correctly shaped as a single `- **…` bullet (matching `LLR-B64-1.1`'s "one bullet").
   The C-35 rider is **one** line with **no** column-0 markdown, so it nests inside the existing C-35
   bullet as `LLR-B64-2.1` requires. C-42 is a `## ` heading plus six `- ` bullets — all intended
   structure for a new `##` section. The `VERIFY.md` extension is **19 lines with zero `##`
   headings**, which independently confirms `LLR-B64-4.1`'s *"shall not introduce a new `##`
   heading"* is satisfied by the drafted text and not merely asserted. Nothing in any block can
   restructure its host file.

2. **Every adversarial literal is inside an inline code span.** `` `# PWNED` `` (`:172`),
   `` `SYM_A&vert;PASSED&vert;0x0` `` (`:173`), `` `p.open("w")` `` (`:146`),
   `` `"](" not in note` `` (`:174`), `` `&#160;` `` (`:176`). Two consequences worth stating:
   the `# PWNED` example cannot become a heading in `engineering-rules.md`; and — the one I
   specifically wanted to rule out — the forged-verdict example **cannot forge anything in its own
   host document**, because markdown-it/GFM do not resolve `&`-entities inside code spans, so
   `&vert;` renders literally as `&vert;` rather than collapsing into the `|` that would fake a table
   cell. The example is inert in exactly the way it describes not being inert elsewhere.

3. **No unattributed imperative.** Every imperative in the four blocks is a *discharge obligation
   addressed to the predicate author* ("Write the predicate against the escaped spelling", "run the
   producer over a real fixture", "identify the producer … run it"), which is the intended function
   of a control. The adversarial constructs appear only as **subjects of descriptive sentences**
   ("an injected `# PWNED` heading reports "no change" under subtraction"; "`SYM_A&vert;PASSED&vert;0x0`
   renders as…, a forged verdict fragment"), never as a directive to produce them. No clause creates
   an obligation an agent could discharge in a harmful, unbounded or destructive way — **with the
   single exception of the mutation-execution clause, which is F1 and is about scope, not about
   content.**

---

## Cleared explicitly (so the absence of findings is legible, not assumed)

- **No credentials, keys, tokens, OAuth secrets, or SSH material** in any batch-64 artifact. The
  ~20 `token` matches are all *markdown-it parser tokens* (`{t.type for t in toks}`), a false-positive
  class of the pattern, not credentials.
- **No third-party data flow.** No client data, no PII beyond the operator's own account name (F2),
  no LFPDPPP surface.
- **No new external tool, MCP server, Composio connector, n8n node, or API integration.** Nothing to
  scope-review; the standing "never wave through a new integration" rule is not engaged.
- **No destructive command surface** in the batch's own plan: `§5` edits five files across five
  increments, all additive inserts, all backed up at Inc-0. No `rm -rf`, no `Remove-Item -Recurse`,
  no force push, no migration, no rename of a shared folder.
- **No dependency change**, no lockfile movement, no supply-chain surface.
- **No deploy or release path.** In-VCS leg (`docs/engineering-rules.md`) goes through the normal
  PR/CI/diff-review gate; the three out-of-VCS legs are local files with Inc-0 backups.
- **Auth flows: N/A.** No tokens stored, refreshed, or revoked.
- **Backups precede writes.** `LLR-B64-6.1` orders the backup before the first write and `§5` Inc-0
  edits no destination — the ordering is correct, which is the single most important property of the
  whole evidence record and it is right.

---

## Evidence checklist

| item | ✓/✗ | evidence |
|---|---|---|
| Each finding has what · where · why · recommendation | ✓ | F1/F2/F3 above, each with a `file:line` |
| Each finding has a severity rating | ✓ | MAJOR ×1, MINOR ×2, blockers 0 |
| No secret values appear in this output | ✓ | none found to report; F2 names the *locations* (`01-requirements-architect.md:399`, `PLAN.md:70`) and the account-name string only because it is the operator's own and is the thing to grep for |
| Verdict is explicit | ✓ | OK-with-mitigation, stated at the top and repeated below |
| New tool/integration scope + blast radius addressed | ✓ **N/A, and stated so** | no integration in scope; the *behavioural* analogue — mandated mutation execution — is scope-reviewed in full at F1/S-2 |
| Baseline "unchanged" claims verified by hash, not grep | ✓ | S-1 table: three SHA256s measured this session, all matching `§6` PRE |

---

## Verdict

- [ ] OK to ship
- [x] **OK to ship with the listed mitigation applied first** — **F1**, ~200 B appended to C-40's
      DISCHARGE sentence, landing in **Inc-3** alongside C-40 itself. F2 needs no action. F3 is a
      free strengthening, non-blocking.
- [ ] Block — must fix HIGH findings before ship

**Residual risk after F1 is applied: LOW, and I want to say that plainly rather than pad the lane.**
This batch writes no code, ships no integration, moves no data off the machine that is not already
the operator's own, and takes byte-identical backups of all three unversioned destinations before
touching them. Judged as a *documentation* change it is unusually well-instrumented. The single
security-relevant question — *does the new instruction this batch installs into the agent's own
governing files create an unbounded behaviour?* — has one honest answer, F1, and a two-line fix.

---

*Reviewed by `security-reviewer` · Phase 2 · batch-64 · 2026-07-27. Independent of the architect and
QA lanes. No file modified except this deliverable; all three out-of-VCS baselines re-verified
unmodified by SHA256 at review start.*
