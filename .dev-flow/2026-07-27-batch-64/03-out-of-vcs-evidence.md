# batch-64 — Out-of-VCS evidence record (HLR-B64-6)

**BLUF: all six frozen blocks landed byte-intact at their specified positions; every file delta matched
its pre-derived prediction exactly; three of the five edited files have no git history, so this record
is their only rollback and audit trail.**

Discharges `LLR-B64-6.1` (pre-edit backups), `-6.2` (PRE/POST rows taken in the editing increment),
`-6.3` (POST≠PRE gate), `-6.4` (expected delta stated before the edit, citing §3 as the diffable source).

---

## 1. The frozen manifest, verified by a third party

`§3.0` of `01-requirements-consolidated.md` froze six paste blocks. Before any file was touched, the
orchestrator **independently re-implemented §3.0's extraction rule** and reproduced all seven digests:

| # | block | destination | bytes | SHA256 |
|---|---|---|---|---|
| 1 | §3.1 C-40 | `~/.claude/commands/dev-flow.md` | 6 219 | `5cb146e9…` |
| 2 | §3.2 C-35 rider | `~/.claude/commands/dev-flow.md` (in place) | 2 411 | `4b4e3bad…` |
| 3 | §3.3 C-42 | `docs/engineering-rules.md` | 4 306 | `db1fa905…` |
| 4 | §3.4 extension | `~/.claude/skills/tui-design/VERIFY.md` | 1 540 | `b1cdc970…` |
| 5 | §3.5 lineage entry | `project_devflow_control_lineage.md` | 5 962 | `059b7bad…` |
| 6 | §3.6 BACKLOG reconciliation | `.dev-flow/BACKLOG.md` (4 spot edits) | 7 265 | `3a6c7374…` |
| — | concatenation | — | **27 703** | `92029b6f…` |

Three independent parties have now reproduced this manifest: the fold that authored it, the
measurement pass, and the orchestrator. **A figure in this batch is admissible only if it names the
block hash it was measured against** (§3.0, normative).

## 2. PRE / POST rows

| file | in VCS | PRE bytes | POST bytes | Δ | predicted Δ | PRE sha256 | POST sha256 |
|---|---|---|---|---|---|---|---|
| `docs/engineering-rules.md` | ✅ | 15 127 | 19 435 | **+4 308** | +4 308 ✅ | `278b808d…` | `5618029c…` |
| `~/.claude/skills/tui-design/VERIFY.md` | ❌ | 10 142 | 11 684 | **+1 542** | +1 542 ✅ | `23cf75e6…` | `3c6016fc…` |
| `~/.claude/commands/dev-flow.md` | ❌ | 59 259 | 67 891 | **+8 632** | +8 632 ✅ | `44660d7c…` | `85979683…` |
| `project_devflow_control_lineage.md` | ❌ | 36 401 | 42 365 | **+5 964** | +5 964 ✅ | `d9f84f9e…` | `1a366bf4…` |
| `.dev-flow/BACKLOG.md` | ✅ | 76 440 | 82 328 | **+5 888** | +5 888 ✅ | `118b1ca1…` | `f6768bd0…` |
| | | | | **+26 334** | | | |

**`LLR-B64-6.3` gate:** no POST SHA256 equals its PRE — no increment silently failed to write.

**Backups (`LLR-B64-6.1`)**, taken before the first write, in the session scratchpad
`…/scratchpad/b64-baselines/`: `dev-flow.md.PRE`, `VERIFY.md.PRE`,
`project_devflow_control_lineage.md.PRE`, `engineering-rules.md.PRE`. The two in-VCS files are
additionally recoverable via git; the three out-of-VCS files are recoverable **only** from these
copies, which is why this section exists.

### On the `+8 632` figure — it took four terms and three parties to get right

The delta for `dev-flow.md` was wrong in three successive artifacts before it was measured:

| stated | by | error |
|---|---|---|
| `6 219 + 1 522 = 8 630` | fold 2 | a phantom 889 B rider that was never on disk |
| `6 219 + 2 411` | orchestrator | omitted the new bullet's **line terminator** |
| `6 219 + 1 + 2 411 = 8 631` | fold 3 | correct on the terminator; omitted the **space separator** before `(Origin:` |
| **`+8 632`** | measurement pass | derived by **simulating both edits on a scratch copy**, not by addition |

The executed edit produced exactly `+8 632`. Recorded because it is this batch's own thesis in
miniature: **three parties reasoned about the number and each was wrong; the party that ran it was
right.** Per the measurement pass's recommendation the bounded-delta check carries **±1 tolerance** —
a check that fails on one space is one people learn to wave through.

## 3. Placement verification (the `shall` clauses that content ATs cannot see)

`AT-B64-08` and `AT-B64-09` return identical values on a correctly-placed and a mis-placed insert, so
placement needs its own observers. All executed post-edit:

| predicate | requirement | result |
|---|---|---|
| **PP-1** | C-40 after the C-39 bullet, before the UI-geometry pointer | `C-39@31606 < C-40@34013 < pointer@40153` ✅ |
| **PP-2** | rider **inside** the C-35 bullet, before its `(Origin:` | `C-35@25431 < rider@26443 < (Origin:@28838`, same line ✅ |
| **PP-3** | C-42 after `## C-38`, before `## C-34` | `C-38@11928 < C-42@13440 < C-34@17724` ✅ |
| **PP-4** | extension inside `## Pin the truth`, before `## Mutation-test`, **no new `##`** | `1712 < 2058 < 3592`, new headings = **0** ✅ |
| **PP-5** | BACKLOG footer id-range **and** stack list | both clauses ✅ — see §5 |

**Byte-intactness** confirmed per block: each frozen block is present in its destination as an exact
substring. No reflow, no normalisation. This is why the pastes were scripted from the frozen source
rather than retyped — a regenerated block would have broken its hash, which is the failure the freeze
exists to detect.

## 4. Acceptance results transfer by byte-identity

The arm figures in `04-measurement-frozen.md` were measured against the frozen blocks. Each block is
now present in its destination **as an exact substring of the same bytes**, so those results transfer
by identity rather than needing a re-run:

- `AT-B64-04` **9/9** against block 2, three mutations biting **disjoint** clause sets (6/9, 7/9, 7/9,
  8/9); all-needle corruption → 0/9. `arch BLOCKER-1` closed.
- `AT-B64-01` **9/9 CI-domain · 8/9 full-domain**; `AT-B64-02` **1/6 CI-normative · 0/6 full · 0/5
  reclassified** — always reported with its domain named, because the domain is what makes it correct.
- `AT-B64-05` 0/17 · `AT-B64-08` 0/12 (re-verified post-paste on the live file) · `AT-B64-10` 32 ids
  across 3 disjoint declaration shapes, two independent RED carriers.

## 5. `PP-5` — and an orchestrator predicate that flagged a correct implementation

`PP-5` passes on both clauses: the footer's declared range is now `C-10 … C-39` ∪ `{C-40, C-42}`, and
the stack-specific list names `C-13`, `C-32`, `C-34`, `C-37`, `C-38`.

**The orchestrator's first PP-5 check reported FAILURE against this correct implementation.** It
tested `'C-1..C-36' not in footer` — but the new footer deliberately **quotes** the old range to mark
it superseded (*"The previous `C-1..C-36` was wrong in BOTH directions and is superseded"*). The
predicate could not distinguish a **declaration** from a **quoted-superseded mention**.

This is the same failure the discharge auditor recorded on its own first `PP-5` run, reproduced
independently by a second party. It is the exact mechanic C-42 encodes, committed while installing
C-42 — and it is the third mention-vs-declaration boundary error measured in this batch.

## 5b. POST-REVIEW-FOLD state — the manifest is amended, and I broke a property while fixing findings

The independent `code-reviewer` returned **OK-with-fixes: 0 HIGH, 4 MEDIUM, 3 LOW**, byte-fidelity
**6/6** and placement **5/5**, both re-derived from first principles rather than read from §3 above.
All four MEDIUMs shared one root cause the reviewer named exactly: **`file:line` references and counts
carried rather than re-derived** — this batch's own thesis, catching its authors a ninth time.

**Six folds applied to the installed text:**

| # | fix | file |
|---|---|---|
| F2 | *"**Five** related an accounting helper to a string join"* → *"**Three of the five** … to a byte count"*. The claim was false **and self-contradictory**: C-40 named the other two rows as instances (i) and (ii), so the block asserted they were accounting-to-join *and* that they were not | `dev-flow.md` |
| F2b | dropped *"for one defect"* — the corpus spans three subjects | `dev-flow.md` |
| F6 | `(:206)` → `(:207)` | `dev-flow.md` |
| — | lineage's *"five vacuous acceptances authored for ONE defect"* → qualified with the batch-64 measurement (nine, across three subjects) | lineage |
| F1 | a **self-invalidating pointer**: the carry cited `BACKLOG.md:50`, but the same insert shifted that rule to `:59`. Re-cited by its drift-proof label `(PROCESS, new — sec F5)` | `BACKLOG.md` |
| F3 / F4 | bare `:266` re-bound to its real file; the unsupported `(and :36)` dropped | `BACKLOG.md` |

**F2 was not carried as "narrative".** It is a false factual claim in *permanent global governing text*
read by every future batch, in a batch whose thesis is that a document must not assert what it does
not honour.

### The manifest is now STALE for three blocks — stated, not hidden

| block | status |
|---|---|
| 2 (rider), 3 (C-42), 4 (VERIFY ext) | **byte-exact** in their destinations, hashes unchanged ✅ |
| 1 (C-40), 5 (lineage), 6 (BACKLOG) | **deliberately amended by the review folds** — they no longer match `§3.0`'s hashes, correctly |

**The acceptance figures still bind, and that is proven rather than argued.** C-40's *normative body* —
everything before its `(Origin:` — is **byte-identical** between the frozen block and the installed
text: **4 564 B, `sha256=026bb4c6709f2ed64ecc5132…`**, with both `**LIMB` markers, the
`DISCHARGE for both limbs` clause and the mutation-hygiene clause inside it. The arms harness parses
by those limb markers, so `AT-B64-01` (9/9 CI · 8/9 full) and `AT-B64-02` (1/6 CI-normative) are
measured over an unchanged region.

### The defect I introduced: text-mode writes, which is this project's own D3

Applying the folds I used `pathlib.write_text`, which on Windows translates `\n` → `\r\n`. **That is
precisely batch-63's D3 defect — `write_text` vs `write_bytes` and newline translation — committed
inside the batch that encodes "assert against the emitted encoding."**

Measured consequence: `dev-flow.md`, the lineage memory and `BACKLOG.md` are now **uniformly CRLF**
(276/276, 96/96, 153/153 CR/LF) where the Phase-3 writes had left them *mixed* — host CRLF with
LF-only inserted blocks. `docs/engineering-rules.md` (125 CR / 137 LF) and `VERIFY.md` (182/202) were
not re-touched and remain mixed.

**Content is unaffected, and that is verified rather than assumed:** `git diff --stat` on the two
tracked files shows **24 insertions, 3 deletions** — ordinary edits, *not* a whole-file rewrite, which
is what line-ending damage would look like in a diff.

It was caught only because the PRE byte counts my fold script printed (42 276 / 82 187) were **smaller**
than the Phase-3 POST counts (42 365 / 82 328) by exactly 89 and 141 — CR counts, not content. Another
implausible-number catch, which is the luck C-42's mechanic 3 warns against relying on. The uniform-CRLF
end state is the better one for a Windows host, so it is **kept deliberately** rather than reverted;
what was wrong was arriving there by accident.

## 5c. POST-MERGE coherence — `main` moved under the batch, and what that invalidated

`main` advanced 5 commits mid-batch. **PR #143 split `.dev-flow/BACKLOG.md` into `BACKLOG-CODE.md` +
`BACKLOG-PROCESS.md` and reduced `BACKLOG.md` to a router.** That file was the *single* collision point
this batch predicted at kickoff, and it was the *only* conflict — every other changed path was disjoint
(they touched `README.md`, `REQUIREMENTS.md`, `docs/images/*`; this batch touched
`docs/engineering-rules.md`, `state.json`, and 19 new files).

**Resolved by re-derivation, because each side was right about a different thing:** `main`'s shape for
the router (lineage only, carries in the lanes) and **this batch's** footer (the `LLR-B64-5.4` fix,
since `C-1..C-36` was wrong in both directions). The 8 carries were split by lane — §7.1/§7.2/§7.8 to
`BACKLOG-CODE.md`, §7.3–§7.7 to `BACKLOG-PROCESS.md` — and §7.8 was placed beside the `sec F5` rule it
escalates, with its self-reference **re-pointed** because `sec F5` now lives in `BACKLOG-CODE.md`. That
is the same drifting-pointer defect the code review caught as F1, avoided by re-derivation.

Verified: 0 conflict markers · each of the 8 carries present **exactly once** across the three files ·
of `main`'s process lane exactly **2 lines absent — the heading and lead this batch deliberately
replaced**, with both replacements present. **2 replaced, 0 dropped.**

### What the merge invalidated in this batch's own artifacts — stated, not carried silently

| stale claim | reality | impact |
|---|---|---|
| `§3.6` / block 6: *"`.dev-flow/BACKLOG.md` takes **four spot edits**, not one contiguous insert"* | applied across **three** files under the two-lane layout | **description only** — the reconciliation content shipped in full |
| `PP-5` cites `.dev-flow/BACKLOG.md:143-144` | the footer heading is now line **46** of the router | **line citation only** — PP-5 **re-run post-merge and GREEN on both clauses**, verified by content rather than by line number |
| `03` §1 manifest row 6 | block 6's *bytes* were the source; its *application* changed shape | the frozen hashes for blocks 1–5 are unaffected |

**None of this changes what shipped.** The four control texts are byte-verified in place and contain
**zero** references to the backlog's structure (`engineering-rules.md` 0, `VERIFY.md` 0; the five hits
in `dev-flow.md` are pre-existing flow text, not C-40 or the rider).

### NEW FINDING, not this batch's doing but now live — carried

**The global `/dev-flow` command's backlog-reconciliation rule is now stale for this project.** It
instructs every batch to reconcile *"the project's **SINGLE** canonical cross-batch backlog:
`.dev-flow/BACKLOG.md`"* and states *"the batch is NOT closed until `.dev-flow/BACKLOG.md` reflects
it."* After #143 that file is a **router holding no open work** — a batch that follows the instruction
literally would reconcile the wrong file and drop its carries on the floor.

This is pre-existing text this batch did not touch, and the fix is a **placement question** the
operator should rule on (the global command is project-agnostic and arguably should not hard-name a
project's file layout at all, in which case the lane routing belongs in
`docs/engineering-rules.md`). Recorded as a carry rather than fixed here, because it is outside the
operator's encoding ruling for this batch.

## 6. Scope confinement

```
git status --porcelain
   M .dev-flow/BACKLOG.md
   M .dev-flow/state.json
   M docs/engineering-rules.md
  ?? .dev-flow/2026-07-27-batch-64/

git status --porcelain -- s19_app tests examples pyproject.toml   ->   0 files
```

Zero production source, zero tests, zero fixtures, zero build config. The baseline suite was
re-derived at `c779e3d` before any edit — **2 201 passed, 2 skipped, 21 deselected, 3 xfailed, 29
snapshots passed**, exit 0 — closing the oldest number in the batch, which four lanes had carried and
none had re-derived. Ledger `post = 2201 − 0 + 0 = 2201`, as ruled by D-5.
