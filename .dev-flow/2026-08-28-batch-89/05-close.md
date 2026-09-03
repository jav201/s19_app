# 05 — Close · batch-89 · the lean contract, and five closures on the flow's own environment

> ## ⚠ STATUS: **CLOSED WITH DECLARED GAPS — and the batch merged four commits from station P3 before this gate existed**
>
> **Four of this batch's thirteen commits reached `main` at station P3**, as PR #204
> (`1238b7e`, 2026-08-29) and PR #206 (`a2a2534`, merged 2026-08-31T03:10:32Z), with no
> `04-validation.md` and no `05-close.md` on disk. **That is batch-88's defect, repeated.** It is
> recorded here in the same banner form batch-88 used against itself, because a close that leaves
> the reader to discover it is worth less than one that says it first.
>
> **What is different, and it is the whole reason this file can carry live numbers.** The
> remaining **six** commits — `a679ee6`, `c4e6fe5`, `ed03b10`, `c118f6e`, `cf24e29`, `976476d` —
> are still on `claude/batch-89-lean-contract` and have **not** merged. This gate runs *before*
> them. So unlike batch-88's close, which was written a day after its merge with the instrument
> three revisions gone, this one **executed the validator against the tree it is judging**, at the
> revision that produced it.
>
> **Three gaps this close will not smooth over**, each with its own section:
> 1. **No independent `code-reviewer` pass, 0 of 6 increments** (§6). The single largest hole.
> 2. **Four of six increment packets were written retroactively** (§6), after `V27` — shipped by
>    this batch's own increment 6 — reported the hole against its own batch.
> 3. **1,163 lines of new `s19_app` source landed under no requirement and no increment packet**
>    (§1, `G-89-03`).
>
> Read `04-validation.md`'s disclosure block before citing any figure from either file.

> **Notice convention.** `⚠` = declare and continue · `✗` = block · `✓` = satisfied **with its
> citation**.

---

## 1 · What changed

**BLUF: the flow's own record stopped being able to drift from the flow's own work, and the flow
stopped assuming four things about the machine it runs on.** Nothing a user of the s19 application
can now do differs; every requirement in this batch is about the engineering flow itself. That is
worth stating at the top, and the file census says it plainly. **`git diff --name-only
0f40624..HEAD` returns 27 files** — 29 once this close's two artifacts are committed — and they
classify as **20 batch records** (22 with these two), **4 root configuration files**
(`CLAUDE.md`, `README.md`, `pyproject.toml`, and `project.toml` deleted), and **3 Python files**.
**All three Python files are `G-89-03`**: no requirement in this batch names any of them.

| Requirement | Version | Verified by | Verdict |
|---|---|---|---|
| `HLR-89.1` — the live contract is bounded, the ledger is not | v1 | `V26 BUDGET-over` · `BUDGET-at` · `BUDGET-ignores-ledger` · `BUDGET-renders-const` · `BUDGET-derivation` · `BUDGET-chars-not-bytes` | ⚠ **PASS with `G-89-01`** — the property holds; the requirement's own threshold names a fifth arm that has never existed |
| `LLR-89.1.1` — the budget's number lives in the code | v1 | `V26 BUDGET-renders-const` | ✓ |
| `LLR-89.1.2` — the current-state check has a grammar | v1 | `V26 STRIKE` · `STRIKE-wrap` · `STRIKE-not-greedy` | ✓ |
| `LLR-89.1.3` — the link is a PAIRING, checked both ways | v1 | `V26 PAIR-only-live` · `PAIR-only-ledger` · `PAIR-crossed` · `E2E-crossed` | ✓ |
| `LLR-89.1.4` — an omitted pointer is a defect, `none` is the declared empty | v1 | `V26 UNPOINTED` · `UNOWNED` | ✓ |
| `LLR-89.1.5` — armed as REGISTERED, not only as a pure core | v1 | `V26 E2E-adopted` · `E2E-crossed` · `E2E-legacy-over` · `E2E-legacy-under` | ✓ |
| `HLR-89.2` — a verdict under any stdout encoding | v1 | `ENC VERDICT-live` · `VERDICT-domain` · `UTF8-lossless` · `PASS!=NOOP` | ✓ **with its RED observed first** (`P-8`, two surfaces, 2026-08-29) |
| `HLR-89.3` — the flow names an interpreter that exists | v2 (*"resolves"* → *"starts Python when executed"*, `LED-89.11`) | 8 `INT`/`V17` arms | ✓ |
| `HLR-89.4` — the environment contract, DERIVED not asserted | v2 (floor re-derived at rev54, `LED-89.22`) | 23 `V30` arms | ✓ **with its API floor labelled DOCUMENTARY, NEVER EXECUTED** |
| `HLR-89.5` — the runtime preflight | v1 | 12 `PRE` arms | ✓ |
| `HLR-89.6` — the record is checkable, and closed before superseded | v1 | 49 `V27`/`V28` arms (threshold 47, +2 accounted) | ✓ |
| `LLR-89.6.1` · `LLR-89.6.2` · `LLR-89.6.3` · `LLR-89.6.4` · `LLR-89.6.5` — enumerated, never written as a range (C-56) | v1 | 12 · 9 · 10 · 10 · 12 arms | ✓ (all five) |

**16 of 16 requirements verified · 0 blocker fails · 1 threshold not literally dischargeable.**

**The mechanism, in one paragraph per story.**

- **Story 1** split the requirements record into a **live contract** holding current state only and
  an **append-only ledger** holding how each requirement came to say what it says — and the split
  alone is not the fix. Two editable files disagree, which *rehouses* `R-88-17` rather than closing
  it. What closes it is that every requirement names its ledger entries, every entry names its
  requirement, and **`V26` compares the two sets of PAIRS in both directions**. `PAIR-crossed` is
  the discriminating fixture: identical id sets on both sides, only the pairs swapped, on which
  every membership oracle reports a clean pass.
- **Story 2** repaired the selftest at the **stream** — `errors=backslashreplace` on stdout at
  `__main__` — never at the fixture, because the offending character was one instance of a class
  (534 non-cp1252 characters of 28 kinds across the canon rows). The consumer's *encoding* is
  deliberately **not** overridden: forcing utf-8 would trade a loud failure for a quiet corruption.
- **Story 3** found that `python3` on this machine is the Microsoft Store alias — a real file, on
  `PATH`, that `shutil.which` reports and that **exits 49 without starting Python** — and that
  `V17` certified it, printing `SKIP: guard wired` while every rule the guard enforces went
  unenforced. *"Resolves" was the wrong verb.*
- **Story 4** made the environment contract a canon row a rule **derives** from the constructs that
  bind it, and reported the derivation it cannot do: an AST walk is structurally blind to a
  **syntax** floor, because it only ever sees what already parsed.
- **Story 5** made `run()` print three preflight lines before any verdict — git, stdout encoding,
  filesystem case-folding — all three of which were already assumed by shipping rules and none of
  which was reported.
- **Story 6** shipped `V27` and `V28`, and **reported the property it could not implement instead
  of faking it**: batch-88's defective merge and batch-89's correct one are identical in every
  field a local rule can read, so a rule keyed on *"below P4 with commits on `main`"* would be red
  today on correct work.

**Plus, mid-batch and outside the six stories:** the `notchild` traversal guard moved from one
caller into the resolver (`LED-89.20`, `LED-89.21`), `V29` shipped, the validator was made parseable
under the declared gate environment (rev53), and `V8`'s **three** defects were recorded — three,
in four lines, where the item that opened the work had named one (`LED-89.22`).

**Selftest arms: 402 → 565 (+163). Registered rules: 23 → 28, with `_SELFTEST_EXEMPT` empty — no
rule is exempt from proving its own RED.**

⚠ **`G-89-03` — 1,163 lines of new `s19_app` source landed under no requirement and no increment
packet.** `tools/sync_evidence.py` (628 lines, new) and `tests/test_sync_evidence.py` (535 lines,
new) in `c4e6fe5`, plus `tests/test_id_registry.py` (+10/−1) in `ed03b10`. They are the **only**
`.py` changes in the entire batch. They are reconciled in `BACKLOG-CODE.md`, which records
`c4e6fe5` as closing the recursive-SVG-copy `P3` — a real reconciliation, and **not a substitute
for an increment gate**: no source-file cap was evaluated, no RED counterfactual recorded, no
review ran, and no packet exists to say any of that.

---

## 2 · New controls discovered — and where they landed (C-45)

**What this batch produced is five enforceable RULES, not five catalog controls, and the
distinction is the whole content of this section.**

| Control / rule | What failure it closes | Measured origin |
|---|---|---|
| **`V26`** | a requirements record whose conclusions and reasoning drift apart, unnoticed | batch-88's record at 193,364 chars, 65.3% normative text in the forensic register |
| **`V27`** | a `decisions_log` that EXISTS and is not CURRENT — the same picture to every rule that shipped before it | batch-88 froze its log twice inside one batch, the second time **after** the freeze had already been found and repaired |
| **`V28`** | a batch superseded before it was closed, after which no supported path reaches it | batch-88 itself; 9 of 72 batch directories hold neither or only one closing artifact |
| **`V29`** | a rollover that carries the outgoing batch's log forward | `R-89-9`, raised by `V27` against its own batch |
| **`V30`** + the preflight | an environment contract asserted by hand, and three machine assumptions no rule reported | rev53: the validator could not be **parsed** by the interpreter its own gate declares |

**The four landings — recorded, and one of them did not happen:**

| # | Landing | Done? | SHA / path |
|---|---|:--:|---|
| 1 | the **command** (`~/.claude/commands/…`) | ✓ | `dev-flow.md` (§Batch rollover, rev51), `dev-flow-init.md`, `dev-flow-sync.md` — across rev48 → rev56, `~/.claude` at `1fd6748` |
| 2 | its **artifact** (a template section) | ✓ **partial** | `templates/dev-flow/req-template.md` gained the lean-contract field ruling (`LED-89.7`, six fields examined, three returned, three retired, each with its reason written **into** the template at the point of removal). No template section exists for `V27`/`V28`/`V29`/`V30` — they are rules, not artifacts |
| 3 | the **catalog** entry (`dev-flow-lessons`) with its measured origin | ✗ **NOT LANDED** | **`git log --since=2026-08-28 -- dev-flow-lessons` returns zero commits.** The catalog's highest control is still `C-56`, minted by batch-86. Batch-89 wrote none |
| 4 | **committed and pushed**, manifest re-hashed | ✓ | `~/.claude` `1fd6748` = `origin/main` (verified by `ls-remote`, not by a stale local ref) · skills mirror `e825ffd` = `origin/main` · `V7` green: `flow current (7ebb49bee3b82839)` |

### ⚠ The `C-45` catalog debt is now FOUR consecutive batches, and the notice convention says that must be decided here

batch-88's close recorded *"the `C-45` control landings, standing debt across batches 86, 87 and
now 88 — **still 0 landings**."* Batch-89 makes it **four**. The flow's own notice convention is
explicit:

> *"A notice that repeats for three consecutive batches stops being a notice. Either it becomes a
> rule — and then it blocks — or it is retired — and then it stops cluttering the checklist. That
> decision is taken at the batch close and recorded like any other."*

**This close cannot take that decision unilaterally**, because this project's own control-encode
rule requires an AskUserQuestion per control before one is encoded
(`BACKLOG-PROCESS.md` header). **So the decision is ESCALATED, dated, and named as an operator
decision item — not carried silently into a fifth batch, which is the only outcome the convention
actually forbids.** It is filed in §4 below.

**At least three portable lessons exist and are unwritten**, and they are recorded here so they are
not lost if the escalation stalls:

1. **A verification instrument must demonstrate it can report FAILURE before a single PASS from it
   is believed.** Two sentinels in this batch survived their first battery — `SENTINEL-must-be-RED`
   found an arm asserting `msg == _V30_NO_SECTION`, *the same constant on both sides*; and
   `N7-case-probe-is-assumed` replaced a whole case-fold probe with `return True, None` and
   survived twelve mutants, because **this machine really does fold case**, so the verdict was
   armed and the mechanism was not.
2. **An arm over a HELPER is not an arm over the RULE**, and an arm over the CORE is not an arm
   over the LOADER. Increment 1's first `_strip_code` arm called `_strip_code` itself and
   `M19-no-strip-code` survived it; increment 4's `M9` left every core arm green while turning the
   rule into four wrong BLOCKs.
3. **Learning a lesson and encoding it are different acts.** The lessons catalogue already carried
   the `python3` trap, and the flow shipped `python3` anyway — for long enough that `V17`
   certified a guard that had never run.

---

## 3 · Working-file reconciliation (C-44)

**Executed as a mechanical sweep across all three repositories this batch touched, 2026-09-03.**

| File / repo | State | Evidence |
|---|---|---|
| `~/.claude` (primary flow) | ✅ **committed and landed** | `git status --short` → empty. `rev-parse HEAD` = `1fd6748` and `ls-remote origin refs/heads/main` returns **the same SHA** — checked against the remote, not against the local ref `V16` correctly flags as 4.9 days stale |
| `~/.claude/skills` (bundled mirror) | ✅ **committed and landed** | `git status --short` → empty; `HEAD` = `e825ffd` = `ls-remote origin refs/heads/main` |
| `s19_app` — the 6 tail commits | ✅ **committed and pushed**, ⚠ **not yet merged** | `git log HEAD --not --remotes` → empty, so nothing is unpushed. `HEAD` = `976476d` = `ls-remote` of `claude/batch-89-lean-contract`. **No PR is open**, so `main` does not yet carry them and no CI run exists for them |
| `s19_app` — `.dev-flow/2026-08-28-batch-89/04-validation.md`, `05-close.md` | ⏳ **this close's own output**, committed with it | untracked at the moment of the sweep, by construction |
| `s19_app` — `.dev-flow/state.json` | ⏳ **this close's own edit**, committed with it | 26 insertions / 7 deletions; every field and its reason in §5. The serializer was proven to round-trip the file **byte-identically before any mutation**, so the diff is the change and nothing else |
| `s19_app` — `.dev-flow/BACKLOG-PROCESS.md`, `BACKLOG-CODE.md` | ⏳ **this close's own edit**, committed with it | the §4 reconciliation. Both written **encode-to-buffer-then-`os.replace`**, the discipline `BACKLOG-PROCESS.md`'s own header adopted after a mid-truncate left it at 0 bytes; backups taken first, line counts **563 → 615** and **1378 → 1383**, tails verified intact |
| `s19_app` — `.dev-flow/_derived/ATLAS-BATCHES.md` | ⏳ **regenerated**, committed with it | `--atlas --write`, the act `V20`'s own BLOCK message names. **Exactly one line changed** and zero new ids entered the derived plane |
| `C:\Users\jjgh8\close89_*.py` (3 throwaway scripts) | 🗑️ **deliberately deleted after use** | The `state.json` writer, the backlog reconciler and the population sweeper. Outside every repository, and their entire content is now transcribed into the artifacts they produced. Deleted rather than left loose — and named here rather than left to be inferred |
| `s19_app` — `build/` and 16 entries under `prototypes/` | 📋 **left in place ON PURPOSE — pre-existing, another session's** | `git status --short` lists them as `??`. **Reported as FOUND, never swept**: committing another session's work in progress is its own defect, and control `C-44` names it. Untouched by every command this close ran |

**Nothing is in limbo.** Every file this batch created or modified is in exactly one terminal state
above, and the two flow repositories are provably level with their true remotes rather than with a
local ref that has not been fetched in five days.

### Conditional-gate discharge

| Condition | Discharged? | The artifact line that proves it |
|---|---|---|
| `R-89-9` — *"the repair is one line of the rollover procedure, and is a batch-90 candidate"* (`increment-006.md` §4) | ✅ **partially, and the remainder is named** | `decisions_log` was scoped by hand on 2026-08-30 (`2f04ebb`) and is repaired again by this close. **The remainder is NOT discharged**: `stations_active`, `iterations_per_station` and `triggers` are all still byte-identical to batch-88's — verified by loading `git show 0f40624:.dev-flow/state.json` and comparing field by field. This close corrects one of the three; §5 says why not the other two |
| `P-8` — the cp1252 crash gated Story 2's increment | ✅ **discharged by measurement, not assumption** | reproduced on two surfaces before a line of the repair was written; `LED-89.8` corrected the premise's own figure in the same act |
| `HLR-89.3`'s CI asymmetry — *"the runner's provision of `python` was NOT measured"* | ⚠ **NOT discharged, and deliberately so** | `LED-89.10`. No GitHub runner is reachable from this machine. The threshold was narrowed to *agreement among the four LOCAL sites* rather than widened on an unmeasured premise. **Still unmeasured today** |

---

## 4 · Backlog reconciliation — the carry-over contract

**Lane: `BACKLOG-PROCESS.md` (lane B).** Routed per `docs/engineering-rules.md:15-18` — every item
below is an engineering-process item (the global `/dev-flow` command, its rules, its templates).
The one code-lane carry goes to `BACKLOG-CODE.md`, written **there**, per rule (4) of that same
section: *"a carry that belongs to the other lane is written there, in that batch's own close, not
left as a pointer."*

**Both lanes were prioritized cross-lane and pushed 2026-09-03 (`976476d`), hours before this
close. This reconciliation REFERENCES that pass rather than redoing it** — re-routing items a
measured pass has just routed is how an index and its items start disagreeing.

### Move 1 — mark shipped

| Item | Lane · band | Move | Reference |
|---|---|---|---|
| **`batch-89-unclosed`** | PROCESS · `P1` | ✅ **DONE** | `04-validation.md` and `05-close.md` exist; this close's merge SHA is recorded at the merge. `V28` will read batch-89's directory as complete the moment batch-90 opens |
| **`sync-P6`** | PROCESS · `P1` | ✅ **DONE, pending its live proof** | rev56 (`1fd6748`) rewrote `/dev-flow-sync` pre-requisite 2 to derive the closing station from `mode` — `P6` for `full`, **`P5` for `core`**. **The closure is claimed only when the live `/dev-flow-sync` run in this close's step 4 passes it**, which is its first live subject ever; if it refuses, this row reverts to open and the refusal is the finding |
| **`setuptools>=61.0`** | CODE · `P2` | ✅ already marked DONE at the 2026-09-03 pass | closed at `a679ee6` with per-version bracketing executed in throwaway venvs, **including a run at the old floor's exact value, which failed there** |
| **recursive-SVG-copy** | CODE · `P3` | ✅ already marked DONE at the 2026-09-03 pass | closed at `c4e6fe5` by `tools/sync_evidence.py`. ⚠ See `G-89-03`: the closure is real and the work had no increment gate |
| **vault pilot gallery staleness** | CODE · `P3` | ✅ already marked DONE at the 2026-09-03 pass | 96 evidence files, 90 dated 2026-08-31, the other 6 the retired `pv__case_06` set |

### Move 2 — carry forward, drop nothing

**New carries this close surfaces.** All to `BACKLOG-PROCESS.md` unless marked.

| Item | Band | Why it is new |
|---|---|---|
| **`G-89-01`** — `HLR-89.1`'s `Executed verification` names `V26 BUDGET-constant`, an arm that has **never existed at any revision** | `P2` | Found by this close's arm-by-arm re-derivation — the first time anything compared a requirement's named arms against the shipped ones. **Population enumerated first (`R-88-17`): 6 sites, 0 in the flow repo** — `01-requirements.md:81` (the only live normative site), `01-requirements-ledger.md:65` / `:100` (append-only), `increment-001.md:66` / `:276`, `state.json:68`. **Not repaired here**: amending the live contract owes its own ledger entry |
| **`G-89-02`** — `increment-006.md`'s closing section still states increments 4 and 5 were never built, and four packet headers still read *"4 built"* | `P3` | True when written, false now. Carried rather than edited: the packets declare their own write dates, and rewriting them would make the history read cleaner than it was |
| **`G-89-03`** — 1,163 lines of new `s19_app` source shipped under no requirement and no increment packet | `P1` | `c4e6fe5` + `ed03b10`. Reconciled in `BACKLOG-CODE.md` as a closure, never gated as an increment. **The process half is filed here; the code half is already in `BACKLOG-CODE.md`** |
| **`G-89-05`** — `01-requirements-ledger.md:258` carries a design-review citation ungrammatical under `V23` (a bare date after the design-review prefix where a batch-directory name is required), resolving to nothing. **Described, never reproduced — C-56** | `P3` | Live `V23` notice; unrepairable in place because the ledger is append-only |
| **`state.json` rollover remainder** — `iterations_per_station` and `triggers` are still byte-identical to batch-88's | `P2` | The unclosed two-thirds of `R-89-9`. `V29` cannot see it; the `mode`↔`stations_active` NOTICE proposed in the consolidated plan's step 3 would |
| **`V29` returns only its WEAK pass for this batch pair, permanently** | `P3` | batch-88 was superseded before rev51 and has no archived log; rev51 forbids fabricating one. Recorded so a future reader does not mistake the `[-]` for the strong direction |
| **DECISION — the `C-45` catalog debt has now repeated four consecutive batches (86, 87, 88, 89)** | **operator decision item** | The notice convention requires the become-a-rule-or-retire decision at a close. The project's control-encode rule requires an AskUserQuestion first. **Escalated with its three unwritten lessons transcribed in §2**, not carried a fifth time |

**Already filed at the 2026-09-03 pass and reaffirmed here rather than re-registered:**
`R-89-6` + `R-89-7` (`P0`) · `code-reviewer-absent` (`P1`, = `G-89-04`) · `R-88-17` (`P1`) ·
`no-canonical-mutation-harness` (`P1`) · `R-88-19`, `R-88-12`, `F-8` (`P1`) ·
`R-89-8`, `R-89-3` (`P2`) · `ifc-set-repr` (`P3`) · CODE lane `suite-gitignored-state` (`P2`),
`artifacts-capture-nondeterminism` (`P3`).

⚠ **`G-89-06` — no CI run exists for the six unmerged commits, which carry all 1,163 new source
lines.** It is **not** carried to the backlog because the merge discharges it by construction: the
PR triggers `tui-ci`. It is recorded here so the discharge is checked rather than assumed.

### ⚠ This reconciliation reproduced `R-88-17` and caught it — the second such incident in this close

**Marking two items `DONE` in one lane's index left FIVE other sites still asserting they were open
and blocking the close.** Enumerated before anything else was touched:

| # | site | what it still claimed |
|---|---|---|
| 1 | `BACKLOG-PROCESS.md` §*⚠ Read this before using the band order* | *"two `P1`s outrank both lanes' `P0`s operationally… the close artifacts do not exist"* |
| 2 | `BACKLOG-CODE.md` §*⚠ Read this before using the band order* | *"the two items that block it are BOTH in the other lane"* |
| 3 | `BACKLOG-CODE.md` cross-lane block | *"That lane holds 1 `P0`, **13** `P1`, 2 `MAJOR`, **19** `P2` and **12** `P3`"* — the counts I had just changed |
| 4 | `BACKLOG-CODE.md` cross-lane row | `sync-P6` *(blocks the batch-89 close)* |
| 5 | `BACKLOG-CODE.md` cross-lane row | `batch-89-unclosed` *(blocks the batch-89 close)* |

**All five swept in one act**, and the two band-order paragraphs were **kept rather than deleted**:
the tension they name — that a band-first index cannot express operational blocking — outlives the
pair that demonstrated it, and the next such pair will need the same escape hatch.

**`R-88-17` is a standing `P1` in the very lane being reconciled**, and the batch whose close this
is spent an increment on the mechanism built to close it. It still reproduced here. Together with
the `C-56` incident in `04-validation.md` §6, **this close hit two of the project's own catalogued
defect classes while writing the record of a batch about those classes.** Both were caught by
running something rather than by reading, which is the only reason either is in this document as an
incident instead of in the tree as a defect.

### Move 3 — refresh the header

Both lane files get a `last refresh: 2026-09-03 (2026-08-28-batch-89 close)` line and the
`origin/main` tip recorded at the merge SHA. **The 2026-09-03 hand refresh already carries the
correct tip (`a2a2534`) and the correct branch state; this close replaces it with the merge SHA
once the merge lands** — and until then, the honest header is that `main` does not yet carry the
tail.

---

## 5 · `state.json` — every field this close writes, and why

| Field | Before | After | Reason |
|---|---|---|---|
| `decisions_log` | 5 entries, newest 2026-08-30 | **7 entries**, newest 2026-09-03 | The two missing increments. `V27` reported both halves — packets 4 and 5 named by no decision, and the log behind the newest commit — and both findings are true |
| `current_station` | `"P3"` | **`"P5"`** | `mode` is `core`, and `/dev-flow`'s mode table makes `P5` the closing station for `core` (*"`core` closes with `05-close.md`"*, no `06-docs/`). `/dev-flow-sync` rev56 derives exactly this |
| `phase_status` | `"in_progress"` | **`"awaiting-sync"`** | The value `/dev-flow` Phase 6 names when the record is complete and the sync has not run. Also one of the two values `/dev-flow-sync` pre-requisite 2 accepts. ⚠ The old value was `in_progress` with an **underscore**; the schema spells it `in-progress` with a hyphen — a small drift, corrected by being replaced rather than by being edited in place |
| `stations_active` | `['P0','ARQ','P1','PDR','P3']` — **batch-88's array verbatim** | **`['P1','P3','P4','P5']`** | **DERIVED FROM THE ARTIFACTS ON DISK, never from what would make something pass.** `P1`: `01-requirements.md` + `01-requirements-ledger.md` exist. `P3`: six packets under `03-increments/`. `P4`: this batch's `04-validation.md`. `P5`: this file. **`P0`, `ARQ` and `PDR` are dropped** because batch-89 produced no artifact and no decision for any of them — the 2026-08-30 log repair says so in terms: *"no P0, ARQ, P1 or PDR entry was written for batch-89, because no such decision is recorded anywhere in this batch's record and a plausible entry is worse than an absent one."* |
| `iterations_per_station` | `{P0:0, ARQ:0, P1:1, PDR:2, P3:2}` — **batch-88's map verbatim** | **UNCHANGED — declared stale** | batch-89 recorded no iteration counts anywhere. Writing a derived-looking map would be inventing data, which is the one thing this close is least allowed to do. Carried to the backlog as the `R-89-9` remainder |
| `triggers` | `fired: ['A','B1','B4','C','E']`, `evaluated_at: 2026-08-24T21:30`, `record:` → batch-88's `PLAN.md` | **UNCHANGED — declared stale** | Same reason, and worse: the block carries **its own `evaluated_at` timestamp asserting an evaluation that never ran for this batch**, and its `record` points at a `PLAN.md` batch-89 does not have. rev51's rollover table names this exact failure. Repairing it means evaluating triggers for a batch that is already finished, which would be a fabrication with a date on it |
| `batch_objective`, `artifact_homes`, `batch_objective_superseded` | stale / batch-88's / an invented key | **UNCHANGED — declared stale** | `artifact_homes` still resolves every `<batch_id>` path to `.dev-flow/2026-08-24-batch-88/`; `batch_objective` still names the superseded `55000` budget and lists shipped increments as *"NOT IMPLEMENTED"*; `batch_objective_superseded` is a hand-added key rev51 names as the thing not to do. All three are the rollover's job, and repairing them at a close would hide that the rollover never ran |
| `obsidian_synced` | `false` | `false` → **`true` at the sync**, per `/dev-flow-sync` step 8 | ACTIVE case: the sync writes it and step 9 requires it to reach `origin/main` |

⚠ **A tension worth naming rather than resolving quietly.** The consolidated plan's step 2a item 5
says *"do not hand-edit `stations_active` to satisfy anything"*, and §4 item 7 repeats it as a
prohibition. This close edits it. The two are reconcilable on the plan's own wording — the
prohibition is against editing it **to make a check pass**, and `/dev-flow-sync` rev56 states
explicitly that `stations_active` is **not consulted**, so correcting it makes nothing pass. What
it does is stop the field asserting batch-88's evaluation as batch-89's. **The correction is
derived from artifacts, its derivation is written above, and this paragraph exists so the
disagreement can be argued at the criterion rather than discovered later.**

---

## 6 · Declared gaps — what this close cannot deliver

| # | Gap | Why it cannot be closed now |
|---|---|---|
| **`G-89-04`** | **No independent `code-reviewer` pass, 0 of 6 increments.** batch-88 ran that lens 7 times over 7 increments and **6 came back BLOCK** | Not recoverable retroactively at any useful fidelity: three of the six increments were built at revisions the validator has since moved past. What *is* available is a review of the merged diff, and it belongs to a future pass, not to this close. `04-validation.md` §7 measures what the absence cost |
| **`G-89-07`** | **Four of six increment packets are reconstructions** — 1, 2, 3 and 6, all written 2026-08-30 for work committed 2026-08-29 and 2026-08-30 | Cannot be undone. Each says so in its own header with its own dates, which is the only honest form available after the fact. Increments 4 and 5 were written at the gate before any commit, so the batch **ends** doing this correctly |
| **`G-89-08`** | **Per-increment arm and mutant attribution for increments 2 and 3** | One commit (`1d2e9fe`) carries both increments; the +12 arm delta and the 13-mutant battery were never split, and no harness transcript survives. Marked **ABSENT** in both packets rather than apportioned by guess |
| **`G-89-09`** | **Increment 1's mutation tally does not reconcile** — 19 final vs 12 named + 12 review-scored | Both figures are printed in `increment-001.md` §4 rather than averaged. No harness transcript survives in either repository |
| **`G-89-10`** | **`HLR-89.4`'s API floor of 3.7 is documentary and will stay so on this machine** | No interpreter below 3.11 exists here. `V30`'s own finding carries the words *"DOCUMENTARY, NEVER EXECUTED"*, and `04-validation.md` does not upgrade it |
| **`G-89-11`** | **The GitHub runner's provision of a bare `python`** — the premise `flow-selftest.yml:40`'s `python3` asymmetry rests on | Unmeasurable from here, and `LED-89.10` says so rather than assuming. The threshold was narrowed instead of the premise being guessed |

**None of these was filled with a plausible value.** Where evidence does not exist the field is
marked ABSENT with its reason — which is the same discipline batch-88's retroactive close used, for
the same reason.

---

## 7 · Batch metrics — the 12 keys of `core`

```yaml
type: dev-flow-batch
project: s19_app
batch_id: 2026-08-28-batch-89
mode: core
verdict: pass
increments: 6
source_files_max: 0
notices_raised: 21
rework_returns: null
triggers_fired: null
tests_base_to_post: "2735 -> 2760"
new_control: none
open_items_next: 52
```

**Every key's derivation, because a metrics block without one is a claim:**

| Key | How it was obtained |
|---|---|
| `verdict` | `pass` — the enum admits only `pass` / `iterate`. **The real verdict is PASS-WITH-NOTES**, `04-validation.md`; nothing blocks, and 4 evidence-checklist items are ✗ |
| `increments` | **6** packets on disk — `001`, `002`, `003`, `004`, `005`, `006`, enumerated rather than written as a range (C-56 forbids dotted/dashed id shorthand wherever a scanner reads, and `.dev-flow/**` is scanned). All six built. The record declared five stories; Story 6 arrived through the ledger (`LED-89.19`) |
| `source_files_max` | **0** — every one of the six packets declares `0 / 4` source files **in `s19_app`**. ⚠ In the flow repo the maximum is **3** (increment 003: `devflow-validate.py`, `hooks/flow-guard.py`, `hooks/install.py`), under a cap of 4. ⚠⚠ And **2 source files landed in `s19_app` outside any increment** (`G-89-03`), where no cap was evaluated at all. **The single number is the least informative of the three and all three are printed** |
| `notices_raised` | **21** — `grep -o "⚠" | wc -l` over the six packets: 5 + 4 + 4 + 2 + 2 + 4. The contract and the ledger carry **0**, by design |
| `rework_returns` | **`null` — no QA phase checklist exists for this batch.** The key is not dropped and no zero is invented: zero returns and no measurement are different facts |
| `triggers_fired` | **`null`.** `state.json` carries `['A','B1','B4','C','E']` with `evaluated_at: 2026-08-24T21:30`, which is **batch-88's evaluation**, byte-identical. **No trigger set was ever evaluated for batch-89**, so reporting one would be reporting batch-88's |
| `tests_base_to_post` | **COLLECTED counts, not passing counts, and `04-validation.md` §5a says why**: the two endpoints are different pytest invocations — CI's push lane runs the full suite, this close ran the PR lane's `-m "not slow"` — so passing counts are not comparable and collected counts are. Base **2735** from CI run `33352981125` on `a2a2534` (2697 + 35 + 3); post **2760** from this close's run (7 + 2726 + 3 + 3 + 21 deselected). **`2760 = 2735 - 0 + 25`**, and the **+25 was measured independently** by collecting `tests/test_sync_evidence.py` — 25 tests — agreeing exactly with the endpoint delta. ⚠ **The post figure has no CI behind it**: no run exists for the six unmerged commits. ⚠ **7 failures**, inside the 6/10/6 band two open `P2` items already measure, and **none of the seven is in a file this batch touched** |
| `new_control` | **`none`.** Five enforceable rules shipped — `V26`, `V27`, `V28`, `V29`, `V30`, enumerated for the same reason; **zero `dev-flow-lessons` catalog entries**, verified by `git log --since=2026-08-28 -- dev-flow-lessons` returning nothing |
| `controls_stress_tested` (a `full`-mode key, recorded anyway) | **5** — the two sentinels that survived first (`SENTINEL-must-be-RED`, `N7-case-probe-is-assumed`), the two red baselines refused rather than scored, and the broken mutant rewritten rather than counted as a survivor |
| `open_items_next` | **52** — `BACKLOG-PROCESS.md`'s 2026-09-03 index states `P0` 1 · `P1` 13 · `MAJOR` 2 · `P2` 19 · `P3` 12 = **47**, **minus 2** closed here (`batch-89-unclosed`, `sync-P6`), **plus 6** new carries and 1 escalated decision from §4 = **52**. **Re-derivable against the reconciled file rather than against a pre-close snapshot:** the index now reads `P0` 1 · `P1` 12 · `MAJOR` 2 · `P2` 21 · `P3` 15 = **51** open, **+1** decision item = **52**, and the two routes agree. ⚠ Lane B only; `BACKLOG-CODE.md` is counted separately and is not reconciled by this batch beyond the three already-marked closures |

### Declared limits of assurance (ISO 9241-210 and beyond)

**Stated as limits so they are decisions, not discoveries:**

- ⚠ **Evaluation with real users was NOT performed.** No user-facing surface changed; every
  requirement in this batch is about the engineering flow. Inspection with declared criteria is
  what was done instead.
- ⚠ **No independent review lens ran, at any increment.** §6, `G-89-04`.
- ⚠ **The suite figure comes from one machine, one OS, one interpreter, with no CI behind it.**
  `G-89-06`.
- ⚠ **The `python-api` floor of 3.7 is asserted by analysis alone** over an enumerated construct
  catalog that is blind outside itself. Two interpreters are two points, not a range.
- ⚠ **`V27` cannot tell a packet from a placeholder**; six empty files would satisfy it.
- ⚠ **`V26` does not enforce append-only.** Deleting an entry together with its pointer leaves
  both pair sets equal and the gate green (`R-89-5`).
- ⚠ **The three preflight lines are not findings.** They inform; no rule blocks on them.

---

## 8 · The verdict on the batch itself

**1 · The batch shipped the rule that caught the batch, and then obeyed it.** `V27` was written by
increment 6, fired against increment 6's own record within minutes of landing, and its two findings
were declared as `R-89-9` rather than silenced. The four retroactive packets are that finding's
repair; this close is the rest of it. **That sequence is worth more than a batch with no findings
would have been** — and it does not make the retroactive packets equivalent to packets written at
the gate, which is why §6 keeps them as a declared gap rather than a colourful anecdote.

**2 · The strongest evidence in the batch came from instruments turned on their own authors, and
the weakest gap is that no one else ever looked.** Five separate defects were found by a sentinel,
a mutation battery or an arm failing on its own author's expected value — including one
(`INT INTERP-parse`) that would otherwise have false-BLOCKed most of Windows on the one rule whose
BLOCK stops the flow. That is a genuinely good self-check culture. It is also, structurally, the
wrong instrument for the one class of defect where the *author's model* is wrong — and `G-89-01`
is a live specimen: a requirement citing an arm that has never existed survived six increments,
four packets, an append-only ledger and two merges, and was found only when this close compared
each requirement's named arms against the shipped ones for the first time.

**3 · A rollover is a procedure, and this project has now paid for it twice.** batch-88 could not
be synced because it was superseded unclosed; batch-89 opened carrying batch-88's `decisions_log`,
`stations_active`, `iterations_per_station` and `triggers` verbatim. rev51 wrote the procedure and
`V29` reads back one field of it. **Three of the four fields this batch found stale are still
stale at this close, and they are stale on purpose**: correcting them would mean writing iteration
counts nobody recorded and a trigger evaluation nobody ran. **The fix is a rollover that runs, not
a close that fabricates.**
