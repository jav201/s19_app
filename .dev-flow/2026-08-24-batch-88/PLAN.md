# PLAN — s19_app — batch-88 · audit closures (Layer C · assurance limits · RC-2 · canon seeding)

> **Station P0 · INTAKE.** Mode **core**. Artifact language **English**.
> **Naming note, and it is not cosmetic:** the proposal labels its stories `US-<letter>`. Those are
> **proposal-local labels, not requirement ids**, and writing them in a repo document mints phantom
> ids into the derived Atlas — measured, see §6. This plan calls them **Story A / B / C / D / E**
> and reserves the id namespace for the real ids Phase 1 will author.

## 1 · RC-1 — recorded BEFORE deriving anything

| | |
|---|---|
| `origin/main` tip | **`4131a384254e8f764bd3ba7e1d7302322178a97c`** (`4131a38`) |
| `merge-base HEAD origin/main` | `4131a384254e8f764bd3ba7e1d7302322178a97c` — **identical, RC-1 PASS** |
| Branch | `claude/batch-88-audit-closures`, cut from that tip |
| Flow | `2026.08.24-rev46` · `flow_hash 9c1449ed815d267c` — verified against the manifest (C-45 PULL) |
| Selftest | **192 arms, `SELFTEST PASSED`, exit 0** |
| Validator at open | **`0 block · 284 notice · 15 not applicable`** (after the Atlas regen of §5) |

## 2 · Scope — operator-declared

> **⚠ CENSUS BASELINE SUPERSEDED — re-measured 2026-08-25**, per `PDR-2026-08-25-batch-88#D4`.
> Every `276 of 544` and `280 of 544` below is **kept as written and is no longer the
> baseline.** Re-executed: shipped **302 of 570**, patched **306 of 570**, delta **+4**
> (`HLR-053`, `HLR-056`, `US-064`, `US-068`). **The +4 delta survives; the baseline does not**
> — batch-88 declared 26 ids of its own while the figure was being written. The declared
> baseline now lives in `state.json.batch_objective` and `01-requirements.md` `LLR-88.8`, and
> **carries its measurement date as part of the figure**. The prose below is preserved as the
> derivation that was true when it was run, not as a current reading.

**Stories A + B + C + E.** Story D (C-45 reconciliation of 15 half-encoded controls) **deferred** —
it is reconciliation, not design, and defers without damaging the others.

| Story | Gap | Context of use — user · task · environment | Observable outcome | Already shipped? (probe) |
|---|---|---|---|---|
| **A** — Layer C, rule **V24** | ASPICE SWE.5 / DO-178C A-5 | flow operator · close a batch whose map declares `Frozen?` interfaces · s19_app, validator at the gate | `04-validation.md` carries a Layer C table (`Module │ interface │ measure │ node on disk`) and the validator reports the new rule green | **No.** `grep -r "Layer C"` over the flow repo → **0 hits**; `grep '"V24"'` in the validator → **0** |
| **B** — declared limits of assurance | ASPICE SUP.1.BP1 / DO-178C independence 0/67 | reader of a batch close, regulated client included · judge what assurance backs the deliverable · reads `05-close.md` with no access to the session | the close carries the section with its three fixed lines | **No.** `grep -ci "independence\|assurance limit"` in `close-template.md` → **0** |
| **C** — RC-2, rule **V25** | ASPICE SUP.8.BP8 | single operator (more exposure, not less) · open a batch · INTAKE, beside RC-1 | the INTAKE checklist shows RC-2 with executed evidence | **No.** `grep -c "RC-2"` in `phase-checklists.md` → **0** (RC-1 is row 4; RC-2 becomes row 5) |
| **E** — canon consolidation | operator request | human auditor of the project · read the current state without excavating 73 batches · the living canon | the V22 census falls by a measured delta | **No.** V22 reports **276 of 544** batch-declared ids unreflected |

**Risk estimate.** Story A is the highest-criticality and the highest-risk: it is the only one whose
anchor does not exist yet (§4, condition 1) and the only one that can land on the selftest's
synthetic-exemption list and thereby violate acceptance criterion #1. Story C is lowest-risk and goes
first deliberately — it debuts the new-rule pattern on the smallest surface. Story B is
documentation plus a checklist guard. Story E is bulk, mechanical, and parallelisable.

## 3 · Triggers — evaluated AND recorded, each with its probe (C-48)

**Five families fire. batch-87 fired one.** This is not a light batch and the plan says so at intake.

| id | Verdict | Probe output |
|---|---|---|
| **A** — structure | **FIRED** | *Judged, not probed — family A has no mechanical probe by design ("needs the module map to have a probe; until then, judged and said so").* It **plans parallel increments** (two lanes, §7) and **`PDR-2026-08-24-batch-88#D1` changes the module map itself**. → **the ARQ station activates**, and the PDR fires with it. |
| **B1** — shared surface | **FIRED** | The selftest arms `MAP COVERS-complete` and `MAP COVERS-no-ghosts` assert `_RULE_COVERS` completeness. `PDR-2026-08-24-batch-88#D4` touches `_RULE_COVERS`, so the symbol is asserted by arms belonging to another concern. → reverse census (C-26) + design review |
| **B2** — file moves | did not fire | `sha256` of both `close-template.md` copies: **`3e8f07ab9d63fb55` — byte-identical.** It is a deploy, not a fork, so `PDR-2026-08-24-batch-88#D5` resolves without moving anything. **This probe also discharges PDR condition 3 at intake.** |
| **B3** — golden drift | did not fire | `tests/goldens/` holds **7** per-batch report captures (`batch35`…`batch78`). `grep -rl "ARCHITECTURE\|REQUIREMENTS.md\|pyproject" tests/goldens/` → **empty**. No golden captures a source this batch touches. |
| **B4** — consumed artifact | **FIRED** | V24/V25 emit validator lines the gates consume; `phase-checklists.md` is consumed by every batch; the §4 interface table is consumed by **both** V24 and V8. → output-then-consume AT (C-12) |
| **C** — security | **FIRED** | `PDR-2026-08-24-batch-88#D6` adds a dependency to `pyproject.toml` — the dependency/external-integration family. **Re-run over the diff at EVERY gate, not once at P2.** Already PDR condition 5. |
| **D** — interaction | did not fire | The planned file set contains **0 files under `s19_app/tui/`**. Nothing this batch writes changes what a TUI user sees or touches. |
| **E** — size and risk | **FIRED** | **4 stories ≥ 3** and **5+ planned increments ≥ 3.** See §4 — this one changes the batch's obligations. |
| **F** — flow currency | did not fire | local `flow_hash 9c1449ed815d267c` **==** the manifest (V7 green); backlog reconciled at batch-87's close, both lanes. |

## 4 · What firing E costs — the proposal's out-of-scope declaration is partly void

The proposal declares *"estimación/calendario (MAN.3.BP5/BP8 — se declaran fuera para batches
internos; **obligatorios cuando dispare familia E**)"* out of scope.

**Family E fires.** By the proposal's own condition, estimation and schedule are therefore
**obligatory for this batch**, not out of scope. Recorded here rather than discovered at close.

Triggers only raise, never lower (rule 1), and once fired they stay fired even if scope shrinks
(rule 3). Shrinking to ≤2 stories would not retract this: it would require closing this batch and
opening another, with its record.

## 5 · The V20 flow-rev tax, paid (PDR-2026-08-24-batch-88#D8)

`main` opened at **4 block**, all four V20, all one cause: the flow bumped rev45 → rev46 after
batch-87 closed, and the Atlas header stamps the flow that derived it. Regenerated with
`--atlas --write` and committed as this batch's opening act — the pattern batch-87's own P0 followed.

**Ledger, reconciled term by term:** 4 block → 0 (the four V20 collapse into one `[-] atlas current
(4 files, census 1)`, so *not applicable* rises 14 → 15). One notice appeared and then left again:
V16's currency arm flipped to NOTICE because its local ref had gone 1.0 days stale — a **clock
effect, not a change of mine** — and `git -C ~/.claude fetch` returned it. Final: **`0 block ·
284 notice · 15 n/a`**, identical to what batch-87's close recorded.

**Budget the second payment:** Inc 4 bumps to rev47 and will raise the same four V20 again. Full
procedure including step 4 (re-hash) — the rev46 lesson.

## 6 · A live C-56 instance, caught by the control, one regeneration from permanence

Writing this batch's opening documents **minted a phantom id.** The Atlas id scanner adopted the
bare proposal label `US-<E>` from the handoff and registered it as a requirement id: unique ids
1436 → **1437**, "never in the canon" 1004 → **1005**, a new row in `ATLAS-TRACE.md`.

Measured honestly rather than assumed — and the first measurement was **wrong**: `git restore
--staged` unstages but leaves the working tree, so the first grep read the regenerated copy and
reported all five letters as pre-existing. Re-measured from `HEAD` explicitly: `US-<A>`…`US-<D>`
were already present (**pre-existing, part of batch-87's registered 8-feeder / 3-stem carry**) and
`US-<E>` stood at **0**. Exactly one stem was mine.

**Fixed at the source, never in the derived plane:** the five labels were rewritten out of the id
namespace ("Story A/B/C/E"), regenerated, and `US-<E>` verified back to **0**.

**The generalisable lesson, offered to the catalogue:** a proposal that labels its stories with the
`US-` prefix is writing in the id namespace. The moment such a document reaches the repo the labels
become ids. The proposal template should forbid `US-`-prefixed labels for anything that is not a
real requirement id — a guard on the template, not a warning in prose beside it.

## 7 · Lanes — disjoint by construction

| Lane | Increments | File set |
|---|---|---|
| **1** | Inc 1 → Inc 4 | the flow repo (`devflow-validate.py`, `phase-checklists.md`, `close-template.md`, `validation-template.md`, `architecture-template.md`, `FLOW-VERSION.md`) + s19_app's `docs/ARCHITECTURE.md`, `pyproject.toml` |
| **2** | Inc 5+ | s19_app's `REQUIREMENTS.md` and the living-canon family only |

`modules(1) ∩ modules(2) = {}` — the mechanical parallelisation rule is satisfied without appealing
to the different-layers clause. The DDR is the join, and its crossed reverse census is the check
that structurally cannot be done from inside a lane.

## 8 · The PDR, and a declared sequencing deviation

`PDR-2026-08-24-batch-88#D1` … `#D8` are sealed in the vault, verdict **`approved with conditions`**.
It authorises **Inc 1 and Inc 2** and **withholds Inc 3 and Inc 4** until `#D1` lands.

⚠ **Deviation, declared not hidden.** The flow's station order is INTAKE → ARQ → REQUIREMENTS →
**PDR**. This record was sealed **before INTAKE**, and it therefore reviewed the **design proposal**,
not the authored requirements — which is why its item *"every requirement has foreseen coverage"* is
a ⚠ and not a ✓. Reviewing the proposal this early is what caught the load-bearing Story-A defect
before any work started, so the deviation bought something real. **It does not discharge the
station-4 PDR**, which reviews the requirements Phase 1 will author.

🛑 **And the seal rule cannot be honoured by the grammar.** The seal says a changed record is *"a NEW
version with a NEW id"*, but `V23`'s conformance test is
`^(?:PDR|DDR)-\d{4}-\d{2}-\d{2}-batch-[A-Za-z0-9]+#D\d+$` — the batch segment admits **no hyphen**,
so `…-batch-88-v2#D1` does not parse. The grammar can express a decision inside a record but neither
**the record** nor **its version**. This is the second defect found in V23 today (the first: it
cannot tell a citation from a filename). Both are registered for this batch beside
`PDR-2026-08-24-batch-88#D4`, whose subject is precisely *a rule's description matching what it does*.

## 9 · Synergy worth naming

V8 currently reports `docs/ARCHITECTURE.md: map declares no path/** prefixes — it cannot be checked`.
That is the **same file** `PDR-2026-08-24-batch-88#D1` must give a §4 interface table. Landing D1 is
the natural moment to give the map its `path/**` prefixes as well, retiring a standing notice with
work the batch is doing anyway — **to be decided at ARQ, not assumed here.**

## 10 · Mode

**`core`**, unchanged from batch-87 under the same C-50 ruling: the IFC-style record's declared home
is `.dev-flow/<batch>/01-requirements.md`, a Phase-1 artifact `/fast-dev-flow` has no phase for.
No `mode_history` entry — there is no change to record.

## 11 · Authorisation

Confirmed by the operator 2026-08-24: **autonomous; gates self-approved WITH evidence; merge granted
explicitly by the operator at close.** Same pattern as batch-86 and batch-87. Authorisation is
**per batch** — this is its record.

## 12 · 🛑 The gate reports 14 BLOCK at this station, and every one is a KNOWN FLOW DEFECT

**Not this batch's content. F-7's residue, in the window rev39 did not cover.**

batch-85 found `F-7`: `V1`–`V9` were evaluating `.dev-flow/2026-05-05-batch-01/01-requirements.md`,
frozen in May, so **all 14 live BLOCKs named batch-01 ids** and a batch's acceptance criterion *"no
BLOCK attributable to this document"* was true over any content whatsoever. `rev39` fixed it by
making `_artifacts()` prefer the batch `state.json` declares.

**The fix is conditional on the active batch having ALREADY AUTHORED the file.** Read the loader
(`devflow-validate.py:2236`): the bare walk fills every basename first-wins across all 70 batch
dirs; the active-batch pass then overrides **only the basenames that exist inside it**. At P0 the
active directory holds `PLAN.md` and nothing else, so `01-requirements.md` keeps the first-wins
value — batch-01's — and `V1`–`V9` judge a May document. **The pre-rev39 behaviour returns exactly,
including the count.**

**Proved by executed mutation, not asserted:**

| Arm | State of the active batch dir | Validator |
|---|---|---|
| observed | `PLAN.md` only | **14 block** · 284 notice · 14 n/a |
| mutation | any `01-requirements.md` present | **4 block** · 316 notice · 13 n/a |
| restored | `PLAN.md` only | **14 block** · 284 notice · 14 n/a |

And the ids resolve where the mechanism predicts: `LLR-002.1` ×10, `LLR-005.3` ×12, `LLR-009.2` ×3
all live in `.dev-flow/2026-05-05-batch-01/01-requirements.md`, which is the **first** directory
`os.walk` reaches (`2026-05-05-batch-01` sorts first).

**Why this matters more than a cosmetic count.** Every batch passes through this window — between
pointing `state.json` at the new batch and Phase 1 authoring its requirements — and in it the gate
is judging a document from May. A P0 that records *"0 block"* did so only because it ran on the
other side of the window. **The condition is invisible unless someone runs the validator exactly
here, which is what this station just did.**

**Proposed fix direction (design input for this batch, not a decision taken here):** *absent* and
*some other batch's copy* are different states and the loader conflates them. When `state.json`
declares an active batch and that batch lacks an artifact, the loader should report it **ABSENT**
and let the rules that need it SKIP — never substitute a foreign batch's document. This is the same
principle the flow already holds elsewhere: *"`consumers : none` is legal and MUST be written; an
omitted field is a question nobody asked, and the validator treats the two differently."*

**Accounting for this station's gate line.** `14 block` is recorded, not hidden and not explained
away: **0 blocks are attributable to batch-88's content**, 14 are attributable to
`devflow-validate.py:2236`, and the discriminating mutation is in the table above. The figure will
fall to its true value the moment Phase 1 authors `01-requirements.md` — and if it does not, that is
a real finding rather than this one.

**Registered as a batch-88 candidate** beside `PDR-2026-08-24-batch-88#D4`. It is the third defect
this session found in the flow's own rules, and all three share one shape: **a rule whose behaviour
does not match what its description promises.**

---

# Station ARQ — module map amended *(activated by family A)*

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 1 | Module map updated — or "no architecture change" with its empty diff | ✓ | `docs/ARCHITECTURE.md` gains **§10 Composition (by path)** and **§11 Interfaces (`Frozen?`)**. Sections 1–9 unchanged — the map is a standing artifact and batches amend it. |
| 2 | Every planned file falls under a declared module | ⚠ | **266 tracked `.py` classified into 6 prefixes; exactly one orphan, `setup.py`, PREDICTED IN ADVANCE and named in §10.** V8 flipped from *"map declares no `path/**` prefixes — it cannot be checked"* to a checkable rule. Notice delta **net zero** (284 → 284): one unusable notice replaced by one true one. |
| 3 | Interfaces that change, listed | ✓ | **None change.** All three declared Part B contracts are **frozen** for this batch (§11) — batch-88 cites them, never touches them. That is what gives V24 real consumers instead of a synthetic fixture. |
| 4 | Lanes proposed with **disjoint FILE sets**, not just modules | ✓ | Lane 1 = flow repo + `docs/ARCHITECTURE.md` + `pyproject.toml`; Lane 2 = `REQUIREMENTS.md` and the canon family. Disjoint at file level, not merely module level (§7). |
| 5 | `rationale` per structural decision | ✓ | Three rationale rows in §10 (six-module cut · `prototypes/**` declared rather than excluded · `tests/**` as one module), each with its rejected alternative and its re-opening condition. |

## ARQ decision — `PDR-2026-08-24-batch-88#D1` is discharged, with a correction to its own wording

`#D1` asked for *"the §4 interface table"*. **Adopting the template's §4 numbering was rejected** and
the interface table landed at **§11** instead. s19_app's map predates the template: its §4 is
*"Patch Editor flow"*, cited from elsewhere. Renumbering would silently retarget every existing
citation — a rewrite masquerading as an amendment.

**Consequence, and it changes the rule this batch is about to write.** The Layer C rule **must key on
the table's SHAPE — the `Frozen?` column header — never on a section number.** A rule keyed on "§4"
is broken by every project that had a map before adopting the template, which is every project with
history. This is a strictly better rule than the proposal asked for, and it is only visible because
the anchor was checked against a real repo instead of against the template.

⚠ **Therefore the wording of PDR condition 2 is amended here** (*"V24 active over ≥1 interface marked
`Frozen?` in the table D1 created"* — no section number). The DDR re-reads this paragraph, not the
proposal's original sentence.

## A fourth flow finding — V8 cannot classify a root file

The staleness check extracts prefixes matching `` `path/**` `` and tests
`file.startswith(prefix + "/")`. **No declarable prefix can ever match a repository-root file**, so
`setup.py` is unclassifiable by construction and will report as an orphan forever.

The defect is not the notice; it is that the notice **says the wrong thing**. *"under no declared
module — the map is stale, ARQ fires"* asserts a stale map, when the true state is *"the rule cannot
express this file"*. Those are different conditions and the message conflates them — the **fourth**
instance today of the one shape: a rule whose behaviour does not match what its description promises.
Registered beside `PDR-2026-08-24-batch-88#D4`.

## A fifth finding, and it is the sharpest — the module map is invisible in CI

**Found by a self-inflicted mistake, which is the only reason it surfaced.** The ARQ amendment was
written with `cat >> docs/ARCHITECTURE.md` and then staged with `git add docs/ARCHITECTURE.md`.
The write landed; the `add` matched nothing. **Windows resolves the path case-insensitively, git's
index does not.**

| | |
|---|---|
| Tracked path | **`docs/architecture.md`** — lowercase, the only one in the index |
| Path the validator opens | **`docs/ARCHITECTURE.md`** — `devflow-validate.py:245` |
| On Windows (NTFS, case-insensitive) | `os.path.exists(...)` → **`True`**; V8 reads the map and works |
| On a case-sensitive filesystem | `_read()` returns `None` → **`V8 SKIP: "no docs/ARCHITECTURE.md (map not adopted here)"`** |
| CI runners | **`ubuntu-latest`** — `tui-ci.yml:25` and `:61`, `snapshot-regen.yml:23` |

**Consequence.** The module map — *"the **oracle** the A-family triggers read"*, whose whole reason
for living in the repo instead of the vault is that a mechanical check can open it — **does not
exist as far as CI is concerned.** Same repo, same commit, two different V8 verdicts depending on
the developer's filesystem. Every A-family verdict derived on Windows is unreproducible on Linux.

**This is batch-85's `F-7` wearing a different coat.** F-7 was *"a guard can be green because it is
reading the wrong file."* This one is *"a guard can be SKIP because it is reading a path only one
filesystem resolves"* — and SKIP is the quieter failure, because a skipped rule raises nothing at all.

**It also lands directly on this batch's own work.** The Layer C rule will read the same map by the
same hardcoded path. Written as-is, **V24 would be inert in CI** — the "rule that cannot fail" shape
that acceptance criterion #1 exists to forbid. **Fixing this is now a precondition of Story A, not a
side quest.** Two exits, and the choice belongs to the increment: rename the file to match the
validator (touches every existing citation of `docs/architecture.md`), or make the validator resolve
the map case-insensitively (touches one line and no citations). **The second is smaller and does not
retarget anything — the same reasoning that kept the interface table at §11.**

⚠ **Correction to the record.** Commit `01886a1` carries a message describing this map amendment and
**does not contain it** — the failed `git add` is exactly why. The amendment lands in the commit
that carries this section. The defective message is **not rewritten**; it is corrected here, beside
the evidence, per this project's standing discipline of repairing next to a record rather than over it.

### ⚠ Correction to the fifth finding — I made a vacuous claim, and a subagent caught it

The section above states *"the module map is invisible in CI"* and draws from it that *"every
A-family verdict derived on Windows is unreproducible on Linux."* **The first half is true but
measures nothing; the second half is wrong.** Corrected here, beside the original, not over it.

**What was actually measured before:** the mechanism (`devflow-validate.py:245` opens
`docs/ARCHITECTURE.md`, the index holds `docs/architecture.md`, CI images are `ubuntu-latest`).
**What was inferred and presented as observed:** that CI therefore gets a different V8 verdict.

**What is now measured:**

| Probe | Result |
|---|---|
| `grep -rn "devflow-validate\|dev-flow" .github/workflows/*.yml` | **empty — no workflow invokes the validator** |
| `.github/workflows/tui-ci.yml` steps | checkout · setup-python · install · `pytest -q -m "not slow"` (PRs) / `pytest -q` (pushes) · snapshot suite. **No validator step.** |
| `.git/hooks/` (non-`.sample`) | **empty** |
| `devflow-validate` in any `settings.json` hook | **absent** |

**Therefore CI produces no V8 verdict at all**, and "invisible in CI" is invisible the way anything
CI does not read is invisible. The harm I named does not exist, because the thing I claimed was
broken is never run there. **This is the vacuous-claim shape — a statement that cannot be false
because its subject never occurs — which is the same family as C-53 and the rev42 vacuous fixture.
Finding it in my own record is the point of writing measurements down.**

**What survives, restated honestly and at its true severity:**

- The mechanism is **real and latent**. The validator resolves the map only on a case-insensitive
  filesystem. It has only ever been run on Windows, where it resolves.
- It becomes **active the first time the validator runs on Linux** — a CI adoption, a second
  machine, a Linux contributor, a cloud agent session.
- It remains a **precondition for Story A**, and the reason is now sharper rather than weaker: a
  batch whose whole purpose is closing audit gaps is exactly the batch that would put the validator
  in CI. The day that step lands, V24 goes inert on arrival — a new rule that has never once run in
  the environment it was written to guard.

**And the correction has its own lesson.** The subagent drafting the catalogue entry refused to
write "observed" and demanded a CI transcript, listing it as *"predicted, not observed on the
failing platform."* It was right, and it was right about a claim its principal had already committed
to a message. **An independent lens that is allowed to say "you did not measure that" earns its cost
in one finding.**

---

# Inc 0 — the canon-mirror baseline, frozen and classified

**Artifact: `docs/CENSUS-BASELINE-canon-mirror.md`** — 1004 rows, each attributed to the batch
directory that first declares it. Home chosen by **measurement, not preference**: any `.md` under
`.dev-flow/` is read by the Atlas id-scanner (C-56), so the placement was tested in a throwaway copy
with a **positive control** — a sentinel id existing nowhere else — because the null result alone
would have been vacuous. `.dev-flow/**/*.md` reaches the census (**+1**); the reserved name
`01-requirements.md` also moves V22's denominator (**+34**); `_derived/` is a hard V20 BLOCK;
`docs/` and the repo root are unreachable. **Verified after landing: census figures identical
(1004 · 280 · 1436 · 276/544) and zero Atlas movement.**

## ⚠ Correction: the claim that V22 "reads only 3 files" was wrong

`_ifc_corpus()` walks all of `.dev-flow/` and collects **64** files named `01-requirements.md`. Only
**3** carry `FLOW`/`COMPONENT` blocks, and that 3 governs a *different* V22 census — the unowned-LLR
notices. The `276 of 544` spans all 64. The error came from measuring the FLOW/COMPONENT source set
and reporting it as the rule's scope. Corrected beside the original, not over it.

## What the single number was hiding — seven classes, not one backlog

| Class | Count | |
|---|---|---|
| **A** declared requirement, unmirrored | **269** | the true backlog |
| **B** heading in a non-`01-requirements` artifact | **51** | **invisible to V22 by construction** — a metric hole, not a seeding hole |
| **C** citation only, ≥2 occurrences | **426** | judgement zone |
| **D** retired on every occurrence | **7** | |
| **E** **not an id at all** | **129** | 97 range notations (`HLR-001..004`) harvested whole + 32 prose compounds (`LLR-level`, `US-less`) |
| **F** padding variant of a canon id | **11** | `LLR-085.1` vs `LLR-85.1` — a normalisation bug |
| **G** singleton citation | **111** | |

**A + B = 320 unambiguously owed. E + F + G = 251 (25%) are not requirement debt at all.**

**A hypothesis was FALSIFIED and it removes an argument this batch was leaning on.** *"Much of this
predates the canon"* is unavailable: `REQUIREMENTS.md` was added **2026-03-29**, the earliest batch
dir is **2026-05-05**. **Every absent id postdates the canon.**

**Retirement bounded both ways:** 7 ids carry a retirement marker on *every* occurrence; **189** on
*at least one*. The 182-id gap is unresolvable by regex.

## A seventh flow finding — the Atlas tokenizer harvests non-ids

Class E is not debt, it is **`_ATLAS_ID_REQ` failing**: the pattern requires no digit and carries no
lookahead guard, so `HLR-001..004` is taken as one id and the English words `LLR-level`, `US-less`,
`HLR-threshold-vs-LLR` are taken as ids. **129 of the 1004 are this.** Note the asymmetry worth
recording: the rev45 lookahead fix (`(?![-.]\w)`) was applied to the **AT/TC** tokenizer and **not**
to the requirement one — so the defect was already understood, and half-fixed.

Also measured: V22's own test is **substring**, not token, so `HLR-007a` reads as present because
`HLR-007` is. Quantified error: **4 ids** — the whole difference between the published 276 and the
corrected 280.

## Gate line at this station, accounted

**`15 block · 284 notice · 13 n/a`.** 14 are the F-7 residue (§12), **0 attributable to batch-88's
content**, and **1 is V16 — the flow repo went dirty mid-session with 11 `.excalidraw` diagrams
gaining a `rev46 · 2026-08-24` seal element, `mtime` 22:59, authored by neither this orchestrator nor
any dispatched agent's brief.** Per C-44 it is **reported, not swept**: foreign work is never
committed or reverted by the session that finds it.

---

# 🛑 The largest finding of this batch: the test ledger has never been checked

**V5 — "the validation ledger's arithmetic adds up" — has been reporting `SKIP` for 57 of 61
batches, and that SKIP reads as *nothing to check* rather than *I could not check*.**

## The mechanism

`v5_ledger` (`devflow-validate.py:148`) matches
`(\d+)\s*=\s*(\d+)\s*[-−]\s*(\d+)\s*\+\s*(\d+)` — **digits on both sides of the `=`**. The form the
project actually writes is `post = 2714 − 0 + 0`: the word `post`, not a number. It does not match.
Every non-matching file falls to the same terminal line:

```python
return out or [F("V5", SKIP, "04-validation.md", "no ledger expression found")]
```

**A file with a correct ledger and a file with none print the identical sentence.** Verified directly
against batch-87's real `04-validation.md` — the record whose own close asserts *"Ledger
2714=2702+6+3+3 exact"*:

| Input | V5 output |
|---|---|
| batch-87's real `04-validation.md` | `SKIP: no ledger expression found` |
| a file containing only `# nada` | `SKIP: no ledger expression found` |

## The scale, swept over the whole history

| | |
|---|---|
| `04-validation.md` files in history | **61** |
| V5 finds a parseable ledger expression | **4** (batches 09, 10, 11, 74) |
| V5 reports *"no ledger expression found"* | **57** |
| Files whose prose **claims** a reconciling ledger | **34** |

**At least 30 batches asserted a reconciling ledger while the rule that exists to verify it silently
found nothing to verify.** The claims are true — the arithmetic in those records does reconcile when
a human checks it — but they were never *mechanically* true. **Every "ledger reconciles" in this
project's history is a human assertion wearing a green rule's clothes.**

## Why it survived 61 batches, and why that is the real lesson

The file has diagnosed and fixed this exact shape **five times**: `_v7_outcome`'s own docstring
records that *"a missing manifest returned SKIP, rendering `[-] no manifest found` identically to
`[-] flow current`"*, and V7, V15, V20, V22 and V23 each carry a `PASS != NOOP` arm as the remedy.
**V5 is the only rule with a reachable no-op branch and no such arm.** Its `CLEAN` selftest arm
passes because it asserts *"not red"* — which the no-op branch satisfies. **The arm cannot fail.**

This is the vacuous-check family at its largest scale here: not one check that cannot fail, but a
check that could not fail across 61 batches while 34 records cited it.

## Standing on this batch — it changes an acceptance criterion

Story A's criterion #1 — *"no new rule on the selftest's synthetic-exemption list"* — was written to
stop V24 and V25 becoming unfalsifiable. **V5 proves the exemption list is not the only route.** A
rule can carry arms, pass them, and still be inert, if the arms assert only *"not red"* over a branch
that is never red.

**Criterion #1 must be widened before Inc 1 writes a line: every new rule owes a `PASS != NOOP` arm,
and its GREEN arm must assert the pass SENTENCE, not the absence of a BLOCK.**

## ⚠ A scheduling conflict to resolve before Story E produces evidence

> **⚠ RESOLVED AND RE-MEASURED, 2026-08-25.** Story E moved to batch-89 by operator ruling, so
> the conflict this section describes cannot occur in batch-88: the V22 fix lands here and the
> story that measures against it is authored later, over a still oracle — which is exit one of
> the two offered below, taken. **The figures in this section are superseded**: the move is
> **302 -> 306 of 570** measured 2026-08-25, not 276 -> 280 of 544. The **+4 delta is
> unchanged**; only the baseline moved, and it moved because this batch declared its own ids.
> `PDR-2026-08-25-batch-88#D4`.

The proposed V22 oracle fix (substring → token membership) moves the census **276 → 280**. This
batch's own `state.json` `batch_objective` declares:

> *"Story E: canon seeding tranches against the V22 census, **baseline 276 of 544**, oracle = the
> census delta pasted from the validator per tranche."*

**Landing that fix mid-story silently invalidates the story's declared baseline** — the precise
failure this codebase exists to prevent. Two exits, operator's choice: land the fix **before** Story
E produces any tranche evidence and re-baseline to 280 in the objective, or defer the fix past this
batch. **Do not let the number move under a story whose oracle is that number.**

## The other `_RULE_COVERS` mismatches found by the sweep

All 22 entries checked; 13 consistent. Beyond V5 and the already-recorded V8 inversion:

- **V2** — *"every acceptance id drives a node that exists"* tests **substring** membership against
  one concatenated string, so `AT-1` resolves because `AT-10` is on disk. The tokenizer with the
  truncation guard (`_ATLAS_ID_ATTC`) already exists in the same file and is not used here.
- **V6** — *"no should/debería inside a requirement statement"* requires both the `**Statement`
  marker **and** the modal on the **same physical line**, so a wrapped statement false-**passes**.
  `v4_method_without_verification`'s own docstring argues the opposite discipline, in the same file.
- **V16** — its sentence says *"both flow repos"* over **three** declared checkouts; residue of a
  hardcoded pair rev24 deleted from the code and left in the prose.
- **V1** — description narrower than behaviour (it scans every artifact, not only requirements).
- **V9** — judges every batch of closed history, producing **226 of the run's 284 notices**. Declared
  rather than hidden, so not a lie — but the single largest source of noise in the tool, reaching by
  another route the outcome `_artifacts`' docstring forbids for V1–V9.
