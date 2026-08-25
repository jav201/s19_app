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
