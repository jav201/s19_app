# HANDOFF — 2026-09-03 — rev56 intake + backlog: PLAN INPUT

> ## ⚠ WHICH HANDOFF THIS IS
>
> **This file is the INPUT.** It states what was measured, what is decided, and what is still open,
> so a consolidating reviewer does not have to re-derive any of it.
>
> **It is NOT the plan.** The consolidated plan is a SEPARATE file, written by the reviewer:
> `HANDOFF-devflow-session-2026-09-03-CONSOLIDATED-PLAN.md`, in this same directory.
>
> If you are reading this looking for "what do we do next", you want that file. If you are reading
> it to check a figure or a provenance, you are in the right place. **Do not merge the two.**
>
> Prior session handoff, for context only: `HANDOFF-devflow-session-2026-08-25-batch-88.md`.

## 0 · State at handoff

| | |
|---|---|
| flow | **`2026.08.31-rev55`**, `flow_hash 1aab42724c6c1b4a` — clean, pushed to `claude-config` + `agent-skills` |
| validator | **565 arms · 0 FAIL · `SELFTEST PASSED`**, exit 0 under **both 3.11.15 and 3.12.7** |
| gate on `s19_app` | **0 block** · 290 notice · 27 n/a |
| `--map` | `24 files in table order · 24 agree · 0 differ · 0 missing` |
| batch-89 | **all five stories BUILT**, station **P3**, `mode: core`. **NOT closed** — no `04-validation.md`, no `05-close.md` |
| branch | `claude/batch-89-lean-contract`, nothing unpushed |

**Shipped across the session:** rev48 `V26` lean contract · rev49 stdout-encoding hardening + `V17`
executing its interpreter · rev50 `V27`/`V28` · rev51 rollover + `V29` + derived sync copy list ·
rev52 `notchild` traversal guard · rev53 the validator made parseable under the declared gate env ·
rev54 `V8`'s three defects · rev55 `V30` derived environment contract + runtime preflight.

---

## 1 · PART A — the rev56 candidate

**Location:** `C:\Users\jjgh8\kimi\dev-flow-rev56-candidate\` (25 files). Documentation-only,
produced from a standards review dated **2026-09-01**. Applies **P1–P7, P12**; declines **P8–P11**.

### 1.1 Provenance — settled, do not re-check

- **It does not revert our work.** `scripts/devflow-validate.py` is **identical to canon apart from
  line endings** (`diff` after `tr -d '\r'` is empty), carries `V25`–`V30`, 9147 lines.
- **It is built on the real rev55 base** — every rev51 marker matches canon.
- **The README's mirror-commit line is stale** (claims `061bf93`, 2026-07-28, while declaring rev55).
- **The validator never parses the templates or commands — it only HASHES them.** Field-name parsing
  runs against the project's `.dev-flow/` artifacts. So a template edit cannot break the validator
  today; **it breaks the next batch's artifacts, one gate later.** That is why doc-only is not
  low-risk here.
- **Line endings are a "touched" tell:** untouched files are CRLF, the 16 the author edited are LF.
  **Normalize before applying** or `git diff` becomes unreadable.

### 1.2 Measured deltas (LF-normalized — `CHANGES.md`'s table is inflated by CRLF)

| file | claimed | **actual** |
|---|---:|---:|
| `commands/dev-flow.md` | −17,644 | **−17,009** |
| `templates/req-template.md` | −4,039 | **−3,678** |
| `templates/ifc-template.md` | −2,691 | **−2,428** |
| `commands/dev-flow-sync.md` | — | +824 |
| `phase-checklists.md` · `fast-dev-flow.md` · `dev-flow-init.md` | — | +248 · +115 · **0** (the +105 is CRLF) |

### 1.3 What the candidate found that was OURS — four defects, all verified

1. **`/dev-flow-sync`'s ACTIVE branch cannot pass pre-requisite 2 for any `core` batch.** It demands
   the LAST station be `P6` or `6`. **rev51 repaired the key-name half of that same condition
   (`current_phase` → `current_station`) and left the hardcoded `P6`.** Never fired because every
   sync so far took the SUPERSEDED branch. **It fires the moment batch-89 closes.**
2. **The `core` mode branch skipped step 6** — the step that generates the README, with 76 lines of
   frontmatter contract, which is the *only* thing `core` produces.
3. **The hand-kept `V1–V9` table documents 9 rules of 28.** Nineteen undocumented for ≥ 8 revisions.
4. **The selftest exemption hand-list `(V7, V8)` has been stale since rev47.** Measured: `{}` over 28.

### 1.4 Verdicts — per applied proposal

| # | verdict | note |
|---|---|---|
| **P1a** selftest claim → derived | **ADOPT** | verified; complete |
| **P1b** `core` step list | **ADOPT** | verified; `1→2→3→6→7→8→9` is correct |
| **P1c** sync pre-req 2 | **ADOPT WITH FIX** | defect real, **candidate's constant source is wrong** — see §1.6 |
| **P1d** §6.4 → ledger | **HOLD** | half fix — landed at 3 sentences, left §6.4/§6.5 declared at `req-template.md:326`, `:329` and cited at `dev-flow.md:164`. **Three homes for one obligation.** Also invents a *"Body edit landed? column"* the ledger has no columns for |
| **P1e** delete `deliverable + observation` | **REJECT** | **strictly worse than canon.** Field deleted; the Phase-2 blocker that gates on it survives at `req-template.md:82`, `review-template.md:11`, `:33`, `validation-template.md:22`. Author writes nothing, Phase 2 blocks them for it |
| **P2** fast-lane promotion | **ADOPT** | real contradiction, well fixed. **One cross-file inconsistency:** `fast-dev-flow.md:119` says `V7/V15/V16` (correct); P7's edit to `dev-flow.md` says `V15/V16/V17` (wrong — V7 blocks, V17 runs via the guard but is not in its blocking set) |
| **P3** origin extraction | **ADOPT WITH FIX** | 119 of 121 spans landed verbatim; `SKILL.md` **0 removed / 322 added**. **Two defects** — see §1.5 |
| **P4a** `RC-1 → RC-S1` | **ADOPT** | verified: RC-1 = base-currency at 9 sites, blank-artifact at only 2. Validator carries **0** occurrences of either |
| **P4b** verdict tokens | **ADOPT** | `PASS-WITH-NOTES` omission real; `approve`/`iterate` matches `dev-flow.md:168` verbatim |
| **P4c** the **Id grammar** | **REJECT** | **would make the live corpus ungrammatical** — see §1.7 |
| **P4d** lesson ids `V-3/4/5` → descriptions | **HOLD** | de-collides correctly but leaves those rules **with no id at all**. Give them a distinct prefix instead |
| **P5** example rows marked | **ADOPT** | purely additive. Note it disarms a live trap: `dev-flow-sync.md:87` BLOCKs a required table reduced to header+separator, and an author deleting the marked row now trips it. Worth one sentence |
| **P6** field-name language independence | **HOLD** | right intent, **wrong enumeration** — see §1.8 |
| **P7** validator by reference | **ADOPT WITH FIX** | correct shape (rev15 already ruled it). **Severity sentence is unsatisfiable** — see §1.9 |
| **P12a** 7-sentence collapse | **ADOPT** | best-executed change in the bundle: 7 → 0 and 7 new, all sites; obligation survives at `dev-flow.md:228` |
| **P12b** postmortem station grammar | **ADOPT** | clean |
| **P12c** PDR position | **ADOPT WITH FIX** | reorder correct, but *"runs AFTER P2 approval"* hardens one position the live record violates — batch-88 held **two** PDRs. Phrase as the blocking rule + *"may seal more than once per batch, one record per seal"* |
| **P12d** `phase-checklists` scoping | **ADOPT WITH FIX** | factually right; the rewrite leaves the unscoped claim restating itself two clauses later. Delete the second clause |
| **P12e** `close batch` → `request close` | **DROP** | no defect named; operator-typed token in **15 historical artifacts**; leaves the pair asymmetric with `open new batch`. If the intent was *"the agent may not close unilaterally"*, that is **P10**, not a rename |

### 1.5 P3's two defects

**(a) HIGH, one-line fix each.** A binding definition left **both** of its normative homes:

> *"A dependant is not only something that reads the value; it is anything that would break if the
> address moved."*

Measured: `dev-flow.md` canon **1** → candidate **0**; `ifc-template.md` canon **1** → candidate **0**;
`SKILL.md` candidate **2**. **This is the rule that decides what counts as a `consumers` entry, and
`V13`/`V14` parse that field.** The surviving text states the *form* (path, optional `::symbol`) but
not the *scope*, while its worked example still embodies the removed rule.

**Root cause is ours:** canon buried binding doctrine inside an `(Origin: …)` parenthetical, so P3's
mechanical rule was right and its result wrong at that one site. **The rule to mint: a parenthetical
may carry provenance, never a definition.**

Secondary: `ifc-template.md:17` now *uses* "misaddressed-observable" while its definition moved.

**(b) MEDIUM — extraction covered 3 of the 5 files carrying origins.** Un-extracted and the same
shape: `fast-dev-flow.md:145` (421 ch), `:174` (231 ch) — **the file was open for P2**;
`dev-flow-sync.md:148` (234), `:234` (263), `:90` (154) — **open for P1 and P4**;
`validation-template.md` (1 marker).

**On tag adequacy:** 43 of 64 tags name a batch mapping to more than one `SKILL.md` entry
(`batch-14` has 6). What rescues it is that `SKILL.md`'s headings reproduce the rule's title;
confirmed on 9 ambiguous cases. **One resolves poorly** — `dev-flow.md:504` "Golden double-proof
(batch-24)" has no matching heading. And the tag is **not** sufficient where the derivation is the
answer: the ≤ 4 source-file cap's derivation moved out, so the constant survives and *"why 4, and
why source-only?"* does not.

### 1.6 The correct `core`-mode sync condition — and a red herring I introduced

I flagged that batch-89's `stations_active` ends at **P3**, not the `P5` the candidate assumes.
**That was a red herring: the array is stale data, not a counterexample.** Measured:

```
batch-88 at its merge : stations_active = ['P0','ARQ','P1','PDR','P3']
batch-89 today        : stations_active = ['P0','ARQ','P1','PDR','P3']
```

Byte-for-byte identical. batch-89 has carried batch-88's array for six days because the rollover
reset only `decisions_log` — which batch-89's own `decisions_log` records in its `R-89-9` entry.

**`P5` IS the right constant for `core`**, derived from `dev-flow.md:38-43` and `:48`.
**`stations_active` must NOT be the authority**, for three measured reasons: it is **absent from all
20** `state-snapshot-at-close.json` files (the numeric-schema class the fallback exists for), its
order is trigger-shaped (`ARQ`/`PDR`/`DDR` interleave, so "last element" is positional), and it is
not reset at rollover. **Writing it as `stations_active`-derived reintroduces, in the sentence that
repairs pre-req 2, the "silently unevaluable" defect pre-req 2 forbids by name.**

The condition should read: read `mode`; closing station is **`P6` for `full`**, **`P5` for `core`**,
`fast` → command does not apply; read whichever of `current_station` / `current_phase` is present
(numeric maps to `6`/`5`); **neither key present is an ERROR, not a pass**; `stations_active` is not
consulted, and the sentence says why.

**And the rule the investigation actually exposed, which the bundle did not propose:** a NOTICE
comparing `mode` against `stations_active` — *the last station must equal the mode's closing station,
or the rollover did not run.* **It would have caught `R-89-9` at the gate instead of at the sync.**

### 1.7 Why P4's Id grammar must not ship

It declares `AT-NNN` and *"Mint nothing outside it."* Measured over batch-88 + batch-89:

| class | P4 declares | live form | unique ids |
|---|---|---|---:|
| AT | `AT-NNN`, regex `AT-\d+[a-z]?` | **`AT-B<batch>-<n>`** | **23** vs 2 in the declared form |
| TC | `TC-NNN` flat | `TC-B<batch>-<n>` | 24 |
| finding | **not declared at all** | `R-<batch>-<n>` | **67** — including `R-88-17` itself |
| HLR / LLR / US | `HLR-NNN`, `LLR-<HLR>.<M>`, `US-NNN` | `HLR-<batch>.<n>`, 3-part `LLR-N.N.N`, `US-N-N` | 14 / 10 / 2 |

**The validator holds two disagreeing AT grammars** — `_ATLAS_ID_ATTC` accepts `(?:B\d+-)?`, V2's
sibling does not — **and the candidate documented the narrow one.** Adopting it hands `V23` a
grammar that is **RED on correct history**, the false-fail this project already ruled against.

Also: the station mapping mints `REVIEW≡P2` and `DOCS≡P6`, names appearing **zero** times in canon.

**If an id grammar is wanted, derive it from the corpus** and state which form is canonical going
forward versus grandfathered.

### 1.8 P6's enumeration, measured against the validator

The candidate lists 8 field names as validator-parsed. Measured:

| listed | actually parsed? |
|---|---|
| `**Statement` | **yes**, English-only (`_V6_MARKER`) |
| `**Ledger:**` | **yes**, English-only (`_LEAN_PTR`) |
| `**Executed verification:**` | yes, **but Spanish accepted** (`verificaci[óo]n ejecutada`) |
| `**Numeric pass threshold:**` | words irrelevant; **`umbral` accepted** |
| `**Validation:**` · `Traceability` · `Negative control` · `Boundary catalog` | **no** — fixtures/comments only |

**It omits the ones that matter most:**

- **`**Requirement:**`** — `_LEAN_OWNER`, English-only, no fallback. **Declared four lines below the
  warning, in the same preamble the candidate wrote.**
- **`test(` / `analysis(`** — English-only, **no Spanish alternate**. Translate "test" and **V4 goes
  silent on that requirement.** The one whose translation disables a BLOCK rule with no fallback.
- **`FLOW:` / `COMPONENT:`** — the IFC keywords V10–V14 anchor on.
- the heading grammar `#{2,4}\s+(HLR|LLR|US|R)-`, `LED-`, and V5's ledger arithmetic form.

Canon's `ifc-template.md:5-6` was safer precisely because it did **not** enumerate. Either keep that
shape or ship the measured list.

### 1.9 P7's severity sentence

*"Severity is BLOCK unless the tool marks the rule NOTICE"* is **not satisfiable from `--map`**:
**5 of 28** COVERAGE lines carry a severity, and incidentally, in prose. The 23 that don't include
**V9, V25, V27, V28, V30 — all documented NOTICE elsewhere.** A reader following that sentence
classifies five NOTICE rules as BLOCK. Either fix the sentence (severity is per-finding on a real
run) or **teach `--map` to print it** — the latter is a validator change, out of a doc-only bundle's
scope, and is the fix that makes documenting-by-reference complete.

**On the trade:** `--map` needs the tool, and that is still the right trade — the alternative was a
table wrong by 19 rules for eight revisions. But the command file should say what a reader **without**
the tool loses: the rule list and the severities, both.

### 1.10 The bundle's own pattern — one lesson, not five

Every defect found is the same behaviour: **it enumerates from a single source when the population is
larger.** P4 (one regex, not the corpus) · P6 (a plausible list, not the validator) · P3 (three files,
not five) · P1e (one site, not five) · the control census (a hand count, one file over from the table
P7 just deleted for being hand-kept). **That is `R-88-17`, reproduced five times while fixing other
instances of it.** Worth telling whoever produced it — it is one lesson.

**What it did right and should be credited:** declared its non-regenerated hashes rather than faking
them · declined four proposals rather than guessing · flagged two residuals it could have hidden ·
its `CHANGES.md` was accurate about what it did in every place checked.

### 1.11 The two residuals it flagged

**Residual 1 is NOT residual — it is a dead gate.** `req-template.md:54` and `:64` still key live
rules on the retired `Acceptance criteria` field, and `:64` is a **declared Phase-2 blocker whose
entire subject is the retired field**. After the retirement it **can never fire.** Re-point it to
`Numeric pass threshold` + `Executed verification`, where the retirement record says the content went.

**Residual 2 is real, small, mischaracterized.** `dev-flow.md:544` is not syntactically broken; it
parses by ellipsis. The defect is semantic — the bullet is already a MANDATORY close step, so *"only
when the batch closes"* is vacuous. LOW. Correctly declined.

### 1.12 Conflicts with rev52–rev55

**None substantive.** Those revisions are entirely validator-side and the validator is byte-identical
modulo line endings; the candidate documents by reference, so it inherits them. `P1a`'s *"today no
rule is exempt"* is still true at rev55.

Two harmless gaps: the candidate never mentions `V30`, `notchild` or the preflight — **silence, not a
false claim.** And `FLOW-VERSION.md`'s control census fix is half right: the **range** `C-55 → C-56`
is verified correct; the **count** `24 → 25` is unverifiable — `dev-flow.md` cites **33** distinct
`C-` ids and "numbered" is nowhere defined. **Define the term or derive the number.**

---

## 2 · PART B — the backlog

Both queues were routed by hand on **2026-08-30** (batches 88 + 89, which had never been routed
because the routing rule fires at batch CLOSE and neither batch closed), then given a
**prioritization + closure pass on 2026-09-03**.

| file | size |
|---|---:|
| `.dev-flow/BACKLOG-PROCESS.md` | **172,204 B** |
| `.dev-flow/BACKLOG-CODE.md` | **277,754 B** |

Both now carry a **cross-lane prioritized index at the head**, derived from the items rather than
restating them — band, one line, pointer — because a summary beside the thing it summarises is the
defect this project has recorded six times and `NEXT-SESSION.md` forbids in its first line.

### 2.1 What the prioritization pass found on its own

- 🛑 **A `P0` this file's OWN header recorded as CLOSED was still open in the body — for 33
  days.** `R-TUI-102`. `R-88-17` inside the artifact that tracks `R-88-17`.
- **Four figures carried into the pass did not survive re-measurement** and are corrected at their
  items.
- **Amended rather than closed where an act was not a closure** — `requires-python >=3.11` stays open
  because it is a *decision* item; the `setuptools` `P2` closed with its verify clause **executed**.
- ⚠ **An incident inside the pass:** a write to `BACKLOG-PROCESS.md` failed mid-way and is
  **recorded rather than tidied away**, per `C-44`.

### 2.2 Items opened by this session, verified by execution

1. **`/dev-flow-sync` ACTIVE cannot pass pre-req 2 for `core`** — see §1.6. **P1-shaped, fires at
   batch-89's close.**
2. **3 of 531 arms print an unsorted `set` repr and vary run to run** under default `PYTHONHASHSEED`
   (three `IFC` arms). No verdict moves — but **an arm that diffed selftest output would fail on
   noise, and this flow writes that kind of arm.** Mine; small.
3. **The suite's failure count depends on gitignored state** — main repo 7–8 failures, worktrees 4–5.
   Confounded, never isolated. *A suite whose failure count depends on gitignored files cannot be
   trusted to reproduce.*
4. **`tests/_artifacts` capture is non-deterministic for 3 of 15 cases** — a time field renders
   `--:--:--` vs `00:00:00` in `case_03_overlapping_records`, `case_04_bad_checksums`,
   `pv__case_03_overlapping_records`.
5. **No increment of the entire session had an independent `code-reviewer` pass.** Every defect was
   found by the implementer's own sentinels. Process observation, not a code defect.

**Note on the flaky TUI suite:** my session-level finding of "11 non-deterministic failures" has a
**prior and better entry** from batch-87 — 11 node ids, one family, with **measured isolated rates**
(`4 of 10`, `1 of 10`, `order-dependent 0 of 10`) and five explicitly labelled **rate UNMEASURED**
rather than assumed. **Amend that entry; do not mint a rival.**

### 2.3 The instrument-blindness law — the session's largest finding, unencoded

**Five verification instruments reported the opposite of the truth, and none had been tested against
a known-bad input:**

| instrument | reported | truth |
|---|---|---|
| mutation verdict read by substring | 6 of 6 kills = survivors | killed |
| AST walk on the running interpreter | floor 3.7 | 3.12 |
| detector with a backwards regex under ANSI colour | `0 killed / 12 survived` | 12 killed |
| `ast.parse(feature_version=)` | *"3.7 accepts this"* | 3.11 refuses it |
| an arm comparing a constant to itself | green | blind |

**The first three were caught by looking twice. The last two were caught BY DESIGN** — a sentinel
that injects a deliberate failure and requires the detector to score it RED before any verdict is
trusted.

**This is one control, not five fixes:** *a verification instrument must demonstrate it can report
FAILURE before a single PASS is believed.* It is *"a test that cannot fail is vacuous"* applied one
level up — to the apparatus that judges the tests. **Its home is `dev-flow-lessons`, and it is
unencoded.**

---

## 3 · PART C — open operator decisions

**These are Javier's and none has been ruled.** Each is stated so it can be answered, not re-derived.

| # | decision | the shape of the answer |
|---|---|---|
| **D1** | **Adoption shape for the candidate** | three tranches (rev56 verified repairs → rev57 P3 remainder + P7 → hold the rest), or something else |
| **D2** | **P8** — does `/dev-flow-init` seed the current station schema and the rev48 two-file lean contract? | The candidate left the file **byte-identical** (LF delta **0**). The "never migrate old batches" rule already exists, so this concerns only new batches. **Almost certainly yes — and then it is scaffolding work, not a decision** |
| **D3** | **P9** — 11 orphan controls (`C-10, C-11, C-15, C-20, C-35, C-36, C-39, C-45, C-46, C-50, C-53`) | Not 11 decisions — **one existing policy applied 11 times.** `dev-flow.md:202` already rules: portable → global; stack-specific → project doc. Per control pick a bucket: **(a)** portable + gated — gets a template section and an artifact; **(b)** portable + advisory — demotes to `dev-flow-lessons`, no gate; **(c)** s19-specific — moves to `docs/engineering-rules.md`. **C-46 is not cited in `dev-flow.md` at all, so it is (b) already.** Same question for the `PLAN.md` template, the sealed baseline and the 31-key metrics schema |
| **D4** | **P10** — git authority + placement self-application | Three parts: **(i)** who may run which git operation at which station — **ruling this once removes two ad-hoc edits** (P1's step-9 rewrite and the `close batch` rename); **(ii)** does s19-specific content leave the global files for a project overlay; **(iii)** what does `vault:` resolve to |
| **D5** | **P11** — which traceability author is the authority? | There are **three**, not two: `artifact_homes.traceability`, the hand-authored template, and **V20's derived Atlas**. V20 already enforces the derivation both ways, so **the Atlas is the only one that cannot drift** — which makes the template a rendering and Phase-6 generation the author, and settles the sync contract |
| **D6** | **Close batch-89 now, or after the tranches land?** | It has all five stories built and is at P3. Closing needs `04-validation.md` + `05-close.md`, and **`V28`'s window is one batch wide** — the hole becomes permanent when batch-90's directory opens. But **the sync will refuse a `core` batch until §1.6's fix lands** |

---

## 4 · PART D — what the consolidating reviewer is asked to produce

**Write `HANDOFF-devflow-session-2026-09-03-CONSOLIDATED-PLAN.md` in this directory.** Not an edit of
this file — a separate document, and it is the one the next session reads.

It should contain **one ordered plan** that reconciles Part A and Part B, because they are currently
two lists that overlap: the candidate resolves backlog items (`R-89-3` is P3), creates new ones (the
Id grammar's grandfathering question), and its `core`-mode fix **blocks batch-89's close** until it
lands. Specifically:

1. **The single ordered sequence**, with each step's dependency named — what must precede what, and
   why. Where two things can run in parallel, say by what criterion (this session used **file
   ownership**, because the validator's canon table re-hashes on every edit and two agents in it
   corrupt the aggregate).
2. **Which backlog items each tranche closes** — by id, so the closure is checkable rather than
   asserted.
3. **What the candidate ADDS to the backlog** that was not there: at minimum the grandfathered-id
   question, the origin-parenthetical rule, and the `mode` ↔ `stations_active` NOTICE.
4. **A recommendation on D1–D6**, with the argument — not a restatement of the options.
5. **What NOT to do**, and why. This session's most expensive lesson is that a half-fix is worse than
   none: `R-88-17` has 8+ instances and every one was a correction that landed at 1 of N sites.
6. **Anything in this input that does not survive its own re-measurement.** Two of my figures did not
   today (the `stations_active` red herring, and the CRLF-inflated byte deltas). **Check rather than
   inherit** — that is the whole discipline of this record.

**Constraints for the reviewer:** report and write that one file; **change nothing else**, commit
nothing, push nothing. `export PYTHONIOENCODING=utf-8` in every Bash call. Never touch
`prototypes\` or `build\` in `s19_app` (16 untracked files, a parallel session, `C-44`), and do not
edit the two `BACKLOG-*.md` files — they are freshly written and unreviewed.
