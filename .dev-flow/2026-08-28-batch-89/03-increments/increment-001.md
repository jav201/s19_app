# Increment 001 — `HLR-89.1` · `LLR-89.1.1` – `LLR-89.1.5` — the record splits into a live contract and an append-only ledger

> ## ⚠ READ THIS FIRST — THIS PACKET DID NOT GATE THE INCREMENT
>
> **Written 2026-08-30. The increment was committed 2026-08-29 at 12:07:14 -0600
> (`dde935c`) and merged 81 seconds later at 12:08:29 -0600** as
> [PR #204](https://github.com/jav201/s19_app/pull/204), merge commit `1238b7e`. This file is
> **one day younger than the merge it describes** and had no opportunity to stop it.
>
> **Why it is late.** batch-89 opened at station P3 and shipped increment by increment
> without writing a single packet. `V27` — the rule Increment 006 of this same batch shipped
> — reported the hole on 2026-08-30 against its own batch: *"2 `decisions_log` decision(s)
> name an increment with no packet on disk"*. This packet, and the three beside it, are the
> repair of that finding. **They are transcription and reconciliation, not verification.**
>
> **What this packet is NOT allowed to do.** Re-run the validator and report today's numbers
> as this increment's. The validator has moved **two revisions** since — rev48 (this
> increment) → rev49 (Increments 002/003) → **rev50** (Increment 006, 2026-08-30). Every arm
> count, mutant tally and gate line below is **transcribed from the artefact that recorded
> it**, and each carries its source. Where a field has no evidence it is marked **ABSENT**
> with the reason, never filled with something plausible.

| Field | Value |
|---|---|
| Batch | `2026-08-28-batch-89` |
| Increment | `001` of 6 declared — **4 built**; see the closing note of `increment-006.md` for why `004` and `005` do not exist |
| Requirement(s) | `HLR-89.1` · `LLR-89.1.1` · `LLR-89.1.2` · `LLR-89.1.3` · `LLR-89.1.4` · `LLR-89.1.5` |
| Ledger | `LED-89.1` · `LED-89.2` · `LED-89.3` · `LED-89.4` · `LED-89.5` · `LED-89.6` · `LED-89.7` |
| Acceptance | **no id is minted.** `R-89-7` records the executed reason: `V2` resolves an `AT` id against `<project>/tests/` alone, and this requirement's acceptance arms live in `devflow-validate.py --selftest` |
| Flow revision | rev47 → **rev48** |
| Date of the work | `2026-08-29` (record authored `2026-08-28`, per the ledger's own dates) |
| Date of this packet | `2026-08-30` — **after the fact** |

---

## 1 · What changed

**The requirements record became two documents.** `01-requirements.md` is the **live
contract** and holds current state only — no strikethrough, no amendment bullets, no
supersession narration. `01-requirements-ledger.md` is **append-only**, never edited, never
renumbered: how each requirement came to say what it says lives there.

**The split alone is not the fix, and that is the increment's thesis.** Measured on
batch-88's record: 193,364 chars, of which the findings table is **8.1%** and forensic prose
**26.6%** — so moving the ledger out is a **35% cut and not a repair**. The remaining
**65.3%** is *normative* text written in the forensic register, requirements whose
justification sits inside the normative sentence. Splitting the FILES does not separate a
sentence from its reason; splitting THE SENTENCE does. (`LED-89.1`. The three percentages are
the operator's decomposition and were **not re-derived** — `P-2` says so in terms; the record
size *was* re-executed at 197,032 bytes on disk.)

**Worse, a naive split adds a defect surface rather than closing one:** two EDITABLE files
disagree, and `R-88-17` — *"a correction has a population and nothing enumerates it"*,
batch-88's most repeated defect at 8+ instances — is then rehoused, not closed. What closes
it is that the population **is** enumerated: every requirement declares a `**Ledger:**`
field, every entry declares a `**Requirement:**` field, and **`V26` compares the two SETS OF
(requirement, entry) PAIRS in both directions**, BLOCKing on any pair present on one side
only.

**`V26` (NOTICE + BLOCK, selector `S1`, new) checks three things:**

1. **A BUDGET, 54,000 characters, NOTICE and never BLOCK** — a long record is a fact about a
   batch's week, not a defect in its content. **The number is not typed.** It is
   `(_LEAN_CORPUS_MEDIAN_CHARS // 1000) * 1000`, computed by `_lean_budget_from(...)`, and
   `BUDGET-derivation` re-derives the median-floor over five supplied size lists before
   `BUDGET-constant` checks the shipped constant IS that derivation. **The ledger is excluded
   from the measurement** — a budget over an append-only file is a standing instruction to
   delete history — and nothing in the rule's sentences can show that exclusion, so
   `BUDGET-ignores-ledger` holds the live text fixed and moves the ledger by 40,000 chars.
2. **A CURRENT-STATE check on Markdown strikethrough, paragraph-bounded.** Deliberately NOT a
   vocabulary guard: per `R-88-16` a token stream has a grammar to derive a class from and
   prose does not. `~~x~~` is a delimiter and therefore has one (`LED-89.4`).
3. **A both-ways LINK compared as PAIRS, not as sets.** `PAIR-crossed` is the discriminating
   fixture: identical requirement-id and entry-id sets on both sides with only the pairs
   swapped, on which **every membership oracle reports a clean pass**.

**Operator ruling on the requirement field set (`LED-89.7`), decided on measurement:** of the
six template fields examined, **only two change what gets TESTED**. `Boundary catalog`
returns as *generative* — each ticked class is an arm somebody owes — scoped to every
requirement whose `Validation` is `test` or `analysis`. `Acceptance test(s)` returns with
`owed at <increment>` as the declared empty. `Negative control` gets its own named slot: it
was inline in **9 of 10** batch-88 thresholds, so exactly one requirement had no RED side
**and nothing said so**. `Acceptance criteria (informative)` (5.6% of batch-88's record,
self-declared informative), `Deliverable + observation`, and the §5.2 dual-traceability
tables retire — each with its reason written **into** the template at the point of removal.

**`V2` is vacuous on this project and now says so out loud.** Its declared-side grammar
harvests **0** of batch-88's nine `AT-B88-NN` ids, and widening it would not have helped:
`V2` resolves an id against `<project>/tests/` and nothing else, while batch-89's acceptance
arms live in `--selftest`. Grammar and resolution are orthogonal. Registered **unrepaired**
as `R-89-6` and `R-89-7`. `R-89-8` states, rather than implies, that the three returned
template fields are mandatory and enforced by no rule.

---

## 2 · Files modified

**Zero source files in `s19_app`.** The rule landed in **two other private repositories** —
`~/.claude` (primary) and its nested `~/.claude/skills` checkout (the bundled mirror).
Anyone reading only this repository's diff will not find the work, and that is worth stating
at the top rather than leaving as a puzzle.

| Repo | Commit | Files | Change |
|---|---|---|---|
| `s19_app` | `dde935c`, 2026-08-29 12:07:14 -0600 | **7 files, +494 / −17** | `01-requirements.md` (+314, new), `01-requirements-ledger.md` (+154, new), `state.json` (14 lines), and the 4 `_derived/ATLAS-*.md` files regenerated at the gate |
| `~/.claude` | `8438000`, 2026-08-29 12:07:26 -0600 | **6 files, +742 / −35** | `docs/tools/devflow-validate.py` (+629 — the rule and its arms), `templates/dev-flow/req-template.md`, `commands/dev-flow.md`, `commands/dev-flow-init.md`, `commands/dev-flow-sync.md`, `docs/FLOW-VERSION.md` |
| `~/.claude/skills` | `a05a291` | mirror | `--sync-bundle` output, byte-identical, never hand-edited |

| Count | Value |
|---|---|
| **SOURCE files** | **`0`** / 4 — in `s19_app`. **1 authored source file** in the flow repo (`devflow-validate.py`) plus 1 declared build output (the bundle mirror); the remaining flow files are templates and command docs |
| Test files | 0 (uncapped) — the arms live in the validator's own `--selftest` |
| Derived files | 4 (`_derived/ATLAS-*.md`) — regenerated at the gate, never authored |

**The tooling had to learn the new file exists, and that half was nearly missed.**
`dev-flow-init.md` scaffolded the ledger in neither its tree nor its seed-by-mode table;
`dev-flow.md` named only the contract at four sites; and — the severe one —
**`dev-flow-sync.md` did not copy the ledger to the vault, so a batch's conclusions would
sync and its reasoning would be silently dropped.** All four fixed in the same commit.

---

## 3 · How to test

```bash
export PYTHONIOENCODING=utf-8     # cp1252 otherwise; see increment-002.md — at rev48 this
                                  # was not optional, the selftest CRASHED without it
python ~/.claude/docs/tools/devflow-validate.py --selftest
python ~/.claude/docs/tools/devflow-validate.py "C:/Users/jjgh8/Github/s19_app" | grep V26
```

> **⚠ These commands do not reproduce this increment's numbers today.** The validator is at
> rev50; this increment shipped rev48. A run today reports **490** arms and 26 rules, not
> 431 and 24. To see rev48, check out `8438000` in `~/.claude`.

---

## 4 · Test results

**All figures transcribed from `dde935c`'s commit message and `FLOW-VERSION.md`'s rev48 row.
None was re-measured for this packet.**

| Measure | Value | Source |
|---|---|---|
| Selftest | **431 arms, 0 fail, `SELFTEST PASSED`** | `dde935c` message |
| Arm delta | 402 → **431** | `FLOW-VERSION.md` rev48 |
| Registered rules | 23 → **24**, selector `S1` | `FLOW-VERSION.md` rev48 |
| `--map` | **24 in table order · 24 agree · 0 differ · 0 missing** | `dde935c` message |
| Gate | **2 block · 287 notice · 21 not applicable** — both blocks are this tree's own *uncommitted changes* rows, not content | `dde935c` message |
| `V26` on its own record | **26,068 chars inside budget · 10 pairings identical both ways** | `dde935c` message |
| Budget corpus | n=65 records predating batch-89, **median 54,367 CHARS** (p25 37,006 · p75 87,505 · max 314,621); **32 of 65 already at or under 54,000** | `P-1`, `LED-89.5`, measured 2026-08-28 |
| Strikethrough corpus | **81 spans before and 81 after**, zero crossing a blank line; batch-88's 47 all retained, 2 genuinely multi-line | `LED-89.6`, measured over all 66 records |
| Glyph-vs-strikethrough | **16** records carry the warning glyph, **10** carry strikethrough | `LED-89.4`, `P-3` |

### Mutation testing — and the record carries two tallies that do not reconcile

| Source | Tally |
|---|---|
| `dde935c` commit message | **19 mutations, 19 red, 0 survived** |
| `FLOW-VERSION.md` rev48 | *"19 mutants, 19 killed, 0 survived, 0 broken"* **and** *"12 named single-edit mutants run: 12 killed, 0 survived, 0 broken"* **and** *"an independent adversarial review then scored 12 fresh mutants and found one survivor"* |

**Reconciliation: ABSENT.** 12 named + 12 review = 24 scored, against a final battery of 19.
Nothing in the record says which mutants were retired, merged or re-run after the review's
survivor was closed, and no harness transcript survives in either repository. **The `19 red /
0 survived` figure is the POST-repair battery** and is the only one either artefact states as
final; the two intermediate tallies are stated here because dropping them would make the
history look cleaner than it was.

**The gate is the run's own baseline and never a typed number**, and that mattered here: a
draft of the batch record wrote *"still emit 425 arm lines"* which, applied as written against
the real baseline, **would have rejected all twelve mutants as broken and made the "12 killed"
result impossible** — a claim in a form that could not have been executed (`R-88-10`).

### 🛑 Four self-reported defects, and two of them are the increment turning on its own author

**(a) The budget was derived in BYTES and enforced in CHARACTERS.** `LED-89.3` set
`_LEAN_MAX_CHARS = 55,000` from four quantiles computed with `os.path.getsize` — bytes,
median 55,367 — while `_v26_outcome` measures `len(text)`. The corpus is UTF-8 with
multi-byte punctuation throughout, so the two disagree by ~1,000 at the median: **a whole
flooring step.** The honest floor is **54,000**; the first cut shipped 55,000. **`LED-89.3` is
left standing exactly as written** and superseded by name in `LED-89.5` — the ledger is
append-only, so a wrong entry is corrected by a new one, never by a rewrite.

> **And the arm that should have caught it compared the literal `55000` against the literal
> `55000`.** It was **flagged as vacuous in the first draft and kept anyway.** *Flagging an
> arm as vacuous is not the same as replacing it, and there was a real defect behind this
> one.* Closed by `BUDGET-derivation` (re-derives the floor over five supplied size lists)
> and `BUDGET-chars-not-bytes` (pins the unit).

**(b) An arm over a HELPER is not an arm over the RULE — committed inside the arm written to
close that very finding.** Writing the boundary catalogue for the strikethrough requirement
put three code-span mentions of `~~` into the record and `V26` raised **2 BLOCKs**: *the rule
forbade its own documentation.* Fixed by reusing `_strip_code`, the helper `V1` already trusts
for the batch-15 false positive, scoped to the strikethrough scan alone so the BUDGET still
measures the real document. **Its first arm called `_strip_code` itself, and mutant
`M19-no-strip-code` SURVIVED it.** The arm now asserts through `_v26_outcome`.

**(c) The independent adversarial review found a survivor the author's battery did not.**
`if ledger is None:` → `if not ledger:`. `_artifacts` maps an UNREADABLE file to `""` rather
than dropping the key, so under the mutant an unreadable ledger silently took the legacy path
and **every BLOCK this rule can raise vanished.** Closed by `LEDGER-empty-string`.

**(d) The two id grammars diverged on their terminator.** A heading ending in a period
yielded a live id one character longer than the ledger's, so **one requirement produced two
unequal pairs and one of the two BLOCKs stated something false.** Closed by a trailing `\b`
and armed by `GRAMMAR-agree`.

**Two more were found by the increment's own arms rather than by review:** three expected
finding COUNTS were written wrong by the same hand that wrote the rule (the `UNPOINTED` and
`UNOWNED` fixtures yield **5** findings, not 6 — a missing pointer removes a pair from one
side rather than adding a finding to both); and a strikethrough sentence was expected without
its delimiters, while `findall` over a group-less pattern returns the whole match.

**The unbounded first cut of the strike pattern** paired the opening `~~` of one span with a
closing `~~` paragraphs away, so the BLOCK quoted innocent prose from another section and any
record merely SHOWING the canonical `~~this~~` as an example BLOCKed outright. batch-89's own
record escaped only by the accident of a space inside its example (`LED-89.6`).

### Independent review

**ABSENT for the packet.** An independent adversarial review of the **code** is recorded in
`FLOW-VERSION.md` rev48 (12 fresh mutants, 1 survivor, plus the id-grammar terminator
finding). **No `code-reviewer` verdict on an increment packet exists, because no packet
existed until today.** batch-88 ran that lens at every increment; batch-89 ran it at none.

---

## 5 · Risks

- **The pairing makes the two documents AGREE; it does NOT enforce append-only, and the code
  briefly claimed it did.** Deleting an entry together with its pointer leaves both sets equal
  and the rule green. Append-only is a convention the template states and nothing checks;
  enforcing it needs git history and is a different subject.
- **`V26`'s pass sentence says only what was checked** — *"no strikethrough delimiter found"*,
  never *"the contract states current state only"*. A record stuffed with warning glyphs, the
  word SUPERSEDED and two versions of one obligation, but no `~~`, passes.
- **`V2` remains vacuous on this project** (`R-89-6`, `R-89-7`), registered unrepaired. The
  `_V2_DECLARED` grammar is frozen by the `WORDING-declared` arm and lifting it needs its own
  increment.
- **The three returned template fields are mandatory and enforced by no rule** (`R-89-8`).
- **`state.json`'s `batch_objective` was written at this increment and still carries the
  superseded `55000` figure** — the value `LED-89.5` refuted the same day. Not repaired here;
  see §6.

## 6 · Pending

- **`04-validation.md` and `05-close.md` do not exist for this batch.** The batch is at
  station P3 and merged from it.
- **`state.json`'s `batch_objective` is stale and self-contradicting:** it names the budget as
  `55000` (superseded by `LED-89.5` to 54,000, computed rather than typed) and lists
  Increments 2 and 3 under *"REMAINING INCREMENTS, NOT IMPLEMENTED"* although both shipped on
  2026-08-29. **Not repaired by this packet** — the write of 2026-08-30 was scoped to
  `decisions_log`, and expanding it silently would be the scope creep this flow forbids.
- **`state.json`'s `artifact_homes` and `triggers.record` still point at
  `.dev-flow/2026-08-24-batch-88/`**, including `artifact_homes.increments`, which names
  batch-88's `03-increments/` while this directory holds batch-89's. Same disposition.

## 7 · Suggested next task

**Increment 002** — the `--selftest` cp1252 crash. Its premise `P-8` was marked UNDECIDABLE at
this point precisely because **every run in this increment had `PYTHONIOENCODING` pinned** and
therefore avoided the crash rather than seeing it. It must be OBSERVED before it is repaired.

---

## Increment gate checklist

**Reconstructed 2026-08-30. This checklist did not gate anything.** `⚠` marks an item that
cannot be discharged retroactively.

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 0 in `s19_app`; 1 authored + 1 declared build output in the flow repos (`8438000`, `a05a291`) |
| 2 | Tests written in the same increment | ✓ | 402 → 431 arms in `8438000`, `FLOW-VERSION.md` rev48 |
| 3 | RED counterfactual captured | ✓ | 19 mutants, 19 red, 0 survived (`dde935c`) — with the tally reconciliation marked ABSENT in §4 |
| 4 | Vacuous arms hunted | **⚠** | Two were shipped and later closed — `BUDGET-constant` (literal vs itself) and the `_strip_code` helper arm that `M19` survived. Both are recorded in §4; neither was caught by the author's own pass |
| 5 | Independent `code-reviewer` pass on the packet | **✗** | No packet existed. The code review that ran is `FLOW-VERSION.md` rev48's adversarial mutant pass; it is not the same lens and is not claimed as one |
| 6 | No file from another lane touched | ✓ | `git show --stat dde935c` — 7 files, all under `.dev-flow/`; nothing under `prototypes/` or `build/` |
| 7 | Frozen interfaces untouched | ✓ | `git show --stat dde935c` — 0 files under `s19_app/`, `tests/` or `tools/` |
| 8 | Every figure carries its source | ✓ | §4's table names the artefact for each row; the two irreconcilable mutant tallies are both printed rather than averaged |
| 9 | Packet written at the increment's gate | **✗** | **Written 2026-08-30, one day after the merge.** This is the defect `V27` reported and this packet repairs |

**An item without a citation is not satisfied — it is asserted.**
