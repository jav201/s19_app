# Increment 007 — `HLR-88.7` / `HLR-88.8` · `LLR-88.13` – `LLR-88.16` — the flow can state that a backup exists, and its own identity is re-declared over the result

> **⚠ C-56 SUBSTITUTION IN THIS PACKET, inherited from Inc 4, Inc 5 and Inc 6.**
> Acceptance ids are written with the prefix `ID-`. Spelling the real prefix here would re-declare
> the id into `_atlas_id_scan`'s `batches` realm — de-minting from one rule's population is
> RELOCATION into another's. Design-review rulings are cited by their decision number in prose
> ("ruling #D3") rather than by their citation token, for the same reason and for `V23`'s.

| Field | Value |
|---|---|
| Batch | `2026-08-24-batch-88` |
| Increment | `007` of 7 — the batch's last and largest |
| Requirement(s) | `HLR-88.7` · `HLR-88.8` · `LLR-88.13` · `LLR-88.14` · `LLR-88.15` · `LLR-88.16` |
| Acceptance | `ID-B88-06` (RC-2 at INTAKE with a command behind it) · `ID-B88-07` (the selftest's per-rule arms) — `HLR-88.8` declares it has no separate acceptance, which is the honest form |
| Date | `2026-08-27` |
| **Kind** | A new rule, a derivation that replaces a hand-maintained sentence, a checklist row, and the revision bump that re-declares the flow's identity over all of it. |

> **⚠ REVISION 2, 2026-08-28. This packet was BLOCKED at HIGH by an independent review that
> scored 26 fresh mutants and found four non-equivalent survivors.** The largest is recorded as
> the **eleventh shape of the vacuous check** in §5, because it defeats this batch's own answer to
> an earlier shape: *a typed sentence pins its WORDING and never its REFERENT.* `V25`'s age oracle
> swept **every** remote while every sentence it prints says `origin` — so the rule rendered its
> headline PASS over a repository whose only backup was 400 days stale, and it survived nine
> typed-sentence arms and six registered-rule E2E arms because every fixture had one remote.
> Fixed here, with the fixture that can see it. The review's verdict on the two honest reports
> from revision 1 — the `return []` crash and the refusal to call the unwired-`ok` mutant
> *killed* — was that **both were right**, and one of them has since been closed as a side effect
> of an unrelated repair (§4.3).

---

## 1 · What changed

### `V25` — the flow can finally say that a backup EXISTS, and how old it is

`devflow-validate.py` gains `V25` (NOTICE, selector `S4`, new), registered in `CHECKS`,
`_RULE_COVERS` and `_RULE_SELECTOR`, split the way every rule in this file is split: a pure
decision core `_v25_outcome`, an I/O half `_v25_probe`, an age oracle `_remote_tip_age_days`, and
the registered rule `v25_backup_verified` that joins them.

**It emits exactly one finding, in one of six states, each with its own sentence:**

| State | Severity | The sentence says |
|---|---|---|
| fresh | `SKIP` | `backup verified: origin answered with N ref(s) and the newest commit on it is D.DD day(s) old, inside the 30-day window` |
| stale | `NOTICE` | "… past the 30-day window, so that many days of work exist in exactly one copy" |
| no remote configured | `NOTICE` | "no backup and no network problem — a configuration fact" |
| remote did not answer | `NOTICE` | "whether any backup exists was NOT checked; this is not a pass" |
| **reachable but EMPTY** | `NOTICE` | "served ZERO refs … this is the ABSENCE of a backup, not the staleness of one" |
| age unknowable | `NOTICE` | "no remote-tracking reference exists locally, so the backup's AGE was not measured" |

**The requirement named four states. There are six, and the two extra ones are the point.**

**(0) The oracle's DOMAIN is the sentence's REFERENT — added at revision 2, and it is the
correction that mattered most.** Every sentence and the `where` field say `origin`, and the ref
COUNT printed beside the age comes from `ls-remote origin`. The first cut took the age over
`refs/remotes/` — **every** remote — so the rule printed **two numbers in one sentence drawn from
two different populations**. Measured by the review: a repository whose `origin` was last pushed
400 days ago and whose `upstream` was fetched today rendered
`SKIP · where=origin · "backup verified: origin answered with 1 ref(s) and the newest commit on it
is 0.00 day(s) old"` — the rule's headline pass over 400 days of work in one copy. The oracle now
reads `refs/remotes/origin/`, and `E2E-two-remotes` is a fixture whose `origin` is 40 days old and
whose `upstream` was fetched now. The same class covers the date field: `committerdate` is what a
backup RECEIVED, `authordate` is what a rebase preserved, and the fresh remote now carries a
**skewed** pair so the two disagree by 40 days.

**And the correct specification was in the record the whole time.** `M-9`, written three days
before any of this code existed, ran
`git for-each-ref --sort=-committerdate refs/remotes/origin` — **the right domain and the right
date field, both of them**. The first cut of `V25` reproduced neither, and nothing noticed, because
**nothing in this flow compares a shipped oracle's command to the probe that justified it**. That
is registered as `R-88-19` in the requirements, and it is a larger finding than the defect: this
batch armed sentences, counts, cardinality, extent, bindings, absence and referents, and never once
asserted that the implementation matches its own measurement. Recorded here rather than left in the
risk table alone, because the packet is where an implementer would look for it.

**(a) `git ls-remote` has FIVE distinguishable results.** The fifth is reachable-but-EMPTY: a
remote that exists and has never been pushed to answers with no refs. A membership test written as
"the call returned something" reads that as answered, the age resolves to nothing, and the rule
prints a STALENESS diagnosis over a repository that has never been backed up at all — the worst
state rendered as a lesser one. `--exit-code` is what makes it nameable; measured on a real empty
bare repository, git returns **exit 2 with empty stdout**. The classifier decides the zero-ref case
on the ref COUNT rather than on the exit status, so it stays correct if git's codes ever move —
which means the flag itself is held in place by an arm that reads the argv of the actual call, and
by nothing else. Said plainly: **the `--exit-code` mutation is killed by the argv arm, not by a
behavioural one**, and that is recorded rather than implied.

**(b) The age oracle measures the BACKUP, not the CONTACT, and the obvious helper measures the
wrong thing.** `_ref_age_days`' own docstring says it returns days since this repo last
*contacted* origin, preferring `FETCH_HEAD`'s mtime — which git writes on every fetch even when
nothing changed. A repository fetched five minutes ago and **never pushed** would have reported
"backup verified, 0.003 days old": the rule inverting its own purpose while printing a pass. Three
inequivalent oracles are in play — that helper, the remote tip, and local `HEAD` — and this rule
names the second in terms, in `_remote_tip_age_days`' docstring and in the block comment above it.

**`M-9` is a blind fixture for this question and is not cited as the GREEN side.** It recorded the
remote tip as identical to the local value, so it cannot tell the three oracles apart. The arm
`AGE-oracle-is-tip` builds a clone whose remote tip is **40 days** old and whose `FETCH_HEAD` was
written **now**, and asserts both numbers: tip `40.0`, contact `0.0`.

**(c) The probe's timeout is asserted on the CALL, not on this file's source.** An unreachable host
with no timeout does not produce a wrong verdict — it **hangs the gate**, and the guard hook that
gates the flow hangs with it. No arm over a pure core can see that, and an arm that greps this file
for `timeout=` is a check on prose. So `_v25_probe` takes its runner as a parameter and `PROBE-argv`
reads the kwargs the call actually passes.

**Severity is NOTICE in every state, including EMPTY.** A stale backup is a fact about the
operator's week, not a defect in the batch's content, and a BLOCK would make the gate a hostage to
connectivity. *No remote configured* is a third state and not a variant of unreachable: collapsing
them prints a network diagnosis for a configuration fact.

### The synthetic-exemption set stops being a sentence and becomes a derivation

Until this increment the selftest ENDED with a hand-written sentence naming which rules it does not
prove synthetically. That is a list maintained beside the thing it describes — the defect this
manifest has now removed five times — and it has a worse property than drifting: **a rule shipping
with no arms at all leaves the sentence merely inaccurate, and the selftest still passes.**

The set is now derived by `_exempt_verdict` as `CHECKS − (rule ids at the LABEL POSITION of this
run's own emitted arm lines)`, printed, and compared against a declared constant that drives `ok`.
Capturing the run's output is a six-line `print` shadow at the top of `selftest()` — the one way to
read what an operator actually reads without threading a sink through two thousand lines of arms.

**The expected value is `∅`, not `{V8}`, and the struck constant could not have passed.** Measured
before any code was written: **22 rules registered, 22 carrying at least one emitted arm label, V8
carrying 29**. The shipped sentence asserts a SEMANTIC property — "V8 is the only rule this
selftest does not prove SYNTHETICALLY; it needs a project map on disk" — and the replacement is a
SYNTACTIC scan over arm labels. They are different predicates over the same names. V8 is heavily
armed; what it lacks is a synthetic fixture, which no label scan can ever see. **That claim
survives in the tail as a separate obligation with no derivation behind it**, and the block comment
above the derivation says so, so the next reader does not reconstruct the conflation from the two
sentences sitting side by side.

The harvest reads the **label position**, and its `PASS != NOOP` corpus carries three shapes that
are not labels — a mid-sentence mention, a prose line that OPENS with the rule id, and a
deeper-indented continuation — because a corpus where the unarmed rule is simply ABSENT cannot tell
a label harvest from a mention harvest, and the selftest's own tail names rules in prose.

### `phase-checklists.md` — RC-2 as INTAKE row 5

Row 5 requires `origin`'s reachability and the age of its newest commit to be recorded in `PLAN.md`
before deriving, with the command in the row. Rows 5-8 shifted to 6-9 with their text byte-identical.
Placing it beside RC-1 is the point: both are recorded-before-deriving conditions about the state of
the remote, and separating them lets one be filled while the other is forgotten.

### `FLOW-VERSION.md` — the bump, taken LAST

`2026.08.24-rev46` / `9c1449ed815d267c` → **`2026.08.27-rev47` / `a280beca91743d7c`**. Two table
rows re-hashed and their line counts corrected (`phase-checklists.md` 139 → 140,
`devflow-validate.py` 3176 → 5648 — the latter had been stale since before this batch opened, which
is the `V7` drift the batch's gate carried from Inc 1). A changelog row was appended. **This edit
was made after every other edit in this increment**, and the evidence runs below post-date the mtime
of all 24 canon files.

**Revision 2 ran the whole procedure again, and that is the procedure rather than a defect.** The
review's fixes touch the validator, so the validator's row was re-hashed a second time
(`a5814eb46aa852f9` → `3fec22d51759d4a9`) and the aggregate moved with it
(`9519967809d27089` → `a280beca91743d7c`). **The revision string does not advance**: rev47 is
unpublished, so this is still rev47's content being finished. What repeated is the ORDERING —
edit, re-hash, re-sync, re-map — which is exactly what `LLR-88.16` says runs last by
construction.

---

## 2 · Files touched

| File | Kind | Change |
|---|---|---|
| `C:\Users\jjgh8\.claude\docs\tools\devflow-validate.py` | source | `V25` (block comment + `_BACKUP_MAX_DAYS`, `_v25_outcome`, `_v25_probe`, `_remote_tip_age_days`, `v25_backup_verified`) + registration in `CHECKS` / `_RULE_COVERS` / `_RULE_SELECTOR` + new selector `S4`; the derivation (`_SELFTEST_EXEMPT`, `_armed_rules`, `_exempt_verdict`) and the `print` capture shim; **26** arms added. **rev 2:** the age oracle's domain narrowed to `refs/remotes/origin/`, `GIT_TERMINAL_PROMPT=0` on the probe, a two-remote fixture and a skewed author/committer pair, and the exemption sweep widened from one rule to all 23 |
| `C:\Users\jjgh8\.claude\templates\dev-flow\phase-checklists.md` | source | INTAKE row 5 added (RC-2); rows 5-8 renumbered 6-9, text byte-identical |
| `C:\Users\jjgh8\.claude\docs\FLOW-VERSION.md` | source | rev47 bump, 2 rows re-hashed and re-counted, aggregate updated, changelog row appended. **rev 2:** the validator's row re-hashed again (`a5814eb46aa852f9` → `3fec22d51759d4a9`, 5584 → 5648 lines), aggregate `9519967809d27089` → `a280beca91743d7c`, and the rev47 row corrected — the revision string does NOT advance, because rev47 is unpublished and it is the ORDERING that repeats, not the content |
| `C:\Users\jjgh8\.claude\skills\dev-flow\` | build output | `--sync-bundle` mirror; `V15` reports *bundle identical* |
| `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-08-24-batch-88\03-increments\increment-007.md` | record | this packet |
| `C:\Users\jjgh8\Github\s19_app\.dev-flow\_derived\` | derived | Atlas regenerated with `--atlas --write` **after** this packet existed |

| **SOURCE files** | **`3`** / 4 — the batch's declared maximum; the bundle is a build output, the packet is a record, the Atlas is derived |
|---|---|

**Nothing was committed.** `prototypes/`, `build/` and every untracked file were left alone. Every
mutant was applied to a COPY under `~/.claude/jobs/c0c0fa47/tmp/`; no live file was ever mutated.

---

## 3 · How to test

```bash
export PYTHONIOENCODING=utf-8
python ~/.claude/docs/tools/devflow-validate.py --selftest          # 402 arms, exit 0
python ~/.claude/docs/tools/devflow-validate.py --map ~/Github/s19_app | sed -n '3,6p'
python ~/.claude/docs/tools/devflow-validate.py ~/Github/s19_app | tail -1
```

Checklist and manifest oracles (they run against a PATH, so a mutated copy can be scored):

```bash
python ~/.claude/jobs/c0c0fa47/tmp/chk7.py ~/.claude/templates/dev-flow/phase-checklists.md
# the start stamp is MANDATORY — see below
python ~/.claude/jobs/c0c0fa47/tmp/man7.py ~/.claude/docs/FLOW-VERSION.md <evidence-run-start-epoch>
```

**`man7.py`'s second argument is not optional, and revision 1 documented it as if it were.** It
defaulted to `time.time()`, which compares *now* against mtimes that are necessarily in the past —
so `RUN-post-dates-edits` was **trivially true and proved nothing**: a vacuous check inside the
harness written to find them. The stamp is now mandatory and the script exits `2` without it.
Capture it after the last source edit and before the evidence runs:

```bash
python -c "import time; print(repr(time.time()))" > /tmp/runstart.txt
```

---

## 4 · Test results

### 4.1 The selftest — 376 → 402 arms, exit 0

```
  V25 PASS-fresh        expected 1 × SKIP   + its own typed sentence · ok
  V25 PASS-fresh-other  expected 1 × SKIP   + its own typed sentence · ok
  V25 BOUND-30-passes   expected 1 × SKIP   + its own typed sentence · ok
  V25 BOUND-31-fails    expected 1 × NOTICE + its own typed sentence · ok
  V25 NO-REMOTE         expected 1 × NOTICE + its own typed sentence · ok
  V25 UNREACHABLE       expected 1 × NOTICE + its own typed sentence · ok
  V25 EMPTY-remote      expected 1 × NOTICE + its own typed sentence · ok
  V25 EMPTY-exit-zero   expected 1 × NOTICE + its own typed sentence · ok
  V25 AGE-unknowable    expected 1 × NOTICE + its own typed sentence · ok
  V25 PASS!=PASS        expected two fresh ages to render two sentences · ok
  V25 SENTENCES-6       expected 6 distinct state sentences · got 6 · ok
  V25 PASS!=NOOP        expected the pass and could-not-check sentences to differ · ok
  V25 SEVERITY-never-BLOCK expected SKIP then 5 × NOTICE · got SKIP/NOTICE/NOTICE/NOTICE/NOTICE/NOTICE · ok
  V25 E2E-fresh         expected 1 × SKIP   through the REGISTERED rule · ok
  V25 E2E-never-fetched expected 1 × NOTICE through the REGISTERED rule · ok
  V25 E2E-stale         expected 1 × NOTICE through the REGISTERED rule · ok
  V25 E2E-two-remotes   expected 1 × NOTICE through the REGISTERED rule · ok
  V25 E2E-empty         expected 1 × NOTICE through the REGISTERED rule · ok
  V25 E2E-no-remote     expected 1 × NOTICE through the REGISTERED rule · ok
  V25 E2E-unreachable   expected 1 × NOTICE through the REGISTERED rule · ok
  V25 AGE-oracle-is-tip expected the tip ~40d and the CONTACT ~0d · got 40.0 vs 0.0 · ok
  V25 PROBE-argv        expected --exit-code, a finite timeout and GIT_TERMINAL_PROMPT=0 on the actual call · ok
  V25 PROBE-empty!=dead expected exit 2 + no output to differ from a call that never completed · ok
  SEL EXEMPT-derived    expected {} over 23 registered rules · got {} · ok
  SEL EXEMPT-PASS!=NOOP expected {V98, V99} and ok FALSE over a corpus that only MENTIONS them · ok
  SEL EXEMPT-domain-all expected each of the 23 registered rules to surface ALONE when its own arm lines are withheld · ok

SELFTEST PASSED
```

`HLR-88.1`'s floor is `>= 240` total and **7 of 7** rules carrying both arm kinds; this increment
supplies V25's two: `PASS-fresh` (the pass SENTENCE, typed) and `PASS!=NOOP` (the pass sentence
differs from the could-not-check sentence). `LLR-88.14`'s floor is `>= 6` arms with `>= 1`
`PASS != NOOP` and 2 boundary arms at 30 and 31 days — **23 arms, both boundaries, both
`PASS != NOOP` and `PASS != PASS`.**

### 4.2 The live `V25` line, the map, and the gate

```
  [-] V25  origin: backup verified: `origin` answered with 9 ref(s) and the newest commit on it is 2.11 day(s) old, inside the 30-day window
  [-] V7   FLOW-VERSION.md: flow current (a280beca91743d7c)
  [-] V15  skills/dev-flow/: 21 files derived from the manifest table, bundle identical
  [-] V20  .dev-flow/_derived/: atlas current (4 files, census 1)
```

```
IDENTITY
  declared   2026.08.27-rev47   a280beca91743d7c
  24 files in table order · 24 agree · 0 differ · 0 missing
    every tabled file matches its declared hash
```

**The bump ran twice, and that is the procedure working rather than a defect.** Revision 2 edits
the validator, so step 4 of the manifest's own bump procedure repeats: re-hash the row, recompute
the aggregate, re-`--sync-bundle`, re-`--map`. The revision string stays at `rev47` because rev47
is unpublished — **it is the ordering that repeats, not the content.** The ordering itself is
asserted rather than asserted-about:

```
  canon  templates/dev-flow/phase-checklists.md         23:21:50
  canon  docs/tools/devflow-validate.py                 00:05:02
  manifest (not a canon row)                            00:10:07
  bundle  (build output)                                00:10:16
  EVIDENCE RUN START                                    00:10:16   post-dates every canon file: True
```

**Gate movement, stated in full and attributed:**

| | baseline | after | why |
|---|---|---|---|
| block | 3 | **2** | `V7` went green (the one movement this increment was allowed to cause). The remaining two are `V16`'s *uncommitted changes* — the same two checkouts that read *7 commits ahead* at baseline; nothing was committed, so `V16` is reporting this increment's own working tree |
| notice | 287 | **287** | unmoved |
| not applicable | 14 | **16** | **+2, and both halves are the same movement counted twice.** `V7`'s pass line is a `SKIP`, so a rule leaving the block census necessarily ENTERS the n/a one — that is the −1 block above and +1 here, one event. The second is `V25`'s own pass line, the arithmetic consequence of registering a rule that passes |

Final gate: **`2 block · 287 notice · 16 not applicable`**, exit 1 on `V16` alone.

The four `V20` Atlas blocks raised by the bump (the Atlas banner carries `flow_version` and
`flow_hash`) were regenerated with `--atlas --write` after this packet existed, which is the count
`PLAN.md` §5 budgeted. Read against the intermediate run — `6 block · 287 notice · 15 n/a`, taken
after the bump and before the regeneration — the Atlas accounts for exactly those four and for the
last n/a: `V20` returns from 4 BLOCKs to its single `atlas current` SKIP.

### 4.3 Mutation testing — 49 single-edit mutations, 47 red

| Set | Count | Result |
|---|---|---|
| mandated (12 `V25` · 7 derivation · 4 checklist §4.4 · 5 manifest §4.5) | 28 | 27 red, 1 survivor (`D4`) |
| self-authored, revision 1 | 15 | 15 red |
| the review's four survivors + two neighbours they opened, revision 2 | 6 | 5 red, 1 measured EQUIVALENT (`R5`) |
| **total single-edit** | **49** | **47 red · 1 equivalent · 1 survivor** |
| multi-edit controls (`D4b` · `D4c` · `D4d` · `R7`) | 4 | they pin WHICH arm does the work, and are not scored as kills |

Every one of the 43 from revision 1 was **re-run against the revised source** and is still red.

**`V25` — all 12 mandated kills red:**

| Mutation | Verdict | Reddened |
|---|---|---|
| threshold moved 30 → 29 | KILLED | 7 arms incl. `BOUND-30-passes` |
| boundary `<=` → `<` at exactly 30.0 | KILLED | `BOUND-30-passes` |
| the threshold passed explicitly by the boundary arms, with the default at 29 | KILLED | 5 arms — the fresh and E2E arms still take the default |
| unreachable collapsed into no-remote | KILLED | `UNREACHABLE`, `SENTENCES-6`, `E2E-unreachable` |
| the pass sentence reworded to a constant | KILLED | 5 arms |
| the measured number replaced by a literal | KILLED | 5 arms incl. `PASS!=PASS` |
| `return []` on the pass path | KILLED | **6** arms — `PASS-fresh`, `PASS-fresh-other`, `BOUND-30-passes`, `PASS!=PASS`, `SEVERITY-never-BLOCK`, `E2E-fresh`. `SENTENCES-6` and `PASS!=NOOP` stay green because the degrade string is itself a distinct sentence; revision 1 said 7 and was counting the verdict line |
| the RULE returns `[]` while the core stays perfect | KILLED | all 6 E2E arms |
| the network call loses its timeout | KILLED | `PROBE-argv` |
| `--exit-code` dropped | KILLED | `PROBE-argv` |
| the age oracle swapped to `_ref_age_days` | KILLED | `E2E-stale` |
| severity raised to BLOCK | KILLED | `UNREACHABLE`, `SEVERITY-never-BLOCK`, `E2E-unreachable` |

**The review's four non-equivalent survivors — all four now red:**

| Mutation | Was | Now | The arm that closes it |
|---|---|---|---|
| the age oracle's domain widened from `refs/remotes/origin/` to `refs/remotes/` | SURVIVED all 401 | **KILLED** | `E2E-two-remotes` — `origin` 40 days old, `upstream` fetched now |
| `committerdate` → `authordate` | SURVIVED all 401 | **KILLED** | `E2E-fresh` — the fresh remote's author and committer dates now disagree by 40 days, and `0.00` is a number only `committerdate` can produce |
| the derivation's domain narrowed at a rule OTHER than `V25` (scored at `V1` and at `V23`) | SURVIVED all 401 | **KILLED** | `EXEMPT-domain-all` — the sweep walks all 23 rules |
| the probe's `GIT_TERMINAL_PROMPT=0` dropped | did not exist | **KILLED** | `PROBE-argv` — the same spy that reads the timeout reads the environment |

**Two neighbours those repairs opened, scored because a repair is a new surface:**

| Mutation | Verdict | Why |
|---|---|---|
| the sweep reverted to iterating `_dom25` instead of `CHECKS` (`R7`, compound with a narrowing) | control — SURVIVED | **This is the defect the repair closes**, kept as a control: iterating the domain under test is the same defect one level in, and the loop then agrees with itself |
| `refs/remotes/origin/` → `refs/remotes/origin` (`R5`) | **EQUIVALENT, by execution** | git matches a `for-each-ref` pattern literally or up to a slash boundary. Measured against a clone carrying a sibling remote named `origin-mirror`: both patterns select exactly `refs/remotes/origin/HEAD` and `refs/remotes/origin/main`. Recorded as equivalent rather than chased, and measured rather than argued from the manual |

**The derivation — 6 of 7 red, and the survivor is recorded, not tidied:**

| Mutation | Verdict | Reddened |
|---|---|---|
| always-empty | KILLED | `EXEMPT-PASS!=NOOP`, `EXEMPT-domain-all` |
| harvest widened from label position to any mention | KILLED | all three `SEL EXEMPT` arms |
| harvest reads this file's SOURCE instead of the emitted output | KILLED | `EXEMPT-domain-all` |
| **derived and printed but not wired to `ok`** | **SURVIVED** | see below |
| equality relaxed to containment | KILLED | `EXEMPT-PASS!=NOOP`, `EXEMPT-domain-all` |
| the domain narrowed to exclude `V25` | KILLED | `EXEMPT-domain-all` — and at revision 2 the same narrowing at **any** of the other 22 rules is killed too, which it was not before |
| the expected value recomputed from the same expression | KILLED | `EXEMPT-PASS!=NOOP`, `EXEMPT-domain-all` |

**Why the survivor survives — and what the `EXEMPT-domain-all` repair did to it, which was not
the repair's purpose.** Deleting `ok &= _dok25` is unobservable to any single edit **while the
derived set's true value is `∅`**: the flag it would have contributed is `True`, so removing it
changes nothing. That is a property of the measured corpus, not of the arms, and it is still true.

At revision 1 the honest form was a PAIR. At revision 2 a **three-way control** says something
stronger, and it is a side effect of widening the domain sweep for `F3`:

```
KILLED    D4c-unarmed-wire-intact                     3 red: SEL EXEMPT-derived; SEL EXEMPT-domain-all
KILLED    D4b-unwired-and-unarmed                     3 red: SEL EXEMPT-derived; SEL EXEMPT-domain-all
SURVIVED  D4d-unwired-unarmed-and-domain-arm-unwired  402 arms, all green
```

`D4b` — the *same* unarming with the `EXEMPT-derived` wire **removed** — is now **red anyway**.
The sweep visits every registered rule, so an unarmed `V25` surfaces inside all 22 *other*
iterations and fails the run through a second, independently-wired arm. Only cutting **both**
wires (`D4d`) lets it pass.

**So the property `LLR-88.14` actually asks for — a rule shipping with no arms makes the selftest
FAIL — is now held REDUNDANTLY, and the single-edit `D4` is equivalent with respect to it.** The
mutation still survives; what it could once have removed, it can no longer remove. Stated this way
rather than as "killed", because the mutant is not red and saying so would be the substitution this
batch exists to end.

**A second battery of 15 mutations nobody named was run, and it found three real defects** — all
three now closed, all three re-scored red:

| Mutation | First run | Now | The defect it exposed |
|---|---|---|---|
| the age oracle takes `min` over the ref stamps instead of `max` | SURVIVED | KILLED | The fresh fixture had **one** remote branch, where the newest and the oldest ref are the same number. Taking the oldest would call a repository pushed a minute ago 40 days stale — the false-fail C-53 names. The fixture now carries a second, 40-day-old branch |
| `_remote_tip_age_days` returns `0.0` instead of `None` when no remote-tracking ref exists | SURVIVED | KILLED | A repository with a remote it has never fetched from would have read "backup verified, 0.00 days old" over a measurement that never happened. A sixth fixture — `E2E-never-fetched` — now reaches that state through the registered rule |
| the harvest's anchor relaxed from a two-space label anchor to a leading-whitespace one | SURVIVED | KILLED | The `PASS != NOOP` corpus's only non-label line began with a word. It now carries a prose line that OPENS with the rule id and a deeper-indented one |

The remaining 12 were red on the first run: an oldest-vs-newest confusion in the pass branch, the
`refs == 0` test moved after the age test, `rc is None` in place of `rc not in (0, 2)`, the `where`
field renamed, a duplicated finding, the probe swallowing a non-git directory, the exemption
constant restored to `{"V8"}`, `V25` dropped from `_RULE_COVERS`, the capture shim not capturing,
an undeclared selector, the stale message replaced by the pass message, and the probe discarding
the exit status.

**A defect the mutation run found that review did not.** `return []` on the pass path first
produced a **CRASH, not a red arm**: the selftest died at **351 arms, exit 1, no verdict line** —
against the **400** the suite emitted at that moment — because the sentence-comparison arms indexed
`[0]` into an empty list. That is the exact signature this batch scores against — *a crash is not a
verdict* — and it would have read as a kill to a naive scorer. The two sentence readers now degrade
to a named string, and the mutant reddens **6 arms** with the verdict line intact.

**One event, one number.** Revision 1 shipped "351 of 401" in `FLOW-VERSION.md` against "351 of
400" in the validator's own comment — the same crash, two figures, in two places an adopting
project reads. Both now say 351 arms against the 400 the suite emitted at that moment, and the
suite's current total is stated separately.

### 4.4 The checklist — 9 rows, 4 byte-identical, 4 mutants red

```
  ok   SEQ-1..9        the # column is exactly 1..9 in order
  ok   BYTES-shifted   the four shifted rows are byte-identical to their pre-state text
  ok   RC2-at-5        RC-2 is INTAKE row 5, immediately after RC-1
  ok   RC2-not-ARQ     RC-2 did not land in the ARQ table, which still holds 5 rows
  ok   MARKER-once     the row marker occurs exactly once (0 -> 1)
```

| Mutation | Verdict | Reddened |
|---|---|---|
| renumbering skipped so two rows share a number | KILLED | `SEQ-1..9` |
| a shifted row's bytes drift | KILLED | `BYTES-shifted` |
| the row lands in the ARQ table instead of INTAKE | KILLED | all four |
| a row silently dropped while another is added | KILLED | `SEQ-1..9`, `BYTES-shifted` |

The third named pin is the file's digest: any byte change to `phase-checklists.md` moves its canon
hash and `V7` goes red — which is precisely the state the gate carried into this increment.
**No vocabulary guard was written**: `R-88-16` established that prose has no grammar to derive a
class from, so no oracle here reads the row's wording for meaning.

### 4.5 The manifest — 5 mutants red, and the row count asserted on every one

```
  ok   ROWS-24                the table parses to 24 rows (got 24)
  ok   MAP-identity           --map: 24 in table order · 24 agree · 0 differ · 0 missing
  ok   V7-aggregate           declared aggregate a280beca91743d7c == recomputed a280beca91743d7c
  ok   ORDER-preserved        the File column's ORDER is the pre-state's, not merely its membership
  ok   MEMBERSHIP-both-ways   no canon path added and none deleted against the pre-state
  ok   REV-bumped             revision 2026.08.27-rev47 differs from rev46's string and hash
  ok   RUN-post-dates-edits   the evidence run started after the mtime of every canon file
```

| Mutation | Rows parsed | Verdict | Reddened |
|---|---|---|---|
| aggregate updated while all 24 rows keep stale (zeroed) hashes | 24 | KILLED | `MAP-identity` |
| the revision string not bumped | 24 | KILLED | `REV-bumped` |
| the bump taken before the last edit | 24 | KILLED | `RUN-post-dates-edits`, and at revision 2 this is a REAL comparison: the mutant passes a start stamp 24 h before the newest canon file's mtime, where revision 1 compared `time.time()` against the past and could not have failed |
| two rows transposed, then re-hashed | 24 | KILLED | `ORDER-preserved` |
| a canon row deleted, then re-hashed | **23** | KILLED | `ROWS-24` + 3 more |

**The row count is asserted on every one**, because `_canon`'s regex is strict and a malformed row
drops silently out of the table — a mutant that loses a row is a DIFFERENT mutant. Four of the five
kept 24 rows and are the mutants intended; the fifth parses 23 by construction and says so.

**Why `--map` is the only oracle for the declared column.** `v7_flow_hash` iterates `_canon`'s
KEYS and recomputes every digest from disk (the `for rel in _canon(home)` loop); it never reads the
declared value. Zeroing all 24 declared hashes therefore leaves the gate's output byte-identical,
and the first mutation above is invisible to `V7` and to `V15` alike.

---

## 5 · Risks

1. **`V25` talks to the network at every gate run.** Measured on this machine the probe returns in
   well under a second, and it carries a 20-second timeout asserted on the call — but a gate run on
   a disconnected machine now costs up to that timeout and prints a NOTICE. The severity choice
   (never BLOCK) is what keeps that from being a blocked gate; the cost is real and is stated
   rather than hidden.
2. **The age is a BOUND, not a proof.** Remote-tracking refs are as fresh as the last fetch, so
   `V25` reports the age of the newest thing origin held *when this repo last looked*. The rule's
   docstring declares this in the same terms `V16` and `FLOW-VERSION.md` already use about
   themselves; nothing local can do better without a fetch.
3. **The `print` shadow inside `selftest()` is unusual.** It is a local function named `print`, so
   every call in the body — including the nested helpers that close over it — is captured. It is
   documented at the point of definition. A future edit that adds a *module-level* helper printing
   arm lines would escape the capture, and the derived set would then name a rule that is in fact
   armed — which fails loudly rather than quietly, but is worth knowing.
4. **The derivation's wire is proved by a pair, not by a single edit** (§4.3). While the expected
   set is `∅`, no single-edit mutant can distinguish wired from unwired.
5. **The bundle and both flow checkouts are uncommitted.** `V16` blocks on exactly that, by design.
   Nothing was committed, per the increment's instructions.
6. **The canon both-ways check compares the table to the PRE-STATE TABLE, not to disk** — recorded
   as a gap, not closed. `MEMBERSHIP-both-ways` catches a row added or deleted against the state
   before this increment, which kills the deletion mutant `LLR-88.16`'s ⚠ names. It does **not**
   catch the other direction the ⚠ was written for: *a flow file on disk that no canon row covers*.
   That direction has no executable oracle here, because "the set of flow files on disk" is not
   defined anywhere the harness can read — deriving it would require a second inventory, which is
   the defect this manifest has removed five times. **A pre-state table is a proxy substituted on
   the exact axis the requirement asked about**, and naming it is the only honest disposition
   available without a declared file set. Owed as a follow-up, not claimed as done.
7. **A directory that is not a git repository renders as "no `origin` remote is configured".** The
   sentence is not false — a non-repository has no remote — but it names a configuration fact where
   the cause is that there is no repository at all. Measured, not theorised; left as-is because a
   seventh state for a case the gate never reaches would be error handling for a scenario that
   cannot happen at a real `.dev-flow` root.
8. **The probe costs up to its 20 s timeout when a remote demands credentials.** `GIT_TERMINAL_PROMPT=0`
   now makes git fail instead of prompting against inherited stdin, which is what turned that case
   from a hang into a verdict. Worst case measured at ≈24 s for a full gate run; the guard hook's
   60 s cap is not at risk.

### The eleventh shape of the vacuous check

**A typed sentence pins its WORDING and never its REFERENT**, and this batch walked into it with
its own instrument in hand.

Shape 4 of this batch was *the pass message rendering a constant where it promises a measurement*,
and the answer was to type every expected sentence as a character-for-character literal. That
closes the wording completely. It says **nothing** about what the numbers inside the sentence are
numbers *of*. `V25` printed a ref count drawn from `ls-remote origin` beside an age drawn from
every remote on the machine, and **nine typed-sentence arms and six registered-rule E2E arms all
passed**, because every fixture had exactly one remote — so the sentence's referent and the
oracle's domain were the same set, and no arm could tell them apart. `committerdate` → `authordate`
survived for the identical reason: both date fields were written from one stamp.

**The detector is not a better sentence arm. It is a FIXTURE WHOSE DOMAIN HAS TWO ELEMENTS THAT
DISAGREE.** That instrument was already in this packet — the `max`/`min` repair at revision 1 added
a second remote *branch* precisely because one branch made the newest and the oldest indistinguishable
— and then it was not applied to the next axis, or the one after. **A one-element domain is invisible
to every assertion written over it, and each axis needs its own second element:** one remote became
two, one branch became two, one date field became two that disagree.

---

## 6 · Pending

- **Commit and push** `claude-config` and the nested `agent-skills` checkout, then re-run the gate:
  `V16`'s two blocks are the only ones left and they clear on push (`C-44`). **Not done here.**
- **`04-validation.md`** — the batch's validation record still owes `V25`'s arm labels enumerated
  one per line, the `V25` gate line pasted, and this increment's ledger arithmetic.
- The `dev-flow-lessons` catalog entry (step 2 of the manifest's bump procedure) — no *control*
  changed this increment, so no entry is owed; recorded so the omission is deliberate.
- **`ID-B88-08`**, the source pin, is unmeasured in this packet: it pins the shipped app, which this
  increment does not touch.
- **The canon both-ways check owes its disk direction** (§5.6). Closing it needs a declared set of
  flow files that is not a second inventory — most likely a walk of the canon roots with a declared
  exclusion list, which is a design question and not a patch.

---

## 7 · Suggested next task

**Phase 4 — write `04-validation.md` for batch-88**, and close the batch. Its first obligation is
the one `LLR-88.1` exists for: the ledger expression, in a form `V5` can now parse, since `V5` was
widened in Inc 1 and 57 of 61 records still carry none. The second is `HLR-88.1`'s **7 of 7**
enumeration — per rule, never as a total — which this increment completes the last member of.

---

## Evidence checklist

| | Item | Evidence |
|---|---|---|
| ✓ | Tests / type checks / lint pass | `--selftest` → **402 arms, `SELFTEST PASSED`, exit 0**; **49** single-edit mutations run, **47 red**, 1 measured EQUIVALENT, 1 survivor whose consequence is now redundantly covered — plus 4 multi-edit controls; final gate `2 block · 287 notice · 16 n/a` with `V7` green and `--map` at `24 agree · 0 differ · 0 missing` |
| ✓ | No secrets in code or output | The only external value read is `git remote get-url origin`, and it is **never printed** — the findings name `origin`, never a URL. No token, path or credential appears in any new sentence |
| ✓ | No destructive commands run without approval | No commit, no push, no delete. Every mutant was written to a COPY under `~/.claude/jobs/c0c0fa47/tmp/`; `prototypes/`, `build/` and untracked files untouched |
| ✓ | File count within cap | **3** source files — the batch's declared maximum — plus one build output, one record and one derived directory, each labelled in §2 |
| ✓ | Review packet attached | This document at **revision 2**, written before `--atlas --write` regenerated the Atlas. Every figure in it was re-measured after the revision-2 source edits; none was carried across |
