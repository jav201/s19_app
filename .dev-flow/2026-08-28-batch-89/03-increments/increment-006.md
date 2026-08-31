# Increment 006 — `HLR-89.6` · `LLR-89.6.1` – `LLR-89.6.4` — `V27` and `V28`, and a property reported unimplementable rather than shipped

> ## ⚠ READ THIS FIRST — THIS PACKET DID NOT GATE THE INCREMENT, AND THE INCREMENT IS WHY IT EXISTS
>
> **Written 2026-08-30. The increment was committed the same day at 20:07:13 -0600**
> (`686733c`), and is **not merged** — `git log origin/main..HEAD` lists it as still only on
> `origin/claude/batch-89-lean-contract`.
>
> **The self-reference is the point and must not be smoothed over.** This increment shipped
> `V27`, a rule that reports when `state.json`'s `decisions_log` does not correspond to the
> increment packets on disk. **It registered the finding against its own batch and shipped
> without repairing it** — as `R-89-9`, declared rather than silenced. Minutes after it landed,
> the gate printed:
>
> ```
> [!] V27  .dev-flow/state.json: 2 `decisions_log` decision(s) name an increment with no
>          packet on disk -- increment(s) 1, 2. The same disagreement read from the other
>          side, and a membership test in one direction cannot see it
> [!] V27  .dev-flow/state.json: the newest `decisions_log` entry is dated 2026-08-27 while
>          the newest commit touching the batch directory is dated 2026-08-30 -- the ledger
>          is behind the work it is supposed to record, which is the freeze batch-88 shipped
>          with
> ```
>
> **This packet, and the three beside it, are the repair of that finding.** Written after the
> fact, for work already committed. They are transcription and reconciliation, not
> verification.
>
> Figures are transcribed from `686733c`'s message, `FLOW-VERSION.md`'s rev50 row, and
> `LED-89.13` – `LED-89.19`. Where a field has no evidence it is marked **ABSENT** with the
> reason.

| Field | Value |
|---|---|
| Batch | `2026-08-28-batch-89` |
| Increment | `006` of 6 declared — **4 built**. **A sixth increment on a record that opened declaring five**; see the closing note below for why `004` and `005` do not exist |
| Requirement(s) | `HLR-89.6` · `LLR-89.6.1` · `LLR-89.6.2` · `LLR-89.6.3` · `LLR-89.6.4` |
| Ledger | `LED-89.13` – `LED-89.19` |
| Premises | `P-10` · `P-11` · `P-12` · `P-13` |
| Findings registered, unrepaired | `R-89-9` (the rollover never scoped this log) · `R-89-10` (the unimplementable property) |
| Acceptance | **no id is minted** (`R-89-7`). `owed at Increment 6` in the live contract, discharged by the arms in §4 |
| Flow revision | rev49 → **rev50** |
| Date of the work | `2026-08-30` |
| Date of this packet | `2026-08-30` — **after the commit** |

---

## 1 · What changed

**`V18` verifies that `state.json` DECLARES a batch and stops there.** Nothing anywhere checked
that its `decisions_log` **corresponds** to anything, and batch-88 paid for that twice inside
one batch: the log **froze on 2026-08-27** with no entry for increments 3 through 7; the batch
**caught and repaired the identical freeze mid-flight** (`0e3445a`, finding F-D); and **it
re-froze**. Nothing saw it either time, because *a log that EXISTS and a log that is CURRENT
are the same picture to every rule that ships*.

### `V27` — NOTICE, selector `S1` plus the project repo's commit history

**Coverage is a CORRESPONDENCE and is checked in both directions** — every increment packet on
disk named by a decision, **and** every increment a decision names having a packet. One
direction is not the property: a log naming increments 1–9 over three packets satisfies
*"every packet is logged"* while describing work that does not exist.

**The harvest reads the `decision` field and NEVER `notes`, and that is the rule's sharpest
decision — forced by the real record** (`LED-89.13`). batch-88's P0 entry at `0f40624` carries
the notes *"…authorises Inc 1 and Inc 2, WITHHOLDS Inc 3 and Inc 4 until #D1 lands"* — prose
about a design review that had **not authorised the work yet** — so a harvest over `notes`
reports increments 3 and 4 **LOGGED**, on the one record the rule exists to have caught.

**Currency is the half no document-only rule can have:** a stale record cannot tell you it is
stale. The newest entry is compared against the newest commit touching the batch directory,
asked of git **with a pathspec** — without it the question becomes *"when was this repository
last committed to"*, a different and always-fresher number. Equality is **CURRENT, not
behind**. The newest entry is a **maximum**, never `log[-1]`, because an append-only log is
written in order by convention and nothing enforces it. **git-unaskable and no-commit-yet are
two DIFFERENT unchecked states**, neither of which is the pass sentence — *Increment 003 of
this same batch already paid for collapsing two causes into one message.*

### `V28` — NOTICE, selector `S3`

**The property was asked for as *"a batch does not reach `main` below station P4"*, and it is
not implementable as stated. That answer is the deliverable, not a shortfall** (`LED-89.14`,
`R-89-10`).

| | batch-88 | batch-89 |
|---|---|---|
| merge | `0f40624`, PR #203, 2026-08-28 07:27 | `dde935c`, PR #204, 2026-08-29 12:08 |
| station at merge | `P3` | `P3` |
| `04-validation.md` / `05-close.md` on disk | absent / absent | absent / absent |
| verdict | **defect** | **correct — the batch ships increment by increment** |

**Every field a local rule can read is identical, and the second one is correct.** A rule keyed
on *"any batch commit in `main` while station < P4"* is **RED TODAY ON CORRECT WORK** — `C-53`'s
false fail, and worse than no rule, because *a rule that cries wolf is how people learn to
ignore the gate.*

**What separates them arrives later, and it is SUPERSESSION.** batch-88's merge was never the
defect; its **abandonment** at that station was, and the hole became permanent the instant a
newer batch directory opened beside it — mechanically, because `state.json` is **single-slot**:
once `batch_id` moved, `/dev-flow-sync` and every other tool that reads *"the batch"* could no
longer see batch-88, and its two closing artifacts were written by hand a day late saying so.

So `V28` checks the property that **is** separable: **the batch a newer batch superseded holds
its validation and close artifacts.** Its three costs are written into its own block comment
rather than left to be discovered — it **fires one station late**, it **never looks at a
commit**, and it has a **one-batch window**.

**Both rules are NOTICE, ruled rather than defaulted** (`LED-89.15`), and the third reason
decides it: `state.json` is the flow's own bookkeeping that no increment owns; a project
wording its log differently would BLOCK forever; and **the defect being closed is
INVISIBILITY, not permission.** batch-88's freeze was never blocked by anything and never
needed to be — it needed to be **SEEN**.

> **The honest limit, stated with the ruling:** `run()` exits non-zero only on BLOCK and the
> guard hook runs `V7`/`V15`/`V16` alone. What these rules buy is **a sentence in front of a
> reader at every gate, not an enforcement.**

**Story 6 reached the record through the ledger.** The record that opened 2026-08-28 declared
five stories. batch-88's close, written 2026-08-29, then measured two defects no rule could
see. The scope moved by **APPENDING the reason** (`LED-89.19`) and amending the current
sentence — never by striking the old one, which `V26` would BLOCK, and never by leaving the
table saying five while six shipped, which nothing would have caught. **This is the mechanism
Increment 001 built, used for the first time on a change it did not anticipate.**

---

## 2 · Files modified

**Zero source files in `s19_app`.** Both rules landed in `~/.claude`.

| Repo | Commit | Files | Change |
|---|---|---|---|
| `s19_app` | `686733c`, 2026-08-30 20:07:13 -0600 | **6 files, +285 / −11** | `01-requirements.md` (+140/−…), `01-requirements-ledger.md` (+133), the 4 `_derived/ATLAS-*.md` files |
| `~/.claude` | `3a2c5eb`, 2026-08-30 20:06:57 -0600 | **2 files, +773 / −4** | `docs/tools/devflow-validate.py` (+770 — both rules and their arms), `docs/FLOW-VERSION.md` |
| `~/.claude/skills` | `029e441` | mirror | `--sync-bundle` output, never hand-edited |

| Count | Value |
|---|---|
| **SOURCE files** | **`0`** / 4 — in `s19_app`. **1 authored source file** in the flow repo plus 1 declared build output (the bundle mirror) |
| Test files | 0 (uncapped) — the arms live in `--selftest` |

> **`state.json` was NOT touched by this commit** — and it is the file both new rules report
> on. `LED-89.15` gives the reason it could not have been: *"this increment does not own that
> file and could not have cleared its own block"*, which is one of the three arguments for
> NOTICE over BLOCK. The consequence is `R-89-9`, still open at the moment `686733c` landed.

---

## 3 · How to test

```bash
export PYTHONIOENCODING=utf-8
python ~/.claude/docs/tools/devflow-validate.py --selftest            # 490 arms, SELFTEST PASSED
python ~/.claude/docs/tools/devflow-validate.py "C:/Users/jjgh8/Github/s19_app" | grep -E "V27|V28"
```

> **⚠ The gate output changes with this batch's own record.** The `V27` transcript quoted in
> the header block above is the state **at the commit**, with zero packets on disk. Running the
> same command after these four packets and the scoped `decisions_log` exist reports the
> agreement instead. Both are real; each carries its date.

---

## 4 · Test results

| Measure | Value | Source |
|---|---|---|
| Selftest | **490 arms**, `SELFTEST PASSED` | `FLOW-VERSION.md` rev50 |
| Arm delta | 443 → **490** (+47) | `FLOW-VERSION.md` rev50 |
| Registered rules | 24 → **26** | `FLOW-VERSION.md` rev50 |
| `V27` / `V28` arms | **47** report `ok` | `HLR-89.6` threshold |
| `V26` on this record | **41,060 chars inside the 54,000 budget · no strikethrough · 22 (requirement, entry) pairings identical in both directions** | `686733c` message |
| Corpus sweep behind `V28`'s window | of **72** batch-shaped directories, **9** hold neither or only one closing artifact — batches **25, 63, 66, 71, 73, 75, 78, 79, 85** | `P-12`, `LED-89.16`, measured 2026-08-30 |
| batch-88's log at its merge | **10 entries**, newest **2026-08-27**, only **2** decisions naming an increment (1 and 2), against **7** packets on disk at `0f40624` | `P-10`, reproduced 2026-08-30 |
| **Gate line at this commit** | **ABSENT** | not recorded in the commit message; the batch has no `04-validation.md` to hold it |
| Gate re-derived today, 2026-08-30, **before these packets existed** | **0 block · 292 notice · 22 not applicable**, exit 0 | run for this packet; **today's measurement, not the increment's** |

### The arms that earn their place

- **`V27 NOTES-DONT-COUNT`** — the discriminator, and *it works only because its fixture's two
  FIELDS DISAGREE*. Its fixture is batch-88's real P0 entry, whose `notes` name increments 1
  to 4 while its `decision` names none. An entry whose decision and notes say the same thing
  cannot tell the two harvests apart.
- **`V27 HISTORIC-b88`** — replays the ten real entries against the seven packets
  `git ls-tree -r 0f40624` shows, and asserts `{3, 4, 5, 6, 7}` unlogged plus a ledger dated
  one day behind its own merge.
- **`V27 E2E-git-date`** — builds a repository, commits the batch directory and asserts the
  rendered date equals the one it reads from `git log` **itself**, twice: on a log dated with
  that date and on one dated `2000-01-01`. **The arm holds no calendar literal and cannot rot.**
- **`V28 PRED-complete`** — a **COMPLETE predecessor between an incomplete older batch and an
  incomplete ACTIVE batch**. A corpus sweep reports the older one; a rule reading the active
  batch reports batch-89's correct by-design state; **only the predecessor reading passes.**
  Three candidate oracles separated by one fixture.
- **`V28 ORDER-agrees-today` / `ORDER-numeric`** — ordering is `(date, batch NUMBER as int)`.
  Over the real corpus lexical order **agrees**, because every number is two digits, which is
  *why* `ORDER-numeric` must be synthetic: `2026-09-01-batch-10` sorts before
  `2026-09-01-batch-9` lexically, making a batch its own successor's predecessor.
- **Both `LIVE-agree` arms** re-derive their expected answer from `state.json`, `git log` and
  the directory listing rather than compare against a typed one, **so neither rots when a
  batch opens.**

### Mutation testing — 25 named single-edit mutants: **24 killed, 1 survived, 0 broken**

Baseline **490 arms, zero red**. Each mutant scored **against the run's own baseline arm
count**, with the kill criterion being **the SET of failing arm labels GROWING**, never the
FAIL count.

| Mutant | Effect |
|---|---|
| `M1-harvest-notes` | reddens `NOTES-DONT-COUNT` and `HISTORIC-b88` and nothing else |
| `M2-unpacketed-silent` / `M14-packets-ignored` | each reddens **one direction** while the other stays green — which is what proves they are two obligations |
| `M3-currency-off-by-one` (`<` → `<=`) | reddens **ten** arms — the widest blast radius in the increment |
| `M4-oldest-not-newest` | reddens `CURRENCY-MAX-NOT-LAST` |
| `M8-no-pathspec` | reddens `E2E-git-date` **alone** — that arm is the only thing standing between the rule and a question it was not asked |
| `M9-causes-collapse` / `M13-malformed-date-accepted` | each reddens one |
| `M6-registered-noop` / `N9-registered-noop` (`return []`) | redden **6** and **3** arms and **NO core arm** — the gap `LLR-89.6.4` exists to close |
| `N2-judges-the-active-batch` / `N3-judges-the-earliest` / `N10-holds-of-the-wrong-batch` | redden **9**, **8**, **8** |
| `N1-lexical-order` | reddens `ORDER-numeric` alone |
| `N4-one-close-name` | reddens `POSTMORTEM-COUNTS` |

### 🛑 Three things that went wrong inside the mutation pass, all recorded rather than tidied

**(a) The first mutation baseline came back RED, and it was not the mutants' fault.** A flat
copy of the validator was tried first. **Increment 003's own `INT FOUR-PLACES-agree` arm reads
three sibling scripts by walking up from `__file__`**, so outside a flow-shaped tree it reports
the layout instead of the interpreters. **A baseline that is already red cannot score
anything**, and *lowering the bar to accommodate it would have been the vacuous check one level
out.* The battery was moved to a **mirrored flow tree** (`docs/tools/` plus `hooks/`). This is
the **second** red baseline in two increments — Increment 003 discarded one too.

**(b) One mutant was REWRITTEN because it was BROKEN, not because it survived.**
`M13-nodate-silent` (`if not days:` → `if False:`) **crashed at 454 arms with no verdict
line**, which the harness refused to score: *a crash prints no FAIL and reads exactly like a
survivor* — the same shape Increment 002 was written about. The guard it removes is what stops
an `IndexError` on an empty list, so it could never have been silent. Replaced by
`M13-malformed-date-accepted`, which drops the `_V27_DAY` filter and reddens `NODATE` alone.

**(c) The one survivor is recorded EQUIVALENT BY EXECUTION rather than chased.**
`M15-zero-padding-dropped` removes `0*` from the harvest pattern. With it the quantifier eats
the zeros; without it `int()` does. **No input separates them, `Increment 0` included.** Left
in place because its sibling `_V27_PACKET` reads filenames, where the intent is worth stating.

### 🛑 Two findings the live gate raised the moment the rules shipped — both TRUE, both left open

- **`R-89-9`** — `state.json`'s `decisions_log` was never reset when batch-89 opened, so it
  still held batch-88's **ten** entries while `batch_id` read `2026-08-28-batch-89`. **The
  per-batch convention is real:** batch-88's log at `0f40624` carries **not one** batch-87
  entry (`P-13`). One line of the rollover procedure is the repair. **Shipped unrepaired.**
- **`R-89-10`** — the unimplementable property itself, above.

### Independent review

**ABSENT.** No `code-reviewer` verdict exists for this increment.

---

## 5 · Risks

- **`V28` fires one station late, never looks at a commit, and has a one-batch window.** Two
  unclosed rollovers in a row and the older batch is never judged again (`LED-89.16`). All
  three costs are in the rule's own block comment; none is hidden.
- **Neither rule enforces anything.** `run()` returns non-zero only on BLOCK. A reader who
  ignores NOTICE lines is exactly as unprotected as before — **and batch-88's freeze was never
  blocked by anything.**
- **`V27` cannot tell a packet from a placeholder.** It matches `increment-0*N.md` and reads
  nothing inside. Four empty files would satisfy it. *These four packets are the first test of
  that bound, and it is a real one.*
- **The currency comparison is date-granular.** A log written the same day as a commit is
  current, however many hours behind. That is `LED-89.17`'s deliberate choice and it is also a
  ceiling on what the check can see.
- **`R-89-9` was closed on 2026-08-30 by scoping the log by hand.** Nothing prevents the next
  rollover from repeating it; that repair belongs to the flow's rollover procedure, which is
  not this repository.

## 6 · Pending

- **This increment is not on `main`.** `686733c` sits on
  `origin/claude/batch-89-lean-contract` only.
- **`04-validation.md` and `05-close.md` do not exist for this batch.** By `V28`'s own logic
  the hole becomes permanent the instant a newer batch directory opens beside this one.
- **`state.json`'s `batch_objective`, `artifact_homes` and `triggers.record` are still
  batch-88's or stale**, including the superseded `55000` budget figure and Increments 2 and 3
  listed as *"NOT IMPLEMENTED"*. The 2026-08-30 write was scoped to `decisions_log`.
- **`R-89-6`, `R-89-7`, `R-89-8` and `R-89-10` remain open**, registered unrepaired.

## 7 · Suggested next task

**Phase 4 — write `04-validation.md` for batch-89, then `05-close.md`, before a newer batch
directory opens beside this one.** That is the exact sequence `V28` exists to report on, and
batch-88's `04-validation.md` and `05-close.md` — both written retroactively on 2026-08-29 and
both saying so at the top — are what it costs when the sequence is not followed.

---

## ⚠ Why there is no `increment-004.md` and no `increment-005.md`

**They were approved and never built.** They are not missing from this record; they are missing
from the work.

| Increment | Requirement | Status |
|---|---|---|
| **004** | `HLR-89.4` — the environment contract, DECLARED as a canon row and **derived** from the source constructs that bind it | **specified, not implemented.** Ledger `LED-89.2`. Acceptance stands as `owed at Increment 4`; negative control `owed at Increment 4` |
| **005** | `HLR-89.5` — a runtime preflight reporting git, stdout encoding and filesystem case-folding | **specified, not implemented.** Ledger `none`. Acceptance stands as `owed at Increment 5` |

`01-requirements.md` §1 says it in its own scope table — Stories 4 and 5 carry no
**implemented** marker where Stories 1, 2, 3 and 6 do — and the ledger records how Story 6
arrived on a record that declared five (`LED-89.19`).

**The four packets are numbered 001, 002, 003 and 006, and the gap is deliberate.**
Renumbering them 1–4 would close the hole visually and **silently rewrite what was planned**,
which is precisely the shape `V26`'s append-only ledger and `V27`'s both-ways correspondence
exist to prevent. A record that reads cleanly by hiding what did not happen is worth less than
one that reads awkwardly and is true.

---

## Increment gate checklist

**Reconstructed 2026-08-30, hours after the commit. This checklist did not gate anything.**

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 0 in `s19_app`; 1 authored + 1 declared build output in the flow repos (`3a2c5eb`, `029e441`) |
| 2 | Tests written in the same increment | ✓ | 443 → 490 arms; 47 `V27`/`V28` arms |
| 3 | RED counterfactual captured | ✓ | 25 named mutants, 24 killed, 1 measured EQUIVALENT, 0 broken — scored against the run's own baseline, kill criterion = the failing-label SET growing |
| 4 | A red baseline refused rather than scored | ✓ | §4(a) — the flat-copy baseline was rejected and the battery moved to a mirrored tree |
| 5 | A broken mutant refused rather than counted as a survivor | ✓ | §4(b) — `M13-nodate-silent` crashed at 454 arms and was rewritten |
| 6 | Findings registered rather than silenced | ✓ | `R-89-9` and `R-89-10`, both TRUE, both shipped unrepaired and named |
| 7 | Independent `code-reviewer` pass | **✗** | none ran |
| 8 | No file from another lane touched | ✓ | `git show --stat 686733c` — 6 files, all under `.dev-flow/`; nothing under `prototypes/` or `build/` |
| 9 | Frozen interfaces untouched | ✓ | 0 files under `s19_app/`, `tests/` or `tools/` |
| 10 | The rule's own finding against its own batch cleared | **✗** at the commit, ✓ on 2026-08-30 | `R-89-9` shipped open; the `decisions_log` was scoped and these packets written the same day, **after** the commit |
| 11 | Packet written at the increment's gate | **✗** | **Written 2026-08-30, after `686733c` landed.** The defect `V27` reported and this packet repairs |

**An item without a citation is not satisfied — it is asserted.**
