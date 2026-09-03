# Validation — s19_app — Batch `2026-08-28-batch-89` · the lean contract + five environment closures

> ## ⚠ READ THIS FIRST — WHAT THIS DOCUMENT DID AND DID NOT GATE
>
> **Written 2026-09-03, at station P4, before the batch's remaining six commits reach `main`.**
> That makes it a **split verdict**, and the split is the first thing a reader needs:
>
> | | commits | station at merge | did this document gate them? |
> |---|---|---|---|
> | **Already on `main`** | `dde935c` · `1d2e9fe` · `686733c` · `2f04ebb` — merged as **PR #204** (`1238b7e`, 2026-08-29) and **PR #206** (`a2a2534`, merged 2026-08-31T03:10:32Z) | **P3** | **NO.** They merged from station P3, three to five days before this file existed. This document had no opportunity to stop them |
> | **Not yet on `main`** | `a679ee6` · `c4e6fe5` · `ed03b10` · `c118f6e` · `cf24e29` · `976476d` | — | **YES.** These six are still on `claude/batch-89-lean-contract` and this gate precedes their merge |
>
> **So batch-89 repeated batch-88's defect and then stopped repeating it.** Four commits went to
> `main` from P3 with no validation artifact — the same shape `04-validation.md` of
> `.dev-flow/2026-08-24-batch-88/` records against itself. The remaining six did not, and the
> difference is that this file was written before them rather than after.
>
> **Two things about this batch's evidence that are weaker than batch-88's, stated here rather
> than buried:**
>
> 1. **Four of the six increment packets were written retroactively.** Increments 1, 2, 3 and 6
>    were built and committed with **zero** packets on disk; `V27` — shipped by increment 6 of
>    this same batch — reported the hole against its own batch, and the four packets are the
>    repair. Each says so in its own header with its own dates. Increments 4 and 5 were written
>    at the gate, before any commit, and say that too.
> 2. **No increment had an independent `code-reviewer` pass. Not one, of six.** Every defect
>    recorded in this batch was found by the implementer's own sentinel, mutation battery or
>    arm. That is a real gap in this batch's evidence, not a footnote: batch-88 ran that lens at
>    every one of its seven increments and six came back BLOCK. The comparison is in §7.
>
> **What was re-derived for this document, and what was transcribed.** Every figure below carries
> its source and its class. **Class A** was executed today at rev56 by this document. **Class B**
> is transcribed from the artefact that measured it, at the revision it was measured at, and was
> **not** re-run. **Class C** is marked **ABSENT** with the reason. No figure was averaged, and
> no figure without a source was written.

---

## ✅ Verdict (read first)

| | |
|---|---|
| **Result** | **PASS-WITH-NOTES** |
| **Requirements** | **16 of 16** carry executed verification · **0** blocker fails |
| **Black-box acceptance (Layer B)** | ⚠ **no `AT` id is minted in this batch, by measured ruling** (`R-89-7`). Layer B is discharged through the `--selftest` `E2E-*` and `LIVE-agree` arms, which drive the registered rule rather than its pure core. The reason `V2` cannot express this is itself a shipped finding — see §3 |
| **Surface-reachability (bidirectional)** | ⚠ **1 gap** — `HLR-89.1`'s `Executed verification` names an arm that has never existed at any revision. See `G-89-01` |
| **Supersession inspection** | ⚠ **1 live stale reference** — `increment-006.md`'s closing section still states that increments 4 and 5 were never built. See `G-89-02` |
| **Test ledger** | ✓ **reconciles: `2760 = 2735 - 0 + 25`** (COLLECTED counts — the two endpoints are different pytest invocations; §5a). The `+25` was corroborated by collecting the new file directly. ⚠ **7 failures**, inside two open `P2` items' measured 6/10/6 band; **none of the seven is in a file this batch touched** |
| **Mechanical gate** | ✓ **before this close's writes: `0 block · 290 notice · 27 not applicable`, exit 0.** ✓ **after: `0 block · 288 notice · 29 not applicable`, exit 0** — the delta is exactly `V27`'s two findings becoming passes. Both runs pasted in §1 |
| **Validator selftest** | ✓ **565 arms · 565 `ok` · 0 FAIL · `SELFTEST PASSED`** on **both** 3.11.15 and 3.12.7 — re-derived today by direct count, not carried |
| **Independent review** | ✗ **0 of 6 increments.** The single largest evidence gap in this batch |
| **Evidence checklist** | see the final section — 4 items marked ✗ |

**Why PASS-WITH-NOTES and not PASS.** Every requirement has executed verification and the gate is
clean, so nothing blocks. But three things are true at once that a bare PASS would hide: an
independent review lens ran zero times; four packets are reconstructions; and one requirement's
own threshold cites an arm that does not exist. None of the three is a code defect. All three are
holes in the *evidence*, which is what this station is for.

---

## 1 · The mechanical gate, executed today

**Command, and it is the only interpreter this project's gate is declared against:**

```bash
export PYTHONIOENCODING=utf-8
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
  ~/.claude/docs/tools/devflow-validate.py C:/Users/jjgh8/Github/s19_app
```

**Preflight (the three lines increment 5 shipped, printed above the first verdict):**

```
devflow-validate · C:\Users\jjgh8\Github\s19_app
  git · 2.49.0, at or above the 2.28.0 floor
  stdout · encoding `utf-8`, errors `backslashreplace` -- every finding is emitted verbatim
  filesystem · FOLDS CASE -- probed at C:\Users\jjgh8\AppData\Local\Temp, on the same volume as the tree under check
```

**Result line:**

```
0 block · 290 notice · 27 not applicable
EXIT=0
```

**Distribution of the 290 notices, counted from the run rather than described:**

| rule | lines | what they are |
|---|---:|---|
| `V9` | **228** | increment packets across the whole corpus declaring no SOURCE count. **Historic, and measured rather than assumed:** `find .dev-flow -name 'increment-*.md'` returns **243**, so 15 declare a count `V9`'s pattern can read — and **all 6 of batch-89's are among them**, each returning `n=0`, verified by running `V9`'s own regex over the six files |
| `V13` | **52** | undeclared reachers of batch-87's IFC component addresses. Not this batch's subject |
| `V26` | 5 | **all `ok`** — this batch's own rule, over this batch's own record |
| `V30` | 4 | **all `ok`** — the environment contract, all four floors derived and agreeing |
| `V22` | 4 | canon-seeding census, the standing backlog |
| `V27` | 3 | **2 findings + 1 pass** — see §4; both findings are what this close repairs |
| `V8`, `V7`, `V16`, `V23`, `V25`, `V28`, `V29`, and 13 others | 1 each | see below |

**The four lines that matter to this batch, quoted verbatim:**

```
[-] V7   FLOW-VERSION.md: flow current (7ebb49bee3b82839)
[!] V27  .dev-flow/state.json: 2 increment packet(s) are named by no `decisions_log` decision --
         increment(s) 4, 5.
[!] V27  .dev-flow/state.json: the newest `decisions_log` entry is dated 2026-08-30 while the
         newest commit touching the batch directory is dated 2026-09-03 -- the ledger is behind
         the work it is supposed to record, which is the freeze batch-88 shipped with
[-] V28  .dev-flow/2026-08-24-batch-88/: `2026-08-24-batch-88`, the batch `2026-08-28-batch-89`
         superseded, holds `04-validation.md` and a close artifact
```

**`V7` green is load-bearing and is why this document may cite live numbers at all.** The local
flow is **rev56** (`~/.claude` commit `1fd6748`, *"dev-flow rev56: the verified repairs from the
rev56 candidate…"*), and the validator is **byte-untouched by rev56** — measured, not assumed:
`git diff --name-only 4f2c817 1fd6748 -- docs/tools/devflow-validate.py` returns **0 files**, and
rev56's 11 changed files are all commands, templates and `FLOW-VERSION.md`/`deployment.md`. **So
the instrument that produced this batch's rev55 figures is the instrument that ran this gate.**
That is the difference from batch-88's close, which could not re-run anything because the
instrument had moved three revisions under it.

### The gate run AGAIN, after this close's writes — because a repair claimed is not a repair shown

```
0 block · 288 notice · 29 not applicable
EXIT=0
```

**The delta is exactly two lines and nothing else moved.** Diffing the two runs rule by rule:

```
-   2   [!] V27          (the two findings)
-   1   [-] V27
+   3   [-] V27          (all three lines now pass)
```

290 − 2 = 288 notices; 27 + 2 = 29 not-applicable. **Every other rule is byte-identical between the
two runs**, which is what makes the claim *"this close repaired `V27`'s two findings"* checkable
rather than asserted. The three passing lines now read:

```
[-] V27  all 6 increment packet(s) on disk are named by a `decisions_log` decision
[-] V27  6 increment(s) named by a `decisions_log` decision, each with a packet on disk
[-] V27  the newest `decisions_log` entry is dated 2026-09-03 and the newest commit touching the
         batch directory is dated 2026-09-03, so the ledger is not behind the work
```

⚠ **One BLOCK appeared between the two runs and was cleared by the declared act.** Writing these
two artifacts changed the corpus, so `V20` blocked on
`.dev-flow/_derived/ATLAS-BATCHES.md: committed copy differs from what the corpus derives`. The fix
is the one `V20`'s own message names — `--atlas --write` — and **the regenerated diff is exactly
one line**: batch-89's row moving from `x · x · · · · ·` to `x · x x · x · ·` as the validation and
close artifacts appear. **Zero new ids were adopted into the derived plane**, which is the C-56
check discharged by measurement rather than by intention.

**Two notices that are true and are NOT this batch's to close:**

- `[!] V16 ~/.claude: level with origin/main, but that reference was last refreshed 4.9 day(s)
  ago — the comparison is against a LOCAL ref, so this is an identity check, not a currency one.`
  Stated, not fixed: the fix is `git -C ~/.claude fetch`, and the flow repo is not this batch's
  working tree at this station.
- `[!] V23` on `01-requirements-ledger.md:258` — a design-review citation that does not match the
  declared design-review grammar, which requires the prefix to be followed by a batch-directory
  name and optional version and decision suffixes. **The malformed token is described
  and not reproduced here, per C-56**: `.dev-flow/**` is corpus to the id scanners, so quoting it
  would move the defect from one site to two. What is wrong with it, in words: after the
  design-review prefix it carries a bare **date** where the grammar requires a **batch-directory
  name**, so it
  resolves to nothing. The ledger is **append-only** and this close will not edit it. Carried —
  see §6.

---

## 2 · Layer A — functional (white-box), per requirement

**Method, and it is a re-derivation rather than a reading.** For each requirement, the arms named
in its own `Executed verification` field were looked up **in today's live `--selftest` output**
and their verdicts read off. The instrument that did the lookup was proven first: fed one real arm
and one fabricated one, it returned `ok` and `MISSING` respectively, so it can report a negative.
Without that proof a clean sweep would be worth nothing.

```
V26 BUDGET-at                                ok
V26 THIS-ARM-DOES-NOT-EXIST                  MISSING     <- the proof
V27 HISTORIC-b88                             ok
V99 FAKE                                     MISSING     <- the proof
```

### High-level requirements (6)

| Req | Method | Executed verification (today, rev56) | Numeric threshold | Result | Evidence |
|---|---|---|---|---|---|
| **`HLR-89.1`** — bounded contract, unbounded ledger | `test` | 4 of the 5 named arms resolve `ok`: `V26 BUDGET-over`, `BUDGET-at`, `BUDGET-ignores-ledger`, `BUDGET-renders-const`. The fifth, **`V26 BUDGET-constant`, does not exist** | "5 arms report `ok`; the budget finding is NOTICE when over and SKIP when at or under, never BLOCK" | ⚠ **PARTIAL** | the property holds — the live gate reads `V26 01-requirements.md: the live contract is 47040 characters, inside the 54000-character budget`, severity SKIP, and the two arms that actually carry the derivation (`BUDGET-derivation`, `BUDGET-chars-not-bytes`) are `ok`. **The threshold as written cannot be discharged**: see `G-89-01` |
| **`HLR-89.2`** — a verdict under any stdout encoding | `test` | `ENC VERDICT-live`, `ENC VERDICT-domain`, `ENC UTF8-lossless`, `ENC PASS!=NOOP` — **4 of 4 `ok`** | "emits `SELFTEST PASSED` and its full arm count under cp1252, matching utf-8 exactly" | ✓ | `ENC VERDICT-live` runs a real child `--selftest` under `PYTHONIOENCODING=cp1252` and asserts the verdict LINE. The RED side was **observed before the repair** on two surfaces (`P-8`, `LED-89.8`) — that is the counterfactual and it is dated 2026-08-29 |
| **`HLR-89.3`** — the flow names an interpreter that exists | `test` | `INT FOUR-PLACES-agree`, `INT WIRING-collects`, `INT INTERP-parse`, `INT RUNS!=IS-PYTHON`, `INT PASS!=NOOP`, `INT ISFILE!=RUNS`, `INT V17-registered`, `V17 BLOCK-unrunnable` — **8 of 8 `ok`**; the whole `V17` block is 9 of 9 | "the 3 shebangs and the generated hook command name 1 distinct interpreter; `V17` BLOCKs on an interpreter that runs without starting Python" | ✓ | live gate: `[-] V17 ~/.claude/settings.json: guard wired on UserPromptSubmit (1 hook), and its interpreter starts Python`. The threshold is **agreement among the four LOCAL sites**, not a global count of zero — `flow-selftest.yml:40` keeps `python3` by ruling (`LED-89.10`) on an explicitly **unmeasured** premise |
| **`HLR-89.4`** — the environment contract, DERIVED | `analysis` | 23 `V30` arms, **23 of 23 `ok`**, incl. `V30 LIVE-derived`, `SYNTAX-fv-is-blind`, the four `ROW-*-BLOCKS` negative controls, and `E2E-fixture-disagrees` | Python executed floor **3.11**, API floor **3.7** *documentary*, git **2.28.0**, third-party imports **0**; BLOCK when declared and derived disagree | ✓ | the live gate prints all four floors as derived findings, each naming what bound it: `from __future__ import annotations` at `devflow-validate.py:41` over 15 catalogued constructs / 3 files; `git init -b` at `:6934` and 2 further sites, **all inside `--selftest`**; 13 top-level modules resolving under `python -S -E`. The API floor's own finding carries the words *"DOCUMENTARY, NEVER EXECUTED"* |
| **`HLR-89.5`** — the runtime preflight | `test` | 12 `PRE` arms, **12 of 12 `ok`** | "3 preflight lines, each naming its measured value; git absent produces a distinct sentence from git present and below the floor" | ✓ | the three lines are quoted at the head of §1 — this document's own gate run **is** the observation. `PRE ABSENCES-differ` asserts exactly-one-of-five marker phrases; `PRE E2E-git-blinded` proves it in a child process with git filtered off `PATH`, asserting `shutil.which` is `None` **first** |
| **`HLR-89.6`** — the record is checkable, and closed before superseded | `test` | `V27` **34 arms** + `V28` **15 arms** = **49 of 49 `ok`**, incl. `V27 HISTORIC-b88`, `V28 HISTORIC-rollover`, `V27 LIVE-agree`, `V28 LIVE-agree` | "**47** `V27`/`V28` arms report `ok`" | ✓ **threshold met and exceeded, and the delta reconciles exactly** | 47 was the count at rev50 when the requirement was written. Today's 49 is 47 **+ 2**: `V27 GUARD-traversal` and `V27 GUARD-currency`, both added by the mid-batch traversal-guard work and both named by `LLR-89.6.5`. **The delta is accounted for, not absorbed** |

### Low-level requirements (10)

| Req | Named arms | Threshold | Result |
|---|---|---|---|
| `LLR-89.1.1` — the budget's number lives in the code | `V26 BUDGET-renders-const` | 1 arm `ok` | ✓ |
| `LLR-89.1.2` — the current-state check has a grammar | `V26 STRIKE`, `STRIKE-wrap`, `STRIKE-not-greedy` | 3 arms `ok` | ✓ |
| `LLR-89.1.3` — the link is a PAIRING, checked both ways | `V26 PAIR-only-live`, `PAIR-only-ledger`, `PAIR-crossed`, `E2E-crossed` | 4 arms `ok` | ✓ — `PAIR-crossed` is the discriminating fixture: identical id sets both sides, only the pairs swapped, on which every membership oracle passes |
| `LLR-89.1.4` — an omitted pointer is a defect, `none` is the declared empty | `V26 UNPOINTED`, `UNOWNED` | 2 arms `ok`, each fixture yielding exactly 5 findings | ✓ |
| `LLR-89.1.5` — armed as REGISTERED, not only as a pure core | `V26 E2E-adopted`, `E2E-crossed`, `E2E-legacy-over`, `E2E-legacy-under` | 4 arms `ok` | ✓ |
| `LLR-89.6.1` — coverage is a correspondence | `V27 UNLOGGED`, `UNPACKETED`, `BOTH-WAYS`, `NOTES-DONT-COUNT`, `HISTORIC-b88` + 6 `harvest-*` | 12 arms `ok` | ✓ — `NOTES-DONT-COUNT` works **only because its fixture's two fields disagree** |
| `LLR-89.6.2` — currency measured against the work | `V27 STALE`, `CURRENCY-EQUAL`, `CURRENCY-AHEAD`, `CURRENCY-MAX-NOT-LAST`, `NOGIT`, `NOCOMMIT`, `NODATE`, `CAUSES-DISTINCT`, `E2E-git-date` | 9 arms `ok` | ✓ — `E2E-git-date` holds no calendar literal and cannot rot |
| `LLR-89.6.3` — the subject is the superseded batch | `V28 PRED-complete`, `PRED-missing-both`, `PRED-missing-04`, `PRED-missing-05`, `POSTMORTEM-COUNTS`, `FIRST`, `NO-ACTIVE`, `GHOST-ACTIVE`, `ORDER-numeric`, `HISTORIC-rollover` | 10 arms `ok` | ✓ |
| `LLR-89.6.4` — both rules armed as REGISTERED | `V27 E2E-clean`, `E2E-frozen`, `E2E-nolog`, `E2E-plan-not-a-packet`, `E2E-git-date`, `V28 E2E-pass`, `E2E-notice`, `V27 LIVE-agree`, `V28 LIVE-agree`, `V28 ORDER-agrees-today` | 10 arms `ok` | ✓ |
| `LLR-89.6.5` — a declared batch id resolves to a direct child of `.dev-flow/` | `ART A9-dot`, `A9-dotdot`, `A9-nested`, `A9-trailing-sep`, `A9-freeze-noop`, `V18 notchild`, `notchild-SENTENCE`, `CAUSES-differ`, `TRAVERSAL-notice`, `TRAVERSAL-up`, `V27 GUARD-traversal`, `GUARD-currency` | 12 arms `ok` | ✓ |

**Layer A coverage: 16 of 16 requirements carry executed verification, 0 orphans, 1 threshold
(`HLR-89.1`) not literally dischargeable.** Every arm named by every requirement was looked up in
today's run; **exactly one lookup returned `MISSING`**, and it is `G-89-01`.

---

## 3 · Layer B — behavioral (black-box) acceptance

**No `AT` id is minted in this batch, and that is a measured ruling rather than an omission.**
`R-89-7` records the executed reason: `V2` resolves an `AT` id against `<project>/tests/` **and
nothing else**, while every acceptance surface this batch produced lives in
`devflow-validate.py --selftest`, in another repository. An id in the numeric form was minted
experimentally into the record and the gate answered that it has **no node on disk**; it was then
withdrawn by **deleting the token**, because `V2` harvests its declared side without
`_strip_code`, so an id quoted inside backticks is still declared.

**What discharges Layer B instead — the through-the-registered-rule arms.** Every one of these
drives the **shipped** rule over a built fixture tree, not the pure core, which is the C-12
output-then-consume discipline expressed in this batch's terms:

| Story | Surface driven | Deliverable observed | repr · boundary · negative | Result |
|---|---|---|---|---|
| Story 1 — the split | `V26` as a REGISTERED rule over a built batch directory | the finding COUNT and severity vector, before anything else is compared | ✓ `E2E-adopted` · ✓ `E2E-legacy-over` / `E2E-legacy-under` (the DEFAULT threshold, which is what makes the constant observable) · ✓ `E2E-crossed` | pass |
| Story 2 — the verdict under any encoding | a real child `--selftest` process under `PYTHONIOENCODING=cp1252` | the verdict LINE, `SELFTEST PASSED`, and an arm count at least this run's | ✓ `VERDICT-live` · ✓ `VERDICT-domain` (5 encodings, probe **harvested from the canon**) · ✓ `PASS!=NOOP` | pass |
| Story 3 — the interpreter | `V17` driven through a real `settings.json` naming an executable that is not Python | the BLOCK and its sentence | ✓ `V17 BLOCK-unrunnable` · ✓ `INT INTERP-parse` (5 command shapes incl. a quoted path with a space) · ✓ `INT RUNS!=IS-PYTHON` | pass |
| Story 4 — the environment contract | `V30` registered, over a fixture manifest that AGREES and one that DISAGREES | the four floor sentences and the BLOCKs | ✓ `E2E-fixture-agrees` · ✓ `E2E-no-section` · ✓ `E2E-fixture-disagrees` · ✓ `E2E-live` | pass |
| Story 5 — the preflight | `run()` itself, and a child process with git filtered off `PATH` | the three printed lines | ✓ `E2E-git-present` · ✓ `THREE-LINES` · ✓ `E2E-git-blinded` | pass |
| Story 6 — the record checked against the work | `V27`/`V28` registered, over built repositories with real commits | finding counts, rendered dates read back from `git log` itself | ✓ `E2E-clean` · ✓ `E2E-git-date` (twice, incl. a log dated 2000-01-01) · ✓ `E2E-frozen` / `E2E-nolog` | pass |

**And the strongest Layer B evidence this batch has is this document's own gate run.** `V26`,
`V27`, `V28` and `V30` were all executed against **this batch's real record** in §1, not against a
fixture — and `V27` returned **two true findings about batch-89 itself**, which is the shape a
non-vacuous acceptance is supposed to have.

⚠ **The bound, stated:** `V27` cannot tell a packet from a placeholder — it matches
`increment-0*N.md` and reads nothing inside. Six well-formed packets satisfy it, and so would six
empty files. This is recorded in `increment-006.md` §5 as a known bound and is not closed here.

---

## 4 · The two `V27` findings — what they are and what this close does with them

Both were raised by a rule **this batch shipped**, against **this batch's own record**, and both
are true.

| finding | true? | disposition in this close |
|---|---|---|
| *"2 increment packet(s) are named by no `decisions_log` decision — increment(s) 4, 5"* | **yes** | **repaired.** Increments 4 and 5 were built 2026-08-31 and committed 2026-09-03 (`cf24e29`); their packets exist and were written at the gate; only the ledger entries were missing. Two `decisions_log` entries are added by this close, dated to the work |
| *"the newest `decisions_log` entry is dated 2026-08-30 while the newest commit touching the batch directory is dated 2026-09-03"* | **yes** | **repaired by the same two entries**, which are dated `2026-09-03` and therefore make the ledger current against `cf24e29` and `976476d` |

**`V29` returns the WEAK pass, and it is worth reading as a limit rather than a green light:**

```
[-] V29  .dev-flow/state.json: all 5 `decisions_log` entry(ies) are dated on or after
         `2026-08-28-batch-89` opened, but `2026-08-24-batch-88` holds no readable archived log,
         so a SAME-DAY rollover carrying a foreign log would NOT be visible here — batches 86,
         87 and 88 all opened on 2026-08-24. This is the weak pass, not the strong one.
```

batch-88 was superseded **before rev51** existed, so it has no `decisions-log.json` archive, and
per rev51's own ruling *"batches superseded BEFORE rev51 have no archive and will not get a
fabricated one."* **This close does not write one.** The consequence is that `V29`'s strong
direction stays unavailable for this batch pair, permanently, and the reader should not take the
`[-]` as more than it says.

---

## 5 · Test ledger

**Two populations, and they must not be mixed.** This batch's arms live in a different repository
from this batch's pytest suite, and the two were counted separately.

### 5a — the pytest suite (this repository)

| Key | Value | Source |
|---|---|---|
| `tests_base` | **2697** passed · 35 skipped · 3 xfailed | CI run `33175465525`, job `98862812405`, on `0f40624` — batch-88's merge, which is batch-89's base. Recorded independently in `.dev-flow/2026-08-24-batch-88/04-validation.md` (A-3) |
| **mid-batch, on `main`** | **2697** passed · 35 skipped · 3 xfailed in 3277.12s | CI run `33352981125` on `a2a2534` (PR #206 merge), **re-read today** via `gh run view --log`. `tui-ci` success, `snapshot` success (`29 passed, 3 deselected in 89.46s`). Identical population: the four merged commits added **0** pytest tests |
| `tests_deleted` | **0** | no test file removed anywhere in `git diff --name-status 0f40624..HEAD` |
| `tests_added` | see below | `tests/test_sync_evidence.py` is **new, 535 lines**, and `tests/test_id_registry.py` gained 10 lines — both in the **unmerged** tail |
| `tests_post` | see below | executed locally today |
| **CI on the unmerged tail** | **ABSENT — no run exists** | `gh run list` shows the newest `tui-ci` run at `a2a2534`, 2026-08-31T03:10:34Z. **None of `a679ee6`, `c4e6fe5`, `ed03b10`, `c118f6e`, `cf24e29`, `976476d` has ever been through CI.** They are pushed to the branch with **no PR open**, so no `pull_request` run was triggered either |

**The local run, executed for this close.** `pytest -q -m "not slow"` on
`C:/Users/jjgh8/anaconda3/envs/s19env/python.exe` (3.11.15), 2026-09-03. **pytest's own summary
line, verbatim:**

```
7 failed, 2726 passed, 3 skipped, 21 deselected, 3 xfailed in 2339.00s (0:38:58)
```

### ⚠ The two endpoints are DIFFERENT INVOCATIONS, and that has to be said before any arithmetic

**CI run `33352981125` was a `push` event**, and `.github/workflows/tui-ci.yml` routes a push to
`pytest -q` — the **full** suite, `slow` included (`:49`). This close's run is
`pytest -q -m "not slow"` (`:45`, the pull-request lane). **So `2697 passed` and `2726 passed` are
not two measurements of one population**, and a signed-balance ledger laid across them without
saying so would be arithmetic over two different sets.

**The comparable quantity is COLLECTED**, because `-m "not slow"` *deselects* rather than removes:

| | invocation | collected | how |
|---|---|---:|---|
| base — CI on `a2a2534` | `pytest -q` (push lane) | **2735** | 2697 passed + 35 skipped + 3 xfailed |
| post — this close, local | `pytest -q -m "not slow"` (PR lane) | **2760** | 7 failed + 2726 passed + 3 skipped + 3 xfailed + 21 deselected |

**Ledger: `2760 = 2735 - 0 + 25`.** And the `+25` is **not** inferred from the two endpoints — it
was measured independently and the two agree exactly:

```
pytest --collect-only -q tests/test_sync_evidence.py   ->  25 tests collected
pytest --collect-only -q tests/test_id_registry.py     ->  13 tests collected
```

`tests/test_sync_evidence.py` is **new** and contributes **all 25**. `tests/test_id_registry.py`
was modified (+10/−1) and contributes **0 new tests** — its 13 predate the batch, and the added
lines bump a scanned-corpus bound inside an existing test, exactly as `ed03b10`'s subject says.
**Two independent routes to the same 25 is what makes this figure trustworthy**; had they
disagreed, the endpoint subtraction would have been the one to distrust.

| Key | Value | Source |
|---|---|---|
| `tests_base` (collected) | **2735** | CI `33352981125`, job log final line, re-read today |
| `tests_deleted` | **0** | no test file removed in `git diff --name-status 0f40624..HEAD` |
| `tests_added` | **25** | direct collection of the new file, corroborated by the endpoint delta |
| `tests_post` (collected) | **2760** | this run's summary line |
| `tests_post` (passing) | **2726** | same line. **Not comparable to CI's 2697** — see above |
| duration | **2339.00 s (38:58)** | same line |
| skipped, base vs post | **35** vs **3** | **cause ABSENT.** Both figures are read from their runs; the 32-skip difference spans a platform change (Linux runner vs Windows) *and* an invocation change, and this close did not isolate which. Recorded as observed rather than explained |

### ⚠ 7 failures — a KNOWN OPEN ITEM, cited and not re-diagnosed

**The consolidated plan named this confound in advance** — *"the suite's failure count depends on
gitignored state… record figures and cite those items; do not re-diagnose them inside the close"* —
and two open `BACKLOG-CODE.md` entries already own it:

- **`flaky-family-preexisting`** (`P2`, amending batch-87's carry (1)) — **three runs measured at
  the 2026-09-03 pass gave 6 / 10 / 6 failures**, a union of **18** node ids of which **17 are
  non-reproducible**, and a combined population of **23** with the earlier eleven. **7 sits inside
  that measured band.**
- **`suite-gitignored-state`** (`P2`) — the pass that filed it **named the mechanism**: 16 of 700
  app constructions in the tests pass no `base_dir` and fall back to `Path.cwd()`. **The confound
  is present in this working tree** — `.s19tool/` exists at the repo root with five saved project
  directories (`HQSSS`, `p1test`, `patches`, `temp`, `test1`) plus a rotating log, none of it
  tracked by git. **A CI checkout has none of it.**

**The seven failing nodes, recorded so the population can be compared rather than described:**

| # | node | reported cause |
|---|---|---|
| 1 | `tests/test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` | `AssertionError: []` |
| 2 | `tests/test_tui_legend.py::test_at023c_issues_legend_button_opens` | `AssertionError` on legend text |
| 3 | `tests/test_tui_legend.py::test_at023d_close_dismisses_modal` | `NoMatches` — no node matches the close button |
| 4 | `tests/test_tui_patch_big.py::test_at075a_titles` | subtitle count mismatch after a 4th entry |
| 5 | `tests/test_tui_patch_editor_v2.py::test_at064b_json_popup_edit_confirm_cancel_and_geometry` | `NoMatches` — cancel button |
| 6 | `tests/test_tui_patch_editor_v2.py::test_tc329_popup_seed_and_load_text_apply_seam` | `NoMatches` — json text area |
| 7 | `tests/test_tui_variants.py::test_variant_help_modal_fits_at_both_sizes` | help body not visible at 80x24 |

**✓ THE LOAD-BEARING OBSERVATION: not one of the seven is in a file this batch touched.** The
batch's own new tests — all 25 in `tests/test_sync_evidence.py` — **passed**, and so did all 13 in
`tests/test_id_registry.py`. All seven failures are in pre-existing TUI modal and report tests, six
of the seven in the `NoMatches`/modal-geometry family the flaky carry already describes. **That is
a checkable claim, not a reassurance**: it is falsified the moment a failing node names one of
those two files.

**What this does and does not license.** It does **not** license reading the seven as regressions
from this batch — the authoritative population is CI, **green at 2697 / 35 / 3 on `a2a2534`**. It
does **not** license the opposite either: **no CI run exists for the six unmerged commits**
(`G-89-06`), so the 1,163 new source lines have been executed on exactly one machine, once, in a
tree carrying a known confound. **The merge is what turns this into evidence**, and until then the
honest statement is this paragraph rather than a number.

### 5b — the validator selftest (`~/.claude`, a different repository)

| Key | Value | Class | Source |
|---|---|---|---|
| arms at batch open (rev47) | **402** | B | `.dev-flow/2026-08-24-batch-88/04-validation.md`, Inc 7 row |
| after increment 1 (rev48) | **431** | B | `dde935c` commit message; `FLOW-VERSION.md` rev48 |
| after increments 2 + 3 (rev49) | **443** | B | `1d2e9fe` commit message; `FLOW-VERSION.md` rev49. **The split between the two increments is ABSENT** — one commit, two increments |
| after increment 6 (rev50) | **490** | B | `FLOW-VERSION.md` rev50 |
| after the rollover work (rev51) | **516** | B | `FLOW-VERSION.md` rev51 |
| rev52 — the traversal guard moves to the resolver | *not stated in the row* | **ABSENT** | `FLOW-VERSION.md` rev52 records no arm figure. Not inferred from its neighbours |
| after the parse fix (rev53) | **524** | B | `FLOW-VERSION.md` rev53 |
| after `V8`'s three defects (rev54) | **530** | B | `FLOW-VERSION.md` rev54, corroborated independently by `increment-004.md` §4's *"Arm delta, rev55: 530 → 565"* |
| after increments 4 + 5 (rev55) | **565** | **A** | **re-derived today**: `--selftest \| grep -cE '^  \S+ '` → **565**, of which **565** end in `· ok`. Verified on 3.11.15 (`s19env`, the gate env) **and** 3.12.7 (base Anaconda), both `SELFTEST PASSED`, both exit 0 |
| arms today (rev56) | **565** | **A** | rev56 is documentation-only; the validator is byte-untouched, so the count is unmoved and this is the same measurement |
| **Net movement over the batch** | **565 = 402 − 0 + 163** | **A** | 402 at open, 565 today, **+163**. No arm was deleted |
| registered rules | **23 → 28** | A/B | 23 at rev47 (B, `FLOW-VERSION.md`); **28 today** (A, `SEL EXEMPT-domain-all`: *"each of the 28 registered rules"*), and `_SELFTEST_EXEMPT` is empty — **no rule is exempt** |

### 5c — mutation testing

**Transcribed per increment, never totalled — the batteries were run at five different revisions
against five different baselines, and a sum across them would assert a single population that
never existed.**

| Increment | Named single-edit mutants | Killed | Survived | Broken | Source |
|---|---:|---:|---:|---:|---|
| 001 (`V26`, rev48) | **19** final | 19 | 0 | 0 | `dde935c` message. ⚠ **The tally does not reconcile** — `FLOW-VERSION.md` rev48 also records *12 named* + *12 review-scored*; `increment-001.md` §4 prints both and marks the reconciliation **ABSENT** rather than averaging |
| 002 + 003 (rev49) | **13** | 13 | 0 | 0 | `FLOW-VERSION.md` rev49; `LED-89.11` files them under `HLR-89.3`, so the battery **cannot be assumed evenly split** between the two increments. **Per-increment attribution: ABSENT** |
| 006 (`V27`/`V28`, rev50) | **25** | 24 | **1** | 0 | `increment-006.md` §4. The survivor `M15-zero-padding-dropped` is recorded **EQUIVALENT BY EXECUTION** — no input separates the two forms — rather than chased |
| 004 (`V30`, rev55) | **13** + sentinel | 13 | 0 | 0 | `increment-004.md` §4, scored against a GREEN baseline in a mirrored flow tree |
| 005 (`PRE`, rev55) | **14** + sentinel | 14 | 0 | 0 | `increment-005.md` §4 |

**The rev55 pair is the one row with two independent sources that agree.** `FLOW-VERSION.md`'s
rev55 row records **27 mutants applied, 27 killed, 0 survivors**, both batteries in a mirrored flow
tree; the two packets record **13** and **14** separately. **13 + 14 = 27**, so the packet split and
the revision total reconcile exactly — which is precisely what increments 2 and 3 could not do, and
the contrast is the argument for writing the packet at the gate rather than afterwards.

**Three episodes inside those batteries that this close will not smooth over**, because each is
the mutation harness catching something about *itself*:

1. **Two red baselines, in two different increments.** Increment 003 discarded a first harness run
   whose baseline was already red and **reported that it did so**; increment 006 hit the same wall
   — `INT FOUR-PLACES-agree` walks up from `__file__` and reports the layout outside a flow-shaped
   tree — and moved the battery to a mirrored tree. *A baseline that is already red cannot score
   anything, and lowering the bar would have been the vacuous check one level out.*
2. **Two sentinels SURVIVED their first battery, and both were right to.** Increment 004's
   `SENTINEL-must-be-RED` exposed an arm asserting `msg == _V30_NO_SECTION` — **the same constant
   on both sides**. Increment 005's `N7-case-probe-is-assumed` replaced the entire case-fold probe
   with `return True, None` and survived a whole 12-mutant battery, because **this machine really
   does fold case**: the verdict was armed, the mechanism was not.
3. **One mutant was rewritten because it was BROKEN, not because it survived.** Increment 006's
   `M13-nodate-silent` crashed at 454 arms with no verdict line — *which reads exactly like a
   survivor* — and was replaced rather than scored.

⚠ **There is no canonical mutation harness.** Every battery above was a throwaway, so none of
these results can be re-run or accumulated. That is already a standing `P1` in
`BACKLOG-PROCESS.md` (`no-canonical-mutation-harness`), re-measured at this batch as **0 files,
with 42 throwaway mutants across rev52, rev54 and rev55 behind it**.

---

## 6 · Gaps detected

| ID | Requirement | Gap | Severity | Proposed action |
|---|---|---|---|---|
| **`G-89-01`** | `HLR-89.1` | **Its `Executed verification` names `V26 BUDGET-constant`, an arm that has NEVER existed at any revision.** `git log -S "BUDGET-constant" -- docs/tools/devflow-validate.py` in `~/.claude` returns **nothing**; `BUDGET-derivation` appears in `8438000` (rev48), the commit that shipped `V26` itself. The threshold *"5 arms report ok"* therefore counts a phantom, and only 4 of the 5 named arms are real | **major** | Carry to `BACKLOG-PROCESS.md`. **Population enumerated before proposing any change** (`R-88-17`): **6 sites, all in `s19_app/.dev-flow/`, 0 in the flow repo** — `01-requirements.md:81` (**the only live normative site**), `01-requirements-ledger.md:65` and `:100` (**append-only, must not be edited**), `increment-001.md:66` and `:276` (historical, self-declared retroactive), `state.json:68` (`decisions_log[0].notes`, historical). **Not repaired by this close**: amending the live contract is a requirements change owing its own ledger entry, and this close is not scoped to it |
| **`G-89-02`** | record integrity | **`increment-006.md`'s closing section still says increments 4 and 5 "were approved and never built"** and explains why the packet numbering skips them. Both were built 2026-08-31 and their packets exist. The header rows of packets 001, 002, 003 and 006 likewise all read *"of 6 declared — **4 built**"*, which was true when written and is false now | **minor** | Carry. These are **historical packets that declare their own write dates**; editing them would rewrite a record to look cleaner than the history was, which is the shape `V26`'s append-only ledger exists to prevent. The correction belongs in this close and in `05-close.md`, not in the packets |
| **`G-89-03`** | none — no requirement covers it | **1,163 lines of new `s19_app` source landed in this batch under no requirement and no increment packet.** `tools/sync_evidence.py` (**628 lines, new**) and `tests/test_sync_evidence.py` (**535 lines, new**) in `c4e6fe5`, plus `tests/test_id_registry.py` (+10/−1) in `ed03b10`. They are the only `.py` changes in the whole batch (`git diff --name-status 0f40624..HEAD -- '*.py'` → exactly 3 files) | **major** | Reconciled **only** in `BACKLOG-CODE.md`, which records `c4e6fe5` as closing the recursive-SVG-copy `P3` item. That is a real reconciliation and it is not a substitute for an increment gate: no source-file cap was checked, no RED counterfactual recorded, no review ran. Carry as a named process finding |
| **`G-89-04`** | `HLR-89.6` and every other | **No independent `code-reviewer` pass, 0 of 6 increments.** All six packets say `ABSENT` in their own words | **major** | Already filed as `code-reviewer-absent`, `P1`, `BACKLOG-PROCESS.md`, opened 2026-09-03. Reaffirmed here with the batch-88 comparison in §7 |
| **`G-89-05`** | `V23` | **`01-requirements-ledger.md:258` carries a design-review citation that does not match the declared grammar** — after the design-review prefix it names a bare date where the grammar requires a batch-directory name, so it resolves to nothing. **The token is described, never reproduced (C-56)** | **minor** | Not repairable here — the ledger is append-only. A correcting entry is a requirements act; carry |
| **`G-89-06`** | — | **The six unmerged commits have never been through CI.** No `tui-ci` run exists for any of them, and the tail contains 1,163 lines of new source | **major** | **Closed by the merge itself**: opening a PR triggers `tui-ci`. Until then the only execution evidence for that source is the local run in §5a, on one machine, one OS, one interpreter |

### ⚠ An incident inside this document, recorded because it is the same class it is reporting

**The first draft of this file reproduced the malformed design-review citation verbatim, three
times, and the gate caught it.** Re-running the validator after writing — rather than assuming a
document is inert — returned **three NEW `V23` notices** at `04-validation.md:126`, `:317` and
`05-close.md:217`, taking the defect's population from **1 site to 4**.

That is **C-56** exactly: *"any artifact a scanner reads is INPUT — including the artifacts written
to PROVE something,"* and *"a mutation reverted in its target file but SPELLED verbatim in a
transcript is NOT reverted."* The rule was written after batch-86 adopted three phantom ids from an
increment packet that quoted a corrupted token. **This close reproduced it while reporting it**,
which is worth recording rather than quietly fixing: a control is not encoded until the act it
forbids feels wrong to perform, and this one did not.

**The repair took TWO passes, and the first one failing is the more useful half.** Pass 1 removed
the full citation but kept the bare prefix in prose — *"after the `<prefix>-` prefix"* — and the
next gate run **still returned three `V23` notices**, because the harvester matches the prefix
followed by a hyphen and does not care that the rest is English. **A partial repair of a scanned
token is not a repair**, and only re-running the gate a second time showed it. Pass 2 removed the
letters entirely, describing the citation as *"the design-review prefix"*, and the count returned
to **1** — the original site, in the append-only ledger, which this close does not edit.

**Swept at all four sites, not the three the gate named** — the fourth is `state.json`'s own close
entry, which today's `V23` does not scan and which was corrected on the principle rather than on
the finding. That is `R-88-17`'s discipline applied to a defect discovered during its own close.

---

## 7 · The missing review lens — measured, not asserted

This is the batch's largest evidence gap and it deserves its own section rather than a row.

| | batch-88 | batch-89 |
|---|---|---|
| increments | 7 | 6 |
| independent `code-reviewer` passes | **7** | **0** |
| of those, returning BLOCK | **6** | — |
| defects found by an independent lens | at least 1 HIGH in each of Inc 1, 2, 3, 4, 5, 7 | **1** — the adversarial mutant pass recorded in `FLOW-VERSION.md` rev48, which found the `if ledger is None:` → `if not ledger:` survivor. **It is a code review of the validator, not a `code-reviewer` pass on an increment, and `increment-001.md` explicitly declines to claim it as one** |
| defects found by the implementer's own sentinels | many | **all of them** |

**What that costs, stated concretely rather than in principle.** Every defect this batch recorded
— the bytes-vs-characters budget, the self-agreeing `NO-SECTION` arm, the assumed case-fold probe,
the whitespace-split interpreter that would have false-BLOCKed most of Windows, the arm over a
helper that `M19` survived — was caught by the author's own instrument. **That is genuinely better
than nothing, and it is not an independent lens.** The one class it structurally cannot catch is
the class where the author's *model* is wrong, which is exactly the class an independent reviewer
exists for. `G-89-01` is a small instance sitting in the record right now: a requirement citing an
arm that has never existed survived six increments, four packets, a requirements ledger and two
merges, and was found by this close's arm-by-arm re-derivation — **the first time anything
compared the requirement's named arms against the shipped ones.**

⚠ **`increment-004.md` and `increment-005.md` both mark checklist item 5 — "Vacuous arms hunted" —
as `⚠`, with the note *"caught by the battery, neither by review."*** The packets said this about
themselves before this close said it about them.

---

## 8 · Supersession-completeness inspection

| Superseded marker | grep result | All surviving refs negative? | Evidence |
|---|---|---|---|
| `BUDGET-constant` (an arm name that never shipped) | **6 hits**, all under `.dev-flow/` | **no** — `01-requirements.md:81` is a **live normative claim** | enumerated in `G-89-01`. The other 5 are append-only-ledger or self-dated historical prose |
| the `55000` budget figure (superseded by `LED-89.5` to 54,000, computed) | live in `state.json`'s `batch_objective` | **no** — it is a live field | the shipped constant is correct; the gate prints `inside the 54000-character budget`. `state.json`'s prose is stale, declared in §9 |
| `project.toml` (deleted in `1d2e9fe`) | 2 stale readers remain: `s19_app/tui/workspace.py:508`, `tests/test_changes_schema.py:523` | **yes — inert** | both are `pyproject.toml or project.toml`; the `or` branch is dead. Declared in `CLAUDE.md` by `a679ee6`, *"harmless, not broken"* |
| `python3` in the flow | 4 sites measured; 3 changed to `python`, 1 kept by ruling | **yes** | `flow-selftest.yml:40` keeps it with a comment saying why (`LED-89.10`); `FLOW-VERSION.md:202` untouched as historical prose |

---

## 9 · `state.json` — what this close found stale, beyond what it repairs

The rollover into batch-89 retired **nothing**. Measured by loading batch-88's state at its own
merge and comparing field by field:

```
git show 0f40624:.dev-flow/state.json   ->  stations_active      = ['P0','ARQ','P1','PDR','P3']
                                            iterations_per_station = {P0:0, ARQ:0, P1:1, PDR:2, P3:2}
                                            triggers.fired        = ['A','B1','B4','C','E']

.dev-flow/state.json (today)            ->  stations_active      = ['P0','ARQ','P1','PDR','P3']
                                            iterations_per_station = {P0:0, ARQ:0, P1:1, PDR:2, P3:2}
                                            triggers.fired        = ['A','B1','B4','C','E']
```

**Three fields are byte-identical to batch-88's, not one.** `R-89-9` was registered and closed for
`decisions_log` alone; these three are its unclosed remainder. What this close does with each is in
`05-close.md` §3, and the short form is: **`stations_active` is corrected from the artifacts on
disk; `iterations_per_station` and `triggers` are NOT**, because batch-89 recorded no iteration
counts and never evaluated a trigger set, and writing plausible values for either would be exactly
the fabrication this flow forbids.

Also stale and **not repaired here**, each declared rather than silently carried:
`batch_objective` still names the `55000` budget and still lists increments 2 and 3 under
*"REMAINING INCREMENTS, NOT IMPLEMENTED"*; `artifact_homes` and `triggers.record` still resolve to
`.dev-flow/2026-08-24-batch-88/`; and `batch_objective_superseded` is an invented key that no rule
or command reads — rev51's rollover table names it by name as the thing not to do.

---

## Evidence checklist — this document

| | Item | Evidence |
|---|---|---|
| ✓ | The gate was executed, not described | §1, full output, exit 0, `0 block · 290 notice · 27 not applicable`, on `s19env` 3.11.15 |
| ✓ | The instrument that read the arms was proven able to report a negative | §2 — one real arm returned `ok`, two fabricated ones returned `MISSING`, before any sweep result was believed |
| ✓ | The selftest figure was re-derived, not carried | 565 counted directly from the run on **two** interpreters; every one of the 565 ends `· ok` |
| ✓ | Every non-trivial figure carries its source and its class | §5's tables label each row A (executed today) or B (transcribed with its artefact) |
| ✓ | Figures that cannot be sourced are marked ABSENT | per-increment arm split for increments 2/3; per-increment mutant split for increments 2/3; increment 1's mutant-tally reconciliation; CI on the unmerged tail |
| ✓ | No figure attributed to a revision that did not produce it | rev56 is documentation-only and the validator is byte-untouched, stated in §1; all pre-rev55 figures are Class B |
| ✓ | The population of a correction was enumerated before proposing it | `G-89-01`: 6 sites, listed with line numbers, before any repair was proposed — and the repair was **declined** as out of scope |
| ✓ | No secrets | no token, credential or URL beyond the public repository; `V25` reads `git remote get-url` and never prints it |
| ✓ | No destructive commands, and the parallel session's lane untouched | read-only git throughout plus one pytest run; `git status --short` shows `prototypes/` and `build/` still untracked and unmodified (C-44 / C-33 lane guard) |
| ✗ | **Independent `code-reviewer` pass, any increment** | **0 of 6.** §7 |
| ✗ | **Packets written at the increment's gate** | **2 of 6** (increments 4 and 5). Increments 1, 2, 3 and 6 are reconstructions dated 2026-08-30 |
| ✗ | **CI green on the tree being validated** | **No CI run exists for the six unmerged commits**, which contain all 1,163 new source lines. `G-89-06` |
| ✗ | **`HLR-89.1`'s threshold discharged as written** | The fifth named arm has never existed. `G-89-01` |
