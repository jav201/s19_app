# QA validation-methods plan — batch-88 Phase 1 (qa-reviewer deliverable, 2026-08-24)

> ## ⚠ SWEPT 2026-08-26 — this file was authored BEFORE the scope cut and BEFORE the
> ## station-4 design review, and nothing had touched it since.
>
> **The analysis stands. Its SCOPE and its FIGURES do not.** Found by an adversarial review of
> the batch's progress, which observed that every prior lens — a security review, a condition
> audit, a code review, a mutation catalog — took `01-requirements.md` as the world. This is
> the batch's **third** live Phase-1 artifact and no lane covered it.
>
> **What expired, and where it is corrected in place below:**
>
> 1. **Stories A and B left the batch** (operator ruling 2026-08-25, `state.json`). This file
>    still plans arms for `V24` in **8** places and devotes the whole of **§4** to Story B's
>    review-debt ledger. Both are batch-89 work now. §4 carries its own banner.
> 2. **The census baseline moved twice.** This file carries `276` ×4, `280` ×4 and `544` ×3,
>    and **zero** occurrences of the live figures. Re-derived 2026-08-25: shipped **302 of
>    570**, patched **306 of 570**. The **+4 delta survives** every re-measurement; the
>    baseline survives none, because every batch declares ids of its own.
> 3. **§7.5's "decision owed before Inc 5" was taken and shipped.** Banner at §7.5.
>
> **⚠ The requirement that forbids a stale declared baseline cannot see this file.**
> `LLR-88.8`'s threshold reads *"0 occurrences of `276 of 544` or `280 of 544` as a declared
> baseline"* — but its quantified population is *"the baseline figures of **those two
> documents**"*, meaning `state.json` and `PLAN.md`. A rule scoped by naming its documents
> cannot notice a third one. That is the finding, not the typo: **the scope cut swept the two
> artifacts the ruling named and left the third**, which is the same shape that left
> `LLR-88.4` demanding `8 of 8` over a seven-member population.

> Returned by the Phase-1 `qa-reviewer` dispatch, run **in parallel** with the architect authoring
> `01-requirements.md`. Nothing here is an edit to that file. Every finding below is offered as a
> **HYPOTHESIS to be confirmed by execution at the fold**, never as a correction applied to another
> agent's work.
>
> **Every figure in this file came out of a command run this session.** Where a command contradicted
> the dispatch brief, the command governs and the contradiction is stated in the open (§6.1). Where a
> mutation I wrote turned out to be a no-op, I say so and retract the finding it produced (§2.5).
> Thresholds for Phase 3+ are marked `DERIVE-AT-AUTHORING` and name the probe that prints them;
> **no figure in §0 or §5 is to be copied into the record — re-execute and paste the transcript.**

**C-56 hygiene, applied to this file.** This file lives under `.dev-flow/**/*.md`, so the Atlas id
scanner reads it and any requirement-shaped token in it becomes a registered id. The selftest
fixtures discussed in §2 contain synthetic canon ids; they are written here as **`ID-064` /
`ID-064a`** rather than with their real prefix, and the malformed design-review tokens in the V23
arms are **described rather than pasted**, because pasting a non-conforming token would mint a V23
NOTICE against this document. Substitutions are flagged at each site.

**Notation.** `W` = `C:\Users\jjgh8\Github\s19_app`, branch `claude/batch-88-audit-closures` ·
`PY` = `C:\Users\jjgh8\anaconda3\envs\s19env\python.exe` (used **directly**, never through
`conda run`, and never without `PYTHONIOENCODING=utf-8` — see §6.1) · `ORIG` = the shipped validator,
LF-normalised · `PATCHED` = the 29-arm proposal · `MUT/<n>` = a single-edit mutant of `PATCHED`, each
guarded by an `assert s != src` so a mutation that changes nothing is a hard error rather than a
silent green.

Method label for every criterion below is **inspection (operator-local executed verification)**.
The validator lives outside the repository, so a `test (integration)` label naming a pytest node
that cannot exist would be C-18. The one exception is §5, the suite gate, which is a real pytest run
owned by the orchestrator.

---

## 0 · Pre-state, measured on `W` this session (re-derive; do not cite)

| Probe | Command | Value as measured |
|---|---|---|
| branch tip | `git rev-parse HEAD` | `d1405242eb6cac84d69c2060d1f72c310aa6f566` |
| RC-1 | `git merge-base HEAD origin/main` vs `git rev-parse origin/main` | both `4131a384254e8f764bd3ba7e1d7302322178a97c` — **still identical, RC-1 holds at Phase 1** |
| gate line, ORIG | `PYTHONIOENCODING=utf-8 PY ORIG W` | **`14 block · 284 notice · 14 not applicable`**, exit **1** |
| the 14 blocks, by rule | `grep '^  \[x\]' \| grep -oE 'V[0-9]+' \| sort \| uniq -c` | **all 14 are `V4`** — see §1.4 |
| gate line, PATCHED | `PYTHONIOENCODING=utf-8 PY PATCHED W` | **`0 block · 284 notice · 16 not applicable`**, exit **0** |
| V22 census, ORIG | same run, `grep 'living canon'` | **`276 of 544`** |
| V22 census, PATCHED | same run | ~~**`280 of 544`**~~ — **superseded, see the banner at the head of this file: 306 of 570 measured 2026-08-25**. Original reading preserved: — the scheduling conflict in PLAN §"⚠ A scheduling conflict" is **confirmed by execution**, not predicted |
| V7 | same run | `flow current (9c1449ed815d267c)` — matches the manifest hash PLAN §1 records |
| selftest, ORIG | `PY ORIG --selftest` | **192 arms**, `SELFTEST PASSED`, exit 0 |
| selftest, PATCHED | `PY PATCHED --selftest` | **221 arms**, `SELFTEST PASSED`, exit 0 |
| new arm labels | `diff` of the two arm-label streams | **exactly 29**, all named in §2.1 |
| suite size | `PY -m pytest -q -m "not slow" --collect-only` | **2714 of 2735 collected, 21 deselected**, in 0.88 s |
| ordering plugins | `PY -m pip list \| grep -i pytest` | `pytest 8.4.2` · `pytest-textual-snapshot 1.1.0` · `syrupy 4.8.0` — **no `pytest-randomly`**, collection order deterministic |
| A-1 precondition | `git diff --stat $(git merge-base HEAD origin/main) -- s19_app/ tests/ tools/ pyproject.toml` | **empty, exit 0** — holds today, and **this batch plans to break it**, see §5.2 |
| close-template copies | `sha256sum` on both | identical, prefix `3e8f07ab9d63fb55` — PLAN §3's B2 probe reproduces |
| marker vocabulary in the flow | `grep -rniE "reviewed-by\|authored-by\|sign-?off"` over `~/.claude` `.md`/`.py` | **0 hits in any template or in the validator** — the human-review marker is genuinely new, §4 |

---

## 1 · The governing lesson, re-measured rather than accepted

### 1.1 · V5's two sentences are byte-identical — verified, not quoted

Executed against batch-87's **real** `04-validation.md`, the record whose own close asserts a
reconciling ledger, and against a file containing only a one-line heading:

| Input to `v5_ledger` | Output |
|---|---|
| `.dev-flow/2026-08-24-batch-87/04-validation.md` | `('SKIP', 'no ledger expression found')` |
| a file containing only `# nada` | `('SKIP', 'no ledger expression found')` |
| structural equality of the two finding lists | **`True`** |

The brief's central claim survives independent execution. It is the premise of everything below.

### 1.2 · V5's arms, enumerated — and there is no `PASS != NOOP` among them

`grep -E '^  V5 '` over the 192-arm baseline returns exactly two arms: `V5 RED` and `V5 GREEN`.
By contrast V23 already carries `V23 PASS!=NOOP-msg`. **V5 is the rule with a reachable no-op branch
and no arm that can see it**, exactly as the brief states.

### 1.3 · The `_artifacts` patch does NOT close V5 — measured

This matters because the 29 arms contain no V5 arm at all, and it would be easy to assume the
loader fix covers it. It does not:

| `v5_ledger` input | Patched output |
|---|---|
| artifact absent (`{}`) | `('SKIP', 'no 04-validation.md')` |
| a present document with no parseable ledger | `('SKIP', 'no ledger expression found')` |

The loader fix separates **absent** from **present**. It leaves **present-and-unparseable**
indistinguishable from **present-and-checked**, which is the defect. *(Stated because the
improvement is easy to over-read, not because the brief claims otherwise.)*

### 1.4 · A measured refinement to PLAN §12

PLAN §12 attributes the 14 station-P0 blocks to `V1`–`V9`. Measured: **all 14 are `V4`.** The
mechanism PLAN describes is correct and its mutation table reproduces; the *attribution* is looser
than the evidence. Under the patch V2, V4, V5 and V6 all move to an ABSENT sentence, which is why
`not applicable` rises 14 → 16 while `notice` is unchanged at 284.

### 1.5 · The batch's own signature defect, reproduced by the batch's own patch

PLAN records eight instances of one shape: *a rule whose behaviour does not match what its
description promises*. `PATCHED`'s `_artifacts` docstring still reads **"the declared batch's copies
WIN"** — preference semantics — while the new body implements **exclusion**: when `state.json`
declares a batch, no other batch's file is loaded at all. Different rules. The docstring describes
the old one. **No arm in the 29 asserts docstring/behaviour agreement, and none can** (§7.1).

---

## 2 · Arm-by-arm audit of the 29 proposed arms

### 2.1 · Verdict summary

| Verdict | Count | Arms |
|---|---|---|
| **ACCEPT** | **19** | `ROOT-not-stale` · `ROOT-reads-apart` · `SUBDIR-still-stale` · `ROOT-sentinel` · `CASE-resolves` · `CASE-absent` · `FOREIGN-not-judged` · `OWN-still-judged` · `ABSENT!=FOREIGN` · `FALLBACK-survives` · `SCOPE-stated` · `GR-decision` · `GR-ddr` · `GR-alnum-batch` · `GR-record` · `GR-filename` · `GR-version` · `GR-version-dec` · `GR-bare-hash` |
| **STRENGTHEN** | **5** | `CASE-nodir` · `GR-nodate` · `GR-placeholder` · `GR-path` · `FILENAME-not-notice` |
| **REJECT** | **5** | `CASE-adopted` · `CASE-exact-wins` · `SUBSTRING-not-refl` · `EXACT-reflected` · `PLAIN-missing` |

### 2.2 · The executed kill-mutation matrix

Every row is a mutant built from `PATCHED` by a single textual edit, asserted non-no-op at build
time, then run through `--selftest` with the env python directly.

| Mutant | The edit | Selftest | Arms it reddened |
|---|---|---|---|
| `m1_read_ci` | `_read_ci` body reduced to `return _read(path)` — **the kill mutation the D2 comment names** | **PASSED** | **none** |
| `m2_v8_msg` | V8's ternary collapsed to the single old sentence | FAILED | `ROOT-not-stale`, `ROOT-reads-apart` |
| `m3_artifacts` | `_artifacts` first-wins prefill restored | FAILED | `FOREIGN-not-judged`, `ABSENT!=FOREIGN` |
| `m4_v22_substr` | `rid not in canon_ids` reverted to `rid not in canon` — **the kill mutation the D1b comment names** | **PASSED** | **none** |
| `m5_v22_msg` | V22 notice reverted to the old sentence | FAILED | `SCOPE-stated` |
| `m6_v23_grammar` | `_V23_OK` reverted to the pre-batch regex | FAILED | `GR-record`, `GR-filename`, `GR-version`, `GR-version-dec`, `FILENAME-not-notice` |
| `m7b_no_dollar` | trailing `$` dropped from `_V23_OK` | FAILED | `GR-bare-hash` |
| `m7d_combined` | leading `^` dropped **and** the rule switched to `.search` | **PASSED** | **none** — while the rule now calls a filesystem path conforming (§2.5) |
| `m8_root_decl` | the root-declared orphan filter deleted | FAILED | `ROOT-sentinel` |
| `m9_resolve_all` | `_resolve_ci` reduced to `return name` | FAILED | `CASE-resolves`, `CASE-absent` |
| `m10_v8_pass` | V8's PASS sentence replaced by the SKIP no-op wording | **PASSED** | **none** (§7.2) |
| `m11_subdir_msg` | the sub-directory orphan sentence replaced | FAILED | `SUBDIR-still-stale` |
| `m12_nodir` | `_resolve_ci`'s `OSError` branch returns `[]` instead of `None` | **PASSED** | **none** |
| `m13_exact` | `_resolve_ci` stops preferring the exact name | **PASSED** | **none** |

### 2.3 · REJECT — `CASE-adopted` and `CASE-exact-wins` (V8, D2)

**`CASE-adopted` cannot fail on the only machine that runs it.** It asserts
`_read_ci(".../docs/ARCHITECTURE.md") is not None` over a fixture containing
`docs/architecture.md`. Measured on this host:

```
os.path.exists(<tmp>/docs/ARCHITECTURE.md)       ->  True
plain _read(<tmp>/docs/ARCHITECTURE.md) is None  ->  False
```

Windows resolves the casing itself, so **the plain `_read` already satisfies the assertion**. The
arm's own comment names the kill mutation "revert `_read_ci` to `_read`"; `m1_read_ci` is exactly
that mutation and **the selftest stayed green**. It also survived `m9_resolve_all`. This is the
brief's shape precisely: an arm that passes on both sides of the change it exists to guard — and it
is the arm that would carry Story A's declared precondition.

**`CASE-exact-wins` is unfalsifiable for the same structural reason.** It asserts that a *directory
containing exactly one file* resolves to that file. `m13_exact` deletes the exact-name preference
entirely and the arm stays green, because a case-folded scan over a one-entry directory returns the
same answer. The fixture that could distinguish them — a directory holding **both** casings — is
**not creatable on this filesystem**, which is the whole reason the defect exists.

**Rewrite owed (design input, not an edit).** Both must move off the filesystem, because the
filesystem is the confound. `_resolve_ci`'s decision core takes a *directory listing*; give it one
as data and the arm asserts the same thing on every platform:

- `CASE-adopted-linux` — drive the decision core with the literal entry list `["architecture.md"]`
  and the wanted name in upper case; assert it returns `architecture.md`. **Reddening mutation
  (C-40):** delete the case-folded loop — goes red on Windows and on Linux alike.
- `CASE-exact-wins-both` — drive it with `["architecture.md", "ARCHITECTURE.md"]`; assert the exact
  name wins. **Reddening mutation:** `m13_exact`. Impossible as a temp directory here; trivial as a
  list.
- `CASE-rule-level` — additionally drive **`v8_module_map`** itself (not the helper) over a fixture
  whose map file differs in case, and assert the **PASS sentence** `"<n> modules, no orphan files"`,
  never `is not None`. **Reddening mutation:** `m1_read_ci` — which must then go red.

Until `CASE-rule-level` exists, **Story A's precondition is asserted by no arm that can fail.**

### 2.4 · REJECT — `SUBSTRING-not-refl`, `EXACT-reflected`, `PLAIN-missing` (V22, D1b)

These three are **tautological**: they compute the oracle in the test and then assert against it.

```python
_tok22 = set(_ATLAS_ID_REQ.findall(_canon22))   # the test recomputes the rule's expression
good  = (rid not in _tok22) is want_missing      # ... and asserts against its own recomputation
```

The rule — `v22`'s `if rid not in canon_ids:` — is **never called**. `m4_v22_substr` reverts the
oracle to substring membership and **the selftest stays green**, while the same run's real output
moves the census from 280 back to 276. Measured, with the synthetic ids written as `ID-064` /
`ID-064a` per the C-56 note:

```
_ATLAS_ID_REQ.pattern                     = \b(?:US|HLR|LLR)-[\w.]+(?:-[\w.]+)*\b
findall over the fixture                  = ['ID-1', 'ID-064a']   # both substituted   (substituted)
substring truth ('ID-064' in canon text)  = True    <- what the rule USED to do
token truth     ('ID-064' in the set)     = False   <- what the rule does NOW
```

Note the arms do prove the *pattern* behaves as claimed, and that is worth something — but the
patch's subject is the **rule's oracle**, and no arm touches it.

**Rewrite owed.** One arm replaces all three: call the V22 census producer over a two-batch fixture
whose canon contains only the `a`-suffixed variant, and assert the emitted **census figure** and
**the sample id in the message**. **Reddening mutation (C-40):** `m4_v22_substr` — the figure must
move. The existing three may stay as pattern-level regression controls, relabelled so no reader
mistakes them for oracle coverage.

### 2.5 · STRENGTHEN — the V23 group is in the wrong probe regime

**A retraction first.** I built a mutant switching `_v23_outcome` from `.match` to `.search` and
recorded it as a kill-coverage failure. **That mutation is semantically a no-op**: `_V23_OK` is
already `^…$`-anchored, so `.search` and `.match` are equivalent. The finding it produced is
withdrawn. The correct mutation is the *combination* — drop `^` **and** switch to `.search` — and
that one is decisive:

```
m7d_combined:  SELFTEST PASSED   (all 12 V23 arms green)
m7d _v23_outcome([("<a filesystem path ending in a record filename>", "r.md:1")])
   -> [('SKIP', '1 design-review citation(s), every one conforming to the grammar')]
```

**The rule declares a filesystem path "conforming to the grammar" and every arm stays green.**
Cause: **11 of the 12 arms call `bool(_V23_OK.match(tok))` directly.** They test the compiled
pattern, not the rule. The one arm that drives `_v23_outcome` — `FILENAME-not-notice` — asserts a
**positive**, so a rule that has stopped rejecting anything cannot move it.

Concretely: `GR-nodate`, `GR-placeholder` and `GR-path` are the set's only negative controls, and
**none of them is in the same regime as its target** — the probe-regime rule is violated for exactly
the arms whose job is to prove the rule still says no.

`FILENAME-not-notice` additionally asserts only the **severity set** `== {SKIP}` and never the
sentence, which is the V5 shape in miniature; it survives here only because the pre-existing
`V23 PASS!=NOOP-msg` arm backstops it.

**Rewrite owed.** Add **`GR-rule-negatives`**: drive `_v23_outcome` with the three malformed shapes
(described, not pasted: a path-prefixed record filename; an angle-bracket placeholder batch segment;
a date-less record) and assert **`NOTICE` for each, one row per token**. Change
`FILENAME-not-notice` to assert the **pass sentence** `"<n> design-review citation(s), every one
conforming to the grammar"`, so it is distinguishable from the no-citations no-op sentence.
**Reddening mutation (C-40):** `m7d_combined` — `GR-rule-negatives` must go red where all 12 present
arms do not.

### 2.6 · STRENGTHEN — `CASE-nodir` conflates two states

`m12_nodir` makes the `OSError` branch return `[]` instead of `None` and the arm stays green,
because an empty listing produces `None` by the same route. The arm therefore cannot tell
**"the directory does not exist"** from **"the directory exists and is empty"** — the same
absent-versus-empty conflation the batch is fixing in `_artifacts`. **Strengthening:** assert the
two cases produce distinguishable results, or drive the rule and assert the SKIP sentence
`"no docs/ARCHITECTURE.md (map not adopted here)"`. **Reddening mutation:** `m12_nodir`.

### 2.7 · Two false-accepts the new V23 grammar admits, and one is pre-existing

Measured against `PATCHED._V23_OK` (tokens paraphrased per the C-56 note):

| Shape | Parses? | Status |
|---|---|---|
| record + `-v2` | **True** | intended — this is what the old grammar could not express |
| record + `-DRAFT` | **True** | **new**: the batch segment now admits *any* hyphenated suffix. `GR-version` proves hyphens are admitted; it does **not** prove a version is expressible *as a version*. |
| record + three chained pseudo-versions | **True** | **new**, same cause |
| a record dated month 13 day 99 | **True** | **pre-existing** — `\d{4}-\d{2}-\d{2}` never validated a date, and this batch does not widen it. Recorded so nobody attributes it to `PDR-2026-08-24-batch-88#D4`. |

**Owed as a design question, not a defect claim:** does the flow *want* `-<anything>` in the batch
segment, or specifically `-v<n>`? The arm set has **no negative control asserting a non-version
suffix is rejected**, so whichever answer is chosen, the grammar currently cannot be shown to hold
it. This is a Phase-1 question for the architect, offered as a hypothesis.

### 2.8 · A determinism note on `FALLBACK-survives` (accepted, with a caveat)

The patch adds `sorted(fns)` to the walk. That orders **filenames within a directory**; it does not
order **directories**, so the no-`state.json` fallback's first-wins is still `os.walk` order across
batch directories. `FALLBACK-survives` uses a **single**-directory fixture and therefore cannot see
this. The arm is sound for what it asserts; the residual non-determinism should be named in the
record rather than left for a future batch to rediscover.

---

## 3 · The mandatory arm set for every rule this batch adds or patches

**This section is the acceptance layer for Story A, Story C and the patched rules. It is a
constraint on the implementation, not a description of it.** Criterion #1 as widened in PLAN
§"Standing on this batch" applies to **every row**.

Each row owes **all four** columns. A row missing any one is not shippable.

| Target | (a) `PASS != NOOP` arm — the two sentences asserted **different as strings** | (b) GREEN arm asserts the **pass sentence** | (c) RED arm executed against **unpatched** code and shown to FAIL there | (d) named reddening mutation (C-40) |
|---|---|---|---|---|
| **V24** (Layer C, new) | pass sentence vs the sentence for *map present, no `Frozen?` column* vs the sentence for *no map at all* — **three** distinct strings, asserted pairwise unequal | assert the literal pass sentence, never `sev != BLOCK` | the rule does not exist unpatched; the RED arm must instead fail against an **always-SKIP stub V24** — that stub is the "unpatched code" for a new rule | delete the `Frozen?`-column detection and return SKIP unconditionally |
| **V24** anchor | an arm asserting the rule keys on the **`Frozen?` column header**, never a section number (ARQ's amended condition 2) | assert V24 finds the table when it sits at §11 **and** at §4 | drive it over a map whose interface table is at a *different* section number | change the anchor to a literal `§4` match — the §11 fixture must go red |
| **V24** case-resolution | an arm driving **V24 over a fixture whose map file differs in case** | assert the pass sentence, not `is not None` | `m1_read_ci` | revert V24's map read to `_read` — see §2.3; without this V24 inherits the unfalsifiable arm |
| **V25** (RC-2, new) | RC-2 *recorded with evidence* vs *row present but empty* vs *row absent* — three strings | assert the pass sentence | fail against an always-SKIP stub V25 | delete the evidence-presence test |
| **V22** (oracle) | covered for the message by `SCOPE-stated`; **owed** for the oracle | assert the emitted **census figure**, per §2.4 | `m4_v22_substr` must turn it red | reverting `canon_ids` to `canon` |
| **V23** (grammar) | `V23 PASS!=NOOP-msg` exists and holds | change `FILENAME-not-notice` to assert the pass sentence (§2.5) | `m7d_combined` must turn `GR-rule-negatives` red | dropping `^` and switching the rule to `.search` |
| **V5** (ledger) | **the batch's headline arm.** Assert three distinct strings: *ledger parsed and reconciles* · *ledger parsed and does NOT reconcile* · *no ledger expression found*. Feed the first the project's real `post = … − … + …` form and require its output **not** to be the third string | assert the reconciling **pass sentence with its arithmetic**, never `sev != BLOCK` | today `v5_ledger` returns the no-op sentence for batch-87's real file (§1.1) — that transcript **is** the failing-on-unpatched evidence, already captured | narrow the ledger regex back to digits-on-both-sides; the real-file arm must go red |
| **V2** (substring oracle) | *no AT ids declared* vs *every AT id resolves* vs *artifact absent* — three strings | assert the pass sentence | an arm where a two-digit AT id is on disk and the one-digit id is not; must be RED before the tokenizer swap | reverting to substring membership against the concatenated string |
| **V6** (same-line modal) | **structurally blocked — see §7.3.** V6 returns `[]` when it passes | *unsatisfiable until V6 emits a pass sentence* | an arm with the marker and the modal on **different physical lines**; RED after the fix, GREEN before | requiring marker and modal on one line again |
| **V8** (root / case) | `ROOT-reads-apart` covers the two NOTICE sentences | **owed**: no arm asserts V8's pass sentence — `m10_v8_pass` replaces it with the no-op wording and the selftest stays green | `m2_v8_msg`, `m8_root_decl`, `m11_subdir_msg` all execute and redden | as listed in §2.2 |
| **`_artifacts`** | **owed**: assert the ABSENT sentence `"no 01-requirements.md"` differs from every rule's PASS sentence, for V2, V4, V5 and V6 together. Measured today, all four differ — an arm must **hold** that, because nothing does | assert each rule's pass sentence over a good fixture | `m3_artifacts` reddens `FOREIGN-not-judged` and `ABSENT!=FOREIGN` — executed | restoring the first-wins prefill |
| **`_artifacts`** docstring | **owed and unmechanisable — see §7.1.** Route to the human-review marker instead | — | — | — |

**A note on (c) for new rules.** "Execute the RED arm against unpatched code" is not literally
available for V24 and V25, which do not exist before this batch. The equivalent that preserves the
brief's intent is the **always-SKIP stub**: build the rule's arms, replace the rule body with
`return [F("V24", SKIP, "-", "<the no-op sentence>")]`, run the selftest, and require the arms to go
red. An arm set that passes against the stub is a rule that ships inert. **This substitution is
declared here rather than discovered at the gate.**

---

## 4 · The human-review marker — a REVIEW-DEBT LEDGER

> **⚠ VOID FOR BATCH-88 — Story B moved to batch-89 by operator ruling 2026-08-25.**
> Kept in full and unedited, because the design is sound and batch-89's own PDR allocates the
> rule number this section could not mint. **Nothing in §4 is an obligation of this batch**, and
> the mandatory arm set in §3 is to be read without it. The prior design record's condition 2
> travelled with the story and is re-owed at batch-89's PDR.

### 4.1 · What it is, stated so the rule cannot drift from it

Each batch proceeds **autonomously** and **accrues review debt**. The marker **discharges** debt. It
is not a permission gate and it is not a quality certificate. It records four things and one
optional thing:

| Field | Required | Example value |
|---|---|---|
| `reviewed-by` | yes | `Javier Granados` |
| `reviewer-id` | **reserved, optional** — a stable operator handle for a future multi-reviewer world; absent is legal and MUST be distinguishable from present-and-empty | *(absent)* |
| `date` | yes | an ISO `YYYY-MM-DD` |
| `phase` | yes | the phase at which review happened — `P1`, `P2`, `P3`, `P4`, `P5` |
| `authored-by` | yes | the agent or operator that authored the work being reviewed |

`authored-by` sits **beside** `reviewed-by` precisely so a one-sided sign-off is visible: if the two
resolve to the same identity, the record shows self-review, and the rule says so rather than
blocking. **Self-review is a legal, recorded state — not a failure.** A rule that blocked it would
make the honest declaration more expensive than the dishonest one.

**Placement — measured, offered as a hypothesis.** `_artifacts` under the patch keys **any** `.md`
in the active batch directory by basename, and the active batch's copy is the only one loaded.
Verified on a two-batch fixture: with a `00-review-ledger.md` in both the active and a stale batch
directory, `_artifacts` returned `{'00-review-ledger.md': <the active batch's content>}`. A
dedicated basename therefore works, and — unlike `05-close.md` — is readable at **any** phase, which
the `phase` field requires. **The decision belongs to the architect; the measurement is offered so
the choice is informed.**

### 4.2 · The split — and the hard part is the right-hand column

| **CHECKABLE** (the rule may assert this) | **NOT VERIFIABLE** (the rule must NOT claim this) |
|---|---|
| the marker block is **present** in the active batch's artifact set | that a review **actually happened** |
| each required field is **present** | that the reviewer **read** anything |
| each required field is **non-placeholder** — not empty, not `<…>`, not `TBD`/`TODO`/`N/A` | that the review was **competent**, **thorough**, or **independent in fact** |
| `date` **parses** as an ISO calendar date | that the date is the date review *actually* occurred |
| `phase` is a member of the **declared phase set** | that review at that phase was the *right* phase |
| `reviewed-by` parses as a **non-empty name-shaped string** | that the named person is a real person, or consented |
| `authored-by` is **present** | that authorship is truthfully attributed |
| `reviewed-by` and `authored-by` are **both present**, and whether they are **equal** | that a differing pair means the review was **independent** |
| `reviewer-id` **absent** vs **present-and-empty** are reported as different states | anything about review **quality** |

**The rule's own sentence must state its limit.** The pass sentence is owed a clause naming what it
did not check — the same discipline that made V22's `SCOPE-stated` arm necessary. Proposed shape,
for the architect to adopt or replace:

> `review debt DISCHARGED at <phase> by <name> on <date>; authored-by <author>. PRESENCE and FORM
> only — this rule does not and cannot verify that the review was performed, competent, or
> independent.`

### 4.3 · Arms — including the negative arms that prove the rule does not over-claim

**Positive and no-op separation (mandatory):**

- `MARK-PASS!=NOOP` — the discharged sentence and the **undischarged** sentence asserted
  **different as strings**. *Reddening mutation:* return the same string from both branches.
- `MARK-PASS!=ABSENT` — the discharged sentence and the **artifact-absent** sentence asserted
  different as strings. This is the `_artifacts` lesson applied at birth: *no marker file* and
  *marker file with no marker* are different states.
- `MARK-GREEN-sentence` — the GREEN arm asserts the **literal discharged sentence including the
  name, date and phase it parsed**, never `sev != BLOCK`. *Reddening mutation:* drop the field
  interpolation from the message.

**Field-level:**

- `MARK-placeholder-rejected` — a marker whose `reviewed-by` is an angle-bracket placeholder is
  **not** discharged, and the sentence says *placeholder*, not *absent*. *Reddening mutation:*
  delete the placeholder test; the arm must go red.
- `MARK-date-unparseable` — a marker whose `date` is `soon` is not discharged. *Reddening
  mutation:* accept any non-empty string as a date.
- `MARK-phase-unknown` — a `phase` outside the declared set is not discharged. *Reddening
  mutation:* accept any string.
- `MARK-one-sided-visible` — `reviewed-by` present and `authored-by` **absent** produces a sentence
  that **names the missing side**. *Reddening mutation:* stop reading `authored-by`.
- `MARK-self-review-recorded` — `reviewed-by == authored-by` **discharges** the debt **and** the
  sentence says *self-review*. Two assertions, both required: a rule that blocked here would be
  wrong, and a rule that stayed silent here would be useless.
- `MARK-id-absent!=empty` — `reviewer-id` omitted and `reviewer-id:` present-but-empty produce
  **different sentences**. *Reddening mutation:* coalesce missing to empty string. This is the flow's
  own standing principle (*"`consumers : none` is legal and MUST be written; an omitted field is a
  question nobody asked"*) applied to the new field.

**Negative arms that prove the rule does NOT over-claim — the ones that make the split real:**

- `MARK-no-quality-claim` — assert the discharged sentence **contains the limiting clause** and
  **does not contain** any of the words `verified`, `approved`, `correct`, `sound`, `adequate`,
  `independent` used of the review itself. *Reddening mutation:* rewrite the sentence to say
  *"review verified"* — the arm must go red. **This is the arm that stops the vacuous shape from
  being reintroduced by a future wording change**, and it is why the sentence is asserted as a
  string rather than by severity.
- `MARK-content-blind` — feed the rule two markers **identical in every field** but attached to
  batches with wildly different work, and assert the rule returns the **same** verdict. This arm
  asserts the rule's **blindness on purpose**: it documents that the rule is a ledger entry and not
  an assessment, and it fails loudly if someone later makes the rule peek at content it cannot
  judge. *Reddening mutation:* make the verdict depend on anything outside the marker block.
- `MARK-absent-is-not-a-failure-of-review` — assert the **undischarged** sentence does **not** claim
  that review was skipped or refused; it claims only that debt is **outstanding**. *Reddening
  mutation:* change the sentence to *"review was not performed"* — a claim the rule cannot support,
  and the arm must go red.

### 4.4 · How undischarged debt renders — and the difference is itself an arm

| State | Severity | Sentence shape |
|---|---|---|
| discharged | SKIP | `review debt DISCHARGED at <phase> by <name> on <date>; authored-by <author>. PRESENCE and FORM only — …` |
| **undischarged** — no marker anywhere in the active batch | **NOTICE** (loud), never SKIP | `review debt OUTSTANDING for this batch — <n> phase(s) closed with no discharge. This batch has proceeded autonomously and NOTHING has recorded a human reading it.` |
| marker present, a required field placeholder or unparseable | **NOTICE** | names **which field** and says *placeholder*, distinct from *absent* |
| marker present, one side missing | **NOTICE** | names the missing side |
| self-review | SKIP + the self-review clause | discharged, and visibly one-sided |

**`MARK-LOUDER` is the arm.** Assert (i) the undischarged sentence and the discharged sentence are
different strings, (ii) the undischarged **severity is strictly louder** than the discharged one,
and (iii) the undischarged sentence is **strictly longer** and contains the word `OUTSTANDING`.
*Reddening mutation:* make the undischarged branch return SKIP with the discharged wording — i.e.
reproduce V5 — and the arm must go red. **This arm is the whole point of the marker: it is the arm
that V5 never had.**

**Deliberately NOT a BLOCK.** Debt accrual is the normal operating state of this project — 61
batches of it. A rule that blocked on undischarged debt would gate every batch on the operator's
calendar, and the predictable outcome is a placeholder marker written to clear the gate, which is
strictly worse than a loud honest NOTICE. Recorded here as a decision with its reason, so a future
batch that wants to raise it has something to argue with.

---

## 5 · Pre-registered flaky-node disposition for the P4 gate

**Registered BEFORE the gate run, per the brief. Batch-86 pre-registered a node whitelist and
batch-87 refuted it by measurement — overlap between the pre-registered set and the observed set was
exactly one node, and the `n = 1` "passes isolated" diagnosis was recorded as vacuous (C-53). No
whitelist appears below and none may be introduced at the gate.**

### 5.1 · The criterion — disposition by CLASS MEMBERSHIP

Adopted unchanged from batch-87's P4 amendment, restated so this batch's gate is governed by a rule
it wrote down in advance. A FAILED node is dispositioned **pre-existing** only when **all three**
hold, **each with its own transcript**:

- **A-1 (structural).** `git diff --stat $(git merge-base HEAD origin/main) -- s19_app/ tests/ tools/ pyproject.toml` is **empty, exit 0**. Without this, nothing below applies.
- **A-2 (repeated isolation).** The node is re-run **N ≥ 10** times in isolation on the same tree and the same interpreter, and its isolated failure **RATE is recorded as a figure** — `4 of 10`, `0 of 10` — **never as the word "passes"**. An `n = 1` isolated run is not evidence and may not be cited as any.
- **A-3 (family).** The failure signature is a member of the recorded family: the **modal push / mount race** — a `NoMatches` on a modal-screen widget id raised at query time, where the *same node fails on a different selector on different runs*.

Sub-classes, tracked separately: **order-dependent** (isolated rate `0 of 10`) and **timing race**
(isolated rate non-zero — the worse class, carried separately).

**Still a BLOCKER, so the rule keeps teeth:** a FAILED node satisfying A-1 but **failing A-3**, or
any node whose A-1 is false. **Zero failures is also a result** — state which nodes did not recur,
by id.

### 5.2 · 🛑 A-1 is TRUE today and this batch plans to make it FALSE

Measured this session: the A-1 diff is **empty, exit 0**. But `pyproject.toml` is **inside A-1's
declared scope**, and PLAN §3 (trigger family C) and §7 (Lane 1) both put `pyproject.toml` in this
batch's file set — `PDR-2026-08-24-batch-88#D6` adds a dependency to it. **From Inc 4 onward, A-1 is
false by this batch's own design, and with it every disposition that depends on it.**

Stated in advance rather than discovered at the gate, with the disposition that governs after Inc 4:

- **A-1 does not become optional.** It is replaced by **A-1′ (scoped structural)**: the diff over
  `s19_app/ tests/ tools/` alone must be **empty, exit 0**, **and** the `pyproject.toml` diff must be
  shown to be **dependency-declaration lines only** — no packaging, no `[tool.pytest]`, no marker or
  path configuration. The second half is what makes the first half meaningful, because a
  `pyproject.toml` change *can* redden the suite.
- If the `pyproject.toml` diff touches anything pytest reads, **A-1′ fails and no node is
  dispositioned pre-existing at this gate.** Every failure is a blocker until the diff is narrowed.
- The A-1′ transcript is owed **twice**: once before the gate run and once after, since Inc 4 may
  land between them.

### 5.3 · What measurement would REFUTE this disposition — declared in advance

The criterion is falsifiable, and here is how, so the gate cannot quietly rescue it:

1. **A-3's family is refuted** if a node satisfying A-1′ and showing a non-zero isolated rate has a
   signature **outside** the modal push/mount family — e.g. an assertion-value mismatch, a snapshot
   diff, or a `NoMatches` on a **non-modal** widget id. Then the family is either wrong or
   under-specified, and it must be **re-derived from this gate's transcripts**, not widened to
   absorb the counterexample.
2. **A-2's threshold is refuted** if a node's isolated failure rate at N = 10 differs materially
   from its rate at N = 30 — i.e. N = 10 is itself too small a sample. **Trigger:** any node landing
   in the band `1 of 10` through `3 of 10`, where the binomial spread is wide enough that the figure
   does not separate "rare race" from "never". Such a node is re-sampled at **N = 30** before
   disposition.
3. **The class approach as a whole is refuted** if the set of nodes satisfying A-1′ and A-2 and A-3
   turns out to be **as unstable across gate runs as the whitelist was** — concretely, if fewer than
   half the nodes dispositioned pre-existing at this gate were dispositioned pre-existing at
   batch-87's. Then class membership is doing no better than a list, and the correct response is to
   record that and stop dispositioning by class, not to adjust the class until it fits.
4. **A-1′ is refuted** if a gate run with an empty `s19_app/ tests/ tools/` diff nonetheless shows a
   failure **traceable to the `pyproject.toml` dependency change** — which would prove the scoped
   split does not isolate what it claims to.

**In every case the refuting measurement is recorded BESIDE this section, never over it** — the
batch-87 pattern. A criterion rewritten to match its result is worth nothing.

---

## 6 · The gate procedure

### 6.1 · ⚠ The brief's environment fact is incomplete — measured, and the command governs

The brief says: *use the env python directly, because `conda run` destroyed a gate run's evidence
via a cp1252 `UnicodeEncodeError`*. **That is necessary and not sufficient.** Measured this session
with `conda run` nowhere in the picture:

```
PY -c "import sys;print(sys.stdout.encoding)"           -> cp1252
PY -c "import sys;print(sys.stdout.encoding)"  > file    -> cp1252
PY -c "print('check \u2713')"                            -> exit 1, UnicodeEncodeError
PYTHONIOENCODING=utf-8 PY -c "print('check \u2713')"     -> exit 0, "check ✓"
```

**The env python's stdout is `cp1252` whether piped, redirected, or attached to the console.** I hit
the identical crash while probing V5 with the env python invoked directly. `conda run` widens the
blast radius; it is not the cause.

**Two distinct harms, both real:**

1. **Destruction.** A character outside cp1252 — `✓`, `≥`, `🛑`, all of which this batch's artifacts
   contain — raises `UnicodeEncodeError` mid-run and the evidence is gone.
2. **Silent mangling.** A character *inside* cp1252 survives the encode but is rendered as `?` in
   the captured transcript. The `ORIG` gate run without the guard printed
   `14 block ? 284 notice ? 14 not applicable` where the separator is `·`. Exit code as expected, no
   error, a corrupted record. **This is the quieter failure and the one that would reach the
   archive.**

**The validator does not guard its own stdout** — `grep -n "reconfigure\|PYTHONIOENCODING"` over the
validator returns **0 hits**; the three `errors="replace"` sites are all on file *reads*.

**Therefore `PYTHONIOENCODING=utf-8` is mandatory on every validator and pytest invocation in this
batch, not optional.** batch-87's P4 amendment already carries it in the prescribed suite command;
this section states *why* it is load-bearing rather than decorative, and extends it from the suite to
the validator.

### 6.2 · Invocation

```
# validator, at any station
PYTHONIOENCODING=utf-8 /c/Users/jjgh8/anaconda3/envs/s19env/python.exe \
    ~/.claude/docs/tools/devflow-validate.py "$W" > 04-gate-<station>.txt 2>&1

# the suite, at P4, owned by the orchestrator
PYTHONIOENCODING=utf-8 /c/Users/jjgh8/anaconda3/envs/s19env/python.exe \
    -m pytest -q -m "not slow" > 04-suite.txt 2>&1
```

**Rules, each with its cost already paid once:**

- **Never `conda run -n s19env`** for any invocation on this corpus. It buffers the child's stdout
  and re-prints it through a `cp1252` writer; measured at batch-87's P4 gate, it left 8 KB of crash
  diagnostics where a 40-minute suite result should have been, **with no test summary at all**.
- **Never pipe a gate run through `tail`** (C-19 — evidence destroyed once). **Redirect the whole
  run to a file**, then read the file. This applies to `head`, `grep` and `less` in the same
  position: the run's output is the evidence and it is written down before it is filtered.
- **Strip ANSI before grepping `^FAILED`.** The suite emits colour and the escape sequences survive
  redirection.
- **Read the exit code separately.** The validator exits **1** when blocks exist and **0** when they
  do not — measured today, `14 block` → exit 1, `0 block` → exit 0. Exit code alone is not the gate
  line; capture both.
- **One complete run, owned by the orchestrator (C-25).** This phase does **not** run `pytest`; a
  qa-authored figure would be a second run and a second truth. The `--collect-only` figure in §0
  (2714 of 2735, 21 deselected) is a **denominator**, not a result.

### 6.3 · The gate line's accounting obligation

The station gate line must be recorded with its **attribution split**, not as a bare figure: how
many blocks are attributable to **this batch's content**, and how many to a **known flow defect**
with the discriminating mutation named. PLAN §12 does this for the 14 F-7 residue blocks; the same
accounting is owed at every subsequent station, and the figure must **fall to its true value** the
moment Phase 1 authors `01-requirements.md` — measured today as **14 → 0** under the patch. **If it
does not fall, that is a real finding rather than this one.**

---

## 7 · What cannot be validated as specified — stated rather than papered over

### 7.1 · Description-versus-behaviour agreement is not mechanisable

This batch found **eight** instances of one shape, and PLAN calls it the batch's signature: *a rule
whose behaviour does not match what its description promises*. `_RULE_COVERS` is checked **both
ways** against `CHECKS` — `COVERS-complete` and `COVERS-no-ghosts` are set differences, so adding V24
or V25 without a description goes red. **But those arms check that a description EXISTS. Nothing
checks that it is TRUE**, and nothing can: it is a natural-language claim about a program's
behaviour.

Consequence, stated plainly: **V24's and V25's descriptions cannot be mechanically validated, and
neither can `_artifacts`' corrected docstring (§1.5).** This is the single largest thing in this
batch that has no arm and can have none. **It is precisely what the human-review marker exists to
carry** — the marker cannot verify review quality (§4.2), but a discharged marker is the only record
this project can produce that a human read a description beside its behaviour. The two sections are
a matched pair: §7.1 names the gap, §4 records who looked at it.

### 7.2 · V8 has no pass-sentence arm and this patch does not add one

`m10_v8_pass` replaces V8's PASS sentence with the SKIP no-op wording and the selftest stays green.
Nine of the 29 arms are V8 arms and none of them asserts the pass sentence. Owed as row "V8 (b)" in
§3.

### 7.3 · V6's GREEN arm is structurally unsatisfiable as the brief specifies

Measured: `v6_modal_in_statement` over a clean requirement document returns **`[]`** — an empty
finding list, no line at all. **A rule that emits nothing when it passes has no pass sentence to
assert**, so the mandate *"the GREEN arm must assert the PASS SENTENCE"* cannot be met for V6
without first giving V6 a pass sentence.

Two exits, and the choice belongs to the increment: give V6 a SKIP pass sentence in the shape the
other rules use (consistent, one line, adds one `not applicable`), or declare V6 **exempt from the
GREEN-sentence mandate in the record**, with this measurement as the reason. **What is not
acceptable is asserting `sev != BLOCK` and calling it a GREEN arm** — that is exactly the V5 shape
the mandate exists to forbid.

### 7.4 · Two arms cannot be made falsifiable on this filesystem

`CASE-adopted` and `CASE-exact-wins` (§2.3) cannot be armed against a temp directory on Windows,
because the confound *is* the filesystem. The rewrite in §2.3 moves them onto a directory listing
passed as data, which is falsifiable everywhere. **Until that lands, any claim that V24 or V8
resolves the map on a case-sensitive host is `predicted, not observed on the failing platform`** —
the exact phrasing PLAN's fifth-finding correction adopted, and it applies again here.

### 7.5 · The V22 scheduling conflict is confirmed, and it is a Phase-1 blocker

> **⚠ DISCHARGED 2026-08-26. The section was right, and both of its exits were taken.**
> The operator ruled the V22 oracle fix **lands first**, and Story E moved to batch-89 — so the
> number can no longer move under the story whose oracle it is. **Increment 1 shipped the fix**
> and the re-baseline is recorded in `state.json` and `PLAN.md`.
>
> **Its figures are superseded twice over.** The move is **302 → 306 of 570** measured
> 2026-08-25, not 276 → 280 of 544; the **+4 delta is unchanged** and the four ids are named
> (`HLR-053`, `HLR-056`, `US-064`, `US-068`). And the sentence below directing a re-baseline
> **to 280** is exactly what `LLR-88.8` now forbids as a declared baseline — preserved here
> because it was correct when written and because striking it silently would hide that this
> file sat outside the requirement's declared population.

Measured: the token fix moves the census **276 → 280** on the real repo. `state.json`'s
`batch_objective` declares Story E's baseline as **276 of 544** and its oracle as *"the census delta
pasted from the validator per tranche"*. **Landing the oracle fix mid-story silently invalidates the
story's declared baseline.** The two exits are the operator's, unchanged from PLAN: land the fix
**before** Story E produces any tranche evidence and re-baseline the objective to 280, or defer the
fix past this batch. **Do not let the number move under a story whose oracle is that number.** This
is now confirmed by execution rather than predicted, which promotes it from a risk to a decision
owed before Inc 5.

---

## 8 · Evidence checklist (qa-reviewer, Phase 1)

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then | **✗ — deliberate substitution** | The consumer of this plan is a selftest arm set, not a manual operator. The Given/When/Then equivalent is §3's four-column contract, whose columns (c) and (d) are strictly stronger: they demand an **executed failure** on unpatched code and a **named** reddening mutation. Declared, not omitted silently. |
| 2 | Test cases have explicit Expected, not vague "works" | ✓ | Every row of §2.2 states the mutant, the selftest verdict, and the exact arms reddened. §3 states the asserted **string** per row. |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | empty → `MARK-id-absent!=empty`, `CASE-nodir` (§2.6); boundary → §2.7's suffix and date table; invalid → `MARK-date-unparseable`, `MARK-phase-unknown`; error → §6.1's `UnicodeEncodeError`, reproduced. |
| 4 | Regression checklist exists | ✓ | §2.2's mutants `m2`/`m3`/`m6`/`m11` are executed regression kills; §2.8 names the residual the `FALLBACK-survives` fixture cannot see. |
| 5 | Exit criteria stated | ✓ | §3: a row missing any of the four columns is not shippable. §5.1: A-1 and A-2 and A-3, all three with transcripts. §5.2: A-1′ after Inc 4. |
| 6 | No real PII / secrets | ✓ | The only name is the operator's own, `Javier Granados`, as the marker's declared `reviewed-by` value. No credentials, no tokens, no paths outside this machine's already-recorded roots. |
| 7 | Test results section left **blank** unless actually run | ✓ | §0 and §2.2 are results I **executed** and they carry their commands. §3, §4 and §5 are **pre-registered and unfilled** — no verdict is asserted for a run that has not happened. |
| 8 | **Layer B (black-box):** deliverables observed through the SHIPPED surface | ✓ | Every §0 figure comes from running the shipped validator over the real repository, and §2.2 from its real `--selftest` entry point. No arm audited here was judged by reading it alone: **fourteen mutants were built and executed.** |
| 9 | **Bidirectional surface-reachability** | ✓ **and this is the audit's core finding** | Measured in both directions and it **fails for 14 of the 29 arms**: the V22 trio and 11 of the 12 V23 arms never reach the handler — they assert against an expression the test itself recomputes (§2.4) or against the compiled pattern rather than the rule (§2.5). The marker rule in §4 is specified handler-first for exactly this reason. |
| 10 | **No unfilled template** | ✓ | No stray placeholder, no `TC-NNN`, no empty required row. The `DERIVE-AT-AUTHORING` markers are deliberate deferrals that **name their probe**, per C-39. |
| 11 | Kill mutation executed for every arm claimed as covered | **partial, and quantified** | 19 of 29 arms have a **demonstrated** kill. 5 are STRENGTHEN with the missing mutation named. 5 are REJECT: 3 survive the kill their own comment names (`m4`), 2 survive theirs (`m1`, `m13`). **Every one of the 14 mutants was asserted non-no-op at build time**, so a mutation that changed nothing was a hard error rather than a silent green — the C-40 discipline applied to the audit itself, and it caught my own bad mutation (§2.5). |
| 12 | Findings offered as hypotheses, not edits | ✓ | This file is the only file written. `01-requirements.md` was not read, not opened, and not modified. |
