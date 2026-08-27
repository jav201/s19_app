# Increment 003 — `LLR-88.1` · `LLR-88.10` · `LLR-88.11` — the sentence family: two rules that pass and could-not-check in one voice

| Field | Value |
|---|---|
| Batch | `2026-08-24-batch-88` |
| Increment | `003` of 7 |
| Requirement(s) | `LLR-88.1` (V5 ledger) · `LLR-88.10` (V8 map resolver) · `LLR-88.11` (V8 root file) |
| Acceptance | `AT-B88-03`, `AT-B88-05` |
| Date | `2026-08-27` |

---

## 1 · What changed

**Three rules stopped saying the same thing about two different worlds.**

**V5 — the ledger.** The shipped rule appended a finding only on FAILURE and returned
`no ledger expression found` otherwise, so **61 of 61** validation records printed one
byte-identical sentence — including the four whose ledger parsed *and reconciled*. Measured, not
inferred: over the whole `.dev-flow/` corpus the shipped rule produced **0** blocks and **61**
copies of that sentence. The grammar now admits four families and the outcome core has **three**
distinguishable states — no document · a document with no readable ledger · a document whose
ledgers reconcile, **naming the figures**.

| Family admitted | cumulative records reached, of 61 |
|---|---|
| A — shipped, `digit = digit − digit + digit` | **4** |
| B — + a WORD left operand | **7** |
| C — + the reversed direction, `base − d + a = post` | **15** |
| D — + multi-term additive, `2714 = 2702 + 6 + 3 + 3` | **19** |

**Family E — arrow progressions — is REFUSED on merit, not on cost.** `1171 → 1180 → 1181` reaches
2 more records and carries neither a deleted nor an added term, so there is nothing to reconcile;
admitting it would report a *sequence* as a reconciled *ledger*. `ARROW-refused` is the arm that
says so. 21 of 61 is the ceiling of the whole family, which is why `≥ 34` was struck as unreachable.

**V8 — the map resolver.** The rule opened `docs/ARCHITECTURE.md` while git tracks
`docs/architecture.md`. `_resolve_ci(entries, want)` is a **pure decision core taking a listing as
DATA**, and that split is a design constraint the arms imposed rather than a preference: the
exact-match preference is observable only when one directory holds both casings, and on this
filesystem **the two casings cannot coexist — writing the second overwrites the first.** Through a
real directory the preference is unarmable. `_read_resolved` is the thin filesystem wrapper, and it
is **non-recursive on purpose**: `docs/diagrams/architecture.md` exists beside the real map.

**V8 — the root-file sentence.** `setup.py` used to be told *"the map is stale, ARQ fires"* — advice
that sends its reader to edit a file that could not have helped. **No `path/**` prefix has a
directory component to match a root file at all.** Two sentences now, plus a bare recursive
sentinel ``**`` that classifies root files **without** silencing sub-directory orphans.

---

## 2 · Files modified

| File | Kind | Change |
|---|---|---|
| `C:\Users\jjgh8\.claude\docs\tools\devflow-validate.py` | source | V5 grammar + outcome core, V8 resolver + outcome core, **54** arms |
| `C:\Users\jjgh8\.claude\skills\dev-flow\scripts\devflow-validate.py` | build output | `--sync-bundle` mirror, verified byte-identical after `tr -d '\r'` |

**SOURCE files: 1 / 4.**

---

## 3 · Test results

**Selftest:** `SELFTEST PASSED`, exit 0, **298** arm lines — **244** before, **+54** here. The V5
block reads **27**, the V8 block **29**. `LLR-88.1` demands ≥ 12 V5 arms, `LLR-88.10` ≥ 7 resolver
arms, `LLR-88.11` ≥ 6.

**Gate, live:** `3 block · 287 notice · 13 not applicable`. The three blocks are the known flow-repo
lifecycle — `V7` hash drift, by design until Inc 7's bump, and `V16` ×2. **No fourth block.**

**The rules this increment touched moved the notice count by ZERO**: it read `286` before the
increment and `286` after it, and the `+1` is `V9` counting THIS packet as a new increment file.
That is exactly why `LLR-88.11` struck the count as evidence — it cannot see the change it was
supposed to witness, and it moves for reasons unrelated to the change.

**The corpus, swept rather than sampled** (`CORPUS-reconciled`, `CORPUS-no-invented`):

| | pre | post |
|---|---|---|
| records reporting a reconciliation | **0** (4 parsed, all still printed the silence sentence) | **19** |
| records reporting an ABSENT ledger | **61** | **42** |
| records the rule invents a failure against | 0 | **0** |

The four floor records still parse — **4 of 4**, asserted **per record by name with its expected
arithmetic**, never as a count: `b09 782 = 733 − 3 + 52` · `b10 816 = 782 − 0 + 34` ·
`b11 839 = 816 − 0 + 23` · `b74 2441 = 2408 − 0 + 33`.

### The mandatory battery — 16 kills, **16 reddened, 0 survivors on the first arm set**

Every mutant was built as a single edit against a **COPY** under
`C:\Users\jjgh8\.claude\jobs\c0c0fa47\tmp\` and asserted **non-no-op at build time** — a mutation
that changed nothing is a hard error in the harness, not a silent green. Harness: `kills.py`.

| id | the edit | reddened by |
|---|---|---|
| `A1` | bind `base, post` where the code binds `post, base` | `FLOOR-b09/b10/b11/b74`, `V5 GREEN` |
| `A2` | bind `a, d` where the code binds `d, a` | `FLOOR-b09/b10/b11/b74` |
| `A4` | `!=` → `==` in the reconciliation test | `V5 RED`, `V5 GREEN`, every `FLOOR-*` |
| `A5` | drop `−` (U+2212), ASCII only | `FLOOR-b09/b11/b74` — the DISK arms; every typed fixture stayed green |
| `A6` | word CLASS → enumeration `(post\|base\|total)` | `WORD-unknown`, `ADDITIVE-word`, `CORPUS-reconciled` |
| `A7` | word-left branch appends nothing (rule returns `[]`) | `DISK-word-b87`, `WORD-unknown`, `CORPUS-reconciled` |
| `A9` | narrow the left operand to word-only | `V5 RED`, `FLOOR-b09/b11/b74` |
| `A10` | revert the widening to digit-left | `DISK-word-b87`, `WORD-unknown`, `CORPUS-reconciled` |
| `A11` | force `d = 0` after unpacking | `FLOOR-b09`, `CORPUS-no-invented` |
| `B1` | delete the exact-match preference, keep the fold | `CI-exact-lower` — **and only that one** |
| `B2` | delete the case-folding, keep exact | `CI-folds`, `CI-mixed-fold`, `READ-through-case` |
| `B5` | install the resolver inside the general reader | `RESOLVER-local` — **and only that one** |
| `B6` | make the resolver scan recursively | `READ-not-recursive`, `READ-through-case` |
| `C1` | collapse the root sentence into the staleness sentence | `ROOT-sentence` |
| `C3` | widen the root test to "not under any declared prefix" | `SUBDIR-sentence`, `SENTINEL-root-only` |
| `C5` | sentinel classifies everything, not just root files | `SENTINEL-root-only`, `E2E-sentinel` |

Two are worth naming because each was killed by exactly ONE arm:

- **`B1` was caught by `CI-exact-lower` alone, and `CI-exact-upper` survives it.** Deleting the
  exact-match preference leaves the fold loop, which walks a *sorted* listing — and
  `sorted(["architecture.md", "ARCHITECTURE.md"])` puts the uppercase first, so asking for
  `ARCHITECTURE.md` gets the right answer for the wrong reason. **Both directions had to be armed.**
- **`A5` was caught only by the DISK arms.** Every typed fixture in this file uses the ASCII hyphen;
  the corpus uses U+2212. `_v5_corpus()` locates the real `.dev-flow/` tree and four arms read real
  records off it. **Only the expected sentence is typed** — the input is never synthesised.

### 🛑 The review found a whole CLASS my battery could not reach: **it never crossed the I/O boundary**

An independent `code-reviewer` returned **BLOCK** — 3 HIGH, 5 MEDIUM, 2 LOW — with a diagnosis
sharper than any single finding: **every mutant I built attacked a pure core, and the pure cores are
exactly where my arms live.** Nothing in the battery touched the code between a core's inputs and
the disk, so that code was entirely unarmed. Its 23-mutant battery, disjoint from mine, found
**13 survivors**. All 13 now redden (`kills2.py`).

| # | Finding | The single edit that survived 282 green arms | Fix |
|---|---|---|---|
| **F1 HIGH** | **`v8_module_map` had ZERO executing arms.** The selftest's `CHECKS` loop covers only V1/V2/V4/V5/V6/V9; every V8 arm called a core directly. `return []` as the rule's first statement kept the selftest green — and so did `sentinel = False`, `sentinel = True`, `prefixes = []`, `tracked = []`, and repointing the map read at the decoy in `docs/diagrams/` | `sentinel = False` — **`LLR-88.11`'s sentinel half dead in production** while `SENTINEL-root-only`, which passes `sentinel=True` as a **literal**, stays green | 3 `E2E-*` arms drive the real rule over a temporary git index (`git init` + `git add`; `git ls-files` reads what is STAGED, so no commit and no identity config are needed), asserting `(where, msg)` pairs **by equality** — with the map written LOWERCASE and asked for in UPPERCASE, so the resolver is exercised end to end too |
| **F2 HIGH** | the "resolver stays local" arm scanned for the **NAME**, not the property | a one-line `_read` that calls the **pure core** inline case-folds every read in the file without ever spelling the wrapper's name | `RESOLVER-local` now scans **both** identifiers and asserts the production call sites are exactly `_read_resolved` then `v8_module_map` |
| **F3 HIGH** | the no-ledger sentence's **content** was unarmed — `== _V5_NO_LEDGER` is equality against the constant under test | reword the constant to `ledger reconciles: …` and the live gate announces a reconciliation for a record with **no ledger at all**: this rule's flagship defect, restored in a stronger form, with every V5 arm green | `ABSENCE-says-absent` asserts `"no ledger" in` and `"reconcil" not in` the constant, `_V5_NOFILE` against a **typed** literal, and that the third sentence **does** start `ledger reconciles:` |
| **F4 MED** | same shape on the absent-document sentence | `_V5_NOFILE = "ledger reconciles"` — distinctness survives because the reconciled sentence carries a figure suffix | folded into `ABSENCE-says-absent` |
| **F5 MED** | family C's **WORD right operand** — the requirement's own example — had no arm and no corpus record; every family-C match on disk is digit-on-the-right | replace the word alternative with a second `NUM` (group count preserved, so no crash) | `REVERSED-word` uses `zzquantum`, a token absent from the corpus |
| **F6 MED** | **no V5 arm asserted the finding's `where` field** | `"04-validation.md"` → `"-"`: the reader loses the pointer to the judged document | every V5 arm now asserts `_f5[0][:2]` |
| **F7 MED** | `LLR-88.10`'s *"pass sentence asserted by equality **at the rule level**"* was met by a **core-level** arm — the one threshold item that would have reached the region F1 shows was unarmed | — | `E2E-pass-sentence` |
| **F8 MED** | the selftest hard-depends on one machine's history: **7 FAIL, exit 1** against a foreign `.dev-flow`, with no explanation, because the hint fired only when NO corpus was found | — | `_v5_why()` distinguishes *no corpus* from *the wrong corpus* and names `DEVFLOW_CORPUS` |
| **F9 LOW** | `_V8_ROOT_MSG` could assert staleness **without using the word** — two strings, one condition | reword the tail to *"the map has fallen behind, ARQ fires"* | `SENTENCES-differ` adds the **positive** claim, `"not behind" in _V8_ROOT_MSG` |
| **F10 LOW** | `_read_resolved`'s bare-filename path was latent and unarmed | `parent or "."` → `parent`: every bare name silently returns `None` | `READ-bare-name` resolves a bare name from the cwd |
| **F11 LOW** | quadratic backtracking on long unbroken token runs (measured 3.27 s at 8 000 chars, clean O(n²)) | — | **no change** — real prose breaks the class every few characters and the 61-record sweep runs in **0.29 s**. Recorded so a later batch does not rediscover it |

**And the fix for F3 caught my own wording before the mutant did.** The first version of
`ABSENCE-says-absent` went red against the shipped sentence, which said *"NOTHING was reconciled"* —
an honest negation the predicate could not distinguish from a claim. **I changed the sentence, not
the arm**: it now reads *"NOTHING was checked here"*.

**The review's own negative findings, recorded because they are evidence too** (F12): all **923**
`.md` files under `.dev-flow/` swept through `_v5_ledgers` — **91** ledgers parsed, exactly **1**
non-reconciling, and it is *this packet* quoting the `BLOCK-additive` fixture in its own prose (V5
reads only `04-validation.md`, so no rule sees it). **0** cross-line matches across the 61 records.
The dedup guard is load-bearing — removing it reddens **5** arms. Narrowing the additive form's
`{2,}` to `{1,}` reddens `CORPUS-no-invented` with 1 invented block, so that arm does real work.

---

### 🛑🛑 A SECOND review, differently owned: **nobody had attacked the WORDING**

51 fresh mutants, **8 survivors, 4 real defects** — and its meta-finding is the sharpest yet,
because it names a shape neither of the two prior lenses touched:

> **Both earlier lenses attacked the code's BEHAVIOUR. Nobody attacked the message constants'
> WORDING — which is the one thing this increment's entire value consists of.** Every arm that
> names a sentence compares it to the SYMBOL rather than to typed text, so **routing was pinned
> and the sentences were free.**

`_V5_NOFILE` happened to be pinned by typed equality. The other three were defended only by
`in` / `not in` predicates, and **all three leaked while 288 of 288 arms stayed green**:

| Constant | The reword that passed | Why the predicate could not see it |
|---|---|---|
| `_V5_NO_LEDGER` | ends *"the accounting in this record was checked and is correct"* | `"no ledger" in` ✓ and `"reconcil" not in` ✓ — **42 of 61 records would print it**. LLR-88.1's flagship defect restored in a STRONGER form than the one I removed |
| `_V8_ROOT_MSG` | *"…and the map is not behind — update the map, which has fallen behind and must list this file"* | `"not behind" in` matches inside a sentence that then **asserts the opposite**. A substring cannot tell a claim from its negation elsewhere in the same sentence — and the operator's own amendment to `LLR-88.11` does not close this |
| `_V8_STALE_MSG` | stripped to *"the map is stale"*, remedy dropped | nothing asserted it at all |

**Fix: all four constants — plus `_V5_RECONCILED`, `_V5_DERIVED` and `_V8_NO_GIT` — are now
pinned by TYPED equality**, character for character, beside the routing arms. The substring
predicates stay: they document *why* the wording matters. Equality is what makes a reword a
**decision** instead of an accident.

| # | Finding | Fix | Verified |
|---|---|---|---|
| **F1 HIGH** | three message constants escapable (above) | 6 `WORDING-*` arms, typed | `E1`/`E2`/`E3` now RED |
| **F2 HIGH** | `RESOLVER-local` guards the **identifier**, not the property — a `_read` that reimplements the fold with `os.listdir` + `.lower()`, or with `glob`, spells neither name and passed. `LLR-88.10` calls this "the one prohibition running nothing can detect", so this arm was the sole defence and was **narrower than the prohibition** | `READER-stays-exact` pins `_read`'s **BODY**: exactly 5 non-blank lines, none containing `listdir`, `walk`, `glob` or `.lower()` | `E4`/`E5` now RED |
| **F3 MED** | V8's `git not available` branch unarmed. Replacing its return with `tracked = []` made V8 print **`N modules, no orphan files` — a pass sentence for an enumeration that never ran**, both SKIP so severity cannot see it. *The exact family this increment exists to close, in the rule I had just restructured.* Separately, git off PATH killed `--selftest` with a raw `FileNotFoundError` after **53 of 298** arms, leaving 245 unrun | absence carried as `tracked is None` (which `[]` cannot impersonate) into `_v8_outcome`; `_V8_NO_GIT` sentence; `E2E-no-git` blinds PATH and drives the real rule; `NO-GIT!=PASS`; `shutil.which` guard in `_mk8` returns a **named sentinel** so the arms fail with a reason instead of crashing | `E6` now RED |
| **F4 MED** | `_v5_ledgers` quadratic, and **my own F11 figure understated it ~4×** because I measured prose, not digit runs — the worse case. **8 000 digits = 6.60 s; 20 000 = 41.2 s, on every gate run.** This is a hex-editor project; a pasted dump is not hypothetical and V5 has no length guard | a `(?<![A-Za-z0-9_-])` lookbehind on all three patterns | **41.2 s → 0.004 s** at 20 000 digits; **exact no-op** over all 61 records and over the live gate line |
| **F5 MED** | **`ledger reconciles:` claimed a check that could not fail, for 5 of my 19.** Where the left operand is a word the rule *derives* `post`, so the predicate is arithmetically incapable of being false — yet the sentence was byte-identical in shape to the checked case. **My docstring was honest about this; the emitted sentence was not** — this increment's own headline defect, one level up | the pass sentence **splits**: `_V5_RECONCILED` vs `_V5_DERIVED`. `bad` is restricted to stated ledgers, which makes the flag load-bearing — force it false and the BLOCK arms go red | measured **14 checked + 5 derived-only** (batches 07, 20, 21, 22, 86) + the 2 mixed folded in; `CHECKED!=DERIVED` arm; `E7`/`E8` now RED |

F6 and F7 were LOW and need no action. **F7 judged the corpus binding CORRECT** — a self-skipping
arm is the vacuous check this file refuses, the failure is loud, named and self-remediating, and
`DEVFLOW_CORPUS` was verified to work from a foreign cwd.

**Combined battery: 34 scored, 34 RED, 0 survivors** (`kills.py` · `kills3.py`), deduplicated
across the three lenses. One mutant remains **declared no-op and unscored**: dropping `sorted()`
from the resolver's listing.

**What I take from three passes.** Pass 1 attacked the cores and found nothing, because the arms
were written against the cores. Pass 2 attacked the I/O and found the cores' arms proved nothing
about the rule. Pass 3 attacked the *strings* and found that everything proved so far was about
**routing**, while the sentences — the entire product of this increment — were unpinned. Each pass
was blind to the next one's axis, and no amount of mutants along one axis reveals another.

---

## 4 · Risks, and the things I could NOT arm

- **`_v5_corpus()` ties seven arms to a machine that has the corpus, and they FAIL rather than skip
  when it is absent.** That is deliberate — a self-disabling arm is the vacuous check this file
  exists to refuse — but it is a real portability cost in a validator that `--sync-bundle` ships to
  `~/.claude/skills/`. The failure now names which of the two happened and points at
  `DEVFLOW_CORPUS`, but **it is still red for any other project**, and that is a standing decision
  the operator may want to revisit.
- **The three `E2E-*` arms shell out to `git` three times each.** If `git` is absent they fail —
  honest, but a second machine dependency the selftest did not have before.
- **Dropping `sorted()` from the resolver's listing is a genuine NO-OP on this host and is NOT
  scored in either direction** — at most one entry can case-match on a filesystem where the two
  casings cannot coexist, so the tie-break it orders is unreachable. Same category as returning
  `[]` instead of `None` for an absent directory, which is likewise unscored.
- **`B6`'s mutant is a coherent four-line edit, not a single token, and I am saying so rather than
  calling it single-edit.** A one-token recursion is incoherent — the listing and the path join must
  agree — and every one-token version I built returned `None` for the wrong reason and *survived*.
- **The `[:20]` orphan cap is shared across both V8 sentences and is KNOWINGLY UNARMED.** Above
  twenty orphans, which sentence appears is decided by `git ls-files` ordering. A 21-orphan fixture
  is disproportionate; recorded so a later batch does not rediscover it as a defect.
- **The sub-directory half of `LLR-88.11` remains unobservable in any LIVE run.** The repository has
  exactly one V8 orphan and it is `setup.py`, a root file. `SUBDIR-sentence`, `SENTINEL-root-only`
  and `E2E-two-sentences` are synthetic; there is no live instance to corroborate them.
- **The `>= 19` threshold in `LLR-88.1` counts 5 unfalsifiable records as coverage**, and the
  requirement's threshold text needs the same split the sentence just got: **14 checked + 5
  derived**. Reported to the operator, who will amend it. Until then this packet reports the split
  rather than the bare 19.
- **`LLR-88.11`'s amendment landed while I worked, and it still cannot express F1's second row.**
  The operator added a mandated **POSITIVE** claim ("the map is not behind") beside the negative
  predicate, and my `SENTENCES-differ` arm asserts exactly that — **but so does the `E2` mutant**,
  which contains `"not behind"` and then asserts the opposite four words later. **Only typed
  equality closes it**, and a requirement cannot mandate typed equality without quoting the
  sentence it mandates. `WORDING-root` is that quotation, in the arm rather than in the document.
- **The widened V5 grammar reads prose.** `CORPUS-no-invented` asserts **0** blocking records across
  all 61, but it is a snapshot. A future record writing `40 = 30 + 5 + 2` in an unrelated sentence
  will BLOCK — the intended trade against a rule that reads nothing.
- **V5's live line judges `2026-05-05-batch-01`'s document, not batch-88's.** That is the artifact
  loader defect `LLR-88.5` describes and **Inc 5** fixes; this increment did not touch it, so V5's
  new sentence is currently being said about the wrong record.

---

## 5 · Pending

- **One requirement amendment owed, not made here:** `LLR-88.1`'s threshold should read
  **14 checked + 5 derived**, not a bare 19. (`LLR-88.11`'s was made by the operator mid-increment;
  I did not touch `01-requirements.md` — its modification in `git status` is theirs.)
- **Inc 5 must land before V5's live line means anything about the active batch.**
- `V7` stays red until Inc 7's bump, by design. `V16` ×2 — the flow repos carry local commits never
  pushed, plus this increment's uncommitted edit. **Nothing was committed by this increment.**
- The derived Atlas was regenerated with `--atlas --write` AFTER this packet existed.

---

## 6 · Suggested next task

**Inc 4** — the scope family: `LLR-88.2` (V2 acceptance ids become token membership) and `LLR-88.3`
(V6's modal check becomes statement-scoped, **and gains a pass sentence**). Two carry-overs from
here: **arm the rule, not only its core** — F1 is a pattern, not an accident, and V2/V6 have the
same shape — and the plan's own warning that V6's hole is real with **0** instances fallen through
it (930 statements, 207 wrap, 5 carry a modal, V6 caught all 5), so the packet must not imply a live
escape was found.

---

## Increment gate checklist

| # | Item | ✓ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 1 authored + 1 build output |
| 2 | Tests in the same increment | ✓ | 54 arms, 244 → 298 |
| 4 | RED counterfactual | ✓ | **34 scored, 34 reddened, 0 survivors** across three batteries (16 mandatory · 13 from review 1 · 8 from review 2, deduplicated); each asserted non-no-op at build time; 1 declared no-op excluded |
| 5 | Reverse census | ✓ | `RESOLVER-local` proves the core is called only by its wrapper and the wrapper only by `v8_module_map`; V5's old single regex had no other consumer |
| 6 | `code-reviewer` — a HIGH blocks | ✓ | **TWO independent reviews, both BLOCK.** R1: 3 HIGH + 5 MED + 2 LOW, 13 survivors. R2: 51 fresh mutants, 8 survivors, 4 real defects. All findings taken; all 21 demonstrated survivors re-verified RED |
| 9 | Coverage verified on disk | ✓ | 61-record sweep executed: 19 reconcile, 42 absent, 0 invented; 923-file prose sweep in the review |
| 10 | Load-bearing emptiness | ✓ | `SENTINEL-root-only` and `E2E-sentinel` assert an ABSENCE (`setup.py` not reported) **in the same run** as the positive (`tools/rogue.py` still reported) |
| 11 | Mutation verdicts per arm | ✓ | §3 tables name, per mutant, which arms reddened |

**An item without a citation is not satisfied — it is asserted.**
