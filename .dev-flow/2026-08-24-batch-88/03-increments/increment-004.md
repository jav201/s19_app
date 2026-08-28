# Increment 004 — `LLR-88.2` · `LLR-88.3` — the scope family: two rules that read a line where they mean a set

> **⚠ C-56 SUBSTITUTION IN THIS PACKET, and it is here because the first version needed it.** Acceptance ids are written with the prefix `ID-`. The real prefix appears only inside the arms, which the Atlas does not read. The first version of this packet spelled them, and **that re-declared three of them into `_atlas_id_scan`'s `batches` realm** — the census went to **1484** where the corpus is **1481**, and one of the three was a stale-`.pyc` id, so the census this commit regenerates carried *an id present for a reason that is not a test node*: the exact defect `LLR-88.2` exists to close, reinstated by the fix's own paperwork.
>
> **The lesson is the shape, not the slip.** De-minting from one rule's population is not removal — it is RELOCATION, and the destination is inside another rule's population unless someone checks. `01-requirements.md` was swept and the record was not. **Fourth distinct C-56 instance in this batch.**

| Field | Value |
|---|---|
| Batch | `2026-08-24-batch-88` |
| Increment | `004` of 7 |
| Requirement(s) | `LLR-88.2` (V2 acceptance-id resolution) · `LLR-88.3` (V6 modal scope **and its new pass sentence**) |
| Acceptance | `AT-B88-07` (the arm floor, per rule) — the pass-sentence family of `AT-B88-03`, applied to V6 |
| Date | `2026-08-27` |

---

## 1 · What changed

**Two rules stopped asking a question narrower than the one they meant, and one of them stopped
saying nothing when it passed.**

**V2 — acceptance-id resolution.** The rule concatenated every file under `tests/` into one blob
and asked whether the declared id was a **substring** of it. That answered a question nobody asked:
the shortest id in any family could never fail, because a longer sibling contained it. It now
resolves against the **set of tokens** `_ATLAS_ID_ATTC` harvests — the truncation-guarded tokenizer
that already lived in this file — and the corpus **excludes `__pycache__`.**

| the corpus, measured on this repository | distinct ids |
|---|---|
| every file under `tests/`, as the shipped rule read it | **989** |
| the same walk with `__pycache__` excluded | **980** |

The 9-id difference is not tidiness. Those ids resolved **only** because a stale `.pyc` still
carried a string literal from source that no longer exists, and `.pyc` files are gitignored — so a
fresh clone answered differently. An id resolving for a reason that is **not a test node** is the
entire defect class this rule exists to close, and it stood at nine live instances inside the rule
meant to catch it.

**The declared side is deliberately unchanged**, and that is a decision rather than an omission.
`LLR-88.2` states one side of a comparison and is silent on the other; using `_ATLAS_ID_ATTC` on
**both** sides reads like a simplification and would make this repository's letter-initial ids
harvestable, start judging `TC-` ids, and violate the requirement's own acceptance criterion. The
`LIVE-line` arm is what turns that silence into a guard.

**V6 — the modal.** The rule required the statement marker and the modal on the **same physical
line**. A statement that wrapped carried its modal on a line the rule never looked at. Measured
pre-state: same line → **1 BLOCK**; the identical words one line break later → **no finding, no
line at all**; success → **also no finding, no line at all**. The rule now evaluates the whole
**statement block** — the marker's line plus its indented continuation lines, terminated by the
next requirement heading or the next unindented list item — and **emits a pass sentence naming the
number of blocks it scanned**, at `SKIP`, distinct from its could-not-check sentence.

| the live corpus, 65 `01-requirements.md` documents | |
|---|---|
| `**Statement`-shaped markers | **954** |
| markers inside a requirement scope — the population V6 judges | **944** |
| of those, blocks spanning more than one physical line | **223** (23.6 %) |
| BLOCKs, shipped rule → this rule | **0 → 0** |

**A quarter of the population was outside the rule's reach, and the widening invents nothing.**
Both halves of that sentence are load-bearing: `LLR-88.3`'s own acceptance says the negative arm is
the important one, and a rule that started calling correct requirements wrong would be a worse
trade than the miss it removed.

**⚠ This packet does not claim a live escape was found.** The increment plan warned against exactly
that, and the sweep above is the measurement that refuses it: **0 statements have fallen through
the hole in 65 documents.** The hole is real, it is a quarter of the population wide, and nothing
has walked through it yet.

---

## 2 · Files modified

| File | Kind | Change |
|---|---|---|
| `C:\Users\jjgh8\.claude\docs\tools\devflow-validate.py` | source | `_v2_tokens` + V2 call-site and sentence constants; `_v6_blocks` + `_v6_outcome` pure cores + V6 pass sentence; `_v2_live_root` / `_v2_why`; **37** arms. `_tree_text` **deleted** — V2 was its only consumer |
| `C:\Users\jjgh8\.claude\skills\dev-flow\scripts\devflow-validate.py` | build output | `--sync-bundle` mirror; `V15` reports *bundle identical* |

| **SOURCE files** | **`1`** / 4 — the bundle is a declared build output, not an authored file |
|---|---|

**Nothing was committed.** `prototypes/`, `build/` and every untracked file were left alone.

---

## 3 · Test results

**Selftest:** `SELFTEST PASSED`, exit 0, **344** arm lines — **298** before, **+46** here (V2 **22**,
V6 **24**). `LLR-88.2` demands ≥ 4 V2 arms plus three named `⚠` arms; `LLR-88.3` demands ≥ 6 V6 arms
plus four named `⚠` arms.

| arm set | arms | scored mutants | survivors |
|---|---|---|---|
| written from the mandatory kill table | 328 | 16 | **0** |
| + the independent battery's ten gaps | 335 | 37 | **0** |
| **+ the third review's population axes** | **344** | **50** | **0** |

**Gate, live:** **`3 block · 287 notice · 14 not applicable`**, exit 1 — unchanged in blocks from
the baseline `3 block · 287 notice · 13 not applicable`; V2 keeps its `[-]` and V6 adds one, which
is the whole of the `13 → 14` move. The three blocks are the flow-repo lifecycle: `V7` hash drift
until Inc 7's bump, and `V16` ×2 for this increment's uncommitted edit.

> ~~`5 block · 287 notice · 13 not applicable`, exit 1 … V2 traded its `[-]` for two `[x]`~~ —
> **superseded, kept beside the correction rather than overwritten.** That reading was true for the
> hours between this fix and the upstream `C-56` de-minting, and the section below explains why it
> existed at all. It is the figure the two-BLOCK narrative in *"The two new blocks"* rests on.

**That the counts stayed still is not evidence the change landed** — the arm block is.

### 🛑 The two new blocks, and why the brief expected one — ***SUPERSEDED, see the C-56 section at the foot of this packet***

```
  [x] V2   tests/: ID-043 has no node on disk
  [x] V2   tests/: ID-250c has no node on disk
  [-] V6   01-requirements.md: 24 statement block(s) scanned, no modal inside any statement
```

**`P-7` is REFUTED — and by this batch's own document.** `P-7` recorded that V2 has no live
instance here and prints `no AT ids declared`, because the project's acceptance ids are
letter-initial. That was true when it was measured. It stopped being true when `LLR-88.2`'s two
`⚠` bullets were written, because they spell **digit-initial ids in prose** and the declared-side
pattern cannot tell a citation from a declaration. The live line **before** this increment was
already not the one `P-7` recorded:

| | line |
|---|---|
| `P-7`, as recorded | `[-] V2 01-requirements.md: no AT ids declared` |
| measured at this station, **before** the fix | `[-] V2 tests/: 2 AT ids, all resolved` |
| measured **after** the fix | the two `[x]` lines above |

**Both blocks are the rule working, and each is a different one of the two defect classes the fix
was written for:**

- **`ID-043`** — declared as a truncation of `ID-043.2` in the `⚠` prose. Substring said **TRUE**;
  the only nodes on disk are `ID-043a`, `ID-043b`, `ID-043c`. This is the prefix-shadow defect,
  live, in the document that describes it.
- **`ID-250c`** — resolves under the shipped rule and under a token walk that includes
  `__pycache__`, and **only** from a stale `.pyc`. It is one of the nine ids the requirement
  enumerates. Exclude bytecode and it is gone.

**This needs an operator ruling, and it is not mine to make.** Either the `⚠` bullets stop minting
declarations (the `C-56` hygiene failure `PDR-2026-08-25-batch-88#D2` already recorded once this
batch, in `V23`), or `tests/` gains the two nodes. **I changed neither the requirements document nor
`tests/`.**

### The mandatory battery — 16 kills, **0 survivors on the first arm set**

Every mutant is a single coherent edit against a **COPY** under
`C:\Users\jjgh8\.claude\jobs\c0c0fa47\tmp\`, asserted non-no-op at build time. For each one the
harness records all four things a crash can fake: **it imported · its arm count · its exit code ·
which NAMED arm printed FAIL.** A kill with no named arm is scored as a crash. Harness: `kills4.py`.

| id | the edit | reddened by |
|---|---|---|
| `MV2-07` | declared side swapped to `_ATLAS_ID_ATTC` | **`LIVE-line`**, `DOTTED-on-disk` |
| `MV2-02` | substring fallback reinstated (2 parts: the helper and the clause) | `PREFIX-shadow`, `PYCACHE-excluded`, `DOTTED-on-disk` — **it lost `LIVE-line` when the de-minting emptied the live declaration; three synthetic arms still hold it** |
| `MV2-03` | tokenizer → `\b(?:AT\|TC)-\S+`, truncation guard lost | `PUNCTUATED-ids`, `EXACT-present`, `NESTED-corpus`, `PYCACHE-excluded` |
| `MV2-04` | corpus restricted to `.py` | **`NON-PY-corpus`** — and only that one |
| `MV2-05` | walk made non-recursive (guarded against an absent `tests/`) | `NESTED-corpus`, `NON-PY-corpus` |
| `MV2-08` | token side strips the fraction, `t.split(".")[0]` | **`DOTTED-on-disk`** — and only that one |
| `MV6-02` | heading terminator dropped | **`NEXT-HEADING`** — and only that one |
| `MV6-03` | unindented-item terminator dropped | **`RATIONALE-sibling`** — and only that one |
| `MV6-09` | the block's END line reported instead of its start | `WRAPPED-modal`, `SUB-BULLETS`, `TWO-MODALS`, `H4-SCOPE`, `BLANK-LINE-SPAN`, `DEEP-BLOCK` — **it was killed by one arm before the third review added multi-line fixtures** |
| `MV6-12` | `if not blocks: return []` | `NO-MARKER`, `EMPTY-DOCUMENT` |
| `MV6-13` | blocks anchored on requirement HEADINGS, so the count reports headings | `COUNT-blocks`, `SAME-LINE`, `WRAPPED-modal`, `NEXT-HEADING`, `PASS!=NOOP`, + 2 shipped |
| `MV6-S1` | pass sentence reworded to assert the OPPOSITE | `WORDING-pass` + every fixture asserting the rendered pass line |
| `MV6-S2` | mandated phrase kept, then negated four words later | `WORDING-pass` + the same set |
| `MV6-S4` | both sentences wrong, differing by a trailing period | `WORDING-pass`, `WORDING-nofile`, `NO-DOCUMENT` |
| `MV6-S6` | pass sentence emitted at `NOTICE` | **`PASS-severity`** + the generic `V6 GREEN` filter |
| `MV6-S7` | `where` degraded to `-` | **`PASS-severity`** + every rendered-line arm |

**Six of the sixteen are still killed by exactly one arm** (nine were, before the third review's
fixtures widened four of them): the battery has almost no redundancy, so removing one arm removes
one guard.

**And zero survivors here proves less than it looks.** These sixteen mutants are the ones the
requirement named, and my arms were written from that list. A battery that scores the arms it
generated is a tautology — which is why there is a second one.

### 🛑 The independent battery: **21 mutants nobody named, 10 SURVIVORS on the first arm set**

Written against the *code* rather than against the list (`kills4b.py`). All ten were real gaps.

| id | the single edit that survived 328 green arms | why every arm missed it |
|---|---|---|
| **`Y2`** | **the Spanish modal deleted** — `\bshould\b\|\bdeber[íi]a\b` → `\bshould\b` | **the highest-value survivor.** The rule is *named* `should/debería` and every arm exercised the English half. The live document carries **24** occurrences of `debería` — all outside a statement, so the live run cannot arm it either. **Half the rule was free to delete.** |
| `Y4` | `re.I` dropped from the modal | no fixture capitalised a modal |
| `Y5` | `re.I` dropped from the marker | no fixture lowercased `**Statement` |
| `Y6` | word boundaries dropped — `shoulder` becomes a modal | no fixture contained the modal as a substring of an innocent word, which is every fixture written on purpose. This is the false-FAIL direction the rule's neighbour warns is *"as expensive as passing a wrong one"* |
| `Y1` | any level-2..4 heading opens a requirement scope | every fixture's headings were requirement headings |
| `Y8` | the requirement scope never closes | same blind spot, reached by a different edit |
| `Y13` | the scope guard dropped from block detection | same blind spot, third edit — **10 of the 954 live markers sit outside a requirement scope** and nothing saw them |
| `Y9` | the terminator ignores indentation, so an indented sub-bullet ends the block | no fixture put a sub-bullet inside a statement |
| `Y11` | the block capped at two lines | no fixture had a modal on the **third** line of a block |
| `X3` | an EMPTY requirements document reported as an ABSENT one | `if not req` reads as a tidier `is None`; the two-outcomes-one-sentence shape **this batch exists to close**, arriving through a refactor instead of a rule |

**Seven arms were added for the ten** (`SPANISH-modal`, `CASED-modal`, `SHOULDER-not-modal`,
`NON-REQ-HEADING`, `SUB-BULLETS`, V6 `EMPTY-DOCUMENT`, V2 `EMPTY-DOCUMENT`). `CASED-modal` kills
`Y4` and `Y5`; `NON-REQ-HEADING` kills `Y1`, `Y8` and `Y13`; `SUB-BULLETS` kills `Y9` and `Y11`.

**Combined after two batteries: 37 scored · 37 RED · 0 survivors.** That figure did not survive
contact with a third lens — see below.

**What the two batteries say together.** The mandated list is oriented at the *mechanism* — the
tokenizer, the corpus, the terminators, the sentences. It contains nothing about the modal's own
**vocabulary**, its **case**, its **word boundaries** or the **scope** it is read in, because those
were never the defect under discussion. An arm set built from a requirement inherits the
requirement's blind spots, and the only way to see them is to attack the code with a list the
requirement did not write.

---

### 🛑🛑🛑 A THIRD review, and the axis is neither behaviour nor wording: **POPULATION**

An independent review returned **BLOCK** on 35 fresh mutants under the full crash guard: **15
survived all 335 green arms.** Its meta-finding is the sharpest of the three, and it is the one my
own §4 predicted I could not see:

> **The arms sweep VALUES and sample CARDINALITY and EXTENT.** Every fixture in both rules is a
> 1–3 line document producing at most one finding, so the population axes — how many findings a
> rule may emit, how far a block reaches, how deep a walk prunes — are each pinned at a single
> point. Everything about what each rule *says* is well armed; nothing about how much of the
> document each rule *reaches*.

I reproduced all thirteen classes independently before fixing anything (`kills4c.py`): **13 built,
13 survivors, each importing, each printing 335 arms, each exiting 0.** Then measured what each
would cost on the live corpus — because a survivor whose blast radius is unknown is a finding
without a size.

| # | the single edit that survived 335 green arms | measured cost on the live corpus | now reddened by |
|---|---|---|---|
| **F2a HIGH** | `[:1]` on V2's BLOCK comprehension | a gate line saying the document has ONE unresolved id when it has ten | **`TWO-MISSING`** |
| **F2b HIGH** | `[:1]` on `_v6_outcome`'s comprehension | same, one rule over | **`TWO-MODALS`** |
| **F3 HIGH** | lookahead capped at 2 continuations | **623 of 1998 block lines (31%) silently unscanned** | **`DEEP-BLOCK`** |
| **F3′ HIGH** | lookahead capped at 8 continuations | 68 lines unscanned; 32 live blocks run to 9+ | **`DEEP-BLOCK`** |
| **F4a MED** | `_V6_REQ_HEAD` `#{2,4}` → `#{2,3}` | **78 of 944 blocks (8%) never open a scope** | **`H4-SCOPE`** |
| **F4a′ MED** | `_V6_ANY_HEAD` `#{1,4}` → `#{1,3}` | a `####` non-requirement section never closes the scope | **`H4-SCOPE`** |
| **F4b MED** | the marker must carry the colon inside the bold | 21 of 944 blocks lost | **`BOLD-THEN-COLON`** |
| **F4c MED** | a blank line terminates the block | 50 scanned lines lost | **`BLANK-LINE-SPAN`** |
| **F5a** | the `__pycache__` prune fires only at the `tests/` root | **zero cost here — this repo has exactly one `__pycache__` and it is at the root.** A shared `~/.claude` tool meets nested ones as the norm | **`PYCACHE-excluded`**, refixtured nested |
| **F5b** | the corpus predicate drops `.json` | 3 `.json` files under `tests/` (alongside 155 `.py`, 109 `.svg`, 6 `.md`) | **`NON-PY-corpus`**, now two extensions |
| **F7** | `_v2_why` returns `""` | a bare `FAIL` with no cause — the shape `_v5_why` exists to prevent | **`WHY-no-tree`**, **`WHY-moved`** |
| **R1** | `set()` dropped from the declared ids | duplicate BLOCK lines per repeated citation | **`TWO-MISSING`** |
| **R2** | `sorted()` dropped, document order kept | a gate line whose order changes with prose edits | **`TWO-MISSING`** |

**`F3` was not a coverage gap — it was a FALSE SENTENCE inside the anti-vacuity machinery.**
`SUB-BULLETS`'s comment claimed it reddened *"a lookahead capped at one continuation line"*, but
its modal sat on the **second** continuation, so a cap of 2 — and of 8 — survived it. `LLR-88.4`
requires every arm block to name the mutation that turns it red; that comment named one it did not
turn red, and **a reader auditing the arms would have ticked the lookahead axis as covered.** The
comment now says what the fixture actually kills, and `DEEP-BLOCK` takes the axis: measured over
the 944 live blocks, continuations run to a **maximum of 16** (p99 11, p95 7), so the fixture puts
the modal on the **16th** — the corpus maximum, which makes **any** cap red rather than only the
shallow ones.

**`R1` and `R2` are mine, not the review's, and they are a regression the upstream `C-56` fix
caused.** Both were killed in my second battery by `LIVE-line` alone, when it asserted **two BLOCK
lines**. De-minting the requirement's prose emptied the live declaration, `LIVE-line` became a
one-line SKIP assertion, and **the cardinality and ordering of V2's finding list silently lost
their only guard.** Re-measured after the de-minting: 21 scored, **2 survivors**. `TWO-MISSING`
restores both from a synthetic fixture that no document edit can empty — which is where they
should have been.

**One mutant is scored as a PROBABILISTIC kill and is reported as such**: `list(set(...))` — sorted
dropped, set kept. String hashing is randomised per process, so the order is random per run.
Measured: **red in 10 of 12 runs** (3 ids ⇒ 5/6 expected). `TWO-MISSING` kills the deterministic
order-dropping variant (`dict.fromkeys`, document order) every time; it kills this one five times
in six. **That is stated rather than counted as a kill.**

**Also restored: the disk-side walk now executes against a real tree.** On the SKIP path V2 returns
*before* `_v2_tokens` is reached, and after the de-minting the live document declares no ids — so
**no arm was executing the harvest against a real filesystem at all**, which is the structural
reason F5's mutants all survived. `LIVE-corpus` calls `_v2_tokens` on the live `tests/` and asserts
a **floor** (`≥ 100`, got 980) plus membership of one known-real node, never the exact count.

**Combined across all three batteries: 50 scored · 50 RED · 0 survivors** (`kills4.py` ·
`kills4b.py` · `kills4c.py`), each importing, each printing **344** arms, each exiting 1, each
naming the arm that reddened it. One further mutant declared probabilistic and unscored.

**What three lenses on one increment say.** Lens 1 asked what the rules *do* — 16 mutants, 0
survivors, and it proved almost nothing, because the arms were written from its list. Lens 2 asked
what the rules *are* — vocabulary, case, boundaries, scope — and found 10. Lens 3 asked *how much
of the document the rules reach* — cardinality, extent, walk depth — and found 15 more. **Each
lens was blind to the next one's axis, and the count of survivors went UP with each pass.** The
useful number in this packet is not 0; it is **25 real gaps found by two lenses that were not the
requirement's.**

---

## 4 · Risks, and the things I could NOT arm

- **`LIVE-line` is pinned to today's `01-requirements.md`**, and it has already moved once —
  the upstream `C-56` de-minting turned it from two BLOCK lines into one SKIP line. It failed
  loudly and `_v2_why()` named both candidate causes, which is what sent the reader to the
  document rather than to the code. **But the episode is also the risk**: an arm whose input is a
  living document carries that document's edit rate, and it took `R1`/`R2` down with it when it
  moved. Everything load-bearing is now armed synthetically as well.
- **A blank line does not terminate a statement block** — a statement followed by a blank line and
  then *unindented prose* (neither a heading nor a list item) swallows that prose. `LLR-88.3`
  names exactly two terminators and I did not add a third. **This is now a DECISION with an arm
  behind it** (`BLANK-LINE-SPAN`) rather than a judgment defended by prose: the third review
  agreed the behaviour is correct and noted only that nothing held it. Measured: 15 of the 944
  live blocks contain a blank line, all 15 produce no finding, and a blank-line terminator would
  cost 50 scanned lines.
- **Statement blocks can OVERLAP** where a statement is written as bold prose rather than as a
  bullet, because such a line does not terminate the previous block. Measured: **12 overlapping
  pairs** across the 944 live blocks, **0 modals in any of them**, so no duplicate finding exists
  today — but a modal inside an overlap would be reported twice. `LLR-88.3` does not address it
  and I did not widen the rule to. Recorded so a later batch does not rediscover it.
- **`list(set(...))` on the declared ids is a PROBABILISTIC kill, not a kill** — 10 of 12 runs,
  because Python randomises string hashing per process. The deterministic order-dropping variants
  die every time. Stated rather than counted.
- **`_strip_code` is NOT applied to V6 blocks — declared no-op, unscored in either direction.**
  A fenced code block inside a statement would have its modal read as prose. Zero live instances
  across 65 documents.
- **Case folding on the V2 corpus is likewise a declared no-op and unscored** (4 lowercase
  occurrences, none decisive).
- **V2 and the Atlas now share one tokenizer.** `_ATLAS_ID_ATTC` is a cross-consumer coupling that
  did not exist before: an edit made for the Atlas moves V2's verdicts. Its truncation behaviour is
  pinned by three shipped `_atl` arms, but **nothing states the coupling**, and no arm fails with a
  message naming it.
- **`_tree_text` was deleted.** V2 was its only consumer, verified by grep across the file. If a
  future rule wants raw tree text it must reintroduce it — deliberately, which is the point.
- **The `PYCACHE-excluded` fixture writes a `.pyc`-named file containing UTF-8 text**, not real
  bytecode. It exercises the *directory* exclusion, which is what the rule implements; it does not
  exercise anything about bytecode decoding.
- **`MV2-02` and `MV6-S4` are two-part edits and I am saying so rather than calling them
  single-token.** A substring fallback needs both the clause and the helper it calls; "both
  sentences wrong, differing by a trailing period" is a statement about two constants.
- **`LIVE-corpus` pins one real test node by name.** If that node is renamed the arm reddens for a
  `tests/` reason, not a validator reason. The alternative — asserting only a count — is what the
  floor avoids, since 980 churns with every test added. Chosen deliberately; `_v2_why` names it.
- **F6, unfixed by decision:** overlapping blocks, above. **F5's `.pyc` fixture still writes UTF-8
  text under a `.pyc` name** — it exercises the directory prune, which is what the rule
  implements, not bytecode decoding.
- **No live V6 escape was found and none is claimed.** 944 blocks, 223 of them multi-line, 0 BLOCKs
  before and 0 after.

---

## 5 · Pending

- **`P-7` HOLDS after the de-minting** and needs no amendment. `LLR-88.2`'s live-line criterion
  says *"the live SKIP line"* and the live line is a SKIP again, so arm and criterion agree; the
  ~~two-BLOCK reading~~ above is kept beside the correction rather than overwritten.
- **`LLR-88.3` should name what a blank line does.** The requirement names two terminators and is
  silent on the blank line; the behaviour is now armed and measured, so the sentence is cheap to
  write and expensive to leave implicit — the exact shape this batch keeps paying for.
- **`LLR-88.4`'s per-arm-comment obligation has no mechanical check**, which is how
  `SUB-BULLETS` shipped naming a mutation it did not kill. Nothing in the selftest can read a
  comment. Raised, not solved here.
- `V7` stays red until Inc 7's bump, by design. `V16` ×2 — this increment's uncommitted edit to
  both flow repos. **Nothing was committed.**
- The derived Atlas was regenerated with `--atlas --write` AFTER this packet existed.

---

## 6 · Suggested next task

**Inc 5** — the artifact loader (`LLR-88.5`). It is a prerequisite for reading any of this
correctly: until it lands, `V5` judges a document from May while `V2` and `V6` judge batch-88's,
so the gate line mixes two batches. Two carry-overs from here:

1. **Run independent batteries along DIFFERENT axes, and expect the survivor count to rise.**
   16 mandated kills found 0; 21 invented ones found 10; 35 more along the population axis found
   15. Inc 3 learned that arms aimed at cores prove nothing about rules; this increment learned
   that arms aimed at a requirement prove nothing about what the requirement never discussed, and
   then that arms sweeping VALUES prove nothing about CARDINALITY, EXTENT or DEPTH. **Ask each
   new rule: how many findings may it emit, how far does it reach, and how deep does it walk?**
2. **Check the loader fix against V2's declared-id harvest**, because Inc 5 changes *which
   document* V2 reads and therefore which ids it declares — and `LIVE-line` asserts that document's
   line character for character.
3. **Sweep every rule's population, not just the record it names.** The `C-56` relocation that
   cost `R1`/`R2` happened because a de-mint from one rule's population landed in another's.

---

## Increment gate checklist

| # | Item | ✓ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 1 authored + 1 build output (`V15`: *bundle identical*) |
| 2 | Tests in the same increment | ✓ | 46 arms, 298 → **344**, `SELFTEST PASSED`, exit 0 |
| 4 | RED counterfactual | ✓ | **50 scored, 50 reddened, 0 survivors** across three batteries (16 mandated + 21 independent + 13 population-axis); each non-no-op at build time; each kill carries a **named** arm, ≥ 344 printed arms and exit 1, so no crash is scored as a kill. **25 of the 50 survived a green selftest on first contact** and are listed with their measured corpus cost; 1 further mutant declared probabilistic and unscored |
| 5 | Reverse census | ✓ | `_tree_text` had exactly one consumer (grep, whole file) and was deleted with it; `_v2_tokens` and `_v6_blocks`/`_v6_outcome` have one caller each |
| 9 | Coverage verified on disk | ✓ | 65-document sweep: 954 markers → 944 in scope, 223 multi-line, 1998 scanned lines, continuations max **16** / p99 11 / p95 7, 12 overlapping pairs, **0 → 0** BLOCKs; `tests/` token corpus 989 → 980 excluding `__pycache__`, 980 re-harvested live by `LIVE-corpus`; every third-review survivor priced against this corpus |
| 10 | Load-bearing emptiness | ✓ | `PYCACHE-excluded` asserts an ABSENCE (`ID-101` unresolved) **in the same run** as a presence (`ID-102` resolved); `NO-MARKER` and both `EMPTY-DOCUMENT` arms assert the finding COUNT before comparing any sentence |
| 11 | Mutation verdicts per arm | ✓ | §3's three tables name, per mutant, which arms reddened, and mark the six still killed by exactly one. **`SUB-BULLETS`'s comment named a mutation it did not kill and was corrected**, which is the failure mode this row exists for |
| — | Secrets | ✓ | no key, token, `.env` or credential read, written or printed |
| — | Destructive commands | ✓ | none run; `prototypes/`, `build/` and all untracked files untouched; **no commit** |

**An item without a citation is not satisfied — it is asserted.**

---

## 🛑 Post-implementation: the requirement's own prose had DECLARED two ids, and P-7 came back

This increment shipped with the live gate at **5 block**, two of them `V2` BLOCKs, and the packet
above reported `P-7` — *"V2 has no live instance in this repository"* — as **refuted**. It was
not. **The requirement's own amendment bullets, written the day before, spelled digit-initial
acceptance ids in prose**, and V2's declared-side pattern harvests them from anywhere in the
document because it cannot tell a citation from a declaration.

So the two BLOCKs were **real instances of exactly the two defect classes this fix exists to
close** — one a prefix shadow, one resolving only from stale bytecode — **and both existed only
because the requirement described them.** The bullet warning that a dotted id is truncated by the
declared side is precisely what put a dotted id on the declared side.

**Ruled: de-mint the prose**, the same disposition C3 took for V23. Adding test nodes for prose
examples would be inventing acceptance cases to satisfy a documentation accident. The ids now
carry the substituted prefix `ID-` and the convention is declared in `LLR-88.2` itself. Verified:
the declared-side harvest over the record is now **empty**, the live line is back to
`no AT ids declared`, and **`P-7` holds**.

**This is the third distinct C-56 instance in this batch and the first to REFUTE A PREMISE by the
act of documenting the requirement that rests on it.** The first two minted V23 notices; this one
minted requirement ids and moved a gate by two blocks.

**`LIVE-line` was re-pointed, and it earned its keep on the way.** It failed loudly when the live
line moved and its failure text named both candidate causes — *"either the fix regressed, or
`01-requirements.md` changed which AT ids it declares — read both before editing the arm"* — which
is what sent the reader to the real cause instead of to the code. Re-verified after re-pointing:
the declared-side swap (`MV2-07`, the highest-value mutant in the catalog) is still killed, and
**`LIVE-line` is one of the three arms that kills it**, which is the job `LLR-88.2` assigned it.

Final gate: **3 block · 287 notice · 14 n/a** — the three are the flow-repo lifecycle (`V7`
hash drift until Inc 7's bump, `V16` ×2 for this increment's uncommitted edit). Selftest **344
arms**, exit 0. **Nothing was committed.**
