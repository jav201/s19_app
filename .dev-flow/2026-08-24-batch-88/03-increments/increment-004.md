# Increment 004 — `LLR-88.2` · `LLR-88.3` — the scope family: two rules that read a line where they mean a set

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

**Selftest:** `SELFTEST PASSED`, exit 0, **335** arm lines — **298** before, **+37** here (V2 **18**,
V6 **19**). `LLR-88.2` demands ≥ 4 V2 arms plus three named `⚠` arms; `LLR-88.3` demands ≥ 6 V6 arms
plus four named `⚠` arms.

**Gate, live:** `5 block · 287 notice · 13 not applicable`, exit 1 — from a baseline of
`3 block · 287 notice · 13 not applicable`. The notice count did not move; V2 traded its `[-]` for
two `[x]` and V6 gained a `[-]`, which is why the *not applicable* figure is also unchanged at 13.
**That the counts stayed still is not evidence the change landed** — the arm block is.

### 🛑 The two new blocks, and why the brief expected one

```
  [x] V2   tests/: AT-043 has no node on disk
  [x] V2   tests/: AT-250c has no node on disk
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

- **`AT-043`** — declared as a truncation of `AT-043.2` in the `⚠` prose. Substring said **TRUE**;
  the only nodes on disk are `AT-043a`, `AT-043b`, `AT-043c`. This is the prefix-shadow defect,
  live, in the document that describes it.
- **`AT-250c`** — resolves under the shipped rule and under a token walk that includes
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
| `MV2-02` | substring fallback reinstated (2 parts: the helper and the clause) | `PREFIX-shadow`, `PYCACHE-excluded`, `DOTTED-on-disk`, `LIVE-line` |
| `MV2-03` | tokenizer → `\b(?:AT\|TC)-\S+`, truncation guard lost | `PUNCTUATED-ids`, `EXACT-present`, `NESTED-corpus`, `PYCACHE-excluded` |
| `MV2-04` | corpus restricted to `.py` | **`NON-PY-corpus`** — and only that one |
| `MV2-05` | walk made non-recursive (guarded against an absent `tests/`) | `NESTED-corpus`, `NON-PY-corpus` |
| `MV2-08` | token side strips the fraction, `t.split(".")[0]` | **`DOTTED-on-disk`** — and only that one |
| `MV6-02` | heading terminator dropped | **`NEXT-HEADING`** — and only that one |
| `MV6-03` | unindented-item terminator dropped | **`RATIONALE-sibling`** — and only that one |
| `MV6-09` | the block's END line reported instead of its start | **`WRAPPED-modal`** — and only that one |
| `MV6-12` | `if not blocks: return []` | **`NO-MARKER`** — and only that one |
| `MV6-13` | blocks anchored on requirement HEADINGS, so the count reports headings | `COUNT-blocks`, `SAME-LINE`, `WRAPPED-modal`, `NEXT-HEADING`, `PASS!=NOOP`, + 2 shipped |
| `MV6-S1` | pass sentence reworded to assert the OPPOSITE | `WORDING-pass` + every fixture asserting the rendered pass line |
| `MV6-S2` | mandated phrase kept, then negated four words later | `WORDING-pass` + the same set |
| `MV6-S4` | both sentences wrong, differing by a trailing period | `WORDING-pass`, `WORDING-nofile`, `NO-DOCUMENT` |
| `MV6-S6` | pass sentence emitted at `NOTICE` | **`PASS-severity`** + the generic `V6 GREEN` filter |
| `MV6-S7` | `where` degraded to `-` | **`PASS-severity`** + every rendered-line arm |

**Nine of the sixteen were killed by exactly one arm**, which is the number worth reading: the
battery has almost no redundancy, so removing one arm removes one guard.

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

**Combined: 37 mutants scored · 37 RED · 0 survivors**, each with a named arm, each importing, each
printing **335** arms (never a handful) and exiting 1.

**What the two batteries say together.** The mandated list is oriented at the *mechanism* — the
tokenizer, the corpus, the terminators, the sentences. It contains nothing about the modal's own
**vocabulary**, its **case**, its **word boundaries** or the **scope** it is read in, because those
were never the defect under discussion. An arm set built from a requirement inherits the
requirement's blind spots, and the only way to see them is to attack the code with a list the
requirement did not write.

---

## 4 · Risks, and the things I could NOT arm

- **`LIVE-line` is pinned to today's `01-requirements.md`.** It asserts two typed BLOCK lines
  character for character, so an operator edit that removes or renames those two `⚠` citations
  turns the arm red for a *documentation* reason. That is the price of the only arm that can see
  `MV2-07`; `_v2_why()` prints *"the live line moved — either the fix regressed, or
  `01-requirements.md` changed which AT ids it declares; read both before editing the arm."*
- **V2 now BLOCKS on the live tree and the gate exits 1 for a reason this increment created.**
  Two blocks, not the one the station brief predicted. The cause is `P-7`'s expiry, above. **An
  operator ruling is owed before Inc 5**, and the packet does not pretend the gate is clean.
- **A blank line does not terminate a statement block**, so a statement followed by a blank line
  and then *unindented prose* (neither a heading nor a list item) would swallow that prose.
  Measured: **15** of the 944 live blocks contain a blank line and **all 15 produce no finding**.
  `LLR-88.3` names exactly two terminators and I did not add a third. Recorded rather than fixed.
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
- **No live V6 escape was found and none is claimed.** 944 blocks, 223 of them multi-line, 0 BLOCKs
  before and 0 after.

---

## 5 · Pending

- **The operator ruling on V2's two live blocks** — amend the `⚠` prose so citations stop reading
  as declarations, or add the nodes. Blocking for the batch's gate line, not for this increment.
- **`P-7` should be marked expired in `01-requirements.md`**, beside its measurement, in the same
  superseded-not-overwritten form `P-9` uses. I did not touch that document.
- **`LLR-88.2`'s live-line criterion says "the live SKIP line"** and the live line is now two BLOCK
  lines. The arm satisfies the criterion's *intent* — a real run of the real rule over the real
  tree, asserted character for character — and contradicts its *letter*. Reported, not
  unilaterally rewritten.
- `V7` stays red until Inc 7's bump, by design. `V16` ×2 — this increment's uncommitted edit to
  both flow repos. **Nothing was committed.**
- The derived Atlas was regenerated with `--atlas --write` AFTER this packet existed.

---

## 6 · Suggested next task

**Inc 5** — the artifact loader (`LLR-88.5`). It is a prerequisite for reading any of this
correctly: until it lands, `V5` judges a document from May while `V2` and `V6` judge batch-88's,
so the gate line mixes two batches. Two carry-overs from here:

1. **Run an independent battery, not only the named one.** 16 mandated kills found 0 survivors;
   21 invented ones found **10**. The ratio is the lesson, and it reproduced Inc 3's finding along
   a new axis — Inc 3 learned that arms aimed at cores prove nothing about rules, and this
   increment learned that arms aimed at a requirement prove nothing about the parts of the rule
   the requirement never discussed.
2. **Check the loader fix against `V2`'s new live blocks**, because Inc 5 changes *which document*
   V2 harvests ids from and therefore which ids it declares.

---

## Increment gate checklist

| # | Item | ✓ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 1 authored + 1 build output (`V15`: *bundle identical*) |
| 2 | Tests in the same increment | ✓ | 37 arms, 298 → **335**, `SELFTEST PASSED`, exit 0 |
| 4 | RED counterfactual | ✓ | **37 scored, 37 reddened, 0 survivors** across two batteries (16 mandated + 21 independent); each non-no-op at build time; each kill carries a **named** arm, ≥ 335 printed arms and exit 1, so no crash is scored as a kill |
| 5 | Reverse census | ✓ | `_tree_text` had exactly one consumer (grep, whole file) and was deleted with it; `_v2_tokens` and `_v6_blocks`/`_v6_outcome` have one caller each |
| 9 | Coverage verified on disk | ✓ | 65-document sweep: 954 markers → 944 in scope, 223 multi-line, **0 → 0** BLOCKs; `tests/` token corpus 989 → 980 excluding `__pycache__`; live `V2` and `V6` lines pasted in §3 |
| 10 | Load-bearing emptiness | ✓ | `PYCACHE-excluded` asserts an ABSENCE (`AT-101` unresolved) **in the same run** as a presence (`AT-102` resolved); `NO-MARKER` and both `EMPTY-DOCUMENT` arms assert the finding COUNT before comparing any sentence |
| 11 | Mutation verdicts per arm | ✓ | §3's two tables name, per mutant, which arms reddened — and mark the nine killed by exactly one |
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

Final gate: **3 block · 287 notice · 14 n/a** — the three are the flow-repo lifecycle. Selftest
**335 arms**, exit 0.
