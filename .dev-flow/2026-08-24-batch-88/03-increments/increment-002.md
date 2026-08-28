# Increment 002 — `LLR-88.9` — the strict design-review grammar, and the harvester that feeds it

| Field | Value |
|---|---|
| Batch | `2026-08-24-batch-88` |
| Increment | `002` of 7 |
| Requirement(s) | `LLR-88.9` (both halves) |
| Acceptance | `AT-B88-04` |
| Date | `2026-08-26` |

---

## 1 · What changed

**Two halves, and the second is the one nobody had specified until this batch measured it.**

**The grammar.** `_V23_OK` admits four forms, each distinctly expressible — the bare record, its
`.md` filename, a `-v<n>` version, and a decision inside either — and **rejects** a batch segment
carrying any other hyphenated component. The permissive repair that admits arbitrary hyphens makes a
batch-*directory* name parse as a record, and the operator rejected it.

**The harvester.** `_V23_TOKEN` takes `\S+`, so it swallows whatever punctuation abuts a citation,
and the discard is the only thing narrowing it back. rev46 used `str.rstrip`, which **halts at the
first character outside its set** — so one unlisted delimiter shielded every listed one behind it,
and the backtick, which *was* listed, stayed unreachable through a `*`. Replaced by an anchored
**character class**, `[^A-Za-z0-9#]+$`.

**The `#` is kept deliberately, and this is where the requirement was wrong.** `LLR-88.9` first said
the discard is *"derived from every trailing character that no citation can end in"* — which reads
literally as `[^A-Za-z0-9]+$`, and **that repairs the bare-hash form into an accepted bare record: a
discard set that makes invalid input valid.** Follow the original wording exactly and it is not a
mutant, it is the shipped bug. Corrected in the requirement before this increment was written.

---

## 2 · Files modified

| File | Kind | Change |
|---|---|---|
| `~/.claude/docs/tools/devflow-validate.py` | source | grammar, discard class, harvest call, 26 arms |
| `~/.claude/skills/dev-flow/scripts/devflow-validate.py` | build output | `--sync-bundle` mirror |

**SOURCE files: 1 / 4.**

---

## 3 · Test results

**Selftest:** `SELFTEST PASSED`, exit 0, **244** arm lines (192 batch baseline · +2 Inc 1 · **+50** here, of which 24 were added by the review pass). **Live `V23`:** 50 citations, every one conforming — unchanged, and that is the point: this
increment's oracle was already **still**, so the live corpus contributes **zero** discriminating
evidence and every arm is synthetic.

**Harvester, measured:** **12 of 12** M-11 Markdown contexts now recover a clean citation
(pre-state: 8 of 12 mangled). **10 of 10** delimiters that appear in *neither* M-11's table *nor*
rev46's strip set also recover — which is the only observation that separates a class from a longer
list.

**The four forms, live:** bare record, `.md` filename, `-v<n>` version and a decision inside a
version all parse. **`02-review-security.md` can now cite the design record that mandated it** — it
could not before, and said so in its own header.

### The mutation battery — 24 scored, **24 killed, 0 survivors**

Every mutant asserted **non-no-op at build time**, so a mutation that changed nothing was a hard
error rather than a silent green.

| Class | Mutants | Killed by |
|---|---|---|
| permissive relapse (1 char), the rejected `full.diff` grammar | 2 | `GR-hyphen-dir`, `GR-hyphen-dec`, + all three E2E |
| boundary — `$` dropped, digits optional, dot unescaped, alternation split, tail mandatory, version generalised, case folded | 7 | `GR-*` rejection rows |
| discard — enumeration, `#` dropped, "ends in a digit", unanchored, inverted, one char back, revert to `rstrip` | 7 | `DISCARD-class`, `DISCARD-not-greedy`, `DISCARD-PASS!=NOOP` |
| harvester scope — per-line collapsed, first match only, first line only, canon root dropped, no descent, file filter, silent-empty, `\b` dropped | 8 | `E2E-where`, `E2E-notice`, `E2E-unlaundered`, `HARVEST-boundary` |

**`mv23-40` is the entry that justifies the whole approach.** Swapping the class for an enumeration
is a **no-op across all twelve M-11 contexts** — across the entire arm population `LLR-88.9`'s
`≥ 8` threshold mandates — and breaks **10 of 10** novel delimiters. **Only `DISCARD-class` caught
it.** An arm set satisfying the literal threshold cannot. The count measured effort, not coverage.

### 🛑 Five of my own arms were vacuous, and the battery said so before any reviewer did

The battery ran against a catalog authored by an independent lens that **was never shown these
arms** — so it derived what *should* kill an arm set rather than confirming what does. First run:

| Survivor | What it means | Closed by |
|---|---|---|
| `mv23-08` decision digits optional | `…#D` with no number becomes valid | `GR-dec-nodigit` |
| `mv23-11` the dot unescaped | `…-batch-88-md` — a hyphenated component admitted through a missing backslash | `GR-md-hyphen` |
| `mv23-15` case folded | `-V2` and `.MD` become valid | `GR-case-ver`, `GR-case-ext` |
| `mv23-25` `\b` dropped | a citation shape **inside a word** becomes a false notice against prose | `HARVEST-boundary` |
| `mv23-35` canon root dropped | **my fixture's own defect**: I put a *conforming* citation in `REQUIREMENTS.md`, so removing that population root was unobservable | the canon root now carries a **non-conforming** citation |

The last one is the sharpest. The catalog had warned in as many words that the natural fixture —
one flat directory, one citation per line, `.dev-flow/` only — misses the walk's descent, the canon
root and the per-line iteration. I built the two-deep tree and the shared line, and still made the
canon root inert by giving it a citation that conforms.

---

### 🛑 The review found a whole CLASS my battery could not reach

An independent `code-reviewer` returned **BLOCK**, and its diagnosis is sharper than its
finding: **my discard arms SAMPLED one citation instead of SWEEPING the class.** Every one was
built from `…-batch-88#D1`, which pins the keep class at exactly the two characters that token
ends in — `1` and `#`. The other two terminals this grammar newly admits, `.md` (ends in `d`)
and `-v<n>`, **never traversed the harvester at all**: they existed only as grammar rows, and
grammar rows call `_V23_OK` directly.

Verified end-to-end: narrowing the class by **one character** (`0-9` → `0-8`) left **220 of 220**
arms green *and* fired a false NOTICE against a conforming citation **live in this repository**.
That is the M-11 defect this increment exists to close, reintroduced with a green gate.

The reviewer's own sweep: **3,426 single-edit mutants** over the two changed literals — **137
survived my arm set, 82 of them harmful.** My battery killed 24 of 24 and the claim was true;
it was true *of the catalog*, not of the arm set. **And the catalog could not have covered it**:
it was derived from the requirement, and the requirement never says the discard's ALPHABET must
be exercised — only its delimiters.

| # | Finding | Fix |
|---|---|---|
| **F1 HIGH** | the class sampled, not swept | `GRAMMAR-alphabet` and `DISCARD-alphabet` sweep all **94** printable ASCII characters; `RECOVER-dec` / `RECOVER-file` / `RECOVER-ver` run the three terminal shapes through all twelve contexts; **7** more rejection rows from the survivor set |
| **F2 MED** | three arms asserted CONFORMANCE, not IDENTITY — *"some conforming token came back"* | all now assert `== the citation`. **Same weakening family as the substring arm that escaped Inc 1**: a predicate broad enough to be satisfied by the wrong answer |
| **F3 MED** | the NOTICE sentence still described `#D<n>` only, so a reader told about a hyphenated batch-dir was advised to add a decision suffix the grammar no longer wants — **and no arm asserted the notice text at all** | sentence names all four forms; `NOTICE-names-forms` asserts it |
| **F4 MED** | twelve contexts collapsed into one `all()` where the threshold says ≥ 8 — equal kill-power, no diagnosability | one arm per context, each naming its own |

**Post-fix: 244 arms.** All eight survivors the reviewer demonstrated are killed, and the
original 24-mutant battery still reads 24 of 24.

**The lesson is not "run more mutants."** Both of this increment's blind spots were *shapes* no
one had thought to attack — the fixture's shape in the first pass, the arm's sampling in the
second. A catalog derived from a requirement inherits that requirement's silences.

## 4 · Risks

- **Every arm here is synthetic and the acceptance says so.** The live corpus scores identically
  under the shipped, permissive and strict grammars. There is no census to move and no notice count
  to watch: if an arm is vacuous here, **nothing else catches it**. That is why the battery, not the
  arm count, is this increment's evidence.
- **`mv23-05b` is a genuine no-op and is excluded from scoring** — `.match` → `.search` on an
  already-anchored pattern. The catalog names it because this batch's own QA plan had to retract a
  finding produced by exactly that mutant. The lethal edit is the *pair* (`^` dropped **and**
  `search`), which is two edits and therefore not a single-edit mutant.

## 5 · Pending

- **`02-review-security.md` can now be repaired** — its header states it had to *describe* the
  record id rather than write it, "until Inc 2 lands". Inc 2 has landed. Deferred while an
  adversarial progress review is reading that file.
- `V7` stays red until Inc 7's bump, by design. `V16` ×2 = local commits never pushed.

## 6 · Suggested next task

**Inc 3** — the sentence family (V5's ledger, V8's map resolver, V8's root-file message). Note the
QA plan's `CASE-adopted` and `CASE-exact-wins` arms were **rejected** and the rejection independently
confirmed: both stay green when the fix is reverted.

---

## Increment gate checklist

| # | Item | ✓ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | 1 authored + 1 build output |
| 2 | Tests in the same increment | ✓ | 26 arms |
| 4 | RED counterfactual | ✓ | 24 scored, 24 killed, 0 survivors; each non-no-op at build |
| 5 | Reverse census | ✓ | no rule, arm or test keys on the old grammar; V23's own line is the only consumer |
| 6 | `code-reviewer` — a HIGH blocks | ✓ | ran; **BLOCK**, 1 HIGH + 3; all four taken and re-verified |
| 9 | Coverage verified on disk | ✓ | 12/12 and 10/10 measured; 220 arms counted from the run |
| 10 | Load-bearing emptiness | ✓ | `HARVEST-boundary` asserts an ABSENCE; its positive control is that the same pattern **does** harvest the unembedded form |
| 11 | Mutation verdicts per arm | ✓ | §3 table names, per mutant, which arms failed |

**An item without a citation is not satisfied — it is asserted.**
