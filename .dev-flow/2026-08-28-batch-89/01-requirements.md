# Requirements — s19_app — 2026-08-28-batch-89 · the lean contract

> **This document is the LIVE CONTRACT. It holds current state only.**
> No strikethrough, no amendment bullets, no supersession narration, no measurement inside a
> normative sentence. How each requirement came to say what it says is in
> `01-requirements-ledger.md`, which is **append-only** and is never edited. Every
> requirement below names its ledger entries; every ledger entry names its requirement; `V26`
> compares the two sets of pairs in both directions.

> **Id discipline (C-56).** Writing an id in any `.dev-flow/**.md` file DECLARES it to the
> corpus scanner, and moving text into an appendix under `.dev-flow/` does not un-declare it.
> The ledger therefore lives under `.dev-flow/` deliberately: traceability survives the split.
> No story ids are minted here — the operator's five scope items are named **Story 1** to
> **Story 5**, following the batch-88 exemplar, because this session cannot verify a `US-NNN`
> id against the whole census without minting the candidate it is testing.

---

## 1 · Scope

Five stories, approved by the operator. **Only Story 1 is implemented in this record's own
increment**; Stories 2 to 5 are specified here and implemented in later increments.

| # | Story | Increment |
|---|---|---|
| **Story 1** | The requirements record splits into a live contract and an append-only ledger, and a rule enforces the split | 1 — **implemented** |
| **Story 2** | `--selftest` survives a cp1252 stdout, and an arm proves it | 2 |
| **Story 3** | The flow invokes `python`, not `python3`, and `V17` verifies the guard's INTERPRETER | 3 |
| **Story 4** | The flow declares an environment contract, and a rule DERIVES it from source | 4 |
| **Story 5** | A runtime preflight reports git, stdout encoding and filesystem case-folding | 5 |

**Out of scope:** reforming this template's own preamble register; the batch-88 findings
`R-88-5` through `R-88-8` and `R-88-12` through `R-88-19`, which remain open and are not
carried by any requirement below.

---

## 2 · Premise evaluation (C-43)

Every figure below was produced by a command this session ran, except where the Tier says
`inherited`. Where a figure here disagrees with what the command prints, the command is right.

| # | Premise | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| P-1 | The corpus PREDATING batch-89 holds 65 `01-requirements.md` records with a median of **54,367 CHARACTERS** | premise | ✅ TRUE | `python` over `glob('*/01-requirements.md')`, 2026-08-28, `len(read())`: `n=65 median=54367` (p25 37,006 · p75 87,505 · max 314,621). **The same population in BYTES is median 55,367 (p25 37,789 · p75 89,790 · max 322,289)** — `os.path.getsize`, and the corpus is UTF-8 with multi-byte punctuation, so the two disagree by ~1,000 at the median | budget floor derived from it — `HLR-89.1`. **The unit is load-bearing: the rule measures `len(text)`, so the bytes figure would have set the floor 1,000 too high.** The population EXCLUDES batch-89's own record, the 66th, because it is this rule's subject — see `LED-89.5` |
| P-2 | batch-88's record is 193,364 chars, of which 8.1% is the findings table and 26.6% forensic prose, leaving 65.3% normative text in the forensic register | inherited | ✅ TRUE (size re-executed) | `wc -c` 2026-08-28: **197,032** bytes on disk today. The 193,364 char figure and the three percentages are the operator's decomposition and were **not re-derived this session** | the decomposition is what justifies "splitting files is not enough"; the ratio is inherited, the conclusion is not load-bearing on its exact value |
| P-3 | Markdown strikethrough is the only supersession marker with a grammar; the warning glyph is not | premise | ✅ TRUE | measured over all 65 pre-batch-89 records, 2026-08-28: 16 carry the glyph, 10 carry strikethrough. Inspection of the glyph's sites shows it marking current-state warnings as often as amendments | `LLR-89.1.2` checks strikethrough and deliberately not vocabulary |
| P-4 | `python3` is invoked at 4 sites in the flow | premise | ✅ TRUE | `grep -rn python3` 2026-08-28: `devflow-validate.py:1`, `hooks/flow-guard.py:1`, `hooks/install.py:1` (shebangs) and `.github/workflows/flow-selftest.yml:40` | `HLR-89.3` |
| P-5 | `devflow-validate.py` imports zero third-party modules | premise | ✅ TRUE | its only import lines are `from __future__ import annotations` and `import builtins, hashlib, json, os, re, shutil, subprocess, sys, tempfile, textwrap, time` — all stdlib | `HLR-89.4` |
| P-6 | The Python floor is 3.7, bound by `capture_output=` with `text=` | premise | ✅ TRUE | `subprocess.run(..., capture_output=True, text=True, ...)` inside **`v8_module_map`** (`devflow-validate.py:572-573` at this commit). Both kwargs landed in CPython 3.7 | `HLR-89.4`; cited by SYMBOL, see `LED-89.2` |
| P-7 | A full `--selftest` needs git ≥ 2.28.0, bound by `git init -b` | premise | ✅ TRUE | `_g(d, "init", "-q", ..., "-b", "main", ...)` inside the **V25 fixture builder in `selftest()`**. `git init -b` landed in git 2.28.0. It is reached only by the selftest, never by the gate | `HLR-89.4`; the operator's citation `:5299` was **correct before this increment and is stale after it** — see `LED-89.2` |
| P-8 | `--selftest` crashes under a cp1252 stdout, emitting zero arms and no verdict line | inherited | ❓ UNDECIDABLE here | **not reproduced this session.** Every run in this increment set `PYTHONIOENCODING=utf-8`, so the defect was avoided rather than observed | `HLR-89.2` specifies it; reproducing it is Increment 2's first act, and Increment 2 blocks until it is reproduced |
| P-9 | The local toolchain satisfies both floors | premise | ✅ TRUE | `git version 2.49.0.windows.1`, `Python 3.12.7` | this machine cannot demonstrate a floor VIOLATION, which is why `HLR-89.4` obliges derivation from source and not a runtime probe |

**Gate rule:** ❌ and ❓ both block. `P-8` is dispositioned explicitly: it is a premise of
Story 2 and it gates Story 2's increment, not this one.

---

## 3 · High-level requirements

### HLR-89.1 — the live contract is bounded and the ledger is not
- **Traceability:** Story 1
- **Ledger:** LED-89.1, LED-89.3, LED-89.5, LED-89.7
- **Statement:** The validator shall report the live contract's size against a declared
  character budget, and shall exclude the ledger from that measurement.
- **Rationale (informative):** a budget over an append-only file is a standing instruction to
  delete history.
- **Validation:** `test`
- **Executed verification:** `python devflow-validate.py --selftest`, arms
  `V26 BUDGET-over`, `V26 BUDGET-at`, `V26 BUDGET-ignores-ledger`,
  `V26 BUDGET-renders-const`, `V26 BUDGET-constant`
- **Numeric pass threshold:** 5 arms report `ok`; 0 FAIL; the budget finding is `NOTICE` when
  over and `SKIP` when at or under, and is never `BLOCK`
- **Priority:** high
- **Acceptance test(s):** `owed at Increment 1` — **no id is minted**, and `R-89-7` records the
  executed reason: `V2` resolves an `AT` id against `<project>/tests/` alone, and this
  requirement's acceptance arms live in `devflow-validate.py --selftest`.
- **Negative control:** executed. Mutant `M14-strike-unbounded` (restore the unbounded `re.S`
  pattern) reddens `STRIKE-blank-line`; `M13-budget-in-BYTES` (`len(live.encode('utf-8'))`)
  reddens `BUDGET-ignores-ledger` and `PASS-typed`. Every named mutant RED, 0 survived, 0
  broken — the count is read from the harness output, not restated here, for `LLR-89.1.1`'s
  reason.
- **Boundary catalog:** ☑ empty — no live contract (`NOLIVE`) and no ledger beside it
  (`NOLEDGER`) · ☑ boundary — a contract of exactly `_LEAN_MAX_CHARS` (`BUDGET-at`) · ☑ invalid
  — pairs crossed with both id sets identical (`PAIR-crossed`) · ☑ error — an unreadable ledger
  arriving as `""` (`LEDGER-empty-string`). Every ticked class names the arm that owes it.
- **Acceptance (black-box):** observable outcome — a reader running the gate sees one line
  stating the record's size and the budget · shipped surface — `devflow-validate.py` · the
  number is the rule's own constant, rendered, so no document holds a second copy of it.

### HLR-89.2 — the selftest states a verdict under any stdout encoding
- **Traceability:** Story 2
- **Ledger:** none
- **Statement:** When stdout cannot encode a character the selftest prints, the selftest shall
  still emit its arm lines and its verdict line.
- **Rationale (informative):** a crash prints zero arms and no FAIL, which is indistinguishable
  from a pass to every consumer that reads the exit code alone.
- **Validation:** `test`
- **Executed verification:** the selftest run in a subprocess with `PYTHONIOENCODING=cp1252`,
  asserting the verdict line is present and the arm count is at its full value
- **Numeric pass threshold:** the run emits `SELFTEST PASSED` and its full arm count under
  cp1252, matching the count emitted under utf-8 exactly
- **Priority:** high
- **Acceptance test(s):** `owed at Increment 2`
- **Negative control:** owed at Increment 2, and it is the increment's FIRST act: the RED side
  is the crash itself, which `P-8` records as NOT yet reproduced. A repair whose failing case
  was never observed is unverifiable.
- **Boundary catalog:** ☑ empty — stdout with no encoding declared · ☑ boundary — a codec that
  encodes every arm label but not the verdict line · ☑ invalid — cp1252 against `\u2212` · ☑
  error — stdout redirected to a pipe, which is the configuration that hid it.
- **Acceptance (black-box):** observable outcome — the operator on a default Windows console
  sees a verdict instead of a traceback · shipped surface — `devflow-validate.py --selftest`.

### HLR-89.3 — the flow names an interpreter that exists on this machine
- **Traceability:** Story 3
- **Ledger:** none
- **Statement:** The flow shall invoke `python`, and `V17` shall verify the guard's declared
  INTERPRETER in addition to the guard's path.
- **Rationale (informative):** `python3` is not on `PATH` on Windows, so a guard wired to it is
  wired to nothing — and `V17` currently reports such a wiring as green.
- **Validation:** `test`
- **Executed verification:** `grep -rn python3` over the flow's four sites returns 0; a `V17`
  arm whose settings fixture names an interpreter that does not resolve
- **Numeric pass threshold:** 0 remaining `python3` sites; the `V17` arm BLOCKs on an
  unresolvable interpreter and stays green on a resolvable one
- **Priority:** high
- **Acceptance test(s):** `owed at Increment 3`
- **Negative control:** owed at Increment 3 — a settings fixture naming an interpreter that
  does not resolve must turn `V17` RED; today it stays green, which is the defect.
- **Boundary catalog:** ☑ empty — no interpreter named at all · ☑ boundary — an interpreter
  that resolves on PATH but is not executable · ☑ invalid — `python3` on a machine without it ·
  ☐ error — N/A: a malformed settings file is already `V17`'s own BLOCK and is not this
  requirement's class.
- **Acceptance (black-box):** observable outcome — the guard runs on a fresh Windows checkout ·
  shipped surface — the `UserPromptSubmit` hook.

### HLR-89.4 — the environment contract is declared and DERIVED, never asserted
- **Traceability:** Story 4
- **Ledger:** LED-89.2
- **Statement:** The flow shall declare its environment contract as a canon row, and a rule
  shall derive that contract's floors from the source constructs that bind them.
- **Rationale (informative):** a floor written down by hand is a claim; a floor derived from
  the construct that raises it is a measurement that cannot rot.
- **Validation:** `analysis`
- **Executed verification:** the rule scans this file set for the binding constructs and
  compares what it finds against the declared row
- **Numeric pass threshold:** Python floor **3.7** (bound by `capture_output=` with `text=`),
  git floor **2.28.0** for a full selftest (bound by `git init -b`, reached by the selftest
  alone), third-party imports **0**; the rule BLOCKs when the declared row and the derived
  values disagree
- **Priority:** medium
- **Acceptance test(s):** `owed at Increment 4`
- **Negative control:** owed at Increment 4 — a declared row disagreeing with the derived
  floors must BLOCK; a rule that only ever agrees with the row is the duplicate-oracle defect.
- **Boundary catalog:** ☑ empty — no binding construct found, which must not read as "floor
  0" · ☑ boundary — a construct raising the floor to exactly the declared value · ☑ invalid — a
  declared floor BELOW what the source binds · ☑ error — a source file that does not parse.
- **Acceptance (black-box):** observable outcome — a reader can see which line of code raises
  each floor · shipped surface — the canon row and the rule's finding.
- **Note:** every citation supporting this requirement anchors on a SYMBOL, never a line — see
  `LED-89.2`.

### HLR-89.5 — the runtime preflight reports what the gate assumes
- **Traceability:** Story 5
- **Ledger:** none
- **Statement:** Before the gate's rules run, the flow shall report whether git is present and
  at or above its floor, what encoding stdout carries, and whether the filesystem folds case.
- **Rationale (informative):** all three are assumed by rules that already ship, and none is
  reported; the selftest's own tail admits case-folding is unproven.
- **Validation:** `test`
- **Executed verification:** the preflight run against a fixture with git absent from `PATH`,
  and against one with a case-folding filesystem
- **Numeric pass threshold:** 3 preflight lines, each naming its measured value; git absent
  produces a distinct sentence from git present and below the floor
- **Priority:** medium
- **Acceptance test(s):** `owed at Increment 5`
- **Negative control:** owed at Increment 5 — git removed from `PATH` must produce a different
  sentence from git present-but-below-floor; collapsing the two is the defect `V25` already
  paid for with its "no origin configured" third state.
- **Boundary catalog:** ☑ empty — git absent from `PATH` · ☑ boundary — git at exactly 2.28.0 ·
  ☑ invalid — a version string that does not parse · ☑ error — a case-folding filesystem, which
  the selftest's own tail admits is unproven today.
- **Acceptance (black-box):** observable outcome — the operator sees the three assumptions
  stated before any verdict · shipped surface — the gate's own output.

---

## 4 · Low-level requirements

### LLR-89.1.1 — the budget's number lives in the code
- **Traceability:** HLR-89.1
- **Ledger:** LED-89.3, LED-89.5
- **Statement:** The budget threshold shall be a constant that the rule's sentences render,
  and no artifact shall restate its value.
- **Validation:** `test`
- **Executed verification:** arm `V26 BUDGET-renders-const`, which passes a threshold that is
  not the constant and asserts the constant does not appear in either sentence
- **Numeric pass threshold:** the arm reports `ok`; a hardcoded figure in either sentence
  reddens it
- **Negative control:** executed — `M18-floor-not-applied` (drop the kilo-char flooring)
  reddens `BUDGET-derivation`; `M5-median-widened` reddens four arms.
- **Boundary catalog:** ☑ empty — a single-element size list · ☑ boundary — a median that is
  already a multiple of 1,000 · ☑ invalid — an unsorted list · ☑ error — an even-length list,
  where "the middle" is a choice and not a fact.

### LLR-89.1.2 — the current-state check has a grammar
- **Traceability:** HLR-89.1
- **Ledger:** LED-89.4, LED-89.6
- **Statement:** The rule shall BLOCK on a Markdown strikethrough span in the live contract,
  and shall not judge the register of the prose.
- **Validation:** `test`
- **Executed verification:** arms `V26 STRIKE`, `V26 STRIKE-wrap`, `V26 STRIKE-not-greedy`
- **Numeric pass threshold:** 3 arms report `ok`; a wrapped span is found; a bare `~~ ~~` is
  not a span
- **Negative control:** executed — `M1-strike-never` (a pattern that cannot match) reddens 4
  arms; `M14-strike-unbounded` reddens `STRIKE-blank-line`.
- **Boundary catalog:** ☑ empty — a bare `~~ ~~` pair · ☑ boundary — a span wrapping one line
  but not crossing a blank line · ☑ invalid — an opening marker whose partner is in a later
  section · ☑ error — a record that merely SHOWS `~~this~~` as documentation.

### LLR-89.1.3 — the link is a PAIRING, checked both ways
- **Traceability:** HLR-89.1
- **Ledger:** LED-89.1
- **Statement:** The rule shall compare the set of (requirement, entry) pairs declared by the
  live contract against the set declared by the ledger, and shall BLOCK on any pair present in
  exactly one of them.
- **Validation:** `test`
- **Executed verification:** arms `V26 PAIR-only-live`, `V26 PAIR-only-ledger`,
  `V26 PAIR-crossed`, `V26 E2E-crossed`
- **Numeric pass threshold:** 4 arms report `ok`. `PAIR-crossed` is the discriminating one: it
  holds both id sets identical on both sides and swaps only the pairs, so every membership
  oracle passes it and only a pairing fails it
- **Negative control:** executed — `M2-only-ledger-blind` and `M3-only-live-blind` each redden
  4-5 arms; `M7-pairing-is-membership` reddens 14.
- **Boundary catalog:** ☑ empty — no pairs on either side · ☑ boundary — one pair differing in
  one direction only · ☑ invalid — crossed pairs with identical id sets · ☑ error — a heading
  whose id grammar disagrees with the ledger's (`GRAMMAR-agree`).

### LLR-89.1.4 — an omitted pointer field is a defect, and `none` is the declared empty
- **Traceability:** HLR-89.1
- **Ledger:** none
- **Statement:** The rule shall BLOCK on a requirement carrying no `**Ledger:**` field and on a
  ledger entry carrying no `**Requirement:**` field.
- **Validation:** `test`
- **Executed verification:** arms `V26 UNPOINTED`, `V26 UNOWNED`
- **Numeric pass threshold:** 2 arms report `ok`; each fixture yields exactly 5 findings with
  the field-absence BLOCK in its declared position
- **Negative control:** executed — `M9-unpointed-silent` and `M12-unowned-silent` each redden
  exactly one arm, which is the tightest coupling in this rule.
- **Boundary catalog:** ☑ empty — `none` written explicitly · ☑ boundary — a field present but
  naming zero ids · ☑ invalid — the field omitted entirely · ☑ error — an entry naming no
  requirement, which contributes no pair and would otherwise be invisible.

### LLR-89.1.5 — the rule is armed as REGISTERED, not only as a pure core
- **Traceability:** HLR-89.1
- **Ledger:** none
- **Statement:** The rule shall be exercised through the registry over a real directory tree
  whose shape matches the corpus's.
- **Validation:** `test`
- **Executed verification:** arms `V26 E2E-adopted`, `V26 E2E-crossed`, `V26 E2E-legacy-over`,
  `V26 E2E-legacy-under`, each building a batch directory holding both documents at its root
  and a populated `03-increments/`
- **Numeric pass threshold:** 4 arms report `ok`; each asserts the finding COUNT and the
  severity vector before comparing anything else; the two legacy arms take the DEFAULT
  threshold, which is what makes the constant observable
- **Negative control:** executed — `M6-registered-noop` (`return []`) reddens all four E2E
  arms and NO core arm, which is precisely the gap this requirement exists to close.
- **Boundary catalog:** ☑ empty — a batch directory with no ledger · ☑ boundary — a contract
  one character under the budget · ☑ invalid — a crossed pairing on a real tree · ☑ error — a
  batch tree with a populated sub-directory, the shape a flat fixture cannot see.

---

## 5 · Validation strategy

**Layer A (white-box).** `python devflow-validate.py --selftest` — 0 FAIL, `SELFTEST PASSED`.
**The arm counts are deliberately not restated here.** Read them from the run:
`--selftest | grep -c '^  '` for the total and `grep -c '^  V26 '` for this rule's, which is
the same argument `LLR-89.1.1` makes about the budget — a figure copied into prose is a second
copy that drifts, and the first draft of this section proved it by carrying 425/23 after the
run had moved to 426/24.

**Layer B (acceptance).** This document and its ledger ARE the acceptance artifact for Story 1:
the shape is proven by expressing batch-89's own requirements in it and by the gate reading
them. An `AT` id is not minted, for the reason given under Id discipline.

**Mutation.** 12 named single-edit mutants of `V26`, each asserted non-no-op, each asserted to
still import and to still emit **the baseline arm count captured from the unmutated file in the
same run** before being scored. **12 killed, 0 survived, 0 broken.** A mutant that crashes is
reported BROKEN and never counted as killed. **The gate is the RUN'S baseline and never a typed
number:** an earlier draft of this line wrote "still emit 425 arm lines", which — applied as
written against a 426-arm baseline — would have rejected all 12 mutants as broken and made the
"12 killed" result impossible. The claim and the harness disagreed, and the prose was wrong.

### Batch acceptance criteria
- Every registered rule carries at least one arm asserting its PASS SENTENCE as typed text.
- `--selftest` exits 0 with 0 FAIL; `--map` reports every manifest file agreeing.
- 0 BLOCK from `V26` over this batch's own record.

---

## 6 · Open findings

| id | Finding | Disposition |
|---|---|---|
| **R-89-1** | Deleting the ledger takes every BLOCK `V26` can raise to zero, and **the flow's own tooling never created the file**: `dev-flow-init.md` scaffolded it in neither the tree nor the seed table, `dev-flow.md` named only the contract, and `dev-flow-sync.md` did not copy it to the vault | **Fixed, and the sync omission was the severe half** — it was silent DATA LOSS, not a coverage gap: the batch's conclusions synced and its reasoning did not. The ledger is now seeded by `dev-flow-init.md` in the same act as the contract, declared as `P1_ledger` in `state.json`, and copied by `dev-flow-sync.md`. Absence is now a **NOTICE naming the unadopted shape**, not a bare SKIP |
| **R-89-2** | An arm comparing the literal 55000 to the literal 55000 is an identity, not a check — and a real defect was hiding behind it: the budget was DERIVED in bytes and ENFORCED in characters | **Fixed.** The constant is now computed by `_lean_budget_from`, and `BUDGET-derivation` re-derives the median-floor over five supplied size lists instead of asserting the answer. `BUDGET-chars-not-bytes` pins the unit. The lesson generalises: **an arm that asserts a rule's ANSWER cannot see a wrong DERIVATION**, and flagging the arm as vacuous was not the same as replacing it |
| **R-89-6** | **`V2` HAS BEEN VACUOUS ON THIS PROJECT ALL ALONG, and its pass line is a true sentence about a grammar nobody uses.** `_V2_DECLARED` is `\bAT-\d+[a-z]?\b`; batch-88 declared `AT-B88-01` … `AT-B88-09`; the rule harvests **0** of them and prints *"no AT ids declared"* | **Registered, not repaired — and it corrects a belief this batch started with.** The instinct that acceptance tests were "the executable half" was wrong: they were never machine-consumed either. Repair is not a one-line widening — `_V2_DECLARED` is FROZEN by the `WORDING-declared` arm from batch-88 Increment 4, a freeze earned because rewording a constant to assert its opposite once left 288 arms green. Lifting it needs its own increment, and batch-88 already registered the governing shape: *freezing a function also freezes the place its invariant belongs* |
| **R-89-7** | **`V2` resolves an `AT` id against `<project>/tests/` AND NOTHING ELSE, so a batch whose acceptance surface is elsewhere cannot satisfy it with a correct id.** batch-89's acceptance arms live in `devflow-validate.py --selftest` | **Measured, not argued.** An id in the numeric form, taking a number free across the whole corpus (141-149 are unused), was minted into this record experimentally and the gate answered that it *has no node on disk*. The id was then withdrawn — **and withdrawing it meant deleting the TOKEN, not quoting it**, because `V2` harvests its declared side WITHOUT `_strip_code`, so an id written as guidance inside backticks is still declared — a fourth `V2` observation, registered nowhere else: **a token was not left in place solely to produce a BLOCK whose sentence is false about reality.** So this record writes `owed at <increment>` — the field's declared empty — in all five requirements. **Widening `V2`'s node corpus beyond `tests/` is the real fix and is a batch-90 candidate**; it is orthogonal to `R-89-6`, and neither path considered for the grammar would have touched it |
| **R-89-8** | **The three fields returned by the 2026-08-28 ruling — `Boundary catalog`, `Acceptance test(s)`, `Negative control` — are template-MANDATORY and checked by NO rule** | Stated rather than implied. `V4` checks that a `test`/`analysis` requirement carries an executed verification and a numeric threshold; it knows nothing of these three. A mandate carried by convention is carried by nobody — which is the measured argument that returned `Negative control` in the first place (inline in 9 of 10 thresholds, so exactly one requirement had no RED side and nothing said so). **The same argument applies to this row**, and a rule for them is a batch-90 candidate |
| **R-89-5** | `V26` does **not** enforce append-only, and the code once claimed it did. Deleting an entry TOGETHER WITH its pointer leaves both pair sets equal and the gate green | Registered and stated where the claim used to be. What the pairing closes is the failure a split would otherwise ADD — the two documents disagreeing. Append-only is a CONVENTION the template states; enforcing it needs git history and is a separate subject, not attempted here |
| **R-89-3** | The template's own preamble is 38,687 chars written in the register this batch is removing from records | Out of scope, deliberately. Those blocks are normative rules whose parenthetical origins are their evidence; moving them is a second reform needing its own increment and its own ledger |
| **R-89-4** | `P-8` — the cp1252 crash — is specified without having been reproduced this session | Gates Increment 2 rather than this one. Increment 2 reproduces it before repairing it |
