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

Six stories. **Story 6 is an amendment to a record that opened declaring five** — it was
authorised after batch-88's close measured two defects that no rule could see (`LED-89.19`),
and the scope moved through the ledger rather than by editing the opening sentence, which is
exactly the mechanism Increment 1 built. Stories 4 and 5 remain specified and unimplemented.

| # | Story | Increment |
|---|---|---|
| **Story 1** | The requirements record splits into a live contract and an append-only ledger, and a rule enforces the split | 1 — **implemented** |
| **Story 2** | `--selftest` survives a cp1252 stdout, and an arm proves it | 2 — **implemented** |
| **Story 3** | The flow invokes `python`, not `python3`, and `V17` verifies the guard's INTERPRETER | 3 — **implemented** |
| **Story 4** | The flow declares an environment contract, and a rule DERIVES it from source | 4 |
| **Story 5** | A runtime preflight reports git, stdout encoding and filesystem case-folding | 5 |
| **Story 6** | The `decisions_log` is checkable against the work, and a batch is closed before a newer one supersedes it | 6 — **implemented** |

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
| P-4 | `python3` is invoked at 4 sites in the flow | premise | ✅ TRUE, with one path corrected | `grep -rn python3` 2026-08-28 found 4 sites; re-measured 2026-08-29, the count holds and one path did not: the CI file is `~/.claude/.github/workflows/flow-selftest.yml:40`, **not** under `s19_app`. Three shebangs now say `python`; the CI site KEEPS `python3` — see `LED-89.10` | `HLR-89.3` |
| P-5 | `devflow-validate.py` imports zero third-party modules | premise | ✅ TRUE | its only import lines are `from __future__ import annotations` and `import builtins, hashlib, json, os, re, shutil, subprocess, sys, tempfile, textwrap, time` — all stdlib | `HLR-89.4` |
| P-6 | The Python floor is 3.7, bound by `capture_output=` with `text=` | premise | ❌ FALSE in its predicate; **3.7 survives as the API floor only** | **RE-DERIVED 2026-08-31 by both methods**, because rev54 removed `text=` from `v8_module_map` and a constant may not be carried across a substituted predicate (`R-88-18`). **API floor 3.7**, now bound independently at two surviving surfaces — `from __future__ import annotations` in the import block, and `capture_output=` at the **9 remaining** `subprocess.run` sites — so the citation no longer rests on the one construct the batch itself edits. **SYNTAX floor is a separate derivation and the AST method is blind to it**: `ast.parse(feature_version=)` accepts the rev53 PEP 701 construct at *every* version 3.7–3.12 while real 3.11.15 refuses it. See `LED-89.22` | `HLR-89.4`; cited by SYMBOL, see `LED-89.2`, `LED-89.22` |
| P-7 | A full `--selftest` needs git ≥ 2.28.0, bound by `git init -b` | premise | ✅ TRUE | `_g(d, "init", "-q", ..., "-b", "main", ...)` inside the **V25 fixture builder in `selftest()`**. `git init -b` landed in git 2.28.0. It is reached only by the selftest, never by the gate | `HLR-89.4`; the operator's citation `:5299` was **correct before this increment and is stale after it** — see `LED-89.2` |
| P-8 | `--selftest` crashes under a cp1252 stdout, emitting zero arms and no verdict line | inherited | ✅ TRUE in its load-bearing half, ❌ FALSE in its figure | **REPRODUCED 2026-08-29, Increment 2's first act, on two surfaces.** `PYTHONIOENCODING` unset + stdout redirected: exit 1, `UnicodeEncodeError` on `\u2212`, **12 arm lines**, no verdict. `PYTHONIOENCODING=ascii`: exit 1 on `\u00b7` in the FIRST arm line, **0 arm lines**, no verdict. The crash and the missing verdict are real; **"zero arms" is a property of the ENCODING, not of buffering** — see `LED-89.8` | `HLR-89.2` |
| P-9 | The local toolchain satisfies both floors | premise | ❌ FALSE in its rationale | `git version 2.49.0.windows.1`. **This machine holds TWO interpreters — conda `s19env` at `3.11.15` and base Anaconda at `3.12.7` — so it CAN demonstrate a floor violation, and rev53's was found by executing 3.11.15, never by analysis.** "Cannot demonstrate a violation" is the belief that left the syntax floor unmeasured while every measurement was taken on 3.12. Derivation from source stays obliged, but it is now the *second* method, not the only one — see `LED-89.22` | `HLR-89.4` |

| P-10 | batch-88's `decisions_log` froze on 2026-08-27 with no entry for increments 3 through 7, after the batch had already found and repaired the identical freeze | inherited from `05-close.md` §5 `G5-05` | ✅ TRUE | **REPRODUCED 2026-08-30 against the record itself.** `git show 0f40624:.dev-flow/state.json` -- the state as it stood at the merge -- holds **10 entries**, newest dated **2026-08-27**, and only two `decision` fields name an increment (1 and 2). Seven packets existed at that commit (`git ls-tree -r 0f40624`), so **increments 3, 4, 5, 6 and 7 were unlogged at merge time** | `HLR-89.6`; the arm `V27 HISTORIC-b88` replays exactly this |
| P-11 | batch-88 merged to `main` from station P3 with `04-validation.md` and `05-close.md` absent, and batch-89 merged Increment 1 to `main` from station P3 with the same two files absent | premise | ✅ TRUE, and it is the reason `HLR-89.6`'s second half is NOT the property that was asked for | `git ls-tree -r dde935c -- .dev-flow/` (the commit that first put batch-89's directory on disk): batch-88 held `01-requirements.md`, `01b-qa-validation-plan.md`, `02-review-security.md`, `PLAN.md` and seven packets, and **neither closing artifact**. `state.json` at the same commit declares `current_station: P3`. batch-89's own merge is `dde935c` under PR #204, at station P3, and is **correct** | `LED-89.14` -- the two are the same picture on disk, so no rule keyed on "below P4 with commits in `main`" can separate them |
| P-12 | A corpus-wide sweep for missing closing artifacts is unusable on this project | premise | ✅ TRUE | `os.listdir` over the 72 batch-shaped directories under `.dev-flow/`, 2026-08-30: **9 hold neither or only one** of `04-validation.md` / `05-close.md` / `05-postmortem.md` -- batches **25, 63, 66, 71, 73, 75, 78, 79, 85** | `LED-89.16`; `V28` judges the IMMEDIATE PREDECESSOR alone, and pays for it with a one-batch window |
| P-13 | `state.json`'s `decisions_log` is scoped to one batch and is reset when a batch opens | premise | ✅ TRUE by convention, ❌ VIOLATED right now | batch-88's log at `0f40624` holds 10 entries and **not one** of batch-87's, so the convention is real. The log on disk today still holds those same 10 batch-88 entries while `batch_id` reads `2026-08-28-batch-89` | `R-89-9`. This is why `V27` reports two `decisions_log` decisions naming increments with no packet on the live record: the finding is TRUE, and its subject is the rollover, not the rule |

**Gate rule:** ❌ and ❓ both block. `P-8` gated Story 2's increment and **that gate was
discharged by measurement, not by assumption** — reproduced before a line of the repair was
written, and its figure corrected in the same act (`LED-89.8`).

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
- **Ledger:** LED-89.8, LED-89.9
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
- **Acceptance test(s):** `ENC VERDICT-live` (a child `--selftest` under
  `PYTHONIOENCODING=cp1252`, asserting one `SELFTEST PASSED` line and an arm count at least
  this run's) · `ENC VERDICT-domain` (the verdict survives every non-ASCII canon character on
  5 stdout encodings) · `ENC UTF8-lossless` (utf-8 output stays byte-identical)
- **Negative control:** `ENC PASS!=NOOP` — the SAME probe text must still KILL an unhardened
  stream on all 4 non-utf-8 encodings, so the arms above cannot pass by the probe going ASCII.
  The RED side was observed before the repair: `P-8`, both surfaces.
- **Boundary catalog:** ☑ empty — stdout with no encoding declared · ☑ boundary — a codec that
  encodes every arm label but not the verdict line · ☑ invalid — cp1252 against `\u2212` · ☑
  error — stdout redirected to a pipe, which is the configuration that hid it.
- **Acceptance (black-box):** observable outcome — the operator on a default Windows console
  sees a verdict instead of a traceback · shipped surface — `devflow-validate.py --selftest`.

### HLR-89.3 — the flow names an interpreter that exists on this machine
- **Traceability:** Story 3
- **Ledger:** LED-89.10, LED-89.11, LED-89.12
- **Statement:** Every flow script executed by shebang shall name `python`, and `V17` shall
  verify that the guard's declared INTERPRETER **starts Python when executed**, in addition to
  verifying the guard's path.
- **Rationale (informative):** `python3` is not on `PATH` on Windows, so a guard wired to it is
  wired to nothing — and `V17` currently reports such a wiring as green.
- **Validation:** `test`
- **Executed verification:** the three shebangs and `install.py`'s generated hook command
  compared for agreement; `V17` driven through a real `settings.json` naming an interpreter
  that executes but is not Python
- **Numeric pass threshold:** the 3 shebangs and the generated hook command name **1** distinct
  interpreter; `V17` BLOCKs on an interpreter that runs without starting Python and SKIPs on
  one that starts Python. The CI site keeps `python3` by ruling (`LED-89.10`), so the threshold
  is agreement among the four LOCAL sites, not a global count of zero.
- **Priority:** high
- **Acceptance test(s):** `INT FOUR-PLACES-agree` · `INT WIRING-collects` (a real settings.json
  + on-disk guard + dead interpreter ⇒ 1 unrunnable and BLOCK; a live one ⇒ 0 and SKIP) ·
  `INT INTERP-parse` (5 command shapes) · `V17 BLOCK-unrunnable`
- **Negative control:** `INT RUNS!=IS-PYTHON` — a real executable that RUNS but is not Python
  must be refused. `INT ISFILE!=RUNS` alone is insufficient and was measured so: it reaches
  only the OSError branch, and a probe returning `True` unconditionally survived it
  (`LED-89.11`). `INT PASS!=NOOP` holds the other side, so the probe cannot pass by always
  refusing.
- **Boundary catalog:** ☑ empty — no interpreter named at all · ☑ boundary — an interpreter
  that resolves on PATH and executes but is not Python (the Store alias; exit 49) · ☑ invalid —
  a quoted interpreter path containing a space, which a whitespace split mangles into a false
  BLOCK (`LED-89.12`) · ☐ error — N/A: a malformed settings file is already `V17`'s own BLOCK
  and is not this requirement's class.
- **Acceptance (black-box):** observable outcome — the guard runs on a fresh Windows checkout ·
  shipped surface — the `UserPromptSubmit` hook.

### HLR-89.4 — the environment contract is declared and DERIVED, never asserted
- **Traceability:** Story 4
- **Ledger:** LED-89.2, LED-89.22
- **Statement:** The flow shall declare its environment contract as a canon row, and a rule
  shall derive that contract's floors from the source constructs that bind them.
- **Rationale (informative):** a floor written down by hand is a claim; a floor derived from
  the construct that raises it is a measurement that cannot rot.
- **Validation:** `analysis`
- **Executed verification:** the rule scans this file set for the binding constructs and
  compares what it finds against the declared row; **and, separately, the declared floor's
  interpreter is EXECUTED against the file set**, because the scan cannot see a syntax floor
- **Numeric pass threshold:** Python floor **3.11** — the declared floor is the lowest version
  the file set has been EXECUTED to parse and pass on (`3.11.15`, the gate env), not the
  lowest an AST walk permits. The **API floor is 3.7**, derived and recorded as a lower bound
  that is *documentary, never executed*: no interpreter below 3.11 exists on this machine, so
  3.7–3.10 is asserted by analysis alone and must say so. git floor **2.28.0** for a full
  selftest (bound by `git init -b`, reached by the selftest alone), third-party imports **0**;
  the rule BLOCKs when the declared row and the derived values disagree
- **Two derivations, not one (rev54):** the rule owes BOTH — (a) **stdlib-API floor**, an AST
  walk for version-gated constructs, and (b) **SYNTAX floor**, which an AST walk on the
  running interpreter *structurally cannot see*, because it only ever sees what already
  parsed. `ast.parse(feature_version=)` is NOT a substitute: measured 2026-08-31, it accepts
  the rev53 PEP 701 construct at every version 3.7 through 3.12, while `s19env`'s real 3.11.15
  refuses it with `SyntaxError: unterminated string literal`. A claimed floor must name the
  interpreter that REFUSES the version below it, or be labelled documentary. See `LED-89.22`.
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

### HLR-89.6 — the record is checkable against the work, and a batch is closed before it is superseded
- **Traceability:** Story 6
- **Ledger:** LED-89.14, LED-89.15, LED-89.19
- **Statement:** The flow shall report, at every gate, whether `state.json`'s `decisions_log`
  corresponds to the increments on disk in both directions and is no older than the newest
  commit touching the batch directory, and whether the batch a newer batch superseded holds
  its validation and close artifacts.
- **Rationale (informative):** `V18` checks that the batch is DECLARED and stops there, so a
  frozen ledger and a current one are the same picture to every rule that ships; batch-88 shows
  the cost twice in one batch.
- **Validation:** `test`
- **Executed verification:** `--selftest` arms `V27 HISTORIC-b88` and `V28 HISTORIC-rollover`,
  each replaying the real record as it stood at the commit that made the defect permanent, plus
  `V27 LIVE-agree` and `V28 LIVE-agree` over the live corpus
- **Numeric pass threshold:** 47 `V27`/`V28` arms report `ok`; `HISTORIC-b88` reports
  increments 3-7 unlogged and a ledger one day behind its own merge; `HISTORIC-rollover`
  reports batch-88 superseded holding neither closing artifact
- **Priority:** high
- **Acceptance test(s):** `owed at Increment 6` — the same `V2` constraint `R-89-7` records
- **Negative control:** executed — `M6-registered-noop` and `N9-registered-noop` (`return []` on
  each rule's outcome path) redden 6 and 3 arms respectively and NO core arm.
- **Boundary catalog:** ☑ empty — a batch with no packets and no log entries · ☑ boundary — a
  ledger dated exactly the day of the newest commit, which is NOT behind · ☑ invalid — a batch
  directory name that is not batch-shaped · ☑ error — the flow run outside a git repository,
  where currency cannot be checked and must not report a pass.
- **Acceptance (black-box):** observable outcome — the gate prints the freeze instead of
  staying silent about it · shipped surface — `devflow-validate.py`'s gate output.

**What `HLR-89.6` deliberately does NOT say, and the reason is `P-11`.** It does not say *a
batch shall not reach `main` below station P4*. That property is not checkable from the data on
disk: batch-88's defective merge and batch-89's correct one are the same picture at the instant
each happened. What separates them is SUPERSESSION, which arrives later. `LED-89.14` states the
reformulation, what it costs, and what was refused.

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

### LLR-89.6.1 — coverage is a correspondence, not a membership test
- **Traceability:** HLR-89.6
- **Ledger:** LED-89.13
- **Statement:** The rule shall report every increment packet on disk that no `decisions_log`
  DECISION names, and every increment a decision names that has no packet, as two findings with
  two sentences, and shall not read the `notes` field.
- **Validation:** `test`
- **Executed verification:** arms `V27 UNLOGGED`, `V27 UNPACKETED`, `V27 BOTH-WAYS`,
  `V27 NOTES-DONT-COUNT`, `V27 HISTORIC-b88`, and the six `V27 harvest-*` grammar arms
- **Numeric pass threshold:** 12 arms report `ok`. `NOTES-DONT-COUNT` is the discriminating
  one: its fixture is batch-88's real P0 entry, whose NOTES name increments 1 to 4 while its
  DECISION names none, so a harvest over `notes` reports increments 3 and 4 logged on the exact
  record this rule exists to have caught
- **Negative control:** executed — `M1-harvest-notes` reddens `NOTES-DONT-COUNT` and
  `HISTORIC-b88`; `M2-unpacketed-silent` and `M14-packets-ignored` each redden one direction
  while leaving the other green, which is what proves they are two obligations.
- **Boundary catalog:** ☑ empty — an empty `decisions_log` with packets on disk · ☑ boundary —
  a decision naming an increment number that exists and one that does not, in one log ·
  ☑ invalid — `reincrement 4`, which is not a reference · ☑ error — `Increment 007`, whose
  zero padding must resolve to the same packet as `increment-007.md`.

### LLR-89.6.2 — currency is measured against the work, and its absence is not a pass
- **Traceability:** HLR-89.6
- **Ledger:** LED-89.17
- **Statement:** The rule shall compare the newest `decisions_log` date against the date of the
  newest commit touching the batch directory, shall treat equality as current, and shall report
  git being unaskable and the batch having no commit yet as two DIFFERENT unchecked states,
  neither of which is the pass sentence.
- **Validation:** `test`
- **Executed verification:** arms `V27 STALE`, `V27 CURRENCY-EQUAL`, `V27 CURRENCY-AHEAD`,
  `V27 CURRENCY-MAX-NOT-LAST`, `V27 NOGIT`, `V27 NOCOMMIT`, `V27 NODATE`,
  `V27 CAUSES-DISTINCT`, `V27 E2E-git-date`
- **Numeric pass threshold:** 9 arms report `ok`; `E2E-git-date` builds a repository, commits
  the batch directory, and asserts the rendered date equals the one it reads from `git log`
  itself — twice, on a log dated with that date and on one dated 2000-01-01 — so the arm holds
  no calendar literal and cannot rot
- **Negative control:** executed — `M3-currency-off-by-one` (`<` → `<=`) reddens 10 arms;
  `M4-oldest-not-newest` reddens `CURRENCY-MAX-NOT-LAST`; `M8-no-pathspec` reddens
  `E2E-git-date` alone; `M9-causes-collapse` and `M13-malformed-date-accepted` each redden one.
- **Boundary catalog:** ☑ empty — a log whose entries carry no parseable date · ☑ boundary —
  a log dated exactly the commit's day · ☑ invalid — a date written `26/08/2026` · ☑ error —
  a directory that is not a git repository at all.

### LLR-89.6.3 — the subject is the batch that was superseded, never the active one
- **Traceability:** HLR-89.6
- **Ledger:** LED-89.16
- **Statement:** The rule shall judge the batch-shaped directory immediately preceding the
  active one by date and by batch NUMBER, shall accept `05-postmortem.md` beside
  `05-close.md`, and shall judge no other batch.
- **Validation:** `test`
- **Executed verification:** arms `V28 PRED-complete`, `V28 PRED-missing-both`,
  `V28 PRED-missing-04`, `V28 PRED-missing-05`, `V28 POSTMORTEM-COUNTS`, `V28 FIRST`,
  `V28 NO-ACTIVE`, `V28 GHOST-ACTIVE`, `V28 ORDER-numeric`, `V28 HISTORIC-rollover`
- **Numeric pass threshold:** 10 arms report `ok`. `PRED-complete` is the discriminating one:
  its fixture holds a COMPLETE predecessor between an incomplete older batch and an incomplete
  ACTIVE batch, so a corpus-wide sweep reports the older one, a rule reading the active batch
  reports batch-89's correct by-design state, and only the predecessor reading passes
- **Negative control:** executed — `N2-judges-the-active-batch` reddens 9 arms,
  `N3-judges-the-earliest` 8, `N10-holds-of-the-wrong-batch` 8; `N4-one-close-name` reddens
  `POSTMORTEM-COUNTS`; `N1-lexical-order` reddens `ORDER-numeric` alone.
- **Boundary catalog:** ☑ empty — an active batch that is the earliest on disk · ☑ boundary —
  two batches sharing a date whose numbers order differently lexically and numerically ·
  ☑ invalid — an active id naming `design/`, which is not batch-shaped · ☑ error — `.dev-flow/`
  holding loose `.md` files and non-batch children, which no listing may admit.

### LLR-89.6.4 — both rules are armed as REGISTERED, and against the real record
- **Traceability:** HLR-89.6
- **Ledger:** LED-89.18
- **Statement:** Each rule shall be exercised through the registry over a real directory tree,
  and at least one arm per rule shall re-derive its expected answer from the live corpus rather
  than compare it against a typed one.
- **Validation:** `test`
- **Executed verification:** arms `V27 E2E-clean`, `V27 E2E-frozen`, `V27 E2E-nolog`,
  `V27 E2E-plan-not-a-packet`, `V27 E2E-git-date`, `V28 E2E-pass`, `V28 E2E-notice`,
  `V27 LIVE-agree`, `V28 LIVE-agree`, `V28 ORDER-agrees-today`
- **Numeric pass threshold:** 10 arms report `ok`; the two `LIVE-agree` arms recompute the
  expected findings from `state.json`, `git log` and the directory listing and assert AGREEMENT
  with the registered rule, so neither rots when a batch opens
- **Negative control:** executed — `M6-registered-noop` reddens 6 arms and `N9-registered-noop`
  3, and NO core arm moves in either case.
- **Boundary catalog:** ☑ empty — a tree with no ledger at all · ☑ boundary — a tree holding
  `00-increment-plan.md`, which is not a packet · ☑ invalid — a `.dev-flow/` carrying
  `design/`, `tools/` and loose HANDOFF files · ☑ error — a real repository, so the git path is
  executed and not modelled.

### LLR-89.6.5 — a declared batch id resolves to a direct child of `.dev-flow/`, or to nothing
- **Traceability:** HLR-89.6
- **Ledger:** LED-89.20, LED-89.21
- **Statement:** `_active_batch_state` shall resolve a declared `batch_id` to an absolute path
  whose parent directory is `.dev-flow/` itself, shall return no path and a distinct fifth
  reason code when the declared id names anything else, and shall be the only place in the file
  where that test is made — the quantified population being every call site that reaches a
  declared `batch_id`, of which there are seven.
- **Validation:** `test`
- **Executed verification:** arms `ART A9-dot`, `ART A9-dotdot`, `ART A9-nested`,
  `ART A9-trailing-sep`, `ART A9-freeze-noop`, `V18 notchild`, `V18 notchild-SENTENCE`,
  `V18 CAUSES-differ`, `V18 TRAVERSAL-notice`, `V18 TRAVERSAL-up`, `V27 GUARD-traversal`,
  `V27 GUARD-currency`
- **Numeric pass threshold:** 12 arms report `ok`. Three of them carry the whole claim and the
  other nine are their controls. `A9-freeze-noop` compares the map `_artifacts` returns against
  the map rev51's caller-side guard produced, over **7** declared ids, values included — it is
  the arm that had to pass before the freeze could be lifted, because `LLR-88.5`'s acceptance
  froze `_active_batch_dir` precisely to hold that map still. `V27 GUARD-traversal` reaches the
  registered rule over a tree whose `03-increments/` sits BESIDE `.dev-flow/`, and asserts the
  finding COUNT of 3 before asserting that increment 42 is named nowhere. `V27 GUARD-currency`
  asserts the OTHER half of the same rule: the currency sentence must refuse to check rather
  than render the whole tree's newest commit.
- **Negative control:** executed — `M5-code-only` returns the poisoned path alongside the new
  code, so `V18` announces the traversal while every caller still receives it, and it reddens
  the packet and `_active_batch_dir` conjuncts while leaving `V18` green; `M2-cheap-dotdot`
  substitutes the substring test batch-88 measured agreeing by accident; `M3-no-abspath` runs
  the test on the unnormalised join, where `..` collapses to a direct child; `M1-guard-off`
  restores rev51 exactly. Full battery and verdicts in `LED-89.21`.
- **Boundary catalog:** ☑ empty — an id of `"."`, which names `.dev-flow/` itself and is the
  case that EXISTS and is not a batch · ☑ boundary — `"z/"`, a legitimate batch wearing one
  trailing separator, which must resolve rather than be refused · ☑ invalid — `"a/03-increments"`,
  the NESTED id that is the only member of the domain separating a direct-child test from the
  cheaper `".." in active`; `"."` and `".."` agree with the cheap test by accident · ☑ error —
  `"../.."`, which walks out of the project.

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

**Mutation, Increment 6.** 25 named single-edit mutants of `V27` and `V28`, run in a MIRRORED
flow tree (`docs/tools/` plus `hooks/`, because rev49's `INT FOUR-PLACES-agree` arm reads three
sibling scripts by walking up from `__file__`); no live file was mutated. The broken-floor is
the run's own baseline arm count and the kill criterion is the SET of failing arm labels
GROWING, never the FAIL count. **Baseline: 490 arms, zero red. 24 killed, 1 survived, 0 broken.**
The survivor is recorded EQUIVALENT by execution rather than chased — see `LED-89.18`.

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
| **R-89-9** | **`state.json`'s `decisions_log` was not reset when batch-89 opened.** It still holds batch-88's ten entries while `batch_id` reads `2026-08-28-batch-89`, so the live gate reports *2 `decisions_log` decision(s) name an increment with no packet on disk -- increment(s) 1, 2* | **Registered, and the finding is TRUE.** `P-13` shows the per-batch convention is real — batch-88's log carries not one batch-87 entry — so the log describes work that is not this batch's. The repair is in `state.json`, which this increment does not own and did not touch; it is one line of the rollover procedure in `dev-flow.md`, and is a batch-90 candidate. **Reported rather than silenced: suppressing the direction that fires would be discarding the half that measured the defect** |
| **R-89-10** | **The property "a batch does not reach `main` below station P4" is NOT implementable as stated, and `V28` is not it.** `P-11` measures why: batch-88's defective merge and batch-89's correct one are the same picture on disk | **Stated as a finding, not shipped as a rule.** What shipped is the separable property — closure before supersession — which fires ONE STATION LATE, has a ONE-BATCH window, and never looks at a commit. All three costs are written into the rule's own block comment and into `LED-89.14`. A rule keyed on the station and the merge would be red on batch-89 today, on correct work |
| **R-89-3** | The template's own preamble is 38,687 chars written in the register this batch is removing from records | Out of scope, deliberately. Those blocks are normative rules whose parenthetical origins are their evidence; moving them is a second reform needing its own increment and its own ledger |
| **R-89-4** | **CLOSED 2026-08-29** — `P-8`, the cp1252 crash, has been reproduced | Reproduced on two surfaces before any repair was written, and the premise's figure was corrected by the same measurement (`LED-89.8`) |
