# Requirements ledger — s19_app — 2026-08-28-batch-89

> **Append-only.** Entries are added in chronological order and never rewritten, never
> renumbered, never deleted. An entry that turns out wrong is superseded by a NEW entry that
> names it. The live contract is `01-requirements.md`; this file records how it came to say
> what it says. Every entry names the requirement it amends; every requirement names its
> entries. `V26` compares the two sets of pairs in both directions and BLOCKs on any pair
> present on one side only.
>
> This file lives under `.dev-flow/` deliberately: writing an id here DECLARES it to the
> corpus scanner, so traceability survives the split (C-56).

### LED-89.1 — the split alone is not the fix, and the pairing is what makes it safe
- **Requirement:** HLR-89.1, LLR-89.1.3
- **Date:** 2026-08-28
- **What changed:** the requirements record became two documents — an editable live contract
  and this append-only ledger — and `V26` was written to enforce the split, the current-state
  check and the both-ways link.
- **Why:** moving the findings table and the forensic prose out of batch-88's record is a
  **35% cut and not a fix**: the remaining 65.3% is normative text written in the forensic
  register, requirements whose justification sits inside the normative sentence. Splitting
  files does not separate a sentence from its reason; splitting the sentence does. And a
  naive split into two EDITABLE files does not reduce the defect surface — it adds one,
  because the two disagree. That is `R-88-17`, batch-88's most repeated defect at 8+
  instances, rehoused rather than closed. What closes it is that the population **is**
  enumerated: every (requirement, entry) pair is declared on both sides and compared as a
  PAIRING. A count, a membership test, or "every id in the ledger exists" each discards the
  pairing, which is exactly where the failure lives — the argument `V15` already makes about
  the bundle.
- **Evidence:** batch-88 record decomposition (findings 8.1% · forensic prose 26.6% ·
  normative remainder 65.3%, operator's measurement); arm `V26 PAIR-crossed`, whose fixture
  holds identical requirement-id and entry-id sets on both sides and swaps only the pairs —
  every membership oracle reports a clean pass on it.

### LED-89.2 — the citations anchor on symbols, because this increment moved the lines
- **Requirement:** HLR-89.4
- **Date:** 2026-08-28
- **What changed:** the environment contract's two binding citations are written as SYMBOLS
  rather than as `file:line`.
- **Why:** the operator's brief cited `git init -b` at `devflow-validate.py:5299`. That
  citation was **correct when it was written and stale by the time it was checked**, because
  this increment inserted the `V26` rule and its arms above it. Measured 2026-08-28: the
  construct now sits at `:5527`, exactly 228 lines lower, inside the V25 fixture builder in
  `selftest()`. This is `R-88-9` — a `file:line` citation into a file the batch itself EDITS
  is stale by construction — reproduced by the very brief that registered it.
- **Evidence:** `grep -n '"init"'` returns `3988` and `5527`; the `-b main` form is the
  second. `capture_output=` with `text=` resolves at `:572-573`, inside `v8_module_map`, and
  is unmoved because this increment inserted below it.

### LED-89.3 — the budget's number is chosen from the corpus and lives only in the code
- **Requirement:** HLR-89.1, LLR-89.1.1
- **Date:** 2026-08-28
- **What changed:** `_LEAN_MAX_CHARS` was set to 55,000 and both budget sentences render it.
- **Why:** `R-88-19` — a measurement written into the record is not a constraint unless
  something checks the implementation against it. A figure restated in a record is a second
  copy that can drift silently, so the record cites the SYMBOL and holds no copy of the value.
  The number itself is chosen from evidence rather than taste: the 65 `01-requirements.md`
  records under `.dev-flow/`, measured 2026-08-28, have a MEDIAN of 55,367 chars, and the
  budget is that median rounded down to 55,000. Half the records this flow has ever produced
  already sit under it, so the budget cannot be accused of demanding a shape the flow has
  never reached. It is NOTICE and never BLOCK: a long record is a fact about a batch's week,
  not a defect in its content.
- **Evidence:** `n=65 median=55367`, p25 37,789 · p75 89,790 · max 322,289, `python` over
  `glob('*/01-requirements.md')`, 2026-08-28. Arms `V26 BUDGET-renders-const` (the sentences
  render the threshold PASSED IN, never a literal) and `V26 BUDGET-constant` (the constant is
  55000). Mutant `M5-constant-widened` (55000 → 550000) killed by 3 arms.

### LED-89.4 — the register is not policed, and that is a ruling rather than an omission
- **Requirement:** LLR-89.1.2
- **Date:** 2026-08-28
- **What changed:** `V26`'s current-state check is Markdown strikethrough and nothing else. It
  does not forbid the warning glyph, nor the words "superseded", "amended" or "measured".
- **Why:** `R-88-16` — a token stream has a grammar to derive a class from and prose does not,
  so a prose claim is pinnable by typed equality and never by forbidding what it may not say.
  `~~x~~` is a Markdown DELIMITER and therefore has a grammar; text that is present and void
  at once is exactly the two-states-at-once shape the lean contract removes. A vocabulary
  guard, by contrast, would kill the wordings someone thought of and no others — and would
  false-fail correct work, which is C-53's expensive failure.
- **Evidence:** measured over all 65 records, 2026-08-28: **16 carry the warning glyph, 10
  carry strikethrough**. Inspection of the glyph's sites shows it marking warnings that ARE
  current state at least as often as amendments. Whether a normative sentence carries its own
  justification therefore remains a reviewer's judgement and a Phase-2 blocker class, stated
  in the template rather than mechanised badly.

### LED-89.5 — the budget was derived in BYTES and enforced in CHARACTERS
- **Requirement:** HLR-89.1, LLR-89.1.1
- **Date:** 2026-08-28
- **Supersedes:** `LED-89.3`, whose figures and whose 55,000 floor are wrong. **That entry is
  left standing exactly as written** — this ledger is append-only, so a wrong entry is
  corrected by a new one that names it, never by a rewrite. Read `LED-89.3` as history and
  this entry as current state.
- **What changed:** `_LEAN_MAX_CHARS` moved from 55,000 to **54,000**, and it is no longer
  typed: it is computed by `_lean_budget_from(...)` from a recorded median, with the flooring
  rule expressed in code rather than in prose.
- **Why:** the four quantiles justifying 55,000 were computed with `os.path.getsize` — BYTES —
  while `_v26_outcome` measures `len(text)` — CHARACTERS. The corpus is UTF-8 with multi-byte
  punctuation throughout, so the two disagree by ~1,000 at the median, which is a whole
  flooring step: the honest floor was 54,000 and the shipped one was 55,000. **This is
  `R-88-19` in its purest form** — four figures written into a record with nothing comparing
  them to the implementation — and the arm that should have caught it, `BUDGET-constant`,
  compared the literal `55000` against the literal `55000`. It was flagged as vacuous in the
  first draft and kept anyway; **flagging an arm as vacuous is not the same as replacing it,
  and there was a real defect behind this one.**
- **Evidence:** measured 2026-08-28 over the 65 records predating batch-89 —
  CHARS median 54,367 (p25 37,006 · p75 87,505 · max 314,621); BYTES median 55,367 (p25
  37,789 · p75 89,790 · max 322,289); 32 of 65 sit at or under 54,000. The population
  self-excludes batch-89's own record, the 66th, because including the subject would let the
  rule move its own threshold — stated here rather than left silent. Arms
  `V26 BUDGET-derivation` (re-derives the median-floor over five supplied size lists) and
  `V26 BUDGET-chars-not-bytes` (pins the unit).

### LED-89.6 — the strikethrough span may not cross a blank line
- **Requirement:** LLR-89.1.2
- **Date:** 2026-08-28
- **What changed:** `_LEAN_STRIKE` gained a blank-line bound —
  `~~(?=\S)(?:(?!\n[ \t]*\n).)+?(?<=\S)~~`.
- **Why:** the first cut was unbounded `re.S`, so the opening `~~` of one span paired with a
  closing `~~` paragraphs away. Two consequences, and the second is worse than the first:
  the BLOCK quoted innocent prose from a different section, and **any record that merely
  SHOWS the canonical `~~this~~` as an example BLOCKed outright** — the rule eating its own
  documentation as a delimiter. batch-89's own record escaped only by the accident of a space
  inside its example.
- **Evidence:** measured over all 66 records, 2026-08-28: **81 spans before and 81 after**,
  zero of them crossing a blank line; batch-88's 47 spans all retained, 2 of which are
  genuinely multi-line, so the wrap case is still exercised by the real corpus and not only by
  a fixture. Arm `V26 STRIKE-blank-line` asserts both halves — a span never crosses a blank
  line, and an intra-paragraph wrap still matches.

### LED-89.7 — six fields ruled, three returned and three retired
- **Requirement:** HLR-89.1
- **Date:** 2026-08-28
- **What changed:** `req-template.md`'s requirement field set. **Returned as live and
  mandatory:** `Boundary catalog` (scoped, explicitly, to every requirement whose `Validation`
  is `test`/`analysis` — HLR or LLR alike, because the catalog exists to generate cases for an
  arm and an `inspection` requirement has no arm to generate them for), `Acceptance test(s)`
  (with `owed at <increment>` as the declared empty), and `Negative control` (its own named
  slot). **Retired:** `Acceptance criteria (informative, complementary)`, `Deliverable +
  observation`, and the §5.2 dual-traceability TABLES.
- **Why:** the operator's criterion, measured: **of the six fields, only two change what gets
  TESTED.** The other four describe or justify, and their home is this ledger. `Boundary
  catalog` is the most load-bearing of the six because it is GENERATIVE rather than descriptive
  — each ticked class is an arm somebody owes — at 9 instances and 6,182 chars in batch-88.
  `Acceptance test(s)` is 896 chars for 9 ids, 0.5% of that record, and buys traceability.
  `Negative control` was inline in **9 of 10** thresholds, meaning exactly one requirement had
  no RED side **and nothing said so**; *a test that cannot fail is vacuous* is this flow's
  central doctrine, and a doctrine carried by convention is carried by nobody. Against that:
  `Acceptance criteria` was **5.6% of batch-88's record** and self-declared informative;
  `Deliverable + observation` restated `Validation` plus `Executed verification`; and the
  traceability tables transcribed the `Traceability` field, populated in **10 of 10** measured
  — a second copy of one truth, which is the shape this flow has paid for repeatedly.
- **Evidence:** the retirement reasons are written INTO `req-template.md` at the point of
  removal, never silently deleted, so a reader meeting the gap finds the argument. **The three
  returned fields are mandatory and enforced by no rule — `R-89-8` says so rather than letting
  the word "mandatory" imply a check that does not exist.**
### LED-89.8 — `P-8` was reproduced before it was repaired, and the reproduction corrected it
- **Requirement:** HLR-89.2
- **Date:** 2026-08-29
- **What changed:** `P-8` moved from ❓ UNDECIDABLE to a measured result, and its figure
  changed. The premise claimed the crash emits **zero arms**; the crash emits **whatever the
  encoding allows before it meets a character it cannot carry**.
- **Why:** repairing an unobserved defect repairs the wrong thing. Two surfaces were run
  before any code was written. `PYTHONIOENCODING` unset with stdout redirected to a file:
  exit 1, `UnicodeEncodeError: 'charmap' codec can't encode character '\u2212'`, **12 arm
  lines on disk**, no verdict. `PYTHONIOENCODING=ascii`: exit 1 on `\u00b7` — the separator
  in every arm line — inside the FIRST arm, **0 arm lines**, no verdict.
- **Evidence:** the operator's two conflicting measurements (zero arms; ~12 arms) are **both
  correct and neither is about buffering**, which was the stated cause. Python flushes the
  text buffer at interpreter shutdown even after the exception, so the bytes already encoded
  do reach the file. What differs is the ENCODING: cp1252 carries `\u00b7` and dies later at
  `\u2212`; ASCII carries neither and dies at the first line. **The load-bearing half of
  `P-8` — exit 1 with no verdict line, indistinguishable from a genuine failure — held on
  both.** This is why the arms use a domain of 5 encodings: one encoding is not a domain, and
  this defect demonstrates that rather than illustrating it.

### LED-89.9 — the repair is at the stream, not at the fixture, and the corpus figure was wrong
- **Requirement:** HLR-89.2
- **Date:** 2026-08-29
- **What changed:** the fix reconfigures stdout/stderr's ERROR HANDLER to `backslashreplace`
  at `__main__` (`_harden_streams`), rather than ASCII-ing the V5 ledger fixture that holds
  the `\u2212`. The consumer's ENCODING is deliberately not overridden.
- **Why:** the fixture's `\u2212` is the character that fires today, not the class. Forcing
  `encoding=utf-8` would end the crash by writing bytes a cp1252 reader misreads — trading a
  loud failure for a quiet corruption. Changing only `errors` keeps a capable stream
  byte-identical (`ENC UTF8-lossless`) and gives an incapable one a readable `\u2212`.
- **Evidence:** the corpus figure in the increment's brief — **601 non-cp1252 characters of 6
  kinds** — did not reproduce. Measured 2026-08-29 over the 22 canon rows of
  `docs/FLOW-VERSION.md`: **534 non-cp1252 characters of 28 distinct kinds**, and against an
  ASCII stdout the real domain is **2511 non-ASCII characters of 38 kinds**. (Sweeping canon
  **plus** the generated bundle mirror gives 1310 of 34 kinds, which is the likeliest origin
  of the 601 — a double count of a duplicated tree.) An arm asserting the fixture contains no
  `\u2212` would pin one instance of a 38-member class; `ENC VERDICT-domain` harvests its
  probe FROM the canon instead, so a new character entering any canon file enters the arm
  with it.

### LED-89.10 — the CI site keeps `python3`, and that asymmetry is the ruling
- **Requirement:** HLR-89.3
- **Date:** 2026-08-29
- **What changed:** `HLR-89.3`'s threshold stopped being *0 remaining `python3` sites*. Three
  shebangs changed to `python`; `.github/workflows/flow-selftest.yml:40` **keeps** `python3`.
- **Why:** that job runs on `ubuntu-latest`, where `python3` is the correct name and a bare
  `python` may not exist. The brief's own caution — do not break CI to fix Windows — is
  incompatible with a global count of zero. **The GitHub runner's provision of `python` was
  NOT measured** (no runner is reachable from here), and an unmeasured premise is not a
  licence to change a working CI line.
- **Evidence:** the correction has a population, so it was swept (`R-88-17`). Live `python3`
  claims outside this batch's own new prose: `FLOW-VERSION.md:10` (V17's row) and
  `flow-selftest.yml:57` (V17's description) — both updated; `flow-selftest.yml:40` — kept,
  with a comment saying why so a later reader does not "unify" it; `FLOW-VERSION.md:202` —
  historical changelog prose quoting the lessons catalogue, correctly untouched. **The
  selftest therefore asserts that the four LOCAL sites agree with each other and never that a
  given name runs**, which is what makes the asymmetry safe: `INT FOUR-PLACES-agree` is true
  on both platforms.

### LED-89.11 — "resolves" was the wrong verb, and a surviving mutant is what proved it
- **Requirement:** HLR-89.3
- **Date:** 2026-08-29
- **What changed:** `HLR-89.3` said `V17` must BLOCK on an interpreter that *does not
  resolve*. It now says *does not start Python when executed*, and `_interpreter_runs`
  executes the token and reads back a marker.
- **Why:** resolving is exactly what the defect passes. Measured on this machine: `python3`
  resolves to the Microsoft Store alias in `WindowsApps` — a real file, on PATH, that
  `shutil.which` reports and `os.path.isfile` confirms — which prints "Python was not found"
  and **exits 49**. Executing `hooks/flow-guard.py` through its own shebang exited **49**. A
  rule written to the old verb would have called that machine green.
- **Evidence:** the first version of the arm used a temp text file as the dead interpreter.
  That fixture is not executable, so `_interpreter_runs` refuses it from the `OSError` branch
  and never evaluates its return expression — and the mutant replacing that expression with
  `return True`, which restores the original defect exactly, **SURVIVED the full selftest**.
  `INT RUNS!=IS-PYTHON` was added with a real program discovered at runtime (`git` here), and
  the collector fixture in `INT WIRING-collects` was switched to it. 13 of 13 mutants killed
  afterwards, against a GREEN baseline — the first harness run had a red baseline and its
  "kills" were discarded rather than reported.

### LED-89.12 — getting the interpreter WRONG is the same rule lying in the other direction
- **Requirement:** HLR-89.3
- **Date:** 2026-08-29
- **What changed:** `_cmd_tokens` was added so a QUOTED span in a hook command stays whole,
  and `_guard_interpreter` uses it. `_guard_path_resolves` is untouched.
- **Why:** the existing tokenizer splits on whitespace and discards quotes, which is harmless
  for asking whether some token ends in `flow-guard.py` and not harmless for naming the
  interpreter. The default Windows install lives under `C:\Program Files\...`, so the
  correctly quoted command `"C:/Program Files/Py/python.exe" ~/.claude/hooks/flow-guard.py`
  yielded an interpreter of `Files/Py/python.exe` — which cannot run, so the NEW `V17` would
  have BLOCKed a perfectly wired machine. That is the `C-53` false fail, on the one rule whose
  BLOCK stops the flow, for most of Windows.
- **Evidence:** found by `INT INTERP-parse` failing on its own author's expected value, before
  the increment closed — the arm was written with `C:/Program` as the expectation and the run
  returned `Files/Py/python.exe`. A quoted GUARD path was added to the same domain so a space
  on either side is covered, taking it to 5 command shapes.

---

### LED-89.13 — the harvest reads the decision and never the notes, and the real record is why
- **Requirement:** LLR-89.6.1
- **What changed:** the coverage harvest was scoped to the `decision` field of each
  `decisions_log` entry. `notes` is not read.
- **Why, measured:** the wide harvest is the obvious first cut and it is wrong on the only
  record that matters. batch-88's P0 entry at `0f40624` carries the notes *"PDR-2026-08-24-
  batch-88 sealed in the vault, verdict approved with conditions: authorises Inc 1 and Inc 2,
  WITHHOLDS Inc 3 and Inc 4 until #D1 lands."* — prose about a design review that had not
  authorised the work yet. Harvesting it reports increments 3 and 4 LOGGED. The narrow harvest
  reports `{3, 4, 5, 6, 7}` unlogged, which is what `05-close.md` §5 `G5-05` recorded.
- **What this cost:** a fixture whose `decision` and `notes` agree cannot tell the two
  harvests apart, so `NOTES-DONT-COUNT` had to be built from that entry rather than typed.
  `M1-harvest-notes` reddens exactly two arms — `NOTES-DONT-COUNT` and `HISTORIC-b88` — and
  every other coverage arm stays green under it.

### LED-89.14 — "below P4" is not implementable, and saying so is the deliverable
- **Requirement:** HLR-89.6
- **What changed:** the second half of the batch's Story 6 was NOT implemented as asked. The
  rule that shipped, `V28`, checks closure before SUPERSESSION.
- **Why, measured:** two merges, both from station P3, both with `04-validation.md` and
  `05-close.md` absent from the batch directory:

  | | batch-88 | batch-89 |
  |---|---|---|
  | merge | `0f40624`, PR #203, 2026-08-28 07:27 | `dde935c`, PR #204, 2026-08-29 12:08 |
  | station at merge | `P3` | `P3` |
  | `04` / `05` on disk | absent / absent | absent / absent |
  | verdict | **defect** | **correct — the batch ships increment by increment** |

  Every field a local rule can read is identical. A rule reading *"any batch commit in `main`
  while station < P4"* is RED ON BATCH-89 TODAY, on correct work, which is C-53's false-fail
  and worse than no rule at all.
- **What separates them, and when:** batch-88's merge was not the defect. The defect was that
  the batch was ABANDONED at that station and a newer batch directory opened beside it. That
  is the instant the hole became permanent, mechanically: `state.json` is SINGLE-SLOT, so once
  `batch_id` moved to batch-89, `/dev-flow-sync` and every other tool that reads *"the batch"*
  could no longer see batch-88. Its `04-validation.md` and `05-close.md` were written by hand
  on 2026-08-29, a day late, and both say so at the top.
- **What it costs, written into the rule rather than discovered later:** `V28` fires ONE
  STATION LATE — the rollover is the earliest instant at which the two pictures differ, and it
  is after the merge; it never looks at a commit; and it has a one-batch window (`LED-89.16`).
  A validator cannot block a merge in any case, so the choice was never between blocking and
  firing late — it was between firing late and firing on correct work.

### LED-89.15 — NOTICE, and the third reason is the one that decides it
- **Requirement:** HLR-89.6
- **What changed:** both rules report at `NOTICE`, never `BLOCK`, in every state.
- **Why:** (a) `state.json` is the flow's own bookkeeping and no increment owns it, so a BLOCK
  would stop the very commit whose act of writing clears it — this increment does not own that
  file and could not have cleared its own block; (b) a project whose log does not use this
  flow's decision wording would BLOCK at every gate forever; (c) **the defect being closed is
  INVISIBILITY, not permission.** batch-88's freeze was never blocked by anything and never
  needed to be. It needed to be SEEN. A line printed at every gate is the whole repair.
- **The honest limit of that ruling:** `run()` returns non-zero only on BLOCK, so neither rule
  fails the gate's exit code, and `hooks/flow-guard.py` runs `V7`, `V15` and `V16` alone. What
  these rules buy is a sentence in front of a reader at every gate — which is exactly what was
  missing twice — and not an enforcement.

### LED-89.16 — the one-batch window is bought with a measurement
- **Requirement:** LLR-89.6.3
- **What changed:** `V28` judges the IMMEDIATE PREDECESSOR of the active batch and no other.
- **Why, measured 2026-08-30:** of the 72 batch-shaped directories under `.dev-flow/`, **nine**
  hold neither or only one of `04-validation.md` / `05-close.md` / `05-postmortem.md` —
  batches 25, 63, 66, 71, 73, 75, 78, 79 and 85. A corpus-wide sweep therefore prints nine
  notices about closed history at every gate for the rest of the project's life, and a rule
  nobody can act on is a rule nobody reads.
- **What it costs:** two unclosed rollovers in a row and the older batch is never judged again.
  Stated rather than left to be discovered.
- **Two things the ordering had to get right, and only one of them is visible today:** the
  predecessor is chosen by `(date, batch NUMBER as an int)`. Over the real corpus lexical order
  AGREES, because every batch number is two digits — `ORDER-agrees-today` asserts that, and it
  is why `ORDER-numeric` must be synthetic: `2026-09-01-batch-10` sorts before
  `2026-09-01-batch-9` lexically, which would make a batch its own successor's predecessor.
  `05-postmortem.md` counts as the close artifact beside `05-close.md` because both names are
  live in the corpus; accepting one would report batch-85's real close as absent.

### LED-89.17 — currency needs git, and its two absences are not one absence
- **Requirement:** LLR-89.6.2
- **What changed:** the currency half asks git for the newest commit touching
  `.dev-flow/<batch>/` and compares dates as `YYYY-MM-DD` strings.
- **Why the pathspec is load-bearing:** without it the question becomes *"when was this
  repository last committed to"*, which is a different and always-fresher number.
  `M8-no-pathspec` reddens `E2E-git-date` and nothing else, so that arm is the only thing
  standing between the rule and a question it was not asked.
- **Why two absences and not one:** `_git` returns `None` when git is absent, times out or
  fails, and the EMPTY STRING when it ran and matched nothing. Those are opposite states — an
  unchecked obligation versus a checked one with nothing to be behind — and Increment 3 of this
  batch already paid for collapsing two causes into one message. `M9-causes-collapse` reddens
  the arm that holds them apart.
- **Why the comparison is `<` and not `<=`:** a ledger written the same day as the commit is
  CURRENT. `M3-currency-off-by-one` reddens ten arms, which is the widest blast radius in this
  increment and the reason the boundary is armed at equality rather than inferred.
- **Why the newest entry is a maximum and not the last row:** an append-only log is written in
  order by convention and nothing enforces it. `M4-oldest-not-newest` reddens
  `CURRENCY-MAX-NOT-LAST`, whose fixture inserts one older row after two newer ones.

### LED-89.18 — the mutation battery, its one survivor and its one rewritten mutant
- **Requirement:** LLR-89.6.4
- **What changed:** 25 named single-edit mutants were run against `V27` and `V28`.
- **Result:** baseline 490 arms, zero red. **24 killed, 1 survived, 0 broken.**
- **The mutants live in a MIRRORED flow tree**, `docs/tools/` plus `hooks/`, under the job's
  scratch directory. A flat copy was tried first and the baseline came back RED: rev49's
  `INT FOUR-PLACES-agree` arm reads three sibling scripts by walking three directories up from
  `__file__`, so outside a flow-shaped tree it reports the layout instead of the interpreters.
  **A baseline that is already red cannot score anything**, and lowering the bar to accommodate
  it would have been the vacuous check one level out.
- **The survivor is recorded EQUIVALENT by execution rather than chased.**
  `M15-zero-padding-dropped` removes `0*` from the harvest pattern. With it, the quantifier
  eats the zeros and the group captures `7`; without it the group captures `007` and `int()`
  eats them instead. No input separates the two, `Increment 0` included. It is left in place
  because its sibling `_V27_PACKET` reads filenames where the intent is worth stating.
- **One mutant was REWRITTEN because it was BROKEN, not because it survived.**
  `M13-nodate-silent` (`if not days:` → `if False:`) crashed at 454 arms with no verdict line,
  which the harness correctly refused to score: a crash prints no FAIL and reads exactly like a
  survivor. The guard it removes is what stops an `IndexError` on an empty list, so the mutant
  could never have been silent. It was replaced by `M13-malformed-date-accepted`, which drops
  the `_V27_DAY` filter instead — the real defect shape — and reddens `NODATE` alone.

### LED-89.19 — a sixth increment on a record that declared five
- **Requirement:** HLR-89.6
- **What changed:** §1's scope table gains **Story 6**, and its opening sentence now says six.
- **How, and why it matters:** through this ledger. The record that opened on 2026-08-28
  declared five stories; batch-88's close, written 2026-08-29, then measured two defects no
  rule could see (`G5-05`, and the merge accounted in `04-validation.md` §6). The scope moved
  by APPENDING the reason here and amending the current sentence there — never by striking the
  old one, which `V26` would BLOCK, and never by leaving the table saying five while six were
  shipped, which nothing would have caught. **This is the mechanism Increment 1 built, used for
  the first time on a change it did not anticipate**, and it is the demonstration the increment
  was asked for.

### LED-89.20 — the freeze was lifted, and what pins the behaviour now
- **Requirement:** LLR-89.6.5
- **Date:** 2026-08-31
- **What changed:** the direct-child test moved out of `_artifacts` and into
  `_active_batch_state`, which gained a fifth resolution code, `notchild`. `_active_batch_dir`'s
  BODY is unchanged — `LLR-88.5`'s acceptance froze that function and it is still frozen to the
  letter; what moved is the resolver behind it, which the freeze never named. `_artifacts` lost
  the two-line guard it had carried since batch-88, because it can no longer fire.
- **Why the freeze was lifted, and it is not the reason batch-88 offered.** batch-88 registered
  the amendment as a fork: lift the freeze on `_active_batch_dir` for one line, **or** state the
  contract as *"whatever `state.json` says, unvalidated"* and audit every caller. **Both branches
  were measured on 2026-08-31 and both are insufficient, for the same reason.**
  `_active_batch_dir` is not the leak's only mouth. `_v27_newest_commit` reaches the declared id
  through `os.path.basename(path)` on `_active_batch_state`'s return value and **never calls
  `_active_batch_dir` at all** — so a guard placed inside `_active_batch_dir`, the literal
  amendment on offer, closes `_v27_packets` and leaves the currency half of the SAME RULE reading
  the whole corpus. The invariant belongs to whatever resolves a declared id against the
  filesystem. That is `_active_batch_state`, and putting it there closes seven call sites at once
  instead of three.
- **And the second branch is `R-88-17` wearing a contract.** *"Validating it is every caller's
  job"* has no population: it is discharged by auditing today's callers and re-auditing at every
  future one, forever, with nothing able to tell you when an audit was skipped. `V27` is the
  proof — batch-88 wrote the prediction down and the eighth day produced the caller.
- **The freeze turned out to protect nothing, and that is armed rather than asserted.**
  `LLR-88.5` froze the function so `_artifacts` would read *"exactly as it did at rev39"*, so the
  question the amendment owed was not whether the new home is tidier but **whether the map
  moved**. `ART A9-freeze-noop` reproduces rev51's caller-side guard as a reference
  implementation and compares the two maps over seven declared ids — the three traversals, a
  legitimate batch, a ghost, a trailing separator, and `../..` — values included. **Identical
  everywhere.** Had it moved, the honest answer was to report that the freeze protects something
  real and take the other branch; it does not, and the arm is what makes that a measurement.
- **Evidence, measured 2026-08-31 on the rev51 code** over a fixture carrying an `03-increments/`
  BESIDE `.dev-flow/` and another at `.dev-flow/` root:
  - `batch_id: ".."` → `_v27_packets` returned **`{42}`** — a packet from outside the corpus,
    which `V27` then NOTICEd as work on disk its ledger had failed to record. **This is worse
    than the account the defect was reported under.** The prediction was that the `listdir` would
    raise and `V27` would report zero packets and pass green over a ghost id; that is only what
    happens when the escaped directory holds no `03-increments/`. When it holds one, the rule
    does not fall silent — it **names a foreign increment number as this batch's**.
  - `batch_id: "."` → `_v27_packets` returned `{77}` from `.dev-flow/03-increments/`, and
    `_v27_newest_commit` ran `git log -- .dev-flow/.` and rendered the newest commit of the
    **whole `.dev-flow/` tree** as *"the newest commit touching the batch directory"* — then
    PASSED on it.
  - `batch_id: "z/"` → a legitimate batch, one trailing separator: the loader read the right
    directory while `os.path.basename` of the unnormalised join was the **empty string**, so
    `V18` named batch `''` and `V27` reported that no batch was declared to ask git about. The
    returned path is now absolute, which closes that form; `ART A9-trailing-sep` pins it and
    `M4-raw-return` is the only mutant it kills.
- **What `V18` now says, and it is the visible half.** `.` and `..` were reported `ok` —
  *"active batch declared and on disk"* — which batch-88 called *"strictly worse than the ghost
  case, because ghost at least announces itself."* They now resolve to `notchild` and announce
  themselves. The three `ART A9-*` rows previously asserted `_active_batch_state(d)[1] == "ok"`
  as a deliberate PAIR decision; **that decision is reversed here on purpose**, and the reversal
  is recorded rather than quietly re-typed.
- **The population of the correction, enumerated, because a correction has one.** The claim
  *"the direct-child test is checked in the caller rather than in `_active_batch_dir`, which
  `LLR-88.5` freezes"* stood in five places. **Corrected: 2** — `_artifacts`' docstring and the
  selftest's `A9` block comment, both rewritten to name the new home. **Corrected: 1** —
  `.dev-flow/BACKLOG-PROCESS.md`'s P1 item, marked closed with a pointer here. **Deliberately
  NOT corrected: 2** — `.dev-flow/2026-08-24-batch-88/01-requirements.md`'s `LLR-88.5` bullet
  and `03-increments/increment-005.md`. Those are a CLOSED batch's record; they were true when
  written, that bullet is the entry which predicted this defect correctly, and rewriting closed
  history to match today is the failure `V26`'s append-only ledger exists to prevent. The two
  sites are named here so the population is enumerated rather than merely swept.

### LED-89.21 — the mutation battery for the traversal guard, and the trap it reproduced
- **Requirement:** LLR-89.6.5
- **Date:** 2026-08-31
- **Baseline:** 524 arms, 0 FAIL, `SELFTEST PASSED`, taken from the run's own mirrored tree.
- **Verdicts — 7 mutants, 6 applicable, 6 KILLED, 0 SURVIVORS, 1 control:**

| mutant | verdict | killed by |
|---|---|---|
| `M1-guard-off` (`if False:`) | KILLED | `A9-dot`, `A9-dotdot`, `A9-nested`, `A9-freeze-noop`, `V18 TRAVERSAL-*`, `V27 GUARD-*` |
| `M2-cheap-dotdot` (`".." in batch`) | KILLED | `A9-dot`, `A9-nested`, `A9-freeze-noop`, `V18 TRAVERSAL-notice`, `V27 GUARD-currency` |
| `M3-no-abspath` (test on the raw join) | KILLED | `A9-dot`, `A9-dotdot`, `A9-trailing-sep`, `A9-freeze-noop`, `V18 TRAVERSAL-*` |
| `M4-raw-return` (guard kept, return raw) | KILLED | `A9-trailing-sep` **alone** |
| `M5-code-only` (`return path, "notchild"`) | KILLED | `A9-dot`, `A9-dotdot`, `A9-nested`, `A9-freeze-noop`, `V27 GUARD-traversal` |
| `M6-cause-collapse` (fifth cause says the fourth's words) | KILLED | `V18 notchild-SENTENCE`, `V18 TRAVERSAL-*` |
| `M7-CRASH-control` (undefined name) | **CRASH** | reported CRASH at 0 arms, never SURVIVED |

- **`M5-code-only` is the discriminating mutant and it is why the arms assert the PATH and not
  only the code.** It reports `notchild` correctly — `V18` stays entirely green, every severity
  and every sentence — while handing the poisoned path back to all seven callers. An arm block
  that had asserted the new diagnosis and stopped there would have passed it. The rows assert
  `_active_batch_dir(d) is None` and `_v27_packets(d) == set()` for exactly this reason.
- **`M4-raw-return` is killed by ONE arm and that is the point, not a weakness.** Nothing else in
  524 arms observes the difference between a normalised and an unnormalised return, because every
  other fixture writes a `batch_id` with no trailing separator. Deleting `A9-trailing-sep` as
  redundant would restore a live defect silently.
- **THE rev49 TRAP WAS REPRODUCED, LIVE, ON ALL SIX KILLS.** The harness records, per mutant,
  whether `SELFTEST PASSED` appears anywhere in the output as well as what the FINAL `SELFTEST`
  line says. **On every one of the six kills the substring is present while the final line reads
  `FAILED`** — `ENC VERDICT-live` prints it mid-run from a child process. A harness matching by
  substring would have scored **6 of 6 as survivors** and this increment would have shipped
  believing it was unarmed. The verdict is taken from the final line, and the observation is
  printed per mutant rather than assumed.
- **The harness corrupted its own baseline once, and the abort is what caught it.** The first
  sweep opened the target with `open(TARGET, "w", encoding="utf-8")`, and Windows text mode
  rewrote every LF as CRLF on restore — the baseline came back RED at 2 FAIL and the harness
  **aborted rather than scoring**, which is the property `LED-89.18` paid for one increment
  earlier. Both read and write now pass `newline=""`. **A harness that silently corrupts the file
  it is scoring reports mutants that never ran**, and a red baseline is the only thing standing
  between that and seven fabricated verdicts.
- **Mirrored tree, not a flat copy** (`docs/tools/` beside a real `hooks/`), for the reason
  `LED-89.18` records: `INT FOUR-PLACES-agree` walks up from `__file__` and a flat copy returns
  a RED baseline that can score nothing.
- **Not scored, and named rather than left silent:** `M6-cause-collapse` does not redden
  `V18 CAUSES-differ`, because the substituted string still differs from `ghost`'s by a few
  characters. `CAUSES-differ` is armed by construction and this battery does not exercise it; the
  arm that carries the fifth cause's meaning is `notchild-SENTENCE`, which compares the whole
  sentence as typed text and does redden.

### LED-89.22 — a rule that named the wrong cause, and a floor re-derived by the method that can see one
- **Requirement:** HLR-89.4
- **Date:** 2026-08-31
- **What changed:** `v8_module_map`'s enumeration was rewritten (`git ls-files -z`, explicit
  `encoding="utf-8"`, a returncode branch, and a narrowed `except`), and `HLR-89.4`'s Python
  floor was RE-DERIVED rather than carried across the predicate that changed.

**The defect: one sentence over three different worlds.** The rule ran
`subprocess.run(..., capture_output=True, text=True)` under a bare `except Exception`, and
`text=True` decodes with the locale codepage — cp1252 on this machine, measured on both
interpreters. The file states the opposing law 725 lines away in `_git`'s own docstring. Three
faults, none of them loud:
1. **The wrong cause, named confidently.** A `UnicodeDecodeError` became `tracked = None`,
   which is the `_V8_NO_GIT` path, so V8 announced *"git could not be run, so NO file was
   enumerated"* about a run in which git ran fine and returned bytes Python refused to decode.
   The rule did not fall silent; it testified incorrectly.
2. **A FALSE PASS that the file's own comment says was "one edit away".** It was not away at
   all. `subprocess.run` does not raise on a non-zero exit, so a root outside any repository
   gave `stdout == ""` → `.split() == []` → **not `None`** → V8 printed `N modules, no orphan
   files`. Reproduced: exit **128**, empty stdout, `fatal: not a git repository`.
3. **Silent under-enumeration.** `core.quotepath` defaults to TRUE, so git ASCII-quotes
   non-ASCII paths to `"\304\201.py"` — which does not end in `.py` and was therefore skipped
   from the orphan check entirely — and whitespace `.split()` cut `two words.py` into `two` and
   `words.py`: one phantom orphan against a file that does not exist, one real file never
   checked.
- **Why quotepath is the whole point:** it is a git config **this flow does not own**, and it
  is the only reason fault 1 had not fired. Measured both ways on a throwaway repo:
  `quotepath=true` yields ASCII that cp1252 decodes; `quotepath=false` yields raw UTF-8 whose
  `c4 81` (U+0101) is **undefined in cp1252** and raises. A defect that waits on someone else's
  config is still a defect. `-z` emits paths verbatim under either setting, which is why the
  fix removes the dependency instead of documenting it; `QUOTEPATH-invariant` asserts the
  verdict does not move when the config does.
- **The third time this batch:** Increment 3 paid for collapsing two causes into one message,
  `LED-89.17` held two absences apart in `_git`, and this is the same family a third time. The
  absence is now carried with its REASON (`absent_reason`, defaulting to `_V8_NO_GIT`, so every
  pre-existing arm keeps its meaning) and `_V8_GIT_FAILED` says *"git RAN and exited
  non-zero"*. `ABSENCES-differ` asserts the two do not share a phrase.

**The floor, re-derived by both methods.** `R-88-18` forbids carrying a constant across a
substituted predicate, and removing `text=` substituted this one.
- **(a) stdlib-API floor — 3.7.** An AST walk for version-gated constructs. The floor no longer
  rests on the edited site: it is bound independently by `from __future__ import annotations`
  and by `capture_output=` at the **9 remaining** `subprocess.run` calls. The constant survived;
  it was re-derived, not carried, and it is now cited at surfaces this batch does not edit.
- **(b) SYNTAX floor — and this is the method that was missing.** An AST walk on the running
  interpreter **structurally cannot see a syntax floor**: it only ever sees what already
  parsed. That is how rev53's PEP 701 f-string reached the gate env as a `SyntaxError`.
  `ast.parse(..., feature_version=)` is **not** the fix — measured 2026-08-31, it reports
  "parses" for that construct at **every** version 3.7 through 3.12, while the real
  `s19env` 3.11.15 refuses it: `SyntaxError: unterminated string literal`. The documentary
  method is demonstrably blind to the exact floor it was reached for.
- **What is executed and what is not, stated plainly:** the file compiles and passes
  `SELFTEST` on **3.11.15** and **3.12.7**, both executed. **No interpreter below 3.11 exists on
  this machine**, so 3.7–3.10 is asserted by analysis alone. `HLR-89.4` therefore declares
  **3.11** — the lowest floor with an interpreter that RUNS it — and records 3.7 as a
  documentary API lower bound. Declaring 3.7 would repeat rev53 exactly: a number with no
  interpreter behind it.

**Mutation battery — 9 applied, 7 killed, 2 survivors, both argued.** Mutants ran as copies in
a **mirrored flow tree** (`docs/tools/` beside a real `hooks/`) because `INT FOUR-PLACES-agree`
walks three directories up from `__file__`; a flat copy returns a RED baseline, and a red
baseline scores nothing. Baseline in the mirror: `SELFTEST PASSED`. Verdicts are read from the
**final line beginning `SELFTEST `** — a substring match instead hits `ENC VERDICT-live`, which
prints `SELFTEST PASSED` mid-run from a child process at output line 452.
- **Sentinel first:** `SENTINEL-must-be-RED` corrupts `_V8_NO_GIT` and was **KILLED**, so the
  detector is proven able to see red before any verdict is trusted.
- Killed: `M1-restore-text=True` (crashes now instead of lying — the narrowed `except` no
  longer swallows the decode failure), `M2-drop--z-keep-encoding`, `M3-ignore-returncode` (the
  false pass), `M4-collapse-two-causes`, `M5-core-ignores-reason`, `M6-reword-git-failed`.
- **Survivors, named rather than counted as covered.** `M7-errors-strict` and
  `M8-drop-empty-filter` both survive and both are argued **equivalent on this platform**:
  NTFS stores names as UTF-16, so git always emits valid UTF-8 and `errors=` is unreachable;
  and `-z`'s trailing NUL yields an `""` element that no branch can act on. Neither is a
  coverage gap this battery could close with a fixture, and neither is claimed as a kill.

**Population sweep of the two figures, enumerated.**
- `01-requirements.md` **P-6** (the floor's predicate), **P-9** (the "cannot demonstrate a
  violation" rationale), **HLR-89.4** threshold + Ledger field — **all corrected, live**.
- `devflow-validate.py`'s selftest tail claimed V8's `git ls-files` enumeration was one of two
  I/O steps "unproven synthetically" — **corrected**: it is now driven end to end, and it had
  stood named-as-uncovered for seven revisions while holding three defects.
- `FLOW-VERSION.md` **rev53** states the 3.7 derivation is refuted and reports **524 arms**.
  **CLOSED HISTORY, true when written, deliberately left**: 524 was the count that day, and a
  revision row records what a revision found. Named here so the population is enumerated rather
  than silently partial. **One claim in that row is measurably wrong and is corrected here
  rather than in it:** rev53 reports "byte-identical arm output" across 3.11.15 and 3.12.7.
  Measured 2026-08-31, three arm lines (`IFC ids-declared`, `IFC list-named`,
  `IFC list-multiline`) print a `set` repr whose order varies **run to run on a single
  interpreter** under default `PYTHONHASHSEED`. No verdict moves — all three read `ok` every
  time — but the output is not byte-identical between any two runs, let alone between two
  interpreters, and a future arm that diffed selftest output would fail on noise. Not repaired
  in this increment: it is `_atlas`-adjacent output hygiene, outside the two figures this entry
  moves, and it is recorded so it is not rediscovered as a defect.
- `LED-89.2`'s evidence line cites `capture_output=` with `text=` at `:572-573`. **CLOSED
  HISTORY, and the ledger is append-only**: it was correct when written, the construct it cites
  no longer exists, and this entry supersedes it rather than rewriting it.
