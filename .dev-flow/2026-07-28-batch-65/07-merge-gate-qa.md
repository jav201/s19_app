# batch-65 — Phase 7 — FINAL PR-LEVEL MERGE GATE (QA lane)

- **Batch:** `2026-07-28-batch-65` · **Branch:** `claude/batch-65-code-lane` · **HEAD:** `7dfb82c`
- **PR:** [#149](https://github.com/jav201/s19_app/pull/149) · **Base:** `origin/main` @ `f28ba45`
- **Reviewer:** qa-reviewer (independent) · **Date:** 2026-07-28
- **Scope:** the merged whole, `git diff origin/main...HEAD` — 29 files, +19122 / −132.

## VERDICT: **BLOCK**

Three HIGH findings. **None touches shipped behaviour** — the code, the tests, the
frozen guards, the byte identity and the migration content are all provably clean, and
the migration is proven lossless and non-mutating by blob-SHA equality. All three
blocks are on the batch's own record-keeping, and all three are one-pass edits to
`.dev-flow/BACKLOG-CODE.md`, `05-postmortem.md` and the artifact headings.

- **HIGH-1** — the 64 → 65 renumber rewrote paths but not identity; `batch-64` now
  resolves to a different, already-merged batch.
- **HIGH-2** — `05-postmortem.md:302` claims `G-1/G-2/G-3` are *"all now in Lane A"*.
  They are in **neither** backlog file. A carry asserted as landed that did not land.
- **HIGH-3** — Phase-4 finding `F-3` has **no disposition anywhere**, and the metrics
  row that should have caught it miscounts.

HIGH-2 and HIGH-3 are the sharper pair. This batch's entire thesis is *do not claim
what you did not do*, and it enforced that ruthlessly on `R-TUI-098` (which passes
clean). The same discipline was not applied to its own closeout.

---

## 1. The merge-gate checklist

| # | Row | Result | Re-runnable citation |
|---|---|---|---|
| 1 | Dual traceability intact — `AT-194…203` / `TC-480…499`, zero gaps | **PASS** | `python -m pytest tests/test_report_addendum_bound.py tests/test_tui_report_seam.py -q` → `57 passed`. 28 in-range node definitions = 9 AT + 19 TC = the live ledger at `01-requirements.md:1140-1141`. Every `US`/`HLR`/`LLR` binds ≥1 id; union of the TC column = 19 = the full live set, so no orphan TCs. §6.2 (`01-requirements.md:1200-1224`) and `06-docs/traceability-matrix.md:52-70` agree row-for-row. |
| 1b | `AT-195` / `TC-496` retired and binding nothing | **PASS** | `grep -rn "AT-195\|TC-496" tests/` → **no matches** (exit 1). Neither appears in either chain table; only mentions are the retirement rows `01-requirements.md:1120-1121`, `06-docs/traceability-matrix.md:85-86`. |
| 2 | Zero engine-frozen diffs — both guards, all seven paths | **PASS** | `python -m pytest tests/test_engine_unchanged.py "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main" "…_no_name_only_diff_vs_main" "…_engine_imports_still_resolve" -q` → `4 passed`. Independently: `git diff origin/main...HEAD --stat -- <each of the 7 paths>` → **0 lines each**. |
| 3 | No cross-increment regression — Inc-3 did not weaken Inc-1/Inc-2 | **PASS** | `python -m pytest tests/test_report_field_census.py -q` → `34 passed`. Inc-3's guard is non-vacuous: `test_head_of_line_guard_detects_a_planted_violation` (`tests/test_report_field_census.py:1148`) plants the offending spellings into the **real** `report_service.py` text, not a toy — a positive control for an absence-assertion. |
| 4 | Every gate carry discharged or explicitly carried with its numbers | **FAIL — HIGH-2, HIGH-3** | **Phase-2 46/46 is CLEAN** and survives independent mechanical re-derivation: master record `01-requirements.md:3276` §17 (27 first-gate rows) + `:3400` §17.6 (19 re-gate ids, 16 rows after merging three cross-lane duplicate pairs); a scripted presence check of all 46 lane-keyed ids → **0 missing**. 25 FOLDED · 2 FOLDED (narrowed) · 1 named sub-part rejected in writing (`SEC-S5` fold 2, `:3335`) and that rejection **is** carried at `BACKLOG-CODE.md:41`. All 11 increment findings trace to a disposition (9 folded pre-commit; `Inc-2 M2`/`M3` carried to Inc-3, closed as `A-46`/`A-43`, `03-increments/increment-003.md:55,86-91`). **Phase 4 is where it breaks** — see HIGH-2 and HIGH-3. |
| 4b | `F-4` carried in both required places | **PASS** | `.dev-flow/BACKLOG-CODE.md:35` and `REQUIREMENTS.md:4999-5001`, both honest about the §6.3 gate-condition conflict. `FIX-NONE`/`FIX-SCOPE` recorded RED-then-fixed at `03-increments/increment-002.md:195-196`, bound `TC-484`/`TC-499` at `:208,:214`. |
| 5 | Non-claim discipline holds in the SHIPPED text; `TC-497` passes | **PASS (with MED-3)** | `python -m pytest -q "tests/test_report_addendum_bound.py::test_tc497_shipped_requirement_carries_the_residuals_with_their_numbers"` → `1 passed`. All five obligations present verbatim: DoS **not** closed `REQUIREMENTS.md:4896`; candidate-consumption independence only `:4875-4876`; `R` **relocated, not removed** `:4928-4929`; `B-3(b)` **reduced, not eliminated** `:4887-4888`; eviction **DISCLOSED … NOT PREVENTED** `:4918`. 13 closure-word hits scanned; 11 correctly negated or scoped, 2 LOW (below). |
| 6 | Byte identity 6/6 shapes; `tests/goldens/` untouched | **PASS** | `python -c "…_golden_shapes()"` → **6** shapes `[FIXGOLD, R1V1E0, R1V1E1, R1V1E200, R2V3E66, R3V2E5]`. `python -m pytest tests/test_report_addendum_bound.py -q -k "byte_identity or at196 or golden"` → `2 passed`. `git diff origin/main...HEAD --name-status -- tests/goldens/` → a single `A` (added), **zero `M`, zero `D`** — no golden re-baselined. |
| — | Batch nodes overall | **PASS** | `python -m pytest tests/test_report_addendum_bound.py tests/test_report_field_census.py tests/test_tui_report_seam.py -q` → **`91 passed in 117.75s`**. |
| — | Lint on changed production files | **PASS** | `python -m ruff check s19_app/tui/services/report_service.py s19_app/tui/services/report_addendum.py` → `All checks passed!`. The known `F821` at `app.py:5477` is pre-existing: `git diff origin/main...HEAD --name-only -- s19_app/tui/app.py` → empty. |
| — | No unfilled template | **PASS** | Every `AT-NNN`/`TC-NNN`/`<...>` hit in the batch-65 folder is generic prose inside backticks (e.g. `01b-qa-catalog.md:8` *"this lane allocates NO `AT-NNN`/`TC-NNN`"*). Zero `TODO`/`FIXME`/`TBD`. |
| — | Layer B (black-box, shipped surface) | **PASS** | `AT-200` (`tests/test_tui_report_seam.py:426`) drives the real `S19TuiApp` under `App.run_test()`, pushes the real `ReportViewerScreen`, presses the real `#report_generate` button, and observes the notice in **both** the written file and the rendered text. |
| — | Production blast radius | **PASS** | `git diff origin/main...HEAD --numstat -- s19_app` → 2 files, `+565/−33` — exactly the figure `BACKLOG-CODE.md:18` claims. |

## 2. Migration audit (64 → 65)

The operator's four questions, answered by execution.

**(a) Does the batch-65 folder hold the complete artifact set? — YES, provably.**

```bash
diff <(git ls-tree -r --name-only 98b5b7a .dev-flow/2026-07-27-batch-64/ | sed 's|.*batch-64/||' | sort) \
     <(git ls-tree -r --name-only HEAD     .dev-flow/2026-07-28-batch-65/ | sed 's|.*batch-65/||' | sort)
# → IDENTICAL ARTIFACT SET
```

20 artifacts, phases 0–6 complete. The only file absent relative to a closed batch is
this `07-merge-gate-qa.md`.

**Content is equivalent too, and the migration mutated nothing.** Every artifact
whose blob changed vs the pre-migration tip differs **only** in batch-path rewrite
lines:

```bash
for f in $(git ls-tree -r --name-only HEAD .dev-flow/2026-07-28-batch-65/ | sed 's|.*batch-65/||'); do
  diff <(git show 98b5b7a:.dev-flow/2026-07-27-batch-64/$f) <(git show HEAD:.dev-flow/2026-07-28-batch-64/$f) \
  | grep "^[<>]" | grep -v "2026-07-2[78]-batch-6[45]"
done
# → no output: every artifact change is a batch-path rewrite and nothing else
```

The six code/test files are **byte-identical** to `98b5b7a` (blob-SHA equality on
`REQUIREMENTS.md`* , `test_report_addendum_bound.py`, `test_report_field_census.py`,
`report_service.py`, `report_addendum.py`, `test_tui_report_seam.py`,
`goldens/batch64/addendum-below-bound.md`).
*`REQUIREMENTS.md` differs by **exactly one line** — `:5002`, the batch-id in the
Status line. `git diff 98b5b7a HEAD -- REQUIREMENTS.md` is a 1-line hunk.

> **On the operator's "could the migration have changed behaviour?" question: no, and
> the mechanism does not exist.** All six files under `s19_app/` and `tests/` carry
> identical blob SHAs to the pre-migration tip. Re-running the ~28-minute suite would
> exercise byte-identical inputs. I did not re-run it and I do not need to.

**(b) Did the 3-way merge preserve both sides? — YES, provably lossless.**

```bash
git diff origin/main...HEAD --numstat -- .dev-flow/BACKLOG-CODE.md      # → 21  1
diff <(git show 374ad90:.dev-flow/BACKLOG-CODE.md) <(git show HEAD:.dev-flow/BACKLOG-CODE.md) | grep "^<"
# → exactly ONE line: the batch-63 D1 bullet this batch closed and replaced
```

Exactly one line removed — the D1 bullet the batch legitimately closed — and 21 added.
Nothing from the other session was dropped; its three new P3 bullets survive as
unchanged context. Zero conflict markers anywhere in the diff.

**(c) Did anything land in the OTHER batch's folder? — NO.**

```bash
git diff origin/main...HEAD --stat -- .dev-flow/2026-07-27-batch-64/   # → empty
```

Nine filenames exist in both folders with **different** content — which is the
collision itself, correctly resolved: both records survive intact, neither
overwritten. The one file this branch adds outside its own folder,
`.dev-flow/2026-07-26-batch-63/state-at-close.json`, self-identifies as
`"batch_id": "2026-07-26-batch-63"` and belongs there.

**(d) Does anything still reference the old batch number where it should not? — YES.
This is HIGH-1.**

Path references were rewritten correctly and completely. **Identity references were
not rewritten at all.**

```bash
grep -rn "2026-07-27-batch-64" --include="*.md" --include="*.py" --include="*.json" . \
  | grep -v "^./.dev-flow/2026-07-27-batch-64/"
# → 2 hits, BOTH correct (they refer to the genuine merged batch-64)
grep -rc "batch-64" .dev-flow/2026-07-28-batch-64/ | grep -v ":0$"
# → 69 occurrences across 19 files
grep -rn "^# " .dev-flow/2026-07-28-batch-64/ | grep -c "batch-64"    # → 17 of 29 H1s
```

---

## 3. Findings by severity

### HIGH-1 — the renumber rewrote paths but not identity, and `batch-64` now resolves to a different merged batch

`.dev-flow/2026-07-27-batch-64/` is occupied by the process lane's batch, merged as
#144/#145/#146. Every surviving `batch-64` string in this batch therefore points a
reader at someone else's work.

- **17 of 29 H1 headings** in `.dev-flow/2026-07-28-batch-64/` still read `batch-64`,
  including `05-postmortem.md:1`, `04-validation.md:1`, `06-docs/executive-summary.md:1`,
  `06-docs/traceability-matrix.md:1`, `06-docs/diagrams/architecture.md:1`.
- **`PLAN.md` in both folders carries the byte-identical H1** `# batch-64 — PLAN (living
  compendium)` over different content. `05-postmortem.md` and `04-validation.md` are the
  same shape. The renumber disambiguated the directory and left the documents colliding —
  the same failure one level down. `/dev-flow-sync` folders by `batch_id` (correct), but
  Obsidian search and `[[wikilink]]` resolution key on titles, and batch-64 is already
  in the vault (#146).
- **`REQUIREMENTS.md` contradicts itself inside the shipped requirement.** `:4873`
  `## Bounded declared-region addendum — batch-64 (R-TUI-098)` vs `:5002`
  `Status: Added in batch 2026-07-28-batch-65`. The migration touched the second and not
  the first, so a reader cannot tell which is authoritative.
- **`.dev-flow/BACKLOG-CODE.md` — the file the next batch reads at Phase 0 — misroutes.**
  `:5` *"Last refresh: 2026-07-27 (batch-64 close) … batch-64 ships on
  `claude/batch-64-addendum-producer-bound`"* — that branch is the **backup** of
  pre-migration history per `state.json:233`, not the shipping branch. `:18` *"DONE,
  batch-64"*. `:35` *"(P2, batch-64 Phase-4 F-4)"*. `:37` *"New defects found in passing
  at batch-64"*. **This count MOVES, so it is stated with its basis — a count without its commit
  is a claim with an expiry date.** At **`7dfb82c`** the split was **13 = 4 theirs + 9 this batch
  mislabelling itself**, and those 9 were the target of the corrective pass. **Re-derived at
  `dc6aa71` (2026-07-28, batch-70, merge-gate item 1): 9 occurrences on 7 lines — 4 `§7.x` bullet
  markers (theirs, `:118` `:125` `:126` `:148`) + 1 further legitimate reference to their `D-5`
  constraint (`:125`) + 3 navigational / backup-branch-name / renumbering-event references
  (`:7` `:27` `:28`) + 1 replica of this very claim (`:28`). ZERO mislabels remain.**
  *(Corrected TWICE. This row first read "zero". It was then rewritten to "the only **four** …
  so the other **nine** are this batch mislabelling itself" — which **contradicted its own
  parenthetical in the same row**, "only four" against a stated total of 13, and whose
  "mislabelling" category is now **empty**. The re-gate prescribed that wording as item 1's fix;
  applying it verbatim would have planted a third false figure, so it was re-derived instead.)*

**Not in scope of this finding, and correctly left alone:** the stable id namespace —
`US-B64-1/2`, `AT-194…203`, `TC-480…499`, `HLR-103`, `LLR-103.x`, and the golden path
`tests/goldens/batch64/`. These are baked into passing tests and the byte-identity
golden; renaming them would churn code for no traceability gain. They need a one-line
disclosure, not a rewrite.

**Remedy (documentation-only, no code, no test):** rewrite the ~69 identity occurrences
— H1s, the `REQUIREMENTS.md:4873` heading, the `BACKLOG-CODE.md` header and prose, the
recorded branch — to `batch-65` / `claude/batch-65-code-lane`; add one line stating that
`B64`/`batch64` **identifiers** are retained deliberately.

### HIGH-2 — `G-1/G-2/G-3` are claimed carried to Lane A and are in neither backlog

`05-postmortem.md:302`:

> `| Findings carried out | **F-4** + 3 non-gating gaps (G-1/G-2/G-3) — all now in Lane A |`

The three gaps are defined at `04-validation.md:420,426,430`:

- **G-1** — `TC-487` observes duplicate/equal-start-nested geometry through
  `_addendum_lines`, **not** through the written file (white-box only).
- **G-2** — `TC-483` asserts the line-count bound through `_addendum_text`
  (white-box only).
- **G-3** — three disclosed residual figures (`≈ 11.6 kB/region`, `≈ 20 kB/region`,
  `86.5–93.9 B/hit`) sit **outside `TC-497`'s grep list** and *"can decay silently"*.

```bash
grep -n "TC-487\|TC-483\|white-box only\|grep list\|decay\|11.6 kB\|86.5" \
     .dev-flow/BACKLOG-CODE.md .dev-flow/BACKLOG-PROCESS.md
# → no output
```

Absent from both lane files. The only `G-1` strings in `BACKLOG-CODE.md` are batch-52's
unrelated empty-flow item (`:58`, `:62`). G-3's own text at `04-validation.md:430` even
reads *"recorded here so the Lane-A …"* — the intent to carry is written down; the
execution never happened.

**Why this is HIGH and not a nit:** G-3 is a *self-identified decay path in `TC-497`* —
the very check the merge-gate brief relies on for the non-claim discipline. Losing it
means three residual figures can go stale with nothing watching. And the failure mode
is the one this batch exists to eliminate: a positive claim in a shipped artifact that
does not survive a grep.

### HIGH-3 — Phase-4 finding `F-3` has no disposition anywhere, and the metrics row hides it

```bash
grep -rn "F-3\b" .dev-flow/2026-07-28-batch-65/ .dev-flow/BACKLOG-CODE.md \
     .dev-flow/BACKLOG-PROCESS.md REQUIREMENTS.md | grep -v "LLR\|HLR"
# → exactly ONE hit: .dev-flow/2026-07-28-batch-65/04-validation.md:456 (its own raising)
```

`F-3` states that `increment-003.md` §4.1 pastes `4  '988 B/entry'` where the shipped
file has 3. Both halves verified:

```bash
grep -n "988 B/entry" .dev-flow/2026-07-28-batch-65/03-increments/increment-003.md
# → :150   4  '988 B/entry'          ← still uncorrected
grep -c  "988 B/entry" REQUIREMENTS.md
# → 3                                 ← Phase-4's count was right
```

It appears in no §10 "Conditions on close" (`04-validation.md:588-598` lists only
F-1/F-2 as folds and F-4 as the carry), no postmortem row, no `06-docs/`, neither
backlog. **Actual Phase-4 tally: F-1 folded (`REQUIREMENTS.md:4956`), F-2 folded
(`:4989-4998`), F-4 carried — 2 folded + 1 carried + 1 vanished.** But
`05-postmortem.md:301` records *"Phase 4: 3 folded, 1 carried"* and `state.json`
decision 17 repeats *"three folded, one carried to Lane A"*. The miscount is what let
`F-3` disappear: 3 + 1 = 4 reconciles against the raised count, so nothing flagged it.

Substantively `F-3` is a minor evidence nit in a frozen packet — but it is precisely
the *"pasted number that does not reproduce"* class the batch spent three spec
revisions removing, and §17 exists to make exactly this impossible.

### MEDIUM-1 — the Phase-5 record cites a HEAD that is not on the shipping branch

`05-postmortem.md:12`: *"**Branch:** `claude/batch-64-addendum-producer-bound`,
`082ada9` → `9d21d9a` (5 commits)."*

```bash
git merge-base --is-ancestor 9d21d9a HEAD   # → NOT an ancestor
git merge-base --is-ancestor 082ada9 HEAD   # → ancestor: yes
```

`9d21d9a` lives only on the pre-migration backup branch. The merge-gate standard is a
re-runnable citation per row; the postmortem's terminal SHA is not reachable from what
is being merged.

### MEDIUM-2 — `04-validation.md:13` self-contradicts on a single line

> `- **Batch:** \`2026-07-28-batch-64\` · **Branch:** \`claude/batch-64-addendum-producer-bound\``

New number, retired branch, one line apart.

### MEDIUM-3 — `TC-497` greps the whole file, not the section its label names

`tests/test_report_addendum_bound.py:2828` is `if figure in requirements`, not
`in section` (`section` is computed later, `:2849`, only for the letters check). The
figure `988 B/entry` also occurs at `REQUIREMENTS.md:4870`, inside the **batch-63 /
`R-TUI-097`** entry. Executed mutant — rewrite only the in-`R-TUI-098` occurrences:

```
MUTANT drops fig0 from section -> shipped TC-497 still GREEN? True
MUTANT -> section-scoped variant GREEN?                      False
```

So one of the seven pinned figures can be deleted from `R-TUI-098` with `TC-497` green.
This is this project's own encoded rule — *a predicate must test what its LABEL claims*
(batch-63) — and the fix is one word: `if figure in section`.

*Not a defect:* `TC-497`'s semantic half greps no honesty phrase (an executed
overclaim-inversion mutant keeps it GREEN), but the docstring `:2805-2813` and the
traceability row `REQUIREMENTS.md:4982` both state plainly that the semantic half is a
delegated judgement, not a grep. That is a coverage gap **honestly labelled** — the
non-claim discipline (a)/(c)/(d)/(e) is protected by a self-signature
(`03-increments/increment-003.md:338-339`), itself disclosed and carried.

### MEDIUM-4 — RC-1 is stale and the branch is behind `origin/main`

`state.json` records `rc1: origin/main tip = 082ada9; HEAD = 082ada9`. Actual:

```
origin/main : f28ba45      HEAD : 7dfb82c      merge-base : e47b7da
merge-base == origin/main tip ?  NO — branch is behind by 1 commit
```

**No merge risk.** The missing commit `f28ba45` (#147) touches only `prototypes/*`;
`comm -12` against this batch's file list is empty. But RC-1 was never re-asserted after
the migration, so the recorded invariant does not describe the branch being merged.

### MEDIUM-5 — the shipped requirement's "and nowhere else" is now false

`REQUIREMENTS.md:5007-5009` says the six residuals are *"**stated here and OWED to
`BACKLOG-CODE.md`** as this batch's mandatory Lane-A close step; until that
reconciliation lands they are recorded in this entry and in `01-requirements.md` §10,
**and nowhere else**"*. The reconciliation **has** landed —
`.dev-flow/BACKLOG-CODE.md:25-36` carries all six. The conditional phrasing means this
was true when written, but it ships false.

It fails **safe** (an understatement, not an overclaim) so it does not breach the
non-claim contract in row 5, and `TC-497` does not grep it. But it is inside the section
`TC-497` polices and it now contradicts the backlog. Same edit pass as HIGH-2/HIGH-3.

### LOW

- **LOW-0** — the 11 increment-gate findings live only in `state.json`
  (`/inc1/code_review`, `/inc1/folded_before_commit`, `/inc2_ruling`) and the commit
  bodies `0a6595b` / `c2c63db`; `03-increments/*.md` carry only 6 numbered *author*
  findings. Nothing vanished and the batch **discloses this itself** —
  `05-postmortem.md:175`: *"Two increment-gate code reviews (11 findings) were never
  persisted as artifacts"* — filed as process item 9 (`:437`). Recorded so the next
  reader does not go looking in the increment files.
- **LOW-1** — `state.json` at HEAD drops `origin/main`'s `merged` key
  (`{"pr":144,"squash_sha":"71126c9",…}`), and `.dev-flow/2026-07-27-batch-64/` has no
  `state-at-close.json`. batch-64's close state survives only in git history
  (`git show origin/main:.dev-flow/state.json`). That is the other lane's omission, but
  this batch is the one overwriting the shared file — and it *did* archive batch-63's.
- **LOW-2** — `TC-497`'s window is `anchor → EOF` (`:2849`). Exact today because
  `R-TUI-098` is the last section; append any requirement after it and both the
  `does NOT claim` and `(a)`–`(f)` checks become satisfiable from the wrong section
  (`(a) **`/`(b) **`/`(c) **` already occur at `:761`, `:765`, `:776`, `:3719`, `:4281`).
- **LOW-3** — `REQUIREMENTS.md:4902` *"they scale with `E` where the bounded addendum no
  longer does"* is stronger than what `AT-194`/`TC-493` measure (ratio ≤1.30 per
  `E`-doubling, not zero growth). Same tension in the Statement at `:4876-4878`.
- **LOW-4** — two nodes this batch added carry no `AT`/`TC` id:
  `test_head_of_line_guard_detects_a_planted_violation` and the
  `test_census_every_planted_field_renders_verbatim[notice_variant]` arm. Both are
  spec'd (`01-requirements.md:2556-2562`, `:2861`) and both match the host file's
  un-idded convention, but the `+32` suite delta at `06-docs/traceability-matrix.md:155`
  includes 2 untraced nodes while the matrix states *"Orphan nodes: 0"*.
- **LOW-5** — retired batch-63 ids appear as prose in test docstrings (`AT-165` at
  `tests/test_report_addendum_bound.py:359`, `:1444`; `AT-193b` at
  `tests/test_report_field_census.py:1151`), against `01-requirements.md:1124`'s *"must
  not appear as live ids anywhere"*. No `test_at165_*` node exists, so the rule is not
  violated — but a grep lands in test files rather than only the retirement row.
- **LOW-6** *(pre-existing, not this batch)* — `tests/test_engine_unchanged.py:120`
  `_ENGINE_PATHS` omits `s19_app/tui/color_policy.py`; the `test_tui_directionb.py:5443`
  set includes it, so the seventh path is covered by one guard only. Both guards diff
  against **local** `main` (`e47b7da`), one commit behind `origin/main` — immaterial here
  (`git diff main origin/main -- <7 paths>` → empty), but the guards are only as fresh as
  the local ref.

## 4. Already-dispositioned, re-verified not re-raised

- `ruff` `F821` at `app.py:5477` — confirmed pre-existing (`app.py` not in the diff).
- Ten mutant arms not re-runnable (Phase-4 F-4) — confirmed carried at
  `BACKLOG-CODE.md:35` **and** disclosed at `REQUIREMENTS.md:4999-5001`.
- `FIX-NONE` / `FIX-SCOPE` — recorded executed at Inc-2.
- The three de-lettered residual bullets — **adequate.** `BACKLOG-CODE.md:27` carries an
  explicit warning above the section (*"Three of the six were mis-lettered… match these
  by CONTENT"*), and the six bullets correspond 1:1 to the six non-claims in
  `REQUIREMENTS.md`. Removing a wrong letter beats keeping one; a future grep for a
  letter now finds nothing rather than the wrong residual, which fails safe.

## 5. Evidence checklist

- [x] Acceptance criteria use Given/When/Then — inherited from `01b-qa-catalog.md`; this phase is a gate, not a new AT set.
- [x] Test cases have explicit Expected — every row above cites a command and its exact output.
- [x] Edge cases include empty, boundary, invalid, error — `AT-198` arms `le_K`/`interior`/`K_plus_1`; `AT-199` forgery; `AT-201`/`202` negative naming.
- [x] Regression checklist exists — checklist row 3, executed (`34 passed`).
- [x] Exit criteria stated — §"VERDICT".
- [x] No real PII / secrets — diff reviewed; fixtures only.
- [x] Test results are REAL, not left blank — every figure in this document was executed in this session.
- [x] Layer B black-box — `AT-200` through `App.run_test()` + real `ReportViewerScreen` + written file.
- [x] Bidirectional surface-reachability — inputs via the screen's `TextArea`/`Button`; deliverable observed in file **and** viewer.
- [x] No unfilled template — verified by grep, zero live placeholders.

## 6. What unblocks the merge

Three HIGH, all documentation, all in one editing pass. No code, no tests, no goldens,
no re-run of the 28-minute suite.

1. **HIGH-2** — add `G-1`/`G-2`/`G-3` to `.dev-flow/BACKLOG-CODE.md` with their numbers
   (`TC-487` white-box, `TC-483` white-box, and the three figures outside `TC-497`'s
   grep list), or strike the *"all now in Lane A"* claim at `05-postmortem.md:302`.
   Carrying them is the better fix — G-3 is a live decay path in `TC-497`.
2. **HIGH-3** — give `F-3` a disposition (fold it by correcting
   `03-increments/increment-003.md:150` from `4` to `3`, or carry it), and correct
   `05-postmortem.md:301` + `state.json` decision 17 from *"3 folded, 1 carried"* to
   the true tally.
3. **HIGH-1** — rewrite the ~69 identity occurrences to `batch-65` /
   `claude/batch-65-code-lane`, and add one line stating that the `B64` / `batch64`
   **identifiers** are retained deliberately. MEDIUM-1, MEDIUM-2 and MEDIUM-5 are the
   same pass.

**Recordable as carries at the operator's discretion, not blockers:** MEDIUM-3
(`TC-497` scope leak — one word, `requirements` → `section`) and MEDIUM-4 (re-assert
RC-1; the branch is 1 commit behind on `prototypes/` only, zero overlap).

Everything else on this page is green and stays green — rows 1, 1b, 2, 3, 4b, 5 and 6,
plus lint, Layer B, template hygiene and blast radius. Once the three edits land this
is a **MERGE**.


---

> **Correction applied 2026-07-28 after the re-gate.** The orchestrator's fix for HIGH-1 was a blanket `batch-64` -> `batch-65` pass over 20 artifact files. Its stated rationale — *my artifacts predate the collision, so every mention is a self-reference* — held for 19 of them (66/66 substitutions verified correct, line by line, by the re-gate). It did **not** hold for THIS file, which was written *after* the collision and is *about* it, so `batch-64` here meant the OTHER batch on nearly every line. Twenty-four lines have been restored and six references to the never-existent `.dev-flow/2026-07-27-batch-65/` cleared. **The rationale was never verified before it was acted on — which is the same defect class this batch spent two gates removing, committed while closing that batch's own findings.**
