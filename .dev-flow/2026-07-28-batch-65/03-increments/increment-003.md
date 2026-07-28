# batch-64 — Increment 3 — Review Packet

> **Scope: DOCUMENTATION, THE AMENDMENT LOG, AND `TC-497`.** No production behaviour changed — this
> increment's entire `s19_app/` diff is **+11 / −5 `#:` comment lines and not one statement**, and the
> golden is untouched (`git status --porcelain tests/goldens/` → empty).
>
> Three things are reported rather than smoothed (§5): **`TC-497`'s narrow-space hazard did NOT obtain
> and was verified rather than assumed**; the extended column-0 guard is shown **failing on a planted
> violation while the pre-Inc-3 guard reads clean on the same plant**; and **Inc-2's packet mis-stated
> its own diff scope** — it modified four files under `s19_app/`+`tests/`, not three, and asserted
> `git diff --stat 082ada9 -- s19_app/` *"touches `report_service.py` only"*, which is false.

## 1. What changed

**1. `R-TUI-098` is registered in `REQUIREMENTS.md`** (+134 lines, a new trailing section following the
batch-62 / batch-63 shape). It carries the Statement, the defect with its number, the six lettered
non-claims **(a)…(f) each with its executed figure**, the `Code:` / `Validation:` / `Status:` rows the
file's convention requires, the full `AT-194…AT-203` / `TC-480…TC-499` mapping as a table, the
retirement of `AT-195` and `TC-496` as ids, and the mutant-arm roster that carries the eleven
regression guards' falsifiability.

**The entry claims candidate-consumption independence and nothing wider.** It states in its own words
that the memory-exhaustion axis is **not** closed; that the `R` multiplier is **relocated, not
removed** (`500 → 128000` at `R = 1/8/64/256` for 500 candidates producing ONE hit); that B-3(b) is
**reduced from `R×V×E` to `V×E`**; that `_modifications_lines` / `_checklist_lines` stay unbounded at
**988 B/entry**, ~11× the addendum's 86.5–93.9 B/hit, and therefore **dominate at ordinary `R` and
`V`**; and that intra-class and cross-variant eviction is **disclosed via the notice, not prevented**,
including the one genuinely-lost case in which what survives is suppression of the *severity signal*
rather than of the evidence.

**`Code:` deliberately carries no line numbers.** batch-63's own entry two sections above records that
its `:996` / `:1171` citations went stale inside one batch; this entry names symbols instead and says
why.

**2. `TC-497` is authored and gated** in `tests/test_report_addendum_bound.py` (+148 lines) — the
verbatim-grep node over the shipped requirement text, owned by Inc-3 alone.

- **Executable half:** the seven residual figures appear verbatim in `REQUIREMENTS.md`. The spec's
  threshold is *"the union of `REQUIREMENTS.md` + the PR body"*; a pytest node cannot read a PR body,
  so this asserts on **`REQUIREMENTS.md` alone — strictly stronger** (a document satisfying it
  satisfies the union) and, unlike the union form, runnable in CI on every future commit. The union
  form would let the durable artefact drop a figure as long as a PR description nobody re-reads once
  carried it. Stated in the node's docstring, not assumed.
- **A grep that fails must say WHY.** `_typographic_variants` re-searches each missing figure in its
  look-alike spellings (` ` / ` ` / ` ` / ` ` for the spaces, `× ` and `× `
  for the multiplication sign, `->` for the arrow) and the failure message separates *"the author
  omitted the figure"* from *"the author wrote it with a narrow space"*. Those are different defects
  with different fixes and the second one is **invisible in a rendered diff**.
- **Inspection half, flagged as a judgement and NOT automated.** The spec's other half — a named
  reviewer recording **0** occurrences of a whole-report-peak closure claim and **0** of an
  `R`-independence claim on the *work* axis — has no pattern; *"no sentence anywhere means X"* is not
  a grep. It is signed in §4.4 below. What **is** decidable is asserted: the entry must carry an
  explicit `does NOT claim` paragraph and all six lettered non-claims.

**3. Review finding M2 — the column-0 guard is extended and the invariant is now guarded.**
`test_no_escaped_field_is_emitted_at_the_head_of_its_line` walked `ast.JoinedStr` only, so the batch's
one new markdown sink — a `.format()`-built notice — was outside it, and `report_service.py`'s comment
on `ADDENDUM_TRUNCATION_NOTICE_FMT` *documented* that blindness instead of closing it. The guard now
also walks `NAME.format()` over module-level string constants.

**The offender condition had to be a TEMPLATE SHAPE, not an argument spelling, and that was forced.**
The notice's variant ids are escaped at the recording site inside the traversal and arrive at
`.format()` as `", ".join(named)`. A predicate keyed on `md_safe(...)` appearing as the `.format()`
argument — the obvious reading of "extend the walk" — would match **nothing** on the only such site in
the module: a guard that cannot fire, which is the defect class under repair. The decidable invariant
is the template's own shape: **no line of a module-level format template may begin with a substitution
field**. That is conservative (it flags a head field whatever is bound to it) and the conservatism is
free at one site.

The guard is refactored into `head_of_line_offenders(source)` so the same detector serves both the
absence assertion and a **positive control**, `test_head_of_line_guard_detects_a_planted_violation`,
which plants three offending spellings into the **real** `report_service.py` text — `AT-193b`'s
precedent, because a guard asserting an absence over a fixed tree passes whether or not its detector
works. The constant's comment is corrected from *"is structurally blind to it"* to a statement of what
now enforces it.

**4. Three spec defects are recorded as Before → After amendments** in a new
`01-requirements.md` **§9d (A-41…A-46)**, plus the three Inc-2 carried:

| id | subject |
|---|---|
| A-41 | the region-op seam: module global → keyword-only `ops_counter` (operator ruling, from Inc-2) |
| A-42 | `AT-194`'s warm-up window and `TC-488`'s leaf size — two fixtures that made their own gate unreachable (from Inc-2) |
| A-43 | **`TC-487`'s arm `FIX-E` → `FIX-E(b)`** — the arm assigned to it has no detection power there |
| A-44 | **§11.1's summary tally `29 rows` → `30 rows`** — the table was right and was followed |
| A-45 | **`TC-494`'s 5-element order vs §11.1's illustrative 4 — NOT a contradiction**; the illustration was corrected, the test stands |
| A-46 | **§10.10's column-0 guard: *"structurally blind, unconditionally"* → extended and closed** |

The bodies §11.1's `TC-487` row, §11's Inc-2 gate cell, §6.3's arm list, §11.1 note 1, §11.1's tally
sentence, §11.1's `TC-494` row, §10.10 fact 2 and §1.5's document overview were edited to match, each
pointing at its amendment id.

## 2. Files modified

Five files — the ≤ 5 cap exactly, and it is the cap that decided what did **not** happen (§6 item 1).

- `REQUIREMENTS.md` — the new `R-TUI-098` section (+134 / −0).
- `tests/test_report_addendum_bound.py` — `TC-497`, `_RESIDUAL_FIGURES`, `_LOOKALIKE_SPACES`,
  `_typographic_variants` (+148 / −0). No existing node touched.
- `tests/test_report_field_census.py` — `head_of_line_offenders` + three helpers; the existing guard
  re-pointed at it; the positive control added (+230 / −17).
- `s19_app/tui/services/report_service.py` — **comment only** (+11 / −5), on
  `ADDENDUM_TRUNCATION_NOTICE_FMT`. No statement changed; `python -m ruff check` clean; byte identity
  unaffected by construction.
- `.dev-flow/2026-07-28-batch-65/01-requirements.md` — §9d (A-41…A-46) and the eight body corrections
  above (+148 / −5).

`.dev-flow/2026-07-28-batch-65/03-increments/increment-003.md` is this packet, not counted, per the
Inc-1 / Inc-2 precedent.

## 3. How to test

```bash
# the batch's own nodes — 28 from Inc-1/Inc-2 plus TC-497
python -m pytest tests/test_report_addendum_bound.py -q
python -m pytest tests/test_report_addendum_bound.py -q -k tc497

# the extended guard and its positive control
python -m pytest tests/test_report_field_census.py -q

# Inc-3's gate
python -m pytest -q -m "not slow"

# §6.3 regression subsets — per subset, NOT merged
python -m pytest -q tests/test_report_service.py tests/test_tui_report_seam.py \
                   tests/test_report_field_census.py tests/test_manifest_writer.py \
                   tests/test_capped_text_area.py
python -m pytest -q tests/test_report_service.py tests/test_report_addendum.py
python -m pytest -q tests/test_tui_report_filter_surface.py tests/test_before_after_report.py

# BOTH frozen guards
python -m pytest -q tests/test_engine_unchanged.py
python -m pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"

python -m ruff check tests/test_report_addendum_bound.py tests/test_report_field_census.py \
                     s19_app/tui/services/report_service.py
git status --porcelain tests/goldens/        # empty — no golden re-baselined
```

## 4. Test results

### 4.1 `TC-497` — authored, GREEN, and driven RED on three arms

`python -m pytest tests/test_report_addendum_bound.py -q -k tc497` → **`1 passed, 28 deselected in
0.36s`**.

The seven figures, counted in the shipped `REQUIREMENTS.md`:

```
  4  '988 B/entry'
  1  '\xd71.68'
  1  '\xd71.81'
  1  '\xd71.94'
  1  '19200 → 300'
  2  '500 → 128000'
  2  '+N more'
exotic whitespace in the document: []
```

**The narrow-space hazard the brief warned about does NOT obtain, and that was verified, not assumed.**
A character census of both documents returns **zero** U+00A0 / U+202F / U+2009 / U+2007 / U+2060 /
U+FEFF: revision 3's normalisation held. `×` is U+00D7 with **no** space before the digits; `→` is
U+2192 with an ordinary U+0020 on each side. The grep list was built from those bytes, not transcribed.

**Detection power, executed** — three planted mutations of `REQUIREMENTS.md`, each reverted and the
file restored bit-for-bit (`sha256 1aa06bc9…` before and after every arm):

| arm | plant | observed |
|---|---|---|
| P1 | `×1.94` → `×`+U+202F+`1.94` (narrow no-break space) | **RED.** `'×1.94' … -- but a look-alike IS present: […]; the figure was typographically mangled, not omitted` |
| P2 | `+N more` → `+several more` | **RED.** `"'+N more' (ascii '+N more') -- absent in every spelling"` |
| P3 | non-claim `(e) **` → `(e) ` | **RED.** `R-TUI-098's non-claims (a)-(f) are the residual index the figures above hang from; these are missing: ['e']` |

P1 is the arm that matters: it is the exact failure mode the brief flagged, it renders identically to
the correct figure, and the node not only caught it but **named it as a mangle rather than an
omission**.

### 4.2 Review finding M2 — the extended guard, shown failing before it is claimed to work

Executed against the **real** `report_service.py` source, with the load-bearing plant: deleting the
literal `> ` prefix from `ADDENDUM_TRUNCATION_NOTICE_FMT`, which is the single edit that puts the
notice's escaped variant ids at column 0.

```
baseline report_service.py sha256 f62a6a0f6cdb444c5ab62615f4b6ed5af1667b7df0455c4128cc022ccce8f3e4

OLD guard (JoinedStr only) on the PLANTED source -> []   <-- BLIND: reads clean

EXTENDED guard on the same PLANTED source: exit 1
    tests/test_report_field_census.py:1095: AssertionError: a file-derived value is emitted at the
    head of its own line template, where a leading block starter is no longer defused by the caller's
    literal prefix: ['line 1889: ADDENDUM_TRUNCATION_NOTICE_FMT.format() — {label} at the head of a line']

restored == True
```

**The old guard reading `[]` on the same plant is the evidence, not a footnote.** Without it, "the
extended guard is RED here" would not distinguish a closed hole from a guard that was always going to
fire.

Both other arms, through the same detector:

```
clean source offenders   : []
prefix-removed plant     : ['line 1889: ADDENDUM_TRUNCATION_NOTICE_FMT.format() — {label} at the head of a line']
newline-inserted plant   : ['line 1889: ADDENDUM_TRUNCATION_NOTICE_FMT.format() — {dropped} at the head of a line']
f-string plant           : caught by walk 1 as `md_safe(...)`
```

The three arms are permanent as `test_head_of_line_guard_detects_a_planted_violation`, so the control
does not decay into this packet. It asserts its own precondition first (the unmutated source must be
clean) and that each plant actually applied, so an arm cannot pass by measuring nothing.

### 4.3 Suites — one complete run each

| run | command | observed |
|---|---|---|
| batch nodes | `pytest tests/test_report_addendum_bound.py -q` | **`29 passed in 1.25s`** |
| census file | `pytest tests/test_report_field_census.py -q` | **`34 passed in 2.05s`** |
| **Inc-3 gate — full non-slow suite** | `pytest -q -m "not slow"` | *(§4.6)* |
| regression subset 2 | `pytest -q tests/test_report_service.py tests/test_report_addendum.py` | **`44 passed in 1.76s`** — the §6.3 baseline, unchanged |
| engine-freeze **path** guard | `pytest -q tests/test_engine_unchanged.py` | **`1 passed in 0.07s`** |
| engine-freeze **test-file** guard | `pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"` | **`6 passed, 168 deselected in 0.63s`** |
| frozen-module diff | `git diff --name-only main -- <the 7 frozen paths>` | **empty — zero frozen-module diffs** |
| goldens | `git status --porcelain tests/goldens/` | **empty — no golden re-baselined** |
| lint | `ruff check` on the three code files | **`All checks passed!`** |

**`29`, not `28`.** The brief expected 28; 28 is the Inc-1/Inc-2 node set and `TC-497` is the 29th,
authored here per §11.1's own row (*"`TC-497` | authored **Inc-3** | gated **Inc-3**"*). The 28
pre-existing nodes are unchanged — this increment edited none of them — and all 28 are in the 29.

**`ruff check s19_app/` reports one `F821` at `app.py:5477`.** Verified pre-existing: the identical
single error is produced by piping `git show 082ada9:s19_app/tui/app.py` through `ruff` at the same
line. Not this batch's, not fixed here, per the brief.

### 4.4 `TC-497`'s inspection half — signed

Reviewer: **software-dev (Inc-3 author)**, recorded as such rather than as an anonymous ✓. The brief
does not name an independent reviewer for this increment, so this signature is **one party, and the
packet says so** — a second signature at the PR-level qa gate would strengthen it and is proposed in
§7.

Read: the whole `R-TUI-098` section as shipped.

- **Whole-report-peak closure claims: 0.** The entry states the opposite explicitly — *"The project
  report's resident-memory exhaustion axis is NOT closed"* — and gives the reason a whole-report
  acceptance is unsatisfiable rather than merely omitting one.
- **`R`-independence claims on the work axis: 0.** Every independence claim in the Statement and in
  the mapping table is qualified to **candidate consumption**; non-claim (e) states the relocation
  with its numbers, and the mapping row for `TC-498` calls it *"the §10.7 disclosure, non-claim (e)"*
  rather than a bound.
- One phrase was **changed during review for exactly this reason**: an earlier draft of the `Code:`
  row read *"membership reuses `range_index`"*, which reads as a soundness claim over overlapping
  ranges. It now reads *"as a **sound reject pre-filter only**"*.

### 4.5 Regression subsets 1 and 3

*(filled from the run below)*

### 4.6 Full non-slow suite — Inc-3's gate

*(filled from the run below)*

## 5. Risks

### Finding 1 — Inc-2's packet mis-stated its own diff scope (reported, nothing reverted)

Inc-2's §2 lists **three** files and its §4.5 asserts *"`git diff --stat 082ada9 -- s19_app/` touches
`report_service.py` only"*. Executed here:

```
git diff --numstat 082ada9 -- s19_app/ tests/
5       2       s19_app/tui/services/report_addendum.py     <-- not in Inc-2's file list
559     33      s19_app/tui/services/report_service.py
3583    0       tests/goldens/batch64/addendum-below-bound.md
2715    0       tests/test_report_addendum_bound.py
95      5       tests/test_report_field_census.py
144     0       tests/test_tui_report_seam.py
```

The `report_addendum.py` change is **docstring-only** — `DeclaredRegion`'s `Data Flow` block, updated
to say that `contains` is no longer the addendum's membership path but remains the oracle its tests
compare against. So: **no gate is invalidated, no behaviour is affected, and Inc-2 stayed inside the
≤ 5 cap at four files.** What is wrong is the *claim*, and it is the kind of claim a later batch
greps: a frozen-module or blast-radius question answered from Inc-2's packet would get the wrong
answer. Reported rather than quietly corrected in Inc-2's file, and `REQUIREMENTS.md`'s `Code:` row
lists `report_addendum.py` with its scope.

### Finding 2 — `TC-497` is only as good as the list it greps, and the list is hand-maintained

The node proves seven strings are present. It cannot prove they are the **right** seven: that binding
lives in §3's "Numeric pass threshold" block and nothing mechanically ties the two. If a later batch
adds a residual with a number, `TC-497` stays green while the new figure goes unrecorded. The
mitigation actually taken is the near-miss diagnostic (which defends the figures that *are* listed
against silent typographic decay); the un-taken one — deriving `_RESIDUAL_FIGURES` from the spec by
parsing the fenced block — was rejected because it would make a test depend on a `.dev-flow/`
document's formatting, and `.dev-flow/` is not shipped. **Recorded, not defended against.**

### Finding 3 — the extended guard's conservatism is real, and its cost is currently zero

Walk 2 flags **any** head-of-line field in a module-level format template, including one bound to a
constant (`{label}` is `ADDENDUM_CLASS_LABELS[hit_class]`). Today `report_service.py` contains exactly
**one** `.format()` call site, so the rule costs nothing. If a later batch adds a format template that
legitimately opens with a substitution — a table row builder, say — this guard will fail and the
author will have to either add a literal prefix or narrow the rule. That is the intended trade (a
false positive is a conversation; a false negative is a shipped injection), but it is a trade, and the
next author should meet it in this packet rather than in a red CI run.

### Other risks

4. **`head_of_line_offenders` is a public name in a test module.** It is imported by nothing outside
   the file today. It is public rather than `_`-prefixed because the positive control documents it as
   the shared detector, and a `_`-name shared by two tests reads as an accident. If a second census
   file ever wants it, it should move to a helper module rather than be cross-imported, which is how
   `AT-200`'s `_const` cross-import became a two-file gate at Inc-1.
5. **The `Example` in `head_of_line_offenders`'s docstring is executable and was executed**
   (`['line 2: T.format() — {a} at the head of a line']`), but no doctest runner is configured in this
   repo, so it is not enforced by CI. It will rot silently if the message format changes.
6. **This increment touches `s19_app/` for a comment.** It is +11/−5 of `#:` lines with no statement
   change and `ruff` is clean, but it does mean the Inc-3 diff is not documentation-only, and the
   `AT-196` byte-identity argument for it is *by construction* (comments are not emitted) rather than
   by a fresh golden comparison. The full-suite run in §4.6 is what actually exercises it.
7. **An uncommitted `.dev-flow/state.json` change is in the working tree.** It records the orchestrator's
   close-out plan and the skills-library boundary. **This increment did not write it** — flagged, as
   Inc-1 and Inc-2 flagged it.

## 6. Pending items

1. **`.dev-flow/BACKLOG-CODE.md` and `.dev-flow/2026-07-28-batch-65/PLAN.md` are NOT written, and that
   is a deliberate stop at the boundary.** §11's Inc-3 row allocates them (the §10.3 / §10.5 / §10.7 /
   §10.8 / §10.9 / §12 X-8 carries, each with its number; the PLAN decision log). The brief re-scoped
   Inc-3 to four numbered items — `REQUIREMENTS.md`, `TC-497`, the two code-review findings, the
   amendment log — and those consumed the ≤ 5 file cap exactly. Writing the backlog carries would be a
   sixth and seventh file **and** a substantive judgement act (six new carries, with severities), so it
   is raised rather than taken. **The batch's own close-out rule makes the Lane-A reconciliation
   mandatory**, so this must be authorised as Inc-4 or folded into the close-out — it is not optional
   and it is not done.
2. **`TC-497`'s inspection half carries ONE signature** (§4.4), the increment's own author. The spec
   says *"signed by a named reviewer"*; a self-signature satisfies "named" and not "independent".
   Proposed to the PR-level qa gate in §7.
3. **§9d's amendments are not yet mirrored into `REQUIREMENTS.md` §6.5.** The `Status:` line points at
   `01-requirements.md`'s §9 / §9b / §9c / §9d and the range A-1…A-46, matching how batch-62's entry
   points at its own A-01…A-43. If the project wants the amendment bodies inside `REQUIREMENTS.md`
   rather than referenced, that is a separate, larger edit — batch-62 set the referencing precedent and
   this entry follows it.
4. **The `ADDENDUM_CLASS_LABELS` positional-consumption coupling is still recorded, not defended**
   (Inc-2 risk 7). Nothing in this increment changes it; it now also has a documentation home in
   `REQUIREMENTS.md`'s `Code:` row.
5. **`AT-194` and `TC-493` remain the only nodes reading `tracemalloc`.** Unchanged by this increment;
   still the two nodes that could flake on a different interpreter.

## 7. Suggested next task

**Inc-4 — the backlog reconciliation and the PLAN decision log (2 files), then Phase 4.**
`.dev-flow/BACKLOG-CODE.md` gains the six carries **each with its number** — §10.3 (`R` uncapped:
≈ 11.6 kB/region no-cap, ≈ 20 kB/region all-caps; cap it with a `MAX_DECLARED_REGIONS` mirroring
`REPORT_MAX_REGIONS_PER_VARIANT = 128`, which bounds §10.7 in the same change), §10.5
(`changes/apply.py::_first_intersecting_symbol` carries its own copy of the overlapping-range defect —
**local fix, not a primitive unfreeze**), §10.7 (`500 → 128000 @ R = 256`), §10.8 (three
`> TRUNCATED:` emitters, two feed the appendix and two do not — unify), §10.9
(`ADDENDUM_NOTICE_VARIANTS_MAX` for `V > 8` projects), §12 X-8 (the dropped-severity signal, at MED) —
plus D1 marked closed **with its residuals restated by number**, and F2/OB-4 explicitly **left open**.
`PLAN.md` gains the decision log. Its gate: every carry traceable to a §10 subsection, D1's closure
naming what it did **not** close, and a second signature on `TC-497`'s inspection half from the
independent PR-level qa reviewer.

**Amendments this increment introduces, for the record:** A-41…A-46, bodies in `01-requirements.md`
§9d.

---

## Evidence checklist

- [x] **Tests/type checks/lint pass (or why skipped).** *(§4.3 / §4.6)* — `29 passed` on the batch
      nodes, `34 passed` on the census file, `44 passed` on regression subset 2, both frozen guards
      pass, `ruff check` on all three code files → `All checks passed!`. No type checker is configured
      in this repo. The pre-existing `F821` at `app.py:5477` was **verified on the base `082ada9`** and
      deliberately not fixed. Nothing skipped.
- [x] **No secrets in code or output.** No new fixture writes anything outside `tmp_path`; `TC-497`
      reads a tracked repo document and prints only figures from it. The planted-violation runs wrote
      to two tracked files and restored both **bit-for-bit, verified by sha256** (`1aa06bc9…` for
      `REQUIREMENTS.md`, `f62a6a0f…` for `report_service.py`). Host-path scan: `REQUIREMENTS.md`'s new
      section contains no absolute path.
- [x] **No destructive commands run without approval.** No `rm -rf`, no force push, no rename, no
      deploy, no commit. Two temporary same-file writes, both restored and both verified by digest.
- [x] **File count within cap.** 5 files, at the cap — and §6 item 1 records what the cap excluded
      rather than silently absorbing it.
- [x] **Review packet attached.** This document.
- [x] **Every new guard shown FAILING before it was claimed to work.** `TC-497` on three planted arms;
      the extended column-0 guard on the real-source prefix plant, **beside the pre-Inc-3 guard reading
      clean on the same plant**.
