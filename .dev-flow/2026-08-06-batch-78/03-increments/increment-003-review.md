# Code Review — batch-78 Increment 3 (`AT-B78-31`)

> Independent `code-reviewer` lane. Reviewed commit **`c88b0ad`** against base **`aaa382d`**.
> Repo `C:\Users\jjgh8\Github\s19_app`, branch `claude/batch-78-cmdbar-a2bdiff`.
> Every figure below was **re-executed in this review**, not read from the packet.

---

## BLUF

**PASS — OK to advance. Zero HIGH findings.** The node is a genuine C-12
output-then-consume acceptance: it drives the shipped Report button with the
**real** generators, re-reads both files **from disk**, and compares against the
fixture's own run list. All three declared mutations reproduce exactly as the
packet reports, including the distinction that is the increment's finding —
**`LLR-122.4`'s literal wording does not compile and reddens in the driver, while
§5.3's wording reddens on the node's own assertion.** `C-78-xv` is a sound
lesson and I recommend encoding it.

Six findings: **2 MEDIUM, 4 LOW, 0 HIGH.** Both MEDIUMs are about the new
**driver's** discipline, not about the node's oracle. Neither blocks.

| # | Finding | Severity |
|---|---|---|
| **F1** | `_b78_press_report` waits on a **level**, not an edge — unsound on a second press in one app, and it is advertised for inheritance | 🟡 MEDIUM |
| **F2** | The driver's `C-78-xii` conformance was **argued, not executed**; Inc-2 set the discharge bar at a perturbation census. **Now discharged by this review** | 🟡 MEDIUM |
| **F3** | `_b78_section` raises a bare `ValueError` on a heading change; R-2's stated mitigation does not cover that arm | 🔵 LOW |
| **F4** | Design-choice-2's rationale is empirically false for this regex | 🔵 LOW |
| **F5** | §6.1 and §4.3's restore-proof describe an **uncommitted** tree; the reviewed commit contains the change | 🔵 LOW |
| **F6** | `LLR-122.4`'s "**128** painted" half is never asserted green — only in the mutation transcript | 🔵 LOW |

---

## Scope reviewed

`git diff aaa382d..c88b0ad` — `tests/test_tui_diff_screen.py` **+199 / −0**
(lines 1650–1848: 2 module constants, 4 helpers, 1 node) plus the packet
`increment-003.md`. **`git diff --stat aaa382d..c88b0ad -- s19_app/` is empty —
zero production change, confirmed independently.**

---

## What I verified as SOUND

### 1. It is genuinely C-12 output-then-consume ✅

Traced the whole path rather than trusting the claim:

- `_b78_drive_compare` (Inc-2, `tests/test_tui_diff_screen.py:244-270`)
  monkeypatches **`compare_images` only**. `generate_diff_report` and
  `generate_diff_report_html` are **not** patched anywhere on this path —
  confirmed by reading the helper and by the fact that the parsed documents
  carry the real generator's `## Runs` / `<h2>Runs</h2>` structure.
- `_b78_press_report` sets `#diff_report_dest.value`, which is **exactly** the
  field the shipped panel reads to build the message
  (`screens_directionb.py:6872-6877`), then presses `#diff_report_button`.
- The oracle is `expected_starts = [start for start, _end, _kind in runs]`,
  built in the test body from its own fixture. **Nothing** in the expectation
  reads `panel._runs`, the generators, or `DISPLAY_MAX_RUNS`.
- Both files are re-read with `read_text` from a fresh `tmp_path` destination,
  and the driver asserts **exactly one** `.md` and one `.html` are present.

**If either generator were monkeypatched this would be a consumer-contract
guard and could not serve as the gate. It is not.**

### 2. The three mutations — re-executed independently ✅

I re-derived the harness from scratch (own anchors, own post-images) rather than
running the author's. Discipline applied: anchor matches **exactly once**;
post-image **absent before / present after**; **pre-image absent after**; sha
compared to the fixed tree **and to every previous mutation**; restore from an
**out-of-tree byte copy**, verified by sha.

```
############ BASELINE  sha 21e3ad53c3c687b9 ############       [matches the packet]
  VERDICT: GREEN            1 passed in 1.35s

############ MUTATION A  runs=panel._runs INTO THE REPORT KWARGS (LLR-122.4, literal)
  anchor matches                        : 1
  post-image absent-before/present-after : True/True
  pre-image (anchor) absent after write  : True
  sha fixed -> mutated                  : 21e3ad53c3c687b9 -> d4bf542c5d095621   [matches the packet]
  VERDICT: RED
E   AssertionError: the report worker took a FAILURE ARM, so no complete file exists to
    observe; #diff_status reads "Diff report failed: TypeError: generate_diff_report()
    got an unexpected keyword argument 'runs'"
    tests\test_tui_diff_screen.py:1719   <-- IN THE DRIVER
############ A REVERTED - sha MATCH=True ############

############ MUTATION B  route the report off panel._runs (§5.3, type-preserving)
  anchor matches                        : 1
  post-image absent-before/present-after : True/True
  sha fixed -> mutated                  : 21e3ad53c3c687b9 -> af088c305b6a901a  distinct from A
  VERDICT: RED
E   AssertionError: the written Markdown report must list EVERY run of the comparison,
    in order; it lists 128 of 200. First missing start address: 2048
    tests\test_tui_diff_screen.py:1827   <-- ON THE NODE'S OWN ASSERTION
############ B REVERTED - sha MATCH=True ############

############ MUTATION C  cap ONLY the HTML generator's input
  anchor matches                        : 1
  post-image absent-before/present-after : True/True
  sha fixed -> mutated                  : 21e3ad53c3c687b9 -> eb0de113142472bb  distinct from A and B
  VERDICT: RED
E   AssertionError: the written HTML report must list EVERY run of the comparison, in
    order; it lists 128 of 200. First missing start address: 2048
    tests\test_tui_diff_screen.py:1834   <-- the MARKDOWN clause passed; only HTML reddened
############ C REVERTED - sha MATCH=True ############

############ FINAL sha 21e3ad53c3c687b9 == baseline: True ############
```

*(B and C shas differ from the packet's because my post-images alias the imports
`_dc`/`_DR`; A's sha matches the packet **exactly**, which cross-validates both
harnesses. `s19_app/tui/app.py` is byte-identical to `HEAD` after the run —
`git diff HEAD -- s19_app/tui/app.py` is empty and the sha is back to
`21e3ad53c3c687b9`.)*

**The distinction holds, and it is the increment's real finding.** F-1's
classification is correct by the project's own control (*a counterfactual must
fail on its ASSERTION*): mutation A prevents the subject from executing at all —
`TypeError` at the call boundary, swallowed by the worker's `except Exception`,
surfaced as a status line, caught by the driver's failure arm at line 1719. The
node's assertion never runs. **That certifies the driver, not the predicate.**
§5.3's semantic wording is the one that discharges the node.

**Verdict on `C-78-xv`: sound, and I recommend encoding it.** The evidence is
unusually clean — one document, two sections, the *same* mutation, and only one
of the two is executable. The generalisation ("a declared mutation must be
stated as a value substitution that type-checks") is the right altitude: it is a
property of the *statement*, not of this call site, and it composes with the
existing `record-the-substituted-VALUE` control rather than restating it. §7's
Inc-4 row already carries the same family (NEW-3), which is independent
corroboration that this is a recurring class and not a one-off.

### 3. The HTML clause is independently live ✅

Mutation C is the arm that matters and it does what the packet claims: the
Markdown assertion **passed** and the HTML assertion reddened on its **own**
message. A second clause that only ever fails alongside the first is not a
second observable; this one is.

### 4. The oracle is a start-address LIST ✅

`assert md_starts == expected_starts` — a full ordered list, not a count.
Confirmed in the transcript: the message names *which* run went missing
(`First missing start address: 2048`), and `2048 = 128 × 16` is arithmetic
evidence the drop was the display cap specifically. A count oracle could not
say that, and could not catch reordering or de-duplication. Correct call, and
correct given this batch's history with count-vs-set.

### 5. The section parser does exactly what it claims (structurally) ✅

Generated a real 200-run report pair directly from
`diff_report_service` with **populated** mem maps (the harder case — the test's
own fixture has `path=None`, so its hex windows are empty) and enumerated every
heading:

```
MD:   # Diff report / ## Statistics / ## Runs / ## Hex windows / ### Runs 0x...
HTML: <h1>Diff report</h1> / <h2>Statistics</h2> / <h2>Runs</h2> / <h2>Hex windows</h2>
MD rows in section=200   whole-document=200   total=200
HTML rows in section=200 whole-document=200   total=200
```

The `## Runs` → `\n## Hex windows` slice is correct, and `\n## ` cannot
false-stop on `\n### `. Also confirmed the report generator itself imposes **no**
run cap or byte budget (`diff_report_service.py:1129, 1238, 1693, 1905`), so the
requirement is not silently bounded by the producer.

### 6. `_b78_press_report` is a REAL completion wait ✅ (not `pause()` in disguise)

The mechanism is sound: `_start_diff_report_worker` writes the success status
via `call_from_thread` (`app.py:5107-5112`), which **blocks the worker** until
the callback has run on the UI thread — and that call is reached only after
**both** generators have returned and closed their files (`app.py:5067`, `:5080`,
`:5092`). Reaching `"Diff report written:"` therefore happens-after both writes.
All four failure arms (`Report refused:` `:5075`, `HTML report refused:` `:5099`,
`Diff report failed:` `:5089`, `No comparison yet` `:4972`) are named and raise
loudly, so the wait is total.

**I executed the census the packet only argued** (see F2):

```
injected delay    0 ms/generator -> 200 of 200 runs re-read from disk, complete=True
injected delay   50 ms/generator -> 200 of 200 runs re-read from disk, complete=True
injected delay  500 ms/generator -> 200 of 200 runs re-read from disk, complete=True
```

Two delays an order of magnitude apart plus a control arm. **The driver holds.**

### 7. F-5 is TRUE, and the two nodes really do carry the unsound shape ✅

I proved the mechanism rather than reasoning about it:

```
worker-set size immediately after press() : 0
wait_for_complete() returned after        : 0.8 ms   (the generators sleep 1000 ms)
#diff_status right after the wait         : 'Compared A.s19 vs B.s19: 1 runs.'
-> F-5 CONFIRMED (the wait did not wait)
```

`Button.press()` only posts `Pressed`; the handler that creates the
`@work(thread=True)` worker has not run, so the worker set is **empty** and
`wait_for_complete()` is a no-op. `test_tc024_report_trigger_surfaces_paths`
(`:462`) and `test_tc024_report_trigger_invalid_dest_refused` (`:510`) both carry
it, and both are green only because their generators are `write_text` stubs.

**Judgment on scope: leaving them was RIGHT.** They are pre-existing, §7 gives
Inc-3 exactly one file and one node, and — decisively — they are **fragile, not
false**. Their assertions (`md_path.name in status`, `"bad destination" in
status`) would *fail loudly* under a lost race, not pass vacuously, and their
stub generators cannot become slow by accident. Nothing batch-78 ships depends
on them: §7 lists TC-024 in no increment. Recording `C-78-xiv` with both node
names is the correct handling.

**One addition I'd make to the carry** — see F-lint below: both nodes carry a
comment on disk asserting the race *was* fixed:

> `# ... A bare pause() passed only because the fake generators are instant — a race this suite must not depend on.` followed by `await app.workers.wait_for_complete()`

That comment is now **known false**, and a false comment claiming a race is
handled is worse than the unsound wait itself, because it tells the next reader
to stop looking. `C-78-xiv` should name the comment explicitly so whoever
discharges it deletes the claim, not just the call.

### 8. Ledger, gate, snapshot, tree hygiene ✅ — all reproduced

| Claim | Packet | My re-execution | |
|---|---|---|---|
| The node | `1 passed in 1.48s` | `1 passed in 1.35s` | ✅ |
| C-34 gate, FULL form, one run | `207 passed in 265.07s` | **`207 passed in 278.26s`** | ✅ |
| `--collect-only` | `2631` | **`2631 tests collected`** | ✅ `2626 + 2 + 3 = 2631` reconciles |
| Snapshot | 1 cell, `[diff-comfortable-120x30]` | **`1 failed, 31 passed`, that cell only** | ✅ no second cell moved |
| No production change | 0 | `git diff --stat aaa382d..c88b0ad -- s19_app/` empty | ✅ |
| C-26 reverse-grep, whole tree | resolves only in the one file | all 7 new symbols resolve **only** in `tests/test_tui_diff_screen.py` | ✅ |
| F9 (no third driver copy) | new driver | `_b78_press_report` shares no code with `_b78_press_compare`; waits a different signal for a different handler | ✅ |
| Tree untouched | no `add -A`, no stash | `git status --short` = `?? build/` + the parallel session's `prototypes/*` only | ✅ |

**P-50 reproduced.** `on_ab_diff_panel_report_requested` (`app.py:4960-5019`)
reads `self._diff_last_result` at `:4998` and passes it **whole** to the worker at
`:5019`; the `kwargs` dict (`:5006-5013`) contains `mem_map_a`, `mem_map_b`,
`project_dir`, `dest_input`, `a2l_records`, `mac_records` — **`panel._runs` is
never in it.** Baseline GREEN with all 200 runs in both written files.

**One check the packet did not claim, which I ran anyway:** six other
`test_at_b78_*` nodes already exist on this branch and none are in
`AT-TC-REGISTRY.jsonl`. `tests/test_id_registry.py` (G1–G7) is **green — 13
passed** — so Inc-3's new node introduces no registry drift. Not an issue; noted
so Inc-11 does not inherit a surprise.

### 9. Convention conformance ✅

Matches Inc-2's `AT-B78-18` shape exactly: fixture size (`_B78_OVER_CAP_RUNS =
200`) fixed **independently** of `DISPLAY_MAX_RUNS`; `0 < painted < total` as the
non-vacuity co-assertion; the constant-quoting guard **last** so a cap mutation
reddens the capping clause and not the guard (Inc-2 F-1). §5.1 rules 1, 4, 8 and
9 all satisfied. Docstring carries Intent / Falsifiability / Non-vacuity per the
module's convention.

---

## Findings

### F1 — `_b78_press_report` waits on a LEVEL, not an EDGE  [MEDIUM]

- **What:** The loop returns as soon as `"Diff report written:"` is *present* in
  `#diff_status`. Nothing snapshots the status before the press and nothing
  requires it to *change*. Inc-2's `_b78_press_compare` is edge-triggered by
  contrast — it captures `before = app._diff_compare_generation` and waits for a
  strict increase (`:230-234`). The report handler writes no status on entry, so
  the previous press's success line survives the second press.
- **Where:** `tests/test_tui_diff_screen.py:1711-1735`.
- **Executed, not argued:**
  ```
  second press -> raised after 0.8 ms   (the md generator alone sleeps 400 ms)
  detail: the success status was written but the destination does not hold
          exactly one report of each kind: md=[], html=[]
  files actually in the second destination: []
  ```
  The driver returned on the **first** press's status, 0.8 ms in.
- **Why it matters:** Today, nothing. One node, one press, and the
  `len(written_md) == 1` glob assertion catches the second-press case **loudly**
  — so there is no false-green and this is not a HIGH. But the docstring
  explicitly sells the driver for inheritance — *"nodes not yet written inherit
  it"* — and states it carries the `C-78-xiii` positive co-assertion for them.
  **That guarantee is only sound for a single press.** A future node that
  presses Report twice gets a failure blaming the *destination*, which is
  precisely the wrong place to look, and would cost someone the same hour Inc-2
  spent on `C-78-xii`.
- **Suggested fix** — one line, same edge-triggered discipline as the compare driver:
  ```python
  app.query_one("#diff_report_dest").value = str(dest_dir)
  before = str(app.query_one("#diff_status").render())     # ADD
  app.query_one("#diff_report_button").press()
  status = ""
  for _ in range(750):
      status = str(app.query_one("#diff_status").render())
      if status == before:                                  # ADD: not yet observed
          await pilot.pause(0.02)
          continue
      ...
  ```

### F2 — the driver's `C-78-xii` conformance was argued, not executed  [MEDIUM]

- **What:** `C-78-xii` states its own discharge standard: *"Discharge is a
  perturbation census at two delays an order of magnitude apart, with a control
  arm."* Inc-3 mints a **new** completion-wait driver and discharges it with a
  paragraph of `call_from_thread` reasoning. No perturbation was run.
- **Where:** `increment-003.md` §1 "The completion wait"; packet §4.3 contains
  three mutations, none of which perturbs timing.
- **Why it matters:** This is Inc-3's own F-1 lesson turned on its author. F-1's
  finding is that *the requirement author must execute the mutation they declare,
  not only name it* — and the same increment then asserts a timing property by
  construction. The reasoning happens to be right, but "happens to be right" is
  what `C-78-xii` cost this batch 14 nodes to learn.
- **Status: DISCHARGED BY THIS REVIEW.** Injected delays of 0 / 50 / 500 ms per
  generator; the driver returned the complete 200-run file at every arm (§6
  above). No further work is owed — but the evidence belongs in the packet, not
  only here.
- **Suggested fix:** paste the three-arm census into §4.3 as mutation D, and
  extend `C-78-xv`'s neighbourhood with the corollary: *a newly minted
  completion wait discharges by census, on the same terms as the control that
  created it.*

### F3 — `_b78_section` raises a bare `ValueError` when the heading moves  [LOW]

- **What:** `text.index(heading)` raises `ValueError: substring not found` if
  `## Runs` / `<h2>Runs</h2>` ever changes. R-2 in the packet claims the failure
  is diagnosable because *"the message prints `len(md_starts)`, and `0` vs `128`
  distinguishes 'format moved' from 'runs were capped'"*. That holds for a **row
  format** change; it does **not** hold for a **heading** change.
- **Where:** `tests/test_tui_diff_screen.py:1738-1746`; packet §5 R-2.
- **Executed:** `_b78_md_report_run_starts(<doc with '## Run table'>)` →
  `ValueError: substring not found`. No node name, no count, no context.
- **Why it matters:** Diagnostics only — the node still fails loudly. But this
  file's convention is that every failure names its subject, and a bare
  `ValueError` from a helper is the one failure in the new code that does not.
- **Suggested fix:**
  ```python
  start = text.find(heading)
  assert start != -1, (
      f"the written report no longer carries a {heading!r} section, so the run "
      f"table cannot be located; the document's headings are "
      f"{re.findall(r'^#{1,3} .*$|<h[123]>.*?</h[123]>', text, re.M)[:8]}"
  )
  ```
  and narrow R-2 to the row-format arm it actually covers.

### F4 — design-choice-2's rationale is empirically false for this regex  [LOW]

- **What:** Both the packet (§1, "Three deliberate choices", #2) and the
  `_b78_section` docstring justify the slicing with *"a whole-document regex
  would have counted rows that are not run entries"*.
- **Where:** `tests/test_tui_diff_screen.py:1740-1743`; packet §1.
- **Measured:** with **populated** mem maps so the hex windows actually render,
  whole-document `= 200`, section `= 200`, total `= 200` — in **both**
  documents. The regex demands two consecutive `| 0x........ |` fields; hex
  windows are `render_hex_view` rows inside ```` ```text ```` blocks and
  `<pre>` and carry no such pair. The slicing changes nothing today.
- **Why it matters:** The slicing is good defensive practice and I would keep
  it. But a justification stated as measured fact, which is not, is the
  lower-grade cousin of the vacuous check this batch keeps finding — and it
  invites the next author to trust the claim instead of the guard.
- **Suggested fix:** reword to the honest form: *"scoped to its own section so
  the parser cannot drift onto the hex-window dumps if the run-row format ever
  loses its second hex field; measured today, the whole-document count and the
  section count agree at 200."*

### F5 — §6.1 and §4.3's restore-proof describe a tree that no longer exists  [LOW]

- **What:** §6 pending item 1 reads *"The increment is NOT committed. The
  working tree carries `tests/test_tui_diff_screen.py` modified and nothing
  else"*, and §4.3's "Restore proof" cites `git status --short` listing exactly
  one modified file. The reviewed commit `c88b0ad` **contains** the change and
  the tree is **clean** (`git status --short` = `?? build/` + the parallel
  session's untracked `prototypes/*`).
- **Where:** `increment-003.md` §4.3 "Restore proof", §6 item 1.
- **Why it matters:** Small, but the restore evidence is the load-bearing part of
  a mutation run, and half of it is now stated against a vanished tree state.
  The **sha** half is the half that matters and it survives — I re-derived
  `21e3ad53c3c687b9` and confirmed `git diff HEAD -- s19_app/tui/app.py` is
  empty. This is exactly why the sha proof beats the `git status` proof.
- **Suggested fix:** drop §6 item 1 (or restate as *"committed at `c88b0ad`;
  merge decision owed"*) and cut the `git status` sentence from §4.3, keeping the
  sha.

### F6 — `LLR-122.4`'s "128 painted" half is never asserted green  [LOW]

- **What:** §4's numeric pass threshold is *"the written file holds **200** run
  entries against **128** painted"*. The node asserts the 200 exactly, and the
  painted side only as `0 < painted < total`. The 128 appears **only** in
  mutation B's transcript (`128 of 200`, first missing `2048 = 128 × 16`).
- **Where:** `01-requirements.md:515`; `tests/test_tui_diff_screen.py:1841-1846`.
- **Why it matters:** The author's choice is **correct** and I would not change
  the test — §5.1 rule 4 forbids a cap's expected value from depending on the
  constant under test, so `painted == 128` would either quote `DISPLAY_MAX_RUNS`
  (certifying the constant) or hardcode `128` (a C-36 phantom). `AT-B78-18` makes
  the same call. But §4 and §5.1 rule 4 are in **tension on disk**, and the
  resolution currently lives only in a review file.
- **Suggested fix:** at batch close, amend `LLR-122.4`'s threshold to
  *"the written file holds **200** run entries while the panel paints **strictly
  fewer** (128 today); the exact painted value is deliberately not asserted —
  §5.1 rule 4"*. Same treatment §4 already gives `LLR-122.3`.

### F-lint — `C-78-xiv` should name the false comment, not just the call  [LOW, folded into F-5's carry]

Both `TC-024` nodes carry a comment claiming the `wait_for_complete()` **fixed**
the instant-generator dependence. It did not (0.8 ms, empty worker set). The
carry as worded targets the call; it should target the claim.

---

## Verdict

- [x] **OK to advance.** Zero HIGH. The node is a sound C-12 through-surface
      acceptance, both clauses are independently live, the mutation distinction
      reproduces exactly, and every ledger/gate/snapshot figure re-executed to
      the packet's numbers.
- [ ] OK with the listed fixes applied first
- [ ] Block

**Recommended before batch close (none blocking):** F1's one-line edge trigger
and F2's census paste are the two worth doing while the context is warm — both
protect nodes that do not exist yet, which is the same argument `C-78-xiii`
already won. F3–F6 are documentation and diagnostics.

**Encode `C-78-xv`.** Its evidence is the cleanest single-occurrence case in the
batch: one document, two sections, one mutation, only one of them executable.

---

## Evidence checklist

- [x] **Diff read in full** — `tests/test_tui_diff_screen.py:1650-1848`, all 199 added lines; plus `increment-003.md` §§1–7 and the evidence checklist.
- [x] **Correctness pass (edge / None / error paths)** — all four worker failure arms traced to `app.py:4972, 5075, 5089, 5099`; the `zero_runs` branch (`diff_report_service.py:1379, 2048`) checked for a vacuous-pass path (there is none — the parser yields `[]` and the assertion reddens); the level-trigger race executed (F1).
- [x] **Simplicity pass** — no premature abstraction. 4 helpers, each used; no speculative parameters. `_b78_section`'s `stop in text[after:]` copies the tail to test membership then re-scans — `find` would be simpler, folded into F3's fix rather than raised separately.
- [x] **Reuse / duplication checked** — F9 holds: `_b78_press_report` duplicates neither `_b78_press_compare` nor `_press_compare`; C-26 reverse-grep over the whole tree shows all 7 new symbols resolve only in the increment's file, no collision.
- [x] **Tests reviewed for intent, not just behaviour** — the oracle is the fixture's own list, re-read from disk; both clauses reddened on their own messages under distinct mutations; the non-vacuity co-assertion and the constant-quoting guard are present and correctly ordered.
- [x] **Verdict explicit** — **PASS / OK to advance**; 0 HIGH, 2 MEDIUM, 4 LOW.
- [x] **Nothing modified that I did not create** — `s19_app/tui/app.py` restored from an out-of-tree byte copy and verified `21e3ad53c3c687b9` == baseline == `HEAD`. No `git add -A`, no `git stash`, no reset. The parallel session's `prototypes/memmap2.*` were never read into, staged or touched.
