# Inc-11 — merge-gate response: H-1, H-2, H-4

**Date:** 2026-08-12 · **Branch:** `claude/batch-79-cmdbar-deletion`
**Trigger:** the independent qa-reviewer merge gate returned **BLOCK** (4 HIGH / 5 MEDIUM / 5 LOW).
**Authorisation:** operator ruling 2026-08-12 — fix H-1 + H-2 + H-4, re-verify H-2/H-4 first, and run
the **full suite before every commit** from here on.

---

## 0 · BLUF

**The merge precondition paid for itself on its first use.** H-1 is a production regression that six
shipped tests catch, in two files **no session in this batch ever ran** — the batch's green was
derived from four test files out of thirty-plus. H-2 violated the very threshold `HLR-120` states, at
2 of 3 supported terminal sizes. H-4 was an acceptance arm that passed while certifying nothing.

**All three are the same defect one layer apart: a requirement clause with no implementing predicate.**
`LLR-120.2` says the project row *"shall not alter the existing three artifact slots"* — nothing
asserted it. `HLR-120` says the bar names both *"on 10 of 10 screens"* — the fixture could not make it
fail. `TC-B78-12`'s second arm asserted absence over a strip the payload never reached.

**Nothing was taken on the reviewer's word.** H-2 and H-4 were re-measured here before either was
touched, per the operator's ruling.

---

## 1 · H-1 — six shipped tests regress · CONFIRMED, FIXED

### Measured, both directions

| Tree | `test_unload_feature.py` + `test_help_toggle_and_a2l_panel.py` |
|---|---|
| `829adc6` (base) | **16 passed** |
| HEAD before fix | **6 failed / 10 passed** |
| HEAD after fix | **16 passed** |

### Mechanism

Inc-7 (`a1ab35c`) gave the Loaded panel's new project row the **`loaded-detail`** marker — the same
class the three artifact slots carry (set in `LoadedArtifactsPanel`'s slot-row builder). Two shipped readers
select on it and index the result **positionally** as `[primary, mac, a2l]`:

```
tests/test_unload_feature.py:270          for cell in panel.query(".loaded-detail")
tests/test_help_toggle_and_a2l_panel.py:72  cells = list(panel.query(".loaded-detail"))
```

The query began returning **4** cells with the project at index 0, silently re-pointing every artifact
index by one. `_detail_texts()[1]`, documented as MAC, returned the S19 row.

### Fix

The project row's detail cell carries **`loaded-project-detail`**, listed beside `.loaded-detail` in
`styles.tcss` so the two keep identical geometry and only the marker differs. The row keeps
`loaded-slot` for the column rhythm — verified nothing selects that positionally.

### The clause that had no predicate

`AT-B78-09` asserted only `"demoproj" in panel` over a **joined strip**. A containment check over a
concatenation **cannot see arity**: the project string is present whether the query returns 3 cells or
4. `LLR-120.2`'s threshold — *"the three slot rows' text unchanged (set equality)"* — had no
implementing assertion at all.

`AT-B78-09` now asserts over the **query**, which is what the shipped readers actually use:

- `len(panel.query(".loaded-detail")) == 3`
- **co-assertion (C-40):** exactly **1** `.loaded-project-detail` cell exists and names the project.
  Without it, deleting the project row outright would satisfy the arity clause — absence is trivially
  compatible with "exactly three".

---

## 2 · H-2 — a long project name evicts the A2L · RE-VERIFIED INDEPENDENTLY, FIXED

### Re-measured here before touching anything

Payload: project `ECU_calibration_release_2026_customerA_v161`, A2L
`ASAP2_ECU_calibration_release_2026_v161.a2l`.

| Terminal | project on | A2L on | verdict |
|---|---|---|---|
| 120×30 | 10/10 | **0/10** | threshold VIOLATED |
| 80×24 | 10/10 | **0/10** | threshold VIOLATED |
| 160×40 | 10/10 | 10/10 | passes |

`HLR-120`'s stated threshold is *"contains both on **10 of 10** screens"*. The A2L was visible before
this batch, on the command bar `HLR-118` deleted — so this is a **regression**, not merely an unmet
new requirement.

### Mechanism, and why the layer matters

`#status_context` is **one `Label` holding one composed string**, clipped by CSS at `max-width: 70%`.
The halves therefore cannot be bounded against each other in the stylesheet — whichever is written
second is the one that disappears. Measured:

```
composed string          91 columns
cell allocated width     53 @ 80x24 · 81 @ 120x30 · 91 @ 160x40
Label.render()           returns all 91 at EVERY size
```

**`render()` returned the full string while the painted strip was missing the A2L** — the identical
distinction that made the four gates in the mid-batch review's F2 structurally incapable of seeing F1.
The observable had to be the painted strip.

### Fix

`_compose_context_line` bounds the two halves in the **composer**, where the single string is built:
fair share of the budget with **slack redistribution** — each half may take half, and a half needing
less lends the remainder to the other. Neither can evict the other, and a short name is never
truncated merely because its partner is long. The budget is derived from the bar's live width times
`_CONTEXT_MAX_SHARE`, falling back to **53** — the measured cell width at the narrowest supported
terminal, i.e. the safe end of the range, never an optimistic one.

### Why `AT-B78-08` could not catch it

`AT-B78-08` varies the **status message** length — the horizontal axis F1 was about — but its context
fixture is `demoproj` / `b79ctx.a2l`, 8 and 10 columns, which fit at every size. It was blind **by
fixture construction, not by predicate design.**

> *A bound between two values is untested until both values are large at the same time.*

New nodes, in the free `B79` namespace (`TC-B78-45` is **taken** by `HLR-123`'s mechanism node —
checked before allocating):

- **`TC-B79-01`** — both halves survive on 10/10 screens at all three sizes. Asserts a discriminating
  **fragment** of each half, not the whole name, because the fix's whole point is that each half
  survives in *truncated* form — asserting the full string back would forbid the fix. Co-asserts the
  **project** half too: a fix that evicted the project instead is the same defect with the operands
  swapped.
- **`TC-B79-02`** — `_CONTEXT_MAX_SHARE` and the stylesheet's `max-width` agree. The budget is a rule
  stated in two places, which is this batch's signature defect shape, so it is asserted rather than
  left in a comment.

---

## 3 · H-4 — `TC-B78-12`'s second arm was vacuous · RE-VERIFIED INDEPENDENTLY, FIXED

### Re-measured here

```
'evil' in #status_context rendered : True
'evil' in #loaded_slots strip      : False        <-- the arm asserted over THIS
current_file.a2l_path              : None
#loaded_slots strip                : 'PROJ  demoproj   S19   a.s19  4 B · 1 rng   [u] MAC   (none)'
```

The payload was written to `current_a2l_path`; the panel's A2L slot reads `current_file.a2l_path`.
The hostile string never arrived, so the control-class clause ran over a strip that never received it
and passed **for that reason**. This is precisely the arm the spec added because *"two surfaces need
two arms"* — and the second arm was the one certifying nothing.

The presence co-assertion existed but was applied **only to `#status_context`**, then the loop
asserted absence over **both** strips. One surface's presence proof was doing duty for two.

### Fix

- The payload now rides on the **project name**, the one value that provably reaches both surfaces
  through `_compose_project_label` — and the limb `LLR-120.4` names that nothing asserted.
- The presence co-assertion moves **inside** the per-surface loop, so neither surface can go quiet
  without failing.

---

## 4 · Counterfactuals — 4 arms, 0 survivors

Each arm **restores the defect the fix removed** on the fixed tree; the guarding node must go RED on
its **own** assertion. Recorded as the substituted VALUE.

| Node | Substituted value | Verdict |
|---|---|---|
| `AT-B78-09` arity | `_build_project_row` detail cell → `classes='loaded-detail'` | RED — *"selected 4"* |
| `TC-B79-01` | `_compose_context_line` → `lambda self, p, a: f'{p}  \|  {a}'` | RED — A2L absent on 10 screens |
| `TC-B79-02` | `styles.tcss` `max-width: 70%` → `60%` | RED — *"caps at 60% but constant is 70%"* |
| `TC-B78-12` | `_refresh_loaded_panel` → `lambda self, *a, **k: None` | RED — *"must actually REACH #loaded_slots"* |

**Batch total for Inc-11: 9 arms, 0 survived, 0 errored.**

---

## 5 · Findings

### F-4 — the batch's green was measured on 4 files out of 30+, and that is how H-1 survived 5 increments.

Every increment gate in this batch ran `test_tui_commandbar` · `test_id_registry` ·
`test_tui_directionb` · `test_tui_diff_screen`. H-1 landed at Inc-7 and broke two files outside that
set. It stayed invisible through Inc-8, 9, 10 and 11 — and through the HANDOFF's claim that
*"everything else is green"*, which was never a measurement of "everything else".

**A gate's scope is part of its claim.** "289 passed" is true and was never evidence for the sentence
it was used to support. Operator ruling 2026-08-12: the **full suite** runs before every commit for
the rest of this batch.

### F-5 — three HIGH findings, one shape: a requirement clause with no implementing predicate.

| Clause | Stated in | Asserted by |
|---|---|---|
| *"shall not alter the existing three artifact slots"* | `LLR-120.2` | **nothing** |
| *"contains both on 10 of 10 screens"* | `HLR-120` threshold | a fixture that could not overflow |
| *"two surfaces need two arms"* | `HLR-120` acceptance | one arm, over a strip the payload missed |

Each was written down, reviewed through three Phase-2 rounds and two review lanes, and carried into
implementation — with nothing in the tree able to detect its violation. The project's dominant defect
class is not "the wrong assertion" but **the absent one**, and it hides because the requirement text
*reads* as though it were covered.

### F-6 — the AT/TC registry is blind to all 106 batch-78/79 acceptance nodes. **Found by accident; executed, not inferred.**

`tests/test_id_registry.py` was run expecting the two new `TC-B79-*` nodes to trip **G1** — *"an id on
a test node that nobody registered"*. It passed. That is the wrong outcome, so the deriver was
executed directly rather than read:

```
_FUNC_ID_RE  test_at_b78_09_loaded_panel_names_the_project  -> NO MATCH
             test_tc_b79_01_a_long_project_cannot_evict_... -> NO MATCH
             test_tc489_candidate_consumption_is_r_indep... -> ['_tc489']    ✅
             test_tc016s_density_layout_snapshot            -> ['_tc016s']   ✅

derive_named_nodes over the whole corpus : 678 ids, of which B78/B79-shaped = 0
iter_tokens("AT-B78-12") -> governed=False, conforming=False, key=None
iter_tokens("TC-489")    -> governed=True,  conforming=True,  key='TC-489'

test nodes named `test_at_b7*` / `test_tc_b7*` : 106
registry rows in that namespace                :   0
```

`_FUNC_ID_RE` (`tools/id_registry.py:95`) is
`(?:^|_)(at|tc)_?(\d+(?:_\d+)?)([a-z]+)?(?=_|\Z)` — it requires **digits immediately after
`at`/`tc`**, so `at_b78_09` never parses. And because a non-conforming token is classified
`governed=False`, G3 and G5 skip it too. **Batch-78 minted an id namespace outside the project's own
id grammar, and every guard declines to police it silently rather than complaining.**

This lands squarely on the Lane B finding already on record — *the id GRAMMAR is undefined* — and it
is the same vacuous-input-set shape as F-2, two layers up: the guard's input set is whatever its
regex happens to parse, and an id form it cannot parse is indistinguishable from an id form that does
not exist.

**It also qualifies `AT-B78-14`.** That node was recorded as a PIN because nothing needed
reconciling. The sharper statement: for **this namespace** the registry never had anything to
reconcile, because it contains no rows for it at all. `AT-B78-14` checks LIVE→node over rows that, for
`AT-B78-*` / `TC-B79-*`, do not exist.

**NOT fixed here.** Changing the grammar reclassifies tokens repo-wide and is Lane A registry-tooling
work. Registered as a carry; operator decision owed.

### F-7 — a gate invoked through a PowerShell pipe reported the wrong exit code, and swallowed its own output.

The first full-suite run was `pytest tests/ ... | Select-Object -Last 45`. It reported **exit 4**
(pytest "usage error") with an **empty** output file — no test ever ran that way. Re-run as
`pytest ... > file 2>&1` with `$LASTEXITCODE` read directly, it reported **exit 1** and the real 29
failures.

This is `C-78-xx` — *a gate invoked through a pipe takes the PIPELINE's exit status* — already carried
in this project's backlog with no owner, now observed live and costing one 45-minute suite run. **A
gate's exit code must be read from the gate, never from the pipeline it was piped into.**

---

## 6 · Verification

```
pytest tests/test_unload_feature.py tests/test_help_toggle_and_a2l_panel.py
  -> 16 passed        (6 failed / 10 passed before the fix; 16 passed at base 829adc6)

pytest tests/   [FULL SUITE — the operator's new gate, first ever run in this batch]
  run 1 (H-1/H-2/H-4)      -> 29 failed, 2654 passed, 2 skipped, 3 xfailed  45:42
  run 2 (M/L fixes)        -> 29 failed, 2655 passed, 2 skipped, 3 xfailed  35:02
  run 3 (N-1..N-6)         -> 30 failed, 2655 passed  <- F-9, the binding guard
  run 4 (F-9 fixed)        -> 29 failed, 2656 passed, 2 skipped, 3 xfailed  35:32

  ALL 29 failures are `test_tc016s_density_layout_snapshot[*]` — Inc-12's
  known, canonical-CI-only regen. ZERO other failures at run 4.
  Collected total 2690. Ledger: 2686 -> 2688 (TC-B79-01/02) -> 2689 (TC-B79-03)
  -> 2690 (TC-B79-04). Reconciles.

  Run 3 is kept in this record deliberately. It is the only run that caught F-9,
  and it is the second time in one session that the full suite found something
  four targeted files could not.

mutation harness -> 4 arms, 0 survived/errored  (9 for Inc-11 overall)

ruff check s19_app tests --output-format=concise     [REPO-WIDE, both trees]
  at 829adc6 (base) -> 7 errors
  at HEAD           -> 7 errors
  IDENTICAL: same rules, same files, same order.
    1x F821 `Dict`  (app.py — the line number moves with the batch's edits)
    4x F401         (tests/test_flow_crc_ribbon.py, tests/test_flow_crc_ui.py)
    2x E741         (tests/test_flow_crc_ui.py)
  ZERO ruff regressions from this batch.
```

⚠️ **The repo-wide figure is stated because every earlier claim in this batch was scoped to the
files it touched.** "Ruff clean apart from the pre-existing `F821`" was true of those files and
invited the reading that the repo has one ruff error; it has **seven**. The merge gate had already
flagged the HANDOFF's *"ruff clean on every file this batch touched"* as an overstatement, and this
is the same imprecision one layer out — a figure is only as honest as the corpus it names. Measured
against a `git worktree` of the base rather than inferred.

---

## 7 · Files

| File | Change |
|---|---|
| `s19_app/tui/screens_directionb.py` | H-1 — the project row's own marker class; later, symbol-anchored citations |
| `s19_app/tui/styles.tcss` | H-1 — `.loaded-project-detail` beside `.loaded-detail`; N-4 comment merge |
| `s19_app/tui/app.py` | H-2 — `_compose_context_line`, `_clip_to`, 4 constants; N-1 resize recompose; N-2 column measurement |
| `tests/test_tui_commandbar.py` | `AT-B78-09` arity · `TC-B79-01…04` · `TC-B78-12` per-surface presence |
| `tests/test_tui_diff_screen.py` | M-1, L-5, and the citation sweep |
| `tests/test_tui_patch_history_strip.py` | F-9 — explicit `encoding="utf-8"` |
| **SOURCE files** | **`3`** — `app.py`, `screens_directionb.py`, `styles.tcss`, as the UNION across every commit this packet spans (`4c5aa5d`, `12191a3`, `16e0d12`, `701b456`, `ed96f7a`, `ca7609f`, `c879d24` and the anchor-correction commit); the largest single commit also touched 3, and per-commit counts are `3/2/2/2/0/1/0`. Under `C-47`'s cap of 4, below the warning threshold. Tests and `.dev-flow/**` are outside the count. *(The enumeration is spelled out because an earlier version named only the first four commits — correct in its figure, under-inclusive in its span.)* |

---

## 7b · SECOND merge gate — BLOCK. The H-2 fix was incomplete on two axes.

The re-gate verified **all 14 prior findings closed** and then blocked on the fix itself. Every
finding below was reproduced here before being touched.

### N-1 (HIGH) — the H-2 defect fully returned after a terminal resize

`_compose_context_line` budgets from a width read **at write time**, and `on_resize` did not
recompose. Executed:

```
(160,40) -> (80,24)   A2L present before: True   after: False
(160,40) -> (120,30)  A2L present before: True   after: False
```

Byte-for-byte the H-2 symptom — the A2L absent on 10/10 screens at exactly the two sizes the first
gate named — against `HLR-120`'s **unconditional** threshold. `TC-B79-01` could not see it: it
composes once per fixed-size run. **Blind by scenario construction**, one axis over from the *"blind
by fixture construction"* critique that node's own docstring levels at `AT-B78-08`.

**The first fix for it did nothing, and that is the interesting part.** Calling
`update_project_labels()` from `on_resize` changed no observable: instrumented, the handler fires and
the deferred call runs, but reads

```
update_project_labels bar=156 ctx=91 app.size=80      <- terminal already 80, bar still 156
```

The bar's cached `size.width` is **stale mid-resize**; `App.size.width` is not. So the recompose
budgeted for the size being *left*. The budget now derives from the terminal width minus
`_CONTEXT_BAR_INSET` (measured 80→76, 120→116, 160→156), scheduled through `call_after_refresh`.

### N-2 (MEDIUM-HIGH) — the bound was measured in code points, not columns

**Self-caught before the gate reported it**, then confirmed by it. `_clip_to`'s docstring said
*"columns"*; it measured `len()`. A 42-character CJK project composed to **55 code points and 101
columns against an 81-column budget** — a legal Windows directory name restoring the eviction. Now
`rich.cells.cell_len` / `set_cell_size`, which also handles a cap landing mid-glyph.

### N-3 (MEDIUM) — the fix's actual design had no assertion

Two arms against `TC-B79-01`, both **GREEN**: the A2L starved to a fixed 10 columns, and both slack
branches deleted. So *fair share* and *slack redistribution* — the two properties that are the only
reason the method is more than a `min()` — were unasserted; the node detected **total eviction** and
nothing else. **`F-5`'s shape reproduced inside the fix written to close `F-5`.**

`TC-B79-04` pins all three axes: apportionment (a half that fits is never truncated; an overflowing
half gets strictly more than an even split), resize (through a real `pilot.resize_terminal`), and
columns (a CJK fixture). Both previously-GREEN arms now go RED on it.

### N-4 / N-5 / N-6 — the prose fixes carried their own defects

- **N-4** — the commit that fixed M-2's stale comments **added a new false one**: two stacked blocks
  on `#status_context`, the first claiming `width: 1fr`, the rule setting `width: auto`. Merged.
- **N-5** — the line-citation fix landed in `styles.tcss` **only**, and the same commit created four
  new stale citations by inserting lines above them. The sharpest: **`AT-B78-32`'s docstring — the
  node re-authored specifically to argue a line range "looks like a measurement" and is "one
  insertion away from failing the same silent way" — was itself citing `screens_directionb.py:6712`
  for a comment that this branch had pushed to `:6822`.** All replaced with symbol names and
  descriptions.
- **N-6** — F-6's carried node count said `106`, and the commit that wrote it added the 107th. Now
  stated with its **pattern and commit**, and narrowed to `tests/*.py` because a recursive grep also
  matches the 8 tracked `.pyc` binaries — the same inflation that made an Inc-8 figure read 10 for 4.

### N-7 (LOW) — degenerate widths, carried

Below `bar_width <= 7` the composer returns the bare separator, and at `avail == 1` it returns
`"  |  …"`, evicting the project. Unreachable at supported sizes; recorded rather than fixed.

### F-9 — a binding-freeze guard was killed by prose in another module, and reported the wrong error

The full suite after the N-fixes returned **30** failures, not the expected 29. The extra:
`test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff`, dying with

```
AttributeError: 'NoneType' object has no attribute 'splitlines'
```

Cause: it runs `git diff main -- s19_app/tui/app.py` with `subprocess.run(..., text=True)` and **no
`encoding`**, so Python decodes with `locale.getpreferredencoding()` — **cp1252** here. A codepoint
cp1252 cannot map entered that diff, the reader thread raised `UnicodeDecodeError`, `stdout` came
back `None`, and the guard crashed.

> ⚠️ **RETRACTED — the cause first recorded here was false, and the third gate caught it.** This
> section said the trigger was the CJK fixture added to `TC-B79-04` in `tests/`. **That is
> impossible**: the pathspec is `-- s19_app/tui/app.py`, which excludes `tests/` entirely.
> Re-derived on that exact diff — CJK present: **False**; non-ASCII present: `U+00AB U+00BB U+2014
> U+2026 U+26A0 U+FE0F`. The real trigger was **`⚠️` in `on_resize`'s docstring — in the very file
> being diffed, added by this batch's own commit.** `U+FE0F` (VS16) encodes to `ef b8 8f`, supplying
> the cited `0x8f`. At base `app.py` carried 9× `U+26A0` and **0× `U+FE0F`**.
>
> **The retraction changes the lesson, not just the detail.** *"The blast radius crossed modules
> through git"* is false — it never left `app.py`. And the risk axis is not content-vs-paths but
> *"does the captured output contain any non-cp1252 codepoint"*, which `⚠️` trips and which this
> codebase's comments use everywhere.

What survives, and is worth keeping:

1. **The guard failed in the worst available way** — not RED on its own assertion, and not silently
   green, but with an `AttributeError` naming `splitlines`. Anyone reading that sees a broken test,
   not "the binding census did not run".
2. **Only the full suite could catch it.** The targeted runs used at every earlier increment of this
   batch never touch `test_tui_patch_history_strip.py`. This is `F-4` collecting a second scalp
   inside the same session that recorded it.
3. **A guard can be disarmed by prose.** Not across modules as first claimed, but by an ordinary
   comment edit in the file under guard — which is a *smaller* radius and a *more likely* trigger.

Fixed at the one call that decodes file content, verified live afterwards (36 089 chars, 0
replacement characters, an injected `Binding(` line still detected); the other **eight** siblings are
enumerated and carried. A narrow patch taken deliberately, with the general control registered.

## 7c · THIRD merge gate — BLOCK. Two records were wrong and one new node was vacuous.

The third pass confirmed **N-1 and N-2 survive every attack it mounted** — budget equals the painted
cell exactly at 80/100/120/160/200, inset `= 4` at every width, `_clip_to` correct across 14 boundary
cases including mid-double-width caps, VS16, ZWJ and combining marks. It blocked on three things.

### G-1 (MED-HIGH) — **F-9's recorded cause was false.** See the retraction in §F-9 above.

The operator was being asked to decide the 8-sibling sweep from a stated risk axis
(content-vs-paths) that **was not the axis that fired**. Corrected in this file and in
`BACKLOG-CODE.md`; the fix itself was verified correct and left alone.

### G-2 (MED) — `TC-B79-04` closed two of three branches and claimed all three

Asked to write an implementation that passes the new node and is still wrong, the gate produced one
in a line: substitute `a2l_cap = 12` in the **both-overflow** branch. Reproduced here — **GREEN,
survived**. It only reddens at `a2l_cap <= 1`, because the discriminating fragment `"ASAP2_ECU"` is
9 characters.

**And that is the branch production actually takes.** Project 42 columns, A2L 43: at 80×24
`avail=48, half=24`; at 120×30 `avail=76, half=38` — both halves overflow at both sizes where the
defect was measured. So axis 1 exercised only the two *slack* branches, and the effective guarantee
was *"the A2L gets ≥ 10 of ~48 columns"* while the docstring claimed an even split.

Closed by axis 1b: with both halves overflowing, neither may fall below `half - 1`.

**This is F-8 recurring for the third consecutive commit** — and this time inside the node written
specifically to close the previous instance of it.

### G-3 (MED) — the citation fix recurred, and its "correction" was wrong on arrival

Five stale citations at HEAD, four written or broken by this batch.

> ⚠️ **RETRACTED at the fourth gate — the mechanism recorded here was false, and the false version is
> what made the sweep under-scoped.** This paragraph said the cause was one line —
> `from rich.cells import cell_len, set_cell_size` at the top of `app.py` — *"which shifted every
> `app.py` citation by +1"*. Measured: `app.py` grew **11 753 → 12 163, +410 lines**, and the shift is
> **not uniform** — it grows with depth in the file. Every figure below is stated with the anchor that
> produces it, because a shift figure without an anchor is not re-derivable, only re-inventable:
>
> ```
> git show 829adc6:s19_app/tui/app.py | grep -n 'BINDINGS = \['           -> 1338
> git show HEAD:s19_app/tui/app.py     | grep -n 'BINDINGS = \['          -> 1339    (+1)
> git show 829adc6:s19_app/tui/app.py | grep -n 'def _apply_width_regime' -> 6246
> git show HEAD:s19_app/tui/app.py     | grep -n 'def _apply_width_regime'-> 6351    (+105)
> ```
>
> *(An earlier draft of this retraction also quoted `+14` and `+168` with no anchor for either. They
> were dropped rather than kept: the fifth gate flagged them under this batch's own rule — an
> unstated pattern is an unstated definition — and a retraction of a false figure is a poor place to
> introduce two unverifiable ones.)*
>
> **"+1" holds only ABOVE the batch's first body edit.** That is precisely why the sweep found five
> citations clustered near `BINDINGS` and none deeper — the wrong mechanism produced a search that
> could only find the shallow ones, and then the record declared the class closed. A future batch
> inheriting "an import shifts citations by +1" would under-scope its own sweep identically.
>
> **And the deepest one was not an `app.py` shift at all.** `tests/test_tui_diff_screen.py` cited
> `command_bar.py:279`/`:295` for the palette-close premise — accurate at base in a 296-line file,
> pointing **past end-of-file** at HEAD, because `HLR-118` took that file to **260 lines**. The
> batch's own headline deletion invalidated it, and it survived in one of the three files this very
> sweep edited.

The sharp one is `AT-B78-32`'s docstring — the node re-authored across two prior commits precisely to
remove stale citations, which closes with *"Any edit ABOVE the block shifts it, so `1338-1392` is one
insertion away from failing the same silent way."* The next commit made that insertion. **And the
"corrected" range was already wrong when it was written**: the block was `1339-1393`, never
`1338-1392`.

All line numbers are now gone from that docstring. Also corrected: `action_show_help_panel`'s line
(accurate at base, broken by this batch), the `deque(maxlen=4)` line, the `BINDINGS` range in
`screens_directionb.py`, and `styles.tcss:1623` — which pointed at `#diff_hex_b`, ~47 lines short of
the `border: none` rule it named.

### G-4 / G-5 / G-6 (LOW) — fixed

- The `on_resize` docstring described the mechanism its own commit deleted (it said the budget comes
  from the status bar's width; it comes from `App.size`). Corrected — and the real reason for the
  deferral is now stated: **`App.size` is stale inside the handler while `event.size` is not.**
- `_CONTEXT_FALLBACK_BUDGET`'s comment was false twice: an unmounted `App.size` returns `Size(80,25)`
  rather than 0, so the "pre-mount" path never reaches it, and at the only width that can (≤ 4
  columns) a 53-column budget is the *optimistic* end, not the "SAFE" one it claimed.
- `N-7` was recorded in this file and **never registered in `BACKLOG-CODE.md`** — a carry that would
  have died at the batch close. Registered.

## 7d · Self-caught after the fourth gate: **four of seven symbol anchors named the wrong symbol**

The fifth gate's brief contained the warning that found this: *"an anchor that names the wrong symbol
is the same defect in a form that cannot go stale."* Checked before the gate could:

| Anchor as written | Verdict | The real symbol |
|---|---|---|
| `S19TuiApp.RAIL_ITEMS` | ❌ **does not exist — invented** | `S19TuiApp.BINDINGS` |
| `S19TuiApp._report_execution_results` → `_scan_patch_change_files()` | ❌ does not contain it | `S19TuiApp._scan_patch_change_files` |
| `S19TuiApp._report_execution_results` maps `variant_id` | ❌ does not | `S19TuiApp._refresh_patch_variant_select` |
| `S19TuiApp._apply_prepared_load` (A2L glyph in name cell) | ❌ wrong method | `S19TuiApp._build_a2l_table_cells` |
| `S19TuiApp._compute_mac_view_payload` (MAC glyph in Tag cell) | ❌ wrong method | `S19TuiApp._populate_mac_datatable` |
| `CommandBar._dispatch_palette_entry` / `.on_list_view_selected` | ✅ both call `close_palette()` | — |
| `S19TuiApp.compose` holds `CommandBar(self._build_palette_entries())` | ✅ | — |

**Root cause: I derived the anchors with an `awk` that took the nearest preceding `def` and never
checked semantics.** It produced plausible method names for every line — which is precisely the
failure mode §4 records as *"a plausible-looking count is the dangerous outcome; an impossible one
gets checked."* Every one of the five wrong anchors *reads* correct.

**And the original citation was wrong too.** `app.py:687-691`, cited for the rail-key claim, resolves
at the batch base to `_STRIP_CELL_GLYPH` / `_STRIP_GAP_GLYPH` — nothing to do with rail bindings. So
the line number was false *before* this batch, and replacing it by machine produced a second false
reference. Two independent errors on one sentence.

**Now verified by execution, not inspection.** A harness resolves all 17 anchors written this session
against the AST and asserts each CONTAINS the substring its sentence claims — plus the six class
attributes cited by name. All 17 pass. The rail claim is now re-derived and quoted from the live
tree: key `'2'` → `show_screen('a2l')` desc `'A2L Explorer'`, key `'3'` → `show_screen('mac')` desc
`'MAC View'`.

> **The generalisable half:** *replacing a line number with a symbol removes the staleness failure
> mode and introduces a correctness one.* A stale line number is detectable by anyone who follows it;
> a wrong symbol name reads as authoritative forever. **A symbol anchor must be executed against the
> tree, exactly like a figure.** Registered as a control candidate.

### F-8 — the lesson that outranks all of them

**FIVE separate fixes in this session each carried a defect of the same class they were fixing, and
the pattern held across three consecutive gate passes:**

| The fix | The defect it carried | Found by |
|---|---|---|
| The vacuous-input-set guard (`AT-B78-14`) | used a vacuous input set | self, in minutes — it failed loudly |
| The line-citation fix (N-5) | created four new stale citations | gate 2 |
| …and its own correction (G-3) | the "corrected" range was wrong **on arrival** | gate 3 |
| The context bound (`TC-B79-01`) | no assertion on how it apportions (N-3) | gate 2 |
| …and its replacement (`TC-B79-04`, G-2) | left the branch production actually takes unasserted | gate 3 |

*A fix is a change, and a change made under the pressure of a blocked gate is where this project's
dominant defect class reproduces most reliably.* Three observations that follow:

1. **The counterfactual is not optional on a fix.** It is the only thing that caught N-3 and G-2, and
   in both cases the node looked thorough and read as complete.
2. **A correction is itself a change and inherits the risk.** Two of the five above are corrections
   of corrections. There is no terminal state reached by editing carefully — only by re-measuring.
3. **The most dangerous artifact in this session was not code.** Four of the five are prose or
   acceptance-side, and the one that reached the operator's decision (F-9's false cause, G-1) would
   have had them decline a sweep on a risk axis that was not the one that fired.

---

## 8 · Still owed — NOT absorbed silently

- **The gate's 5 MEDIUM and 5 LOW are NOT fixed.** M-1 (a comment citing `132x28` where the constant
  is `27`) · M-2 (production docstrings still naming `set_context_labels`, deleted at Inc-11, and
  `styles.tcss:55-60`, which `LLR-118.3` explicitly required to be amended) · M-3 (six nodes moved to
  private-method calls while their Intent still says *"routes"*, plus a duplicated line at
  `test_tui_commandbar.py:588-591`) · M-4 (`_apply_unload` clearing `current_a2l_path` — a production
  change outside every in-scope requirement, tested only for its display effect) · M-5 (a docstring
  claiming a `_FIND_GOTO_INPUTS` set-equality assertion that does not exist) · L-1…L-5.
  **Operator decision owed:** fix in this batch, or carry to Lane A.
- **Increment records for Inc-8, Inc-9, Inc-10** still do not exist. The merge gate judged the refusal
  to reconstruct them correct, and named the price: **H-3 is the one claim a missing Inc-9 record let
  through** — a factual error about Inc-9's own work.
- **Inc-12** — the 29-golden snapshot regen, canonical CI only, its own PR.
- **`TC-B79-01` / `TC-B79-02` are unregistered** in `AT-TC-REGISTRY.jsonl` — along with the other
  **104** nodes in that namespace. See **F-6**: this is not an omission at this increment, it is a
  grammar gap that no guard can currently see. **Operator decision owed**, Lane A.
- **`C-78-xx` is owed an owner and now has live evidence** (F-7). It cost a 45-minute suite run in
  this session alone.
