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
class the three artifact slots carry (`screens_directionb.py:2059`, `:2069`). Two shipped readers
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
  -> 29 failed, 2654 passed, 2 skipped, 3 xfailed in 2742s (45:42)
     ALL 29 failures are `test_tc016s_density_layout_snapshot[*]` — Inc-12's
     known, canonical-CI-only regen. ZERO other failures.
     Collected total 2688 = 2686 + 2 (TC-B79-01, TC-B79-02). Ledger reconciles.

mutation harness -> 4 arms, 0 survived/errored  (9 for Inc-11 overall)

ruff check s19_app/tui/app.py s19_app/tui/screens_directionb.py \
           tests/test_tui_commandbar.py tests/test_tui_directionb.py
  -> 1 error: F821 `Dict` at app.py:5814 — PRE-EXISTING, present identically at
     829adc6. Stated precisely because the HANDOFF's "ruff clean on every file
     this batch touched" overstated it, as the merge gate noted.
```

---

## 7 · Files

| File | Change |
|---|---|
| `s19_app/tui/screens_directionb.py` | H-1 — the project row's own marker class |
| `s19_app/tui/styles.tcss` | H-1 — `.loaded-project-detail` beside `.loaded-detail` |
| `s19_app/tui/app.py` | H-2 — `_compose_context_line`, `_clip_to`, 3 constants |
| `tests/test_tui_commandbar.py` | `AT-B78-09` arity clause · `TC-B79-01` · `TC-B79-02` · `TC-B78-12` per-surface presence |

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
