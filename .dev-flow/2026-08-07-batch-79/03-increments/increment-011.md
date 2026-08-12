# Inc-11 — HLR-121's three acceptances

**Date:** 2026-08-11 · **Branch:** `claude/batch-79-cmdbar-deletion` · **Base:** `origin/main` @ `829adc6`
**Predecessor:** `23af21f` landed the DELETION and its census; this increment lands the ACCEPTANCES it owed.

---

## 0 · BLUF

`AT-B78-12/13/14` are written, green, and each is **RED under a recorded mutation on its own
assertion** — 5 arms, 0 survivors, 0 errors. **The go-to mutation the handoff recorded as owed is
discharged**: `_apply_goto` is the single shared mechanism behind all three `_handle_goto*` paths,
the structural twin of the `find_string_in_mem` import that reached only the search half.

**Two findings, both of the batch's signature shape — a rule stated in prose beside a mechanism that
does not carry it.** One is the spec's (`AT-B78-14` cannot be the GATE §5.3 predicted); one is mine,
committed inside the very guard written to prevent it.

---

## 1 · What changed

| File | Change |
|---|---|
| `tests/test_tui_commandbar.py` | `AT-B78-12` (PIN), `AT-B78-13` (GATE), `AT-B78-14`; 2 helpers; 6 constants; `_B79_REGISTRY_SOURCE` extracted so the counterfactual can re-point it |
| `tests/test_tui_directionb.py` | `TC-029` docstring corrected — **comment-only, no assertion touched** (§4) |

No production file is touched. The deletion shipped at `23af21f`.

---

## 2 · The three acceptances

### `AT-B78-12` (PIN) — the 9-row behaviour payload

Re-reads `tests/goldens/batch78/at-b78-12-search-goto-payload.json` **from disk** via the sanctioned
`_b78_artifact` reader and compares it to a fresh live capture driven through the three screens' own
shipped Buttons. It never regenerates the artifact.

Three deliberate choices:

- **Anti-regeneration guard asserted BEFORE the comparison.** 9 rows, and each row carrying exactly
  `LLR-121.2`'s seven fields. Without these, an artifact rebuilt from the post-change tree would make
  the comparison a tautology — and it would pass. This is the same defect that left `AT-B78-03` green
  at `36 == 36`.
- **Keyed comparison, not positional.** Comparing by index also fails when only the traversal order
  moved, which is not a behaviour change and sends a reader hunting a defect that is not there.
- **The digest is asserted SECOND and only once the rows agree.** The handoff is right that the oracle
  is the row-by-row comparison; a digest can say *something* moved, never *what*. It is kept because it
  additionally proves the live capture **serialises to the stored bytes** under `LLR-121.2`'s pinned
  recipe — which the row comparison alone does not show.

### `AT-B78-13` (GATE) — the class-qualified AST + CSS-selector census

0 definitions of the seven symbols; 0 **live** selectors for the six deleted ids; `#command_bar_slot`
and `#command_bar` retained.

**The comment strip is load-bearing, not tidiness.** `styles.tcss:66-71` is a comment that names all
six deleted ids as the record of what was removed. A census over the raw text finds every one and
reports the deletion as incomplete — **the fifth time in this batch a bare text search would have
counted the wrong thing.** Arm 4 proves the strip discriminates, and a further clause asserts the
comment is still present, so the strip cannot silently degrade into matching nothing.

Every absence clause carries a presence co-assertion (C-40): the census asserts it actually resolved
`CommandBar`, that `visible_palette_actions` survives on it, and that `action_focus_find` /
`action_focus_goto` survive on `S19TuiApp`. Absence is trivially true of a module that failed to parse.

### `AT-B78-14` — the registry guard

Every `LIVE` row's `tests/` node resolves to a symbol that exists. Guards: >100 LIVE rows loaded,
>500 node references checked.

---

## 3 · Counterfactuals — 5 arms, per node id, 0 survivors

Every arm is applied to a **copy** of the fixed tree and recorded as the **substituted VALUE**, never
as "the deleted operator". Every arm failed on the node's **own assertion**; none merely errored.

| Node | Substituted value | Verdict |
|---|---|---|
| `AT-B78-12` | `S19TuiApp._apply_goto` → `lambda self, view, addr: False` | RED (own assertion) |
| `AT-B78-12` | `app.find_string_in_mem` → `lambda *a, **k: None` | RED (own assertion) |
| `AT-B78-13` | `command_bar.py` + `def focus_find(self): return None` on `class CommandBar` | RED (own assertion) |
| `AT-B78-13` | `styles.tcss` + live rule `#find_input { width: 10; }` | RED (own assertion) |
| `AT-B78-14` | a LIVE row's node → `::test_tc006_DELETED_BY_MUTATION` | RED (own assertion) |

**Arm 1 is the owed one.** `find_string_in_mem` is a module-level import used by all three
`_handle_search*` paths, so batch-78's recorded mutation could only ever reach the search half.
`_apply_goto` (`app.py:11777`, called at `:11833`, `:11884`, `:11933`) is its exact twin on the go-to
side. The substitution reaches **6 of the 9 rows** — the 3 hit rows lose both `Goto 0x…` and their
focus address, and the 3 miss rows lose the `Address … not in loaded file.` line. The 3 empty rows are
correctly unaffected: they bail before `_apply_goto` is reached.

**Arm 2 re-derives the search half on THIS tree** rather than inheriting batch-78's digest triple. A
carried number is re-derived, not copied.

---

## 4 · Findings

### F-1 — `AT-B78-14` cannot be the GATE the spec predicted. The spec's premise is FALSE.

§5.3 records `AT-B78-14` as **"GATE — RED after deletion"**, on the stated evidence that **"4 LIVE rows
name the doomed nodes"**. Executed against the implementation that shipped:

```
test nodes deleted across 829adc6..HEAD:  0
```

Inc-8 re-pointed `TC-038`, Inc-10 re-pointed `TC-006`, and Inc-11 re-pointed the six posting nodes onto
`_handle_search` / `_handle_goto`. **Nothing was deleted, so no reconciliation was ever owed and the
registry was already consistent.** `AT-B78-14` is therefore green before and after — a **PIN**, not a
GATE, and it is labelled that way in its own docstring rather than left to read as a gate that gated.

The node is kept: it is what makes "the registry is consistent" checkable rather than asserted, and
arm 5 shows it discriminates. But **recorded as a gate it would have been a vacuous one**, which is
this project's dominant defect class.

### F-2 — the guard against a vacuous input set was written with a vacuous input set. Mine.

`AT-B78-14`'s first form collected only `ast.FunctionDef` / `ast.AsyncFunctionDef`. It reported **34
LIVE rows naming a missing node** — and every one of the 34 was a real, present symbol that happened
to be a `class`: `TestSetupLoggingSurface`, `TestCrossFileCompatibilityCoEmission`, `_CountingList`,
`_UnsafeMarkupTextArea`, `_Row`, `_FixedApplyDatetime`.

A registry node id is `module::symbol` for a function, a class **or** a class-scoped method. Restricting
the input set to functions is the identical defect the `_B78_NON_WRITING_CALLS` allowlist was inverted
to avoid, one layer down — **committed inside the guard written to close it**, which is the third time
this batch's own thesis has reproduced inside its own fix.

It failed **loudly** (34 impossible-looking rows), and that is the only reason it was caught in
minutes. §4's rule holds exactly as written: *a plausible-looking count is the dangerous outcome; an
impossible one gets checked.* Had the census been function-only over a corpus where every node
happened to be a function, it would have been silently correct and silently fragile.

### F-3 — `TC-029` describes a surface deleted two increments ago, and nothing went red.

`test_tc029_command_bar_inputs_reachable_by_keyboard` claims *"the three command-bar surfaces are
reachable"* and cites the command bar's find / go-to inputs. `HLR-118` deleted both. The node was
**never touched in this batch** (`git log -S` over `829adc6..HEAD` returns nothing) and is green.

It is green **by an id coincidence**: the deleted inputs were `#find_input` / `#cmdbar_goto_input`,
while the assertions name `#search_input` / `#goto_input` — the **workspace's own** inputs
(`app.py:2021`, `:2023`), which `HLR-119` re-homed the keys onto. So the assertions kept testing
something true while the prose described something that no longer exists.

Its two siblings were re-pointed explicitly with comments. This one was missed *because nothing about
it went red* — the same reason the stale `AT-B78-32` line range survived three Phase-2 rounds and two
review lanes. **Corrected in the docstring only; the assertions are right and are left alone.**

---

## 5 · Verification

```
pytest tests/test_tui_commandbar.py tests/test_id_registry.py \
       tests/test_tui_directionb.py tests/test_tui_diff_screen.py
  -> 289 passed in 510.63s
     (commandbar 37 -> 40, registry 13, directionb 183, diff_screen 53)

ruff check tests/test_tui_commandbar.py tests/test_tui_directionb.py
  -> All checks passed!

mutation harness -> 5 arms, 0 survived/errored
```

**Ledger:** 2683 → **2686**, exactly **+3**, one per new acceptance.
**Stated pattern** (an unstated pattern is an unstated definition): total nodes reported by
`python -m pytest tests/ --collect-only -q`, run from the repo root at this commit.

**The 29 `test_tc016s_density_layout_snapshot[*]` failures are unchanged and remain Inc-12's**, which
is canonical-CI-only. They are excluded above deliberately, not by accident.

---

## 6 · Decisions taken without asking

| # | Decision | Why it was mine |
|---|---|---|
| 1 | `AT-B78-14` recorded as a **PIN**, contradicting §5.3's "GATE — RED after deletion" | The spec's premise is false against the shipped implementation (F-1). Re-labelling it is honesty about what it can detect; silently keeping the GATE label would ship a vacuous gate |
| 2 | The digest kept in `AT-B78-12` as a **secondary** clause | The handoff calls it "a convenience"; it is kept because it additionally proves byte-level serialisation, and ordered after the rows so it can never be the thing that reports a behaviour change |
| 3 | `TC-029`'s **docstring** corrected, assertions untouched | The assertions are correct post-`HLR-119`; the prose is not. Changing the assertions would be a behaviour claim I have no requirement for |
| 4 | `_B79_REGISTRY_SOURCE` extracted as a module constant | Its two siblings already were, and an inline `Path(...)` cannot be re-pointed by a counterfactual — the arm would have been unwritable |

---

## 7 · Owed, and NOT silently absorbed

- ⚠️ **Increment records for Inc-8, Inc-9 and Inc-10 do not exist on disk.** Only `increment-006.md`,
  `increment-007.md`, `increment-007-entry-gate.md` and `increment-010-entry-gate.md` were written.
  The commits exist and carry detailed messages, but the flow's per-increment artifact does not.
  **They are NOT reconstructed here** — writing them now from commit messages would manufacture
  evidence of observations nobody made. Recorded as a gap for the operator.
- **Inc-12** — the 29-golden snapshot regen, canonical CI only, its own PR.
- The five carries registered at `682df07` in `.dev-flow/BACKLOG-CODE.md` remain open.
- **F-3 has a generalisable half worth a control candidate:** *a node re-pointed by an increment must
  be re-read for prose that names the deleted surface — greenness is not evidence the node still
  describes what it tests.* Registered, not encoded (encoding needs operator approval).
