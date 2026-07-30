# Increment 4 — G-1 separability guard · focus-traversal pin · REQUIREMENTS.md registration

> Batch `2026-07-30-batch-72`, Phase 3, **final increment**. Branch
> `claude/batch-72-design-defect-634a67` @ `0169108`. Artifact language: English.
> **TEST + DOCS ONLY — no file under `s19_app/` was modified** (proof in §5).

---

## BLUF — read this first

Three of the four specified items landed as written. **One did not, and it is reported rather than
improvised:** the increment brief and `01-requirements.md` HLR-072-3 both specify TC-514 as
*"`Switch(` has exactly **one** construction site in the whole `s19_app/` package"*. That number is
**FALSE on the tree TC-514 must run against**. It was true of `origin/main`, which is what
`00-measurements.md` M-1 measured; Inc-3 then deleted the per-toggle row helper (one `Switch(` call
invoked twice) and inlined both toggles into the pair row, so the count is now **2**. Asserting the
carried `== 1` would have shipped a RED test. Full disposition in §6 **D-1**.

| # | Item | Outcome |
|---|---|---|
| 1 | **AT-214** — G-1 Switch separability, derived subject set | ✅ landed, GREEN, **counterfactual RED on its own assertion line** |
| 2 | **TC-514** — derived-set completeness | ⚠️ landed on a **re-derived** property; the specified `== 1` is measured FALSE — **§6 D-1** |
| 3 | **TC-520** — focus traversal pinned, both regimes | ✅ landed, GREEN, properties not literal chain |
| 4 | **REQUIREMENTS.md** — ADD `R-TUI-100`, AMEND both legend rows | ✅ landed |

Ledger reconciles exactly: **2393 + 3 = 2396**. Both frozen-guard arms green. No snapshot ran, none
regenerated, none failed.

---

## 1. What changed

### 1.1 AT-214 — the G-1 Switch separability guard (HLR-072-3)

`test_at214_no_two_switches_render_vertically_abutting`, pilot at 120x30, CRC screen reached through
the shipped surface (`pilot.press("0")`, never a `.focus()` proxy — C-16). Three clauses:

1. **the subject set is DERIVED** — `app.screen.query(Switch)` filtered `region.area > 0`, never
   hand-listed (C-31). A hand-listed set is precisely the vacuity this control exists to prevent, and
   the area filter is load-bearing: zero-area phantoms sit at `Region(0,0,0,0)` and a naive walk pairs
   them nonsensically at `y=0`;
2. **non-empty (`>= 2`)** — so a broken walk, a renamed widget class, or a screen that never mounted
   cannot satisfy clause 3 vacuously;
3. **zero abutting pairs** under the §1.3 relation, evaluated over ordered `permutations` so the
   directional relation is checked both ways.

The §1.3 relation is implemented verbatim in the helper `_vertically_abutting`:

```python
b.y == a.y + a.height and a.x < b.x + b.width and b.x < a.x + a.width
```

The x-band clause is what stops two controls in different bench columns from counting as stacked
merely because their rows line up.

**Clause 4 (the C-40 counterfactual) is executed at this gate, not encoded** — a permanently-reverted
tree is not a counterfactual. Full transcript with three hashes in §4.

### 1.2 TC-514 — the derived-set completeness guard

`test_tc514_every_switch_construction_site_is_on_the_crc_designer`. This node carries the argument
AT-214's query cannot carry on its own: `App.query` is **screen-scoped**
(`app._get_dom_base() -> Screen`), so it certifies "no abutting pair *on the CRC screen*", **not**
"anywhere in the app". The static source scan is the load-bearing evidence. Two arms:

- (a) exactly one module in `s19_app/` imports `Switch` at all, and
- (b) every `\bSwitch\(` construction site in the package is in that module,

plus a non-vacuity assertion that the scan resolved files and found at least one site, so a
mis-resolved root cannot pass it silently. **The property, not the count** — see §6 **D-1**.

### 1.3 TC-520 — the focus-traversal pin (the C-16 flag coming due)

`01-requirements.md` §6.3 flagged the interaction axis `assumed — verify in target framework at
Phase 3`. It was verified at the Inc-1/2 gate and it **changed**: `ScrollableContainer.can_focus` is
True on textual 8.2.8, so the Legend's tab cycle grew from 1 focusable stop to 3 and now follows pane
document order. Nothing anywhere asserted a legend tab order.

`test_tc520_legend_focus_traversal_is_pinned_in_both_regimes` **accepts and pins** it, per the
independent review's recommendation. Three PROPERTIES, both regimes:

| Clause | Property | Why it is not brittle |
|---|---|---|
| (a) | initial focus is `#legend_close` | the part that must NOT have regressed — unchanged from the single-pane modal |
| (b) | both panes appear in `screen.focus_chain` | the reachability guarantee behind G-4; goes RED **at the cause** if a future change makes the panes non-focusable |
| (c) | at 80x24 the key pane **precedes** the card pane in the chain | the operator's key-first decision expressed on the keyboard surface, not only the geometric one |

**Deliberately NOT a literal chain.** A `== [card, key, close]` equality would break on any future
pass-through container and would be asserting the framework's widget inventory rather than the
operator-visible guarantee.

**Why the 3rd stop is accepted rather than repaired:** at the floor the key is scroll-only *by
design* (AT-217 clause 3). Making the panes `can_focus = False` to restore the old 2-stop cycle would
leave the colour key **keyboard-unreachable at 80x24**, failing guard G-4 outright.

Clause (c) is measurably non-vacuous — the order genuinely differs by regime:

```
(120, 30)  focused='legend_close'  chain=['legend_card_pane', 'legend_key_pane', 'legend_close']
(80, 24)   focused='legend_close'  chain=['legend_key_pane', 'legend_card_pane', 'legend_close']
```

Applied at 120x30 the same assertion would be FALSE. It discriminates.

### 1.4 REQUIREMENTS.md (§5.3.5)

**ADD `R-TUI-100`** — the CRC Designer bench layout, post-batch-72 state. §5.3.5's premise
re-executed and **re-confirmed** immediately before the edit: `crc_live_verify` → 0 hits,
`verdict hero` → 0, `crc_bench` → 0, `Designer` → 0. The obligation was genuinely to **ADD**; this
registers the CRC Designer view for the first time, batch-59's bench layout never having been
registered. The row states the pair row, the `Self-test` row inside `#crc_algorithm_fields`,
`#crc_top_right` holding Warnings only, the `Switch`-separability rule, and the `_recompute` census.
It carries a four-item **"what this requirement deliberately does NOT claim"** block (no `Select`
height cap — W-1; no hero-extent ratio — the pre-existing 2.54:1; no `Switch` state-word guarantee —
R-1; the CRC floor is unmeasured), and records `AT-B59-05`'s retirement as deletion, never an edit
into passing.

**AMEND `R-LEGEND-MODAL-001`** — `#legend_body` is now the two-pane wrapper holding
`#legend_card_pane` + `#legend_key_pane`. Its `LegendScreen` code ref was also stale (`:474` no
longer addresses the class) and is refreshed to `:1039`.

**AMEND `R-LEGEND-GEOMETRY-001`** — its Code line documented
`#legend_body { height: 1fr; overflow-y: auto }`; the `overflow-y` has moved to the panes and the
body is now `overflow: hidden`. Recorded as a **§6.5-style Before/After amendment block**, per the
convention already used at `REQUIREMENTS.md:439`, `:464`, `:4244` — a named CSS declaration moving to
a different element is recorded, not edited silently.

Every test node cited in a Validation line was **verified to exist on disk first** (18 nodes,
collected by pytest — §3.4). Coverage signed off from intent would be a false claim.

---

## 2. Files modified

| File | Δ | What |
|---|---|---|
| `tests/test_crc_designer_view.py` | +148 | AT-214, TC-514, `_vertically_abutting`, `_SWITCH_CTOR`, `permutations` import |
| `tests/test_legend_two_pane.py` | +84 | TC-520 |
| `REQUIREMENTS.md` | +150 −6 | ADD `R-TUI-100`; AMEND `R-LEGEND-MODAL-001`; AMEND `R-LEGEND-GEOMETRY-001` + §6.5 Before/After |

**3 files — within the ≤5 cap. Zero files under `s19_app/`.**

---

## 3. How to test

```bash
# the new nodes
pytest tests/test_crc_designer_view.py -k "at214 or tc514"
pytest tests/test_legend_two_pane.py -k tc520

# frozen guards, BOTH arms (C-27)
pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "tc031 or tc032"

# blast radius
pytest tests/test_crc_designer_view.py tests/test_legend_two_pane.py \
       tests/test_tui_legend.py tests/test_legend_n8.py tests/test_legend_scope_and_logwidth.py

# the hard constraint
git diff --stat HEAD -- s19_app/     # MUST be empty
```

---

## 4. Test results — executed output

### 4.1 The new nodes

```
$ python -m pytest tests/test_crc_designer_view.py -q -k "at214 or tc514"
..                                                                       [100%]
2 passed, 38 deselected in 1.50s

$ python -m pytest tests/test_legend_two_pane.py -q -k "tc520"
.                                                                        [100%]
1 passed, 8 deselected in 3.04s
```

### 4.2 Frozen guards — BOTH arms (C-27)

`tc031_*` guards the engine **modules**; `tc032_*` guards the engine **test files**, which is the arm
that matters most for a test-only increment. Both were run, plus `test_engine_unchanged.py`:

```
$ python -m pytest tests/test_engine_unchanged.py \
    tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main \
    tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main \
    tests/test_tui_directionb.py::test_tc031_engine_imports_still_resolve \
    tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main \
    tests/test_tui_directionb.py::test_tc032_no_engine_test_function_is_skipped \
    tests/test_tui_directionb.py::test_tc032_directionb_tests_do_not_monkeypatch_engine_functions
configfile: pyproject.toml
plugins: anyio-4.14.2, textual-snapshot-1.1.0, syrupy-4.8.0
collected 7 items

tests\test_engine_unchanged.py .                                         [ 14%]
tests\test_tui_directionb.py ......                                      [100%]

============================== 7 passed in 0.61s ==============================
EXIT=0
```

### 4.3 Blast radius

First run **FAILED**, and the failure was mine — reported rather than quietly fixed, because it is
the more interesting result:

```
FAILED tests/test_crc_designer_view.py::test_orphaned_per_toggle_helper_is_deleted
E         Left contains one more item: 'tests\\test_crc_designer_view.py'
tests\test_crc_designer_view.py:1720: AssertionError
================== 1 failed, 107 passed in 128.98s (0:02:08) ==================
```

**Cause:** TC-511's pass threshold is a repo-wide grep for the retired helper's name returning **zero
hits across `s19_app/` and `tests/`**. The file therefore assembles that token from fragments on
purpose (`_ORPHANED_SWITCH_HELPER = "_switch" + "_row"`) so it cannot falsify its own assertion. I
wrote the literal token into TC-514's docstring while explaining D-1, which falsified it. Fixed by
referring to the helper by description and pointing at the existing constant. **The guard worked
exactly as designed** — this is a shipped control catching a live regression at its own gate.

Re-run, clean:

```
$ python -m pytest tests/test_crc_designer_view.py tests/test_legend_two_pane.py \
    tests/test_tui_legend.py tests/test_legend_n8.py tests/test_legend_scope_and_logwidth.py
tests\test_tui_legend.py ..............                                  [ 58%]
tests\test_legend_n8.py .......................................          [ 94%]
tests\test_legend_scope_and_logwidth.py ......                           [100%]
======================= 108 passed in 132.78s (0:02:12) =======================
EXIT=0
```

### 4.4 C-26 reverse-grep + node existence

```
_switch_row                : 0 hits          <- TC-511's threshold, restored
_ORPHANED_SWITCH_HELPER    : 6 hits
_SWITCH_CTOR               : 2 hits
_vertically_abutting       : 3 hits
permutations               : 3 hits
focus_chain                : 3 hits
legend_close               : 7 hits
```

All 18 test nodes cited in the `REQUIREMENTS.md` Validation lines were confirmed on disk by
`pytest --collect-only` **before** being cited.

### 4.5 Full suite — `pytest -q -m "not slow"`

Exceeds the 10-minute foreground tool cap, so it was run detached and its exit code and tail read
from **that run's own output file** (C-19):

```
--------------------------- snapshot report summary ---------------------------
29 snapshots passed.
2370 passed, 2 skipped, 21 deselected, 3 xfailed in 1455.16s (0:24:15)
EXIT=0
```

Reconciles against the collected total: `2370 + 2 + 21 + 3 = 2396` = the measured collection. **29
snapshots passed; none failed and none was regenerated** — the P-2/P-3 premise holds.

> **Stated precisely.** This run was launched **before** a late edit that added parameter type hints
> to the `_vertically_abutting` helper (PROJECT_RULES.md makes hints mandatory) and reworded one
> docstring line. Both changes are non-behavioural, but the run therefore does not cover the final
> bytes. The gap was closed by re-running **both edited files in full** afterwards:
> `49 passed in 105.65s, EXIT=0`, plus `ruff check` → `All checks passed!`. Recorded rather than
> glossed as "full suite green".

### 4.6 Lint

```
$ python -m ruff check tests/test_crc_designer_view.py tests/test_legend_two_pane.py
All checks passed!
```

`ruff format --check` reports both files would be reformatted — but it reports the **same two files**
at `HEAD` with my changes stashed. **Pre-existing drift, not introduced by this increment**;
`ruff format` is evidently not enforced in this repo. Stated rather than passed over.

---

## 4A. AT-214 clause 4 — the C-40 counterfactual (MANDATORY), full transcript

### 4A.1 Method, and the trap that was avoided

The brief warned that on a sibling increment `PYTHONPATH` **did not** override the worktree package —
the counterfactual ran green against the unmutated tree and looked like a pass. Root cause
established by probe before running anything:

```
$ python -c "import s19_app,sys; print('loaded from:', s19_app.__file__); print(sys.path[0:5])"
loaded from: C:\...\worktrees\next-batch-backlog-8a6c43\s19_app\__init__.py
sys.path[0:5]: ['', 'C:\\Python314\\python314.zip', ...]

$ cd / && python -c "import s19_app"
ModuleNotFoundError: No module named 's19_app'
```

`s19_app` is **not installed anywhere** — no editable install, no `.pth`. It resolves purely from
`sys.path[0] == ''`, i.e. **the current working directory**. `PYTHONPATH` entries are appended
*after* `sys.path[0]`, so running from the worktree meant the worktree always won. The fix is not a
different env var: the run must have **cwd inside the private copy**.

Method used, satisfying option **(a)** of the brief — prove which tree loaded:

- private copy built with `cp -r`, **never `git worktree add`** (which writes into the shared
  `.git/worktrees/`);
- copy contains `s19_app/`, `tests/conftest.py`, `tests/test_crc_designer_view.py`, `pyproject.toml`;
- a throwaway `conftest.py` in the copy emits a `pytest_report_header` printing the **resolved
  package directory** and the **sha256 of the loaded `crc_designer_view.py`**, so the transcript
  proves the tree from inside the run itself;
- `cd <copy> && python -m pytest …`.

### 4A.2 The three hashes

| Stage | Artifact | sha256 |
|---|---|---|
| **before** | `git show HEAD:s19_app/tui/crc_designer_view.py` (blob) | `73879009c52ae43d469ef7aa3326f15e59b14384dadd7a5e40cc64878c748f82` |
| **mutated** | `git show origin/main:…` (blob) = the private copy after restore | `37fe94f85cb616c83052c2e142add9fe18b5fa6cd28dc7734398248fb8685d74` |
| **restored** | the private copy re-restored to HEAD | `73879009c52ae43d469ef7aa3326f15e59b14384dadd7a5e40cc64878c748f82` |

Separately, the **shared worktree** file's own hash, before and after the entire exercise:

| Stage | sha256 of `<worktree>/s19_app/tui/crc_designer_view.py` |
|---|---|
| BEFORE | `2121d3312d5d7ac910aba9677e36b28f56ddb99e003ff832f54022c0219e851e` |
| AFTER | `2121d3312d5d7ac910aba9677e36b28f56ddb99e003ff832f54022c0219e851e` — **IDENTICAL** |

> The worktree hash differs from the `git show HEAD:` blob hash because `core.autocrlf=true` stores
> LF in the blob and checks out CRLF. Both are internally consistent; what matters is
> **before == after**.

### 4A.3 The mutation is real, not a typo'd no-op

A typo'd mutation also "fails", for the wrong reason. Proof the compose genuinely reverted:

```
$ diff <(git show HEAD:…crc_designer_view.py) <copy>/s19_app/tui/crc_designer_view.py
<             # LLR-072-1.1: ONE labelled Reflection pair — each toggle carries its
<                 Label("Reflection", classes="crc-field-label"),
<                 Switch(value=algo.refin, id="crc_field_refin", classes="crc-field-switch"),
<                 Switch(
>             self._switch_row("Reflect in", "crc_field_refin", algo.refin),
>             self._switch_row("Reflect out", "crc_field_refout", algo.refout),
>     def _switch_row(label: str, field_id: str, value: bool) -> Horizontal:
>             Switch(value=value, id=field_id, classes="crc-field-switch"),
```

The reverted file has the per-toggle helper and its two stacked calls back.

### 4A.4 The RED run — fails on AT-214's own assertion line

```
$ cd <scratchpad>/cf214 && python -m pytest tests/test_crc_designer_view.py -k "at214 or tc514"

TREE IN USE           : C:\...\scratchpad\cf214\s19_app
crc_designer_view.py  : sha256 37fe94f85cb616c83052c2e142add9fe18b5fa6cd28dc7734398248fb8685d74
rootdir: C:\...\scratchpad\cf214

...
        switch_ids, abutting = asyncio.run(_drive())
        assert len(switch_ids) >= 2, (...)
>       assert abutting == [], (
            f"no two Switch widgets may render vertically abutting (G-1); "
            f"abutting pairs: {abutting!r} out of {switch_ids!r}"
        )
E       AssertionError: no two Switch widgets may render vertically abutting (G-1);
E         abutting pairs: [('crc_field_refin', 'crc_field_refout')] out of
E         ['crc_field_refin', 'crc_field_refout']
E       assert [('crc_field_...ield_refout')] == []
E         Left contains one more item: ('crc_field_refin', 'crc_field_refout')

tests\test_crc_designer_view.py:1852: AssertionError
=========================== short test summary info ===========================
FAILED tests/test_crc_designer_view.py::test_at214_no_two_switches_render_vertically_abutting
================= 1 failed, 1 passed, 38 deselected in 1.87s ==================
```

Four things this transcript establishes, in order of what could have gone wrong:

1. **the correct tree loaded** — `TREE IN USE` is the private copy, and the printed sha256 is
   `origin/main`'s. This is the check that the sibling increment lacked;
2. **the failure is an `AssertionError` on AT-214's own assertion line** (`:1852`), not an
   `ImportError`, `NameError`, or collection error
   (`feedback_counterfactual_must_fail_on_its_assertion`);
3. **the reported pair is exactly M-1's `c01`** — `('crc_field_refin', 'crc_field_refout')`, the one
   violating pair the census predicted, and the derived set contains exactly the 2 switches M-1
   inventoried. The AT is measuring the thing the requirement is about;
4. **TC-514 PASSED on the mutated tree** (`1 failed, 1 passed`) — correct and expected. TC-514 is the
   completeness guard, not the gate: single-module confinement holds in both trees. Its invariance
   under the change is a property, not a defect, and is now stated as such.

### 4A.5 Control arm — the copy is not simply broken

A RED run proves nothing if the private tree fails for an unrelated reason. Same copy, same cwd, file
restored to HEAD:

```
$ cd <scratchpad>/cf214 && python -m pytest tests/test_crc_designer_view.py -k "at214 or tc514"
TREE IN USE           : C:\...\scratchpad\cf214\s19_app
crc_designer_view.py  : sha256 73879009c52ae43d469ef7aa3326f15e59b14384dadd7a5e40cc64878c748f82
====================== 2 passed, 38 deselected in 1.71s =======================
```

Same tree, same harness, **only the file content differs** → GREEN. The RED is caused by the
mutation and by nothing else.

### 4A.6 Integrity + teardown

```
$ sha256sum <worktree>/s19_app/tui/crc_designer_view.py
2121d3312d5d7ac910aba9677e36b28f56ddb99e003ff832f54022c0219e851e   <-- identical to BEFORE

$ git diff --stat HEAD -- s19_app/
(no output)

$ git status --porcelain
 M tests/test_crc_designer_view.py
 M tests/test_legend_two_pane.py

$ rm -rf <scratchpad>/cf214
```

**VERDICT: C-40 discharged.** AT-214 is falsifiable, fails RED on its own assertion for the right
reason, and the shared worktree is byte-identical throughout.

---

## 5. Risks

| # | Risk | Severity | Mitigation / status |
|---|---|---|---|
| R-1 | **AT-214 and TC-514 coincide with AT-213 today.** Only 2 `Switch` widgets exist, both in the pair row, so G-1 currently polices exactly the pair AT-213 already asserts | ⚠️ Low — **openly stated, not dressed up** | This is the requirement's own admission (HLR-072-3 scope note). What makes it a guard is that the subject set is *derived*: a third `Switch` on this screen is policed with no test edit, and TC-514 fails the moment one is constructed elsewhere |
| R-2 | **TC-514's assertion is now a set of file paths.** A legitimate future `Switch` outside the CRC Designer turns it RED | ⚠️ Low, and intended | That is the alarm firing correctly: it means AT-214's screen-scoped query is no longer complete and the AT must widen. The failure message says so |
| R-3 | `REQUIREMENTS.md` code refs are line numbers into `crc_designer_view.py` / `styles.tcss` / `screens.py` | ⚠️ Low | Every ref was re-read from disk at write time. Line refs drift by nature — the batch-18 `LegendScreen :474` ref had already gone stale, and was refreshed as part of this edit |
| R-4 | `ruff format --check` fails on both test files | ⚪ None introduced | **Pre-existing at HEAD** — verified by stashing. Not this increment's regression, and not enforced by CI |
| R-5 | Full `pytest -q -m "not slow"` exceeds the 10-min tool cap | ⚪ Closed | Run detached; **`2370 passed, 2 skipped, 21 deselected, 3 xfailed`, EXIT=0, 29 snapshots passed** (§4.5). §5.3.4 still assigns the Phase-4 run to the **orchestrator** (C-25) — this one is evidence, not a substitute for that gate |

---

## 6. Pending items

### D-1 — TC-514's specified constant is FALSE on this tree (the one thing not done as written)

**Status: NOT improvised. Re-derived, labelled in the test docstring, and escalated here.**

| | |
|---|---|
| **Specified** | *"assert `Switch(` has exactly **one** construction site in the whole `s19_app/` package"* — the brief, and `01-requirements.md` HLR-072-3 (*"exactly **one** construction site … `crc_designer_view.py:467`, executed grep"*), and `00-measurements.md` M-1 (*"**2** `Switch` widgets from **1** construction site"*) |
| **Measured on `origin/main`** | `s19_app/tui/crc_designer_view.py:467` — **1 site**. The specification was correct *when written* |
| **Measured on `HEAD` (`0169108`)** | `:325` and `:327` — **2 sites** |
| **Cause** | LLR-072-1.2 **deleted** the per-toggle row helper, which held one `Switch(` call invoked twice. Inc-3 then inlined both toggles into the pair row. The refactor that this batch itself performed converted 1 site into 2 |

Executed evidence:

```
$ git grep -n "Switch(" origin/main -- 's19_app/*.py'
origin/main:s19_app/tui/crc_designer_view.py:467:            Switch(value=value, id=field_id, classes="crc-field-switch"),

$ git grep -n "Switch(" HEAD -- 's19_app/*.py'
HEAD:s19_app/tui/crc_designer_view.py:325:                Switch(value=algo.refin, id="crc_field_refin", ...),
HEAD:s19_app/tui/crc_designer_view.py:327:                Switch(
```

**Options considered:**

| Option | Expected result | Consequence |
|---|---|---|
| A — assert `== 1` as specified | TC-514 immediately RED | ❌ ships a failing test asserting a falsified premise |
| B — silently change to `== 2` | GREEN | ❌ hides that a carried number was never re-derived, and re-plants the same brittle constant for the next batch to trip over |
| C — assert the **property** the count stands for | GREEN, and it is the actual load-bearing claim | ✅ chosen, and reported here |
| D — halt the whole increment | — | ⚠️ the other three items are independent and unaffected |

**What was implemented (C).** The requirement's own words state the purpose: the fact exists so that
*"every `Switch` that can exist is on the CRC screen and inside the queried scope."* The count was
always incidental to that; **single-module confinement** is the property, and it survives the refactor
untouched. TC-514 therefore asserts (a) only `crc_designer_view.py` imports `Switch`, and (b) every
`\bSwitch\(` site in the package is in that module — plus non-vacuity. This is the project's own
control in action: *a carried number is re-derived, not copied* (batch-63).

**Owed at close:** correct HLR-072-3's scope note and M-1's completeness paragraph, both of which
state "1 construction site" as a present-tense fact about a tree where it is no longer true.

### D-2 — TC-520 is not in the requirements' §5.2 traceability table

`01-requirements.md` §5.2 allocates `TC-510..TC-519`; the batch's own review then directed that the
focus-traversal pin *"belongs in **this** batch"*. **TC-520** is the next free id (census re-run at
Phase 3 — 0 hits repo-wide for `AT-214`, `TC-514`, `TC-520` outside this batch's directory). §5.2
needs a row added at close: `US-072-2 | HLR-072-6 | 6.1, 6.2 | AT-217 | TC-517, TC-518, TC-520`.

### D-3 — full-suite run still owed by the orchestrator

Executed here and green (§4.5), but §5.3.4 requires the Phase-4 run be **launched and collected by
the orchestrator** (C-25). This run is evidence, not a discharge of that gate.

### D-4 — carried to backlog by `R-TUI-100`, unchanged by this increment

The `Select` affordance-density finding (W-1, with its measurement), the pre-existing **2.54:1**
hero-extent violation (G-3), and the retired G-2 switch-state-word guarantee (R-1). All three are
recorded in `R-TUI-100`'s "deliberately does NOT claim" block so they are traceable from
`REQUIREMENTS.md`, not only from the batch directory.

---

## 7. Ledger + suggested next task

### Ledger

| Quantity | Value |
|---|---|
| base (pre-increment, this branch @ `0169108`) | **2393** |
| `A` (added) | **3** — `AT-214`, `TC-514`, `TC-520` |
| `D` (deleted) | **0** |
| **post (measured)** | **2396** |
| reconciliation | `2393 + 3 = 2396` ✅ **exact** |

```
$ python -m pytest --collect-only -q | tail -2
2396 tests collected in 0.92s
```

### Snapshots

**None regenerated, none run, none failed.** Consistent with P-2/P-3: neither the CRC screen nor the
Legend modal is snapshot-captured (0 CRC snapshots and 0 legend snapshots on disk, re-probed at
Phase 2). Had one failed, the instruction was to STOP — it did not arise.

### Suggested next task

**Phase 4 (validation), owned by the orchestrator.** Specifically:

1. launch and collect the full `pytest -q -m "not slow"` run yourself (C-25);
2. fold **D-1** — correct HLR-072-3's scope note and `00-measurements.md` M-1 from "1 construction
   site" to the re-derived property, so the next batch does not inherit the stale constant;
3. fold **D-2** — add the TC-520 row to §5.2;
4. reconcile `BACKLOG-CODE.md`: line 153's CRC-snapshot claim is measured **FALSE** (P-2) and the
   three W-1 / G-2 / G-3 carries are owed entries.

---

## Evidence checklist

- [x] **Tests/type checks/lint pass** — `ruff check` **All checks passed!**; new nodes 3/3 green;
      blast radius **108 passed**; frozen guards **7 passed, EXIT=0**; full suite **2370 passed,
      EXIT=0, 29 snapshots passed**. `ruff format --check` fails **identically at HEAD**
      (stash-verified pre-existing) — §4.6, stated not buried.
- [x] **No secrets in code or output** — the increment adds test assertions, a source-path scan and
      documentation prose. No credentials, tokens, env files or host-identifying content beyond the
      scratchpad paths already standard in this batch's artifacts.
- [x] **No destructive commands run without approval** — the only `rm -rf` targeted the scratchpad
      private copy (`<scratchpad>/cf214`), created by this session for this purpose. `git worktree
      add` deliberately **not** used (it writes into the shared `.git/worktrees/`). One `git stash` /
      `git stash pop` pair, verified restored (§4.5).
- [x] **File count within cap** — **3** of ≤5. `git diff --stat HEAD -- s19_app/` → **empty**.
- [x] **Review packet attached** — this document.
- [x] **C-40 counterfactual executed** — §4A, RED on AT-214's own assertion line at
      `test_crc_designer_view.py:1852`, tree-of-record proven by in-run header, control arm GREEN,
      three hashes recorded, worktree byte-identical before/after.
- [x] **C-26 reverse-grep** — §4.4, all touched symbols.
- [x] **C-19 evidence from one complete run per gate** — exit code and tail read from each run's own
      output; the blast-radius failure is reported as it happened rather than replaced by the re-run.
