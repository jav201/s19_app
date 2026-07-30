# Increment 1+2 code review — batch 2026-07-30-batch-72

> Independent review of commit `6854234` (`git diff 54c4b29..6854234`), performed against
> `01-requirements.md` **revision 3**, `00-measurements.md`, and the two increment packets.
> Reviewer did **not** write the code and did **not** edit any source or test file in the shared
> worktree. All execution was done in an isolated detached worktree at `6854234`
> (created, used, verified clean, removed). Artifact language: English.

---

## BLUF

**BLOCK — one HIGH finding.** The code is correct: every LLR-072-5.1/5.2/6.1/6.2/7.1 detail the
requirement earned the hard way is present and I re-measured each one. Nine of the eleven
mutations I ran reddened the node that claims to own them, AT-217's "reachable under scroll" clause
is genuinely non-vacuous, and the TC-516 census is an accurate, honest mirror of the nine real query
sites. The AT-216 oracle-mutation report is exactly right and stated honestly.

**What blocks: the wide regime's defining property is asserted by nothing.** HLR-072-5 requires the
panes **side by side, card left, key right**. No node in this batch asserts any horizontal
relationship between the two panes. I removed the `#legend_dialog.legend-narrow ` prefix from all
three narrow CSS rules — the *exact* slip that `styles.tcss:1567-1570` and increment-002's risk
table both claim the tests catch — and the wide regime silently collapsed into a **vertical stack**
(card above key, the pre-batch defect shape) while all 8 nodes stayed **GREEN, exit 0**. The risk
table's claim *"TC-517 + AT-216 (wide, unchanged) together would catch a regression"* is falsified
by execution. Fix is ~2 assertions on already-measured numbers.

---

## Scope reviewed

`git diff 54c4b29..6854234` — 5 files, +1181/−3:

| File | Lines |
|---|---|
| `s19_app/tui/screens.py` | `+1029-1036` (constant), `1203-1245` (`compose`), `1247-1288` (`_apply_width_regime`, `on_mount`, `on_resize`), import `events` |
| `s19_app/tui/styles.tcss` | `1539-1588` (4 hunks) |
| `tests/test_legend_two_pane.py` | new, 697 lines |
| `.dev-flow/…/increment-001.md`, `increment-002.md` | packets |

Read in full. Everything below is executed, not reasoned.

---

## Clean axes (stated explicitly — these are sound)

**Scope discipline — verified by diff, not by assertion.**

- `git diff --name-only origin/main 6854234 -- <frozen set incl. legend.py>` → **empty**.
- `git diff 54c4b29..6854234 -- styles.tcss | grep -E "^[-+].*(sev-|band-|legend-card-)"` → **no
  output**. Not one line added or removed in those blocks.
- No snapshot file in the diff, and `grep -rn -i legend tests/test_tui_snapshot.py` shows **no
  snapshot test opens `LegendScreen`** — premise P-2 independently confirmed, so "no snapshot
  failed" is meaningful rather than lucky.
- `legend.py` untouched (TC-519 verified RED under an appended byte — see table).

**Correctness against the LLRs — every "earned the hard way" detail present and re-measured.**

| Detail | Evidence |
|---|---|
| `id="legend_body"` on the wrapper | `screens.py:1236`; `grep -rn legend_body tests/` returns exactly the 9 pre-existing query lines, all still resolving |
| `self.app.size.width`, not `self.size.width` | `screens.py:1283,1288`. The requirement's *fact* is true: measured `requested=(120,30) → app.size=Size(120,30), screen.size=Size(118,28)` |
| All three narrow rules prefixed | `styles.tcss:1575,1579,1584` — all three carry `#legend_dialog.legend-narrow` |
| `move_child` idempotent | `screens.py:1279-1280` guarded on `body.children[0] is not first`; 4 regime transitions in TC-517 with no drift or exception |
| `_render_card`/`_render_key` re-parented, not reconstructed | `screens.py:1234-1235` — each called **once**, same order as before; TC-515 pins counts and reddens on a dropped widget |
| Breakpoint cited, not invented | `_LEGEND_NARROW_WIDTH = 120` vs `app.py:6202  narrow = width < 120` — verified identical |

**Measured geometry reproduces the packets exactly** (my own probe on `6854234`):

```
size=(120,30) narrow=False  body Region(6,6,107,15) layout=horizontal children=[card,key]
              card Region(6,6,64,15) msy=18    key Region(70,6,43,15) msy=0
size=(80,24)  narrow=True   body Region(6,6,68,9)  layout=vertical  children=[key,card]
              key  Region(6,6,68,4) msy=6      card Region(6,10,68,5)
```

**Gate suite reproduced independently:** `pytest -q test_legend_two_pane test_tui_legend
test_legend_n8 test_legend_scope_and_logwidth test_engine_unchanged test_tui_directionb` →
**242 passed in 295.86s, exit 0**. Matches increment-002 §4 exactly.

**`width: 70% → 96%` is safe.** Dialog fits inside the screen at 40/60/80/120/200 cols — measured
`fits=True` at every one.

**AT-216 clause 4 honesty — the implementer's claim is correct.** I re-ran the `display: none`
mutation: RED on **clause 2b only**, on the identical `Region(0,0,0,0)` message. The module
docstring (`tests/test_legend_two_pane.py:39-42`) states plainly that clauses 1 and 2a are *blind*
to it and why. That is honest reporting, not implied coverage.

**Regression risk (the 9 sites) — census is accurate.** `grep -rn legend_body tests/` (excluding the
new file) returns 9 query lines; `_LEGEND_BODY_QUERY_SITES` lists exactly those 9. I traced every
helper to its callers to confirm each site is probed on a view its own test actually drives:
`_artifact_headings` (scope:34) is called on `mac` at `:61`; `_modal_meanings` (tui_legend:60) on
`mac` at `:190`; `_legend_body_text` (n8:284) on `mac` at `:354`; n8:387 → `issues`; scope:88/89 →
`workspace`; scope:121 → `a2l`; tui_legend:338/407 → `flow`. All resolve non-empty except
scope:88, which its own test asserts `== 0` and the census correctly records as expected-empty —
with a second arm proving that selector resolves elsewhere (`:121`, a2l). C-38 properly discharged,
and mutation **M7** proves the census reddens.

**Convention / simplicity — no findings.**

- `ruff check screens.py tests/test_legend_two_pane.py` → **All checks passed.**
- `compose` and `_apply_width_regime` carry the fixed section order with `Data Flow` **and**
  `Dependencies`; type hints agree with the docstring types.
- `on_mount` (no docstring) and `on_resize` (one line) match the file's own convention — 6 of 7
  other `on_mount`s in `screens.py` carry none.
- `LegendScreen._apply_width_regime(self, width: int) -> None` deliberately mirrors
  `S19TuiApp._apply_width_regime`'s name and signature. Good reuse of the existing idiom; nothing
  over-built, nothing speculative. The screen-owned hook is *necessary*, not preference — I
  confirmed `width-narrow` is applied only to `#workspace_shell`/`#workspace_body` (`app.py:6203`).
- **Escape does not dismiss `LegendScreen`** — but that is pre-existing, not a regression: measured
  at `tabs=0` (focus on `#legend_close`) too. `BINDINGS = ['tab','shift+tab','ctrl+c']`. Out of
  scope; noted only so it is not mistaken for new.

---

## Findings

### F1 — The wide regime's side-by-side layout is pinned by nothing; the packet's specificity claim is false  [Severity: HIGH]

- **What:** HLR-072-5 requires the panes **"side-by-side — card left, key right"**
  (`01-requirements.md:224-225`), and LLR-072-5.2's own declared verification is *"measured: card 64
  cols, key 43 cols"* (`:338`). Neither is encoded. `grep -n "region.x|region.right|\.width" 
  tests/test_legend_two_pane.py` returns **zero assertions** — every geometric clause is a
  *containment* or *ordering* claim, all of which are equally true of a vertical stack.

- **Where:** `tests/test_legend_two_pane.py:206-223` (AT-216 clause 2/3); requirement
  `01-requirements.md:224-243`, `:338`; the falsified claim is
  `03-increments/increment-002.md:154`.

- **Why it matters — executed, not reasoned.** I removed the `#legend_dialog.legend-narrow ` prefix
  from all three narrow rules (3 occurrences, the real historical slip):

  ```
  $ pytest -q tests/test_legend_two_pane.py     # narrow rules UNPREFIXED
  exit 0
  8 passed in 21.74s
  ```

  and the wide regime is **broken**:

  ```
  size=(120,30) narrow_class=False   body layout=vertical
    card Region(x=6, y=6, width=107, height=7)     <- full width
    key  Region(x=6, y=13, width=107, height=8)    <- BELOW the card
    body contains key: True
  ```

  That is the *shipped defect this batch exists to remove* — the key back under the card — and
  AT-216 stays green on all four clauses: the row is in the key pane ✓, the key pane is in the body
  ✓ (stacked, but inside), `max_scroll_y == 0` ✓ (at width 107 the key wraps into 8 rows).
  TC-516/TC-517 are blind too: document order is still `[card, key]` and the class is still absent.

  Two weaker mutations confirm the axis is unguarded: swapping `3fr`/`2fr` (key wider than card) →
  **8 passed**; `height: 1fr → height:auto` on the *wide* key pane → **8 passed**.

  This meets the project's own definition of the dominant defect class: the acceptance test for
  HLR-072-5 does not test HLR-072-5, and a review packet asserts coverage that execution disproves.
  Nothing about the *code* is wrong — the prefix is correctly there. The problem is that its being
  there is load-bearing and unpinned.

- **Suggested fix** (measure already exists — card `right = 70`, key `x = 70`, both `y = 6`). In
  `_measure_key_pane`, add:

  ```python
  card_pane = legend.query_one("#legend_card_pane")
  ...
      "card_right": card_pane.region.right,
      "card_y": card_pane.region.y,
      "key_x": key_pane.region.x,
      "key_y": key_pane.region.y,
      "card_region": card_pane.region,
  ```

  and a clause 2c in `test_at216_…`:

  ```python
  # clause 2c — the WIDE regime's defining property: side by side, card LEFT.
  # Containment and ordering are both true of a vertical stack, so neither can
  # see an unprefixed narrow rule winning in the wide regime (executed: it
  # stacks the panes at card y=6 / key y=13 and AT-216 stayed green).
  assert m["key_x"] >= m["card_right"], (
      f"the key pane must sit to the RIGHT of the card, not stacked: "
      f"card={m['card_region']} key={m['key_region']}"
  )
  assert m["key_y"] == m["card_y"], (
      f"the panes must share a top edge (side by side): "
      f"card={m['card_region']} key={m['key_region']}"
  )
  ```

  Verified against both trees: baseline `70 >= 70` and `6 == 6` → GREEN; unprefixed mutation
  `6 >= 113` → RED. Also update `increment-002.md:154`'s specificity claim to name the clause that
  actually carries it.

---

### F2 — TC-518's textual arm is whitespace-exact, and its live arm only probes the floor  [Severity: MEDIUM]

- **What:** arm (a) is `assert "height: auto" not in body` — a literal substring. Arm (b) resolves
  the live unit **only at 80x24**, where the *narrow* rule wins, so it can never observe the wide
  rule's height.
- **Where:** `tests/test_legend_two_pane.py:635-649`.
- **Why it matters:** executed — writing `height:auto` (no space) in the **wide** `#legend_key_pane`
  rule passes both arms: `8 passed`. TC-518 is the declared guard against the degenerate regime
  (LLR-072-6.2) and its scan claims to cover every `#legend_key_pane` rule (`len(blocks) >= 2`), so
  a spelling-sensitive predicate under-delivers on its own label.
- **Suggested fix:**

  ```python
  import re
  _HEIGHT_AUTO = re.compile(r"height\s*:\s*auto")
  ...
      assert not _HEIGHT_AUTO.search(body), (...)
  ```

  and add a 120x30 probe alongside the 80x24 one so both regimes' resolved units are asserted
  `Unit.FRACTION`.

---

### F3 — `on_mount`'s width argument is unpinned; a Resize masks it  [Severity: LOW]

- **What:** mutating **only** `on_mount`'s call to `self.size.width` leaves all 8 nodes green
  (`2 passed` on `-k "tc517 or at216"`), because a `Resize` arrives right after mount and
  `on_resize` re-applies the correct regime. Mutating `on_resize`, or both, correctly reddens
  TC-516 **and** TC-517 (verified both ways).
- **Where:** `s19_app/tui/screens.py:1283`.
- **Why it matters:** the requirement singles this out as the detail most likely to be got wrong
  (`01-requirements.md:339`), and half of it is unguarded. The code is **correct**; this is a
  coverage note, and the risk is that a future edit to `on_mount` alone goes unnoticed.
- **Suggested fix:** in TC-517, take the first sample *before* any pause that could deliver a
  Resize, or add a direct unit-level assertion that `on_mount` was called with the app width — e.g.
  assert `has_class("legend-narrow") is False` immediately on `app.screen` after `press("k")` at
  `run_test(size=(_LEGEND_NARROW_WIDTH, 30))` with `on_resize` monkeypatched to a no-op. Optional;
  do not block on it.

---

### F4 — `#legend_body { overflow: hidden }` is pinned by nothing  [Severity: LOW]

- **What:** reverting it to `overflow-y: auto` → `8 passed`.
- **Where:** `s19_app/tui/styles.tcss:1549`.
- **Why it matters:** self-reported in both packets (increment-001 §5, increment-002 §6) — I am
  confirming it, not discovering it. The consequence is the three-nested-scroll-context state
  LLR-072-5.2 exists to prevent; at current content sizes the symptom is invisible.
- **Suggested fix:** one line in TC-518's stylesheet scan
  (`assert "overflow: hidden" in body` for the `#legend_body` block), or carry it to the backlog
  with this measurement attached. Author's call.

---

### F5 — AT-218 clause 4 is unencoded and unmentioned in the test  [Severity: LOW]

- **What:** the requirement gives AT-218 four clauses; the test implements 1–3. Clause 4 ("the three
  legend test files stay green") is a gate-run property, discharged in increment-001 §4 — but
  neither the module docstring nor `test_at218_…`'s docstring says so.
- **Where:** `tests/test_legend_two_pane.py:393-404` vs `01-requirements.md:299`.
- **Suggested fix:** one sentence in the test docstring: *"Clause 4 (the three legend files stay
  green) is a gate-run property, discharged in the increment packet, not encodable here."*

---

### F6 — `on_resize` ignores `event` for a reason that is not stated at the ignore site  [Severity: LOW]

- **What:** `on_resize(self, event: events.Resize)` reads `self.app.size.width` and discards
  `event`. The App-level sibling at `app.py:6212` **does** use `event.size.width`, so the divergence
  is real and a future "cleanup" would look like a fix.
- **Where:** `s19_app/tui/screens.py:1286-1288`.
- **Suggested fix:** append to the one-line docstring: *"Reads `self.app.size.width`, not
  `event.size` — under a modal the screen size is 2 smaller than the terminal (measured: 118 at a
  120-col terminal), which would flip the wide regime narrow."*

---

## Per-AT / per-TC falsifiability table

Every row executed independently in an isolated worktree; mutations reverted and the tree verified
clean before removal.

| Node | Mutation that reddens it | Result | Verdict |
|---|---|---|---|
| **AT-216** c1 (anchor) | drop one card widget (M6) — passes; c1 has no independent mutation run | c1 not separately falsified | ⚠️ weak alone, but redundant with TC-515 |
| **AT-216** c2a (row ⊂ pane) | key pane `width: 2fr → 12` | **RED** `row not inside key pane (key=Region(101,6,12,15))` | ✅ |
| **AT-216** c2b (pane ⊂ body) | key pane `display: none` | **RED** `Region(0,0,0,0) not inside Region(6,6,107,15)` | ✅ — and **only** 2b, as reported |
| **AT-216** c3 (`max_scroll_y == 0`) | — no mutation reddened c3 first; c2a fires earlier | not independently observed | ⚠️ ordering, not vacuity |
| **AT-216 — side-by-side** | unprefix the 3 narrow rules | **GREEN (8 passed)** while the wide regime stacks | ❌ **F1** |
| **AT-217** c1 (key above card) | `move_child` → no-op | **RED** `assert 10 < 6` | ✅ |
| **AT-217** c2 (card ≥ 2 rows) | narrow key `height: 1fr → auto` | **RED** `card=Region(6,16,68,1)`, `assert 1 >= 2` | ✅ tooth confirmed |
| **AT-217** c3 (reachable under scroll) | remove `scroll_visible(animate=False)` | **RED** `last_row_in_key=False` | ✅ **not vacuous** |
| **AT-218** c1 (`render().spans`, C-37) | strip `[orange3]…[/]` from the sample | **RED** `'orange3' in set()` | ✅ |
| **AT-218** c2 (`markup=False`) | drop `markup=False` on band rows | **RED** `[True,True,True,True,False]` | ✅ |
| **AT-218** c3 (9-site census, C-38) | key pane moved outside `#legend_body` | **RED** `scope_and_logwidth.py:34 resolved 0 widgets` | ✅ |
| **TC-515** (M-6 counts) | `_render_card()[:-1]` | **RED** `{'mac': (16,6), 'map': (19,7)}` | ✅ |
| **TC-516** (wrapper + census) | key pane outside body; also `self.size.width` on both sites | **RED** both ways | ✅ |
| **TC-517** (class + order flip) | `move_child` no-op; `on_resize` deleted; `self.size.width` | **RED** all three | ✅ |
| **TC-518** (no `height: auto`) | narrow key `height: auto` | **RED** both arms | ✅ narrow only — see **F2** |
| **TC-519** (`legend.py` unchanged) | append a byte to `legend.py` | **RED** `['s19_app/tui/legend.py']`; ref resolved `origin/main`, **no skip** | ✅ |

C-32 (regions, not a content harness), C-37 (`render().spans`, not `render_line`) and C-38 (census
of every query site) are all correctly applied. No assertion in the module passes on an empty query.

---

## Focus traversal — recommendation

**Measured** (`focus_chain` on `6854234`):

```
120x30  initial focus = legend_close   chain = [card_pane, key_pane, legend_close]
80x24   initial focus = legend_close   chain = [key_pane, card_pane, legend_close]
tab cycle wraps correctly in both; the modal is never lost
```

**Accept the behaviour, and pin it in this batch.** Reasons:

1. It is not a regression in the part that matters — initial focus is still `#legend_close`,
   unchanged.
2. The 3rd stop is *required*, not incidental. At the floor the key is **scroll-only by design**
   (AT-217 clause 3, G-4 "≤1 interaction"). If the panes were made `can_focus = False` to restore
   the old 2-stop cycle, the key would become unreachable by keyboard at 80x24 and G-4 would fail.
   The stacking reorder also puts the key pane **first** at the floor, which is the operator's own
   Phase-1 preference expressed in focus order.
3. Nothing is broken today: `grep focus_chain|focused.id|press("tab")` across all four legend test
   files returns **nothing** — no test asserts a tab order anywhere.

**But pin the properties, not the literal chain.** A `== [card, key, close]` assertion is brittle
against any future container. Suggest a TC asserting: (a) `screen.focused.id == "legend_close"` on
open in both regimes; (b) both pane ids appear in `[w.id for w in screen.focus_chain]`; (c) at 80x24
the key pane precedes the card pane in that list. This belongs in **this** batch — the batch caused
the change, and increment-001 §5 already carries it as "not covered by any node".

---

## Verdict

- [ ] OK to advance
- [ ] OK with the listed fixes applied first
- [x] **BLOCK — F1 (HIGH) must be fixed before the gate**

F1 only: add AT-216 clause 2c (two assertions, values already measured) and correct
`increment-002.md:154`'s specificity claim. F2 is a recommended fix in the same pass. F3–F6 are
recommendations; none blocks. Re-review of the clause-2c diff alone is sufficient to clear the gate.

---

## Evidence checklist

- [x] **Diff read in full** — `54c4b29..6854234`: `screens.py:1029-1036,1203-1288`,
      `styles.tcss:1539-1588`, `tests/test_legend_two_pane.py:1-697`, both packets.
- [x] **Correctness pass (edge / None / error paths)** — `move_child` guarded on empty `children` and
      on already-first (`screens.py:1279`); idempotent across 4 measured regime transitions; dialog
      fits at 40–200 cols; escape-dismissal absence confirmed pre-existing.
- [x] **Simplicity pass** — nothing premature; `ruff` clean; the screen-owned hook is necessary
      (`width-narrow` provably cannot reach a `ModalScreen`, `app.py:6203`).
- [x] **Reuse / duplication checked** — `LegendScreen._apply_width_regime` deliberately mirrors
      `S19TuiApp._apply_width_regime`'s name/signature; `_render_card`/`_render_key` reused
      unmodified; `legend.py` byte-identical to `origin/main`.
- [x] **Tests reviewed for intent** — 16 falsification runs; 15 nodes/clauses redden on a named
      mutation, **1 axis (wide side-by-side) does not** → F1.
- [x] **Regression risk** — TC-516 census matches `grep` ground truth 9/9, every helper traced to a
      caller on the declared view; gate suite reproduced independently at **242 passed, exit 0**.
- [x] **Scope discipline verified by diff** — frozen set empty, `.sev-*`/`.band-*`/`.legend-card-*`
      untouched, no snapshot touched and none captures this screen.
- [x] **No source or test file edited in the shared worktree** — all execution in an isolated
      detached worktree, verified clean (`git status --porcelain` empty) before removal.
- [x] **Verdict explicit** — BLOCK on F1.
