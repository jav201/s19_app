# Code Review — Increment 005 (HLR-124, three width/height regimes)

**Reviewer:** `code-reviewer` (independent; did not write this increment)
**Diff under review:** `b12b205..9015b7f` on `claude/batch-78-cmdbar-a2bdiff`
**Repo:** `C:\Users\jjgh8\Github\s19_app`
**Date:** 2026-08-06

---

## BLUF

**Verdict: BLOCK on one HIGH.** The increment is unusually well-evidenced — I
re-derived every headline figure independently and **all of them reproduce to
the digit**, including the eight-row regime table, the `26` re-derivation, the
`29`-with-the-bar explanation, `A-2`'s false premise, and the `M9` INERT result.
**The Inc-4 `M2` gap the author flagged and did not close: I executed it, and
Inc-4's discharge has NOT lapsed.**

The block is on a different axis, and it is one the packet does not raise:
**`_DIFF_MIN_H = 26` admits two terminal heights in the SHIPPED end state where
the panel selects the deliverable "fallback" regime and paints ZERO hex rows** —
a header line and nothing else. That is the silently-empty results area HLR-124
exists to abolish, and by the batch's own file plan the constant cannot be moved
after Inc-5.

| Severity | Count |
|---|---|
| **HIGH** | **1** |
| MEDIUM | 2 |
| LOW | 4 |

---

## Scope reviewed

| File | Lines in diff | Read |
|---|---|---|
| `s19_app/tui/screens_directionb.py` | `+289 / -16` (`:6569-6600` constants, `:6683-6707` BINDINGS, `:6778-6789` fields, `:6845-6858` compose, `:6862-7035` regime + overlay + paging, `:7420-7444` the page branch) | in full |
| `s19_app/tui/app.py` | `+28` (`_apply_diff_regime` + one call in `on_resize`) | in full |
| `s19_app/tui/styles.tcss` | `+102` (`:1523-1636`) | in full |
| `tests/test_tui_diff_screen.py` | `+692 / -8` (`_b78_open_run_list`, the `_B78_INC4_SHORT` move, the Inc-5 block) | in full |
| `.dev-flow/.../01-requirements.md` | `+3 / -3` (the coordinator's three corrections) | in full |

**4 source/test files, cap 5.** ✓ Confirmed. The `01-requirements.md` edit is the
coordinator's, not the author's.

---

## What I verified as SOUND (executed, not read)

Every measurement below is my own, from scripts I wrote, not the author's helpers.

### S-1 · The regime table reproduces on all eight sizes — exactly

Read off the live tree with an independently re-implemented ancestor-chain
painted-height metric (`content_region` clipped through every `Widget` ancestor,
per Inc-1's correction — **not** §5.1 rule 1's form).

| Terminal | Regime | `#diff_hex_a` w × painted h | Author's claim | Match |
|---|---|---|---|---|
| 80×24 | notice (both axes) | 0 × 0 | 0 × 0 | ✅ |
| 80×30 | notice (**width only**) | 0 × 0 | 0 × 0 | ✅ |
| 120×24 | notice (**height only**) | 0 × 0 | 0 × 0 | ✅ |
| 120×30 | fallback | **90** × 1 | 90 × 1 | ✅ |
| 132×44 | fallback | **102** × 8 | 102 × 8 | ✅ |
| 160×40 | wide, list beside (`list_width = 22`) | **100** × 2 | 100 × 2 | ✅ |
| 138×40 | fallback | **108** | 108 | ✅ |
| 139×40 | **wide** | **79** — the first fit, to the column | 79 | ✅ |

Widest emitted `render_hex_view` row measured at test time: **79**. Every
deliverable regime clears it. `_DIFF_WIDE_MIN = 139` needs no correction.

### S-2 · `_DIFF_MIN_H = 26` is correctly re-derived, and the discarded circular sweep was right to be discarded

Re-run independently with `AbDiffPanel`'s regime classes **forced** to
`diff-fallback` (so the constant cannot select the branch it measures) and the
command-bar row hidden:

```
W = 94 :  25 -> 0, 26 -> 1, 27 -> 1, 28 -> 2    FLOOR = 26
W = 120:  25 -> 0, 26 -> 1, 27 -> 1, 28 -> 2    FLOOR = 26
W = 138:  25 -> 0, 26 -> 1, 27 -> 1, 28 -> 2    FLOOR = 26
```

**Width-independent, exactly as the spec claimed — only the value moved.** ✅

And the spec's `29` is reproducible, which is what makes the drafted figure
explicable rather than merely wrong. With the command-bar row **still present**:

```
W = 94 / 120 / 138:  28 -> 0, 29 -> 1    FLOOR = 29  (all three widths)
```

✅ `C-78-xxiv` and `C-78-xxv` are both earned by real evidence.

### S-3 · `A-2`'s premise is FALSE — confirmed by execution

```
CommandBar declares BINDINGS in its own __dict__: False
CommandBar defines on_key:                        False
after ctrl+k : palette_is_open=True  focus=palette_input
after escape : palette_is_open=True  focus=palette_input
```

**There is no palette `escape`-to-close to shadow.** Both Phase-2 lanes accepted
a constraint against nothing. The author is right, and the finding is material.
The coordinator's `LLR-119.3` correction states the Inc-9 consequence
**accurately** — it forbids inheriting the constraint, names the two dispositions,
and requires Inc-9 to choose in writing rather than assume. ✅ (One gap: see F-6.)

### S-4 · Inc-2's ATs are genuinely re-armed, not re-labelled

Mutation: `add_class(self._RUNS_OPEN)` → `remove_class(...)`, so the overlay
never opens. Applied-checked, sha-chained, restored.

```
AT-B78-15  FAILED   AT-B78-16  FAILED   AT-B78-17  FAILED
E  AssertionError: the run-list overlay must open on 'f' in the fallback
   regime; #diff_range_list.display is False
POST (restored): 3 passed
```

**All three redden.** `AT-B78-15`/`-17`, which the author reports would have
stayed green against a `display: none` list, now fail. ✅ The `C-78-xiii`
driver-guard shape holds. (Diagnostic caveat at F-4.)

### S-5 · The counterfactuals I re-ran are honest

| Arm | Result | Verdict |
|---|---|---|
| **M3** (`C-78-xxiii` mapping — the failed WIDTH axis named `height`) | `AT-B78-29` + `TC-B78-32` RED, both on their own `AssertionError` | ✅ reproduces |
| **M9** (`priority=True` on the panel's `escape`) | **green — INERT**, reproduced | ✅ **the PIN label is honest, not a downgrade** |
| Restore | `FINAL sha == baseline` (`e5f692070c154848`) across my four arms | ✅ |

M9 is genuinely inert: Textual collects priority bindings from the screen and app
namespaces, and a `Container`-level binding is on neither. Labelling `TC-B78-51`
arm 2 a **PIN** with the attempted mutation recorded is the correct disposition,
and it is recorded rather than quietly dropped. **This is not a fix being
avoided.**

### S-6 · The stacking finding (F-1) is real, and dropping the chrome is SOUND

The horizontal budget genuinely fits one window: at 160 the widest supported
terminal, `#diff_columns` has 132 content cells against `L + 5 + 79 + 5 ≤ C`.
Two 79-cell windows cannot sit side by side at any supported width, so stacking
is forced, not chosen. Measured consequence at 120×30: the results pane is 6 rows
and two bordered boxes spend 8 on chrome. **Dropping the border and vertical
padding in the fallback regime only** is the difference between 2 hex rows and 0,
and it trades away nothing the spec relies on:

- Horizontal padding is **kept** — 90 content cells at 120×30, well clear of 79. ✅
- The wide regime **keeps** its bordered boxes, so the spec's own 160-column
  arithmetic (100 content cells) is untouched. ✅
- The two stacked windows stay distinguishable without a border because each
  carries its own `Image A —` / `Image B —` header line. ✅

The scoping to `.diff-fallback` is what makes this sound. I would have blocked a
blanket border removal.

### S-7 · The mechanical checks

| Check | Result |
|---|---|
| **4 files, cap 5** | ✅ |
| **App `BINDINGS` untouched** — `AT-B78-32` safe | ✅ zero `BINDINGS` hunks in `app.py`'s diff; the change is at `on_resize`, far below `:1338-1392` |
| All new bindings **widget-scoped, `show=False`** | ✅ 4/4 on `AbDiffPanel` |
| `f` / `escape` / `[` / `]` free at App level | ✅ none present in the App `BINDINGS` block |
| **Collection census 45** (Inc-4: 35), `D = 0`, `A = 10` | ✅ `45 tests collected`; `git show b12b205` gives 35 |
| **Ledger `2637 + 10 = 2647`** | ✅ as arithmetic, and the packet labels it arithmetic |
| **Snapshots: one cell only** | ✅ `1 failed, 31 passed` — `[diff-comfortable-120x30]` alone. **No second cell moved**, re-run by me |
| **C-17** | ✅ `#diff_hex_a` / `#diff_hex_b` still `markup=False`; `#diff_size_notice` `markup=False` at construction |
| **SEC-F2** | ✅ `_notice_text` composes author-constant strings + `width`/`height`/`_DIFF_MIN_*` integers only; no path, label or artifact name is reachable. Bounded before the sink existed — the right order |
| **C-26 reverse-grep** over the whole `tests/` tree | ✅ all five new symbols defined once, no consumer outside the owning module |
| **C-39 literals** in the new nodes | ✅ `139` = 0; `94` = 1 but **inside a docstring**, not executable; `29`/`26` only as node-id substrings. No executable literal |
| `_apply_diff_regime` matches the `_apply_width_regime` precedent (bare `query_one`, no guard) | ✅ conformance over taste |
| Working tree not dirtied; `prototypes/memmap2.*` untouched; no `git add -A`, no `git stash` | ✅ mutations ran in a detached worktree, since removed |

### S-8 · The three new carries — judged individually

| Carry | Verdict |
|---|---|
| **`C-78-xxiv`** — *a sweep its own threshold can veto* | ✅ **EARNED, and general.** I reproduced both the circular and the forced sweep; they differ by 3 rows and the circular one is indistinguishable from a real floor. This is a genuine measurement-design control, not a restatement of an existing one |
| **`C-78-xxv`** — *a geometry constant carried across a layout change is stale* | ✅ **EARNED.** `29` was measured honestly on a side-by-side layout the same requirement's width arithmetic already made impossible. Strong sibling to the batch's `re-derive, never re-cite` line |
| **`C-78-xxvi`** — *`bool(widget)` is `len(children) > 0`* | ✅ **EARNED, and the self-report is creditable.** Framework-specific but the general form (*probe with `is None`, never truthiness, on anything that might be a container*) transfers. The author caught it before shipping a code comment describing a fix for a bug that did not exist |

---

## THE FLAGGED GAP — Inc-4's `M2` against the moved `_B78_INC4_SHORT`

**Executed. The discharge has NOT lapsed. This is a PASS.**

Mutation `high = end + self.DISPLAY_CONTEXT_BYTES` → `high = end`, applied in a
detached worktree at `9015b7f`, applied-check `True`, sha
`e5f692070c154848 → 27500b5c59753671`, restored.

```
--- X1  Inc-4 M2 vs the MOVED _B78_INC4_SHORT (132x26)
    MUT rc=1 | 1 failed, 1 passed in 5.59s
    E  AssertionError: the window must span exactly the run plus one context
       row on each side; expected ['0x00000FF0', '0x00001000', '0x00001010'],
       emitted ['0x00000FF0', '0x00001000']
    E  assert [4080, 4096] == [4080, 4096, 4112]
    FAILED tests/test_tui_diff_screen.py::test_at_b78_22_window_spans_the_run_plus_context
    POST (restored) rc=0 | 2 passed
```

`AT-B78-22` reddens **on its own address assertion**, with the identical message
Inc-4's transcript recorded at 132×24 — not on an error, not in the driver, and
not on the containment co-assertion (which remains declared inert). The exact arm
survives the fixture move intact. **The author's reasoning was correct; it is now
a transcript.** R-4's open item is closed.

---

## Findings

### F-1 — `_DIFF_MIN_H = 26` ships two heights that pass deliverability and paint ZERO hex rows  ·  **[Severity: HIGH]**

- **What:** `_DIFF_MIN_H` is defined and measured as *"the first terminal height
  at which a window paints a **content row**"*. But `_render_run_windows` writes
  `f"Image A — {header}\n{text_a}"`, so **screen line 0 of each window is the
  HEADER**. A painted content height of 1 therefore delivers **zero bytes**.

  Executed, in the **post-Inc-10 end state the constant is defined for** (command
  bar hidden), driving a real comparison and counting painted hex rows:

  | Terminal | Regime | capacity | **Visible HEX rows** |
  |---|---|---|---|
  | 120×25 | notice | — | — (the operator is told why) |
  | **120×26** | **fallback** | **0** | **0** ← header only |
  | **120×27** | **fallback** | **0** | **0** ← header only |
  | 120×28 | fallback | 1 | 1 |
  | 120×30 | fallback | 2 | **2** ✅ (R-1's accepted viewport, exact) |

  At H = 26 and 27 the panel declares the terminal deliverable, hides the notice,
  and shows the operator a header line and nothing else. **That is the silently
  empty results area HLR-124 exists to abolish** — and it is strictly worse than
  H = 25, where the operator at least gets a notice explaining the problem.

  This is **not** the temporary Inc-5→Inc-10 window the packet discloses in R-1
  (heights 26–28 while the bar is present). It is **permanent in the shipped end
  state**, and it is not disclosed anywhere in the packet, the docstring or the
  spec correction.

- **Root cause — a conflict inside the spec that was resolved silently.** The
  batch carries two metrics for the same idea:
  - §2.8 D-1's height axis: *"the window has **at least one visible content
    row**"* → the author's `painted >= 1` → **26**.
  - `LLR-125.2`, **normative**: *"`#diff_hex_a` **shall render at least one hex
    row of content**"* → **28**.

  The author picked the weaker of the two without surfacing that the spec
  contains both. Engineering rule 7 (*surface conflicts, don't average them*) and
  the batch's own **BL-3** — which caught this exact "green with the result area
  still at zero" shape once already — both point at `LLR-125.2`'s metric.

- **Why it blocks rather than carries.** The packet's own R-1 reasoning is that
  **Inc-10's file set does not include `screens_directionb.py`, so the constant
  cannot be changed later.** This is decided at Inc-5 or it ships.

- **Where:** `s19_app/tui/screens_directionb.py:6585-6600` (`_DIFF_MIN_H` and its
  docstring) · `:7451-7452` (the header that occupies line 0) ·
  `01-requirements.md` §4 `LLR-124.1` and §2.8 D-1.

- **Compounding — there is no acceptance node at the height floor at all.**
  `TC-B78-31` does the **width** floor on both sides *and* asserts the
  consequence: *"`_DIFF_MIN_W` is only the right floor if the window is unwrapped
  AT it."* Nothing does the same for `_DIFF_MIN_H` — **the axis whose value this
  increment changed.** `TC-B78-32`'s height arm sits at `_DIFF_MIN_H - 1` and
  asserts only that the notice appears. Applying `TC-B78-31`'s own standard to
  the height axis is what surfaces this, and it would have failed.

- **Suggested fix.** Re-derive against `LLR-125.2`'s metric and add the missing
  boundary node. Measured post-Inc-10, **28 is the width-independent floor for
  ≥ 1 visible hex row** (27 → 0 and 28 → 1 at `W = 94`, `120` and `138` alike):

  ```python
  #: `_DIFF_MIN_H` — the first terminal height at which a window paints at least
  #: one HEX ROW. Screen line 0 of each window is the `Image A — Run #…` header,
  #: so a painted content height of 1 delivers ZERO bytes; the floor is the first
  #: height at which painted content height reaches 2. Re-derived post-Inc-10,
  #: fallback forced: 27 -> 0 hex rows, 28 -> 1, 30 -> 2. Width-independent at
  #: W = 94, 120, 138. This is `LLR-125.2`'s metric ("at least one hex row of
  #: content"), not D-1's weaker "one visible content row", which counts the
  #: header — see F-1 at the Inc-5 gate.
  _DIFF_MIN_H = 28
  ```

  plus a height-floor node mirroring `TC-B78-31`'s form:

  ```python
  def test_tc_b78_XX_the_height_floor_delivers_a_hex_row(tmp_path: Path) -> None:
      """The height floor is only the right floor if a HEX ROW is visible AT it.

      The sibling clause for `_DIFF_MIN_H` that `TC-B78-31` carries for
      `_DIFF_MIN_W`. Counting painted CONTENT rows is one row too weak: line 0
      of each window is the header, so `painted >= 1` is green with zero bytes
      on screen -- the state HLR-124's notice regime exists to replace.
      """
      at = _b78_regime_probe(tmp_path, (120, _DIFF_MIN_H), prepare=_hide_command_bar)
      below = _b78_regime_probe(tmp_path, (120, _DIFF_MIN_H - 1))
      assert not at["notice_shown"]
      assert at["hex_a_painted"] >= 2, (
          f"at exactly _DIFF_MIN_H the window must paint the header AND at "
          f"least one hex row; painted {at['hex_a_painted']}"
      )
      assert below["notice_shown"]
      assert "height" in below["notice_text"]
  ```

- **⚠️ Knock-on that must be re-verified, not assumed.** Raising the floor to 28
  puts `_B78_INC4_SHORT = (132, 26)` back in the **notice** regime, breaking
  `AT-B78-22`'s subject a second time. It will need to move again — **132×28 is
  the candidate and I measured it**: with the bar present and the fallback forced,
  `132×28` gives `capacity = 0` and `#diff_hex_a.size.height = 0`, so
  `AT-B78-22`'s `content_h == 0` precondition still holds (`132×26 → 0/0`,
  `132×28 → 0/0`, `132×29 → 0/1`). **Inc-4's `M2` must nonetheless be
  re-executed against the new size** — I have shown above that this check is
  cheap and re-runnable, so do not discharge it by reasoning a second time.

- **Alternative disposition, if the operator rules the header sufficient:** then
  D-1's height axis and `LLR-125.2` must be reconciled *in writing* and the
  26–27 dead zone recorded as an accepted state in the spec, not only in a
  packet risk row. What is not acceptable is leaving the two metrics
  contradicting each other with the weaker one silently shipped.

---

### F-2 — the WIDE regime has capacity 1 and pagination is disabled: 65 of 66 rows unreachable at the widest supported terminal  ·  **[Severity: MEDIUM]**

- **What:** `check_action` gates `page_window_down` / `page_window_up` on
  `_REGIME_FALLBACK`, so `[` and `]` are inactive above `_DIFF_WIDE_MIN`.
  Executed on a 0x400-byte run:

  ```
  (160, 40)  diff-wide      capacity=1  emitted_rows=66  check_action(page)=False  ']' moved: False
  (139, 40)  diff-wide      capacity=1  emitted_rows=66  check_action(page)=False  ']' moved: False
  (132, 44)  diff-fallback  capacity=7  emitted_rows=66  check_action(page)=True   ']' moved: True
  ```

  The operator on the **widest** supported terminal sees 1 of 66 rows and has no
  key to reach the rest; the operator on a **narrower** one reaches all of them.
  Inc-4's `R-6` ("runs longer than the pane overflow invisibly") is closed for
  the fallback regime and left open for the wide one, and the packet does not say so.

- **Where:** `s19_app/tui/screens_directionb.py:6970-6974` (`check_action`).

- **Why it matters:** it is a capability **inversion** — more terminal, less
  reach. HLR-124 scopes the pagination *clause* to the fallback branch, so this
  is spec-conformant; but nothing in the spec asks for pagination to be
  *removed* in the wide regime. The gate is an added restriction with no benefit,
  and removing it deletes a condition rather than adding one.

- **Suggested fix** (one line, and it makes the method simpler):

  ```python
  if action in ("page_window_down", "page_window_up"):
      # Overflow is a property of the run vs the pane, not of the regime; the
      # wide regime's capacity is 1 at 160x40 (measured), so gating these to
      # the fallback strands 65 of 66 rows on the widest supported terminal.
      return not self.has_class(self._REGIME_NOTICE)
  if action == "toggle_run_overlay":
      return self.has_class(self._REGIME_FALLBACK)
  ```

  `TC-B78-52`'s existing clauses then extend to the wide regime with a second
  arm at 160×40. If the coordinator prefers to hold the spec's literal scope,
  record the wide-regime overflow as an explicit open carry — it is currently
  invisible.

---

### F-3 — `AT-B78-23`'s "painted ≥ 1" co-assertion counts the header, and passes today only incidentally  ·  **[Severity: MEDIUM]**

- **What:** `test_at_b78_23_no_wrapped_row_in_the_wide_regime` asserts
  `measured["hex_a_painted"] >= 1` with the message *"an unwrapped window that
  paints no content row delivers nothing"*. Because line 0 is the header, that
  predicate is **green at zero bytes**. It passes today only because 160×40
  happens to paint 2 (header + 1 hex row) — a margin of exactly one row, not a
  property the assertion pins.

- **Where:** `tests/test_tui_diff_screen.py:2857-2860`.

- **Why it matters:** this is the same shape as F-1 and the same shape as the
  batch's own **BL-3** (*"`AT-B78-26`'s row-height clause is green with the
  result area still at zero"*). The node's own docstring names the M3 trap
  correctly — *"a window can be 'unwrapped' while painting nothing at all"* — and
  then closes it with a metric one row too weak to do so.

- **Suggested fix:** raise the threshold and say what the extra row is.

  ```python
  assert measured["hex_a_painted"] >= 2, (
      f"an unwrapped window that paints no HEX ROW delivers nothing: line 0 is "
      f"the 'Image A - Run #...' header, so a painted content height of 1 is "
      f"zero bytes on screen. Painted height is {measured['hex_a_painted']}"
  )
  ```

  Same correction applies wherever the batch reads painted content height as a
  delivery predicate; `LLR-125.2` already words the intent correctly and
  `AT-B78-26` at Inc-10 should inherit the `>= 2` form, not the `>= 1` one.

---

### F-4 — `AT-B78-15`/`-16`/`-17` now fail on the driver's guard, not on their own subject  ·  **[Severity: LOW]**

- **What:** with the overlay broken, all three redden with *"the run-list overlay
  must open on 'f'"* — the driver's message, not the node's. A reader triaging a
  future red `AT-B78-17` sees an overlay complaint rather than a selection one.
- **Where:** `tests/test_tui_diff_screen.py:245-274` (`_b78_open_run_list`), called
  from `_b78_drive_compare:295`.
- **Why it matters:** this is the acknowledged `C-78-xiii` trade and it is the
  right call — the alternative is two nodes passing over an invisible list. It is
  still an assertion, not an error, which satisfies *a counterfactual must fail
  on its ASSERTION*. Recorded so the diagnostic distance is known, not to be
  changed.
- **Suggested fix:** none required. Optionally name the affected nodes in the
  guard message so a future triage lands in the right place first time.

---

### F-5 — a regime change on resize does not re-derive the window's row count  ·  **[Severity: LOW]**

- **What:** `on_resize` → `apply_regime` toggles the CSS class, but
  `_render_run_windows` is not re-called, so `capacity` changes underneath a
  window whose row list was computed for the old pane. Executed: 139×40 →
  138×40 moves capacity `1 → 5` while the rendered window is unchanged.
- **Where:** `s19_app/tui/app.py:6303-6307` · `screens_directionb.py:6862-6893`.
- **Why it matters:** inherited from Inc-4 (the pane-derived count is a
  render-time read) and not introduced here, but regime switching makes it
  reachable in a new way. `TC-B78-30` is honest — it asserts only that the
  windows do not blank — so nothing is falsely claimed. A short run simply stays
  smaller than the pane could show until the next selection.
- **Suggested fix:** if cheap, have `apply_regime` re-render when the regime
  actually changes and a comparison exists:
  ```python
  if regime != previous and self._has_result:
      self._render_run_windows(self._selected_run)
  ```
  Otherwise carry it explicitly — it is currently unstated.

---

### F-6 — the `LLR-119.3` correction removes the palette constraint without saying whether `palette_input` is in LLR-119.1's scope  ·  **[Severity: LOW]**

- **What:** the correction is accurate about the false premise and correctly
  refuses to pre-decide Inc-9. But `LLR-119.3` governs *"the six local inputs of
  LLR-119.1"*, and `#palette_input` **is** an `Input` that holds focus on
  `ctrl+k` (executed). Whether Inc-9's new `escape`-off-input handler is meant to
  cover it is now unstated in either direction.
- **Where:** `01-requirements.md` §4, `LLR-119.3`'s replaced `C-16` note.
- **Suggested fix:** add one clause to the correction — *"`#palette_input` is
  outside `LLR-119.1`'s six; Inc-9 must state whether its handler reaches it"* —
  or confirm it is in the six. A dropped constraint should leave a question, not
  a silence.

---

### F-7 — the "unpiped transcript" claim is not verifiable from committed artifacts  ·  **[Severity: LOW / informational]**

- **What:** the packet's `C-78-xx` self-report (first run piped through `tail`,
  eight arms' transcripts discarded, shipped transcript is the second unpiped
  run) is creditable and I have no reason to doubt it — but `mutate_inc5.py`
  lives in the author's scratchpad and is not committed, so **there is no artifact
  against which to check it.** The transcript's internal consistency (nine
  complete arms, chained shas, `FINAL == baseline`) is consistent with an unpiped
  run and I reproduced three of the nine arms independently with matching
  verdicts. That is corroboration, not confirmation.
- **Suggested fix:** none for this increment. `C-78-xx`'s standing fix (move the
  gate into the RC-1 pre-commit hook) remains the right owner, and it is
  correctly listed as unowned process work.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Diff read in full | ✓ | `b12b205..9015b7f`, all 6 files; `screens_directionb.py:6569-7444`, `app.py:6281-6310`, `styles.tcss:1523-1636`, `tests/test_tui_diff_screen.py:245-2698+` |
| Correctness pass (edge / None / error paths) | ✓ | Page clamp verified sound: growth (`capacity > rows`) and paging are mutually exclusive, so `(rows-1)//capacity` is 0 exactly when it should be; `]` past the end self-corrects (write-back); `[` floors at 0; `capacity == 0` skips the branch. **F-1**, **F-2**, **F-5** |
| Simplicity pass (no premature abstraction) | ✓ | No speculative generality found. `_apply_diff_regime` is one statement and correctly keeps the arithmetic in the panel; the regime constants are named, not inlined; `check_action` is the framework's own hook, not a bespoke gate. **The one simplification available REMOVES a condition** — F-2 |
| Reuse / duplication checked | ✓ | No fifth driver copy: `_b78_open_run_list` is a step inside the existing `_b78_drive_compare`, 4 lines. Inc-1's `_b78_painted_content_height` reused unchanged (`C-78-vi`). `width-narrow` correctly NOT overloaded (11 rules across workspace/map/patch/rail). `F9`'s pre-existing duplication unchanged — none added |
| Convention conformance | ✓ | Full docstring sections on every new public method; `#:` comments on every new constant and field; `_apply_diff_regime` matches the `_apply_width_regime` precedent including its unguarded `query_one`; all styling id/class-scoped in `styles.tcss`, no `DEFAULT_CSS`; no `_nodes`/`_context` shadowing |
| Tests reviewed for intent, not behaviour | ✓ | Every node's docstring states WHY. Preconditions are asserted, not assumed (`TC-B78-52`'s overflow precondition, `TC-B78-51`'s focus precondition, `AT-B78-29`'s both-axes precondition). `TC-B78-53` is an **equality**, not a threshold — correctly rejecting an implementation that shrinks the window while the overlay is up. Both quantities in `AT-B78-23` are measured, neither literal. **The gaps are F-1's missing height-floor node and F-3's one-row-weak metric** |
| Independent re-execution of the packet's figures | ✓ | Regime table (8 sizes), `_DIFF_MIN_H` sweep (2 states × 3 widths × 11 heights), `A-2` premise, snapshot census, collection census, C-39 literals — all reproduced by my own scripts |
| Counterfactuals re-executed independently | ✓ | 4 arms in a detached worktree, applied-checked, sha-chained, `FINAL == baseline`, worktree removed |
| No unapproved / destructive commands; parallel session untouched | ✓ | No `git add -A`, no `git stash`, no `git reset`, no regen. `prototypes/memmap2.*` never opened. Tracked tree verified clean after every run |
| Verdict explicit | ✓ | below |

---

## Verdict

- [ ] OK to advance
- [ ] OK with the listed fixes applied first
- [x] **Block — must fix the HIGH finding before advancing**

**Blocking:** **F-1**. `_DIFF_MIN_H = 26` ships two terminal heights (26–27,
post-Inc-10) that pass the deliverability condition and paint zero hex rows,
resolving a live conflict between D-1's height metric and `LLR-125.2`'s in favour
of the weaker one, without surfacing that the conflict exists — and the height
axis is the only regime axis with no boundary acceptance node. **28 is the
measured value under `LLR-125.2`'s metric, width-independent.** Because Inc-10's
file set excludes `screens_directionb.py`, this cannot be deferred.

**Recommended before merge (non-blocking):** F-2 (one line, and it simplifies
`check_action`) and F-3 (`>= 2`, plus inherit the corrected form into
`AT-B78-26` at Inc-10). F-4 through F-7 are recordings.

**Explicitly clean, and said so rather than padded:** the regime table, the
`_DIFF_MIN_H` re-derivation *method*, the `29`-with-the-bar explanation, `A-2`'s
false-premise finding and the coordinator's correction of it, the Inc-2 AT
re-arming, `M3`, `M9`'s INERT/PIN honesty, the stacking analysis and the
chrome-drop decision, the restore proof, the file cap, C-17, C-26, C-39, SEC-F2,
the snapshot bound, and the ledger census. **And the gap the author flagged
without closing — Inc-4's `M2` against the moved fixture — I executed, and it
still reddens `AT-B78-22` on its own address assertion. That discharge has not
lapsed.**

**Handoffs:** `security-reviewer` — nothing to escalate; the one new sink
(`#diff_size_notice`) is bounded at construction and at composition, and
`AT-B78-29` asserts it rather than assuming it. `qa-reviewer` — F-1's missing
height-floor node and F-2's wide-regime reachability gap are coverage items in
your lane once the fix lands.
