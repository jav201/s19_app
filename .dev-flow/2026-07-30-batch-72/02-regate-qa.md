# Phase-2 RE-GATE — qa-reviewer — batch 2026-07-30-batch-72

> Reviewer: `qa-reviewer` · Artifact: `01-requirements.md` **revision 2** · Tree:
> `claude/batch-72-design-defect-634a67` @ `0a56ef6` · Scope: **discharge review of the acceptance
> layer only**. Every ruling below cites executed command output or `file:line`. Nothing is labelled
> `UNVERIFIED` in this pass — every claim I make was run.

## BLUF

**Verdict: `approve`.** All five of my Phase-2 blockers are **CLOSED**, verified by re-reading and
re-execution rather than by trusting the fold. The acceptance layer is now falsifiable end-to-end:
seven ATs, seven live HLRs, a bijection, and every AT has a named mutation that reddens it.

**My own rejected proposal, recorded.** I proposed re-scoping G-1 to same-widget-class adjacency and
asserted it "has exactly one violating pair today". `00-measurements.md` M-1 executed it: **7 pre,
6 post** — unsatisfiable. My own Q-1 transcript listed the counter-evidence
(`crc_field_width`→`crc_field_poly`, `crc_field_poly`→`crc_field_init`,
`crc_field_name`→`crc_field_aliases`, `crc_field_xorout`→`crc_field_check`,
`crc_coverage_intra_gap`→`crc_coverage_join`) and I hedged instead of counting. The `Switch`-only
rule adopted at revision 2 is the correct one and I re-verified its two numbers below. I do not
re-litigate it.

**Three majors survive, all on predicates the fold itself wrote** — which is where I was told to look
hardest, and it is where they are:

| # | Finding | Where |
|---|---|---|
| **N-1** | AT-216 clause 1's comparison **relation** is unstated, and equality is FALSE. Executed: `row_text == meaning` → `False`; `meaning in row_text` → `True` | AT-216 |
| **N-2** | AT-214's counterfactual names `_switch_row` — a helper **LLR-072-1.2 deletes**. Executed literally it is a `NameError` at compose time, i.e. an error, not an assertion | AT-214 / §5.3.1 |
| **N-3** | AT-219's substantive clause is **already TRUE on the shipped tree** (all six sinks are `markup=False` today), and `len(tuple) >= 6` does **not** couple the tuple to `_recompute` | AT-219 |

Each is a one-to-three-line authoring correction, not a redesign. N-1 and N-2 fail loudly if
uncorrected; **N-3 is the one that can pass silently**, and it is the strengthening I want folded
before Phase 3 authoring.

---

## Q1 — Discharge of Q-1 … Q-12

### Q-1 — AT-214 unauthorable · **CLOSED** (not by my fix)

Revision 2 §3 HLR-072-3: *"**No two `Switch` widgets shall render vertically abutting**"*, with the
scope paragraph stating openly: *"A same-widget-class rule was then proposed and also **rejected on
measurement** (7 pre → 6 post)."*

Re-verified, not trusted:

```
$ grep -rn "Switch(" s19_app/ | grep -v "\.pyc"
s19_app/tui/crc_designer_view.py:467:            Switch(value=value, id=field_id, classes="crc-field-switch"),
```

**One construction site in the entire package.** M-1's executed transcript: `app.query(Switch) -> 2`;
`=== (c) SWITCH-SWITCH abutting pairs: 1 ===` (`c01` = refin@y=32 → refout@y=33). The subject-set
completeness argument in §3 ("complete by construction — a future third `Switch` enters the guarded
set automatically") is therefore **true as stated**, and it is what converts this from
special-pleading into a general guard. CLOSED.

### Q-2 — counterfactual wrong-reason failure modes · **PARTIALLY CLOSED**

Revision 2 AT-214 clause 4: *"revert **`compose`'s pair row to the two `_switch_row` calls**"* …
*"keep the AT's queried ids resolvable in both trees, and paste the transcript showing an `assert`
failure plus the restore hash."*

- **Failure mode 2 (CSS may not own the observable) — CLOSED.** The artifact now names `compose`,
  not the CSS, and states the reason (*"the fusion is partly a *compose* fact"*).
- **Failure mode 1 (errors instead of asserting) — CLOSED on the query axis.** AT-214 is **id-free**:
  clause 1 derives via `app.query(Switch)` (a type query, which returns an empty `DOMQuery` rather
  than raising) and clause 3 is a pure geometry relation. No `#id` appears in the AT. Both trees
  resolve. M-1 already executed the old-tree side and it produces `2` Switches with `1` abutting
  pair → clause 3 evaluates to `False` → **assertion failure, not error**. The C-40 discharge is
  demonstrable today from M-1 alone.
- **NOT closed — see N-2 below.** The instruction quotes a helper the batch removes.

### Q-3 — AT-217 reachable-under-scroll · **CLOSED**

HLR-072-6 now says *"the full key **reachable under scroll**"*, and AT-217 clause 3 is
*"**reachable under scroll, NOT required visible:** `#legend_key_pane.max_scroll_y >= 1` and the last
key row scrolls into a non-empty on-screen region via `scroll_visible()`"* with the measured
rationale (*"the floor content budget is **9** rows and the key content is **10 (mac) / 11 (map)**"*).
`Widget.scroll_visible` exists on textual 8.2.8 (verified below). CLOSED.

### Q-4 — AT-216 matches the wrong pane · **CLOSED**

AT-216 clause 1 now anchors on *"the `{legend-row, sev-warning}` classes inside `#legend_key_pane`"*
and compares to `LEGEND_TABLE["MAC"]["Pale yellow"][1]`. Executed over the real
`LegendScreen(sections=("MAC",), view_key="mac")`:

```
rows matching {legend-row, sev-warning} in the mac KEY set:  1   (idx 2)
card widgets with {legend-row, sev-warning}:                 0
card widgets containing the literal 'Pale yellow':           1   (idx 12, classes ['legend-card-sub'])
card widgets containing the MEANING string:                  0
```

**Both anchors independently disambiguate the panes.** The class anchor excludes the card (0 hits);
the meaning-string anchor also excludes it (the card caption is *"Orange vs Pale yellow — two paint
pipelines, one severity"*, which contains the literal but not the meaning). The card-caption
false-match I raised is gone. CLOSED — with the relation caveat at N-1.

### Q-5 — visibility clause invisible to the harness · **CLOSED**

AT-216 clause 2 is now *"**region containment, not rendered text**: `#legend_key_pane.region
.contains_region(row.region)` with `scroll_offset == (0, 0)` asserted"*, clause 3 adds the cause-level
`max_scroll_y == 0`, clause 4 adds the `display: none` oracle mutation.

API existence verified on the target framework (this is the C-42 hazard my Q-5 flagged):

```
Region.contains_region : True      Widget.scroll_offset  : True
Region.overlaps        : True      Widget.scroll_visible : True
Widget.max_scroll_y    : True      Widget.visible_region : False   <- correctly NOT used
Region(0,0,10,10).contains_region(Region(1,1,2,2)) -> True ; (Region(9,9,5,5)) -> False
```

And the oracle is falsifiable in **both** directions with already-executed evidence:
post-fix M-2 gives `key_pane=Region(70,6,43,15)` containing `Pale yellow=Region(70,11,43,3)` → TRUE;
shipped tree gives `row=Region(22,27,...)` outside `body=Region(22,6,76,15)` → FALSE. CLOSED.

### Q-6 — AT-213 names no value · **CLOSED**

AT-213 clause 3: *"`#crc_field_refin` is seeded **`True`** … drive it to **`False`** … assert
`#crc_custom_vector_result` transitions **`0xCBF43926` → `0x1898913F`**"*. Executed:

```
seed CRC-32/ISO-HDLC refin True refout True check 0xcbf43926
default vector result : 0xCBF43926
refin=False result    : 0x1898913F
```

Format also verified: `_format_hex` (`crc_designer_view.py:172-178`) emits `0x` + **uppercase** hex,
so the two literals are byte-exact as written. CLOSED.

### Q-7 — AT-215 near-misses · **CLOSED**

AT-215 clause 3 names `0x00000000` and excludes both near-misses verbatim (*"clearing the field
yields `○ NO-EXPECTED` … a non-hex keystroke yields `"Invalid parameters: …"`; neither satisfies this
clause"*). Executed:

```
_VERDICT_TOKENS {True: ('✓ MATCH', ...), False: ('✗ MISMATCH', ...), None: ('○ NO-EXPECTED', ...)}
check=0 verdict token ('✗ MISMATCH', '#fd8383')
```

CLOSED.

### Q-8 — HLR-072-4 has no AT node · **WITHDRAWN-BY-THE-BATCH**

HLR-072-4 is struck (§3, §6.5 W-1) on M-4's measurement: `height: 3` renders `CRC-32/ISO-HDLC` as
`CRC-32/I` with no ellipsis. The C-18 violation is dissolved rather than fixed, and `AT-219` is
reallocated to the new HLR-072-8. **My proposed fix would have shipped a control that lies about its
value** — the withdrawal is the better outcome and I record it as such.

### Q-9 — stale ledger base · **CLOSED**

§5.3.7: *"base = 2379 (measured 2026-07-30 @ `b556e35`)"*. Re-executed now at `0a56ef6`:

```
$ python -m pytest --collect-only -q | tail -3
2379 tests collected in 0.79s
```

Unchanged across the fold commit. CLOSED.

### Q-10 — ID census · **CLOSED / re-confirmed** — see Q3(d)

### Q-11 — C-27 frozen test files · **CLOSED** (no change required; still true)

### Q-12 — zero-area `SelectOverlay` phantoms · **CLOSED**

§1.3 now *binds* the term: *"**focusable control** | `widget.focusable and widget.region.area > 0`
… The area filter is not cosmetic: six zero-area `SelectOverlay` phantoms exist (M-1)"*, and AT-214
clause 1 carries the `region.area > 0` filter. CLOSED.

### Also closed from my evidence checklist

| Item | Ruling |
|---|---|
| #9 — four `_recompute` ids observed by no AT | **CLOSED** by HLR-072-8 / AT-219; all six now in one census |
| #10 — TC ids assigned as a *range* with no semantics | **CLOSED**; §5.2 assigns 10 distinct stated observables (checked one-by-one at Q3b) |
| AT-218 must read `render().spans`, not `render_line(0)` | **CLOSED**; AT-218 clause 1 says so, and it is executable: `render().spans` → `[Span(0, 81, style='orange3')]` |
| AT-218 is a pin, not a gate | **CLOSED**; labelled in §3 verbatim |

**Score: 12 of 12 dispositioned — 10 CLOSED, 1 PARTIALLY CLOSED (Q-2 → N-2), 1 WITHDRAWN-BY-THE-BATCH.**

---

## Q2 — C-40 falsifiability table over the NEW AT set

| AT | Declared subject | Subject in the predicate's expression? | Exact mutation that reddens it | Verdict |
|---|---|---|---|---|
| **AT-213** | refin/refout share one row band; toggling refin moves the CRC | ✅ yes — clause 1 names both switch ids; clause 3 names `#crc_custom_vector_result` and the exact two values | `crc_designer_view.py` — restore the two `self._switch_row("Reflect in"/"Reflect out", …)` calls at `:301-302` → `y=32` vs `y=33` → clause 1 `==` FALSE. Independently: drop `refin=` from `_current_algorithm` (`:651`) → clause 3 frozen at `0xCBF43926` | **SOUND** |
| **AT-214** | no two `Switch` widgets abut vertically | ✅ yes — the set is `app.query(Switch)`; the relation is §1.3's abutment predicate over exactly that set | `crc_designer_view.py:301-302` — restore the two `_switch_row` calls (**and the helper, see N-2**) → M-1 measured that tree at 1 abutting `Switch` pair → clause 3 FALSE **on the assert**, not on a query | **SOUND** — with N-2 folded into the counterfactual wording |
| **AT-215** | `#crc_kat_verdict` under `#crc_algorithm_fields`; verdict flips through the real `Input.Changed` path; `#crc_live_verify` gone | ✅ yes — ancestor id, verdict id, and the discriminating negative all named | `crc_designer_view.py` — leave the verdict inside the `#crc_live_verify` wrapper → clause 1 ancestor walk FALSE **and** clause 4 non-empty. Independently: break `on_input_changed` (`:593-603`) → clause 3 stays `✓ MATCH` | **SOUND** — the only AT in the set carrying a discriminating negative |
| **AT-216** | the `{legend-row, sev-warning}` key row is region-contained by `#legend_key_pane` at `scroll_offset 0`, and the pane does not scroll | ✅ yes — clause 2 names the containing pane and the row; clause 3 names the cause | `styles.tcss` — remove `#legend_key_pane { width: 2fr }` (or set `display: none`, the artifact's own clause 4) → containment FALSE. Shipped tree already gives `row=Region(22,27,…)` vs `body=Region(22,6,76,15)` → FALSE | **SOUND** — with N-1 (state `in`, not `==`) |
| **AT-217** | key precedes card at 80x24, card not starved, key reachable under scroll | ✅ yes — clause 2 is the non-vacuity tooth and clause 3 the reachability tooth | `styles.tcss` LLR-072-6.2 — swap `#legend_key_pane { height: 1fr }` for `height: auto` → M-3 measured `card_h=1` → clause 2 (`>= 2`) FALSE **and** `key_scrolls=False(max=0)` → clause 3 (`>= 1`) FALSE. Drop `legend-narrow` entirely → clause 1 FALSE | **SOUND** — strongest AT in the set; **two independent teeth** |
| **AT-218** | the *unchanged* legend data pipeline | ⚠️ partial by design — its subject is invariant under this batch | `screens.py:1117` — drop the `_MAC_WARNING_SAMPLE_STYLE` wrapper → `render().spans` empty → clause 1 FALSE | **PIN-NOT-A-GATE** — and the artifact **says so** in §3, which is the correct disposition |
| **AT-219** | the six `_recompute` sinks all render `markup=False`, read from a live module-level tuple | ⚠️ **the flag clause is invariant under this batch's change** — all six are already `markup=False` (executed below) | `crc_designer_view.py:353` — drop `markup=False` from `#crc_custom_vector_result` → assertion FALSE. `len >= 6` reddens only on a truncated tuple | **PIN-NOT-A-GATE, unlabelled** — see N-3 |

**ATs whose value is invariant under the change they gate: AT-218 (labelled, correct) and AT-219
(unlabelled, N-3).** Every other AT has a concrete, named, single-file mutation that reddens it.

### N-1 — AT-216 clause 1: the comparison relation is unstated, and equality is FALSE · **major**

AT-216 clause 1 says *"compare its text to `LEGEND_TABLE["MAC"]["Pale yellow"][1]`"*. The index is
**correct** — I checked for the C-36 phantom the brief asked about and it is not one:

```
LEGEND_TABLE['MAC']['Pale yellow'] : tuple len 2
  [0] 'Pale yellow'
  [1] 'warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity'
```

But the row is built as `f"{classification} — {meaning}"` (`s19_app/tui/screens.py:1191`), so:

```
row text        : 'Pale yellow — warning: symbol only in MAC (not A2L), duplicate-address alias, or overlap ambiguity'
text == meaning : False
meaning in text : True
```

An implementer reading "compare its text to X" and writing `==` gets a **RED on a correct
implementation** — the exact false-fail shape C-36 exists to prevent, arriving through the relation
rather than the index. The in-file precedent the artifact leans on is containment
(`tests/test_legend_n8.py:356`: `assert L.LEGEND_TABLE["MAC"]["Pale yellow"][1] in text`).

**Fix (one clause):** *"…assert `LEGEND_TABLE["MAC"]["Pale yellow"][1] in row.render().plain`
(containment — the row prefixes the classification name), matching
`tests/test_legend_n8.py:356`."* Naming `render().plain` also forecloses a wrapped-screen-text
accessor: at 43 cols the row wraps to 3 lines (M-2), so any line-oriented harness breaks containment.

### N-2 — AT-214's counterfactual names a helper this batch deletes · **major**

AT-214 clause 4 says: *"revert **`compose`'s pair row to the two `_switch_row` calls** on a private
copy"*. But LLR-072-1.2 says: *"`_switch_row` (`:453-469`) becomes orphaned; **delete it**."*

On the fixed tree the helper does not exist, so the literal instruction produces an
`AttributeError`/`NameError` inside `compose` → the pilot dies during mount → **the counterfactual
errors instead of asserting**, which is exactly the failure the project's own rule forbids
(`feedback_counterfactual_must_fail_on_its_assertion`). Since §5.3.1 makes the transcript a batch
acceptance criterion, an un-executable instruction there means the C-40 discharge ships undischarged.

**Fix (one sentence):** *"On the private copy, restore `crc_designer_view.py` wholesale from
`origin/main` (`git -C <copy> checkout origin/main -- s19_app/tui/crc_designer_view.py`), which
restores both `_switch_row` and its two call sites. This is safe for AT-214 specifically because
AT-214 references **no `#id`** — its subject set is `app.query(Switch)`, a type query that resolves
in both trees."* M-1 already proves the old-tree side yields `2` Switches and `1` abutting pair, so
the failure lands on clause 3's `assert`.

### N-3 — AT-219: the census is a pin, and `len >= 6` does not couple the tuple to `_recompute` · **major**

Two executed facts.

**(a) The flag clause is already TRUE on the shipped tree.** All six sinks carry `markup=False`
today:

```
crc_designer_view.py:341  Static("", id="crc_coverage_preview",     markup=False, …)
crc_designer_view.py:353  Static("", id="crc_custom_vector_result", markup=False, …)
crc_designer_view.py:367  Static("", id="crc_json_preview",         markup=False, …)
crc_designer_view.py:397  Static("", id="crc_kat_verdict",          markup=False, …)
crc_designer_view.py:403  Static("", id="crc_warnings",             markup=False, …)
crc_designer_view.py:411  Static("", id="crc_coverage_window",      markup=False)
```

§2.4's claim that *"4 of the 6 CRC sinks were pinned by a test and 2 were not"* is **exactly right** —
verified: `_render_markup` assertions exist for `#crc_kat_verdict` (`tests/test_crc_designer_view.py:347,355`),
`#crc_json_preview` (`:486,494`), `#crc_warnings` (`:605,613`), `#crc_coverage_window` (`:1084,1112,1169,1196`);
none for `#crc_custom_vector_result` or `#crc_coverage_preview`. So AT-219 closes a real *coverage*
gap. But it is a **regression pin**, not a gate: its assertion does not distinguish pre- from
post-batch. AT-218 is labelled *"REGRESSION PIN, not a gate"*; AT-219 is not, and it should be — for
the same reason and by the same C-40 corollary. (This is not an argument to drop it: US-072-3 is
explicitly a guard story. It is an argument to label it, so nobody at Phase 4 reads its green as
evidence the batch worked.)

**(b) `len(tuple) >= 6` admits a tuple of six wrong ids — and worse, a *decoupled* tuple.** The
brief's question, answered directly: **yes, the guard is too weak.** The failure that matters is not
six arbitrary ids; it is a tuple that is hoisted, asserted, and then **ignored by `_recompute`**,
which keeps its six hardcoded `query_one` calls at `:1115-1121`. AT-219 passes, `len >= 6` passes,
every flag passes — and the tuple has become decorative. A seventh sink added later to `_recompute`
would then be covered by nothing, which is the precise scenario the AT's own rationale
(*"a seventh surface added later is covered automatically"*) claims to prevent.

**Fix — add a coupling tooth (executable in the same pilot):**

> *"…and prove `_recompute` **consumes** the tuple: monkeypatch the module-level tuple to append one
> non-existent id, drive one `Input.Changed`, and assert `_recompute` takes its `NoMatches` early
> return (`crc_designer_view.py:1122-1124`) — i.e. the six live sinks do **not** update. Restore the
> tuple. This fails if `_recompute` kept hardcoded queries, and it is the only clause in AT-219 that
> is FALSE before the hoist."*

That single clause converts AT-219 from a pin into a pin **plus** a genuine gate on the one thing
HLR-072-8 actually changes, and it discharges C-40 limb 1 for the new story.

---

## Q3 — Coverage sweep

### (a) One owning AT node per HLR (C-18) — ✅ **clean, bijective**

| HLR | AT | HLR | AT |
|---|---|---|---|
| HLR-072-1 | AT-213 | HLR-072-5 | AT-216 |
| HLR-072-2 | AT-215 | HLR-072-6 | AT-217 |
| HLR-072-3 | AT-214 | HLR-072-7 | AT-218 |
| HLR-072-4 | *withdrawn* | HLR-072-8 | AT-219 |

**7 live HLRs, 7 ATs, no HLR sharing a node, no AT carrying two subjects.** Revision 1's
*"TC-level + a pilot height assertion inside AT-213's run"* is gone, and §5.2 says so explicitly.
The C-18 finding that drove Q-8 is closed structurally, not by patch.

### (b) Every LLR has a TC, each with a distinct stated observable — ⚠️ **9 of 11, 2 unexplained**

| TC | Observable as stated in §5.2 | Distinct? |
|---|---|---|
| TC-510 | pair-row structure | ✅ |
| TC-511 | `_switch_row` orphan removal | ✅ |
| TC-512 | `#crc_top_right` single child | ✅ |
| TC-513 | `.crc-hero` selector absent | ✅ |
| TC-514 | derived `Switch` set non-empty ≥ 2 | ⚠️ **verbatim restatement of AT-214 clause 2** — zero marginal information (minor) |
| TC-515 | pane ids + widget counts vs M-6 | ✅ |
| TC-516 | `#legend_body` is the wrapper; 9 sites non-empty | ✅ |
| TC-517 | `legend-narrow` flips at the 120 breakpoint | ✅ — and it is load-bearing: §LLR-072-6.1 states why AT-217's geometry alone cannot distinguish "stacked because the rule fired" from "stacked because the panes collapsed" |
| TC-518 | no `height: auto` on the key pane | ✅ |
| TC-519 | `legend.py` diff vs `origin/main` empty | ✅ |

**No TC is assigned as a range.** My checklist-#10 finding is closed.

**Gap (minor):** **LLR-072-2.1** (re-parent `#crc_kat_verdict`) and **LLR-072-2.4** (delete
AT-B59-05) have **no TC and no stated reason**. Both are defensible — 2.1 is fully covered by
AT-215 clauses 1/2/4, and 2.4 is discharged by the ledger `D = 1` — but the artifact already
demonstrates the right pattern at LLR-072-8.1, where the TC column reads
*"— *(AT-219 is itself the live-oracle census)*"*. Apply that pattern to 2.1 and 2.4.

### (c) C-26 reverse-grep over the newly touched symbols — executed

```
$ for s in <symbol>; do grep -rl -- "$s" tests/ --include="*.py"; done
legend_card_pane          -> <NONE>
legend_key_pane           -> <NONE>
legend-narrow             -> <NONE>
crc_top_right             -> tests/test_crc_designer_view.py
crc_kat_verdict           -> tests/test_crc_designer_view.py
crc_custom_vector_result  -> tests/test_crc_designer_view.py
crc_json_preview          -> tests/test_crc_designer_view.py
crc_warnings              -> tests/test_crc_designer_view.py
crc_coverage_preview      -> tests/test_crc_designer_view.py
crc_coverage_window       -> tests/test_crc_designer_view.py
crc_algorithm_fields      -> <NONE>
crc-field-switch          -> <NONE>
_switch_row               -> <NONE>
crc_live_verify           -> tests/test_crc_designer_view.py
legend_body               -> test_legend_n8.py, test_legend_scope_and_logwidth.py, test_tui_legend.py
```

- `legend_card_pane` / `legend_key_pane` / `legend-narrow` → **0 files**, as expected: they are new
  ids, so these are new obligations. Correctly reflected — §6.3 lists them alongside
  `crc_algorithm_fields`, `crc-field-switch`, `_switch_row` as *"new obligations, not preserved ones"*.
- **All six `_recompute` ids are grepped in one file** — so the CRC blast radius really is
  `tests/test_crc_designer_view.py` alone, confirming §5.3.3's list.
- `#legend_body` descendant query sites, counted exactly:
  `test_legend_n8.py:284,387` · `test_legend_scope_and_logwidth.py:34,88,89,121` ·
  `test_tui_legend.py:60,338,407` = **9**. HLR-072-7 clause 3's "all 9 descendant query sites" and
  P-12's "9" are **accurate**, not rounded.

### (d) ID census and the ledger base — executed at `0a56ef6`

```
$ grep -rhoE "AT-[0-9]+" REQUIREMENTS.md tests/ .dev-flow/ docs/ --exclude-dir=2026-07-30-batch-72 | sort -u -V | tail -3
AT-210 / AT-211 / AT-212
$ grep -rhoE "TC-[0-9]+" ... --exclude-dir=2026-07-30-batch-72 | sort -u -V | tail -3
TC-508 / TC-509 / TC-1728          (TC-1728 = the separate legacy series, not a collision)
$ grep -rhoE "R-TUI-[0-9]+" REQUIREMENTS.md | sort -u -V | tail -3
R-TUI-097 / R-TUI-098 / R-TUI-099
```

**AT-213..219 free · TC-510..519 free · R-TUI-100 free.** §5.2 and §6.5 A-8 both confirmed.

```
$ python -m pytest --collect-only -q | tail -3
2379 tests collected in 0.79s
```

**Ledger base 2379 confirmed at `0a56ef6`** (the artifact measured it at `b556e35`; the fold commit
did not move it).

**Is `D = 1` the complete deletion set? — ✅ YES.** Two checks:

1. `test_verdict_hero_center_aligned_in_hero_row` (`tests/test_crc_designer_view.py:1003-1047`) is a
   **single, non-parametrized** `def` taking only `tmp_path` — it collects as exactly one node. Its
   five asserts (`under_top_right`, `not under_bench`, `kat_descendant`,
   `content_align == ("center","middle")`, `crc_hero`) are each falsified by Variant B, so §6.5 A-1's
   *"deleted, never edited into passing"* is the right call.
2. **LLR-072-1.2's `_switch_row` removal drops no TC.** `grep -rl "_switch_row" tests/` → **0 files**.
   The helper is private and pinned by nothing, so its deletion removes no collected node.

`post = 2379 − 1 + A`. Correct as written.

---

## Q4 — Verdict

# `approve`

The acceptance layer clears all three axes:

| Axis | Ruling | Evidence |
|---|---|---|
| **Coverage** | ✅ clean | 7 HLRs ↔ 7 ATs, bijective (C-18). 9 of 11 LLRs carry a TC with a distinct stated observable; the 2 without are covered by a stronger black-box node and by the ledger — they need a stated reason (minor), not a new test. All four handoff guards G-1..G-4 dispositioned. Both the input dimensions (`refin`, `check`) and all six output sinks are now exercised through the handler |
| **Certainty** | ⚠️ three named majors | **N-1** AT-216's comparison relation · **N-2** AT-214's counterfactual names a deleted helper · **N-3** AT-219 is an unlabelled pin whose `len >= 6` does not couple the tuple to `_recompute`. Each is a 1–3 line authoring correction. N-1 and N-2 fail loudly; **N-3 is the only one that can pass silently** |
| **Evidence** | ✅ clean | Every threshold in revision 2 traces to an executed transcript in `00-measurements.md`. I re-ran the six that mattered — the `Switch` construction-site count, the `LEGEND_TABLE` index and relation, the six `markup=False` sinks, the `_render_markup`/`Region`/`scroll_visible` API surface on textual 8.2.8, the ID census, and the 2379 base — and all six reproduce |

**Why `approve` and not `iterate`:** zero blockers survive. Every AT has a named, single-file
mutation that reddens it, and the two ATs that are invariant under this batch's change are
identifiable as such (one already labelled, one flagged at N-3). N-1/N-2/N-3 are **binding
authoring corrections for Phase 3**, not gaps in the requirement's logic — the requirement says the
right thing in each case and under-specifies *how* to assert it.

If the orchestrator's process treats "a major on a brand-new AT" as iterate-worthy, **N-3 is the one
that justifies it** — it is the sole acceptance for a brand-new story, it was written by the fold,
and its one substantive clause is green before the batch starts.

**Do not re-open:** the G-1 `Switch`-only scope, the HLR-072-4 withdrawal, and the G-2 retirement are
settled by measurement and I have no executed counterexample to any of them.

---

## Evidence checklist

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then | ✗ | Project V-model AT/TC convention (`docs/engineering-rules.md`); conformance over house style (global rule 11). Not a finding |
| 2 | Test cases have explicit Expected, not vague "works" | ✓ | Every AT now names values: `0xCBF43926 → 0x1898913F` (AT-213), `0x00000000 → ✗ MISMATCH` (AT-215), `max_scroll_y == 0` (AT-216), `card.height >= 2` (AT-217). All four re-executed |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | AT-215 clause 3 names both near-misses (`○ NO-EXPECTED` on empty, `"Invalid parameters: …"` on non-hex). AT-216/217 are the boundary cases (1 row of slack at 120x30; 9-row budget at the floor). AT-214 clause 2 is the empty-set guard |
| 4 | Regression checklist exists | ✓ | §5.3.2-4; extended by the C-26 table at Q3(c) |
| 5 | Exit criteria stated | ✓ | §5.3, seven numbered criteria incl. the "if any snapshot fails, STOP" premise-guard |
| 6 | No real PII / secrets | ✓ | Artifact + probes contain only CRC constants, widget ids and worktree paths. Probes written to the scratchpad, never the repo |
| 7 | Test results left blank for the human | ✓ | No AT is marked passed — none is authored yet. This document reports only greps, probes and `--collect-only` |
| 8 | Layer B — deliverable observed through the SHIPPED surface, boundary + negative | ✓ | §5.1 mandates `App.run_test()` through the real bindings (`0` / `k`), never `.focus()` (C-16). Negative evidence present: AT-215 clause 4 (`query("#crc_live_verify")` empty), AT-214 clause 3 (zero pairs), AT-216 clause 4 and AT-214 clause 4 (executed oracle mutations) |
| 9 | Bidirectional surface-reachability | ✓ | Inputs `refin` / `check` driven through `Switch.Changed` / `Input.Changed`; **all six** `_recompute` output sinks observed by AT-219 (was 2 of 6 at revision 1). Legend outputs observed by region, not by text |
| 10 | No unfilled template | ✓ | `grep -nE "TC-NNN\|AT-NNN\|<[a-z_]+>\|TBD\|reserved"` over `01-requirements.md` → no placeholder hits; the four matches are prose (`preserved`) |

*Probe: `<scratchpad>/regate_probe.py`. No repo file was written except this review.*
