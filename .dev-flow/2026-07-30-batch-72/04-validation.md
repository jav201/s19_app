# Validation — s19_app — Batch 2026-07-30-batch-72

> Phase 4 artifact. Owner: `qa-reviewer`. Executes the validation strategy fixed in
> [`01-requirements.md`](01-requirements.md) §5 (revision 3, as amended at close by `d13bb1c`).
> Branch `claude/batch-72-design-defect-634a67` @ `d13bb1c`. Artifact language: English.
>
> **The Phase-4 gate run was launched and collected by the ORCHESTRATOR (C-25, §5.3.4).** It was not
> re-run here. Every count below is read from that run's own output. Reconciliation used only short,
> targeted commands (`--collect-only`, greps, `sha256sum`, `git diff --name-only`) executed in this
> worktree; **no source or test file was modified by this phase.**

## ✅ Verdict (read first)

- **Result: PASS.** No blocker. Phase 5 (post-mortem) may proceed.
- **Requirements:** 7 HLR in force / 7 pass · **0** blocker fails. (`HLR-072-4` is WITHDRAWN at
  revision 2 — §6.5 W-1 — and is not counted as in force.)
- **Layer A (white-box):** ✓ **11/11** TCs (`TC-510..TC-520`) reconciled to a real on-disk collected
  node. Every id verified by `pytest --collect-only -q`, not by intent.
- **Layer B (black-box):** ✓ **7/7** ATs (`AT-213..AT-219`) map to **exactly one distinct** on-disk
  node (C-18 / V-5). **No AT is realized "in parts".** One documentation gap only: `AT-218` clause 4
  is a gate-run property that the node's docstring does not say is out-of-node (G-001, LOW).
- **Surface-reachability (bidirectional):** ✓ **13/13 input dimensions driven through the handler**
  and **21/21 named outputs/deliverables observed.** P-4's six `_recompute` surface ids: at revision 1
  four of six were observed by **no** AT — **AT-219 clause 1 closes that**, observing all six through
  the shipped surface. Scope stated honestly in §4.3.
- **Counterfactual / oracle-mutation ledger:** ✓ **4 executed in this batch**, all RED on their own
  assertion line, all with before/mutated/restored evidence; the two whole-file ones carry three
  hashes each and one carries a control arm. §3.
- **PINS labelled, not smuggled:** ✓ `AT-218` and `AT-219` clause 1 are declared **regression pins,
  not gates** (§5) — a C-40-corollary obligation discharged in the requirement, in the test
  docstrings, and here.
- **Supersession inspection:** ✓ all surviving refs to `_switch_row`, `#crc_live_verify`, `.crc-hero`
  and `AT-B59-05` are **negative assertions or retirement comments** — zero live dependencies. §6.
- **Test ledger:** ✓ reconciles exactly — `2379 − 1 + 18 = 2396`; measured collection **2396**. §7.
- **Premise re-check (C-43):** ✓ P-2/P-3 hold — **29 snapshots passed, none regenerated, none
  failed**, and `git diff --name-only origin/main -- '*__snapshots__*'` is **empty**. **D-1** is
  recorded as a premise the batch **falsified during its own execution**. §8.
- **Evidence checklist (qa-reviewer):** ✓ complete, §10.

> Every line above is ✓. The Detail below is reference.

---

## 1. The gate run of record (C-19, C-25)

One complete run, evidence read from that run's own output:

```
$ python -m pytest -q -m "not slow"
--------------------------- snapshot report summary ---------------------------
29 snapshots passed.
2370 passed, 2 skipped, 21 deselected, 3 xfailed in 1606.71s (0:26:46)
GATE_EXIT=0
```

`2370 + 2 + 21 + 3 = 2396` — identical to the measured collection (§7) and to the ledger
`2379 (base) − 1 (D) + 18 (A) = 2396`.

Reconciliation commands executed by this phase (short, targeted — no second full run):

```
$ python -m pytest --collect-only -q | tail -3
2396 tests collected in 0.79s

$ git diff --name-only origin/main -- '*__snapshots__*' tests/test_tui_snapshot.py
(no output)

$ git diff --name-only origin/main
.dev-flow/…  REQUIREMENTS.md
s19_app/tui/crc_designer_view.py   s19_app/tui/screens.py   s19_app/tui/styles.tcss
tests/test_crc_designer_view.py    tests/test_legend_two_pane.py
```

**Frozen set (C-27, §5.3.2):** `core.py`, `hexfile.py`, `range_index.py`, `validation/`,
`tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` — and `tui/legend.py`, TC-519's subject — **appear
in no diff line vs `origin/main`.** Both guard arms (`test_tc031_*` engine modules, `test_tc032_*`
engine test files) ran green at every increment gate and inside the Phase-4 run.

---

## 2. Layer A — functional (white-box): every TC reconciled to a real node

> `Node` = the exact id from `python -m pytest --collect-only -q`, verified in this phase.
> No TC below is signed off from intent.

| Req | TC | **On-disk collected node** (`file::test_name`) | Def. line | Executed verification | Numeric / exact threshold | Result |
|---|---|---|---|---|---|---|
| LLR-072-1.1 | **TC-510** | `tests/test_crc_designer_view.py::test_reflection_row_structure` | `:1665` | one `.crc-field-row` holds both switches; label inventory | `["Reflection","in","out"]` exactly | ✅ pass |
| LLR-072-1.2 | **TC-511** | `tests/test_crc_designer_view.py::test_orphaned_per_toggle_helper_is_deleted` | `:1700` | repo-wide grep for the retired helper token, assembled from fragments so the node cannot falsify itself | **0** hits in `s19_app/` + `tests/` (re-executed §6) | ✅ pass |
| LLR-072-2.2 | **TC-512** | `tests/test_crc_designer_view.py::test_hero_right_column_holds_warnings_only` | `:1723` | `#crc_top_right` child-group census | exactly **1** child group | ✅ pass |
| LLR-072-2.3 | **TC-513** | `tests/test_crc_designer_view.py::test_retired_hero_selectors_absent_from_stylesheet` | `:1751` | stylesheet text scan | `"crc-hero"` **not in** text; `"crc_live_verify"` **not in** text (`:1763-1764`) | ✅ pass |
| HLR-072-3 | **TC-514** | `tests/test_crc_designer_view.py::test_tc514_every_switch_construction_site_is_on_the_crc_designer` | `:1858` | (a) exactly one module imports `Switch`; (b) every `\bSwitch\(` site is in it; (c) non-vacuity | `{crc_designer_view.py}` = the whole site set; site count `>= 1` | ✅ pass — **on a RE-DERIVED property, see §8 D-1** |
| LLR-072-5.1 | **TC-515** | `tests/test_legend_two_pane.py::test_tc515_panes_hold_the_unmodified_render_output` | `:259` | both panes resolve; per-pane widget counts vs M-6 | mac `(17, 6)`, map `(20, 7)` (`:256`) | ✅ pass |
| LLR-072-5.1 / P-12 | **TC-516** | `tests/test_legend_two_pane.py::test_tc516_legend_body_is_the_two_pane_wrapper` | `:370` | `#legend_body` is the wrapper; the **9** shipped descendant query sites each resolve as their own test expects (C-38) | 9/9 sites, incl. the one expected-empty site with a second arm proving the selector resolves elsewhere | ✅ pass |
| LLR-072-6.1 | **TC-517** | `tests/test_legend_two_pane.py::test_tc517_width_regime_flips_class_and_pane_order` | `:563` | `legend-narrow` class **and** `#legend_body` document order flip, both directions, across 4 regime transitions | class `True`@80x24 / `False`@120x30; children `[key,card]` narrow / `[card,key]` wide; breakpoint read from `_LEGEND_NARROW_WIDTH`, never the literal `120` | ✅ pass |
| LLR-072-6.2 | **TC-518** | `tests/test_legend_two_pane.py::test_tc518_key_pane_never_uses_height_auto` | `:649` | (a) **regex** `height\s*:\s*auto` over every `#legend_key_pane` rule; (b) live unit @80x24; (c) live unit @120x30 | `>= 2` rule blocks found; `Unit.FRACTION` at **both** sizes | ✅ pass — **F2 fold verified on disk** (`:665`, regex not substring; 120x30 arm present `:684`) |
| LLR-072-7.1 | **TC-519** | `tests/test_legend_two_pane.py::test_tc519_legend_module_unchanged_vs_main` | `:700` | `git diff origin/main -- s19_app/tui/legend.py` | **empty**; ref resolves, node does not skip | ✅ pass |
| LLR-072-6.1 (§6.5 **D-2**) | **TC-520** | `tests/test_legend_two_pane.py::test_tc520_legend_focus_traversal_is_pinned_in_both_regimes` | `:756` | (a) initial focus; (b) both panes in `focus_chain`; (c) floor order | (a) `legend_close` both regimes; (b) 2/2 pane ids present; (c) key **precedes** card @80x24 | ✅ pass |

**Reconciliation result — Layer A: 11 of 11 TCs map to exactly one real collected node. Zero
orphans, zero phantom ids.** `TC-520` was allocated outside the Phase-1 reservation block
(`TC-510..519`) and now carries its §5.2 traceability row, folded at `d13bb1c` (§6.5 D-2).

---

## 3. The counterfactual / oracle-mutation ledger

> **Six** mutations were executed in this batch (plus one control arm). Collected here in one table
> because that is the only place they can be compared. **A declaration that a clause is "the tooth"
> is not evidence; each row below is a run.**
>
> *Corrected at the Phase-6 gate: this section originally said "four" and omitted **CF-5** and
> **CF-6**, both of which have pasted transcripts failing on their own assertion lines in the
> increment packets. The discrepancy was found by the `docs-writer` cross-reading this artifact
> against `03-increments/` while building the traceability matrix, and it is recorded rather than
> quietly renumbered. It understates the evidence, so no verdict changes — but an evidence ledger
> that undercounts its own evidence is exactly the kind of claim this batch has spent four gates
> refusing to accept from anyone else.*

| # | Subject | Mutation | Where executed | Result — key transcript lines | Hashes (before → mutated → restored) |
|---|---|---|---|---|---|
| **CF-1** | **AT-216 clause 4** (C-32 discharge, demanded by the requirement) | `#legend_key_pane.styles.display = "none"` applied inside `_measure_key_pane` immediately after the modal opens | Inc-1 §4; **independently reproduced** by the Inc-1/2 code review on an isolated worktree | `E AssertionError: the key pane Region(x=0, y=0, width=0, height=0) is not inside #legend_body Region(6,6,107,15) — it is rendering off-dialog` · `tests\test_legend_two_pane.py:201` · `1 failed in 1.74s` | in-process style mutation, reverted; no file hash recorded |
| **CF-2** | **AT-216 clause 0** (the F1 fold — the wide regime's *defining* property) | remove the `#legend_dialog.legend-narrow ` prefix from all **3** narrow rules in `styles.tcss` — the real historical specificity slip | **Orchestrator-run** at the F1 fold (`0169108`) | wide regime collapses to a **vertical stack** — `card Region(6,6,107,7)` / `key Region(6,13,107,8)`; **pre-fold: all 8 nodes GREEN, exit 0**; **post-fold: AT-216 RED on clause 0** (`assert m["key_right_of_card"]`) | `styles.tcss` `c65ac445…` → `010c44b2…` → `c65ac445…` |
| **CF-3** | **AT-214 clause 4** (C-40 discharge, whole-file revert) | `git checkout origin/main -- s19_app/tui/crc_designer_view.py` on a **private `cp -r` copy** (never `git worktree add`), run with **cwd inside the copy** | Inc-4 §4A | `E AssertionError: no two Switch widgets may render vertically abutting (G-1); abutting pairs: [('crc_field_refin','crc_field_refout')] out of ['crc_field_refin','crc_field_refout']` · `tests\test_crc_designer_view.py:1852` · `1 failed, 1 passed, 38 deselected` | blob `73879009…` → `37fe94f8…` → `73879009…`; shared worktree file `2121d331…` **identical before and after** |
| **CF-3b** | **AT-214 control arm** | same copy, same cwd, file **restored to HEAD** — the arm that proves the copy is not simply broken | Inc-4 §4A.5 | `TREE IN USE : …\cf214\s19_app` · `sha256 73879009…` · `2 passed, 38 deselected in 1.71s` | — (restored state of CF-3) |
| **CF-4** | **AT-217 clause 2** (the declared non-vacuity tooth) — the **degenerate-regime probe** | `#legend_dialog.legend-narrow #legend_key_pane { height: 1fr }` → `height: auto` | Inc-2 §4(a); reproduced by the Inc-1/2 review | `E AssertionError: the card pane is starved (the degenerate 'height: auto' key regime): card=Region(x=6, y=16, width=68, height=1)` · `assert 1 >= 2` · **AT-217 clauses 1 and 3 stay GREEN**, TC-518 also RED | CSS edit, reverted; verified by `git diff --stat` |

| **CF-5** | **TC-517 / LLR-072-6.1** — the `move_child` reorder, i.e. the re-gate's N-1 finding executed against its own fix | disable the `move_child` call in `_apply_width_regime`, leaving the class toggle and the CSS intact | Inc-2 §4(b) | the `legend-narrow` class still flips and the panes still **stack**, but in the **wrong order** — proving CSS can stack and cannot order, which is precisely why LLR-072-6.1 owns the ordering | in-process, reverted |
| **CF-6** | **AT-219 clause 2** (the GATE arm — the only clause FALSE before the hoist) | re-bind the **pre-batch** `_recompute` (hardcoded queries, ignoring the module tuple), then monkeypatch the tuple with a bogus id | Inc-3 §4 | fails **on its own assertion line** — `assert after == before`, with the verdict having moved `✓ MATCH` → `✗ MISMATCH`, i.e. the live surfaces updated when a bogus id should have forced the `NoMatches` early return | in-process re-bind, reverted |

### 3.1 What each row establishes — stated plainly, including where it is weaker than it looks

- **CF-1 reddened clause 2b ONLY.** Say it plainly: clauses 1 and 2a are **blind** to `display: none`,
  because the pane *and* its rows both collapse to `Region(0,0,0,0)` and a zero region trivially
  `contains_region` a zero region. The mutation the requirement demanded is therefore carried entirely
  by the arm the Phase-2 re-gate added (N-3). This does **not** make 2a vacuous on the real tree
  (measured: row `Region(70,11,43,3)` genuinely inside key `Region(70,6,43,15)`), but the coverage
  claim belongs to 2b and is recorded as 2b's. Both the increment packet and the module docstring
  (`tests/test_legend_two_pane.py:39-42`) state this; so does this artifact.
- **CF-2 is the most consequential run of the batch.** Before the F1 fold, the batch's own review
  showed the acceptance test for HLR-072-5 did **not** test HLR-072-5: the shipped defect this batch
  exists to remove — the key back under the card — could be reintroduced with **all 8 legend nodes
  green**. Two weaker mutations confirmed the same unguarded axis (swap `3fr`/`2fr` → 8 passed;
  wide key `height: 1fr → auto` → 8 passed). The fold added `clause 0` at
  `tests/test_legend_two_pane.py:170-174, 211-220`: `key.region.x >= card.region.right` **and**
  `key.region.y == card.region.y`. **Verified in this phase:** the worktree `styles.tcss` is
  `c65ac445a4f17b861e4c7fdf142759f1cb30293a70d67488a282c925265d8e05` — byte-identical to the recorded
  *before* and *restored* hash, so the mutation left nothing behind.
- **CF-3 avoided the trap that would have made it worthless.** `s19_app` is installed nowhere (no
  editable install, no `.pth`); it resolves purely from `sys.path[0] == ''`, so `PYTHONPATH` cannot
  override a worktree and a sibling increment's counterfactual had silently run against the *unmutated*
  tree. The fix was cwd, not an env var, plus a throwaway `conftest.py` emitting a
  `pytest_report_header` that prints the **resolved package dir and the sha256 of the loaded module** —
  so the transcript proves its own tree. The failure is an `AssertionError` on AT-214's own assertion
  line, not an `ImportError`/`NameError`
  (`feedback_counterfactual_must_fail_on_its_assertion`), and the reported pair is exactly M-1's
  predicted `c01`.
- **CF-3b is the control arm** and it is not optional: a RED run proves nothing if the private tree
  fails for an unrelated reason. Same copy, same harness, **only the file content differs** → GREEN.
- **CF-4 proves clause 2 is the ONLY tooth in the degenerate regime.** Ordering (clause 1) and
  reachability-under-scroll (clause 3) are both TRUE when the card is starved to `height=1` — exactly
  M-3's measured prediction, reproduced. Without clause 2, AT-217 would accept a floor layout that
  overflows `#legend_body`.
- **AT-219's own gate (clause 2)** is a fifth executed non-vacuity discharge, listed separately in
  §4.2 because it is an in-node monkeypatch rather than a tree mutation: with the **pre-batch**
  `_recompute` re-bound onto the class, a bogus id in the tuple changes nothing and the verdict flips
  `'✓ MATCH' → '✗ MISMATCH'` — `AssertionError` on its own line, `exit=1` (Inc-3 §4).

---

## 4. Layer B — behavioural (black-box) acceptance

> Every AT drives the **shipped surface** — `pilot.press("0")` for the CRC bench, the ratified `k`
> binding for the Legend (`_open_legend`, `tests/test_legend_two_pane.py:73-103`) — never a `.focus()`
> proxy (C-16). Reconciled to the real collected node per V-5.

### 4.1 The reconciliation table

| US | AT | **On-disk node (exactly ONE)** | Def. line | Surface driven | Deliverable **observed** | repr · boundary · negative | Result |
|---|---|---|---|---|---|---|---|
| US-072-1 | **AT-213** | `tests/test_crc_designer_view.py::test_reflection_pair_row_shares_one_band_and_drives_the_kernel` | `:1451` | `pilot.press("0")` → `#crc_field_refin.value = False` (the real `Switch.Changed` reactive path) | `refin.region.y == refout.region.y`; exactly **1** `Label` strictly between the switches' x-bands; `#crc_custom_vector_result` text | ✓ seeded `True` (non-default drive, C-10) · ✓ **exact** transition `0xCBF43926 → 0x1898913F`, not a `!=` · ✓ `seeded_on` asserted, so a dead seed cannot pass | ✅ pass |
| US-072-1 | **AT-214** | `tests/test_crc_designer_view.py::test_at214_no_two_switches_render_vertically_abutting` | `:1802` | `pilot.press("0")`; subject set **derived** from `app.screen.query(Switch)` filtered `region.area > 0` (C-31) | the abutting-pair list under the §1.3 relation, over ordered `permutations` | ✓ derived set asserted `>= 2` (anti-vacuity) · ✓ zero abutting pairs · ✓ **CF-3 whole-file counterfactual RED + control arm GREEN** | ✅ pass |
| US-072-1 | **AT-215** | `tests/test_crc_designer_view.py::test_kat_verdict_demoted_to_self_test_row_under_check` | `:1527` | `pilot.press("0")` → `#crc_field_check.value = "0x00000000"` (real `Input.Changed`) | ancestry `#crc_algorithm_fields`; the on-screen row text; `#crc_kat_verdict` content; `len(query("#crc_live_verify"))` | ✓ `123456789` named on screen · ✓ `MATCH → MISMATCH` measured transition · ✓ **two near-misses excluded by name** (`NO-EXPECTED`, `Invalid parameters`) + the discriminating negative `wrappers == 0` | ✅ pass |
| US-072-2 | **AT-216** | `tests/test_legend_two_pane.py::test_at216_key_pane_shows_warning_row_without_scrolling` | `:179` | `k` binding, **mac** view, 120x30 | **cl.0** side-by-side geometry (`key.x >= card.right`, shared `y`); **cl.1** the `{legend-row, sev-warning}` row text; **cl.2** painted-region containment both directions incl. `#legend_body ⊇ #legend_key_pane`; **cl.3** `max_scroll_y` | ✓ anchored on classes + `LEGEND_TABLE` containment (never `==`, never a literal) · ✓ `max_scroll_y == 0` fails on the **cause** (14 rows in 15 — one row of slack) · ✓ **CF-1 + CF-2** | ✅ pass |
| US-072-2 | **AT-217** | `tests/test_legend_two_pane.py::test_at217_floor_stacks_key_above_card_and_key_is_reachable` | `:489` | `k` binding, mac view, **80x24 floor** + a real `scroll_visible(animate=False)` interaction | `key.region.y < card.region.y`; `card.region.height`; `key.max_scroll_y`; the last key row's area **and** containment after scrolling | ✓ key-first (the operator's P-8 decision) · ✓ boundary: `card_height >= 2` — **CF-4 proves this is the only tooth** · ✓ `n_key_rows >= 1` + `last_row_area > 0` block a vacuous pass | ✅ pass |
| US-072-2 | **AT-218** *(**PIN**, §5)* | `tests/test_legend_two_pane.py::test_at218_pipeline_preserved_regression_pin` | `:419` | `k` binding, mac **and** map views, 120x30 | `#legend_mac_warning_sample`'s inline orange read from **`render().spans`** (C-37, never `render_line(0)`), coupled to the live `_SEVERITY_TO_RICH_STYLE`, not a hex literal; band-key rows' `_render_markup`; the 9-site census | ✓ two views · ✓ `_render_markup is False` on rows that literally contain `[lo,hi)` · ✓ census reddens on a pane moved out of `#legend_body` | ✅ pass |
| US-072-3 | **AT-219** *(cl.1 = **PIN**; cl.2 = the gate, §5)* | `tests/test_crc_designer_view.py::test_recompute_surface_ids_are_the_live_markup_census` | `:1593` | `pilot.press("0")`; **cl.2** drives a real `Input.Changed` on `#crc_field_xorout` with the module tuple monkeypatched | **cl.1** `_render_markup` of **all six** live surfaces, iterated from the module tuple (C-31, never hand-listed); **cl.2** `#crc_kat_verdict` content immobility under the `NoMatches` early return | ✓ `len(tuple) >= 6` · ✓ live-oracle iteration (a 7th sink is covered with no test edit) · ✓ **negative:** a bogus id must make the surfaces **stop** moving; baseline `MATCH` asserted first so the gate cannot pass on a dead app | ✅ pass |

**Reconciliation result — Layer B: 7 of 7 ATs map to exactly ONE distinct on-disk node. Zero ATs are
satisfied "in parts"; zero UNREALIZED.** Revision 1's C-18 violation (`HLR-072-4`'s acceptance
smuggled into AT-213's run) does not exist on the shipped tree: `HLR-072-4` is withdrawn (§6.5 W-1),
AT-213 carries one subject, and the CRC test diff contains **no** `Select` height assertion.

### 4.2 AT-219's gate arm — recorded separately because it is a different kind of evidence

Clause 2 is the **only** clause of AT-219 that is FALSE before the hoist, which is what makes it the
gate rather than a pin. Its discharge (Inc-3 §4) re-bound the **pre-batch** `_recompute` body onto the
class in-process and re-ran the drive:

```
COUNTERFACTUAL _recompute = pre-batch (hardcoded queries)
before='✓ MATCH'
after ='✗ MISMATCH'
AssertionError: with a bogus id in the module tuple _recompute must take its NoMatches
early return; the verdict moved '✓ MATCH' -> '✗ MISMATCH', so the tuple is declared but
not consumed
exit=1
```

The consumption is **by name**, verified on disk at `s19_app/tui/crc_designer_view.py:1134-1146` — a
dict comprehension keyed on `surface_id`, then six named lookups. **Not a positional unpack**, per the
re-gate's N-5 correction: an unpack would raise `ValueError` on the UI thread the moment a seventh
surface is declared, and clause 1 could not detect it.

### 4.3 P-4's six surfaces — does AT-219 close the revision-1 gap? **Yes, at the scope it claims.**

`_recompute` queries six ids and aborts on the first `NoMatches`; at revision 1, **four of the six
were observed by no AT**. Stated precisely:

| `_recompute` surface id | Observed by an AT of THIS batch? | How | Content-level oracle |
|---|---|---|---|
| `crc_kat_verdict` | ✅ AT-215 cl.3, AT-219 cl.1 + cl.2 | value transition `MATCH → MISMATCH`; markup flag; immobility under the gate | this batch |
| `crc_custom_vector_result` | ✅ AT-213 cl.3, AT-219 cl.1 | **exact** `0xCBF43926 → 0x1898913F`; markup flag | this batch |
| `crc_json_preview` | ✅ AT-219 cl.1 | markup flag, via the live tuple through the pilot | pre-existing `::test_json_preview_roundtrips_through_mounted_widget` (`:303`) |
| `crc_warnings` | ✅ AT-219 cl.1 | markup flag | pre-existing `::test_three_warn_conditions_through_view` (`:788`) |
| `crc_coverage_preview` | ✅ AT-219 cl.1 | markup flag | pre-existing `::test_coverage_preview_shows_both_policy_oracles` (`:680`) |
| `crc_coverage_window` | ✅ AT-219 cl.1 | markup flag | pre-existing `::test_coverage_window_renders_colored_glyphs_with_live_oracles` (`:1053`) |

**Verdict: the gap is closed as scoped.** All six ids now resolve *through the shipped surface* inside
an AT of this batch, which is what HLR-072-8 asks for. The honest limit: for four of the six, AT-219
observes the **markup-safety flag**, not the rendered value; their content oracles are pre-existing
batch-58/59 nodes, which are green in the gate run but are **not** this batch's ATs. That is the
requirement's own scope (US-072-3 is a markup-safety story), not an unremarked shortfall.

---

## 5. The two PINS — labelled as pins, not gates (C-40 corollary)

> This is an obligation, not a footnote. A test whose declared subject is **invariant under the
> change the batch makes** cannot be the thing that proves the change landed. Both are kept — each is
> the only thing that would catch a specific accidental regression — and both are labelled so nobody
> mistakes them for the gate.

| Pin | Node | Declared subject | Why it is invariant under THIS batch | Why it is kept anyway | Where it is labelled |
|---|---|---|---|---|---|
| **AT-218** | `test_at218_pipeline_preserved_regression_pin` (`:419`) | the **unchanged** legend data pipeline: `LEGEND_EXAMPLES` role mapping, `_render_card`, `_render_key` incl. the map band-key branch, and the preserved ids | LLR-072-7.1 forbids any `legend.py` edit and the widgets are **re-parented, never reconstructed**; TC-519 proves the diff vs `origin/main` is empty. A pipeline that was not touched cannot be *proved to work* by a test of it | it is the only node that would catch an accidental data-layer edit — e.g. a "grouping helper" that rebuilt rows from text and dropped `#legend_mac_warning_sample`'s markup (S-2b). Its clause-by-clause mutations all reddened (review table: orange strip → RED; `markup=False` drop → RED; pane moved out of body → RED) | `01-requirements.md` HLR-072-7 (*"labelled a REGRESSION PIN, not a gate"*); test file `:415-418`; this table |
| **AT-219 clause 1** | same node as the gate, `test_recompute_surface_ids_are_the_live_markup_census` (`:1593`) | every `_recompute` sink reports `_render_markup is False` | **all six sinks are already `markup=False` on `origin/main`** (`crc_designer_view.py:341,353,367,397,403,411` pre-batch). The clause is TRUE before and after | it is exactly the guard S-1 asked for: `compose` was rewritten in this batch, and a dropped flag would let a typed `[` reach `f"Invalid parameters: {exc}"` and raise `MarkupError` on the UI thread (`_recompute` has no `try/except` around the `.update()` calls). It is a **live oracle** — a seventh sink is covered with no test edit | `01-requirements.md` HLR-072-8 AT-219 cl.1; test docstring `:1599-1606`; this table |

**The corresponding gates are named and distinct:** for HLR-072-7 the gate is TC-519 (the empty diff)
plus AT-216/217's geometry; for HLR-072-8 the gate is **AT-219 clause 2**, the only clause that is
FALSE before the hoist (§4.2).

---

## 6. Bidirectional surface-reachability matrix

> Every named INPUT dimension exercised **through the handler**, and every named OUTPUT/deliverable
> **observed** — not only through the service API. Extends A-5 (batch-11).

### 6.1 Inputs

| # | Input dimension | Handler / surface | Driven at the surface? | Node | Status |
|---|---|---|---|---|---|
| I-1 | rail key `0` → CRC Designer screen | `S19TuiApp` binding → `pilot.press("0")` | yes | AT-213, AT-214, AT-215, AT-219, TC-510, TC-512 | ✓ |
| I-2 | `#crc_field_refin` toggle (**non-default**: seeded `True` → driven `False`) | `Switch` reactive setter → `Switch.Changed` → `on_switch_changed` → `_recompute` | yes | AT-213 `:1494` | ✓ |
| I-3 | `#crc_field_check` edit | `Input.Changed` → `_recompute` | yes | AT-215 `:1560` | ✓ |
| I-4 | `#crc_field_xorout` edit (the gate's drive) | `Input.Changed` → `_recompute` under a monkeypatched tuple | yes | AT-219 cl.2 `:1643` | ✓ |
| I-5 | `k` binding → Legend modal | `LegendScreen` push via `_open_legend` (`app.set_focus(None)` first, so `k` is not swallowed by a filter input) | yes | AT-216, AT-217, AT-218, TC-515..518, TC-520 | ✓ |
| I-6 | rail view = **mac** | `app.action_show_screen("mac")` then `k` | yes | AT-216, AT-217, AT-218, TC-515, TC-518, TC-520 | ✓ |
| I-7 | rail view = **map** (the band-key branch) | same | yes | AT-218 cl.2, TC-515 | ✓ |
| I-8 | the other 7 legend view keys (`a2l`, `issues`, `workspace`, `flow`, …) | same | yes — via the 9-site census, each site probed on the view **its own test drives** | TC-516, AT-218 cl.3 | ✓ |
| I-9 | width regime **wide** (120x30) | `on_mount` → `_apply_width_regime(self.app.size.width)` | yes | AT-216, TC-515, TC-517, TC-518 cl.c, TC-520 | ✓ |
| I-10 | width regime **floor** (80x24) | same | yes | AT-217, TC-517, TC-518 cl.b, TC-520 | ✓ |
| I-11 | **resize event** across the breakpoint, both directions | `on_resize` → `_apply_width_regime` | yes — 4 transitions, idempotence asserted | TC-517 | ✓ |
| I-12 | scroll interaction at the floor | `scroll_visible(animate=False)` on the last key row | yes | AT-217 cl.3 | ✓ |
| I-13 | a **bogus** surface id injected into the live census tuple | `monkeypatch` on the module attribute → `_recompute`'s `NoMatches` early return | yes | AT-219 cl.2 | ✓ |

### 6.2 Outputs / deliverables

| # | Named output / deliverable | Producer | Observed at the surface? | Node | Status |
|---|---|---|---|---|---|
| O-1 | one shared row band for `refin`/`refout` | `compose` pair row | yes — `region.y` equality | AT-213 cl.1, TC-510 | ✓ |
| O-2 | the interleaved separability `Label` | `compose` (`Label("out")`) | yes — strictly between the two x-bands, count `== 1` | AT-213 cl.2 | ✓ |
| O-3 | `#crc_custom_vector_result` value | `_recompute` → `_custom_vector_text` | yes — exact `0xCBF43926 → 0x1898913F` | AT-213 cl.3 | ✓ |
| O-4 | zero vertically-abutting `Switch` pairs (G-1) | layout | yes — derived DOM walk | AT-214 | ✓ |
| O-5 | `Switch` single-module confinement | source tree | yes — static scan + non-vacuity | TC-514 | ✓ |
| O-6 | `#crc_kat_verdict` re-parented under `#crc_algorithm_fields` | `compose` | yes — ancestry walk | AT-215 cl.1 | ✓ |
| O-7 | the reference vector `123456789` **on screen** | `compose` sub-label | yes — rendered row text | AT-215 cl.2 | ✓ |
| O-8 | the live tri-state verdict at its new parent | `_recompute` → `_verdict_text` | yes — `MATCH → MISMATCH`, near-misses excluded | AT-215 cl.3 | ✓ |
| O-9 | `#crc_live_verify` **absent** (discriminating negative) | `compose` | yes — `len(query(...)) == 0` | AT-215 cl.4 | ✓ |
| O-10 | `#crc_top_right` holds Warnings only | `compose` | yes — child-group census | TC-512 | ✓ |
| O-11 | `.crc-hero` / `#crc_live_verify` selectors retired | `styles.tcss` | yes — stylesheet text scan | TC-513 | ✓ |
| O-12 | `_render_markup is False` on all **six** `_recompute` sinks | `compose` `markup=False` kwargs | yes — live-tuple iteration through the pilot | AT-219 cl.1 | ✓ |
| O-13 | the module tuple is **consumed**, not merely declared | `_recompute` | yes — bogus-id early return observed as surface immobility | AT-219 cl.2 | ✓ |
| O-14 | wide regime: panes **side by side, card left** | `compose` + wide CSS | yes — `key.x >= card.right`, shared `y` | AT-216 cl.0 | ✓ **(added by the F1 fold; unobserved before it)** |
| O-15 | the MAC `Pale yellow` key row inside `#legend_key_pane`, no scroll | `_render_key` re-parented | yes — class anchor + `LEGEND_TABLE` containment + region containment + `max_scroll_y == 0` | AT-216 cl.1-3 | ✓ |
| O-16 | `#legend_body` ⊇ `#legend_key_pane` (not rendering off-dialog) | wrapper geometry | yes | AT-216 cl.2b | ✓ |
| O-17 | floor: key **above** card, card non-degenerate, key reachable under scroll | narrow CSS + `move_child` | yes — three clauses, CF-4 confirms cl.2 is the tooth | AT-217 | ✓ |
| O-18 | per-pane widget inventory unchanged vs M-6 | `_render_card` / `_render_key` re-parented | yes — mac `(17,6)`, map `(20,7)` | TC-515 | ✓ |
| O-19 | `#legend_mac_warning_sample` inline orange + band-key `markup=False` + the 9 body-rooted sites | data pipeline (untouched) | yes — `render().spans`, flags, census | AT-218 | ✓ |
| O-20 | keyboard reachability of both panes; floor focus order | focus chain | yes — `screen.focus_chain` in both regimes | TC-520 | ✓ |
| O-21 | `s19_app/tui/legend.py` byte-identical to `origin/main` | git | yes — empty diff, no skip | TC-519 | ✓ |

**Result: 13/13 inputs driven through the handler; 21/21 named outputs observed. Zero gaps.**

---

## 7. Supersession-completeness inspection (V-3) — executed in this phase

```
$ grep -rn "<retired helper token>" s19_app/ tests/ --include=*.py --include=*.tcss   → 0 hits
$ grep -rn "crc_live_verify"        s19_app/ tests/ --include=*.py --include=*.tcss   → 5 hits
$ grep -rn "crc-hero"               s19_app/ tests/ --include=*.py --include=*.tcss   → 2 hits
$ grep -rn "test_verdict_hero_center_aligned_in_hero_row" …                           → 1 hit
```

| Superseded marker | grep | All surviving refs NEGATIVE? | Evidence (`file:line`) |
|---|---|---|---|
| the per-toggle row helper (`_switch_row`) | **0** hits | n/a — fully removed | LLR-072-1.2 threshold met; TC-511 pins it. The token is assembled from fragments in the test so the node cannot falsify its own assertion (a real self-catch: Inc-3 and Inc-4 each tripped it once) |
| `#crc_live_verify` | 5 | ✅ **yes** — 3 in AT-215's negative clause, 2 in TC-513's absence assertion | `tests/test_crc_designer_view.py:1544, 1568, 1589` (AT-215 cl.4) · `:1752, 1764` (TC-513) |
| `.crc-hero` | 2 | ✅ **yes** — both TC-513's absence assertion | `tests/test_crc_designer_view.py:1752, 1763` |
| `AT-B59-05` / `test_verdict_hero_center_aligned_in_hero_row` | 1 | ✅ **yes** — a retirement **comment**, not a function | `tests/test_crc_designer_view.py:1004-1011`. **Deleted, never edited into passing** (LLR-072-2.4). §6.5 A-1 re-derives the surviving obligation as AT-215 cl.1/2/4 |
| `#legend_body` (P-12: candidate for retirement — **premise FALSE**) | 9 shipped sites + the wrapper | ✅ **preserved as the two-pane wrapper**; all 9 sites resolve as their own tests expect | TC-516, AT-218 cl.3 |

**No live dependency on any superseded marker.**

---

## 8. Signed-balance test ledger

| base | − D | + A | = post | actual collected | passed-lean (gate run) | reconciles? |
|---|---|---|---|---|---|---|
| **2379** (measured 2026-07-30 @ `b556e35`) | **1** (`AT-B59-05`, LLR-072-2.4) | **18** | **2396** | **2396** (`--collect-only -q`, re-executed this phase) | 2370 passed + 2 skipped + 21 deselected + 3 xfailed = **2396** | ✅ **yes, exactly** |

`A = 18`, itemised: Inc-1/2 `+8` (AT-216, AT-217, AT-218, TC-515..519) · Inc-3 `+7` (AT-213, AT-215,
AT-219, TC-510..513) · Inc-4 `+3` (AT-214, TC-514, TC-520). Per-increment checkpoints, each executed:
`2379 + 8 = 2387` → `2387 − 1 + 7 = 2393` → `2393 + 3 = 2396`.

Revision 1's base figure of 2358 was **stale by 21** and was re-measured rather than carried — the
same control that D-1 (§9) is an instance of.

---

## 9. Premise re-check at the validation gate (C-43)

| # | Premise | Tier | Verdict **at the validation gate** | Executed evidence at this gate |
|---|---|---|---|---|
| **P-2** | (Backlog line 153) "any change will drift the CRC snapshot cells" | premise | ❌ **FALSE — confirmed, third independent probe** | The gate run reports **`29 snapshots passed`** with **0 failed and 0 regenerated**. `git diff --name-only origin/main -- '*__snapshots__*' tests/test_tui_snapshot.py` → **empty**, executed in this phase. Inc-3 §4 ran the full snapshot file (`207 passed, 29 snapshots`); the Inc-1/2 review independently confirmed *"no snapshot test opens `LegendScreen`"* |
| **P-3** | The Legend modal is not snapshot-captured | premise | ✅ **TRUE — confirmed** | same probe; 0 legend snapshots on disk |
| — | §5.3.6: *"If any snapshot fails, **STOP** — a premise was wrong"* | control | ✅ **never triggered** | Inc-1 §4, Inc-2 §4, Inc-3 §4, Inc-4 §7 and the Phase-4 gate run all report snapshots passing; **no regen PR is owed** and `BACKLOG-CODE.md:153` is owed a correction at close |
| **P-4** | `_recompute` queries six ids; all must stay mounted | premise | ✅ **TRUE**, and the revision-1 observation gap is **CLOSED** — §4.3 | `crc_designer_view.py:125-133` (the hoisted tuple) + `:1134-1146` (named consumption); AT-219 cl.1 resolves all six through the pilot |
| **P-8** | Floor stacking order = key first | hypothesis → requirement | ✅ **now VERIFIED, not merely decided** | it remained a hypothesis until AT-217 passed. It passes: `key_y < card_y` at 80x24, and TC-520 cl.(c) shows the same order on the **keyboard** surface |
| **P-11** | A `Switch`-only abutment rule is FALSE pre-batch and satisfiable post-batch | hypothesis | ✅ **TRUE — executed both arms** | **CF-3**: 1 violating pair on `origin/main` (`('crc_field_refin','crc_field_refout')` — exactly M-1's `c01`), **0** on HEAD |
| **P-12** | `#legend_body` may be retired | premise | ❌ **FALSE — confirmed** | preserved as the wrapper; TC-516 shows all 9 descendant sites resolving |
| **D-1** | *"`Switch(` has exactly **one** construction site (`crc_designer_view.py:467`)"* | premise stated as present-tense **fact** in HLR-072-3 **and** in M-1 | ❌ **FALSE — and the batch falsified it ITSELF, mid-execution** | `git grep -n "Switch(" origin/main -- 's19_app/*.py'` → **1 site** (`:467`); `git grep -n "Switch(" HEAD` → **2 sites** (`:325`, `:327`). Cause: LLR-072-1.2 **deleted** the per-toggle helper (one `Switch(` call invoked twice) and LLR-072-1.1 inlined both toggles. TC-514 was re-derived to assert **single-module confinement** — the property the count was a proxy for — plus non-vacuity. Spec corrected at `d13bb1c` |

### 9.1 D-1 is the premise that changed *during* execution — and why that matters here

This is the one premise on the list whose truth value moved **inside the batch**, not between batches.
The options were tabled and the third was taken:

| Option | Expected result | Consequence |
|---|---|---|
| A — assert `== 1` as specified | TC-514 immediately RED | ❌ ships a failing test asserting a falsified premise |
| B — silently change to `== 2` | GREEN | ❌ hides that a carried number was never re-derived, and re-plants the identical brittle constant for the next refactor |
| C — assert the **property** the count stands for | GREEN, and it is the load-bearing claim | ✅ chosen, reported at Inc-4 §6, folded into the spec at `d13bb1c` |

**The general lesson, and it reads C-39's rider backwards:** a measured constant is true *of the tree
it was measured on*. When the batch **is** what changes that tree, a pre-batch constant can be
falsified **by the batch's own success**. Prefer the invariant the number stands for whenever the
number is downstream of your own edit. This is a Phase-5 candidate.

A second, smaller instance of the same class is already recorded: **N-4**, the re-gate's precision
correction that `App.query` is *screen-scoped* (`app._get_dom_base() -> Screen`), so AT-214's query
does not by itself certify "anywhere in the app" — the **grep** in TC-514 carries that argument. Both
belong to the same failure mode: a claim whose stated scope exceeded what its mechanism could support.

---

## 10. Gaps / residual risk

> None is a blocker. G-001..G-003 are the code review's unfolded LOW findings; G-004..G-007 are
> declared open risks carried from `01-requirements.md` §6.3 / the increment packets.

| ID | Requirement | Gap | Severity | Proposed action |
|---|---|---|---|---|
| **G-001** | HLR-072-7 / AT-218 | The requirement gives AT-218 **four** clauses; the node implements 1-3. Clause 4 (*"the three legend test files stay green"*) is a **gate-run property** — discharged at Inc-1 §4 (239 passed), Inc-2 §4 (242 passed), Inc-4 §4.3 (108 passed) and the Phase-4 run — but the node's docstring (`:420-430`) does not say it is out-of-node. Review finding **F5**, not folded | minor | one sentence in the test docstring at close. **The clause itself is discharged**; only its labelling is missing |
| **G-002** | LLR-072-5.2 | `#legend_body { overflow: hidden }` is **pinned by nothing** — reverting it to `overflow-y: auto` leaves 8 nodes green (review **F4**, executed). Self-reported in Inc-1 §5 and Inc-2 §6 before the review confirmed it | minor | backlog with the measurement, or one line in TC-518's stylesheet scan. Symptom (three nested scroll contexts) is invisible at current content sizes |
| **G-003** | LLR-072-6.1 | `on_mount`'s width argument is **unpinned**: mutating *only* `on_mount` to `self.size.width` leaves all nodes green, because a `Resize` arrives right after mount and `on_resize` re-applies the correct regime. Mutating `on_resize`, or both, correctly reddens TC-516 **and** TC-517. Review **F3** | minor | optional; the requirement singles this detail out (`:339`) and half of it is unguarded. Code is **correct** — this is a coverage note |
| **G-004** | HLR-072-1 / HLR-072-2 | **The CRC screen is unmeasured and unpinned at the 80x24 floor.** `00-measurements.md` records no CRC-screen floor measurement and no node adds one. The Self-test row is tight at 120x30 (label 13 + `123456789` 10 + verdict; `○ NO-EXPECTED` is 13 chars, and the `Invalid parameters: …` fault string is long) | minor | bounded: the verdict is a height-auto `Static` inside a `.crc-field-row`, so an overlong string **wraps** rather than truncating — the M-4 silent-truncation mode does not apply. Backlog a floor measurement |
| **G-005** | HLR-072-3 | **AT-214 and TC-514 coincide with AT-213 today.** Only 2 `Switch` widgets exist and both are in the pair row, so G-1 currently polices exactly the pair AT-213 already asserts | minor, **openly stated** | this is the requirement's own admission (HLR-072-3 scope note). What makes it a guard rather than a duplicate is that the subject set is **derived**: a third `Switch` on this screen is policed with no test edit, and TC-514 reddens the moment one is constructed elsewhere |
| **G-006** | HLR-072-5 | **AT-216 has one row of slack** — key content is 14 rows in a 15-row pane for both mac and map. One extra key row, one reworded meaning that wraps, or a key pane narrower than 43 cols pushes the map key past the fold | minor | already mitigated at the **cause** by cl.3 (`max_scroll_y == 0`), which fails before the symptom appears. Keep as a known tripwire |
| **G-007** | US-072-3 scope | For **four** of the six `_recompute` sinks, this batch's AT observes the **markup flag**, not the rendered value; their content oracles are pre-existing batch-58/59 nodes (§4.3) | informational | correct for a markup-safety story; recorded so a later reader does not over-read AT-219's coverage |
| **G-008** | repo hygiene | `ruff format --check` reports both touched test files would be reformatted — **identically at HEAD with the changes stashed**. Pre-existing drift; `ruff format` is not enforced by CI | informational | stated, not fixed (out of scope). `ruff check` → `All checks passed!` |

### 10.1 Owed at close (carried, not dropped)

1. `BACKLOG-CODE.md` **line 153** — the CRC-snapshot claim is measured **FALSE** (P-2). Correct it.
2. Backlog entries owed with their measurements attached: **W-1** (`Select` affordance density — the
   measured lever is pane *width*, not height), **G-2** (the retired `Switch` state-word legibility
   guarantee, §6.5 R-1), **G-3** (the pre-existing **2.54:1** hero-extent ratio against a 6:1 law —
   a violation this batch neither causes nor worsens). All three are already recorded in
   `REQUIREMENTS.md` `R-TUI-100`'s *"deliberately does NOT claim"* block.
3. G-001..G-003 above (the unfolded LOW review findings).
4. Escape-key dismissal of `LegendScreen` does not work — **pre-existing**, measured at `tabs=0`;
   `BINDINGS = ['tab','shift+tab','ctrl+c']`. Noted only so it is not mistaken for new.

### 10.2 Escaped-bug regression

**None.** No defect escaped the suite into a shipped surface during this batch. Two in-batch defects
were caught by the batch's own controls and are recorded rather than smoothed over:

| Defect | Caught by | Pre-fix RED kind | Post-fix |
|---|---|---|---|
| AT-216 did not observe the wide regime's defining property (side-by-side) | the independent Inc-1/2 code review's **executed** mutation (CF-2), not by reasoning | **value** — the wide regime measurably stacked (`card y=6` / `key y=13`) while 8 nodes stayed green | AT-216 **clause 0** added at `0169108`; verified RED on the mutation, GREEN on the baseline (`70 >= 70`, `6 == 6`) |
| TC-518's `height: auto` scan was whitespace-exact and probed only the floor | same review (**F2**) | **value** — `height:auto` (no space) in the *wide* rule passed both arms | regex `height\s*:\s*auto` + a 120x30 live-unit arm; verified on disk at `tests/test_legend_two_pane.py:665, 684` |

---

## 11. Exit-criteria verdict — Coverage / Certainty / Evidence

| Axis | Bar | Verdict | Basis |
|---|---|---|---|
| **Coverage** | Every HLR in force has an AT that observes its outcome through the shipped surface; every LLR has a TC; every named input driven and every named output observed | ✅ **MET** | 7/7 ATs and 11/11 TCs reconciled to distinct real nodes (§2, §4); 13/13 inputs and 21/21 outputs (§6). The one axis that was genuinely uncovered — the wide regime's side-by-side property — was found by **execution** and closed before the gate (§10.2) |
| **Certainty** | The green is not vacuous: each declared tooth is shown to be the tooth, and the pins are labelled | ✅ **MET** | 4 counterfactuals + AT-219's gate arm, each RED on its own assertion line with before/mutated/restored evidence (§3); 15 further falsification runs in the independent review's per-node table; the two pins declared as pins in the requirement, the test docstrings **and** §5. AT-214's counterfactual additionally carries a control arm and an in-run tree-of-record header — the check the sibling increment lacked |
| **Evidence** | Every number read from a run's own output; the ledger reconciles; frozen guards and premises re-checked | ✅ **MET** | Gate run `GATE_EXIT=0`, `2370+2+21+3 = 2396` = measured collection = `2379 − 1 + 18` (§8); frozen set absent from the diff and both guard arms green; snapshots `29 passed / 0 regenerated` with the snapshot-path diff **empty**, re-executed here (§9); every AT/TC id in this artifact verified by `--collect-only`, and every `file:line` re-read from disk |

> **Overall: PASS.** No blocker, no unmet axis. The residual items in §10 are minor/informational and
> are carried, not dropped.
>
> **The single most important thing this batch learned is not a test result: it is D-1.** The batch
> falsified one of its own spec constants by succeeding at the refactor that constant described. The
> right response was neither to ship a RED test nor to re-pin the number, but to assert the invariant
> the number was standing in for. §9.1.

---

## 12. Evidence checklist — qa-reviewer (full)

- [x] **Acceptance criteria use Given/When/Then** — ✅ equivalently: `01-requirements.md` states each
      AT as *pilot at `<size>`, reached through `<binding>` (Given) → drive `<input>` (When) → assert
      `<observable>` (Then)*, e.g. AT-213 cl.3 (`:146-149`), AT-215 cl.3 (`:171-175`). The project's
      house form is AT/TC clauses, kept for consistency (rule 11).
- [x] **Test cases have explicit Expected, not vague "works"** — ✅ every threshold in §2 and §4 is a
      literal: `0xCBF43926 → 0x1898913F`, `max_scroll_y == 0`, `card_height >= 2`, mac `(17,6)` /
      map `(20,7)`, `Unit.FRACTION`, `len(tuple) >= 6`, `wrappers == 0`.
- [x] **Edge cases include empty, boundary, invalid, error** — ✅ empty: `query("#crc_live_verify")`
      → 0 (AT-215 cl.4), the expected-empty census site (TC-516). boundary: the 80x24 floor
      (AT-217, TC-517/518/520), `card_height >= 2`, the 14-in-15 row budget. invalid: a bogus id in
      the census tuple (AT-219 cl.2); the `Invalid parameters` and `NO-EXPECTED` near-misses
      **explicitly excluded** (AT-215). error path: `_recompute`'s `NoMatches` early return observed
      as surface immobility.
- [x] **Regression checklist exists** — ✅ §7 (supersession), §5 (the two pins), plus the declared
      blast radius `test_crc_designer_view.py` / `test_tui_legend.py` / `test_legend_n8.py` /
      `test_legend_scope_and_logwidth.py` / `test_legend_two_pane.py`, re-run green at every increment
      gate (**108 passed** at Inc-4) and inside the Phase-4 run.
- [x] **Exit criteria stated** — ✅ §11, per axis, with the basis for each.
- [x] **No real PII / secrets** — ✅ this artifact contains test ids, hashes, geometry and command
      output only. Host paths appear as `<worktree>` / `<scratchpad>`. No credentials, tokens or
      env-file content.
- [x] **Test results left blank unless actually run** — ✅ every result here is transcribed from a run
      **someone actually executed**, attributed to its owner: the Phase-4 gate run to the
      **orchestrator** (C-25), CF-1/CF-4 to Inc-1/Inc-2, CF-2 to the orchestrator's F1 fold,
      CF-3/CF-3b to Inc-4, the 15-row falsification table to the independent code review. **This
      phase re-ran nothing but short reconciliation commands**, each shown with its output in §1 and
      §7.
- [x] **Layer B (black-box): every output-producing story's deliverable observed through the SHIPPED
      surface with boundary + negative evidence** — ✅ §4.1. `pilot.press("0")` for all four CRC ATs;
      the ratified `k` binding for all three legend ATs; no `.focus()` proxy anywhere (C-16). Every
      AT carries a boundary and a negative column, and none is white-box-only.
- [x] **Bidirectional surface-reachability** — ✅ §6: 13/13 inputs driven through the handler, 21/21
      named outputs observed. The six `_recompute` ids (P-4) are itemised in §4.3, including the
      honest limit on four of them.
- [x] **No unfilled template** — ✅ no `<...>`, no `TC-NNN`, no empty required row. Every row cites a
      real node id, a `file:line` re-read from disk in this phase, or executed command output.

---

### Appendix — provenance of every id used in this artifact

```
$ python -m pytest tests/test_legend_two_pane.py tests/test_crc_designer_view.py --collect-only -q
… tests/test_legend_two_pane.py::test_at216_key_pane_shows_warning_row_without_scrolling
  tests/test_legend_two_pane.py::test_tc515_panes_hold_the_unmodified_render_output
  tests/test_legend_two_pane.py::test_tc516_legend_body_is_the_two_pane_wrapper
  tests/test_legend_two_pane.py::test_at218_pipeline_preserved_regression_pin
  tests/test_legend_two_pane.py::test_at217_floor_stacks_key_above_card_and_key_is_reachable
  tests/test_legend_two_pane.py::test_tc517_width_regime_flips_class_and_pane_order
  tests/test_legend_two_pane.py::test_tc518_key_pane_never_uses_height_auto
  tests/test_legend_two_pane.py::test_tc519_legend_module_unchanged_vs_main
  tests/test_legend_two_pane.py::test_tc520_legend_focus_traversal_is_pinned_in_both_regimes
  tests/test_crc_designer_view.py::test_reflection_pair_row_shares_one_band_and_drives_the_kernel
  tests/test_crc_designer_view.py::test_kat_verdict_demoted_to_self_test_row_under_check
  tests/test_crc_designer_view.py::test_recompute_surface_ids_are_the_live_markup_census
  tests/test_crc_designer_view.py::test_reflection_row_structure
  tests/test_crc_designer_view.py::test_orphaned_per_toggle_helper_is_deleted
  tests/test_crc_designer_view.py::test_hero_right_column_holds_warnings_only
  tests/test_crc_designer_view.py::test_retired_hero_selectors_absent_from_stylesheet
  tests/test_crc_designer_view.py::test_at214_no_two_switches_render_vertically_abutting
  tests/test_crc_designer_view.py::test_tc514_every_switch_construction_site_is_on_the_crc_designer

49 tests collected in 0.30s
```

All **18** nodes this batch adds are present; none of the 18 ids cited above is absent from the
collection. The CRC file's node names are descriptive rather than `at213`-prefixed — each carries its
`AT-`/`TC-` id in its docstring's first line, verified by grep at the line numbers given in §2 and
§4.1.
