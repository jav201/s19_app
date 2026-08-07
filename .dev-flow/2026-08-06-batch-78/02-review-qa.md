# Phase 2 — cross-agent review, **qa-reviewer lane** — batch `2026-08-06-batch-78`

**Under review:** `.dev-flow/2026-08-06-batch-78/01-requirements.md` (804 lines, 31 `AT-B78-nn`, 45 `TC-B78-nn`, 13 increments)
**Axis:** testability — whether these acceptances can actually fail.
**Repo:** `C:\Users\jjgh8\Github\s19_app` · branch `claude/batch-78-cmdbar-a2bdiff` @ `544f16b`
**Method:** every finding below is executed. All mutations were applied **in-process** (monkeypatch / subclass) from an out-of-repo scratchpad with `PYTHONDONTWRITEBYTECODE=1`, and reverted in the same process with the predicate re-run. **`git diff --stat -- s19_app/ tests/ .dev-flow/` is empty** — no tracked file was modified by this lane. `state.json`, `PLAN.md`, `00-measurements.md`, `01-requirements.md`, `AT-TC-REGISTRY.jsonl` and `prototypes/memmap2.*` were **read only**.

---

## BLUF

**1 blocker · 6 major · 8 minor.** The document is unusually strong on falsifiability discipline — six of its most dangerous predicates are genuinely sound and I reproduced their discharges to the digit. The residue concentrates in three places:

| # | The shape | Instances |
|---|---|---|
| **1** | **The F-6 defect it fixed has a live sibling it did not look for** — `AT-B78-22` reads its expected value from `AbDiffPanel.DISPLAY_CONTEXT_BYTES`, the class under test, and is **executed-INERT under a 4× mutation of it**. A second sibling is already **on disk** in the file `Inc-2` edits. | Q-M1, Q-M2 |
| **2** | **Four predicates whose named mutation does not redden the predicate as worded** — the mutation was named but never executed, and when executed it leaves the predicate green. | Q-M4, Q-M5, Q-m1, Q-m2 |
| **3** | **Two "derived" sets that are not derived** — the `OWNING == 3` set has no stated derivation and the two honest derivations disagree (7 vs 3); the delete-symbol set disagrees with itself (six vs seven) in adjacent sections. | Q-M3, Q-m4 |

Plus one plan-level blocker: **`Inc-9` schedules four AT arms that cannot go green until `Inc-10` lands**, confirmed by re-executing the vertical ladder.

**Would any acceptance false-fail a correct implementation? Yes — four.** `LLR-126.1`'s *"none truncated"* is **already false on `origin/main`** (7 of 14 chips painted at 80×24); `assert len(OWNING) == 3` fails under the obvious tree derivation (7); `HLR-124`'s *"the literals … appear 0 times in the tests"* is already false (`94`×1, `29`×4 in `tests/test_tui_directionb.py`); and `AT-B78-11`'s `== 7` fails a conforming implementation that *reduces* the status-bar height.

---

## 1 · BLOCKER

### Q-B1 · `Inc-9` schedules four AT arms that require `Inc-10`'s work

**§7 Inc-9** realizes `AT-B78-04…07`, **`AT-B78-24`**, **`AT-B78-25` (fallback)**, **`AT-B78-27`**, `AT-B78-29`, and its own content is **HLR-119** (re-home `/`·`g`). But:

- `HLR-125`'s Statement: *"at a terminal of **120×30 with the command-bar row removed**, the hex windows **shall** render at least one hex row of content."*
- The command-bar row is removed by **`HLR-118` = Inc-10**, which the table places **after** Inc-9.
- Inc-9's own cell admits the dependency in prose — *"which need S-8 **and** the bar's rows"* — and then schedules them anyway.

**Re-executed vertical ladder** (S-8 simulated as `styles.height = 1` on the three control rows, S-1 as `display = False` on `#command_bar_row`, a 6-run comparison rendered, `#diff_hex_a` measured as `size.height` = content and `region.intersection(#screen_diff.region).height` = clipped):

```
(120, 30)  CONTENT rows: [0, 0, 2]    CLIPPED rows: [0, 4, 6]     (shipped / S-8 / S-8+S-1)
(132, 44)  CONTENT rows: [7, 13, 16]  CLIPPED rows: [11, 17, 20]
(80, 24)   CONTENT rows: [0, 0, 0]    CLIPPED rows: [0, 0, 1]
```

This reproduces the orchestrator's figures **exactly** (120×30 → 0/0/2; 132×44 → 7/13/16; 80×24 → 0 throughout). The document's measurement is right; its **plan contradicts it**. At Inc-9 the 120×30 content height is **0**, so:

| AT arm at Inc-9 | Can it go green at Inc-9? |
|---|:-:|
| `AT-B78-27` — "≥1 emitted hex row at 120×30" | ❌ 0 content rows |
| `AT-B78-24` — the 120×30 arm (`size.width >= 79` **and** clipped-width co-assertion) | ❌ the window is not painted |
| `AT-B78-25` — the fallback arm (list costs 0 permanent rows, viewport paginates) | ❌ no visible viewport |
| `AT-B78-29` — the 80×24 notice | ✅ 80×24 fails width regardless of the bar |

**Why this is a blocker and not a scheduling nit:** a gate that cannot pass is resolved in practice by weakening the acceptance or `xfail`-ing it, and this project has shipped exactly that failure twice (batch-76's four vacuous acceptances). The document's whole D-15/R-4 argument — *Lane 2 first because Lane 1 drifts 29 goldens* — survives the fix.

**Fix (mechanical):** move `AT-B78-24`'s 120×30 arm, `AT-B78-25`'s fallback arm and `AT-B78-27` to **Inc-10** (or a new `Inc-10b` after the deletion), leaving `AT-B78-29` at Inc-9. Restate Inc-9's gate as *"per-arm verdicts at 80×24 / 132×44 / 160×40; the 120×30 arms are owed at Inc-10."*

---

## 2 · MAJOR

### Q-M1 · `AT-B78-22` is a live sibling of F-6 — **executed INERT**

`HLR-123`'s Statement and threshold: *"the rendered window **shall** always include the selected run's bytes plus `DISPLAY_CONTEXT_BYTES` of context on each side"* / *"the emitted span covers `[start − DISPLAY_CONTEXT_BYTES, end + DISPLAY_CONTEXT_BYTES)`"*.

The expected value **is** `AbDiffPanel.DISPLAY_CONTEXT_BYTES`, read from the class under test. §5.3's own transcript cell says so out loud — *"derived from the constant today"* — and still verdicts it **GATE**.

**Executed** (probe drives `render_comparison` at 132×44 over a single run `0x1000–0x1004`, parses the emitted row addresses out of `#diff_hex_a`, builds the expectation from the constant exactly as worded):

```
PRE   ctx=16 green=True  want=['0xff0','0x1000','0x1010']                             emitted=['0xff0','0x1000','0x1010']
MUT   ctx=64 green=True  want=['0xfc0','0xfd0','0xfe0','0xff0','0x1000','0x1010',
                               '0x1020','0x1030','0x1040']                             emitted=[identical]
POST  ctx=16 green=True
VERDICT: INERT (mutation left it GREEN)
```

`DISPLAY_CONTEXT_BYTES 16 → 64` — a **4× change to the very quantity the requirement is about** — leaves the predicate green, because the fixture expectation and the implementation move together. This is F-6's shape verbatim, in the requirement immediately after the one where F-6 was found and fixed.

It is also mislabelled: `AT-B78-22` is red today only because run 3 cannot be selected. Its **own** clause is unfalsifiable. Per §1.3's definition it is a PIN riding on `AT-B78-20`'s redness.

**Fix, mirroring `LLR-122.3`'s own rewrite:** fix the expected span to a **literal independent of the constant** (`0x0FF0`, `0x1000`, `0x1010` for a run at `0x1000–0x1004`), and put the constant in a **guard** only — `assert AbDiffPanel.DISPLAY_CONTEXT_BYTES == 16, "re-derive the fixture"`. C-39's *"quote the constant, never its value"* applies to the guard, not the expectation — the document already states this rule at §5.1 rule 4 and then does not apply it here.

### Q-M2 · A second inert cap guard is **already on disk**, in the file `Inc-2` edits, and the document never names it

`tests/test_tui_diff_screen.py:284` `test_tc029_display_caps_bound_on_screen_runs` — a **LIVE** registry node — is the F-6 shape verbatim:

```python
over = AbDiffPanel.DISPLAY_MAX_RUNS + 50            # fixture reads the constant
...
assert n_displayed <= AbDiffPanel.DISPLAY_MAX_RUNS  # expectation reads the constant
```

**Executed, same in-process mutation the document used for `AT-B78-18`:**

```
PRE  DISPLAY_MAX_RUNS=   128   AT-B78-18 green=True (128,(128,200))  |  shipped tc029 green=True (over=178,  stored=128)
MUT  DISPLAY_MAX_RUNS=100000   AT-B78-18 green=GUARD-FIRED           |  shipped tc029 green=True (over=100050, stored=100000)
POST DISPLAY_MAX_RUNS=   128   AT-B78-18 green=True (128,(128,200))  |  shipped tc029 green=True (over=178,  stored=128)
```

`test_tc029` **stays GREEN under `128 → 100000`** — it certifies the constant, not the capping. `HLR-122`'s Statement says *"the display caps and the 'showing N of M' notice **shall** be preserved"*, and `LLR-125.1` explicitly instructs the implementer to *"check for duplication before minting a new node"* against the neighbouring `tests/test_tui_diff_screen.py` nodes. So the batch will land a hardened `AT-B78-18` beside an inert `test_tc029` guarding the same clause, in the same file, in the same increment — and a future reader will reasonably take the older node as coverage.

**Fix:** name `test_tc029` in `LLR-122.3` with an explicit disposition — either rewrite it to the `AT-B78-18` form in `Inc-2`, or carry it (`C-78-g`) with the executed transcript above as evidence. Do not leave it undispositioned.

### Q-M3 · `OWNING` is not a derived set — the derivation is unstated and two honest derivations disagree (7 vs 3)

§5.1 rule 3 and `HLR-119`'s Acceptance both claim: *"the owning set is **computed in the test body** from the tree (C-31) with `assert len(OWNING) == 3` as a completeness guard — a universal over an emptied query is otherwise vacuous."*

But `P-10` establishes that **nothing unmounts**: every input resolves on every screen. So "from the tree" must mean a per-screen-container query — and the document never states the pattern.

**Executed** — three candidate derivations, per `SCREEN_CONTAINER_IDS` container:

```
derivation  any Input                           -> n=7  ['a2l','crc_designer','diff','flow','mac','patch','workspace']   len==3 guard: FAIL
derivation  id ~ (search|goto)_input$           -> n=3  ['a2l','mac','workspace']                                        len==3 guard: PASS
derivation  id contains 'find' or 'search'      -> n=3  ['a2l','mac','workspace']                                        len==3 guard: PASS
```

Two consequences, both real:

1. **The obvious derivation gives 7, and `assert len(OWNING) == 3` would false-fail it.** The A2L screen alone carries four inputs (`a2l_tag_find_input`, `a2l_tags_filter_input`, `alt_goto_input`, `alt_search_input`); patch carries five; `crc_designer` carries thirteen.
2. **Any derivation that yields 3 is an id whitelist** — i.e. `LLR-119.1`'s implementation map, inverted. `AT-B78-04` iterates `OWNING` and `AT-B78-05` iterates its 7-screen complement, so **both partitions come from the artefact under test**. If the implementation misclassifies one screen in each direction, `len` stays 3, both ATs iterate the wrong sets, and both stay green while wrong. That is C-40 limb 2's exact failure mode, and the `len == 3` guard does not close it.

This project's own control applies verbatim: *an unstated grep pattern is an unstated definition.*

**Fix:** state the pattern in the AT — *"a screen owns find/goto iff `app.query_one(f'#{container}').query(Input)` yields an id matching `(search|goto)_input$`"* — assert the resulting set **equals** `{workspace, a2l, mac}` **and** that its union with the notice set equals `SCREEN_CONTAINER_IDS.keys()` (which `LLR-119.1` already asserts). Keep `len == 3` as a redundant guard, not as the guard.

### Q-M4 · `AT-B78-28` — the named mutation does not redden the predicate, and the observable is the wrong layer

`LLR-126.1` / `HLR-126` threshold: *"`app.active_bindings` filtered on `.show and .enabled` **still contains all 14** pre-existing chips at 80×24, **none truncated**."* §5.3's mutation column: *"add a `show=True` binding"*; its transcript column holds a **census**, not a transcript — the mutation was never executed.

**Executed** (mutation applied via an `S19TuiApp` subclass adding `Binding("ctrl+alt+z", "probe_chip", "ProbeChip", show=True)`; a first attempt with `ctrl+y` silently failed to apply because that key is already bound — recorded so the negative is not mistaken for a result):

```
BASE chips(model) = 14  ['ctrl+k','ctrl+d','ctrl+l','ctrl+s','slash','g','q','x','k','question_mark','plus','minus','comma','period']
MUT  chips(model) = 15   applied = True
predicate as specified — "still CONTAINS all 14"  -> True     <-- NOT reddened
set-EQUALITY form                                 -> False    <-- would redden
```

**A containment predicate is satisfied by a superset.** The mutation the document names is precisely the one the predicate cannot see.

**And the layer is wrong.** `active_bindings` is the binding model; the requirement's claim (*"undisplaced"*, *"none truncated"*, D-2's *"would contend with the measured 14 chips in 78 columns"*) is about painted Footer real estate. Measured at the painted layer:

```
80x24  Footer.size.width = 78   Footer child widgets = 15
       children FULLY PAINTED inside the width = 7   ['ctrl+k','ctrl+d','ctrl+l','ctrl+s','slash','g','q']
       (the remaining chips are laid out at x = 68, 82, 92, 100, 109, 118, 126 — beyond 78)
120x30 Footer.size.width = 118  children fully painted = 14
```

So at 80×24 the Footer is **already over-subscribed on `origin/main`: 7 of 14 chips are painted.** Two effects:

- **False-fail risk (real).** An implementer who reads `"none truncated"` honestly — at the painted layer, which §5.1 rule 1 tells them to do — gets **7 ≠ 14 and fails a correct implementation on the unmodified tree.**
- `C16` / `P-51` are a *model* count presented as a *real-estate* budget. D-2's conclusion (do not add an App chip) is unaffected — it is more right, not less — so this is an acceptance defect, not a decision defect.

**Fix:** (a) make the predicate **set-equality** on the `show and enabled` key set, not containment; (b) restate the second clause at the layer that holds the fact — *"the count of Footer children whose region lies wholly inside `Footer.size.width` at 80×24 is **unchanged at 7**"* — and record 7 as a measured baseline, not 14; (c) execute the `show=True` mutation and paste the transcript.

### Q-M5 · `AT-B78-19` is **GREEN today** with an unsatisfiable precondition — labelled GATE, mutation "none needed"

§5.3: `AT-B78-19` | *"App keys survive off-list focus"* | mutation **"none needed"** | transcript *"`j`/`p` frozen, `k` show=True"* | verdict **GATE**.
`HLR-122`'s AT list: *"anti-shadow: **with the list focused**, `k` still opens the legend and `j` still reaches its App action."*

**Executed** at 132×44 with a 6-run comparison rendered:

```
run list type = Static   can_focus = False
app.focused after set_focus(#diff_range_list) = RailItem(id='rail_item_workspace')
after 'k': screen_stack 1 -> 2   top = LegendScreen
```

`set_focus` on the run list **silently does not take** — focus lands on a rail item — and `k` opens the Legend anyway. The predicate is **green today with its precondition false**. It is therefore:

- not a gate by §1.3's own definition (*"a gate can go RED under a named, executed mutation of its declared subject"*) — the transcript cell is a census, not a transcript;
- green for a reason that has nothing to do with its subject — the exact shape the project's *counterfactual must fail on its ASSERTION* control closes;
- **missing the precondition assertion the document itself mandates elsewhere.** `LLR-119.4` requires every HLR-119 focus AT to `assert app.focused is None` before a key press. `AT-B78-19` needs the mirror-image assertion and does not have it.

**Fix:** add `assert app.focused is <the run list>` as a precondition (it will fail today, correctly — this is a Phase-3 AT), relabel as **PIN**, and name its real discharging mutation: *add `Binding("k", …)` to the run list's `BINDINGS` and confirm the legend no longer opens*. Owed at `Inc-2`'s gate.

### Q-M6 · C-18 — one AT pair is forced onto a single node, one AT is realized "in parts", and no on-disk node is named for any of the 31 ATs

C-18: *"Each AT maps to exactly **one distinct** on-disk test node exercising the full chain; 'covered in parts' = unrealized."*

Three findings, in descending severity:

1. **`AT-B78-26` and `AT-B78-27` must share one node — and are assigned to different increments.**
   `LLR-125.2` Acceptance: *"asserted in the **same test** as `LLR-125.1`."* §5.3: *"`AT-B78-27` … asserted in the same run as `AT-B78-26`."*
   §7: `Inc-1` realizes **`AT-B78-26`**; `Inc-9` realizes **`AT-B78-27`**.
   These cannot both hold. If they share a node, `Inc-1`'s gate runs a node containing `AT-B78-27`'s clause, which per Q-B1 is red until `Inc-10` — so **`Inc-1`'s gate cannot pass**. If they are separate nodes, `LLR-125.2`'s C-40 co-assertion (*"separated, the height assertion is invariant under an implementation that compacts the rows and still leaves the result area at zero"*) is violated, and per-node CC-1 verdicts become impossible for the pair either way.
   **Fix:** make it **one** AT with two clauses (`AT-B78-26` absorbing 27), landing whole at `Inc-10`; retire the id 27, or reallocate it.

2. **`AT-B78-25` is realized in parts.** §7: `Inc-5` → *"`AT-B78-25` (wide arm)"*; `Inc-9` → *"`AT-B78-25` (fallback)"*. Its declared subject — *"the regimes are **observably different**"* — is inherently a comparison across both regimes and cannot be exercised by either arm alone. Neither increment's gate observes the AT. **Fix:** land `AT-B78-25` whole at the later increment; give `Inc-5` a narrower id for the wide layout.

3. **The document names zero on-disk test nodes.** `grep '::' 01-requirements.md` → **0 hits**; no `def test_…` anywhere. The AT→artefact mapping stops at the *file* level (§7's Files column). C-18 is therefore undischarged for all 31 ATs at Phase 1. This is defensible as a Phase-3 obligation, but §9's checklist claims *"Two-layer requirements: Acceptance block + AT, both chains ✓ … zero orphans"* without stating that node allocation is deferred. **Fix:** one line in §5.1 — *"C-18 node allocation is owed at each increment's gate; one distinct node per AT id"* — plus the two structural fixes above.

---

## 3 · MINOR

| # | Finding | Evidence |
|---|---|---|
| **Q-m1** | **`AT-B78-03`'s named mutation is inert.** §5.3 gives its reddening mutation as *"as `AT-B78-02`"* (`action_focus_palette` body → `None`). Executed: the palette **action set is invariant** under it. It is labelled a PIN, so nothing is over-counted — but the table asserts a reddening mutation that does not redden. **Fix:** name a mutation on the *set's producer*, e.g. drop `focus_find` from `S19TuiApp.BINDINGS` and confirm 37 → 36. | `PRE 10/10 open, n=37` · `MUT 0/10 open, n=**37**` · `POST 10/10 open, n=37` |
| **Q-m2** | **`AT-B78-18`'s recorded transcript is not of the specified predicate.** `LLR-122.3` specifies a `assert 200 > DISPLAY_MAX_RUNS` **guard**. Executed with the guard in place, the `128 → 100000` mutation is caught by the **guard's `AssertionError`**, never reaching the assertion; §5.3's recorded `RED (rendered_rows=200, notice=None)` can only come from a **guard-less** form. Both forms redden, so the AT is **not vacuous** — but the discharge was executed against a different predicate than the one specified, and this project's own control (*a counterfactual must fail on its assertion*) says which one counts. **Fix:** place the guard **after** the capture, or record both transcripts. | `MUT … AT-B78-18 green=GUARD-FIRED "guard: fixture must exceed the cap"` |
| **Q-m3** | **The `AT-B78-12` digest triple is not re-derivable.** `0a159da97fa81714 → 9d6c9b6aeadac6fa → 0a159da97fa81714` appears four times across the two documents with **no hash function, no payload serialisation and no fixture** stated anywhere. §5.3's own "Restore proof" paragraph argues *"a hash alone would not prove this"* — and then this row's entire discharge **is** a hash triple. The direction is sound (the middle digest differs, so the mutation applied and the predicate is sensitive). Separately: `find_string_in_mem` is the module-level import used by all three `_handle_search*` paths (`app.py:11468`, `:11559`, `:11609`), so the mutation reaches the **search** half of the 9-row payload on all three screens — the **go-to** half is undischarged. **Fix:** state the recipe; add a second mutation on `_handle_goto`'s address parse. | grep over both docs: 4 occurrences, 0 recipes |
| **Q-m4** | **The delete-symbol set disagrees with itself.** `HLR-121` threshold: *"an AST census finds **0** definitions of the **six** symbols (today 1 each)"*. `LLR-121.1` threshold: *"**0** for the **seven**"*. §5.4: *"✅ **7** symbols present"*. Executed AST census over `s19_app/` (75 modules, `command_bar.py` present): the delete set is **7**, one definition each; `PaletteAction`, `action_focus_find`, `action_focus_goto` each 1 (correctly preserved). This is §10.3's own lesson landing inside the document that records it: *a census whose count and whose enumeration come from different patterns has measured neither.* Also: the census must be **class-qualified** (`CommandBar.Find` / `.Goto`) — a bare-name AST census on `Find`/`Goto` would false-fail the day any module defines those names. | `Find 1 · Goto 1 · on_command_bar_find 1 · on_command_bar_goto 1 · focus_find 1 · focus_goto 1 · set_context_labels 1` |
| **Q-m5** | **`HLR-124`'s literal-count threshold is unscoped and already false.** *"the literals `139`, `94`, `29` and `26` appear **0** times in the tests."* `LLR-124.1` scopes it to *"the acceptance tests"*; `HLR-124` does not. Executed over the C-34 gate suite: `tests/test_tui_directionb.py` already contains `94` ×1 and `29` ×4. As worded at HLR level the threshold **false-fails on `origin/main`**. `26` is additionally a poor sentinel — a two-digit integer that any address, range or size can produce. **Fix:** scope to *"the new `AT-B78-*` / `TC-B78-*` nodes"* and drop `26` in favour of asserting `size.width` against a computed value. | `test_tui_diff_screen.py: 0/0/0/0` · `test_tui_directionb.py: 139→0, 94→1, 29→4, 26→0` |
| **Q-m6** | **`AT-B78-11` is green today (labelled GATE) and its threshold is stricter than its requirement.** `LLR-120.3`: *"**shall not increase** its rendered height"*; `AT-B78-11`: `size.height == 7`. Executed: `#workspace_status_bar` is **7 on all 10 screens at both 80×24 and 120×30** — so the predicate passes on the unmodified tree, its named mutation (*"set the new label to its own row"*) requires the unbuilt feature and was not executed, and the transcript cell reads *"7 today"*, which is a measurement not a mutation. By §1.3 it is a **PIN with an owed mutation**, not a gate. `== 7` also **false-fails** a conforming implementation that reduces the height. **Fix:** relabel PIN, assert `<= 7` with a `== 7` note, discharge at `Inc-7`. | `{'workspace':7,'a2l':7,'mac':7,'map':7,'issues':7,'patch':7,'diff':7,'flow':7,'checks':7,'crc_designer':7}` |
| **Q-m7** | **`C7` mixes units inside one row**, three sections after F-8 records that exact hazard. *"`#diff_hex_a` **clipped** rows: 80×24 → 0 · 120×30 → 0 · 132×44 → **11** · 160×40 → **7 content**"* — `11` is clipped, `7` is content, in the same list under a "clipped" label. `#diff_hex_a` carries `border: round` + `padding: 1` (`styles.tcss:1481-1490`), so **content = clipped − 4**. Executed: 132×44 content `7/13/16` vs clipped `11/17/20`. I initially mis-read the document because of this and had to re-derive; a Phase-3 implementer will too. **Fix:** label every geometry figure with its layer, as §1.3 promises. | see Q-B1 ladder |
| **Q-m8** | **§5.3 collapses three rows and five ATs never get their own limb-1 check.** `AT-B78-15/16/17` share one row (one subject, one transcript: *"`type=Static can_focus=False`; `ListView` under `#diff_columns` = 0"*), as do `AT-B78-23/24` and `AT-B78-26/27`. `AT-B78-16` (mouse-only, off-viewport) and `AT-B78-17` (resolved style triple, ≥2-row guard) have materially different subjects and observables from `AT-B78-15`, and neither is checked against its own expression. Given §5.1 rule 7 mandates **per-resolved-node-id** verdicts (CC-1), the falsifiability table should be per-id too. **Fix:** split the three rows into eight. | §5.3 lines 600, 606, 608 |

---

## 4 · Verified **SOUND** — what I executed and found correct

These were re-executed independently, not read.

| Claim | Executed result |
|---|---|
| **C3 / P-31** — the diff panel's emitted hex row is **79**, not 81 | `render_hex_view` max = **79** · `render_hex_view_text` max = **81`. F-1 is correct. |
| **P-39 / D-3** — the palette action set is **37** and contains `focus_find` + `focus_goto` | `_build_palette_entries()` n=**37**, 37 distinct · `visible_palette_actions()` n=**37** · both present |
| **`AT-B78-02`'s discharge** — `action_focus_palette` body → `None` | **reproduced exactly**: `PRE 10/10 → MUT 0/10 → POST 10/10`, with `set_focus(None)` + `assert app.focused is None` before each press |
| **P-33 vertical ladder** | reproduced **to the digit**: 120×30 → 0/0/**2** content · 132×44 → **7/13/16** · 80×24 → 0/0/0 |
| **P-36 / LLR-120.3 baseline** — status bar is 7 rows everywhere | **7 on all 10 screens**, at both 80×24 and 120×30 |
| **P-49 / LLR-118.3** — the deletable CSS span is `:66-102`, **not** Phase-0's `:55-102` | exact: `#command_bar_slot` `:51`, `#command_bar` `:61-64`, `#command_bar_row` `:66`, `#command_bar_prompt` `:73`, `#cmdbar_project` `:80`, `#cmdbar_a2l` `:88`, `#find_input` `:96`, `#cmdbar_goto_input` `:100-102`, `#command_palette` `:104`. The correction is right and it matters. |
| **P-37** — deleting commandbar nodes reddens G2 | 4 LIVE rows (`TC-007` 12 nodes, `TC-008` 21, `TC-009` 10, `TC-039` 2); **`TC-008` names 5** commandbar nodes. Confirmed. `TC-039` names **only 2**, both commandbar — the `A-5` empty-`nodes` transition is a live risk, correctly flagged. |
| **`LLR-121.1`'s preserve set** | `PaletteAction` 1 · `action_focus_find` 1 · `action_focus_goto` 1 — the D-3 argument (palette stays at 37 because only the `CommandBar` helpers go) holds at the source |
| **`AT-B78-18`'s rewritten cap form** | genuinely reddens under `DISPLAY_MAX_RUNS 128 → 100000` (via the guard — see Q-m2) and under the `total_runs → len(self._runs)` substitution. The F-6 rewrite **works**. |
| **§5.4 traceability arithmetic** | all **45** `TC-B78-nn` allocated across 9 HLR chains with **no duplicate and no gap**; all **31** `AT-B78-nn` allocated across 9 stories. Zero orphans, as claimed. |
| **§5.5 ID reconciliation** | the QA lane's document carries exactly **22** `AT-B78-nn`; §5.5 accounts for 22 (21 MERGED + 1 NEW). **No QA observable was dropped.** The dropped A2L-in-Loaded-panel clause is correctly marked VACUOUS (`'engine_v3.a2l' in loaded_panel → True` today). |
| **The six PINs** | `AT-B78-02, 03, 10, 12, 18, 31` — **none is a quietly downgraded gate.** Each is genuinely invariant under the change it accompanies and green on the current tree. The PIN labelling is honest. (The defects run the *other* way — see Q-M5, Q-m6, Q-M1: three GATE labels that are really PINs.) |
| **`P-51`'s chip count** | **14** exactly, and identical at 80×24 and 120×30 — the number is right; only the layer is wrong (Q-M4) |
| **Working tree** | `git diff --stat -- s19_app/ tests/ .dev-flow/` **empty**; `git status --porcelain` shows only the parallel session's untracked `prototypes/memmap2.*`, `build/`, `prototypes$f.png`, `prototypes/out/` and the security lane's `02-review-security.md` |

---

## 5 · Answers to the five specific questions asked

| Q | Answer |
|---|---|
| **1. Re-execute the falsifiability table; did the mutations apply and did the predicate go red on its own assertion?** | Of the **6** rows claiming an executed mutation, **2 reproduce cleanly** (`AT-B78-02`, `AT-B78-18`), **1 is inert** (`AT-B78-03` — set stays 37), **1 is unverifiable** (`AT-B78-12` — digest with no recipe), **2 are owed** (`AT-B78-10`, `AT-B78-31`, honestly labelled). Of the **4** rows naming an *un-executed* mutation, **1 does not redden the predicate as worded** (`AT-B78-28`) and **1 has an empty transcript cell** (`AT-B78-25`: mutation *"force one regime for all widths"*, transcript `—`). `AT-B78-18` reddens through its **guard**, not its assertion (Q-m2). |
| **2. C-40 limb 1 on every GATE — is the declared subject in the predicate's own expression?** | **21 of 24 GATE-labelled ATs pass.** Three fail: `AT-B78-22` (subject *is* the constant it reads — Q-M1), `AT-B78-19` (subject unreachable, precondition silently false — Q-M5), `AT-B78-11` (subject is *"spends no row"*, expression is a literal `7` already true — Q-m6). One partial: `AT-B78-23/24`'s *"widest emitted row"* is computed by a **fresh** `render_hex_view` call rather than read from the text `#diff_hex_a` actually emitted — two pure functions of the same input. Sound as long as the test passes the panel's own `mem_map` and `row_bases`; **strengthen** by reading the widest line out of the rendered window instead. |
| **3. C-40 limb 2 on every quantified set — is each derived, and would the guard fail if the set shrank?** | **`SCREEN_CONTAINER_IDS` (10)** ✅ genuinely rule-derived. **`R` from the fixture's run list** ✅ derived. **The 37-member palette set** ✅ producer-derived. **`OWNING == 3`** ❌ derivation unstated, two honest forms give 7 vs 3, and both `AT-B78-04` and `AT-B78-05`'s partitions come from the artefact under test (Q-M3). **The AST census set** ❌ hand-listed and self-inconsistent, six vs seven (Q-m4) — the corpus co-assertion guards the *modules*, not the *symbols*. **The 14-chip footer census** ❌ hand-listed, containment not equality, wrong layer (Q-M4). |
| **4. C-18 — does every AT map to exactly one on-disk node?** | **No.** Zero nodes are named in the document; `AT-B78-26/27` are forced onto one node while assigned to different increments; `AT-B78-25` is realized in parts across `Inc-5` and `Inc-9` (Q-M6). |
| **5. C-31 on cap tests — did any sibling of the `DISPLAY_MAX_RUNS` defect survive?** | **Two.** `AT-B78-22` in the document (executed INERT under `DISPLAY_CONTEXT_BYTES 16 → 64` — Q-M1) and `test_tc029_display_caps_bound_on_screen_runs` already on disk in the file `Inc-2` edits (executed INERT under `DISPLAY_MAX_RUNS 128 → 100000` — Q-M2). |
| **6. Are the six PINs genuinely un-reddenable, and is anything labelled GATE inert?** | PINs: **all six are honest**, none is a downgraded gate. GATEs: **three are inert or green today** — `AT-B78-11`, `AT-B78-19`, `AT-B78-22`. §9's checklist row *"Every AT demonstrated RED pre-change ✓ — 9 of 9"* is therefore **overstated**: it is 9 of 9 *stories*, not 31 of 31 ATs, and at least three ATs are green on `origin/main`. |
| **7. Does each increment's gate observe what that increment lands?** | **10 of 13 yes.** `Inc-9` cannot pass as written (Q-B1). `Inc-1`'s gate is contradicted by `LLR-125.2`'s same-node requirement (Q-M6.1). `Inc-5`'s gate observes only half of `AT-B78-25` (Q-M6.2). Notably **sound**: `Inc-0` (artifact capture in its own commit before any production edit, `git show` on the stored blob), `Inc-3` (the `runs=panel._runs` mutation executed and pasted), `Inc-8` (re-point the 16 `_project_label()` sites **while both surfaces exist**, gated on `grep -rn 'cmdbar_project' tests/ → 0`) and `Inc-11` (G1–G7 plus a zero-line diff over the six handlers) — each of those gates would go red if its work were absent. |

---

## 6 · Would any acceptance **false-fail a correct implementation**?

**Yes — four, and one of them fails on the unmodified tree today.**

| # | Acceptance | Why it false-fails | Severity |
|---|---|---|---|
| 1 | `LLR-126.1` — *"the 14 chips … **none truncated** at 80×24"* | At the painted layer only **7 of 14** chips fit in the 78-column Footer **today**. Any honest painted-layer reading fails a correct implementation. | major (Q-M4) |
| 2 | `AT-B78-04` — `assert len(OWNING) == 3` | The obvious tree derivation yields **7**. The guard fails a correct, faithfully-derived implementation. | major (Q-M3) |
| 3 | `HLR-124` — *"the literals `139`, `94`, `29`, `26` appear **0** times in the tests"* | Already false: `94`×1 and `29`×4 in `tests/test_tui_directionb.py`. | minor (Q-m5) |
| 4 | `AT-B78-11` — `size.height == 7` | The requirement says *"shall not increase"*; `== 7` fails an implementation that **reduces** the height. | minor (Q-m6) |

The document already caught one of these in itself (F-4, the phantom `(1/1)`) and states the lesson correctly — *a display form asserted without executing it*. Items 1 and 3 above are the same class, one layer over.

---

## 7 · Evidence checklist (qa-reviewer lane)

| Item | ✓/✗ | Evidence |
|---|:-:|---|
| Every claimed-vacuous AT shown vacuous **by an executed mutation that left it green** | ✓ | Q-M1 (`ctx 16→64`, green), Q-M2 (`cap 128→100000`, green), Q-M4 (`+1 show=True chip`, contains-all → True), Q-m1 (`action_focus_palette→None`, n stays 37) |
| Every mutation confirmed **applied**, not typo'd | ✓ | Q-M4 records a first attempt (`ctrl+y`) that silently did **not** apply — already bound — and the corrected `ctrl+alt+z` that did (`applied=True`, 14→15) |
| Predicates checked for reddening **on their own assertion**, not on an error | ✓ | Q-m2 (`AT-B78-18` reddens via its guard's `AssertionError`); Q-M5 (`AT-B78-19` is green with its precondition silently false) |
| Recorded digests spot-checked | ✓ | Q-m3 — not re-derivable; no hash function, serialisation or fixture stated in either document |
| C-40 limb 1 applied to every GATE | ✓ | §5, Q2 — 21/24 pass, 3 named |
| C-40 limb 2 applied to every quantified set | ✓ | §5, Q3 — 3 derived, 3 not |
| C-18 checked | ✓ | Q-M6 |
| C-31 cap-shape sweep completed | ✓ | Q-M1, Q-M2 |
| Six PINs individually assessed | ✓ | §4 — all honest; the mislabels run the other way |
| Increment gates assessed one by one | ✓ | §5, Q7 |
| False-fail risk assessed explicitly | ✓ | §6 — four, one already false on `origin/main` |
| Sound findings stated, not only defects | ✓ | §4 — 13 verified-sound claims |
| No real PII / secrets in any test case | ✓ | all fixtures synthetic (`0x1000` run tuples, `{a: a & 0xFF}` maps, `tempfile.mkdtemp()` bases) |
| Nothing modified that this lane did not create | ✓ | `git diff --stat -- s19_app/ tests/ .dev-flow/` empty; this file is the lane's only write |
| No unfilled template | ✓ | no `<…>`, no `TC-NNN`, no empty required row |

---
---

# RE-GATE — round 2 · qa-reviewer lane

**Under review:** `.dev-flow/2026-08-06-batch-78/01-requirements.md` **revision 2** (939 lines, was 804)
**Method:** unchanged — every verdict below is executed in-process from an out-of-repo scratchpad with `PYTHONDONTWRITEBYTECODE=1`, mutations reverted in the same process. **`git diff --stat -- s19_app/ tests/` is empty** and `git status --porcelain -- s19_app/ tests/` is empty: **this lane touched no source or test file.** The only file this lane has written, in either round, is this review.

## RG-BLUF

**Round 1: 1 blocker / 6 major / 8 minor. Round 2: 1 blocker / 2 major / 2 minor.**

**11 of 15 round-1 findings are fully closed and I reproduced the closures.** The four that are not share **one cause**, and it is the cause the revision created §6.4a to prevent: **revision 2's fixes landed in the LLRs and in §5.3, and were not swept into the HLR `Numeric pass threshold` lines — which are the normative text an implementer encodes.** §6.4a then asserts two of those sweeps happened. Two of my four round-1 false-fails therefore survive verbatim in the current file.

The substantive engineering is good. `AT-B78-03`'s BL-1 rewrite is the standout: the author found a **deeper** defect than I reported — not merely a wrong mutation but a *producer-derived circularity* — and I reproduced both halves exactly. The blocker fix was made the right way: **the arms were moved and three of the four came back stronger**, not softened.

**Both figures the coordinator asked me to settle go to the author. I was wrong on both.**

---

## RG-1 · Round-1 findings — closed / not closed

| # | Round-1 finding | Verdict | Executed evidence |
|---|---|---|---|
| **Q-B1** | Inc-9 schedules arms needing Inc-10 | ✅ **CLOSED** — and **not softened**, verified clause by clause (RG-2) | ladder re-executed at four sizes, reproduces §7's BL-2 block **exactly** (below). One consequence introduced → **NEW-2** |
| **Q-M1** | `AT-B78-22` inert under `ctx 16→64` | ⚠️ **CLOSED as to inertness · NOT closed as to discharge** | rewritten literal expectation is real and sensitive — emitted `['0xff0','0x1000','0x1010']` **==** the three stated literals. But the named mutation **cannot reach the assertion** → **NEW-3** |
| **Q-M2** | inert `test_tc029` on disk, unnamed | ✅ **CLOSED** | `LLR-122.3` names it, quotes my transcript verbatim, and **Inc-2's Content and gate both require the rewrite in the same increment** (*"`test_tc029` reddens under `cap 128 → 100000` after the rewrite"*). Registry impact reasoned correctly: node **name** unchanged → G2 unaffected. Carried-not-fixed was the wrong answer and it was not taken. |
| **Q-M3** | `OWNING` derivation unstated (7 vs 3) | ⚠️ **CLOSED in HLR-119 + LLR-119.1 · NOT propagated to §5.1 rule 3** | HLR-119's Acceptance now states the regex normatively, quotes my 7-vs-3 table, asserts **set equality**, demotes `len == 3` to redundant. §5.1 rule 3 (line 602) still reads *"the owning set computed in the test body with `assert len(OWNING) == 3`"* → **NEW-1 (i)** |
| **Q-M4** | Footer: containment predicate + wrong layer | ⚠️ **CLOSED in LLR-126.1 · NOT propagated to HLR-126 or C16** | `LLR-126.1` is now correct (set-equality; painted baseline 7). `HLR-126`'s threshold and AT line still say *"contains all 14 … none truncated"*; `§2.4 C16` still says *"**14** chips in a 78-column Footer"* → **NEW-1 (ii)(iii)** |
| **Q-M5** | `AT-B78-19` green with precondition false | ✅ **CLOSED** | relabelled **PIN**; `LLR-122.2`'s restored acceptance criterion adds `assert app.focused is <the run list>`; the real mutation (`add Binding("k", …)`) is named and owed at Inc-2. My round-1 transcript is quoted as the consequence of the architect lane's lost criterion — the two-directions-one-defect reading is correct. |
| **Q-M6** | C-18: one node, in parts, no nodes named | ✅ **CLOSED, all three parts** | (i) `AT-B78-27` **retired** into `AT-B78-26`, one node, whole at Inc-10, with explicit retirement lines in §5.6.3 and §5.7 (*"its id is permanently spent"*). (ii) `AT-B78-25` lands whole. (iii) **§5.1 rule 9** now states C-18 allocation is owed per increment gate and admits the document names **zero** `::` paths — re-verified: `grep -c '::'` → **0**. |
| **Q-m1** | `AT-B78-03`'s mutation inert | ✅ **CLOSED — and generalised beyond what I found** | reproduced end-to-end (RG-3) |
| **Q-m2** | `AT-B78-18` guard placement | ✅ **CLOSED for the cap AT** · not generalised to its sibling | `LLR-122.3` now evaluates the guard **after** the capture. The same lesson was not applied to the AT rewritten in the same revision → **NEW-3** |
| **Q-m3** | digest triple not re-derivable | ✅ **CLOSED** | `LLR-121.2` states the row tuple, sorted-key JSON `ensure_ascii=True`, `blake2b(digest_size=8)` over UTF-8; demotes the digest to *"a convenience, not the oracle"*; names the go-to gap and owes a second mutation at Inc-11 |
| **Q-m4** | six vs seven symbols | ✅ **CLOSED** | HLR-121's threshold now enumerates all **seven**, class-qualified, with *"executed today: 1 each, total 7"* — matching my AST census |
| **Q-m5** | literal-`0` threshold unscoped / already false | ⚠️ **CLOSED at HLR-124 · LLR-124.1 stale** | HLR-124 scoped to *"the new `AT-B78-*` / `TC-B78-*` nodes"* and drops `26`, quoting my counts. `LLR-124.1` still says *"`139`, `94`, `29`, **`26`** … 0 times in the acceptance tests"* → **NEW-4** |
| **Q-m6** | `AT-B78-11` `== 7` false-fails a reduction | ❌ **NOT CLOSED in the normative thresholds** | §5.3 says *"Threshold relaxed to `<= 7`"*. `HLR-120` (line 248) and `LLR-120.3` (line 429) **both still say `== 7`**. §6.4a does not list this change at all → **NEW-1 (iv)** |
| **Q-m7** | C7 mixes units | ✅ **CLOSED** | C7 now gives **content** `0 / 0 / 7 / 3` and **clipped** `0 / 0 / 11 / 7` separately, every figure layer-labelled — reproduces my ladder exactly. (Nit: the appended identity *"clipped = content + 4"* is false in its own first two columns, where both are 0.) |
| **Q-m8** | §5.3 collapsed 3 rows / 7 ATs | ✅ **CLOSED** | `AT-B78-15/16/17` now carry three rows with **distinct subjects and distinct observables**; `23/24` split by regime; `26` alone |

**Fully closed: 11 · partially closed: 3 · not closed: 1** (Q-m6). Every residue rolls into NEW-1, NEW-3 or NEW-4.

---

## RG-2 · The blocker fix: moved, not softened — verified clause by clause

The specific historical failure I warned about is an unsatisfiable gate resolved by weakening the acceptance. It did not happen. **Three of the four moved arms came back stronger.**

| AT | rev-1 predicate | rev-2 predicate | Verdict |
|---|---|---|---|
| `AT-B78-24` | *"no wrapped row at 132×44 and, post-US-78-8/1, at 120×30"* | **same two sizes**, plus a clipped **height ≥ 1** co-assertion (M3: *"a clipped-width-only clause is invariant under total vertical invisibility"*) | ✅ **strengthened** |
| `AT-B78-25` | split — *"(wide arm)"* at Inc-5, *"(fallback)"* at Inc-9 | lands **whole**; the AT line carries the **union** of both arms: *"at 160 the list is visible beside the window; at 120 it reserves **0** permanent columns and the viewport paginates"* | ✅ **strengthened** (C-18 satisfied) |
| `AT-B78-26` | row heights only; the joint clause lived in `AT-B78-27` | **absorbs** `AT-B78-27` — three rows clip to 1 **and** `#diff_status` visible **and** ≥1 hex row at 120×30 with the bar removed, **one node**, whole at Inc-10 | ✅ **strengthened**; `-27` explicitly retired, observable preserved |
| `AT-B78-29` | at Inc-9 | at **Inc-5**, unchanged predicate | ✅ **unchanged**, and genuinely passable there — 80×24 fails width by pure geometry (`C = 70` → window 65 < 79) with no S-8/S-1 dependency |

**Ladder re-executed at four sizes** (S-8 = `styles.height = 1` on the three control rows; S-1 = `display = False` on `#command_bar_row`; 6-run comparison rendered):

```
(160, 40)  shipped (3, 7)    S-8 only (9, 13)    S-8+S-1 (12, 16)     (content, clipped)
(132, 44)  shipped (7, 11)   S-8 only (13, 17)   S-8+S-1 (16, 20)
(120, 30)  shipped (0, 0)    S-8 only (0, 4)     S-8+S-1 (2, 6)
 (80, 24)  shipped (0, 0)    S-8 only (0, 0)     S-8+S-1 (0, 1)
```

**Reproduces §7's BL-2 block cell for cell, all twelve pairs, including the 160×40 row neither round-1 lane had measured.** The premise the move rests on is sound. `AT-B78-33`'s figures (`shipped 7 → compacted 13` at 132×44) reproduce, so **Inc-1's replacement gate is a real gate**: `13 > 7` is false today and true after Inc-1, with no Lane-1 work.

---

## RG-3 · `AT-B78-03` — the closure I most wanted to check, reproduced in full

The author's claim is stronger than my Q-m1: not just that my named mutation was wrong, but that rev-1's predicate was **structurally circular** — it compared `visible_palette_actions()` against `_build_palette_entries()`, and both read the same live `self.BINDINGS` (`app.py:5760`), so **any** change to `BINDINGS` moves both sides together.

**Executed.** Mutation = drop the `focus_find` entry from `S19TuiApp.BINDINGS`. Two earlier attempts of mine did **not** apply and are recorded so their green is not mistaken for a result: a subclass cannot remove an ancestor's binding (Textual merges the whole MRO), and an `isinstance(b, Binding)` filter misses it because `focus_find` is stored as a **tuple**, not a `Binding` — the block is mixed (`{'tuple', 'Binding'}`, n=38). Filtering on the action through the producer's own accessor applies it:

```
PRE   producer=37 observed=37   MUT producer=36 observed=36   applied=True
  rev-1 form (observed == live producer):   PRE=True   MUT=True    <-- INERT
  rev-2 form (observed == Inc-0 artifact):  PRE=True   MUT=False   <-- REDDENS
POST  producer=37 observed=37   rev-1=True   rev-2=True
```

`(True,37,37) → (True,36,36) → (True,37,37)` reproduces the author's transcript **exactly**. **BL-1 is real, the rewrite works, and §5.1's new rule 10** — *"an invariance AT takes its expectation from a committed pre-change artifact, never from the live producer"* — is the correct generalisation. This is the best fix in the revision.

---

## RG-4 · The two disputed figures — **both settled in the author's favour**

**(a) Footer painted count.** My round-1 *"120×30 → 14 painted"* used a looser metric than the author's. Re-executed with both metrics side by side:

```
 (80, 24)  Footer.width= 78  children=15  model(show+enabled)=14  PAINTED WHOLLY INSIDE= 7   (starts-inside-terminal= 9)
(120, 30)  Footer.width=118  children=15  model(show+enabled)=14  PAINTED WHOLLY INSIDE=12   (starts-inside-terminal=14)
(160, 40)  Footer.width=158  children=15  model(show+enabled)=14  PAINTED WHOLLY INSIDE=14   (starts-inside-terminal=15)
```

**The author is right: 7 / 12 / 14.** My "14" at 120×30 was *children starting inside the terminal width*, not *children painted wholly inside `Footer.size.width`* — a different predicate, and the author's is the one that matches the claim being made. **I withdraw my figure.** We already agreed on 7 at 80×24, which is the load-bearing number, and 160×40 → 14 is confirmed.

**(b) `_project_label` call sites.** My round-1 report quoted the document's own **16**; I did not derive it. Re-derived by regex over all of `tests/`, excluding definitions:

```
test_tui_patch_variant.py   defs=1  CALLS=8  lines=[153, 155, 233, 305, 583, 599, 607, 772]
test_tui_variants.py        defs=1  CALLS=6  lines=[107, 154, 239, 274, 307, 394]
TOTAL _project_label CALL sites in tests/ = 14
```

**The author is right: 14, not 16.** (My first pass used `grep -c`, which counts *lines*, and `test_tui_directionb.py` / `test_tui_app.py` mention the name in prose without calling it.) **I withdraw my figure.** LLR-121.4's threshold and Inc-8 now both say 14 and are correct.

Both corrections are the same class as the one I raised against the document last round: *a count and its enumeration produced by different patterns.* It landed on me this time.

---

## RG-5 · NEW findings

### NEW-1 · BLOCKER — revision 2's fixes did not reach the HLR `Numeric pass threshold` lines, and §6.4a asserts two sweeps that did not happen

§6.4a exists because *"the recurring root cause in this batch is a change applied where it was noticed and not swept to its dependents."* Five instances survive in the current file; **two of them are the false-fails the coordinator asked me to confirm closed**, and **two are named as swept dependents in §6.4a's own table**.

| # | Where | Current text (verbatim, revision 2) | Should read | §6.4a claim |
|---|---|---|---|---|
| **i** | `§5.1` rule 3, line 602 | *"the owning set computed in the test body with `assert len(OWNING) == 3`"* | the stated regex + set-equality; `len == 3` redundant | **listed as swept** — *"§5.1 rule 3 … the `len == 3` guard demoted to redundant"*. It was not. |
| **ii** | `HLR-126` threshold, line 348 | *"`app.active_bindings` … still **contains all 14** pre-existing chips at 80×24, **none truncated**"* (and the AT line: *"the 14 chips are undisplaced"*) | set-**equality** on the model key set + painted count unchanged at **7** | not listed as a dependent. **This is the text the document itself proves false-fails `origin/main`** (LLR-126.1: *"rev-1's 'all 14, none truncated' false-fails `origin/main` itself"*) |
| **iii** | `§2.4` C16, line 95 | *"**14** chips in a 78-column Footer at 80×24"* | model **14** / painted **7**, layer-labelled | **listed as swept** — *"C16 now distinguishes the model count (14) from the painted count (7)"*. It does not. |
| **iv** | `HLR-120` threshold line 248 **and** `LLR-120.3` threshold line 429 | *"`#workspace_status_bar.size.height` **== 7**"* | `<= 7`, per §5.3's own cell | not listed. §5.3 states *"Threshold relaxed to `<= 7`"* — the relaxation exists **only** in the falsifiability table |
| **v** | `HLR-124` Statement line 311, threshold line 314, AT line | *"a notice naming **the unsatisfied axis** and the value **it** requires"* / *"at 80×24 the notice … names the **width** axis"* | *every* unsatisfied axis; at 80×24 **both** | `LLR-124.4` says the opposite in its Statement, Geometry **and** threshold: *"at 80×24 the notice names **BOTH** axes"*. M7 was fixed at LLR level only, so the **HLR predicate still passes the exact defect M7 was raised to close** |

**Why blocker.** An implementer encodes the `Numeric pass threshold`. Instance (ii) fails on the unmodified tree under any honest painted-layer reading; instance (iv) fails a conforming implementation that *reduces* the status-bar height; instance (v) leaves the weaker of two contradictory normative `shall` clauses in the parent requirement. And a propagation-sweep table that reports a sweep which did not occur is worse than no table — it is an audit that certifies its own gap.

**Fix (mechanical, ~6 edits, no re-derivation):** propagate the five thresholds from their already-correct LLR/§5.3 counterparts, then re-run §6.4a's table as an **enumeration** (grep each changed token across the file) rather than as a recollection.

### NEW-2 · MAJOR — `LLR-124.3` (the fallback layout) has no increment, and Inc-10's file list cannot host it

BL-2 moved the *acceptances* to Inc-10 but not the *work*.

- Rev-1 Inc-5 Content: *"HLR-124 **wide + fallback layouts** and the notice regime"*. Rev-2 Inc-5 Content: *"HLR-124 **wide layout** + the notice regime"* — "fallback" removed.
- Rev-2 Inc-10 Content: *"HLR-118 — delete `#command_bar_row` + CSS `:66-102`. **Plus the four arms BL-2 moved here**"* — the arms, not the layout.
- §6.4a confirms the intent: *"A-2 re-pointed **Inc-5 → Inc-10**"* (A-2 **is** the fallback overlay's dismissal mechanism).
- **Inc-10's file list is `command_bar.py`, `styles.tcss`, `tests/test_tui_commandbar.py`, `tests/test_tui_diff_screen.py` (4)** — no `screens_directionb.py`, no `app.py`.

`LLR-124.3` requires *"the run list … presented without permanently reserving columns or rows"* (an overlay widget) and *"the selected run's bytes beyond the visible rows … reachable by pagination"*. Neither is expressible in `styles.tcss`. `AT-B78-25` asserts *"the viewport **paginates**"* and lands at Inc-10. **So Inc-10's gate cannot pass with Inc-10's stated content and file budget** — the same failure mode as Q-B1, one level down.

**Fix:** name `LLR-124.3` in Inc-10's Content and add `screens_directionb.py` to its file list (→ 5 files, still within the ≤5 rule). No AT changes.

### NEW-3 · MAJOR — `AT-B78-22`'s named discharging mutation cannot reach its assertion, in either guard placement

The Q-M1 rewrite is correct: the expectation is now three literal addresses, and I confirm the panel emits exactly them (`['0xff0','0x1000','0x1010']`). But the guard is `assert AbDiffPanel.DISPLAY_CONTEXT_BYTES == 16` — an **equality on the very constant the named mutation changes**. Unlike the cap AT's guard (`200 > DISPLAY_MAX_RUNS`, which only fires past 200), **no placement can let the mutation reach the assertion**:

```
PRE  ctx=16   guard-FIRST: green=True     guard-AFTER: green=True
MUT  ctx=64   guard-FIRST: GUARD RAISED   guard-AFTER: GUARD RAISED
POST ctx=16   guard-FIRST: green=True     guard-AFTER: green=True
```

Q-m2's own lesson — *a counterfactual must fail on its assertion, not on an error* — was applied to `LLR-122.3` and **not** to the AT rewritten in the same revision. §7 Inc-4's gate criterion, *"`AT-B78-22` **reddens under `ctx 16 → 64`** after the rewrite"*, is therefore unexecutable as written; an implementer will either accept an `AssertionError` from the guard as "red" (it is not — it never evaluated the subject) or delete the guard (losing C-39).

**Fix:** keep the guard and name a mutation on the **implementation**, not the constant — e.g. `screens_directionb.py:7027` `low -= low % HEX_WIDTH` → `low -= 0`, or `:7028` `high = end + ctx` → `high = end`. Either reddens the three-literal comparison with the guard still true.

### NEW-4 · MINOR — `LLR-124.1` keeps the `26` sentinel HLR-124 dropped; HLR-124's parenthetical describes the wrong sentence

`HLR-124`'s threshold now reads *"the literals `139`, `94` and `29` … in the new `AT-B78-*` / `TC-B78-*` nodes"* and explains that `26` is dropped. `LLR-124.1`'s threshold (line 546) still reads *"the literals `139`, `94`, `29`, **`26`** appear 0 times in the acceptance tests"*. Separately, HLR-124's inline warning *"(⚠️ **unscoped**, this threshold is already false on `origin/main` …)"* is attached to a sentence that **is** scoped — it describes rev-1's form and reads as describing its own. Both are one-line edits.

### NEW-5 · MINOR — `AT-B78-33` hard-codes its pre-change baseline

`AT-B78-33` is a genuine gate and I reproduced it (`132×44: 7 → 13`). But its expectation is the bare literal **7**, a measured pre-change value with nothing tying it to a capture. A test cannot re-measure the pre-change geometry after the change lands, so the literal is the only *inline* option — but Inc-0 already commits a pre-change artifact, and §5.1's new **rule 10** states the principle exactly (*"an invariance AT takes its expectation from a committed pre-change artifact"*). **Fix:** add the 132×44 `#diff_hex_a.size.height` to Inc-0's artifact and read the baseline from it. Cost: one line in an artifact that is already being written.

---

## RG-6 · The three relabelled ATs, and the 9 PINs

The coordinator's bar: hold the three new PINs to the round-1 standard, and check none is a gate downgraded to avoid fixing it.

| AT | Green today? | Downgrade to dodge a fix? | Evidence |
|---|:-:|---|---|
| `AT-B78-11` | ✅ green | **No.** The subject genuinely does not move until the feature exists; the named mutation (*"set the new label to its own row, confirm 7 → 8"*) is real and owed at Inc-7 | `{all 10 screens: 7}` at 80×24 **and** 120×30 (round-1 execution). Under either `== 7` or `<= 7` the predicate passes on `origin/main` — it is an invariant, i.e. a PIN |
| `AT-B78-19` | ✅ green | **No.** Relabelling is paired with the *restored* precondition assertion and a real named mutation, so the node gets **stronger** as a PIN than it was as a fictitious gate | `set_focus(#diff_range_list)` → focus lands on `RailItem(id='rail_item_workspace')`; `k` opens the Legend anyway (round-1 execution) |
| `AT-B78-03` | ✅ green | **No.** rev-1's form was inert; rev-2's artifact form **reddens** (RG-3) — it is a PIN because the palette set is genuinely invariant across the batch, which is D-3's whole point | `rev-1 MUT=True (inert) · rev-2 MUT=False (reddens)`, mutation confirmed applied |
| `AT-B78-32` 🆕 | ✅ green | **No.** A restored architect observable (zero-line `git diff` over `app.py:1338-1375`), trivially true today, mutation named and owed at Inc-6 | correct PIN by construction |
| six original PINs | — | **No** — re-affirmed from round 1 | `AT-B78-02, 10, 12, 18, 31` unchanged; `-03` rewritten |

**9 PINs is a lot, and the document says so.** But the count moved the honest direction: **six of the nine carry an owed mutation at a named increment gate**, and none was upgraded to close a gap. §9's checklist row is now correct — *"Every **story** demonstrated RED pre-change … **9 of 9 stories**. ⚠️ Not 31 of 31 ATs"* — which is exactly the correction I argued for.

---

## RG-7 · Would any acceptance now false-fail a correct implementation?

**Two of my four survive; no new one was introduced.**

| # | Round-1 false-fail | Status |
|---|---|---|
| 1 | `LLR-126.1` *"none truncated"* (7 of 14 painted on `origin/main`) | ❌ **NOT CLOSED** — fixed at LLR-126.1, survives verbatim at `HLR-126`'s threshold and AT line → NEW-1 (ii) |
| 2 | `assert len(OWNING) == 3` (honest derivation gives 7) | ⚠️ **PARTIALLY** — fixed at HLR-119 / LLR-119.1, survives at `§5.1` rule 3 → NEW-1 (i) |
| 3 | *"the literals … appear 0 times in the tests"* | ✅ **CLOSED** — scoped to the new nodes at HLR-124 |
| 4 | `size.height == 7` vs *"shall not increase"* | ❌ **NOT CLOSED** — `<= 7` exists only in §5.3; `HLR-120` and `LLR-120.3` both still say `== 7` → NEW-1 (iv) |

**New false-fails introduced: none.** NEW-1 (v) is the opposite hazard — HLR-124's singular-axis threshold is *weaker* than LLR-124.4's, so it would pass a notice naming only width at 80×24, the exact case M7 was raised to close. That is a vacuity, not a false-fail, and it is listed as such.

---

## RG-8 · Nothing I raised was silently dropped

Checked one by one against the current file: all 15 round-1 findings appear in revision 2 by id (`Q-B1`, `Q-M1`…`Q-M6`, `Q-m1`…`Q-m8`), each with a disposition and, where I supplied one, my executed transcript quoted rather than paraphrased. Q-M6.3 — which the closure list did not mention — is addressed as **§5.1 rule 9**, and I re-verified its factual claim (`grep -c '::'` → 0). Q-m7 is addressed at C7. Q-m8 is addressed by splitting §5.3's rows. **Zero of my findings were dropped, downgraded without reason, or answered by assertion alone.**

---

## RG-9 · Re-gate evidence checklist

| Item | ✓/✗ | Evidence |
|---|:-:|---|
| Every closure re-executed, not read | ✓ | RG-2 (ladder ×4 sizes ×3 configs), RG-3 (`AT-B78-03` PRE/MUT/POST), RG-4 (Footer ×3 sizes, `_project_label` regex), NEW-3 (`AT-B78-22` ×2 guard placements ×3 ctx values) |
| Failed mutations recorded, not hidden | ✓ | RG-3 — two attempts that did **not** apply (MRO merge; `isinstance(b, Binding)` misses the tuple form) are stated so their green is not read as a result |
| The three relabelled ATs held to the round-1 PIN bar | ✓ | RG-6 — all three genuinely invariant today; none a dodge |
| `AT-B78-25` consolidation checked for lost observables | ✓ | RG-2 — the AT line carries the union of both rev-1 arms; `AT-B78-27`'s retirement is explicit in §5.6.3, §5.7 and §7 |
| C-40 limb 1 applied to every **rewritten** predicate | ✓ | `AT-B78-03` ✅ (artifact oracle, reddens) · `AT-B78-22` ✅ subject in expression, ⚠️ mutation cannot reach it (NEW-3) · `AT-B78-28` ✅ set-equality reddens · `AT-B78-26` ✅ joint clause · `AT-B78-33` ✅ moves 7→13 · `AT-B78-11` ✅ correctly demoted |
| False-fails re-checked, and new ones hunted | ✓ | RG-7 — 2 closed, 2 survive, 0 introduced |
| Disputed figures settled by execution, not argument | ✓ | RG-4 — **both go to the author**; I withdraw 14→12 and 16→14 |
| Nothing raised was silently dropped | ✓ | RG-8 |
| No source, test or state file touched | ✓ | `git diff --stat -- s19_app/ tests/` empty; `git status --porcelain -- s19_app/ tests/` empty; `01-requirements.md`, `state.json`, `PLAN.md`, `00-measurements.md`, `AT-TC-REGISTRY.jsonl`, `prototypes/memmap2.*` read only |
| Round 1 preserved, not overwritten | ✓ | this section is appended below the round-1 checklist |
| No manufactured findings | ✓ | 5 new findings, each a verbatim quote from the current file or an executed transcript; round 2 is **1/2/2** against round 1's **1/6/8** |

---
---

# RE-GATE — round 3 · qa-reviewer lane

**Under review:** `01-requirements.md` **revision 3** (971 lines, was 939)
**Constraints held:** `git status --porcelain -- s19_app/ tests/` **empty**; all mutations in-process from an out-of-repo scratchpad, reverted with the predicate re-run. This review file is the only thing this lane has written in three rounds.

## RG3-BLUF — **CLEAN AT BLOCKER LEVEL**

**Round 1: 1 / 6 / 8 → Round 2: 1 / 2 / 2 → Round 3: 0 blocker / 1 major / 2 minor.**

**Both my blockers are closed and I reproduced both closures by execution.** `NEW-3` was closed with *my* mutation, and I confirm it reddens **on the assertion** — not on an error — with the guard true throughout. `NEW-2` was closed **better than I proposed**, and I confirm my own fix would have been insufficient.

The one major is new and is the mirror of the defect the revision was built to fix: **the painted-child clause that §1.3's new normative definition exists to support cannot fail at the size both normative thresholds name first.** Executed: `+1 show=True chip` → painted count stays **8** at 80×24 and **13** at 120×30; it moves only at 160×40 (15 → 16). `AT-B78-28` is still a genuine gate — its *set-equality* clause reddens — but one of its two clauses is inert where it is asserted.

**On the figures I conceded in round 2: the coordinator's ruling is confirmed by execution, and my round-2 concession was wrong.** `Footer.region.x == 1` at all three sizes; the child discarded by the frame-mixing form is Textual's built-in `ctrl+p` chip, which ends **flush** with the absolute right edge at *every* size. **8 / 13 / 15 is correct.**

---

## RG3-1 · The two blockers

### NEW-1 — thresholds + a register certifying sweeps that did not happen · ✅ **CLOSED**

Independent stale-term sweep with **my own** regexes, not the author's, over the shipped file:

| My probe | Hits |
|---|---|
| `contains all 14` / `still contains` | **0** |
| `== 7` (status-bar) | **0** |
| `names the width axis` | **0** |
| `the unsatisfied axis and the value it requires` | **0** |
| `` `26` `` as a sentinel | **0** (line 547 now reads *"the literals `139`, `94` and `29` … `26` is **dropped as a sentinel**"*) |
| `len(OWNING) == 3` as a bare assertion | **0** — §5.1 rule 3 (line 611) now carries the stated regex `(search\|goto)_input$`, **set-equality** to `{workspace, a2l, mac}`, and the length guard explicitly *"kept only as a redundant guard … the bare length assertion false-fails the obvious tree derivation, which yields 7"* |

All five NEW-1 instances are fixed, plus the two the register surfaced that no reviewer had listed (`LLR-123.2`'s own threshold two lines below its corrected Statement; `§5.5`'s header still asserting the superset premise `§5.6.3` withdraws). **The register is genuinely derived** — it is the right shape and it found more than three reviewers did. Residue in the register itself is **NEW-10**, minor.

**Also verified closed from earlier rounds:** Q-M3 (§5.1 rule 3), Q-M4 (HLR-126 + C16), Q-m5 (LLR-124.1), Q-m6 (`HLR-120` line 249 and `LLR-120.3` line 432 both now `1 <= size.height <= 7`).

### NEW-2 — `LLR-124.3` had no implementing increment · ✅ **CLOSED, and my proposed fix was the inferior one**

Rev-3 Inc-5 Content: *"**HLR-124 in full — `LLR-124.1` (constants + regime class), `LLR-124.2` (wide layout), `LLR-124.3` (fallback: overlay + paginated viewport), `LLR-124.4` (notice regime)**"*, files `screens_directionb.py`, `app.py`, `styles.tcss`, `tests/test_tui_diff_screen.py`. Inc-10 now states explicitly: *"**No production code for HLR-124 is written here — Inc-10 OBSERVES the fallback layout built at Inc-5**"*.

**Checked against §7's own file × increment map, which is what settles it:**

```
screens_directionb.py | 2, 4, 5, 6, 7
app.py                | 5, 7, 9, 11        <-- Inc-10 is NOT in this row
```

`LLR-124.1` puts the regime toggle on the `_apply_width_regime` / `on_resize` precedent, which lives in **`app.py`**; `LLR-124.3`'s overlay lives in **`screens_directionb.py`**. **My fix — add `screens_directionb.py` to Inc-10 — would have supplied one of the two and left the regime toggle homeless**, reproducing the same defect one file over. Inc-5 already owns both. The author's choice is correct and the reason given (not mixing diff-panel layout work into the command-bar-deletion increment of a strictly-sequential plan) is the right second reason. **I withdraw my proposed fix.**

### NEW-3 — `AT-B78-22`'s mutation could not reach its assertion · ✅ **CLOSED, re-verified on the assertion**

Both candidate mutations executed against the shipped fixture, guard evaluated **after** the capture:

```
PRE  (unmutated)           : guard_const=16   assertion green=True
MUT  low -= 0   (architect): guard_const=16   assertion green=True          <-- INERT
MUT  high = end (QA)       : guard_const=16   RED ON THE ASSERTION
                                              (got ['0xff0','0x1000'] != the three literals)
POST (restored)            : guard_const=16   assertion green=True
```

Three things confirmed: **(a)** the encoded mutation reddens on the **assertion**, not on an error, with the guard **true** throughout — which is the whole point of NEW-3; **(b)** the architect lane's proposal really is inert on this fixture — `low = 0xFF0` and `0xFF0 % 16 == 0`, so the alignment step is already a no-op and removing it changes nothing; the rejection-with-counter-transcript was right; **(c)** the restored predicate emits exactly `['0xff0','0x1000','0x1010']`. §7's Inc-4 gate now names the implementation mutation and states why the constant mutation cannot serve.

---

## RG3-2 · The Footer figures — the coordinator's ruling confirmed, my round-2 concession withdrawn

```
 (80, 24)  Footer.region.x=1  size.width= 78  abs_right= 79  children=15
      §1.3 NORMATIVE (absolute containment) =  8    rev-2 frame-mixing form =  7
      child ending FLUSH with abs_right: ['ctrl+p']
(120, 30)  Footer.region.x=1  size.width=118  abs_right=119  children=15
      §1.3 NORMATIVE = 13    rev-2 frame-mixing form = 12    flush: ['ctrl+p']
(160, 40)  Footer.region.x=1  size.width=158  abs_right=159  children=15
      §1.3 NORMATIVE = 15    rev-2 frame-mixing form = 14    flush: ['ctrl+p']
```

**8 / 13 / 15 is correct.** The discarded child is Textual's built-in `ctrl+p` command-palette chip — right-aligned, ending flush with the absolute right edge at every size, and excluded by comparing an absolute `x + width` against a relative `size.width`. My round-1 instinct that the document's figure was wrong was right; **the correction I accepted in round 2 was wrong, and I withdraw it.** Both my round-2 figures were errors of the same class I was auditing for: a quantity reported without its measurement convention.

**Dependent sites derive from §1.3's definition, with one exception:** C16 (line 96) ✓, HLR-126's threshold (line 351) ✓, LLR-126.1's threshold (line 597) ✓, LLR-126.1's Geometry narrative (line 596) ✓ — all cite the rule and read **8** @80×24 with 13 / 15 alongside. §5.3's `AT-B78-28` row does not → **NEW-9**.

`_project_label = 14` stands; noted for my own method — `grep -c` counts lines, and that is exactly how the figure went wrong for the document and then for me.

---

## RG3-3 · NEW findings

### NEW-8 · MAJOR — the painted-child clause is inert at the size both normative thresholds name first

`HLR-126` (line 351) and `LLR-126.1` (line 597) both assert *"the **painted** child count under §1.3's containment rule is unchanged at **8** @80×24"*, and §5.3 names the mutation *"add `Binding("ctrl+alt+z", …, show=True)`"*. Executed, applying that mutation for real (subclass; the key is free, and the model set moves 14 → 15, so the mutation is confirmed applied):

```
 (80, 24)  BASE model=14 painted= 8    MUT model=15 painted= 8    painted clause reddens? NO
(120, 30)  BASE model=14 painted=13    MUT model=15 painted=13    painted clause reddens? NO
(160, 40)  BASE model=14 painted=15    MUT model=15 painted=16    painted clause reddens? YES
   80x24 BASE painted = ['ctrl+k','ctrl+d','ctrl+l','ctrl+s','slash','g','q','ctrl+p']
   80x24 MUT  painted = ['ctrl+k','ctrl+d','ctrl+l','ctrl+s','slash','g','q','ctrl+p']   (identical)
```

At 80×24 the Footer is already saturated, so a new chip is laid out past the right edge and **cannot** change the painted count. The clause states a true fact about the system and is therefore not *wrong* — but as an acceptance clause at the stated size **it cannot fail under the only mutation named for it.**

**This does not make `AT-B78-28` vacuous** — its set-equality clause on the model key set reddens (`contains-all True` / `set-equality False`, re-executed), and that is the gate. But the painted clause is the one the R-5 ruling and the new normative §1.3 definition were created to support, and it is the clause an implementer would read as guarding displacement. It is a PIN wearing a GATE's clothes, at 80×24.

**Fix, and it is one line:** assert the painted count **per size** — §5.1 rule 7 already mandates per-arm CC-1 verdicts — or move the load-bearing arm to **160×40**, where the count moves 15 → 16. Keep 8 @80×24 as the stated baseline; just stop presenting it as the arm that catches displacement.

### NEW-9 · MINOR — §5.3 was not swept to the new painted figure or to the status-bar floor

Two cells in the falsifiability table carry superseded values. Both are records rather than normative text, which is why this is minor — but one of them is a **figure appearing twice with two values**, which is the register's own newly-adopted standing check (b), unmet on the revision that adopted it.

| Line | Current text | Should read |
|---|---|---|
| **:656** (`AT-B78-28`) | *"the painted-layer baseline is **7**, not 14"* … *"Painted layer @80×24: `Footer.size.width=78`, 15 children, **7 fully painted**"* | **8**, per §1.3 / C16 / HLR-126 / LLR-126.1 |
| **:640** (`AT-B78-11`) | *"Threshold relaxed to `<= 7`"* | `1 <= h <= 7` — the NEW-7 floor, which both normative thresholds now carry |

`:656` could not surface in the register because the Footer row's pattern is `none truncated\|contains all\|chips` — **it enumerates the words, not the number**, and line 656 contains none of the three. `:640` is dispositioned *"✔ intended"*, which was true before the floor was added in the same revision.

### NEW-10 · MINOR — the register's stated hit counts do not reproduce against the file it ships with, and one row dispositions 4 of its 6 hits

I re-executed all fourteen of §6.4a's own regexes against the shipped 971-line file. **Two of fourteen reproduce the claimed count exactly** (`len(OWNING) == 3` → 3 ✓, `_KIND_LABEL` → 3 ✓). Most of the rest differ by exactly +1, which is the register row's own text matching its own pattern — a benign self-reference artifact. Two differ by more:

- **Footer painted count** — claimed **6**, actual **7** (one self-hit → 6 real), but the row dispositions only **4**. The undispositioned real hits are `:150` (P-51), `:180` (D-2's ruling), `:349` (HLR-126 Rationale) and `:715` (§5.5's historical record) — **four sites still presenting the model count 14 as a column budget** (*"14 chips in 78 columns at 80×24"*), which §1.3's definition now makes a conflation. `:715` is a historical record and correct-as-is; the other three are informative text whose conclusion is unaffected — D-2's *"do not add an App chip"* is if anything strengthened by 8-of-15 — so nothing normative turns on them. But the row's promise is *"disposition of **every** hit"*.
- **superset premise** — claimed **3**, actual **7**; the extra hits are rev-2/rev-3 text using the word in its ordinary sense (*"satisfied by a superset"*), i.e. the count was taken before those edits landed.

**The pattern:** the register's numbers were captured at an intermediate state and not re-run against the final file — which is the obligation the section itself declares one paragraph later (*"re-run, not re-read"*). The shape of the control is right and it earned its keep; it needs to be the **last** step before close, not a mid-revision snapshot.

---

## RG3-4 · Also verified

| Check | Result |
|---|---|
| **Six `shall` reworded to non-modal — did any clause lose binding force?** | **No.** Executed scan: **40** `- **Statement**` lines, **0** of them lacking `shall`, **0** of them carrying a non-`shall` modal (`should/must/may/might/will/ought/could`). `shall` outside Statement lines = **5**, every one a quotation or a grep-pattern column. The M10 rewording moved *free-standing* `shall`s out of notes; it did not weaken a Statement. The C-17 clause moved the other way — from a note into `LLR-122.1`'s Statement **with a node** (`TC-B78-48`) — which is a strengthening. (§9 states 43 / 3 where I count 40 / 5; a counting-convention divergence, not a defect — the load-bearing claim, *0 free-standing normative `shall`*, verifies.) |
| **The nine PINs — still honest, none upgraded?** | **Yes, honest; none upgraded.** Executed tally of §5.3: exactly **9** PIN rows — `AT-B78-02, 03, 10, 11, 12, 18, 19, 31, 32` — **the identical set as round 2**. No AT was demoted to a PIN in this revision, and no PIN was promoted to close a gap. `AT-B78-11`'s new `1 <= h <= 7` is green today (height is 7 on all 10 screens) so it remains correctly a PIN, and NEW-7's floor is a real strengthening: a bare `<= 7` would have been satisfied by a collapsed bar of height 0, and it is now co-asserted with `AT-B78-08` in the same run. |
| **`AT-B78-33`'s baseline (my NEW-5)** | **Closed.** Inc-0 now captures `#diff_hex_a.size.height` at 132×44 alongside the palette list and the search payload; Inc-1's gate reads the baseline **from the artifact**, not from an inline literal. §5.1 rule 10 applied correctly. |
| **My NEW-4 (`26` sentinel)** | **Closed** — LLR-124.1's threshold now reads `139`, `94`, `29` scoped to the new nodes, with `26` dropped and the reason stated. |

---

## RG3-5 · Would anything now false-fail a correct implementation?

**No. All four round-1 false-fails are closed, and no new one was introduced.**

| # | Round-1 false-fail | Round-3 status |
|---|---|---|
| 1 | Footer *"none truncated"* / *"all 14"* | ✅ **CLOSED** — HLR-126 and LLR-126.1 both assert the painted count **unchanged at 8 @80×24**, which is the true `origin/main` figure |
| 2 | `assert len(OWNING) == 3` | ✅ **CLOSED** — set-equality on the stated regex; the length guard is explicitly redundant, at HLR-119, LLR-119.1 **and** §5.1 rule 3 |
| 3 | literal-`0` threshold | ✅ **CLOSED** — scoped to the new nodes at both HLR-124 and LLR-124.1 |
| 4 | `size.height == 7` | ✅ **CLOSED** — `1 <= size.height <= 7` at HLR-120 and LLR-120.3, with the floor's rationale stated |

**NEW-8 is a vacuity, not a false-fail:** 8 @80×24, 13 @120×30 and 15 @160×40 are all true on the unmodified tree, so a correct implementation passes. The defect is that the 80×24 arm cannot *fail*.

---

## RG3-6 · Disposition

**CLEAN AT BLOCKER LEVEL.** Nothing in revision 3 blocks; **no cap breach arises from this lane.**

- **0 blocker · 1 major (NEW-8) · 2 minor (NEW-9, NEW-10).**
- All three are **one-line or few-line edits inside acceptance/record text**. None requires re-measurement, re-design, or a change to any requirement, increment, ID or file budget. NEW-8's fix is to state the painted arm per size — a rule §5.1 already mandates.
- Every round-1 and round-2 finding is now closed. Across three rounds this lane raised **1 + 1 + 0 blockers**, and the blocker count went to zero without a single acceptance being weakened to get there — every fix moved work or strengthened a predicate.
- Two of my own figures were wrong across the three rounds (`Footer painted 14`, then conceding `7`) and both were the same class of defect I was auditing for: a quantity reported without its measurement convention. §1.3's new **painted child** definition is the right permanent answer, and it exists because three parties produced three counts.

## RG3-7 · Round-3 evidence checklist

| Item | ✓/✗ | Evidence |
|---|:-:|---|
| Register completeness tested, not trusted | ✓ | all 14 of its regexes re-executed against the shipped file; 2/14 reproduce exactly; the Footer row's 6 hits vs 4 dispositions enumerated by line (NEW-10) |
| Own independent stale-term sweep run | ✓ | RG3-1 — six probes the register does not use; all 0 hits |
| `NEW-3` re-verified to redden **on the assertion** | ✓ | `high = end` → RED on assertion, `guard_const=16` throughout; `low -= 0` → green, confirming the rejection |
| `NEW-2` fix verified against §7's file map | ✓ | `app.py` row = increments 5, 7, 9, 11 — Inc-10 absent; my proposed fix would have supplied only `screens_directionb.py` |
| Footer figures settled by execution | ✓ | `region.x=1`; abs_right 79/119/159; flush child `ctrl+p` at every size; **8/13/15** |
| New vacuity hunted, not assumed absent | ✓ | NEW-8 — the `+1 chip` mutation applied for real (model 14→15) and the painted count measured at all three sizes |
| Reworded `shall` checked for lost binding force | ✓ | 40 Statement lines, 0 without `shall`, 0 with a foreign modal |
| Nine PINs re-tallied and re-assessed | ✓ | identical set to round 2; none upgraded |
| False-fails re-checked, new ones hunted | ✓ | RG3-5 — 4 of 4 closed, 0 introduced |
| Own errors corrected in public | ✓ | RG3-2 — round-2 concession to 7/12/14 withdrawn; RG3-1 — my Inc-10 fix withdrawn as inferior |
| No source, test or state file touched | ✓ | `git status --porcelain -- s19_app/ tests/` empty |
| Rounds 1 and 2 preserved | ✓ | appended, not overwritten |
| No manufactured findings | ✓ | 3 findings, each an executed transcript or a verbatim line quote; **0 blocker** stated plainly rather than padded |
