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
