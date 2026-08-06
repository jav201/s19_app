# Phase 2 — cross-agent review, **architect lane** — batch `2026-08-06-batch-78`

**Under review:** `.dev-flow/2026-08-06-batch-78/01-requirements.md` (804 lines) @ `544f16b`, branch `claude/batch-78-cmdbar-a2bdiff`.
**Reviewer:** architect lane (did not author the document under review).
**Method:** every finding below carries an **executed** transcript, a `file:line` re-derived this session, or a command output. Where I disagreed with a delegated enumeration I re-measured and say so.
**Probe hygiene:** all mutations applied **in-process** (rebinding the imported class attribute), reverted in the same process, predicate re-run. `git diff --stat -- s19_app/ tests/` **empty** after every probe. Nothing in the repo was written except this file. `state.json`, `PLAN.md`, `00-measurements.md`, `01-requirements.md`, `AT-TC-REGISTRY.jsonl` and `prototypes/memmap2.*` were read only.

---

## BLUF

**3 blocker · 11 major · 8 minor. The document needs design work before Phase 3, but the design work is small and local — it is not a re-derivation.** Its measured foundation is genuinely solid: I re-executed 9 of the load-bearing figures independently and **every one reproduced**, including the two the batch corrected late (79 cells, `W ≥ 94`) and the one it flagged `assumed` (`H = 29`, which I confirmed at three widths rather than the document's two). The failures are not in the measurements. They are in three places:

1. **One acceptance is provably inert** — `AT-B78-03` as worded cannot fail. I removed an entire command from `BINDINGS` and it stayed GREEN.
2. **Four acceptances are scheduled one increment before the increment that makes them passable.** A correct implementation fails Inc-9's gate.
3. **The merge was audited in one direction only.** §5.5 reconciles QA→canonical and claims "0 RETIRED". Its own stated rule — "the architect allocation is canonical (**superset**)" — is false: at least one architect acceptance criterion exists in neither the merged document nor a retirement line.

The document's dominant self-declared virtue — falsifiability discipline — is also where it fails: the defect shape it catches twice (F-6, the cap AT that certifies its own constant) survives in `AT-B78-03` in a stronger form.

---

## 1 · What I checked and found SOUND

Listing this first, because a review that reports only failures gives the gate no way to judge coverage.

### 1.1 Geometry — re-executed, all reproduce

Probe: `S19TuiApp.run_test(size=(W,H))` → `action_show_screen("diff")` → `size.*` and `region.intersection(#screen_diff.region)`, swept over 12 terminal sizes.

| Claim | Doc | Re-executed | Verdict |
|---|---|---|---|
| Emitted hex row (`render_hex_view`) | **79** (P-31, C3) | **79** — and invariant across dense / sparse / high-address maps (`0xFFFFFFF0`) | ✅ |
| `render_hex_view_text` is the wrong producer | 81, workspace only | **81**; delta is exactly the 2-space indent; the panel imports `render_hex_view` at `screens_directionb.py:7021`, calls it `:7030-7031` | ✅ |
| `C = W − rail − 6` | P-32 | exact at **all 12** sampled widths | ✅ |
| Rail 4 / 22, breakpoint at 120 | C6 | `119 → 4`, `120 → 22` | ✅ |
| Box chrome 5 per bordered column | C4 | residual `C − (list+hexa+hexb) = 15` across 3 boxes at **every** width | ✅ |
| `C` by terminal: 80→70 · 120→92 · 132→104 · 160→132 | C5 | 70 / 92 / 104 / 132 | ✅ |
| Width floor `W ≥ 94` | P-34c, D-1 | `93 → C=83 → window 78 ✗`; `94 → C=84 → 79 ✅`; no dead zone at the rail switch (`119 → 104 ✅`, `120 → 87 ✅`) | ✅ |
| Wide breakpoint 139 under `L ≤ C − 89` | LLR-124.1 | `138 → C=110`, `139 → C=111` = `22 + 89` exactly | ✅ |
| `#diff_status` clips to **0** at 120×30 and 80×24 | HLR-125 | 0 and 0 | ✅ |
| Control rows 3/3/3; `#diff_select_row_b` clips to 2 at 80×24 | LLR-125.1 | 3/3/3 everywhere; at 80×24 `rowB=2`, `action_row=0` | ✅ |
| **The C-32 trap is real** | §1.3, §5.1 rule 1 | at 120×30 `#diff_hex_a.region.height = 4` while the clipped intersection is **0** — a `region`-only predicate does ship the bug green | ✅ |

### 1.2 The `assumed` height constant — stronger than the document claims

`_DIFF_MIN_ROWS_H = 29` is flagged `assumed` (A-1) because it came from simulating S-8 with `styles.height = 1`. I re-ran that simulation and extended it.

```
compact + bar removed, #diff_hex_a CONTENT rows:
  120x28 -> 0    120x29 -> 1    120x30 -> 2    120x32 -> 4    120x40 -> 12
   80x24 -> 0     80x29 -> 1     80x30 -> 2
   94x29 -> 1     94x30 -> 2
```

P-33c reproduces **exactly** (28→0, 29→1, 30→2, 32→4, 40→12). The document justified width-independence from two points at W=80; I confirmed the same floor of 29 at **W=80, W=94 and W=120** — including W=94, the exact coordinate `LLR-124.4`'s boundary threshold names and which neither lane had measured. **A-1's residual risk is lower than stated, and no acceptance false-fails a correct implementation on account of 29**, provided Phase 3 re-derives it as A-1 already mandates: every acceptance keyed on the height axis either quotes the symbol (`H = _DIFF_MIN_ROWS_H`, LLR-124.4) or sits far below any plausible floor (`TC-B78-32` at `H = 24`).

### 1.3 Code citations — spot-audited, ~50 of ~95

Every one of these resolved exactly: `command_bar.py` 69, 111, 118, 125, 139–150, 195–196, 204, 208, 212, 216 · `app.py` 1879, 1916, 1930, 5758, 5772, 5816, 5980, 5984, 5995, 6025, 6205, 6232, 11290, 11328, 11351, 11638–11639, 11641–11644, 11646, 4953, 5836, 1364 · `screens_directionb.py` 6566, 6623, 6624, 6627, 6739, 6759, 6766, 6769, 6921, 7003, 7016, 7019, 7021, 7026–7034, 1738, 1848, 1891 · `styles.tcss` 51, 55–60, 61–64, 66, 73, 80, 88, 96, 100–102, 104 · `tests/test_tui_directionb.py` 753–754, 897–898, 6058–6072, 6325–6326 · `tests/test_tui_commandbar.py` 169, 251, 256, 279, 369, 419, 545 · `tests/test_loadfilescreen_input.py` 54.

**All 8 sites of LLR-121.4's RED-by-design census are exact to the line.** That census is the highest-risk list in the document (it decides what breaks and when) and it is clean.

### 1.4 Corrections the batch made late — all verified correct

- **P-49 (CSS span `:66-102`, not Phase-0's `:55-102`)** — confirmed: `#command_bar_slot` `:51-53`, block comment `:55-60`, `#command_bar` `:61-64` all **survive**; `#command_bar_row` starts `:66`; `#cmdbar_goto_input` ends `:102`; `#command_palette` starts `:104`. Phase 0's span would have deleted a surviving block. The correction is right and load-bearing.
- **P-33b (the shipped diff golden shows no results columns)** — confirmed by entity-decoded scan of `[diff-comfortable-120x30].svg`: `Runs` False, `Image A` False, `Image B` False, `Compare` True, `Report` True. 29 snapshot cells total ✓.
- **P-48 (`test_universal_paste.py` is NOT at risk)** — confirmed: it drives `#palette_input` (`:201`), its AST census sweeps `_TUI_DIR.rglob("*.py")` for **stock `Input()`** (`:52`), and it holds no count assertion and no `find_input` reference. Deleting two `OsClipboardInput` constructions cannot redden it.
- **P-38c (no `(1/1)` for a single-variant project)** — confirmed: the suffix branch is gated on `len(variant_set.variants) > 1` (`app.py:11333`) and `tests/test_tui_variants.py:259` pins the plain form. The phantom the batch caught in itself was real.
- **P-37 (registry G2 goes red)** — confirmed against `AT-TC-REGISTRY.jsonl` (1373 rows): exactly **4 LIVE** rows name `test_tui_commandbar` nodes — `TC-007` (2), `TC-008` (**5**), `TC-009` (4), `TC-039` (2). Widening US-78-4 by one file is correct.
- **P-39 / D-3 (palette stays at 37)** — executed: `visible_palette_actions()` n=**37**, contains `focus_find` **and** `focus_goto`; `_build_palette_entries()` n=37. Same at 80×24 / 120×30 / 132×44.
- **P-51 / C16 (14 Footer chips)** — executed: exactly `['ctrl+k','ctrl+d','ctrl+l','ctrl+s','slash','g','q','x','k','question_mark','plus','minus','comma','period']`, identical at all three sizes. The document's list is verbatim correct.
- **C10 / P-20 (frozen keymap)** — `_PRE_BATCH_BINDINGS` is 14 tuples; `j` and `p` present; **neither `slash` nor `g` present**; `k` is bound `show=True` at `app.py:1359` and is *not* frozen. D-4's reasoning holds on all four legs.
- **C-38 blast radius** — reproduces to the number over `tests/`: `diff_range_list` **8 / 3 files**, `AbDiffPanel` **25 / 5 files**, `render_comparison` **5 / 3 files**.
- **Lane-1 at-risk test files = 6** — my own C-26 reverse-grep of all 15 deleted symbols/ids across `tests/` returns the union `{test_tui_commandbar, test_tui_directionb, test_tui_patch_variant, test_tui_variants, test_loadfilescreen_input}` = 5, plus `test_tui_app` (blind stubs, P-38b) = **6**. Matches.
- **Amendment Before-texts** — `REQUIREMENTS.md:594-596` and `:1130-1133` quoted **verbatim exact**.

### 1.5 Structure

- **Normative-keyword claim is SOUND on the point that matters.** 39 `**Statement:**` lines (9 HLR + 30 LLR = 39 ✓). Programmatic scan for `should|must|may|might|will|ought|can|could` over all 39: **zero hits**. **No blocker on this axis.** (The weaker claim about `shall` placement is false — see M10.)
- **ID sizing is sound.** All 31 `AT-B78-nn` and all 45 `TC-B78-nn` appear; **no gaps, no unminted ids**. `_meta.next_free` untouched.
- **Every AT is realized by exactly one increment.** I enumerated §7's ATs-realized column: 31 of 31 assigned, none orphaned, none double-realized (`AT-B78-25` is deliberately split by arm across Inc-5/Inc-9, and `AT-B78-03`/`AT-B78-12` are additionally *enabled* by Inc-0).
- **The two-axis notice regime is genuinely two-axis, and both arms are independently reachable.** Verified: `80×30` passes height (2 content rows post-S-8/S-1) and fails width (`C=70` → window 65 < 79); `120×24` passes width (`C=92` → 87 ≥ 79) and fails height (24 < 29). A single conjunction would indeed be wrong in each single-axis case. The document is right to force axis-naming. (What it does not specify is the *both*-fail case — M7.)
- **The R-4 ordering conclusion survives** even though its stated figure is at the wrong layer (M1): at 132×44 the shipped `#diff_hex_a` has **7 content rows**, so Lane 2's acceptances really are observable with no Lane-1 work.
- **Security posture (R-8) is correct as a judgement.** I found no new file, network, credential or subprocess path in scope. The only new data path is display text to a rendered label, and LLR-120.4 binds it with `markup=False` at construction with a live precedent (`app.py:1916`). No `security-reviewer` gate is owed for this scope. **One gap:** the same control is *not* carried to the run-list widget swap — see M10.

---

## 2 · BLOCKERS

### 🔴 BL-1 · `AT-B78-03` is inert. Executed proof: removing a whole command from `BINDINGS` leaves it GREEN.

**Where.** `01-requirements.md:210` (HLR-118 Acceptance) — *"the palette's action set, derived from `app._build_palette_entries()`, **never hand-listed** (C-31)"*; `:211` — ***`AT-B78-03`** (**PIN**) the action set equals the producer-derived 37-member set*; `:587` (§5.3) — *"✅ derived from the producer"*, reddening mutation *"as `AT-B78-02`"*.

**Why it cannot fail.** `CommandBar` is constructed as `CommandBar(self._build_palette_entries())` (`app.py:1878`) and `visible_palette_actions()` returns `[e.action for e in self._visible_entries]` (`command_bar.py:204-205`), where `_visible_entries` is initialised to that same tuple (`:137`). Observed and expected are the **same producer**: the predicate is `f(x) == f(x)`.

**Executed transcript** (in-process, restored, `git diff --stat -- s19_app/ tests/` empty):

```
# the predicate exactly as HLR-118 words it, driven through ctrl+k with an asserted blur
PRE  : (set_equality=True, observed=37, expected=37)
removed binding: Binding(key='question_mark', action='show_help_panel', ..., show=True)
MUT  : (set_equality=True, observed=36, expected=36)   <- GREEN. The predicate is INERT.
POST : (set_equality=True, observed=37, expected=37)

# second mutation: substitute focus_find/focus_goto for other actions (set size preserved in intent)
PRE  : set_equality=True  count=37  has_focus_find=True   has_focus_goto=True
MUT  : set_equality=True  count=35  has_focus_find=False  has_focus_goto=False
POST : set_equality=True  count=37  has_focus_find=True   has_focus_goto=True
```

`set_equality` is **True under both mutations**. Only the literal-`37` count clause and the explicit `focus_find`/`focus_goto` membership checks discriminate — and the Acceptance block explicitly forbids hand-listing, which is what those clauses are.

**Additionally, §5.3's declared reddening mutation for this row does not bear on its subject.** Nulling `action_focus_palette` prevents the palette *opening*; `visible_palette_actions()` returned 37 in my probe with the palette never opened. So the row is marked discharged by a mutation that cannot touch it.

**This is F-6 in a stronger form.** The document catches "a cap AT that expects the constant certifies the constant, not the capping", generalises it, and rewrites `AT-B78-18`. `AT-B78-03` is the same shape one level up: an *invariance* AT that derives its expected set from the system under test certifies the derivation, not the invariance. `AT-B78-03` is the sole evidence for **D-3**, the ruling that closes QA's blocker B-3.

**Minimal correction.** `AT-B78-03` compares `visible_palette_actions()` against the **Inc-0 committed artifact re-read from disk** — the C-12 output-then-consume shape already specified for `AT-B78-12`, and Inc-0 already captures exactly this payload (`:752`, *"the 37-action palette list, own commit, before any production edit"*). Delete *"derived from `app._build_palette_entries()`"* from `:210` and *"derived from the producer"* from `:587`; record the reddening mutation against the artifact form (removing a `BINDINGS` entry then reddens, because the artifact does not move). C-31 is misapplied at `:210`: for an invariance claim the "rule" is the pre-change capture, not the live producer.

---

### 🔴 BL-2 · Four acceptances are scheduled at Inc-9; their prerequisite lands at Inc-10. A correct implementation fails Inc-9's gate.

**Where.** `:748` — *"`AT-B78-24`'s 120×30 arm, `AT-B78-25`'s fallback arm, `AT-B78-27` and `AT-B78-29` depend on **US-78-8 and US-78-1**. Those arms land in **Inc-9**, on the Lane-1 side."*
US-78-1 = HLR-118 = deletion of `#command_bar_row` = **Inc-10** (`:762`). Inc-9's file list (`:761`) is `app.py, screens_directionb.py, tests/test_tui_commandbar.py, tests/test_tui_diff_screen.py` — it does **not** include `command_bar.py`, so the row still exists at Inc-9's gate.

**Executed** (120×30, `#diff_hex_a` as `(clipped_h, content_h, cols_clipped, status_clipped)`):

```
120x30  shipped        = (0, 0, 0, 0)
120x30  compact only   = (4, 0, 3, 1)   <- Inc-1..Inc-9 state: content rows still ZERO
120x30  compact+nobar  = (6, 2, 6, 1)   <- only reachable after Inc-10
```

`AT-B78-27` is *"at 120×30 with the bar removed, `#diff_hex_a` renders ≥ 1 hex row"* (`:326`). At Inc-9 the content height is **0**. The gate is RED for a correct implementation.

Inc-9 must still precede Inc-10 — `/` and `g` have to be re-pointed before their inputs are deleted, or the actions resolve nothing — so the ordering is right and the **arm placement** is wrong.

**Minimal correction.** Move `AT-B78-24`'s 120×30 arm, `AT-B78-25`'s fallback arm and `AT-B78-27` from Inc-9 to **Inc-10**. `AT-B78-29` (80×24, width axis) is width-only — at W=80, `C=70` → window 65 < 79 fails regardless of the bar — so it can move **earlier**, to Inc-5, where the notice regime is built. Restate `:748` naming Inc-10, not Inc-9.

---

### 🔴 BL-3 · Inc-1's gate is an invariant, and it contradicts the document's own "same test" clause.

**Where.** Two normative statements say the pair must be one test:
- `:325` (HLR-125 Acceptance) — *"⚠️ **C-40:** `height == 1` on the control rows is invariant under a change that also collapses the result area to zero — the second clause is what makes the pair a gate, and it is asserted in the **same** test."*
- `:547` (LLR-125.2) — *"⚠️ **C-40:** asserted in the **same test** as LLR-125.1. Separated, the height assertion is invariant under an implementation that compacts the rows and still leaves the result area at zero."*

§7 separates them by **eight increments**: `AT-B78-26` → Inc-1 (`:753`), `AT-B78-27` → Inc-9 (`:761`). Two tests in two increments cannot be one test.

**Executed — the document's own warning is exactly what happens.** With the control rows compacted and nothing else changed, at 120×30: rows → 1, `#diff_status` clipped → **1**, `#diff_hex_a` content → **0**. `AT-B78-26`'s full predicate (*"the three rows clip to 1 and `#diff_status` is visible"*) is **GREEN with the result area still empty** — the precise state `:325` says the pair exists to prevent. Inc-1 ships on an invariant.

**Minimal correction.** Inc-1 can be gated on a real observable without any Lane-1 work: at **132×44** compaction alone moves `#diff_hex_a` content from **7 → 13** (executed: `shipped=(11,7,…)`, `compact=(17,13,…)`). Add to Inc-1's gate a strict-increase clause on `#diff_hex_a.size.height` at 132×44 against the pre-change baseline of 7, asserted in the same run as the three 1-row clauses. Then either (a) re-scope the "same test" clause at `:325`/`:547` to *"the row-height clause is never asserted alone"*, or (b) keep `AT-B78-26`+`AT-B78-27` as one test and move it wholly to Inc-10 — but (a) is better, because it keeps Inc-1 gated.

---

## 3 · MAJOR

### M1 · C7 states a clipped figure and labels it "content"; the increment-order rationale then quotes the wrong layer.

`:85` (C7) header reads **"`#diff_hex_a` clipped rows"** but its last cell reads *"160×40 → 7 **content**"*. Executed: at 160×40 `#diff_hex_a` clipped = **7**, `size.height` = **3**. At 132×44 clipped = **11**, content = **7**. The document's own P-33 (`:126`) gives `160×40 → 3 / 9 / 12 content` — **3**, not 7. Two rows of the same document give the same widget at the same size as 7 and as 3, in a document whose §1.3 makes exactly this distinction load-bearing.

It propagates into the ordering rationale, `:747`: *"the diff result area is already visible at 132×44 with **11 clipped rows** today"* — the operative quantity for "how many hex rows can paint" is the **content** height, **7**. **The conclusion survives** (7 > 0, verified), so R-4/D-15 stands; the figure does not. Fix: state 132×44 as `#diff_hex_a` **content 7** / clipped 11, and correct C7's 160×40 cell to `clipped 7 / content 3`.

### M2 · "shall not exceed the window's clipped visible height" admits four rows of invisible overflow.

`:283` (HLR-123 Statement) and `:494` (LLR-123.2) bound the emitted row count by the **clipped visible height**. Executed, for these bordered boxes clipped = content + 4 (2 border + 2 padding, vertically) whenever the widget is inside the host:

```
132x44  #diff_hex_a  region/clipped 11  content 7   (delta 4)
160x40               region/clipped  7  content 3   (delta 4)
120x30               region 4, clipped 0, content 0 (delta 4)
```

An implementation emitting 11 rows into a 7-row box passes. §5.5 row 18 (`:659`) adopted this clause because it *"kills a 'just make it 40' fix"* — it kills 40 and not 11. Fix: bound the count by `#diff_hex_a.size.height` (content), and keep the clipped read as the separate visibility co-assertion.

### M3 · The "actually on screen" clipped-**width** clause is invariant under total vertical invisibility.

`:308` — *"plus the clipped visible width, so the window is not merely un-wrapped but **actually on screen**"*; adopted from QA at `:660`. Executed at 120×30, shipped: `#diff_hex_a` clipped region = **(width 30, height 0)**. A window with **zero** visible rows reports a non-zero clipped width. The clause cannot do the job it was adopted for. Fix: co-assert clipped **height ≥ 1** in the same read.

### M4 · Six vs seven deleted symbols — the AST census as specified cannot detect a violation of its own requirement.

- `:254` (HLR-121 numeric pass threshold) — *"an AST census finds **0** definitions of **the six symbols**"*
- `:598` (§5.3) — *"all **six** symbols + all six selectors exist"*
- `:251` (HLR-121 Statement) and `:434`/`:436` (LLR-121.1) name **seven**: `Find`, `Goto`, `on_command_bar_find`, `on_command_bar_goto`, `focus_find`, `focus_goto`, **`set_context_labels`** — and LLR-121.1's threshold says *"0 for the **seven**"*.

`set_context_labels` (`command_bar.py:216`) is the seventh, and LLR-120.1 removes its only call site (`app.py:11351`, verified). A six-symbol census therefore passes while a dead `set_context_labels` survives — violating HLR-121's own Statement. (The **six ids** figure for the CSS selector census is correct: `command_bar_row`, `command_bar_prompt`, `cmdbar_project`, `cmdbar_a2l`, `find_input`, `cmdbar_goto_input`.) Fix: `:254` and `:598` → **seven symbols**, enumerated, six selectors.

### M5 · `TC-B78-41` carries two unrelated subjects.

- `:229` — *"☑ **error** — `focus_find` before mount → no raise, `TC-B78-41`"*
- `:377` — *"`TC-B78-41` additionally asserts that with A2L active `#search_input` is **still resolvable** while the action resolves the A2L input"*
- `:667` — *"`TC-02` (routing on `_active_screen_key`) → 🆕 `TC-B78-41`"*

One id, two nodes: an error-class no-raise case and the white-box routing discrimination P-10 demands. In a project with a node-level registry guard this is not cosmetic. Fix: mint `TC-B78-46` for the routing discrimination (batch-scoped ids are free, §5.6) and leave `TC-B78-41` as the pre-mount error case.

### M6 · `_DIFF_WIDE_MIN` / `_DIFF_MIN_W` are declared "content units" and used as terminal widths.

`:511-512` (LLR-124.1) — *"`_DIFF_WIDE_MIN = 139` (**content units** …)"* … *"**The constants are in content units**; Phase 3 asserts against `size.width`, never against the CSS declaration."*
`:300` (HLR-124 Statement) — *"When the **terminal width** is at least the wide-regime breakpoint …"*

At W=139 the content width `C` is **111**, not 139 (executed). The precedent the LLR names, `_apply_width_regime`, receives `event.size.width` — a terminal width (`app.py:6239-6240`). An implementer following the "content units" sentence and comparing `#diff_columns.size.width` to 139 would not switch to the wide layout until **W = 167**. This is the batch's own **F-5** defect (*"a breakpoint reported without its units is not re-derivable"*, `:698`) reproduced inside the LLR that corrected it. Fix: declare `_DIFF_WIDE_MIN = 139` and `_DIFF_MIN_W = 94` as **terminal** widths and `_DIFF_MIN_ROWS_H = 29` as a **terminal height** (its name says "rows", which it is not); scope the "content units" sentence to the *list-width* figure alone (22 content = 26 border-box).

### M7 · The both-axes-fail case is unspecified, and it is the only case the notice acceptance actually tests.

HLR-124 (`:300`) and LLR-124.4 (`:529`) say the notice names *"the unsatisfied axis"* — singular. Executed: **80×24 fails both** (`C=70` → window 65 < 79, **and** H=24 < 29). `AT-B78-29` (`:309`) asserts that at 80×24 the notice *"names the **width** axis"*. Nothing in the document says what a notice must contain when both axes fail; an implementation that names the height axis first, or that emits a combined message in a form the predicate does not match, fails a correct implementation — or passes a wrong one. Fix: add to LLR-124.4 *"when both floors fail, the notice shall name both axes and both required values"*, and re-key `AT-B78-29` accordingly. Alternatively move `AT-B78-29` to a **width-only** failure — my sweep confirms `80×30` is width-only post-S-8/S-1 (2 content rows).

### M8 · §7's isolation claim is false by enumeration.

`:766` — *"**No increment edits a file another in-flight increment edits.** … **Inc-9 is the single crossing point** and it lands after both lanes' prerequisites."*

Enumerating §7's own Files column:

| File | Increments | Crosses lanes? |
|---|---|---|
| `styles.tcss` | 1, 2, 5 · **7, 10** | ✅ yes |
| `screens_directionb.py` | 2, 4, 5, 6 · **7, 9** | ✅ yes |
| `app.py` | 5 · **7, 9, 11** | ✅ yes |
| `tests/test_tui_diff_screen.py` | 1, 2, 3, 4, 5, 6, **9** | ✅ yes |
| `tests/test_tui_commandbar.py` | 0, 7, 9, 10, 11 | Lane 1 + Inc-0 |

**Three production files cross the lane boundary, not one.** The claim is true only under strict sequential execution, in which case no two increments are ever "in flight" and the sentence is vacuous. This matters concretely: `:717` (R-9) records that **a parallel session is writing in this tree right now**, and the sentence invites an executing session to parallelise Lane 2 with Lane 1. Fix: replace the sentence with the file×increment table above and state the execution model (strictly sequential) explicitly.

### M9 · GATE/PIN labelling is inconsistent with the criterion §5.3 actually applies.

§1.3 (`:51`) defines a PIN as *"invariant under the change it accompanies"*. §5.3's operative discriminator is the **"RED today"** verdict. Five rows carry **GATE** with neither a RED-today verdict nor an executed reddening transcript:

| Row | Verdict cell | Mutation cell | Transcript cell |
|---|---|---|---|
| `AT-B78-11` (`:596`) | GATE | *"set the new label to its own row"* | *"7 today"* — a measurement, not a mutation; 7 before and 7 after a correct change |
| `AT-B78-19` (`:602`) | GATE | *"none needed"* | cannot run today — no list exists to focus |
| `AT-B78-22` (`:605`) | GATE | **"none needed"** | *"derived from the constant today"* — **green today and green after**; `screens_directionb.py:7026-7029` already emits `run ± DISPLAY_CONTEXT_BYTES` |
| `AT-B78-25` (`:607`) | GATE | *"force one regime for all widths"* | **"—"** (empty) |
| `AT-B78-28` (`:609`) | GATE | *"add a `show=True` binding"* | *"14 chips / 78-col Footer measured"* — a measurement, not a mutation |

`AT-B78-22` is the clearest: labelled GATE, mutation column says *"none needed"*, and the behaviour it asserts is the shipped behaviour. By the document's own §1.3 it is a **PIN**. Meanwhile `AT-B78-18` — which *does* carry two executed reddening transcripts — is labelled a PIN. The label is anti-correlated with the evidence in at least these two cases.

Consequently `:800` (*"**6 PINs** … four carry an owed mutation"*) undercounts, and `:799` (*"Every AT demonstrated RED pre-change ✓ — 9 of 9, each executed"*) is a **per-story** figure presented as a per-AT one. Fix: re-label `AT-B78-11/19/22` as PINs with owed mutations at their increment gates; supply the missing transcripts for `AT-B78-25` and `AT-B78-28`; restate `:799` as "9 of 9 **stories** are RED today; 31 ATs comprise N gates and M pins".

### M10 · Normative `shall` outside requirement Statements — and one such clause has no acceptance at all.

`:803` claims *"`shall` appears only in HLR/LLR **Statement** lines and in §6.5's proposed requirement texts"*. Executed scan: five normative `shall` clauses live in **Rationale / Acceptance-criteria / ⚠️** notes — `:219`, `:308`, `:318`, `:462`, `:475`, `:504` — and §6.5's amendment texts use *"must"*, not *"shall"*, so the exemption does not apply either.

The load-bearing one is **`:462` (LLR-122.1)**: *"⚠️ **C-17:** the list renders `markup=True` and escapes the artifact summaries with `rich.markup.escape`. The replacement **shall** preserve that escape or render `markup=False`."*

Verified on disk: `_render_run_list` imports `escape` (`screens_directionb.py:6980`) and applies it to both artifact summaries (`:6984-6985`), while the target widget is `markup=True` (`:6766`). **The widget-type swap of LLR-122.1 is exactly where that escape gets lost** — and there is **no AT and no TC for it**. `TC-B78-12` covers C-17 only for HLR-120's project/A2L sinks. The document's own security posture (R-8, `:716`) rests on C-17 being carried at every new display sink; here it is asserted in a note and never gated. Fix: promote the clause into LLR-122.1's **Statement** and add a TC to HLR-122's boundary catalog — an artifact summary containing `[red]evil[/]` renders verbatim with no `MarkupError`, mirroring `TC-B78-12`.

### M11 · The merge was audited in one direction. §5.5's stated rule is false, and at least one architect observable exists in neither the merged document nor a retirement line.

`:638` — *"**Rule applied:** the architect allocation is canonical (**superset**, bound to the LLR structure). Every QA AT is mapped by subject, never by number."* §5.5 then reconciles **QA → canonical only**. The architect lane's own 30 ATs and 39 TCs are never reconciled, and the merged set is **not** a superset of them.

Verified instances (quoted from `01-requirements-architect.md`, then located — or not — in the merged document):

- **`01-requirements-architect.md:371`, LLR-118.1 Acceptance criteria — dropped wholesale, no retirement line:**
  > *"`#command_palette` remains a direct child of `CommandBar`; `CommandBar` remains composed at `app.py:1878` (**the palette must not move screens**)."*
  Merged LLR-118.1 (`01-requirements.md:353-356`) has Statement / Symbols / Validation and **no Acceptance criteria line**. `AT-B78-01`'s surviving co-assertion is `len(app.query("#command_palette")) == 1` (`:210`) — satisfied **wherever the palette lives**. HLR-118's whole premise is that the palette is a *sibling* that must not be disturbed by the row deletion; the one clause that guarded its position is gone. **This is the C-40 limb-2 instance-(ii) defect the review brief asked for.** Fix: restore the clause as LLR-118.1 acceptance criteria and add `#command_palette`'s parent identity to `AT-B78-01`'s co-assertion.
- **`01-requirements-architect.md:354` — id re-used for a different subject, unrecorded:** architect `AT-B78-29` = *"**the no-regression arm** — `git diff` over the App `BINDINGS` block is **0** lines"*. Merged `AT-B78-29` (`:309`) = the 80×24 notice axis. The observable itself survives, demoted to a threshold clause (`:336`, `:555`), but it no longer has a node and §5.5 does not say so.
- **`01-requirements-architect.md:285` — two run-list boundary cases lost their nodes:** *"exactly one run (`up`/`down` are **no-ops, no crash**), `TC-B78-18`"* and *"`up` on the first entry and `down` on the last, `TC-B78-19`"*. Merged `TC-B78-18` is the `DISPLAY_MAX_RUNS` case and `TC-B78-19` is the 1-run style-guard case (`:277`); the **list-edge no-op** case has no node anywhere, and HLR-122's merged catalog carries **no ☑ error class at all** (its last entry is marked "negative").

A delegated exhaustive enumeration reported a further ~12 dropped granular clauses in both directions (QA's post-Ctrl+K `#palette_input` focus target; QA's MAC arm of the wrong-pane discriminator; QA's *"`app.focused` is still `None`"* postcondition on the 7 notice screens; QA's positive Escape target; architect `TC-B78-03/07/10/22/33/37` subjects overwritten; architect LLR-122.2's blur-discipline acceptance criterion). **I verified the three quoted above directly and am reporting the remainder as delegated-and-unverified** — they should be re-checked at Phase 3 rather than taken on this review's authority.

Fix: run §5.5's reconciliation in **both** directions before the gate, and correct `:638`'s "superset" premise and `:665`/`:801`'s "0 RETIRED · No QA observable was dropped" to the reconciled truth.

---

## 4 · MINOR

| # | Finding | Evidence |
|---|---|---|
| **m1** | **`_project_label()` call sites are 14, not 16** — and the 16 was produced the way §10.3 warns about. Actual: `test_tui_patch_variant.py` 153, 155, 233, 305, 583, 599, 607, 772 = **8**; `test_tui_variants.py` 107, 154, 239, 274, 307, 394 = **6**. The doc's 9 and 7 (`:132`) are grep **line** counts minus one — they include the `def` and exclude the docstring. Cited as 16 at `:132`, `:427`, `:741`, `:760`. Not gating: LLR-121.4's real threshold is `grep -rn 'cmdbar_project' tests/` → 0, which is correct (5 lines, 3 files today). But it is *"a census whose count and enumeration came from different patterns"* — the batch's own §10.3 lesson, reproduced. |
| **m2** | **Line-citation drift, six instances, all ±1–2:** `_apply_display_caps` is `screens_directionb.py:6926` not `:6925` (`:86`, `:474`) · `render_comparison` is `:6877` not `:6879` (`:67`, `:489`) · the caps-notice branch is `:6995-6999` not `:6994` (`:460`, `:474`) · `rich.markup.escape` is imported `:6980` / used `:6984-6985`, not `:6986` (`:462`) · the `> 1` variant gate is `app.py:11333` not `:11332` (`:134`, `:236`, `:427`) · `g2_live_entries_have_nodes` is `tests/test_id_registry.py:222` not `:223` (`:131`, `:446`). |
| **m3** | **`_KIND_LABEL` is exactly derivable at `screens_directionb.py:6637`** yet is flagged *"`assumed — re-derive the exact line at Phase 3`"* (`:502`, A-6). An assumption flag on a one-grep fact inflates the assumption count and dilutes the four flags that are real. |
| **m4** | **LLR-125.2's ladder contradicts §5.3 on its first figure.** `:545` gives `#diff_columns` shipped = **1** at 120×30; `:608` gives `clipped=(92,0)` and `:317` says *"both have a clipped visible height of ZERO"*. I measure **0**. The other four figures of the ladder (3/0, 6/2) reproduce exactly. |
| **m5** | **135 vs 136.** `:512` says a CSS `width: 22` list *"moves the breakpoint to 135"*, matching P-34b's executed sweep (`:124`). §6.3 F-5 (`:698`) still records **136** as the reconciled figure. |
| **m6** | **`TC-B78-31`'s wording collides with HLR-124's zero-literals rule.** `:303`/`:514` require the literals `139`, `94`, `29`, `26` to appear **0 times in the tests**; `:310` words `TC-B78-31` as *"`W = 94` … and `W = 93`"*. The intent is clearly `size=(_DIFF_MIN_W, …)` / `(_DIFF_MIN_W − 1, …)`; say so, or the two clauses read as contradictory. |
| **m7** | **§5.5's TC reconciliation points at nodes with different subjects.** `:667` maps QA `TC-05` (*80×24 bounded degradation*) → `TC-B78-32`, but `TC-B78-32` (`:310`) is the **120×24 height-only** case; the 80×24 case actually lives in `AT-B78-29` and `TC-B78-34`. Likewise `TC-01` (*slot height*) → `TC-B78-40`, but `TC-B78-40` (`:212`) is the palette open/switch/reopen case. (The slot-height observable itself is safe — it is in `AT-B78-01`'s threshold, `:205`.) Bookkeeping errors in the table whose job is to prove nothing was lost. |
| **m8** | **Inc-12 edits 29 files** against §7's heading *"(dependency-ordered, ≤5 files each)"*. Self-evidently intentional (CI-only snapshot regen), but it breaks the stated invariant without saying so. |

---

## 5 · Evidence checklist (architect review)

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated explicitly | ✓ | §2.4's 16 constraints re-executed where measurable — C3, C4, C5, C6, C7, C10, C16 all reproduce (§1.1, §1.3); C7 carries a units defect (M1) |
| ≥2 alternatives considered | ✓ | Reviewed D-1's regime matrix, D-2's clause-by-clause ruling and D-4's two binding policies; each is a real comparison, not a post-hoc justification |
| Recommendation tied to constraints | ✓ | D-1's floors traced to executed measurements (`W≥94`, `H≥29`, both re-derived here); D-4 traced to C10 and C16, both re-executed |
| Risks listed | ✓ | This review: 3 blocker · 11 major · 8 minor, each with an executed transcript or a `file:line` |
| Cost / latency estimated | ✓ | Column/row budget is the cost axis; re-measured at 12 widths and 14 heights (§1.1, §1.2). No new I/O, network or compute in scope |
| Diagram when flow is non-trivial | ✓ | Agree with the document's ✗-with-reason: the S-7 budget is a numeric matrix and a diagram would blur it |
| What would change the recommendation | ✓ | §6 below |
| Two-layer requirements: Acceptance block + AT, both chains | ✓ | All 9 HLRs carry a first-class Acceptance block; 31 AT / 45 TC ids complete with no gaps; every AT realized by exactly one increment. **Caveat:** the behavioral chain has one inert node (BL-1) and one normative clause with no node at all (M10) |
| Reviewer's own mutations restored | ✓ | All in-process; `git diff --stat -- s19_app/ tests/` **empty** after each; predicate re-run to its pre-value (37 → 36 → 37) |

---

## 6 · Disposition

**NOT ready to implement as written. Needs design work — but bounded, local design work, not a re-derivation.** The measured foundation is sound and I could not break it.

**Must close before Phase 3 (blockers):**
1. **BL-1** — re-specify `AT-B78-03` against the Inc-0 artifact. *Wording change only; Inc-0 already captures the payload.*
2. **BL-2** — move three arms from Inc-9 to Inc-10, and `AT-B78-29` to Inc-5. *Table edit.*
3. **BL-3** — give Inc-1 a non-invariant gate (the 132×44 content-height increase, 7 → 13, already executed here). *Adds one clause.*

**Should close before Phase 3 (the majors that change what gets built, not just what gets written):** M4 (six→seven symbols — otherwise the census cannot detect its own requirement's violation), M6 (constant units — otherwise the wide regime never triggers below W=167), M7 (both-axes-fail rule), M10 (C-17 on the run-list swap has no acceptance), M11 (reconcile the merge in the second direction; restore LLR-118.1's palette-position invariant). M2, M3, M5, M8, M9 are acceptance-strength and bookkeeping and can be folded into the same pass.

**What would change this verdict.** If BL-1 is answered by pointing at Inc-0's artifact as the intended oracle all along, it drops to minor (a wording fix). If the executing session is confirmed strictly sequential *and* §7's isolation sentence is deleted rather than restated, M8 drops to minor. Nothing I found would change the batch's scope, its story set, its regime design or its increment ordering — R-4/D-15 survives, D-1's three regimes survive, D-4's keymap survives.

**One structural observation for the postmortem.** This document catches the "predicate certifies its own producer" defect twice — F-6 in QA's cap AT and, generalised, in its own `AT-B78-18` — writes the lesson down, and then ships `AT-B78-03` with the same shape. It records F-5 (*"a breakpoint reported without its units is not re-derivable"*) and then declares two terminal widths to be content units in the very LLR that carries the correction. It records §10.3 (*"a census whose count and enumeration come from different patterns has measured neither"*) and then reports 16 call sites where there are 14. **The lesson is not that the controls failed — it is that a lesson recorded in prose is not a control. Three of this batch's own recorded lessons were violated in the same document that records them.** The two that were violated in a *checkable* form (the modal-keyword scan, the id-completeness scan) both passed — because they are mechanical. The three that were violated are the ones stated only as prose.
