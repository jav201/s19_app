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

---
---

# RE-GATE — revision 2 (939 lines, uncommitted working tree over `cd62bc6`)

**Everything below is a second, independent pass.** Round-1 findings above are left untouched; the history is the evidence. Every "closed" verdict here was re-executed, not read. All probes in-process, restored, `git diff --stat -- s19_app/ tests/` **empty**.

## RE-GATE BLUF

**Round 1: 3 blocker · 11 major · 8 minor. Round 2: 3 of 3 blockers CLOSED · 9 of 11 majors CLOSED · 6 of 8 minors CLOSED — and 1 NEW blocker · 2 NEW majors · 5 NEW minors, all of them introduced or left by the fixes themselves.**

Revision 2 is a large and honest improvement. The two headline repairs are real and I proved them by execution rather than accepting them: **BL-1's new oracle genuinely breaks the same-producer loop**, and **§5.6's reverse audit found a loss I had missed**. The relabelled GATEs are honest — none was downgraded to dodge a fix.

The remaining problem is the one the coordinator predicted: **the fixes were applied where the defect was noticed and not swept to every dependent.** The BL-2 arm move left `LLR-124.3` with no implementing increment. `Q-M4`'s replacement Footer baseline is itself off by one — and the document's own enumeration contradicts its own count. `M2`'s content-vs-clipped fix landed in the HLR and in the LLR's Statement but not in that same LLR's numeric threshold. §6.4a — the section added *to prevent exactly this* — does not list either of the two changes that actually failed to propagate.

---

## RG-1 · Round-1 blockers

### BL-1 — CLOSED, verified by side-by-side execution

The coordinator's specific question — *does an artifact captured by the same code path still break the loop?* — is answered by the **temporal** freeze, not by the capture path. I built the Inc-0 artifact exactly as §7 specifies (captured from the shipped surface on the pre-change tree, written to disk), then ran both oracle forms against the **same mutation in the same process**:

```
Inc-0 artifact written: 37 actions, sha f1348719c081eef8
                             artifact-form            producer-form
PRE                          (True,  37, 37)          (True,  37, 37)
MUT  (drop Binding           (False, 36, 37)  <-RED   (True,  36, 36)  <-still INERT
      question_mark
      -> show_help_panel)
POST                         (True,  37, 37)          (True,  37, 37)
artifact sha unchanged: f1348719c081eef8
```

The artifact's hash is **identical across the mutation**: the expectation does not track the producer, so the observed set moves alone and the predicate reddens. **The loop is broken.** HLR-118's Acceptance (`:212`) now says *"compared against the Inc-0 artifact re-read from disk … **never against `app._build_palette_entries()`**"*, Inc-0's gate (`:874`) says *"this artifact is `AT-B78-03`'s only oracle"*, and §5.1 rule 10 (`:607`) generalises the class correctly. The author also re-executed and recorded that rev-1's declared mutation (`action_focus_palette` → `None`) leaves the action set invariant — which matches what I found independently in round 1.

### BL-2 — arms CLOSED, but the move opened NEW-1

Verified by enumerating §7's ATs-realized column rather than reading the prose: **all 32 live ATs are assigned to exactly one increment, none orphaned, none double-realized.** `AT-B78-24`/`-25`/`-26` are at **Inc-10** (`:884`), `AT-B78-29` at **Inc-5** (`:879`), Inc-9 realizes `AT-B78-04…07` only (`:883`). The arms were **moved, not softened** — each keeps its full predicate. The §7 file × increment map (`:890-897`) was swept consistently: `screens_directionb.py` no longer lists Inc-9; `tests/test_tui_diff_screen.py` gained Inc-10. The BL-2 narrative at `:857-866` reproduces my executed ladder correctly. **The scheduling defect is fixed.** What the move broke is NEW-1 below.

### BL-3 — CLOSED, figure re-verified

`AT-B78-33` (`:650`, `:875`) gates Inc-1 on `#diff_hex_a.size.height` at 132×44 rising from the pre-change baseline. My own round-1 sweep is the independent confirmation: **shipped `(content 7, clipped 11)` → compaction alone `(content 13, clipped 17)`** — a strict increase reachable with no Lane-1 work. Inc-1 is no longer gated on an invariant, and `:875` requires it asserted in the same run as the three 1-row clauses and the `#diff_status` clause.

---

## RG-2 · Round-1 majors

| # | Verdict | Evidence |
|---|---|---|
| **M1** C7 layer mislabel | **CLOSED** | `:86` now carries both layers: content `0 · 0 · 7 · 3`, clipped `0 · 0 · 11 · 7`. **Identical to my independent measurement.** §7's ordering rationale (`:855`) now quotes *"7 content rows today"*, the operative number. |
| **M2** clipped bound 4 rows loose | **PARTIAL — see NEW-3** | HLR-123 Statement and threshold (`:297`) now say **content** height; LLR-123.2's Statement (`:524`) says **content**; **LLR-123.2's own numeric threshold (`:527`) still says "≤ its clipped height"** |
| **M3** clipped-width invariant | **CLOSED** | `:642` — `AT-B78-24` now carries *"plus clipped **height ≥ 1** (M3)"*. My evidence was the executed `(width 30, height 0)` at 120×30. |
| **M4** six vs seven symbols | **CLOSED** | `:631` *"all **seven** symbols (1 definition each, executed)"*; Inc-11 gate (`:885`) *"**seven-symbol, class-qualified** AST census"*; §5.6.1 records the strengthening. |
| **M5** `TC-B78-41` double subject | **CLOSED** | `TC-B78-46` minted for the routing discrimination (`:757`, `:673`); the pre-mount error case keeps `-41`. |
| **M6** constant units | **CLOSED** | `:541-542` — *"`_DIFF_WIDE_MIN = 139` **terminal columns** … `_DIFF_MIN_H = 29` **terminal rows**"*, with my exact counter-example carried: *"an implementer comparing `#diff_columns.size.width` to 139 would not switch regime until **W = 167**"*. Renamed `_DIFF_MIN_ROWS_H` → `_DIFF_MIN_H`. |
| **M7** both-axes-fail unspecified | **CLOSED** | `:559` Statement now says *"naming **every** unsatisfied axis"*; `:560-562` — 80×24 fails **both** and the threshold requires the notice to name **both**; width-only (`80×30`) and height-only (`120×24`) arms specified separately. Bonus: SEC-F2 bounds the new notice surface. |
| **M8** isolation claim false | **CLOSED** | `:888-899` — the claim is withdrawn, the file × increment table is printed, and the plan is declared *"explicitly **strictly sequential**"*. Three production files crossing the lane boundary is now stated, not denied. |
| **M9** GATE/PIN labelling | **CLOSED**, relabels audited honest | `:614`, `:654` — **24 GATEs / 9 PINs**. All three relabels move **toward** honesty, none away: `AT-B78-11` green today (`7` on all 10 screens) with a mutation owed at Inc-7; `AT-B78-19` green today **with its precondition silently false** (I reproduced this — see RG-3); `AT-B78-22` was an inert PIN and is rewritten into a real gate. §9 (`:934`) now says *"9 of 9 **stories**, not 31 of 31 ATs"*. **No GATE was downgraded to avoid fixing it.** |
| **M10** normative `shall` outside Statements | **PARTIAL** | The load-bearing half is **closed**: `TC-B78-48` is minted as *"the M10 C-17 node"* (`:757`) for the run-list markup escape, and the functional chain routes it to HLR-122 (`:673`). The claim itself is **not** closed: §9 (`:938`) still asserts *"`shall` appears only in HLR/LLR **Statement** lines"* while an executed scan finds **12** occurrences outside them (`:221, 319, 329, 491, 496, 505, 534, 629, 734`, plus the legitimate `:204` *"Statement (continued)"*). §6.5's amendment texts use *"must"*, so that exemption still does not apply. |
| **M11** one-directional merge audit | **CLOSED — and it found more than I did** | §5.6 (`:710-754`) audits all 19 architect acceptance criteria: **14 merged · 3 superseded-with-reason · 2 lost-and-restored**. The second loss is `LLR-122.2`'s blur discipline, which I did not find. **I reproduced its consequence exactly** — see RG-3. §5.6.2 restores the two overwritten subjects as `AT-B78-32` / `TC-B78-47`, and confirms the six subjects I had flagged *delegated-and-unverified* do reconcile. |

**Modal discipline re-checked:** 39 `**Statement:**` lines, programmatic scan for `should|must|may|might|will|ought|can|could` → **zero hits**. Still sound.

---

## RG-3 · Independent re-execution of the author's claimed closures

### Q-M5 / `AT-B78-19`'s silently-false precondition — reproduces exactly

```
target_type='Static'   can_focus=False
app.set_focus(#diff_range_list)  ->  focused = ('RailItem', 'rail_item_workspace')
```

`set_focus` on the `Static` run list does not take; focus lands on the workspace rail item, and `k` opens the Legend regardless. `AT-B78-19` was green today **without ever reaching its subject** — which is why restoring LLR-122.2's blur discipline is not bookkeeping. This is the single strongest catch in revision 2 and it is real.

### Q-M1 / `AT-B78-22` — structurally confirmed inert in its rev-1 form

Re-read at source: `low = max(0, start - self.DISPLAY_CONTEXT_BYTES)` (`screens_directionb.py:7026`), `high = end + self.DISPLAY_CONTEXT_BYTES` (`:7028`), `row_bases = range(low, high, HEX_WIDTH)` (`:7029`). Rev-1's expectation was computed from the same class attribute, so a `16 → 64` mutation moves expectation and observation together — the F-6 shape, exactly as claimed. The rewrite to three literal addresses reddens. This corroborates my round-1 M9 entry, which flagged `AT-B78-22` as green-today with mutation *"none needed"*.

### m5 / 135 vs 136 — CLOSED, and the "rejection" rests on a misreading of my finding

My round-1 m5 said, verbatim: *"`:512` says … **135**, matching P-34b's executed sweep. §6.3 F-5 (`:698`) still records **136**."* **I reported the internal contradiction and identified 135 as the correct figure — I never asserted 136.** Settled by arithmetic on my own measured constants: `C = W − 28` for `W ≥ 120` (measured exact at 12 widths), so an 18-content-cell list needs `C ≥ 18 + 89 = 107` → `W ≥ 135`; at `W = 134`, `C = 106` → window `106 − 18 − 10 = 78` fails; at `W = 135`, `C = 107` → **79 passes**. **135 is right.** Revision 2 fixed it the way I asked: §6.3 F-5 (`:785`) now reads *"**135** (18-content-cell list, authored CSS `width: 22`) vs **139** (22-content-cell list) are the same bound at two list widths"*. The finding is closed; the rejection framing is not accurate.

### Round-1 minors

`m2` line drift — spot-checked closed · `m3` `_KIND_LABEL` — closed at `screens_directionb.py:6637-6641`, matching my round-1 figure (but see NEW-5) · `m6` — closed, `TC-B78-31` is now worded `size=(_DIFF_MIN_W, …)` and `(_DIFF_MIN_W - 1, …)` (`:321`) · `m7` — closed, explicitly re-pointed to `TC-B78-34` and crediting the finding (`:708`) · `m8` — closed (`:901`).
`m1` **PARTIAL** and `m4` **NOT CLOSED** — see NEW-5 and the note at the end of RG-4.

---

## RG-4 · NEW findings

### NEW-1 (blocker) · The BL-2 move left `LLR-124.3` — the fallback layout — with no implementing increment.

Revision 1's Inc-5 read *"**HLR-124** wide **+ fallback** layouts and the notice regime *(width arms only)*"*. Revision 2's Inc-5 (`:879`) reads **"HLR-124 wide layout + the notice regime"** — the word *fallback* was dropped when its observing ATs moved out. A grep for `fallback` across the whole document returns **no increment that builds it**: `:552` defines `LLR-124.3`, `:642-643` place `AT-B78-24`/`-25` at Inc-10, `:914` puts assumption `A-2` (the overlay's dismissal mechanism) at Inc-10.

**Inc-10 cannot build it.** Its file set is `command_bar.py`, `styles.tcss`, `tests/test_tui_commandbar.py`, `tests/test_tui_diff_screen.py` — **no `screens_directionb.py`, no `app.py`** — and §7's own file × increment map (`:893-894`) confirms neither file is allocated to Inc-10. So a Phase-3 executor who builds Inc-5 to its content line arrives at Inc-10 with `AT-B78-24` (*"no hex row wraps, **fallback regime**"*) and `AT-B78-25` (*"the regimes are observably different … at 120 it reserves 0 permanent columns and the viewport paginates"*) both RED and **no allocated file in which to make them green** — forcing either a 6-file Inc-10 that contradicts the map, or the weakened acceptance this project has recorded as its historical failure mode.

`A-2` compounds it: §6.4a (`:815`) re-points A-2 from Inc-5 to Inc-10 *because the AT moved*, so the overlay's dismissal mechanism is now chosen in an increment that does not own it and verified in an increment that cannot change it.

**Minimal correction.** Restore *fallback* to Inc-5's content cell — *"**HLR-124** wide **+ fallback** layouts + the notice regime"* — since Inc-5's existing 4-file set (`screens_directionb.py`, `app.py`, `styles.tcss`, `tests/test_tui_diff_screen.py`) already supports it; annotate Inc-10 as **observing** a layout built at Inc-5; and return `A-2`'s owner to **Inc-5** (where the mechanism is chosen) with its discharge noted at Inc-10. Related nit: Inc-5 now ships the wide layout with `AT-B78-25`'s wide arm unchecked until Inc-10, because `AT-B78-23` asserts only no-wrap.

### NEW-2 (major) · `Q-M4`'s replacement Footer baseline is itself wrong — and the document's own enumeration contradicts its own count.

`:585` states: *"there are **15** children … and **only 7 are painted wholly inside the width** (the rest are laid out at x = 68, 82, 92, 100, 109, 118, 126)"*. **That list has 7 entries. 15 − 7 = 8, not 7.** The sentence refutes its own figure.

Executed independently at three sizes, printing every child's absolute `x`, `width` and right edge:

```
80x24   Footer.region=Region(x=1, y=22, w=78, h=1)   size.width=78   children=15
        ... FooterKey(x=60,w=8 ->68)  FooterKey(x=67,w=12 ->79)  FooterKey(x=68,w=14 ->82) ...
        region-relative containment (x>=1 and x+w<=1+78=79) :  8 painted
        frame-mixing form            (x+w <= 78)             :  7 painted
120x30  region-relative: 13    frame-mixing: 12
160x40  region-relative: 15    frame-mixing: 14
```

The Footer is **inset by one column** (`region.x = 1`), so its painted span is absolute `[1, 79)`. There is exactly one right-aligned child per size — ending at 79 / 119 / 159, i.e. **flush with the Footer's right edge** — and it is painted. The document's 7 / 12 / 14 comes from comparing an **absolute** child coordinate against a **relative** width (`size.width = 78`), which discards that child at every size. **The honest painted counts are 8 / 13 / 15.**

The conclusion survives — rev-1's *"all 14, none truncated"* is still wrong, because 14 ≠ 8 either — but `LLR-126.1`'s threshold (`:586`) is keyed on *"unchanged at **7**"*, and `:585`'s claim that rev-1 *"false-fails `origin/main` itself **under any honest painted-layer reading**"* is falsified by the honest reading. A Phase-3 author who writes proper containment measures 8 on `origin/main` against a spec that says 7.

**Minimal correction.** State the containment predicate explicitly (region-relative: `child.region.x >= footer.region.x and child.region.x + child.region.width <= footer.region.x + footer.size.width`) and re-derive the baselines to **8 @ 80×24**, 13 @ 120×30, 15 @ 160×40. The set-equality repair on the *model* key set (`:585`, executed `+1 chip → contains-all True, set-equality False`) is correct and unaffected.

### NEW-3 (major) · M2's content-vs-clipped fix was not swept inside its own LLR.

`LLR-123.2`'s Statement (`:524`) now bounds the row count *"above by the window's **content** height"*, and HLR-123's threshold (`:297`) says *"each is **≤** its pane's **content** height"*. **`LLR-123.2`'s own numeric pass threshold (`:527`) still reads *"each is **≤** its clipped height"*** — two lines below its corrected Statement. Executed, clipped = content + 4 for these bordered boxes (132×44: 11 vs 7; 160×40: 7 vs 3; 120×30: 4 vs 0), so the surviving threshold still admits **four rows of invisible overflow**. One-word fix; it is the same block, not a distant dependent.

### NEW-4 (minor) · The withdrawn "superset" premise is still asserted at its original site.

§5.6.3 (`:752`) withdraws it: *"`§5.5`'s 'the architect allocation is canonical (superset)' is **withdrawn**."* §5.5's own header (`:679`) still reads: *"**Rule applied:** the architect allocation is canonical (superset, bound to the LLR structure)."* Of the three claimed withdrawals, this is the one recorded but not applied; §7's and §9's withdrawals are clean (`:888`, `:934`).

### NEW-5 (minor) · Two figures corrected in one place and left stale in another.

- **`m1` (14 vs 16 `_project_label()` call sites):** corrected at P-38 (`:133`, *"14 call sites"*) and Inc-8 (`:882`, *"re-point the **14**"*), **still 16** at §6.5 Amendment B (`:849`, *"guarded by the 16 re-pointed `_project_label()` call sites"*). My enumeration stands: 8 in `test_tui_patch_variant.py` + 6 in `test_tui_variants.py` = **14**.
- **`A-6` vs `LLR-123.3`:** `:532` records `_KIND_LABEL` as *"re-derived this session — the earlier `assumed` flag is [removed]"* at `screens_directionb.py:6637-6641`, while §8 `A-6` (`:918`) still lists *"`LLR-123.3`'s `_KIND_LABEL` line"* as an open assumption.

### NEW-6 (minor) · §6.4a omits the two changes that actually failed to propagate.

§6.4a (`:809-825`) is the section added to enforce coordinator rule 2. Its nine rows cover BL-2, BL-3, the `-27` retirement, the `_DIFF_MIN_H` rename, `safe_text`, `OWNING`, the Footer baseline, the seven symbols and `test_tc029`. It does **not** list the 14-vs-16 census correction (NEW-5) or the content-vs-clipped correction (NEW-3) — the only two edits in this revision whose dependents were in fact missed. A propagation register that omits the changes that failed to propagate has not measured propagation.

### NEW-7 (minor) · `AT-B78-11`'s relaxed threshold is satisfied by a collapsed status bar.

`:629` relaxes the threshold from `== 7` to `<= 7` so it cannot false-fail a height *reduction* — correct reasoning for the *"shall not increase"* wording. But `<= 7` is also satisfied by a `#workspace_status_bar` of height **0**. `AT-B78-08` (both names readable on 10 screens) would catch that, but the two are separate ATs and nothing requires them in the same run. Add a `>= 1` floor, or co-assert `AT-B78-11` with `AT-B78-08`.

### `m4` — still open, unchanged

`LLR-125.2`'s ladder (`:576`) still reads *"shipped **1/0**"* for `#diff_columns` / `#diff_hex_a` at 120×30, while §5.3 (`:644`) records `#diff_columns clipped=(92,0)` and HLR-125's rationale says both clip to **ZERO**. My measurement: **0**. The other four ladder figures (3/0, 6/2) reproduce exactly.

---

## RG-5 · Re-gate disposition

**Revision 2 is NOT yet ready to implement — but it is one small edit away, and the gap is far narrower than round 1's.**

| Round-1 | Closed | Partial | Open |
|---|---|---|---|
| 3 blockers | **3** | — | — |
| 11 majors | **9** | 2 (M2, M10) | — |
| 8 minors | **6** | 1 (m1) | 1 (m4) |

| New at revision 2 | Count |
|---|---|
| blocker | **1** — NEW-1, `LLR-124.3` has no implementing increment |
| major | **2** — NEW-2 Footer baseline off by one; NEW-3 M2 unswept inside its own LLR |
| minor | **4** — NEW-4, NEW-5, NEW-6, NEW-7 |

**Must close:** **NEW-1** (restore *fallback* to Inc-5's content cell; re-point `A-2` to Inc-5) — a two-cell edit, no re-derivation, Inc-5's file set already supports it.
**Should close in the same pass:** **NEW-2** (state the containment predicate; baselines 8 / 13 / 15), **NEW-3** (`:527` clipped → content), **M2**/**M10**'s residue (`:527`, `:938`), **m1**'s residue (`:849`), **m4** (`:576`), NEW-4 (`:679`), NEW-5 (`:918`), NEW-7.

**What would change this verdict.** If Inc-5 is confirmed to build all of HLR-124 — LLR-124.1 through .4 — and its content cell says so, NEW-1 drops to minor and **revision 3 is implementable**. Nothing found in this pass touches scope, story set, regime design, increment ordering or the measured foundation: I re-verified the 79-cell row, `C = W − rail − 6`, the 4/22 rail, chrome 5, the `W ≥ 94` floor, the 135 and 139 breakpoints, the content/clipped ladder and the 37-action palette, and **every one still reproduces**.

**Process note for the postmortem.** Round 1's structural observation was that *a lesson recorded in prose is not a control*. Revision 2 tested that directly: it added §6.4a, a propagation register, as prose. Both edits whose dependents were missed are absent from that register — while every mechanical check in this document (the modal scan, the id-completeness scan, the AT-to-increment enumeration) came back clean again. **The register did not fail because the author was careless; it failed because a register you fill in by hand measures your attention, not your propagation.** The one control that would have caught NEW-1, NEW-3 and NEW-5 is mechanical and cheap: assert that every `LLR-nnn.n` appears in some increment's content cell, and that every figure appearing more than once in the document appears with one value.

---
---

# RE-GATE — revision 3 (971 lines, uncommitted working tree over `cd62bc6`)

Third independent pass. Rounds 1 and 2 above are untouched. Every verdict re-executed. All probes in-process; `git diff --stat -- s19_app/ tests/` **empty**; the only file I wrote is this one.

## RE-GATE 3 BLUF

**No blockers. 1 major · 4 minors, all documentation-layer. Revision 3 is implementable.**

Round-2 findings: **NEW-1 (blocker) CLOSED · NEW-2 CLOSED at the requirement layer · NEW-3 CLOSED · NEW-4, NEW-5, NEW-6, NEW-7 CLOSED · M2 CLOSED · M10 CLOSED · m4 CLOSED.** Every one verified by re-execution, not by reading the closure claim.

The derived §6.4a is the real result of this round, and it works: **it fixed 15 sites, including all three the hand-filled register had *claimed* as swept.** My round-2 diagnosis ("a register you fill in by hand measures attention, not propagation") is adopted verbatim at `:824` and the two mechanical Phase-3 gate checks I proposed are written in at `:852`. I ran the first of them myself — **all 30 LLRs are now covered by an increment Content cell** — and it is exactly the check that would have caught BLK-A.

The one major is the sharpest possible answer to the coordinator's "test this hardest" question, and it is *not* the failure mode expected. **The term list is complete and the regexes do fire — `enum.py`'s Footer term surfaces the stale site when I re-run it. The failure moved downstream, to the disposition step:** §6.4a documents a narrower pattern than the script executes and defers the numeric baseline to a row that does not exist, so the one site the enumeration found went un-dispositioned and `§5.3` still carries the withdrawn number **7** where the requirement now says **8**.

---

## RG3-1 · BLK-A (my NEW-1) — ✅ CLOSED, and the author's reasoning is correct

**Verified mechanically, not by reading.** I ran the coverage assertion the author adopted:

```
increment rows: 13
HLRs named in Content cells : HLR-118 … HLR-126   (9 of 9)
LLRs named in Content cells : LLR-121.4, LLR-122.4, LLR-124.1, LLR-124.2, LLR-124.3, LLR-124.4
LLRs defined in the document: 30
LLRs with NO increment (by name or via parent HLR): NONE
```

Inc-5 (`:907`) now reads **"HLR-124 in full — `LLR-124.1` (constants + regime class), `LLR-124.2` (wide layout), `LLR-124.3` (fallback: overlay + paginated viewport), `LLR-124.4` (notice regime)"**, and Inc-10 (`:912`) states **"No production code for HLR-124 is written here — Inc-10 OBSERVES the fallback layout built at Inc-5, using the test file it already owns."** The file map (`:924-929`) is consistent: Inc-5 holds `screens_directionb.py` + `app.py` + `styles.tcss`; Inc-10 retains `tests/test_tui_diff_screen.py`.

**The rejection of the additive fix is right, checked against the file map myself.** `LLR-124.1`'s Statement requires the regime to be applied by a CSS class, and its Symbols cite the `_apply_width_regime` ← `on_resize` precedent — both in **`app.py`** (`:6205`, `:6239-6240`, verified on disk in round 1). Adding only `screens_directionb.py` to Inc-10 would have given Inc-10 the overlay widget and **not** the regime toggle: `app.py` appears at increments 5, 7, 9, 11 and never at 10. So the additive fix supplies half the fallback, exactly as the author argues. Second reason also holds: it keeps diff-panel layout out of the command-bar-deletion increment, preserving the C-30 snapshot rationale.

**One record correction.** The coordinator's message says *"You and QA both proposed adding `screens_directionb.py` to Inc-10."* That is not what this lane proposed. My round-2 minimal correction reads, verbatim: *"Restore fallback to Inc-5's content cell … since Inc-5's existing 4-file set already supports it; annotate Inc-10 as **observing** a layout built at Inc-5; and return `A-2`'s owner to **Inc-5**."* All three clauses were adopted, and the document itself attributes it correctly at `:918` (*"the architect lane proposed restoring the build to Inc-5. **I took the architect's**"*) and at `:946` (`A-2` → **Inc-5**, discharged at Inc-10). **This finding should be recorded as adopted, not superseded.** (Third attribution slip this batch, after m5 and the `AT-B78-22` mutation below; the document gets all three right — the routing messages do not.)

## RG3-2 · NEW-2 (Footer) — ✅ CLOSED at the requirement layer, ⚠️ one dependent site missed → NEW-8

The §1.3 definition (`:52`) is **normative and correct**, and it is the rule I executed:

> *"A Footer child is painted **iff** `child.region.x >= footer.region.x` **and** `child.region.x + child.region.width <= footer.region.x + footer.size.width` — containment evaluated **entirely in absolute (screen) coordinates** … `Footer.region.x == 1` (executed), so comparing an **absolute** child `x + width` against the **relative** `size.width` mixes frames and silently discards the right-aligned child that ends flush with the edge. This is the same **units** defect as `_DIFF_WIDE_MIN`'s content-vs-terminal confusion (M6)."*

Tying it to M6 is right and is a better generalisation than swapping the number would have been. Dependents that **do** derive from it:

| Site | Value | Verdict |
|---|---|---|
| `:592-594` LLR-126.1 geometry table | **8 / 13 / 15**, with the frame-mixing form (7/12/14) shown beside it for contrast | ✅ matches my executed measurement exactly |
| `:597` LLR-126.1 numeric threshold | *"unchanged at **8**"* | ✅ |
| `:351` HLR-126 numeric threshold | *"unchanged at **8** @80×24 (13 @120×30, 15 @160×40)"* | ✅ |
| `:596` narrative | *"exactly one right-aligned child per size — ending at 79 / 119 / 159, flush with that edge — and it **is** painted"* | ✅ reproduces my transcript |

The site that does **not**: `:656`, §5.3's `AT-B78-28` row — see NEW-8.

## RG3-3 · The `AT-B78-22` mutation — rejection CORRECT, replacement SOUND, both executed

First, a record correction: **this lane proposed no mutation for `AT-B78-22`.** My round-2 entry states only that rev-1's form was *"structurally confirmed inert"* and that the literal-address rewrite reddens. The `low -= low % HEX_WIDTH` proposal did not come from here.

On the substance — and I was wrong in round 1 about the source, which is worth recording: **`low -= low % HEX_WIDTH` DOES exist**, at `screens_directionb.py:7027`. I read `:7026`, `:7028` and `:7029` in round 1 and skipped `:7027`. The rejection is nonetheless correct, and here is why, executed:

```
                              base row_bases                          mutated                       reddens?
0x1000-0x1014 (doc fixture)   ['0xff0','0x1000','0x1010','0x1020']
  low -= low % HEX -> low -= 0  ['0xff0','0x1000','0x1010','0x1020']  IDENTICAL                      NO
  high = end + ctx -> high = end ['0xff0','0x1000','0x1010']          last base dropped              YES
0x10-0x14 (shipped fixture)   ['0x0','0x10','0x20']
  low -= low % HEX -> low -= 0  ['0x0','0x10','0x20']                 IDENTICAL                      NO
  high = end + ctx -> high = end ['0x0','0x10']                       last base dropped              YES
0x1005-0x1014 (UNALIGNED)     ['0xff0','0x1000','0x1010','0x1020']
  low -= low % HEX -> low -= 0  ['0xff5','0x1005','0x1015']           shifted                        YES
```

Because `DISPLAY_CONTEXT_BYTES == HEX_WIDTH == 16`, `low = start − 16` is congruent to `start` mod 16 — so the alignment step is a **no-op for every 16-aligned run start**, which both candidate fixtures are. The rejection holds on the doc's fixture *and* on the fixture already in `tests/test_tui_diff_screen.py`.

The replacement `high = end + ctx → high = end` **drops the trailing row base** at both fixtures. An AT asserting three literal addresses including the trailing one therefore fails **on its assertion** — no exception, no guard error, just a missing address. `:906` (Inc-4's gate) states exactly this: *"`AT-B78-22` reddens on its ASSERTION under the implementation mutation `high = end + ctx → high = end` (the constant mutation raises in the guard and never reaches the ass[ertion])"*. **Verified. NEW-3 CLOSED.**

## RG3-4 · Round-2 residue — all closed, each re-executed

| Finding | Verdict | Evidence |
|---|---|---|
| **M2** clipped-vs-content bound | ✅ **CLOSED** | `:527` corrected; §6.4a row `:835` records it as `✘ FIXED` with the note *"LLR-123.2's own numeric threshold, two lines below its corrected Statement"* — my exact finding |
| **M10** normative keyword | ✅ **CLOSED, re-executed** | My scan: **40** normative Statement lines, `should\|must\|may\|might\|will\|ought\|can\|could` → **0 hits**; `shall` outside Statements → 5 lines, of which `:8` is the declaration and `:970` the checklist row, leaving **3 substantive, all quotations** (`:640` quotes *"shall not increase"*, `:745` quotes LLR-123.3, `:834` is a grep-pattern column). Matches the author's claim. Six sites were reworded to non-modal rather than the claim being re-asserted. |
| **NEW-3** | ✅ **CLOSED** | see RG3-3 |
| **NEW-4** superset premise | ✅ **CLOSED** | `:690` now reads *"the architect allocation supplies the **id namespace**; **neither lane's content is a superset of the other's**"*. The withdrawal is applied at its own site, not only recorded in §5.6.3. |
| **NEW-5** stale figures | ✅ **CLOSED, both halves** | `16 … _project_label` → **0 hits** document-wide; §8 `A-6` (`:950`) now reads *"`_KIND_LABEL` is **no longer assumed** — re-derived at `screens_directionb.py:6637-6641`"*, matching the line I derived in round 1 |
| **NEW-6** §6.4a hand-filled | ✅ **CLOSED** | rebuilt as a derived enumeration; audited in RG3-5 |
| **NEW-7** `<= 7` admits a collapsed bar | ✅ **CLOSED** | `:432` — *"`1 <= #workspace_status_bar.size.height <= 7` on all 10 screens"*. The `>= 1` floor is exactly what I proposed. |
| **m4** LLR-125.2 ladder | ✅ **CLOSED** | `:579` — *"shipped **0/0**"*, with the rev-1/rev-2 error recorded. Matches my measurement of `#diff_columns` clipped **0** at 120×30. |
| **A-2** owner | ✅ **CLOSED** | `:946` — **Inc-5** (chosen where the code is written), **discharged at Inc-10** |
| **Inc-0 / `AT-B78-33`** | ✅ improved beyond what I asked | `:902` adds `#diff_hex_a.size.height` at 132×44 to the Inc-0 capture, and `:903` reads the baseline **from the artifact, not an inline literal** — §5.1 rule 10 applied to the BL-3 gate. My independent measurement confirms the value: shipped content **7**. |

---

## RG3-5 · Audit of the derived enumeration (the coordinator's "test hardest")

**Term list — essentially complete.** `enum.py` carries 20 terms covering every round-1/2/3 finding that changed a figure or a normative term: the Footer counts, `OWNING`, status-bar height, the unsatisfied axis, clipped-vs-content, symbol count, `_project_label`, `_KIND_LABEL`, the superset premise, the `26` sentinel, `fallback`, the regime constants, `markup=False`, `AT-B78-27`, 135/136, `test_tc029`, the `AT-B78-22` mutation and the `AT-B78-33` baseline. I could not find a changed term with no regex.

**Regexes — they fire.** I re-ran `enum.py` myself rather than trusting the printed counts. The Footer term returns **11 hits** and `:656` is among them. The regexes are not the weak link.

**Where it fails: the disposition step.** §6.4a's Footer row (`:836`) documents the pattern `none truncated\|contains all\|chips` → 6 hits, and closes with *"plus the baseline itself re-derived, **see R-5 below**"*. **There is no R-5 row below** — the table ends with the `AT-B78-22` row at `:848`. So the numeric baseline term, which is the one that finds the stale site, has no row and no disposition. That is NEW-8.

**Verdict on the control.** It is a genuine improvement and it earned its keep — 15 fixed sites, including all three the recalled register had claimed as swept, and two thresholds no reviewer had listed (`:95`, `:348`). But a derived enumeration has three stages — input set, match, disposition — and revision 2's defect was at stage 1 while revision 3's is at stage 3. **The register is now derived; the accounting of it is still by hand.** The cheap fix is to make `enum.py` fail loudly: print `UNDISPOSITIONED` for any hit whose line number is absent from §6.4a's row text, and exit non-zero.

**Mechanical gate checks (`:852`) — one verified, one owed.** Check (a), *every `LLR-nnn.n` appears in some increment's Content cell*, **holds** (executed, RG3-1). Check (b), *every figure appearing more than once appears with one value*, is stated as a Phase-3 gate check and is **not yet run** — and NEW-8 is precisely the defect it would catch, which is fair evidence the check is the right one.

---

## RG3-6 · NEW findings

### NEW-8 (major) · §5.3's `AT-B78-28` row still carries the withdrawn **7**, and the enumeration surfaced it.

`:656`, the falsifiability row for `AT-B78-28`, reads:

> *"…set **equality**, and the painted-layer baseline is **7**, not 14 … Painted layer @80×24: `Footer.size.width=78`, 15 children, **7 fully painted**"*

Under §1.3's now-normative rule the painted count at 80×24 is **8** — as `:351`, `:592` and `:597` all state. Both clauses of `:656` are stale: the baseline claim (present tense, normative in force) and the executed-transcript cell. My measurement stands: region-relative containment gives **8 / 13 / 15**; the frame-mixing form gives 7 / 12 / 14, and `:592-594` prints both, so the document already knows the distinction two hundred lines earlier.

This is **not** a regex miss. Re-running the author's own script:

```
R-5  footer painted count   [\b(7|12|14|8|13|15)\b(?=[^|]*(chip|Footer|painted|truncat))]   -> 11 hit(s)
  ...
   656: | `AT-B78-28` | discoverability without displacing the Footer | ... the painted-layer baseline is **7**, not 14 ...
```

The enumeration found the site; §6.4a never dispositioned it, for the structural reason in RG3-5.

**Why major and not blocker** — stated explicitly so the judgement is auditable under the iteration cap: the requirement layer is internally consistent at 8 across a normative definition and two thresholds, and it governs what Phase 3 implements; §5.3 is an evidence record, not an acceptance specification. A Phase-3 author keying `AT-B78-28` off HLR-126/LLR-126.1 gets the right number. But the contradiction is on the exact figure this round was convened over, and it must not survive into Phase 3.

**Minimal correction.** Rewrite `:656`'s third and fifth cells to the §1.3 rule: baseline **8**, transcript *"15 children, **8** painted under §1.3's rule (7 under the frame-mixing form rev-2 used)"*; add the numeric Footer term as its own §6.4a row with `:656` marked `✘ FIXED`.

### NEW-9 (minor) · §6.4a's documented patterns are not the patterns that ran.

`enum.py` carries **20** terms; §6.4a documents **17** rows. Unrepresented: the numeric Footer-count term (the one that finds `:656`) and the `AT-B78-33` baseline term. The Footer row's printed pattern (`none truncated\|contains all\|chips`) is narrower than the three Footer regexes the script actually executes. §6.4a is headed *"Method (**re-runnable**)"* (`:828`) — a register whose printed patterns differ from its script cannot be re-derived from the document, which is the property the heading claims. Fix: generate the table from `enum.py` rather than transcribing it.

### NEW-10 (minor) · §9's scan denominator is 43 where the normative count is 40.

`:970` reports *"**43** `**Statement**` lines"*. A literal grep for `**Statement` matches 43 lines, but three are not statements: `:8` (the normative-keyword declaration), `:731` (a §5.6.1 table cell quoting an architect criterion) and `:970` (the row itself). The correct denominator is **40** — 39 `- **Statement:**` plus one `- **Statement (continued):**`. **The result is unaffected** — I re-ran the modal scan over the correct 40 and got 0 hits — but this row's whole claim is *"Executed scan, not asserted"*, so its denominator should be the normative set.

### NEW-11 (minor) · `screens_directionb.py:7027` is dead for every 16-aligned run start, and `LLR-123.2` does not say so.

Executed above: `low -= low % HEX_WIDTH` changes nothing whenever the run starts 16-aligned, because `DISPLAY_CONTEXT_BYTES == HEX_WIDTH == 16` makes `low ≡ start (mod 16)`. Both candidate fixtures are aligned, so **no acceptance in the batch exercises that line**. It is the reason the rejected mutation was inert, and it is a latent trap for `LLR-123.2`, whose row arithmetic is still `assumed` under `A-6`: any Phase-3 change to `DISPLAY_CONTEXT_BYTES` away from 16 silently activates an untested step. Fix: one sentence in LLR-123.2's Geometry, and an **unaligned run start** in `TC-B78-24`'s fixture (it already exercises the `max(0, …)` clamp, so it is the natural home).

---

## RG3-7 · Round-3 disposition

**Revision 3 IS implementable.**

| | Round 2 | Round 3 |
|---|---|---|
| blocker | 1 (NEW-1) | **0** |
| major | 2 (NEW-2, NEW-3) | **1** (NEW-8) |
| minor | 4 | **4** (NEW-9, -10, -11, and no carry-overs) |

**No cap breach.** I looked hard for a blocker and there is not one: the design, the regime derivation, the increment ordering, the file allocation and the acceptance set all survive this pass, and the one mechanical check I could run — every LLR covered by an increment — passes. NEW-8 is a stale cell in a validation record that three normative sites already contradict; calling it a blocker would be manufacturing one.

**Recommended before Phase 3 (all documentation-layer, none design):** fix `:656` to 8 (NEW-8); add the numeric Footer term as its own §6.4a row and generate the table from `enum.py` (NEW-9); correct §9's denominator to 40 (NEW-10); note `:7027`'s aligned-start no-op in LLR-123.2 and give `TC-B78-24` an unaligned fixture (NEW-11).

**What I re-verified as still sound in this pass:** the 40-statement modal scan · the 30-LLR increment coverage · the `app.py`-ownership argument behind the BLK-A fix · §1.3's painted-child rule against my own 8/13/15 measurement · the `AT-B78-22` mutation arithmetic at three fixtures · the `AT-B78-33` baseline of 7. The measured foundation from rounds 1 and 2 is unchanged and was not re-litigated.

**Closing process note.** Across three rounds the same shape recurred at successively deeper layers: revision 1 lost content in a **merge**; revision 2 lost it in a **hand-filled register**; revision 3 loses one site in the **disposition of a derived register**. Each fix was correct and each moved the defect one stage downstream rather than eliminating it — which is what progress on this class actually looks like. The remaining stage is the only one still manual, and `enum.py` exiting non-zero on an undispositioned hit would close it. That is a five-line change and it is worth making before Phase 3, because it is the difference between a control that reports and a control that *gates*.
