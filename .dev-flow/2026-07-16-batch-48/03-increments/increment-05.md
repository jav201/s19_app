# Increment 05 — batch-48 · Patch Editor BIG · JSON colouring + paste-cap gauge (R-TUI-079 / HLR-079)

**Status: STOPPED AT A SPEC GATE — partial. 1 file added (`s19_app/tui/json_highlight.py`), 0 files modified,
0 tests written.** The mechanism is built and verified; the increment stops because **two locked-spec decisions
block the test layer**, and one of them makes the batch's gate-blocking C-17 AT **vacuous**.

**Scope attempted:** US-P4 / HLR-079 — LLR-079.1 (in-place `_highlights`) · 079.2 (tokenizer robustness) ·
079.3 (C-17 ★★) · 079.4 (gauge) · 079.5 (C-29) · **+ brief item C** (close Inc-4's C-29 gap) · **+ D** (F3/F4/F5).

---

## 1. What changed

**`s19_app/tui/json_highlight.py` (NEW, unwired).** The complete LLR-079.1 mechanism, verified end-to-end at the
`textual==8.2.8` pin:

- `tokenize_json_line(line)` — a pure, single-pass regex tokenizer emitting `(start_byte, end_byte, token_name)`
  in **UTF-8 byte offsets** (m-2). Four token classes: key / string / number / keyword. Cannot raise (LLR-079.2).
- `build_json_theme()` — a `TextAreaTheme` whose `syntax_styles` carries the **closed, author-fixed** token
  vocabulary. This is the mechanical reason pasted text can never name a style.
- `highlights_supported(widget)` — the feature-detect gate (A9 / R8), read on **every** rebuild so a
  monkeypatched `False` degrades the live widget (which is how AT-079d forces a branch CI cannot reach).
- `JsonHighlightTextArea(CappedTextArea)` — overrides `_build_highlight_map` to **re-populate after the base
  clears**. Riding Textual's own rebuild hook is what makes spans survive an edit *by construction*, rather than
  a `Changed` handler racing the rebuild.

**Nothing is wired.** `#patch_paste_text` is still a plain `CappedTextArea`; no gauge exists; the strip is
untouched. The tree is 1 untracked file — no behaviour changed, no test moved.

---

## 2. ★ The LLR-079.1 probe — RUNG 1, RECORDED (TC-079.1's obligation, discharged)

**Rung 1 (in-place `_highlights`) ships.** Not "either" — rung 1. All three pass conditions MEASURED:

| Condition | Result |
|---|---|
| **1. Distinct rendered styles** | **PASS** — 4 hues paint via `_render_line`: `#7dd3fc` key · `#bbc8e8` string · `#b565f3` number · `#91abec` keyword (≥3 required) |
| **2. Spans survive an edit** (m-3) | **PASS** — after `insert(" ")`, still 4 distinct. The `_build_highlight_map` override repopulates on the base's own hook |
| **3. Non-ASCII byte offsets** (m-2) | **PASS** — `'{"n": "sensor→α", "v": 12}'` → `json.string` span `(6,19)`; `line.encode("utf-8")[6:19]` decodes to `'"sensor→α"'` **exactly** |

Verbatim (probe 3):
```
tok nonascii: [(1,4,'json.key'), (6,19,'json.string'), (21,24,'json.key'), (26,28,'json.number')]
   json.string  bytes[6:19] = '"sensor→α"'
```
**§6.5 Amendment B is NOT needed.** The mechanism is sound.

---

## 3. ⛔ BLOCKER-1 — `AT-079b` is UNSATISFIABLE and `AT-079c`'s span clause is VACUOUS (measured)

**The spec mandates a mechanism whose effect is structurally invisible at the observation point it also
mandates.** Both were verified by reading the pinned source *and then* measuring.

`TextArea._render_line` (`_text_area.py:1440`) does `line = self.get_line(line_index)` — a **fresh** `Text` — and
stylizes **that local copy** at `:1503`. `get_line` (`:1328`) is unconditionally
`Text(line_string, end="", no_wrap=True)`. So an external caller's `get_line(i)` gets a brand-new **unstyled**
object every call. Measured, with `_highlights` fully populated:

```
get_line(0)      : '{"a": 1}' spans= []
get_line identity: False
_highlights      : {0: [(1, 4, 'json.key'), (6, 7, 'json.number')]}
```

Consequences, both load-bearing:

1. **`AT-079b` cannot pass.** Its single pass condition — *"≥3 distinct token styles across `ta.get_line(i).spans`
   summed over the buffer's lines"* — is **unreachable by any implementation** of LLR-079.1's mandated mechanism.
   `.spans` is always `[]`. This is not "hard"; it is structurally impossible.
2. **⚠ `AT-079c` ★★ — the batch's gate-blocking C-17 AT — is VACUOUS in its span clause.** *"`.spans` carries 0
   payload-derived spans"* is **constant-true**: `.spans == []` on a safe implementation, on an unsafe one, and
   on one that was never written. It **cannot fail**, so it is **non-evidence** — the precise defect 01b itself
   names for `ta.text` (*"passes even if the rendering path is unsafe"*), reproduced one accessor over.
   *(`AT-079c`'s `.plain`-verbatim and 0-raises clauses are real and do discharge work — only the span clause is dead.)*

**This is the SEVENTH vacuous check on this batch**, and it rhymes exactly with the PLAN's Phase-5 lesson: the
answer was in the file. `01b` reasoned carefully that `ta.text` is tautological and moved the observation point
**one step short** — to another accessor that never sees the render path either.

**The honest oracle is the PAINTED result** — `ta._render_line(y)`'s segment styles, where the styles actually
land. That is the same correction F2 forces on Inc-4's strip (assert what paints, not what a pre-layout accessor
returns). **One root cause, two increments.**

**Why I stopped instead of substituting it:** re-pointing a **locked, gate-blocking C-17 AT**'s observation point
is a **§6.5 amendment**, and I have no authority to amend a locked requirement — the same wall Inc-4 hit and
recorded (*"I did not have authority to amend a locked requirement"*). Inc-4 could ship anyway because 01b's
*conclusion* survived its wrong *reasoning*. Here the **pass condition itself cannot be met**, so I cannot
implement AT-079b as written at all — I must deviate, and the deviation is on the batch's C-17 gate. Guessing the
oracle would determine the whole shape of `tests/test_tui_patch_json.py`.

**Proposed amendment (for the operator, not taken):** AT-079b + AT-079c's span clause observe
`ta._render_line(y)` segment styles. AT-079c keeps `.plain` verbatim via `get_line(i).plain` (genuinely the
document text on the render path) + 0 raises, and **gains** a real span oracle. Strictly stronger than the text.

---

## 4. ⛔ BLOCKER-2 — the gauge's `threshold_style` collides with the Inc-2b hue reservation

The brief mandates `threshold_style` for the gauge. `threshold_style` returns **GREEN / YELLOW / RED**. The
**Inc-2b operator decision RESERVES those three hues for *verdicts* inside `#patch_editor_panel`**
(`_GLYPH_STYLE`; Inc-4's strip). A gauge painted yellow inside that panel is a second claimant on the same finite
hue vocabulary in the same container — **the exact shape of the Phase-5 control candidate.**

It is genuinely arguable both ways and I will not silently pick:
- **For:** §6.5 **Amendment F** (batch-47) makes *yellow ≡ warning **app-wide***. "Your paste is near the cap and
  will be truncated" is a warning in exactly that sense — the *same* meaning, not a competing one. Inc-2b's
  conflict was between two **non-severity** uses (chip *function* vs *verdict*); a cap gauge is a real severity.
- **Against:** inside this panel green already means "check passed". Green-for-"buffer roomy" makes an analyst
  read one hue two ways in one container — the harm Inc-2b bought a palette to prevent.

**I caught the identical collision in my own code before it landed:** my first `_JSON_SYNTAX_STYLES` painted
`json.keyword` **YELLOW**. A JSON literal is not a warning. Fixed to `HILITE` (`#91abec`) — all four token hues
are now non-verdict — and the reasoning is recorded in the module so the next reader cannot re-introduce it. That
near-miss is the evidence that this namespace is live and undefended: **nothing in the test suite would have
caught it**, exactly as the Phase-5 candidate predicts.

---

## 5. ★ C-29 RE-MEASURED (brief item C) — Inc-4's wrap is real, WORSE than recorded, and the budget is 14 not 16

**Measured myself at both regimes; inherited nothing.** The layout is **responsive and inverted**: 120×30 is the
batch-46 **3-column** layout (narrow, tall windows); 80×24 **stacks** them (wide, short).

| | `#patch_win_checks` region | body content | **strip region** | **strip content (the REAL budget)** |
|---|---|---|---|---|
| **80×24** | 68×12 | 66×3 → 64×3 | **64×1 — fits** | **62** |
| **120×30** | **22**×11 | 18×4 → **16**×4 | **16×2 — WRAPS** | **14** |

**F1 is confirmed exactly: the strip WRAPS at 120×30 and FITS at 80×24.** Two corrections on top:

1. **⚠ The budget is 14, not 16.** "22-23 is the WINDOW width, not the content budget" — correct, but the brief's
   replacement figure (**16**, the *body* content) is **also one level too generous**. The strip's own
   `content_region.width` is **14** (2 cols to padding). **The brief's own worked option —
   `✓2 ✗1 ◐3 ` = 9 + a 7-cell bar = 16 — therefore ALSO WRAPS.** This is C-29's lesson landing a third time in
   three increments: *measure the real container, not its parent.*
2. **⚠ The defect is worse than "it wraps" — at 2-digit counts it wraps MID-TOKEN.** Measured:

```
120×30, agg 2/1/3  →  line0: '✓ 2  ✗ 1  ◐ 3 '     line1: '███░░░░░      '
120×30, agg 12/34/56 → line0: '✓ 12  ✗ 34  ◐ '    line1: '56  █░░░░░░░  '
```
The `◐` glyph is **orphaned from its count**: it reads as uncheckable-with-no-number, and `56` reads as a label on
the bar. That is a **wrong-answer legibility defect on a verdict surface**, reachable by any change-set with ≥10
entries — not cosmetic. *Nothing is broken today only because the counts stay single-digit in the fixtures.*

**Also measured (unrecorded anywhere):** at **80×24 the strip is at `y=59` on a 24-row screen** — below the fold
at scroll 0. `region.height == 1` reads "fits" for a widget **that is not on screen**. A naive geometry arm
asserting only `height == 1` at 80×24 would have been a *seventh* false-confidence oracle. (Not a B2 defect — the
body is a `VerticalScroll` by batch-46's design and the strip is not a docked button — but the F2 arm must assert
the painted result at **120×30**, where the widget is actually composited.)

### The design call (made, with what I rejected)

**DECISION: an intentional two-line strip with tight separators — line 1 `✓{p} ✗{f} ◐{u}`, line 2 the 8-cell bar.**

- At **120×30 (14)**: counts fit to 3 digits (`✓123 ✗456 ◐789` = 14 exactly); the bar fits. **h=2 — identical to
  what paints today**, so it costs nothing at the primary regime and *removes the mid-token wrap*.
- At **80×24 (62)**: h goes 1→2, costing one row **inside a body the user must scroll anyway** (the strip is
  already below the fold). Cheap.
- Deterministic — no geometry in the builder, so the `__new__` unit tests stay valid.

**Rejected — and why:**
- **Tighter separators on ONE line** (the brief's suggestion): **arithmetically impossible.** The budget is 14, not
  16; and it breaks at 2-digit counts regardless. This is the option the inverted record pointed at.
- **Responsive width:** needs the builder to know geometry — either a width param (first-layout-0 hazard) or
  `self.query_one` inside the builder (breaks the `__new__` tests). Buys one row at a regime where the strip is
  below the fold anyway. Cost > benefit.
- **Drop the bar** (fits 14 on one line, and F4 is right that the counts are authoritative): guts HLR-078's
  "proportional bar" — an acceptance relaxation needing a §6.5 amendment. Not mine, and the bar is the story.

**NOT IMPLEMENTED** — it rewrites Inc-4's asserted format (`✓ 2  ✗ 1  ◐ 4  {bar}`) across
`tests/test_tui_patch_checks_strip.py`, which I did not start while blocked on §3/§4.

---

## 6. Files

| File | State |
|---|---|
| `s19_app/tui/json_highlight.py` | **NEW, unwired** — tokenizer + theme + feature-detect + `JsonHighlightTextArea` |

**0 modified. 1 added. Cap 5 ✓.** Planned remainder (5 total): `screens_directionb.py` (gauge + strip + wiring) ·
`tests/test_tui_patch_json.py` (NEW) · `tests/test_tui_patch_checks_strip.py` (F2 + F3) ·
`tests/test_tui_insight_style.py` (F4/F5).

## 7. Test results — executed, pasted verbatim

**Tree-clean verification (the precondition), run BEFORE any measurement:**
```
$ git rev-parse HEAD
43f08f604d58c4c2f46988e269fbce163e092676
$ git status --short
$ git diff HEAD --stat -- s19_app/ tests/
```
Both empty. Branch `feat/batch-48-patch-big`. **Verified myself; the brief was not trusted.**

**ruff:**
```
$ python -m ruff check s19_app/tui/json_highlight.py
All checks passed!
```

**C-27 dual-guard — 0 frozen diff:**
```
$ git diff main --stat -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
    s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
(empty)
```

**No suite run. No tests written.** The new module is unwired and imported by nothing, so no existing test can
observe it. **I am not claiming a green suite** — I did not run one, and saying so is the point.

**Destructive commands: none.** No `git checkout` / `stash` / `reset`. Every probe was a read or a scratchpad
script; the one code fix (YELLOW → HILITE) was an inverse edit.

## 8. Risks

- **The `_build_highlight_map` override is a private-internal hook.** Verified at the 8.2.8 pin; guarded by
  `highlights_supported`. If a future Textual renames it, the override silently stops being called and the buffer
  goes unstyled — **cosmetic, not a crash**, which is the recorded basis of the operator's in-place decision. But
  note the failure is *silent*: no test would fail unless it asserts on the painted result (§3).
- **The tokenizer is line-local**, so a JSON string spanning lines mis-tokenizes from the second line. Change-set
  JSON does not contain embedded newlines in strings; recorded, not defended.
- **§5's design call is unimplemented** — the mid-token wrap is live on `main` and in this branch.

## 9. Pending items

1. **⛔ §6.5 amendment for AT-079b + AT-079c's span clause** → observe `_render_line(y)` segments. **Blocks the
   test layer.** Operator/orchestrator decision.
2. **⛔ Gauge hue ruling** (§4) — `threshold_style` vs the Inc-2b reservation.
3. Gauge widget + wiring; strip two-line fix; AT-079a/b/c/d + TC-079.1/.1a/.1b/.1c/.2/.3/.4; F2/F3/F4/F5.
4. **Inc-4's F3 is real and located** — but at **`tests/test_tui_patch_checks_strip.py:469-472`**, not `:521-525`
   as briefed (stale coordinates again; the PLAN's own warning). Confirmed constant-true: `new_members` and
   `dir(Widget)` are both literals, bound to nothing in `PatchEditorPanel`.
5. **C-22:** no snapshot disposition — nothing renders differently yet.

## 10. Suggested next task

**Resolve §3 and §4, then re-dispatch Inc-5 with the oracle fixed.** §3 is worth raising at Phase 5 regardless:
*01b correctly diagnosed the `ta.text` tautology and then moved the observation point one accessor short of the
render path* — the sixth and seventh vacuous checks share one root with F2. **"Assert the painted result" is the
general control**, and it now has three independent sightings in one batch (Inc-4's strip, AT-079b, AT-079c).

---

## Evidence checklist

- [✗] **Tests/type checks/lint pass** — **ruff clean; NO test suite run and NO tests written.** Not applicable at
  a stop, and not claimed.
- [✓] **No secrets** — probes used synthetic JSON literals only.
- [✓] **No destructive commands** — none. No `git checkout`/`stash`/`reset`; the one revert was an inverse edit.
- [✓] **File count within cap** — 1 of 5.
- [✓] **Review packet attached** — in-conversation.

---
---

# Increment 05 — RESUMED (rulings resolved). **Status: COMPLETE.**

**5 files (cap 5), + 2 mandated docs.** Both blockers were resolved by ruling; §3/§4/§5 above are the
*stopped* record and stand as written. This section records what shipped.

## 1. What changed

**RULING 1 — AT-079b/c re-pointed to the PAINTED result.** `tests/test_tui_patch_json.py` (NEW) observes
`TextArea._render_line(y)` segments. §6.5 **Amendment E** written to `REQUIREMENTS.md`. The C-17 gate now
has an **anti-vacuity arm** (`test_tc079_3_c17_oracle_discriminates`): it runs AT-079c's predicate against a
`from_markup` TextArea and asserts the predicate **rejects** it.

**RULING 2 — NEW HUE `MAGENTA = "#f587d6"`** in `insight_style.py` + `cap_gauge_style()`. §6.5 **Amendment
F-1**. Gauge wired at `#patch_paste_gauge`; `#patch_paste_text` swapped to `JsonHighlightTextArea`.

**RULING 3 — the two-line strip** built as designed; `_CHECK_STRIP_BAR_CELLS`'s note rewritten; F2 geometry
arm (`test_tc078_5_strip_geometry_painted`), F3 (bind-the-literal), F4 (docstring).

## 2. ★ Three false oracles found *while building the oracle* (the 8th, 9th, 10th of the batch)

The brief said "if an AT exists to catch a mutation, apply that exact mutation and watch it fail". Doing
that on my **own** new tests broke three of them before they shipped:

| # | Trap | How it would have shipped green |
|---|---|---|
| **8** ⚠ | **The cursor line MASKS payload-derived styles.** `_render_line:1460-1461` stylizes the ENTIRE cursor line AFTER any style it carries; rich's later span wins. | AT-079c with its payload on line 0 **passes on a provably unsafe buffer.** MEASURED on the unsafe control: line 0 → `[('P','#121212'),('WNED','#e0e0e0')]` (masked) vs line 1 → `[('SECOND','red')]` (injected). My first draft did exactly this. |
| **9** | **`_render_line(y)` indexes VISUAL lines, not document lines.** | At 120×30 the buffer is ~17 cells; every payload wraps and `_render_line(1)` returns the wrapped **tail of line 0** (`': 1}'`). The oracle asserts on text never under test. |
| **10** | **AT-079d is an ABSENCE assertion** (“renders unstyled”). | Anything that hides the styles greens it — including trap 8. |

Pinned by `_assert_off_cursor_line` / `_assert_no_wrapping`, and AT-079d is **mutation-verified** (remove the
monkeypatch → RED), so it observes the fallback rather than the masking.

**The generalization:** the batch's lesson has been *"assert the painted result"*. Traps 8-9 sharpen it —
**the painted result has its own confounders**, and moving the observation point closer to the pixels does
not by itself make an oracle honest. What made these visible was not reading; it was applying the mutation
and watching what the oracle actually saw.

## 3. The hue: MEASURED, and the measurement changed the answer

`MAGENTA #f587d6`, hue **316.9°**, **≥43.0° from every claimant**: RED 43.1 · PURPLE 43.1 · orange3 69.6 ·
mac_oor 77.4 · HILITE 94.1 · LBLUE 94.2 · YELLOW 107.9 · CYAN 117.5 · GREEN 162.1.

**Two corrections to the brief's figures:**
1. **"Free band ≈300-330°" is wrong** — only **[313.9°, 320.0°]** (6.1° wide) clears 40°. "46° from PURPLE,
   40° from RED" describes **two different points**. 316.9° is the arc's max-min point.
2. **The global optimum is a LIME (~110°, min-dist 45.0° — *larger*) and it is REJECTED** for the brief's own
   Orange logic: it sits **between YELLOW (64.8°) and GREEN (154.8°)**, i.e. between two verdicts. Distance
   is a necessary condition; *not sitting between two verdicts* is the objective. Both arcs are asserted.

**`threshold_style` NOT parametrised** (my call): a palette parameter lets any caller inject any three hues
into any container — reopening the Inc-2b hole — and does not fit anyway (the gauge is **one hue at three
intensities**, not three hues). Sibling function, not a fork.

## 4. C-26 census caught a real break BEFORE the suite did

`tests/test_capped_text_area.py::test_five_construction_sites` asserts `#patch_paste_text` is constructed as
the **string** `"CappedTextArea"`. `JsonHighlightTextArea` **is** a `CappedTextArea` subclass — the cap is
fully intact — but the AST filter dropped the site and it failed `got None`: a **false alarm the first time a
subclass appeared**, and the same shape would be a **false pass** if a subclass ever overrode the cap.
Widened to `issubclass`. **Mutation-verified**: a bare `TextArea` at that site → RED.

⚠ This is the census hitting a **value**, not a symbol — the seed table's known gap.

## 5. Geometry (C-29), re-measured with the gauge mounted

| | strip content | gauge content | strip painted |
|---|---|---|---|
| **80×24** | 62 | 60 | h=2 ✓ |
| **120×30** | **14** | **15** | h=2 ✓ |

Counts ≤14 at 3 digits (`✓123 ✗456 ◐789` = 14 exactly); gauge ≤13 (`64.0K / 64.0K`). **Nothing wraps.**

**What the geometry arm can and cannot see:** `render_line` resolves for a laid-out but scrolled-out widget,
so **both** sizes assert the painted contract. It does **not** assert on-screen compositing at 80×24 — the
strip sits at **y=59 on a 24-row screen**, below the fold at scroll 0 (batch-46's `VerticalScroll` design;
the strip is not a docked button, so B2 does not bind it). A `height == 1` assertion there would have been
another false oracle: it reads "fits" for a widget that is not on screen. The asserted height is **2** and it
is the intentional shape, not a fit claim.

## 6. Files

| File | State |
|---|---|
| `s19_app/tui/insight_style.py` | M — `MAGENTA` + `cap_gauge_style` |
| `s19_app/tui/screens_directionb.py` | M — gauge + JSON wiring + two-line strip + F4 |
| `tests/test_tui_patch_json.py` | **NEW** — AT-079a/b/c/d + TC-079.2/.3/.5/.5b |
| `tests/test_tui_patch_checks_strip.py` | M — two-line format + F2 arm + F3 |
| `tests/test_capped_text_area.py` | M — forced by the C-26 census |
| `REQUIREMENTS.md` | Mandated — §6.5 Amendments **E** + **F-1** |
| `.dev-flow/…/increment-05.md` | Mandated — this record |

`s19_app/tui/json_highlight.py` — **0 diff vs `4bfe7df`** (mutation round-trips reverted by inverse edit).

⚠ **F4's TC-078.4 docstring + F5's trim are DEFERRED** — both live in `tests/test_tui_insight_style.py`, the
**6th** file. The cap held instead. F4's load-bearing half (the `_check_strip_text` docstring, which is what
a reader actually reads) **shipped**; both deferrals are LOW and F5 was optional.

## 7. Test results — ONE run, invocation NAMED, pasted verbatim

**Invocation: `python -m pytest -q -p no:randomly` — the FULL suite (nothing deselected).**
⚠ I added `-p no:randomly` (order determinism) — the reference at `a0f156d` was plain `pytest -q`. Flagged
because it is a deviation from the reference invocation, not because I saw a flake.

```
1523 passed, 2 skipped, 5 xfailed, 1 warning in 1190.93s (0:19:50)
```

**Reference @ `a0f156d`: 1514 passed / 2 skipped / 5 xfailed / 0 failed. Delta = +9 passed, EXACTLY the 9
tests added** (8 × `test_tui_patch_json.py` + 1 × `test_tc078_5_strip_geometry_painted`). 0 failed, xfail
count unmoved (5), **0 xpassed** — no pre-existing mark silently flipped.

**ruff** — clean on all 6 touched code/test files:
```
$ python -m ruff check s19_app/tui/insight_style.py s19_app/tui/screens_directionb.py \
    s19_app/tui/json_highlight.py tests/test_capped_text_area.py \
    tests/test_tui_patch_checks_strip.py tests/test_tui_patch_json.py
All checks passed!
```
`a2l.py:926` F841 remains the known **frozen** carry (unfixable while a2l.py is engine-frozen) — not mine.

**C-27 dual-guard — raw frozen diff vs `main` = EMPTY:**
```
$ git diff main --stat -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
    s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
(empty)
```

**C-7 purity (AST, not grep):** `self.app` occurrences in `PatchEditorPanel` = **NONE**; imports inside the
class = **NONE**. `mem_map`-style parameter-threading preserved — the gauge reads its own child widget.

**MUTATION LEDGER — applied to the tree, suite RUN, output READ, reverted by INVERSE EDIT:**

| # | Mutation | Result |
|---|---|---|
| M-1 | `#patch_paste_text` → bare `TextArea` | **4 FAILED** — test_capped(issubclass) + AT-079b intended; AT-079a/c **collateral**. Recorded: a mutation tripping 4 tests for 3 reasons proves less than it looks. |
| M-2 | AT-079c predicate vs a `from_markup` TextArea | **REJECTED** it (`PWNED` red, brackets consumed) — the discrimination proof, now a **shipped test**. |
| M-3 | tokenizer → codepoint offsets | **1 FAILED: TC-079.2 only.** AT-079a/b/c/d all PASSED — the byte bug is silent and no C-17 arm sees it. |
| M-4 | remove AT-079d's monkeypatch | **RED** — AT-079d observes the fallback, not the masking. |
| M-5 | strip → the Inc-4 one-line form | **RED** at both sizes. @120×30 reproduced the defect exactly: `h=3`, `['✓ 12  ✗ 34  ◐', '56  ', '█░░░░░░░']`. |
| M-6 | `test_five_construction_sites` vs bare `TextArea` | **RED** — the widened issubclass oracle still catches a real regression. |

**C-22 snapshot disposition:** both `patch-comfortable-{80x24,120x30}` cells already ride
`_batch48_patch_drift_marks` (`xfail(strict=False)`) from Inc-1 and **ABSORB** this increment's repaint
(gauge + JSON hues + two-line strip). **Their passing is NOT evidence.** Prediction: still exactly 2 cells,
no new ones — containment holds (everything is inside `#patch_editor_panel`; `MAGENTA` has no CSS rule and
no palette-set oracle enumerates it — verified). Regen = canonical CI, post-merge. **Never local.**

**Destructive commands: NONE.** No `git checkout`/`stash`/`reset`. Every mutation reverted by inverse edit;
`json_highlight.py` verified byte-identical to `4bfe7df` afterwards.
⚠ **My own error, caught and repaired:** two heredocs collapsed `\n` into real newlines, corrupting
`screens_directionb.py` (a duplicated broken `append`) and `test_tui_patch_checks_strip.py` (an unterminated
f-string). Both repaired by exact edits; the latter also left mixed line endings, normalized to CRLF (the
repo is `core.autocrlf=true`, whole tree CRLF).

## 8. Risks
- The `_build_highlight_map` override + `_render_line` are **private Textual internals**, pinned at 8.2.8 and
  guarded by `highlights_supported`. A rename degrades the buffer **silently** (cosmetic, no crash) — now at
  least AT-079b would go RED, which was not true before this increment.
- **The C-17 oracle is width- and cursor-sensitive** (traps 8/9). Both preconditions are asserted, so the
  failure mode is a loud test rather than a silent false green — but a future re-layout of the JSON window
  will trip `_assert_no_wrapping`. That is the intended behaviour, not a defect.
- The tokenizer is **line-local**: a JSON string spanning lines mis-tokenizes from line 2. Change-set JSON has
  no embedded newlines. Recorded, not defended (carried from the stopped record).
- The gauge fires on `TextArea.Changed`, which is posted by the **document edit**, so all ingresses are
  covered by construction. A future second `TextArea` in the panel would need the id filter — it is there.

## 9. Pending items
1. **F4's TC-078.4 docstring + F5's trim** — DEFERRED (6th file, cap held). Both LOW; F5 optional.
2. **Canonical-CI snapshot regen** for the 2 patch cells (post-merge follow-up; retires `_batch48_patch_drift_marks`).
3. Remaining Batch-B stories: **US-P5 live before/after card** (the headline) · US-P6 history strip.
4. **Phase-5 candidate, sharpened** (§2): *"assert the painted result"* is necessary but **not sufficient** —
   the painted result has confounders (cursor-line masking, visual-vs-document indexing). The control that
   actually works: **apply the mutation to your own new oracle and watch it fail** — that is what found traps
   8/9/10, and reading would not have.
5. **C-26 seed-table gap, second instance:** the census hit a **value** (`"CappedTextArea"` as a string in an
   AST filter), not a symbol. Inc-2 found the same class for `styles.tcss`. Census on values/artifacts.

## 10. Suggested next task
**US-P5 — the live before/after card** (the Batch-B headline). Recon is already recorded in the PLAN's "four
facts": before-bytes MUST come from `LoadedFile.mem_map` (not `last_summary`, whose `before_bytes` is `None`
pre-apply); thread `mem_map` as a **parameter** (C-7 — the panel has 0 `self.app`, re-verified this increment);
index-align **positionally**, never by address; and re-measure C-29 **with the card mounted** — the 14-cell
budget at 120×30 is the binding constraint and it is now measured three times over.

## Evidence checklist
- [✓] **Tests/type checks/lint pass** — `pytest -q -p no:randomly`: **1523 passed / 2 skipped / 5 xfailed /
  0 failed**, pasted above. ruff clean on all 6 files (`a2l.py:926` = known frozen carry).
- [✓] **No secrets** — synthetic JSON + payload literals only.
- [✓] **No destructive commands** — none; every mutation reverted by inverse edit, `json_highlight.py`
  verified 0-diff after.
- [✓] **File count within cap** — **5 of 5** code/test + 2 briefed docs (`REQUIREMENTS.md` §6.5 amendments,
  this record). The 6th file (`test_tui_insight_style.py`) was **declined**, not silently taken.
- [✓] **Review packet attached** — in-conversation.
