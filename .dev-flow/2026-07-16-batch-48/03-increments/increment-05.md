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
