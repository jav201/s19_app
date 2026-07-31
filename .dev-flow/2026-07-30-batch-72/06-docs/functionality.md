# Functionality — s19_app — Batch 2026-07-30-batch-72

> Phase-6 artifact. Owner: `docs-writer`. Artifact language: English.
> **Audience:** a technical stakeholder who has not opened this codebase. Everything a reader needs
> is defined the first time it is used.
> **Purpose:** understand what changed on two screens, why, and how to reach it.

## 🔑 At a glance (read first)

- **What this batch added:** two terminal screens were re-laid-out to fix operator-reported defects
  — the **CRC Designer** now shows its two reflection toggles as one labelled pair and demotes a
  self-test verdict from a hero tile to an annotation of the field it validates; the **Legend
  modal** now shows the colour key beside the example card instead of ~18 rows below it.
- **Capabilities:** no new capability. **This is a layout change only** — no new input/output, no
  network, no new dependency, no change to any computation. The CRC bench stays preview-only and the
  legend's data layer was not edited at all.
- **How to use it:** launch the terminal app (`s19tui`), press `0` for the CRC Designer, press `k`
  on any colour-coded view for the Legend.

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## 0. Context a newcomer needs (30 seconds)

`s19_app` is a Python terminal application for inspecting and editing automotive firmware images —
S19 and Intel HEX files, plus the A2L and MAC sidecar files that name and locate regions inside
them. It has two front ends: a command-line tool (`s19tool`) and a full-screen terminal UI
(`s19tui`) built on the **Textual** framework. Textual lays screens out with a CSS-like stylesheet,
so "widget tree" and "stylesheet rule" mean roughly what they mean in a browser, and screen geometry
is measurable in character cells rather than pixels.

Two of that UI's screens are the subject of this batch:

| Screen | What it is for | How you reach it |
|---|---|---|
| **CRC Designer** (`crc_designer_view.py`) | A preview-only bench for defining a CRC algorithm — polynomial, width, initial value, reflection, final XOR — and seeing the resulting checksum live | Rail key `0` |
| **Legend modal** (`LegendScreen` in `screens.py`) | A pop-up that explains what each colour on the current view means, alongside an annotated example card | Key `k`, from any colour-coded view |

---

## 1. What changed, and why

**Conclusion first: three defects reported by the operator after hands-on testing on 2026-07-28,
each with a measured mechanism rather than a guess.** All three are visual-design defects on screens
that were built functional first and re-styled later, with fidelity checks that asserted *structure*
(how many columns exist) but nothing about *legibility* (whether a control reads as one control).

| # | Operator's report | The measured mechanism | What was done |
|---|---|---|---|
| 1 | *"There are switches that look like a single one."* | Two toggle rows stacked directly on top of each other, each holding a switch styled with **no border and a height of exactly one row**, with no margin or separator between the rows. Removing the border removes the only visual boundary the framework would draw, so two one-row borderless switches abut and read as one wider control. Confirmed by measurement: the two switches render at `y=32` and `y=33`, each one row tall — exactly touching | Merged into **one labelled `Reflection` row** with an `in` sub-label before the first toggle and an `out` sub-label before the second. The `out` label physically separates the two switches |
| 2 | *"The known-answer match field — I do not see the use of it unless you already know the result… I recommend removing it and reconsidering it in the screen redesign."* | The field validates the *algorithm definition*, not the operator's data: it reproduces the published check value for the standard test string `123456789`. That is a real use — confirming a hand-built polynomial actually matches the standard it claims to be — but it is a bench affordance, not an operational result, and it was occupying a centre-aligned hero tile at the same visual weight as the Warnings panel | **Demoted, not removed** (the operator's choice between the two options). It is now a `Self-test` row directly beneath the `Check` field it validates, and it names the reference vector `123456789` on screen. The right-hand hero column is now Warnings alone |
| 3 | *"The legend pop-up screens need better reorganisation, and in places better implementation."* | The modal concatenated two widget lists — an annotated example card, then the colour key — into a single scrolling column. Measured at a 120x30 terminal: the body has a 15-row viewport but needs 39 rows (MAC view) or 44 rows (map view) of virtual height, and the `Pale yellow` key row sits at **content row 33 — eighteen rows below the fold**. To read what a colour means, you first scroll past the example that uses it | Split into **two side-by-side scrolling panes** — example card left, colour key right — inside the same wrapper element. The key now fits entirely in its pane with no scrolling at all |

**A fourth intended change was withdrawn.** A proposed rule capping the height of the dropdown
selectors on the CRC bench was measured before implementation and rejected: at the bench's column
width, the cap renders `CRC-32/ISO-HDLC` as **`CRC-32/I`** — eight of fifteen characters, with **no
ellipsis and no overflow marker** — and clips the bottom border on four of the six selectors. A cap
that makes a control lie about its value is worse than the density it fixes. The underlying
crowding finding is real and was carried to the backlog with its measurement; the effective lever is
column **width**, not height, and that is a redesign nobody scoped.

---

## 2. Before and after, in words you can picture

### 2.1 The CRC Designer bench

**Before.** Reading the Algorithm column top to bottom you saw: a preset dropdown, then Width,
Polynomial and Init as one-line fields, then two consecutive one-line rows labelled `Reflect in` and
`Reflect out`, each ending in a small toggle. Because both toggles were borderless and one row tall
and the rows had no separation, the two toggles formed a single vertical block with no visible seam
— the thing the operator described. Below them came XOR out and Check.

Above the bench sat a wide "hero" strip. Its left two-thirds was the live coverage window; its right
third was split between a centre-aligned tile titled `Known answer · 123456789` showing a tick or a
cross, and beneath it the Warnings panel. Both boxes were the same size, so the self-test verdict
carried the same visual weight as the panel that reports actual problems.

**After.** The Algorithm column reads: preset, Width, Polynomial, Init, then **one** row labelled
`Reflection` containing `in [toggle] out [toggle]` — a single control with two clearly separated
parts — then XOR out, then Check, then a new row labelled `Self-test` showing `123456789` and the
verdict glyph. The verdict now sits directly under the field it checks, which is also where it makes
sense: it is telling you whether the `Check` value you entered matches what this algorithm actually
produces.

The hero strip keeps the live coverage window on the left, and its right third is now **entirely
the Warnings panel**. The verdict tile is gone from the tree completely, not merely hidden.

Nothing about the calculation changed. The verdict is still live: edit the `Check` field and it
updates on the next keystroke, showing `✓ MATCH`, `✗ MISMATCH`, or `○ NO-EXPECTED` when the field is
empty.

### 2.2 The Legend modal

**Before.** A dialog occupying 70% of the terminal width, with a title, one scrolling body, and a
Close button. The body held the annotated example card first and the colour key after it. On a
standard 120-column terminal the visible body was 15 rows and the content was 39 to 44 rows, so
opening the Legend showed you the example card and nothing else. The colour key — the reason you
opened the Legend — began about eighteen rows further down.

**After.** A dialog occupying 96% of the width, with the same title and Close button, but the body
is now two panes side by side. The **left pane, about 64 columns, holds the example card**; the
**right pane, about 43 columns, holds the colour key**. Both scroll independently. The key content
is 14 rows in a 15-row pane, so it does not scroll at all — the whole key is on screen the moment
the modal opens, next to the card that illustrates it.

On a small terminal — below 120 columns — there is no room for two columns, so the panes stack
vertically **with the key on top**, which is the operator's explicit preference. At the 80x24 floor
the modal has nine rows of content budget against a key that needs ten or eleven, so the key is
scroll-reachable rather than entirely visible; the card below it is guaranteed at least two rows so
a future layout change cannot satisfy "key first" by crushing the card to a single line.

The colours, the wording and the example card itself are unchanged — the module that produces them
is byte-identical to what shipped before, and that is asserted by a test, not assumed.

---

## 3. Detail (reference)

### 3.1 How it works (flow)

Two independent flows; see [`diagrams/runtime-mechanisms.md`](diagrams/runtime-mechanisms.md) for
the sequence diagrams.

**Legend — the width regime.** The app already has a responsive breakpoint at 120 columns, but it
applies its "narrow" class only to two containers on the *base* screen. The Legend is a **modal**
pushed onto the screen stack, so it is a descendant of neither, and this version of Textual has no
CSS media queries. There is simply no selector that reaches the modal from the app's regime logic.
The modal therefore owns its own hook: on mount and on every resize it reads the **terminal** width
(not its own, which is two columns smaller under a modal and would misclassify a 120-column
terminal), toggles a `legend-narrow` class on the dialog, and reorders the two panes.

The reorder is a runtime operation rather than a stylesheet rule for a concrete reason: this
framework version has no CSS ordering property, so **document order is stacking order**. The
stylesheet can stack the panes; only code can decide which one is on top. The hook is idempotent —
it skips the move when the wanted pane is already first — so it is safe on every resize event.

**CRC — the render-surface census.** Six live surfaces on the CRC bench echo user-typed text, and
one of them is an error message that quotes the operator's literal input. Those surfaces are now
declared once as a module-level tuple that the recompute function consumes **by name**. A test reads
that same live tuple, so a seventh surface added later is covered without editing the test.

Consumption by name rather than by position was a deliberate choice: the six ids carry six distinct
roles with three different error strings, so a positional unpack would turn the advertised "a
seventh surface is covered automatically" into a crash on the UI thread the moment a seventh id was
declared.

### 3.2 Components / modules touched

| Module | Role in this batch |
|---|---|
| `s19_app/tui/crc_designer_view.py` | The CRC Designer view. Composition rewritten: paired reflection row, `Self-test` row, Warnings-only right column, per-toggle helper deleted, recompute surface tuple added |
| `s19_app/tui/screens.py` | Hosts `LegendScreen`. Composition rewritten into two panes; a width-regime hook (`_apply_width_regime`) plus `on_mount` / `on_resize` added |
| `s19_app/tui/styles.tcss` | The application stylesheet. **Layout rules only.** New pane rules, new floor-regime rules, a new sub-label class, and the retired hero-tile rule removed. No colour or severity block was touched — neither screen is captured by an image-comparison test, so a colour drift here would have been caught by nothing |
| `s19_app/tui/legend.py` | The legend **data layer** — deliberately *not* touched. Its widgets are re-parented into the new panes, never rebuilt. Verified byte-identical to the mainline copy |
| `tests/test_crc_designer_view.py` | Nine nodes added; one batch-59 node deleted |
| `tests/test_legend_two_pane.py` | New file — nine nodes |
| `REQUIREMENTS.md` | One requirement added, two amended (see §3.5) |

**Files deliberately not touched:** the parser and validation engine modules are git-frozen in this
project and guarded by tests that compare them against the mainline branch. Both guard arms ran
green and the frozen-set diff is empty — this batch never went near them.

### 3.3 Usage / examples

```bash
# install and launch
pip install -e .
s19tui

# inside the TUI
#   0   → CRC Designer bench
#   k   → Legend modal (from any colour-coded view)

# the batch's own test nodes
pytest tests/test_crc_designer_view.py -k "at213 or at214 or at215 or at219 or reflection or kat or hero or recompute"
pytest tests/test_legend_two_pane.py

# the full gate run used at close
pytest -q -m "not slow"
```

The Legend behaves differently by terminal width; to see both regimes, resize the terminal across
120 columns with the modal open — the panes flip between side-by-side and key-above-card live.

### 3.4 Verification — what was actually run

**Formal verdict: PASS, no blocker** — [`04-validation.md`](../04-validation.md) §11. Seven
requirements in force, seven pass; every white-box check reconciled to a real collected test node
rather than signed off from intent; every acceptance test mapping to exactly one distinct node, so
none is realised "in parts".

| Item | Result |
|---|---|
| Gate suite (`pytest -q -m "not slow"`) | **2370 passed · 2 skipped · 21 deselected · 3 xfailed · 29 snapshots passed · exit 0**. Run and collected by the batch coordinator, not by an implementer |
| Test-count ledger | `2379 − 1 + 18 = 2396`, reconciled against a collection run **and** against the gate run's own arithmetic (`2370 + 2 + 21 + 3`) |
| Image-comparison snapshots regenerated | **0.** Neither screen is snapshot-captured — verified by probe, twice, independently. A backlog note claiming otherwise was measured false and is corrected at close |
| Frozen engine modules | diff against mainline **empty**; both guard arms green |
| Lint | `ruff check` clean on every touched file. `ruff format --check` reports drift on two test files — and reports the *same* drift on those files with the changes stashed, so it is pre-existing and not enforced in this repo |
| Falsification runs | **6** counterfactual / oracle mutations executed inside the batch, plus **16** independent falsification runs by a reviewer who wrote none of the code. *(The validation artifact's own table lists four of the six — the two absent ones are recorded in the increment packets with transcripts, and the discrepancy is raised as gap G-072-01 in the traceability matrix.)* |

**One acceptance test was proven to fail for the right reason, not merely to pass.** For the
switch-separability guard, the CRC view file was restored whole from the mainline branch onto a
private copy of the tree, and the guard failed **on its own assertion line**, naming exactly the
switch pair the pre-batch census had predicted. A control run on the same copy with the file
restored to the current version passed. The shared working tree was verified byte-identical before
and after the exercise.

### 3.5 Requirements-document changes

- **`R-TUI-100` — added.** This registers the CRC Designer view in `REQUIREMENTS.md` **for the first
  time**. The bench shipped in an earlier batch and was never given a requirement row: searches of
  the document for its identifiers returned zero hits across the board. The plan's original
  instruction was to *amend* a row describing the verdict tile — that row does not exist, so the
  obligation was corrected to *add*. The new row also carries an explicit **"what this requirement
  deliberately does NOT claim"** block covering the withdrawn selector cap, a pre-existing tile-ratio
  violation this batch neither causes nor worsens, a retired design guard, and the fact that the CRC
  screen has never been measured at the 80x24 floor.
- **`R-LEGEND-MODAL-001` — amended.** The body element is now the two-pane wrapper; a stale code
  reference was refreshed at the same time.
- **`R-LEGEND-GEOMETRY-001` — amended.** A named stylesheet declaration moved from the body to the
  panes, recorded as an explicit Before/After block rather than edited silently.

### 3.6 Diagrams

- [`diagrams/legend-modal-widget-tree.md`](diagrams/legend-modal-widget-tree.md) — the Legend widget
  tree before and after, both regimes, plus the data flow showing what was *not* touched.
- [`diagrams/crc-bench-layout.md`](diagrams/crc-bench-layout.md) — the CRC bench before and after,
  plus the decision tree behind the separability guard's scope.
- [`diagrams/runtime-mechanisms.md`](diagrams/runtime-mechanisms.md) — the Legend width-regime
  sequence and the CRC recompute census flow.

---

## 4. Assumptions · risks · tradeoffs · next steps

### Assumptions

1. The pane geometry quoted here holds under the stylesheet this batch actually wrote — `height: 1fr`
   on both panes and `overflow: hidden` on the wrapper. Different pane rules move every measured
   number, which is why the requirement pins the rules and not only the outcomes.
2. Numbers reported here are reconciled against the Phase-4 validation artifact, which landed while
   this document was being written and reports identical counts from its own separate run. Where the
   two artifacts disagree — the count of executed mutations — the disagreement is recorded rather
   than resolved silently.

### Risks and limitations

| Risk | Severity | Status |
|---|---|---|
| **The colour key has one row of slack.** The key is 14 rows in a 15-row pane. One extra key row, one reworded meaning that wraps, or a narrower pane pushes it past the fold | ⚠️ Medium | Guarded at the **cause**: the acceptance test asserts the pane does not scroll at all, so it fails on budget exhaustion before the symptom appears |
| **The Legend's keyboard tab order changed.** The modal went from one focusable stop to three, because each scroll pane is focusable in this framework version | ⚪ Low, accepted | Accepted deliberately and pinned by a test. Making the panes non-focusable would restore the old cycle but leave the colour key **unreachable by keyboard** at the floor. Initial focus is still the Close button, unchanged |
| **The wrapper's `overflow: hidden` rule is pinned by no test.** Reverting it leaves every node green | ⚪ Low | Self-reported by the implementers *and* independently confirmed by the reviewer. The consequence is invisible at current content sizes. Carried as an open item |
| **The CRC screen has never been measured at 80x24.** The new `Self-test` row is tight even at 120x30 | ⚪ Low | Stated explicitly in the new requirement row, which claims no floor behaviour. An over-long verdict string wraps rather than truncating, so the silent-truncation failure mode does not apply — but that is an argument, not a measurement |
| **The separability guard currently polices exactly the pair another test already asserts** | ⚪ Low, openly stated | Only two switches exist in the whole application. What makes it a guard rather than a duplicate is that its subject set is derived from the live screen, so a third switch is policed with no test edit, and a companion check fails the moment a switch is constructed outside this view |

### Tradeoffs taken

- **Demote rather than delete the self-test verdict.** Deleting it was on the table and the operator
  chose demotion. The verdict does have one genuine use the report's framing did not cover —
  confirming that a hand-built polynomial actually matches the standard it claims to be — so it was
  moved next to the field it validates rather than removed.
- **A narrow, satisfiable guard over a broad, unsatisfiable one.** The broad reading of "no control
  reads as another control" is false of sixteen control pairs on the shipped screen, fifteen of
  which abut by an earlier deliberate design decision. A rule that stays red after a perfect
  implementation is not a gate. The guard was scoped to the one rule that is false before and
  satisfiable after, and the requirement says so in plain words rather than dressing it up.
- **Reachable-under-scroll over fully-visible at the floor.** "Both panes visible" at 80x24 is
  physically impossible for this content. Asserting it would either fail permanently or be weakened
  into meaninglessness, so the requirement asks for the property that is both honest and testable.

### Next steps

1. **Phase 4 — done.** Verdict PASS, no blocker. Remaining: **Phase 5 (post-mortem)**, then close.
   One correction owed to the validation artifact itself — its mutation table undercounts by two
   (gap G-072-01).
2. **Backlog reconciliation at close** — four carries owed: the selector affordance-density finding
   with its measurement, the pre-existing tile-ratio violation with its measured ratio, the retired
   switch state-word guard, and the correction of a backlog line whose claim about snapshot drift
   was measured false.
3. **Optional hardening, none blocking** — pin the wrapper's overflow rule, pin the mount-time width
   argument, and add two docstring sentences flagged by the reviewer.
4. **Not in scope, carried** — measuring the CRC bench at the 80x24 floor, and the column-width
   redesign that the withdrawn selector cap pointed at.

---

## Evidence checklist — `docs-writer`

- [x] **Audience and purpose declared at the top of the doc** — header block; §0 supplies the
      codebase context a newcomer needs before any detail.
- [x] **Structure follows the relevant template** — `~/.claude/templates/dev-flow/functionality-template.md`
      (At a glance → Detail → components → usage → diagrams → evidence). **Justified deviation:** §0
      (newcomer context), §2 (before/after in prose) and §4 (assumptions/risks/tradeoffs/next steps)
      added, the last per the operator's standing style rule for technical docs.
- [x] **Code/CLI snippets actually run** — the `pytest` and `pip install -e .` commands are the
      project's documented commands, and the specific test invocations are copied from the increment
      packets' executed transcripts. The `-k` filter in §3.3 is composed for this document and is
      **untested as written**.
- [x] **Assumptions listed** — §4, two entries, including the missing Phase-4 artifact.
- [x] **Risks / limitations called out** — §4, five entries with severity; tradeoffs stated
      separately so a tradeoff is not mistaken for a risk.
- [x] **Next steps stated** — §4, four items, ownership named on the first.
- [x] **Diagrams included where flow is non-trivial** — §3.6, three files; the two runtime flows get
      sequence/flow diagrams precisely because they are not visible in the widget trees.
- [x] **No invented APIs / version numbers / metrics** — every figure traced to `00-measurements.md`,
      an increment packet, or the independent review. Where a number could not be verified from the
      source material it is absent, not estimated.
