# Increment 003 — `HLR-132` · `HLR-133` — legend A: the grouped spec sheet with a live band key + the command-bar interlock

> **Agent note.** The increment ran on a **Kimi coder subagent under the coordinator's
> brief** (`evidence/inc003-brief.md`, verbatim). No commit/push/stash by the agent lane —
> the coordinator committed `4458a7f` at the increment's verification.

| Field | Value |
|---|---|
| Batch | `2026-10-11-batch-93` |
| Increment | `003` |
| Lane (if the batch forked) | none — one lane, sequential: builds on inc-001+002's landed tree; owns the legend-sheet + interlock delta |
| Requirement(s) | `HLR-132` · `HLR-133` · `LLR-132.1`–`.4` · `LLR-133.1` |
| Acceptance | `AT-293` · `AT-295` · white-box `TC-676` – `TC-681` (6 ids, 9 executing arms) |
| Agent | `kimi` (coder subagent), coordinator-briefed |
| Date | `2026-10-13` (coordinator's commit `4458a7f`, 2026-10-13 01:04 −06:00) |

---

## 1 · What changed

**The map's `k`-legend is reborn as the grouped spec sheet (legend A, the operator's
2026-08-06 ruling), and its band key cannot drift from the domain.** Pushing `k` on the
map view opens a modal whose body `_render_map_sheet()` composes **four grouped,
bordered boxes, in order**: **Entropy bands** — the `build_band_key_rows()` rows (glyph ·
label · `[lo,hi)` range · meaning) plus the `╱` gap-hatch row, the box title
live-titled from `ENTROPY_WINDOW_BYTES` — · **Map anatomy** (four rendered sample →
meaning pairs: band bar · ruler · glance chips · stats line) · **Region row** (one
rendered sample row + one field-key line) · **Keys** (the pinned
`↑↓ / j k select · click inspect · double-click / ↵ open hex · Esc close` line). The
band rows are sourced **LIVE at compose time** — `screens.py` reads
`build_band_key_rows()` when the sheet composes (screens.py:1248), never a hand-copied
label list; the rows keep their `band-*` paint, render `markup=False` (the literal
`[lo,hi)` brackets, the TC-N8-11 precedent), and no A2L severity row leaks into the
sheet. **The map card retires; Esc dismisses.** No line wraps at 80×24 or 120×36
(LLR-132.2 — the wrap audit's law covers this surface too), and the full-bleed
legend-sheet chrome exists because the contract's pinned 71-cell Keys line cannot fit
the stock 96% dialog at the floor (measured box interior 74).

**The interlock arm guards the do-not-resurrect law.** `tests/test_command_bar_interlock.py`
scans the whole `s19_app/tui` package + `styles.tcss` at an AST level with
comment/docstring zones excluded and **whole-token ids**: no live reference to
`#command_bar_row` nor the bar's find/goto input ids (`#find_input` /
`#cmdbar_goto_input`) survives anywhere — the lookalikes (`a2l_tag_find_input`, the hex
`#goto_input`) never trip it, and P-2's comment/docstring mentions are the only
survivors (the arm masks exactly those zones). The arm can FAIL: TC-679 plants a live
reference — a widget id in Python source, a query string, a CSS rule — in a scanned
file and the arm reddens, while a mere comment and the lookalikes stay clean. `AT-295`
binds the acceptance: the shipped surface is clean (TC-678/679) **and** the live map
screen composes no command-bar widget (the DOM arm).

**Two repairs rode the same increment, both measured.** (a) The registry's high-water
had drifted: `TC` read 663 while the tree already carried ids past it — repaired to
**681** (AT 292 → 295), the same class batch-91's P0 caught. (b) The registry guard's
scanned-file bound had drifted to 164 (one module added without a bump) — re-measured
and repaired to **166** (+ `test_legend_map_sheet.py` + `test_command_bar_interlock.py`),
with the drift admitted in the guard's own comment. (c) A **pre-existing** race, not of
this batch's making: `AT-023`'s modal-mount family could read the legend body before
`push_screen` mounted it under load (a single `pilot.pause()` does not guarantee the
mount). Fixed at the root along the inc-001 bounded-poll precedent: `_settle_legend`
polls — never unbounded — until the `LegendScreen` is on top with its body composed,
and reports failure honestly at the bound.

---

## 2 · Files modified

**The budget counts SOURCE files only. This increment: 3 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens.py` | `source` | HLR-132 | `LegendScreen` gains the map branch: `_render_map_sheet()` (the four grouped boxes, the live `build_band_key_rows()` read at compose, the full-bleed sheet chrome) + `action_close_legend`; the map card retired; `Esc` dismisses (260 lines touched) |
| `s19_app/tui/legend.py` | `source` | HLR-132 · LLR-132.4 | `build_map_anatomy_samples()` (the map-authored sheet data: the four anatomy sample/meaning pairs + the region-row sample + field key) — routed through the same escaping discipline the N8 lines established (244 lines touched) |
| `s19_app/tui/styles.tcss` | `source` | HLR-132 · LLR-132.2 | the `.legend-sheet-box` / `.legend-sheet-line` rules + the full-bleed sheet chrome (+39) |
| `tests/test_legend_map_sheet.py` | `test` | HLR-132 (TC-676 · TC-677 · TC-680 · TC-681 · AT-293) | **new** (7 arms) — the four-boxes census + line census, the in-fixture domain mutation (the hand-copy detector), the no-wrap law + the audit counterfactual + Esc, the other-views byte-identity control |
| `tests/test_command_bar_interlock.py` | `test` | HLR-133 (TC-678 · TC-679 · AT-295) | **new** (3 arms) — the clean-scan arm, the plant arm, the map-screen DOM arm |
| `tests/test_legend_n8.py` | `test` | LLR-132.3 | adapted to the new map path (the N8 scoping control over the other views — replace, never weaken) |
| `tests/test_legend_scope_and_logwidth.py` | `test` | LLR-132.3 | adapted (the scope suite stays green) |
| `tests/test_legend_two_pane.py` | `test` | LLR-132.3 | adapted (the two-pane suite stays green) |
| `tests/test_tui_legend.py` | `test` | HLR-132 (the AT-023 modal-mount family over the legend modal) | the modal-mount race fixed at the root: `_settle_legend` bounded poll; the AT-023a–e arms settle the mount before reading the body |
| `tests/test_id_registry.py` | `test` | HLR-132 · HLR-133 (registry guard) | `EXPECTED_SCANNED_TEST_FILES` 164 → **166**, the drift admitted in the comment (the bound had moved without a bump; the two new modules measured) |
| `AT-TC-REGISTRY.jsonl` | `config` | HLR-132 · HLR-133 (id minting) | `TC-676`–`TC-681` + `AT-293` + `AT-295` LIVE; `_meta.high_water` AT 292 → 295 · TC 663 → **681** (the drifted water repaired — the tree already carried 676–681's neighbors), `next_free` 296 / 682 |

| Count | Value |
|---|---|
| **SOURCE files** | **`3`** / 4 |
| Test files | 6 (2 new + 4 adapted/repaired; uncapped) |
| Config files | 1 (`AT-TC-REGISTRY.jsonl`; outside the count) |

---

## 3 · How to test

```bash
# the sheet + the interlock + the settled legend family
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest tests/test_legend_map_sheet.py \
  tests/test_command_bar_interlock.py tests/test_legend_n8.py \
  tests/test_legend_scope_and_logwidth.py tests/test_legend_two_pane.py \
  tests/test_tui_legend.py -q -p no:cacheprovider

# the registry guard (the high-water + the scanned bound)
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest tests/test_id_registry.py \
  -q -p no:cacheprovider

# the sheet probe (read-only; prints the box census + the floor budget)
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
  .dev-flow/2026-10-11-batch-93/evidence/inc003_sheet_probe.py
```

The ONE complete gate-suite run is the coordinator's (`C-25`), in flight at this
packet's write; per-area runs only here. Full-suite figures: `<suite at close>`.

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | the live-source unit (`test_tc677_sheet_band_rows_equal_live_build`) + the interlock's clean-scan unit | green in the increment's per-area run — transcript `evidence/inc003-perarea-run.txt`: **79 passed**, 0 failed, exit 0 |
| **A · white-box** `TC-676`–`TC-681` ↔ LLR-132.1–.4 · LLR-133.1 | `core` · `full` | 6 ids · 9 arms | 9 passed — the sheet arms 7 + the interlock arms 2; the AT-023a–e family re-ran green under the settle in the same run |
| **B · black-box** `AT-293` · `AT-295` | `core` · `full` | 2 acceptances | `AT-293` — the sheet through the shipped `k` path (the four boxes, the mutated label flowing through, Esc, the other views byte-identical — TC-676/677/680/681 are its executing arms); `AT-295` — zero live command-bar refs + the map screen composes no command-bar widget |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | **M1 (the domain mutation, TC-677):** one band renamed + one band added upstream **in-fixture** — the sheet must show the mutated domain with zero legend-code change; the retired label's absence is the hand-copy detector. **M2 (the plants, TC-679):** a planted live `#command_bar_row` reference — a widget id in Python source, a query string, a CSS rule — in a scanned file. **M3 (the sheet audit counterfactual, TC-680):** one over-long line mounted into a sheet box |
| Instrument | the shipped arms in `tests/test_legend_map_sheet.py` / `tests/test_command_bar_interlock.py` (the mutations live in-fixture or in planted throwaway modules the arm itself manages; no shipped byte is written) + `evidence/inc003_sheet_probe.py` (the read-only box census) |
| Where it ran | this tree — in-fixture mutations and plant-limbs only |
| Transcript | `evidence/inc003_sheet_probe.out.txt` — the emitted sheet census at 120×36 and 80×24 (every line `[1]` row tall, `cells ≤ box interior`, `after Esc: Screen`); the RED limbs are the suite arms (the mutated domain parsed back; the plant flagged; the over-long line named) |
| Restore proven by | n/a — nothing on disk mutated by the in-fixture arms; the plant limb's planted module is the arm's own throwaway, deleted by the test |
| Bytecode cache | suite runs with `-p no:cacheprovider`; the probe writes no bytecode into the evidence home |
| Arms resolved at baseline | **3** — M1 resolves on the two TC-677 arms (flow-through + equal-live-build), M2 on the TC-679 plant arm, M3 on the TC-680 counterfactual arm; each arm is a named node |
| Verdict granularity | per resolved node id — each arm invoked separately, its own assertion the failure surface |
| Arms that stayed GREEN | under M1 the anatomy box (canonical band vocabulary via `band_style`) survives the re-cut; under M2 the comment-mention and lookalike limbs stay clean; under M3 the unmounted sheet stays clean — each named in the arms' statements |

| Field | Value |
|---|---|
| **RED counterfactual** | M1: the in-fixture band-domain mutation (one rename + one addition) reddens the hand-copy detector — the sheet must parse back as exactly the mutated domain (`test_tc677_band_key_mutated_upstream_flows_through`); M2: the planted live `#command_bar_row` reference reddens the interlock arm (`test_tc679_interlock_arm_plant_reddens`); M3: the over-long line mounted into a sheet box reddens the sheet audit naming that line (`test_tc680_sheet_audit_counterfactual_reddens`). Transcript `evidence/inc003_sheet_probe.out.txt`; in-fixture/throwaway only — no shipped byte mutated |

| Field | Value |
|---|---|
| **Mutation verdicts** | `test_tc677_band_key_mutated_upstream_flows_through`: M1 (domain rename+add) **KILLED**. `test_tc677_sheet_band_rows_equal_live_build`: M1 **KILLED** (the rows equal the live build or the arm reddens). `test_tc679_interlock_arm_plant_reddens`: M2 (planted live id / query / CSS) **KILLED**. `test_tc680_sheet_audit_counterfactual_reddens`: M3 (over-long line mount) **KILLED**. Arms that stayed GREEN: the anatomy-vocabulary limb under M1, the comment/lookalike limbs under M2, the unmounted sheet under M3. 0 SURVIVED · 0 CRASH · 0 BAD. Transcript `evidence/inc003_sheet_probe.out.txt` (the emitted-form census) + the suite runs |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the TC-677 hand-copy detector | the mutated band domain (M1) | the label column no longer parses back as the live domain — the arm reddens naming the retired label (a hand-copied list cannot track an upstream mutation) |
| the TC-679 interlock plant arm | the planted live references (M2: id / query string / CSS rule) | the arm flags the planted reference — proven able to FAIL (C-43) before the shipped clean-scan PASS (TC-678) was believed |
| the TC-680 sheet-audit counterfactual | the mounted over-long line (M3) | the audit reddens naming the line — the same audit's unmounted walk is clean at both geometries |
| `evidence/inc003_sheet_probe.py` (the box census) | none planted | its failure surface is the suite arms; it prints the emitted box census for the record — declared |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 3 instruments shown RED before their PASS was believed (the hand-copy detector, the interlock plant arm, the sheet-audit counterfactual); the census probe declared |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the sheet's boxes + lines | `inc003_sheet_probe.py` walks the emitted `.legend-sheet-box` containers: border titles, per-line row heights, `cell_len` vs the measured box interior, then Esc | at 120×36 and 80×24: the four boxes in order, every line `[1]` tall and in budget (0 `WRAP` flags), `after Esc: Screen` — transcript `inc003_sheet_probe.out.txt` |
| the other views' legends | TC-681's byte-comparison of the workspace/a2l/mac/issues + fallback renders against sha256 pins taken on the inc-002 tree | byte-identical at both geometries (a map-path leak reddens) |
| the interlock scan | TC-678's AST-level walk over the emitted `s19_app/tui/**` + `styles.tcss` bytes | CLEAN — 0 live references; the comment/docstring zones are the only survivors (P-2's mentions) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifact classes, each asserted against the emitted bytes (the composed sheet, the other views' renders, the scanned source) |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | the interlock's PASS is an absence claim (no live `#command_bar_row` reference anywhere in the scanned set) |
| If the result is an ABSENCE, what made the search wide enough | the scan covers the whole `s19_app/tui` package + `styles.tcss` at AST level (comments/docstrings excluded, whole-token ids) — the scanned set is enumerated from the tree, not assumed |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc679_interlock_arm_plant_reddens`'s statement: the arm must be able to FAIL (C-43) — it protects the do-not-resurrect CONCLUSION, not a rendering behavior |
| Conjunctive criteria: one mutation per conjunct | M2 plants each reference class separately (id · query · CSS); M1 exercises the rename and addition conjuncts in one fixture |
| Synthetic instance of the absent case | the planted live references ARE the synthetic resurrection the tree lacks |
| **Positive control for every probe that returned an ABSENCE** | the same unmodified scanner on the planted file returns the NON-absent output (the flag) — the plant limb is the positive control |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "build_map_anatomy_samples\|_render_map_sheet\|legend-sheet" tests/` | the new sheet surface is named by `tests/test_legend_map_sheet.py`, `tests/test_legend_n8.py`, `tests/test_legend_scope_and_logwidth.py`, `tests/test_legend_two_pane.py` — all green |
| B2 file moved on disk | `git diff --name-status 8bf3f4e..4458a7f -- s19_app/ tests/ \| grep -c "^R"` | **0** renames |
| B3 byte-identical golden captures this source | `git diff --name-status 8bf3f4e..4458a7f -- tests/__snapshots__/ tests/goldens/` | **0** entries — the map snapshots unchanged (the sheet is a modal, not in the map cells) |
| B4 artifact produced here is consumed elsewhere | `grep -rln "build_band_key_rows" s19_app/ tests/` | the live band-key builder is consumed by the N8 legend paths and the new sheet branch; every consumer re-validated green |
| A3 interface consumed by another module changed | `git show 4458a7f -- s19_app/tui/screens.py \| grep -A3 "def __init__"` | `LegendScreen(sections, view_key)` signature + the `k`/button call sites (`app.py:5973-5995`) survive unchanged — the map content lives entirely in the map `view_key` path |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run (B1 · B2 · B3 · B4 · A3); B2/B3 returned 0 with their commands printed |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the registry high-water trailed the tree (TC drift) | every TC id on disk must sit at or below `high_water` | the guard's own G7 over the landed inc-002 tree | 1 site (the `_meta` line) | 1 | 0 — single-site repair, 663 → 681 |
| the scanned-file bound had drifted (one module added unbumped) | every test module is counted by the guard | `tools/id_registry.py`'s own `scanned_test_files()` + the guard's assertion | 164 → 166 (the drift + the two new modules) | 1 (the constant) | 0 — measured, the drift admitted in the comment |
| the legend tests pin the old map format | every legend test module's map-path expectation | the brief names the legend modules; the diff enumerates (`git show 4458a7f --name-only -- tests/`) | 4 modules adapted | 4 | 0 — behavior oracles preserved (LLR-132.3's other-views control is the byte-identical pin) |

| Field | Value |
|---|---|
| **Correction population** | 3 corrections, each enumerated from its authority (the guard's own RED, the measured count, the brief's module list) before the first site was edited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| the map card (the pre-sheet map legend content) | retired — `_render_map_sheet` replaces the card on the map branch | yes — a resurrection fails TC-676's box census (a fifth content shape reddens the exact line census) | `tests/test_legend_map_sheet.py::test_tc676_sheet_four_grouped_boxes` |
| the hand-copied band labels | the sheet reads `build_band_key_rows()` live at compose (screens.py:1248) | yes — a hand-copied label fails TC-677 the moment the domain mutates | the TC-677 arms + the guard's token census over `legend.py` |
| the one-`pause()` modal mount | `_settle_legend` bounded poll in `test_tui_legend.py` | yes — the AT-023a–e arms settle the mount before reading the body | `tests/test_tui_legend.py` (`_settle_legend`) |

### Signed-balance test ledger

`post = base − deleted + added` → the increment added **10** test functions, deleted **0**;
batch-level balance is in `04-validation.md`; the base/post collected figures are the
coordinator's `<suite at close>` numbers.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `human:coordinator` · PASS — reviewed the sheet against legend A's capture and LLR-132.1's box order/line census, the live-source mechanism (`build_band_key_rows` read at compose — the hand-copy detector exercised by the in-fixture mutation), the interlock's AST scan (whole-token ids, the comment/docstring zones, the three plant classes), the registry repairs (the drifted high-water and the measured 166 bound), and the AT-023 settle as the inc-001 bounded-poll precedent applied to a pre-existing race. No HIGH. The reviewer is the same human who owns the `C-25` suite run — declared |

---

## 5 · Risks

- **The sheet's band box lives while `build_band_key_rows()` lives.** A future edit that
  hand-copies labels into `legend.py` passes every presence check and fails only the
  mutation arm (TC-677) — which is exactly the design, and why the arm mutates the
  domain rather than grepping for literals.
- **The interlock scans the shipped tree as written today.** A new scanned file added
  outside `s19_app/tui` would not be covered until the scan's set is re-derived; the
  scan enumerates from the tree, so the drift is visible in the arm's own file list.
- **The full-bleed chrome is a floor-geometry compromise** (the pinned 71-cell Keys
  line cannot fit the stock 96% dialog at 80×24 — measured interior 74). A wider Keys
  line would outgrow it; the sheet audit (TC-680) covers the surface.

## 6 · Pending items / spec deviations

- None owed by this increment. The unspent chartered ids (`AT-294`, `TC-671`, `TC-672`)
  are spare-reservation bookkeeping for the close, per the batch-91 precedent.

## 7 · Suggested next task

The batch close — `04-validation.md` + `05-close.md`, then the coordinator's fold-canon
of `HLR-125..133` / `LLR-*.x` into `REQUIREMENTS.md`.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | **3 / 4** — the screen branch + the legend data + the sheet styles |
| 2 | Tests written in this same increment | all | ✓ | 2 new modules (`test_legend_map_sheet.py` 7 arms · `test_command_bar_interlock.py` 3 arms) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the live-source unit + the clean-scan unit |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | M1 (TC-677 domain mutation) · M2 (TC-679 plants) · M3 (TC-680 over-long mount); transcript `inc003_sheet_probe.out.txt`; no shipped byte mutated |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | 5 probes with commands; B2/B3 zero-hits printed |
| 6 | `code-reviewer` passed — verdict and reviewer in **§4b** | `core` · `full` | ⚠ | no `code-reviewer` agent lens ran; `human:coordinator` reviewed instead — declared in §4b |
| 7 | No file from another lane touched | all | ✓ | single lane; batch-92's merged set and the engine-frozen files carry 0 diff |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | no frozen file in the diff; `ENTROPY_BANDS` / `ENTROPY_BAND_LABELS` byte-identical |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | the sheet census walks the emitted boxes; the scan enumerates the tree; the pins are sha256 over emitted bytes |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | the interlock's absence claim carries the plant as its synthetic instance + positive control |
| 11 | **Mutation verdicts** declared — per arm, inert arms named | all | ✓ | per-arm KILLED verdicts above; the GREEN limbs named; 0 SURVIVED · 0 CRASH · 0 BAD |
| 12 | **Instrument RED-proof** declared | all | ✓ | 3 instruments shown RED before their PASS was believed; the census probe declared |
| 13 | **Correction population** declared | all | ✓ | 3 corrections, each enumerated from its authority before the first edit |
| 14 | **Emitted-form assertion** declared | all | ✓ | the composed sheet, the other views' renders, the scanned source — asserted against emitted bytes |
| 15 | **Independent review** names somebody | all | ✓ | `human:coordinator`, §4b |
| 16 | **Evidence files** declared — digests of the STORED bytes | all | ✓ | 5 artifacts below, each re-hashable at its path |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| the coordinator's brief (verbatim) | `.dev-flow/2026-10-11-batch-93/evidence/inc003-brief.md` | `55b2fc289f261c4fbddec96abc67cba1bc37d46815775de87a1e4cc8da3aef2c` |
| the sheet box-census probe | `.dev-flow/2026-10-11-batch-93/evidence/inc003_sheet_probe.py` | `07bb72a4ff69a74db0d74b9113339694d30e00fdd9018c2ee70d2d667ced70ef` |
| the sheet's emitted census (120×36 + 80×24, Esc limb) | `.dev-flow/2026-10-11-batch-93/evidence/inc003_sheet_probe.out.txt` | `1404ac2245c3a595554875651d1b33aebc33b9fac68da9fce38c395e10567d07` |
| the other-views byte-identity hash probe | `.dev-flow/2026-10-11-batch-93/evidence/inc003_hash_probe.py` | `0631a824c7c872352552cca75d3cb725677fbfa3251821523f302721fe708727` |
| the increment's per-area run (sheet + interlock + settled legend family, 79 passed, exit 0) | `.dev-flow/2026-10-11-batch-93/evidence/inc003-perarea-run.txt` | `3652b93adaa7621ae33e6a965ff3d247425e6ccea69d0e3ce048c715437202b4` |

| Field | Value |
|---|---|
| **Evidence files** | 5 artifacts, each at the batch's declared evidence home and cited with the digest of its stored bytes |
