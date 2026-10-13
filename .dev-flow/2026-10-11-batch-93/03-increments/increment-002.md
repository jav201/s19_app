# Increment 002 — `HLR-130` · `HLR-131` — the wrap audit (a real harness) + the responsive regimes

> **Agent note.** The increment ran on a **Kimi coder subagent under the coordinator's
> brief** (`evidence/inc002-brief.md`, verbatim). No commit/push/stash by the agent lane —
> the coordinator committed `8bf3f4e` at the increment's verification.

| Field | Value |
|---|---|
| Batch | `2026-10-11-batch-93` |
| Increment | `002` |
| Lane (if the batch forked) | none — one lane, sequential: this increment builds on inc-001's landed tree and owns only the wrap-audit + regime delta |
| Requirement(s) | `HLR-130` · `HLR-131` · `LLR-130.1`–`.2` · `LLR-131.1`–`.3` |
| Acceptance | white-box `TC-664` – `TC-670` (the audit's limbs + counterfactual) · `TC-673` – `TC-675` (the regime arms) — 10 ids, 10 executing arms |
| Agent | `kimi` (coder subagent), coordinator-briefed |
| Date | `2026-10-12` (coordinator's commit `8bf3f4e`, 2026-10-12 23:38 −06:00) |

---

## 1 · What changed

**The wrap audit ships as a real harness, and it caught defects — including its own
first fix.** `tests/test_tui_map_wrap.py` renders the shipped map screen at five
geometries (80×24 · 100×30 · 120×36 · 140×40 · 160×48) and walks every authored line
of every surface (header · band segments · ruler ticks · chips · region rows ·
inspector body · stats strip · pane chrome), asserting each fits its widget's measured
region width — 0 overflow lines, never a terminal-emulated wrap. Run against the
shipped inc-001 tree the audit measured real defects, all fixed at authorship (the
assertion was never weakened):

1. **Inspector A2L symbol names wrapped mid-content** (file-derived, unbounded): an
   82-cell name in the 38-col side-by-side interior, a 202-cell name at both regimes.
   Fixed via the house clip seam `_clip_to_cells` (`cell_len`/`set_cell_size` +
   ellipsis, mirroring `S19TuiApp._clip_to`) against `_inspector_body_width()`.
2. **The audit caught the fix's own first defect**: the clip budget ignored the
   inspector's vertical-scrollbar gutter (a 40-cell clipped line in the 38-col painted
   budget at 100×30) — the budget now subtracts `_INSPECTOR_SCROLLBAR_GUTTER` (**2**,
   measured) unconditionally, safe exactly because the scrollbar appears when a long
   name overflows.
3. **The pre-selection hint wrapped at every side-by-side geometry** (59-cell
   one-liner in the 40-col interior): re-authored as two lines (29/28 cells) joined
   through `Text` directly — `safe_text`'s C0 scrub would eat the newline (the house
   rule: newlines join `Text` lines directly).

Zero overflows across all five geometries after the fixes
(`evidence/inc002_probe_after.out.txt`); the harness's counterfactual (LLR-130.2) fails
on an injected over-long line and is clean without it (TC-670).

**The regimes are anchored to the panel's own measured width — never the terminal's.**
The stack threshold was re-measured pilot-style and recorded:
`_MAP_STACK_MIN_WIDTH = 86 = 51 + 35` — the contract's ~84 estimate corrected for the
scrollbar (the inset's "2-column slop" IS the scrollbar: at panel 86 the row widget
measures 35 with the list's 2-col scrollbar, 37 without; at 85 the 34-limb wraps). The
43-gate now picks its inset per regime via the shared `_is_stacked_width` predicate
(`_MAP_PANEL_TO_ROWS_INSET_STACKED = 8`, measured at four stacked geometries — closing
inc-001's recorded floor limitation: the 80×24 rows now carry the microbar). The
regime decision reads the panel width at render time; every resize re-apportions — the
width flip re-runs `render_ranges` itself (single selection authority,
generation-guarded), each `.map-region-list` is stamped with its render generation and
`_apply_auto_selection` resolves only the stamp-matched list (bounded retry), focus is
taken synchronously through `Screen.set_focus` (the deferred `Widget.focus()` callback
was measured dropping inside the transition), and the width-0 pass arms exactly one
bounded retry (LLR-131.3). **The map snapshots are unchanged** — both cells pass
green on the new law.

---

## 2 · Files modified

**The budget counts SOURCE files only. This increment: 2 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens_directionb.py` | `source` | HLR-130 · HLR-131 (+ LLR-130.1–.2 · LLR-131.1–.3) | the `_clip_to_cells` seam + the scrollbar-gutter-aware clip budget (`_INSPECTOR_SCROLLBAR_GUTTER = 2`, measured), the two-line pre-selection hint, `_MAP_STACK_MIN_WIDTH = 86` + `_MAP_PANEL_TO_ROWS_INSET_STACKED = 8` + the `_is_stacked_width` regime predicate, the generation-stamped row lists, the single-authority width flip, the synchronous focus path (+544 lines) |
| `s19_app/tui/styles.tcss` | `source` | HLR-131 | the stacked-regime rules (49 lines touched) |
| `tests/test_tui_map_wrap.py` | `test` | HLR-130 (TC-664 · TC-665 · TC-666 · TC-667 · TC-668 · TC-669 · TC-670) | **new** — the wrap-audit harness: the five-geometry matrix, the one-line limbs (header/stats · rows · hostile names · hint · chips/chrome), and the injected-line counterfactual |
| `tests/test_tui_map_big.py` | `test` | HLR-131 (TC-673 · TC-674 · TC-675) | 3 new arms: the stack-threshold boundary (panels 83/84/85/86/87 under a NARROW workspace class) · the live-resize re-apportionment (160×48 → 120×36 → 96×30 → 160×48) · the width-0 first-frame bounded retry |
| `tests/test_tui_directionb.py` | `test` | HLR-131 | 3 test-side re-aims riding the synchronous-focus measurement (the inc-001 precedent — assertions untouched): `_settle_selection` waits for focus to rest on a LIVE row; `test_b01_region_click_snaps_hex_to_far_range` settles the deferred auto-selection before the gesture (measured ~1-in-3 mid-gesture navigations); the shared click helpers bind targets from the panel's LIVE rows |
| `AT-TC-REGISTRY.jsonl` | `config` | HLR-130 · HLR-131 (id minting) | `TC-664`–`TC-670` · `TC-673`–`TC-675` LIVE with statements + nodes; `high_water` TC 663 → 675, `next_free` 676 |

| Count | Value |
|---|---|
| **SOURCE files** | **`2`** / 4 |
| Test files | 3 (1 new + 2 adapted; uncapped) |
| Config files | 1 (`AT-TC-REGISTRY.jsonl`; outside the count) |

- ⚠ **At exactly 4 source files:** not reached — 2.

---

## 3 · How to test

```bash
# the wrap audit (the whole harness — never a -k subset of its limbs)
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest tests/test_tui_map_wrap.py \
  -q -p no:cacheprovider

# the regime arms + the settled click family
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest tests/test_tui_map_big.py \
  tests/test_tui_directionb.py -q -p no:cacheprovider

# the before/after evidence probes (read-only; print the audit facts)
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
  .dev-flow/2026-10-11-batch-93/evidence/inc002_probe.py        # the wrap walk
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
  .dev-flow/2026-10-11-batch-93/evidence/inc002_boundary_probe.py # the live-resize legs
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
  .dev-flow/2026-10-11-batch-93/evidence/inc002_regime_probe.py   # the panel↔terminal mapping
```

The ONE complete gate-suite run is the coordinator's (`C-25`), in flight at this
packet's write; per-area runs only here, per the brief. Full-suite figures: `<suite at
close>`.

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | the audit's counterfactual (TC-670) + the regime pins | green — the increment's per-area runs, two transcripts: the wrap harness `evidence/inc002-perarea-run.txt` (**31 passed**, 0 failed, exit 0) + the regime/click modules `evidence/inc002-regime-perarea-run.txt` (**290 passed**, 0 failed, exit 0) |
| **A · white-box** `TC-664`–`TC-670` ↔ LLR-130.1–.2 · `TC-673`–`TC-675` ↔ LLR-131.1–.3 | `core` · `full` | 10 ids · 10 arms | 10 passed — the wrap harness 7 (`tests/test_tui_map_wrap.py`, in the 31-run) + the regime arms 3 (`tests/test_tui_map_big.py`, in the 290-run); the adapted `test_tui_directionb.py` re-aims re-ran green in the 290-run |
| **B · black-box** | `core` · `full` | the batch's Layer-B acceptance for this scope rides inc-001's `AT-292` + inc-003's `AT-293`/`AT-295` (the batch chartered one `AT` per story, not per increment) | see `04-validation.md` Layer B |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | **M1 (the counterfactual, LLR-130.2):** the harness's test-only injection seam mounts ONE deliberately over-long authored line into a surface → the audit must FAIL naming that line. **M2 (the before-state):** the shipped inc-001 tree's three real defects (the 82-cell and 202-cell A2L names, the 59-cell hint) — the audit measured them RED before any fix was believed |
| Instrument | `tests/test_tui_map_wrap.py`'s injection seam (the shipped arm, executed by the suite) + `evidence/inc002_probe.py` (the read-only probe printing the audit facts) |
| Where it ran | this tree — M1 composes the over-long line in-fixture (no shipped byte mutated); M2 ran against the landed inc-001 tree |
| Transcript | `evidence/inc002_probe.out.txt` (M2: `WRAP DEFECTS     : 2` / `: 1`, each naming its line) → `evidence/inc002_probe_after.out.txt` (fixed tree: `WRAP DEFECTS     : 0` at all five geometries; the clipped names end in the house ellipsis) |
| Restore proven by | n/a for M1 (in-fixture mount, nothing on disk); M2 is the shipped before-state itself, restored-by-commit (`8bf3f4e` carries the fixes) |
| Bytecode cache | suite runs with `-p no:cacheprovider`; the probes write no bytecode into the evidence home |
| Arms resolved at baseline | **2** — the counterfactual arm and the fixed-tree arm, one transcript each |
| Verdict granularity | per named defect line — each WRAP DEFECT names its surface, line and cell count |

| Field | Value |
|---|---|
| **RED counterfactual** | M1: the injected over-long line mounted through the test-only seam reddens the audit, naming that line (TC-670, `test_tc670_injected_overlong_line_fails_the_audit`) — transcript: the probe pair below; M2: the shipped inc-001 tree's three defects reddened the same audit (`evidence/inc002_probe.out.txt`). Restore: in-fixture/in-memory, nothing on disk mutated |

| Field | Value |
|---|---|
| **Mutation verdicts** | `test_tc670_injected_overlong_line_fails_the_audit`: M1 (over-long line mount) **KILLED** — the audit fails naming the line (≥1 failure per injected line, 0 false passes on the clean walk). The three before-state defects: each **KILLED** the fixed assertion set on the inc-001 tree (named in `inc002_probe.out.txt`). Arms that stayed GREEN: the demo-fixture limbs at every geometry, before and after. 0 SURVIVED · 0 CRASH · 0 BAD. Transcripts `evidence/inc002_probe.out.txt` / `evidence/inc002_probe_after.out.txt` |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `tests/test_tui_map_wrap.py` (the audit harness) | the injected over-long authored line (M1) + the shipped inc-001 tree's three defects (M2) | `WRAP DEFECTS : 2` / `: 1` naming each line, and the TC-670 arm RED naming the injected line — before the fixed-tree PASS (`WRAP DEFECTS : 0` at five geometries) was believed |
| `evidence/inc002_probe.py` / `inc002_boundary_probe.py` / `inc002_regime_probe.py` (the evidence probes) | none planted | their failure surface is the suite's assertion arms; the probes print facts for the record — declared, not claimed |
| the audit's own first clip fix | the shipped first-fix tree (budget without the scrollbar gutter) | the audit's 100×30 walk measured a 40-cell clipped line in the 38-col painted budget → `_INSPECTOR_SCROLLBAR_GUTTER = 2` — the instrument caught its own author's defect before any external reviewer did |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 2 instruments shown RED before their PASS was believed (the audit harness ×2 — the injected line and the inc-001 defects — and the harness's catch of its own first fix); the three fact-printing probes declared |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the painted map surface at five geometries | the audit's cell-width walk over each emitted `Static`'s rendered plain text vs its measured region | 0 overflow lines after the fixes (`inc002_probe_after.out.txt`); 3 before (`inc002_probe.out.txt`) |
| the stack/stacked regimes | TC-673's boundary arms at panels 83/84/85/86/87 (terminals 95–99) under the NARROW class | stacked below 86, side-by-side at/above; the compact row fits its widget exactly at 86 |
| the re-apportioned resize legs | TC-674's live pilot 160×48 → 120×36 → 96×30 → 160×48 | after every leg: the bar takes the grid content width, the rows rebuild to the gate's form, the peek re-cuts (17 → 5 → 1 → 17), the stats re-render — 0 stale surfaces |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifact classes, each asserted against the emitted rendered bytes/geometry, not intent |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | the wrap audit's PASS is an absence claim (no overflow line anywhere on the surface) — bounded by the five-geometry walk over every authored line class |
| If the result is an ABSENCE, what made the search wide enough | the walk covers every surface the contract names (header · band segments · ruler · chips · rows · inspector body · stats · chrome) at every tested geometry; a surface class the walk missed would be invisible — declared as the harness's declared scope, not an unlimited claim |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc670_injected_overlong_line_fails_the_audit`'s docstring: the audit that cannot fail proves nothing (C-43) — the guard protects the no-wrap CONCLUSION |
| Conjunctive criteria: one mutation per conjunct | M1 (injected line) and M2 (the three shipped defects) exercise the two conjuncts separately |
| Synthetic instance of the absent case | the injected over-long line IS the synthetic overflow the tree lacks |
| **Positive control for every probe that returned an ABSENCE** | the same unmodified probe on the inc-001 tree returned the NON-absent output (3 named WRAP DEFECTS) — the probe's positive control is the before-transcript itself |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "_clip_to_cells\|_MAP_STACK_MIN_WIDTH\|_is_stacked_width\|_INSPECTOR_SCROLLBAR_GUTTER" tests/` | the new seams/constants are named by `tests/test_tui_map_wrap.py` + `tests/test_tui_map_big.py` — both green |
| B2 file moved on disk | `git diff --name-status ae0ef4f..8bf3f4e -- s19_app/ tests/ \| grep -c "^R"` | **0** renames |
| B3 byte-identical golden captures this source | `git diff --name-status ae0ef4f..8bf3f4e -- tests/__snapshots__/ tests/goldens/` | **0** entries — both map snapshot cells pass unchanged on the new law (the 80×24 fold shows the overview stack; the 120×30 cell is side-by-side in both laws with identical row limbs) |
| B4 artifact produced here is consumed elsewhere | `grep -rln "test_tui_map_wrap" tests/ tools/` | consumed by no other module (the audit stands alone); the registry names its arms as the TC-664–670 nodes — the guard re-validates |
| A3 interface consumed by another module changed | `grep -rn "_clip_to_cells" s19_app/ tests/` | defined and consumed inside `screens_directionb.py`; the test seam reaches it in-fixture only — no cross-module interface moved |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run (B1 · B2 · B3 · B4 · A3); B2/B3 returned 0 with their commands printed; B4's consumers re-validated |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the shipped inc-001 tree wraps three authored lines | every authored line of every surface at the five geometries | the audit's own first walk (`inc002_probe.py` over the inc-001 tree) | 3 defects | 3 (the clip seam + the gutter constant + the hint re-authoring) | 0 — the walk after the fixes measured 0 |
| the stack threshold was a contract estimate (~84) | the smallest panel width at which the compact row fits its widget | executed: 51 (re-verified inset) + 35 (compact row) = 86, with the 86/85 limbs measured (`inc002_regime_probe.py` across terminals 60–120) | 1 constant | 1 | 0 — single-site correction, recorded in the constant's note |

| Field | Value |
|---|---|
| **Correction population** | 2 corrections, each enumerated by the audit's/measured walk before its first site was edited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| the 59-cell one-line pre-selection hint | re-authored as two lines (29/28 cells); the audit's hint limb (TC-668) fails on the one-liner | yes — a resurrection wraps at every side-by-side geometry and reddens TC-668 | `evidence/inc002_probe_after.out.txt` (the hint limb: two authored lines, 0 defects) |
| the unclipped A2L-name authorship | clipped via `_clip_to_cells` against the gutter-aware budget; TC-667 fails on an unclipped name | yes | the same transcript's hostile-name limb (0 defects at five geometries) |
| the terminal-keyed regime decision | replaced by the panel-width predicate; TC-673's NARROW-class arms fail a terminal-keyed regime | yes | `tests/test_tui_map_big.py::test_tc673_stack_regime_boundary_arms` |

### Signed-balance test ledger

`post = base − deleted + added` → the increment added **10** test functions, deleted **0**;
batch-level balance is in `04-validation.md`; the base/post collected figures are the
coordinator's `<suite at close>` numbers.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `human:coordinator` · PASS — reviewed the audit's walk scope against HLR-130's surface list, the three defects' before/after transcripts (each defect named, the fixes at authorship), the 86-threshold derivation (51 + 35 with both boundary limbs measured), the generation-stamp/synchronous-focus mechanism against the measured mid-transition drop, and the three test-side re-aims (assertions untouched — settles for a real timing change, per the inc-001 precedent). No HIGH. The reviewer is the same human who owns the `C-25` suite run — declared |

---

## 5 · Risks

- **The audit walks the surfaces the contract names; a new surface class added later is
  invisible to it until the walk's scope is extended.** TC-670 protects the audit's
  failure ability, not its scope.
- **The regime predicates are measured on the shipped chrome.** A chrome change (pane
  padding, the inspector's fixed width) shifts the insets; the constants carry their
  measurement notes, and TC-673/674 redden on a drifted threshold.
- **The test-side settles bound retries, not timing proofs.** Under extreme load a
  settle bound could be hit; the helpers report failure honestly at the bound rather
  than waiting forever (the docstrings say so).

## 6 · Pending items / spec deviations

- None owed by this increment. The two `TC-671`/`TC-672` ids of the chartered block were
  not spent (the audit's limbs minted as TC-664–670 instead) — the spare bookkeeping is
  the close's, per the batch-91 precedent.

## 7 · Suggested next task

Increment 003 — legend A (the spec sheet) + the command-bar interlock (`HLR-132` · `HLR-133`).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | **2 / 4** |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_tui_map_wrap.py` (new, 7 arms) + 3 regime arms in `tests/test_tui_map_big.py` |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | TC-670 (the counterfactual) + the regime pins are the unit layer |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | M1 (injected over-long line, TC-670) + M2 (the inc-001 tree's 3 defects); transcripts `inc002_probe.out.txt` / `inc002_probe_after.out.txt` |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | 5 probes with commands; B2/B3 zero-hits printed |
| 6 | `code-reviewer` passed — verdict and reviewer in **§4b** | `core` · `full` | ⚠ | no `code-reviewer` agent lens ran; `human:coordinator` reviewed instead — declared in §4b |
| 7 | No file from another lane touched | all | ✓ | single lane; the batch-92 merged set and the engine-frozen files carry 0 diff |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | no frozen file in the diff; `entropy_service.ENTROPY_BANDS` / `entropy_style.ENTROPY_BAND_LABELS` byte-identical (LLR-127.2) |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | the walk's transcripts are the painted bytes; the threshold derivation executed |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | the no-wrap PASS is an absence; the injected line is the synthetic instance; the before-transcript is the positive control |
| 11 | **Mutation verdicts** declared — per arm, inert arms named | all | ✓ | per-arm verdicts above; the clean limbs named as the arms that stayed GREEN; 0 SURVIVED · 0 CRASH · 0 BAD |
| 12 | **Instrument RED-proof** declared | all | ✓ | the audit harness shown RED twice (injected line; inc-001 defects) + its catch of its own first fix; the fact probes declared |
| 13 | **Correction population** declared | all | ✓ | 2 corrections, enumerated by the measured walks before the first edit |
| 14 | **Emitted-form assertion** declared | all | ✓ | the painted surface, the regime renders, the resize legs — asserted against emitted geometry |
| 15 | **Independent review** names somebody | all | ✓ | `human:coordinator`, §4b |
| 16 | **Evidence files** declared — digests of the STORED bytes | all | ✓ | 9 artifacts below, each re-hashable at its path |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| the coordinator's brief (verbatim) | `.dev-flow/2026-10-11-batch-93/evidence/inc002-brief.md` | `2327728b11d8d793c43f5f9f2d47899808c54511f0136a2ad547d54599a2ab31` |
| the re-measured thresholds + audit findings | `.dev-flow/2026-10-11-batch-93/evidence/inc002-pilot-measurements.md` | `53bfe387cd82190a648f03e302ca56f6ab3f85c2b031cc6eff2a5d8df439c37b` |
| the wrap-audit walk probe | `.dev-flow/2026-10-11-batch-93/evidence/inc002_probe.py` | `77bbde6607380ea32fdbd66fb0f47b61bd0e4ab8517e2606e4ad00b14ca479c0` |
| the audit's before-transcript (the inc-001 tree's defects) | `.dev-flow/2026-10-11-batch-93/evidence/inc002_probe.out.txt` | `3a198f779ed6ca7c8ad403980f0a1ba3536a26e7ac67682b026bff0ce61f2d2f` |
| the audit's after-transcript (0 defects at five geometries) | `.dev-flow/2026-10-11-batch-93/evidence/inc002_probe_after.out.txt` | `de115e480542e236a9310e06a274a4022ac9c7ff82c0e19cded33f18ef7f4092` |
| the panel↔terminal regime probe | `.dev-flow/2026-10-11-batch-93/evidence/inc002_regime_probe.py` | `dca2ab37bc9f76dd7a6ee19152299e80ae92b3dd249586e10248ef9091fbb969` |
| the live-resize boundary probe | `.dev-flow/2026-10-11-batch-93/evidence/inc002_boundary_probe.py` | `b2cf657b2306fe604bf19638ec14b68c6d3abbc49e8b784281656500a931a7d9` |
| the increment's per-area run (the wrap harness, 31 passed, exit 0) | `.dev-flow/2026-10-11-batch-93/evidence/inc002-perarea-run.txt` | `f4ff6d8a6d152fe1a39e59a5be4f61594b95d46997caeddc3f5df0f3ea9f9420` |
| the increment's per-area run (the regime/click modules, 290 passed, exit 0) | `.dev-flow/2026-10-11-batch-93/evidence/inc002-regime-perarea-run.txt` | `47b0087fd41c3128d4a1b9436e89844cc159020541b6511847b1c817d0453483` |

| Field | Value |
|---|---|
| **Evidence files** | 9 artifacts, each at the batch's declared evidence home and cited with the digest of its stored bytes |
