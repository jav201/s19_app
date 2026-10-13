# Increment 001 — `HLR-125` – `HLR-129` — the cockpit core: chrome kit, scrollable region list + full-height inspector, one-line chips + stats, pilot-measured thresholds

> **Agent note.** The increment ran on a **Kimi coder subagent under the coordinator's
> brief** (`evidence/inc001-brief.md` is that brief, verbatim). No commit/push/stash by
> the agent lane — the coordinator committed `ae0ef4f` at the increment's verification.

| Field | Value |
|---|---|
| Batch | `2026-10-11-batch-93` |
| Increment | `001` |
| Lane (if the batch forked) | none — one lane on the main checkout; the three increments are **sequential on the Memory Map surface** (inc-002's and inc-003's briefs open with "increment 001 has LANDED — build on it, do not re-do it"), so the later packets restate only their own delta |
| Requirement(s) | `HLR-125` · `HLR-126` · `HLR-127` · `HLR-128` · `HLR-129` · `LLR-125.1`–`.2` · `LLR-126.1`–`.4` · `LLR-127.1`–`.4` · `LLR-128.1` · `LLR-129.1`–`.3` |
| Acceptance | `AT-292` · white-box `TC-656` – `TC-663` (8 ids, 13 executing arms) |
| Agent | `kimi` (coder subagent), coordinator-briefed |
| Date | `2026-10-12` (coordinator's commit `ae0ef4f`, 2026-10-12 21:37 −06:00) |

---

## 1 · What changed

**The Memory Map surface is an inspector cockpit.** Every map surface renders inside
the shared bordered, titled pane chrome (HLR-125): the map pane carries the lit title
`Memory Map` and the subtitle `{N} regions · ░▒▓ k`; the inspector pane titles itself
`Inspector — 0x{start:08X}` with the `↑↓ · ↵ hex` affordance hint. The left pane stacks
band bar (1 row) → ruler → glance chips → the scrollable region list (HLR-126.1); the
list scrolls (9 demo rows overflow the viewport; the scrollbar is asserted
behaviorally, not by glyph — the contract's declared capture limitation). The
full-height inspector shows the five aligned fields at identical value columns
(offset 9) and the **8-byte peek**: exactly `ADDR` + two spaces + eight 2-hex bytes =
**33 cells**, unmapped bytes rendering `··` to keep the width, row count cut from the
measured pane height minus the 6 field rows, floored at 1 and monotone in height
(HLR-128 / LLR-126.3). The glance block retires to **one line of chips** (R-TUI-061's
amendment): counts are merged-run tallies, shares are the **mapped-byte** share — the
only reading under which the capture's chips sum to 100 (the P1 correction). The seven
statistics move to **one always-visible adaptive line** (HLR-113's amendment): the
84-cell full form at and above the measured threshold, the 66-cell compact form below
it, never scrolled away.

**Every threshold is a named constant carrying its pilot measurement, not a magic
number** (C-29): `_STATS_FULL_MIN_WIDTH = 84` (the full form's own measured width,
matching the contract's P1 capture measurement), `_REGION_ROW_MICROBAR_MIN_WIDTH = 43`
(the smallest value consistent with both capture limbs: microbar absent at the 41-col
120×36 pane, present at the 81-col 160×48 pane), `_MAP_PANEL_TO_ROWS_INSET = 51`
(panel padding 4 + inspector 44 + gutter 1 + pane border/padding 4 − 2 measurement
slop — the recorded note admits the stacked-regime over-subtraction; the regime-aware
re-derivation is HLR-131's, and landed in inc-002). Method for every number:
`evidence/inc001-pilot-measurements.md`.

**Two test-side repairs and one re-derivation, all measured.** (a) The
region-click test family failed intermittently; the root cause was **test-side** — the
helpers bound their target from `app.query(RegionRow).first`, which can match a
superseded render's row — while the product click path was verified intact; the family
was re-aimed with a **bounded hit-test poll**. (b) The map snapshot captures carried a
focus-scroll race (the capture could run before the scheduled focus scroll settled);
the race was fixed at the root in the capture discipline and the two map baselines
regenerated. (c) The batch-77 band-strip golden was **re-derived, not hand-edited**:
80-wide cells 66 → **62** (the chrome kit's two cells per side), 120×30 50 → 41, with
the independent allocator derivation asserted to agree before the bytes were written.

---

## 2 · Files modified

**The budget counts SOURCE files only. This increment: 3 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens_directionb.py` | `source` | HLR-125 · HLR-126 · HLR-127 · HLR-128 · HLR-129 (+ all their LLRs) | the `MemoryMapPanel` re-composition (+892/−): the shared pane chrome, the cockpit layout, the aligned field block, the 33-cell 8-byte peek, the chips line, the adaptive stats line, the fixed-width region rows with the width-aware microbar, and the three pilot-measured thresholds as named constants |
| `s19_app/tui/app.py` | `source` | HLR-125 · HLR-126 | the map renderer host re-aimed at the re-composed panel (+9/−) |
| `s19_app/tui/styles.tcss` | `source` | HLR-125 · HLR-126 · HLR-129 | the pane-chrome and cockpit layout rules, the chips/stats/peek styles (166 lines touched) |
| `tests/test_tui_map_big.py` | `test` | HLR-125 · HLR-126 · HLR-127 · HLR-128 · HLR-129 (TC-656 · TC-657 · TC-658 · TC-659 · TC-660 · TC-661 · TC-662 · TC-663 · AT-292) | 13 new executing arms (the eight TC ids; TC-659/660/661/662 carry two arms each) + the DOM adaptations of the pre-existing arms (the behavior oracles of LLR-126.4/127.4 preserved — the old DOM expectations replaced, never weakened) |
| `tests/test_tui_directionb.py` | `test` | HLR-126 · HLR-127 | DOM expectation adaptations to the new layout (behavior oracles preserved) |
| `tests/test_map_click_chain.py` | `test` | HLR-126 · HLR-127 | the region-click family root-caused test-side and re-aimed with the bounded hit-test poll (the product path verified intact first) |
| `tests/test_tui_snapshot.py` | `test` | HLR-125 · HLR-126 | the focus-scroll capture race fixed at the root (the bounded-settle precedent) |
| `tests/__snapshots__/...sity_layout_snapshot[map-comfortable-80x24].svg` | `generated` | HLR-125 · HLR-126 | the map baseline regenerated — the layout changed by design; the CI snapshot lane remains the source of truth (local font drift declared) |
| `tests/__snapshots__/...sity_layout_snapshot[map-comfortable-120x30].svg` | `generated` | HLR-125 · HLR-126 | same — the 120×30 map cell |
| `tests/goldens/batch77/at-b77-02-gapless-band-strip.txt` | `generated` | HLR-125 | the band-strip golden **re-derived** (80-wide 66 → 62 cells, 120×30 50 → 41 — the chrome kit's columns), the independent allocator derivation asserted to agree before write |
| `AT-TC-REGISTRY.jsonl` | `config` | HLR-125 – HLR-129 (id minting) | `TC-656`–`TC-663` + `AT-292` LIVE with statements + nodes; `_meta.high_water` AT 286 → 292 · TC 648 → 663, `next_free` 293 / 664 |

| Count | Value |
|---|---|
| **SOURCE files** | **`3`** / 4 |
| Test files | 4 (uncapped) |
| Generated files | 3 (the 2 snapshot baselines + the re-derived band-strip golden; outside the count) |
| Config files | 1 (`AT-TC-REGISTRY.jsonl`; outside the count) |

---

## 3 · How to test

```bash
# the increment's own arms (the map module + the click family + the snapshot cells)
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest tests/test_tui_map_big.py \
  tests/test_map_click_chain.py tests/test_tui_directionb.py tests/test_tui_snapshot.py \
  -q -p no:cacheprovider

# the pilot-measured thresholds + cockpit facts, re-rendered (the evidence probe)
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
  .dev-flow/2026-10-11-batch-93/evidence/inc001_render_check.py

# the registry guard (the minted ids + the high-water)
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest tests/test_id_registry.py \
  -q -p no:cacheprovider
```

The ONE complete gate-suite run is the coordinator's (`C-25`), in flight at this
packet's write; this increment ran per-area runs only, per the brief's discipline. The
full-suite figure is a `<suite at close>` placeholder owed by that run.

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | the pilot measurements + the threshold/row/peek pins (`test_tc660_row_widths_pin_the_threshold`, `test_tc661_peek_row_count_is_monotone_in_pane_height`, `test_tc662_stats_threshold_boundary_limb`) | green — the per-area run: `evidence/inc001-perarea-run.txt` (302 passed / 27 failed, exit 1 — the census below) |
| **A · white-box** `TC-656`–`TC-663` ↔ LLR-125.1–129.3 | `core` · `full` | 8 ids · 13 arms | 13 passed (`tests/test_tui_map_big.py`) — inside the run |
| **B · black-box** `AT-292` ↔ US-125/US-126 | `core` · `full` | 1 arm | 1 passed — `test_at292_cockpit_acceptance_at_120x36` (zero clicks: every surface chromed and populated, stats + chips visible without scrolling, nine rows column-straight) — inside the run |

**The run's failure census, named rather than smoothed** (`evidence/inc001-perarea-run.txt`):
302 passed / **27 failed — every one a `test_tc016s_density_layout_snapshot[…]` cell on a
NON-map surface** (workspace · a2l · mac · issues · patch · diff), i.e. the known
environmental snapshot/font family — the baselines were generated in CI's font
environment and the rendered SVG differs in font metrics on this machine (the family's
standing record: batch-91's close, batch-92's noise floor). **Zero map cells fail** —
the batch's own regenerated baselines (`map-comfortable-80x24` / `map-comfortable-120x30`)
pass, which is the only snapshot surface this batch's diff moves. The other three modules
in the run (`test_tui_map_big` · `test_map_click_chain` · `test_tui_directionb`) are fully
green.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | no separate in-batch mutation battery for this increment — the increment's own defects were caught **after landing, by the next increment's audit harness**, and the P1 negative controls were the pre-land RED evidence. Both are named here rather than a battery invented: **(a)** the inc-002 wrap audit's probe, run against this increment's shipped tree, measured `WRAP DEFECTS: 2` (the 82-cell and 202-cell A2L symbol names) and `WRAP DEFECTS: 1` (the 59-cell pre-selection hint) — real REDs of real defects on this tree, fixed at authorship in inc-002; **(b)** the four P1 executable negative controls (column alignment on single-space rows · one-line stats on `build_stats_text` · the peek format on `_region_hex_peek` · stats visibility at 120×36), recorded as executable-RED in `02-review.md`'s qa checklist |
| Instrument | `evidence/inc002_probe.py` (the wrap audit harness — project code, run read-only against the shipped inc-001 tree; no on-disk mutation, chosen deliberately while suite runs were in flight) · the P1 controls per `02-review.md` |
| Where it ran | this tree, read-only — the probe mutates nothing; the hostile lines are fixture inputs composed in memory |
| Transcript | `evidence/inc002_probe.out.txt` — `WRAP DEFECTS     : 2` / `: 1` with the offending lines named (`A_VERY_LONG_SYMBOL_NAME_THAT_WILL_NOT_FIT_INSIDE_THE_INSPECTOR_PANE_WIDTH_AT_ALL`, the 202-`x` name, the 59-cell hint) |
| Restore proven by | n/a — no shipped byte was mutated by the probe (in-memory fixture inputs only); the probe's own transcripts are the stored evidence |
| Bytecode cache | the probes ran under the house env with `-p no:cacheprovider` discipline; the stored transcripts carry no bytecode side effects |
| Arms resolved at baseline | n/a — see the mutation row: the RED evidence here is the two audit transcripts + the four P1 controls, each a named executable, not a per-arm battery |
| Verdict granularity | per named defect (three wrap defects) + per P1 control (four) |
| Arms that stayed GREEN | the probe's own clean limbs at the same geometries (`WRAP DEFECTS : 0` on the demo fixture rows) — named in the same transcript |

| Field | Value |
|---|---|
| **RED counterfactual** | the wrap-audit probe's transcripts against this increment's shipped tree (`evidence/inc002_probe.out.txt`: the 2-defect hostile-name limb + the 1-defect hint limb, each naming its line) and the four P1 executable negative controls (`02-review.md`) — no separate in-batch battery; declared rather than invented |

| Field | Value |
|---|---|
| **Mutation verdicts** | none — no in-batch mutation battery in this increment; the defect-detection verdicts live in increment 002's packet (the audit that caught this increment's three wrap defects and proved its counterfactual TC-670) |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `evidence/inc001_render_check.py` (the cockpit-facts probe) | none planted — it prints the cockpit facts (pane titles/subtitles, chips, row forms, peek) for eyeball diff against the capture; its failure surface is the assertion arms in `tests/test_tui_map_big.py` | declared, not claimed |
| `tests/test_tui_map_big.py`'s new arms | the three wrap defects this tree carried (the audit transcripts above) | the audit's WRAP DEFECTS lines — before any PASS on the fixed tree was believed (inc-002's `inc002_probe_after.out.txt`: `WRAP DEFECTS : 0` at all five geometries) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 1 instrument shown RED via the stored audit transcripts (the wrap probe, reddened by this tree's three defects); the render-check probe's reliance on eyeball diff + the suite's assertion arms declared |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the re-derived band-strip golden | `AT-B77-02`'s byte-comparison over `read_bytes()` of the emitted golden + the independent allocator derivation asserted to agree before write | 80-wide cells 66 → 62, 120×30 50 → 41, and the two derivations in agreement (the golden re-derived, never hand-edited) |
| the two regenerated snapshot baselines | the snapshot cells re-run green against the emitted `.svg` bytes (the CI lane remains the source of truth; local font drift declared) | both map cells pass; the other cells untouched |
| the cockpit render | `inc001_render_check.py` drives the shipped screen at 100×30 / 120×36 / 160×48 and prints the painted facts (`inc001-map-120x36.svg` / `inc001-map-160x48.svg`) | chips `· 1 19% ░ 1 5% ▒ 4 57% ▓ 3 19%`, fixed-width rows, 8-byte peek, the always-visible stats line — matching the variant-C capture |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifact classes, each asserted against the emitted bytes (the golden file, the baseline SVGs, the painted screen), not against intent |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | no absence claim — every census (chips sum, row offsets, peek width) is a bounded positive measurement over the demo fixture |
| If the result is an ABSENCE, what made the search wide enough | n/a |
| Guard labelled as protecting a CONCLUSION, not a behaviour | n/a |
| Conjunctive criteria: one mutation per conjunct | n/a |
| Synthetic instance of the absent case | the hostile-name limbs (the 82-cell and 202-cell fixture names) are the synthetic over-long instances the audit composed — they are what the wrap defects looked like before inc-002 clipped them |
| **Positive control for every probe that returned an ABSENCE** | n/a — no absence probe |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "MemoryMapPanel\|_STATS_FULL_MIN_WIDTH\|_REGION_ROW_MICROBAR_MIN_WIDTH" tests/` | the panel and its constants are named by `tests/test_tui_map_big.py`, `tests/test_tui_directionb.py`, `tests/test_map_click_chain.py` and the inc-002 wrap module — all re-validated green in the per-area runs |
| B2 file moved on disk | `git diff --name-status 2f63a0c..ae0ef4f -- s19_app/ tests/ \| grep -c "^R"` | **0** renames — the layout work re-composes in place; the batch-92 moves (`render/hexview.py`, `utils.safe_text`) are consumed at their new homes, not re-created |
| B3 byte-identical golden captures this source | `grep -rl "map_detail_body\|map-region-list" tests/__snapshots__/ tests/goldens/ 2>/dev/null` | hits: the two regenerated map baselines (named above) + the re-derived band-strip golden — each accounted for as a by-design regeneration with its derivation recorded |
| B4 artifact produced here is consumed elsewhere | `grep -rln "render_ranges\|update_memory_map" s19_app/tui/app.py` | the host's `update_memory_map` → `render_ranges` path is the sole consumer chain; it re-ran green through the adapted directionb/click-chain modules |
| A3 interface consumed by another module changed | `git show ae0ef4f -- s19_app/tui/app.py` (the only other shipped module in the diff) | the host diff is the re-aim (+9 lines); no engine-frozen file (`color_policy.py`, `range_index.py`, the `_ENGINE_PATHS` set) in the diff |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run (B1 · B2 · B3 · B4 · A3) with their commands and verdicts; B2 returned 0 with its command printed; B3's hits are the three by-design regenerations, each with its derivation |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the demo fixture's DOM expectations pin the OLD layout | every memmap test module's DOM assertion must be replaced with the new contract's truth, never weakened | the brief names the four memmap modules; the diff enumerates them (`git show ae0ef4f --name-only -- tests/`) | 4 modules named; 3 carried adaptations (`test_tui_map_big.py`, `test_tui_directionb.py`, `test_map_click_chain.py`) + the snapshot capture | 4 | 0 — `test_memmap_entropy_merge.py`'s oracle turned out not to pin the retired DOM (verified green unchanged) |
| the snapshot baselines cover the changed surface | every snapshot cell whose pixels the layout change moves | `git show ae0ef4f --name-only -- tests/__snapshots__/` | 2 map cells | 2 | 0 — the other cells' surfaces are untouched; both re-ran green |
| the band-strip golden's width budget shifted with the chrome | the golden's recorded cell widths must equal the re-derived allocator widths | the independent allocator derivation (asserted to agree before write) | 1 golden (4 rows) | 1 | 0 — single-site re-derivation |

| Field | Value |
|---|---|
| **Correction population** | 3 corrections, each enumerated from its authority (the brief's module list, the snapshot diff, the golden's own derivation) before its first site was edited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| the retired glance block + the old stats home (the pre-change DOM) | the new arms assert the chips line and the one-line stats; the old glance/stats selectors carry no surviving live ref in the map surface | yes — a resurrection fails `test_tc662_stats_one_line_adaptive_visible` / `test_tc663_glance_chips_sum_to_one_line` | `tests/test_tui_map_big.py` (the TC-662/663 arms); the adapted `test_tui_directionb.py` DOM expectations |

### Signed-balance test ledger

`post = base − deleted + added` → the increment added **13** test functions, deleted **0**:
batch-level balance (with inc-002's +10 and inc-003's +10) is in `04-validation.md`; the
base/post collected figures are the coordinator's `<suite at close>` numbers.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `human:coordinator` · PASS — reviewed the re-composition against the contract's LLR blocks (chrome · stack order · aligned fields · peek format · stats forms · chips semantics), the pilot-measurement methods in `evidence/inc001-pilot-measurements.md` (each number re-derivable), the test-side root-cause of the click family (product path verified intact before any test was re-aimed), and the re-derived golden's agreeing allocator derivation. No HIGH. The reviewer is the same human who owns the `C-25` suite run — declared, so the reader knows the lens and the runner are one pair of eyes |

---

## 5 · Risks

- **The thresholds are pilot-measured on the demo fixture and the captures.** The 43/84/51
  constants carry their methods; a different fixture mix could want different values, and
  the constants' notes say so. The boundary limbs (TC-660/662) pin exactly-at vs one-below.
- **The stacked-regime over-subtraction** recorded in `_MAP_PANEL_TO_ROWS_INSET`'s note
  (the 80×24 floor rows rendered microbar-free) was a known limitation of this increment;
  it closed in inc-002 with the regime-aware inset — recorded there, not here, to keep the
  record sequential.
- **Snapshot baselines regenerated locally.** The CI snapshot lane is the source of truth;
  local font drift is declared. If CI disagrees, the baselines are regenerated there and
  the record names it.

## 6 · Pending items / spec deviations

- None owed by this increment. The batch-level items (the visual verdict sheet for the
  operator, the fold-canon) land in `05-close.md` / the coordinator's owed steps.

## 7 · Suggested next task

Increment 002 — the wrap audit + the responsive regimes (`HLR-130` · `HLR-131`).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | **3 / 4** — the panel module + the host re-aim + the stylesheet; one surface cannot be cut smaller |
| 2 | Tests written in this same increment | all | ✓ | 13 new arms in `tests/test_tui_map_big.py` (TC-656–663 + AT-292), new in this increment |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the pilot pins (`test_tc660_row_widths_pin_the_threshold` · `test_tc661_peek_row_count_is_monotone_in_pane_height` · `test_tc662_stats_threshold_boundary_limb`) are the unit layer |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | the wrap-audit transcripts against this tree (`evidence/inc002_probe.out.txt`, 3 named defects) + the four P1 executable controls (`02-review.md`); no in-batch battery — declared, not smoothed |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | 5 probes with commands and verdicts; B2's zero-hit carries its command |
| 6 | `code-reviewer` passed — verdict and reviewer in **§4b** | `core` · `full` | ⚠ | no `code-reviewer` agent lens ran; `human:coordinator` reviewed instead — the substitution is declared in §4b, not hidden behind a name |
| 7 | No file from another lane touched | all | ✓ | single lane; batch-92's merged set untouched (the engine-frozen files carry 0 diff) |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | no `color_policy.py` / `range_index.py` / `_ENGINE_PATHS` file in the diff; the batch-92 `render/` addresses consumed, not re-created |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | every threshold re-measured against the shipped formatter (`evidence/inc001-pilot-measurements.md`); the render-check probe's captures are the painted bytes |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | no absence claim; the hostile fixture names are the synthetic over-long instances |
| 11 | **Mutation verdicts** declared — per arm, inert arms named | all | ✓ | none — no in-batch battery; declared (the defect verdicts live in increment 002's packet) |
| 12 | **Instrument RED-proof** declared | all | ✓ | the wrap probe shown RED on this tree's 3 defects before any fixed-tree PASS was believed; the render-check probe's eyeball-diff reliance declared |
| 13 | **Correction population** declared | all | ✓ | 3 corrections, each enumerated from its authority before the first edit |
| 14 | **Emitted-form assertion** declared | all | ✓ | the golden's emitted bytes + the agreeing derivation; the regenerated baselines re-run green; the painted screen captured |
| 15 | **Independent review** names somebody | all | ✓ | `human:coordinator`, §4b |
| 16 | **Evidence files** declared — digests of the STORED bytes | all | ✓ | 6 artifacts below, each re-hashable at its path |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| the coordinator's brief (verbatim) | `.dev-flow/2026-10-11-batch-93/evidence/inc001-brief.md` | `c1d1c03ba97d16eb16b90a10c27ff2a1a2bf01d1c9da2566de0f88b8156233fa` |
| the pilot measurements (C-29) | `.dev-flow/2026-10-11-batch-93/evidence/inc001-pilot-measurements.md` | `5e972866e2d768113796105bdfe8ecab441f0824c55a4c18c5e14a372f497d90` |
| the cockpit-facts render probe | `.dev-flow/2026-10-11-batch-93/evidence/inc001_render_check.py` | `02c971c373812b07753580a06f6e10029eca82da3e868cafb4d8d639c3127e00` |
| the 120×36 rendered capture | `.dev-flow/2026-10-11-batch-93/evidence/inc001-map-120x36.svg` | `e81f3a8cb8d62e298dcbc349ae1abe38743078b164a4241a2b40fb518b26b9a1` |
| the 160×48 rendered capture | `.dev-flow/2026-10-11-batch-93/evidence/inc001-map-160x48.svg` | `3dd06d28e2f5821e72c46ab0035afd804bfcd815c2748a736ddda4842526b3ec` |
| the increment's per-area run (302 passed / 27 failed — the tc016s CI-font census named in §4) | `.dev-flow/2026-10-11-batch-93/evidence/inc001-perarea-run.txt` | `9842852140df9be09fcbb48f5ae018f041d555acacd6ce25515def74387bf6cd` |

| Field | Value |
|---|---|
| **Evidence files** | 6 artifacts, each at the batch's declared evidence home and cited with the digest of its stored bytes (the inc-002 audit transcripts that carry this increment's RED evidence are digested in increment 002's packet) |
