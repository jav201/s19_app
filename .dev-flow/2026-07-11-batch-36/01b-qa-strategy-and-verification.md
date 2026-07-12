# 01b — QA Strategy & Verification Plan · batch-36 (US-058 / US-059 / US-060)

> Phase 1 QA artifact. Binds to the §2.6 story intake in `01-requirements.md` (US-058/059/060).
> Written in PARALLEL with the architect's HLR/LLR/AT derivation (which EXTENDS `01-requirements.md`);
> this file does not edit that file. AT ids here are referenced by story (AT-058x / AT-059x / AT-060x);
> the architect assigns the exact numbers — reconcile at the Phase-1 gate.
> Author: qa-reviewer. Status: strategy locked for Phase-2 review; TC/AT bodies are Phase-3 work.
> Style baseline: `.dev-flow/2026-07-10-batch-35/01b-qa-strategy-and-verification.md`.

---

## 0. Scope recap (one sentence each)

1. **US-058 (B-22)** — the Patch Editor's paste box (`TextArea#patch_paste_text`) renders enough
   lines to read/edit a multi-line change-set, and the change-file pane's control groups (file ·
   patch-script · checks · paste) sit in distinct, non-clipped, non-overlapping regions at **80
   AND 120 cols**. Compose + CSS only — zero behaviour/wiring change (same constraint as US-057).
2. **US-059 (B-24)** — a **Hex** section appears in BOTH legend surfaces (the `LegendScreen` modal
   and the report legend), documenting each hex-cell colour → meaning, sourced from the shipped
   hex-render styles; the anti-drift `LEGEND_TABLE`/coupling unit tests are extended to cover it.
3. **US-060 (B-23)** — `tmp/stress_smoke/` (3 tracked files) is relocated under `examples/` as a
   discoverable case; the 54M `professional_validation/case_06_large_nested_a2l` slow duplicate is
   pruned while the 37M top-level `case_06_large_nested_a2l` real-vendor large-A2L is retained; the
   example smoke + pilot-gif suites stay green with **no functional-coverage regression**.

Recon grounding (file:line): patch compose `screens_directionb.py:1908-1922` (`patch_paste_row` /
`patch_paste_text` / `patch_pane_changefile`); patch geometry oracle `tests/test_tui_patch_layout.py:79-169`;
patch snapshot cells `tests/test_tui_snapshot.py:504,519` (`_TWO_SIZE_SCAFFOLDS=("patch","map")`,
comfortable-only); legend table `legend.py:33-109`; modal consumer `screens.py:527-539` (tolerant
`COLOUR_SEVERITY.get`); report consumer `report_service.py:1318-1323`; anti-drift `tests/test_tui_legend.py:58-85`;
hex styles `color_policy.py:13-14` used at `hexview.py:397-433`; example discovery
`tests/test_examples_smoke.py:44-70` + `tests/test_examples_pilot_gifs.py:49-62`; sizes measured
`examples/case_06=37M`, `examples/professional_validation/case_06=54M`, `tmp/stress_smoke=9K`, `examples/=96M`.

---

## 1. Validation method per story

Layer A = white-box TCs on the mechanism (constants, compose tree, region math, `_legend_lines`).
Layer B = black-box ATs through the SHIPPED surface: Textual Pilot (`App.run_test()`) driving the
REAL screen/handler, then re-reading what the shipped surface produced (rendered Label text, region
geometry, or the report file on disk — C-12). **No AT is a perceptual demo.** SVG snapshots are
executable pixel-diff `test`s (they lock layout after canonical-CI regen), not acceptance-by-eye.

| Story | Requirement area | Method | Layer A TC(s) (↔ LLR) | Layer B AT(s) — SHIPPED surface (↔ US) | Counterfactual (RED pre-change) |
|---|---|---|---|---|---|
| US-058 | Paste box readability | **test** | TC-058-1 compose+CSS: `#patch_paste_text` declares the taller sizing; the four control-group containers (`#patch_doc_file_row`/`#patch_doc_controls`/`#patch_checks_controls`/`#patch_paste_row`) exist with the expected parentage | **AT-058a** (Pilot, 80 **and** 120): open Patch Editor → assert `query_one("#patch_paste_text").region.height >= N` AND the control-group rectangles are pairwise non-overlapping AND none clips past the panel right (C-13 budget) | today the paste box renders ≤2 rows → `region.height >= N` (N≈6) fails; and/or a group overlaps at 80-col floor |
| US-058 | Layout pixel-lock | **test** (snapshot) | — | `patch-comfortable-80x24` + `patch-comfortable-120x30` cells (§4) | current baselines encode the cramped layout → both cells drift RED until canonical-CI regen |
| US-059 | Hex legend in modal | **test** | — | **AT-059a** (Pilot): open `LegendScreen` via the real `k` key → assert a **Hex** artifact header Label present AND each hex row's exact meaning string appears in `_modal_meanings(screen)` | no Hex block in `LEGEND_TABLE` today → the Hex header + meanings are absent |
| US-059 | Hex legend in report | **test** | TC-059-2: `_legend_lines()` output contains `### Hex` + each hex row `- **…** — …` line | **AT-059b** (Pilot, C-12 output-then-consume): generate a project report through the shipped report path → re-read the written `reports/*.md` → assert the `### Hex` section + each hex meaning present in the FILE | report generated today has no Hex section in its `## Legend` |
| US-059 | Anti-drift coupling | **test** | TC-059-1: (a) structure test updated to `set(LEGEND_TABLE)=={"A2L","MAC","Issues","Hex"}`; (b) NEW hex coupling — each Hex row's colour maps to the live `FOCUS_HIGHLIGHT_STYLE`/`MAC_ADDRESS_OVERLAY_STYLE` (imported from the frozen `color_policy`, read-only); (c) TC-S1 severity-orphan check scoped to exempt the non-severity Hex overlay colours | — (unit-only; no user surface of its own) | change a hex style constant without updating the legend → coupling fails; add Hex with a colour that silently diverges from `color_policy` → fails |
| US-060 | Relocation + prune (on-disk) | **inspection + test** | — | **AT-060a** (on-disk + discovery): assert `tmp/stress_smoke/` absent; the relocated case dir present under `examples/` and picked up by `_discover_cases`; `examples/professional_validation/case_06_large_nested_a2l` absent; `examples/case_06_large_nested_a2l` (real-vendor large-A2L) **retained**; `examples/` byte-size materially reduced vs the pinned before-value | today `tmp/stress_smoke/` exists, the pv__ case exists, and the relocated case is not discovered |
| US-060 | No coverage regression | **test** | — | **AT-060b**: the retained top-level `case_06_large_nested_a2l` still passes `test_case_loads_through_service_layer` (enrich+validate over a large nested A2L) and the relocated case passes the same smoke param | contingent on I-060-1 (§5) — if the pruned copy exercised a distinct parser branch, coverage would drop |
| US-060 | Duplication equivalence (gate) | **inspection** | — | I-060-1 (§5): structural diff of the two `case_06` A2Ls proving the 54M copy is a scale duplicate, not a distinct-construct fixture | — (analysis gate that AUTHORIZES the delete) |

**Analysis-only items:** I-060-1 is the sole non-executable gate; it is a *precondition* to the
delete, recorded with its evidence before implementation. Everything else lands as an executable
`test` or a pinned snapshot. Phase-4 operator demo replays AT-058a + AT-059a manually (script from
the ATs) — demo is illustration, never the acceptance verdict.

---

## 2. C-10 / C-12 / C-18 discipline (shift-left — owned here)

### 2.1 C-10 — a passing AT must be IMPOSSIBLE where the behaviour is absent/defaulted
- **AT-058a asserts CONTENT, not non-empty.** The pass condition is a CONCRETE height threshold
  `region.height >= N` where N is set in Phase 1 STRICTLY GREATER than today's rendered paste
  height (measured pre-change, pasted into the ledger). "Paste box exists / is visible" is BANNED —
  it passes today. The non-overlap assertion uses the rectangle-intersection idiom already in
  `tests/test_tui_patch_layout.py:161-169` (zero intersecting pairs), asserted at BOTH widths.
- **AT-059a/b assert the ACTUAL row text.** The pass condition is the exact hex-row meaning
  string(s) present in the rendered modal Labels / the written report file — not "a Hex header
  exists" and not "the legend is non-empty". Mirror the existing `LEGEND_TABLE["MAC"]["Orange"][1]
  in meanings` idiom (`tests/test_tui_legend.py:181`) with the new Hex meaning(s).
- **AT-060a asserts the retained fixture BY NAME and the deleted paths ABSENT**, plus a numeric
  size reduction against a pinned before-value — not "examples is smaller" by feel. `_discover_cases`
  actually returning the relocated case id is the discriminator (a bare file-move that the loader
  can't pick up — e.g. no `*.s19` primary — would fail here).

### 2.2 C-12 — output-then-consume for the report leg (AT-059b)
The report AT does NOT call `_legend_lines()` and assert on its return (that is the Layer-A TC-059-2).
It drives the SHIPPED report-generation surface (the report dialog/worker that the operator triggers),
lets the handler WRITE the `reports/*.md`, RE-READS that file from disk, and asserts the `### Hex`
section is present in the bytes that were actually written. Idiom home: the report-seam reread
pattern (`tests/test_tui_report_seam.py`, and the byte-content reread in `tests/test_report_service.py`
`test_full_report_content`). This kills the failure mode where the renderer is right but the
generation path never emits the legend section into the file.

### 2.3 C-18 — every AT is EXACTLY ONE on-disk node driving the whole named chain
| AT | Single on-disk node (target file) | Whole-chain-in-one-node? |
|---|---|---|
| AT-058a | `tests/test_tui_patch_layout.py` (new function) | ✓ one node opens the editor, resizes to 80 then 120, asserts height + non-overlap + no-clip in the same body |
| AT-059a | `tests/test_tui_legend.py` (new function) | ✓ opens modal via `k`, asserts Hex header + meanings |
| AT-059b | `tests/test_tui_report_seam.py` (new function) | ✓ generate → reread file → assert Hex section, end-to-end |
| AT-060a | `tests/test_examples_layout.py` (NEW file) or extend `test_examples_smoke.py` | ✓ one node asserts all on-disk + discovery facts; pick ONE home at Phase-3 |
| AT-060b | existing param `test_case_loads_through_service_layer[case_06_large_nested_a2l]` (retained) + the new relocated-case param | ✓ each is a single parametrized node |
| TC-059-1 | `tests/test_tui_legend.py` | ✓ |
**Flag:** no AT is realizable only "in parts". AT-060a is the one to watch — do NOT split the
"deleted / retained / discovered / size-reduced" facts across separate tests; they are one coherent
post-condition of the change and belong in one node so a partial migration can't half-pass.

---

## 3. Boundary and negative sets (concrete cases — cut only with written justification)

### 3.1 US-058 geometry (C-13 budget)
| # | Case | Expected | Home |
|---|---|---|---|
| L1 | 80x24 floor | paste height ≥ N; all four control groups within `host_content` (no clip past panel right); groups pairwise non-overlapping | AT-058a |
| L2 | 120x30 primary | same, at the wider regime | AT-058a |
| L3 | paste box vs patch-script controls seam | the taller paste box does NOT overlap/absorb `#patch_doc_controls` region | AT-058a (overlap idiom) |
| L4 | 2×2 pane invariant preserved | the four `#patch_pane_*` still form a genuine 2×2 grid (the existing `_assert_2x2` oracle stays green) — US-058 reshapes the change-file pane's INTERIOR, not the outer grid | existing `tests/test_tui_patch_layout.py` AT-033a/b (SURVIVES §6) |
| L5 | id + wiring survival | every id from `screens_directionb.py:1908-1922` survives; `on_button_pressed` untouched | TC-058-1 + existing patch-editor v2 census |

Boundary note: N (min paste rows) is the single tunable — Phase-1 fixes it from the change-set JSON
line count the operator must read (`DUMMY_CHANGESET_TEXT` is the shipped seed; N ≥ its line count is
the natural floor). Negative: at 80 cols the mechanism must NOT reintroduce the horizontal clip
US-057 already guards.

### 3.2 US-059 hex-legend content (sourced, not invented)
The hex view uses EXACTLY these cell styles (`hexview.py:412-433`): `FOCUS_HIGHLIGHT_STYLE="bold
yellow"` (focus/highlight byte range from goto/search) and `MAC_ADDRESS_OVERLAY_STYLE="bold orange3"`
(byte at a MAC record address), plus the default unstyled foreground (normal image byte). The Hex
legend rows MUST be exactly this set (architect enumerates + names them in Phase 1; QA pins that they
come from `color_policy.py:13-14`, not authored prose):
| # | Hex colour (display) | Meaning to document | Coupling source |
|---|---|---|---|
| H1 | Yellow | focused/highlighted byte range (goto/search target row) | `FOCUS_HIGHLIGHT_STYLE` |
| H2 | Orange | byte covered by a MAC record address (MAC overlay) | `MAC_ADDRESS_OVERLAY_STYLE` |
| H3 | White/default | normal image byte, no overlay | (no style — default fg) |
| H4 (optional) | `> ` row marker | focus-row indicator (glyph, not a colour) — document as a note or omit; Phase-1 call | `hexview.py:406` |
Negative/anti-drift: TC-059-1(b) imports the two style constants and asserts each documented Hex
colour maps to the live constant, so a future engine change to a hex style with no legend update
fails. Empty boundary: AT-059a re-uses the `test_at023f` pattern — the static legend shows the Hex
section even with NO file loaded (`tests/test_tui_legend.py:284-300`).

### 3.3 US-060 relocation + prune
| # | Case | Expected | Home |
|---|---|---|---|
| M1 | relocated case discoverability | new dir has a `*.s19`/`*.hex` primary so `_pick_primary` resolves (stress.s19 via fallback glob, `test_examples_smoke.py:79-84`); NOT named `professional_validation`; sorts as a `case_*` | AT-060a + AT-060b |
| M2 | `tmp/stress_smoke/` fully gone | dir absent AND `git ls-files tmp/stress_smoke` empty (it is git-tracked: 3 files) — a move must `git mv`, not leave orphans | AT-060a |
| M3 | real-vendor large-A2L retained | `examples/case_06_large_nested_a2l/` present with its `*.a2l` (D-1 bare minimum) | AT-060a |
| M4 | pv__ slow duplicate removed | `examples/professional_validation/case_06_large_nested_a2l/` absent | AT-060a |
| M5 | `SLOW_CASE_IDS` no longer references a ghost | after M4, `{"pv__case_06_large_nested_a2l"}` is dead → pruned to `set()` (or the entry removed) so the set stays honest | edit + asserted in AT-060a |
| M6 | size reduction | `examples/` reduced by ~54M (96M→~42M); assert `< pinned_before_bytes` with a comfortable margin | AT-060a |
| M7 | negative: snapshot guard still holds | `test_tui_snapshot.py:690-706` (forbids `professional_validation`/`case_06_` in snapshot SETUP code) still passes — the delete adds no such reference | existing guard (SURVIVES) |
| M8 | doc accuracy | `docs/architecture.md:152` (names `pv__case_06_large_nested_a2l` as the slow case) updated | Phase-6 docs edit (flagged) |

---

## 4. Snapshot-drift prediction — per-cell (C-22)

Snapshot matrix (`tests/test_tui_snapshot.py:115-116,504-521`): restyled screens
`["workspace","a2l","mac","issues"]` × {compact,comfortable} × 3 sizes; scaffold screens
`["map","patch","diff"]` at comfortable, with `patch`+`map` carrying BOTH 80x24 and 120x30.

| Cell | US | Drift? | Why (per-cell) | Disposition |
|---|---|---|---|---|
| `patch-comfortable-80x24` | US-058 | **YES** | the change-file pane's interior reflows — paste box gains height and the control groups re-lay at the tight floor; every pixel of that pane moves | `xfail(strict=False)` batch-36 comment → **canonical-CI regen only** post-merge |
| `patch-comfortable-120x30` | US-058 | **YES** | same interior reflow at the primary width | `xfail(strict=False)` → canonical-CI regen |
| `map-comfortable-{80x24,120x30}` | — | NO | map scaffold untouched | stay green — any drift here is a scope violation |
| `diff-comfortable-120x30` | — | NO | diff scaffold untouched | stay green |
| `{workspace,a2l,mac,issues}-{compact,comfortable}-{3 sizes}` (24) | — | NO | restyled screens don't touch the patch screen; US-059 legend is a MODAL (not in the matrix — `LegendScreen` is absent from `_RESTYLED_SCREENS`/`_SCAFFOLD_SCREENS`); US-060 uses `case_00_public`/synthetic generators only (`:704`), not the moved cases | stay green |

**Upper bound: exactly 2 cells drift, both `patch`, both `comfortable`.** US-059 and US-060 drift ZERO
snapshot cells. Regen rule (memory `reference_snapshot_regen_env`): the two patch baselines are
regenerated ONLY in canonical CI (`.github/workflows/snapshot-regen.yml`, pinned `textual==8.2.8`),
run at the merge commit, with containment verified in the run log (no other cell moved). **Local
regen is forbidden** — it drifts unrelated baselines. Precedent: batch-22/25/33/35 patch-cell xfail→regen
(`tests/test_tui_snapshot.py:456-521`).

---

## 5. US-060 coverage-preservation map

**Claim:** deleting the 54M `pv__case_06_large_nested_a2l` loses NO functional-requirement coverage,
because every code path it exercises is also exercised by the retained 37M top-level
`case_06_large_nested_a2l` (which runs in the DEFAULT suite, not `slow`).

**Gate I-060-1 (must complete before the delete is authorized):** structurally diff the two
`case_06` A2Ls (construct census — record layout depth, section kinds, symbol/record counts).
Expected finding: the pv__ copy is a *scale* duplicate (larger, same construct shapes). If instead
it contains a construct the top-level case lacks (a distinct parser/validator branch), the delete is
BLOCKED until that branch is covered elsewhere. This is the crux the requirements §2.6 open question
flags ("are the two copies genuinely duplicative") — QA treats it as a hard precondition, not an
assumption.

| Test node (before) | Behaviour it exercises | After the change | Coverage verdict |
|---|---|---|---|
| `test_examples_smoke::case_06_large_nested_a2l` (37M, default) | load large image → `enrich_tags_and_render` → `build_validation_report` over a large nested A2L | UNCHANGED, retained + still default-run | **HELD** — large-A2L enrich+validate stays covered by default CI |
| `test_examples_smoke::pv__case_06_large_nested_a2l` (54M, `slow`) | same pipeline at larger scale (~490s) | REMOVED | **NO functional loss** (contingent on I-060-1): identical code path to the retained case; the perf/scale dimension is separately covered by the `large_s19/a2l/mac` conftest generators (`tests/conftest.py:308-335`) + `slow`-marked stress tests, and is `-m "not slow"`-excluded from default CI anyway |
| `test_examples_smoke::<relocated stress case>` | load + enrich + validate the relocated triple | ADDED | **NET NEW** coverage (previously `tmp/stress_smoke/` had 0 code references — untested) |
| `test_examples_pilot_gifs::pv__case_06_large_nested_a2l` (`slow`) | Pilot-drives the TUI over the large case, emits SVG+GIF evidence | REMOVED | GIF/Pilot evidence for a large case retained via the top-level `case_06` gif param |
| `test_examples_pilot_gifs::<relocated stress case>` | Pilot evidence for the relocated case | ADDED | net new |
| `SLOW_CASE_IDS` (`test_examples_smoke.py:44`) | attaches `slow` mark during discovery | `{pv__case_06_large_nested_a2l}` → pruned (M5) | dead reference removed; no behaviour change |
| `test_tui_snapshot.py:690-706` negative guard | snapshot setup references no non-public example path | UNCHANGED | **HELD** (delete adds no reference) |
| `docs/architecture.md:152` | documents the slow case | update (M8) | doc accuracy, not test coverage |

**Net test-node delta:** smoke = −1 (pv__case_06) +1 (relocated) = **0**; gif = −1 +1 = **0**. The
swap is coverage-neutral-plus (adds the previously-untested stress triple). Any node count change
beyond this offsetting pair is unexpected and must be explained in the Phase-3 ledger.

**C-14 location-move census (observers of the moved/deleted paths, swept):**
`test_examples_smoke.py` (discovery + `SLOW_CASE_IDS`) — EDIT; `test_examples_pilot_gifs.py`
(discovery) — AUTO-ADJUSTS, no hard path; `test_tui_snapshot.py:690` (negative guard) — SURVIVES;
`docs/architecture.md:152` — DOC EDIT; `examples/case_00_public/MANIFEST.md:21` (names the RETAINED
top-level `case_06`) — SURVIVES; `tests/conftest.py`/`test_tui_app.py` `stress.*` — UNRELATED
(these are `make_large_*` generators writing to `tmp_path`, a name-only collision with the repo's
`tmp/stress_smoke/stress.*`). No other observer references the moved/deleted paths.

---

## 6. Supersession census (change-first) — pins this batch moves

| # | Pin (file:line) | What it pins | Disposition |
|---|---|---|---|
| 1 | `tests/test_tui_legend.py:78` (`test_legend_table_has_documented_artifacts_and_rows`) | `set(LEGEND_TABLE)=={"A2L","MAC","Issues"}` + per-artifact row sets | **SUPERSEDE** — add `"Hex"` to the artifact set and pin the Hex row set; record the change in the test docstring |
| 2 | `tests/test_tui_legend.py:58-72` (`test_legend_table_covers_all_severities`, TC-S1) | every severity reachable via a legend colour AND no orphan colour (`used_colours <= COLOUR_SEVERITY \| {"White"}`) | **SUPERSEDE** — Hex overlay colours (Yellow, Orange3) are NOT severities; scope the orphan check to the severity-driven artifacts (A2L/MAC/Issues) and add a SEPARATE hex-colour coupling (TC-059-1b) against `FOCUS_HIGHLIGHT_STYLE`/`MAC_ADDRESS_OVERLAY_STYLE`. Do NOT silently loosen the existing severity guard for A2L/MAC/Issues |
| 3 | `tests/test_tui_legend.py:303-323` (`test_tc023_1`, modal renders all rows) | `headers == list(LEGEND_TABLE)` + `len(meanings)==_TOTAL_ROWS` | **SURVIVES** (both read `LEGEND_TABLE` dynamically; `_TOTAL_ROWS` is a live sum) — but rerun as a regression; the Hex header must appear in `headers` in table order |
| 4 | `tests/test_tui_legend.py:353-376` (`test_tc_s2`, report↔modal same rows) | report + modal render the SAME meaning set | **SURVIVES** (dynamic) — extends automatically to Hex; explicit regression rerun |
| 5 | `tests/test_report_service.py:728-761` (legend rows in report) | every `LEGEND_TABLE` row appears in `_legend_lines`/report | **SURVIVES** (dynamic) — Hex rows auto-covered; rerun |
| 6 | `tests/test_tui_snapshot.py:504` two patch cells (80x24 + 120x30) | patch scaffold pixels | **DRIFT → xfail(strict=False)** until canonical-CI regen (§4) |
| 7 | `tests/test_tui_patch_layout.py:79-215` (AT-033a/b + grid-size-3 + no-clip) | the outer 2×2 pane grid + `#patch_doc_controls` grid geometry | **SURVIVES** — US-058 reshapes the change-file pane INTERIOR, not the outer grid; explicit regression rerun at 80/120. If the chosen mechanism perturbs `#patch_doc_controls` grid-size, EXTEND with a docstring note |
| 8 | `tests/test_tui_patch_editor_v2.py:67` region (id census incl. `patch_paste_text`, `patch_checks_run_button`) | widget-id survival | **SURVIVES** (compose-only) — rerun; add the geometry AT-058a alongside |
| 9 | `tests/test_examples_smoke.py:44` `SLOW_CASE_IDS` | attaches `slow` to pv__case_06 | **SUPERSEDE** — prune the dead entry after M4 (§5 M5) |
| 10 | `tests/test_examples_smoke.py:47-70` + `test_examples_pilot_gifs.py:49-62` discovery loops | dynamic examples enumeration | **SURVIVE** — auto-adjust to the case swap; rerun both full sets in the census check |
| 11 | `tests/test_tui_snapshot.py:690-706` snapshot-setup path guard | no non-public example path in snapshot setup | **SURVIVES** — delete adds no reference; rerun |
| 12 | `examples/case_00_public/MANIFEST.md:21` | names the RETAINED top-level `case_06` | **SURVIVES** |
| 13 | `docs/architecture.md:152` | names pv__case_06 as the slow case | **UPDATE** (Phase-6 docs) |

No engine-frozen module is edited: `legend.py` and `screens.py`/`report_service.py` are non-frozen;
`color_policy.py` is imported READ-ONLY by TC-059-1 (the frozen-diff guard `test_tui_legend.py:104-123`
stays green). US-058 touches compose (`screens_directionb.py`) + CSS (`styles.tcss`) only. US-060
touches no engine module.

---

## 7. Test-count ledger base

```
python -m pytest --collect-only -q   →   1362 tests collected in 1.68s
```
(tree: worktree `heuristic-wu-1c7c49` @ 7df60dd base, branch `claude/ui-layout-backlog-review-f9a343`, 2026-07-11.)
Phase-3 ledger tracks: base 1362 → +N new (each named: AT-058a, AT-059a, AT-059b, TC-058-1, TC-059-1,
TC-059-2, AT-060a, [+ relocated-case params auto-add ~2, pv__case_06 params auto-drop ~2 → net ~0])
→ −0 deleted by hand (supersessions #1/#2/#9 are in-place edits with docstring notes). Any hand
deletion needs a census row above authorizing it.

---

## 8. Exit criteria for the batch's QA gate

- Every AT in §1/§2.3 exists at its single on-disk node (§2.3 table); live-RED ones have recorded
  pre-impl failure output (inline paste at the gate).
- AT-058a passes GREEN at 80 AND 120 with the measured N pinned; the two patch snapshot cells are
  `xfail(strict=False)` (not silently deleted) pending canonical-CI regen.
- US-059: AT-059a (modal) + AT-059b (report file reread) green; TC-059-1 supersessions #1/#2 applied
  with the hex↔constant coupling in place; the frozen-diff guard green.
- US-060: I-060-1 duplication-equivalence completed and its evidence recorded BEFORE the delete;
  AT-060a on-disk facts green; `examples/` size reduction asserted against the pinned before-value;
  full example smoke + pilot-gif suites green; `SLOW_CASE_IDS` pruned; `docs/architecture.md` updated.
- Full suite green except exactly the two §4 xfail patch snapshot cells. Any other drift = scope
  violation, not a regen candidate.
- No engine-frozen module diffs (`tests/test_engine_unchanged.py`, `test_tui_directionb.py` guards green).
- Census rows 1, 2, 6, 7, 9, 10, 13 dispositions executed and noted in-test.

## 9. Highest-risk QA gaps (Phase-2 watch-list)

1. **US-060 duplication equivalence (I-060-1) is a real, un-discharged assumption.** The whole
   coverage-preservation claim rests on the 54M pv__ A2L being a scale duplicate of the retained 37M
   one. This is NOT yet verified — it is the requirements' own open question. If the copies diverge
   in construct kinds, deleting the pv__ copy silently drops a parser/validator branch that no
   golden catches. **Mitigation:** I-060-1 is a hard gate before the delete; block on it.
2. **US-059 anti-drift scope creep.** Loosening TC-S1's orphan check to admit the Hex colours must
   NOT also loosen the severity guard for A2L/MAC/Issues (that guard is the reason a new engine
   severity can't ship without a legend colour). The supersession must SPLIT the check
   (severity-artifacts keep the strict guard; Hex gets its own constant-coupling), not blanket-widen
   it. Also: the architect must expose a `hex-colour-name → style-constant` mapping in `legend.py`
   so the coupling is exact, not a fragile substring match on `"yellow"`/`"orange3"`.
3. **US-058 N is under-specified and 80-col-budget-bound.** The minimum readable-lines N and the
   chosen mechanism (3-col reflow vs taller dedicated paste pane) are Phase-1 design; at the 80-col
   floor the C-13 geometry budget is tight (batch-22 measured host ~70 cols). Risk: a mechanism that
   satisfies 120 but clips or overlaps at 80. AT-058a MUST assert at BOTH widths (not 120-only), and
   N must be pinned from the shipped `DUMMY_CHANGESET_TEXT` line count, not guessed.

---

## Testability verdict (per story, as specced)

- **US-058 — TESTABLE.** Outcome is observable through the shipped surface (Pilot region geometry
  at both widths + snapshot pixel-lock). Only open variable is N (min paste rows), legitimately a
  Phase-1 measurement. No blocker.
- **US-059 — TESTABLE.** Both surfaces iterate `LEGEND_TABLE` and tolerate new colours
  (`screens.py:530` `.get()`; `report_service.py:1321` no lookup), so a single `legend.py` edit
  auto-propagates; modal + report-reread ATs are black-box. Caveat (§9.2): the anti-drift
  supersession needs the exposed colour→constant mapping to be exact — flagged, not blocking.
- **US-060 — TESTABLE, WITH A GATE.** On-disk relocation/prune/size and discovery are all
  executably assertable; coverage preservation is provable ONLY after I-060-1 discharges the
  duplication assumption. Testable as specced; the delete is gated on that inspection.

---

## Evidence checklist (qa-reviewer, Phase 1)

- [x] Every story has a black-box AT through the SHIPPED surface — US-058 AT-058a (Pilot region geom); US-059 AT-059a (modal) + AT-059b (report file reread); US-060 AT-060a (on-disk + `_discover_cases`). §1 table.
- [x] Every AT has a stated counterfactual (RED pre-change) — §1 rightmost column + §2.3.
- [x] C-10 satisfied — AT-058a asserts a height THRESHOLD > today's + non-overlap (not "visible"); AT-059a/b assert EXACT hex-row text (not "non-empty"); AT-060a asserts named retained fixture + absent paths + numeric size drop. §2.1.
- [x] C-12 satisfied — AT-059b drives the report generator, rereads the written `reports/*.md`, asserts on the FILE bytes; the `_legend_lines()` unit check is a separate Layer-A TC. §2.2.
- [x] C-18 satisfied — each AT is one on-disk node driving the whole chain; AT-060a explicitly must NOT split its facts. §2.3.
- [x] Snapshot cells named + canonical-CI-regen noted — exactly `patch-comfortable-80x24` + `patch-comfortable-120x30` drift; regen ONLY in canonical CI (`reference_snapshot_regen_env`); US-059/US-060 drift zero cells. §4.
- [x] US-060 coverage map complete — every affected node → behaviour → verdict, net delta 0, C-14 sweep done, gated on I-060-1. §5.
- [x] Edge cases include empty/boundary/invalid/error — §3.1 (80-col floor, seam overlap), §3.2 (no-file-loaded boundary, anti-drift orphan colour), §3.3 (git-tracked orphan, ghost SLOW_CASE_IDS, size margin).
- [x] Regression checklist exists — §6 census (13 rows, file:line).
- [x] Exit criteria stated — §8.
- [x] No real PII / secrets — synthetic/public fixtures only; the retained real-vendor A2L is an existing repo fixture, unchanged.
- [x] Test-results sections left BLANK — no execution claimed; only `--collect-only` (1362) + `du`/`git ls-files` recon were run, outputs quoted (§7, §0).
- [x] No unfilled template — no `<...>` placeholders; N and the exact Hex row set are explicitly deferred to Phase-1 measurement/enumeration with their sources cited (not left as blanks).
