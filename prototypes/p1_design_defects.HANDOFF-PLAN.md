# HANDOFF PLAN — P1 design-defect implementation (prototyped 2026-07-30)

> **For the executing session.** This is the scope + technical map for implementing the
> four operator-flagged design defects of 2026-07-28 (`.dev-flow/BACKLOG-CODE.md`
> §"Operator-flagged 2026-07-28"). The `/tui-design` PROTOTYPE pass those bullets demanded
> is DONE — variants + captured frames live beside this file (see
> `p1_design_defects.NOTES.md` for the brief, state inventory and variant rationale).
> **Ask the operator for the run/approval model at kickoff** — autonomy is per-batch,
> never carried (`feedback_standing_auth_per_batch`). Artifact language: English.

## 1. What exists now (inputs to the batch)

| Artifact | Content |
|---|---|
| `p1_design_defects.NOTES.md` | brief · state inventory · variant rationale · **§7 verdict table the operator must fill** |
| `crc_designer.p1.inapp_prototype.py` | 3 runnable CRC variants (A guard-rails · B paired-reflection+demoted-KAT · C vocabulary+strip), sub-shape A — every shipped `#crc_*` id live |
| `legend_p1.inapp_prototype.py` | 3 runnable Legend variants (A tabbed · B two-pane · C key-first outline), reusing `_render_card`/`_render_key` verbatim |
| `crc_p1.variant_*.svg` (18) | complete frames: 120x30 empty/loaded/**bench**/invalid + 80x24 loaded/bench per variant |
| `legend_p1.variant_*.svg` (9) | complete frames: workspace+mac @120x30, mac @80x24 per variant |

Run commands are in NOTES §6 (needs `PYTHONPATH=.` unless `pip install -e .` was run;
render pin textual 8.2.8 / rich 15.0.0 — same as CI).

**A finding the shots surfaced, free of charge:** at 120x30 the shipped CRC screen shows
ONLY the hero row — every control lives below the fold, and each 3-tall `Select` (with its
overlay wrap at the 1fr column width) costs ~5-6 rows of that fold. Any variant pick
should also weigh flattening Select chrome (`#crc_designer_panel Select` CSS) as part of
the affordance-density fix.

## 2. Decision gates — OPERATOR, at kickoff (blockers, in order)

**Gate 1 — CRC variant** (hybrids welcome; steal across variants):

| Option | Expected result | Consequences |
|---|---|---|
| **A** Guard rails | minimal diff: switch rows get track+word+gap | ✅ smallest snapshot drift ⚠ KAT stays as hero — operator already rejected that; A alone does NOT close the KAT bullet |
| **B** Paired reflection + demoted KAT (recommended) | 1 `Reflection in/out` row; `Self-test` annotation under Check; Warnings own the hero right column | ✅ closes switch bullet structurally ✅ closes KAT bullet as *demote* ✅ keeps `#crc_kat_verdict` queryable (AT surgery minimal) ⚠ moderate snapshot drift |
| **C** Vocabulary + strip | reflection = 1 Select (`none/in/out/both`); KAT gone; warnings strip | ✅ fewest controls ⚠ KAT *removal* = `_recompute` edit + AT-058-08 retirement + requirement amendment ⚠ a Select is 3-tall where 2 switches were 2×1 ❓ "both/none" vocabulary is non-standard for CRC catalogs |

**Gate 2 — KAT field**: ☐ demote (as B) ☐ remove (as C). The measured nuance (backlog
154): `kat_ok` validates the *algorithm definition* against the published `123456789`
check — the standard self-test — not the operator's data. Removal also loses the
save-time mismatch warning's live counterpart. **Recommended: demote.**

**Gate 3 — Legend variant**:

| Option | Expected result | Consequences |
|---|---|---|
| **A** Tabbed | card sections as shallow pages + `Key` tab | ✅ nothing scrolls past a screen ⚠ the key hides behind a tab — the reference answer is 1 click away |
| **B** Two-pane (recommended @120) | key ALWAYS visible beside the card | ✅ directly fixes "the legend is below the fold" ⚠ needs width 96% dialog; stacks at 80x24 |
| **C** Key-first outline | key pinned top, examples as Collapsibles | ✅ best at 80x24 ✅ inverts hierarchy correctly ⚠ Collapsible adds per-section chrome |

A defensible hybrid: **B at wide, C's ordering (key first) when stacked at the floor.**

**Gate 4 — batch slicing + flow tier**: recommended **two batches** —
CRC = full `/dev-flow` (AT surgery + snapshot drift + possible requirement amendment);
Legend = `/fast-dev-flow` (modal is NOT snapshot-captured — verified at N8/batch-125 —
so zero baseline drift). Legend can go first: it is the cheapest surface in the app.

## 3. CRC batch — technical map

- **Files**: `s19_app/tui/crc_designer_view.py` (compose + possibly `_recompute`),
  `s19_app/tui/styles.tcss` (`.crc-field-switch` block ~:1952, bench rules ~:1980-2080).
  Neither is engine-frozen. Do NOT touch `tui/color_policy.py` (frozen).
- **`_recompute` contract** (crc_designer_view.py:1115-1142): queries SIX surface ids and
  the algorithm reader queries both switches — deleting any id breaks every live surface.
  Demote keeps `#crc_kat_verdict` mounted (annotation row); removal must edit
  `_recompute` + `_verdict_text` and retire their tests.
- **Test blast radius — grep before editing** (C-26 reverse census): AT-058-08 and the
  batch-58/59 preview-gating tests pin `#crc_kat_verdict`; AT-B59-03/08 pin the bench
  signature (`len(distinct bench-column ancestors) == 3` — all three variants preserve 3
  columns, but B/C change `#crc_top_right` children; read the AT bodies, don't assume);
  `tests/` grep targets: `crc_kat_verdict`, `crc_field_refin`, `crc_field_refout`,
  `crc_top_right`, `crc_live_verify`, `crc_hero_row`.
- **Snapshots**: CRC cells WILL drift → C-22/C-28 census up front, regen ONLY in
  canonical CI (`snapshot-regen.yml`, textual==8.2.8) as a follow-up PR
  (`reference_snapshot_regen_env`).
- **Requirements**: batch-59's HLR-L*/R-TUI rows describe the bench layout; KAT
  demote/remove amends the LLR-V2.1 verdict row — §6.5 Before/After record
  (`feedback_requirement_amendment_before_after`).

## 4. Legend batch — technical map

- **Files**: `s19_app/tui/screens.py::LegendScreen` (compose + `_render_card`/
  `_render_key` stay; only layout composition changes), `styles.tcss` legend block
  (~:1539-1568). `legend.py` (data) should not need edits — all three variants reuse it
  untouched; grouping is derived from `ROLE_SUB` boundaries (see `_card_sections` in the
  prototype).
- **Preserve**: ids `#legend_dialog` / `#legend_body`-equivalent / `#legend_close` /
  `#legend_mac_warning_sample`; the map band-key branch (`markup=False` rows, `band-*`
  never `sev-*`); S-01 (key rows markup-enabled, bracket-free) and TC-N8-11 escaping.
- **Test blast radius**: `tests/test_tui_legend.py` (TC-322, S-01, sections filtering),
  `tests/test_legend_n8.py` (card content/roles, warning sample, band key). Layout
  reorganization should keep these green if the data pipeline is untouched; any test
  pinning widget NESTING (grep `legend_body`) will need its locator updated.
- **New widgets**: `TabbedContent`/`TabPane` (variant A) or `Collapsible` (C) — stdlib
  textual, no new dependency. NOTE: `TabbedContent(*panes)` treats positionals as
  titles — use the `with TabbedContent(): with TabPane(...):` compose style (the
  prototype hit this).
- **No snapshot drift** (modal not `tc016s`-captured) — but add the missing coverage the
  backlog implies: ≥1 snapshot or render AT of the reorganized modal per view family.

## 5. Design guards → encode as ATs (the operator's "guardas de diseño")

| Guard | AT encoding (black-box, pilot-driven) |
|---|---|
| **G-1 separability** | for each vertically-adjacent pair of focusable controls in the CRC form: assert their `region`s do not abut without a ≥1-row gap, border, or interleaved label between them (pilot-measure regions; the old defect — two `height:1 border:none` switches abutting — must FAIL this) |
| **G-2 state legibility** | toggle `#crc_field_refin` via pilot: assert a rendered WORD/glyph changes somewhere on screen (not only the Switch's internal value) |
| **G-3 hero extent** | the coverage window's rendered extent ≥ 6x any other single bright element on the CRC screen (6:1 law); exactly one majority-bright tile |
| **G-4 key reachability** (Legend) | the colour key is reachable within ≤1 interaction from modal-open at 120x30 AND 80x24 (variant B: 0 — on screen; A: 1 tab; C: 0) |

The counterfactual rule applies (`feedback_counterfactual_must_fail_on_its_assertion`):
prove G-1 red on a copy with the old CSS before trusting it. Consider proposing G-1/G-2
as a general control (C-46 candidate) at the batch postmortem — the skill-side "why
`/tui-design` didn't catch this" item already lives in `BACKLOG-PROCESS.md` (routed
there; don't duplicate).

## 6. Regression / process rails

- `pytest -q` green at every increment; C-27 dual-guard: 0 frozen-file diffs.
- Backlog reconciliation at close (`feedback_backlog_carryover_enforced`): mark the four
  2026-07-28 bullets (CRC switch / KAT / design pass / Legend) with their outcome; the
  P2 KAT bullet resolves via Gate 2's record.
- Prototype teardown when both batches merge: DELETE `crc_designer.p1.*`,
  `legend_p1.*`, `p1_design_defects.*`, `crc_p1.variant_*.svg`, `legend_p1.variant_*.svg`
  (absorb-then-delete convention, `screen_upgrades` precedent).
- Security (C-16/C-17): no new untrusted surface in either batch; every existing
  `markup=False` sink stays `markup=False`; the Legend card lines stay markup-ENABLED by
  design (S-01 escaping already guards them) — do not "fix" that asymmetry in passing.

## 7. Kickoff checklist for the executing session

1. RC-1: fetch; confirm base = `origin/main` tip; verify flow currency vs
   `~/.claude/docs/FLOW-VERSION.md`.
2. Ask operator: Gates 1-4 above + approval model. Show the SVGs inline at the gate
   (`feedback_inline_paste_at_gates`) — the frames are the argument.
3. Read: this file · `p1_design_defects.NOTES.md` · backlog bullets 153-156 ·
   `docs/engineering-rules.md` · memories `project_crc_algorithm_designer`,
   `reference_snapshot_regen_env`, `reference_textual_internal_name_shadowing` (no
   `_nodes`/`_context` widget members).
4. Premise re-check (C-43): re-verify on disk that `styles.tcss:1952` and
   `crc_designer_view.py:301-302` still match the mechanism described here — a parallel
   batch may have moved lines.
