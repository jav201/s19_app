# Phase 2 — Cross-agent review (consolidated) — batch-58

> Three independent reviews (separate files, per decision D2): `02-review-architect.md`, `02-review-qa.md`, `02-review-security.md`. This file consolidates the verdict + the fold list.

## BLUF
**ITERATE-TO-REFINE (Phase 1).** 3 blockers, all **AT-authoring vacuity** (Certainty-axis gap — three acceptance tests can pass while the feature is broken). The requirements themselves are correctly derived (architect: 0 blocker; security: 0 blocker). qa: "all fixes are wording/coverage, not redesign." Fold the list below into `01-requirements.md`, then re-gate.

## Per-reviewer verdict
| Reviewer | Verdict | Blocker | Major | Minor |
|---|---|---|---|---|
| architect | PASS | 0 | 0 | 2 |
| qa-reviewer | CHANGES REQUESTED | **3** | 5 | 5 |
| security-reviewer | OK w/ mitigations | 0 | 1 | 2 |

## Blockers (force iterate-to-refine)
- **B1 — AT-058-04 (JSON preview round-trip), C-12 bypass.** As specced it is satisfiable by headless `parse_template(emit_template(t))`, passing with an empty/stale preview pane. FIX: the AT must read the **mounted preview widget's rendered text** via Textual Pilot and parse THAT back to an equal template.
- **B2 — AT-058-05 (Load/Save), C-12 gap.** Only a headless round-trip exists; no AT drives Save *through the view* → file → Load *through the view* → assert form equality. FIX: add the through-the-surface loop as the gate (keep any headless test as a supplementary consumer-contract guard, not the gate).
- **B3 — AT-CRC-DSN-016 (centerpiece live verdict), C-16 + "same interaction".** Asserts only end-states; passes even with no reactive handler (a re-query recomputes). FIX: capture the verdict widget's content **before and after a single real Textual field-change event**, with NO Run/refresh between — assert it transitioned.

## Majors
- **M4 (qa)** — R-CRC-DSN-007 mandates **3** warn conditions; the spec dropped two. Must cover all three: (1) `intra_gap`/`join="fill"` with no `pad_byte`; (2) `store_width < ceil(width/8)` (silent detection-strength truncation — NOT cuttable); (3) `check` mismatch.
- **M5 (qa)** — the per-policy preview AT (AT-058-07) must name a concrete §3.2 image fixture (two ranges `0x8000-0x8008`+`0x8010-0x8018`, 8-byte gap) and assert the oracle hexes `concat=0x9C5BCBBD` / `fill(0xFF)=0x2A8A3950` **through the view**, not just that two numbers render.
- **F1 (security)** — C-17 markup enumeration in LLR-V5.3 is non-exhaustive: the **JSON preview** (`emit_template` embeds `name`/`aliases`) is the highest-risk sink and is unnamed. Make the enumeration exhaustive (name, aliases, warnings, gap-conflict addresses, preset labels, JSON preview) and extend the hostile-input AT (AT-058-06) to assert literal rendering **at the preview site** too.

## Minors
- **M1 (qa, C-31)** — the "every preset shows MATCH" AT must DERIVE its preset set from `PRESETS` (or guard `len>=known_min`), not hand-list.
- **M2 (qa, C-10)** — the preset-populate AT must drive a NON-DEFAULT preset and assert the form delta vs the seed, not merely confirm the default.
- **M3 (qa, C-17)** — sweep ALL template-derived render sinks (folds into F1).
- **F2 (security)** — `sanitize_project_name` returns `None` on all-symbol/empty names; LLR-V5.2 Save must define the None branch → warn + write nothing (no `None.crc.json`/crash).
- **F3 (security)** — state the Save directory is the app template-lib constant; only the sanitized basename is name-derived (bounded write).
- **A-F1 (architect)** — rail: adopt key **`0`** (natural 10th, unbound) + glyph **`⊕`** (U+2295, "CRC accumulation is XOR", ASCII fallback `R`); name the real edit sites — append `RailEntry("crc_designer","⊕","R","CRC Designer")`, add `Binding("0","show_screen('crc_designer')",…,show=False)`, add `"crc_designer":"screen_crc_designer"` to `SCREEN_CONTAINER_IDS`, write `_compose_screen_crc_designer`; `action_show_screen` needs NO change (data-driven). Note the 1-9 key exhaustion. Triggers C-22/C-28 snapshot census + a "nine→ten" rail-docstring sweep.
- **A-F2 (architect)** — `CrcTemplate` citation off-by-one: `crc_designer_model.py:110` (spec says :109).

## Adjudicated open questions (from Phase 1)
1. **Story count** — CONFIRMED 11 (US-E4/E5/E6 + V1..V8); every view req R-CRC-DSN-001..011 claimed exactly once.
2. **Rail 10th screen** — ACHIEVABLE; `action_show_screen` is data-driven (app.py:5273-5276, zero change), but `RAIL_ENTRIES` is a frozen 9-tuple with keys 1-9 exhausted → 4 additive edits (A-F1). Design-doc "no new handler" claim is literally true; its omission of the tuple/binding edit is the gap.
3. **`sanitize_project_name`** — RESOLVED: `workspace.py:329`, already imported in `app.py:164`, used app.py:5976 → import-reachable, R-5 downgraded.
4. **Four keel-API bindings** — ALL CONFIRMED on-disk: `crc_template.py` absent (facade NEW, sources `parse_template`:504/`emit_template`:625/`read_template`:672/`CrcTemplate`:110); `encode_word`/`decode_word` absent from crc.py (NEW); `parse_job`:554 one-errors on flat (`else: raise` :605) + `emit_job` absent (both NEW); `store_word`:290 big/little **encode** only, no big-endian **decode** anywhere.

## Decision
Autonomous **iterate-to-refine**: fold all blockers + majors + minors into `01-requirements.md` (§3/§4 bodies + §6.5 amendment record), then re-gate Phase 2. Named gap = Certainty axis (3 vacuous ATs). No redesign; the derivation stands.
