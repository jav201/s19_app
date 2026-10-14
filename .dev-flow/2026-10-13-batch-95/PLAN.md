# PLAN — s19_app — Batch 2026-10-13-batch-95

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language.
> **Owed in.** `core` ✓ · `full` ✓
> Seeded by `/dev-flow-init` step 4 at both levels; the living plan is owed at every gate
> that follows (`/dev-flow` §Living plan is the rule's home).

> **Field guide:** `templates/guides/plan-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.
> **Two header labels are read literally and are never translated:** `Standing authorization` and `Last updated`; the field guide names their readers.

The living compendium of this batch: where-we-are · objective · per-story/per-station status ·
roadmap + increment plan · key decisions · risks/watch-items · conventions honored ·
out-of-scope carries · test ledger · decision log (the human-readable mirror of `state.json`).
**Create at batch open and update at every gate and significant checkpoint** — the
orchestrator presents the full plan in-conversation at each phase gate.

## Header

| Field | Value |
|---|---|
| Project | s19_app |
| Batch | 2026-10-13-batch-95 |
| Objective | The cambios_10_12_2026 batch: (1) the Split / Join / Export screen -- the grafted terminal design (V1 chassis + V2's width-118 band + split-mode per-file gantt), the color/glyph preview visor, split/join/export S19+HEX+BIN with skip/fill gaps (pad 0x00), the span guard, palette-first; (2) project save gathers all used files, artifacts project-scoped (no project -> common homes); (3) open-folder buttons on patch/checks/CRC/reports (cross-platform); (4) per-window usage help sections. **Amended mid-P3 (change 5, 2026-10-13):** (5) A2L-referenced patch changes -- the change-set JSON gains the `symbol` reference form alongside the address form, the Patch Editor gains symbol resolution/picker (unresolved = a REFUSAL naming the symbol), the Flow Builder's Load/Patch blocks carry the A2L reference (project or organized workspace folder), and every report attributes each flow change by symbol/address with an A2B diff over a flow-produced image referencing ALL the flow's changes (US-133, HLR-141..143 — `LED-2026-10-13-batch-95.2`) |
| Last updated | P5 · 2026-10-13 (the close — all increments committed to `6c18d95`, the C-25 arbitrated, the record written; see `04-validation.md` / `05-close.md`) |
| Standing authorization | Operator (Javier), 2026-10-13, quoted in `state.json`: the prototype round for the cambios of 2026-10-12 CLOSED -- all four changes + the six rulings accepted, the join preview visor added, the TUI-native pass shipped the graft as the final screen, a color, both verdicts accepted (veredicto-ronda1 / veredicto-tui-pass / veredicto-final in the round's dir). "Implement the batch." Read with the established chain: Gates -- autonomous with the two exceptions; Git -- the COORDINATOR commits and pushes at each close (no PR); Kimi agents under coordinator briefs do NOT commit/push/stash; this batch runs in the MAIN checkout. |
| First gate | Not yet run at P1 authoring (`state.json`: `current_station` P0, `phase_status` not-started). The executed premise evaluation in `01-requirements.md` §2.7 (P-1..P-15) is the P0 evidence pack; the coordinator's P0 gate run appends its exit code and `V7` line here. |
| Premises / RC-1 | RC-1 verified: `origin/main` tip = `348c125` (`git log origin/main` at P1: the batch-94 close commit; local HEAD == origin/main). Premises P-1..P-15 evaluated TRUE in `01-requirements.md` §2.7 -- each with executed evidence (shipped-code line readings, the executed `extracted.json` re-derivation, the frames' geometry, the registry parse). |

## Triggers

The trigger evaluation `state.json`'s `triggers.record` points at: one row per trigger evaluated, fired or not.

| Id | Verdict | Probe output |
|---|---|---|
| <A1 / B1 / …> | <fired / not fired> | NOT EVALUATED at P1 authoring — owed at the coordinator's P0 gate run (`state.json` carries the flow's NOT-EVALUATED marker, not a verdict). |

## Where we are

P1 (the contract) is authored: `01-requirements.md` declares US-129..132, HLR-135..140,
LLR-135.1..140.2, the IFC (4 flows + the engine component), the AT-296..301 / TC-682..711
reservation and the 5.2 acceptance criteria; `01-requirements-ledger.md` carries
LED-2026-10-13-batch-95.1 (the derivation from the round + the three verdicts, with the
commission-vs-round reading notes). P2 (this review) approves with observations. Next: the
P0/P1 gate runs, then P3 increments inside the single lane.

**Amended mid-P3 (change 5, 2026-10-13):** `01-requirements.md` now also declares US-133,
HLR-141..143 + LLR-141.1..143.2 (the A2L-referenced patch changes, the Flow Builder's A2L
reference, the report/diff attribution — premises P-16..P-23 executed at the amendment), the
IFC's `a2l_referenced_patch` flow + the `change_set_wire` component, and the reservation
extended to AT-302..304 / TC-712..718 (registry rows appended, high-water verified).
`01-requirements-ledger.md` carries LED-2026-10-13-batch-95.2 (the operator's words verbatim +
the design decisions). Increment 001 (the engine) is running and untouched; increments 002–004
(not launched) carry the amended scope — see the roadmap below.

## Objective

The cambios_10_12_2026 batch, re-derived from the round's record: the Split / Join / Export
screen (the graft: V1 chassis + the ≥118-col visor band + the split per-file gantt, the four
visor classes, the span guard, palette-first, Esc), the split/join/export semantics (pad `0x00`,
first-range concat base, `‹stem›_joined.‹ext›`, original-offset fill, conflict abort, BIN +
`.addr`), the engine additions (slicer, BIN emitter, fill emitter, the hardened A2L extractor),
the change-1 save-gather, the change-2 open-folder chips on the cross-platform seam, and the
change-3 per-window usage help -- contracted in `01-requirements.md`.

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| US-129 (Split / Join / Export) | contracted | HLR-135/136/137 · AT-296/297/298 · the graft + visor + guard + engine |
| US-130 (save-gather) | contracted | HLR-138 · AT-299 · COPY semantics, project homes, COMMON originals stay |
| US-131 (open-folder chips) | contracted | HLR-139 · AT-300 · 4 windows, cross-platform seam |
| US-132 (usage help) | contracted | HLR-140 · AT-301 · VariantHelpScreen pattern, 9 authored sections |
| US-133 (A2L-referenced changes, change 5) | contracted (mid-P3 amendment) | HLR-141/142/143 · AT-302/303/304 · TC-712..718 · `LED-2026-10-13-batch-95.2` |
| P0 | evidence pack ready | premises P-1..P-15 executed in §2.7; the gate run + trigger evaluation owed |
| P1 | authored | this contract; the P1 gate validates it |
| P2 | this review | approve, observations recorded |
| P3 | queued | increments inside the single lane after the gates |

## Roadmap + increment plan

The increments this batch expects, in order (P3 details land in `03-increments/`): (1) the engine
seam — hardened extractor + slicer + BIN/fill emitters (LLR-137.*, the A2L prerequisite first) —
**running; untouched by the change-5 amendment** (its tag/RECORD_LAYOUT/COMPU_METHOD enrichment
is the amendment's shipped prerequisite); (2) the screen — chassis, visor, regimes, gantt, guard,
plan + export (HLR-135/136) — unchanged; (3) the save-gather (HLR-138) **+ the change-5 patch/flow
seats (HLR-141/142)** — the change-set wire's `symbol` form + the Patch Editor's picker ride the
change-set/ChangeService surfaces, and the Flow Builder's Load/Patch `a2l_ref` rides the
persistence/execution services (inc-003's brief gains both); (4) the open-folder chips + seam
(HLR-139) **+ the change-5 report/diff attribution (HLR-143)** — the flow report's
change-attribution section and the A2B diff reference-all law seat in the report services
(inc-004's brief gains both); (5) the usage-help modal + sections (HLR-140) — unchanged
(the authored `help_sections.md` copy stays operator-editable; a symbol-reference usage note is
the operator's to add, not the contract's). Increments 3–5 remain independent of 1–2 and may
interleave per the lane's gate order; the change-5 seats are bound to their increments' surfaces,
not to a new increment, so no sixth increment is minted.

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-13 | The graft ships as the screen; the HTML mock is superseded | veredicto-tui-pass V=graft + veredicto-final accept |
| 2026-10-13 | Palette-first (`^K` → "Split / Join / Export"), no rail key | ruling Q6/7a; the rail is full (P-1) |
| 2026-10-13 | Pad `0x00` (vs the CRC editor's `0xFF`) | ruling Q1/8a — different intents |
| 2026-10-13 | The change-2 seam is cross-platform (commission) over the round's Windows-only acceptance | the `state.json` objective says cross-platform; recorded in the ledger |
| 2026-10-13 | The change-3 surface is the per-window `VariantHelpScreen`-pattern modal | the round's OQ#6 recommendation; the HelpPanel stays untouched |
| 2026-10-13 | Change 5 amended mid-P3: the wire's `symbol` form is additive; the canonical writer keeps the resolved address (the wire version stays 2.0) | the shipped v2.0 reader rejects a form replacing `address` but tolerates an added optional field (P-19 executed) — leniency is the law, not a hope |
| 2026-10-13 | Change 5: the physical→raw encode is net-new composition on the shipped COMPU_METHOD side tables (decode ships, P-17) | the operator changes VALUES in physical units; the encode cannot be cited as shipped behavior |
| 2026-10-13 | Change 5: Load carries `a2l_ref`, Patch may override; the source homes are the project root then the `.s19tool\workarea\` containment root — no new COMMON folder, no implicit A2L | rides the shipped ref grammar (P-20) + the change-1 homes (P-23); the REFUSAL names the symbol/reference at every seat |

## Risks / watch-items

- The 118-col wide threshold is prototype-measured; P3 re-confirms on the shipped screen (C-29) — a drift re-opens LLR-135.3.
- The "used by this project" gather predicate is undefined by design (O-1); P3 records it — over-gathering copies the library, under-gathering breaks the snapshot promise.
- The round's dir is throwaway; the oracle frames are referenced by path — P4 re-captures if it moved.
- Reservation drift (G-93-01's lesson): the minted ids must stay inside AT-296..304 / TC-682..718; any drift retires the reservation with its reason. (Amendment note: AT-302..304 / TC-712..718 were appended at the registry's numeric high-water — AT-301 → AT-302, TC-711 → TC-712; TC-1728 stays BURNED and does not drag the mark.)
- The change-5 encode direction (physical→raw) is net-new on shipped COMPU_METHOD tables; the conversion limbs (unknown conversion, value outside limits) are P3-recorded in the increment packet.
- The no-project A2L home is the `.s19tool\workarea\` containment root; a per-family COMMON A2L folder is punted (no shipped home exists) — recorded in §6.3 of the contract.

## Conventions honored

- The frame discipline (measured geometry: `(120,36)` ⇒ 118×34) — batch-93's pinning rule carried.
- S1: no markup parsing; every file-derived string a plain `Text` span.
- The 2-colors-per-cell law / C-10 (one visual variable, glyph + hue).
- Calm Dark tokens only (`styles.tcss:26-31` + the severity set) — nothing outside the shipped palette + the two verified tints.
- `styles.tcss` precedence over widget `DEFAULT_CSS`; ids on remounts none (classes only, DuplicateIds).
- EARS `shall`; the reserved field names literal; English (the batch's `state.json` language).

## Out-of-scope carries

- XCP `IF_DATA SEGMENT` extraction (the recon named it; no tab needs it) — tracked in BACKLOG if ever asked.
- A chosen-base join variant — manual localities cover it (8d's ruling).
- Rail-key repurpose, report subfolders, forking Textual's HelpPanel — rejected by the round.
- A per-family COMMON A2L folder for change 5 — no shipped home exists; the workarea containment root serves (LLR-142.2). Routed to `BACKLOG.md` if the operator ever wants a dedicated library.
- A contract-mandated symbol-reference usage-help section — `help_sections.md` is operator-editable copy; the amendment leaves it to the operator.

## Gate notices and runtime absences

None at P1 authoring — the gates have not run. The coordinator's P0/P1 runs append their NOTICEs
here; any rule recorded `not-run` on this runtime is logged with its reason at that gate.

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| `python -m pytest tests -q` (full, pre-merge form) | not this batch's yet | owed at P4 — every ledger figure will state which form produced it |
