# batch-77 — PLAN (living compendium)

> Updated at every gate and significant checkpoint. The operator reads **this**, not the file tree.

**Batch:** `2026-08-01-batch-77` · **Objective:** Memory Map redesign — Variant A (gap-fold band bar) + cross-cutting fixes S-1…S-7
**Charter INPUT:** `prototypes/memmap_variant_a.HANDOFF.md` (operator-approved 2026-08-01) — *input, not spec; everything re-derived*
**Branch:** `claude/batch-77-memmap-variant-a` · **Base:** `origin/main` @ `f8747b8`
**RC-1:** ✅ merge-base == tip (`0	0`) · **flow: `2026.07.28-rev1`** (hash mismatch scoped to the `dev-flow-lessons` catalog, local AHEAD — enforceable surface byte-exact; re-executed, not inherited)
**Lane:** A — `.dev-flow/BACKLOG-CODE.md` (per `docs/engineering-rules.md:17`)
**Language:** English (`state.json.language = "en"`)

---

## 1 · Where we are

**Phase 0 — story intake, AWAITING GATE.** Measurements complete and pasted in
`00-measurements.md`. **15 premises evaluated: 9 TRUE, 4 FALSE, 1 IMPRECISE, 1 new defect found.**
Nothing has been derived into requirements yet — Phase 1 is not started.

The charter's engineering direction survives execution. Its **acceptance layer** does not:
one drafted acceptance is provably vacuous, and the requirement id it says it amends does not exist.
This is the project's dominant defect class (vacuous checks concentrated in specs, not code) arriving
exactly where the charter itself warned it would.

---

## 2 · Objective

Make the Memory Map's hero — the entropy band bar — legible for sparse S-record images,
and close six cross-cutting usability gaps around it, **without** perturbing the shipped
band/colour contract or the frozen engine.

**Measured problem (executed, not asserted):** at 5 regions / 1 030 B / 128 MiB span the bar emits
**64 columns against a 60-column budget**, of which **59 are gap hatch**; runs of
256/256/256/200/62 B all render at **exactly 1 column**. The bar does not fail to *show* regions —
it fails to **discriminate** them, and it **overflows its own budget** doing so.

---

## 3 · Story intake (Definition of Ready) — Phase-0 artifact

Each story states an outcome observable through the **shipped** surface. `AT` ids are **not**
minted here — `AT-TC-REGISTRY.jsonl` is the sole authority and reservation happens in Phase 1
on its own PR (per `docs/engineering-rules.md:46`).

| US | Story (observable outcome) | INVEST | Status |
|---|---|---|---|
| **US-77-1** | Given a sparse multi-region image, when the map renders, the operator sees **each region's bar width order with its mapped size**, gaps folded to fixed markers, **and the bar within its column budget**. A dense no-gap image renders **byte-identical to today**. | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-2** | When the map renders, **every ruler label names a mapped address** (region starts + span end), overlaps collapsed, fold labels carrying gap size. | I·N·V·E·S·**T** | 🟡 **READY-WITH-AMENDMENT** |
| **US-77-3** | The stats line shows a **dual mapped/span readout** with a real percentage and a **humanized** largest gap, replacing `Coverage: 0.00%` + raw bytes. | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-4** | The always-on 4-row legend block is **absent from the map body**; a footer hint points to the existing `k` LegendScreen, which is **unaffected**. | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-5** | The operator can reach and act on regions **with the keyboard only**: focus a row, ↑↓/j/k to move, `Enter` inspects, `o` opens hex — surfaced in Footer + `?`. Mouse N4a split (single=inspect, double=hex) preserved. | I·N·V·E·**S**·T | 🟡 **READY — C-16 FLAGGED** |
| **US-77-6** | With a file loaded, the inspector is **populated with zero clicks** (first region auto-selected). | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-7** | The selected region row is **visually distinguishable** from unselected rows. | I·N·V·E·S·**T** | 🟢 **READY** |
| **US-77-8** | *(charter "optional")* log-scale microbar denominator + column-aligned region rows, ported from Variant C. | — | 🔴 **OUT** |

### Status reasons

- **US-77-1 — the drafted acceptance is replaced, not inherited.** Charter draft #1
  (*"every region ≥1 visible bar column"*) is **already TRUE today** (P-4): `:2066` floors every run at
  `max(1, …)`. It is invariant under the change it gates → **C-40 limb 1**. The discriminating property is
  **width monotonicity** (`bytes(a) > bytes(b) ⇒ cols(a) ≥ cols(b)`, with ≥1 strict inequality on the sparse
  fixture), which is **RED today** because all five widths are equal. The charter's **byte-identical dense
  control** (draft #2) is kept — it is the strongest thing in the drafted set.
  **Absorbs the new P-15 overflow defect** (64 > 60): same `max(1, …)` expression, rewritten by this story.
  Folding it in rather than carrying it is a **recorded autonomous decision (D-2)**.
- **US-77-2 — amendment, not wording.** S-2's cited `LLR-072.3` **does not exist** (P-5). The clause is
  `R-TUI-072`, guarded by the **live, passing** `AT-072b` asserting *exactly 5 ticks* (P-6). Proceeding
  requires a **§6.5 Before/After amendment** to `R-TUI-072` + a re-derived `AT-072b`, and correction of the
  dangling `LLR-072.3` citation at `tests/test_tui_map_big.py:118`. Ready to derive; the amendment is
  Phase-1 work and is **not** a blocker.
- **US-77-5 — C-16 prototype-fidelity flag.** The keyboard path is demonstrated only in a throwaway
  prototype. **Textual performs no spatial arrow-focus by default** — this is the literal origin of C-16
  (batch-27, where `MapCell.on_key` was Enter-only and an `.focus()`-based AT shipped the gap GREEN).
  Carried as **`assumed — verify in target framework at Phase 3`**, and its AT **must press real keys**,
  never call `.focus()`. Story stays READY; the risk is on the mechanism, not the outcome.
- **US-77-8 — OUT, with reason.** No measured defect motivates either idea; the charter explicitly forbids
  silent absorption; and both are visual-design changes that would widen an already 7-story batch past the
  ≤5-files-per-increment discipline. **Registered as a Lane-A carry, not dropped.** Reversible on request.

### Explicitly out of scope (charter §2, honored)
- **Variant B** (two-lane map) — its own batch if ever; registered as a backlog candidate.
- **The CC-1 encoding decision** owed to the operator — unrelated, not absorbed here.

---

## 4 · Roadmap (indicative — Phase 1 owns the real increment cut)

| Inc | Content | Files (≤5) |
|---|---|---|
| Inc-0 | Byte-golden of the **dense no-gap** render, captured from the shipped producer in its own commit (the C-12 control for US-77-1) | tests |
| Inc-1 | US-77-1 gap-fold widths + budget bound | `screens_directionb.py`, `styles.tcss`, tests |
| Inc-2 | US-77-2 ruler + `R-TUI-072` amendment + `AT-072b` re-derivation | `screens_directionb.py`, `REQUIREMENTS.md`, tests |
| Inc-3 | US-77-3 stats + US-77-4 legend demotion | `screens_directionb.py`, `styles.tcss`, tests |
| Inc-4 | US-77-5 keyboard + US-77-6 auto-select + US-77-7 selection style | `screens_directionb.py`, `styles.tcss`, `app.py`, tests |

Snapshot goldens **will** drift → regenerate **only in canonical CI** (textual 8.2.8 pin).
`tui-ci` runs `-m "not slow"` on PRs and the **full** suite on pushes — the **full** form runs before merge,
and every ledger figure states which form produced it.

---

## 5 · Risks & watch-items

| # | Risk | Mitigation |
|---|---|---|
| R-1 | `tests/test_tui_map_big.py` is the blast-radius centre (`AT-072a/b`, `AT-073`, `AT-074`, two `query(RegionRow)` sites) | **C-26 reverse-grep** every touched symbol across all of `tests/` before any increment lands |
| R-2 | Fold markers accidentally becoming `RegionRow`s would corrupt those counts | Keep them inert `Static`s — the `BandSegment` sibling precedent (P-13); gaps are **already** inert (P-14) |
| R-3 | Textual gives no spatial arrow-focus for free (C-16) | AT presses **real keys**; `assumed — verify at Phase 3` |
| R-4 | Snapshot drift mismarked | C-22 per-cell reasoning; C-28 for any Footer binding added by US-77-5 |
| R-5 | Markup/injection via new label paths | **B3 holds**: no file-derived text in bar/rows. Any new label is a count/address/constant. C-17 re-check at Phase 2 |
| R-6 | Charter numbers copied rather than re-derived | Every figure in `00-measurements.md` carries its executed transcript |
| R-7 | **C-33's prescribed liveness discharge is OBSOLETE under this harness** — see finding F-0 below | Deliverable-file monitor armed with a bounded 30-min timeout as the backstop; finding routed to Lane B |

### F-0 — a control whose prescribed discharge no longer executes (found Phase 1, routed to Lane B)

**C-33 says:** discharge sub-agent liveness *"either \[by] an active blocking wait (`TaskOutput block=true`, re-polling on timeout) OR \[by] poll\[ing] a genuine progress signal (touched-file mtime for an implementer; `TaskOutput` status)."* **Both named mechanisms are now unavailable**, measured rather than assumed:

1. **`TaskOutput` is DEPRECATED for `local_agent` tasks** and its own documentation forbids the C-33 usage: the `.output` path *"is a symlink to the full subagent conversation transcript (JSONL) and will overflow your context window."* The sanctioned replacement is the Agent tool's completion notification — i.e. exactly the passive wait C-33 was written to forbid.
2. **The transcript-size signal is dead, verified by sampling:** both lanes' `.output` files sat at **0 bytes with mtime frozen at dispatch** (`17:05:11` / `17:05:46`) across a 45 s interval. This is the batch-49 condition reproduced — and the reason the standing rule is *verify the signal moves before trusting it*, which is what caught it here.
3. **My own first monitor was also inadequate** and I state it plainly: it watched the **deliverable file**, which is written once at the END of the agent's work, so a 0 B reading cannot distinguish "reading hard" from "hung". It is a completion detector wearing a liveness detector's label — the same shape of defect this batch found in the charter's acceptance #1.

**Net:** for a `local_agent` under this harness there is currently **no in-band progress signal**, so C-33's *"STOP + take over once liveness cannot be confirmed"* branch is the only honest discharge, and it must be driven by a **wall-clock bound**, not by a signal. Bound adopted here: **30 min**, enforced by the monitor's timeout.

**Not a batch-77 defect and not app code — this is a process/control item. It is written into `.dev-flow/BACKLOG-PROCESS.md` at this batch's close (Lane B), per the routing rule that a carry belonging to the other lane is written there, never left as a pointer.**

---

## 6 · Invariants that must survive (verified against `f8747b8`)

**B3** no file-derived text in bar/rows · **colour only via `band-*`** (`entropy_style` + `styles.tcss:665-679`), glyphs `· ░ ▒ ▓` are the colour-blind cue (C-10) · **LLR-041.7** panel is presentational · **remount discipline** classes never ids · **fold markers are not `RegionRow`s** · **N4a click split** + `width-narrow` regimes · **no `_nodes`/`_context`** on new widgets · **engine-frozen set off-limits** (source **and** `_ENGINE_TEST_FILES` — C-27 dual guard).

---

## 7 · Test ledger

| Point | Base | −D | +A | Post | Form |
|---|---|---|---|---|---|
| batch-76 close (`fd9124a`) | — | — | — | **2514 passed / 2 skipped / 3 xfailed** | FULL |
| batch-77 Phase 0 | — | — | — | *not yet run* | — |

---

## 8 · Decision log

| # | Decision | Authority | Note |
|---|---|---|---|
| D-1 | Batch numbered **77** | autonomous | Derived from disk + `git branch -r`, not memory — two prior collisions in this project |
| D-2 | **Fold P-15** (64 > 60 budget overflow) into US-77-1 rather than carry it | **autonomous** | Same `max(1, …)` expression the story rewrites; leaving a known overflow inside code being rewritten is how a defect becomes the next batch's premise |
| D-3 | **Replace** charter draft acceptance #1 with width-monotonicity | **autonomous** | Draft #1 measured GREEN on the pre-change tree (P-4) — vacuous per C-40 limb 1 |
| D-4 | **US-77-8 OUT**, registered as a carry | **autonomous** | No measured defect; charter forbids silent absorption; batch already at 7 stories |
| D-5 | Flow-currency mismatch ruled **NON-BLOCKING** | **autonomous** | Re-executed per-file: 11/11 control-bearing files byte-exact; divergence is the catalog only, local AHEAD |
| D-6 | Use subagents per the flow (`code-reviewer` per increment, `qa-reviewer` Phase 4 + merge gate) with C-33 liveness polling | **autonomous** | The accepted kickoff option explicitly names the independent `qa-reviewer` merge pass; overrides the session-harness default |
| D-7 | **Use batch-scoped ids `AT-B77-nn` / `TC-B77-nn`; NO reservation PR** | **autonomous** | `docs/engineering-rules.md:48` prefers them, and the registry's own `_meta.governed` puts letter-initial bodies **outside its authority** (spec §2.3). They cannot collide by construction, and the global pool never has to carry them. **Exception:** `AT-072b` is an *existing* global id being re-derived, not minted — it keeps its number. This removes a whole PR from the critical path. |
| D-8 | **Corrected my own stale carried number** — registry `next_free` is `AT-282 / TC-613`, not `TC-611` | **autonomous** | I had copied batch-76's `state.json` figure instead of re-deriving from the registry. It was stale: batch-76's *own* merge-gate closure minted `TC-611`/`TC-612` after that line was written. **I broke "a carried number is re-derived, never copied" in the very file that records the rule.** Corrected and recorded, not silently overwritten. |
| **R-1** | **Bar width RECONCILES to the real container**, not the constant 60 | **OPERATOR** 2026-08-01 | The batch's central defect: `.map-band-bar` is 21 cols @120×30 vs a 60 budget → **2 of 5 regions invisible**. Reddens the live PIN `test_map_click_chain.py::test_ac6_clipped_segments_are_a_known_layout_limitation`; **deleting it is sanctioned by its own docstring** (*"If the constant and the container were reconciled, DELETE this test"*). Retirement must print an explicit line naming the dropped observable (C-40 limb 2(ii)). |
| **R-2** | **Dense control RE-BASES** after the width fix | **OPERATOR** 2026-08-01 | Byte-identity with *today's* dense render is abandoned deliberately — R-1 changes it by design. New control: **gap-folding is a strict no-op on gapless images at fixed container width**. Golden fixture must use **unequal** runs (768/256 → `[45,15]`); equal 512/512 → `[30,30]` is invariant under any monotone re-weighting and would be vacuous (QA B-5). |
| **R-3** | **Keyboard = ↑↓ + Enter only; `j`/`k`/`o` DROPPED** | **OPERATOR** 2026-08-01 | All three are already bound app-wide (`o`→`open_workarea`, `j`→`dump_a2l_json`, `k`→`show_legend`); `o`/`j` are frozen in `_PRE_BATCH_BINDINGS` under live `TC-011`. Keeps `k` as the legend key so US-77-4's hint stays true. ⚠️ **Scope reduction: the charter's `o` = open-hex keyboard affordance is DESCOPED** — registered as a carry. The **N4a mouse split is unchanged** and remains the route to hex. |
| **R-4** | **Ruler labels the LAST MAPPED BYTE**, not the exclusive `span_end` | **OPERATOR** 2026-08-01 | `span_end` is exclusive (`0x07FFFF3E`; last mapped byte `0x07FFFF3D`), so *"every label names a mapped address"* ∧ *"label at span end"* were mutually unsatisfiable. Also corrects my P-7: **4 of 5** ticks name unmapped addresses today, not 3. |
| — | **Autonomy: autonomous + merge authorized**; merge gated on green CI **and** a clean final independent `qa-reviewer` pass over the whole diff vs `main`. A HIGH finding blocks and returns to the operator. | **OPERATOR** 2026-08-01, `AskUserQuestion` at kickoff — asked fresh, not inherited | |
| — | **Decision recording confirmed** — every un-asked decision recorded in PLAN.md §8, `state.json.decisions_log`, `05-postmortem.md`, and carried to the vault at `/dev-flow-sync` | **OPERATOR** 2026-08-01 | |

---

## 9 · Out-of-scope carries (registered, not dropped)

- **US-77-8** — log-scale microbar denominator + column-aligned region rows (Variant C ports).
- **Variant B** — two-lane map; its own batch if the operator wants it.
- **Dangling id `LLR-072.3`** cited at `tests/test_tui_map_big.py:118` with no definition in
  `REQUIREMENTS.md` — to be corrected inside US-77-2 if that story lands, otherwise a carry.
  (Note: `LLR-*` is **not** covered by the AT/TC registry — operator scoping ruling 2026-07-31.)
