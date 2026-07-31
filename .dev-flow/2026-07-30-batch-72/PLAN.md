# PLAN — batch 2026-07-30-batch-72 — P1 design-defect implementation (CRC B + Legend B)

## Where we are
**Phase 1 APPROVED (2026-07-30) → Phase 2 cross-agent review in progress.** Phase 0
complete. This batch was PREPARED by the prototyping session (the one that ran
`/tui-design` → PR #164 and got the operator's variant verdict); the EXECUTING session
took it over at the Phase-1 gate and carries it to term under **full autonomy + merge
authority**. Nothing is implemented yet.

**Kickoff record (executing session, 2026-07-30).**
- **RC-1 RE-VERIFIED**: `origin/main` tip = `31d87d0` (PR #164 squash, MERGED) = `HEAD`
  = merge-base of `claude/batch-72-design-defect-634a67`. Collision re-check
  `git ls-remote --heads origin | grep batch-72` → **0 hits**.
- **flow: `2026.07.28-rev1` (hash verified)** — `~/.claude` 0 commits behind
  `origin/main`; aggregate `sha256` = `0127a2767ff11c8a`, matching `FLOW-VERSION.md`
  exactly (C-45 PULL discharged).
- **Authorization (per-batch, asked and answered)**: Q1 = *"Full autonomy + merge"* —
  the agent self-approves remaining gates, opens the PR, and merges **only** after the
  final independent PR-level `qa-reviewer` pass over the whole diff vs `main` comes back
  clean; a HIGH finding blocks the merge and returns to the operator. Q2 = *"Acknowledged"*.
- **P-8 RESOLVED**: operator confirmed *"Stack, key first"* — the PROPOSED default was
  confirmed, not overridden.

## Objective
Ship the operator-decided redesigns: **CRC Designer Variant B** (paired Reflection row,
KAT demoted to a `Self-test` row under Check, Warnings owns the hero right column,
Select height capped) and **Legend modal Variant B** (two-pane: card ∥ colour key,
key-first stack at the floor). Route: **full `/dev-flow`** (operator invoked it).

## Status per phase
| Phase | Status | Artifact |
|---|---|---|
| 0 — intake | ✅ done (prep) + RC-1 **re-verified at `31d87d0`** by the executing session | §2.6 of 01-requirements.md |
| 1 — requirements | ✅ **REVISION 3** — rev 1 approved → 9 blockers → rev 2 → re-gate blocker → rev 3 (2 iterations) | `01-requirements.md` + `00-measurements.md` |
| 2 — cross-review | ✅ **re-gate discharged** — qa `approve`, architect's 1 new blocker folded | `02-review.md`, `02-regate-architect.md`, `02-regate-qa.md` |
| 3 — implementation | not-started | suggested cut below |
| 4 — validation | not-started | — |
| 5 — postmortem | not-started | — |
| 6 — docs + PR | not-started | — |

## Kickoff protocol for the EXECUTING session (do these before anything)
1. **RC-1 again**: `git fetch`; branch off the CURRENT `origin/main` tip. Verify PR
   [#164](https://github.com/jav201/s19_app/pull/164) (prototypes + this batch prep)
   MERGED first — this scaffold rides on it. Verify flow currency (C-45 PULL) vs
   `~/.claude/docs/FLOW-VERSION.md`.
2. **Re-read `state.json`** before editing (last-writer-wins; parallel batch-65 may
   have moved it). Confirm `batch_id` is still `2026-07-30-batch-72` and the number is
   still collision-free (`git ls-remote --heads origin | grep batch-72`).
3. **ASK the operator the two kickoff questions** (authorization is per-batch, NEVER
   inherited — `feedback_standing_auth_per_batch`): autonomy + merge authority; and the
   decision-recording acknowledgement. **NOT asked in the prep session on purpose.**
4. **Present the Phase-1 gate**: paste 01-requirements.md §2.7 + §3 inline; get the
   operator's `approve` — including the **P-8 open decision** (floor stacking key-first,
   PROPOSED default).
5. Re-run the ID census (AT-213..218, TC-510..519 reserved — a parallel batch may have
   consumed ids since 2026-07-30).

## Phase-2 outcome — 9 blockers, and what the iterate changed

Three lanes ran in parallel. **The architect and qa lanes independently measured the same
16 abutting focusable pairs and independently concluded G-1 was unsatisfiable** — convergent
rediscovery is what upgraded that from an opinion to a measurement.

Rather than adopt the reviewers' proposed fixes, the fold **executed its own thresholds first**
(C-39 rider) into [`00-measurements.md`](00-measurements.md). That caught a defect *inside the
review*: qa proposed re-scoping G-1 to "same widget class → exactly 1 violation"; measured, it is
**7 pre-batch and 6 post-batch** — still unsatisfiable. Adopting it verbatim would have relocated
the defect, not closed it.

| Blocker | Disposition in revision 2 |
|---|---|
| A-1 AT-B59-05 contradiction | batch-59 verdict-hero **retired**, Before/After at §6.5 A-1, ledger `D=1`, deletion (never an edit-to-pass) |
| A-2 no floor mechanism | **LLR-072-6.1** — the modal owns its own `on_mount`/`on_resize` regime hook at the same 120 breakpoint; **TC-517** asserts the class flips |
| A-3 / Q-1 G-1 unsatisfiable | **re-scoped to `Switch`-only** (measured 1 → 0). Complete by construction: 2 Switches, 1 construction site |
| A-4 G-2 proves the wrong thing | **retired** with an explicit written retirement line + backlog carry (§6.5 R-1) |
| Q-4 / Q-5 AT-216 vacuous ×2 | anchored on the key-row **widget** (derived from `LEGEND_TABLE`), **region-containment** oracle, `max_scroll_y == 0` cause-clause, plus a `display:none` mutation discharge |
| Q-8 HLR-072-4 has no AT | the **requirement itself was withdrawn on measurement** — §6.5 W-1 |
| Q-9 stale ledger base | **2379** @ `b556e35`, measured 2026-07-30 |

**The withdrawal is the headline.** `Select { height: 3 }` renders `CRC-32/ISO-HDLC` as
**`CRC-32/I`** — 8 of 15 characters, no ellipsis, no overflow marker — and clips the bottom border
on 4 of 6 Selects. Minimum legible height is 6, which is what `height: auto` already gives. The
number came from the prototype pass and would have shipped a control that lies about its value.

## Phase-2 RE-GATE — the fold introduced its own blocker, and that is why it ran

qa returned **`approve`** (0 blockers; all 5 of its Phase-2 blockers closed, one *dissolved* by the
HLR-072-4 withdrawal). The architect returned **1 new blocker — created by the fold itself**:

> **N-1.** LLR-072-5.1 pinned `compose` as **card-first**; HLR-072-6 / AT-217 require **key first**
> at the floor. Textual 8.2.8 has no CSS ordering property — only `dock`. Executed with exactly the
> specified compose + CSS + hook: `key.y < card.y` → **False** at 80x24 in both views. The tell was
> *inside the requirement*: LLR-072-6.2's threshold "key h=4, card h=5" is the **key-first**
> measurement, so M-3 had measured a tree the requirement did not specify. Composing key-first
> instead breaks HLR-072-5 (the key would render left at 120x30).
> **Resolved in revision 3:** the regime hook owns the order — `#legend_body.move_child(key,
> before=card)` when narrow, restored when wide. The reviewer executed this remedy and confirmed it
> satisfies all three AT-217 clauses while keeping 64/43 in the wide regime.

Six further majors folded, each with an executed basis: the narrow CSS rules were **unprefixed**
(equal specificity + later source order → they overrode the wide regime, putting the key pane at
`x=113`, outside the body); **AT-216 passed on that broken layout**, so it gains a
`#legend_body.contains_region(pane)` clause; `App.query` is **screen-scoped**, so the Switch
completeness argument is now anchored to the owning **module** rather than to the query (and, after
Inc-4's D-1 catch, to the module rather than to a *site count* — the batch's own refactor turned one
`Switch(` site into two);
AT-214's counterfactual must revert the **whole file** (reverting just the pair row raises
`NameError`, since LLR-072-1.2 deletes `_switch_row` — an error is not an assertion failure);
AT-219 gains a real gate clause (the pin was invariant — all six sinks are already `markup=False`);
and **G-3's stated reason was a rationalisation** — measured, the hero tiles are identical `30x4`
boxes, so the batch changes the bounded quantity by zero, and the 6:1 law is *already* violated on
`main` at **2.54:1**.

## Phase-3 increment cut (re-derived per C-21 — the AT set changed)
- **Inc-1 — Legend two-pane** (`screens.py`, `styles.tcss`, new AT file): LLR-072-5.1/5.2, 7.1.
  ATs 216/218 + TC-515/516/519.
- **Inc-2 — Legend floor regime** (`screens.py`, `styles.tcss`): LLR-072-6.1/6.2. AT-217 + TC-517/518.
  Split from Inc-1 because the regime hook is a *behaviour*, not a layout rule, and owes its own TC.
- **Inc-3 — CRC compose** (`crc_designer_view.py`, `styles.tcss`, tests): LLR-072-1.1/1.2, 2.1-2.4,
  8.1. ATs 213/215/219 + TC-510..513. Includes the AT-B59-05 deletion.
- **Inc-4 — G-1 guard + docs** (tests, `REQUIREMENTS.md`): AT-214 with its C-40 counterfactual
  transcript, TC-514, `R-TUI-100` + the two legend row amendments.

## Key decisions log
| Date | Decision | Source |
|---|---|---|
| 2026-07-30 | CRC = Variant B; Legend = Variant B | operator, verbatim in 01-requirements §6.2 |
| 2026-07-30 | KAT **demoted**, not removed (Gate-2 resolved by the B pick) | operator via variant choice |
| 2026-07-30 | ONE batch, both stories, full `/dev-flow` | operator invoked `/dev-flow`; both stories drift zero snapshots (P-2/P-3) so the two-batch split lost its rationale |
| 2026-07-30 | Backlog premise "CRC snapshot cells drift" is FALSE | executed probe, §2.7 P-2 |
| 2026-07-30 | **P-8 CONFIRMED — floor stacking = key first** | operator at the Phase-1 gate; PROPOSED default confirmed, not overridden |
| 2026-07-30 | **Standing auth GRANTED — full autonomy + merge** | operator kickoff Q1; merge still gated on a clean final PR-level qa pass |
| 2026-07-30 | **Phase-1 gate APPROVED** (Coverage ✅ · Evidence ✅ · Certainty gap = P-8, dispositioned by the answer) | operator; 0 Phase-1 iterations |

## Risks / watch-items
- `state.json` concurrency (batch-65 in flight, last-writer-wins).
- 32 tests in `test_crc_designer_view.py` = CRC blast radius; 3 legend test files
  (P-6). Reverse-grep again per increment (C-26).
- Prototype code is throwaway — REWRITE compose per PROJECT_RULES.md docstring/type
  conventions; do not copy `VariantB` verbatim.
- If ANY snapshot test fails during this batch, a premise was wrong — STOP, no casual
  regen (01-requirements §5.3.6).

## Out-of-scope carries (already in the canonical backlog, lane A)
- Legend variants for `map`/`a2l`/`issues` views were not shot-captured (runnable live).
- The four 2026-07-28 backlog bullets get reconciled at THIS batch's close: bullets 1
  (switches), 2 (KAT), 3 (design pass) close; bullet 4 (Legend) closes; the
  BACKLOG-PROCESS companion item (why `/tui-design` missed these) stays in lane B.

## Test ledger
**base = 2379**, measured `python -m pytest --collect-only -q` on 2026-07-30 @ `b556e35`
(the prep session's 2358 was stale by 21 — M-5). **`D = 1`**: LLR-072-2.4 deletes
`test_verdict_hero_center_aligned_in_hero_row` (AT-B59-05). `D = 1` is the **complete**
deletion set — re-gate confirmed the node is non-parametrized and
`grep -rl "_switch_row" tests/` → 0 files, so LLR-072-1.2's helper removal drops no TC.
`A` = 7 ATs + 10 TCs. Reconcile `post = base − D + A` at each gate.

## Prototype teardown (batch-close obligation)
DELETE `prototypes/crc_designer.p1.*`, `legend_p1.*`, `p1_design_defects.*`,
`p1_review_build.py`, `p1-design-defects-review.html`, `crc_p1.variant_*.svg`,
`crc_p1.shipped.*.svg`, `legend_p1.*.svg` once both stories merge (absorb-then-delete).
