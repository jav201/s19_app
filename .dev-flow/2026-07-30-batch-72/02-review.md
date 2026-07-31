# Phase-2 Cross-Agent Review — batch 2026-07-30-batch-72

> Consolidated by the orchestrator from three independent parallel lane reviews:
> [`02-review-architect.md`](02-review-architect.md) · [`02-review-qa.md`](02-review-qa.md) ·
> [`02-review-security.md`](02-review-security.md).
> Artifact under review: [`01-requirements.md`](01-requirements.md) (Phase-1 approved 2026-07-30).

## BLUF

**9 blockers · 12 majors · 7 minors → `iterate` back to Phase 1.** The two *stories* are sound and
both defects are real — three reviewers measured them independently. What failed review is the
**acceptance layer**: four of the six ATs cannot go RED on the thing they claim to certify, one HLR
has no AT at all, and one HLR has **no implementable mechanism**.

The three findings that matter most, each reproduced by an executed probe rather than argued:

1. **G-1 is unsatisfiable by the planned change (A-3 / Q-1).** Two reviewers independently walked
   `#crc_designer_panel` at 120x30 and both counted **16 vertically-abutting focusable pairs**.
   Variant B fixes exactly **one**. Under the geometric reading AT-214 is RED *after* a perfect
   implementation; under the "interleaved label" reading it is **already GREEN today** (both shipped
   switch rows carry a `Label`), so it is invariant under the change it gates — C-40 limb 1. The
   abutment is not a defect: `styles.tcss:1941-1948` is batch-59's deliberate R9 compact-row
   decision.
2. **HLR-072-6 has no mechanism (A-2).** LLR-072-6.1 prescribes a `width-narrow` rule.
   `width-narrow` is applied only to `#workspace_shell` / `#workspace_body` (`app.py:6202-6208`),
   which live in the **base screen**; `LegendScreen` is a `ModalScreen` pushed on the stack
   (`screens.py:1030`, `app.py:5865`) and is a descendant of neither. Textual 8.2.8 has no media
   queries. The one HLR the operator was explicitly asked to confirm is the one that cannot be built
   from its own LLR.
3. **AT-216 is vacuous twice over (Q-4 / Q-5).** `Pale yellow` is real (`legend.py:142`), but the
   **first** widget matching it is a *card* caption (`legend.py:718`) — in the pane the assertion is
   meant to look away from. And the `render().plain` harness every shipped legend test uses is
   geometry-blind: proven **today**, with the key row at `Region(x=22, y=27)` entirely outside
   `body.region=Region(22,6,76,15)` at `scroll_offset=0`, the harness still returns `True`. The one
   clause AT-216 exists to certify is the one that harness cannot see.

**Convergence is the strongest signal in this review.** The architect and qa lanes ran different
probes, in different scratchpads, and arrived at the same 16-pair census and the same conclusion
about G-1. Independent rediscovery is what upgrades A-3/Q-1 from an opinion to a measurement.

**Security is clean on design** — 0 blockers. No new I/O, network, dependency, or external tool.
The single major (S-1) is that §2.4 asserts a `markup=False` invariant that **no test enforces for
2 of the 6 CRC sinks**, in a batch that rewrites the very `compose` setting those kwargs.

---

## Findings by lane

### Blockers (9)

| # | Lane | Finding | Why it blocks |
|---|---|---|---|
| **A-1** | architect | HLR-072-2 deletes `#crc_live_verify`; the shipped `AT-B59-05` (`tests/test_crc_designer_view.py:1003-1047`) `query_one`s it and asserts four properties — while §5.3.3 requires that file green | Internally unsatisfiable pair. Phase 3 hits a hard stop mid-increment, and the cheap way out is to silently weaken a batch-59 requirement the operator approved |
| **A-2** | architect | HLR-072-6's floor-stacking mechanism cannot reach a modal | The only HLR the operator was asked to confirm has no implementation path; Phase 3 would improvise one with no requirement governing it |
| **A-3** | architect | G-1 unsatisfiable — 16 abutting pairs measured, 1 fixed | AT-214 is RED after a correct implementation; its mandated C-40 counterfactual proves nothing because the assertion is RED on both sides |
| **A-4** | architect | G-2's acceptance proves handler wiring, not state legibility | The state word was **Variant A's** fix (`NOTES.md:66`); B was chosen and "steals nothing" (`:104`). Ships a green guard that cannot fail on the axis it names |
| **Q-1** | qa | Same as A-3, independently derived + the label-reading limb | `_switch_row` already emits a `Label` per row (`crc_designer_view.py:465-469`), so the disjunct is satisfied pre-batch |
| **Q-4** | qa | AT-216's `Pale yellow` matches a **card** caption | The AT would go green on an implementation that renders the key pane empty |
| **Q-5** | qa | AT-216's "without scrolling" is invisible to `render().plain` (project C-32) | Proven vacuous on the shipped tree, on the exact axis the story exists to fix |
| **Q-8** | qa | HLR-072-4 has no AT node — "TC-level + an assertion inside AT-213's run" | C-18 violation: an acceptance realized in parts and smuggled into another AT's node. AT-213 already carries four subjects |
| **Q-9** | qa | Test-ledger base stale — `pytest --collect-only -q` reads **2379**, not 2358 | `post = base − D + A` is corrupted at every later gate |

### Majors (12)

| # | Lane | Finding |
|---|---|---|
| **A-5** | architect | Every numeric geometry commitment (`Select height:3`, `3fr`/`2fr`, `96%`, "80-col floor") is inherited from the prototype with **zero** measurement on the shipped tree — C-13/C-23/C-29. Measured counter-evidence: legend body is `h=15` @120x30 and **`h=9`** @80x24 against ~18 rows of key content |
| **A-6 / S-3** | architect + security | `#legend_body` omitted from HLR-072-7's preserved-id list despite **9** descendant query sites across the 3 blast-radius files + `REQUIREMENTS.md:3352`. Per C-38 a narrowed query that empties still *passes* many assertions |
| **A-7** | architect | LLR-072-2.1's "delete `verdict_group`" drops `Label("Known answer · 123456789")` — the **only** on-screen naming of the KAT reference vector (1 hit repo-wide). Also the wrong verb: the operation must *preserve* a child |
| **A-8** | architect | §5.3.5's REQUIREMENTS.md amendment target does not exist — `crc_live_verify` / `verdict hero` / `crc_bench` / `Designer` all return **0 hits**. The batch-59 bench layout was never registered |
| **A-9** | architect | Derivation gaps: HLR-072-4 has no parent story; HLR-072-3 has no LLR and is a requirement on *the batch*, not the product — which is *why* A-3/A-4 could hide |
| **A-10** | architect | Focus/keyboard traversal unowned (C-16). `ScrollableContainer.can_focus == True` measured; one focusable container becomes two. **G-3 and G-4 vanished** between the handoff plan and §3 with no disposition |
| **Q-2** | qa | AT-214's counterfactual has two wrong-reason failure modes: reverting `crc_designer_view.py` wholesale makes it *error* (not assert), and reverting only `styles.tcss` may not move the geometry at all — the fusion is partly a *compose* fact |
| **Q-6** | qa | `refin` defaults **True**, the opposite of what AT-213 implies. Measured transition: `0xCBF43926 → 0x1898913F` |
| **Q-7** | qa | AT-215 names no value. Two near-misses: clearing the field gives `○ NO-EXPECTED`; non-hex gives `"Invalid parameters: …"`. Clean drive is `0x00000000` |
| **Q-checklist-9** | qa | Four of the six `_recompute` ids (P-4's own subject) are observed by **no AT** |
| **AT-218** | qa | Must read `render().spans` per project C-37, not `render_line` (which reads the theme foreground). It is a **regression pin, not a gate** — label it so per C-40's corollary |
| **S-1** | security | §2.4's C-17 claim is unverified for `#crc_custom_vector_result` and `#crc_coverage_preview` — no `_render_markup` assertion exists. Reachable payload: `_recompute:1127-1135` echoes user-typed text into all six sinks |

### Minors (7)

`A-11` undefined terms (*"wide regime"* = `width >= 120` at `app.py:6202`, uncited; *"focusable
control"* undefined; the *"interleaved label"* disjunct unreachable) · `A-12` §4 LLRs are one-line
sketches, TCs are reservations · `A-13` section numbering (§1.3, §2.1-2.3 missing) · `Q-3` AT-217 is
the healthiest AT; needs *"reachable under scroll"* wording (floor budget measured at 9 rows vs an
11-row MAC key) · `Q-12` six zero-area `SelectOverlay` phantoms pollute a naive `can_focus` walk ·
`S-2`/`S-2b` TC-N8-11 is data-level and gives the render layer no protection; the permitted grouping
helper may wrap but must not reconstruct rows · `S-4` the `.sev-*`/`.band-*` hue values live in the
editable `styles.tcss` and no snapshot would catch a drift.

---

## What came back CLEAN — recorded so it is not re-litigated

| Axis | Verdict | Evidence |
|---|---|---|
| §2.4's six `_recompute` ids | ✅ exactly right; `#crc_live_verify` is **not** among them, so deleting the hero wrapper removes no queried id provided `#crc_kat_verdict` is re-parented | `crc_designer_view.py:1115-1121` |
| `_render_key` preservation (HLR-072-7) | ✅ sound — returns a flat `List[Widget]`, emits no container, map branch included | `screens.py:1132-1192` |
| Normative modal discipline | ✅ zero `should` in the document; every `shall` inside an HLR statement | executed grep, whole doc |
| C-27 frozen test files | ✅ none of the 4 target test files is in `_ENGINE_TEST_FILES` | `test_tui_directionb.py:5494-5505` |
| Frozen-source set | ✅ intersection with §1.2 IN-scope is **empty** | `CLAUDE.md` vs §1.2 |
| ID census | ✅ AT-213..219 and TC-510..519 free (prior max AT-212 / TC-509) | re-executed excluding this batch's own dir |
| Premises P-2, P-3, P-4, P-5 | ✅ re-verified TRUE by a second reviewer | 0 CRC/legend snapshots; six ids; AT-B59-03/08 teeth |
| Both defect premises | ✅ measured directly — switches fused at `y=32`/`y=33` `h=1` borderless; key below the fold at `max_scroll_y=24` | qa probes |
| Legend re-parent markup safety | ✅ safe by construction — `markup=` is a per-widget flag, not inherited | `screens.py:1160-1192` |

---

## Premise re-evaluation (C-43) — what Phase 2 did to §2.7

| Premise | Was | Now | Basis |
|---|---|---|---|
| **P-9** (switch-separability guard is encodable as an AT that fails on the old CSS) | ❓ UNDECIDABLE | ❌ **FALSE as scoped** | Q-1 — unauthorable in both readings. Resolves by re-scoping, not by trying harder |
| **P-6** (reverse census) | ✅ TRUE | ⚠️ **TRUE but imprecise, and it hides a gap** | The legend half holds only as a *union*; `crc_algorithm_fields`, `crc-field-switch` and `_switch_row` are pinned in **zero** test files — new obligations, not preserved ones |
| **P-5** (AT-B59-03/08 survive) | ✅ TRUE | ✅ still TRUE — **but incomplete**: the file's *other* AT, `AT-B59-05`, does **not** survive (A-1) | §2.7 P-5 itself flagged "full blast-radius re-read owed at Phase 2"; this review is that re-read and the debt came due |
| **P-7** (Variant B renders live) | ✅ TRUE | ✅ TRUE for the *wide* case only — the **floor case was never prototyped** (the B prototype has no narrow rule at all) | A-2 / A-5 |
| **NEW P-10** | — | geometry commitments unmeasured on the shipped tree | A-5 → closed by `00-measurements.md` |

---

## Gate decision

**`iterate` back to Phase 1 — 9 blockers.** Per the flow's own rule, blockers force the iterate; no
judgment call is involved.

**Exit-criteria axes, named per the objective-exit-criteria rule:**

- **Coverage** ❌ — HLR-072-4 has no AT (C-18); HLR-072-3 has no LLR; HLR-072-4 has no parent story;
  four of the six `_recompute` ids are observed by no AT.
- **Certainty** ❌ — the dominant failure. AT-214 and AT-216 cannot go RED on what they claim to
  certify; AT-218 is a pin mislabelled as a gate; AT-213/AT-215 name no values.
- **Evidence** ❌ — four geometry numbers carry no measurement and no `assumed — measure` label;
  the ledger base is stale by 21; §5.3.5 points at a REQUIREMENTS.md row that does not exist.

All three axes are unmet, each with named gaps. That is a well-formed `iterate`, not a vague one.
</content>
