# Review — s19_app — Batch 2026-06-09-batch-06

Phase 2 cross-review of `01-requirements.md` (US-001 — MAC↔A2L layout parity). Three reviewers ran in parallel against the live code (architect, qa-reviewer, security-reviewer). **architect and qa-reviewer independently found the same root-cause blocker.**

## Verdict
**ITERATE to Phase 1.** 2 blockers / 4 majors / 4 minors / 0 security. The DESIGN is sound and confirmed (`4fr:3fr` + `min-width:82` floor; Textual `min-width`-over-`fr` clamping **empirically verified working**; all `styles.tcss`/`app.py` `file:line` anchors byte-accurate; `shall`/`should` clean; symbol-citation clean). The blockers are **factual errors in the doc's predicted geometry and its superseded-test inventory** — caught before any code, exactly as the V-model intends. The fix is a documentation-correction pass, not a redesign.

---

## BLOCKERS (force Phase-1 iteration)

### B-1 — `body_w ≈ terminal − 6` is wrong at ≥120 cols (F-A-01 = F-Q-01, found by BOTH reviewers)
**Root cause:** `body_w` is **regime-dependent** because the workspace activity rail (`#workspace_shell.width-narrow #activity_rail`, `styles.tcss:781-786`) collapses below 120 cols:
- term ≥ 120 (rail shown): **`body_w = term − 24`** → at 120, body = **96** (not the doc's 114).
- term < 120 (rail collapsed): `body_w = term − 6` → at 119, body = 113.

The doc generalized a *narrow-regime* measurement (`test_tui_mac_layout.py:148` "~113 at 119") to the fixed regime where it does not hold. Every hard-coded prediction is wrong:
| Doc claim | Real (measured) |
|---|---|
| LLR-001.3: `round(3/7·114) ≈ 49` at 120 | `round(3/7·96) = 41` |
| LLR-001.5: records `≈ 32` cells at 120 | records = `96 − 82` = **14** (still ≥1 ✓) |
| §2.5: transition floor→proportional ~191 term cols | body≥192 ⟹ **term ≈ 216 cols** |

The runtime tests are robust (they read `#workspace_body.region.width` live), so only the **prose, thresholds rationale, and §6.3 starvation bounds** are corrupted — but per the symbol-citation rule, layout geometry asserted as fact with a wrong measurement is a blocker.
**Fix:** propagate `body_w = term − 24` (≥120) / `term − 6` (<120) through §1.3, §2.5, §6.3, HLR-001, LLR-001.3, LLR-001.5. Re-derive all cell counts.

### B-2 — Superseded-test inventory incomplete; a 3rd test still asserts the 35% regime (F-A-02 = F-Q-04)
qa-reviewer measured the real disposition of every batch-05 MAC test under the new model:
| Test | file:line | Under new model | Action |
|---|---|---|---|
| `test_mac_hex_pane_narrow_regime_unchanged` | `test_tui_mac_layout.py:139` | **FAILS** (asserts hex<82 at 119; floors to 82) | rewrite |
| `test_tc021_mac_two_panes_proportional_regime` | `test_tui_directionb.py:1399` | **FAILS** (asserts hex 31–39% of body at 80×24; becomes ~110%) | **rewrite — MISSED by the doc** |
| `test_tc021_mac_two_panes_fixed_regime` | `test_tui_directionb.py:1355` (band `:1389`) | band `hex≤84` breaks above floor | re-band (= TC-021′) |
| `test_mac_hex_pane_width_at_wide_terminal` | `test_tui_mac_layout.py:82` | **SURVIVES** (asserts `≥82` + `narrow==0` at 120) | none (doc wrongly lists as must-fix → F-Q-05) |
| `test_mac_hex_scroll_fills_pane_height` | `test_tui_mac_layout.py:102` | survives | none |
| `test_mac_records_pane_positive_width_at_wide_terminal` | `test_tui_mac_layout.py:171` | survives (= TC-006) | reuse |

§5.3 acceptance says "0 tests left asserting the 35% narrow regime" — `test_tc021_mac_two_panes_proportional_regime` (`:1399`) violates it and is unlisted. **Fix:** add `:1399` to the §5.2 must-rewrite list; correct the disposition table (`:82` survives, not must-fix).

---

## MAJORS

- **M-1 (F-A-03) — Design-intent surfacing for the operator.** With `body = term − 24` and floor = 82, MAC hex stays **pinned at 82 for all widths 120–215 cols** and only grows proportionally above ~216. Consequence: at common widths MAC hex (82) is actually **wider** than A2L hex (42 at 120) — the floor over-satisfies "full row readable" but does NOT "grow like A2L" until very wide terminals. This is the expected result of the operator's floor-priority choice (benefit = no truncation), but the architect recommends the operator explicitly confirm the tradeoff (or revisit the floor value). **→ raised at the gate.**
- **M-2 (F-A-04 = F-Q-02) — TC-005 continuity check verifies the wrong thing.** `|hex_w(121)−hex_w(119)| ≤ 3` passes only because the floor pins both sides to 82; the stated rationale ("no 35%→fr jump") is false — there IS a rail-driven body jump at 120, independent of MAC rules (proof: A2L's own hex jumps 49→42 across 119↔121). **Fix:** reframe TC-005 intent to "floor holds across the retired breakpoint (both sides = 82±3)", OR probe continuity at two widths both above the floor knee (e.g. 200 vs 210, same regime).
- **M-3 (F-A-05) — Records-starvation bound wrong.** Floored records = `body − 82`; with rail (≥120) records ≥1 ⟺ term ≥ 107; without rail (<120) ⟺ term ≥ 89. Replace §6.3's single "<~104 cols" with this dual bound; note the margin at 120 is only ~14 cells (tight but ≥1).
- **M-4 (F-Q-03) — TC-021′ target not pinned.** Pin to `test_tc021_mac_two_panes_fixed_regime` (`test_tui_directionb.py:1355`, band `:1389`) per the symbol-citation rule; state the new band `80 ≤ hex ≤ 86`.

## MINORS
- **m-1 (F-A-07)** — comment block `styles.tcss:264-270` update is mentioned in §6.2 but not a verifiable acceptance item; it is also **already stale** (says `width: 40`). Add an inspection criterion to LLR-001.6 ("0 references to `35%`/`width: 40`/`fixed-width` in MAC comments").
- **m-2 (F-A-08)** — clarify in §5.2 that the `git diff` byte-identity is the *authoritative* A2L-invariance guard; the `-k a2l` band test is a secondary behavioral backstop (a `3fr→43%` swap would pass the band but fail the diff).
- **m-3 (F-Q-05)** — disposition correction folded into B-2 (`:82` survives).
- **m-4 (F-Q-06)** — `min-width`-over-`fr` is now **empirically confirmed** (architect + qa both reproduced the clamp); downgrade the §2.5/§6.3 `assumed` flag to "confirmed in Phase-2 cross-review"; keep TC-004 as the regression guard.

## SECURITY — CLEAN (security-reviewer)
**OK to ship.** No security surface: no secrets, file I/O, deserialization, external tools, auth, or command execution — pure Textual CSS width tokens. No DoS vector (floor is a lower bound inside a fixed viewport; hex render volume capped upstream by `MAX_HEX_BYTES`/`MAX_HEX_ROWS`). The sub-107-col records-pane edge is graceful clipping (Textual shrinks the flexible `4fr` pane toward 0, renders empty — does not raise), and is correctly scoped out below the documented 120-col minimum. Deleting `width-narrow #mac_*` removes no security control.

---

## Phase-1 iteration fix list (for the architect/qa pass)
1. **[B-1]** Correct `body_w` to `term − 24` (≥120) / `term − 6` (<120) everywhere; re-derive all cell counts (120→96, 250→226).
2. **[B-2]** Add `test_tc021_mac_two_panes_proportional_regime:1399` to the must-rewrite list; correct the disposition table (`:82` survives).
3. **[M-2]** Reframe TC-005 / LLR-001.4 continuity claim (floor-holds, not no-fr-jump).
4. **[M-3]** Recompute §6.3 starvation bounds (term ≥107 with rail / ≥89 without).
5. **[M-4]** Pin TC-021′ to `test_tc021_mac_two_panes_fixed_regime:1355`; band `80 ≤ hex ≤ 86`.
6. **[m-1]** Add MAC-comment-block inspection criterion to LLR-001.6.
7. **[m-2]** Note byte-diff authoritative for A2L invariance.
8. **[m-4]** Downgrade the min-width-over-fr `assumed` flag to confirmed.
9. **[M-1]** Operator-confirm the floor tradeoff (or adjust floor value) — gate question.

---

## Phase-2 re-confirmation (after Phase-1 iteration #2 — 2026-06-09)

Operator decisions at the Phase-2 gate: **keep floor = 82** (M-1 tradeoff accepted) and **iterate to correct**. The orchestrator applied all 9 fixes to `01-requirements.md` and re-verified each finding closed:

| ID | Severity | Status | Evidence in `01-requirements.md` |
|----|----------|--------|----------------------------------|
| B-1 | blocker | **CLOSED** | §1.3 adds regime-dependent `body_w` term (`term−24` ≥120 / `term−6` <120); §2.5 measured-anchor bullet; LLR-001.3 `round(3/7·96)=41`; LLR-001.5 `body_w=96 → records=14`; HLR/§6.3 re-derived. grep: 0 stale `114`/`≈32`/`~49`/`round(3/7·114)`. |
| B-2 | blocker | **CLOSED** | §5.2 corrected disposition table lists `test_tc021_mac_two_panes_proportional_regime:1399` (REWRITE) + `:139` (REWRITE) + `:1355` (RE-BAND); marks `:82`,`:102`,`:171`,`:1438` SURVIVE. §6.4 anchors each test by exact line. |
| M-1 | major | **CLOSED** | §2.5 `[decided — Phase-2 gate]` + §2.6 decision (4) + §6.3 tradeoff bullet — floor 82 kept, ~216-col transition documented, operator-accepted. |
| M-2 | major | **CLOSED** | LLR-001.4 reframed: TC-005 = `test_mac_hex_floor_holds_across_retired_breakpoint`, asserts both sides floored (80–86); explicit note that the residual body discontinuity at 120 is the rail's, out of scope. |
| M-3 | major | **CLOSED** | §6.3 starvation bullet: records=`body_w−82`; ≥1 ⟺ term≥107 (rail) / ≥89 (no rail); 14-cell margin at 120. |
| M-4 | major | **CLOSED** | §5.2 TC-021′ pinned to `test_tc021_mac_two_panes_fixed_regime` (`:1355`, band `:1389`), new band `80 ≤ hex ≤ 86`. |
| m-1 | minor | **CLOSED** | LLR-001.6 acceptance + §5.2 TC-007 threshold: 0 stale MAC-comment refs (`35%`/`width: 40`/`width: 82`). |
| m-2 | minor | **CLOSED** | LLR-001.6 acceptance: `git diff` byte-identity authoritative for A2L; `-k a2l` band is secondary backstop. |
| m-4 | minor | **CLOSED** | §2.5 + §6.3: min-width-over-fr downgraded from `assumed` to **confirmed** (both reviewers reproduced the clamp). |

**Normative re-check:** `shall`/`should` — 0 mixed-modal in any HLR/LLR statement (grep verified); the m-1 comment-update obligation lives as a numeric pass threshold (informative phrasing), not a `shall` in acceptance criteria.

**Result:** 2/2 blockers + 4/4 majors + 4/4 minors closed in one iteration; 0 open; security unchanged (CLEAN). Recommend advancing to **Phase 3** (implementation).
