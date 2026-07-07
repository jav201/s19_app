# 05 — Post-Mortem — 2026-07-06-batch-27 — R-TUI-041 Interactive Memory-Map Minimap

Co-authored: architect (process/root-cause) + qa-reviewer (metrics/ledger).

## BLUF
A clean full `/dev-flow` run (Phase 0→4 all PASS, 0 blockers at Phase 4). Test count **1037→1058** (net +21, `1058 = 1037 − 3 + 24`). **1 blocker + majors/mediums all closed; 3 non-blocking carries.** No phase hit the soft 3-iteration cap. The two most valuable moments were both **pre-code catches** — the Phase-2 markup-injection blocker and the mid-Inc-2 arrow-nav gap — and both trace to ONE meta-root-cause: **a controlled-data, cross-tech (HTML) prototype created confidence about outcomes the Textual implementation had never been proven to deliver** (untrusted-input safety; real framework interaction). Prototype-first de-risked *design* correctly but was a false-confidence surface on those two axes; rigorous review + a hardened AT closed both.

## 1. What worked (mechanism)
- **Prototype-first settled the 3 design decisions** (auto-scale, reflow, issue-anchoring) at the Phase-0/1 gate → Phases 1–3 executed against a fixed target.
- **Security engaged at Phase 2, independently** — architect (MAJOR-1) + security (F1) converged on B-1 *before code*; fix was a requirements edit (LLR-041.11), zero code rework. Two reviewers converging = evidence the finding is real.
- **C-13 geometry COMPUTED, not assumed, and held** — 120-col: 98 body − 36 detail = 62 grid (positive); the "ONE fixed sibling" insight distinguished it from the Workspace 3-pane overflow. Inc-3 *measured it live* (grid 50@x26 / detail 36@x78 same-y at 120; stacked at 80). Prediction == measurement.
- **The faithful black-box AT caught the arrow-nav gap** — hardening AT-036a from `.focus()` to real `press("right")` exposed unwired arrows. Black-box-behavioral-acceptance discipline paying off.
- **Parallel batch-26 handled cleanly** — took id 27, verified R-TUI-041 free, overlap assessed BENIGN once, rebase deferred to PR (not re-litigated per increment).
- **Legitimate supersession** — R-TUI-026 → superseded (statement preserved); removed TC-025 tests asserted the old text format, no survivor asserts old output (reviewer-confirmed).

## 2. What didn't / friction
- **Arrow-nav rework (Inc-2 F1 → follow-on)** — the largest friction: prototype demoed arrows + spec assumed `press("right")` + Textual never wired arrows + AT masked it with `.focus()`. Absorbed cleanly (0 engine diffs, review 0 HIGH; ledger 1049→1052) but was pre-emptable rework.
- **Transient docstring overclaim** — the panel docstring claimed "arrow-key navigable" while unimplemented — arguably the **3rd sighting** of the overclaim-docstring pattern (batch-22 logged "watch for 3rd").
- **Coverage-% `.6f` display** unresolved-by-polish (operator kept; value correct, reads oddly for sparse/dense).
- **Snapshot baselines xfail** — batch doesn't fully close until canonical-CI regen + xfail retirement post-merge.
- **Pre-existing full-suite TUI global-state flake** — costs a control run to disprove regression every batch; unaddressed (not batch-27's).

## 3. Scope drift
**No true creep. One in-scope recovery.** Arrow-nav looks like mid-Inc-2 drift but US-036 explicitly promises "click **or keyboard navigation**" and LLR-041.4 "click or keyboard focus/Enter" — wiring arrows closed a hole in *committed* scope, not new scope; operator-chosen with two bounding directives (no conflict, discoverable). Everything else inside the declared surface: ≤5 files/increment, single app.py call-site as planned, 0 engine-frozen diffs, out-of-scope carries (R-3 region naming, Bookmarks, Variants A/C) held.

## 4. Root-cause analysis (deep why)
**B-1 markup injection:** surface = `markup=False→True` sent file-derived `.message`/`.symbol`/`.code` into a Rich-markup sink; `_scrub_issue_message` strips ANSI not `[`/`]`, never touches `.symbol`, is frozen (false comfort). **Deep:** the prototype rendered CONTROLLED data → the untrusted-input surface was *structurally invisible* in the artifact that drove approval; the render-mode change that CREATED the sink was a side effect of a visual (colour) requirement. Caught because reviewers reason about code-path + input provenance, not the demo.

**Arrow-nav gap:** surface = `on_key` handled only Enter; Textual has no default spatial arrow-focus; AT used `.focus()`. **Deep, two independent causes:** (1) a prototype in a DIFFERENT tech than the target does not prove the target framework's interaction behavior — HTML/JS focus says nothing about Textual arrow-focus; the requirement inherited "arrows work" from a non-target tech. (2) an AT driving a PROXY (`.focus()`) instead of the promised mechanism (arrow keys) doesn't verify the story's actual promise — promise and proof drifted; the gap surfaced only when the AT was hardened to the real mechanism.

**Meta-root-cause:** the prototype is the right tool for *design* de-risking; it is NOT evidence for *input-safety* or *target-framework behavior*.

## 5. Candidate controls / lessons — CANDIDATE ONLY (operator decides encoding; never self-encoded per [[feedback_devflow_control_encode_approval]])
- **CANDIDATE C-16 — prototype-fidelity gap:** when a story's interaction promise (keyboard/pointer/focus/animation) is demoed in a prototype built in a DIFFERENT tech than the shipping target, the requirement flags that interaction `assumed — verify in target framework at Phase 3`, and the black-box AT MUST exercise the REAL mechanism (press the actual keys), never a proxy (`.focus()`). Interaction-layer sibling of C-13 (geometry) / C-15 (runtime identity). Origin: Inc-2 arrow-nav.
- **CANDIDATE C-17 — controlled-prototype-data hides untrusted-input surfaces:** an increment that flips any render mode to interpret markup/ANSI/HTML/templates over file-derived/untrusted text owes a markup-safety LLR + a hostile-input AT (bracket/ANSI/link payload) at Phase 1, not as a Phase-2 catch — the approving prototype rendered controlled data and cannot reveal the sink. Origin: B-1 (would have moved it Phase-2-catch → Phase-1-designed-in).
- **WATCH (not encode) — overclaim-docstring 3rd occurrence:** the "arrow-key navigable" docstring is arguably the 3rd sighting of docstring-overclaims-behavior (batch-22 watch-for-3rd). Operator decides whether it crosses the encode threshold.

## 6. Metrics ledger (qa)
- **Iterations/phase:** P0 0 · P1 1 (iterate-to-refine) · P2 1 (blocker→re-gate) · P3 0 gate-reiterations (3 increments + 1 follow-on, each single-pass) · P4 0. No 3-cap hit.
- **Findings:** Phase-2 = 1 blocker + 4 majors + 6 minors → all closed; increment reviews = 0 HIGH each, MEDIUMs = CARRY-F2 (carry), Inc-2 F1 (→arrow-nav, closed), Inc-3 F2 (.6f, operator-kept); LOWs no-action.
- **Test ledger:** 1037 → 1039 → 1049 → 1052 → 1058. D=3 (superseded TC-025 text-list), A=24 (14 white-box TC + 11 black-box AT incl. strengthening splits). Balance ✓.
- **Coverage:** LLR-041.1–.11 each ↔ ≥1 TC (14 nodes); US-035/036/037 each ↔ ≥1 AT (11 nodes); 0 orphan, 0 uncovered.
- **Gates:** 0 engine-frozen diffs (all 3 increments); ruff clean; mypy 0 new; author + independent code-reviewer per increment (+ arrow-nav 2nd pass); Phase-2 tri-review. directionb+guard 122 passed; snapshot 30 passed/2 xfailed.
- **Verify vs claim:** all 25 nodes + guard evidenced by real pasted output; ONLY pending = the 2 map SVG cells' pixel-level baseline (xfail, canonical-CI regen post-merge) — their behavioral content is independently green (AT-035 colors/header; TC-041.10 reflow; arrow/no-scroll AT).

## 7. Items proposed for next batch / close
1. **Baseline regen + xfail retirement** (canonical CI, pinned textual 8.2.8; local FORBIDDEN) — batch-27 doesn't fully close until this lands.
2. **CARRY-F2 lock** (`_EXPECTED_MAP_CELLS_120x30=128`) update in lockstep with regen.
3. **Coverage-% precision** — `.6f` vs adaptive `%g` (operator decision, deferred).
4. **Bookmarks dead-screen** (separate P1 gap, carried).
5. **A2L-symbol region naming / per-cell tooltips** (R-3 deferred) — natural minimap polish.
6. **Pre-existing full-suite TUI global-state flake** — standing cross-batch cleanup candidate.
