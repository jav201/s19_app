# Post-mortem — s19_app — 2026-05-20-batch-02

**Phase:** 5 — Post-mortem
**Iteration:** 1
**Date:** 2026-05-21
**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Branch:** `dev-flow/batch-02-direction-b-restyle` @ `701a849`
**Source artifacts:** `state.json` (`decisions_log`), `01-requirements.md`, `02-review.md`, `03-increments/increment-plan.md` + `increment-001.md` … `increment-012.md` + `keymap-proposal.md`, `04-validation.md`
**Author:** `architect` agent — synthesizing the architecture/process perspective and the QA/quality/metrics perspective (Phase 4 QA evidence authored by the `qa-reviewer` in `04-validation.md`)

---

## 0. Executive summary

Batch-02 restyled the `s19tui` Textual TUI to the "Hex Lab — Direction B" visual language (left activity rail + top command bar + a single-context workspace of 8 screens, re-skinned modals, Calm Dark theme, density toggle). It was a **strictly view-layer batch**: the parsing/validation/service engine was frozen, no new runtime dependency was added.

The batch ran the full V-model dev-flow in 5 phases over **19 iterations** (Phase 1: 4, Phase 2: 2, Phase 3: 12 increments, Phase 4: 1, Phase 5: this document). It closed Phase 4 with a clean gate:

- pytest suite **275 → 419 passing** (net +144), **0 failed, 0 regressions** across all 12 increments.
- The engine-freeze `git diff main` over the 7 frozen modules is **empty — zero bytes changed.**
- All **15 HLR / 38 LLR / 38 active TC** verdict `pass`; all **9 batch acceptance criteria AC-B1..AC-B9** met.
- Phase 2 raised **24 findings** — all 24 closed before Phase 3, plus 5 cosmetic CV items folded into increment 1.

| Phase | Iterations | Artifact | Key result |
|---|---|---|---|
| 1 — Requirements | 4 | `01-requirements.md` | 14 US, 15 HLR, 38 LLR, 38 active TC; 13 OQs resolved |
| 2 — Cross-agent review | 2 | `02-review.md` | iter 1: 0 blockers / 11 majors / 13 minors / 2 info; iter 2: all 24 closed + 5 CV cosmetics |
| 3 — Implementation | 12 increments | 12 packets + `keymap-proposal.md` | +144 tests, engine zero-diff, 8 screens shipped |
| 4 — Validation | 1 | `04-validation.md` | verdict `pass-with-gaps`; 0 blockers; 4 documentary gaps |
| 5 — Post-mortem | 1 | this document | recommend **close-batch**, open follow-up batches B-3A..B-3D |

**Recommendation: `close-batch`.** The batch deliverable is complete and independently validated; the deferred scope (CRC engine, patch logic, bookmark persistence, PDF export) and the documentary gaps are well-scoped follow-up batches, not reasons to keep batch-02 open.

---

## 1. Batch summary

### Objective

Re-layout the existing `s19_app/tui/` package to Direction B ("Rail + Command") and add the new Direction B view screens. Per `state.json`: *"Restyle the s19_app Textual TUI to Direction B (Rail + Command). View-layer only: no data-processing changes, no new runtime dependencies."*

### What shipped

- **Calm Dark theme** — the inline `S19TuiApp.CSS` (~280 lines) extracted to a `styles.tcss` file, then re-themed: one accent hue (`$accent-calm` cyan-blue `#4ec9d4`), dark-only background/foreground/rule tokens, the five `sev-*` severity classes retuned but with class names and semantics unchanged.
- **Activity rail** — a new `rail.py` (`Rail` / `RailItem` widgets): 8 ordered items on keys `1`–`8`, the normative glyph→screen table (`◫ ≡ ◉ ▤ ! ✎ ⏚ ✶` + ASCII fallbacks), a single accent-marked active item, collapsing to an icon-only 4-column width below the 120-column breakpoint.
- **Command bar** — a new `command_bar.py`: a `Ctrl+K` type-to-filter command palette built 1:1 from `BINDINGS`, a `/` find input, a `g` go-to-address input, and the project/A2L context labels relocated from the retired Status tile.
- **8 single-context screens** — Workspace (3-pane re-layout), A2L Explorer, MAC View, Issues Report (promoted to a dedicated screen) — all restyles of working screens; Memory Map, Patch Editor, A↔B Diff (new view scaffolds); Bookmarks ("coming soon" placeholder).
- **Re-skinned modals** — Load / Save / Load-Project modals re-skinned to the Calm Dark tokens.
- **Density toggle** — `Ctrl+D` cycles compact/comfortable; a two-regime width layout (fixed pane widths ≥120 columns, proportional below) resolving the A-03 contradiction.
- **Engine frozen** — `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` byte-identical to `main`.

### What did not ship (deferred by design, C-5)

CRC/checksum computation engine, patch apply/undo/redo logic, bookmark persistence, A↔B diff computation (the Diff screen is a static placeholder), PDF report export. These are carried to follow-up batches — see §7.

---

## 2. What worked

### 2.1 Verbatim-CSS-extraction-then-retheme (architecture)

The single highest-leverage technical decision was increment 1's two-step approach: (a) move `S19TuiApp.CSS` **verbatim** into `styles.tcss` and switch to `CSS_PATH`, confirm the app renders identically (full suite green + a `run_test()` smoke that finds a styled widget), **then** (b) layer the Calm Dark tokens on top. This separated a pure mechanical refactor from a deliberate visual change, so any rendering regression had exactly one of two causes and could be localized. It also meant theme work for the remaining 11 increments touched a `.tcss` file rather than churning `app.py` on every increment — a clean decoupling that held for the whole batch.

### 2.2 Verbatim widget-subtree reuse (architecture)

Every restyled screen (Workspace, A2L Explorer, MAC View, Issues Report) was re-laid-out by **re-nesting existing widget subtrees into new containers** while keeping every inner widget id stable — so no `update_*` renderer was modified. Increment 6's A2L/MAC re-layout is the clearest example: the highest-regression-risk area in the codebase (`R-A2L-*`, `R-TUI-018/019/020`) was restyled with **zero renderer edits** because `update_a2l_tags_view`, `_filter_a2l_tags`, the paging actions and the MAC overlay highlight all kept the ids they query. This is what made the engine freeze achievable without an awkward parallel renderer set.

### 2.3 Engine freeze verified at zero diff (architecture + QA)

HLR-014 — the master no-regression requirement — was validated at the strictest possible level. The Phase 4 `git diff --stat main` over all 7 frozen modules returned **empty output, zero bytes changed**; the 9 engine test files are byte-identical to `main`. TC-031's cosmetic-only rubric was *vacuously satisfied* (nothing to classify). The `render_a2l_view` / `a2l_render.py` view-layer carve-out from finding A-01 turned out not to be needed at all — the A2L re-layout was achievable purely by re-nesting in `app.py`. A "view-layer-only" claim is easy to assert and hard to prove; the zero-diff evidence proves it.

### 2.4 Foundation-first increment ordering (architecture)

The 12-increment sequence — theme tokens → app shell + routing → rail → command bar → restyled screens → modals → new scaffolds → no-regression sweep → snapshot matrix — sequenced dependencies so each increment shipped a runnable `s19tui` and consumed only what earlier increments delivered. The dedicated cross-cutting test increments (11 = binding/reachability/engine-freeze sweep; 12 = snapshot matrix) were correctly placed last, because they cannot be scoped to a single screen and the snapshot baselines cannot be blessed until all 8 screens exist. The ≤5-files-per-increment cap held on **all 12 increments** (increment 1's 4 code/config/test files + 2 dev-flow docs; increment 9 at the cap with the LLR-014.2 carve-out edit) — no separately-gated follow-up was needed, unlike batch-01's increment 1.5.

### 2.5 Three security passes folded into the flow (architecture + security)

The increment plan pre-identified the three security-sensitive surfaces and routed each to a `security-reviewer` confirmation at its own gate, with the evidence captured in-packet: increment 4 (command bar — new input surface, S-1: TC-008/009 AST guards proving no new parsing/decoding code), increment 8 (modals — path containment, S-4: `workspace.py` byte-identical + TC-034 `..\..\` traversal sub-case), increment 12 (snapshot baselines — client-data leak, S-2: a 0-match grep over all 27 committed `.svg` for client tokens). Security was designed into the increment plan, not bolted on at the end.

### 2.6 Suite growth 275 → 419 with zero regressions (QA)

The suite grew by **+144 tests** across 12 increments — `275 → 284 → 291 → 308 → 314 → 327 → 338 → 347 → 359 → 373 → 389 → 419` — and the progression reconciles exactly: each increment added precisely its own new cases and never regressed a prior one. The 27-baseline `pytest-textual-snapshot` matrix is a genuine layout-drift guard rendering every restyled/scaffold screen at every density × size. Every one of the 38 LLR maps to at least one passing TC; AC-B was satisfied 9/9.

---

## 3. What didn't / friction

### 3.1 The handoff `PLAN.md` carried an outdated "replace the CLI" framing

The Hex Lab handoff `PLAN.md` proposed building a from-scratch `hexlab/` package and adding `bincopy` / `pya2l` / `crcmod` runtime dependencies "to replace the CLI." This was **factually obsolete** — `s19_app` already ships a full TUI and engine. Phase 1 had to explicitly reject the framing (constraints C-2, C-3) and re-target every requirement at evolving the existing `s19_app/tui/` package. This consumed Phase 1 effort that a current handoff document would not have. **Learning:** an incoming design handoff must be reconciled against the actual codebase state before it is used as a requirements input — a handoff is a reference, not a contract.

### 3.2 A-03 — the layout contradiction surfaced only in Phase 2

The fixed-width pane mandate (rail 22 + side panes 22 + 40 = 84 columns of fixed chrome) was logically irreconcilable with the 80×24 supported-minimum no-clip mandate. This is a genuine internal contradiction — an implementer cannot code a layout against two mutually exclusive targets — and it was caught by the architect review in Phase 2, not authored cleanly in Phase 1. It forced a product-owner decision (the two-regime breakpoint layout) and was the single must-fix-before-Phase-3 item. It cost a Phase 1 iteration to fold the resolution back in. See the root-cause analysis in §6.

### 3.3 The increment-3 latent CSS defect found in increment 5

Increment 3's collapsed-rail rule was keyed `#workspace_body.width-narrow #rail_slot`, but `#rail_slot` is a **sibling** of `#workspace_body`, not a descendant — so the descendant selector never matched and the rail did not collapse below 120 columns. The defect shipped in increment 3 and lay latent for two increments because no increment-2/3 test exercised the rail width at 80×24; it surfaced in increment 5 when TC-017 first asserted the collapsed 4±1 rail. It was fixed in-scope in increment 5 (toggle `width-narrow` on `#workspace_shell` too, re-key the rule). **Learning:** a CSS rule that no test exercises is unverified — a passing suite did not mean the rule worked. The snapshot matrix (increment 12) would eventually have caught it, but two increments later.

### 3.4 `ruff` and `pytest-textual-snapshot` not pre-installed

`ruff` was absent from the Phase 3 environment for **increments 1–11**; each substituted `python -m py_compile` on every changed Python file and recorded `ruff` as a pending item. `pytest-textual-snapshot` was likewise not installed until increment 12 (where it was needed and did install cleanly). The `ruff` gap means lint-style hygiene (import order, unused names, formatting) is **unverified across the whole batch** — carried to Phase 4 Gap 2 and into the follow-up list. The mitigation (every file compiles; `styles.tcss` is parsed by the Textual engine on every `run_test()` case) covers correctness but not style.

### 3.5 The `SendMessage`-style re-dispatch cost in the command bar

The command bar is presentational and emits messages; the app routes them. Wiring this to the *existing validated handlers* without adding parsing code cost real friction in increment 4: `_handle_goto` takes no address argument (it reads `#goto_input` off the widget tree), so the command-bar go-to input had to carry the id the existing handler already reads, and a 2-line view-layer adapter copies typed text into `#search_input` / `#goto_input` before calling the unchanged handler. Several Textual-version interactions also had to be worked through — `run_action` is async in Textual 8 (an interim non-async version produced a `RuntimeWarning`); the `Input` widget's own `ctrl+k`/`ctrl+d` line-editing bindings shadow the app's palette/density bindings unless the app bindings are marked `priority=True`. The constraint "route to existing handlers, add zero new parsing code" was the right call (it kept the attack/defect surface frozen) but it was not free.

### 3.6 The worktree-isolation / `#view_bar`-retirement ripple

Retiring the `#view_bar` button bar (increment 2) was a planned Direction B change, but it removed `settings_button` — the only trigger for the `#settings_menu` overlay. The settings menu became orphaned (composed and callable, but with no key/UI path to open it) and the carried-forward pending item rippled across increments 2 and 3 before being resolved in increment 4 by resurfacing it as a "Viewer settings" command-palette entry. A retirement that removes a UI element should enumerate everything that element was the sole entry point for, in the same increment.

### 3.7 Headless-only verification across the batch

All Phase 3 verification and the Phase 4 run are headless (`App.run_test()` / `pytest` / computed-style read-back). Increments 6–10 each carry a "Manual TUI pass" pending item — real-terminal eyeballing of border glyphs, font metrics, the dimmed modal backdrop, the Memory Map fill bars, and resize behavior across the 120-column breakpoint. The 27-baseline snapshot matrix is a strong automated mitigation, but the residual subjective-aesthetics surface was never visually confirmed. This is Phase 4 Gap 1.

---

## 4. Scope drift

**Net assessment: scope was held. Zero unapproved scope drift.** Two items warrant explicit examination because they look like drift but are not:

| Item | Increment | Assessment |
|---|---|---|
| Increment-3 latent CSS-defect fix | 5 | **In scope — not drift.** Fixing the sibling-selector defect was directly necessary to satisfy increment 5's own LLR-008.1 (the two-regime layout including the collapsed rail). It was the minimal correct fix, fully disclosed in the increment-5 packet §1/§5, and verified by TC-017. Repairing a latent defect that blocks the current LLR is in-scope corrective work, not feature creep. |
| Settings-menu palette resurfacing | 4 | **In scope — not drift.** Increment 2's planned `#view_bar` retirement orphaned the `#settings_menu` trigger. Increment 4 resurfaced it as one "Viewer settings" command-palette entry beyond the `BINDINGS`-derived set. This is *required* to satisfy C-9 (keyboard reachability) — a mouse-reachable action that lost its only path must regain one. It was an explicit owner-decision item flagged in the increment-2/3 packets, decided before increment 4, and is one palette entry, not a feature. |

Every increment delivered exactly its approved LLR set. No new processing module was added (TC-028 AST-guards this positively); `bincopy` / `pya2l` / `crcmod` are absent from both the new modules' imports and `pyproject.toml`. The `EmptyStatePanel` empty-state wiring (LLR-002.3) added in increment 7 was an *explicitly scoped* LLR, deferred there from increment 2's scope note, not an unrequested add. The `pytest-textual-snapshot` dev-only optional dependency was the approved C-2 scoped exception (OQ-5), declared under `[project.optional-dependencies]`, never under runtime `dependencies` — its transitive `syrupy` is implied by that approved extra, not a new unapproved dependency.

The two cross-cutting test increments (11, 12) added test code only and no production behavior — by design. The one production-test edit outside an increment's own test file (increment 9's 2-line `test_tui_app.py` monkeypatch for the new `update_memory_map` renderer joining the deferred-load chain) is the explicit LLR-014.2 carve-out ("update pre-batch UI tests to the new layout without weakening intent") and was disclosed, counted against the file cap, and *strengthened* the test (it now also asserts the Memory Map refresh runs in the finalize step).

---

## 5. Metrics

### 5.1 Iterations per phase

| Phase | Iterations | Notes |
|---|---|---|
| 1 — Requirements | 4 | Iterative growth: handoff reconciliation, 13 OQ resolutions, A-03 product-owner decision, folding all 24 Phase-2 findings + 5 CV items |
| 2 — Cross-agent review | 2 | iter 1 = parallel architect + qa + security review; iter 2 = closure verification |
| 3 — Implementation | 12 increments | One increment = one supervised gate; ≤5-file cap held on all 12 |
| 4 — Validation | 1 | Single clean pass; no rollback forced |
| 5 — Post-mortem | 1 | This document |
| **Total** | **19** (4+2+12+1) + Phase 5 | |

### 5.2 Findings raised vs closed

| Source | Raised | Closed | Open at gate |
|---|---|---|---|
| Phase 2 iteration 1 | 24 (0 blockers · 11 majors · 13 minors · 2 informational) | 24 | 0 |
| Phase 2 iteration 2 (closure scan) | 5 new (CV-01..CV-05, all minor/cosmetic) | folded into increment 1 | 0 |
| Phase 3 increments | 0 new findings | — | 0 |
| Phase 4 validation | 0 findings; 4 documentary **gaps** recorded | carried to Phase 5/6 | 0 (none gate-blocking) |
| Security passes | 3 (increments 4 / 8 / 12) | evidence captured in-packet | 0 |

**Finding closure ratio: 24/24 Phase-2 findings closed before Phase 3; 5/5 CV items dispositioned.** Phase 3 produced **zero new findings** — a notable contrast with batch-01, which surfaced 18 open findings from its audit objective. This is expected: batch-02 is a restyle against a frozen engine, not an audit; there was no product-bug discovery surface.

### 5.3 Test count growth

`275` (increment 1 baseline) `→ 419` (increment 12) = **+144 net**, 0 failed throughout. Per-increment: 275 → 284 (+9, inc 2) → 291 (+7, inc 3) → 308 (+17, inc 4) → 314 (+6, inc 5) → 327 (+13, inc 6) → 338 (+11, inc 7) → 347 (+9, inc 8) → 359 (+12, inc 9) → 373 (+14, inc 10) → 389 (+16, inc 11) → 419 (+30, inc 12). The 3 documented `xfail` rows and 2 skips are pre-existing batch-01 baseline cases, unchanged through all 12 increments — no Direction B `xfail`. 27 snapshot baselines, all re-matching.

### 5.4 Requirement coverage

| Dimension | Result |
|---|---|
| HLR | 15 / 15 `pass` · 0 partial · 0 fail |
| LLR | 38 / 38 `pass` · 0 partial · 0 fail |
| Active TC | 38 / 38 `pass` (TC-001..TC-039 + TC-016-S; TC-005 retired N/A) |
| Batch acceptance criteria | AC-B 9 / 9 met · 0 not-met |
| Engine freeze (HLR-014) | zero bytes changed across 7 frozen modules |
| Open blocker findings at the Phase 4 gate | 0 |

Phase 4 verdict: **`pass-with-gaps`** — green suite, frozen engine, every requirement and AC satisfied; the `-with-gaps` qualifier records 4 documentary/environmental gaps (manual TUI pass not run headless; `ruff` not run for increments 1–11; the TC-030 global-`BINDINGS` design realization; the CV-03 empty-state-not-snapshotted note). None is a correctness defect; none gates the batch.

---

## 6. Root-cause analysis

### 6.1 Why Phase 1 took 4 iterations

Four Phase-1 iterations is on the high side. The drivers, in order of cost:

1. **Outdated handoff input (§3.1).** The Hex Lab `PLAN.md` framed the work as a `hexlab/` from-scratch rewrite with three new dependencies. Phase 1 had to detect this was obsolete, reject it (C-2/C-3), and re-derive every requirement against the *actual* `s19_app/tui/` package. A handoff reconciled against the codebase before Phase 1 began would have removed this entire iteration's worth of churn.
2. **The A-03 contradiction (§3.2 / §6.3).** The fixed-pane-width-vs-80×24 contradiction was authored *into* the Phase 1 requirements and only caught by the Phase 2 architect review. Resolving it (the two-regime breakpoint layout) is a product-owner decision that changes the supported-size contract — so it needed Javier's sign-off and a dedicated Phase-1 iteration to fold the resolution into LLR-007.1/008.1/009.1/010.1 and reconcile the coupled TCs.
3. **13 open questions + 24 Phase-2 findings folded in one pass.** Iteration 4 was the consolidation iteration — resolve all 13 OQs, fold all 24 findings, apply 5 CV cosmetics. This is healthy convergence, not waste: doing it in one focused pass (as Phase 2's recommended disposition advised) is cheaper than spreading it across phases.

**The avoidable iterations are 1 and 2** — both trace to requirements that did not survive contact with reality (the codebase, in case 1; internal logical consistency, in case 2). Batch-01's post-mortem already identified the same class of root cause ("HLRs derived top-down without bottom-up reading the actual surface") and prescribed a mandatory **surface-enumeration pass before LLR drafting**. Batch-02's A-03 is the *layout-geometry* analogue of that miss: the requirements specified pinned column widths without ever doing the arithmetic against the stated minimum terminal size. The carry-forward discipline holds and should be extended (see §8).

### 6.2 Why Phase 2 took 2 iterations

Two iterations is the *expected, healthy* shape for Phase 2 and not a problem. Iteration 1 is the parallel architect + qa + security review pass (24 findings: 0 blockers, 11 majors, 13 minors, 2 informational). Iteration 2 is the closure-verification pass after Phase 1 iteration 4 folded the fixes — all 24 confirmed closed, 5 new minor/cosmetic CV items surfaced by the closure scan and dispositioned into increment 1. With 0 blockers, the dev-flow did not force a rollback; the second iteration is verification, not rework. The only thing the closure scan reveals about Phase 1 is that even a careful fix pass leaves cosmetic residue (CV-01..CV-05: a rounding-loose worked example, a missing cross-reference, a TC label swap) — which is exactly why a lightweight closure pass exists.

### 6.3 The A-03 contradiction — deeper read

A-03 is worth a standalone note because it is the batch's most instructive defect. The Phase 1 requirements simultaneously asserted (a) pinned fixed pane widths summing to 84 columns of chrome and (b) an 80×24 supported minimum with an explicit no-clip mandate. 84 > 80: at the minimum size the center hex pane is allocated a negative remainder. Both statements were individually plausible and were authored by different parts of the document (the per-screen layout LLRs vs. the density-integrity HLR), so neither author saw the conflict. It was a *latent* contradiction that only a reviewer cross-reading the whole document — or an implementer hitting an un-codeable spec — would surface. The resolution (two-regime breakpoint layout: fixed widths ≥120 columns, proportional below, rail collapses to 4 columns) is sound and was validated numerically by TC-017/019/021 and the CV-04 119/120-boundary checks. **The fix was good; the miss was that requirement arithmetic against the stated constraints was never performed.** This is the concrete lesson for §8.

---

## 7. Items proposed for the next batch

Consolidating the **deferred scope** (C-5) and the **Phase 4 gap / cleanup items** into candidate follow-up batches. Every item below is derivable from an existing decision, gap, or deferral — no new requirements are invented.

### 7.1 Deferred-scope feature batches (the originally-deferred C-5 work)

**Batch B-3A — CRC / checksum engine.** The CRC/checksum computation engine deferred by C-5. This is an *engine* batch — it adds real data-processing logic, so it is **not** view-layer-only and the engine freeze does not apply. Owner: `software-dev`; full architect + qa + security review (a checksum engine is correctness-critical). It is the natural prerequisite for any "verify firmware integrity" feature and is the foundation the Patch Editor's apply path will eventually need.

**Batch B-3B — Patch apply / undo / redo logic.** Wire real logic behind the Patch Editor view shell that batch-02 shipped inert (LLR-012.2). The CLI already has `patch-hex`; this batch brings memory patching to the TUI with an undo/redo history. Depends on B-3A only if patch-apply is gated on a post-patch checksum recompute. Owner: `software-dev`; architect + qa + security review (it mutates firmware images — destructive surface).

**Batch B-3C — Bookmark persistence + A↔B firmware diff.** Two independent deferrals that share a "make a placeholder screen real" shape: (a) bookmark persistence behind the Bookmarks "coming soon" placeholder (LLR-002.2) — needs an on-disk store under `.s19tool/`; (b) the A↔B firmware-diff computation + the real second-file load path behind the static 3-column Diff placeholder (LLR-012.3 / OQ-7). Could be split into two smaller batches if the diff computation proves large. Owner: `software-dev`.

**Batch B-3D — PDF report export.** PDF export of the validation Issues Report, deferred by C-5. This introduces a new runtime dependency (a PDF library) — a one-way-door decision that needs an explicit `architect` + `security-reviewer` evaluation against the cost/lock-in profile *before* the batch opens. Owner: `software-dev` + `docs-writer` (report layout). Lowest priority of the four — it is a convenience feature, not a capability gap.

### 7.2 Hygiene / cleanup batch (Phase 4 gaps + carried cleanup items)

**Batch B-3E — Restyle hygiene sweep.** A small doc/test/cleanup batch consolidating every non-feature carry-forward item. None is a correctness defect; grouping them keeps the feature batches focused:

- **CV-03 — empty-state snapshot baseline.** Add one optional 120×30 empty-state snapshot baseline (currently the no-file empty-state *layout* is functionally covered by TC-037 but not snapshot-guarded). Phase 4 Gap 4.
- **`ScreenScaffold` dead-code removal.** After increment 10 all 8 screens have real content; `ScreenScaffold` is unused by `app.py` but still defined/exported in `screens_directionb.py`. Inert, harmless — remove it.
- **`EmptyStatePanel` id de-duplication.** Workspace / Issues / Memory Map each carry an `EmptyStatePanel` with the shared id `#empty_state_panel`. Benign today (every query is type-scoped to a screen), but it should be made unique before any code needs to query a single panel by id. The legacy shared `id="load_dialog"` across the 3 modals is the same class of issue and can be cleaned in the same pass.
- **Automatic ASCII-fallback detection.** The rail ships the *selectable* `ascii_mode` flag and a defined fallback glyph set, but no automatic terminal-capability probe (LLR-001.3 phrased it "selectable/automatic"). Add a capability probe feeding `Rail(ascii_mode=...)`. Small follow-up; was flagged in the increment-3 packet.
- **`ruff` in CI.** Run `ruff check .` / `ruff format --check .` and add it to `.github/workflows/tui-ci.yml` so lint hygiene is verified going forward — increments 1–11 were never lint-checked. Phase 4 Gap 2. No code change anticipated; if `ruff` flags real issues, fix them in this batch.
- **TC-030 per-screen-`Binding` question.** Phase 4 Gap 3 / increment 11 Risk 1: the keymap proposal §3 lists *per-screen* `show=True` sets, but the implementation realised them through a single app-level `BINDINGS` with context-sensitive dispatch (the footer shows a constant chip set; per-screen behavior lives in the action dispatch). Phase 4 ruled this satisfies LLR-013.2 and is `resolved-by-design`. This is an `architect` decision: either formally accept the global-`BINDINGS` realization in the keymap proposal, or — if a literal per-screen `Binding` presentation is preferred — open it as a small keymap-change item. **Architect recommendation: accept as-is** — a single always-`show=True` dispatcher binding is a superset of every screen's expected set, and the keymap proposal §3 itself defines a screen's footer as "global set + per-screen set". No code change; just a keymap-proposal annotation.
- **Font-family / MAC-highlight-colour tweaks (OQ-6 deferred).** The deferred OQ-6 visual-polish tweaks. Bundle them here as the visual-polish slot; they are subjective and small. Should be paired with the manual real-terminal TUI pass (Phase 4 Gap 1) so the eyeballing and the tweaks happen together.

### 7.3 Suggested execution order

`B-3E` (hygiene — cheap, fast, clears the Phase 4 gaps and unblocks a clean CI) → `B-3A` (CRC engine — the foundational engine work, prerequisite-shaped) → `B-3B` (patch logic, builds on B-3A) → `B-3C` (bookmarks + diff, independent) → `B-3D` (PDF export — lowest priority, needs a dependency decision first). B-3A and B-3C can run in parallel if `software-dev` capacity allows; B-3B should follow B-3A; B-3D should not start until its dependency-evaluation gate clears.

---

## 8. Process learnings for the GRNDIA dev-flow

1. **Reconcile an incoming design handoff against the actual codebase before Phase 1.** The Hex Lab `PLAN.md` "replace the CLI" framing cost a Phase-1 iteration. A handoff is a *reference*, not a contract — Phase 0 should include a one-paragraph reconciliation note stating which parts of the handoff are obsolete and why, before requirements drafting begins.

2. **Do the arithmetic — requirement constraints must be checked against each other numerically.** A-03 (84 columns of fixed chrome vs. an 80-column minimum) was a contradiction that simple addition would have caught at authoring time. Batch-01's post-mortem prescribed a *surface-enumeration* pass before LLR drafting; batch-02 shows the same discipline must extend to **constraint-arithmetic**: any LLR that pins a numeric dimension (width, count, cap, timeout) must cite the calculation that proves it is consistent with every stated bound. Add to the Phase 1 checklist: *"every LLR that fixes a numeric value states the bound it was checked against."*

3. **A CSS / config rule that no test exercises is unverified.** The increment-3 sibling-selector defect passed the suite for two increments because no test asserted the rail width at 80×24. A green suite is not evidence a styling rule *works* — only that it *parses*. When an increment adds a CSS rule with observable layout effect, that increment should add the test that exercises it, not defer it to a later increment's TC.

4. **When retiring a UI element, enumerate everything it was the sole entry point for.** Retiring `#view_bar` silently orphaned the settings menu and rippled a pending item across three increments. A retirement increment should list, in its own packet, every action/overlay that loses its only trigger — and re-home them in the same increment or explicitly defer with an owner decision.

5. **Pre-provision the dev toolchain before Phase 3.** `ruff` was missing for 11 of 12 increments; `pytest-textual-snapshot` for 11 of 12. The `py_compile` substitute is a correctness check, not a lint check — a real coverage gap. Phase 3 increment 1 should verify (and install) the full declared dev toolchain as its first action, so no increment ships with an unverified hygiene surface.

6. **Carry-forward discipline works.** Batch-01's prescribed patterns held: the ≤5-file cap held on all 12 increments without a separately-gated follow-up; parallel-for-review + sequential-for-implement agent dispatch was the template again; the per-increment review packet localized every defect to its increment. The dev-flow itself is sound — the friction in batch-02 was in *requirement authoring*, not in the workflow.

7. **A clean `pass-with-gaps` Phase 4 verdict is the right resolution for documentary gaps.** All 4 Phase-4 gaps were already disclosed in the increment packets and are documentary/environmental, not correctness defects. The `-with-gaps` qualifier records them honestly without forcing a rollback or an extra iteration. This is the verdict working as intended — surface the residue, do not hide it, do not over-react to it.

---

## 9. Decision (user gate)

Per the dev-flow Phase 5 spec, three options:

1. **`close-batch`** *(architect recommends)* — the Direction B restyle deliverable is complete and independently validated: 419-test green suite, zero-diff engine freeze, 15 HLR / 38 LLR / 38 TC all `pass`, AC-B 9/9. Advance to Phase 6 (docs) — update `REQUIREMENTS.md` `R-*` traceability for the new Direction B screens, refresh `docs/diagrams/`, produce the batch functionality summary — then `/dev-flow-sync-en` to upload to the Obsidian vault. The deferred C-5 scope and the Phase 4 gaps are queued as the well-scoped follow-up batches B-3A..B-3E.

2. **`open-new-batch`** — start B-3E (hygiene) or B-3A (CRC engine) immediately, skipping batch-02's Phase 6. **Not recommended** — Phase 6 wraps the restyle into client-facing traceability/docs; skipping it leaves the `R-*` map stale for the next batch's requirements seed.

3. **`iterate`** — reopen Phase 3 to fold one or more Phase-4 gap items inline before closing. **Not recommended** — none of the 4 gaps is a correctness defect; folding them in would be cheaper and cleaner as the B-3E hygiene batch, and `iterate` is meant for blocker-level rework, of which there is none.

**Recommendation: option 1 — `close-batch`.** The batch met every requirement and acceptance criterion with independently verified evidence; the remaining work is genuinely separate scope (deferred features) or hygiene (the gaps), both of which belong in fresh, well-scoped batches rather than in a re-opened batch-02.

---

*Phase 5 post-mortem of batch-02-direction-b-restyle. Synthesizes the architecture/process perspective with the QA/quality/metrics evidence from `04-validation.md` (Phase 4, authored by the `qa-reviewer`). Authored by the `architect` agent — 2026-05-21.*
