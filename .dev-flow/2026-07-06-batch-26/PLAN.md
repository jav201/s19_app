# PLAN.md — 2026-07-06-batch-26 · Feature #12(b) Entropy / data-classification viewer

> Living compendium. Updated at every gate + significant checkpoint. Human-readable mirror of `state.json`.

## Where we are
- **Phase 0 — APPROVED** (bands-only; all 3 stories; US-036 modal geometry MEASURED 48@80 / 76@120 → fits, no fallback).
- **Phase 1 — APPROVED** (operator). 3 US → 3 HLR → 16 LLR; 10 AT + 13 TC + 14-row QC-3 catalog. shall-only (0 flags); C-12/C-13/C-15 clean.
- **Phase 2 — APPROVED** (operator). 0 blockers from all 3 reviewers; 5 major + 6 minor all FOLDED pre-lock. Spec now 17 LLR (new LLR-036.6 cost-cap) + 16 TC. See 02-review.md.
- **Phase 6 — Documentation: APPROVED. STATE = `awaiting-sync`.** traceability-matrix.md (0 gaps), functionality.md, diagrams/diagrams.md (3 Mermaid), executive-summary.md — all in 06-docs/.
- **ALL 6 PHASES COMPLETE — single-pass, 0 iterations/phase.** Awaiting: operator commit/PR → merge → `/dev-flow-sync` → post-merge canonical-CI snapshot regen.
- **Phase 5 — Post-mortem: APPROVED.** Co-authored (05-postmortem.md + 05b-postmortem-qa.md). Single-pass batch (0 iterations/phase); scope-drift NONE; control-encode NONE (all existing controls fired). Weakest counterfactual = US-036 by-construction (QA carry: Pilot-safe binding-absent harness). Snapshot-regen follow-up queued.
- **Phase 4 — Validation: APPROVED — GATE PASS.** Batch modules 60 pass; frozen guards 101 pass; full suite `not slow` **1048 passed / 19 failed (ALL snapshot-drift, non-gating) / 2 skip / 5 xfail**; slow 21 pass. 0 non-snapshot failures. AT/TC→real-node reconciliation complete (0 orphans). 0 frozen diff. Counterfactual ledger complete (AT-037a LIVE RED captured). No blocker.
- **Phase 3 — Implementation: COMPLETE (approved).**
  - **Inc 1 (US-035 service) — `awaiting-gate`.** ✅ `entropy_service.py` + `test_entropy_service.py` (NEW). 14/14 pass, ruff clean, purity confirmed, 0 frozen-set diff. Independent code-review: no HIGH/MED, 3 LOW nits (optional). Substrate finding: S0 header maps `"STRESS"`@0 → 201 ranges/3201 windows (correct, test derives count from actual ranges).
  - **Inc 2 (US-037 report) — `awaiting-gate`.** ✅ `report_service.py` edit (include_entropy + `_entropy_lines` + emit-wiring) + 8 tests. report suite 33 pass, entropy 14 pass, engine-unchanged pass. AT-037a C-12 RED→GREEN captured. Code-review: no HIGH; F1 (01b doc drift addr/H= vs band-count) + F2 (AT-037b off-vs-off weaker than vs-baseline) MEDIUM → folding; F3/F4 LOW optional.
  - **Inc 2 folds CLOSED:** F1 (01b doc reconcile) + F2 (AT-037b `on−block==off` byte-identical, 33 pass). F3/F4 LOW → backlog.
  - **Inc 3 (US-036 modal core) — `in-progress`.** 4 files: screens.py (`EntropyViewerScreen` + `ENTROPY_BAND_COLOUR` + cost-cap consts) · app.py (`action_show_entropy` + `e` binding) · styles.tcss (band classes, reuse `.modal-dialog`) · tests/test_tui_entropy_viewer.py (NEW: AT-036a/b/c + TC-036.1–.5). Emphases: `.modal-dialog` reuse (48/76 by construction), snapshot-at-push, `e`-binding white-box guard (silent-unbind class), cost cap + truncation, no-image no-op.
  - **Inc 3 (US-036 modal core) — `awaiting-gate`.** ✅ 4 files, 12 tests pass, ruff clean, geometry 48/76 confirmed real, `e`-binding registered + white-box-pinned (TC-036.4), cost-cap enforced, snapshot-at-push genuine, 0 frozen diff. Code-review no HIGH; F1 MEDIUM (truncation indicator `max`→`min` so it fires on EITHER cap — latent silent-truncation gap) → folding; F3 LOW (`List[object]`→`List[Widget]`) fold-while-in-file; F2 LOW no-action.
  - **Inc 3b (snapshot cells) — pending.** Add @80×24/@120×30 SVG cells to the snapshot suite, xfail-until-baseline; baselines regen ONLY in canonical CI env (snapshot-regen-env rule). Non-gating (behavioral proof = AT-036a/b).

## Test ledger (cont.)
- **Inc 3: +13** (`test_tui_entropy_viewer.py`, incl. F1 either-cap fold test). **Inc 3b: +2 xfail** snapshot cells (@80×24/@120×30). Running behavioral total = base + 35 (14 + 8 + 13).
- **Phase 3 COMPLETE** — all 17 LLRs covered, all 3 increments approved+folded, Inc 3b non-gating snapshots added.
- **⚠ Snapshot-drift carry (expected, non-gating):** the new global `e`/Entropy footer binding + entropy styles drift **19 of 28 committed baselines** (footer changed on every screen). Snapshot job is `continue-on-error: true` (non-gating). RESOLVED post-merge by the batch-25 `snapshot-regen.yml` canonical-CI regen → re-baseline 19 drifted + 2 new entropy cells → drop the 2 xfails. Same lineage as batch-25. NOT a code defect.
- **Env:** dev/regression run local Python 3.14.4 (cwd-first `.pth`); canonical/CI gate = **3.11** — Phase-4 records the pass there.

## Test ledger
- Base (batch-25 close): full suite green. **Inc 1: +14** (`test_entropy_service.py`), 14/14 pass. **Inc 2: +8** (`test_report_service.py` 25→33). Running post = base + 22. Full reconciliation at Phase 4.
- **Env note:** dev ran locally on Python 3.14.4 (cwd-first `.pth`); CI/canonical gate is **3.11** — batch's final pass recorded there at Phase 4.
- Route: **full `/dev-flow`** (operator AskUserQuestion 2026-07-06). Language: **en**.
- Branch: `claude/hungry-burnell-b75534` @ `6341fd7` (= origin/main tip, batch-25 close). **RC-1 PASS.**

## Objective
Feature #12(b): give the operator a way to see per-window Shannon entropy / data-classification of the loaded firmware image — as a service, a viewer surface, and a report section. Closes feature #12 (a+c shipped batch-24).

## Stories (pre-drafted batch-24 Phase 0 §2.6)
| Story | What | Class (intake) | Risk |
|---|---|---|---|
| US-035 | Headless entropy service (`tui/services/entropy_service.py`) — per-window Shannon entropy → bands | SPIKE | algorithm (window/estimator/thresholds) + ambition (bands vs semantic) |
| US-036 | Entropy viewer surface (strip, colour-by-band, jump-to-address) | SPIKE | HIGH geometry (C-13); surface choice |
| US-037 | Entropy section in project report, per variant | READY-dependent (blocked by US-035) | cheap, zero geometry |

## Roadmap / increment plan (spike-proposed, pending DoR)
1. **Inc 1 — US-035** entropy service (`entropy_service.py`): 256B windows/range, Shannon bits/byte, 4 bands, low-sample tagging. Pure/headless. Full unit TCs on deterministic fixtures.
2. **Inc 2 — US-037** report section: `_entropy_lines` + `ReportOptions.include_entropy`, per-variant. C-12 AT over handler-written report file.
3. **Inc 3 — US-036** viewer: **preceded by `/prototype` measurement** (modal content width + strip cells/row @80/120). Then `ModalScreen` + key binding + jump list + snapshot cells. Split out of batch only if strip can't fit 80-col.

## Key decisions
- 2026-07-06 · Operator chose #12(b) FULL over service+report-only / P3-cleanup / UI-UX pass.
- 2026-07-06 · Spike: substrate real (half-open ranges); **bands-only recommended** (defer semantic); modal+`/prototype` for US-036; report path is near-free (`result.mem_map` already flows).

## Risks / watch-items
- **C-13 geometry** (US-036 viewer): RESOLVED — measured 48@80 / 76@120 usable modal cols; fits with 18-col margin, no fallback.
- **Editable-install worktree trap** (Phase-3 watch): pip's editable `.pth` resolves `s19_app` to a *different* worktree (`lucid-margulis-a63fd4`) by default. In-repo `pytest` run from THIS worktree root puts cwd first (fine); standalone scripts need `sys.path.insert(0, <this worktree>)`.
- **Ambition creep**: semantic code/data classification is heuristic (accuracy risk). Bands-only is deterministic/defensible. Decide before deriving.
- **Sparse memory**: `mem_map` is a sparse `Dict[int,int]` with gaps — entropy windowing must define behavior over gaps/range boundaries.
- **Engine-frozen**: all new code lives outside the frozen set (new service + viewer + report section).

## Conventions honored
- RC-1 base-currency gate (PASS). Per-story already-shipped grep (PASS — net-new).
- ≤5 files/increment; two-layer AT/TC + dual traceability; C-10/11/12/13/15 controls standing.

## Out of scope
- Engine-frozen edits. Semantic classification beyond entropy bands (unless ambition decides otherwise at gate). Report retention/rotation policy changes.

## Test ledger
_Base count TBD at Phase 3 entry._

## Decision log (mirror)
- P0 2026-07-06 · batch-26 initialized (entropy viewer, full slice). RC-1 PASS.
