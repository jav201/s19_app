# Post-mortem — s19_app — Batch 2026-06-17-batch-13

> **Artifact language:** English. Phase 5 artifact. Co-authors: `architect` (§ At a glance + Detail, this document) + `qa-reviewer` (retrospective, merged into the QA retrospective section near the end). Structured for cross-batch sweeping — section order preserved.

## 🔑 At a glance (read first)

- **Outcome:** **closed clean** — PASS, 0 defects, 3 increments, no withdrawals, no iterate-to-Phase-3.
- **Top 3:** ① **Phase-0 premise correction** — the brief's "Patch Editor is an inert shell" premise was false (a stale `app.py:938` docstring), caught at *story intake* before any requirement was derived, re-scoping US-014 to the real gap. ② **Stale local `main` ref** (`ec453a2`, pre-batch-09) would have spuriously failed the write-surface gate; discovered in Phase-3 Inc-2, baseline pinned to `febd843` via Amendment A-1. ③ **Root cause of ②:** the worktree's `main` ref was never updated to the real `origin/main` tip after batches 09–12 merged.
- **New control this batch:** the **requirement-amendment Before/After + Deleted/New record** (§6.5), now encoded durably in `~/.claude/commands/dev-flow.md` (Phase 3).
- **Open items → next batch:** 6 — biggest: **codify reader-as-oracle in PROJECT_RULES** (now its 5th use across batches).
- **Metrics:** iterations 7 (one phase iterated: Phase 1 ×2) · findings 17 closed / 17 opened (0 blocker / 1 major / 16 minor) · ledger 879 → 893 (+14).

> **Batch in one line:** surfaced two existing-substrate TUI capabilities — US-013 (load CRC config from file) + US-014 (paste a change-document into the Patch Editor). No new engine math; the write path was REUSED, not rebuilt.

---

## Detail (reference)

### What worked

- **Phase-0 premise correction — draft-time verification firing at the earliest possible point (Phase 0, not Phase 2).** The brief framed US-014 as "wire the inert Patch Editor (`app.py ~:938` — SHELL INERTE)" and listed a "genuinely new" R-6 write substrate to build (worker-thread write, two-stage confirm, contained emit via `copy_into_workarea`, `verify_written_image` reader-as-oracle). Disk verification at intake contradicted all of it: the "inert shell" was a **stale docstring** at `app.py:938`, not live code. `PatchEditorPanel` (`screens_directionb.py:325`) + `ChangeService` (`change_service.py:284`) + the `app.py` handlers (`:1247`) already shipped load-from-file, apply (INSIDE/PARTIAL/OUTSIDE via `classify_containment`), `emit_s19_from_mem_map`, **contained** write via `copy_into_workarea` (no arbitrary path, no clobber — `apply.py:586-635`), and `verify_written_image` (`change_service.py:867`).
  **Waste avoided (quantified):** US-014's "genuinely new" R-6 write substrate was *already shipped and wired* with the exact containment + verify the brief prescribed — the same surface batches 10/11/12 built. Had the false premise survived, the batch would have re-specified and re-implemented an entire write path that already existed. The §5 validation confirms this counterfactually: the write-surface gate shows `git diff febd843 -- apply.py verify.py workspace.py` = **0 lines** — the batch touched none of it because there was nothing to build. Operator chose **"Trim to the real gap"** at the Phase-0 DoR gate → US-014 reduced to paste-full-changeset + dummy pre-load (CRC parity). *This is the draft-time-verification control firing at Phase 0 — the cheapest point on the V-model — not at the Phase-2 review gate where most of these controls were authored to fire.*

- **Reader-as-oracle reuse — 0 new write surface, mechanically gated.** The re-scoped US-014 feeds its parsed document into the existing `save_patched_image` / `copy_into_workarea` / `emit_s19_from_mem_map` / `verify_written_image` path. This is the reader-as-oracle idiom's **5th** use (b09 compare / b10 IntelHex / b11 manifest / b12 CRC verify-on-write / b13 patch-paste). The **F-S-03 standing gate** turned "0 new write surface" into a hard Phase-4 row — `git diff febd843 -- apply.py verify.py workspace.py` must be empty AND the `emit_s19_from_mem_map`/`save_patched` symbol bodies unchanged — and Phase-4 confirmed both. The gate was elevated precisely because Inc-2 edits `io.py`/`change_service.py` *near* the emit/save symbols, forcing "near" to prove "not touching."

- **Two batch-12 controls applied and earned their keep.** *Consumer-input-contract citation* (would have caught the b12 J-3 mis-binding): each producer→consumer wiring cited the consumer's real input type at `file:line` before code, and this directly forced both seam decisions — US-013's `read_crc_config(path)` returns parsed `(Optional[CrcConfig], list[str])` (wrong type for a `TextArea`) → add `read_crc_config_text` (raw text); US-014's `read_change_document` is path-based with no parse-from-string entry → add `parse_change_document(text)`. *Facade/test blast-radius budgeting:* `PATCH_ACTIONS_V2` (fixed set asserted at `test_tui_patch_editor_v2.py:184`) extended 9→10 stayed within the ≤5-file Inc-3 budget (4 edit points, no `__init__` facade re-exports), and the action-set assertion was correctly classified REUSE-extend, not a new TC.

- **Phase-2 fold discipline — body-first, audited, one real correctness catch.** 1 major + 16 minor folded in a single Phase-1 iteration, **body-first**: §3/§4 LLR/AC edits landed first, then the §6.4 audit rows J-1/J-2/J-3 pointed at them (eliminating the b06/07/08 "claimed but missing" failure mode). The **major (F-A-01)** was a genuine catch, not bureaucracy: moving the parse seam from `json.load(handle)` to `json.loads(text)` required re-homing the `MF-JSON-PARSE` 3-exception catch (`JSONDecodeError`/`RecursionError`/`UnicodeDecodeError`) verbatim, or a malformed paste would silently lose the error code LLR-014.2's threshold names. TC-209 (malformed→`MF-JSON-PARSE`) now pins it; TC-210 (`call_count==1`) pins the refactor as delegation, not duplication.

### What didn't / friction

- **Stale local `main` ref (`ec453a2`, pre-batch-09) — would have spuriously failed the write-surface gate.** Discovered in Phase-3 Inc-2 while running F-S-03. **Root cause:** the worktree's `main` ref was never updated to the real tip (`febd843` = PR #17 merge = `origin/main`) after batches 09–12 merged; `git diff main` therefore diffs against a commit *before* those batches landed their apply.py/verify.py write-path work, falsely surfacing all of it as batch-13's. **Resolution:** spec **Amendment A-1** (§6.5) pinned `<BASE> = febd843` (robustly, `git merge-base HEAD origin/main`), recorded Before/After + Deleted/New. **General lesson (carry):** *gates that diff against `main` must pin the real base commit, not a possibly-stale local ref* — a diff-based gate is only as trustworthy as the commit it diffs against.

- **Pre-existing `F401`/`F40x` in `app.py` + `change_service.py` — correctly left surgical.** 6 `F401` in app.py + 1 (`typing.List`) in change_service.py; verified untouched vs `febd843` (not introduced), left per engineering rule 3. A standing cleanup carry — noise on every ruff run over these files.

- **Minor reporting-accuracy note (F40x count 12 → 6).** The author reported app.py's F40x count as 12 at the Inc-3 review; the independent code-reviewer corrected it to 6. No functional impact (the disposition "pre-existing, leave surgical" was unchanged either way), but it reinforces the value of the per-increment independent review even on non-blocking notes — a count asserted without re-running the linter drifted from the real number.

### Scope drift (planned vs actual)

| Planned | Actual | Note |
|---------|--------|------|
| US-014 = build the R-6 write path for the "inert" Patch Editor | US-014 = add paste + dummy to the already-working Patch Editor; shipped write reused | **Intentional Phase-0 narrowing, NOT drift** — operator-approved at the DoR gate (decision D0) after the premise conflict was surfaced; the deferred items (two-stage modal, worker-thread write) listed explicitly as operator-deferred out-of-scope |
| 3 increments × ≤5 files | 3 increments × 3 files | Held exactly; Phase-2 fold added 0 new files (TC-209/210/211 homed to existing `test_changes_schema.py`) |
| — | No mid-phase scope creep | Increment file lists fixed at Phase 1, no budget breach |

*Distinction:* the US-014 re-scope is a controlled **contraction** decided before requirements derivation, not uncontrolled expansion discovered mid-implementation. It made the batch smaller and removed already-shipped work from scope.

### Metrics (full)

| Metric | Value |
|--------|-------|
| Iterations per phase | `{0:1, 1:2, 2:1, 3:1, 4:1, 5:1}` |
| Findings opened / closed | 17 / 17 |
| Findings by severity (blocker/major/minor) | 0 / 1 / 16 |
| Where caught (Phase 2 / P3 gate / P4) | 17 / 0 / 0 (all in Phase-2 cross-review; per-increment code-review added 5 LOW notes, 0 blocking) |
| Test ledger (base − D + A = post) | 879 − 0 + 14 = **893** (EXACT; I1 +7, I2 +5, I3 +2) |
| Files touched · increments (cap trips) | 6 prod + 3 test · 3 increments (0 cap trips) |
| Full suite | 861 passed / 29 skipped / 3 xfailed / **0 failed** (exit 0, 764.86s); collection 893 |
| LLR / HLR coverage | 6/6 LLR + 2/2 HLR PASS on real verified-present nodes; 0 orphan TCs |
| A-5 surface-reachability | 7/7 story dimensions through the shipped handler (SCOPE-1 did NOT recur) |
| Per-increment code-review | 3/3 APPROVE: I1 (2 LOW) · I2 (1 LOW, pre-existing) · I3 (2 LOW) |
| Commits | `9ab8d3e` (Phase 0-2) · `a8c7080` (I1) · `e42181c` (I2 + §6.5 amendment) · `5197169` (I3) |

### Root causes (only if a phase took ≥2 iterations)

- **Phase 1 iterated ×2** → trigger: the Phase-2 cross-review register (0 blocker / 1 major / 16 minor). Root cause: not a derivation error — the iter-1 requirements were sound (2 HLR / 6 LLR unchanged across the fold); the 17 findings were AC-level tightenings (refactor-fidelity invariants, action-token literal, executable gate command, changeset tripwire). Folded inline body-first in one pass; no re-derivation, no design change. This is the intended cost of the Phase-2 gate working, not a defect in Phase 1.

### Process / workflow findings

> About the dev-flow itself (phases, gates, templates, agents, controls).

- **Draft-time verification reached Phase 0 for the first time.** The premise correction proves the verification controls work at story intake, not only at the Phase-2 gate — a false premise inherited from the brief is cheapest to kill before any HLR is derived from it. *Suggested change:* none needed — the control fired correctly; record it as the canonical example of "verify the brief's premise against disk at intake."
- **Diff-based gates need a pinned base.** The stale-main near-miss is a workflow gap, not a one-off. *Suggested change:* the standing gate definition should require `git merge-base HEAD origin/main` (or an explicitly pinned base SHA), never a bare local `main` ref. (Carry #2.)
- **The §6.5 amendment convention is the Phase-3 analogue of the §6.4 reconciliation log.** It closes the gap that §6.4 (Phase-1 reconciliation) left open: edits made *during* implementation. *Suggested change:* already adopted — encoded in `/dev-flow` Phase 3.

### Product findings

> About the code/product under development.

- US-013 + US-014 both shipped against existing substrate with zero new engine math and zero new write surface (write-surface gate = 0 lines vs `febd843`).
- The stale `app.py:938` docstring ("inert before/after view shell") was corrected as a surgical truth-fix — the live `PatchEditorPanel`/`ChangeService` flow is now accurately described.
- Pre-existing app.py/change_service.py F401s remain (out-of-scope cleanup carry).

### Control lineage

- **New control proposed this batch:** the **requirement-amendment Before/After + Deleted/New record** (§6.5), origin = the Inc-2 stale-main baseline fix (an operator process request: Phase-3 spec edits must be an explicit Before→After + Deleted/New artifact with a parent-HLR re-read, never a silent in-place edit). **Status: adopted** — encoded durably in `~/.claude/commands/dev-flow.md` Phase 3. **Assessment: net-positive, low-cost, keep.** It extends the already-proven §6.4 "artifact-not-process-step" discipline (the batch-07 lesson: a rule that says "re-read" with no required output silently degrades to "I thought about it") from Phase-1 reconciliation to Phase-3 amendments. Cost is a few lines, only when an amendment actually occurs.
- **Prior controls exercised (held):** consumer-input-contract citation (b12) — held, forced both seam decisions; facade/test blast-radius budgeting (b12) — held, PATCH_ACTIONS_V2 9→10 in budget; reader-as-oracle (b09–b12) — held, reused with 0 new write surface; change-first census incl. engine-frozen family (b09/b10) — held, all 6 prod files outside `_ENGINE_PATHS`; body-first §6.4 reconciliation + parent-HLR re-read (b06/07/08) — held, J-1/J-2/J-3 present; A-5 surface-reachability (b11) — held, 7/7 through-handler, SCOPE-1 did not recur.
- **Near-miss:** the stale-main ref — the F-S-03 gate would have spuriously failed had the baseline not been re-pinned at Inc-2; caught by running the gate, not by the census.

### Open / deferred items → next batch

| Item | Type | Reason deferred | Trigger / owner |
|------|------|-----------------|-----------------|
| Codify reader-as-oracle in PROJECT_RULES (now 5th use: b09/b10/b11/b12/b13) | process | Out-of-scope carry since b12; idiom past threshold for a documented rule | Next write-path batch / architect |
| Fix stale local `main` ref hygiene + generalize gate-baseline rule (`git merge-base HEAD origin/main`) | process | Surfaced mid-batch; pinned per-batch via A-1, not yet generalized | Next batch init / orchestrator |
| Pre-existing `app.py` F401 cleanup (6 in app.py + 1 in change_service.py) | product | Out-of-scope (surgical rule); cosmetic | Any batch touching those files |
| A-3 save-flow composition (b11 LEAD) | product | Standing carry, not pulled into b13 | Operator selection |
| RK-3 non-zlib device vector | product | Standing carry (numerical/device-vector coverage) | Operator selection |
| CLI `ops` subcommand (CRC/operations surface is TUI-only) | product | Standing carry; b13 was TUI-only by scope | Operator selection |

**Do NOT re-flag (resolved):** CI trigger gap — `tui-ci` has fired on pushes/PRs to `main` since batch-06 (`bd2c2ad`); any prose suggesting otherwise is stale. (Also resolved at b13 init: batch-12 `obsidian_synced` was already fully synced; flag flipped true.)

---

## QA retrospective (merged)

**BLUF: The validation strategy held end-to-end — 6/6 LLR covered by real passing nodes, A-5 surface-reachability 7/7 through-handler, SCOPE-1 did not recur, and every Phase-2 finding that was folded into an LLR AC earned a passing assertion at Phase 4.** The two QA innovations this batch (the surface-reachability matrix and the executable write-surface gate) both did their job; the only test-debt is honest and pre-existing.

**1. Test-process effectiveness.** The A-5 surface-reachability matrix held: 7/7 story dimensions reached the *shipped handler call-site* (screens.py:795/801/841 for US-013; app.py:1336-1338 for US-014), not just a direct-kwarg service call. SCOPE-1 (the batch-11 "writer complete, surface empty" failure) could not recur because TC-208 enters through `ActionRequested(paste_text=…)`→router→`load_text` and then drives `apply_doc` on the result. Provisional-id discipline (V-5) cost **2 reconciliations at Phase 4** (TC-208's two `-k` selectors collapsed into one stronger end-to-end node; action-set node renamed 9→10), plus **3 call-site line-drifts** (screens.py:774→795/801/841; app.py:1301→1336). **None caused a coverage gap** — every TC-2xx still mapped to exactly one real passing node, 0 orphans.

**2. What validation CAUGHT vs relied on.** The F-A-01 major (`MF-JSON-PARSE` re-homing) earned TC-209 its mandatory place: the valid-parity oracle alone would have passed while a malformed paste silently lost the code, so a dedicated malformed-string assertion was the *only* thing pinning the refactor's hardest guarantee. TC-210 (`call_count==1`) correctly pinned the refactor as **delegation, not duplication** — without it, behavioral parity could pass while a drifting parallel copy existed. TC-207's narrowed oracle (`entries` + `{issue.code}`, not whole-doc `==`) was **the right call**: the `source_path` divergence is real (`parse_change_document` sets `None`; file read re-stamps it), so a whole-doc `==` would have **falsely failed a correct implementation**. F-Q-04 caught this at Phase 2, before code existed.

**3. Coverage honesty.** Phase 4 verified **all mapped nodes + frozen guards EXIST on disk and PASS** — nothing signed off from intent. No vacuous passes: each LLR carries a numeric threshold (byte-equal, `call_count==1`, exactly-1-error, 0 changed lines). The "0 new write paths" gate is a **diff-vs-base inspection** (`git diff febd843` = 0 lines), not a pytest assertion — this is an **acceptable validation method** (a structural absence-of-change cannot be a unit test) and **should be a STANDING row for future write-adjacent batches**, exactly as F-S-03 elevated it.

**4. Test-debt / gaps (honest).** (a) The paste row and CRC config widgets have **no dedicated `.tcss`** and live-terminal visual was **not inspected** (only `run_test` `.display`/`.text`) — non-blocking, no LLR requires it, flag for a future visual pass. (b) TC-208 asserts the save-back **prompt + pre-filled name**, not the actual file write — **correct boundary**, because the write path is unchanged shipped code already covered elsewhere and gated at 0-diff. (c) Pre-existing F401s verified untouched by `git diff febd843` — correctly left surgical.

**5. Process lessons for QA.** The Phase-1 **Executed-verification + numeric-threshold discipline** is what made Phase 4 mechanical rather than judgment-heavy — every row had a runnable command and an objective pass bar. The **baseline-pinning lesson** (`<BASE>=febd843`, not stale local `main` `ec453a2`) was load-bearing: against the stale ref the write-surface gate would have **spuriously failed**. Carry forward: pin the merge-base explicitly in any diff-gated LLR, and keep folding QA findings into ACs at Phase 2 (F-Q-04/F-A-01 prove a finding folded into a mandatory TC is worth far more than one left as advisory prose).

### QA evidence checklist
- [✓] A-5 matrix held 7/7 through-handler — 04-validation.md §4; screens.py:795/801/841 + app.py:1336-1338
- [✓] SCOPE-1 non-recurrence — TC-208 enters via `ActionRequested(paste_text)`→router, not direct kwarg
- [✓] Provisional-id reconciliation = 2 merges + 3 line-drifts, 0 coverage gaps, 0 orphans
- [✓] TC-209 (MF-JSON-PARSE) earned its place — malformed-only path; valid-parity insufficient
- [✓] TC-207 oracle narrowing necessary — `source_path` divergence real; whole-doc `==` would false-fail
- [✓] All nodes verified on-disk + passing, not from intent — 861 passed / 0 failed, 893 collected
- [✓] Write-surface gate is inspection not pytest, acceptable + standing — `git diff febd843` = 0 lines
- [✗] Live-terminal visual NOT inspected (paste row / CRC widgets, no `.tcss`) — `run_test` only; deferred non-blocking

---

### Evidence checklist — architect

- [✓] **Constraints / scope stated explicitly** — At-a-glance + Scope-drift table. Evidence: 01-requirements.md §1.2 in/out-of-scope + §2.6 premise correction.
- [✓] **What-worked grounded in artifacts, not opinion** — premise correction (state.json Phase-0 `awaiting-gate` note + 01-req §2.6); write-surface gate 0 lines (04-validation.md §5.1).
- [✓] **Friction root-caused, not just listed** — stale-main root cause = worktree ref never updated post-merge (state.json I2 note "local main ref is STALE (ec453a2 pre-batch-09)"); resolution §6.5 Amendment A-1.
- [✓] **Scope drift distinguished from controlled change** — Scope-drift table: US-014 re-scope = operator-approved Phase-0 narrowing (decision D0), not creep. Evidence: decisions_log Phase-0 `approved`.
- [✓] **Metrics quantified from real data** — iters {0:1,1:2,2:1,3:1,4:1,5:1} (state.json `iterations_per_phase`); 861/0 + 893 (04-validation.md §1); ledger 879→893 (PLAN.md Test ledger).
- [✓] **New control assessed (value + cost)** — Control lineage: §6.5 amendment convention judged net-positive/low-cost/keep, tied to the batch-07 artifact-not-process-step lesson.
- [✓] **Carries listed with reason/trigger** — Open/deferred table: 3 new + 3 standing carries; CI-trigger explicitly do-not-re-flag.
- [✗ → N/A] **Diagram included when flow is non-trivial** — not applicable; this is a retrospective over an already-validated batch, no new flow to diagram (the change flow is documented in 06-docs/diagrams per Phase 6).
