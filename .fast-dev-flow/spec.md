# Quick Spec — s19_app · batch-25 (P3 snapshot-baseline)

> `/fast-dev-flow`. Route + design forks chosen by operator (AskUserQuestion, 2026-07-03). RC-1 PASS @ `0c06b48` (origin/main tip = batch-24 PR #40 merge). Branch `claude/laughing-gauss-1ccc58` (auto-cut worktree). English.

---

## 1. Objective (1 line)

Make the silently-skipped TUI layout-snapshot suite actually run in CI (a non-blocking job installing the `[dev]` extra), regenerate the 28-cell baseline set **in the canonical CI env only**, drop the 2 permanent patch `xfail` cells, and refresh the vault gallery + `visual-evidence.md`.

---

## 2. User stories (Connextra)

- As a **maintainer**, I want the snapshot suite to actually execute in CI, so that layout drift is caught instead of silently skipped on every PR/push.
- As a **maintainer**, I want the baseline SVGs regenerated in the canonical env and committed, so that the drift oracle compares against the *current* UI (patch 2×2, MAC 82-col) not stale 2026-05-22 images.
- As a **reviewer**, I want the vault snapshot gallery + `visual-evidence.md` to reflect the shipped UI, so that visual evidence isn't misleading.

---

## 3. Acceptance criteria (observable)

- [ ] **AC-1 (US-A):** When CI runs on a PR/push after this batch, the run log shall show the 28 snapshot cells **collected and executed** (not `skipped`) in a dedicated job that ran `pip install -e .[dev]`.
- [ ] **AC-2 (US-A, gating):** When the snapshot job fails or errors, the overall PR gate shall **still pass** (snapshot job is non-required / `continue-on-error`) — an intentional UI change does not wedge merges.
- [ ] **AC-3 (US-B, round-trip):** When the `workflow_dispatch` regen job is triggered in the canonical env, it shall run `pytest tests/test_tui_snapshot.py --snapshot-update` and upload `tests/__snapshots__/` as a downloadable artifact.
- [ ] **AC-4 (US-B, containment) — AMENDED 2026-07-03:** The original text ("only patch+MAC move, else STOP") assumed the committed baselines were current with CI's textual. **Falsified:** the 2026-05-22 baselines predate CI's textual (now 8.2.8), so the canonical-env run drifted 23/28 cells (textual-render drift + the real patch/MAC changes). With **`textual==8.2.8` now pinned in `[dev]`**, a canonical-env regen legitimately rewrites all ~23 drifted cells into one internally-consistent set for that render. Before committing, **spot-check ≥1 non-patch/MAC diff** to confirm it is cosmetic (whitespace/style), not a structural UI regression. The "only patch+MAC" expectation is retired.
- [ ] **AC-5 (US-C):** When the `_SCAFFOLD_CELLS` `xfail` marks are removed and real patch baselines are committed, the 2 patch cells shall pass **green** (all 28 cells green, zero xfail) in the canonical env.
- [ ] **AC-6 (US-D):** When the batch closes, the vault `…/assets/snapshots/` shall carry the regenerated SVGs (copied via the `visual-evidence.md` §5 `-LiteralPath` helper), and `visual-evidence.md` date lines shall be updated to this batch with the stale "MAC predates batch-05" callout retired.

---

## 4. Validation strategy (1 paragraph)

Layer A (mechanical): after the CI env fix, a **CI run log** is the primary evidence for AC-1/AC-2 — the snapshot job shows 28 cells run, and the overall PR check stays green when snapshots fail. AC-3/AC-4 are validated by triggering the `workflow_dispatch` regen job and inspecting its artifact + `git diff --stat tests/__snapshots__/` (only patch/MAC move). AC-5 is validated by a green snapshot job with the xfail marks gone. AC-6 is validated by inspecting the vault folder + the `visual-evidence.md` diff. **Hard constraint honored throughout:** no baseline is regenerated on this Windows-local machine (snapshot-regen-env memory: 2026-05-28 local regen drifted 13/27) — regeneration happens exclusively in the canonical CI env, so the "all 28 green" end state is only reachable after a CI cycle the operator sees in the Actions log. Local `pytest` here can still confirm the suite *collects* 28 cells and skips cleanly when the extra is absent (guard behavior) — the pre-CI smoke.

---

## 5. Non-goals (OUT)

- The pilot GIF/SVG gallery (`assets/pilot/`) — GENERATED evidence, refreshed 2026-07-02, auto-maintained by dev-flow-sync control C-16. **Baselines only.**
- Any engine-frozen module (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`).
- Entropy viewer #12(b) — deferred to batch-26 (BACKLOG).
- Auto-commit of baselines from CI with a write-scoped token (rejected; using `workflow_dispatch` artifact + manual commit).
- Making the snapshot suite a hard/blocking CI gate (rejected; non-blocking).

---

## 6. Detected security flags

- [ ] Auth / identity
- [x] Secrets / config (GitHub Actions `GITHUB_TOKEN` / workflow `permissions:` scoping)
- [x] External integrations (CI/CD pipeline modification — GitHub Actions workflow)
- [ ] Sensitive data
- [ ] Destructive DB
- [ ] Input / attack surface
- [x] Network / exposure (new `workflow_dispatch` trigger + artifact upload)

**`security_required`:** `true`

**Risk summary:** This batch modifies GitHub Actions workflow(s) — a supply-chain / permissions surface. Even with the low-risk options chosen (non-blocking job, `workflow_dispatch` artifact rather than auto-commit), phase B must verify: (1) the new/modified jobs declare **least-privilege `permissions:`** (snapshot + regen jobs need only `contents: read`; artifact upload needs no repo write); (2) no "pwn-request" footgun — the regen job is **`workflow_dispatch`** (manual, requires repo write to trigger), and the PR snapshot job runs on `pull_request` but must **not** execute untrusted fork code with secrets or an elevated token; (3) no secrets echoed into logs. A `security-reviewer` mini-pass reviews the final YAML before close.

---

## 7. Batch status

| Field | Value |
|-------|-------|
| Current phase | C — CODE CLOSED (PR #41 + #42 merged); US-D (vault) pending |
| Started | 2026-07-03 |
| Closed | 2026-07-06 (code) — AC-6/US-D vault refresh remains |
| Promoted to /dev-flow | no |
| Notes | Route=/fast-dev-flow, non-blocking job, workflow_dispatch artifact (operator AskUserQuestion 2026-07-03). RC-1 PASS @ 0c06b48. Regen is CI-env-only. Prior closed spec archived → archive/2026-06-25-spec.md. **Inc 1 APPROVED 2026-07-03**: tui-ci.yml (perms + non-blocking snapshot job) + snapshot-regen.yml (new); security-reviewer OK-to-ship 0 blockers; local smoke 28-skip exit-0. Defaults adopted: update R-TUI-032 (not R-TUI-029); US-D vault → sync-time. PR #41 opened; CI: tui-ci PASS, snapshot FAIL-non-blocking (run conclusion=success → **AC-1 + AC-2 confirmed**). **AMENDMENT 2026-07-03 (operator AskUserQuestion):** canonical-env run drifted **23/28** (not just patch+MAC) — baselines (2026-05-22) predate CI textual 8.2.8; `textual>=8.0.2` unpinned → every release re-drifts. Chose **pin textual + full regen**: added `textual==8.2.8` to `[dev]` (pyproject.toml, ride PR #41 so the pin is on main before regen), AC-4 reframed, full-28 regen. **BLOCKED on merge of PR #41** → then dispatch snapshot-regen (pinned) → Inc 2 (28 baselines + xfail drop + R-TUI-032). |

---

## 8. Close (phase C)

### What changed
Fixed the silently-skipped TUI layout-snapshot drift oracle and re-baselined it to current `main`. Two PRs, both merged:
- **#41** — `tui-ci.yml` gains least-privilege `contents:read` + a non-blocking `snapshot` job (installs `.[dev]`, `continue-on-error`) so the 28-cell suite runs on every PR/push without wedging merges; new `snapshot-regen.yml` (`workflow_dispatch`, artifact upload, no auto-commit) regenerates baselines in the canonical env; pinned `textual==8.2.8` in `[dev]` so baselines are reproducible (runtime `>=8.0.2` unchanged).
- **#42** — 25 regenerated baselines (from the `snapshot-regen` artifact, canonical env only) + drop the 2 patch `xfail` marks → 28/28 green; `.gitattributes` `eol=lf` for cross-platform byte-stability; R-TUI-032 traceability note.

### How it was tested
- **AC-1** ✅ — the `snapshot` job executed the 28 cells in CI (was silently skipped); proven on PR #41's run (56s, real failures) and PR #42's run (green).
- **AC-2** ✅ — snapshot job failure did not fail the overall run (PR #41 run `conclusion=success`).
- **AC-3** ✅ — `snapshot-regen` run 28795179574 regenerated + uploaded the `snapshot-baselines` artifact (`24 updated, 1 generated`).
- **AC-4** ✅ (amended) — all changes confined to the 28-cell snapshot set; spot-check of workspace/issues/a2l/map/diff confirmed the drift is legitimate current-UI content (Legend/Operations keys from batches 18-24) + textual render deltas, not a regression.
- **AC-5** ✅ — `snapshot` job GREEN on PR #42 (28/28, zero xfail); `tui-ci` required check green; both merged.
- Local: `py_compile` OK; suite collects 28 cells, 0 xfail.

### Open risks / pending
- **AC-6 / US-D (vault) — NOT DONE.** The vault gallery (`…/assets/snapshots/`) + `visual-evidence.md` (date lines + retire the stale "MAC predates batch-05" callout) still need refreshing. This is vault-side (outside fast-dev-flow) and post-baseline → handled at sync-time or by the operator. **The batch's DONE-WHEN is not fully met until this lands.**
- The `snapshot` oracle is now stable *only while* `textual==8.2.8` holds; adopting a newer textual requires bumping the pin + re-running `snapshot-regen` (documented in `pyproject.toml` + R-TUI-032).

### Security flags — handling
`security_required: true` (CI/CD modification). `security-reviewer` reviewed the concrete YAML: **0 blockers / 0 majors** — `pull_request` (not `pull_request_target`), least-privilege `contents:read` on both workflows, no secrets, no `github.event.*` shell interpolation, artifact path-scoped, regen holds no write token. Optional follow-up (not blocking): SHA-pin the `actions/*` with a Dependabot entry.

### Suggested commit message
_(both increments already merged — #41, #42)_

