# fast-dev-flow spec — batch 41 — Repo & test hygiene

- **Status:** closed 2026-07-13 (AC-8.1/9.1/10.1/5.1/6.1 green; full gate `1394 passed / 2 skipped / 3 xfailed / 0 failed`; 0 frozen diffs; C-27 dual-guard ×2; C-26 census clean; no security flags)
- **Created:** 2026-07-13
- **Branch:** `claude/batch-41-repo-hygiene-db300a` @ `0954826` (= origin/main tip; RC-1 clean, merge-base == origin/main)
- **Route:** /fast-dev-flow (tracked hygiene batch — operator rule 2026-07-13: NO loose direct edits)
- **Run mode:** autonomous + self-merge (operator-stated, batch-41 kickoff; standing auth is per-batch, never carried). Decisions → MEMORY.md at close (fast-flow does NOT sync the vault).
- **security_required:** FALSE — no sensitive pattern genuinely fires. The `escape` pattern match is a keyboard-key false positive (Escape → dismiss modal); no untrusted-input sink, auth, secrets, or external surface changes. batch-39 already hardened the paste/report sinks.
- **Env note:** the assigned worktree `heuristic-wu-1c7c49` is empty/unregistered; the batch-41 branch is checked out in the MAIN repo dir (non-detached). All work happens in `C:/Users/jjgh8/OneDrive/Documents/Github/s19_app`.

## 1. Objective

Clear the tracked repo/test-hygiene carries before the Flow Builder feature: consolidate a duplicated test helper, retire an obsolete test bypass, pay down ruff debt, and land two batch-37 cleanup folds. **No product-behavior change.** Engine-frozen set (source + test) untouched — C-27 dual-guard every increment.

## 2. User stories (developer-facing hygiene)

- **S-⑧ — One canonicalizer.** As a maintainer, I want the report-byte-identity helper defined once (the existing `conftest.canonical_report_bytes`) instead of duplicated as `_canonical_report_bytes` in two test files, so the golden-comparison logic has a single home.
- **S-⑨ — No frozen-dataclass bypass.** As a maintainer, I want the two `object.__setattr__(matcher, "source_name", …)` test bypasses removed, since `source_name` is already a declared field on `ReportFilterMatcher` and `resolve_report_filter(..., source_name=…)` sets it cleanly.
- **S-⑩ — Green ruff.** As a maintainer, I want the repo's real ruff debt cleared (unused imports, placeholder f-strings, dead assignments) so lint stays a signal.
- **S-⑤ — Escape closes the JSON modal.** As a patch-editor user, I want `Escape` to dismiss `ChangeSetJsonScreen` (cancel), matching every other modal, instead of only the Cancel button.
- **S-⑥ — No vestigial constant.** As a maintainer, I want the dead `ENTROPY_STRIP_MAX_CELLS` constant removed (batch-37 replaced it with the fixed-512 page budget governed by the live `ENTROPY_MAX_ROWS`).

## 3. Acceptance criteria (observable)

**S-⑧ (consolidation — refactor, prove via absence + green goldens):**
- **AC-8.1:** After the change, `def _canonical_report_bytes` appears 0 times in `tests/test_before_after_report.py` and `tests/test_tui_report_seam.py`; both import `canonical_report_bytes` from conftest. The report byte-identity ATs (before/after, report-seam, report-filter-surface) stay green (byte-identical goldens — no golden regen).

**S-⑨ (bypass retire — refactor):**
- **AC-9.1:** `object.__setattr__` appears 0 times in `tests/test_before_after_report.py` and `tests/test_diff_report_service.py`; the `_report_matcher` helpers pass `source_name=name` to `resolve_report_filter`. The audit-header tests that read `matcher.source_name` stay green (same rendered name).

**S-⑩ (ruff):**
- **AC-10.1:** `python -m ruff check s19_app tests` reports **0 errors for the 5 touched files** (`cli.py`, `test_a2l_enriched.py`, `test_compare_service.py`, `test_manifest_writer.py`, `test_variant_execution.py`). RED pre-fix: those files report 7 hits (2×F541, 3×F401, 2×F841).
- **Documented carry (NOT fixed):** `s19_app/tui/a2l.py:926` F841 `header` — a2l.py is **engine-frozen**, cannot touch; remains as a known exception. The 2 `.dev-flow/2026-05-20-batch-02/…` handoff F401s are archived non-source and out of scope.

**S-⑤ (Escape binding — behavior add, RED-first):**
- **AC-5.1:** With `ChangeSetJsonScreen` open, pressing `Escape` dismisses it with `None` (cancel) and leaves the change-set document unchanged — asserted via Pilot (`await pilot.press("escape")`, assert screen popped + doc unchanged). RED counterfactual: pre-fix `Escape` is unbound → the modal stays open.

**S-⑥ (constant retire — refactor):**
- **AC-6.1:** `ENTROPY_STRIP_MAX_CELLS` appears 0 times in `s19_app/`; the entropy-viewer tests are repointed to the live `ENTROPY_MAX_ROWS` (= 512 page budget) with their truncation/cap intent preserved, and `tests/test_tui_entropy_viewer.py` stays green. The live `ENTROPY_MAX_ROWS` (page size, `screens.py:1028`) is NOT removed.

## 4. Validation strategy

Per-item: symbol-absence greps (AC-8.1/9.1/6.1), targeted `ruff check` (AC-10.1), and Pilot ATs for the one behavior add (AC-5.1). Refactor items (⑧/⑨/⑥/⑩) carry no behavior change, so the evidence is: the touched symbol/def is gone AND the pre-existing tests that exercise the surface stay green (report goldens byte-identical, entropy caps preserved). Full gate `pytest -q -m "not slow"` (~13 min) run by the orchestrator each increment + at close. **C-27 dual-guard every increment:** `test_engine_unchanged.py` + `test_tui_directionb.py -k "tc031 or tc032"` (0 frozen diffs expected — no frozen file is touched). C-26 touched-symbol reverse census before closing each increment.

## 5. Non-goals (OUT)

- **⑪ P-1 "1-based index convention"** — DEFERRED (operator, batch-41 kickoff): no concrete defect identified; re-logged as an open carry.
- **`s19_app/tui/a2l.py:926` F841** — frozen, cannot fix; documented exception.
- **`.dev-flow/2026-05-20-batch-02` archive ruff hits** — archived non-source handoff; not project source.
- Any engine-frozen module or frozen TEST file (`_ENGINE_TEST_FILES`).
- No golden regen (goldens must stay byte-identical); no new features; no vault sync (fast-flow).

## 6. Detected security flags

- [ ] Auth / identity  · [ ] Secrets / config · [ ] External integrations · [ ] Sensitive data · [ ] Destructive DB
- [~] Input / attack surface — **false positive:** the `escape` keyword match is a keyboard Escape binding (S-⑤), not HTML/shell escaping; no sink or ingress changes.
- [ ] Network / exposure

**`security_required`: false.** No untrusted-input, auth, secret, or external-surface change. Pure test/lint/UX-key hygiene.

## 7. Increment plan (≤5 files each, 3 increments)

1. **Inc-1 — Ruff debt (⑩).** Files: `s19_app/cli.py` (2×F541), `tests/test_a2l_enriched.py`, `tests/test_compare_service.py`, `tests/test_manifest_writer.py` (3×F401 — `ruff --fix` scoped to s19_app+tests), `tests/test_variant_execution.py` (remove 2 dead `chk_*` assignments, keep the file-writing call). = 5 files. AC-10.1.
2. **Inc-2 — Test-helper hygiene (⑧ + ⑨).** Files: `tests/conftest.py` (docstring tidy — drop the "two originals stay untouched" note, refresh Used-by), `tests/test_before_after_report.py` (delete local `_canonical_report_bytes` + repoint; retire `__setattr__` → `source_name=`), `tests/test_tui_report_seam.py` (delete local `_canonical_report_bytes` + repoint), `tests/test_diff_report_service.py` (retire `__setattr__` → `source_name=`). = 4 files. AC-8.1 + AC-9.1.
3. **Inc-3 — batch-37 folds (⑤ + ⑥).** Files: `s19_app/tui/screens.py` (add `BINDINGS` Escape→cancel action on `ChangeSetJsonScreen`; remove `ENTROPY_STRIP_MAX_CELLS` def + docstring ref), `tests/test_tui_entropy_viewer.py` (repoint 7 refs incl. 2 monkeypatches to `ENTROPY_MAX_ROWS`, preserve intent), `tests/test_tui_patch_editor_v2.py` (new AC-5.1 Escape AT). = 3 files. AC-5.1 + AC-6.1.

(3 increments — at the fast-flow ceiling but within it; no promotion to /dev-flow expected.)

## 8. Batch status

| Field | Value |
|-------|-------|
| Current phase | closed |
| Started | 2026-07-13 |
| Closed | 2026-07-13 |
| Promoted to /dev-flow | no |
| Notes | RC-1 clean; branch in main repo dir (worktree empty); P-1 deferred; a2l.py:926 F841 frozen carry |

## 9. Close

### What changed
Five repo/test-hygiene items, no product-behavior change except one modal key binding:
⑧ consolidated the duplicated `_canonical_report_bytes` golden helper in `test_before_after_report.py` + `test_tui_report_seam.py` onto the existing `conftest.canonical_report_bytes` (now imported by all 3 report consumers); ⑨ retired the two obsolete `object.__setattr__(matcher, "source_name", …)` bypasses — `source_name` is already a declared field, so both now pass `source_name=` to `resolve_report_filter` (zero production change); ⑩ cleared 7 of 8 real ruff hits (2 F541 in `cli.py`, 3 F401, 2 F841 dead assignments); ⑤ added an `Escape`→cancel `BINDINGS` to `ChangeSetJsonScreen`; ⑥ removed the vestigial `ENTROPY_STRIP_MAX_CELLS` constant and repointed its test refs to the live `ENTROPY_MAX_ROWS` page budget.

### How it was tested
- Full gate `pytest -q -m "not slow"`: **1394 passed / 2 skipped / 3 xfailed / 0 failed** (31 snapshots passed).
- Inc-1: ruff exit 0 on the 5 files; 50 passed. Inc-2: 95 report/diff tests passed (byte-identical goldens). Inc-3: 21 entropy + 24 escape/popup passed.
- AC-5.1 RED-first demonstrated: with `screens.py` reverted the Escape AT fails (`assert True is False` — popup stays open); GREEN after.
- C-27 dual-guard clean after Inc-1 and Inc-3 (0 frozen diffs). C-26 reverse census: `_canonical_report_bytes` / `object.__setattr__` / `ENTROPY_STRIP_MAX_CELLS` absent as code across `tests/` + `s19_app/`.

### Open risks / pending (carries, NOT fixed)
- `s19_app/tui/a2l.py:926` F841 `header` — engine-frozen, cannot fix; repo ruff shows exactly this 1 error.
- ⑪ P-1 "1-based index convention" — deferred (no concrete defect).
- `.dev-flow/2026-05-20-batch-02` archived-handoff ruff hits — non-source, out of scope.

### Security flags — handling
`security_required: false`. No sensitive pattern genuinely fired (the `escape` match was a keyboard-key false positive). No untrusted-input/auth/secret/external-surface change.

### Suggested commit message
```
chore(tui): batch-41 — repo & test hygiene (ruff, canonicalizer + __setattr__ retire, Escape fold, entropy const)
```
