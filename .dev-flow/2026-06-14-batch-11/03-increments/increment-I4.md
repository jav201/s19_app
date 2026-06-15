# Increment I4 (FINAL) — TUI manifest write + verify surface (HLR-004)

Batch: 2026-06-14-batch-11 · US-010 · **Closes Phase 3.**
Branch: `claude/batch-11` (worktree `competent-clarke-1e8940`). Not committed — orchestrator commits at the gate.

---

## 1. What changed

Wired the manifest serialize→write→verify pipeline (built headless in I1–I3) into
the TUI project-save flow and surfaced the verify outcome. After the existing
file-copy save rebuilds the active `ProjectVariantSet`, `_handle_save_dialog`
now calls a new orchestration-only helper `_write_and_verify_manifest`, which
invokes the headless `write_project_manifest` then `verify_written_manifest` and
hands the `ManifestVerifyResult` to `_surface_manifest_verify_result`. Surfacing
mirrors batch-10's `_surface_verify_result` quiet/loud shape: a quiet
"Project saved + manifest verified" status on verified; a loud
`severity="error"` notice naming the drift key(s) + plain-text reader-issue
messages on mismatch; and an error notice with the plain-text containment/IO
issue message on a write refusal (`(None, issues)`) — never a crash. app.py
stays orchestration-only: it contains no serialize/write/verify logic, only
calls into the service and renders. Added `R-VAR-003` to REQUIREMENTS.md and a
new TUI pilot test file.

**Scope decision (flagged):** the existing save flow composes no `batch` /
`assignments` lists — it only copies the primary/MAC/A2L files. I therefore
persist `active_variant` (from the rebuilt variant set) with empty
`batch`/`assignments`, which captures the US-010 active-variant-selection
benefit, round-trips cleanly through the reader oracle, and keeps the edit
surgical. Composing `batch`/`assignments` from copied files is not specified for
this batch and would be scope creep — deferred.

## 2. Files modified

| File | Δ | Purpose |
|------|---|---------|
| `s19_app/tui/app.py` | +114 | Import the 3 writer symbols; wire `_handle_save_dialog`; add `_write_and_verify_manifest` + `_surface_manifest_verify_result` (orchestration-only). |
| `tests/test_tui_manifest_save.py` | NEW, 305 | 4 `run_test` pilots: write+quiet-verify, loud mismatch naming drift, refusal error notice (no crash), headless-module probe. |
| `REQUIREMENTS.md` | +35 | New `R-VAR-003` (manifest write+verify, US-010 / HLR-001..004), `Automated`. |

Not touched (by design): `s19_app/tui/screens.py` (existing `SaveProjectPayload`
carries enough — `parent_folder` + `project_name`); `s19_app/tui/services/__init__.py`
(empty by convention — app.py imports the module path directly).

Integration point: **`s19_app/tui/app.py:3535`** — the call
`self._write_and_verify_manifest(project_dir)` sits in `_handle_save_dialog`
(handler at `app.py:3437`) right after the save status line and before
`update_project_labels()`. New helpers: `_write_and_verify_manifest`
(`app.py:3539`), `_surface_manifest_verify_result` (`app.py:3595`).

## 3. How to test

```bash
# New TUI pilots (this increment)
python -m pytest -q tests/test_tui_manifest_save.py

# I1-I3 regression (must stay 19)
python -m pytest -q tests/test_manifest_writer.py tests/test_manifest_verify.py

# Lean suite
python -m pytest -q -m "not slow"

# Collection count
python -m pytest -q --collect-only        # last line

# app.py orchestration-only probes
rg -n "serialize_manifest|json.dump|os.replace" s19_app/tui/app.py     # no NEW manifest logic
rg -n "write_project_manifest|verify_written_manifest" s19_app/tui/app.py  # >=1 (calls the service)

# headless module probe
rg -n "import textual|getLogger|import logging" s19_app/tui/services/manifest_writer.py  # 0

# engine-frozen + rail guards
python -m pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "tc031 or rail"
git diff --stat origin/main -- s19_app/tui/rail.py   # empty
```

## 4. Test results (actual)

| # | Check | Result |
|---|-------|--------|
| 1 | `tests/test_tui_manifest_save.py` | **4 passed** in 4.38s |
| 2 | manifest regression (writer+verify) | **19 passed** in 0.39s |
| 3 | lean `-m "not slow"` | **786 passed, 29 skipped, 21 deselected, 3 xfailed** in 188.74s — **0 failures** (pre lean 782 → 786, +4 new) |
| 4 | `--collect-only` last line | **`839 tests collected in 0.54s`** (pre 835 → 839, +4 new; spec §5.3.1 predicted 829–833 off the 816 baseline — see deviation note) |
| 5a | `rg serialize_manifest\|json.dump\|os.replace s19_app/tui/app.py` | **2** — BOTH pre-existing & unrelated (`app.py:678` debug-log `json.dumps`; `app.py:2744` A2L-export `json.dumps`); origin/main has the same 2. **New lines added by I4 matching the probe = 0** (`git diff origin/main … \| rg '^\+' \| rg …` → 0). No manifest serialize/write/verify logic in app.py. |
| 5b | `rg write_project_manifest\|verify_written_manifest s19_app/tui/app.py` | **7** (≥1 — import + 2 wiring calls + docstrings) |
| 6 | engine-frozen + rail guards (`-k "tc031 or rail"`) | **9 passed**, 90 deselected; `git diff --stat origin/main -- s19_app/tui/rail.py` → **empty** |
| 7 | `rg import textual s19_app/tui/services/manifest_writer.py` | **0** |
| 8 | A-3/V-5 reconciliation | see §A-3/V-5 below |

No coverage tool was run; "covered" below means a passing TC exercises the
behavior, not a line-coverage percentage.

## 5. Risks

- **Save outside the work area.** If the operator chooses a parent folder
  outside `.s19tool/workarea/`, the existing file-copy save (`copy_into_workarea`)
  rejects it FIRST (status "Cannot save project…") and the handler returns before
  the manifest pipeline runs — so the manifest-refusal branch is not reachable
  via the parent-folder path in practice. The refusal SURFACING branch is still
  tested directly (patched `write_project_manifest` → `(None, issues)`), since
  `write_project_manifest`'s own containment can refuse for other reasons (e.g. a
  reparse-point ancestor). Behavior is correct either way: no crash, no
  `project.json` left behind.
- **Empty `batch`/`assignments` written.** By the scope decision the saved
  manifest carries only `active_variant`; a project that needs explicit
  `batch`/`assignments` still requires hand-authoring those keys. Not a
  regression (the reader treats absent lists as empty / batch-all). Deferred.
- **Mismatch test forces drift via tamper.** The mismatch pilot tampers the
  on-disk file between the real write and the real verify (Rule 9: the planted
  `active_variant` flip is exactly the asserted drift key), so it exercises the
  real verify + real surfacing path, not a stubbed result.

## 6. Pending items

**None for I4.** Phase 3 (HLR-001..004) is complete. Out-of-batch deferrals
(unchanged): the CRC first-operation fill-in (QUEUED); composing
`batch`/`assignments` from copied files at save time (not specified this batch).

## 7. Suggested next task

Phase 4 validation: run the full validation matrix (incl. the V-3
supersession-completeness row and the V-4 import-purity probe in
import-statement form), reconcile the collection baseline (839) into
`04-validation`, and confirm `R-VAR-003` status. No further code expected.

---

## Phase-3 closure note

I4 closes Phase 3 of batch-11. The four HLRs are now implemented and covered:

| HLR | Increment | Status |
|-----|-----------|--------|
| HLR-001 serialize + refusal gate | I1 (27b34ae) | covered — `tests/test_manifest_writer.py` |
| HLR-002 contained write | I2 (8dd8498) | covered — `tests/test_manifest_writer.py` |
| HLR-003 verify-on-write | I3 (93adb2f) | covered — `tests/test_manifest_verify.py` |
| HLR-004 TUI surface | I4 (this) | covered — `tests/test_tui_manifest_save.py` |

`project.json` is no longer read-only: the read↔write symmetry that batch-10
established for firmware images (write → re-read → diff) now holds for the
project manifest (write → re-read → key-wise compare), with the reader as the
single oracle.

## A-3 / V-5 reconciliation (provisional → actual)

Spec node ids / `-k` selectors / file paths were `provisional until Phase 3`
(V-5). The implemented names for the I4 (HLR-004) surface:

| Spec (provisional) | Implemented (actual) |
|--------------------|----------------------|
| `tests/test_manifest_*` (TUI surface home unstated) | `tests/test_tui_manifest_save.py` (NEW) |
| TC-004a / LLR-004.1 inspection (save handler calls pipeline) | `test_project_save_writes_and_verifies_manifest` |
| TC-D1 / LLR-004.2 verified branch | `test_project_save_writes_and_verifies_manifest` (quiet status assertion) |
| TC-D1 / LLR-004.2 mismatch branch | `test_manifest_mismatch_surfaces_loud_notice_naming_drift` |
| TC-D1 / LLR-004.2 refusal branch | `test_manifest_write_refusal_surfaces_error_notice_no_crash` |
| TC-004b / LLR-004.3 no-textual probe | `test_manifest_writer_module_is_headless` |
| save handler method (LLR-004.1, unpinned per V-5) | `_handle_save_dialog` (`app.py:3437`) → `_write_and_verify_manifest` (`app.py:3539`) |
| surfacing method/widget id (LLR-004.2, unpinned per V-5) | `_surface_manifest_verify_result` (`app.py:3595`); surfaced via `set_status` + `notify(severity="error")` (no new widget) |

**A-3 new-symbol-into-existing-file:** the only existing file edited with NEW
symbols is `app.py` (the two helpers + the import). `app.py ∉ _ENGINE_PATHS`
(engine-frozen guards green, V-6); no new symbol targets a frozen/allowlisted
file. Confirmed at the gate by the full suite (786 lean / 9 guard tests green).

## Ledger

| Metric | Pre-I4 | Post-I4 |
|--------|--------|---------|
| Lean (`-m "not slow"`) passed | 782 | 786 (+4) |
| Collection (`--collect-only`) | 835 | 839 (+4) |
| manifest writer+verify | 19 | 19 |
| failures | 0 | 0 |

## Deviation (loud)

- **Collection-count baseline drift, NOT introduced by I4.** Spec §5.3.1 pinned
  the baseline at **816** and predicted post ≈ 829–833. The measured baseline at
  I4 start was **835** (so +19 had already accrued across I1–I3 plus other
  in-flight nodes vs the 816 the spec measured on 2026-06-14). I4 adds **+4**
  (835 → **839**). The +4 delta is exactly the new test file's node count and is
  on-model; the absolute number exceeds the spec's 829–833 only because the
  *baseline itself* moved from 816 to 835 between Phase-1 measurement and Phase-3
  I4. Flagged for Phase-4 baseline reconciliation. No nodes were deleted.
- **Probe #5a is non-zero (2) by probe wording, not by violation.** The prompt
  expected `rg serialize_manifest|json.dump|os.replace s19_app/tui/app.py` → 0.
  The 2 hits are pre-existing, unrelated `json.dumps` calls (debug log +
  A2L export) present identically on origin/main; I4 added **0** new lines
  matching the probe. The probe's intent (no manifest serialize/write/verify
  logic in app.py) holds.
