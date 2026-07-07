# Increment 003b — entropy-viewer snapshot cells (US-036, xfail-until-baseline)

> Phase 3, batch-26. NON-GATING layout-drift regression artifact for
> `EntropyViewerScreen`. The behavioral verdict for US-036 is the Inc-3 Pilot
> ATs (AT-036a/b/c) — this increment adds only the snapshot scaffold.

## 1. What changed

- Added **2 SVG snapshot cells** for the entropy-viewer modal
  (`EntropyViewerScreen`) at **80×24** (floor) and **120×30** (primary) to the
  existing batch-25 pinned-textual snapshot suite.
- Both cells are marked **`xfail(reason="baseline pending canonical-CI regen —
  batch-26 US-036", strict=False)`**, mirroring the batch-22 patch-editor cells
  that were CI-locked as xfail until real baselines were generated in the
  canonical CI env (dropped by batch-25).
- New helper `_entropy_run_before(triple)`: installs the public synthetic triple
  (LLR-007.2 — no client artifact) then presses the `e` key binding to open the
  modal over the loaded image. The public S19 is a random-filled multi-range
  image, so `compute_entropy` yields several windows spanning ≥2 entropy bands →
  the strip renders ≥2 distinct band colours.
- New test `test_tc036s_entropy_modal_snapshot` (dedicated, because the entropy
  modal is a pushed `ModalScreen`, not a rail screen — it drives the `e` binding
  rather than `action_show_screen`).
- Count/doc updates: module docstring notes the 2 additive non-gating TC-036-S
  cells; the `tui-ci.yml` snapshot step name now reads "28 baseline cells + 2
  xfail-until-baseline entropy cells".

## 2. Files modified (2)

- `tests/test_tui_snapshot.py` — helper + parametrized xfail cells + test + docstring.
- `.github/workflows/tui-ci.yml` — snapshot job step name (count annotation only).

No existing cell, baseline `.svg`, or non-test source touched. No baseline
generated (`--snapshot-update` never run).

## 3. How to test

```bash
# from the worktree root, dev extra installed (pytest-textual-snapshot + textual==8.2.8)
pip install -e ".[dev]"
pytest tests/test_tui_snapshot.py -m snapshot -q
ruff check tests/test_tui_snapshot.py
```

## 4. Test results (real)

Full snapshot suite (`pytest tests/test_tui_snapshot.py -m snapshot -q`):

```
19 failed, 9 passed, 3 deselected, 2 xfailed, 1 warning in 28.72s
```

- **The 2 new entropy cells report `xfailed` (expected-fail), NOT `failed`** — the
  required outcome. `snap_compare` finds no committed baseline; xfail(strict=False)
  converts the miss into an expected fail.
- **The 19 `failed` cells are the pre-existing 28-baseline matrix, and they fail
  from the Inc-3 FEATURE CODE alone, not from this increment.** Proven by
  isolation:
  - `git stash` (reverts feature code + test edits) → **28 passed** (baselines
    match pre-entropy UI).
  - stash only the test-file + workflow edits (feature code present, my test edits
    reverted) → **19 failed, 9 passed** — byte-identical failure set to the run
    with my edits present. So my test-file changes do not affect any existing
    cell; the drift is the new `e`/Entropy footer binding + entropy styles
    changing every screen's rendered footer vs the pre-feature committed baselines.
- This drift is expected and by design: the snapshot job is `continue-on-error:
  true` (non-gating) precisely to absorb feature UI drift until the canonical-env
  regen re-baselines. The same batch-25 `snapshot-regen.yml` pass that generates
  the 2 entropy baselines will also refresh the 19 drifted cells (feature-ships →
  regen-follows, the batch-25 pattern).

Ruff (`ruff check tests/test_tui_snapshot.py`): exit 0. One `F401 Optional`
finding, **pre-existing on HEAD** (`git show HEAD:… | ruff check -` reproduces
it) — not introduced here; left untouched per surgical-changes discipline. My
additions introduce zero new findings.

## 5. Xfail rationale + where baselines will be generated

Per the snapshot-regen-env convention (memory `snapshot-regen-env`; batch-25
pinned `textual==8.2.8` and regenerates baselines ONLY in the canonical Linux CI
env), baselines are **never generated locally** — a local regen drifts unrelated
cells and breaks the CI oracle. So the 2 cells ship without baselines and are
`xfail(strict=False)`: an expected fail today, never a hard failure, and never a
fabricated local pass (batch-22 lesson). Baselines are generated later via
`.github/workflows/snapshot-regen.yml` (`workflow_dispatch` → artifact, canonical
env, pinned textual). A follow-up then drops these two xfails exactly as batch-25
did for the 2 patch cells (commit 35238ea).

## 6. Risks

- **Low.** Additive-only; no gating test, no baseline, no source-render change.
- The 19 drifted baseline cells are on the NON-GATING (`continue-on-error`)
  snapshot job → they surface in the run log but do not block merge. They are
  resolved by the same canonical regen that baselines the entropy cells, not by
  this increment.
- `strict=False` means if a baseline is ever committed and matches, the cell
  becomes `xpassed` (not an error) — the intended transition signal for the
  follow-up that drops the xfail.

## 7. Pending items / suggested next task

- **Canonical-CI baseline regen** (follow-up, not this increment): run
  `snapshot-regen.yml` in the canonical env after the batch-26 feature merges;
  commit the regenerated `.svg` set (2 new entropy baselines + the 19 refreshed
  drifted cells); then drop the 2 entropy xfail marks → all cells green, zero
  xfail (batch-25 pattern).
- Optional: fold the pre-existing `F401 Optional` cleanup into an unrelated
  hygiene pass (out of scope here).

## Evidence checklist

- [✓] Tests/lint: `2 xfailed` (new cells expected-fail, not failed); ruff exit 0,
  zero new findings (F401 pre-exists on HEAD).
- [✓] No secrets: snapshot renders only the public synthetic triple (LLR-007.2).
- [✓] No destructive commands: no `--snapshot-update`, no baseline written/committed.
- [✓] File count within cap: 2 files.
- [✓] Review packet: this document.
