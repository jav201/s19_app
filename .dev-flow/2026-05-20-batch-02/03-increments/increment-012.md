# Increment 012 — Snapshot test increment (`pytest-textual-snapshot`)

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" restyle)
**Phase:** 3 — Implementation (final increment)
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**Date:** 2026-05-20
**LLRs:** LLR-007.1, LLR-007.2
**TCs:** TC-016 (CV-04 boundary sub-case), TC-016-S

---

## 1. What changed

This is the final increment of the batch — the dedicated **layout-drift snapshot**
increment. It adds the `pytest-textual-snapshot` SVG baseline matrix and the CV-04
breakpoint boundary check; it adds **no production behavior** and touches **no engine
module**.

A new `tests/test_tui_snapshot.py` implements **TC-016-S** — the narrowed
**27-baseline** snapshot matrix pinned by requirements §5.5: the 4 restyled screens
(Workspace, A2L Explorer, MAC View, Issues Report) × {compact, comfortable} ×
{80×24, 120×30, 160×40} = 24 baselines, plus the 3 additive scaffold screens (Memory
Map, Patch Editor, A↔B Diff) at the 120×30 primary size only = 3 baselines. The 27
approved baseline `.svg` files were generated into `tests/__snapshots__/` and verified
to re-match. Every baseline is rendered **only** against the public synthetic fixtures
— the `tests/conftest.py` generators `make_large_s19` / `make_large_a2l` /
`make_large_mac` (LLR-007.2 / S-2); no client artifact is opened. The snapshot tests
carry the `snapshot` pytest marker (registered in increment 1) so they are
deselectable on a constrained CI via `pytest -m 'not snapshot'`.

The same file implements the **CV-04 119/120-column breakpoint boundary check** as two
plain `run_test()`-based tests (no snapshot library): one pins the static regime per
width (proportional `width-narrow` at 119, fixed at 120), one drives a live resize
across the boundary in both directions. The CV-04 checks run on every environment
regardless of whether `pytest-textual-snapshot` is installed.

`pytest-textual-snapshot==1.1.0` (the version pinned in this batch's own
`pyproject.toml` `[project.optional-dependencies] dev` extra — increment 1) **was
installed** in this environment and the 27 baselines **were generated and verified**.
`tests/conftest.py` was **not** modified — the existing generators worked unchanged, so
no snapshot-specific fixture wiring was needed (the increment plan listed it as
"only if needed").

## 2. Files modified

| File | Purpose |
|------|---------|
| `tests/test_tui_snapshot.py` | **New.** The 27-baseline `pytest-textual-snapshot` matrix (TC-016-S), the LLR-007.2 public-fixture-source assertion, and the CV-04 119/120-column boundary check (two `run_test()` tests). |
| `tests/__snapshots__/test_tui_snapshot/` | **New.** 27 approved baseline `.svg` files (one directory, one file slot per the increment plan). Every baseline traces to a `conftest.py` public synthetic generator. |
| `.gitignore` | Added `snapshot_report.html` and `.screenshot_cache/` — the plugin's generated report / cache artifacts (build artifacts, like `.pytest_cache/`); never committed. |

**3 files** — within the ≤5-file cap. No production code, no engine module, no
`app.py`, no widget module, and no existing test file was modified.

### New tests (all carry a `TC-NNN` / `CV-NN` reference, matching conventions)

- `test_tc016s_density_layout_snapshot[<screen>-<density>-<size>]` — the 27-cell
  parametrized snapshot matrix; `@pytest.mark.snapshot`, skipped (not failed) if the
  plugin is absent.
- `test_tc016s_snapshot_setup_loads_only_public_fixtures` — LLR-007.2 public-fixture
  sub-case: the fixture source is the `conftest.py` generators; every generated file
  lives in a pytest temp dir; the setup code (docstrings stripped) references no
  non-public path. Runs without the snapshot library.
- `test_cv04_breakpoint_boundary_119_proportional_120_fixed` — CV-04: the proportional
  regime is in effect at width 119, the fixed regime at width 120.
- `test_cv04_breakpoint_boundary_on_live_resize` — CV-04: a live resize across
  119↔120 flips the `width-narrow` regime in both directions.

## 3. How to test

```bash
# The snapshot matrix (27 baselines) — requires the dev extra installed
python -m pytest tests/test_tui_snapshot.py -q -m snapshot

# The non-snapshot tests (CV-04 boundary + public-fixture sub-case) — always run
python -m pytest tests/test_tui_snapshot.py -q -m "not snapshot"

# Regenerate baselines (reviewed gate — only on an intentional layout change)
python -m pytest tests/test_tui_snapshot.py -m snapshot --snapshot-update

# Full suite (must hold 0 failed)
python -m pytest -q

# App still launchable
python -c "import s19_app.tui"

# ruff is NOT installed in this environment — substituted with py_compile
python -m py_compile tests/test_tui_snapshot.py
```

## 4. Test results — actual output

**`pytest-textual-snapshot` install (declared dev extra, pinned `==1.1.0`):**

```
Successfully installed pytest-textual-snapshot-1.1.0 syrupy-4.8.0
```

Installed successfully — the version pinned in the batch's own `pyproject.toml` dev
extra. Baselines **were** generated in this environment (no CI gap, unlike `ruff`).

**Baseline generation (`--snapshot-update`):**

```
27 snapshots generated.
27 passed, 3 deselected in 23.08s
```

**Snapshot matrix re-run (no `--snapshot-update` — baselines must match):**

```
27 snapshots passed.
27 passed, 3 deselected in 22.75s
```

**Baseline directory — exactly 27 `.svg` files:**

```
tests/__snapshots__/test_tui_snapshot/  →  27 files
  24 restyled : {workspace,a2l,mac,issues} × {compact,comfortable} × {80x24,120x30,160x40}
   3 scaffold : {map,patch,diff} at comfortable-120x30
```

**CV-04 boundary + public-fixture sub-case (`-m "not snapshot"`):**

```
3 passed, 27 deselected in 1.31s
```

(The 3 = `test_cv04_breakpoint_boundary_119_proportional_120_fixed`,
`test_cv04_breakpoint_boundary_on_live_resize`,
`test_tc016s_snapshot_setup_loads_only_public_fixtures`.)

**`snapshot` marker deselection works** — `-m "not snapshot"` deselects all 27
baseline cells, keeps the 3 library-independent tests.

**Full suite (`pytest -q`):**

```
419 passed, 2 skipped, 3 xfailed in 162.30s (0:02:42)
27 snapshots passed.
```

- Pre-increment baseline (after increment 11): **389 passed / 2 skipped / 3 xfailed /
  0 failed**.
- After increment 12: **419 passed / 2 skipped / 3 xfailed / 0 failed**.
- Delta: **+30 passed** = 27 snapshot cells + 1 public-fixture sub-case + 2 CV-04
  boundary tests. **0 failed, 0 regressions.** The 2 skipped and 3 xfailed are the
  documented pre-existing baseline cases — unchanged.

**S-2 leak check (committed `.svg` baselines):**

```
grep -i  case_0[1-6] | professional_validation | client | BalanceTube | STMicro | ASAP2_Demo
  →  0 matches across all 27 SVGs
grep     snap.s19 | snap.a2l | snap.mac | MEAS_ | CHAR_ | SNAP_
  →  matches (synthetic generator content only)
```

Every committed baseline embeds **only** synthetic generator content (`snap.*`
filenames, `MEAS_*` / `CHAR_*` / `MAC_TAG_*` / `SNAP_*` synthetic symbols). No client
firmware name, no non-public `examples/` case directory, no proprietary symbol appears
in any committed `.svg`. **LLR-007.2 verdict: PASS.**

**`import s19_app.tui`:** `import s19_app.tui OK`.

**`py_compile`:** `py_compile tests/test_tui_snapshot.py OK` (ruff not installed —
`py_compile` substituted per the brief).

### Verdict summary

| TC | LLR | Verdict | Evidence |
|----|-----|---------|----------|
| TC-016-S | LLR-007.1 | PASS | 27 baselines generated + re-verified; matrix matches §5.5 exactly (24 restyled + 3 scaffold). |
| TC-016-S (public-fixture sub-case) | LLR-007.2 | PASS | Snapshot setup loads only the `conftest.py` generators; 0 client/non-public tokens in any committed `.svg`. |
| TC-016 (CV-04 boundary) | LLR-007.1 | PASS | Proportional regime at width 119, fixed at 120 — pinned statically and on a live resize. |

## 5. Risks

- **Snapshot environment sensitivity.** `pytest-textual-snapshot` SVGs depend on the
  Textual version and the rendering environment. The baselines here were generated on
  `textual 8.0.2` (the `>=` floor in `pyproject.toml`) on Windows. A different
  `textual` minor version or a font-metric difference on another machine could produce
  a diff that is environmental, not a real regression. Mitigation: the `snapshot`
  marker makes the matrix deselectable (`-m 'not snapshot'`); baseline regeneration is
  a reviewed gate, not auto-accept (requirements §5.5). If the team's CI pins a
  different `textual`, the baselines should be regenerated once on that environment
  and re-reviewed.
- **27-file diff review discipline.** A future PR that legitimately changes a layout
  will produce up to 27 changed `.svg` files. The matrix is already narrowed from
  ~48 to 27 to keep it reviewable, but a reviewer must still treat a baseline diff as
  an intentional-change gate, not rubber-stamp it. The `--snapshot-report` HTML the
  plugin emits is the intended review aid.
- **`run_before` setup vs. real load pipeline.** The snapshot `run_before` installs
  the `LoadedFile` through the load/parse **services** directly (the deterministic
  headless path used by every increment-5/6/7 test) rather than the off-thread load
  worker. This is the established, intentional test pattern in this batch; it
  faithfully exercises the same renderers but does not snapshot the load-progress
  transient states — those are not part of the LLR-007.1 layout-integrity contract.
- **No empty-state baseline.** Per the TC-016-S note (CV-03), the 27-baseline matrix
  renders only file-loaded screens, so the no-file empty-state *layout* is not
  snapshot-guarded. Empty-state layout is functionally covered by TC-037 (increments
  2/7); only empty-state layout *drift* is unguarded. The optional 120×30 empty-state
  baseline was left out at implementer discretion (it would add an un-pinned 28th
  baseline outside the §5.5 count).
- **`syrupy` transitive dependency.** Installing `pytest-textual-snapshot==1.1.0`
  pulled `syrupy==4.8.0` as a transitive dev dependency. This is dev/test-only and
  does not touch the `s19tui` runtime footprint (`rich`, `textual`) — consistent with
  the C-2 scoped exception. It is implied by the declared dev extra, not a new
  unapproved dependency.

## 6. Pending items

- None for this increment. TC-016-S (27 baselines) and the CV-04 boundary check are
  implemented, generated and passing; the full suite is green at **419 passed / 2
  skipped / 3 xfailed / 0 failed**.
- **Cross-functional handoff — `security-reviewer` (S-2).** Per the increment plan,
  the 27 committed snapshot `.svg` baselines should get a `security-reviewer`
  confirmation that no client data leaked. Evidence is provided in §4 (the S-2 leak
  grep: 0 non-public tokens; all content is synthetic-generator output) — this is a
  recommended sign-off, not a blocker.
- **Phase 3 is complete.** All 12 increments of batch-02-direction-b-restyle are
  implemented and approved. All 38 LLRs and all 38 active TCs (TC-001..TC-039 +
  TC-016-S; TC-005 retired N/A) are covered.

## 7. Suggested next task

**Phase 3 (Implementation) is complete — the batch advances to Phase 4
(Validation).** Increment 12 is the final increment of the V-model implementation
phase. Phase 4 runs the consolidated validation gate against the §5.8 batch acceptance
criteria (AC-B1..AC-B8): full traceability, the green `pytest` suite, the snapshot
verdict, the engine-freeze verdict, and the zero-blocker rule. The two recommended
`security-reviewer` sign-offs folded across the batch — increment 4 (command bar, new
input surface, S-1), increment 8 (modals, path containment, S-4), and increment 12
(snapshot baselines, client-data leak, S-2) — should be collected before the Phase 4
gate closes. No further implementation increment is planned.
