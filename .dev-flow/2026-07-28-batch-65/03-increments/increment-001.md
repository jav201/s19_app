# batch-65 — Increment 1 — Review Packet

> **Scope: TESTS AND GOLDEN ONLY.** `s19_app/tui/services/report_service.py` was **not** touched —
> `git diff --stat 082ada9 -- s19_app/` is **empty**, which is what makes the golden a capture *from*
> the shipped producer rather than a certificate the rewrite writes for itself (C-12).

## 0. Toolchain entry gate (first action, per the brief)

| tool | declared | found | verdict |
|---|---|---|---|
| Python | 3.11 in CI | **3.14.4** | present — nothing installed |
| `pytest` | required | **8.4.2** | present |
| `ruff` | required | **0.15.17** | present |

No tool was missing, so nothing was installed and nothing was silently skipped.

---

## 1. What changed

Authored the batch-65 acceptance and test nodes for `R-TUI-098` / `HLR-103` / `LLR-103.1…103.6` — **29
collected pytest nodes over the 28 live ids of §6.2** — and captured the byte-identity golden **from the
SHIPPED `_addendum_lines` at base revision `082ada9`**, before the producer is rewritten. The nodes are
authored to the verdicts §11.1 derived by execution: **13 RED · 12 GREEN regression guards · 4
`xfail(strict=True)`**. Two mechanisms the spec decided rather than delegating are implemented exactly as
written:

1. **`_const(name, fallback)` inside test bodies, never a module-level import** (§11.1 note 4). A
   module-level import of `MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION` on this tree is a pytest **collection
   error**, which `xfail` does not cover and which would take down every node in the file. A RED produced
   by an `ImportError` proves nothing about whether the predicate reaches the behaviour.
   `pytest --collect-only` reports **0 errors**, which is the evidence that no such import survived.
2. **Addendum-scoped notice counting with the `or EOF` arm, and an empty scope FAILS** (§3 US-B64-2,
   revision 3). `_addendum_scope` raises when the heading is absent or the span is blank, so "no notice"
   can never be read out of "no scope". Executed on a real report: the addendum is heading **#7 of 7**
   and there is **no** following `^## ` — the EOF arm is load-bearing, not defensive.

## 2. Files modified

- `tests/test_report_addendum_bound.py` — **NEW**. 28 collected nodes: `AT-194`, `AT-196…AT-199`,
  `AT-201…AT-203`, `TC-480…TC-495`, `TC-498`, `TC-499`, plus the scope/notice oracle, the fixture
  builders, the re-iterable counting instrument, and the golden capture procedure `_capture_golden`.
- `tests/goldens/batch64/addendum-below-bound.md` — **NEW**, 155 702 bytes, six delimited documents
  (the architect lane's five `(R,V,E)` shapes + the qa lane's hostile `FIXGOLD`), every one **below the
  per-(region, class) bound**, captured from the shipped producer. Host-path scan of the committed
  bytes: **0** matches for `[A-Za-z]:[\/]` / `/Users/` / `/home/` / the operator's username.
- `tests/test_tui_report_seam.py` — **extended** with `AT-200` and its flood change-document writer
  (+144 lines, 0 deletions). No existing test in this file was modified; `_write_change_document` is
  untouched because the `AT-055b` golden was captured over it.

Three files — exactly the §11.1 allocation, within the ≤ 5 cap.

## 3. How to test

```bash
python -m pytest tests/test_report_addendum_bound.py -q -rf
python -m pytest tests/test_tui_report_seam.py -q -k at200
python -m pytest tests/test_report_addendum_bound.py --collect-only -q   # 0 errors

# §6.3 regression subsets — per subset, NOT merged into one number
python -m pytest -q tests/test_report_service.py tests/test_tui_report_seam.py \
                   tests/test_report_field_census.py tests/test_manifest_writer.py \
                   tests/test_capped_text_area.py
python -m pytest -q tests/test_report_service.py tests/test_report_addendum.py
python -m pytest -q tests/test_tui_report_filter_surface.py tests/test_before_after_report.py

# BOTH frozen guards — a single-guard check is incomplete
python -m pytest -q tests/test_engine_unchanged.py
python -m pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"

python -m ruff check tests/test_report_addendum_bound.py tests/test_tui_report_seam.py
```

Golden re-capture (valid **only** against the pre-batch-65 producer):

```bash
python -c "import sys,tempfile; sys.path.insert(0,'tests'); \
from pathlib import Path; from test_report_addendum_bound import _capture_golden; \
print(_capture_golden(Path(tempfile.mkdtemp())))"
```

## 4. Test results

### 4.1 Observed vs §11.1 expected — every node, all four columns

Every figure in the table below comes from **one** complete run of each file — not stitched.

Run A — `python -m pytest tests/test_report_addendum_bound.py -q --tb=line -rf`
→ tail **`12 failed, 12 passed, 4 xfailed in 1.25s`**, **exit code 1**. All 12 RED messages in the table
are that run's own `--tb=line` output.

Run B — `python -m pytest tests/test_tui_report_seam.py -q -k "at200 or declared_region_in_dialog" --tb=line`
→ tail **`1 failed, 1 passed, 26 deselected in 13.80s`**, **exit code 1**. `AT-200`'s row is that run's
own output; the passing node is the pre-existing `AT-024c` declared-region drive `AT-200` extends.

| node | §11.1 expected @ Inc-1 | category / rule | **observed** | evidence from this run |
|---|---|---|---|---|
| `AT-194` | RED | ratio-valued | **RED** | `delta(E=2000)=408661 delta(E=4000)=1052325 ratio=2.575 > 1.30` — margin **98 %** over (≥ 25 % required) |
| `AT-196` | GREEN — regression guard, by construction | boolean | **GREEN** | 6/6 shapes byte-identical to the Inc-1 golden |
| `AT-197` | RED | boolean | **RED** | `expected exactly 1 addendum notice for 'change-file issue'; observed 0 — all addendum notices: []` |
| `AT-198[le_K]` | GREEN by vacuity | boundary-valued | **GREEN** | class total 199 → notices `[]` |
| `AT-198[K_plus_1]` | RED | boundary-valued | **RED** | `class total 201 == K+1 must produce EXACTLY 1 addendum notice line; observed 0: []` |
| `AT-198[interior]` | GREEN by vacuity | boundary-valued | **GREEN** | class total 200 → notices `[]`, hit lines `200` |
| `AT-199` | RED | boolean | **RED** | `at a class total of K+1 the addendum must carry exactly ONE genuine notice; observed []` — the escaping arms above it passed first |
| `AT-200` | RED | boolean | **RED** | `201 in-region entries per variant exceed the cap 200, but the written report discloses nothing; addendum-scoped notices in the file: []` |
| `AT-201` | RED | boolean | **RED** | `the notices name []; the classes actually cut are ['change-file issue']` |
| `AT-202` | RED | boolean | **RED** | `expected exactly one addendum notice to read the variant field from; observed []` |
| `AT-203` | RED | boolean | **RED** | `the flooded region's sub-section must carry exactly the one notice for its cut class; observed []` — both `### ` sub-sections asserted FOUND first |
| `TC-480` | RED | boolean | **RED** | `the region renders 201 hit lines of the cut class, above the bound 200` |
| `TC-481` | GREEN by vacuity | boundary-valued | **GREEN** | 199 hit lines ≤ 200, notices `[]` |
| `TC-482` | GREEN by vacuity | boundary-valued | **GREEN** | 200 hit lines, notices `[]` |
| `TC-483` | RED | boundary-valued (no margin) | **RED** | `class total 201 renders 201 hit lines, above the bound 200` — the adjacent pair `TC-482` GREEN / `TC-483` RED is the gate |
| `TC-484` | GREEN by construction | boolean | **GREEN** | `None.` on all three empty sub-cases; 1-byte region → 1 hit |
| `TC-485` | GREEN by construction (pure guard, no arm) | boolean | **GREEN** | `guard source = ['if options.declared_regions:']`; `R = 0` → no addendum heading |
| `TC-486` | GREEN by construction | boolean | **GREEN** | 0x5000 beyond the inner region's end → 1 hit; 0x1800 present; 0x2000 emitted twice |
| `TC-487` | GREEN by construction | boolean | **GREEN** | duplicate ×3 → 3 hits; equal-start-nested → 2 hits |
| `TC-488` | RED | exact-equality (per-arm) | **RED** | overlapping, `consumed/N`: `R=1 → 300/300 (×1, SHIP is CORRECT here)`, `R=8 → 2400/300 (×8)`, `R=64 → 19200/300 (×64)` |
| `TC-489` | RED | exact-equality (per-arm) | **RED** | disjoint, `R=1 → 300/300`, `R=8 → 2400/300`, `R=64 → 19200/300`; re-iterability control passed first |
| `TC-490` | `xfail(strict=True)` | n/a | **XFAIL** | `ADDENDUM_NOTICE_VARIANTS_MAX` absent |
| `TC-491` | GREEN — regression guard | boolean | **GREEN** | same producer, same input, two run roots → identical, and equal to the golden |
| `TC-492` | `xfail(strict=True)` | n/a | **XFAIL** | all four constants absent |
| `TC-493` | RED | ratio-valued | **RED** | `peak(E=1000)=92988 peak(E=2000)=184316 ratio=1.982 > 1.25` — margin **58.6 %** over |
| `TC-494` | GREEN by construction | boolean | **GREEN** | order `['modification','issue','modification','issue','issue']` on an `S = 2` fixture |
| `TC-495` | `xfail(strict=True)` | n/a | **XFAIL** | no notice to compare a hit line against |
| `TC-498` | `xfail(strict=True)` | n/a | **XFAIL** | `report_service._LAST_ADDENDUM_REGION_OPS` absent — the walk it counts does not exist |
| `TC-499` | GREEN by vacuity | boolean | **GREEN** | report-wide `> TRUNCATED:` fires **outside** the addendum (asserted), addendum-scoped notices `[]` |
| `TC-497` | n/a — Inc-3 | n/a | **not authored** | its subject does not exist before Inc-3 |

**Observed tally: 13 RED · 12 GREEN · 4 `xfail(strict=True)` · 1 n/a = 30 rows over 28 live nodes.**

**Divergence from §11.1 — one, and it is arithmetic in the spec, not a verdict disagreement.** Every
single per-node verdict matched. §11.1's *summary line* says *"13 RED · 11 GREEN · 4 xfail · 1 n/a = 29
rows over 28 live nodes"*. Its own table enumerates **twelve** GREEN rows (`AT-196`, `AT-198` arms 1 and
2, `TC-481`, `TC-482`, `TC-484`, `TC-485`, `TC-486`, `TC-487`, `TC-491`, `TC-494`, `TC-499`), and
`13 + 12 + 4 + 1 = 30`, which is also what `28 live nodes + 2 extra AT-198 rows` requires. The **table is
right and the tally is off by one**; see §5/§6 below.

Every RED is a **real** RED: none is an `ImportError`, none is a collection error, and each fails on the
assertion its own row names. In `AT-199`, `AT-202`, `AT-203`, `TC-488`, `TC-489` and `TC-499` the fixture
preconditions are asserted **before** the failing predicate and all passed, so the RED cannot be an
accident of the fixture.

### 4.2 Regression sets (§6.3) — per subset, not merged

| subset | baseline in §6.3 / §7 T-8 | observed | verdict |
|---|---|---|---|
| `test_report_service.py` + `test_tui_report_seam.py` + `test_report_field_census.py` + `test_manifest_writer.py` + `test_capped_text_area.py` | **123 passed** | **`1 failed, 123 passed in 133.82s`** | 123 preserved exactly; the 1 failure is `AT-200`, the increment's own expected RED |
| `test_report_service.py` + `test_report_addendum.py` | **44 passed** | **`44 passed in 1.82s`** | unchanged; the four addendum tests at `test_report_service.py:896-960` stay green **unmodified** |
| `test_tui_report_filter_surface.py` + `test_before_after_report.py` | (other `canonical_report_bytes` consumers) | **`29 passed in 115.35s`** | unchanged |
| `tests/goldens/batch35/at055b-project-report.md` | must not change | `git status --porcelain tests/goldens/batch35/` → **empty** | unchanged |

### 4.3 BOTH frozen guards

| guard | command | result |
|---|---|---|
| engine-freeze **path** guard | `pytest -q tests/test_engine_unchanged.py` | **`1 passed in 0.08s`** |
| engine-freeze **test-file** guard (TC-031/TC-032) | `pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"` | **`6 passed, 168 deselected in 0.87s`** |

Neither touched file is in `_ENGINE_PATHS` or `_ENGINE_TEST_FILES` (read at
`tests/test_engine_unchanged.py:120-131` and `tests/test_tui_directionb.py:5442-5468`), and
`git diff --stat 082ada9 -- s19_app/` is empty.

### 4.4 Collection and lint

```
python -m pytest --collect-only -q tests/           -> 2256 tests collected, 0 errors
   (2227 before this increment + 28 new + AT-200)
python -m ruff check tests/test_report_addendum_bound.py tests/test_tui_report_seam.py
   -> All checks passed!
```

## 5. Risks

1. **The suite is intentionally RED at Inc-1 and stays RED until Inc-2 lands.** 13 nodes fail by design.
   CI on this branch will be red for the whole gap. This is the specced RED→GREEN sequencing, but it is
   worth stating rather than discovering at the next push.
2. **`AT-194` and `TC-493` read `tracemalloc` peaks and are the only nodes with measurement noise.**
   Observed across 4 independent runs (2 Phase-3 probe runs + 2 pytest runs): `AT-194`
   2.000 / 2.478 / 2.575 / 2.614, `TC-493` 1.982 / 1.982 / 1.982.
   All sit far above their thresholds (1.30 and 1.25) and above the ≥ 25 % RED margin (1.625 / 1.5625),
   and both build every fixture **before** `tracemalloc.start()` with a warm-up call first (inherited
   finding #7). The residual risk is on the Inc-2 **GREEN** side, not here.
3. **`TC-498` pins a seam Inc-2 must implement.** The spec left Phase 3 the choice between a module-level
   `report_service._LAST_ADDENDUM_REGION_OPS: int` and an `_ops_counter` callable; authoring the test
   forced the choice, and **the module-level int is now pinned**. Inc-2 must implement that name, reset
   at entry and written at exit, and record the choice in the docstring — or `TC-498` XPASSes/stays RED
   for the wrong reason.
4. **The golden is 152 kB in one file.** §11 allocates exactly one golden path and the increment is
   capped at three files, so the six documents share a file behind a `<!-- s19tool-golden-shape: … -->`
   delimiter. The parser strips exactly one newline after each delimiter; a shape whose document did not
   end in a newline would corrupt the split, so `_capture_golden` asserts it does.
5. **`AT-200` uses `_const` imported from `test_report_addendum_bound`.** That is deliberate — a second
   copy of the scope predicate is a second place for the "no notice / no scope" confusion to reappear —
   but it means Inc-2's `_const`-deletion gate has to cover **two** files. §6 records this.
6. **`TC-494` asserts a 5-element order, not §11.1's illustrative 4.** §11.1's evidence column shows
   `['mod','issue','mod','issue']`; this node's fixture also carries a check-result issue, so the
   asserted sequence is `['modification','issue','modification','issue','issue']`. That is a **stronger**
   assertion covering `LLR-103.4`'s "after all of that result's summaries, that result's check-result
   issue hits" clause, and it is GREEN — the verdict §11.1 requires. Flagged because the evidence string
   differs from the one the spec printed.
7. **An uncommitted `.dev-flow/state.json` change is in the working tree.** It records the Phase-2
   approval and the Phase-3 kickoff. **This increment did not write it** — flagged because it is outside
   the three-file scope.

## 6. Pending items

1. **`FIX-NONE` and `FIX-SCOPE` are specified and NOT executed** — the spec's only knowingly-open item
   (§11.1 note 1, C-39). What was executable now **was** executed: the nodes they arm (`TC-484` and
   `TC-499`) are authored and GREEN, and each asserts the fixture precondition the arm needs to be
   meaningful — `TC-484` pins `None.` on all three empty sub-cases plus the 1-byte region, and `TC-499`
   asserts the pre-existing `:1134` emitter fires **outside** the addendum scope, which is exactly the
   condition under which a report-wide count and a scoped count differ. What **cannot** be executed until
   Inc-2: both arms mutate a producer that does not exist on `082ada9`, so neither carries a RED figure
   and neither may be covered by a blanket ✓ in §13. Their first real verdict is Inc-2, exactly like
   `FIX-B…FIX-I`'s reproduction against the implemented producer.
2. **`TC-497` is not authored** — Inc-3 owns it (authored *and* gated there).
3. **Inc-2's `_const` deletion gate must cover two files.** §11's gate reads
   `rg -n "_const\(" tests/test_report_addendum_bound.py` → 0 hits. `tests/test_tui_report_seam.py` now
   also imports `_const` for `AT-200`. Current counts: 6 call sites in the bound module, 1 import + 1 use
   in the seam module. **Spec gap, not a code defect** — the grep as written would pass while a fallback
   survives in the seam file.
4. **Spec defect — §11.1's tally is off by one.** *"11 GREEN … = 29 rows"* should read **12 GREEN … = 30
   rows**. Re-derived from the spec's own per-node rows and from this run, which agree with each other.
   The per-node table — the thing the Inc-1 gate actually requires reproduced — is **correct**; only the
   summary sentence is wrong. Worth fixing in Inc-3's amendment log so a later reader does not "correct"
   a node to make the arithmetic work.
5. **`ADDENDUM_CLASS_LABELS` is consumed as a positionally-indexed sequence.** §8.1 defines it as a
   3-tuple indexed by class ordinal, and this module indexes it that way. If Inc-2 defines it as a
   `dict`, `_class_labels()[1]` breaks. Recording the coupling rather than defending against it.

## 7. Suggested next task

**Inc-2 — the producer (2 files):** the four `LLR-103.6` constants + the single-pass, region-indexed
`_addendum_lines` (`LLR-103.1/.2/.3/.5`) in `s19_app/tui/services/report_service.py`, plus the
`tests/test_report_field_census.py` obligations of §10.10. Its gate: every Inc-1 expected-RED node flips
GREEN, every Inc-1 GREEN guard stays GREEN, the four `xfail(strict=True)` markers are **removed** and
those nodes GREEN, the mutant arms are reproduced against the **implemented** producer (including the two
new ones, `FIX-NONE` and `FIX-SCOPE`), the `_const` fallbacks are deleted from **both** test files, and
the `K → 37` mutation is green over the `K`-derived nodes only.

---

## Evidence checklist

- [x] **Tests/type checks/lint pass (or why skipped).** `ruff check` on both test files → `All checks
      passed!`. Every regression subset at or above its baseline (`123` / `44` / `29`). The 13 RED nodes
      are the increment's specified output, not a skip. No type checker is configured in this repo.
- [x] **No secrets in code or output.** Every fixture is a synthetic in-memory object graph under
      `tmp_path`. Host-path scan of the committed golden: **0** matches for `[A-Za-z]:[\/]`, `/Users/`,
      `/home/`, or the operator's username; `canonical_report_bytes`'s `_assert_no_host_path_residue` ran
      on every captured shape.
- [x] **No destructive commands run without approval.** No `rm -rf`, no force push, no rename, no
      deploy, no commit. Only file writes inside the worktree.
- [x] **File count within cap.** 3 files (`tests/test_report_addendum_bound.py`,
      `tests/goldens/batch64/addendum-below-bound.md`, `tests/test_tui_report_seam.py`) — the §11.1
      allocation, under the ≤ 5 cap.
- [x] **Review packet attached.** This document.
- [x] **Coverage claimed from the artifact, not from intent.** Every node above was confirmed present on
      disk by `pytest --collect-only` at the path §11.1 names — 28 in
      `tests/test_report_addendum_bound.py`, `AT-200` in `tests/test_tui_report_seam.py`.
