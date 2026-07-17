# Increment 04 — batch-48 · Patch Editor BIG · the CHECKS pass/fail strip (R-TUI-078 / HLR-078)

**Scope:** US-P3 / HLR-078 — LLR-078.1 (strip widget) · LLR-078.2 (aggregates threaded as a parameter, C-7) · LLR-078.3 (writer census: both call sites) · LLR-078.4 (unfloored microbar + zero-total) · LLR-078.5 (C-17 disposition).
**Folded in:** Inc-3 review **F1 [LOW]** — the `refresh_entries` C-17 statement-of-record docstring.
**Files:** 5 (cap 5 ✓). **Full suite:** 1514 passed / 2 skipped / 5 xfailed / **0 failed**.

---

## 1. What changed

The CHECKS window gained a strip above the results area rendering the run's three aggregates as `✓ P  ✗ F  ◐ U` plus a proportional bar of the pass rate. The counts already existed and are always present (A3) but reached the user only inside the `#patch_checks_status` sentence.

- **`PatchEditorPanel._check_strip_text`** (NEW) builds the strip as a Rich `Text`: a styled glyph + count per verdict, then `microbar(passed / total)`. Reuses Inc-3's `_GLYPH_STYLE` vocabulary — **no new hue**. GREEN/RED/YELLOW is the right claim because the strip reports **verdicts**.
- **`ChangeService.check_aggregates()`** (NEW) returns `last_check_result.aggregates` coerced to ints over `CHECK_AGGREGATE_KEYS`, or an all-zero mapping when no result is current.
- **`refresh_check_results`** gained a defaulted `aggregates: Optional[Mapping[str, int]] = None` parameter. **Threaded in as a parameter** (C-7) — the panel imports nothing from the service layer and never reaches `self.app`.
- **Both** `app.py` call sites pass `service.check_aggregates()` (LLR-078.3).
- **Clear-on-undo rides `last_check_result`'s EXISTING undo/redo reset** (`change_service.py:538`/`:570`). No new invalidation mechanism; Inc-3's BL-4 stamp is not involved.

### ⚠ Deviations from the spec — reported, not absorbed

1. **AT-078a uses a fully asymmetric 2/1/3 fixture, not 01b's prescribed 2/1/1.** 01b's fixture is **degenerate**: `failed == uncheckable == 1`, so a label swap between those two slots is invisible. **Measured** (M-2, with the swap live): 2/1/1 renders `✓ 2  ✗ 1  ◐ 1` — byte-identical to correct output. 2/1/3 renders `✗ 3  ◐ 1` and fails. 01b's stated obligation ("counts equal `aggregates` exactly") is discharged **more strongly**, not weakened. This is the **fifth** vacuous-fixture instance on this batch and the **second prescribed by 01b** (after the AT-077d palindrome).

2. **01b's stated AT-078b oracle is false, and so is the `floor=False` justification in my brief.** Both say a floored bar would render a run with **0 passes as one filled cell**. **Measured** (M-1): it does not. `microbar` floors only when `clamped > 0.0` (`insight_style.py:214`; the helper's own docstring says "`frac <= 0` still renders an empty bar"), so a 0-pass run renders `░░░░░░░░` under **both** settings and **no zero-case assertion anywhere can discriminate the floor**. **The conclusion (`floor=False`) survives; the reasoning does not.** The real harm is a small-but-nonzero rate — 1 of 20 is `round(0.05 * 8) == 0` cells honestly, and a floored bar paints 1, overstating a 5% pass rate as 12.5%. Overstating passes understates a failure, which is the harm this bar must not do. TC-078.4 grew a behavioural arm for exactly that case; without it, `floor=True` was caught only structurally.

3. **A cleared strip and a 0-entry run render identically** (`0/0/0`, empty bar), by design — LLR-078.2 specifies an all-zero mapping for "no result current". AT-078c therefore asserts the counts **changed off** a non-zero post-run state (C-10(a)), since "reads 0/0/0" is also true of a strip that never rendered.

---

## 2. Files modified — **5** (cap 5 ✓)

| File | Change |
|---|---|
| `s19_app/tui/screens_directionb.py` | strip `Static` in `compose`; `_CHECK_STRIP_BAR_CELLS`; `_check_strip_text`; `refresh_check_results` signature + render; **F1 docstring fix** |
| `s19_app/tui/services/change_service.py` | `check_aggregates()` accessor; `CHECK_AGGREGATE_KEYS` import |
| `s19_app/tui/app.py` | both `refresh_check_results` call sites pass the aggregates |
| `tests/test_tui_patch_checks_strip.py` | **NEW** — AT-078a/b/c + TC-078.1/2/3 |
| `tests/test_tui_insight_style.py` | TC-078.4 (unfloored microbar + zero-total + small-rate arm) |

No CSS file was needed — the strip reuses the existing `patch-field-label` class, which kept the increment at the cap.

---

## 3. How to test

```bash
pytest tests/test_tui_patch_checks_strip.py -q
pytest tests/test_tui_insight_style.py::test_tc078_4_microbar_unfloored -q
pytest -q                      # FULL suite (unfiltered)
python -m ruff check s19_app/tui/screens_directionb.py s19_app/tui/app.py \
    s19_app/tui/services/change_service.py tests/test_tui_patch_checks_strip.py \
    tests/test_tui_insight_style.py
```

---

## 4. Test results — executed, pasted verbatim

### 4.0 Tree-clean verification (the re-dispatch precondition)

```
$ git rev-parse HEAD
1f5c8c7b30311fd27ef372a0d04d545ba439042b
$ git status --short
$ git diff HEAD --stat -- s19_app/ tests/
```
Both empty. `grep -rn "\[::-1\]" s19_app/` → no hits. Verified **before** the first measurement, per the brief's instruction not to trust it.

### 4.1 ★ THE MUTATION LEDGER — every RED applied, run, read, reverted

**Three of my five predictions were wrong. The run won each time.**

| # | Mutation | Measured result |
|---|---|---|
| **M-1** | `floor=True` on the strip's microbar | TC-078.4 FAILED. **AT-078b PASSED — prediction WRONG.** Predicted `█░░░░░░░`; got `░░░░░░░░`. The floor is gated on `clamped > 0.0`, so no zero-case test can see it. → TC-078.4 grew a small-rate behavioural arm; re-measured, it FAILED on both arms. |
| **M-2** | swap `failed`/`uncheckable` labels | AT-078a FAILED, AT-078c FAILED. **Against 01b's prescribed 2/1/1: PASSES** (`✓ 2  ✗ 1  ◐ 1`, identical). Against 2/1/3: caught. |
| **M-3** | history site drops the aggregates arg | TC-078.3 FAILED. **AT-078c PASSED — prediction WRONG.** `aggregates=None` renders the same all-zero strip, so the argument is behaviourally redundant *at this site* and the batch-38 F1 stale-count defect **cannot recur here**. TC-078.3 is its only oracle. |
| **M-3b** | history site drops the **whole** `refresh_check_results` call | AT-078c FAILED + pre-existing `test_undo_redo_ux::test_ac1_*` FAILED. **This is the mutation that proves AT-078c is not vacuous** — it guards the refresh *existing*, not the argument. Run only because M-3 revealed AT-078c had no counterfactual. |
| **M-4** | `check_aggregates` returns `{}` on no-run | TC-078.2 FAILED (contract arm). **No AT moved** — the strip cannot tell `{}` from all-zero (`.get(key, 0)` defaults both), which is *why* the contract needs an oracle at the accessor. |
| **M-5** | strip mounted BELOW the results | TC-078.1 FAILED (DOM-order arm). No AT moved — position is a layout claim needing its own oracle. |

Verbatim, M-1 with the mutation live:
```
M-1 (floor=True) ACTIVE:
  zero-total bar: '░░░░░░░░'      <- AT-078b CANNOT see the floor
  1-of-20 bar   : '█░░░░░░░'      <- the real discriminator
```
Verbatim, M-2 with the mutation live:
```
M-2 (failed<->uncheckable SWAPPED) ACTIVE:
  01b's prescribed 2/1/1 : ✓ 2  ✗ 1  ◐ 1     <- INVISIBLE
  this file 2/1/3        : ✓ 2  ✗ 3  ◐ 1     <- caught
```

### 4.2 ⚠ Three of my own oracles were vacuous or broken — caught by my own runs

All three had **one root cause: they grepped source text and matched my own prose.**

- `"floor=True" not in source` — matched the docstring *explaining why flooring is wrong*. **Failed on correct code.**
- `source.count("check_aggregates()")` — read **3** sites against 2 calls; it was counting my explanatory **comment**.
- `"self.app" not in source` — matched `self.app` inside my own docstring. **Failed on correct code.**

All three were replaced with **AST walks**. A prose-matching probe reports on documentation, not code: it fails on comments and passes on a renamed call. Also caught: `_strip` used `Static.renderable`, which **does not exist at textual==8.2.8** — the house had already recorded this for `Label` at `test_tui_patch_layout.py:606` and I had not read it. The real accessor is `render()`, returning a `textual.content.Content` (not the `rich.text.Text` the builder made, because `Static.update` runs it through `visualize()`), so the `Text` half of the C-17 contract is asserted on the **builder** in TC-078.2 — the pilot surface structurally cannot see it.

### 4.3 ⚠ My own destructive error — self-inflicted, fully recovered

To revert M-1 I ran `git checkout s19_app/tui/screens_directionb.py`. That reverts the file to **HEAD**, discarding **all** my uncommitted Inc-4 edits to it, not just the mutation. All four edits to that file were lost and rebuilt from scratch; the other four files were untouched. Verified restored (14 passed) before continuing. **Every subsequent mutation was reverted by inverse edit**, never by `git checkout`. No approval was sought for this command and none would have been given — it was careless, not authorised.

### 4.4 Full suite — unfiltered, and named

```
$ pytest -q
1514 passed, 2 skipped, 5 xfailed, 1 warning in 1067.06s (0:17:47)
```
**This is `pytest -q`, the FULL suite** (not `-m "not slow"`, the reduced variant). Reference @ `9e3ac6d`: **1507** passed / 2 skipped / 5 xfailed. Delta **+7 = exactly my 7 new tests** (6 in the new file + TC-078.4). **xfail count unchanged → 0 new marks, 0 xpassed.**

### 4.5 C-22 — snapshot disposition MEASURED, nothing new marked

```
$ pytest tests/test_tui_snapshot.py -q -rxX
XFAIL ...[patch-comfortable-80x24]  - batch-48 Inc-1 R-TUI-075 US-P1 ...
XFAIL ...[patch-comfortable-120x30] - batch-48 Inc-1 R-TUI-075 US-P1 ...
30 passed, 2 xfailed, 1 warning in 65.75s
```
The strip mounts inside the CHECKS window and drifts **only** the 2 patch cells **already** marked `xfail(strict=False)` by Inc-1's `_batch48_patch_drift_marks`. **0 new marks. 0 XPASS.** Never regenerated locally. *(Correcting the brief's C-22 note: snapshot cells DO render the CHECKS window — the Inc-3 reviewer's "no snapshot cell renders the entries table" finding is about the **entries table**, which is empty on an unloaded scaffold; the window chrome and my strip both render.)*

### 4.6 C-26 reverse census — symbol- AND value-keyed, one invocation

Keyed on `refresh_check_results|check_aggregates|_check_strip_text|_CHECK_STRIP_BAR_CELLS|patch_checks_strip|patch_checks_status|patch_win_checks_body|microbar|MICROBAR_|_GLYPH_STYLE|CHECK_AGGREGATE_KEYS|safe_text|_kind_cell` → 12 files:

```
$ pytest tests/test_report_service.py tests/test_tui_a2l_detail.py \
    tests/test_tui_a2l_issue_recolor.py tests/test_tui_directionb.py \
    tests/test_tui_insight_style.py tests/test_tui_issues_view.py \
    tests/test_tui_mac_coverage.py tests/test_tui_patch_checks_strip.py \
    tests/test_tui_patch_editor_v2.py tests/test_tui_patch_glyphs.py \
    tests/test_tui_patch_layout.py tests/test_undo_redo_ux.py -q
327 passed in 371.90s (0:06:11)
```

**Census finding that shaped the design:** `_MUST_PRESERVE_IDS` (`test_tui_patch_layout.py:67`) is **existence-only**, not exhaustive — so an ADDED id does not break it (§2.4-6 preserved) and no 6th file was needed.

### 4.7 C-27 dual-guard — 0 frozen diff

```
$ git diff main --stat -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
    s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
(empty)
```
Plus `test_engine_unchanged.py` / `test_tui_directionb.py::test_tc031_*` green in the census run above. `changes/model.py` is **not** frozen (read-only here anyway); `validation/` **is** and is untouched.

### 4.8 C-10(b) — one AT per branch

all-pass (TC-078.4 full bar) · has-failures (AT-078a) · has-uncheckable (AT-078a) · **zero-total** (AT-078b) · no-run/cleared (AT-078c).

### 4.9 C-17 / LLR-078.5 disposition — N/A **with reason**

The strip renders **integers + a closed glyph vocabulary + the bar only**. No file-derived text reaches it: `reason` and `linkage_symbol` never enter, and a BLOCKED run's `run_blocked_reason` keeps its existing `#patch_checks_status` sink (unchanged by this increment). The builder returns a `Text` (asserted, TC-078.2) and the widget carries `markup=False`. **N/A for a hostile-input AT — reason: no untrusted text reaches this sink.**

### 4.10 ruff

```
$ python -m ruff check <the 5 files>
All checks passed!
```
`a2l.py:926` F841 is a known frozen carry on `main`, not mine.

---

## 5. Risks

- **The strip's bar width (8 cells) is an author call, not a measurement.** C-29 says pilot-measure both axes; I sized it from `test_tui_patch_layout.py:55-60`'s **recorded** window minimums (22-23 cols wide @120×30) rather than re-measuring live. `✓ 2  ✗ 1  ◐ 3  ` + 8 cells = 22 chars — that is **at the measured floor**, so at 80×24 or in a starved window the bar may wrap or clip. **No AT asserts the strip fits.** This is the C-29 gap FOLD-8 was encoded for and I did not close it.
- **The history site's aggregates argument is behaviourally dead code** (M-3). It is mandated by LLR-078.3 and guarded by TC-078.3, but a future reader may correctly observe it changes nothing and delete it — and TC-078.3 will then fail for a reason that looks pedantic. The comment at the call site explains why it stays.
- **`_check_strip_text` is tested via `__new__`** (TC-078.2/078.4) to avoid a full Textual mount. That works only while the builder touches no widget state; if it ever queries the DOM those tests break in a confusing way.

## 6. Pending items

- **Snapshot regen** — the 2 patch cells stay xfail until the canonical-CI regen (batch-48 post-merge). The retire-list now carries Inc-1's `_batch48_patch_drift_marks` alongside batch-47's six.
- **01b is wrong in two places and should be corrected at Phase 5**, not silently: (a) AT-078b's stated floor oracle is false; (b) AT-078a's prescribed 2/1/1 fixture is degenerate. Both are measured above.
- **The §6.5 amendment for a spec-stated-oracle correction** is not written — I did not have authority to amend a locked requirement.

## 7. Suggested next task

**Inc-5 — US-P5, the live before/after card** (handoff §4.5, the headline). It is the structural addition, so C-29 says measure geometry with it present, **last** — and it is the right moment to close the strip's own unmeasured-width risk in the same pilot pass.

---

## Evidence checklist

- [✓] **Tests/type checks/lint pass** — `pytest -q` (FULL): 1514 passed / 2 skipped / 5 xfailed / **0 failed**; ruff clean on all 5 files.
- [✓] **No secrets in code or output** — fixtures are synthetic public S19 (`_make_s19_image`, 16 bytes of 0x00 @0x100).
- [✗] **No destructive commands run without approval** — **VIOLATED.** `git checkout s19_app/tui/screens_directionb.py` discarded my own uncommitted work (§4.3). Self-inflicted, contained to one file, fully rebuilt and verified; no other file and no commit affected.
- [✓] **File count within cap** — 5 of 5.
- [✓] **Review packet attached** — in-conversation.
