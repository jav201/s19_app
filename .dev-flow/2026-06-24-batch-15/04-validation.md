# Validation — s19_app — Batch 2026-06-24-batch-15 (US-016)

> Phase 4 artifact. Executed by `qa-reviewer`; orchestrator independently spot-verified the tree state post-evidence-capture. Both layers + bidirectional surface-reachability + escaped-bug regression evidence.

## ✅ VERDICT: PASS

The escaped-bug closure is **proven**: AT-016.2 was demonstrated **RED on the pre-fix tree** (status `'Compared degenerate.s19 vs full.s19: 1 runs.'`, `sev-ok`) and flips **GREEN post-fix** (`sev-error` naming `degenerate.s19`), driving the real `#diff_compare_button` with **no `compare_images` monkeypatch**. All 4 ATs green; full suite 898 collected / 866 passed / 0 failed / 0 errored; engine-frozen guards pass. The one judgment call — provisional white-box TC-230/231 vs the 4 ATs — is **reconciled as subsumed** (with reasoning, §3). No reverse edge → forward to Phase 5.

---

## 1. Layer B — behavioral (black-box) acceptance

`python -m pytest tests/test_tui_diff_compare_realpath.py -v` → **4 passed in 2.58s**. No-monkeypatch proof: `grep compare_images tests/test_tui_diff_compare_realpath.py` → exactly 1 hit (the module docstring stating there is NO monkeypatch). Drives `S19TuiApp.run_test` → `action_show_screen("diff")` → types `#diff_path_a`/`#diff_path_b` → presses the real `#diff_compare_button`.

| AT | §3 oracle | Verdict | Observed deliverable |
|---|---|---|---|
| **AT-016.1** (representative / regression lock) | ≥1 `changed` run + `sev-ok`, 0 exceptions | **PASS** | `is_ok`, `not is_error`, `"changed" in #diff_range_list` |
| **AT-016.2** (boundary/degenerate — the proof) | `#diff_status.has_class('sev-error')` AND names side AND `result.refused is False` | **PASS post-fix / RED pre-fix** | `reached_display_path` True, `is_error` True, `"degenerate.s19" in status_text` |
| **AT-016.3** (negative — raise path) | refusal `sev-error`, 0 unhandled exceptions | **PASS** | `is_error` True on unresolvable path; `run_test` clean |
| **AT-016.4** (negative — over-correction guard) | NOT `sev-error`; proceeds `sev-ok` | **PASS** | `not is_error` AND `is_ok` for a valid 2-byte image |

Coverage: representative + boundary/degenerate + negative-raise + negative-over-correction; **deliverable observed** (both `#diff_status` severity AND `#diff_range_list` rows read back through the Pilot). Fails if the diagnostic is silently absent.

---

## 2. Escaped-bug regression evidence (mandatory, §5.3) — the load-bearing gate

`git stash push -- s19_app/tui/app.py` (stashed ONLY the fix; the untracked test stayed).

**RED — pre-fix tree, AT-016.2 verbatim:**
```
test_at_016_2_degenerate_image_is_flagged_not_silent FAILED
E  AssertionError: an empty-map image vs a full image must surface a sev-error status,
E  not a silent sev-ok; status was 'Compared degenerate.s19 vs full.s19: 1 runs.'
E  assert False is True
tests\test_tui_diff_compare_realpath.py:162: AssertionError
1 failed in 1.14s
```
The §5.3 pinned oracle fires: pre-fix `#diff_status` renders `sev-ok` (`has_class('sev-error') is False`) with a spurious `only_b` run (F-A-02), while the pre-condition `reached_display_path is True` passed even pre-fix — proving the bug is reached through the **non-refused silent display branch**, not the refusal return (F-Q-03 discrimination holds).

**Restore + GREEN — `git stash pop`:** fix restored (`grep -c failed_sides` → 9), all 4 ATs re-run GREEN (`4 passed in 2.55s`). Orchestrator independently confirmed post-pop: stash list empty, app.py fix intact, only `app.py` changed, 4 ATs green. **Same input: `sev-ok '…1 runs.'` pre-fix → `sev-error` naming `degenerate.s19` post-fix.**

---

## 3. Layer A — white-box + TC-230/231 reconciliation (V-5) — the judgment call

**Finding:** TC-230 (LLR-016.1 white-box unit) and TC-231 (LLR-016.2 integration) were **NOT created as separate tests** — `grep -rn "_diff_load_maps|TC-230|TC-231" tests/` → 0 matches. Inc 1 shipped only the 4 black-box ATs.

**Verdict: (a) RECONCILE — TC-230/231 subsumed by AT-016.2 / AT-016.1. Deliberate reconciliation, not a silent omission.** The two-layer "covered = BOTH layers" rule is satisfied because the ATs exercise the white-box MECHANISM with **real inputs, no mock**:
- **TC-230 (LLR-016.1 mechanism) ⊆ AT-016.2.** The predicate `not mem_map and _source_has_content(image)` (app.py:2220-2221) + the caller's conditional `sev-error` branch (app.py:2144-2155) is driven end-to-end by AT-016.2 with a real on-disk degenerate file → real `S19File` parse → `records==[]` → predicate fires. No mock between the button and the predicate; a unit test would assert the same predicate over the same lines.
- **TC-231 (LLR-016.2 mechanism) ⊆ AT-016.1.** Verification-only (engine unchanged); AT-016.1 drives real `compare_images` → `result.runs` → `#diff_range_list` with a fixed 1-changed-run fixture shape.
- **Consistent with the spec's own framing** (§5.2 already maps LLR-016.3 → the ATs as a deliberate exception, F-A-06/F-Q-06). Extending it to LLR-016.1/.2 fits a small display-side fix where the AT drives the exact predicate with real inputs.

**Why not (b) iterate-to-fix:** a separate `_diff_load_maps` unit test is near-duplicative of a predicate already exercised end-to-end by AT-016.2's RED→GREEN pair. The escaped-bug class this batch closes is precisely *"green white-box that never observed the surface"* — adding white-box around the same predicate does not strengthen the acceptance guarantee the ATs provide.

**Phase-6 carry (non-blocking):** retire the provisional `TC-230`/`TC-231` ids in `01-requirements.md` §5.2 + REQUIREMENTS.md so they don't survive as orphans (recorded in §6.4 reconciliation log).

---

## 4. Per-requirement verdict (0 orphan ids)

| Requirement | Verdict | Passing node (real, no mock) |
|---|---|---|
| **HLR-016** | **PASS** | 4 ATs (016.1/.2/.3/.4 GREEN; 016.2 RED pre-fix captured) |
| **LLR-016.1** | **PASS** | `test_at_016_2_*` (real predicate → `sev-error` naming side; `markup=False` preserved) + guard `test_at_016_4_*` |
| **LLR-016.2** | **PASS** | `test_at_016_1_*` (real `result.runs` → `changed` run + `sev-ok`) |
| **LLR-016.3** | **PASS** | whole real-path suite + no-monkeypatch inspection + RED-pre-fix evidence |

Provisional ids reconciled: `AT-016.1/.2/.3/.4` → the 4 real functions; `TC-230/231` → subsumed (§3). No orphans (pending the §6.4/REQUIREMENTS.md note).

---

## 5. Bidirectional surface-reachability matrix (through `#diff_compare_button`)

| Direction | Dimension | Through handler? | Evidence |
|---|---|---|---|
| INPUT | `#diff_path_a` / `#diff_path_b` (typed absolute) | ✓ | `_drive_compare` sets `.value` then presses button |
| INPUT | degenerate (non-empty → empty map, no raise) | ✓ | AT-016.2 inline `"S1ZZGARBAGE\nNOTANSREC\nS1!!!!\n"` |
| INPUT | well-formed S19 | ✓ | AT-016.1 via `emit_s19_from_mem_map` |
| INPUT | missing/unresolvable (raises → refuses) | ✓ | AT-016.3 |
| INPUT | tiny-but-valid (few bytes) | ✓ | AT-016.4 |
| OUTPUT | `#diff_status` `sev-error` | ✓ | AT-016.2/.3 `has_class("sev-error")` |
| OUTPUT | `#diff_status` `sev-ok` | ✓ | AT-016.1/.4 `has_class("sev-ok")` |
| OUTPUT | named failed side | ✓ | AT-016.2 `"degenerate.s19" in status_text` |
| OUTPUT | `#diff_range_list` runs | ✓ | AT-016.1 `"changed" in range_text` |

Every input dimension AND every output deliverable reachable through the button handler — none exercised only via direct service kwargs.

---

## 6. Full suite (authoritative) + frozen guards + census

`python -m pytest -q` → **866 passed, 29 skipped, 3 xfailed in 865.17s (14:25), exit 0.** Collection **898** (= 894 baseline + 4 ATs); 866 + 29 + 3 = 898. **0 failed / 0 errored.**

Engine-frozen guards PASS: `test_engine_unchanged.py::test_tc027_*` + `test_tui_directionb.py::test_tc031_*` (3 nodes) all green. *(Note: the spec's `tc031_engine_modules_unchanged_vs_main` node id was provisional; the real nodes are `tc027_*` + the three `tc031_*` — all green.)*

Census: `git diff --stat` shows **only `s19_app/tui/app.py`** changed (+51/−13) among production files; no engine / `compare_service` / widget change (D-5 honored). `#diff_status` stays `markup=False` (LLR-016.1 plain-text invariant holds). Pre-existing app.py ruff F401/F402 (MEMORY.md, 6 errors) — NOT a regression, out of scope.

---

## 7. Feedback-edge determination
Black-box **PASS** (4/4, RED→GREEN proven) + white-box **reconciled as subsumed** → **no reverse edge.** No `iterate-to-fix`, no `iterate-to-refine`. Forward to Phase 5.

## 8. §5.3 batch acceptance — all met
- [✓] 4 ATs GREEN post-fix. [✓] Escaped-bug evidence captured (AT-016.2 RED pre-fix, verbatim). [✓] No monkeypatch escape (grep: 1 docstring hit). [✓] TC-230/231 reconciled as subsumed (deliberate, §3). [✓] No regression (866/0/0; frozen guards pass). [✓] R-2 reachability answered (degenerate reaches non-refused display path; no halt).

**Carry (Phase 6, non-blocking):** retire provisional `TC-230`/`TC-231` ids; record LLR-016.1/.2 as verified-by-AT.
