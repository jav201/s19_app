# Review — s19_app — Batch 2026-06-24-batch-15 (US-016 only)

> Phase 2 artifact. Reviewers (in parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer`. Single story: US-016 (A↔B compare false "no diff"). US-015 deferred at Phase 0.

## ✅ Verdict (read first)

> **ITERATION-2 RESOLVED (2026-06-24):** operator chose `iterate`. All 5 majors + 15 minors were folded into the §3/§4/§5 ACs inline (audit at §6.4 J-1..J-5). Every finding below is **fixed**. Re-confirmation gate pending.

- **Gate:** PROCEED to Phase 3 (after the iter-2 fold, now complete). **0 blockers.**
- **Findings:** **0 blocker · 5 major · 15 minor** (architect 0/2/6 · qa 0/3/4 · security 0/0/5).
- **shall/should check:** ✓ clean — every `shall` inside an HLR/LLR Statement; 0 `should`-as-modal in any Statement (architect triple-confirmed).
- **Two-layer (blockers):** ✓ every story has an `AT` · output req names deliverable+observation · both trace chains complete · ATs are genuinely black-box (drive `#diff_compare_button`, observe `#diff_status`/`#diff_range_list`, no internal-symbol assertions).
- **Census (change-first):** done — best-effort + gate-confirmed. All touched files (`app.py` + new test + fixture + `REQUIREMENTS.md`) OUTSIDE the engine-frozen set; `app.py`/`compare_service.py`/`screens_directionb.py` confirmed absent from `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:120-127`).
- **Security:** ⚠ 5 minor (3 confirmed-clean, 2 advisory). **Sign-off ADVISORY** — zero new write/exec/network/external surface (read-only display-side change).
- **Evidence checklists (architect / qa / security):** ✓ all three complete.

> **Two load-bearing Phase-2 results:** (1) **R-2 is REACHABLE** — architect verified a concrete degenerate input exists (a non-empty file whose every S-record is malformed → `records==[]` → empty `mem_map`, WITHOUT the constructor raising; `core.py:266-272` collects per-line errors, re-raises only `FileNotFoundError`/I-O). So the fix premise holds and AT-016.2 can be made RED pre-fix. (2) **D-2 is CORRECT** — batch-14's "stop swallowing" would not fix the headline case (a raise already refuses upstream at `compare_service.py:549`); the genuine fix is detect-degenerate + override the unconditional `sev-ok`.

---

## Detail (reference)

### Findings register

| ID | Reviewer | Sev | Area / Req | What | Disposition | Status |
|----|----------|-----|------------|------|-------------|--------|
| **F-A-01** | architect | **major** | HLR-016 Statement (clause 2) | "`sev-ok` '0 runs' clean compare" is too narrow — a one-side-degenerate input yields `only_b` runs + `sev-ok` (also a false verdict), which a literal reading of the `shall` would not cover. | Reword the outcome run-count-agnostic: "…rather than presenting a `sev-ok` status (whether 0 runs or runs derived from a partially-loaded pair) or blank hex windows with no explanation." | open |
| **F-A-02** | architect | **major** | AT-016.2 + R-2 + LLR-016.3 | AT-016.2 fixture intent is ambiguous between the one-side-degenerate (`only_b`+`sev-ok`) and both-empty (0-run) sub-cases; an implementer could build either and believe they matched the spec. | Disambiguate: AT-016.2 uses ONE degenerate side (non-empty source → empty map) and asserts `sev-error` naming that side; pre-fix it currently renders `only_b` + `sev-ok` (the RED condition). | open |
| **F-Q-01** | qa | **major** | AT-016.2 / §5.3 / LLR-016.3 | The "RED pre-fix" oracle is stated 3 inconsistent ways (no `sev-error` / presence of `sev-ok` / "0 runs"). These can disagree (pre-fix may be `only_b`+`sev-ok`, non-empty runs). | Pin ONE primary assertion: pre-fix `#diff_status.has_class('sev-error') is False` AND post-fix `is True`; demote the "0 runs/sev-ok" phrasings to corroborating notes. | open |
| **F-Q-02** | qa | **major** | R-2 / LLR-016.3 reachability gate | Gate-clear threshold is directional but not a named observable fixture pair; the naive empty-vs-nonempty fixture does NOT reproduce the headline (gives `only_X`, not 0 runs). | Name the candidate construction (all-error-line S19 → display-side empty without raise, paired vs well-formed) + the pre-fix oracle; if no construction yields display-side-empty-without-raise → halt. | open |
| **F-Q-03** | qa | **major** | AT-016.2 / LLR-016.1 | **Highest-value.** AT-016.2 could pass pre-fix for the WRONG reason: if the degenerate input makes `compare_images` *refuse*, the existing `result.refused`→`sev-error` branch fires and AT-016.2 collapses into AT-016.3, proving nothing about the swallow. | Add mandatory pre-condition: AT-016.2 MUST assert `result.refused is False` pre-fix (bug reached via the silent display path, not the refusal path). If only a refusing input is producible → R-2 not cleared → halt+escalate. | open |
| **F-A-03** | architect | minor | citations | `#diff_status` widget mis-cited at `:1123` (that's the `set_status` def); the widget is constructed at `screens_directionb.py:1086-1088`. | Correct widget citation to `:1086`; keep `set_status` refs at `:1123`. | open |
| **F-A-04** | architect | minor | LLR-016.1 / R-3 | The "degenerate map for a non-empty source path" predicate is unstated; edge: an S0-only file is NOT empty (`get_memory_map` includes S0 data, `core.py:490-493`); the genuinely-degenerate input is all-records-rejected (`records==[]`, file bytes>0). | Pin the predicate to the observable: "source file >0 non-blank lines AND loaded map empty (`records==[]`)"; cite `core.py:489-494`. Guards R-3. | open |
| **F-A-05** | architect | minor | LLR-016.1 / R-5 / Inc 2 | `_diff_load_maps` also feeds the report path; changing its `(dict,dict)` return shape ripples. Inc 2 doesn't commit to a carrier strategy. | Constrain: carry the load-failure signal OUT-OF-BAND (not by mutating the maps tuple consumed by the report path); Inc 2 touches `on_ab_diff_panel_report_requested` if shape changes. | open |
| **F-Q-04** | qa | minor | AT-016.1 / TC-231 | "two genuinely-different files" doesn't pin the diff shape; the `==len(result.runs)` half is objective, but reproducibility needs the expected run count. | Phase 3: record the fixture's exact expected run count (e.g. differ in 2 byte runs → assert 2 rows). | open |
| **F-Q-05** | qa | minor | AT-016.3 / R-3 | No AT exercises the legitimately-empty-VALID image (the negative-of-the-negative); AT-016.3 covers the raising path, a different branch. | Add AT-016.4 (legit-empty valid → NOT `sev-error`) OR explicitly flag it as white-box-only (LLR-016.1 condition test) in §6.3. | open |
| **F-A-06 / F-Q-06** | architect/qa | minor | §5.2 LLR-016.3 row | LLR-016.3's functional cell is populated by the ATs (it IS the test artifact) — benign self-reference, but should be stated as a deliberate exception. | One-line note: LLR-016.3 is the acceptance-test artifact; its functional verification is the "no `compare_images` monkeypatch" inspection, not a separate TC. | open |
| **F-A-07** | architect | minor | §6.4 | The D-2 refinement of batch-14's LLR-016.1 is a cross-batch decision change; §6.4 reconciliation log is empty. | One row: D-2 is a NEW derivation (batch-14 code never landed → nothing to amend); records the supersession explicitly. | open |
| **F-A-08** | architect | minor | fixture / Inc 1 | Degenerate fixture listed in 3 candidate locations, none pinned (AC-artifact citation rule). | Pin to an INLINE `tmp_path` write (2-line malformed-S19 string) — keeps Inc 1 at 1–2 files, avoids an `examples/` asset that could trip guards. | open |
| **F-Q-07** | qa | minor | §5.2 / V-5 | `-k` selectors are implementer-owned tokens not individually flagged provisional. | One line: "all `-k` selectors are provisional-until-Phase-3 (V-5)." | open |
| **F-S-03** | security | minor (advisory) | LLR-016.1 | The new diagnostic names operator-influenceable text (path/parser-error). Verified safe NOW (`#diff_status` `markup=False`, `screens_directionb.py:1088`), but the spec doesn't REQUIRE plain-text surfacing — an implementer could wrap it in Rich markup. | Add AC: side/path/error text passed to `set_status` as PLAIN text; do NOT interpolate into Rich markup; keep `#diff_status` `markup=False`; Phase-3 inspection check. | open |
| **F-S-04** | security | minor (advisory) | fixture | Degenerate fixture must stay synthetic (no secrets/PII), not trip a tripwire. Spec already on track. | Phase-3 inspection line: asset is synthetic firmware-shaped bytes; if under `examples/`, not in a guarded path. | open |
| **F-S-01/02/05** | security | minor (info) | — | Confirmed CLEAN: 0 new write/exec/network surface (F-S-01); path-resolution & size-capping unchanged (F-S-02); engine-frozen integrity preserved, only `app.py` edited (F-S-05). | No action; basis for ADVISORY sign-off. | confirmed |

### shall / should check
✓ Clean. Every `shall` inside an HLR/LLR Statement (lines 159-160, 189, 200, 210). Zero `should`-as-modal inside any Statement; the `should` tokens present are informative/risk prose. **No blocker.**

### Two-layer acceptance review (blockers)

| Story / Req | (a) AT present | (b) deliverable+method named | (c) both chains | (d) black-box pure | Status |
|-------------|----------------|------------------------------|-----------------|--------------------|--------|
| US-016 / HLR-016 | yes (AT-016.1/.2/.3) | yes (`#diff_status` severity + `#diff_range_list` runs, via Pilot) | yes (behavioral + functional) | yes (no `_diff_load_maps`/`result.runs` internals asserted) | ✓ |

> Caveat from F-Q-03: black-box purity holds, but AT-016.2 must additionally assert `result.refused is False` pre-fix to prove it reaches the silent path, not the refusal path. Folded as a tightening, not a blocker.

### Supersession / change-first census
Files × guard families run: `app.py` (production) + new test file + inline degenerate fixture + `REQUIREMENTS.md` checked against the engine-frozen guard family (`_ENGINE_PATHS`, `tests/test_engine_unchanged.py:120-127` + `test_tui_directionb.py::test_tc031_*`). All OUTSIDE the frozen set. `compare_service.py`/`screens_directionb.py`/`color_policy.py` read-only this batch. Reservation: the increment gate (Inc 2) re-runs the frozen guards as the completeness guarantee.

### Security review summary
**ADVISORY sign-off (not mandatory).** Zero new write/exec/network/external-action surface — the fix only reads files the existing compare flow already resolves and flips one status-line severity. 2 advisory hardening notes (F-S-03 plain-text requirement; F-S-04 synthetic-fixture inspection), both already satisfied by current code; folding them into the spec prevents future regression.

### Evidence checklists (full)
All three reviewers returned completed evidence checklists (✓/✗ + one-line evidence) in their Phase-2 outputs (architect: R-2 reachability + D-2 soundness verified on disk; qa: two-layer + black-box purity + bidirectional reachability verified; security: read-only surface + markup=False + frozen integrity verified). Retained in the orchestrator's Phase-2 record.

### Orchestrator recommendation
**ITERATE-LIGHT → re-confirm → proceed.** 0 blockers; R-2 reachable + D-2 correct ⇒ the batch premise holds. The 5 majors are a single cluster (make AT-016.2's pre-fix-RED oracle precise + guard it against the refusal-collapse — F-Q-03 is the load-bearing one) plus the F-A-01 run-count-agnostic HLR wording. All findings are deterministic LLR-AC tightenings (the reviewers' own prescriptions) — no re-derivation, no design change — mirroring the batch-13 iter-2 pattern. Fold C1–C6 inline, re-verify, then PROCEED to Phase 3.
