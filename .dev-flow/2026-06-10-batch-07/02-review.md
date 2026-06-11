# Review — s19_app — Batch 2026-06-10-batch-07

Phase 2 cross-review of `01-requirements.md` (8 HLR / 51 LLR). Three reviewers in parallel against live code: architect (40+ anchors re-verified), qa-reviewer (~60 anchors + 10-row disposition audit + collector re-run), security-reviewer (2 behaviors verified against the actual runtime). Full reviewer reports preserved in the Phase-2 transcripts; this artifact is the consolidated, deduplicated finding register.

## Verdict
**ITERATE to Phase 1** (blockers force it per dev-flow rule). **4 unique blockers / 17 majors / 13 minors.** The structure is sound — derivation clean, shall/should clean, anchor hygiene "best of any batch so far" (architect), disposition table verified to re-add exactly with 10/10 sampled rows correct at assertion level. The blockers are concentrated on the cross-architect seam (C-6 staleness after the late operator-decision LLRs) and on three unexecutable verification specs. All fixes have exact text from the reviewers; three items need operator decisions at the gate.

---

## BLOCKERS

| ID | Finding | Fix |
|---|---|---|
| **B-1** (F-A-01 ≡ F-Q-03 — found independently by both) | **C-6 canonical schema is stale vs the late LLRs.** `saved_path` (002.7) and `issues` (002.8) are consumed by the report (007.4) but absent from C-6 and producer LLR-002.5's field list — the C-6 identity check fails as written; Phase 3 would build a `ChangeSummary` the report can't consume. | Add `saved_path`, `issues` (+ types) to C-6 summary-level set and LLR-002.5's enumeration; restate 006.5's inspection over the extended set. |
| **B-2** (F-A-02) | **Check-document declaration faults have no carrier to the report.** `CheckRunResult` (004.3/C-6) has no `issues` field; 004.4 returns issues as a separate tuple element; 006.5 consumes only the two objects → in the variant execution→report chain, check declaration faults are dropped (violates gate decision 2 + US-003). | Add `issues: list[ValidationIssue]` to `CheckRunResult` (004.3 + C-6), mirroring 002.8; simplify 004.4's return to the single object. |
| **B-3** (F-Q-01) | **Retirement grep false-passes always.** LLR-003.3's `grep -r "read_cdfx\|write_cdfx\|…"` as written uses BRE where `\|` is literal — returns 0 hits on ANY tree. The load-bearing retirement inspection is a guaranteed false-pass. | `grep -rE` (or `rg`); self-test the probe pre-retirement (must find hits today). |
| **B-4** (F-Q-02) | **Determinism verification cannot pass.** "Double-apply `to_dict()` equality" (002.5): the 2nd apply sees the patched mem_map → `before_bytes` differ; `timestamp_utc` differs between runs. Same clock problem in 004.3. | Assert serialization determinism (same object, two `to_dict()` calls) or apply to two deep copies with an injected fixed clock; freeze timestamp for 004.3. |

## MAJORS (consolidated)

**Architect (F-A-03..10):**
- **F-A-03** — 001.3 vs 001.8 contradiction: a v1 file triggers both `CHG-FORMAT` and `CHG-V1-FORMAT`; 001.8's "exactly 1" fails. Fix: v1 detection precedes generic format validation (suppression rule in 001.8).
- **F-A-04** — disposition `blocked` (002.1) missing from the enumerations in HLR-002(3)/002.5/C-6. Fix: add it.
- **F-A-05** — **save-back reuse assumption is false (verified now, not Phase-3):** the CLI path serializes an `S19File` object (`_write_s19` `cli.py:89`, `set_bytes_at` `core.py:407`) while the v2 engine is mem_map-pure; AND `hexfile.py` has **no writer at all** → HEX save-back is unimplementable via any existing path. Fix: re-scope 002.7 — NEW mem_map-based S19 emitter in `changes/io.py`; **HEX save-back scope = operator decision**.
- **F-A-06** — E5→E6 dependency inversion: 005.6 references the manifest (E6 artifact). Fix: E5 ships first-variant default; manifest-override moves to E6.
- **F-A-07** — **increment-fit violations unacknowledged:** E3 far exceeds the 5-file cap (7+ deletions + 4 code files + ~13 test files); E5 = 6 files. Fix: per-increment budgets in §6.5; **operator approval or split (E3a/E3b, E5a/E5b) = operator decision**.
- **F-A-08** — **check-collision semantics inherited unexamined:** two expectations over one address ERROR-blocks the whole check document; the overwrite-hazard rationale doesn't transfer to read-only expectations. **Operator decision:** keep ERROR (uniform) vs demote intra-check collisions to WARNING.
- **F-A-09** — 007.8's input enumeration is false (tool version + variant inventory + options not derivable from the stated inputs). Fix: enumerate C-6 objects + mem_maps + `ProjectVariantSet` + `ReportOptions` + `__version__` (`s19_app/version.py:1`).
- **F-A-10** ≡ **F-Q-13** — §5.2 TC index omits 002.7/002.8 (49 ids vs 51 LLRs); 002.8's test file missing from the 002 row. Fix: assign TC-051/052 (no renumbering), add the file.

**QA (F-Q-04..12):**
- **F-Q-04** — 001.2's `bytes` grammar conflates two grammars: `parse_new_bytes` (cited) actually accepts commas/decimals/`0x` — if the wire grammar narrows to strict two-hex-digit, the 4 parse-helper SURVIVES rows become REWRITE. Fix: decide wire vs TUI-input grammar split, state in C-1.
- **F-Q-05** — 007.5 collision scheme triple-inconsistent (regex vs "-NN" vs the cited `_{counter}` pattern); 008.3's ordering breaks within a collision group. Fix: pin `<ts>(-NN zero-padded)?-report.md`, regex `(-\d{2})?`, drop "mirroring".
- **F-Q-06** — 007.2 window formula underflows below address 64 / overflows at image top; gap-byte rendering and window-merge unspecified. Fix: clamp formula + 2 mandatory edge fixtures + merge rule.
- **F-Q-07** — in-session "no Textual import" assertions unreliable (sys.modules polluted by earlier tests). Fix: subprocess isolation or static import-graph inspection; monkeypatch `App.__init__` for "no App constructed".
- **F-Q-08** — **SURVIVES vs E3 package deletion:** ~60 of 69 SURVIVES rows import `cdfx.*`/`cdfx_service` → die at collection post-E3. Fix: define SURVIVES = assertion bodies unchanged + mechanical import re-pointing as an explicit E3 task.
- **F-Q-09** — `cdfx/memory_display.py` has no declared fate (12 SURVIVES tests depend on it; the package gets deleted). Fix: declare destination (e.g. `changes/display.py`) in 003.3 + C-4.
- **F-Q-10** — 002.7's TUI half (prompt/suggestion/decline/containment-of-typed-name) has no executed verification. Fix: pilot test + adversarial-filename case (merges with F-S-01).
- **F-Q-11** — 002.8's "persistently visible" can false-pass on a transient render. Fix: 3-stage test (render → unrelated action → still visible → re-validate clean → cleared).
- **F-Q-12** — 005.6's verify target (workspace-level file) can't drive `_handle_load_project`. Fix: re-point to a `tests/test_tui_variants.py` pilot.

**Security (F-S-01/02/03/06 — verdict: OK to ship WITH mitigations applied first):**
- **F-S-01** — 002.7 filename containment under-specified: `_safe_name` (`unified_io.py:464`) forces `.json` + workarea root, neither holds here; Windows reserved names (`CON.s19`), traversal, absolute paths unhandled; batch-04's containment test suite is 4/4 RETIRE with no v2 replacement. Fix text provided (sanitizer equivalent + staged write via `copy_into_workarea` + ≥3 adversarial cases).
- **F-S-02** — **verified live:** `codecs.lookup("zlib_codec")` succeeds (non-text codec) → `value.encode()` raises `LookupError`, NOT the `UnicodeEncodeError` LLR-001.4 handles; `codes` with >0x10FFFF raises `ValueError` — both escape and violate "without raising". Fix: text-encoding allowlist check in 001.3 + broadened exception coverage in 001.4 + 2 new fault cases.
- **F-S-03** — `project.json` paths have no resolution root/containment/read caps; `resolve_input_path` (cwd+repo-root walking) is too permissive for a file-driven manifest. Fix: resolve against project dir only; escape/absolute/reparse → ERROR + skip; capped read path.
- **F-S-06** — **verified live (Textual 8.2.5):** `Markdown` defaults `open_links=True` → clicked link opens the system browser; a foreign `.md` in `reports/` would be listed and rendered. Fix: `open_links=False`, no `LinkClicked` handler, viewer size cap; one assertion in the viewer test.

## MINORS
F-A-11 (timestamp spelling, merge into F-Q-05) · F-A-12 (006.6 anchor `:31-33`→`:391`) · F-A-13 (tool version source, subsumed by F-A-09) · F-A-14 (`align16` notation → pure math or NEW flag) · F-A-15 (003.2 "exactly 8 actions" vs E6 scope action — state extension) · F-A-16 (001.3 entry-content under metadata fault — specify zero entries) · F-A-17 (execution mode recorded in the report header) · F-Q-14 (suite-delta formula → exact ledger form `792−229+R+ΣN_i`) · F-Q-15 (003.4 threshold names no case set) · F-Q-16 (004.2 cover all 3 uncheckable provocations) · F-Q-17 (005.3/005.5 unnamed test targets) · F-Q-18 (006.6 "no freeze" observable definition) · F-Q-19 (007.3/007.6/007.8 inspections + stale "pending" qualifiers in §6.6 + `_start_load_worker` off-by-one `:4577`→`:4578`) · F-S-04 (pre-encode length check before encoding) · F-S-05 (`context_bytes` domain 0..REPORT_CONTEXT_BYTES_MAX NEW) · F-S-07 (raw-bytes-in-reports rule: gitignored-only, never logged, public-fixture-only test data).

## CLEAN (explicitly verified)
shall/should (0 violations) · derivation US→HLR→LLR (complete) · anchor accuracy (100+ anchors re-verified across reviewers; 1 off-by-one found) · environmental-measurement rule (all constants flagged/measured) · measured-disposition rule (totals re-add; 10/10 sampled rows correct; collector counts re-confirmed 344) · NEW flags (all new test files verified absent today) · XML→JSON defense twins (size-cap, deep-nesting, ceilings all have surviving twins; the only gap is the never-raises guard extended to codecs = F-S-02's tests).

## Operator decisions needed at the gate (3)
1. **F-A-05 — HEX save-back scope:** S19 save-back needs a NEW mem_map emitter (fine, E2); but `.hex` variants have NO writer in the codebase. Build an Intel HEX emitter too, or S19-only save-back this batch?
2. **F-A-07 — increment budgets:** E3 inherently exceeds 5 files (package deletion + ~13 test files). Approve an explicit budget exception, or split E3a (UI consolidation) / E3b (retirement enactment) and E5a/E5b?
3. **F-A-08 — check-file collision semantics:** two expectations over one address — ERROR-block the whole check document (uniform with changes) or WARNING (redundant expectations aren't destructive)?

## Phase-1 iteration fix list
All 4 blockers + 17 majors + 13 minors have concrete fix text above (security fixes verbatim from F-S-01/02/03/06). One editing pass over `01-requirements.md`; the 3 operator decisions slot into 002.7, §6.5, and 004.1 respectively.

---

## Phase-2 re-confirmation (after Phase-1 iteration #2 — 2026-06-10)

Operator decisions at the gate: **D-1** save-back S19-only this batch (HEX emitter = batch-08 candidate; `.hex` prompt declines with `saved_path=None`) · **D-2** split E3→E3a/E3b and E5→E5a/E5b (E3b carries the explicit ~20-25-file budget exception, predominantly deletions/test re-pointing) · **D-3** intra-check collisions = ERROR uniform (WARNING alternative recorded as REJECTED).

The architect applied all 34 findings + 3 decisions to `01-requirements.md` (394→444 lines) with the **§6.7 reconciliation audit** (45 rows: every finding → parent-HLR re-read disposition → landed body anchor), body-first per the template rule. Orchestrator independently verified the load-bearing closures:

| Check | Evidence | Status |
|---|---|---|
| B-1/B-2 (`saved_path` + `issues` through C-6/002.5/004.3/006.5/007.4) | 10 + 13 occurrences across producer/consumer LLRs; 004.3 now carries `issues: list[ValidationIssue]` mirroring 002.8; 004.4 returns the single object | **CLOSED** |
| B-3 (BRE grep false-pass) | LLR-003.3 mandates `grep -rE`/`rg` with the `-E`-is-mandatory rationale AND a self-tested probe (must return >0 hits pre-retirement, recorded in the E3b packet); §5.1 generalizes the rule | **CLOSED** |
| B-4 (determinism spec) | 002.5/004.3 re-specified: injectable `now_fn` clock (NEW), serialization-determinism / fixed-clock double-run | **CLOSED** |
| D-1/F-A-05 | `emit_s19_from_mem_map` (NEW, `changes/io.py`); false CLI-reuse claim withdrawn; HEX declared out-of-scope with batch-08 note | **CLOSED** |
| D-2/F-A-07 | §6.5 rewritten: E1, E2, E3a, E3b (budget exception recorded), E4, E5a, E5b, E6, E7, E8 with rebound dependencies | **CLOSED** |
| D-3/F-A-08 | LLR-004.1: ERROR uniform + rejected alternative documented | **CLOSED** |
| F-S-02 | text-encoding allowlist (`_is_text_encoding` probe) in 001.3; broadened exception coverage in 001.4 | **CLOSED** |
| F-S-06 | LLR-008.1: `open_links=False`, no `LinkClicked` handler, viewer size cap | **CLOSED** |
| F-A-10/F-Q-13 (TC index) | TC-051 (002.7) + TC-052 (002.8) assigned without renumbering; roll-up → TC-053 (TC-050 retired-unassigned, noted inline); 002 row carries `test_tui_patch_editor_v2.py` | **CLOSED** |
| F-Q-04 (grammar) | Resolved strict-wire / permissive-TUI-input split (preserves the 4 parse-helper SURVIVES rows), recorded in 001.2 + C-1 | **CLOSED** |
| F-Q-08 (SURVIVES definition) | §6.6 vocabulary note: assertion bodies unchanged + mechanical import re-pointing = explicit E3b task | **CLOSED** |
| Remaining majors/minors | §6.7 audit table rows verified present for all 34 findings; spot-checked F-Q-05 (regex `(-\d{2})?`), F-Q-07 (subprocess/static-import probes), F-S-01 (sanitizer + 3 adversarial filenames), F-S-03 (manifest project-dir-only resolution), F-Q-16 (3 uncheckable provocations in 004.2) | **CLOSED** |
| Normative re-check | 0 `should` in statements (grep); audit-table mentions are informative prose | **PASS** |

**Result: 4/4 blockers + 17/17 majors + 13/13 minors closed in one iteration; 0 open. Security mitigations all applied as spec amendments. Recommend advancing to Phase 3** (first increment: E1 + CI-1 riding the same PR).
