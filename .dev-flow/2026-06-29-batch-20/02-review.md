# 02 — Cross-agent review — batch-20 (D-1 + D-2)

> Phase 2. Three reviewers in parallel (architect ∥ qa-reviewer ∥ security-reviewer) against the Phase-1 `01-requirements.md`.
> **Outcome: 0 blockers. architect PROCEED · qa PROCEED · security GRANTED.** 4 minor + 2 LOW-security findings, all folded body-first into §3/§4/§5/§6 of the spec. Reconciliation audit in §6.4.

## Verdicts
| Reviewer | Verdict | Blocker | Major | Minor |
|---|---|---|---|---|
| architect | PROCEED | 0 | 0 | 2 |
| qa-reviewer | PROCEED | 0 | 0 | 2 |
| security-reviewer | GRANTED | 0 | 0 | 2 (LOW) |

## Two-layer review (blocker gate) — all PASS
- (a) every story has a black-box AT — US-024: AT-028a (gate) + AT-027a/b/c + AT-028b (guard); US-025: AT-029a/b/c/d. ✓
- (b) every output-producing requirement names its observable deliverable + observation method — on-disk `project.json` via `read_project_manifest`, TextArea `.text`, notify channel. ✓
- (c) BOTH traceability chains complete — behavioral (US→AT) + functional (US→HLR→LLR→TC). ✓
- (d) ATs are genuinely black-box — drive the shipped surface, assert the deliverable, reference no internal symbol as the assertion (verified by qa: `self._declared_regions` appears only in white-box TCs). ✓

## architect findings
- **Supersession census (change-first) — COMPLETE & ACCURATE.** `ReportViewerScreen(` = `app.py:1860` + `screens.py:620` doctest + `tests/test_tui_report_seam.py:372` (2 latter safe via default 3rd param). `_write_and_verify_manifest` = 1 caller (`app.py:3770`, keyword-only symmetric w/ batch-16 precedent). `_parse_declared_regions` = 2 usages (`screens.py:781` + `tests/test_tui_report_seam.py:350`), both in Inc-C modify-set. No missed call site. 0 frozen-file edits.
- **Derivation / D-1 split / A→B→C order — PASS.** Inc B genuinely depends on Inc A's `self._declared_regions` attribute (LLR-027.1 declares; LLR-028.1 populates; LLR-028.2 reads). No orphan HLR/LLR.
- **Seed/parse symmetry — PASS.** `f"{r.name},{r.start},{r.end}"` (decimal) round-trips through `int(x,0)` to the identical tuple. Parser `.strip()`→`split(",")`→exactly-3-parts confirmed at `screens.py:565-578`.
- **Back-compat — PASS.** No path sets a non-empty `self._declared_regions` default; serializer omits the empty key (`manifest_writer.py:330-334`); AT-027c + TC-027.3 assert 0-byte delta. `should`-misuse: none.
- **MINOR-1** (folded F-A1): D-2 makes the comma-edge *louder* (visible skip-count) — documentation fold.
- **MINOR-2** (folded F-A2): `:372` 2-arg construction census addendum.

## qa-reviewer findings
- **CRITICAL — notify observability PASS.** `Widget.notify` (inherited by `Screen`) delegates to `self.app.notify`; the batch-19 `_notices()` helper monkeypatches the instance `app.notify` → a `ReportViewerScreen.self.notify` is captured. **AT-029a–d are not vacuous.**
- **C-12 gate/guard separation — PASS.** AT-028a is a true single-chain through-surface test (real save → re-read real project.json → unmodified load → assert TextArea); reverts RED if either save-thread or load-seed breaks. AT-028b is a hand-written-project.json consumer GUARD that stays green under a reverted save handler ⇒ structurally cannot satisfy the gate. Confirmed.
- **C-10 — PASS.** AT-027a asserts the exact 2-tuple (not `len>0`); D-2 = one AT per branch (malformed/invalid/blank-excluded) + negative absence.
- **minor-1** (folded F-Q1): AT-029a/b assert the standalone count token (`\b1\b`), not a substring.
- **minor-2** (folded F-Q2): AT-028a assert `.text` against a literal, not a reconstruction.
- **Phase-3 carry C-P3a:** port `_notices()` into `test_tui_report_seam.py` (no capture helper there today).

## security-reviewer findings — GRANTED (batch-19 catch defended)
- **Q1 SAVE writes only construction-scrubbed names** — `DeclaredRegion.__post_init__` scrubs+caps at construction (`report_addendum.py:72-90`); `serialize_manifest` emits the post-scrub `region.name`.
- **Q2 LOAD re-scrubs** — `_parse_manifest_declared_regions` reconstructs via the `DeclaredRegion` ctor (`variant_execution_service.py:349-352`) ⇒ malicious project.json sanitized; malformed entries dropped (collect-don't-abort).
- **Q3 no seed injection** — scrub strips `\n`/`\r`/control (`validation/model.py:20` `[\x00-\x1f\x7f]`) ⇒ name can't hold a newline ⇒ `"\n".join` can't smuggle a line; `TextArea.text` is raw text (no Rich markup interpretation).
- **Q4 no new external-write surface** beyond project.json (already scrubbed both ends). **Q5 D-2 notify = count only**, no operator-text echo.
- **F1 (LOW):** comma round-trip — correctness/UX, no security impact (data loss, never injection). **F2 (LOW):** keep notify count-only (forward guard; spec already complies → Phase-3 carry C-P3b).

## Scope-change re-routing check
No requirement change in this phase added a new external-write/output surface (the only external write — project.json — was already in scope and security-reviewed). No re-invocation needed.

## Fold disposition
All 6 findings applied body-first to `01-requirements.md` (§6.3, §4 LLR-028.3, §5.2 AT-028a + AT-029a/b) + audited in §6.4. Phase-3 carries C-P3a/b/c recorded in §6.4. No blocker → no iterate-to-refine.
