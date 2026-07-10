# 02 — Cross-agent review · batch-33 · check-result reasons + per-entry taint

**BLUF.** Three Phase-2 lenses over the locked `01-requirements.md`: architect **BLOCKERS(1)** →
`iterate-to-refine` executed same-gate; security **PASS-with-conditions** (2 major, 2 minor); the
narrow QA fold-verify agent **stalled** (watchdog kill, no output) and its mandate was folded into
the post-amendment verification pass (separate agent, results recorded in the gate decision). All
findings folded in one amendment iteration (10 folds, §12 fold record in 01-requirements.md); totals
unchanged (12 ATs · 15 LLRs · 9 TCs) + one NEW issue code `CHG-DECL-STRUCTURE`.

## Findings register (all folded)

| ID | Sev | Lens | Finding | Disposition |
|----|-----|------|---------|-------------|
| B-1 | **blocker** | architect | The locked attribution rule (allowlisted code × address equality) **wrongly taints a healthy constructed entry** sharing an address with a SKIPPED declaration — every reader skip site emits `address=` (io.py:1018-1166), so a duplicated-then-edited file (skipped bad-bytes decl at X + healthy entry at X) gets a FALSE "entry at 0xX carries [CHG-BYTES-SYNTAX]"; contradicts §1.2 rule 2 and US-050's promise; neither AT-050b nor TC-050.2 as written could catch it | LLR-050.1 split: **non-blocking set** (6 skip codes + CHG-DECL-STRUCTURE; unknown codes still block) vs **taint-attribution set** = {CHG-COLLISION} only (sole code emitted against constructed entries, validate.py:110-122); LLR-050.2 restricted; TC-050.2 same-address pin; R-B02-2 corrected; entry-index attribution REJECTED (ValidationIssue is engine-frozen, no index exists at skip time) |
| S-F1 | major | security | `MF-BAD-STRUCTURE` is dual-use — envelope fault (io.py:526,728-736) AND per skipped junk declaration (io.py:879-897); under the fail-safe it would block the whole run on ONE junk element, re-introducing the removed collective-taint behavior | New `CHG-DECL-STRUCTURE` code for the declaration-level case (non-blocking + non-tainting); envelope variant stays run-blocking; AT-050b non-object-declaration fixture |
| S-F2 | major | security | Unbounded reason interpolations: `{codes}` can hold ~100k duplicates; `{kind!r}` bounded only by the 256 MB read cap, landing on the deliberately-untruncated `#patch_checks_status`; LLR-051.5 multiplies by row count — local-DoS class | §1.3/LLR-051.3 caps: `{codes}` sorted+deduped+cap-5 "+N more"; `{kind!r}` 64-char display cap (keep `!r` — control-char escaping); owner TC-051.2 |
| S-F3 | minor | security | The in-batch funnel scrub closes FIVE pre-existing sibling exposures (`{kind!r}`, `{fmt!r}`, `{encoding!r}`, `{value_mode!r}`, `{entry_type!r}` — all verbatim file text into markup-enabled log labels), not one; hostile fixture only exercised `kind` | Five-sibling closure recorded; TC-051.4 pushes a hostile `encoding` token through `_report_change_result` |
| S-F4 | minor | security | Scrub placement: pre-escaping before the 50-char cap would bisect escape sequences (`[[`→`[`) and silently alter content; a stray CLOSE tag crashes `Label.update` with MarkupError even untruncated | LLR-051.8: scrub at/after the cap, never pre-escape; preferred `markup=False` at Label construction (app.py:1271-1274 — sole writer confirmed; zero intended-markup users of set_status, byte-identical rendering) |
| A-m1 | minor | architect | AT-051c's composed fixture: STRING entries raise at change_service.py:443-453 under a broken-encoding envelope and never reach the document | Fixture note: BYTES entries (or use CHG-VALUE-MODE-UNKNOWN) |
| A-m2 | minor | architect | TC-050.2's existing skipped-address bullet does not cover the same-address cross case | Distinct pin added (rides B-1 fold) |
| A-m3 | minor | architect | `ok=False` is observable only on the ChangeActionResult return (app discards it on this path) | AT-051b names the observation point |
| A-m4 | minor | architect | No diagram of the reason travel path | Accepted as-is (tabulated); optional — not folded |

**Architect confirmed-sound (M-checks):** LLR-051.8 seam IS the single choke point (sole writer
app.py:8892-8895; the two out-of-scope markup surfaces — `#status_text`, verify-mismatch `notify` —
carry non-reason text: observation O-2 logged as a future hygiene candidate). AT-051c composed-path
harness FEASIBLE (change_service keeps faulted documents, add_entry appends without re-validation).
Aggregates contract tolerant of {0,0,N} everywhere censused (report totals via .get; variant status
execution-derived; app never reads result.ok on the run_checks path). shall/should CLEAN.

**Security confirmed-safe:** issue CODES are repo-controlled constants at all 30+ minting sites
(only the named string fields are file-derived); reason templates embed codes+counts only, never
issue MESSAGE text; `linkage_symbol` (file-derived) is NOT rendered by this batch's surfaces.

## Two-layer blocker checks
(a) every US ≥1 black-box AT ✓; (b) deliverables + observation methods named (incl. AT-051b's
status-vs-log split and AT-051f's stated no-consumer status) ✓; (c) both chains complete at
HLR→LLR/TC (§5) ✓; (d) ATs black-box at the Run-checks button / service-return / rendered surfaces ✓.
Supersession census: draft §6.1 re-verified line-accurate (01b Task A rows 30-36); the :406 pinned
literal supersession is Inc-2's obligation. C-14 n/a (no file moves).

## Gate
One iteration executed against the named B-1 gap (Certainty axis). Post-amendment verification pass
(covering the stalled agent's checklist + the 10 folds) recorded in the gate decision in state.json.
Axes: Coverage — chains + reason-code ownership complete incl. the new code; Certainty — the false-
taint mode has a named regression pin; counterfactual directions intact; Evidence — every fold traces
to a finding, every finding to file:line. → **approve** on verification CLEAN.
