# 02 — Cross-agent review · batch-29

**BLUF.** Tri-agent independent review (architect · qa-reviewer · security-reviewer). **1 BLOCKER, 5 majors,
5 minors, 2 security-minors.** The blocker (B-1) is an **AT-authoring** defect (wrong monkeypatch locus),
not a wrong requirement — the HLR/LLR structure is sound, derivation traces clean, `shall`/`should` clean,
0 engine-frozen, counterfactuals real, the C-14 census verified complete, and the "recolor colour oracle
is on `#a2l_tags_list` (not retired)" claim is independently confirmed correct. All findings are resolved
by folding into `01-requirements.md` v2 (§6.6 record) — no iterate-to-Phase-1 requirement change needed.
**Recommendation after fold: approve.**

Reviewer verdicts: architect **0 blockers**; qa **1 blocker**; security **0 blockers, safe-to-implement**.

---

## BLOCKER (folded into v2)

**B-1 (qa) — AT-042b monkeypatch target bypasses the cap it asserts.** The reused idiom
(`test_loadfilescreen_input.py:231`) monkeypatches `read_os_clipboard` *wholesale* with a lambda, so the
real capped `read_os_clipboard` (LLR-044.2 locus, `:265-269`) never runs; `action_paste` then does
`splitlines()[0]` on the full blob → `input.value` len `== CAP+5_000_000`, so AT-042b **fails post-fix**
(false red) or forces a second cap in `action_paste` (contradicting the single-funnel LLR-044.3/.4).
**Fix (folded):** re-target the injection BELOW `read_os_clipboard` — monkeypatch `os_clip_mod._STRATEGIES = (("fake", lambda: blob),)`
so the real capped `read_os_clipboard` runs inside `action_paste`. AT-042b annotated NOT to copy the
wholesale-monkeypatch idiom. (AT-042a is already correct — it passes `strategies=` into the real function.)

## MAJOR (all folded into v2)

**M1 (arch) — HLR-044.1-clip overclaims "memory spike."** The shall-statement promises an oversized
clipboard "cannot cause a memory spike," but LLR-044.1–.5 bound only *downstream* use and R-044-1 admits
transient full materialization inside tk/ctypes/PS before the cap. Only the deferred LLR-044.6 would deliver
"no memory spike." **Fix (folded):** reword the HLR to what it delivers (bounds `splitlines` cost, the value
into widget/logs, and a hang), with the transient-materialization caveat in the statement; LLR-044.6 remains
the named residual.

**M2 (arch) — LLR-043.R8 (restore) has no genuine white-box TC.** The §5 cell cites AT-021 (black-box) + the
precompute formatter TC — but the latter tests the *orphaned DataTable payload*, not the shipped `IssueRow`
node. The functional chain US-043→LLR-043.R8→TC is incomplete. **Fix (folded):** add **TC-043-restore.1**
(white-box: `IssueRow.compose` yields a related node whose plain text is `", ".join(related_artifacts) or "-"`
built via `safe_text`). **Merges with security-F1** into one TC that also asserts a bracket/ANSI payload
injected into a test issue's `related_artifacts` renders literal.

**M3 (arch) — "no live caller" for `precompute_issue_datatable_payload` is wrong.** The load worker still
invokes it (`app.py:6649/:7161`), populating caches (`:6650-6651/:6955-6956`). LLR-043.R4 removes only the
*consumer*; post-retirement the caches are **dead-written every load, never read** — not orphaned.
**Fix (folded):** restate TC-043-retire.4 predicate precisely ("no *consumer* of the cached rows remains;
precompute may still be invoked by the worker; caches dead-written pending follow-up") and extend R-043-3 to
name the dead cache writes for the follow-up batch's scope.

**M-1 (qa) — AT-043-c17 file-derived triple-payload isn't producible as one REF symbol.** A single
whitespace-delimited A2L REF token can't carry a space-bearing `message`; the code **chip** renders the fixed
constant `A2L_BROKEN_REFERENCE` (hostile token reaches only the *detail/symbol* node); two ghost symbols need
two GROUP refs; raw `\x1b` survival through the frozen lexer is unverified. **Fix (folded):** restructure the
fixture as **multiple REF entries** (one hostile no-whitespace token each: `MAP_Model[bold]`,
`x[link=file:///etc]`); assert on the **`.issue-detail`** node, not the chip; drop the raw ANSI byte from the
file-derived variant (retained by the seeded AT-039e, which the spec correctly keeps); verify tokenization
against `a2l.py`/`rules.py` in Phase 3 before committing the fixture.

**M-2 (qa) — whole-list count-guard is thresholded and scoped wrong.** `len(filtered) < page_size` (200)
does NOT guarantee `query(IssueRow) == whole list` because mounted rows cap at `_GROUP_DISPLAY_MAX = 40`; a
41–199-issue fixture passes the guard yet mounts only 40. And the guard was framed for "exactly one" asserts
only — the **absence** asserts (`test_at_036a/c`, `test_at_037a` `not any(...)`) are equally cap-vacuous
(`test_at_036c` has no "exactly one" assert at all). **Fix (folded):** restate as
`assert len(filtered) <= _GROUP_DISPLAY_MAX` (or assert the `IssueGroupHeader.issue_count`), required on
**every** whole-list claim — counts AND absences — in all migrating AT-036*/AT-037* functions.

## MINOR (folded / noted)

- **m1 (arch) + m-1 (qa) — R6/R8 both touch `IssueRow.compose`; "unchanged" is ambiguous.** Reword R6 to guard
  the markup-safety/behavior of the existing two cells (not the literal line range); R8 states it **appends** a
  third `safe_text` node carrying a dedicated **`.issue-related`** selector so AT-021 can query it black-box. (folded)
- **m2 (arch) — stale compat comments.** R1/R2 also remove the adjacent DataTable comments (`app.py:1475-1481`,
  `styles.tcss:783-788`) to avoid doc-debris. (folded)
- **m3 (arch) — R5 docstring.** R5 notes updating `on_data_table_row_selected`'s Data Flow/Dependencies
  docstring (removed `_jump_to_validation_issue_by_index`). (folded)
- **m4 (arch) — LLR-044.5 is a corollary of LLR-044.2** (bounded logging follows from capping `text` before the
  `len`); flagged non-independent, no separate verification item. (noted)
- **m-2 (qa) — AT-021 selector + ordering.** AT-021 row order derives from `SEVERITY_ORDER` (error→warning); the
  related node uses the `.issue-related` selector; keep the precompute formatter TC for dual coverage. (folded)
- **m-3 (qa) — two preserved behaviors covered by-retention, not by new AT** (failure-notification-not-fired on a
  capped non-empty paste; paging-advances post-retirement via retained census row 14). Acceptable; recorded so the
  gate notes coverage is by-retention. (noted)

## SECURITY (0 blockers — safe to implement)

- **F1 (minor) — C-17 safety of the NEW related node is untested defense-in-depth.** `related_artifacts` carries
  only fixed engine type-tokens today (all 7 producers in `validation/engine.py`: `["a2l","mac","s19"]` etc.), so
  no live injection path — MINOR. **But** if a future rule ever routes file-derived text into `related_artifacts`,
  the node silently becomes a second injection sink with no test. **Fix (folded, merged with arch-M2):**
  TC-043-restore.1 asserts the node is `safe_text`-built and renders a hostile payload literal; document the
  "type-token-only" contract at the engine producers. *(Conditional-BLOCKER only if the field's origin ever changes.)*
- **F2 (minor, acceptable) — residual transient materialization** (deferred LLR-044.6). Blast radius is local
  (same user's clipboard, no remote/multi-tenant surface); PS layer additionally timeout-bounded. Correctly
  disclosed as R-044-1/R-044-3. No action required this batch.
- **Confirmations:** `safe_text` is a genuine literal renderer (`screens_directionb.py:370`, `Text(value, style=style)`,
  never `from_markup`); the cap does NOT reopen PR #54's subprocess surface (argv-list / shell=False / no user input
  in the command / timeout intact); engine-frozen integrity preserved (`model.py` read-only); no clipboard/file text
  logged (length-only).

## Positive confirmations (cross-verified)
- Counterfactuals real: `test_tc023_...` currently asserts the DataTable IS mounted (`is_datatable==1`) → AT-043a/c
  `1→0` genuinely red pre-fix; `read_os_clipboard` returns verbatim today → AT-042a genuinely red pre-fix.
- C-14 census complete: independent grep of `validation_issues_list|get_row_at|_issue_rows` — all hits in the 5
  named files; colour oracle (`_a2l_row_list` on `#a2l_tags_list`) untouched; only `_issue_rows` content migrates.
- Headless viability confirmed for both stories (injected strategies + Pilot).

## Evidence checklist
- [✓] Findings classified blocker/major/minor with file:line + fix — above.
- [✓] `shall`/`should` audited — architect: no modal `should` in any HLR/LLR.
- [✓] Two-layer completeness checked — every story has a black-box AT (B-1/M2 fix the *authoring*, not the presence).
- [✓] Supersession/location census (C-14) re-verified by an independent grep — complete.
- [✓] Security re-invoked for the new external/render surface (restored related node) — F1.
- [✓] All accepted findings folded into `01-requirements.md` v2 §6.6; blocker resolved pre-gate.
