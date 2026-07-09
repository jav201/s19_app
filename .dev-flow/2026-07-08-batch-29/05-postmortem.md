# 05 — Post-mortem · batch-29 · clipboard read cap + legacy Issues DataTable retirement

## 1. BLUF

**Both stories shipped clean: US-042 bounds the OS-clipboard read to 64 KiB (R-TUI-044); US-043
retired the hidden `#validation_issues_list` DataTable so `GroupedIssuesPanel` is the sole Issues
surface, with the "Related artifacts" info restored onto `IssueRow`.** 5 increments, ledger **1171 →
1183** (final full suite 1158 passed / 2 skipped / 23 xfailed / 0 failed), **0 engine-frozen diffs**,
**0 production regressions**. Phase-2 tri-agent review caught **1 blocker + 5 majors + 5 minors + 2
security-minors — all folded pre-code, 0 escaped**.

**The single most important lesson:** *a spec-level AT can pass Phase-2 review, be folded through the
requirements, and still never get built* — **AT-043-c17** (the file-derived C-17 acceptance test the
review mandated) was silently unrealized across Inc2–4 and only surfaced at the Phase-4 reconciliation,
because no increment explicitly *owned* its realization. It cost one test to close in Inc5, but it
should have been caught the moment its surface landed, not two phases later. The batch's other gap —
the C-14 removal census missing a direct-caller of the deleted private method — is the same shape of
error: a completeness check scoped to the wrong axis.

The batch's headline *win* is structural: because `GroupedIssuesPanel` had already been running
alongside the hidden DataTable since batch-28, the retirement could be sequenced **readers-first,
widget-last** — the suite stayed green at every increment boundary, with no big-bang removal.

---

## 2. What worked

**The retire-while-parallel strategy kept the suite green through a widget removal.** Because the
grouped panel already ran in parallel with the `display:none` DataTable (batch-28 legacy), the
increments were sequenced so the test *readers* migrated **before** the widget was deleted:
- Inc2 (`increment-002.md` §1) added the `.issue-related` node and migrated AT-021 **while the
  DataTable stayed mounted** — additive, suite green.
- Inc3 (`increment-003.md` §1) re-pointed the 6 census readers (rows 12/13/15/16/17/18) onto the
  **live** grouped panel while the DataTable was still present — every migrated reader had to pass
  against the panel *before* removal, so a faulty migration reddened immediately, not at removal time.
- Inc4 (`increment-004.md` §1) removed the DataTable **last**, when nothing read it anymore.

This is the "output-then-consume" discipline applied to a retirement: the risky deletion happened
against a suite that had already been proven to observe the replacement surface.

**Phase-2 caught the AT-042b blocker pre-code — a C-10 authoring defect stopped before implementation.**
B-1 (`02-review.md` "BLOCKER") found that the reused idiom monkeypatched `read_os_clipboard`
*wholesale*, so the real capped funnel (LLR-044.2) would never run — the test would have *bypassed the
very cap it asserted*, going false-red post-fix or forcing a contradictory second cap in `action_paste`.
Re-targeting the injection to `os_clip_mod._STRATEGIES` (below the cap) was folded into the spec §3 and
honored in Inc1 (`increment-001.md` §4, AT-042b note). A wrong *test*, not a wrong requirement — caught
by an independent reviewer reading the actual monkeypatch locus.

**The C-14 census drove the 5-file migration with no surprise at the removal.** The 18-row census
(built Phase-1, independently grep-verified complete in Phase-2, `02-review.md` "Positive
confirmations") correctly scoped the *colour* oracle to the untouched `#a2l_tags_list` (a different
DataTable) so only the `_issue_rows` *content* read-back migrated — the lower-risk finding. When Inc4
deleted the widget, the census map meant the removal itself produced no reader breakage beyond the one
gap noted in §3.

**In-flight catches — real defects found and fixed before the gate, none escaping to prod**
(`04-validation.md` §6):
1. **Inc3 async double-count (test bug):** a whole-DOM `query(IssueRow)`/`query(IssueGroupHeader)`
   between a grouped re-render and the next `pilot.pause()` counted not-yet-removed rows → 60/40.
   Fixed by awaiting the pause before summing; the latent trap was then noted for AT-043a/b in Inc4.
2. **Inc4 census-missed white-box test:** `test_populate_issues_datatable_records_filtered_index`
   directly called the removed `_populate_issues_datatable` → would `AttributeError`. Caught during
   Inc4, retired (drove the −1 ledger deviation).
3. **Inc4 `_drive_panel` 40-cap dedup:** the shared panel-render helper flooded the error group past
   `_GROUP_DISPLAY_MAX=40`, hiding sparse cross-codes; re-seeded one representative issue per distinct
   code, with an honest caveat recorded (no longer proves "all N instances render" — a DataTable-era
   property the cap makes impossible; fails loud if distinct codes > 40).

---

## 3. What didn't (and the fixes)

**The operator brief under-credited the blast radius.** The brief named 2 test files; reality was 5,
including the two batch-24 recolor-oracle suites (`test_tui_a2l_issue_recolor.py`,
`test_validation_service_supplemental.py`). This was **caught at Phase-0 intake by an independent grep**
(`state.json` `controls_active`: "briefings under-credit … reality is 5 → verify-don't-trust"), *not*
by trusting the brief — and it was surfaced and accepted at the DoR gate before any code. This is the
system working: the interruption-protocol "briefings under-credit" rule turned a would-be mid-batch
surprise into a Phase-0 correction. The lesson is not new but re-confirmed: **verify the census; never
inherit a blast radius.**

**AT-043-c17 was specified, folded, and silently NOT implemented — the batch's key process gap.**
The file-derived C-17 acceptance test (load an A2L with hostile no-whitespace `REF_*` symbols → shipped
chain emits `A2L_BROKEN_REFERENCE` carrying the literals → assert literal render on the grouped
`.issue-detail`, proving token survival through the *frozen* `a2l.py` lexer end-to-end) was:
- authored in Phase-1 spec §3,
- restructured and re-approved in Phase-2 (qa M-1: multiple REF entries, assert on `.issue-detail`),
- then **covered only in parts** across Inc2–4 (the seeded `test_at_039e_c17_…` render leg + a
  service-level parse leg) — **never joined into one on-disk node driving the full chain**.

Nothing in Inc2–4 flagged the absence because **no increment's scope explicitly listed "realize
AT-043-c17"**. It surfaced only at the Phase-4 reconciliation (`04-validation.md` §6 note 3, §7), where
every provisional spec id was matched to a real `def test_…` node and this one had no home. It was
closed in Inc5 (`increment-005.md`) — one test, `test_at_043_c17_file_derived_hostile_ref_symbol_
renders_literal` (`test_tui_a2l_issue_recolor.py:326`) — but **it should have been caught at the Inc
(Inc2) where the `.issue-related`/grouped C-17 surface landed**, not deferred to a post-hoc audit.

**The C-14 census itself missed a white-box direct-caller.** The census keyed on readers of the
*widget id / string* (`validation_issues_list`, `get_row_at`, `_issue_rows`) — it did **not** enumerate
direct callers of the *removed private method* `_populate_issues_datatable`. So
`test_populate_issues_datatable_records_filtered_index` (a white-box test that called the helper
directly, never touching the widget id) was absent from the 18-row map and only caught when it broke in
Inc4 (`increment-004.md` §"Ledger delta" deviation; `04-validation.md` §6.2). It was correctly retired
— its removal is mandatory, not discretionary — but a census that had grepped the symbol name as well
as the widget id would have listed it up front.

---

## 4. Scope drift — assessment

**Controlled; stayed within the spec's named surface.** Two deviations, both disclosed:

- **6th file in Inc4** (`increment-004.md` §2, §"Deviation"): a **1-line stale docstring** in
  `issues_view.py:7` ("retained beside them" → "fully retired … sole Issues surface"). Doc-only, forced
  by the grep-clean gate (the false docstring would otherwise fail the "`#validation_issues_list` = 0
  source hits" invariant). Nudged the increment to 6 files vs the ≤5 norm; the code-reviewer approved it
  as spec-§1-covered (`state.json` Inc4 entry, "F3 6-file batch-approved").
- **Inc5 added** (`increment-005.md`): a whole extra increment, but it is **gap-closure of a mandated
  spec AT**, not new scope — it realizes AT-043-c17, which §3 already required. In-scope by definition.

Net: no feature creep, no un-planned refactor of adjacent code, no engine-frozen touch. The one true
scope *addition* (Inc5) was mandated work that had been missed, not new ambition. The 6th-file
deviation was the minimum edit the grep gate demanded.

---

## 5. Metrics

| Dimension | Value | Source |
|---|---|---|
| Iterations per phase | P0=1, P1=1, P2=1, P3=1, P4=1, P5=1 (all single-pass) | `state.json` `iterations_per_phase` |
| Increments | 5 (Inc1 clip · Inc2 restore · Inc3 census-migrate · Inc4 removal · Inc5 gap-close) | `03-increments/` |
| Phase-2 findings | **1 blocker · 5 major · 5 minor · 2 security-minor** — all folded (§6.6), **0 escaped** | `02-review.md`, `01-requirements.md` §6.6 |
| Findings caught at Phase-2 (pre-code) | B-1 + M1/M2/M3 + qa M-1/M-2 + minors + F1/F2 (13) | `02-review.md` |
| Gaps caught at Phase-4 (post-code, pre-merge) | **1** — AT-043-c17 unrealized → closed Inc5 | `04-validation.md` §6/§7 |
| Defects caught at increment gate (in-flight) | **3** — async double-count (Inc3), census-missed `_populate` test (Inc4), `_drive_panel` 40-cap dedup (Inc4) | `04-validation.md` §6 |
| Production regressions | **0** | `04-validation.md` BLUF |
| Engine-frozen diffs | **0** (`git diff main -- <frozen set>` EMPTY; guard passes) | `04-validation.md` §1 |

**Test ledger (base 1171 → 1183 collected; 1158 passed final):**

| Increment | Scope | Δ | Cumulative | Note |
|---|---|---|---|---|
| Inc1 | US-042 clipboard cap (AT-042a–f + TC-042.1–.3) | +9 | 1180 | F841 fix net 0 |
| Inc2 | LLR-043.R8 restore (+TC-043-restore.1; AT-021 rewritten in place) | +1 | 1181 | additive, DataTable still mounted |
| Inc3 | C-14 census rows 12/13/15/16/17/18 | 0 | 1181 | rewrites-in-place |
| Inc4 | DataTable removal + AT-043a/b/c (+3), retire worker-precomputed-cells (−1) + census-missed `_populate` test (−1) | +1 | 1182 | −1 deviation vs task's expected +2 |
| Inc5 | AT-043-c17 file-derived C-17 | +1 | 1183 | gap-closure |

**Files touched (10):** product — `tui/os_clipboard_input.py`, `tui/app.py`, `tui/issues_view.py`,
`tui/styles.tcss`; tests — `test_loadfilescreen_input.py`, `test_tui_issues_view.py`,
`test_tui_directionb.py`, `test_tui_app.py`, `test_tui_a2l_issue_recolor.py`,
`test_validation_service_supplemental.py`. **0 engine-frozen.**

**Final full suite** (`04-validation.md` §1, orchestrator ~18 min at Inc4, +1 after Inc5):
**1158 passed · 2 skipped · 23 xfailed · 0 failed** (1183 collected). The 23 xfails are 20 batch-28
Issues/workspace snapshot cells absorbing restyle drift + 3 pending baselines — cleared only by
canonical-CI regen (pinned `textual==8.2.8`; local regen FORBIDDEN).

---

## 6. Root causes (the two real gaps)

**Why AT-043-c17 slipped: a spec AT with no increment that owned its realization ("folded but not
assigned").** The V-model routed the AT correctly through authoring (P1) and review (P2), but the
Phase-3 increment plan (`state.json` P3 entry) was structured around *code surfaces* — clip cap,
restore node, census migration, removal — and never mapped each §3 AT to the increment that must
realize it. AT-043-c17's two legs (render safety, parse emission) happened to be touched by different
increments for other reasons, creating the *illusion* of coverage ("covered in parts") with no single
node proving the end-to-end invariant. The V-model's traceability matrix is only enforced at Phase-4;
nothing at the *increment* level asserted "every AT whose surface I just shipped now has a distinct
on-disk node." The fix that worked (Phase-4 reconciliation catching it) is a *backstop*, not a *gate* —
it caught the miss one phase too late.

**Why the census missed the direct-caller: it was scoped to widget-id/string readers, not to callers
of the removed symbol.** A location/surface-move census (C-14) exists to enumerate everything that
observes the thing being removed. This census enumerated everything that read the *widget* (by id, by
`get_row_at`, by `_issue_rows`) — a screen/DOM-observation frame. But a removed widget usually comes
with removed *helpers* (`_populate_issues_datatable`), and a white-box test can call the helper directly
without ever naming the widget id. That test was invisible to a widget-id grep. The census frame was
"who sees this on screen," when for a *code* removal it also needed to be "who calls this symbol."

---

## 7. Candidate controls — PROPOSED, NOT encoded

*Per the control-encode-approval rule, controls are proposed only; the operator was asleep under
standing auth, which explicitly forbids self-encoding. These await explicit operator approval.*

**C-CAND-A — spec-AT realization gate (per-increment + Phase-4).**
- *Failure it addresses:* AT-043-c17 was authored (P1), folded (P2), yet unrealized until Phase-4 —
  because "covered in parts" masqueraded as coverage and no increment owned it.
- *Proposed rule:* At each Phase-3 increment that lands a surface named by an `AT-NNN`, **and** at the
  Phase-4 reconciliation, assert every §3 `AT-NNN` maps to **exactly one DISTINCT on-disk `def test_…`
  node** — never "covered by the combination of X and Y." An AT with legs split across nodes is
  UNREALIZED until a single node drives the full named chain end-to-end.
- *Where it'd live:* dev-flow.md Phase-3 increment-gate checklist + Phase-4 reconciliation step.

**C-CAND-B — removal-census includes direct callers of the removed symbol.**
- *Failure it addresses:* the C-14 census keyed on widget-id/string readers and missed
  `test_populate_issues_datatable_records_filtered_index`, a white-box direct-caller of the removed
  private method — caught only when it broke in Inc4.
- *Proposed rule:* A C-14 location/surface-move census for a **removed** symbol must grep **direct
  callers of the symbol and any private helpers being removed** (`_populate_issues_datatable`,
  `_jump_to_validation_issue_by_index`, …), not only readers of the widget id / rendered string. The
  census table gets a "direct-caller" column alongside the "surface-reader" column.
- *Where it'd live:* the C-14 control definition (census construction step) in dev-flow.md.

*(No third candidate proposed — the other two gaps this batch, the under-credited brief and the async
double-count, are already covered by the existing interruption-protocol "briefings under-credit" rule
and the Inc3-noted async-pause trap respectively; encoding a new control for them would be redundant.)*

---

## 8. Items proposed for the next batch

- **R-043-3 — precompute dead-write retirement.** `precompute_issue_datatable_payload`
  (`app.py:752`) is still invoked by the load worker (`app.py:6525` / `app.py:7037`); its caches
  (`_validation_issue_cell_rows` / `_validation_issue_cell_styles`) are now **dead-written every load,
  never read** (the consumer was deleted in Inc4/LLR-043.R4). Retire the worker calls + both caches +
  the `test_tc021_precompute_payload_emits_related_cell` / `…_emits_eight_columns_and_styles` formatter
  TCs that pin them. Left surgically in place this batch (`04-validation.md` §7).
- **Canonical-CI snapshot regen** (pinned `textual==8.2.8`, `snapshot-regen.yml`) to clear the 20
  batch-28/29 Issues/workspace xfail cells (DataTable removal was SVG-neutral — `display:none` had zero
  layout — plus the `.issue-related` node drift). Local regen FORBIDDEN.
- **R-044-6 — true source memory bound.** The current post-read cap bounds all *downstream* use but
  each reader (tk/ctypes/PS) still transiently materializes the full clipboard string before the cap
  (residual R-044-1). Only worth building if profiling ever shows the transient materialization is the
  real cost; then implement the deferred LLR-044.6 (bounded `subprocess.Popen(...).stdout.read(CAP+1)`
  + terminate for the PS layer).

---

## 9. Evidence checklist

| Claim | Citation |
|---|---|
| Both stories shipped; verdict PASS-WITH-NOTES; 0 production regressions | `04-validation.md` BLUF, §6 |
| Ledger 1171 → 1183; final 1158 passed / 2 skipped / 23 xfailed / 0 failed | `04-validation.md` §1; per-inc `increment-00{1..5}.md` ledger sections |
| 0 engine-frozen diffs (`git diff main -- <frozen set>` EMPTY; guard passes) | `04-validation.md` §1; each increment "Frozen-diff"/engine-guard line |
| Retire-while-parallel sequencing (readers first, widget last) | `state.json` P3 entry; `increment-002.md` §Scope, `increment-003.md` §Scope, `increment-004.md` §Scope |
| B-1 blocker (AT-042b bypassed the cap) caught pre-code, folded | `02-review.md` "BLOCKER"; `01-requirements.md` §6.6; `increment-001.md` §4 AT-042b note |
| Phase-2 tally 1 blocker / 5 major / 5 minor / 2 security-minor, all folded, 0 escaped | `02-review.md`; `01-requirements.md` §6.6 |
| C-14 census independently grep-verified complete (colour oracle on `#a2l_tags_list`, not retired) | `02-review.md` "Positive confirmations"; `increment-003.md` §"Untouched" |
| In-flight catches: async double-count / census-missed `_populate` / `_drive_panel` dedup | `04-validation.md` §6.1–6.3; `increment-003.md` §5, `increment-004.md` §5 |
| Brief under-credited blast radius (2 named → 5 real); caught Phase-0 by grep | `state.json` `controls_active` + P0 "approved" (DoR) entry |
| AT-043-c17 authored (P1) + folded (P2 qa M-1) but unrealized until Phase-4; closed Inc5 | `01-requirements.md` §3/§6.6; `04-validation.md` §6 note 3, §7; `increment-005.md` |
| AT-043-c17 realized node | `test_tui_a2l_issue_recolor.py:326` (`04-validation.md` §5) |
| Census missed direct-caller of removed private method | `increment-004.md` §"Ledger delta" deviation; `04-validation.md` §6.2 |
| Scope drift: 6th file (doc-only, grep-gate-forced) + Inc5 (mandated gap-close) | `increment-004.md` §2/§Deviation; `increment-005.md` §Scope |
| R-043-3 precompute dead-write follow-up (exact sites) | `04-validation.md` §7; `increment-004.md` §5 R-043-3 |
| 23 snapshot xfails → canonical-CI regen (local FORBIDDEN) | `04-validation.md` §7; `increment-004.md` §"Snapshot disposition" |
