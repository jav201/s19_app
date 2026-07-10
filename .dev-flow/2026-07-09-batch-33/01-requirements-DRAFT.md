# 01 — Requirements DRAFT · batch-33 · B-02: self-explaining check results + per-entry taint

**BLUF.** Three TUI-side stories on the Patch Editor Checks surface, **0 engine-frozen** modules touched
(`tui/changes/`, `tui/services/`, `screens_directionb.py` are all outside the frozen set).
Today `run_check_document` collapses EVERY entry to a bare `uncheckable` token whenever the document
carries any ERROR issue or has the wrong `kind` (collective taint, `check.py:166`), and containment-driven
uncheckables (`PARTIAL`/`OUTSIDE`/no-image) also surface reason-less (`check.py:187`). Operator decisions
(baseline backlog 2026-07-09, B-02 — already made, baked in here): **(1)** per-entry taint replaces
collective taint; **(2)** wrong document kind stays a whole-run block but with one loud, specific
run-level reason; **(3)** every uncheckable entry carries its reason; **(4)** an info affordance explains
check semantics. **US-050** per-entry taint (engine), **US-051** reasons everywhere (model + display),
**US-052** checks info affordance. Two locked requirements need §6.5 before/after amendments
(**R-CHK-001**, **R-PATCH-CHECKS-CLARITY-001**). C-17 applies: the wrong-kind run-level reason can embed
a file-derived `kind` token → markup-safety is an LLR with a hostile AT. Aggregate keys
(`passed`/`failed`/`uncheckable`) are public-ish contract — shape preserved, only *values* shift under
per-entry taint.

Language: English. Route: full /dev-flow.

> **Numbering note (Phase-2 reconciliation required):** this worktree branched at batch-29; the
> batch-30/31/32 artifacts (and their US/HLR/AT numbers) are not on this branch. US-050/051/052,
> HLR-050/051/052, AT-050*/051*/052* are **provisional** — renumber against the merged main before lock.

---

## 1. Scope & context

- **Engine (pure) code:** `s19_app/tui/changes/check.py` (`run_check_document`), `s19_app/tui/changes/model.py` (`CheckRunEntry`, reason vocabulary).
- **Service/display code:** `s19_app/tui/services/change_service.py` (`run_checks`, `check_rows`), `s19_app/tui/screens_directionb.py` (`PatchEditorPanel.refresh_check_results`, `#patch_checks_help`).
- **Engine-frozen set (READ-only, 0 diff target):** `core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py`. None of the touched files is frozen; `validation/model.py::ValidationIssue` is read, never modified.
- **Apply gate UNCHANGED:** `apply_change_document`'s whole-document ERROR/kind gate (LLR-002.1) stays as is — apply *mutates*, so the conservative gate is correct there. This batch deliberately breaks the "apply-gate mirror" decision (D-3, `check.py:13-20` module docstring) for the *read-only* check path only.
- **Out of scope:** project-report `### Checklists` table shape (`report_service.py:782-793`) — reason travels in the model (`to_dict`) so a later batch can surface it; see Open Question Q2. Headless `run_checks_for_project` and variant execution inherit the new semantics automatically (same engine) but gain no new CLI/report surface.

### 1.1 Current behavior (code-verified, every claim cited)

| # | Current behavior | Evidence (file:line) |
|---|------------------|----------------------|
| C1 | `not_runnable = document.has_errors or document.kind != "check"` — one boolean gates the whole run | `s19_app/tui/changes/check.py:166` |
| C2 | Under the gate, EVERY entry gets `CHECK_UNCHECKABLE` with no reason; `actual_bytes=None` | `check.py:176-177` |
| C3 | `PARTIAL`/`OUTSIDE`/`UNVALIDATED_NO_IMAGE` entries also collapse to the bare `uncheckable` token (else-branch) | `check.py:186-187` |
| C4 | `CheckRunEntry` has NO reason field (fields: entry_type, address_start/end, expected/actual_bytes, result, linkage, linkage_symbol) | `s19_app/tui/changes/model.py:618-625` |
| C5 | Result tokens `pass`/`fail`/`uncheckable` + `CHECK_RESULT_DOMAIN` + `CHECK_AGGREGATE_KEYS = ("passed","failed","uncheckable")` are module constants; docstrings call issue codes/domains public contract | `model.py:548,552,558,561-565,571` |
| C6 | `CheckRunResult.to_dict` serializes per-entry dicts WITHOUT any reason key | `model.py:742-758` |
| C7 | Display row text: `0x..-0x.. expected [..] actual [..] -> {token}`; severity map pass→sev-ok, fail→sev-error, uncheckable→sev-warning | `s19_app/tui/services/change_service.py:1064-1067` (text), `:75-79` (`_CHECK_RESULT_SEVERITY`) |
| C8 | Status line `Checks: P passed, F failed, U uncheckable`; `ok = failed == 0` — an all-uncheckable blocked run reports `ok=True` | `change_service.py:1008-1014` |
| C9 | Rows are mounted markup-safe (`Static(..., markup=False)`); the status label is a plain `Label.update(status_line)` (markup **enabled** by Textual default) | `s19_app/tui/screens_directionb.py:2290` (rows), `:2286` (status), `:1898` (`#patch_checks_status`) |
| C10 | `#patch_checks_help` label exists: "Checks: runs the loaded change document's checks against the loaded image." | `screens_directionb.py:1869-1874`; locked by REQUIREMENTS.md `R-PATCH-CHECKS-CLARITY-001` (:3132-3135) |
| C11 | app.py routes `run_checks` → `service.run_checks(...)` → `panel.refresh_check_results(service.check_rows(), result.message)` | `s19_app/tui/app.py:1667-1674` |
| C12 | Reader is skip-and-continue per entry: a faulted entry declaration appends ONE addressed issue and constructs NO entry — `document.entries` holds only structurally valid entries | `s19_app/tui/changes/io.py:825-830` (loop), `:1018-1028,:1058-1067,:1131-1140,:1144-1154` (skip sites, all with `address=`) |
| C13 | Any metadata-level ERROR → **zero entries** ("faulted envelope", F-A-16); metadata issues carry NO address | `io.py:682-738`; `model.py:206-207` |
| C14 | Entry-count ceiling drops the overflow with ONE address-less `MF-ENTRY-LIMIT` issue; the in-ceiling prefix IS parsed | `io.py:813-823` |
| C15 | `CHG-COLLISION` is the only ERROR that names a *constructed* entry's address (one finding per collision, `address=entry.address`) | `s19_app/tui/changes/validate.py:40-42,112-121` |
| C16 | Precedent for entry-attribution already ships: `ChangeService.rows` builds `fault_addresses` from ERROR issues with non-None address and suffixes `" / fault"` on matching entries | `change_service.py:1110-1115,1137-1138` |
| C17 | Issue codes: document-envelope family `MF-JSON-PARSE, MF-BAD-STRUCTURE, MF-SIZE-CAP, MF-PATH-UNRESOLVED, CHG-V1-FORMAT, CHG-FORMAT, CHG-KIND-UNKNOWN, CHG-VALUE-MODE-UNKNOWN, CHG-ENCODING-UNKNOWN`; entry-scoped family `CHG-ADDRESS-SYNTAX, CHG-BYTES-SYNTAX, CHG-VALUE-EMPTY, CHG-ENCODE-FAIL, MF-ENTRY-LIMIT, CHG-COLLISION` | `io.py:158-203`, `validate.py:42` |
| C18 | Aggregate consumers: status line (`change_service.py:1004-1012`), report totals + per-checklist line + per-entry table (`s19_app/tui/services/report_service.py:590-596,778-793`), tests (`tests/test_report_service.py:97-99,152-157`, `tests/test_variant_execution.py:439`) | cited inline |
| C19 | Tests pinning the CURRENT collective-taint / bare-token behavior (supersession census input): `tests/test_checks_engine.py:203-246` (error-doc + wrong-kind → all-uncheckable), `tests/test_tui_patch_editor_v2.py:401-408` (kind=change run pinned as `"Checks: 0 passed, 0 failed, 2 uncheckable"`), row-text pins `tests/test_change_service.py:492-544`, TC-024 display test `tests/test_tui_patch_editor_v2.py:749-816`, help-label ATs `:1770-1874` | cited inline |

### 1.2 Decided semantics (the mapping rule — investigated per operator decision 1)

Document errors map to entries as follows (all grounded in C12–C17):

1. **Entry-scoped ERRORs on *constructed* entries.** Only `CHG-COLLISION` can name a constructed
   entry (C15). Rule: an ERROR issue whose code is in the entry-scoped family AND whose
   `address` matches a constructed `entry.address` taints exactly that entry →
   `uncheckable` with reason `entry-fault`. This reuses the shipped `fault_addresses` idiom (C16).
2. **Entry-scoped ERRORs on *skipped* declarations** (`CHG-BYTES-SYNTAX` etc. — the declaration never
   became an entry, C12). They taint nothing: the run proceeds over the constructed entries; the fault
   already surfaces in the declaration-faults panel (`refresh_issues`, `screens_directionb.py:2191-2224`).
   Same for the address-less count-ceiling `MF-ENTRY-LIMIT` (C14) — the kept prefix is healthy.
3. **Document-envelope ERRORs** (the C17 envelope family) **block the whole run** with a run-level
   reason naming the code(s). Via the reader this case always has `entries == []` (C13), so per-entry
   taint is vacuous there; the blocking rule exists for documents *composed after load* through the
   entry-editor UI on top of a faulted envelope. Classification is an **allowlist of entry-scoped codes;
   unknown/future codes default to blocking** (fail-safe).
4. **Wrong kind** (`document.kind != "check"`, reachable on this path with kind `"change"` from the
   reader, or any raw token on a programmatically composed document) blocks the whole run with the loud
   decision-2 reason. Evaluated FIRST (before rule 3) — it is the more specific, actionable message.
5. **Containment** (`PARTIAL`/`OUTSIDE`/`UNVALIDATED_NO_IMAGE`, `check.py:186-187`) stays per-entry
   `uncheckable`, now with reasons `partial`/`outside`/`no-image`.

### 1.3 Reason taxonomy (decided — `CHECK_UNCHECKABLE_REASON_DOMAIN`, canonical order)

All display strings are C-9-compliant (addresses, codes, counts — never byte/value content).
`{...}` placeholders are formatted values; anything file-derived is flagged.

| reason_code | Scope | Display string (reason text) | File-derived text? |
|-------------|-------|------------------------------|--------------------|
| `doc-kind` | run-level block | `this is a change-set (kind {kind!r}), not a check-set — Run checks needs kind 'check'` | **YES** — `kind` is verbatim document text on the composed/pasted path → C-17 |
| `doc-fault` | run-level block | `document carries {n} error-severity declaration fault(s) [{codes}] — fix the document before running checks` | No (codes are constants, n is a count) |
| `entry-fault` | per-entry | `entry at 0x{addr:X} carries [{code}] — see declaration faults` | No |
| `partial` | per-entry | `range partially outside the loaded image [partial]` | No |
| `outside` | per-entry | `range outside the loaded image [outside]` | No |
| `no-image` | per-entry | `no image loaded` | No |

`reason_code` is the stable token (tests/serialization assert on it); the display string is the
human sentence. Both ride `CheckRunEntry` (`None` on `pass`/`fail`); run-level blocks additionally
ride `CheckRunResult` (`run_blocked_reason_code` / `run_blocked_reason`, `None` on a runnable
document). On a blocked run every enumerated entry is `uncheckable` carrying the run-level
reason_code/reason (aggregates keep their three-key shape and still count the entries — C18 consumers
unchanged in shape).

## 2. User stories & Definition of Ready

**US-050 (per-entry taint)** — *As an operator running checks over a check-set whose document collected
errors, I want healthy entries checked normally and only the entries that themselves carry an error
marked uncheckable, so one bad declaration doesn't hide the real pass/fail picture.* READY. Behavior
change to a locked requirement (R-CHK-001) → §6.5 record. Observable through the check-result rows and
the aggregates in the status line.

**US-051 (reasons everywhere)** — *As an operator reading check results, I want every `uncheckable`
outcome — per-entry or whole-run — to state WHY (containment, entry fault, document fault, wrong kind),
so I never have to guess or re-ask.* READY. Observable through the shipped row text in
`#patch_checks_results` and the `#patch_checks_status` line.

**US-052 (info affordance)** — *As an operator, I want a short always-visible explanation of check
semantics (check vs change kind, per-entry reasons, containment) on the checks surface, so the topic
stops recurring.* READY. Observable through the rendered `#patch_checks_help` text.

### US-052 surface options (real options — pick at gate; recommendation stated)

| Option | Surface | Cost | Notes |
|--------|---------|------|-------|
| **A (recommended)** | Extend the existing `#patch_checks_help` Label (`screens_directionb.py:1869-1874`) to 2–3 short lines | Lowest — existing widget, existing AT harness (`test_at032a/b`), one §6.5 text amendment | Panes scroll (`overflow-y: auto`, R-PATCH-2X2-LAYOUT-001) so added lines cannot clip; AT-032a asserts a token *substring* (`test_tui_patch_editor_v2.py:1772-1774`) which the extension preserves |
| B | New legend `Label`/`Static` inside `#patch_pane_checks` above `#patch_checks_results` (`:1898-1899`) | Low-mid — new id + CSS; help sits where results render but duplicates surface | Viable fallback if the changefile pane's text budget reads cramped at 80×24 |
| C | `?` button + small modal screen | Highest — new modal machinery for static text | Over-engineered for a 3-line explanation; rejected under simplicity-first |

Recommendation: **A** — cheapest surface consistent with the operator's ask; Phase-3 re-checks the
80×24 fit (C-13 note below).

## 3. Acceptance (black-box) blocks — EARS + counterfactual direction

Surface: `#patch_checks_results` row text/classes, `#patch_checks_status` line, `#patch_checks_help`
render, and `run_check_document` / `CheckRunResult` for engine-level ATs. Harness reuse: the
`check_runner` seam and Pilot idioms of `tests/test_tui_patch_editor_v2.py:749-816`.

### US-050 — per-entry taint

| AT | EARS statement (WHEN/WHILE … the system shall …) | Counterfactual direction |
|----|---------------------------------------------------|--------------------------|
| **AT-050a** (gate) | WHEN checks run on a `kind="check"` document whose issues include an entry-scoped ERROR naming constructed entry E's address (a `CHG-COLLISION` fixture) alongside healthy entries H1 (matching image bytes) and H2 (mismatching), the system shall report H1 `pass`, H2 `fail`, and only E `uncheckable` with reason_code `entry-fault`; aggregates `{passed:1, failed:1, uncheckable:1}` | Pre-change RED: all three are `uncheckable`, aggregates `{0,0,3}` (`check.py:166,176-177`) |
| **AT-050b** (skipped-declaration) | WHEN a check file contains one syntactically faulty entry declaration (dropped by the reader with `CHG-BYTES-SYNTAX`) plus two healthy entries, the system shall check both constructed entries normally (pass/fail per image) and surface the declaration fault only in the declaration-faults area | Pre-change RED: `has_errors` taints both constructed entries |
| **AT-050c** (negative — clean doc unchanged) | WHEN checks run on a clean `kind="check"` document over a loaded image, the system shall produce exactly the pre-change results (pass/fail/containment-uncheckable per entry, same aggregates) | Passes pre-change too — guards against over-aggressive gating |
| **AT-050d** (apply unchanged) | WHEN a change document with any ERROR is applied, the system shall still block every entry (`disposition="blocked"`) — the apply gate is NOT relaxed | Passes pre-change; RED if the taint relaxation leaks into `apply.py` |

### US-051 — reasons everywhere

| AT | EARS statement | Counterfactual direction |
|----|----------------|--------------------------|
| **AT-051a** (containment reasons) | WHEN checks run with entries in `PARTIAL`, `OUTSIDE`, and no-image states, each uncheckable row rendered in `#patch_checks_results` shall contain its reason text (`partially outside the loaded image` / `outside the loaded image` / `no image loaded`) after the `uncheckable` token | Pre-change RED: rows end at the bare token (`change_service.py:1064-1067`) |
| **AT-051b** (wrong-kind loud block) | WHEN Run checks is pressed with a `kind="change"` document loaded, the system shall post a status line starting `Checks:` and containing `not a check-set` + `needs kind 'check'`, mark the run result not-ok, and every enumerated row shall carry the `doc-kind` reason | Pre-change RED: silent `Checks: 0 passed, 0 failed, N uncheckable` with `ok=True` (`change_service.py:1008-1014`; pinned at `test_tui_patch_editor_v2.py:406`) |
| **AT-051c** (doc-fault block, composed path) | WHEN a document carrying an envelope-family ERROR (e.g. `CHG-ENCODING-UNKNOWN` via paste) has entries composed onto it through the entry editor and checks run, the system shall block the run with a status reason naming the fault count and code(s) | Pre-change RED: bare all-uncheckable, no reason |
| **AT-051d** (boundary — reason absent on pass/fail) | WHEN an entry results `pass` or `fail`, its row shall NOT carry any reason suffix and `CheckRunEntry.reason`/`reason_code` shall be `None` | Guards reason-spam; passes pre-change (vacuously), RED if reasons over-attach |
| **AT-051e** (C-17 hostile, file-derived) | WHEN a pasted document declares a hostile markup kind token (e.g. `kind: "x[bold][link=file:///etc]y"` — metadata-faulted, then entries composed, then Run checks), the rendered status line and any rows shall show the literal brackets with no `MarkupError`, no style leak, no link token consumed | RED if the status label renders file text through Textual markup (`Label.update` markup-on default, `screens_directionb.py:2286`). *Precedence note: kind is evaluated first (§1.2 rule 4) so the hostile kind reaches the `doc-kind` template verbatim.* |
| **AT-051f** (serialization additive) | WHEN `CheckRunResult.to_dict()` is called, each entry dict shall carry `reason` and `reason_code` keys (`None` on pass/fail) and the result dict shall carry the run-block fields; all pre-existing keys and the three aggregate keys unchanged | Pre-change RED: keys absent (`model.py:742-758`) |

### US-052 — info affordance

| AT | EARS statement | Counterfactual direction |
|----|----------------|--------------------------|
| **AT-052a** | WHEN the Patch Editor is shown, the rendered `#patch_checks_help` text shall contain (i) the existing what/which-artifact token span, (ii) a check-vs-change kind token span, and (iii) an uncheckable-rows-carry-reasons token span | Pre-change RED for (ii)/(iii); (i) guards the AT-032a token (`test_tui_patch_editor_v2.py:1772-1774`) |
| **AT-052b** (regression) | WHEN the help text is extended, the Checks button id (`patch_checks_run_button`), its `run_checks` action routing, and the button's short label shall be unchanged | Rides the AT-032b harness (`:1808-1874`) |

## 4. Requirements (HLR / LLR)

### HLR-050 — per-entry check gate (traces US-050; amends R-CHK-001 via §6.5)
*When executing a `kind="check"` document, the system shall gate checkability per entry — an entry is
uncheckable if and only if (a) the run is blocked at document level (HLR-051 statements 1–2), (b) an
entry-scoped ERROR finding names the entry's address, or (c) the entry's containment is not fully
INSIDE — and shall compare every other entry against the image normally. The apply engine's
whole-document gate shall be unchanged.*

- **LLR-050.1** — define the entry-scoped code allowlist beside the reader codes it classifies
  (`CHG-ADDRESS-SYNTAX`, `CHG-BYTES-SYNTAX`, `CHG-VALUE-EMPTY`, `CHG-ENCODE-FAIL`, `MF-ENTRY-LIMIT`,
  `CHG-COLLISION`); any ERROR whose code is outside the allowlist is document-blocking (fail-safe
  default for future codes).
- **LLR-050.2** — in `run_check_document`, replace the single `not_runnable` boolean (`check.py:166`)
  with: (i) run-block evaluation (kind first, then blocking ERRORs); (ii) a per-entry taint set built
  from entry-scoped ERROR addresses matching constructed entries (the `fault_addresses` idiom,
  `change_service.py:1110-1115`); (iii) the existing INSIDE compare path unchanged for untainted entries.
- **LLR-050.3** — purity preserved: no Textual import, no mem_map mutation, injectable clock —
  the existing LLR-004.2/004.4 contract carries over verbatim.
- **LLR-050.4** — engine-frozen diff stays 0 (`git diff main -- <frozen set>` empty).

### HLR-051 — reason carrier + display (traces US-051)
*The system shall attach a machine-stable reason code and a human-readable reason to every uncheckable
outcome: (1) a document whose `kind` is not `"check"` blocks the whole run with the `doc-kind` reason;
(2) a document carrying a blocking ERROR blocks the whole run with the `doc-fault` reason naming count
and codes; (3) tainted entries carry `entry-fault`; (4) containment uncheckables carry
`partial`/`outside`/`no-image`; and the Patch Editor shall render per-entry reasons in the result rows
and run-level reasons in the status line, markup-safe end to end.*

- **LLR-051.1** — `model.py`: add `CHECK_UNCHECKABLE_REASON_DOMAIN` (§1.3 tokens, canonical order);
  `CheckRunEntry` gains `reason_code: Optional[str]` + `reason: Optional[str]` (default `None`);
  `CheckRunResult` gains `run_blocked_reason_code` / `run_blocked_reason` (default `None`).
- **LLR-051.2** — `to_dict` emits the new fields additively; every pre-existing key, key order
  intent, and the three `CHECK_AGGREGATE_KEYS` are unchanged (C18 consumers keep working unmodified).
- **LLR-051.3** — reason strings follow C-9 (addresses/codes/counts only, never byte or value
  content) and use exactly the §1.3 templates.
- **LLR-051.4** — `ChangeService.run_checks` message: unchanged
  `Checks: P passed, F failed, U uncheckable` on a runnable document; on a blocked run
  `Checks: not run — {run_blocked_reason}` (keeps the `Checks:` prefix contract pinned at
  `test_tui_patch_editor_v2.py:1858-1859`) and `ok=False` (a blocked run must not report success —
  supersedes the `ok = failed == 0` corner at `change_service.py:1014`).
- **LLR-051.5** — `ChangeService.check_rows` appends ` — {reason}` to the row text on uncheckable
  rows only; pass/fail row text is byte-identical to today (`change_service.py:1064-1067`); severity
  mapping `_CHECK_RESULT_SEVERITY` unchanged.
- **LLR-051.6 (C-17)** — every surface rendering reason text is markup-safe: result rows keep
  `Static(..., markup=False)` (`screens_directionb.py:2290`); the status line stops flowing through a
  markup-enabled `Label.update` (`:2286`) — render via `safe_text` (`screens_directionb.py:374`) or a
  markup-disabled widget. Hostile-input AT-051e is the gate.
- **LLR-051.7** — the run-level reason also reaches `ChangeActionResult`/`_report_change_result`
  (`app.py:1667-1674`) so the notification names the reason, not only the status label.

### HLR-052 — checks info affordance (traces US-052; amends R-PATCH-CHECKS-CLARITY-001 via §6.5)
*The system shall extend the checks help element to state, in at most three short lines: what Run
checks does and on which artifact (existing sentence, token span preserved); that it requires a
`kind="check"` document (a change-set must be Applied, not checked); and that uncheckable rows carry
their reason.*

- **LLR-052.1** — Option A (§2): extend the `#patch_checks_help` Label text (`screens_directionb.py:1869-1874`);
  id, classes, and position unchanged; static literal text only (no file-derived content → no C-17 surface).
- **LLR-052.2** — the AT-032a token span (`runs the loaded change document's checks against the loaded
  image`) survives verbatim inside the extended text.
- **LLR-052.3** — 80×24 fit re-verified in Phase 3 (C-13: the label lives in the scrollable
  `#patch_pane_changefile`; extension adds height, never width).

## 5. Dual traceability (both chains required)

| US | HLR | LLR | Black-box AT | White-box TC |
|----|-----|-----|--------------|--------------|
| US-050 | HLR-050 | LLR-050.1–.4 | AT-050a–d | TC-050.1–.3 |
| US-051 | HLR-051 | LLR-051.1–.7 | AT-051a–f | TC-051.1–.4 |
| US-052 | HLR-052 | LLR-052.1–.3 | AT-052a–b | TC-052.1 |

## 6. Validation methods + white-box TCs

All three stories: **Test** (automated AT + TC), fully headless (engine ATs direct; display ATs via
Pilot on the shipped surface). US-052 adds **Inspection** (rendered text) and snapshot **Analysis**
(the help-label extension may shift the patch-screen SVG cells → xfail-until-canonical-CI-regen per
the standing snapshot policy; local regen FORBIDDEN).

| TC | LLR | Mechanism (HOW) |
|----|-----|-----------------|
| TC-050.1 | LLR-050.1 | allowlist constant exists; every §1.1-C17 entry-scoped code present; an unknown code classifies as blocking |
| TC-050.2 | LLR-050.2 | taint-set builder: ERROR+entry-scoped+address-match → tainted; skipped-declaration address (no constructed entry) and address-`None` entries → no taint |
| TC-050.3 | LLR-050.3/.4 | purity probe (no Textual import on the check path — reuse the F-Q-07 subprocess idiom of `tests/test_checks_engine.py`); frozen diff 0 |
| TC-051.1 | LLR-051.1/.2 | model fields default `None`; `to_dict` additive keys; determinism (two calls compare equal) |
| TC-051.2 | LLR-051.3 | each §1.3 template renders with addresses/codes/counts only — no `expected_bytes`/`value` content in any reason string (C-9 grep-style assert over a full-domain fixture) |
| TC-051.3 | LLR-051.4/.7 | blocked run → `ok=False` + `Checks: not run — …` message; runnable run message byte-identical to today |
| TC-051.4 | LLR-051.5/.6 | `check_rows` suffixes reasons on uncheckable only; status surface renders a bracket payload literally (unit-level companion to AT-051e) |
| TC-052.1 | LLR-052.1/.2 | rendered help text contains all three token spans; widget id/classes unchanged |

### 6.1 Supersession census (tests pinning superseded behavior — migrate WITH the code)

| Test (file:line) | Pins today | Disposition |
|---|---|---|
| `tests/test_checks_engine.py:203-229` (error-doc not runnable) | all-uncheckable collective taint | SUPERSEDE → per-entry taint semantics (AT-050a/b become the new gates) |
| `tests/test_checks_engine.py:232-246` (wrong kind) | bare all-uncheckable | SUPERSEDE → blocked-run reason fields asserted |
| `tests/test_tui_patch_editor_v2.py:401-408` | literal `"Checks: 0 passed, 0 failed, 2 uncheckable"` on a kind=change run | SUPERSEDE → `Checks: not run — …` (AT-051b) |
| `tests/test_tui_patch_editor_v2.py:749-816` (check display) | uncheckable row text ends at token; status line | UPDATE: status unchanged (kind=check fixture); uncheckable rows gain reason suffix |
| `tests/test_change_service.py:485-505, 508-544` | row text + css classes | UPDATE: reason suffix on uncheckable rows; classes unchanged |
| `tests/test_checks_engine.py:157-198, 280-300, 340-355` | healthy/no-image/serialization/mixed | SURVIVE (semantics unchanged); additive asserts optional |
| `tests/test_report_service.py:97-157`, `tests/test_variant_execution.py:439` | aggregate keys/values | SURVIVE (shape unchanged; fixtures are kind=check) |
| `tests/test_tui_patch_editor_v2.py:1770-1874` (AT-032a/b) | help token substring + wiring | SURVIVE by construction (LLR-052.2); AT-032b's `startswith("Checks:")` survives via LLR-051.4 prefix |

### 6.5 Requirement amendments (Before/After — locked requirements edited)

- **R-CHK-001** (REQUIREMENTS.md:1631-1647) — *Before:* "uncheckable covering any entry whose target
  range is not fully readable" under a whole-document not-runnable gate mirroring the apply gate
  (ERROR or wrong kind → every entry uncheckable, reason-less). *After:* per-entry gate (§1.2): only
  document-blocking faults and wrong kind block the run (with run-level reasons); entry-attributable
  ERRORs taint only their entry; containment uncheckables carry reasons; `CheckRunEntry`/`CheckRunResult`
  carry `reason_code`/`reason`/run-block fields. Rationale: operator decision B-02-1/2/3 — checks are
  read-only, so the conservative apply-mirror gate hides information without protecting anything.
  Apply gate (HLR-001 statement 4 / LLR-002.1) explicitly NOT amended.
- **R-PATCH-CHECKS-CLARITY-001** (REQUIREMENTS.md:3132-3135) — *Before:* the label shall read exactly
  `"Checks: runs the loaded change document's checks against the loaded image."`. *After:* the label
  shall contain that sentence as its first line plus the kind-requirement and reasons lines (LLR-052.1/.2).
  Rationale: operator decision B-02-4 (info prompts so the topic stops recurring).

## 7. Assumptions / risks

- **R-B02-1 (medium):** `CheckRunResult` consumers beyond those censused (C18) could exist in the
  batch-30..32 code absent from this worktree — Phase-2 MUST re-run the `aggregates`/`check_rows`/
  `to_dict` consumer grep on merged main before lock. Same for US/HLR/AT numbering (BLUF note).
- **R-B02-2 (low):** address-match taint keys on `entry.address` equality (the shipped C16 idiom).
  Two entries at the same address are a `CHG-COLLISION` pair anyway; no silent mismatch mode identified.
- **R-B02-3 (low):** `entry-fault` currently has exactly one producer (`CHG-COLLISION`). The allowlist
  + address-match rule generalizes to future entry-scoped ERROR codes without further engine change.
- **R-B02-4 (low, intentional):** on a blocked run the enumerated entries still count under
  `uncheckable` (aggregate values, not shape) so `report_service` tables keep rendering; a report
  reader sees counts consistent with the per-entry table.
- **R-B02-5 (snapshot):** the extended help label may shift patch-screen SVG cells →
  xfail-until-canonical-CI-regen; local regen forbidden (standing policy).
- **C-17 exposure is real, not theoretical:** the `doc-kind` reason embeds verbatim document text on
  the composed/pasted path (§1.3); LLR-051.6 + AT-051e are the mandatory Phase-1 controls.

## 8. Open questions (decision-requiring only)

1. **Collision taint for checks:** a `CHG-COLLISION` pair declares overlapping *expected* ranges — for a
   read-only compare both could legitimately run. Draft taints the address-matched entry (`entry-fault`,
   conservative, consistent with the entries-table `" / fault"` marker at `change_service.py:1137-1138`).
   Flip to "collision never taints checks"? (Removes the only current `entry-fault` producer; AT-050a
   would need a constructed-document fixture instead.)
2. **Report surface:** should the project report's per-entry Checklists table
   (`report_service.py:782-793`) gain a Reason column this batch (report-shape change, golden updates),
   or defer to a report-focused batch with reasons already carried in `to_dict`? Draft defers.

## 9. Evidence checklist (Phase 1)

- [✓] Constraints stated — §1 scope, frozen set, aggregate contract, C-17.
- [✓] ≥2 alternatives where real — US-052 surface options A/B/C (§2); taxonomy/blocking classification decided by operator + code structure, not open.
- [✓] Every US has ≥1 black-box AT on the shipped surface — §3.
- [✓] Dual traceability complete — §5.
- [✓] Counterfactual direction stated per AT (C-10), incl. negative (AT-050c/051d) + hostile (AT-051e) + regression (AT-050d/052b).
- [✓] Every current-behavior claim cited file:line — §1.1 (disk-verified this worktree, 2026-07-09).
- [✓] C-17 — file-derived reason text identified (§1.3), markup-safety LLR (051.6) + hostile AT (051e) at Phase 1 as mandated.
- [✓] Supersession census — §6.1 (row-format + gate-behavior pins mapped).
- [✓] §6.5 before/after for both locked-requirement edits.
- [✓] What would change the recommendation — Q1/Q2 (§8) + R-B02-1 renumbering/consumer re-census on merged main.
- [✓] 0 engine-frozen — LLR-050.4; no frozen file touched.
