# Review — s19_app — 2026-05-05-batch-01

**Phase:** 2 — Cross-agent review
**Iteration:** 1
**Date:** 2026-05-05
**Source artifact under review:** [`.dev-flow/01-requirements.md`](01-requirements.md)
**Reviewers:** `architect`, `qa-reviewer`, `security-reviewer` (parallel)

---

## Aggregate summary

| Reviewer | Blockers | Majors | Minors | Verdict |
|---|---|---|---|---|
| architect | 0 | 7 | 5 | pass-with-fixes |
| qa-reviewer | 0 | 6 | 4 | pass-with-fixes |
| security-reviewer | **2** | 3 | 2 | **iterate-required** |
| **Total** | **2** | **16** | **11** | **iterate-required (blockers force rollback to Phase 1)** |

### Why this review forces iteration back to Phase 1

Per `/dev-flow-en` Phase 2 spec: *"if blockers exist, force `iterate` back to phase 1."* Two security blockers (S-001, S-002) describe coverage gaps in HLR-005 / LLR-005.x that the requirements doc must close before implementation can begin. Both are write-side / symlink-traversal concerns that the doc currently misroutes between LLR-005.1 (read path) and LLR-005.2 (write path).

### `shall` / `should` discipline check

- ✅ **Zero `should` found inside any HLR/LLR `Statement:` bullet** (verified by grep both before review and confirmed by architect agent).
- ⚠️ **One stray `shall not`** outside formal Statements (§2.4 Constraints, third bullet). Architect A-001, classified `major` — not a blocker on its own, but should be reworded into LLR-002.1 as a normative clause or out of normative voice.

---

## Architect findings

### Summary
- blockers: 0
- majors:   7
- minors:   5
- one-line verdict: pass-with-fixes

### Findings

#### A-001 — `shall not` appears in informative §2.4 Constraints [major]
- **Target:** §2.4 Constraints, third bullet
- **Observation:** *"Severity colour names are public contract (`Red`, `Orange`, `Green`, `White`, `Grey`) and **shall not** be renamed."* Informative narrative text using normative `shall not`.
- **Why it matters:** The doc's own preamble forbids `shall` outside HLR/LLR Statements because it creates dual-source-of-truth requirements.
- **Recommended fix:** Move colour-name stability into a new acceptance criterion under LLR-002.1, or reword to "Severity colour names are part of the public contract per LLR-002.1 and are not renamed in scope of this batch."

#### A-002 — "the audit shall record a finding" is too soft to verify [major]
- **Target:** HLR-001..009 Statements; LLR-001.1, LLR-001.2, LLR-002.2, LLR-003.1, LLR-004.1, LLR-005.1, LLR-006.1, LLR-007.1, LLR-007.3, LLR-008.1, LLR-008.2, LLR-009.2
- **Observation:** "Recording a finding" / "producing a matrix" / "enumerating" are not defined in §1.3 or §5. Two reviewers could each claim done with incompatible artifacts.
- **Why it matters:** Verifiability collapses without a fixed finding schema.
- **Recommended fix:** Define `Finding` once in §1.3 — *"row in the audit packet with fields {ID, Target file/symbol, Observation, Severity, Recommended fix}"* — and have each LLR reference that schema.

#### A-003 — HLR-007 Statement compounds three obligations behind one `shall` [major]
- **Target:** HLR-007 Statement (LLR-007.2 inherits)
- **Observation:** Fuses (1) issue is created, (2) issue lands in `ValidationReport.issues`, (3) panel actually renders it. `build_validation_report` returns a payload — it does not render.
- **Why it matters:** A test that asserts only (1)+(2) passes HLR-007 by the letter while the rationale promises (3).
- **Recommended fix:** Split into HLR-007a (engine emits + populates `issues`) and HLR-007b (Issues panel renders the entry; verify via Textual snapshot or a query against the rendered widget).

#### A-004 — LLR-002.1 vs LLR-008.2 risk inconsistent verdicts on the same code [major]
- **Target:** LLR-002.1 and LLR-008.2
- **Observation:** Both walk rule→code→severity but anchor against different policy sections (A2L/MAC colour map vs. Issues Tile tier policy). For an issue code that carries both row-colour and Issues-panel semantics, the two checks could record contradictory verdicts.
- **Why it matters:** Same drift, two conclusions, ambiguous remediation.
- **Recommended fix:** Add a cross-LLR criterion: *"If LLR-002.1 records divergence on code C, LLR-008.2 must also; mismatch is itself a finding."*

#### A-005 — `s19tool` CLI entry point not covered by any HLR [major]
- **Target:** §2.6, HLR-001..009, §1.2 Scope
- **Observation:** `pyproject.toml` ships `s19tool` (CLI) and `s19tui` (TUI). §1.2 lists TUI files in scope; `s19_app/cli.py` is absent; no US/HLR mentions CLI subcommands (`info`, `verify`, `dump`, `patch-hex`).
- **Why it matters:** The CLI shares parsers and validation but has its own argparse / exit-code / Rich-formatting surface that the audit does not touch.
- **Recommended fix:** Either add an explicit *"CLI audit deferred to follow-up batch"* line in §1.2, or add US-007 + at least one HLR/LLR pair covering CLI subcommand contracts and exit-code semantics.

#### A-006 — LLR-006.1 mixes accessor contract with severity-map invariant [major]
- **Target:** LLR-006.1, third acceptance bullet
- **Observation:** Statement is about A2L accessors, but the third bullet asserts *"Severity colour map keys remain a strict superset of `ValidationSeverity` members"* — a property of `tui/color_policy.py`. Overlaps LLR-002.1 / TC-053 with no cross-reference.
- **Why it matters:** Dual source of truth on the same invariant.
- **Recommended fix:** Move that bullet into LLR-002.1 (or a new LLR-002.3) and reference by ID from LLR-006.1.

#### A-007 — LLR-007.3 hand-waves duplicate-address alias and overlap-ambiguity severity [major]
- **Target:** LLR-007.3 Statement and 2nd acceptance bullet
- **Observation:** REQUIREMENTS.md distinguishes `Orange` (alias when alias policy is warning) from a hard `Red` (duplicate A2L symbol configured as error). LLR-007.3 collapses these and never specifies how the audit picks the active alias policy.
- **Why it matters:** Severity expectation depends on runtime configuration; without specifying it the LLR cannot deterministically pass/fail.
- **Recommended fix:** Add *"Active alias policy at audit time is recorded; only that policy is verified; codes that support both policies are enumerated with both expected severities."*

#### A-008 — `SEVERITY_CLASS_MAP` only checked one-way [minor]
- **Target:** LLR-002.1, TC-053
- **Observation:** No LLR mandates the bidirectional invariant *"every `ValidationSeverity` ↔ a `SEVERITY_CLASS_MAP` entry ↔ a colour in {Red, Orange, Green, White, Grey}"*.
- **Recommended fix:** Add a one-line acceptance criterion to LLR-002.1: *"Bidirectional map: every `ValidationSeverity` has an entry AND every map key is a defined `ValidationSeverity`."*

#### A-009 — `R-TUI-018/019/020` not visibly traced in §5.2 [minor]
- **Target:** §5.2 coverage table, LLR-004.1
- **Observation:** LLR-004.1 acceptance lists `R-TUI` family generically, but §5.2 spot-checks specific IDs and never names the newer `R-TUI-018/019/020` rows (all currently `Automated`).
- **Recommended fix:** Append a TC-033 row *"LLR-004.1 — confirm `R-TUI-018/019/020` still pass on `pytest -q`"*.

#### A-010 — LLR-001.1 missing R-READ-001 [minor]
- **Target:** LLR-001.1 Statement
- **Observation:** Lists `R-PARSE-001..005`, `R-VAL-001/002`, `R-HEX-001..003` but omits `R-READ-001` (line-by-line read; ignore empty lines).
- **Recommended fix:** Add `R-READ-001` to the matrix scope.

#### A-011 — LLR-001.2 references "MAC test files" without naming them [minor]
- **Target:** LLR-001.2 Statement, last clause
- **Recommended fix:** Cite the actual `tests/test_tui_mac.py` (verify by glob first).

#### A-012 — LLR-005.1 Windows-device-name list is incomplete [minor]
- **Target:** LLR-005.1 acceptance bullet 1
- **Observation:** Tests `CON`/`PRN`/`NUL` but Windows reserves the full set: `CON, PRN, AUX, NUL, COM1..9, LPT1..9`, plus extension variants (`CON.txt`).
- **Recommended fix:** Replace with *"(`CON, PRN, AUX, NUL, COM1..9, LPT1..9`, including with-extension forms)"*.

---

## QA-reviewer findings

### Summary
- blockers: 0
- majors:   6
- minors:   4
- one-line verdict: pass-with-fixes

### Findings

#### Q-001 — Inspection rows lack a defined evidence artefact [major]
- **Target:** §5.2 rows TC-001, TC-010, TC-020, TC-030, TC-040, TC-050, TC-060, TC-070; §5.3 acceptance bullets generally.
- **Observation:** Inspection rows cite specific files/symbols (so scope is bounded) but none tells the auditor what evidence record to emit. "Cross-read" / "walk" / "audit" do not map to a checkable artefact. The doc gates pass/fail on "zero blocker findings" but never says where the auditor records that a row was inspected with no finding (the positive case).
- **Why it matters:** Two auditors running this batch could produce non-equivalent deliverables and both claim "pass". The QA gate cannot adjudicate.
- **Recommended fix:** In §5.1 (Inspection paragraph) state the deliverable shape: a markdown matrix with columns `R-* | implementing symbol | asserting test | verdict | finding ID (if any)`. (Couples with A-002.)

#### Q-002 — LLR-007.2 lacks a fixture-creation owner per incompatibility class [major]
- **Target:** LLR-007.2 statement; §5.2 row TC-062.
- **Observation:** TC-062 says "Verify error + report co-emission per class on the `large_project` fixture (or minimal hand-crafted fixture)." `large_project` covers some classes (out-of-range, name mismatch) but does not deterministically cover S19/HEX overlap, parsed-record corruption, duplicate-address alias, symbol-only-in-A2L, or symbol-only-in-MAC at the right cardinality. The doc does not assign who builds the missing per-class fixture nor where it lives.
- **Why it matters:** LLR-007.1 enumerates ~8 classes; without a fixture-per-class plan the integration test silently skips classes the default fixture does not trigger, and TC-062 passes while the contract is unverified.
- **Recommended fix:** Split TC-062 into TC-062.a … TC-062.h (one per class), and add a §5.2 line per class naming where the trigger fixture lives (e.g. `tests/fixtures/overlap_s19_hex/`, `tests/fixtures/duplicate_alias_mac/`). Mark the missing ones explicitly as "fixture to be added in implementation phase".

#### Q-003 — Severity round-trip method mix on LLR-002.1 splits unclearly [major]
- **Target:** LLR-002.1; §5.2 rows TC-011 (inspection), TC-012 (analysis), TC-013 (test integration).
- **Observation:** TC-012 is `analysis` but LLR-002.1's acceptance ("Every issue code … is enumerated with its severity and resulting CSS class") is a deterministic table — testable as a parametrised unit test built from `validation/model.py` and `color_policy.SEVERITY_CLASS_MAP`. Calling it `analysis` weakens the rubric. The LLR-002.1 method (`test (integration)`) is also inconsistent with TC-011/TC-012 row methods.
- **Why it matters:** Round-trip from `ValidationIssue.code → ValidationSeverity → CSS class` is exactly the contract that R-3 (in §6.3) flags as not test-covered today. Demoting it from test to analysis re-creates the same gap.
- **Recommended fix:** Convert TC-012 to `test (unit)` in `tests/test_validation_engine.py` (or a new `tests/test_color_policy_round_trip.py`); keep TC-011 inspection only as the "code → rule" reachability check. Reconcile the LLR-002.1 method with the row methods.

#### Q-004 — Demo rows lack a capture-artefact specification [major]
- **Target:** §5.2 row TC-032.
- **Observation:** TC-032 says "remain manual; capture screen evidence" but does not say what file/format/length is required, where it is filed, or what the rubric is for "demo passes". Compare to LLR-001.1 which is explicit ("Each cell cites a specific function and a specific `def test_*` name").
- **Why it matters:** Demo without a captured artefact is unauditable — at the gate, a verbal "I ran it" passes the bullet.
- **Recommended fix:** Add to §5.1 Demo paragraph: *"Each demo row produces (a) a `.png` screen capture under `.dev-flow/evidence/<TC-NNN>/` and (b) a one-paragraph transcript stating the steps run and the observed pass/fail, signed by the demo runner."*

#### Q-005 — §5.3 hidden-requirement bullet on TUI orchestration [major]
- **Target:** §5.3 bullet *"TUI orchestration boundary verified: no parsing, enrichment, or validation logic lives in `tui/app.py`; all such calls route through `tui/services/`."*
- **Observation:** This bullet is more strict than HLR-003 / LLR-003.1 (which only require enumeration, not absence). Silently elevates "no bypass exists" to a gate condition. If a single legacy bypass survives in `app.py` (~5k LOC), the gate fails even though HLR-003 would just record a finding.
- **Why it matters:** A tighter gate criterion than the HLR creates a hidden requirement not traced from any HLR/LLR.
- **Recommended fix:** Restate as *"TUI orchestration boundary audit completed: every parse/enrich/validate call site in `tui/app.py` is enumerated and classified as `routed via services/` or `bypass — finding-NNN`."* Pass = enumeration is complete.

#### Q-006 — `major` deferral process is undefined [major]
- **Target:** §5.3 bullet *"Zero `blocker`-severity findings open at the gate; any `major` finding has a written deferral or fix plan."*
- **Observation:** "Written deferral or fix plan" has no template, owner, or location specified. A QA gate evaluator cannot mark this pass/fail.
- **Why it matters:** This is the kind of bullet that always passes by convention regardless of project state.
- **Recommended fix:** *"every `major` finding has an entry in `.dev-flow/02-review.md` §Deferrals with: finding ID, owner, target batch, blast radius if not fixed."*

#### Q-007 — TC ID gaps and missing per-`R-*` mapping under LLR-004.1 [minor]
- **Target:** §5.2 coverage table.
- **Observation:** No duplicate TC IDs; sparse numbering is fine. But the per-`R-*` mapping under LLR-004.1 collapses many rows into TC-031/TC-032 and is hard to audit row-by-row.
- **Recommended fix:** Add a mini sub-table under LLR-004.1 listing each `R-*` row → its TC ID.

#### Q-008 — LLR-009.1 false-positive risk acknowledged but not gated [minor]
- **Target:** LLR-009.1; §6.3 risk R-5.
- **Observation:** R-5 says "Verify the fixture seeds before running" but does not assign a TC. QA confirmed via inspection of `tests/conftest.py` that `make_large_s19/a2l/mac` are seeded (`seed=0` in `large_*` fixtures), so the fixture IS deterministic — R-5 can be promoted from open risk to verified pre-condition.
- **Recommended fix:** Add to LLR-009.1 acceptance criteria: *"Pre-condition: `tests/conftest.py::make_large_s19/a2l/mac` are confirmed seeded (`seed=0` in `large_*` fixtures); verified by code inspection of `tests/conftest.py` lines 106 / 191 / 270."*

#### Q-009 — TC-041 mislabelled as `test (integration)` [minor]
- **Target:** §5.2 row TC-041.
- **Observation:** `sanitize_project_name` and `resolve_input_path` are pure-function probes against `tmp_path` — `tests/test_tui_workspace.py` is unit-level.
- **Recommended fix:** Re-label TC-041 (and TC-042) as `test (unit)` to match `tests/test_tui_workspace.py` conventions.

#### Q-010 — LLR-008.1/8.2 forward+reverse tables overlap LLR-002.1 [minor]
- **Target:** LLR-002.1, LLR-008.1, LLR-008.2.
- **Observation:** LLR-002.1 (round-trip code → severity → CSS) is a strict subset of LLR-008.2 (rule → code → severity). Without scope deconfliction, the auditor produces two near-identical matrices.
- **Recommended fix:** Add a one-line note to LLR-002.1: *"The colour-class column extends the rule→code→severity matrix from LLR-008.2; do not duplicate the rule mapping here."*

---

## Security-reviewer findings

### Summary
- blockers: **2**
- majors:   3
- minors:   2
- one-line verdict: **iterate-required**

### Findings

#### S-001 — `copy_into_workarea` destination-containment NOT covered by any LLR [BLOCKER]
- **Target:** HLR-005 Statement; LLR-005.1 acceptance criteria; LLR-005.2.
- **Observation:** LLR-005.1 says the audit "shall record a finding for any path that **escapes `.s19tool/workarea/`**…" but `resolve_input_path` is a *read* path, not a workarea-write path — it intentionally resolves arbitrary user-supplied locations. The acceptance criterion conflates these two surfaces. The real workarea-write path that needs the "escape `.s19tool/`" check is `copy_into_workarea` (s19_app/tui/workspace.py lines 74–89), which does **no** containment check on `destination`: callers can pass any `Path` and the function will `mkdir(parents=True)` and `shutil.copy2` into it. LLR-005.2 covers `copy_into_workarea` but only for "collision-free destination names" — not for "destination is contained inside `.s19tool/workarea/`."
- **Threat scenario:** A future caller (or refactor in `screens.py` / `app.py`) passes a `destination` derived from an unsanitised project name into `copy_into_workarea`, writing user-supplied content into an arbitrary directory.
- **Recommended fix:** Reword LLR-005.2 to require an audit check that `copy_into_workarea`'s `destination` is `resolve()`-contained inside `<base_dir>/.s19tool/workarea/` (using `Path.resolve()` + `is_relative_to`) on every call site, and that the function rejects destinations outside that root. Add a TC under TC-040 series for "destination-containment probe." Move the "escape `.s19tool/workarea/`" wording out of LLR-005.1 (read path) and into LLR-005.2 (write path).

#### S-002 — Symlink / NTFS junction follow-through not covered [BLOCKER]
- **Target:** HLR-005 Statement; LLR-005.1 / LLR-005.2 acceptance criteria.
- **Observation:** Neither LLR mentions reparse points, NTFS junctions (`mklink /J`), or symbolic links. `shutil.copy2(source, target)` follows symlinks on the source side by default, and `Path.iterdir()` in `validate_project_files` does not distinguish a real file from a junction-to-elsewhere. On Windows, directory junctions can be created without the SeCreateSymbolicLinkPrivilege.
- **Threat scenario:** A project directory contains a junction `prj.s19 -> C:\Users\jjgh8\AppData\Roaming\…`. `validate_project_files` accepts it as a "file"; subsequent re-save through `copy_into_workarea` reads through the junction and copies that content into the audit trail.
- **Recommended fix:** Add to LLR-005.1 and LLR-005.2: *"the audit shall verify that `validate_project_files` rejects directory entries whose `is_symlink()` is true or whose `lstat().st_file_attributes` indicates a reparse point, and that `copy_into_workarea` resolves both `source` and `destination` and refuses to operate when either escapes the configured workarea root or crosses a reparse point."* Add a corresponding TC.

#### S-003 — Unbounded copy size and unbounded workarea growth not in scope [major]
- **Target:** HLR-005 Statement (resource-use clause).
- **Observation:** HLR-005 names "unbounded resource use" but LLR-005.2 only enforces the 5 MB log cap and collision-free names. There is no LLR or TC checking that `copy_into_workarea` rejects a 50 GB file masquerading as `.s19` or that the projects directory itself has a cap.
- **Recommended fix:** Add LLR-005.3 *"the audit shall confirm `copy_into_workarea` rejects sources larger than a configurable cap (recommended default: 256 MB) and that the workarea total size is bounded or surfaced."* Add TC-044 inspection cell.

#### S-004 — `sanitize_project_name` Windows reserved names and length cap not covered [major]
- **Target:** LLR-005.1 acceptance criteria.
- **Observation:** Implementation (line 92–95) is `"".join(ch for ch in name.strip() if ch.isalnum() or ch in {"-","_"})`. `..` and path separators collapse to empty (good). But `CON`, `PRN`, `NUL`, `AUX`, `COM1..9`, `LPT1..9` survive sanitisation unchanged — they are pure alphanumerics. No length cap either.
- **Threat scenario:** Project name `CON` causes `mkdir CON` to either fail non-deterministically or alias the console device, breaking the TUI.
- **Recommended fix:** Add to LLR-005.1: *"`sanitize_project_name` shall reject (return `None`) names that, after cleaning, equal a Windows reserved device name (case-insensitive: `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`) or exceed 64 characters."* (Couples with A-012.)

#### S-005 — Issue-message scrubbing not specified [major]
- **Target:** HLR-002, HLR-007, HLR-008 (cross-cutting).
- **Observation:** No HLR/LLR addresses what `ValidationIssue.message` is allowed to contain. Symbol names from MAC files and tag names from A2L files flow into rules and end up in `ValidationReport.issues`, rendered by the Issues panel and (via the rotating logger) into `s19tui.log`. Messages with `\n`, ANSI escapes, or oversize strings disrupt log integrity and panel formatting.
- **Threat scenario:** Malformed MAC file containing a "symbol name" with embedded `\n[2026-05-05] CRITICAL: cleared by admin\n` produces a forgeable log line.
- **Recommended fix:** Add LLR-002.3: *"the audit shall confirm that issue messages emitted by `validation/rules.py` strip control characters (`\n`, `\r`, ANSI `\x1b[`) and truncate to a documented max length (recommended 500 chars)."*

#### S-006 — `setup_logging` failure-mode behaviour not audited [minor]
- **Target:** LLR-005.2.
- **Observation:** `setup_logging` swallows `Exception` on the `log_path.touch()` line but does not handle the case where `RotatingFileHandler(log_path, ...)` itself raises (read-only filesystem, ACL deny, parent path is a junction loop).
- **Recommended fix:** Add to LLR-005.2: *"audit shall confirm `setup_logging` raises a clean error or falls back to a non-file handler if `.s19tool/logs/` is non-writable; silent failure is treated as a finding."*

#### S-007 — Case-only collision treated as informative, not normative [minor]
- **Target:** LLR-005.2.
- **Observation:** "differ only in case" appears in informative acceptance criteria. On case-insensitive Windows filesystems this matters.
- **Recommended fix:** Promote to a normative LLR clause so it is asserted, not assumed.

### Out-of-scope confirmation (per this app's threat model)
- **Auth / authorization:** N/A. Tool is single-user offline desktop. Doc correctly omits auth controls — do not pad.
- **Network egress / DNS / TLS:** N/A. No network surface.
- **Secrets / credentials:** N/A. No keys, tokens, or `.env` are read or written.

---

## Cross-agent thematic clusters

The 27 findings group into seven themes. When iterating Phase 1, fixing the cluster head usually closes the rest:

1. **Workspace-IO write surface (BLOCKER)** — S-001, S-002, S-004, S-006, S-007 + A-012. Rewrite LLR-005.1 (read-path) vs. LLR-005.2 (write-path) split; introduce LLR-005.3 (resource caps).
2. **"Finding" as a defined deliverable schema** — A-002, Q-001, Q-006. Define `Finding` once in §1.3; reference everywhere.
3. **Severity / colour / Issues-tier deconfliction** — A-004, A-006, A-008, Q-010. Cross-reference LLR-002.1 ↔ LLR-006.1 ↔ LLR-008.2.
4. **HLR-007 obligation split (engine vs. panel render)** — A-003, A-007. Split into HLR-007a + HLR-007b.
5. **Per-class fixture plan for LLR-007.2** — Q-002. Split TC-062 into class-specific TCs.
6. **Validation method consistency** — Q-003, Q-009. Reconcile LLR/TC method labels; promote round-trip from `analysis` to `test (unit)`.
7. **Coverage gaps** — A-005 (CLI), A-009 (R-TUI-018/19/20), A-010 (R-READ-001), A-011 (MAC test files), S-003 (resource caps), S-005 (message scrubbing).

---

## Verdict

**iterate-required.** Two security blockers (S-001, S-002) describe coverage gaps in the workspace-IO HLR/LLR set that must be closed in `01-requirements.md` before implementation can proceed. The dev-flow Phase 2 spec mandates rollback to Phase 1 when any blocker is open.

### Recommended Phase 1 iteration 3 scope

Minimum set to clear blockers + high-leverage majors:

1. **(blocker)** Restructure LLR-005.* into clear read-path / write-path / resource-cap LLRs that explicitly cover `copy_into_workarea` destination containment and symlink/junction follow-through. → closes S-001, S-002, S-004, A-012, S-007.
2. **(high leverage)** Define `Finding` schema in §1.3 and reference from all "audit shall record a finding" Statements. → closes A-002, Q-001, Q-006 in one pass.
3. **(scope clarity)** Split HLR-007 into HLR-007a (engine emits + populates) and HLR-007b (panel renders). → closes A-003, A-007.
4. **(method consistency)** Promote severity round-trip from `analysis` to `test (unit)` and reconcile LLR-002.1 with row methods. → closes Q-003, Q-009.
5. **(scope decision)** State CLI scope explicitly in §1.2 — either deferred or covered by a new US-007 + HLR. → closes A-005.

Minor findings (A-008, A-009, A-010, A-011, Q-007, Q-008, S-006, S-007, A-001 wording) can be folded in opportunistically during the same iteration since they are one-line edits.

---

*Generated by parallel review pass: `architect` (agent `aa15f7479dde66f33`) + `qa-reviewer` (agent `abe2076f8f8a96ca8`) + `security-reviewer` (agent `a75b59c3aa51e5196`).*

---

# Phase 2 — iteration 2 review packet

**Date:** 2026-05-05
**Source artifact under review:** `.dev-flow/01-requirements.md` (now at iteration 3)
**Reviewers:** `architect`, `qa-reviewer`, `security-reviewer` (parallel re-review)
**Scope:** (a) verify closure of prior findings, (b) scan for new issues introduced by iteration 3.

## Aggregate summary — iter 2

| Reviewer | Prior findings still open | New blockers | New majors | New minors | Verdict |
|---|---|---|---|---|---|
| architect | 0 of 12 | 0 | 1 (A-N02) | 4 | pass-with-fixes |
| qa-reviewer | 0 of 10 | 0 | 3 (Q-N01, Q-N02, Q-N03) | 3 | pass-with-fixes |
| security-reviewer | 0 of 7 | 0 | 0 | 4 + 1 informational | pass-with-fixes |
| **Total** | **0 of 29** | **0** | **4** | **11 + 1 informational** | **pass-with-fixes** |

### Phase 2 iter 1 blocker closure (the headline)

| Prior blocker | Iter 3 evidence | Verdict |
|---|---|---|
| **S-001** — `copy_into_workarea` destination-containment not covered | LLR-005.3 mandates `Path.is_relative_to` + TC-046 probe; "escape `.s19tool/workarea/`" wording moved out of LLR-005.1 (read path) into LLR-005.3 (write path); §5.3 acceptance bullet names it. | **closed** |
| **S-002** — Symlink / NTFS junction follow-through not covered | LLR-005.3 covers BOTH source AND destination ("either resolved path traverses a symbolic link or NTFS reparse point"); LLR-005.4 covers `validate_project_files` read side; TC-047 marked Windows-only with `pytest.mark.skipif`. | **closed** |

`shall`/`should` discipline: re-verified clean. No `should` inside Statements; no stray `shall` in informative voice (the iter 1 §2.4 `shall not` was removed in iter 3).

---

## Architect findings — iter 2

### Closure verdict on prior architect findings (A-001..A-012)

| Finding | Verdict | Evidence |
|---|---|---|
| A-001 | closed | §2.4 third bullet rewritten without `shall not` (points at LLR-002.1). |
| A-002 | closed | §1.3 defines `Finding`, `Audit matrix`, and `Deferral` schemas; §5.1 makes the matrix MANDATORY. |
| A-003 | closed | HLR-007 split into 007a (engine) + 007b (panel render). |
| A-004 | closed | LLR-002.2 cross-LLR consistency clause added. |
| A-005 | closed | §1.2 explicitly defers `s19_app/cli.py` to follow-up batch. |
| A-006 | closed | LLR-006.1 drops severity-map invariant (moved to LLR-002.1). |
| A-007 | closed | LLR-007.3 records active alias policy. |
| A-008 | closed | LLR-002.1 asserts bidirectional invariant. |
| A-009 | closed | TC-033 added; LLR-004.1 names R-TUI-018/019/020 explicitly. |
| A-010 | closed | LLR-001.1 lists R-READ-001 first; TC-002 names it. |
| A-011 | closed | LLR-001.2 cites `tests/test_tui_a2l.py` and `tests/test_tui_mac.py`. |
| A-012 | closed | LLR-005.2 enumerates the full Windows reserved set with-or-without extension. |

**All 12 closed. No regressions detected.**

### New architect findings (iter 3 introductions)

#### A-N01 — LLR-002.3 secondary trace muddies HLR ownership [minor]
- **Target:** LLR-002.3 Traceability line ("HLR-002 (with secondary trace to HLR-007a, HLR-008)").
- **Observation:** §1.3 schema treats each LLR as decomposing exactly one HLR; secondary traces are introduced here without defined semantics. Does not contradict single-source-of-truth, but a Phase 4 traceability walker may double-count.
- **Recommended fix:** Drop the secondary trace OR add a one-line note to §1.3 clarifying that "secondary trace" means informative reference, not parent decomposition.

#### A-N02 — LLR-005.3 binds an audit obligation to a product change without a Phase-3 increment binding [major]
- **Target:** LLR-005.3 Statement + Note + §6.3 R-6.
- **Observation:** R-6 is candid that the checks "may not exist in `copy_into_workarea` today" but §5.3 asserts the property as if verifiable in this batch. The doc does not specify (a) whether Phase 2 iter 2 passes when the implementation gap is acknowledged but unfixed, or (b) what the Phase-3 increment boundary is. Same anti-pattern as Q-005 (which iter 3 fixed for the orchestration audit).
- **Recommended fix:** Add to LLR-005.3 acceptance the same "Pass = enumeration is complete; closing the gap is tracked in §Deferrals OR scheduled as Phase-3-increment-N" phrasing used in LLR-003.1; cross-link from R-6 to a named Phase-3 increment slot.

#### A-N03 — LLR-005.3 size-cap voice is split between normative and "recommended default" [minor]
- **Target:** LLR-005.3 acceptance vs. §6.3 R-6 wording.
- **Recommended fix:** Pick one. Either fix 256 MB normatively (and remove "recommended default" from R-6) or make it configurable.

#### A-N04 — TC-090 is outside its numeric block [minor]
- **Target:** §5.2 row LLR-002.3 → TC-090.
- **Recommended fix:** Renumber TC-090 → TC-015 to fit the LLR-002.x block.

#### A-N05 — §5.3 issue-message scrubbing bullet is stricter than LLR-002.3's audit-only verb [minor]
- **Target:** §5.3 bullet "Issue-message scrubbing verified...".
- **Observation:** LLR-002.3 says "shall verify" / "shall record a Finding" — audit verdict, not enforcement. §5.3 rewrites this as "enforced in every rule emission". Soft recurrence of the Q-005 pattern.
- **Recommended fix:** Reword §5.3 bullet to "Issue-message scrubbing audited: every rule emission is checked; divergences recorded as Findings (LLR-002.3)."

---

## QA-reviewer findings — iter 2

### Closure verdict on prior QA findings (Q-001..Q-010)

| Finding | Verdict | Evidence |
|---|---|---|
| Q-001 | closed | §5.1 mandates audit-matrix shape; verdict enum in §1.3. |
| Q-002 | closed | TC-062 split into TC-062.a..h with explicit fixture mapping. |
| Q-003 | closed | TC-012 reclassified as `test (unit)`; lives in `tests/test_color_policy_round_trip.py`. |
| Q-004 | closed | §5.1 Demo paragraph mandates `.png` + signed transcript; gate-fail clause. |
| Q-005 | closed | LLR-003.1 acceptance "Pass = enumeration is complete"; §5.3 matches. |
| Q-006 | closed | §5.3 mandates §Deferrals entries with the four named fields. |
| Q-007 | closed | LLR-004.1 mandates per-`R-*` mini sub-table. |
| Q-008 | closed | LLR-009.1 acceptance + §6.3 R-5 promote to verified. |
| Q-009 | closed | TC-041 / TC-042 labelled `test (unit)`. |
| Q-010 | closed | LLR-002.1 deconfliction line added. |

**All 10 closed.**

### New QA findings

#### Q-N01 — TC-047 junction probe will be silently skipped on the only CI runner [major]
- **Target:** LLR-005.3 acceptance bullet 3; §5.2 row TC-047; `.github/workflows/tui-ci.yml` (Linux-only).
- **Observation:** TC-047 is the blocker-S-002 closing test, gated to Windows via `pytest.mark.skipif`. CI runs only `ubuntu-latest`. Net: TC-047 always skipped in CI, so S-002 closure depends on out-of-band manual Windows runs.
- **Recommended fix:** Add to LLR-005.3 acceptance: *"TC-047 is executed on a Windows host before the Phase 4 gate, with pytest output (stdout + exit code) attached to the corresponding `.dev-flow/03-increments/increment-NNN.md`."* (CI matrix expansion is §1.2 out-of-scope.)

#### Q-N02 — TC-090 conflates two distinct probes; needs a/b split [major]
- **Target:** LLR-002.3 acceptance bullets 1 + 2; §5.2 row TC-090.
- **Observation:** Two distinct probes (control-char/ANSI scrub; 500-char truncation) mapped to one TC. Same anti-pattern as the original TC-062 (Q-002). Allows partial pass to silently report as pass.
- **Recommended fix:** Split into TC-090.a (scrub) and TC-090.b (truncation).

#### Q-N03 — TC-064 vs TC-065 scope overlap; TC-064 is a strict subset of TC-065 [major]
- **Target:** §5.2 rows TC-064 and TC-065; LLR-007.4 acceptance.
- **Observation:** Both are panel-render snapshot tests; TC-065 is the parametrised version. TC-064 has nothing TC-065 doesn't cover.
- **Recommended fix:** Delete TC-064 (preferred) OR narrow it to a single-class smoke test and document which class.

#### Q-N04 — `tests/fixtures/` does not yet exist; Phase 3 must allocate an increment [minor]
- **Target:** LLR-007.2 acceptance; §5.3 fixture-presence bullet; §6.3.
- **Observation:** Verified by glob — directory is absent. Fixture build will reach the ≤5-files-per-increment ceiling (3 fixture files + conftest update + test extension).
- **Recommended fix:** Add §6.3 R-9: *"LLR-007.2 mandates three new fixture directories under `tests/fixtures/`. Phase 3 increment plan must allocate one increment of ≤5 files for fixtures + loader entry in `tests/conftest.py` + test additions."*

#### Q-N05 — §5.3 lacks a checklist bullet for the new demo capture-artefact gate [minor]
- **Recommended fix:** Add to §5.3: *"Every demo-method TC row in §5.2 has both `.dev-flow/evidence/<TC-NNN>/<TC-NNN>.png` and a signed transcript present."*

#### Q-N06 — §5.1 inspection-deliverable example list is sparse for class-keyed matrices [minor]
- **Recommended fix:** Add one example to §5.1: *"Examples of valid leading-column values: `R-PARSE-002`, `CROSS_MAC_S19_OUT_OF_RANGE` (issue code), `validate_a2l_mac_pairing` (rule function name), `Errors:invalid-address` (Issues-tier item)."*

---

## Security-reviewer findings — iter 2

### Pre-check: `s19_app/tui/workspace.py` unchanged since iter 1
Re-read confirms: no containment check on `copy_into_workarea` destination; no symlink/junction rejection on either function; no size cap; `setup_logging` still swallows the `touch()` exception silently. **§6.3 R-6 is honest** — LLR-005.3 / 5.4 / 5.5 describe new product behaviour that does not exist yet.

### Closure verdict on prior security findings (S-001..S-007)

| Finding | Prior severity | Verdict | Evidence |
|---|---|---|---|
| **S-001** | **blocker** | **closed** | LLR-005.3 mandates `Path.is_relative_to`; TC-046 probe; §5.3 acceptance names it. |
| **S-002** | **blocker** | **closed** | LLR-005.3 covers source AND destination; LLR-005.4 covers `validate_project_files`; TC-047 Windows-only. |
| S-003 | major | closed | 256 MB cap in LLR-005.3 + TC-044. |
| S-004 | major | closed | LLR-005.2 enumerates full reserved set with-or-without extension. |
| S-005 | major | closed | LLR-002.3 added with control-char + ANSI strip + 500-char cap. |
| S-006 | minor | closed | LLR-005.5 requires clean error or fallback; silent failure → Finding. |
| S-007 | minor | closed | LLR-005.4 promotes case-only collision to normative. |

**All 7 closed, including both blockers.**

### New security findings

#### S-N01 — `Path.resolve()` alone is not sufficient on Windows [minor]
- **Target:** LLR-005.3 acceptance ("resolves both `source` and `destination`").
- **Observation:** `Path.resolve()` follows symlinks but does not *flag* that traversal happened. A junction-to-elsewhere silently resolves. The implementation must additionally use `os.lstat() & FILE_ATTRIBUTE_REPARSE_POINT` per parent component.
- **Recommended fix:** Add to LLR-005.3 acceptance: *"reparse-point detection walks every parent component of both resolved paths via `os.lstat()` + `FILE_ATTRIBUTE_REPARSE_POINT`; resolution alone is not sufficient on Windows."*

#### S-N02 — 256 MB size-cap rationale not documented [minor]
- **Recommended fix:** Add to LLR-005.3: *"Cap rationale: realistic A2L upper end ≈100 MB (per `tests/conftest.py` generators); 256 MB leaves 2.5× headroom. Cap is configurable per-call to allow regression testing."*

#### S-N03 — 500-char message cap may truncate legitimate aggregated diagnostics [minor]
- **Recommended fix:** Add to LLR-002.3: *"Rules that need detail beyond 500 chars shall emit multiple `ValidationIssue` records rather than rely on truncation."*

#### S-N04 — R-6 "≤1 file" bound under-counts test impact [minor]
- **Target:** §6.3 R-6.
- **Observation:** Adding the LLR-005.3 checks will touch `workspace.py` + its callers (`screens.py`, `app.py` — they currently assume `copy_into_workarea` always succeeds) + `tests/test_tui_workspace.py`. Within the 5-file cap but not single-file.
- **Recommended fix:** Reword R-6 to acknowledge the caller updates.

#### S-N05 — Windows directory junctions don't require admin [informational]
- **Target:** §6.2 / threat-model framing.
- **Recommended fix:** Add to §6.2: *"Windows directory junctions do not require elevated privilege; therefore the symlink/junction rejection in LLR-005.3/5.4 is in scope even for single-user offline use."*

---

## Verdict — iter 2

**pass-with-fixes** (no blockers). The 4 majors are doc-only fixes:

- **A-N02** — LLR-005.3 needs a Phase-3 increment binding (mirror LLR-003.1 pattern).
- **Q-N01** — LLR-005.3 needs a "TC-047 manual Windows run before gate" acceptance bullet.
- **Q-N02** — TC-090 → TC-090.a / TC-090.b.
- **Q-N03** — Delete TC-064 (or narrow scope).

The 11 minors + 1 informational are all one-line edits and can fold into the same iteration as the majors.

**Estimated effort to clear all majors + minors:** one focused Phase 1 iteration 4, ≤30 minutes. Inline drafting is fine — no agent re-spawn needed.

---

*Generated by parallel re-review: `architect` (agent `aff77dcb435083c20`) + `qa-reviewer` (agent `acc18614bd06d5f83`) + `security-reviewer` (agent `a4eb04f3a163cac25`).*

---

# Deferrals

Per `01-requirements.md` §5.3 acceptance criterion *"every `major`-severity Finding is logged in `.dev-flow/02-review.md` §Deferrals with fields `{ID, owner, target batch, blast radius if not fixed}`"*. The user approved the iter 2 verdict on 2026-05-05 and chose to advance to Phase 3 with the four iter-2 majors carried forward as deferrals.

| ID | Severity | Owner | Target batch / phase | Blast radius if not fixed |
|---|---|---|---|---|
| A-N02 | major | Javier (jav201) | This batch — fold into Phase 3 increment 1 review packet (the LLR-005.3 implementation increment) | LLR-005.3 acceptance is ambiguous about whether the audit can pass while implementation work is still pending; risks Phase 4 gate confusion. Mitigate by adding the "Pass = enumeration is complete OR scheduled as Phase-3-increment-N" wording into the increment 1 packet's LLR-005.3 closure note. |
| Q-N01 | ~~major~~ **CLOSED 2026-05-07** | Javier (jav201) | This batch — closed | TC-047 (junction probe, the only test closing blocker S-002) is `pytest.mark.skipif`-gated to Windows; CI is `ubuntu-latest` only. **Closure:** canonical Windows-host run captured 2026-05-07 (Windows 11 / Python 3.14.4 / pytest 9.0.3); test PASSED. Stdout attached to [`increment-001.md` §6](.dev-flow/03-increments/increment-001.md). Phase 2 blocker S-002 closed at the canonical level. |
| Q-N02 | major | Javier (jav201) | This batch — Phase 3 increment that lands LLR-002.3 (currently planned for increment 4) | TC-090 conflates control-char scrub and 500-char truncation. Risk: a partial implementation that scrubs but does not truncate (or vice versa) reports as pass. Mitigate by splitting TC-090 → TC-090.a (scrub) + TC-090.b (truncate) when the LLR-002.3 test lands; record split in the increment 4 packet. |
| Q-N03 | major | Javier (jav201) | This batch — Phase 3 increment that lands LLR-007.4 (currently planned for increment 5) | TC-064 is a strict subset of TC-065 (both panel-render snapshot tests, TC-065 parametrised). Risk: duplicate evidence row in the audit matrix; auditor confusion about which TC ID to record pass/fail under. Mitigate by deleting TC-064 (or narrowing to a single-class smoke test) when the LLR-007.4 test lands; record in the increment 5 packet. |
| F-7.2-01 | major | Javier (jav201) | **Follow-up batch** (engine work — out of scope for this audit batch) | The `validate_artifact_consistency` engine has no rule for **S19/HEX cross-image overlap** and no `ValidationIssue.code` for that class. Existing `overlapped_addresses` set is intra-S19 only. Surfaces in Phase 3 increment 5 as TC-062.a `xfail`. **Recommended fix in follow-up batch:** add a `CROSS_S19_HEX_OVERLAP` code at WARNING tier in `s19_app/validation/model.py`-adjacent constants and a rule in `s19_app/validation/rules.py` that consumes both memory maps and emits one issue per overlapping address window. Blast radius if not fixed: a project that loads both an S19 and an Intel HEX image with disagreeing data at the same address will silently load with no warning, and the user has no surfaced indicator. The intra-S19 detector does not catch this case because the two images are kept as separate parsed objects. |
| F-7.2-02 | minor | Javier (jav201) | **Follow-up batch** (engine work — out of scope for this audit batch) | Parsed-record corruption is collected at the parser layer for all three artefact types but only **MAC** corruption reaches the engine. `S19File.get_errors()` is not piped into `validate_artifact_consistency`; A2L `address=None` (parser fallback when `ECU_ADDRESS` is missing) is silently skipped at `engine.py:117`. Surfaces in Phase 3 increment 5 as TC-062.h passing only on the MAC subset. **Recommended fix in follow-up batch:** add `S19_PARSE_ERROR` / `S19_CHECKSUM_MISMATCH` codes and pipe `S19File.get_errors()` into the engine; emit `A2L_INVALID_ADDRESS` for the `address=None` case rather than silently skip. Blast radius if not fixed: a corrupted firmware image with an S19 checksum mismatch loads without surfacing the parser error in the Issues panel; an A2L with a malformed CHARACTERISTIC missing `ECU_ADDRESS` produces a tag that is invisible to validation. |
| F-7.7-07 | **major** | Javier (jav201) | **Follow-up batch** (product fix — one-line in `s19_app/tui/a2l.py`) | `validate_characteristic` builds `enrich_a2l_tags_with_values({"tags": [tag], **a2l_data}, mem_map)[0]` at `s19_app/tui/a2l.py:~1223`. The `**a2l_data` spread comes AFTER `[tag]`, so `data["tags"]` overwrites the filtered single-tag list and `[0]` returns the FIRST parsed tag's enrichment, not the requested tag's. Effectively the accessor's name filter is ignored when the requested tag is not first. Surfaces in Phase 3 increment 7 as `test_tc_052_address_outside_memory_marks_failure` xfail. **Recommended fix:** flip the spread order to `{**a2l_data, "tags": [tag]}` (one-line change) and remove the `xfail` decorator. Blast radius if not fixed: any caller of the documented `validate_characteristic(name)` accessor for a tag other than the first parsed tag silently gets the WRONG tag's enrichment with no error — a real data-correctness bug in a public API. |
| F-7.7-02 | minor | Javier (jav201) | **Follow-up batch** (sanitiser tightening, `workspace.py`) | `sanitize_project_name` returns Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`) and their `.ext` variants verbatim, since their letters are alnum-True. LLR-005.2 says these must yield `None`. **Recommended fix:** after the alnum/dash/underscore filter, lowercase the cleaned stem and reject if in the reserved set. Blast radius: project name `CON` causes `mkdir CON` to fail non-deterministically or alias the console device on Windows. |
| F-7.7-03 | minor | Javier (jav201) | **Follow-up batch** (sanitiser tightening, `workspace.py`) | `sanitize_project_name` enforces no length cap; arbitrary-length cleaned names returned as-is. LLR-005.2 says >64 chars must yield `None` (or be truncated). **Recommended fix:** add `if len(cleaned) > 64: return None` before the final return. Blast radius: a 5,000-char alphanumeric name survives and may exceed Windows MAX_PATH (260) when joined with the workarea prefix. |
| F-7.7-04 | minor | Javier (jav201) | **Follow-up batch** (sanitiser tightening, `workspace.py`) | `sanitize_project_name` accepts Unicode confusables (e.g. Cyrillic 'а' U+0430 looking like Latin 'a') because `str.isalnum()` returns True. LLR-005.2 cites Unicode TR36. **Recommended fix:** restrict the alnum check to `ch.isascii() and ch.isalnum()` or use a TR36 confusable detector. Blast radius: low (no remote attacker on offline desktop) but violates the LLR contract. |
| F-7.7-05 | minor | Javier (jav201) | **Follow-up batch** (validation tightening, `workspace.py`) | `validate_project_files` iterates with `item.is_file()`, which **follows symlinks**. LLR-005.4 says symlinked / NTFS-reparse-point entries must be rejected. **Recommended fix:** add `if item.is_symlink() or _is_reparse_point(item): continue` before the suffix dispatch (helper already exists from increment 1). Blast radius: a symlinked entry pointing OUT of the project directory could let a project "include" arbitrary files; less severe than the workarea write-path issue closed by S-N01 (this function only reads metadata). |
| F-7.7-06 | minor | Javier (jav201) | **Follow-up batch** (doc-vs-code reconciliation) | `REQUIREMENTS.md` §Output API documents `schema_ok / memory_checked / in_memory` on the per-tag accessor (`validate_characteristic`); the code surfaces those fields on the bulk validator (`validate_a2l_tags`) instead. Single-tag accessor returns `{ok, name, errors, tag}` with decode/conversion fields nested under `tag`. **Recommended fix:** either document the per-tag/bulk split in `REQUIREMENTS.md` or extend `validate_characteristic`'s top-level dict to mirror the triplet from `validate_a2l_tags`. Blast radius: doc/code drift; downstream consumers reading REQUIREMENTS.md may not find the documented fields where promised. |

The 11 iter-2 minors and 1 informational note (A-N01, A-N03, A-N04, A-N05, Q-N04, Q-N05, Q-N06, S-N01, S-N02, S-N03, S-N04, S-N05) are not formal Deferrals (per §5.3 the schema is mandatory only for `major`-severity Findings). They are folded opportunistically into the Phase 3 increment that touches each LLR. Tracked here for traceability only:

- **A-N01 / A-N03 / A-N05** — wording fixes in §1.3 / §6.3 / §5.3 of `01-requirements.md`. Cosmetic; addressed during Phase 6 documentation if not before.
- **A-N04** — TC-090 → TC-015 renumber. Addressed when TC-090 splits per Q-N02.
- **Q-N04** — fixture-build allocation note (R-9). Addressed when increment 2 lands the fixtures.
- **Q-N05** — §5.3 demo-evidence checklist bullet. Addressed during Phase 4 validation when demo evidence is collected.
- **Q-N06** — §5.1 inspection-example list. Addressed during Phase 4 if the existing prose causes evaluator confusion.
- **S-N01** — `os.lstat()` + `FILE_ATTRIBUTE_REPARSE_POINT` precision note. Addressed during Phase 3 increment 1 implementation (must use it; TC-047 verifies).
- **S-N02 / S-N03** — rationale capture for the 256 MB and 500-char caps. Addressed in increment 1 (size cap) and increment 4 (message cap) implementation comments.
- **S-N04** — R-6 file-count honesty. Addressed when increment 1 actually opens — the file count will speak for itself.
- **S-N05** — Windows junction informational note. Addressed in Phase 6 docs (`06-docs/functionality.md`).
