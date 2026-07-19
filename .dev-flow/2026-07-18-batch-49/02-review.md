# Review — s19_app — Batch 2026-07-18-batch-49

> Phase 2 artifact. Reviewers (parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer`.

## ✅ Verdict (read first)

- **Gate:** **PROCEED to Phase 3** (0 blockers; all majors/minors folded into `01-requirements.md` before implementation).
- **Findings:** **0** blocker · **3** major · **9** minor.
- **shall/should check:** ✓ clean (0 modal `should`/`may` inside any HLR/LLR Statement — architect + qa confirmed; 32 `shall`).
- **Two-layer (blockers):** ✓ every story has an `AT`; output reqs name deliverable+observation; both trace chains complete; ATs genuinely black-box (CHECKS ATs drive the real `#patch_checks_run_button` in one chain).
- **Census (change-first):** best-effort + gate-confirmed. C-26 rail-count census had ONE omission (`test_tc001_rail_composes_eight_ordered_items` :488) — now folded into R-2.
- **Security:** ✓ no blockers; 4 minor hardening notes. No new write/exec/network/parser surface; 0 frozen-file edits.
- **Evidence checklists:** ✓ all three reviewers returned complete evidence checklists.

> Gate = PROCEED. All 40+ cited `file:line`s grep-verified CORRECT by the architect — the core risk surface is clean.

---

## Detail

### Findings

| ID | Reviewer | Severity | Area / Req | What | Disposition | Status |
|----|----------|----------|------------|------|-------------|--------|
| MAJ-1 | qa | major | AT-082a (GATE) | No mandated asymmetric E/W/I distribution + no independent count oracle → circular/label-swap-blind (batch-48 M-2) | FOLD: AT-082a pins 3/1/2 asymmetric + oracle buckets `_validation_issues` by `ValidationSeverity`, per-slot equality | fixed |
| MAJ-2 | qa + security(F4) | major | AT-082f (GATE, C-17) | Threshold weaker than AT-084g; payload unpinned | FOLD: raise to `.plain` verbatim AND `spans==[]`; pin dual-token payload `[/nope]`+`[link=...]` for 082f AND 084g | fixed |
| MAJ-3 | architect | major | LLR-083.1 / R-2 (C-26) | Census omits `test_tui_directionb.py:488` (`positions==[1..8]`) which HARD-FAILS at 9 items; `:506/:513` digit-strings; `EXPECTED_RAIL` def at :449 | FOLD: add :488 to R-2 breaking-set; name :506/:513 (`"12345678"→"123456789"`); correct def cite :449 | fixed |
| MIN-1 | security(F1) | minor | LLR-084.8 | C-17 enum omits `CheckRunEntry.reason` (model.py:680) | FOLD: add `reason` to the enumeration | fixed |
| MIN-2 | security(F2) | minor | LLR-084.2 | `CheckDisplayRow.text` field composition unspecified → C-17 audit can't be mechanical | FOLD: pin the composing fields (author-domain vs file-derived) | fixed |
| MIN-3 | security(F3) | minor | LLR-084.1 | DoS mount-cap referenced ("-style") but no numeric TC | FOLD: NEW TC-084.10 asserts mounted `CheckRow` ≤ cap for an oversized run, cap constant cited | fixed |
| MIN-4 | qa-3 | minor | LLR-082.1 | strip severity set hand-listed vs `SEVERITY_ORDER` | FOLD: note set bounded by `SEVERITY_ORDER`; TC-082.1 covers each member | fixed |
| MIN-5 | qa-4 | minor | AT-084c | Observable byte non-discriminating (image all `0x00`) — only the address `0x102` discriminates | FOLD: AT-084c asserts the `0x102` address row appears in `#checks_hex_pane` | fixed |
| MIN-6 | qa-5 | minor | HLR-084 boundary | Uncheckable/outside-image (`0x9000`, `actual_bytes=None`) hex-select unmapped | FOLD: NEW TC-084.11 (select uncheckable row → address window/placeholder, no crash) | fixed |
| MIN-7 | architect-2 | minor | US-082 refinement log | cites `issues_view.py:69` (class) vs `:103` (`__init__`) | FOLD: cosmetic cite fix | fixed |
| MIN-8 | architect-3/4 | minor | LLR-084.4 / LLR-082.2 | `_check_strip_text` cite into body; `#issues_columns` id at :1768 not :1762 | FOLD: cosmetic cite fixes | fixed |
| MIN-9 | architect-5 | minor | LLR-082.4 | unresolved `AT-082?` token | FOLD: → "TC-082.4 (inspection)" | fixed |

### shall / should check
✓ Clean — 0 modal `should`/`may` inside any HLR/LLR Statement (architect + qa independently confirmed). 32 `shall`.

### Two-layer acceptance review (blockers)
| Story | (a) AT present | (b) deliverable+method | (c) both chains | (d) black-box pure | Status |
|-------|----------------|------------------------|-----------------|--------------------|--------|
| US-082 | yes (AT-082a-f) | yes (rendered strip/glyph/summary elements) | yes | yes (drives `#screen_issues`, asserts rendered widget) | ✓ |
| US-083 | yes (AT-083a-b + AT-084a-g) | yes (rail nav + rendered grouped rows/strip/hex) | yes | yes (drives rail key + real run-checks button, C-12 through-surface) | ✓ |

### Supersession census (change-first) — best-effort + gate-confirmed
Planned files vs guard families: **engine-frozen** — none touched (`_ENGINE_PATHS` = core/hexfile/range_index/validation/mac.py; `change_service.py`+`model.py` NOT frozen — architect-confirmed). **frozen TEST files** — none targeted (`test_tui_directionb.py` is the guard host, NOT frozen; new test files non-frozen). **rail/screen-count guards** — `test_tui_directionb.py` :449(`EXPECTED_RAIL` def)/:488(`positions==[1..8]`)/:506/:513/:698/:741/:779/:881 + key-routing :493; ALL to update to 9 in Inc-3 (LLR-083.1). Reverse-grep confirmed `IssueGroupHeader` tests read `.severity_label`/`.issue_count` attributes (not rendered string) → glyph-prepend safe; the sole summary test (:2215) is renderable-based → str→Text change safe. **The increment gate (full suite green) is the completeness backstop (A-2) — census not stamped "VERIFIED COMPLETE".**

### Security review summary
PASS-WITH-NOTES, 0 blockers. No new external/write/exec/parser surface (hex peek = read-only `render_hex_view_text`; `check_display_rows` read-only). Every file-derived string reaching a new cell (`linkage_symbol`, `reason`, `run_blocked_reason`) covered by LLR-084.8 + the blanket `safe_text` rule (LLR-084.1); `ValidationIssue.symbol` confirmed NOT on the render path (only `.entries` read, not `.issues`). Issues new surfaces are ints+author-constants by construction. 4 minor folds (F1-F4).

### Evidence checklists — all three complete
architect: 40+ citations grep-verified; frozen-set confirmed via `_ENGINE_PATHS`; reverse-grep of touched symbols done. qa: fixtures verified real (`_ASYMMETRIC_ENTRIES` 2/1/3, fail@0x102, image 0x00; issues seeding idiom); frozen-test-file set confirmed clear; C-10/C-12/C-31 checked. security: file-derived-string enumeration complete; no-new-surface confirmed; DoS cap noted.
