# Cross-Agent Review — s19_app — Batch 2026-06-17-batch-13

> Phase 2. Three independent reviewers (architect / qa-reviewer / security-reviewer) over `01-requirements.md`. Findings classified blocker / major / minor with `F-{A,Q,S}-NN` ids. BLUF.

## 1. BLUF verdict

**0 blockers · 1 major · 16 minor. No blocker → no forced iterate. Orchestrator recommendation: ITERATE-LIGHT (Phase-1 iter 2) to fold the 1 major + 4 high-teeth minor clusters into the LLR acceptance criteria, then proceed to Phase 3.** All three reviewers independently recommend *proceed after light tightening*; the findings are cheap edits to existing LLRs (no new requirements, no re-derivation, no design change). `shall`/`should` discipline CLEAN inside every normative statement (triple-confirmed). Change-first census CLEAN — all 6 production + 3 test files independently re-verified OUTSIDE both frozen guard lists. Traceability complete; §6.4 audit correctly empty-by-exception.

| Reviewer | blocker | major | minor |
|----------|---------|-------|-------|
| architect | 0 | 1 (F-A-01) | 5 (F-A-02..06) |
| qa-reviewer | 0 | 0 | 7 (F-Q-01..07) |
| security-reviewer | 0 | 0 | 4 (F-S-01..04) |
| **total** | **0** | **1** | **16** |

## 2. R-D ruling (the delegated decision) — ADVISORY

**Security sign-off on US-014 is ADVISORY, not mandatory.** US-014 introduces **two input-parse surfaces and ZERO new external-write/output surfaces.** The shipped write path is reused verbatim — `save_patched` (change_service.py:807), `save_patched_image` + F-S-01 sanitizer + `copy_into_workarea` containment + no-clobber (apply.py:574-619), `emit_s19_from_mem_map` (io.py:1300), `verify_written_image` (verify.py:119) — none modified by any planned increment. A pasted changeset is exactly as contained as a file-loaded one (same `classify_containment` INSIDE/PARTIAL/OUTSIDE gating → same containment-or-refuse write). The one residual obligation is mechanical: the diff-vs-`main` "0 new write paths" inspection must be a hard Phase-4 gate row (F-S-03), elevated because Inc 2 edits `io.py`/`change_service.py` which also *hold* (in different regions) `emit_s19_from_mem_map`/`save_patched`.

## 3. Findings register

### 3.1 architect (F-A)
| ID | Sev | Finding | Evidence | Disposition |
|----|-----|---------|----------|-------------|
| F-A-01 | **major** | `parse_change_document` must re-home the `MF-JSON-PARSE` try/except (`JSONDecodeError`/`RecursionError`/`UnicodeDecodeError`) wrapping `json.loads(text)`, or malformed paste loses the `MF-JSON-PARSE` code that LLR-014.2's threshold names. Valid-parity TC would pass while the malformed guarantee rests on correct relocation. | io.py:390-411; LLR-014.2 threshold | Add explicit AC to LLR-014.2 + a mandatory malformed-string TC asserting the code (not only valid-parity). Pin as Phase-3 gate. |
| F-A-02 | minor | `__all__` export of `DUMMY_CHANGESET_TEXT` inconsistent (§6.3 says add it; LLR-014.2 AC says only `parse_change_document`). It's consumed cross-module by Inc 3. | io.py:66-98; LLR-014.1/.2 | Align LLR-014.1 to state its `__all__` add. |
| F-A-03 | minor | `ActionRequested` docstring Args list must be updated alongside the new `paste_text` field (PROJECT_RULES docstring discipline); §6.2 budgets it but LLR-014.2 AC doesn't surface it. | screens_directionb.py:413-460 | Note docstring-Args update in LLR-014.2 AC. |
| F-A-04 | minor | New action token never named (`parse_paste` vs `paste_parse` vs `load_paste`); PLAN.md uses `parse_pasted`. Underdetermined. | §6.2; PLAN.md:35; A-5 row US-014-b | Pin the token literal in LLR-014.2. (Same as F-Q-02.) |
| F-A-05 | minor | Census citation precision: "grep `crc_config`" → precise reason is "no `operations/` path or `crc_config.py` in either list." Cosmetic; verdict stands. | test_engine_unchanged.py:120-127; test_tui_directionb.py:3738-3746 | Optional precision note. |
| F-A-06 | minor | `parse_change_document` has no `source_path` (string seam); `read_change_document` sets `source_path=resolved`. LLR-014.3 asserts IDENTICAL apply incl. save-back — could diverge if save-back defaults off `source_path`. | io.py:357,457; LLR-014.3 | Define `parse_change_document` sets `source_path=None`; confirm save-back doesn't depend on it; apply-parity TC must exercise save-back. |

### 3.2 qa-reviewer (F-Q)
| ID | Sev | Finding | Evidence | Disposition |
|----|-----|---------|----------|-------------|
| F-Q-01 | minor | Delegation-guard acknowledged (§5.2.2) but not a mechanical assertion — behavioral parity can pass while a parallel copy drifts. | §5.2.2:320; io.py:266/416 | Add mock.patch TC: `read_change_document(path)` invokes patched `parse_change_document` once with the file text (`call_count==1`). Promote to LLR-014.2 AC. |
| F-Q-02 | minor | New action token never named; `PATCH_ACTIONS_V2` is an exact 9-token frozenset `==` going to 10. (Dup of F-A-04.) | test_tui_patch_editor_v2.py:184-196 | Name token in LLR-014.2 flagged `NEW`, or flag provisional (V-5). |
| F-Q-03 | minor | "0 new write code paths" diff-vs-`main` has no recorded executed pre-state / path span — not mechanically re-runnable. | LLR-014.3:299; change_service.py:741/807 | Specify exact `git diff main -- <paths/symbols>` + expected `0 changed lines`; make it the Phase-4 gate row. (Pairs with F-S-03.) |
| F-Q-04 | minor | Whole-dataclass `==` parity oracle may compare path-coupled fields → could FAIL a correct impl (`ChangeDocument` is `@dataclass(slots=True)`, full structural `__eq__`). | model.py:189; LLR-014.2 threshold | Enumerate `ChangeDocument` fields; if a source/path field exists, narrow oracle to `entries` + `{issue.code}` rather than `doc == doc`. |
| F-Q-05 | minor | The `PATCH_ACTIONS_V2` assertion is a REUSE-extend of an existing node (test:175, 9→10), not NEW — mismarked under "all NEW". | test_tui_patch_editor_v2.py:175 | Mark REUSE-extend distinctly. |
| F-Q-06 | minor | §3 HLR-013 Executed-verification names only `test_tui_crc_surface.py`; omits the `test_crc_config.py` unit-seam node that LLR-013.2/§5 depend on. §3↔§5 not fully aligned. | §3:186; §5.2:292; LLR-013.2:224 | Add `test_crc_config.py -k read_crc_config_text` to §3 HLR-013. |
| F-Q-07 | minor | Mount-state equality (`TextArea.text == DUMMY_CHANGESET_TEXT`) assumes init-text round-trips mount without normalization (Textual `TextArea` trailing-newline behavior). | screens.py:668 (CRC precedent); screens_directionb.py:325 (NEW) | Author `DUMMY_CHANGESET_TEXT` without trailing newline OR add `.rstrip("\n")` tolerance; flag `assumed — verify Phase 3`. |
| (qa note) | — | Line-drift: doc cites `json.load` at io.py:393 (actual ~416). Symbol correct, line stale. | io.py:416 | Phase-4 line reconciliation. |

### 3.3 security-reviewer (F-S)
| ID | Sev | Finding | Evidence | Disposition |
|----|-----|---------|----------|-------------|
| F-S-01 | minor | US-013 read path correctly characterized: uncontained-by-design (read-only, no write → no traversal/symlink write risk) + size-cap BEFORE read + collect-don't-abort. No defect. | crc_config.py:218→227-232→235 | Confirm `read_crc_config_text` keeps the cap on the line BEFORE `read_text` (LLR-013.2 AC-3 already mandates via `size_probe`). |
| F-S-02 | minor | Paste safety sound: `json.loads` (not `eval`), collect-don't-abort. No text-size cap on paste, but negligible — in-memory TextArea, and structure bounded by `MF_ENTRY_COUNT_CEILING=100k` / `MF_RUN_LENGTH_CEILING=1MiB` via reused `_parse_entries`; mega-paste degrades gracefully. | io.py:391-411, 194-202, 702-703 | Optional: a paste-over-ceiling TC asserting `MF-ENTRY-LIMIT` parity. |
| F-S-03 | minor | "0 new write surface" must be a STANDING gate row, not one-time prose — Inc 2 edits `io.py`/`change_service.py` (same files as `emit_s19_from_mem_map`/`save_patched`). | LLR-014.3; PLAN.md:34 | Elevate `git diff main -- apply.py verify.py workspace.py` = empty + symbol-diff on the two Inc-2 files to a hard Phase-4 pass-row. (Pairs with F-Q-03.) |
| F-S-04 | minor | No-secret-leak holds (TC-114 tripwire real; example uses public CRC-32 poly + round addresses). Recommend a SIBLING tripwire for the changeset dummy. | test_crc_config.py:95-110; examples/crc_config.example.json | Add tripwire asserting `examples/**/*changeset*.json` (or v2 glob) is EMPTY, mirroring TC-114. |

## 4. Disposition plan (clusters → where they fold)

No blocker forces iterate. Recommended **iterate-light** folds (deterministic LLR-AC edits, no re-derivation):
- **Cluster 1 — D2 refactor fidelity (F-A-01 major + F-Q-01 + F-Q-04 + F-A-06):** LLR-014.2 gains ACs: (a) `parse_change_document` wraps `json.loads` in the `MF-JSON-PARSE` 3-exception catch + a mandatory malformed-string TC asserting the code; (b) a `mock.patch` delegation TC (`call_count==1`); (c) `source_path=None` defined + parity oracle narrowed to `entries`+`{issue.code}` if a path-coupled field exists (enumerate at draft); (d) apply-parity TC exercises save-back.
- **Cluster 2 — action token (F-A-04 + F-Q-02):** name the literal in LLR-014.2 (proposed `parse_paste`, flagged `NEW — created in Phase 3`).
- **Cluster 3 — diff-vs-main executable + gated (F-Q-03 + F-S-03):** LLR-014.3 specifies the exact `git diff main -- <paths>` + `0 changed lines`; elevated to a hard Phase-4 row.
- **Cluster 4 — changeset tripwire (F-S-04):** add a sibling `examples/**/*changeset*.json` empty-tripwire to Inc 2/3 test scope.
- **Cluster 5 — draft tidy (F-A-02/03/05, F-Q-05/06/07, line-drift):** fold in the same pass; cosmetic/alignment.

## 5. Evidence-checklist summary
- architect 7/7 (✗ only "diagram" — not owed; flow linear). qa 11/11 (✗ noted line-drifts, non-blocking). security 5/5.
- shall/should: CLEAN (0 in statements, triple-confirmed). Census: CLEAN (both frozen lists re-verified independently). Traceability: complete (all 7 §2.6 ACs derivable). §6.4 audit: correctly empty-by-exception (no threshold/statement change; seams resolved into ACs, not normative changes).

## 6. Gate
0 blockers. Orchestrator recommended **iterate (light)**. **Operator: `iterate`.**

## 7. Resolution — Phase-1 iter-2 fold (applied)
All 17 findings (1 major + 16 minor) CLOSED inline, body-first (§4/§5 edits then §6.4 audit rows J-1/J-2/J-3). Summary:
- **C1 (F-A-01 major, F-Q-01, F-Q-04, F-A-06):** LLR-014.2 Statement names `parse_paste` + the `MF-JSON-PARSE` guarantee; threshold narrows the parity oracle to `entries`+`{issue.code}` (since `parse_change_document` sets `source_path=None`), adds `MF-JSON-PARSE` on malformed + delegation `call_count==1`. New TC-209 (malformed) + TC-210 (delegation guard). LLR-014.3 save-back prompt-name parity (F-A-06).
- **C2 (F-A-04, F-Q-02):** action token pinned to `parse_paste` (`PATCH_ACTIONS_V2` 9→10).
- **C3 (F-Q-03, F-S-03):** LLR-014.3 "0 new write paths" now an executable HARD standing Phase-4 gate (`git diff main -- apply.py verify.py workspace.py` = 0 + emit/save_patched symbol bodies = 0).
- **C4 (F-S-04):** TC-211 changeset tripwire (`examples/**/*changeset*.json` empty), in `test_changes_schema.py` (Inc 2 — no new file).
- **C5 tidy:** F-A-02 (`__all__` += `DUMMY_CHANGESET_TEXT`), F-A-03 (docstring-Args note), F-Q-05 (action-set assertion marked REUSE-extend), F-Q-06 (HLR-013 += `test_crc_config.py`), F-Q-07 (rstrip mount tolerance), line-drift io.py:393→416.

**Post-fold verification (orchestrator):** 2 HLR / 6 LLR (unchanged), TC-201..211, 0 `should`-in-statement, §6.4 J-1/J-2/J-3 present, all 4 NEW symbols (incl. `parse_paste`) genuinely absent from `s19_app/`, 0 mojibake, increment file lists unchanged (≤5/inc, no new files). R-D stays ADVISORY. → Phase-2 re-confirmation gate.
