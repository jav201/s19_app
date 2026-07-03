# 02 — Cross-agent review — 2026-07-02-batch-24

> **Verdict: ITERATE-TO-REFINE (forced — 2 BLOCKERS, both with specified fixes; one carries an operator design choice). architect ITERATE · qa APPROVE-with-2-MAJOR · security BLOCK-pending-F1.** ~30 citations re-verified exact; both critical fixture assumptions PROVEN; the census executed with named results. Findings below; dispositions land as §6.4/§6.5 folds after the gate decision.

## 1. Findings register

| ID | Sev | Source | Finding | Fix (specified) |
|---|---|---|---|---|
| **B-1** | **BLOCKER** | architect | **No-MAC sessions wipe `_validation_issues`**: `update_mac_view` clears the list + early-returns when `mac_records` is empty (`app.py:7160-7186`); both US-032/033 AT fixtures are S19+A2L-only → Issues pane always empty there; the LLR-037.3 reorder makes the no-MAC path strictly WORSE (wipe moves ahead of row-render). Also a product-scope hole: HLR-036's "cannot disagree" is false in ANY no-MAC session — adding a MAC to fixtures would green the ATs while the shipped divergence persists (C-12-family masking). P-10 probed `update_a2l_view` but never `update_mac_view`'s body — the C-15 blind spot one function deeper. | **Operator choice at gate:** (a) new/amended LLR: fix the no-MAC branch so a primary+A2L session still computes/retains the validation report; ATs stay MAC-less and gate the real surface (matches story intent; census: 3 no-op monkeypatches + snapshot matrix named) — or (b) rescope both stories to MAC-present sessions, weaken the HLR statements, MAC-bearing fixtures. |
| **B-2** | **BLOCKER** | security | **Stale/cross-project `last_summary` → false-provenance report**: survives project switch + file load (`change_service.py:334,617,669`; `app.py:680,4314-4324`); `ChangeSummary` has no field recording which image was patched; save-back allowed with no project (`dest_dir` falls back to workarea root, `app.py:1499`). Apply+save in project A → open B → `b` → B's loaded file paired against A's patched image, written into B's tree. All specced ATs would pass. | §6.5 amendment to LLR-038.2/.4: stamp `source_image_path` on the summary at save; refusal class #4 (`LoadedFile.path != source_image_path` → stale-summary refusal, 0 files); revalidate `saved_path` inside the CURRENT project dir at trigger; NEW AT-038d (cross-project refusal). Optional: clear `last_summary` on load (also fixes a pre-existing stale Checks-linkage read). |
| A-M1 | MAJOR | architect | AT-037b's "WARNING on a rendered row" boundary is UNBUILDABLE through the shipped chain (the only a2l WARNING emitters are symbol-less or never-a-rendered-row; injection banned for ATs) | Split: "map symbol absent from table" stays in AT-037b (naturally producible); "WARNING doesn't recolour" moves to Layer-A TC-037.2 (constructed issues, GUARD) |
| A-M2 | MAJOR | architect | §6.3 R-1 census claim mis-anchored (P-7 = frozen-set probe, not an issue-count sweep) | Replace with the EXECUTED sweep: exposure LOW — `test_tui_services.py` uses schema-complete/raw dicts (safe with `schema_ok is False` keying — add that sentence to LLR-036.1); render tests inject; gif test asserts nothing |
| Q-M1 | MAJOR | qa | C-12 observation mismatch: 01 says report path from notify/status; 01b reconstructs via glob — leaves LLR-038.3's surfacing unobserved | AT-038a: dir-diff snapshot → assert SURFACED path == the one new file → re-read that path |
| Q-M2 | MAJOR | qa | AT-038a header assert uses `last_summary.saved_path` (internal operand — correlated-failure shape) | Pin the literal: collision drive ⇒ expected basename `img-patched_1.s19` (typed name is NOT a substring — discriminates an echo); internal read demoted to diagnostic |
| S-F2 | MINOR | security | Markdown pipe-injection via parsed-artifact symbols into report tables (pre-existing in run table; new linkage table inherits; `symbol` field is unscrubbed) | `_md_cell()` (escape `\|`, strip ctl chars) in the LLR-038.1 work + one pipe-symbol TC; HTML side already safe (`_esc` verified :826-828) |
| S-F3 | MINOR | security | LLR-038.5 overclaims: projects can live OUTSIDE `.s19tool/` (external parent dir accepted `app.py:4017-4027`) | Reword: "gitignored when the project lives in the default workarea"; TC asserts destination construction |
| S-F4 | MINOR | security | No reparse/symlink check on the `reports/` destination dir (inherited batch-09) | Optional cheap `is_symlink()` check in the composer, or accept-and-document |
| S-F5 | MINOR | security | LLR-038.5 no-logging inspection scope misses the app.py trigger handler | Extend TC-038.5: notify/status carries paths + refusal diagnostics only, never entry byte content |
| Q-m1 | MINOR | qa | AT-038b/c are GUARD-class (pre-impl unbound key = vacuous pass); US-034 counterfactual = AT-038a alone | Mark explicitly; positive-diagnostic asserts load-bearing |
| Q-m2 | MINOR | qa | Stale `action_generate_saveback_report` placeholder in 01b | Rename to `action_before_after_report` |
| Q-m3 | MINOR | qa | Risk-id namespace collision (01 R-1..5 vs 01b R-1..8) | Prefix 01b's family `QR-*` |
| Q-m4/A-m3 | MINOR | both | Citation offsets: 01b regex anchor `:37-39`→`:103-113`; LLR-037.3 idempotence anchor `:5996-6009`→`:7195-7197` | Correct both |
| A-m1 | MINOR | architect | LLR-037.3 must pin the insertion point: reorder lands AFTER `_compute_a2l_enriched_tags()` (`:7413`) — MAC cache key omits enrichment state | Add the clause |
| A-m2 | MINOR | architect | Verify-mismatch × report-offer interaction unstated (`ok=True` + mismatch still stamps `saved_path`) | One sentence: offer intentionally appears (report is honest disk-to-disk); after the error notice per LLR-038.3 |
| A-m4 | MINOR | architect | Map-BUILD ownership unassigned (who constructs it from `_validation_issues`) | One clause in LLR-037.2: `update_a2l_tags_view` builds + passes |
| A-m5 | MINOR | architect | Snapshot matrix not in the census (relevant if B-1 option (a) changes `update_mac_view`) | Add census line; exposure nil-in-expectation (large_a2l is schema-clean) |

## 2. Verified-true highlights (evidence in the agents' reports)

- ~30 citation anchors re-verified exact (2 imprecise, both minors). C-15 probes genuine; the one probe-coverage failure is B-1 (un-probed `update_mac_view` body).
- **Both critical fixture assumptions PROVEN:** missing-`ECU_ADDRESS` characteristic retained with `address=None` (`a2l.py:932` init + `:1068` unconditional append; no 7-token inline address in the fixture shape) → `schema_ok=False`; duplicate symbols keep BOTH table rows (issue emission groups, table doesn't).
- **All counterfactuals confirmed at source:** AT-036a RED today; AT-037a pre-fix non-red; US-034 RED carried by AT-038a (absent deliverable).
- Collision-dedup mechanism real (`_<N>`, `workspace.py:237-238`); micro-spike consequence holds (`apply.py:628-633` never-clobber).
- Census (executed): issue-count pinning exposure LOW (named files); `_a2l_tag_row_severity` single production caller HOLDS (`app.py:7482`); diff-report byte-format pin set doubles as the TC-038.1 regression net; no test pins the update-order.
- Security confirms: HTML escaping (`_esc` :826-828), destination discipline, constructor scrub, `compare_images` fresh-parse, no-project refusal branch.

## 3. `shall`/`should`

0 `should`-as-modal in either artifact (re-scanned).

## 4. Gate

Blockers present → **`iterate-to-refine` forced** (both artifacts; §6.4/§6.5 records). B-2's fix is mechanical (fully specified). **B-1 carries the operator design choice (a) fix-the-wipe vs (b) rescope-to-MAC-present** — decided at this gate, then all findings fold in one iteration and the phase re-presents.
