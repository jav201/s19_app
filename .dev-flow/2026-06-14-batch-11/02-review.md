# Review — s19_app — 2026-06-14-batch-11

Phase-2 cross-agent review of `.dev-flow/2026-06-14-batch-11/01-requirements.md` (US-010 project.json manifest WRITER; 4 HLR / 13 LLR / TC-001..004). Reviewers in parallel, adversarial, 2026-06-14: architect, qa-reviewer, security-reviewer.

## Verdict summary

| Reviewer | Blockers | Majors | Minors | Verdict |
|---|---|---|---|---|
| architect | 1 (F-A-01) | 2 (F-A-02, F-A-03) | 2 | iterate |
| qa-reviewer | 0 | 2 (F-Q-01≡F-A-01, F-Q-02≡F-A-02) | 2 | majors to fix |
| security-reviewer | 0 | 2 (F-S-01, F-S-02≡F-A-02) | 4 | OK-with-mitigations |

**Consolidated: 1 blocker / 3 unique majors / ~6 minors.** Blocker → Phase-1 iteration forced (dev-flow rule). All three substantive findings cluster on ONE root cause (architect): the writer emits project-RELATIVE strings while the reader oracle's representation is RESOLVED ABSOLUTE Paths at a FIXED name — and neither the equality comparison nor the placement primitive is reconciled to that. No operator design decision is newly required: the placement-mechanism resolution (M-2) is the reviewers' unanimous recommendation and falls under the delegated-confirmable latitude.

## Blocker

**B-1 (F-A-01 ≡ F-Q-01) — round-trip equality threshold does not pin the comparison representation; the primary acceptance criterion is unpassable-or-vacuous.** The reader returns `ProjectManifest.batch: list[Path]` / `assignments: dict[str,list[Path]]` as RESOLVED ABSOLUTE Paths (`variant_execution_service.py:235/290/425-461`, `_resolve_manifest_entry`); the writer's intent is project-relative POSIX strings (LLR-001.1/.2). The thresholds (HLR-001:170, glossary:91, LLR-001.3:234/237, LLR-003.1:287, C-1:126) compare "re-read vs intended composition" without naming which representation — if intent = relative strings, `["sub/a.s19"] != [Path("C:/.../sub/a.s19")]` is **unpassable** (batch-07 B-4 class); if silently coerced, **vacuous**. Violates the doc's own "Numeric threshold ⇒ objective" rule. **Fix:** add a normative comparison-representation clause to C-1 + every equality threshold — name ONE canonical form (intent resolved against the same `project_root` via `_resolve_manifest_entry` semantics, matching the established idiom `test_variant_execution.py:163`) and have all thresholds inherit it. The verify comparison (LLR-003.1) inherits the same.

## Majors

**M-1 (F-A-02 ≡ F-Q-02 ≡ F-S-02) — the mandated `copy_into_workarea` DEDUP-suffixes on collision, contradicting the fixed-name/overwrite requirement and silently breaking the reader on every re-save.** LLR-002.1 mandates `copy_into_workarea`, but it appends `_<N>` on collision (`workspace.py:300-311`) → 2nd save lands `project_1.json`; the reader opens only the fixed name (`variant_execution_service.py:344` + `PROJECT_MANIFEST_NAME:84`), so the re-saved manifest is **invisible to the oracle**. LLR-002.2's `.name=="project.json"` threshold fails on re-save; R-3's "overwrite" claim is factually wrong about the primitive. **Security elevation (F-S-02):** verify-on-write re-reads by the *written* (suffixed) path so it falsely "verifies", while every later project load reads the STALE manifest — silent divergence the verify step cannot catch. **Fix (reviewers unanimous, orchestrator locks as the resolution):** do NOT route the manifest through `copy_into_workarea`'s dedup body. Stage to `temp/`, then **atomic `os.replace`** onto `project_dir/"project.json"` after reusing the containment CHECKS (`_find_workarea_root` / `is_relative_to(workarea_root)` / `_path_traverses_reparse_point`, `workspace.py:278-291`). LLR-003.1 re-reads by the canonical `project_dir/PROJECT_MANIFEST_NAME`, not the helper's returned path. Add an AC: after two saves exactly one `project.json` exists (no `project_1.json`) and the reader reads the 2nd save. Rewrite R-3 (atomic replace retires the "no backup" worry).

**M-2 (F-A-03) — the placement-primitive choice is a Phase-1 decision gap deferred to the I2 gate.** D-3 leaves "call `copy_into_workarea` directly OR a thin wrapper" open; per M-1 calling it directly is wrong. This is exactly the "discovered at the increment gate, not Phase 1" failure the batch's own A-1 census discipline targets — applied to a behavioral primitive. **Fix:** lock the mechanism in D-3 as an explicit decision (the atomic-same-name-replace-reusing-containment-checks from M-1); make it the 7th locked gate decision so LLR-002.1 + I2 are unambiguous.

**M-3 (F-S-01, security) — the writer must REFUSE to serialize an escaping/absolute path entry up front, not rely on the reader's later silent skip.** LLR-001.2 states "no MANIFEST-PATH-ESCAPE" as an expected-output property, not an input-validation gate. A poisoned in-memory entry (`../../etc/x`, absolute, junction-traversing) is faithfully serialized; the reader silently skips it on next load (`variant_execution_service.py:261-290`), so the operator gets a manifest that quietly does less than it shows and the escaping string persists on disk. The writer is the natural enforcement point (it holds project_root + entries). **Fix:** NEW LLR-001.5 + AC — the serializer shall refuse (return `(None, [finding])`, write nothing) any `batch`/`assignments` entry that is absolute or resolves outside project_root (reuse the `_resolve_manifest_entry` rejection predicate). TC under HLR-002 (tamper composition with `../../x` → refusal + finding + no file written).

## Minors
- **m-1 (F-A-04 ≡ F-Q-03):** `ProjectVariantSet.active_id` cited `models.py:101` (that's `variants`); field is `:102`. Fix all 3 sites.
- **m-2 (F-A-05):** contract-table consumer anchors for `batch`/`assignments` point at the parse loops; add the resolution anchor `variant_execution_service.py:235/290` (the relative→absolute transform B-1 turns on).
- **m-3 (F-Q-04):** prose `MF-WRITE-CONTAINMENT` vs the code symbol `MF_WRITE_CONTAINMENT` (`io.py:1248`) — align spelling; the NEW `MANIFEST_WRITE_CONTAINMENT` is correctly NEW-flagged.
- **m-4 (F-S-03):** the reader's `MANIFEST_SIZE_CAP_BYTES` (256 MB, `variant_execution_service.py:88/357`) — note that a reader size-cap rejection on re-read is one of the `issues` LLR-003.3 already classifies as mismatch (round-trip claim holds; no new requirement).
- **m-5 (F-S-04):** LLR-004.2 AC — present re-read reader-issue messages as PLAIN text (no Rich-markup interpolation of attacker-controllable `issue.message`).
- **m-6 (F-S-05):** pin the no-logging precedent as an LLR/AC for `manifest_writer.py` (the `verify.py` F-S-07 precedent) + a `rg "getLogger|import logging" → 0` probe.
- **m-7 (F-S-06):** promote "serialize via stdlib `json` encoder, never string assembly" from AC to the LLR-001.1 Statement.

## CLEAN checks (verified, with evidence)
- **Manifest contract identity (C-9, both architect + qa re-ran):** producer {schema_version, active_variant, batch, assignments} = consumer parsed keys (`variant_execution_service.py:395/404/415/432`) = 4 both sides, no drift.
- **Change-first census (§6.3.3, A-1/A-2/A-3) — SOUND, the headline discipline's first real use:** genuinely change-first (keyed on guard CATEGORY over the planned file list), honestly NOT stamped complete (A-2 heeded, "best-effort + gate-confirmed"), correct (manifest_writer.py ∉ frozen set — union of `test_engine_unchanged.py:120` + `test_tui_directionb.py:3738` re-run; root-module guards check only `s19_app/` root `:3201/:3575`; app.py edit flagged gate-confirm; A-3 new-symbol probe present, `git diff --name-only main -- <frozen>` empty). No regression to a fixed-grep checklist, no over-claim.
- **Anchor hygiene:** 12+ citations spot-verified exact by BOTH architect + qa (read_project_manifest:293/395, _resolve_manifest_entry:203, PROJECT_MANIFEST_NAME:84, copy_into_workarea:215, WorkareaContainmentError, verify.py:34/119, build_variant_set:376, write_change_document:1167, frozen-guard lines); exceptions = m-1/m-2. All NEW symbols carry the NEW flag — no fabricated symbol.
- **Normative:** 0 `should` in statements (re-grepped); EARS shape correct; every test/analysis label has Executed-verification + Numeric-threshold; V-5 provisional flags on file paths + `-k` + node ids; probe self-test (LLR-004.3 no-textual) executed with negative control + regime.
- **Security clean surfaces:** destination containment strong (is_relative_to + reparse rejection on source/dest/parents + size cap); no firmware-byte/secret leak in ManifestVerifyResult (paths+ids only, verify.py no-raw-bytes precedent); collect-don't-abort; no new network/subprocess/dep; both planned files engine-frozen-clear.
- Collection baseline 816 reproduces (qa re-ran `--collect-only`); signed-balance `816 − 0 + A` correct form; no SVG snapshot implied.

## Gate
1 blocker → **Phase-1 iteration forced.** B-1 + M-1 + M-2 are the same root seam (relative-string-writer vs resolved-absolute-Path-fixed-name-reader) viewed from comparison + placement; M-3 is a clean security input-gate addition. All are spec-substance fixes, NO requirement-shape change beyond the NEW LLR-001.5 (M-3) — and NO new operator decision: the M-2 placement mechanism (atomic same-name replace reusing containment checks) is the reviewers' unanimous recommendation, locked by the orchestrator under the delegated-confirmable latitude. Orchestrator recommends: iterate to fix B-1 + M-1/M-2/M-3 + fold the minors.

---

## Re-confirmation — iteration 2 (2026-06-15; operator: "iterar")

Architect applied the full register. **11/11 findings CLOSED** (1 blocker, 3 majors, 7 minors) body-first with §6.4 audit rows J-1..J-6. (This review header's "4 HLR / 13 LLR" describes the object at Phase-2 time; the iteration brought it to **4 HLR / 14 LLR** via the new LLR-001.5 — M-3.)

- **B-1 (CLOSED):** canonical comparison form pinned in C-1 + glossary + inherited into HLR-001 threshold / LLR-001.3 / LLR-003.1 — intended `batch`/`assignments` RESOLVED against `project_root` via `_resolve_manifest_entry` semantics before comparison (matches `test_variant_execution.py:163`). Direct relative-vs-resolved comparison now FORBIDDEN. Orchestrator re-verified: "canonical comparison" present ×9.
- **M-1+M-2 (CLOSED):** LLR-002.1 retitled "Stage-then-ATOMICALLY-REPLACE … (NOT via copy_into_workarea's dedup body)"; mechanism = stage to `temp/` → containment CHECKS (`_find_workarea_root`/`is_relative_to`/`_path_traverses_reparse_point`) → atomic `os.replace(staged, project_dir/"project.json")`. Locked in D-3 as the 7th gate decision. LLR-002.2 threshold = two saves → exactly one `project.json` (no `project_1.json`), reader reads 2nd save. LLR-003.1 re-reads by canonical name. R-3 rewritten. Orchestrator re-verified: `os.replace` ×11, LLR-002.2 "never dedup-suffixing on re-save".
- **M-3 (CLOSED):** NEW LLR-001.5 — serializer refuses absolute/escaping entries up front → `(None, [finding])`, writes nothing; TC-001e (tamper `../../x` + absolute). C-9 re-run 4==4 (no key added). Count 13→14.
- **Minors m-1..m-7 CLOSED:** active_id :101→:102, resolution anchors :235/:290, MF_WRITE_CONTAINMENT spelling, size-cap-is-an-issue note, plain-text issue surfacing, no-logging LLR-004.3 + probe, json-encoder normative in LLR-001.1.

**Orchestrator self-check:** 14 LLR headings = §1.5 = §5.3; 6 J-rows; 0 mojibake; 0 `should` in statements; C-9 4=4. **0 open findings.** Ready for the Phase-2 re-confirmation gate.
