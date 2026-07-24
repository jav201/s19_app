# 02 — Phase-2 cross-agent review · batch-53 (FB-P1 flow.json persistence)

**BLUF:** No blocker. The untrusted-loader spine is **verified sound and prototype-proven**
(architect + security both confirmed `_resolve_manifest_entry` reuse, fail-closed whole-flow
reject, size-before-parse, type-strict schema, strict-keys, markup-safe findings). Security
**0 HIGH**. The work is reconciling `01-requirements.md` thresholds **up** to the `01b-catalog`
rigor + de-conflicting two stale catalog F-findings + three contract picks. Resolutions below
are **authoritative amendments (§6.5): on any conflict, §6.5 OVERRIDES the §3/§4 body** — Phase 3
implements the amended contract.

## Reviewers + verdicts
- **architect:** PASS WITH CHANGES — 0 blocker, 3 major, 4 minor. Verified guard/ledger/traceability against source; ledger honest, no `shall`/`should` misuse.
- **security:** OK to proceed with mitigations — **0 HIGH/blocker**, 2 major (F1/F2), 4 low (F3–F6). Core untrusted-load design sound; both majors are one-line spec fixes, not design changes.
- **qa:** CONDITIONAL PASS — 0 blocker, 4 major, 4 minor. Catalog rigorous; requirements doc under-specifies the census (M-1) and permits vacuity-prone thresholds (M-2).

## Findings → authoritative resolutions (AMD-1..12)
| # | Src | Sev | Finding | Resolution (AMD) |
|---|-----|-----|---------|------------------|
| AMD-1 | arch M-1 | major | report block no-op status: `NOTICES`→amber-whole-flow, `SKIPPED`=semantic lie | **report block emits `BLOCK_STATUS_OK` with summary `"report generation deferred (FB-P1b)"`** — green-preserving + honest. LLR-004.3 pinned to OK; TC-021 asserts the whole-flow rollup stays `ok`. |
| AMD-2 | arch M-2 | major | `_flow_block_label` has no report arm → AT-006 vacuous on a `"?"` row | **NEW LLR-004.4:** add the `ReportBlock`→`"REPORT"` arm in `_flow_block_label` (`screens_directionb.py:2459`); **AT-006 tightened** to assert the rendered row reads `REPORT`, not "a row exists". |
| AMD-3 | arch M-3 | major | US-004 over-claims "every flow carries a report" vs delivered (round-trips when present) | **US-004 reworded to the delivered predicate:** "a report block, when present, persists + round-trips; generation deferred to FB-P1b." AT-006 authoring path = **Import of a report-bearing `flow.json`** (the only shipped surface; the panel kind Select does NOT list report in FB-P1). |
| AMD-4 | sec F1 | major | Import copy uses 256 MB default, defeating the 1 MiB flow DoS cap | **LLR-003.4:** `copy_into_workarea(picked, project_dir/"flows", max_size_bytes=FLOW_SIZE_CAP_BYTES)`. Reconcile with catalog §6. AT asserts a >1 MiB external import is refused AT THE COPY step. |
| AMD-5 | sec F2 | major | ReportBlock field-set open → future output-ref surface | **ReportBlock LOCKED field-less for FB-P1** (`{"kind":"report"}`, `_KIND_SPEC["report"]=(None,{})`); strict-keys (V5) rejects any smuggled field. Locked constraint: any future output field MUST pass V7 `FLOW-UNSAFE-OUTPUT-NAME`. Align catalog AT-P1-02 to LLR-004.1. |
| AMD-6 | qa M-1 | major | C-31 reject-arm census lives only in catalog prose, bound to no LLR/AT | **NEW LLR-002.9 (reject-arm census):** normative `set(battery expected_codes) ⊇ set(REJECTING_CODES)` — a new `FLOW-*` reject arm without a battery row goes RED. Plus negative controls (good envelope + benign load clean) in §5.3. The security oracle is now a requirement, derived not hand-listed. |
| AMD-7 | qa M-2 | major | AT/LLR thresholds weaker than catalog + drop anti-vacuity co-asserts | **Reconcile UP:** AT-001 field-by-field + non-default enums (not count-only); LLR-002.8 markup add `region.area>0` + `.plain` non-empty co-assert + the `[red]` style-token case (both rich `Text` and Textual `Content` grammars; `[link=…]` may raise); LLR-003.5 quarantine add `region.area>0` painted + non-empty pre-state; LLR-003.4 add the C-12 mutate-external-after-copy discriminator. |
| AMD-8 | qa M-3 | major | dirty-guard decided in reqs but catalog F-4 still "unresolved", AT-005 no painted/counterfactual | **F-4 RESOLVED** (confirm-discard modal, OQ-3); author catalog AT-P1-18; AT-005 gains the counterfactual (Cancel still calling `set_blocks`→blocks replaced = RED) + painted assert (post-Cancel blocks `.plain` verbatim-unchanged; modal via Pilot query). |
| AMD-9 | qa M-4 | major | catalog F-1 still "BLOCKS gate", AT-P1-17 orphan (report generation, out of scope) | **F-1 marked RESOLVED** (RB-model = Shape A model+persist, generation deferred); **AT-P1-17 dropped/rebound to Shape A (=AT-006/AT-P1-02)**; §7 exit criteria no longer require AT-P1-17. No AT tests generation (correct). |
| AMD-10 | qa m-8 | minor | two id namespaces (AT-001..006 vs AT-P1-*) with no written map | **NEW reconciliation table** (§6.7): AT-001↔{P1-09,-01}; AT-002↔{P1-01/15c + new painted-load}; AT-003↔{P1-12,-13,-14}; AT-004↔{P1-10,-11}; AT-005↔{P1-18 new}; AT-006↔{P1-02}; TC-001..021↔TC-P1-*. |
| AMD-11 | sec F3/F4 · qa m-6 | low→P3-must | (F3) ref-less report branch is NEW logic not in "ALL CASES HELD" — add `ref_field is None` guard KEEPING strict-keys; (F4) reject Windows drive-relative `C:foo` explicitly (edit the reused guard as a SEPARATE tracked change, never fork); (m-6) `run_flow(flow, ctx)` real sig `flow_execution_service.py:70` (not `:128`); report no-op test must not let a source block abort the chain first → report-only or resolvable-source fixture. | Carried as **Phase-3 implementation musts** in §6.5. |
| AMD-12 | arch m-1..m-4 · qa m-5/m-7 | minor | LLR count 15→**20** (headline stale; §5.2 table already lists 20); LLR-002.5 add ref-retention (store original relative ref verbatim; resolved path used only for containment) + "None return stops ref-checks for that block, finding still triggers whole-flow reject"; cite drift (`:368`/`:406` real subdir-skip); AT-002 painted-blocks threshold (positive C-32); 1 MiB accept-side via whitespace-padding or justify cutting. | Folded. |

## Confirmed SOUND (no action)
- Guard reuse-not-fork enforceable (`variant_execution_service.py:205`, containment-only, no fs open, existence deferred). Whole-flow fail-closed correctly specified + tested (AT-P1-04).
- Markup-safety (C-17) thorough (`safe_text` + `markup=False`, AT-P1-14/16). No new external-write surface beyond the work area. No load-time TOCTOU.
- RB scope honored — **no AT falsely tests report content generation** (qa + security both confirmed). 8.3 short-names not a vector here (no allowlist).

## Axis check (gate)
- **Coverage** OK — dual traceability complete; the reconciliation table (AMD-10) closes the id-namespace gap; census (AMD-6) makes the security oracle a requirement.
- **Certainty** — RESTORED by AMD-7 (thresholds up to catalog rigor, anti-vacuity co-asserts) + AMD-6 (derived/guarded C-31 set) + AMD-8 (dirty-guard counterfactual). No pass that cannot fail.
- **Evidence** OK — every finding file:line-grounded; security verified the guard triad + reparse primitive + prototype; architect verified the ledger honesty.

## Gate recommendation
`iterate-to-refine` applied inline as AMD-1..12 (recorded here, §6.5-authoritative). No residual blocker/major. **Ready for Phase 3** on the amended contract. Phase-3 increment cut must own every hardened AT (C-21 re-reconcile: AMD-2 tightens AT-006, AMD-8 adds AT-P1-18, AMD-6 adds the census AT — re-derive the increment plan so each has an owning increment).
