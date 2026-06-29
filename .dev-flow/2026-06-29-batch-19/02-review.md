# Review — s19_app — Batch 2026-06-29-batch-19

> Phase 2 artifact. Reviewers (parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer`. Stories US-020c (declared-region report addendum) + US-020d (issue enrichment + region cross-ref).

## ✅ Verdict (read first)

- **Gate:** **PROCEED to Phase 3** after iterate-light fold (0 blockers; 1 major + 1 MED-security + minors — all folded into the spec).
- **Findings:** 0 blocker · 1 major (architect-M1) · 1 MED (security-F1) · 7 minor. All folded (§6.4 audit).
- **Reviewer verdicts:** architect PROCEED-after-fold · qa PROCEED-after-fold · security **GRANTED**-after-fold.
- **shall/should check:** ✓ clean (architect: `shall` in every HLR/LLR statement; `should` only in rationale/preamble).
- **Two-layer (blockers):** ✓ all four PASS (qa) — every story has an `AT`; output reqs name deliverable+observation; both chains complete (§5.2); ATs genuinely black-box (AT-024c drives `ReportViewerScreen`, C-12 honoured).
- **Census (change-first):** done — best-effort + gate-confirmed. Every planned file checked vs engine-frozen `_ENGINE_PATHS` + package-root placement guards; **0 frozen edits**; NEW `report_addendum.py` in `tui/services/` is outside the root-only placement guard. The increment gate is the completeness guarantee.
- **Security:** GRANTED-after-fold — no HIGH/blocker, no new external/destructive/secret surface (F4/F5 clean); 1 MED (F1, folded) + 2 LOW (folded).
- **Evidence checklists (architect / qa / security):** ✓ all complete.

> Gate = PROCEED. Detail below is reference.

---

## Detail (reference)

### Findings (all folded — body edits landed, §6.4 audited)
| ID | Reviewer | Severity | Req | What | Fold |
|----|----------|----------|-----|------|------|
| **F1** | security | **MED** | LLR-024.1 | region `name` (operator free text) reaches the Markdown report + `project.json` WITHOUT the control-char/ANSI/length scrub `issue.message` gets (`_scrub_issue_message`) → report-integrity injection | LLR-024.1 now scrubs+caps `name` via `_scrub_issue_message` at construction; HLR-024 QC-3 gains an "injection" boundary |
| **M1** | architect | major | LLR-024.1 | "modelled on `CrcRegion`" but `CrcRegion` is half-open `[start,end)` while `DeclaredRegion` is inclusive `[start,end]` → could leak the wrong bounds convention, breaking the inclusive-boundary AT | LLR-024.1 states inclusive explicitly + flags the difference; §3 boundary catalog authoritative |
| F-arch5 | architect | minor | LLR-024.2 | `ReportOptions.declared_regions` needs a `__post_init__` arm + an invalid-case threshold | LLR-024.2 threshold: non-`DeclaredRegion` element → one `ValueError` |
| F-sec3 | security | low | LLR-024.1 | `start>=0` not validated (only `start<=end`) | LLR-024.1: `start<0` raises `ValueError` |
| F-qa1 | qa | minor | §5.2 / LLR-024.2 | TC-S3 (anti-drift) floated with no owning LLR | LLR-024.2 acceptance criterion now owns the single-source invariant; §5.2 row re-keyed |
| F-qa4 | qa | minor | AT-026a | AT read like a white-box service roundtrip | AT-026a tightened to observe the on-disk `project.json` (artifact-on-disk) |
| F-qa3 | qa | minor | §6.4 | LLRs asserted "logged §6.4" against an empty stub (body-first violation) | §6.4 seeded with the fold audit + contract-touch identity re-run |
| m1 | both | minor | LLR-024.1 | `CrcRegion` path missing `operations/` | corrected to `tui/operations/crc_config.py:61` |
| F-arch3 | architect | minor | LLR-026.1 | serializer docstring "exactly 4 keys" goes stale (additive key) — envelope guard is a SUPERSET check, no `schema_version` bump | Phase-3 note recorded in §6.4 contract-touch row (update docstring at Inc4) |
| F-arch4 | architect | minor | LLR-024.3 | `GenerateRequested` field addition | verified sole consumer (app.py:1862); §6.4 contract-touch row records it |

### Anchor verification (architect — all 9 OK)
`_declaration_error_lines`:681 · `ReportOptions`:141 (frozen+slots+`__post_init__`) · `generate_project_report`:960 · `ReportViewerScreen`:542 + `GenerateRequested`:591 · report worker app.py:2014 · `serialize_manifest`:224 / `write_project_manifest`:370 · `read_project_manifest`:293 (collect-don't-abort + size-cap) · `CrcRegion` tui/operations/crc_config.py:61 · `ValidationIssue` address:126/symbol:125/related:128. Cross-variant aggregation feasible from existing `variant_results` (no second engine pass).

### Two-layer acceptance review (qa — all PASS)
(a) every story has an `AT` ✓ · (b) output reqs name deliverable+observation ✓ · (c) both chains complete ✓ · (d) ATs black-box ✓. C-10 (AT-024a content / AT-024b zero-hit / AT-025b no-address discriminate) ✓ · C-12 (AT-024c through `ReportViewerScreen` over the produced file) ✓ · QC-3 catalogs authored ✓ · V-5 provisional-id footnote ✓.

### Security summary (security — GRANTED-after-fold)
Local desktop TUI: no network/auth/secret/exec. Two real input surfaces engaged: `name`→report (F1, folded) + `name`/`start`/`end`→`project.json` (F2 LOW subsumed by F1's cap, F3 LOW folded). No new external/destructive surface (F4); issue enrichment read-only over the already-scrubbed `ValidationIssue` (F5).

### §6.5 amendments
None — all folds are threshold/criterion tightenings recorded in §6.4; no HLR/LLR statement was deleted or its meaning reversed.
