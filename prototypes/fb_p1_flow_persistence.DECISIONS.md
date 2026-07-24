# FB-P1 (batch-53) — operator decisions on the prototype (2026-07-24)

Captured from the operator's review of the colored viz Artifact
(`fb_p1_flow_persistence.artifact.html`). Fold these into Phase-1 requirements —
NO prototype iteration needed.

## D1 — Adopt UI surface 1 (FlowBuilderPanel name-strip + Save/Load row)
The chosen layout is **surface 1** of the viz: the `FlowBuilderPanel` gains a
**name strip** (`Flow: <name>` + dirty glyph `●` / saved `✓`) and the
**Save… / Load…** buttons join the existing Run/Clear row. Save/Load modals and
the quarantine card (surfaces 2–4) stay as designed. This is the FB-P1 UI.

## D2 — NEW requirement: a ref-less REPORT block; every flow generates a report
There is one flow block that **takes no JSON ref** — the **report-generation
block**. Requirement (operator): **every flow must generate its report.**

Implications for FB-P1 (requirements-level; add in Phase 1, do NOT re-prototype):
- `flow_model.py` gains a **ReportBlock** (kind e.g. `"report"`) with **no
  `*_ref` field** — so the serializer/loader must round-trip a **ref-less
  block** (the security guard loop simply has no ref to validate for it).
- Serialization envelope: a report block is `{"kind": "report", ...opts}` — its
  options (if any: format, filename?) TBD in Phase-1 design; note the report
  OUTPUT filename, if configurable, is still a work-area write (goes through
  `save_*`/`copy_into_workarea`, never an arbitrary path).
- "Every flow generates its report" — Phase-1 design decision to settle:
  is the report **explicit-and-optional** (an author-added block) or
  **implicit-always** (auto-appended / always emitted at flow end)? The operator
  phrasing "cada flow debe generar su reporte" leans toward always-generated;
  confirm the model (a mandatory terminal report vs. an optional block) at the
  Phase-1 gate.

## Still-open FB-P1 OQs (from the prototype report, for the Phase-1 gate)
- OQ-1 finding codes `MANIFEST-*` verbatim vs `FLOW-REF-*` wrapper
- OQ-2 no existence-check at load (containment only)
- OQ-3 dirty-guard confirm modal on Load over unsaved edits
- OQ-4 caps 64 blocks / 64-char name / 1 MiB file
