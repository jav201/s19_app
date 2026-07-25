# 04 — Validation · batch-60 (FB-P1b flow-run report generation)

**Verdict: PASS.** 0 batch-60 regressions; both final gates 0-HIGH on the merge tip.

## Test ledger
| | count |
|---|---|
| tests_base (`556db0c`) | 1917 passed (non-slow; the 19 `tc016s` already failing at base) |
| tests_added (batch-60) | 53 (`test_flow_report_service.py` 38 · `test_flow_report_wire.py` 11 · `test_flow_report_ui.py` 3, plus the declared regression edit) |
| tests_deleted | 0 |
| tests_post (`e172fb3`) | **1970 passed** / 2 skipped / 3 xfailed / **19 failed** (25m16s) |

## The 19 failures — pre-existing, not batch-60
All 19 are `test_tc016s_density_layout_snapshot[...]` over workspace/a2l/mac/issues/map/patch/diff
— the batch-58/59 + #128 CRC-snapshot drift already tracked in `.dev-flow/BACKLOG.md` (an
advisory `continue-on-error` CI job). Established as pre-existing at batch-53 by a base
differential against `4f4f20f`; the same 19 appeared unchanged at the batch-60 base
(`556db0c`) and at every gate in this batch. **Critically for this batch:** the Inc-3
`ReportViewerScreen` parser change is non-visual, and the C-34 gate run (directionb +
snapshots, 187 passed) confirmed **0 NEW drift** — the 19 stayed the only failures.

## Per-increment gates
| Increment | Commit | Gate |
|---|---|---|
| Inc-1 composer | `e0521cb` | 30 tests; markup + status oracles move-aside RED-verified; ruff; frozen guards |
| Inc-2 wire | `3c2f80f` | 8 integration ATs; skip-guard exemption RED-verified; 113 flow tests |
| Inc-3 UI + parser | `e8ef802` | 3 tests; both ATs RED-verified; **C-34 full directionb+snapshot = 187 passed, 0 new drift** |
| Hardening (security gate) | `b617b50` | F1/F2 RED-verified; 36 composer tests |
| Hardening (qa gate) | `e172fb3` | M-1/M-4 RED-verified by mutation; 52 batch-60 tests |

## Final gates (whole diff `556db0c..HEAD`, independent subagents)
- **security-reviewer: 0-HIGH — OK to self-merge.** Verified sound: write-path containment (no
  file-derived path component), no silent overwrite, byte budget vs the viewer cap,
  degrade-not-abort scoping, the abort-guard exemption (not abusable — bounded loop, cannot
  clear `aborted`), AMD-4/5/11 as specified, 0 secrets. **2 MAJOR folded** (`b617b50`): F1
  fuzzy-linkify escaping (`www.x`, `x.com`, `a@b`, IDN passed through unescaped — the escape
  set covered only the scheme and protocol-relative families) and F2 absolute-path disclosure
  through exception text. F3 (declare `markdown-it-py`) and F4 (vacuous heading oracle) folded
  too. **F5 carried** (strikethrough survives the hardened parser; affects only the
  pre-existing, wholly-unescaped project reports).
- **qa-reviewer: 0-HIGH PASS on `b617b50`.** Mutation-tested every amendment fold — AMD-3, -4,
  -5, -8, -9, -10, -11, -13 (×2) each confirmed RED under a reintroduced defect. It also found
  the heading-oracle blind spot independently (a `# INJECTED heading` in a written path forged
  an `<h1>`) and confirmed my F4 fix closes it. **4 MAJOR folded** (`e172fb3`): M-1 (the
  whole-document byte budget was entirely unpinned — deleting the guard left all 38 tests
  green), M-2 (TC-011b, the 99-slot collision degrade), M-3 (AT-002b drives the produced `.md`
  through the shipped viewer parser — the full C-12 loop), M-4 (the report never rendered
  `diagnostics`, so a FAILED run never said *why*). Minors folded: the vacuous
  `"WRITE-OUT"` assert and the declared m-5 traversal case.

## Cross-gate note (process)
The two final gates ran concurrently and independently discovered the same class of defect
(heading/linkify oracle blindness). Recorded because the value came from the *independence*,
but it is duplicated effort — a serialized gate would have avoided it. **Any recorded gate
must name the commit it applies to:** security passed `e8ef802`+folds → `b617b50`; qa passed
`b617b50`; the merge tip `e172fb3` carries qa's folds, all RED-verified locally.

## Evidence checklist
- [x] Full non-slow suite on the merge tip — 1970 passed, 19 pre-existing.
- [x] 0 new snapshot drift from the viewer change (C-34 gate, 187 passed).
- [x] Every requirement AT owned by a test (`06-docs/traceability-matrix.md`).
- [x] Every operator decision D-1..D-6 pinned by a discriminating test.
- [x] Security 0-HIGH over the batch diff; MAJORs folded + RED-verified.
- [x] QA 0-HIGH over the batch diff; MAJORs folded + RED-verified.
- [x] Engine-frozen guards green (0 frozen files touched).
- [x] ruff clean on every batch-60 file.
