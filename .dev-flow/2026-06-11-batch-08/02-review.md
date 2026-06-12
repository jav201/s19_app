# Review — s19_app — 2026-06-11-batch-08

Phase-2 cross-agent review of `.dev-flow/2026-06-11-batch-08/01-requirements.md` (iteration-2 draft: 4 HLR / 13 LLR / 12 TC, probes P1–P10, audit table D-1..D-8).
Reviewers (parallel, adversarial, 2026-06-11): architect (completeness/contradictions/derivation/contract identity/audit mechanics/anchors), qa-reviewer (testability/probe re-execution/threshold soundness/coverage audit), security-reviewer (firmware-disclosure paths, no-I/O claim, input-trust, UI hygiene, keybinding routing, supply chain).

## Verdict summary

| Reviewer | Blockers | Majors | Minors | Verdict |
|---|---|---|---|---|
| architect | 2 (F-A-01, F-A-02) | 4 | 4 | iterate |
| qa-reviewer | 1 (F-Q-01 ≡ F-A-01) | 3 | 3 | iterate |
| security-reviewer | 0 | 0 | 4 (advisory) | **OK to ship** |

**Consolidated: 2 unique blockers / 5 unique majors / 10 unique minors.** Per the dev-flow rule, blockers force a Phase-1 iteration.

Cross-reviewer convergences (found independently): F-A-01 ≡ F-Q-01 (nonexistent `.hex` fixture); F-A-02 ≡ F-Q-03 (under-covering TC-008 probe; architect rates blocker — TC-008 is the SOLE verification of LLR-003.2 — adopted); F-A-04 ≡ F-Q-02 (`execute` signature contradiction); F-A-05 ≡ F-Q-06 (`_flush` citation drift).

## Blockers

**B-1 (F-A-01 / F-Q-01) — LLR-001.4 acceptance criterion names a fixture that does not exist.**
Doc line 194 demands "a real `.hex` example from `examples/`"; measured: **0 `.hex` files** anywhere in the repo (`Glob **/*.hex` → 0; examples/ census: 34 a2l, 14 mac, 16 s19, 16 txt, 1 md). The existing suite builds HEX inputs synthetically via tmp_path (`tests/test_hexfile.py:16-21`). Batch-05 "looks like it should exist" class + batch-07 B-4 unimplementable-criterion class. **Fix:** reword the AC to the established inline-HEX/tmp_path idiom (recommended — zero budget impact), or add an `examples/<case>/*.hex` fixture flagged NEW and recount C-5/R-4.

**B-2 (F-A-02 / F-Q-03, + F-Q-05 anchor sub-case) — TC-008 probe does not deliver LLR-003.2's claimed semantics; positive control out of regime.**
Executed counter-probes: `from ..app import …` (the NATURAL reverse-import form one package level below `tui/`, exactly where the target modules live), `from s19_app.tui import app`, and indented function-local `    from textual…` ALL escape the recorded regex (0 hits). The P8b positive control ran on `app.py` — a single-dot regime, not the targets' two-dot regime (environmental-measurement rule violation). TC-008 is the sole verification of LLR-003.2/HLR-003(2): a violating implementation passes. Probe self-test blocker class (b). **Fix:** widen to `\.{1,2}`-relative + `from s19_app.tui import` forms, drop/replace the `^` anchor with `^\s*` for the textual half, record a regime-correct two-dot positive control (synthetic file in a one-level-deeper package); optionally add the runtime `sys.modules`-delta check as belt-and-braces.

## Majors

**M-1 (F-A-04 / F-Q-02) — `execute` signature contradiction; the `now_fn` seam has no home.** LLR-001.1 pins one-arg `execute(loaded)` (TC-009 enforces it); LLR-001.2 mandates `timestamp_utc` from "an injectable `now_fn` clock parameter"; LLR-003.1's `run_operation(..., now_fn=...)` resolves SHARED registry instances and "invokes its execute" — no delivery route. Under the literal signature, TC-001's two-run `to_dict()` equality under a fixed clock is unpassable (B-4 class, caught at review not at implementation). **Fix:** `execute(loaded, *, now_fn: Optional[Callable[[], datetime]] = None)` in HLR-001(1) + LLR-001.1 + forwarding clause in LLR-003.1 (parent + body together + §6.4 audit row).

**M-2 (F-Q-04) — TC-012 render-equality is vacuous or unassertable as written.** Since `result.output is loaded`, a test computing both renders itself compares a dict with itself (vacuity); the non-vacuous reading (widget text vs baseline) is unassertable because LLR-004.3 never pins the argument tuple the view passes to `render_hex_view_text` (the existing call site `app.py:5805` passes app-state-dependent focus/highlight). **Fix:** pin the exact call shape in LLR-004.3 (e.g. `focus_address=None, highlight=None, mac_highlight_addresses=None, max_rows=MAX_HEX_ROWS`) and define TC-012 as widget-text (`.plain`) vs baseline computed with those pinned args.

**M-3 (F-A-03) — "pytest 8.x" asserted as fact 3×; measured runner is pytest 9.0.3 (unpinned).** Environmental-measurement rule class (a). **Fix:** "pytest (measured 9.0.3, 2026-06-11; unpinned)".

**M-4 (F-A-06) — `title` mandated by LLR-001.1 but absent from parent HLR-001(1)'s interface enumeration** (consumed by HLR-004/LLR-004.1 — licensed by the wrong parent). **Fix:** add `title` to HLR-001(1)'s enumeration + §6.4 audit row.

**M-5 (F-A-05 / F-Q-06) — Misanchored citation:** `_flush` cited at `tests/test_tui_variants.py:85`; actual def at **line 70**. **Fix:** 85 → 70.

## Minors

- **m-1 (F-A-07):** P9 BINDINGS block cited 484–507; actually 484–512 (claim itself holds — `x` free re-verified).
- **m-2 (F-A-08):** bare `styles.tcss` path → qualify as `s19_app/tui/styles.tcss` (line anchors within the file are correct).
- **m-3 (F-A-09):** A-4/LLR-004.4 attribute "no parsing" to LLR-003.1's AC, which only says "no I/O" — extend LLR-003.1 (or 001.3) AC with "performs no parsing".
- **m-4 (F-A-10):** §2.1 flags a possible `tui/services/__init__.py` edit; C-5's 10-file recount omits it — list as conditional 11th file.
- **m-5 (F-Q-07):** §5.3 "722 + N where N = number of new test functions" is self-referential — pin **N = 11** (8 unit + 3 pilot, all named node ids collected).
- **m-6 (F-S-01):** the load-bearing no-I/O guarantee has no executed probe — add a filesystem-call inspection probe (`open(|write_text|write_bytes|mkdir|shutil|os.remove|emit_s19_from_mem_map`) over the operations package + service, with positive control on `changes/io.py`.
- **m-7 (F-S-02):** the no-mem_map disclosure guard is acceptance prose, not in TC-001's threshold — add the explicit assertion (`to_dict()['output']` key set == {path, file_type, byte_count} / `'mem_map' not in`).
- **m-8 (F-S-03):** `MAX_HEX_ROWS` cap is only the DEFAULT (`hexview.py:258` lets a caller exceed it; hard floor is the `MAX_HEX_BYTES=65536` truncation at `hexview.py:287-288`) — pin the call shape (folds into M-2's fix).
- **m-9 (F-S-04, advisory):** extend R-6 — the fill-in batch shall treat side-effectful operations as requiring per-execution confirmation + sanitized output paths (batch-07 F-S-01 class), inherited as mandatory like the worker migration.
- **m-10 (F-Q-05):** TC-008 `^` anchor misses indented imports — folds into B-2's fix.

## CLEAN checks (verified results, not omissions)

- **Normative discipline:** 0 `should` inside any HLR/LLR statement (grep); all 17 statements EARS-shaped; every test/analysis label carries Executed verification + Numeric pass threshold.
- **C-2 contract identity re-run (batch-07 B-1 check):** 7=7=7=7 across HLR-001(3), LLR-001.2, both producer rows, test consumer; TUI consumer's subset {operation_id, status, notes, output} adds nothing.
- **§6.4 audit mechanics:** 8/8 "Body edit landed?" pointers grep to existing body text; body-first not violated.
- **Anchor hygiene:** 30+ citations spot-verified exact (exceptions = M-5, m-1, m-2 above); every NEW-flagged symbol confirmed absent (P1/P7 re-run).
- **Probe ledger reproduction:** P1–P10 pre-states ALL reproduce on today's tree (both reviewers independently; P6 → 722 collected re-confirmed twice).
- **Assertion arithmetic:** all 10 threshold formulas re-added and consistent (15/9/6/6/5/2/5/5/4/3).
- **Coverage:** 13/13 LLRs mapped; TC node ids identical between §4 and §5.2; no orphan TC; no TC implies an SVG snapshot (CI-only regen constraint not triggered).
- **Pilot idiom viable:** `App.run_test` confirmed live in `tests/test_tui_variants.py` + `test_tui_report_view.py`; `_flush` helper exists (:70).
- **Security surfaces (live-verified):** hex-render output hard-bounded (`MAX_HEX_BYTES` truncation); no persistence path in any LLR; no new parser/network/subprocess/encoding surface; LoadedFile field citations exact; batch-07 F-S-06 fix intact (`screens.py:375` `open_links=False`) and no Markdown widget in HLR-004; modal is list-selection only (no typed input reaches the filesystem); key `x` free, palette exposure 1:1, no-file guard present; zero new dependencies. **Security verdict: PASS.**

## Gate

2 blockers → **Phase-1 iteration forced** (dev-flow rule). All fixes are verification-substance edits — the requirement set's shape (4 HLR / 13 LLR / 12 TC) is sound and does not change. No operator design decisions required: B-1's recommended resolution (inline-HEX/tmp_path idiom, zero budget impact) follows the repo's own convention; all other fixes are mechanical. Operator may override B-1 toward a committed `examples/*.hex` fixture if a public HEX example is independently wanted.

---

## Re-confirmation — iteration 3 (2026-06-11, operator: "Iterar", B-1 via inline-HEX idiom)

Architect applied the full register to `01-requirements.md` (364 → 388 lines): **17/17 findings CLOSED** (2/2 blockers, 5/5 majors, 10/10 minors; m-8 folded into M-2, m-10 into B-2 — folds noted in the E-table).

**Orchestrator-independent verification of load-bearing closures:**
- **B-2:** widened probe re-executed by the orchestrator — HITS all 3 violation forms (`from ..app import …` two-dot relative, `from s19_app.tui import app` module-object, indented `    from textual.app import App`) at lines 1/2/4, correctly does NOT match the legitimate intra-package `from .model import Operation`, and returns 0 hits / exit 1 on the `changes/apply.py` negative control. Regime-correct controls recorded in LLR-003.2 + P8b (iteration-2 controls marked superseded).
- **B-1:** tmp_path inline-HEX idiom present in LLR-001.4 with the `tests/test_hexfile.py:16-21` precedent citation (grep: 2 hits).
- **M-1:** `execute(loaded: LoadedFile, *, now_fn: …)` signature present at parent + LLR + forwarding clause (grep: 3 hits). **M-3:** "measured 9.0.3" ×4. **m-5:** N=11 / total 733 pinned (×2).
- **§6.4:** new audit series E-1..E-15 (15 rows counted), D-1..D-8 untouched, body-first stated and architect-grep-confirmed 21/21 phrase targets.
- **C-2 contract-touch re-run #2:** recorded (E-3) — signature adds a parameter not a field; 7=7=7=7 holds.
- **shall/should:** 4 file-wide `should` hits, all in the pre-existing normative header — 0 in statements (matches both reviewers' iteration-2 counts).
- **New probe P11** (filesystem-call inspection): executed with positive control on `changes/io.py` → 7 hits; Phase-4 pass condition 0 hits on targets.

**Housekeeping note (non-finding):** the doc carries ~35 pre-existing double-encoded em-dash sequences from the iteration-1 text (mixed encoding); architect's edits used clean UTF-8 and did not normalize the legacy ones. Cosmetic only — flagged for an optional Phase-6 cleanup pass.

**Result: 0 open findings. Document ready for the Phase-2 re-confirmation gate.**
