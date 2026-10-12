# Review — s19_app — Batch 2026-10-11-batch-92

> Phase 2 artifact. Reviewers (in parallel, spawned as independent subagents carrying the flow's role files):
> `qa-reviewer` ∥ `code-reviewer` ∥ `security-reviewer` (trigger C8 fired — family C lens owed).
> Raw lens reports: `review-lens-qa.md` · `review-lens-code.md` · `review-lens-security.md` (this file's Detail sections summarize them; the lens files are the evidence).

## ✅ Verdict (read first)

- **Gate (orchestrator recommendation):** `iterate-to-refine` → Phase 1 — **3 HIGHs** (C1, C2, F-QA-1) are requirement-class amendments; per the station's single return edge, blockers route to P1, not to Phase 3 improvisation.
- **Out-of-scope findings:** `2` named and routed below (C4 frozen-file docstring drift → BACKLOG-CODE.md; C5 informational).

- **Findings:** **3** blocker · **4** major · **3** minor (see table; severities per the lenses' own grading)
- **shall/should check:** ✓ clean (executed grep: 0 `should`/`debería`; 19 normative `shall`)
- **Two-layer (blockers):** ✓ every story has an `AT` · output reqs name deliverable+observation · both trace chains complete · ATs genuinely black-box (qa lens verified, one MINOR gap each in AT-288/291 sharpening)
- **Census (change-first):** done — best-effort + gate-confirmed (code lens: **no missed product consumer** anywhere in `s19_app/` or `tests/`; the contract's own grep PROBE undercounts the test set — finding C3)
- **Security:** ✓ no findings (0 HIGH/MED/LOW; C-17 sink integrity verified with the batch-77 hostile oracle repointed)
- **Evidence checklists (qa / code / security):** ✓ all complete in the three lens files

> Any blocker/⚠ → read the matching Detail part.

---

## Detail (reference)

### Findings
| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| C1 | code-reviewer | blocker | post-Inc-A import graph (render.hexview ↔ tui/__init__ → tui.app) | Render-FIRST cold entries raise `ImportError: cannot import name 'build_row_bases' from partially initialized module 's19_app.render.hexview'` (executed in a scratch-tree simulation of the contract's exact edits, fresh interpreter). Tui-first entries are safe (executed: color_policy imports only `..validation`; the R4 shim chain is one-directional). **The trap fires on the contract's own isolated gate commands** (`pytest tests/test_render_hexview.py`, `tests/test_tui_hexview.py:4`) because `tests/conftest.py` never initializes `s19_app.tui` at module level. | Contract amendment choosing one disposition, written into the LLRs: (a) tui-initializing first import chartered for the isolated test modules; (b) module-level `s19_app.tui` import authorized in `tests/conftest.py` (outside today's touch sets); or **(c — orchestrator recommendation) kill the cycle root: move the style constants DOWN into `render/format` so `render/hexview` imports zero `tui` symbols — render becomes truly tui-free (stronger than the declared residuals; also the only option that protects every future render-first consumer)**. | open |
| C2 | code-reviewer | blocker | LLR-001.1 + map R1 "byte-preserving" | The moved file's OWN imports (`s19_app/tui/hexview.py:16-17`, `from .color_policy` / `from .insight_style`) must be rewritten post-move (`.` now resolves to `s19_app.render`); no contract text authorizes it. Executed literal compliance → `ModuleNotFoundError: s19_app.render.color_policy`. The "byte-identical minus wrappers" hash threshold is unmeasurable as written. | Amend LLR-001.1: name the import-block rewrite explicitly (with C1-(c): the two lines re-point at `render.format`, not `tui`), redefine the hash as base-minus-wrappers-minus-import-block. | open |
| F-QA-1 | qa-reviewer | blocker | `01-requirements.md:148,170,493,513` | Baseline set mismatch: the contract pins "40 pre-existing failures" (carried from PLAN.md / batch-91's different checkout); the measured baseline here is **38 failed / 2722 passed / 2765 collected, all 38 = `test_tc016s_density_layout_snapshot[...]`**. "0 NEW failures" is not mechanically decidable against a count that won't match (38≠40) and a set that is never named. | Ledger amendment (Before/After): pin the reference baseline as the exact set — failing node ids = the 38 tc016s parametrizations (recorded `-k tc016s --co` dump in `evidence/`); pass rule = **set-equality of both the failure set AND the pass set pre/post**, not a count comparison. | open |
| C3 | code-reviewer | major | LLR-001.4 probe + TC-651/TC-653 census design | The contract's pre-state probe pattern matches 6 files/7 occurrences, not the claimed "10 test files". Measured live old-address TEST importers = **8 files in 3 forms** (`from s19_app.tui.hexview import …`, `import s19_app.tui.hexview as …`, `from s19_app.tui import hexview …` at `test_tui_directionb.py:1172,1191` + `test_tui_search_pagination.py:19`). A census built on the stated pattern passes while those still import the dead address. | Census probe must cover all three forms (or be AST-based); correct the "10" claim to the measured 8. | open |
| F-QA-2 | qa-reviewer | major | LLR-001.4 / LLR-003.3 / LLR-004.3 + TC-651..654 specs | C-31 input-set-oracle exposure: positive arms assert over hand-listed consumer sets anchored to the static radiography; nothing requires re-deriving the set from the live tree or a completeness assertion. Module-map F-2 already demonstrated this failure class once (3 services named, 8 real). TC-654 is worse: the R4 shim makes a missed microbar consumer *silently* green. | Amend TC-651/653/654 specs: derive the census set from code at run time (AST/grep import census over `s19_app/`) and assert set-equality against the declared set — radiography-vs-code drift fails the test. | open |
| F-QA-3 | qa-reviewer | major | §5.2 / §6.3 snapshot byte-identity criterion | No chartered observer: no probe id, no manifest path, no threshold, and no pre-move capture artifact exists (`evidence/` empty at review time). Interacts with F-QA-1: the 38 baseline failures are snapshot-family, so "byte-identical" must be DEFINED for that family. | Choose one in the contract. **Orchestrator recommendation (option 2 of the finding): re-scope to "failure-set set-equality AND pass-set set-equality vs the pinned baseline (F-QA-1) + AT-288 as the sole byte-identity oracle"** — mechanical, no new probe machinery; a pure import-move cannot change rendered output without flipping a status somewhere in the 2765. | open |
| C4 | code-reviewer | minor | `range_index.py:29,60,94` docstrings · `test_tui_workspace_layout.py:37` · `diff_report_service.py:35` | Stale `s19_app.tui.hexview` path references post-move; `range_index.py` is frozen → cannot fix this batch. | Census note only; route to BACKLOG-CODE.md lane A at close. | open (routed) |
| C5 | code-reviewer | minor | `services/load_service.py:8` | Importing any `tui.services.*` module drags the full TUI package at import time (`s19_app.tui.app` in `sys.modules` = True, at base AND post-sim). Address-deep neutrality only; no regression vs today. | None — recorded so the gate is not surprised. | open (informational) |
| F-QA-4 | qa-reviewer | minor | AT-291 | Names a whole file, not a concrete node id. | Name the strip node(s) in the AT block. | open |
| F-QA-5 | qa-reviewer | minor | AT-288 | C-10 risk: fixture unnamed, no non-default parameters required through the surface. | Name the fixture / require non-default focus or match parameters. | open |

### shall / should check

✓ clean — executed grep over the contract: zero `should`/`debería`; 19 normative `shall`; the single `must` sits in an informative Rationale line, not a statement (qa lens, `review-lens-qa.md`).

### Two-layer acceptance review (blockers)

| Story / Req | (a) AT present | (b) deliverable+method named | (c) both chains | (d) black-box pure | Status |
|-------------|----------------|------------------------------|-----------------|--------------------|--------|
| US-92-1 / HLR-001 | yes | yes | yes | yes | ✓ (AT-288 sharpens per F-QA-5) |
| US-92-2 / HLR-002 | yes | yes | yes | yes | ✓ |
| US-92-3 / HLR-003 | yes | yes | yes | yes | ✓ |
| US-92-4 / HLR-004 | yes | yes | yes | yes | ✓ (AT-291 names a node per F-QA-4) |

### Supersession census (change-first)

Planned touch sets (map §5/§8) checked against the guard families by the code lens (executed, incl. a full scratch-tree simulation of both increments' exact edits):
- **Behavioral-placeholder / structural-placement:** no behavioral change planned; the moved modules keep their ASTs (C2 governs the 2-line import-block exception).
- **AST-composition:** post-Inc-A sim — tui namespace keeps 12 renderer names, drops the 3 wrappers (A3); negative control `from s19_app.tui import address_in_sorted_ranges` → ImportError as HLR-002 intends (A4); post-Inc-B sim — 6/6 shim-identity `insight_style.X is render.format.X` + value pins `█/░/#54efae/#c5c7d2/#e9e9e9`; `microbar` clamps at frac −0.5/0.5/1.5 → 0/4/8 filled; `safe_text` hostile scrub `a\x9b31mb[red]` → `a31mb[red]`; consumer identities (`is` checks) hold.
- **Frozen-module:** the sim touched only declared sets; `color_policy.py` needed no edit; `range_index.py` untouched (its stale docstrings = finding C4, routed to the backlog).
- **Reservation for the I-gate:** the P3 increment gate must re-derive the test-side census with the C3-corrected three import forms (the sim's script `_p2sim/transform.py` was deleted with the scratch tree; P3's own diff IS the re-run).

### Security review summary

✓ **No findings** (security-reviewer, trigger C8 lens). C-17 contract verified at `tui/screens_directionb.py:878-936`: full C0/DEL/C1 scrub via the single `_CONTROL_SCRUB` table, literal-`Text` wrap, zero `Text.from_markup` call sites in `s19_app/`; the plan moves it verbatim with its table (R7/LLR-003.1). The batch-77 hostile oracle (`tests/test_tui_hostile_map.py`) drives the shipped sink with the control class re-derived in-test — the Phase-3 repoint cannot weaken or bypass it. No new callers, deps, or importability risk at the new addresses. Detail: `review-lens-security.md`.

### Evidence checklists (full) — architect · qa-reviewer · security-reviewer

The architect's ARQ checklist lives in `design/module-map-delta.md` §9 (✓ complete). The qa and security lenses' executed checklists are in `review-lens-qa.md` / `review-lens-security.md` (each ✓ complete, every item with executed evidence). The code lens's four-question verification (repoint claims · import-cycle analysis · surface drift · test blast radius) is in `review-lens-code.md` with executed evidence per item.

## Amendment package routed by this review (the iterate-to-refine payload)

1. **C1+(c) with C2:** render/hexview becomes tui-free — the 5 needed style constants get their canonical home in `render/format.py` (`CYAN, DGRAY, VALUE` move with `insight_style` shimming them — extends the approved R4; `FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE` are DEFINED in `render/format` and pinned-equal to frozen `color_policy`'s copies by a TC, so the freeze is respected and drift is impossible). The moved file's own import block rewrites to `render.format` (C2). Map delta §6.1 residual rows 1–2 are amended from "survives" to "killed this batch". This is a design IMPROVEMENT discovered by review, and it must be ratified at the P1 gate.
2. **F-QA-1:** baseline pinned as the exact 38-node failing set + 2722 pass set; pass rule = set-equality both ways; the `-k tc016s --co` dump recorded in `evidence/`.
3. **F-QA-2 + C3:** TC-651/653/654 census sets derived from the live tree at run time (AST/grep over `s19_app/`), set-equality vs the declared measured sets; the three test-import forms enumerated; the "10 test files" claim corrected to 8.
4. **F-QA-3:** criterion re-scoped to failure-set AND pass-set set-equality + AT-288 as sole byte-identity oracle (chartered in §5.2 with the fixture/non-default parameters per F-QA-5).
5. **F-QA-4:** AT-291 names its concrete strip node(s).
6. **C4:** routed to BACKLOG-CODE.md lane A at close (frozen file). C5 recorded informational.

---

## P2 closure pass — 2026-10-12 (iteration 2)

The batch iterated `iterate-to-refine` to P1; the amendment pass landed; two focused closure lenses re-verified:

- **code-reviewer closure** (`review-closure-code.md`): **C1 CLOSED** — the C1-(c) design was re-simulated end-to-end in a scratch tree (since deleted, tree-proofed probes): cold render-first entries (`import s19_app.render.hexview`, `from s19_app.render.hexview import render_hex_view`, `import s19_app.render.format` — leaves `s19_app.tui` out of `sys.modules`), tui-first entries, service entries, and pytest collection through a no-tui conftest ALL succeed; base-vs-sim render output byte-identical. **C2 CLOSED** — the import-block rewrite is chartered verbatim; the sim body == base − wrappers − import block, byte-identical. **C3 CLOSED** — AST set-equality census matches the measured sets. New findings: **N1 (MEDIUM, FIXED at the gate)** — Inc-A/Inc-B sequencing: the format module creation folded into Inc-A (map §5 + LED-…92.12); **N2 (LOW, FIXED)** — renderer-name threshold 10/10 → 12/12.
- **qa-reviewer closure** (`review-closure-qa.md`): **F-QA-1..5 CLOSED** — flaky-tolerant rule at 8 sites, AST-derived censuses, chartered snapshot criterion, AT-288/291 sharpened, 0 should/debería, TC-655 traced. New finding **F-QA-6 (FIXED at the gate)**: two node ids in `evidence/baseline-failing-set.txt` were truncated by pytest's `-rf` summary width — re-derived in full (`test_at023c_issues_legend_button_opens`, `test_at063c_reparent_safety_at_80`); the file now holds 44 unique full ids.
- **security closure (orchestrator, executed):** the amendments do not touch the C-17 surface — `grep -rn "from_markup" s19_app/` → 24 hits, ALL docstrings/comments stating the never-from_markup posture; 0 call sites. The 0-finding security verdict stands.

**Closure verdict: all P2 findings closed or routed (C4 → backlog lane A at close; C5 informational).** Gate re-run: **exit 0 · 0 block**.
