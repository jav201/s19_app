# Requirements ledger — s19_app — Batch 2026-10-12-batch-94

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._

### LED-2026-10-12-batch-94.1 — HLR-004 boundary catalog: the empty class is ticked
- **Requirement:** HLR-004
- **Date:** 2026-10-13
- **What changed:** HLR-004's Boundary catalog reads `☒ empty ☒ boundary ☒ invalid ☒ error` (was `☐ empty`); the empty arm is owed and already described in the catalog text ("valid JSON with zero entries merges as a no-op"). No other class on that block changed.
- **Why:** Phase-2 qa-reviewer finding qa#1 (requirement-class major): the box contradicted its own catalog text — the empty arm is described but unticked, so nobody owed the arm.
- **What decided the wording:** the qa-reviewer-prescribed correction (tick the empty class; the arm is owed).
- **Evidence:** `02-review.md` findings table, qa#1; contract §3 HLR-004.

### LED-2026-10-12-batch-94.2 — US-003 RC-1(b) probe: scoped, reproduced form
- **Requirement:** HLR-009
- **Date:** 2026-10-13
- **What changed:** §2.6 US-003 refinement-log probe line now reads `grep -ri 'chk\.json' s19_app/` → 0 hits (9 hits in tests/ + 2 goldens are test-side vocabulary, product-clean); "Not shipped" kept.
- **Why:** Phase-2 findings qa#3 / security#3 / architect#4: the unscoped `grep -ri "chk.json"` claim ("no hits") was false — the loose pattern matches test-side fixtures; a probe that cannot demonstrate its pre-state is unproven.
- **What decided the wording:** the reviewer-prescribed scoped command and its recorded output.
- **Evidence:** executed grep 2026-10-13; `02-review.md` findings table, qa#3.

### LED-2026-10-12-batch-94.3 — US-007 RC-1(b) probe: scoped form + panel-absence probes
- **Requirement:** HLR-017
- **Date:** 2026-10-13
- **What changed:** §2.6 US-007 refinement-log probe line now reads `grep -ri 'flowexecution' s19_app/` → 0 hits (the loose pattern hits 7 `flow_execution_service` doc references — the service exists, the surface does not), plus `FlowExecutionPanel`/`CheckEditorPanel` → 0 hits as the panel-absence probes; "Not shipped" kept.
- **Why:** same findings as LED-2026-10-12-batch-94.2 (qa#3 / security#3 / architect#4): the loose pattern conflated the existing service module with the absent surface.
- **What decided the wording:** the reviewer-prescribed scoped commands and their recorded outputs.
- **Evidence:** executed grep 2026-10-13; `02-review.md` findings table, qa#3.

### LED-2026-10-12-batch-94.4 — D-label attributions swept to substance quotes
- **Requirement:** HLR-014, HLR-019, HLR-020, LLR-013.1
- **Date:** 2026-10-13
- **What changed:** every `D1`/`D4`/`D5`/`D1–D5`/`D-set` attribution in the contract now quotes the ruling's substance without a label (e.g. HLR-019: "Operator ruling from the spike intake (`flow_bench.NOTES.md`): chains run sequential by default with parallel control per chain"); the same sweep touched the §1.2 scope note, the §1.4 reference entry, and the §2.6 US-005 open-questions line.
- **Why:** Phase-2 security-reviewer finding security#4: the NOTES files carry no D-labels — the attributions cited a labeling that does not exist at the source (C-15b sweep-back: one correction sweeps every site).
- **What decided the wording:** the reviewer-prescribed rewording — quote substance, never label.
- **Evidence:** `flow_bench.NOTES.md` / `editor_bench.NOTES.md` carry no D-labels (read at P0 and P2); `02-review.md` findings table, security#4.

### LED-2026-10-12-batch-94.5 — LLR-019.2 gains the TC-B94-05 forward edge
- **Requirement:** LLR-019.2
- **Date:** 2026-10-13
- **What changed:** LLR-019.2's Executed verification names AT-B94-21 **and TC-B94-05** (mode capture in the run record), matching what HLR-019's field already claimed.
- **Why:** Phase-2 architect finding arch#2: the LLR named only its AT, so the LLR→TC forward edge the two-layer rule derives was missing on the parallel-mode unit arm.
- **What decided the wording:** the reviewer-prescribed addition (name TC-B94-05 on the LLR).
- **Evidence:** contract §4 LLR-019.2; `02-review.md` findings table, arch#2.

### LED-2026-10-12-batch-94.6 — R-4 B2 census replaced with the executed 11-file list
- **Requirement:** HLR-013
- **Date:** 2026-10-13
- **What changed:** §6.3 R-4's "known consumers" list (5 entries, undercounted) replaced with the executed census — `grep -rl "FlowBuilderPanel\|screen_flow" tests/ s19_app/` → 11 files, itemized (incl. `test_flow_multi_image_ui.py:25`, `test_flow_report_ui.py:22`, `services/flow_execution_service.py`, `services/flow_model.py` doc refs), plus the explicit note that `test_flow_crc_block.py` references block machinery, NOT the panel (0 panel hits).
- **Why:** Phase-2 findings security#2 / architect#3: the hand-listed dependants went short — a census an author reads is where the population hides.
- **What decided the wording:** the reviewer-prescribed executed grep and its verbatim output.
- **Evidence:** executed grep 2026-10-13 (11 files); `02-review.md` findings table, sec#2.

### LED-2026-10-12-batch-94.7 — R-7: inoperative golden probe replaced with the executed observer sweep
- **Requirement:** HLR-010, HLR-014
- **Date:** 2026-10-13
- **What changed:** §6.3 gains R-7: the trigger-table probe `grep -l "flow_" tests/goldens/**/*.md` (matches nothing, exit 1 — INOPERATIVE) is replaced by the executed sweep naming the byte-identity observers — `tests/goldens/batch35/at054b-before-after-report.{md,html}` (asserted by `tests/test_before_after_report.py`; captures the `- Image A: … [external] path=… parse-errors=0` lines HLR-010/HLR-014 pin), `tests/goldens/batch71/ac6-unscoped-flow-report.md` (asserted by `tests/test_flow_report_ac6_golden.py`), and `tests/test_report_addendum_bound.py`; Inc-002/003 packets must name these and rebaseline surgically if they drift.
- **Why:** Phase-2 security-reviewer finding security#1: the recorded probe could never fire (exit 1 on every tree), so the golden drift surface of the two changed report producers was unnamed.
- **What decided the wording:** the reviewer-prescribed observer list and packet-routing obligation.
- **Evidence:** executed sweep 2026-10-13; `02-review.md` findings table, sec#1.

### LED-2026-10-12-batch-94.8 — R-6: variant-retirement observer census with the rewrite/do-not-touch split
- **Requirement:** HLR-006
- **Date:** 2026-10-13
- **What changed:** §6.3 gains R-6: executed census `grep -rln "patch_variant\|VariantSelected\|VariantHelpRequested" tests/` → 9 files, split REWRITE (`test_tui_patch_variant.py` (11 tests), `test_tui_patch_big.py:647-666`, `test_tui_patch_layout.py`, `test_tui_patch_chips.py`, `test_tui_patch_card.py` (4 snapshots), `test_tui_commandbar.py:2151` docstring) vs DO-NOT-TOUCH (`test_tui_variants.py` (11 tests, `action_select_variant`/`SelectVariantScreen`), `test_variant_execution.py`).
- **Why:** Phase-2 qa-reviewer finding qa#2 (implementation-class major): Inc-001 must rewrite the panel-scoped observers and must not delete the app-level project-variant machinery this contract does not retire.
- **What decided the wording:** the reviewer-prescribed split; carried named to Inc-001 (packet obligation).
- **Evidence:** executed grep 2026-10-13 (9 files); `02-review.md` findings table, qa#2.

### LED-2026-10-12-batch-94.9 — HLR-001 threshold gains the view-only census
- **Requirement:** HLR-001
- **Date:** 2026-10-13
- **What changed:** HLR-001's Numeric pass threshold appends: `0 build/apply controls mounted on #screen_checks and #screen_issues (query census, guard-host covered)`.
- **Why:** Phase-2 qa-reviewer finding qa#5 (minor): "the existing Checks and Issues surfaces remain view-only" was asserted in the outcome text but carried no numeric threshold of its own.
- **What decided the wording:** the reviewer-prescribed clause.
- **Evidence:** contract §3 HLR-001; `02-review.md` findings table, qa#5.

### LED-2026-10-12-batch-94.10 — IFC flow rail_selection_to_panel_mount: mounting node split
- **Requirement:** LLR-001.2, LLR-017.1
- **Date:** 2026-10-13
- **What changed:** the flow's second node ("panel mounting for the two new surfaces", solely owned by LLR-001.2) is split into two nodes — check-editor mounting (owner LLR-001.2) and flow-execution mounting (owner LLR-017.1). All other nodes and the SINK unchanged.
- **Why:** Phase-2 architect finding arch#5 (minor): one node, two owners' transforms — a transform two LLRs own is two nodes (C-54); LLR-017.1's mounting claim had no node.
- **What decided the wording:** the reviewer-prescribed split.
- **Evidence:** contract §4 IFC Part A; `02-review.md` findings table, arch#5.

### LED-2026-10-12-batch-94.11 — Rail digit-binding citation corrected to app.py:1361-1370
- **Requirement:** HLR-002
- **Date:** 2026-10-13
- **What changed:** the three `app.py:1362-1371` citations (HLR-002 rationale, HLR-002 shipped surface, §6.2 D-3 row) now read `app.py:1361-1370` — 1371 is the `plus` binding, outside the `1`–`0` digit span.
- **Why:** Phase-2 architect finding arch#6 (minor): a binding-span citation that includes the wrong line pins the wrong surface.
- **What decided the wording:** the reviewer-prescribed span.
- **Evidence:** `s19_app/tui/app.py:1361-1370` read 2026-10-13; `02-review.md` findings table, arch#6.

### LED-2026-10-12-batch-94.12 — US-004 seam cross-reference corrected to HLR-012
- **Requirement:** HLR-012
- **Date:** 2026-10-13
- **What changed:** §1.2's pointer "US-004's seam is decided here at P1 (§6.2, HLR-013)" now names HLR-012, the requirement that actually carries the seam decision.
- **Why:** Phase-2 architect finding arch#1 (minor): the pointer named the fb_a builder requirement instead of the triage requirement.
- **What decided the wording:** the reviewer-prescribed cross-reference.
- **Evidence:** contract §3 HLR-012; `02-review.md` findings table, arch#1.

### LED-2026-10-12-batch-94.13 — US-004 fixture dependency: stand-in executable, operator file field-only
- **Requirement:** HLR-012
- **Date:** 2026-10-13
- **What changed:** §2.6 US-004 refinement-log Feasibility line now reads: the in-repo stand-in `examples/case_00_public/software_a.a2l` (13 990 tags, premise 9) is the executable fixture; the operator's `software_a_2.a2l` is the field-verification target, not a suite dependency.
- **Why:** Phase-2 qa-reviewer finding qa#4 (minor): the dependency named a file that is not in the repo as if the suite depended on it.
- **What decided the wording:** the reviewer-prescribed dependency statement (consistent with premise 9's executed stand-in count).
- **Evidence:** premise 9, `evidence/p1_probe_a2l_unrecognized.txt`; `02-review.md` findings table, qa#4.
