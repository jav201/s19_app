# 04 — Validation — 2026-07-01-batch-23 (US-028 inline variant dropdown)

> **Verdict: PASS** per §5.3 batch acceptance criteria (evidence below).
> Author: qa-reviewer · Executed 2026-07-02 on branch `claude/batch-23-us028` (worktree
> `naughty-rhodes-96200c`, base `f5f8111 == origin/main`, Inc1 uncommitted in tree).
> All results in this artifact were RUN by the validator (commands + verbatim tails cited),
> except the full-suite regression, which is cited from the orchestrator's gate run per the
> Phase-4 task instruction (do-not-re-run rule; targeted runs re-executed here).

---

## 1. V-5 reconciliation — provisional id → real collected node

Binding source: `python -m pytest tests/test_tui_patch_variant.py --collect-only -q`
(run 2026-07-02, **11 tests collected in 0.39s**) + file read of
`tests/test_tui_patch_variant.py` (797 lines; coverage map in module docstring :1-44).

| Provisional id (01/01b) | Real node (tests/test_tui_patch_variant.py) | `-k` binds? |
|---|---|---|
| AT-035a (GATE, C-10) | `::test_at035a_dropdown_switch_updates_label_and_image` | `at035a` ✓ |
| AT-035b (GATE, C-12) | `::test_at035b_switch_persists_on_save_and_load_consumes` | `at035b` ✓ |
| AT-035c (GATE, i+ii) | `::test_at035c_no_project_disabled_placeholder` + `::test_at035c_single_variant_disabled_placeholder` | `at035c` ✓ (2 nodes) |
| TC-035.1 | `::test_tc_035_1_compose_presence` | `tc_035_1` ✓ |
| TC-035.2 | `::test_tc_035_2_variant_group_above_execute_row` | `tc_035_2` ✓ |
| TC-035.3 | `::test_tc_035_3_options_order_preselection_and_triggers` | `tc_035_3` ✓ |
| TC-035.4 | `::test_tc_035_4_routing_guards` | `tc_035_4` ✓ |
| TC-035.5 | `::test_tc_035_5_disabled_state_table` | `tc_035_5` ✓ |
| TC-035.6 | `::test_tc_035_6_switch_writes_nothing_to_disk` | `tc_035_6` ✓ |
| TC-035.7 | `::test_tc_035_7_rapid_double_pick_stays_consistent` | `tc_035_7` ✓ |
| C-12 guard (kept, never gate) | `tests/test_variant_execution.py::test_load_project_honors_manifest_active_variant` (pre-existing, untouched) | — |

All 10 provisional ids bind 1:1 (AT-035c = 2 sub-case nodes as planned in 01b §2). No
orphan node: every collected node maps to exactly one provisional id. File path matches
the A-4 provisional name exactly.

**Counterfactual evidence (QC-2):** the AT-035a RED capture lives in
`03-increments/increment-1.md` §4 ("Counterfactual RED") — routing reverted →
`AssertionError: ... got 'Project: proj:a (1/2)'` at `tests\test_tui_patch_variant.py:166`,
`1 failed in 3.95s`; restored → `11 passed in 31.38s`. The failing assert at :166 is in
the reconciled node `test_at035a_dropdown_switch_updates_label_and_image` (verified: line
166 of the current file is that node's `proj:b (2/2)` gate assert). Counterfactual power
for AT-035b/c is design-level (pre-implementation the widget id does not resolve →
`query_one` raises → RED; reverted route → manifest carries `"a"` → RED, per the node
docstrings) — consistent with the RED capture's failure mode.

---

## 2. Layer A — white-box results per LLR (run by validator)

Command: `python -m pytest tests/test_tui_patch_variant.py -v` (2026-07-02). Verbatim tail:

```
tests/test_tui_patch_variant.py::test_at035a_dropdown_switch_updates_label_and_image PASSED [  9%]
tests/test_tui_patch_variant.py::test_at035b_switch_persists_on_save_and_load_consumes PASSED [ 18%]
tests/test_tui_patch_variant.py::test_at035c_no_project_disabled_placeholder PASSED [ 27%]
tests/test_tui_patch_variant.py::test_at035c_single_variant_disabled_placeholder PASSED [ 36%]
tests/test_tui_patch_variant.py::test_tc_035_1_compose_presence PASSED   [ 45%]
tests/test_tui_patch_variant.py::test_tc_035_2_variant_group_above_execute_row PASSED [ 54%]
tests/test_tui_patch_variant.py::test_tc_035_3_options_order_preselection_and_triggers PASSED [ 63%]
tests/test_tui_patch_variant.py::test_tc_035_4_routing_guards PASSED     [ 72%]
tests/test_tui_patch_variant.py::test_tc_035_5_disabled_state_table PASSED [ 81%]
tests/test_tui_patch_variant.py::test_tc_035_6_switch_writes_nothing_to_disk PASSED [ 90%]
tests/test_tui_patch_variant.py::test_tc_035_7_rapid_double_pick_stays_consistent PASSED [100%]
============================= 11 passed in 29.63s =============================
```

Per-LLR table. **Threshold-audited** = the validator read the node's asserts and confirmed
the LLR's numeric threshold is genuinely encoded (not taken from the increment doc).

| LLR | Node(s) | Method | Result | Threshold genuinely asserted? (file:line evidence) |
|---|---|---|---|---|
| LLR-035.1 | `test_tc_035_1_compose_presence` | pilot | PASSED | ✓ `count == 1` bare (:362) AND `with_project == 1` (:369) — "exactly 1 widget with and without a project"; `disabled` first paint (:363, F-8), `allow_blank=True` (:364), prompt present (:365); no `patch_*` id renamed: `execute_ids == (1,1,1)` (:366) |
| LLR-035.2 | `test_tc_035_2_variant_group_above_execute_row` | pilot, both 80×24 + 120×30 | PASSED | ✓ scroll 0 pinned (:433); Select FIRST row within visible `content_region` — `content_y <= select_y < content_bottom` (:434, the qa MINOR-3 tightened form); no right-edge clip (:439); `vrow_y < erow_y` when the execute row is compositor-mapped (:443-444) + structural compose-order assert `children == [patch_variant_row, patch_execute_row]` (:429) — the @80×24 NULL-region binding = **deviation D-3** (§5 below) |
| LLR-035.3 | `test_tc_035_3_options_order_preselection_and_triggers` | pilot | PASSED | ✓ exact sequence equality `trio == (["Alpha","mid","zeta"], "Alpha", False)` (:524); N==1 → `([], blank, disabled)` (:531, F-2 no preselection); trigger 2 (variant append while shown) → `(["a","b"], "b", False)` (:535, F-3); duplicate stems → full filenames (:528) |
| LLR-035.4 | `test_tc_035_4_routing_guards` | integration | PASSED | ✓ non-active pick → exactly 1 activation `calls == ["b"]` (:613); same-as-active echo → no new call (:618); blank pick filtered in panel (:622); unknown id → guard status `"Variant not found: ghost"` + label unchanged (:625-627); missing file → guard status `"Variant file missing: c.s19"` + label unchanged (:630-631). "0 loads" on the guard branches is evidenced behaviorally (label/active unchanged after `wait_for_complete`), not by a worker count — adequate, noted |
| LLR-035.5 | `test_tc_035_5_disabled_state_table` (+ AT-035c for state-intact) | pilot | PASSED | ✓ `no_project == (True, True)` (:674), `multi is False` (:675), re-evaluation to disabled on project switch (:676); pane geometry stable across states (:679, Q1). The "interaction attempt" leg is observation-only by design (01b R-3: nothing user-drivable on a disabled Select) — pre-declared, not a deviation; state-intact after render = AT-035c(ii) label + hex asserts (:310-313) |
| LLR-035.6 | `test_tc_035_6_switch_writes_nothing_to_disk` + inspection | integration | PASSED | ✓ manifest ABSENT before and after switch (:722-724); full byte-snapshot equality of the project dir `before == after` (:725, "0 bytes changed, 0 files created"). Inspection cross-check RE-RUN by validator: `git diff origin/main -- s19_app | grep -c manifest_writer` → **0** (2026-07-02) |
| LLR-035.7 | `test_tc_035_7_rapid_double_pick_stays_consistent` | integration | PASSED | ✓ label names b (:787) AND rendered content is b's bytes and not a's (:790) — "label == content" coherence; dropdown re-sync `value == "b"` (:793); `active_id == "b"` ∈ original set (:794, secondary diagnostic, stronger than ∈); `files_after == files_before` — 0 files created (:795, phantom-copy guard); suppression surfaced in status (:799). 0 exceptions = the run itself. Timing-assumption comment present (:781-786, review F2 fold) |

---

## 3. Layer B — black-box acceptance (AT-035a/b/c)

### Gate results (validator run, same session as §2): all PASSED.

| AT | Deliverable observed through the SHIPPED surface | Evidence |
|---|---|---|
| AT-035a | **Rendered label**: `_project_label` reads `#cmdbar_project` rendered content (:82-85), asserts `proj:b (2/2)` (:166) after driving `Select#patch_variant_select.value = "b"` (the real-handler-chain drive, :118-119). **Rendered hex content**: workspace hop (`action_show_screen("workspace")`, legitimate navigation per Phase-2 R-1) then `#hex_view` rendered text asserts b's bytes present AND a's bytes gone (:169-174) — content-level, not a relabel | PASSED |
| AT-035b | **Handler-written `project.json` raw-read**: shipped save drive `_handle_save_dialog(SaveProjectPayload(...))` (:219-222, ratified house drive idiom — asserts stay black-box), then raw `json.loads(manifest_path.read_text(...))` (:224-225, not the writer's oracle) asserts `active_variant == "b"` (:237). **Fresh-app consume**: NEW `S19TuiApp` instance (:228), unmodified `_handle_load_project("proj2")`, rendered label asserts `proj2:b (2/2)` (:241) — `a` sorts first, so a manifest-ignoring load observably lands on `a` (counterfactual power on the consume leg) | PASSED |
| AT-035c | (i) no project: widget exists exactly once, `disabled`, blank placeholder, show-screen round-trip survives (:277-280). (ii) N==1: disabled + blank AND loaded state intact — plain `Project: proj` label (:310) + variant a's hex still rendered (:313). No programmatic value-assign on the disabled widget (per 01b's ban) | PASSED (both nodes) |

**Gates are black-box:** every AT pass/fail condition is rendered text, widget public state
(`disabled`, `value`), or on-disk bytes. Grep of the AT nodes for private attrs: none in any
AT assert (the only private read in the file's gate/assert paths is `app._variant_set.active_id`
in **TC**-035.7, explicitly labeled "secondary diagnostic" :775 and accompanied by the
rendered-label + content + files primary asserts; `select._options`/`_allow_blank` appear
only in Layer-A TC probes). Drive-level private-method use (`_handle_load_project`,
`_handle_save_dialog`) is the ratified house idiom (01b §2 header, Phase-2 qa MINOR-5).

### QC-3 boundary/negative catalog → covering node

| Catalog row | Covering node | Gap? |
|---|---|---|
| empty — no project | `test_at035c_no_project_disabled_placeholder` (+ TC-035.5 state row) | no |
| boundary — exactly 1 variant | `test_at035c_single_variant_disabled_placeholder` (+ TC-035.3 F-2, TC-035.5) | no |
| boundary — exactly 2 variants (minimal multi) | `test_at035a_...` fixture {a.s19, b.s19} (:146) | no |
| invalid — BLANK sentinel pick | `test_tc_035_4_routing_guards` (`select.value = Select.NULL`, :591; filtered, 0 activations :622) | no |
| invalid — same-as-active re-pick | `test_tc_035_4_routing_guards` (echo `VariantSelected("b")`, :586; dropped :618) | no |
| error — variant file missing on disk | `test_tc_035_4_routing_guards` (`c.s19` unlinked :602; guard status + no switch :630-631) | no |
| concurrency — rapid double-switch (in-flight pick) | `test_tc_035_7_rapid_double_pick_stays_consistent` | no |

Additional beyond-catalog coverage: unknown/stale id (TC-035.4 "ghost"), N==3 ordering +
duplicate-stem ids (TC-035.3). **No catalog row lacks a covering node — 0 gaps.**

---

## 4. Bidirectional surface-reachability matrix

Inputs are exercised through the widget/handler surface (Select value assignment posts
`Select.Changed` through the real chain, or `VariantSelected` posted at the panel's own
message seam for guard rows); outputs are observed as rendered text / widget state / disk.

| Input ↓ \ Output → | Label | Image content | Dropdown value sync | Disabled state | project.json | No-file-created | Status message |
|---|---|---|---|---|---|---|---|
| Non-default pick via widget | AT-035a (:166) | AT-035a (:169-174) | TC-035.3 after-switch value (:535 analog), TC-035.7 (:793) | TC-035.5 N≥2 (:675) | AT-035b (:237) after save; TC-035.6 absent before save (:724) | TC-035.6 (:725) | n/a (no message expected) |
| BLANK sentinel | TC-035.4 label unchanged | — (no load fired = content untouched, evidenced by 0 activations :622) | filtered in panel | n/a | TC-035.6 regime (no write) | TC-035.4 (no load) | none expected, none asserted-for |
| Same-as-active (echo) | TC-035.4 (:617) | covered by 0-activation (:618) | TC-035.3 repopulate re-sync (:524/:535) | n/a | no write (LLR-035.6 regime) | TC-035.4 | none |
| Unknown/stale id | TC-035.4 (:626) | 0-activation | value untouched (guard) | n/a | no write | TC-035.4 | TC-035.4 `Variant not found` (:627) |
| Missing-file variant | TC-035.4 (:630) | 0-activation | value untouched | n/a | no write | TC-035.4 | TC-035.4 `Variant file missing` (:631) |
| In-flight pick (rapid A→B) | TC-035.7 (:787) | TC-035.7 (:790) | TC-035.7 re-sync (:793) | n/a | no write | TC-035.7 (:795) | TC-035.7 `Variant switch ignored` (:799) |
| No-project state | — (no label change to observe) | — | AT-035c(i) blank (:280) | AT-035c(i) (:279), TC-035.5 (:674) | no write | implicit (no project dir) | none |
| N==1 state | AT-035c(ii) intact (:310) | AT-035c(ii) intact (:313) | blank, no preselect (:309, TC-035.3 :531) | AT-035c(ii) (:308), TC-035.5 (:676) | no write | TC-035.6 regime | none |
| Save (post-switch) | AT-035b consume label (:241) | consume leg activates b | — | — | AT-035b raw-read (:237) | — | — |

Cells marked "—" are combinations with no defined observable for that input (not gaps:
e.g. a no-project state has no image to observe). **Every named input dimension and every
named output/deliverable has ≥1 exercising node — no reachability gap.** Both directions
hold: inputs enter through the shipped widget/handler (never a service-API shortcut for
the gates), outputs are read from the shipped surface (rendered text / disk), not from
the mechanism.

---

## 5. Deviations record (§6.5-style)

Recorded location: `03-increments/increment-1.md` § "Deviations from spec" (Before/After
form); folding into `01-requirements.md` §6.5 is the listed pending item now unblocked by
this gate. Independent re-verification: code-reviewer (orchestrator gate addendum,
increment-1.md) re-verified D-1 and D-2; validator's own spot-checks below.

- **D-1 — blank sentinel `Select.BLANK` → `Select.NULL`.** Framework-fact correction, not
  a behavior change: on installed textual 8.2.5 the blank value is `Select.NULL`
  (`NoSelection`); `Select.BLANK` resolves to the inherited `Widget.BLANK` bool and never
  matches. All test asserts + panel filter bind to `Select.NULL` (module docstring :30-33).
  Verified live at implementation AND independently by code-reviewer. Observable contract
  (blank placeholder, echo-pair absorption) unchanged. Side finding (US-026 dead
  blank-filter) chipped out of scope (task_478df389).
- **D-2 — AT-035b saves into sibling `proj2` (pre-seeded `a.s19`), not back into `proj`.**
  Reason: the shipped save flow's `copy_into_workarea` dedup would rename the re-copied
  active image `b_1.s19`, failing `== "b"` against a CORRECT implementation (pre-existing
  save-flow behavior, out of US-028 scope). C-12 chain intact and re-verified by
  code-reviewer: shipped handler writes the manifest over a 2-variant {a,b} set, raw
  re-read, counterfactual (reverted route → `"a"` → RED), meaningful consume (`a` sorts
  first). Validator confirms the node matches this record exactly (:206-234).
- **D-3 — TC-035.2 `region.y` ordering conditional on compositor mapping @80×24.** A
  fully-below-the-fold execute row reports the NULL region; ordering @80×24 is carried by
  the structural compose-order assert (:429, the LLR's own acceptance criterion) + the
  Select-first-row-visible numeric assert, which held at BOTH sizes. Recorded in
  increment-1.md; validator confirms the code matches (:443 `if erow_w and erow_h`).

**No other unrecorded deviation found.** Spot-check of 3 LLR thresholds vs actual asserts:
(1) LLR-035.3 "exact sequence equality" → tuple-equality `(["Alpha","mid","zeta"], "Alpha", False)`
(:524) — exact; (2) LLR-035.6 "0 bytes changed, 0 files created" → full byte-snapshot dict
equality + manifest-absent (:722-725) — exact; (3) LLR-035.7 "final label id == rendered
content's variant AND 0 files AND active_id ∈ set" → :787/:790/:794/:795 — exact (the
`active_id == "b"` assert is strictly stronger than ∈). One nuance (not a deviation): the
LLR-035.4 "0 loads" on guard branches is proven behaviorally (label/active unchanged after
`wait_for_complete`) rather than by a worker count — the observable is equivalent.

---

## 6. Regression evidence (orchestrator runs, cited — not re-run per task instruction)

- **Full non-slow suite (pre-ff, orchestrator gate run, increment-1.md addendum):
  969 passed / 30 skipped / 3 xfailed / 0 FAILED (467s).** Collection ledger
  991 → **1002** (+11 new nodes, −0) ✓ reconciled — matches this validator's own
  `--collect-only` count of exactly 11 nodes in the new file.
- **Post-ff integration (orchestrator, after PRs #37/#38 merged into the branch base):
  138/138 passing** across `test_tui_patch_variant.py` + `test_tui_patch_editor_v2.py` +
  `test_tui_directionb.py`.
- **Validator's own targeted re-run (this session): 11/11 passed in 29.63s** (§2 tail).
- **Engine-frozen set: 0 diffs vs origin/main** — re-verified directly by validator
  (2026-07-02): `git diff origin/main --stat` over `core.py`, `hexfile.py`,
  `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` →
  empty. Changed-file set = exactly the 5 roadmapped files (+ `state.json` flow bookkeeping).
- **Pre-existing C-12 guard** `test_variant_execution.py::test_load_project_honors_manifest_active_variant`
  untouched and green in the orchestrator's regression set (increment-1.md coverage table).

---

## 7. Verdict — **PASS** (§5.3 batch acceptance criteria)

| §5.3 criterion | Met? | Evidence |
|---|---|---|
| 100 % of LLR-035.1–.6 (+.7) covered by ≥1 passing TC | ✓ | §2 table — 7/7 LLRs, each with a passing node, thresholds audited in-assert |
| US-028 covered by AT-035a/b/c passing incl. QC-3 boundary+negative | ✓ | §3 — 4 AT nodes PASSED; catalog 7/7 rows covered, 0 gaps |
| AT-035b is a true C-12 output-then-consume chain | ✓ | §3 — handler-written manifest raw-read (:237) + fresh-app unmodified-load consume (:241); direct-write test remains guard-only |
| 0 new failures full suite vs main; frozen set green | ✓ | §6 — 969/0 full non-slow + 138/138 post-ff (orchestrator); frozen 0-diff re-verified |
| No requirement without validation method; no `test` LLR without executed verification + numeric threshold | ✓ | §2 — every LLR row cites node + executed result + audited numeric assert |

### QA evidence checklist (execution-time)

- [x] Acceptance criteria use Given/When/Then — 01-requirements §2.6 AC-1/2/3; ATs map 1:1 (§3).
- [x] Test cases have explicit Expected, not vague "works" — every §2/§3 row cites the exact assert with file:line.
- [x] Edge cases include empty, boundary, invalid, error — §3 QC-3 catalog, 7/7 + extras.
- [x] Regression checklist exists — §6 (full suite, targeted 138/138, frozen set, C-12 guard).
- [x] Exit criteria stated — §7 table against §5.3.
- [x] No real PII / secrets — synthetic S19 constants + tmp_path projects only (test file :59-64).
- [x] Test results filled with REAL executed runs — §2 verbatim tail is the validator's own run (`11 passed in 29.63s`); orchestrator citations labeled as such.
- [x] Layer B black-box through the SHIPPED surface with boundary + negative evidence — §3 (rendered label/hex, raw disk read, fresh-app consume; no private-attr gate asserts).
- [x] Bidirectional surface-reachability — §4 matrix, every input dimension and output observed, 0 gaps.
- [x] No unfilled template — every table row carries a real node id / file:line / command output; no `<...>` placeholders remain.

---

## Orchestrator gate addendum (2026-07-02)

- **Full non-slow suite on the f5f8111 base (post PRs #37/#38 ff): 971 passed / 30 skipped / 3 xfailed / 0 FAILED (448s).** Ledger reconciles: 969 (pre-ff full run) + 2 merged-fix regression tests = 971 passed; collected 1002 + 2 = 1004. Batch-23's own delta remains +11 (991 → 1002 on its original base).
- **§6.5 amendments folded post-PASS:** A-6.5-1 (Select.NULL spec-wide, 8 replacements body-first), A-6.5-2 (AT-035b proj2 drive), A-6.5-3 (TC-035.2 compositor-mapping) — see 01-requirements.md §6.5.
- Frozen set: 0-diff vs origin/main f5f8111 (re-verified post-ff).
