# QA Validation Methods — batch-51 · Flow Builder (LOAD notices · CHECK · completed-with-issues · Direction A UI)

**Phase-1 qa-reviewer artifact.** Keyed by **STORY + AT** (the architect derives `R-TUI-085..` in parallel; the HLR/LLR columns are marked `⟨fold⟩` and are reconciled at the Phase-1 fold, not here). Grounded in the SHIPPED code as read at draft time:

- Engine: `s19_app/tui/services/flow_execution_service.py::run_flow` (currently SOURCE/PATCH/WRITE-OUT only; `FLOW_STATUS_OK`/`FLOW_STATUS_ERROR`; `BLOCK_STATUS_OK/ERROR/SKIPPED`). **No `notices`, no `completed-with-issues`, no CHECK, and LOAD does not yet surface parser per-record `errors` — all NEW in Phase 3.**
- Model: `flow_model.py` (`FlowRunResult`, `BlockResult`, status tokens).
- Read-only CHECK seam: `s19_app/tui/changes/check.py::run_check_document` (`check.py:194`) → `CheckRunResult` (`changes/model.py:684`) with `aggregates={passed,failed,uncheckable}` (`model.py:571`) + `run_blocked_reason_code`/`run_blocked_reason` (`model.py:750`). **No mem_map mutation** is a documented contract (LLR-004.2) — the pass-through guarantee rides on it.
- UI: `screens_directionb.py::FlowBuilderPanel` (`:2075`): `#flow_kind` Select / `#flow_ref` Input / `#flow_add` / `#flow_run` / `#flow_blocks` / `#flow_result`; `render_result` (`:2187`) currently dumps text — the Pipeline-Ledger render (gutter/separators/ribbon/banner) is NEW.
- Shipped AT idiom (`tests/test_tui_directionb.py`): `App.run_test(size=…)` → `action_show_screen("flow")` → `_add_flow_block` (set Select `#flow_kind` + Input `#flow_ref`, press `#flow_add`) → press `#flow_run` Button → read `_static_plain(app, "#flow_result")` / `"#flow_blocks"`. Headless engine ATs use `run_flow(flow, FlowContext(project_dir=…))` over a real `.s19tool/workarea/<proj>/` (`tests/test_flow_execution.py`).

---

## 1. Per-requirement validation-method table

| Story / AT | HLR / LLR | What is verified | Method | Executed verification (provisional-until-Phase-3 ids) | Numeric pass threshold |
|---|---|---|---|---|---|
| **US-085** LOAD notices | ⟨fold⟩ HLR-085 | Integrity-flagged image → block `notices` + WARN text; chain continues. Unresolvable → STOP + downstream skipped. | acceptance (AT) + test (unit/integration) | `pytest tests/test_flow_execution.py -k "load_notices or load_stop"` (engine) · `pytest tests/test_tui_directionb.py -k "at_flow_load"` (pilot) | AT-085a + AT-085b both PASS; 0 regressions in `test_flow_execution.py` |
| AT-085a | ⟨fold⟩ LLR-085.x LOAD→WARN mapping | block status == `notices`; WARN finding text present; downstream block status == `ok` (ran) | acceptance (pilot + engine) | run LOAD-over-`warn.s19` flow via shipped surface; assert block status token + downstream ran | status transition observed (see §2) |
| AT-085b | ⟨fold⟩ LLR-085.x STOP mapping | unresolvable image → block `error`; downstream `skipped` | acceptance (pilot + engine) | run LOAD-over-`missing/corrupt.s19`; assert `error` + every downstream `skipped` | downstream all `skipped`, `written_paths == []` |
| **US-086** CHECK read-only + gating | ⟨fold⟩ HLR-086 | present/absent report; image passes through **byte-identical**; CHECK finding advisory (chain continues); gating marks only the block. | acceptance (AT) + test (unit/integration) | `pytest tests/test_flow_execution.py -k "check_passthrough or check_gating"` · `pytest tests/test_tui_directionb.py -k "at_flow_check"` | AT-086a + AT-086b **+ AT-086c (NEW, see §2)** PASS |
| AT-086a | ⟨fold⟩ LLR-086.x pass-through | with-CHECK output bytes == without-CHECK output bytes (re-read from disk); report counts observable | acceptance (C-12 output-then-consume) | run LOAD→CHECK→WRITE-OUT and LOAD→WRITE-OUT; `_reload_s19` BOTH written files; compare | byte-map equality across both runs |
| AT-086b | ⟨fold⟩ LLR-086.x abort-asymmetry (read-only branch) | unreadable check-doc → CHECK `error` **but** WRITE-OUT still runs, file produced, image intact | acceptance | run LOAD→CHECK(bad-doc)→WRITE-OUT; assert CHECK `error` AND WRITE-OUT `ok` AND file exists | `written_paths` non-empty despite CHECK error |
| **AT-086c (NEW)** | ⟨fold⟩ LLR-086.x gating flag | drive gating=**block** (non-default) on a FAILING check → block marked blocked **AND chain still completes** (invariant: chain never blocked) | acceptance (C-10 non-default branch) | run with `gating="block"` on a failing CHECK; assert block blocked AND downstream WRITE-OUT `ok` | downstream produced output; no chain-kill |
| **US-087** status model | ⟨fold⟩ HLR-087 | CLEAN / ISSUES(=completed-with-issues, amber) / FAILED; amber **appears in any generated report**. | acceptance (AT) + test (unit) | `pytest tests/test_flow_execution.py -k "status_rollup"` · report-artifact AT | AT-087a + AT-087b **+ AT-087c (NEW, report)** PASS |
| AT-087a | ⟨fold⟩ LLR-087.x roll-up | output+advisory → `completed-with-issues`; broken-image → `failed`; the two are **distinct tokens** | acceptance | run advisory-carrying flow vs image-breaking flow; assert `completed-with-issues` != `failed` | both tokens observed distinctly |
| AT-087b | ⟨fold⟩ LLR-087.x boundary | all-ok flow → `ok`/CLEAN (no advisories) | acceptance (boundary) | run fully-clean flow; assert `ok` | status == CLEAN token |
| **AT-087c (NEW)** | ⟨fold⟩ LLR-087.x report reflection | generated report artifact contains the `completed-with-issues`/amber outcome | acceptance (C-12 output-then-consume) | produce a report from an ISSUES run; re-read report text/artifact; grep the amber outcome | report artifact contains the ISSUES token; FAILS if silently absent |
| **US-088** Direction A UI | ⟨fold⟩ HLR-088 | vertical block-node pipeline; per-block sev-* gutter; separators; twin ribbon; CLEAN/ISSUES/FAILED banner; markup-safe. | acceptance (AT/pilot) + inspection | `pytest tests/test_tui_directionb.py -k "at_flow_ledger or at_flow_markup"` + snapshot | AT-088a + AT-088b PASS; snapshot drift → canonical-CI regen |
| AT-088a | ⟨fold⟩ LLR-088.x render | run via shipped Run → one node per block; each node's sev-* class == its status; separators = len(blocks)-1; ribbon present; banner matches run status | acceptance (C-31 derived set) | pilot: press `#flow_run`, read rendered ledger widget tree + banner | per-block node+class match (set derived from flow); banner==run status |
| AT-088b | ⟨fold⟩ LLR-088.x markup-safety (C-17) | EVERY file-derived sink on the ledger renders hostile markup literally | acceptance (C-31 sweep) | pilot: hostile strings in ref + check-doc name + notice source; assert literal in each sink | 0 markup parse / style leak on the enumerated sink set |

**Layer-A white-box (TC-NNN, `⟨fold⟩` for exact ids):** unit TCs on the LOAD `errors`→`Finding(WARN)` mapping, the CHECK read-only pass-through (mem_map identity before/after), the abort-asymmetry branch table (image-breaking vs read-only), the status roll-up truth table, and `css_class_for_severity(BLOCK_STATUS_NOTICES)`. These validate the HOW and are **not** acceptance — every story still owes its AT above.

---

## 2. AT-authoring audit (C-10 / C-12 / C-31)

Verdict legend: **STRONG** = as-worded it drives a non-default outcome and asserts observed content with a counterfactual that goes RED pre-fix. **HARDEN** = worded to pass without genuinely exercising the behavior.

### AT-085a — LOAD integrity → notices, chain continues · **HARDEN**
- **Gap (C-10):** `notices` is a non-default status, good — but as worded it can pass by asserting only "WARN text present." It must (a) assert the block status token is exactly `notices` (**not** `ok` and **not** `error`), and (b) assert a **downstream** block ran (`ok`) to prove the chain did not gate. Without (b) a bug that silently aborts after a notice still "shows the WARN text."
- **C-10 counterfactual (must go RED pre-fix):** the SAME flow over a **clean** image must yield block `ok` with **no** notices and identical downstream. Drive both; assert the status differs. (Today `run_flow` has no `notices` token at all, so the assert `status == notices` is RED pre-code — that is the correct RED.)
- **Hardened form:** seed `warn.s19` whose parser `errors` list is non-empty (bad checksum line and/or out-of-order record — derive it from what `S19File.errors` actually collects, don't assume); flow = LOAD(warn.s19)→WRITE-OUT; assert LOAD block `notices`, WARN finding text non-empty, WRITE-OUT `ok`, file on disk. Clean-image counterfactual asserts LOAD `ok`.

### AT-085b — unresolvable image → STOP, downstream skipped · **STRONG (minor note)**
- This is the **image-breaking branch** of the abort-asymmetry (owes one AT per branch; AT-086b is the read-only branch — both present). The shipped `test_run_flow_missing_source_isolates_and_writes_nothing` already asserts `error`+`skipped`+`written_paths==[]` — reuse that shape.
- **Note:** assert every downstream is explicitly `skipped` (not merely "output absent") and `written_paths == []`, so a future partial-write regression can't pass. Distinguish "unresolvable" (missing/escaping ref → already tested) from "unopenable/corrupt" (a present-but-garbage file) — the story says "unresolvable/unopenable"; add the corrupt-but-present case so STOP isn't only exercised via the containment path.

### AT-086a — CHECK read-only pass-through · **HARDEN**
- **Gap (C-12 output-then-consume):** the pass-through claim is only meaningful if the AT drives the **shipped WRITE-OUT handler**, re-reads the **actual produced file bytes**, and compares against a no-CHECK run's produced bytes. A direct `mem_map` equality check inside the engine is a white-box bypass (that's a fine TC, not the AT). The `_reload_s19(written)` idiom in `test_flow_execution.py` is exactly the right consumer re-read — apply it to BOTH runs.
- **C-10 aspect:** drive a CHECK whose report is **non-trivial** (some addresses present, some absent) so `aggregates` has non-zero `passed` AND non-zero `uncheckable`/`failed` — assert the observed counts, not just "a report exists." Derive the present/absent addresses from the seeded image ranges, not hand-picked constants that might all fall inside.
- **Hardened form:** run A = LOAD→WRITE-OUT; run B = LOAD→CHECK(mixed present/absent)→WRITE-OUT; `_reload_s19` both outputs; assert `memmap_A == memmap_B` (byte-identical pass-through) AND run B's check report shows the expected present/absent split.
- **Counterfactual RED pre-fix:** a CHECK that mutated the map would make B differ from A → RED.

### AT-086b — unreadable check-doc → CHECK error, WRITE-OUT still runs · **HARDEN**
- This is the **read-only branch** of the asymmetry and covers "block marks its own op invalid." Solid intent, but harden two ways:
- **(C-12):** assert WRITE-OUT actually produced a file **and** its bytes equal the no-CHECK output (image intact through a *failed* CHECK), not just that the WRITE-OUT block reports `ok`.
- **Scope note:** an unreadable doc is `run_check_document`'s `doc-fault`/`doc-kind` run-block path (`run_blocked_reason_code`, `model.py:750`), a DIFFERENT mechanism from the gating flag. Do not let AT-086b stand in for the gating flag — see AT-086c.

### AT-086c — gating=block on a FAILING check, chain still completes · **NEW / MISSING — highest-risk**
- **Why required (C-10 + operator R-3):** the per-block gating flag is an operator-selectable control with values `advisory` (default) | `block`. C-10 obliges an AT that drives the **non-default** value and asserts the observed marking changed. The operator flagged the advisory-vs-block distinction as "highly user-visible" with an explicit **"no hidden chain-killing"** invariant. **No named AT drives gating=block.** Without it, an implementation where gating=block silently aborts the chain would pass every current AT (AT-086a/b both run over advisory/pass-through paths).
- **Hardened form:** flow = LOAD→CHECK(gating=block, seeded to FAIL)→WRITE-OUT. Assert: (1) the CHECK block is marked blocked/errored (the block's own status flips vs the advisory default — the C-10 observed change); (2) **WRITE-OUT still runs and produces the file** (the invariant: chain never blocked); (3) contrast with gating=advisory on the same failing check → same chain outcome, different block marking. If any AT lets WRITE-OUT be `skipped` under gating=block, that is the hidden chain-kill the operator forbade — it must go RED.

### AT-087a — completed-with-issues vs failed · **HARDEN**
- **Gap (C-10 + observable distinctness):** must assert the two tokens are **distinct and correct**, driving BOTH branches in one AT: an advisory-carrying-but-output-producing run → `completed-with-issues`; an image-breaking run → `failed`. Assert `completed-with-issues != failed` explicitly (guards a roll-up bug that collapses both to `error`, which is exactly the prototype's original defect per NOTES.md fork #1).
- **Gap (C-12, the report clause is unobserved):** US-087 requires the amber outcome to "appear in any generated report." AT-087a checks the status token only. The report is a downstream **deliverable** — it needs its own output-then-consume AT (**AT-087c, NEW**): produce a report from an ISSUES run, re-read the report artifact, and grep the completed-with-issues outcome. Without it the "appears in report" requirement is not black-box observed and the story is only partially acceptance-covered (see §3).

### AT-087b — clean run → CLEAN · **STRONG (boundary)**
- Correct boundary case. Harden minimally: assert **no** advisories/notices present alongside `ok`, so a bug that stamps CLEAN while dropping real notices is caught (i.e. assert the absence, don't just assert the token).

### AT-088a — Pipeline-Ledger render · **HARDEN**
- **Gap (C-12):** must drive the **shipped Run** (press `#flow_run`, let the app call `run_flow` and hand the result to the panel) and observe the **unmodified render**. It must NOT hand-construct a `FlowRunResult` and call `render_result(...)` directly — that bypasses the producer and tests the renderer against a fiction. The pilot idiom (`test_at_flow_add_blocks_and_run_renders_result`) already presses `#flow_run` — keep that.
- **Gap (C-31 input-set-is-an-oracle):** the assertions quantify over sets and must derive them:
  - **one node per block:** node count derived from `len(flow.blocks)`, not hand-counted.
  - **separators = len(blocks) − 1:** derived, so adding a block can't silently drop a separator.
  - **each node's sev-* class == its status:** read the **actual CSS class on the node widget** (via `css_class_for_severity` of that block's status), not a text substring. Explicitly include a `notices` block so `css_class_for_severity(BLOCK_STATUS_NOTICES)` is exercised — a status with no sev-* mapping would render uncolored and this must go RED.
  - **banner matches run:** assert the banner token equals the run's flow-status token for all three of CLEAN/ISSUES/FAILED (three sub-runs), not just one.
- **Geometry caveat (project C-13/C-23/C-29, R-5):** the ribbon-cell and node-column budgets must be pilot-measured in the real boxed `#screen_flow` panel at BOTH 80×24 and the wide regime — do not inherit the HTML prototype's ~96/150-col budget. Flag as `assumed — verify in Phase 3` until measured.

### AT-088b — markup-safety on file-derived fields · **HARDEN**
- **Gap (C-31 sweep / markup-sink completeness):** the shipped `test_at_flow_block_label_markup_safe` covers only the **block ref** in `#flow_blocks`. Batch-51 adds NEW file-derived sinks that each reach the render: the **CHECK report strings** (entry names/reasons from the check doc), the **LOAD notice text** (parser diagnostics carry the file name), **written paths**, per-block **diagnostics**, and any **ribbon/banner** label that echoes file-derived content. The AT must exercise a hostile payload (`evil[red]…`, `[link=x]`, `]`, unbalanced brackets — the batch-33/43/48 class) through EACH sink and assert it renders literally, with the sink set **derived from the render code** (grep every `safe_text(...)` / dynamic-append call site in the new render path), not one hand-picked field.
- **Assert plain AND spans:** per the memory markup-sink rule, crash-only payloads are insufficient — assert the plain text is verbatim AND (where the sink is a Rich `Text`) that no style spans were injected. `[link=…]` at a `Select`/`Content` sink can raise `MarkupError` rather than inject — cover the raise path too.

---

## 3. Stories flagged NOT genuinely black-box / observable

- **US-087 — partially non-observable as worded.** The status-token half (CLEAN/ISSUES/FAILED) is fully observable on the run-result surface and the rendered banner. But the normative clause "the amber ISSUES outcome **appears in any generated report**" has **no AT that observes a report artifact**. A report is a concrete output-producing deliverable; per the Two-layer rule an output-producing requirement's AT must FAIL if the output is silently absent. **Resolution:** add **AT-087c** (generate report → re-read artifact → assert the completed-with-issues outcome present). Until then, US-087's report clause is white-box-only and must not be signed off.
- **US-085 / US-086 / US-088** are genuinely black-box: engine stories observed through the shipped Run surface (`run_flow` result and the rendered `#flow_result`/ledger), UI story observed through rendered `#screen_flow`. No internal-symbol acceptance. **Caveat:** they only stay black-box if the ATs drive the shipped Run button / `run_flow` handler and re-read produced artifacts (the C-12 hardening above) rather than calling `render_result`/reading engine internals directly.

---

## 4. Operator emphasis — US-086 per-block gating (advisory vs block)

The operator called the gating rules "highly user-visible" and forbade hidden chain-killing. Audit against that bar:

- **The advisory-vs-block distinction is NOT yet observable in the AT set.** AT-086a exercises advisory/pass-through; AT-086b exercises the block-own-op-invalid (unreadable doc) path — **neither drives the gating flag's non-default `block` value on an otherwise-runnable failing check.** The distinction that matters to the user (advisory: block goes amber/notices, chain continues; block: block goes blocked/red, chain **still** continues but the block is loudly marked) is untested.
- **No AT currently prevents a hidden chain-kill.** If gating=block were implemented to `skip` downstream, every named AT would still pass. This directly violates the operator invariant.
- **Required additions:**
  1. **AT-086c** (§2) — gating=block on a failing check → block marked blocked **AND** WRITE-OUT still runs. This is the single AT that makes "the chain is never blocked" a black-box guarantee.
  2. **AT-088a must render the gating state visibly** — the block-blocked marking must be a distinct sev-* class from advisory-notices on the ledger gutter, asserted by reading the widget class (C-31 derived), so a user can *see* the difference. If block-blocked and advisory-notices render identically, the "highly user-visible" requirement is unmet even if the engine is correct.
  3. The gating vocabulary surfaced to the user (US-086 open question) must be spec'd at fold with an explicit truth table (gating × check-outcome → block status × chain outcome) so no branch is left implicit.

---

## 5. Evidence checklist

- [✓] Acceptance criteria use observable Given/When/Then via the shipped surface — §1 table + §2 hardened forms name the driven input and observed outcome.
- [✓] Test cases have explicit Expected (status tokens, byte-equality, class match) — not vague "works".
- [✓] Edge cases: empty (clean-image counterfactual AT-085a/087b), boundary (AT-087b, geometry 80×24), invalid (unreadable check-doc AT-086b, corrupt image AT-085b), error (image-breaking vs read-only asymmetry).
- [✓] Regression checklist: `test_flow_execution.py` (4 existing engine tests) + `test_tui_directionb.py` flow ATs must stay green; new `notices`/`completed-with-issues` tokens must not perturb the OK/ERROR paths; snapshot drift on `#screen_flow` expected → canonical-CI regen (local regen FORBIDDEN).
- [✓] Exit criteria: every US has ≥1 passing AT through the shipped surface with boundary+negative evidence; AT-086c + AT-087c added; 0 engine-frozen diffs; dual traceability complete both chains.
- [✓] No real PII / secrets — all fixtures synthetic S19/JSON.
- [✓] Test results left BLANK — Phase 3 fills them; nothing here claims a run.
- [✓] Layer B black-box: every output story observed through Run surface / rendered `#screen_flow` with boundary + negative — flagged where not (US-087 report clause).
- [✓] Bidirectional surface-reachability: gating flag (input dimension) driven through the block/handler (AT-086c); the generated report (output/deliverable) observed (AT-087c) — both were the missing directions.
- [✓] No unfilled template — this artifact carries no `<...>`/`TC-NNN` placeholders except the intentional `⟨fold⟩` HLR/LLR ids the architect owns.
