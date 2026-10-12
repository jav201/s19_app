# Functionality — s19_app — Batch 2026-10-11-batch-92

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 At a glance (read first)

- **What this batch added:** Nothing user-visible. The batch is a behavior-preserving import-layer refactor; the entire functional delta is architectural: a new presentation-neutral `render/` package, three canonical addresses, 6 of 7 measured layer inversions dead, and census guards that now police the import graph.
- **Capabilities:** services consume the hex renderer from `s19_app.render.hexview` (not a `tui/` address) · the markup-safety primitive `safe_text` is served from `s19_app.utils` · `microbar` + the service style constants are served from `s19_app.render.format` · live-tree AST import censuses (TC-651..TC-655) fail on any regression of these edges, including consumers added later · every screen, report, and snapshot renders byte-identically to the pre-move capture (AT-288).
- **How to use it:** No new entry point — the app, the screens, and the reports are reached exactly as before. The only "how to use" is for maintainers: import moved symbols from their new canonical addresses (`render.hexview`, `render.format`, `utils.safe_text`).

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## Detail (reference)

### How it works (flow)

The 2026-10-11 dependency radiography (AST census of `s19_app/`, `model.json`) measured 7 layer inversions — modules in lower layers importing `tui/` presentation modules. The batch relocated the three shared primitives to presentation-neutral homes and repointed every measured consumer, in two sequential increments:

1. **Inc-A (US-92-1, US-92-2)** — `tui/hexview.py` (477 LOC, 0 classes, no Textual import) moved whole-file to `s19_app/render/hexview.py`, byte-preserving except (a) the 3 `range_index` re-export wrappers deleted (ownership stays at the frozen engine `s19_app/range_index.py`) and (b) the style-constant import block rewritten to the new in-package `render/format`, leaving **zero `s19_app.tui.*` imports** in the moved module. The 8 measured consumers (app shell, package `__init__`, screens, 3 report services) repoint to the new address. `render/format.py` was created in the same increment (closure finding N1) to own `microbar`, its glyphs, and the 5 renderer style constants — the review-found render-first import cycle (C1/C2) was killed at its root by moving the constants down, not by priming imports.
2. **Inc-B (US-92-3, US-92-4)** — `safe_text` + its private `_CONTROL_SCRUB` table moved verbatim to `s19_app/utils.py` (the C-17 markup-safety contract — scrub C0/DEL/C1, wrap literal `Text`, never `Text.from_markup` — moved with the function; ~96 internal call sites in `screens_directionb.py` became imports). `validation_service` now imports `microbar` + the palette constants from `render/format`; `tui/insight_style.py` keeps an identity-preserving 8-symbol re-export shim for the view side (`is`-identical, 8/8). The two `render/format` style strings that originate in frozen `tui/color_policy.py` are value-equal **data copies**, pinned to the frozen origins by TC-655 — the freeze is respected by data, not edits.

**Edges dead after the batch (6 of 7 measured inversions):** `load_service`/`report_service`/`diff_report_service` → `tui/hexview` · `validation_service` → `tui/insight_style` · `tui/app` + `tui/__init__` → `tui/hexview` (the `range_index` indirection) · `checks_view`/`issues_view` → `screens_directionb`. **Declared residual:** `change_service → color_policy` (US-92-5, the 7th inversion) — the operator's freeze on `tui/color_policy.py` stands; deferred to BACKLOG-CODE.md lane A.

**The guards that keep it dead:** TC-651/TC-653/TC-654 are live-tree AST import censuses — each derives its consumer set from the code at run time and asserts set-equality, so a consumer added in a future batch fails the test instead of silently re-creating an inversion (the `insight_style` shim would otherwise make a missed consumer silently green). TC-652 asserts the wrapper absence and the renderer surface. TC-655 pins the `render/format` copies value-equal to the frozen origins. AT-288 (report bytes byte-identical to the pinned pre-move capture, sha256 `061ee94c…4c39`) is the batch's byte-identity oracle.

### Components / modules touched
| Module | Role in this batch |
|--------|--------------------|
| `s19_app/render/__init__.py` | New package marker (empty of logic) — creates the render layer |
| `s19_app/render/hexview.py` | New — the relocated pure hex renderer (byte-preserving move; wrappers deleted; tui-free import block) |
| `s19_app/render/format.py` | New — presentation-neutral home of `microbar`, the glyph pair, and the 5 style constants; canonical owner of `CYAN`/`DGRAY`/`VALUE` |
| `s19_app/utils.py` | Modified — canonical home of `safe_text` + `_CONTROL_SCRUB` |
| `s19_app/tui/hexview.py` | Deleted — old address, asserted absent by TC-651 |
| `s19_app/tui/__init__.py` | Modified — wrapper names dropped (import block + `__all__`), renderer surface kept, repointed |
| `s19_app/tui/app.py` | Modified — `range_index` primitives sourced engine-direct; renderer + `safe_text` imports repointed |
| `s19_app/tui/insight_style.py` | Modified — 8-symbol identity shim to `render/format`; retains canonical ownership of the rest of the palette and its view-side helpers |
| `s19_app/tui/screens_directionb.py` | Modified — `safe_text` definition removed; ~96 internal call sites became imports |
| `s19_app/tui/screens.py` · `checks_view.py` · `issues_view.py` | Modified — hexview / `safe_text` import addresses repointed |
| `s19_app/tui/services/{load,report,diff_report,validation}_service.py` | Modified — import addresses repointed to `render.hexview` / `render.format` |
| `tests/test_render_hexview.py` · `tests/test_render_format.py` · `tests/test_import_census.py` | New — the 5 census/pin nodes TC-651…TC-655 |
| 43 existing test nodes in `test_tui_hexview.py` / `test_tui_hexview_classed.py` / `test_tui_helpers.py` (+ the report-service source-census assertion) | Repointed imports; test ids unchanged, 0 nodes deleted |

### Usage / examples

No user-facing usage changes. Maintainer-facing verification commands (all executed in the batch; the census set last re-run clean by the PR-merge qa-reviewer):

```bash
# The 5 census/pin nodes — the import graph's police force (5 passed)
python -m pytest tests/test_render_hexview.py tests/test_render_format.py tests/test_import_census.py -q

# The byte-identity oracle (1 passed; pins report bytes to the pre-move capture)
python -m pytest tests/test_report_service.py -q -k at288

# The behavioral family (AT-289/290/291 realized nodes — 7 nodes, all green)
python -m pytest tests/test_render_hexview.py tests/test_tui_issues_view.py tests/test_tui_mac_coverage.py -q

# The full-suite gate (flaky-tolerant rule over the 52-node known-unstable corpus, contract §5.2)
python -m pytest tests/ -q --tb=no -rf
```

### Diagrams

No diagrams were rendered into this record (`06-docs/diagrams/` is intentionally empty — the batch adds no new surfaces to draw). The batch's visual annex is the **2026-10-11 dependency radiography** — the AST census this batch worked from — rendered at `G:/My Drive/dev-flow-radiografia/Refactor_10_11_26/Diagramas/`:

- `s19_app_modulos.png` / `s19_app_modulos.pdf` / `s19_app_modulos.excalidraw` — the module/dependency map (measured at base `983f898`; the 7 red inversion arrows this batch attacked)
- `model.json` + `extract_model.py` + `gen_diagram.py` — the machine-readable census and its generator

The post-batch state of the edges is written, not drawn: `design/module-map-delta.md` §2 (edges killed / new allowed edges) and the **KILLED** residual rows at `docs/architecture.md:341-345`.

### Evidence checklist — docs-writer
> Attach `docs-writer`'s completed evidence checklist (items in `agents/docs-writer.md`), ✓/✗ + one-line evidence.

- [x] **Audience and purpose declared at the top of the doc** — ✓ technical stakeholder; see the header block and *At a glance*.
- [x] **Structure follows the relevant template** — ✓ the P6 `06-docs/functionality.md` seed, all sections in order, no deviation.
- [x] **Code/CLI snippets actually run** — ✓ the census/AT/gate commands were executed in the batch (`evidence/increment-00{1,2}-*.transcript`, `evidence/p4-full-suite*.txt`); the PR-merge qa-reviewer re-ran the census set 5/5 and the AT family 7/7 (`review-pr-merge-qa.md` §1).
- [x] **Assumptions listed** — ✓ the batch's premises are the contract's §2.7 evaluation (6/6 TRUE); this doc assumes them (behavior-preserving move under the operator's `color_policy.py` freeze).
- [x] **Risks / limitations called out** — ✓ declared residual `change_service → color_policy` (US-92-5); the local suite's 52-node flakiness corpus and its sharpening carry (`05-postmortem.md`).
- [x] **Next steps stated** — ✓ batch-93 (memmap2) rebases onto this tree per `COORDINATION-batch93-memmap.md`; US-92-5 awaits an explicit operator unfreeze.
- [x] **Diagrams included where flow is non-trivial** — ✓ the flow's before/after is the radiography annex cited above; no new surfaces exist to diagram (n/a — no new surface, per `04-validation.md`).
- [x] **No invented APIs / version numbers / metrics** — ✓ every address, hash, and count is sourced from `01-requirements.md`, `04-validation.md`, `05-postmortem.md`, or `design/module-map-delta.md`.
