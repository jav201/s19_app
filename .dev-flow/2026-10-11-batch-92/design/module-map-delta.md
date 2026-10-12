# Module-map DELTA — 2026-10-11-batch-92 (layer-inversion kills)

**Station:** ARQ (p1-arq) · **Agent:** architect · **Base:** rebased `410cde5` (branch `kimi/batch-92-layer-inversions`)
**Oracle under amendment:** `docs/architecture.md` (standing, batch-88-amended). This delta is a *proposal*;
per the gate rule it lands in the standing doc only after operator approval. No file outside this batch record
is modified by this station.

**Evidence states** (`/dev-flow` §Evidence states): every measurement below is `executed` — commands run in the
worktree at `410cde5` on 2026-10-11/12, citations are `file:line`. No `planned`, no `not-run` items.

---

## 0. Verdict summary

1. **One new sub-package** `s19_app/render/` (modules `hexview`, `format`) declared inside the existing
   **product** module — not as a 7th top-level module (see §6.1).
2. **Touched existing modules:** `utils`, `screens_directionb`, `insight_style`, `app`, `tui/__init__`,
   `screens`, `checks_view`, `issues_view`, `services/{load,report,diff_report,validation}_service`.
3. **Parallelisation: NOT parallelisable as cut.** `modules(Inc-A) ∩ modules(Inc-B) = {tui/app.py,
   tui/screens_directionb.py}` + 3 shared test files + the new package marker. Recommended exit: **re-cut as
   sequential** (Inc-A → Inc-B). Mechanical alternative (trunk pre-commit) recorded in §5.
4. **Residuals declared, not hidden:** `render→tui` style-constant edges (2) **killed this batch** by the
   review amendment (C1-(c)/C2, operator-ratified — `render/format` owns the 5 constants, TC-655 pins the
   copies; §6.1) and `change_service→color_policy` (US-92-5 OUT) — §6.
5. **Gate findings the map must see:** the standing doc's §7 frozen list **omits `tui/color_policy.py`** which
   this batch treats as frozen; the story-named consumer sets are **under-measured** (§7).

---

## 1. Composition — new and changed module entries

The batch-88 six-module cut stands: `product = s19_app/**`, `tests`, `tools`, `prototypes`, `flow`, `docs`.
`render/` is declared **at sub-module (file) granularity inside product** — the granularity the
parallelisation rule operates on (§5) and what the staleness check needs (§8). The re-open condition of
batch-88 rationale #1 *is* assessed here and its outcome is recorded in §6.1.

### 1.1 NEW `s19_app/render/hexview.py` (+ `s19_app/render/__init__.py` marker)

Relocates `s19_app/tui/hexview.py` (measured 477 LOC, 0 classes — AST census re-confirmed at base:
`grep -n "^class" s19_app/tui/hexview.py` → empty).

| Viewpoint | Declaration |
|---|---|
| **Encapsulates** | The pure hex-window renderer: `render_hex_view` / `render_hex_view_text`; memory-map builders `build_mem_map_s19`, `build_range_validity_s19`, `build_range_validity_hex`, `build_row_bases`; `find_string_in_mem`; layout constants `HEX_WIDTH`, `MAX_HEX_ROWS`, `MAX_HEX_BYTES`, `FOCUS_CONTEXT_ROWS`, `SEARCH_ENCODING` (current surface verified at `tui/hexview.py:27-360`, `tui/__init__.py:17-31`). |
| **Boundaries** | Pure Python + `rich.text` only. **No Textual import, no widgets, no app state** (verified: `tui/hexview.py:3-17` imports `bisect`, `typing`, `rich.text`, `..core`, `..hexfile`, `..range_index`, two `color_policy` constants, three `insight_style` constants — nothing else). Callable headless: it is the renderer the Markdown/HTML report services already consume as plain strings. |
| **EXPOSES** | The 9 functions + 5 constants above, imported by views and services directly from `s19_app.render.hexview`. No re-export chain: consumers do NOT source it via `tui/__init__` after US-92-2 (§4). |
| **Does NOT belong** | Range-membership primitives (`build_sorted_range_index` / `address_in_sorted_ranges` / `range_in_sorted_ranges` re-export wrappers at `tui/hexview.py:61-141` are **deleted**, US-92-2 — ownership stays in the engine `s19_app/range_index.py:9-79`). Severity→CSS policy (`css_class_for_severity`, stays in `tui/color_policy.py`, US-92-5 OUT). Any Textual/window/widget concern. |
| **Deps — allowed** | `rich.text`; `s19_app.core`, `s19_app.hexfile`, `s19_app.range_index`; style *constants* from `render/format` (in-package; the two `render→tui` residuals are **killed this batch**, §6.1). |
| **Deps — forbidden** | Every other `s19_app.tui.*` symbol; `textual`; `s19_app.validation`; any `tui/services/*`. (This forbidden set is the entire point of the batch: service→presentation edges die here.) |

**Rationale (structural decisions).**

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R1 | Move the file whole, byte-preserving, into a new top-level package `s19_app/render/` | Gradual copy-and-repoint (old module left as a shim) | A shim would keep the `tui.hexview` import address alive — exactly the inverted edge US-92-1 kills; and 11 test files (§5) already pin the new address by repointing. The batch is behaviour-preserving; a coexistence window adds a second source of truth for zero benefit. |
| R2 | `render/` is a package, not two flat modules dropped into `s19_app/` | Flat `s19_app/hexview.py` + `s19_app/format.py` | The two modules share one boundary rule (pure-Rich, no-Textual, service-consumable). A package states that rule once at the directory level and leaves room for the next renderer (report formatters) without another ARQ cycle. The package marker `__init__.py` is empty of logic — owned by Inc-A (§5). |
| R3 | The 5 renderer style constants get their canonical home in `render/format.py` (`CYAN`/`DGRAY`/`VALUE` move — ownership; `FOCUS_HIGHLIGHT_STYLE`/`MAC_ADDRESS_OVERLAY_STYLE` are DEFINED value-equal to the frozen copies); style *policy* may not move | Importing the constants as declared `render→tui` data residuals (the pre-amendment design) | `color_policy.py` is frozen (operator-confirmed, US-92-5 OUT) — the two style strings are data copies pinned to it by **TC-655** (equality assertion, drift fails a test), which the freeze tolerates; `insight_style` carries view-side helpers that must stay put and shims the 3 moved palette constants (R4). Kills the C1 render-first import cycle at its root. |

### 1.2 NEW `s19_app/render/format.py`

| Viewpoint | Declaration |
|---|---|
| **Encapsulates** | Presentation-neutral formatting primitives services need: `microbar` (measured `tui/insight_style.py:216-277`) + its private glyphs `MICROBAR_FILLED`/`MICROBAR_EMPTY` (`:117-118`) + the pure style constants of the `GREEN`/`LABEL`/`VALUE` kin (`:43-61`) + canonical ownership of `CYAN`/`DGRAY` (base `:57`, `:61`) + the renderer's two style strings `FOCUS_HIGHLIGHT_STYLE`/`MAC_ADDRESS_OVERLAY_STYLE` DEFINED value-equal to the frozen `tui/color_policy.py:13-14` (review amendment C1-(c), R3). |
| **Boundaries** | Pure Python + `rich.text` (verified: `microbar` body uses only `Text` + the two glyphs — `insight_style.py:264-277`). No Textual, no CSS, no tui imports. |
| **EXPOSES** | `microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE`, `CYAN`, `DGRAY`, `FOCUS_HIGHLIGHT_STYLE`, `MAC_ADDRESS_OVERLAY_STYLE`. New service consumers MUST import from here, never from `tui.insight_style`. |
| **Does NOT belong** | The view-side helpers that stay in `insight_style`: `human_bytes`, `label_value`, `threshold_style`, `cap_gauge_style` (measured `:124`, `:175`, `:280`, `:322`) and the rest of the palette (`YELLOW/RED/HILITE/LBLUE/PURPLE/MAGENTA`, `DEPTH_*`). |
| **Deps — allowed** | `rich.text` only. |
| **Deps — forbidden** | `s19_app.tui.*`, `textual`, engine, services. |

**Rationale.**

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R4 | Canonical ownership of the 8 service/renderer constants (`microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE`, `CYAN`, `DGRAY`) moves to `render/format.py`; `insight_style` keeps a **re-export shim** for exactly those 8 | Full repoint of all 7 view consumers (`app`, `checks_view`, `issues_view`, `crc_designer_view`, `json_highlight`, `screens_directionb` — measured §7.2) | The increment file budget (≤5 files) and behaviour-preservation: a shim repoints exactly one service edge (`validation_service`) while the view surface is untouched — 0 snapshot risk. Asymmetry with US-92-2 is deliberate and declared: US-92-2 deletes *engine* re-exports (addressing correctness), R4 keeps a *presentation* shim (cosmetic convenience), and the shim's consumer rule ("services use render/format") is written here so it is not mistaken for an edge to "fix". The two `color_policy` style strings are NOT shimmed — `tui` keeps sourcing them from `color_policy` (frozen, canonical-for-tui); only `render/format` carries the pinned copies (R3, TC-655). |
| R5 | `microbar` moves **with** its glyphs and the service-needed constants as one unit | Splitting constants into a third module | `microbar`'s contract includes the glyph pair (`:117-118`); splitting them creates a dependency between two tiny modules to save nothing. One module, one boundary rule (R2). |

### 1.3 CHANGED `s19_app/utils.py`

| Viewpoint | Declaration |
|---|---|
| **Encapsulates** | (existing) `format_bytes`, `is_printable`, `safe_decode` — verified `utils.py:1-27`. **Gains `safe_text`** moved from `screens_directionb.py:881`, together with its private byte-class table `_CONTROL_SCRUB` (`screens_directionb.py:878`, C0/DEL/C1 class — the normative, load-bearing shape per the `:869-877` comment). |
| **Boundaries** | stdlib + `rich.text` only. **No Textual.** Stays importable from any layer (currently only `tui/*` consumes it; the address is presentation-neutral by construction). |
| **EXPOSES** | `safe_text(value, style="") -> Text` as the **canonical markup-/control-safety primitive** (security contract §3). |
| **Does NOT belong** | Any screen/widget logic; `safe_text`'s previous address is retired — `screens_directionb` becomes a consumer like everyone else. |
| **Deps — allowed / forbidden** | allowed: `rich.text`; forbidden: `s19_app.tui.*`, `textual`. |

**Rationale.**

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R6 | Canonical home is the app-root `utils.py`, not `render/` | Putting `safe_text` in `render/format.py` | `safe_text` is a *safety* primitive (C-17/B-1, §3), not a formatter: `checks_view`/`issues_view` consume it as a security sink, and a future non-render consumer must not drag presentation deps in. Root `utils` is the address with zero layer meaning. |
| R7 | `_CONTROL_SCRUB` moves **with** the function, private | Leaving the table in `screens_directionb` as an import | The table is safe_text's single-use private dependency (`:936`); a cross-module constant import for it recreates the very `screens_directionb`-coupling US-92-3 removes. |

### 1.4 CHANGED `s19_app/tui/insight_style.py`

Keeps: the retained palette (`YELLOW/RED/HILITE/LBLUE/PURPLE/MAGENTA`), `DEPTH_*`, `human_bytes`, `label_value`, `threshold_style`, `cap_gauge_style`
(verified `:43-367`). **Loses canonical ownership** of `microbar` + `MICROBAR_*` + `GREEN`/`LABEL`/`VALUE` + `CYAN`/`DGRAY`
(→ `render/format.py`, R4); **gains a re-export shim** for exactly those 8 symbols so the view consumers
(`app.py:85`, `checks_view.py:40`, `issues_view.py:39`, `crc_designer_view.py:81`, `json_highlight.py:82`,
`screens_directionb.py:90` — all measured) are untouched. New edge `insight_style → render/format` is
**allowed and declared**: presentation consuming presentation-neutral primitives is the permitted direction.
Forbidden (unchanged): Textual, engine internals beyond existing use.

### 1.5 CHANGED `s19_app/tui/screens_directionb.py`

Loses `safe_text` + `_CONTROL_SCRUB` (→ `utils.py`, R6/R7); becomes their consumer. Gains nothing.
Its other surfaces (screens, panels, the lazy `hexview` imports at `:3336`/`:7581` repointed by Inc-A) are
unchanged in ownership. Remains the Direction-B screen shell; still does not own engine primitives
(already imports `range_index` directly at `:107` — the posture US-92-2 generalises).

### 1.6 CHANGED consumers (repoint-only, no ownership change)

| Module | Change | Evidence |
|---|---|---|
| `tui/app.py` | hexview import (`:37-42`) → `render.hexview`; range_index wrappers (`:38-40`) → direct `range_index`; `safe_text` (`:66-79`) → `utils` | measured, §7.2 |
| `tui/__init__.py` | drops the 3 range_index wrappers (`:23-30`, `:81-95`); renderer re-export surface preserved, sourced from `render.hexview` | measured |
| `tui/screens.py` | hexview import (`:34`) → `render.hexview` | measured — **not named in US-92-1's story text** |
| `tui/checks_view.py`, `tui/issues_view.py` | `safe_text` (`:41` / `:40`) → `utils` | measured |
| `services/load_service.py` (`:8`), `services/report_service.py` (`:58`), `services/diff_report_service.py` (`:96`) | hexview imports → `render.hexview` | measured |
| `services/validation_service.py` (`:17`) | `GREEN, LABEL, VALUE, microbar` → `render.format` | measured |

### 1.7 RETIRED path

`s19_app/tui/hexview.py` — deleted by Inc-A. Declared here so no reader of the standing doc (whose §1–§9
prose still walks the old tree) mistakes it for drift, and so the post-batch staleness sweep keys correctly.

---

## 2. Dependency — allowed/forbidden edges (the batch's product)

**Edges killed (6 of 7 measured at intake):**

- `services/load_service → tui/hexview` · `services/report_service → tui/hexview` · `services/diff_report_service → tui/hexview`
- `services/validation_service → tui/insight_style`
- `tui/app → tui/hexview` (range_index indirection) · `tui/__init__ → tui/hexview` (wrapper chain) — via US-92-2's direct-to-engine rule
- `checks_view/issues_view → screens_directionb` (the safe_text edge)

**New edges (allowed, declared):** `services/* → render.hexview` · `services/validation_service → render.format`
· `views → render.hexview`/`render.format` · `insight_style → render/format` (shim, R4) · `any layer → utils.safe_text`.

**Residuals:** see §6 (declared, not hidden).

---

## 3. Interface — exposed contracts

1. **`render.hexview` surface** (9 fns + 5 constants, §1.1) is consumed as plain data (`Text`/`str`) by both
   views and report emitters. Changing a name/signature is trigger A3 — it is never done inside a lane.
   **Frozen for this batch at PDR** once Inc-A lands; Inc-B must not touch it.
2. **`render.format` surface** (`microbar`, glyphs, 3 constants) — same rule, frozen at PDR after Inc-B.
3. **`utils.safe_text` contract** (security, context viewpoint feeding the security family): delete every
   C0/DEL/C1 codepoint (`_CONTROL_SCRUB`, LLR-116.7), wrap remainder as literal `Text` — never
   `Text.from_markup` (C-17). The batch-77 precedent (`screens_directionb.py:897-902`) stands: the move must
   not weaken or split the two halves. Hostile-input acceptance tests (`tests/test_tui_hostile_map.py`,
   `test_tui_checks_view.py`, `test_tui_issues_view.py` — all in the Inc-B test set) are the regression oracle.
4. **`tui/__init__` re-export surface**: the 3 range_index names are **removed** (US-92-2, breaking-by-design,
   consumer set fully enumerated §5); the renderer names stay, repointed.

---

## 4. Context — frozen engine and what this batch does NOT touch

Unchanged from standing §7: `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`,
`tui/mac.py` — read-only consumers only. **`tui/color_policy.py` is frozen by this batch's premise**
(operator-confirmed 2026-10-11, US-92-5 OUT) but is **absent from the standing doc's §7 list — a map gap,
finding F-1 (§7)**; the post-gate doc amendment adds it.

US-92-5 **no-op declaration (with evidence):** `css_class_for_severity` stays at
`tui/color_policy.py:16-19`; no map entry for it changes this batch. Evidence: freeze premise re-measured at
base (`grep -n "css_class_for_severity" s19_app/tui/color_policy.py` → `:19`; sole service consumer
`services/change_service.py:66`); requirements ledger US-92-5 = OUT (operator quote recorded). The surviving
`change_service → color_policy` edge is a **declared residual** (§6), not an oversight.

---

## 5. Parallelisation verdict (mechanical rule, p1-arq §12)

Touch sets, measured from the import graph at `410cde5` (product files; `tests/**` handled per §6.2):

```
Inc-A (US-92-1+2, and the format module creation — closure finding N1):
  NEW s19_app/render/__init__.py          NEW s19_app/render/hexview.py
  NEW s19_app/render/format.py            DEL s19_app/tui/hexview.py
  tui/app.py  tui/__init__.py  tui/screens.py  tui/screens_directionb.py
  tui/services/load_service.py  tui/services/report_service.py  tui/services/diff_report_service.py
  tests: test_report_field_census  test_report_service  test_tui_commandbar  test_tui_diff_screen
         test_tui_directionb  test_tui_goto_marker  test_tui_hexview  test_tui_hexview_classed
         test_tui_operations_view  test_tui_search_pagination  test_tui_workspace_layout

Inc-B (US-92-3+4 — safe_text, the insight_style shim, and the service/view repoints):
  s19_app/utils.py  tui/screens_directionb.py  tui/insight_style.py
  tui/checks_view.py  tui/issues_view.py  tui/services/validation_service.py  tui/app.py
  tests: test_a2l_multiline_headers  test_flow_builder_render  test_tui_a2l_detail
         test_tui_a2l_issue_recolor  test_tui_checks_screen  test_tui_checks_view
         test_tui_directionb  test_tui_hostile_map  test_tui_issues_view  test_tui_patch_big
         (+ insight_style importers: test_tui_directionb  test_tui_hexview_classed  test_tui_issues_view
           test_tui_patch_checks_strip  test_tui_patch_glyphs  test_tui_patch_history_strip
           test_tui_patch_json  test_tui_snapshot  test_tui_theme  test_tui_insight_style)
```

`modules(Inc-A) ∩ modules(Inc-B)` (file granularity):

- **product: `tui/app.py`** — A repoints its hexview/range_index header (`:37-42`), B repoints `safe_text`
  (`:66-79`). *The story texts name neither fully:* US-92-1 omits `app.py`'s wrapper imports, US-92-3 omits
  `app.py` as a safe_text consumer (finding F-2).
- **product: `tui/screens_directionb.py`** — A repoints its two lazy `hexview` imports (`:3336`, `:7581`;
  US-92-1's story names only the 3 services — finding F-2); B removes `safe_text`/`_CONTROL_SCRUB`.
- **tests:** `test_tui_directionb.py`, `test_tui_hexview_classed.py`, `test_tui_issues_view.py` appear in
  both lanes' import-repoint sets.
- **new package marker** `s19_app/render/__init__.py` — both lanes create files in a directory that does not
  yet exist; marker ownership must be assigned or the branches collide (add/add).

**Intersection ≠ ∅ ⇒ NOT parallelisable as cut.** Exactly two exits exist per the rule:

- **Exit 1 — re-cut the increments (RECOMMENDED): run Inc-A then Inc-B sequentially.** One agent, one batch;
  A creates the package scaffolding (including the `__init__.py` marker), B drops `format.py` into the
  existing package. No third review packet, no trunk commit, zero merge surface. Cost: the lanes' wall-clock
  concurrency is forfeited — which buys nothing here since both lanes are repoint-mechanical and capped at
  ≤5 product files each.
- **Exit 2 — move the module boundary in ARQ:** examined and **rejected as inapplicable**: the intersection
  is two single files whose import headers both lanes edit at *disjoint line ranges*; no module split can
  turn "two lanes edit app.py" into disjoint file sets short of splitting `app.py` itself — which is not a
  boundary move but a refactor the batch's behaviour-preserving acceptance forbids. (A variant — a trunk
  pre-commit performing all four repoints in `app.py` + both in `screens_directionb.py` before the lanes
  fork — is a legitimate re-cut if the operator wants concurrency; it adds one ≤2-file trunk commit and
  reclassifies those two files as pre-step, leaving the lane sets disjoint. Recorded, not recommended.)

---

## 6. Declared residuals and deferred decisions

### 6.1 Residual dependency edges (declared, not hidden)

| Edge | Symbols | Disposition |
|---|---|---|
| `render/hexview → tui/color_policy` | `FOCUS_HIGHLIGHT_STYLE`, `MAC_ADDRESS_OVERLAY_STYLE` | **KILLED this batch** (review C1-(c), operator-ratified 2026-10-12): `render/format` DEFINES both, value-equal to the frozen `color_policy.py:13-14` (`"bold yellow"` / `"bold orange3"`). `color_policy` remains canonical-for-tui; the copies are pinned to it by **TC-655** (equality assertion) — drift fails a test. |
| `render/hexview → tui/insight_style` | `CYAN`, `DGRAY`, `VALUE` | **KILLED this batch** (review C1-(c)/C2): the moved `render/hexview.py`'s import block rewrites to `from .format import CYAN, DGRAY, VALUE, FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE` — **zero `s19_app.tui.*` imports**. `CYAN`/`DGRAY`/`VALUE` take canonical ownership in `render/format`; `insight_style` shims them (R4 extended, §1.4). |
| `services/change_service → tui/color_policy` | `css_class_for_severity` | US-92-5 OUT (operator freeze). The 7th measured inversion; deferred to BACKLOG-CODE.md lane A. |
| `tui/insight_style → render/format` | shim re-exports | **New, deliberate** (R4). Not an inversion — presentation→presentation-neutral is the allowed direction. Declared so a future dependency radiography does not "fix" it. |

### 6.2 Deferred: the `tests/**` single-module cut (batch-88 rationale #3)

Batch-88 kept `tests/**` as one module, with re-open condition *"when a lane plan needs test file sets to be
disjoint by layer"*. **This batch's ARQ is that trigger**: §5 shows even the sequential verdict depends on
file-level test sets (`test_tui_directionb.py` etc. are in both lanes' repoint sets — harmless sequential,
fatal parallel). For this batch the parallelisation rule is applied at file granularity inside `tests/**`
(rationale #3's letter honoured, its spirit — nothing mechanically reads the split today — preserved: the
staleness checker's prefix classification is untouched). A permanent sub-split of `tests/**` is **deferred as
flow input**; the §5 sequential verdict does not depend on it.

### 6.3 Not taken: `render/` as a 7th top-level module

Carving `s19_app/render/**` out of `product` would make the two prefixes overlap; batch-88 rationale #1 calls
overlapping prefixes *a defect of the document*, and the staleness checker's `startswith(prefix + "/")` rule
cannot express a hole in `s19_app/**` (same expressive limit as the root-file `setup.py` case, registered in
the standing doc §10). **Decision:** keep six modules; declare `render/` at sub-module granularity (§1).
**Flow input registered:** the checker rule should either admit exclusion patterns or state that sub-package
carve-outs are expressed as in-product declarations; otherwise a future genuinely-independent render
interface silently reads as *stale map*.

---

## 7. Findings the gate must see (map vs real tree at `410cde5`)

- **F-1 — the standing map under-declares the freeze.** `docs/architecture.md` §7 (lines 140-145) lists six
  frozen engine modules; **`tui/color_policy.py` is not among them**, while this batch's premise (and the
  operator's 2026-11 ruling recorded in `01-requirements.md` US-92-5) freezes it. Not a contradiction of the
  code — of the oracle. The post-gate doc amendment adds `color_policy` to §7 and notes the batch-92 freeze.
- **F-2 — story-named consumer sets are under-measured (measured, not inferred).** US-92-1 names 3 service
  consumers; the real hexview consumer set also includes `tui/app.py:37`, `tui/screens.py:34`,
  `tui/screens_directionb.py:3336,7581`, `tui/__init__.py:17`. US-92-2 names `app.py` + `tui/__init__`.
  US-92-3 names `checks_view` + `issues_view`; the real `safe_text` consumer set also includes `tui/app.py:79`
  (and `screens_directionb`'s ~80 internal call sites become consumer imports). The ledger's TC plan must
  cover the measured sets; §5's parallelisation verdict already uses them.
- **F-3 — no count drift.** Standing §8 says "roughly 2760 tests"; base collects **2765** (intake-measured,
  `01-requirements.md` RC-1 row: `--co` → 2765, 0 errors). "Roughly" absorbs the delta; no amendment needed.
- **F-4 — tree otherwise matches the map.** `render/` does not exist at base (no orphan/stale flag); §1's
  layer table, §3's package inventories, and §11's three frozen Part B contracts are consistent with the tree
  as far as this batch's scope reads them (engine rows verified by path presence; Part B rows untouched by
  this batch — no screen-layout change).

---

## 8. Checkable paths — full touch list (staleness oracle)

Every file this batch touches, classified against the standing map's declared prefixes. All product paths
verify `startswith("s19_app/")` → module **product**; all test paths → **tests**; this record → **flow**.
No touched file falls under an undeclared module; the only *new* paths (`s19_app/render/__init__.py`,
`s19_app/render/hexview.py`, `s19_app/render/format.py`) classify under the existing `s19_app/**` prefix —
**no checker rule change is required for this batch** (the §6.3/§6.2 flows inputs are for future structure,
not this one).

- `s19_app/render/__init__.py` · `s19_app/render/hexview.py` · `s19_app/render/format.py` *(new)*
- `s19_app/tui/hexview.py` *(deleted)*
- `s19_app/utils.py`
- `s19_app/tui/app.py` · `s19_app/tui/__init__.py` · `s19_app/tui/screens.py` · `s19_app/tui/screens_directionb.py`
  · `s19_app/tui/insight_style.py` · `s19_app/tui/checks_view.py` · `s19_app/tui/issues_view.py`
- `s19_app/tui/services/load_service.py` · `…/report_service.py` · `…/diff_report_service.py` · `…/validation_service.py`
- tests (Inc-A, 11): listed §5 · tests (Inc-B, 20): listed §5 · snapshots: none expected to change
  (repoint-only; acceptance = byte-identical per intake).

---

## 9. Evidence checklist (architect role)

- [x] Constraints stated: behaviour-preserving (intake RC-1) · engine freeze incl. `color_policy` (operator, executed) · ≤5-file increments (flow, standing) · 0 new failures / byte-identical snapshots (intake). *n/a — cost/latency: pure code-motion batch, no runtime dimension.* *n/a — privacy: no user-data handling changes (the security primitive moves address, contract §3).*
- [x] Alternatives: real decisions existed at R1–R7 and §5 exit choice — each has its rejected alternative and re-open condition. No fabricated options.
- [x] Rationale tied to constraints: every structural decision table names its driver.
- [x] Risks: merge/staleness (F-2 under-measured consumer sets → TC gaps), snapshot drift if a repoint changes import-time behaviour (mitigation: repoint-only discipline + full suite), shim permanence (R4 consumer rule), checker expressiveness (§6.3).
- [x] Diagram: n/a — the batch moves no runtime flow, only import edges; the §5 touch-set blocks are the mechanical picture.
- [x] What would change the recommendation: sequential→parallel re-cut via trunk pre-commit (§5 Exit 2 variant) if the operator wants concurrency; render-carve-out (§6.3) if render/ acquires a non-product consumer.
- [x] Two-layer requirements: n/a at ARQ — this station amends the map the requirements derive from; AT blocks live in `01-requirements.md` (verified present, US-92-1..4 each carry Functionality + out-of-scope).
