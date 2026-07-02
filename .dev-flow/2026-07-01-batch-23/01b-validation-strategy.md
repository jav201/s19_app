# 01b — Validation Strategy — 2026-07-01-batch-23 (US-028)

> **Scope:** validation method per requirement area + AT/TC authoring plan for US-028
> (inline variant dropdown in `#patch_pane_variant`). Provisional black-box ids are
> namespaced **AT-035\*** (V-5); white-box ids **TC-035.\***. Authored shift-left at
> Phase 1 against §2.5/§2.6 of `01-requirements.md` (HLR/LLR ids to be bound by the
> architect's §3/§4 — this artifact maps to AC-1/AC-2/AC-3 and will be re-keyed at
> Phase 2 review if HLR numbering differs).
>
> Author: qa-reviewer · Status: **plan** (no tests run — results columns intentionally absent).
>
> **ORCHESTRATOR RECONCILIATION NOTE (2026-07-01, Phase-1 assembly):** the canonical
> TC numbering is the architect's §4 LLR-aligned mapping (TC-035.N ↔ LLR-035.N:
> .1 compose · .2 geometry · .3 options/preselect · .4 routing/guards · .5 disabled ·
> .6 no-write). Where this file's §3 TC numbering differs, read its AREAS as
> authoritative test content and its NUMBERS as superseded. The two unnumbered areas
> fold in: snapshot-only-if-CSS-changes → M-10 / LLR-035.2 note; regression set →
> §5.3 batch criteria (M-7/M-8). AT-035a/b/c ids agree in both artifacts. All ids
> remain provisional per V-5.

---

## 1. Method table (per requirement area)

| # | Requirement area | Method | Justification |
|---|---|---|---|
| M-1 | AC-1 switch-through-surface (label + image content) | **test** (Layer B, Pilot e2e) | User-observable behavior; automatable under the existing sync-wrapper Pilot idiom. |
| M-2 | AC-2 persist-on-save → load consumes (C-12 chain) | **test** (Layer B, Pilot e2e + disk re-read) | Output-then-consume: only a test over the handler-written `project.json` is counterfactual. |
| M-3 | AC-3 empty/degenerate state (Q1: disabled + placeholder) | **test** (Layer B) | Disabled-state + no-crash is directly observable on the widget. |
| M-4 | Options-refresh correctness (set, order) | **test** (Layer A) | Deterministic ordering contract `(name.lower(), name)`; cheap widget-state assert. |
| M-5 | `Select.Changed` routing guards (BLANK / unknown / cancel-equivalent) | **test** (Layer A) | Reuses `_handle_select_variant` guard behavior (`app.py:2997`); each guard branch is assertable. |
| M-6 | Composition order + pane geometry (select group ABOVE `#patch_execute_row`; pane ~35×3 @80×24) | **test** (Layer A, geometry capture) | C-13 says *measure, don't assume* — extend the `_drive_panes` capture (`tests/test_tui_patch_layout.py:44`). Arithmetic-only justification is not accepted for this pane (flagged `assumed` in §2.6). |
| M-7 | Engine-frozen set untouched | **test** (existing) | `tests/test_engine_unchanged.py` `_ENGINE_PATHS` guard already automates this; no new artifact. |
| M-8 | No new parse call sites / thread contract | **test** (existing) | `tests/test_tui_variants.py:172` `test_no_new_parse_loaded_file_call_sites` (AST probe) already guards it; regression-only. |
| M-9 | Docstring/type-hint/REQUIREMENTS traceability conventions | **inspection** | Not behavior; reviewed at the Phase 2/4 gates against PROJECT_RULES.md. |
| M-10 | SVG snapshot of the modified pane (only if `styles.tcss` changes) | **test** (CI-locked, xfail-until-baseline) | Batch-22 precedent: baselines regenerate only in the canonical CI env — never fabricate a local pass. Behavioral proof stays with M-6, not the snapshot. |

Everything behavioral is `test`; the only `inspection` rows are documentation conventions.

---

## 2. Layer B — black-box acceptance tests (provisional AT-035\*)

House black-box definition for this suite (Textual has no external driver): **drive**
via actions/widget interactions a user could perform; **observe** via rendered widget
text, screen state, and on-disk artifacts. Gate assertions must not read service-layer
or private-attribute state (`app._variant_set`, `app._change_service`, …) — those may
appear only as secondary diagnostics, never as the pass/fail condition.
**Drive-level exception (Phase-2 qa MINOR-5, acknowledged):** private-method DRIVES
(`_handle_save_dialog(SaveProjectPayload(...))`, `_handle_load_project(...)`) are the
ratified house idiom one step below the modals (`tests/test_tui_manifest_save.py:114-118`)
— the payload is exactly what the modal dismisses with. The ban above applies to
ASSERTS, not drives; do not retro-tighten it against these gates.

### AT-035a — Switch through the shipped Select (AC-1) — GATE

**Drive:** fresh `S19TuiApp(base_dir=tmp_path)`; build project `proj` with `a.s19` =
`S19_A` (bytes `01 02 03 04` @ `0x1000`) and `b.s19` = `S19_B` (bytes `0A 0B 0C 0D` @
`0x2000`) — the existing constants at `tests/test_tui_variants.py:54-55` are already
**distinguishable at both the address and byte level**; do not invent new fixtures.
`_handle_load_project("proj")` → `_flush` (activates default `a`, 1/2) →
`action_show_screen("patch")` → set the new variant Select's `.value = "b"` (the
US-026 idiom, `tests/test_tui_patch_editor_v2.py:1434` — a value assignment posts
`Select.Changed` through the real handler chain) → `await app.workers.wait_for_complete()`
+ `_flush` (the switch rides the threaded load pipeline).

**C-10 discipline:** the chosen variant is **`b`, the NON-default** (default after load
is `a` by deterministic order). Asserting the default would be vacuous — and Textual's
`Select` does not emit `Changed` when the value is unchanged (VERIFIED 2026-07-01 vs
installed textual 8.2.5: `value: var[...] = var(NULL, init=False)` with no
`always_update`, `_select.py:362`; watcher fires only on change `:600-617` — Phase-2
F-1, version-pinned), so a same-value "switch" physically cannot exercise the route.

**Observables (exact asserts):**
1. Project label (rendered `#cmdbar_project` text via the `_project_label` helper,
   `tests/test_tui_variants.py:76`) contains `proj:b (2/2)`.
2. **Content-level:** the rendered hex view text contains the `0x2000` row with
   `0A 0B 0C 0D` and does NOT contain the `0x1000`/`01 02 03 04` row — proving the
   *loaded image* is variant b's bytes, not merely a relabel. **R-1 RESOLVED (Phase-2):**
   the label needs NO navigation (`CommandBar` is app-persistent, `#command_bar_slot`
   sibling of `#workspace_body`, `app.py:1014-1017`); the hex view IS on the workspace
   screen → exact step: after `wait_for_complete()` + `_flush`, do
   `app.action_show_screen("workspace")` → `_flush` → read
   `str(app.query_one("#hex_view", Static).content)` (idiom of
   `tests/test_tui_directionb.py:1098`). Legitimate user navigation.

**Boundary/negative folded in:** 2-variant project is the minimum meaningful N; the
N=3 ordering and duplicate-stem-id cases are Layer A (TC-035.1) — the AT stays minimal.

**Counterfactual (RED pre-implementation):** the Select widget id does not exist →
`query_one` raises → RED. Post-implementation revert (drop the `Select.Changed` route):
label stays `proj:a (1/2)` and the hex view still shows the `0x1000` row → RED.

### AT-035b — Persist-on-save, output-then-consume (AC-2, C-12) — GATE

**Drive (full chain, one test):**
1. Same setup as AT-035a through the dropdown switch to `b` (workers complete).
2. Drive the **shipped save flow**: `app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="proj"))`
   → `_flush` — the exact idiom of `tests/test_tui_manifest_save.py:114-118`.
3. **Re-read the HANDLER-WRITTEN `project.json` from disk** with `json.loads` (raw
   file read, not the writer's own oracle): assert `payload["active_variant"] == "b"`.
4. **Consume:** a *fresh* `S19TuiApp(base_dir=tmp_path)` instance (unmodified load
   path), `_handle_load_project("proj")` → `_flush` → assert the rendered label reads
   `proj:b (2/2)` (variant b activated by the manifest, not by deterministic order —
   `a` sorts first, so a load that ignores the manifest observably lands on `a`).

**C-12 note — gate vs guard:** the direct-write-then-load variant of this test
**already exists** as `tests/test_variant_execution.py:173`
`test_load_project_honors_manifest_active_variant` (hand-written `project.json` with
`active_variant: "b"`). That test is the consumer-contract **GUARD** — keep it, do not
duplicate it, and never promote it to the gate: it stays green under a reverted
dropdown/save handler, so it has no counterfactual power for US-028.

**Counterfactual (RED pre-implementation / on revert):** with the dropdown route
absent or reverted, the in-memory active id at save time is still `a` → the
handler-written manifest carries `active_variant == "a"` → assert 3 fails RED (and the
fresh-load label reads `proj:a`). The existing writer path (`manifest_writer.py:319`)
is NOT under test here — what is under test is that the *dropdown switch* is the state
the shipped save serializes.

**Boundary:** save is driven exactly once, after the switch — no pre-switch save
(would mask a stale-state bug by overwriting).

### AT-035c — Negative / empty state (AC-3, Q1 resolved: disabled + placeholder) — GATE

Two sub-cases, one test file section:

**(i) No project loaded:** fresh app, `action_show_screen("patch")` → the variant
Select **exists**, `select.disabled is True`, `select.value is Select.NULL` (rendered
placeholder — no false affordance); the screen renders without exception and remains
navigable (a subsequent `action_show_screen` round-trip succeeds).

**(ii) Single-variant project:** `_make_project` with only `a.s19`, load it, open the
patch screen → Select disabled + placeholder; the loaded state is **intact**: rendered
label still shows the plain `proj` form (N==1 back-compat label pinned by
`tests/test_tui_variants.py:259`), and the hex content for `a` is still rendered.

**Do NOT** programmatically assign `select.value` in the disabled cases — that bypasses
the disabled state and tests nothing a user can do. The disabled flag + placeholder +
intact-state observation IS the black-box assert.

**Counterfactual:** pre-implementation the widget is absent → RED. If implemented
always-enabled (Q1 violated), `disabled is True` fails → RED. If the empty-state
options-refresh crashes on `variant_set is None`, the run itself goes RED.

---

## 3. Layer A — white-box TC plan (TC-035.\*)

> **Renumbered to the CANONICAL LLR-aligned ids at Phase-2 (qa MAJOR-1 + F-7 fold):**
> TC-035.N ↔ LLR-035.N. The compose-presence and no-write rows (canonical .1/.6) were
> missing from the original plan and are added here (content = §4's already-specified
> thresholds). Snapshot + regression areas are unnumbered (M-10 / §5.3).

| ID | Area | Plan | Counterfactual |
|---|---|---|---|
| TC-035.1 | Compose presence (LLR-035.1) | Bare panel construction + app with no project + app with a project: `query_one("#patch_variant_select", Select)` inside `#patch_pane_variant` returns exactly 1 widget in every case; constructed `allow_blank=True`, placeholder prompt, `disabled=True` first paint; no existing `patch_*` id renamed/removed. | Widget absent pre-impl → query raises → RED. |
| TC-035.2 | Composition + geometry (LLR-035.2, C-13) | Extend the `_drive_panes`-style capture (`tests/test_tui_patch_layout.py:44`): inside `#patch_pane_variant`, the group's `region.y` < `#patch_execute_row.region.y` (select group ABOVE the buttons); the Select's FIRST row (`region.y`) lies within the pane's visible `content_region` at scroll 0 (tightened per qa MINOR-3); no right-edge clip. Run at 80×24 and 120×30 like AT-033a/b — this MEASURES the ~35×3 budget instead of trusting it. | Compose the group below the row, or overflow → geometry asserts RED. |
| TC-035.3 | Options-refresh + preselection (LLR-035.3) | On patch-screen show with a 3-variant project (`zeta.s19`, `Alpha.s19`, `mid.s19` — the ordering trio of `tests/test_workspace_variants.py:39`), the Select options equal the variant-id list in `(name.lower(), name)` order per `build_variant_set`, and `Select.value == active_id`; N==1 / no-project → options empty + value `Select.NULL` (F-2: NO single-id preselection); re-evaluation fires on BOTH triggers (patch-screen activation AND variant-set change while shown — F-3); duplicate-stem case: ids are FULL FILENAMES (`tests/test_tui_variants.py:376`). Note F-4: repopulate emits `Changed(Select.NULL)`+`Changed(active_id)` — set_options strictly before value assignment. | Drop the options-population call → empty/stale option set → RED; N==1 preselected id → RED. |
| TC-035.4 | `Select.Changed` routing guards (LLR-035.4) | The route must inherit `_handle_select_variant`'s guards (`app.py:2997`): `Select.NULL`/`None` value → no-op (no load spawned, no status error); same-as-active → no activation (echo-loop suppression — absorbs the F-4 repopulate pair); unknown/stale id → warning + no crash + active variant unchanged; missing file → existing guard path. Assert no worker is spawned on the no-op branches. | Route raw values without the guard → BLANK triggers a bogus load or an exception → RED. |
| TC-035.5 | Disabled-state logic (LLR-035.5, Q1) | State table: no project → disabled+BLANK; N==1 → disabled; N≥2 → enabled; after switching projects the state re-evaluates (trigger owned by LLR-035.3 per F-3). | Invert/omit the N<2 branch → RED. |
| TC-035.6 | No-write / Q2 invariant (LLR-035.6) | Capture `project.json` bytes (or its ABSENCE for a never-saved project) pre-switch; dropdown-switch WITHOUT save; assert bytes identical / file still absent (0 bytes changed, 0 files created); cross-check `manifest_writer` call-site count vs `main` unchanged. Positive persist chain = AT-035b (the gate). | An Option-C-style write-on-switch → bytes differ / file appears → RED. |
| TC-035.7 | Switch-during-load race (LLR-035.7, security F2) | Rapid A→B double pick (second pick while the first load is in flight); after `wait_for_complete()` + `_flush`: final label id == rendered content's variant; **0 files created in the project dir** (no phantom `«stem»_1.s19`); `active_id` ∈ original variant set; 0 exceptions. Also covers re-picking the in-flight id (stale-active short-circuit). | Unguarded single-slot stamp → mislabeled state or phantom project-dir copy → RED. |
| — (M-10) | CSS/snapshot (conditional) | Only if `styles.tcss` changes: SVG snapshot cells at 80×24 + 120×30, **xfail-until-baseline** (batch-22 US-031 precedent; baselines only from the canonical CI env — never regenerate locally). | N/A — snapshot is a lock, not the behavioral proof (that is TC-035.2). |
| — (§5.3) | Regression (existing tests, no new code) | Must stay green: `test_no_new_parse_loaded_file_call_sites` (tests/test_tui_variants.py:172 — the dropdown adds ZERO parse call sites), `test_select_variant_updates_label` (:123 — the modal surface is unchanged), `tests/test_engine_unchanged.py` (frozen set), AT-033a/b pane geometry (tests/test_tui_patch_layout.py — the 2×2 grid survives the added group; Phase-2 census: pane regions are fixed 1fr grid cells, inner group cannot move them). | — |

---

## 4. Fixture / helper reuse map (do not invent new builders)

| Reuse | Where | For |
|---|---|---|
| `S19_A` / `S19_B` distinguishable images (4 bytes @0x1000 vs @0x2000) | `tests/test_tui_variants.py:54-55` (duplicated at `tests/test_tui_manifest_save.py:54-55`) | AT-035a content-level assert; AT-035b variants |
| `_make_project(app, name, files)` | `tests/test_tui_variants.py:61` | Project construction in all three ATs |
| `_flush(pilot, count=12)` | `tests/test_tui_variants.py:70` | Deferred apply-chain pumping after loads/saves |
| `_project_label(app)` (rendered `#cmdbar_project`) | `tests/test_tui_variants.py:76` | Label observable in AT-035a/b/c |
| `workers.wait_for_complete()` after a variant switch | `tests/test_tui_variants.py:148` | AT-035a/b (switch rides the threaded load) |
| Shipped-save drive: `SaveProjectPayload` → `_handle_save_dialog` | `tests/test_tui_manifest_save.py:114-118` | AT-035b step 2 |
| `_statuses` / `_notices` capture (if warning asserts needed) | `tests/test_tui_manifest_save.py:64,81` | TC-035.3 unknown-id warning |
| Select-driving idiom: `select.value = <known name>` fires `Select.Changed` | `tests/test_tui_patch_editor_v2.py:1429-1435` (AT-030a) | AT-035a switch; also its `_select_option_values` helper for TC-035.1 |
| Consumer-contract guard (KEEP AS-IS, direct-write manifest → load honors it) | `tests/test_variant_execution.py:173` | AC-2 guard — never the gate |
| Ordering trio `zeta/Alpha/mid` | `tests/test_workspace_variants.py:39` | TC-035.1 order assert |
| Geometry capture pattern `_drive_panes` + `_assert_two_by_two` | `tests/test_tui_patch_layout.py:44,99` | TC-035.4 + TC-035.6 regression |

---

## 5. Harness constraints (binding on the author)

- **pytest-asyncio is NOT installed.** Every async drive is a nested
  `async def _drive()` executed via `asyncio.run(_drive())` inside a plain sync test —
  the exact `_drive_panes` idiom (`tests/test_tui_patch_layout.py:71-96`).
- `Select` value assignment on an **enabled** widget posts `Select.Changed` through the
  real handler (proven by AT-030a). Same-value assignment emits nothing (verified,
  textual 8.2.5 `_select.py:362` — see §2 AT-035a) — one more reason the AT must cycle
  OFF the default (C-10). Also verified: `set_options` RESETS the selection to BLANK
  and fires the watcher (`_select.py:559-575`) → repopulate emits `Changed(Select.NULL)` then
  `Changed(active_id)` after re-sync; and assigning a value not in the options raises
  `InvalidSelectValueError` (`_select.py:594`) → `set_options` strictly before value
  assignment (Phase-2 F-4).
- `shall` is used nowhere in this artifact because no §3 HLR text existed to quote at
  authoring time; re-key AT↔HLR ids at Phase 2.

## 6. Testability risks

- **R-1 (observable location) — RESOLVED at Phase 2:** the `CommandBar` is app-global
  (`#command_bar_slot` sibling of `#workspace_body`, `app.py:1014-1017`; screens are
  hidden-class toggles inside `#workspace_body` only, `app.py:3250-3259`) → the label
  needs NO navigation. The hex view lives in `#screen_workspace` → AT-035a hops via
  `action_show_screen("workspace")` before reading `#hex_view` (exact step bound in §2
  AT-035a observable 2).
- **R-2 (flush depth):** the switch chains screen-event → handler → worker → deferred
  apply. Use `wait_for_complete()` **plus** `_flush(12)` (the proven pair) — a bare
  `pilot.pause()` is a flake generator here.
- **R-3 (disabled-state drive):** nothing user-drivable exists on a disabled Select, so
  AT-035c is observation-only by design; the enabled-path routing gets its negative
  coverage in TC-035.3 instead.
- **R-4 (house purity drift):** older suites assert `app._variant_set.active_id`
  directly. For AT-035\* gates, rendered-text/disk observables ONLY; internal reads are
  secondary diagnostics at most.

---

## 7. QA evidence checklist (authoring-time)

- [x] Acceptance criteria use Given/When/Then — AC-1/2/3 quoted from `01-requirements.md` §2.6; ATs map 1:1.
- [x] Test cases have explicit Expected, not vague "works" — every AT/TC row names the exact observable (label string, byte row, JSON key, disabled flag, region.y).
- [x] Edge cases include empty, boundary, invalid, error — AT-035c (empty/single), TC-035.1 (N=3 order, duplicate stems), TC-035.3 (BLANK/unknown/missing-file).
- [x] Regression checklist exists — TC-035.6 (parse-call-site AST, modal test, engine-frozen guard, 2×2 geometry).
- [x] Exit criteria stated — AT-035a/b/c green as GATES + TC-035.1-.4 green + TC-035.6 set unchanged-green; snapshot row xfail-until-baseline is non-blocking.
- [x] No real PII / secrets — synthetic S19 constants and tmp_path projects only.
- [x] Test results section left blank — this is a strategy artifact; no test has been run and none is claimed.
- [x] Layer B black-box through the SHIPPED surface with boundary + negative evidence — AT-035a (Pilot Select drive, content-level), AT-035b (handler-written project.json + unmodified load), AT-035c (negative), §2 header bans internal-state gate asserts.
- [x] Bidirectional surface-reachability — input dimension (variant choice) exercised through the widget/handler (AT-035a); outputs (label, image content, manifest, re-load activation) each observed (AT-035a obs 1-2, AT-035b steps 3-4).
- [x] No unfilled template — no `<...>` placeholders; provisional ids AT-035a/b/c + TC-035.1-.6 are all bound to concrete drives/asserts.
