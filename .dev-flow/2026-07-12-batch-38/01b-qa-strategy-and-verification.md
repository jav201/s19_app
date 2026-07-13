# 01b — QA Strategy & Verification — 2026-07-12-batch-38

> **Owner:** qa-reviewer (Phase 1). Sibling to `01-requirements.md` (architect-owned) to avoid a write conflict.
> **Scope:** validation method per requirement + the two-layer test strategy (Layer A functional white-box `TC-NNN`, Layer B behavioral black-box `AT-NNN`) for stories **US-065, US-066, US-067, US-068a, US-068b**.
> **Id anchors:** Layer-A TCs start at **TC-332** (batch-37 ended at TC-331). ATs are pre-named in intake: **AT-065a / AT-066a / AT-066b / AT-067a / AT-068a / AT-068b**. LLR numbering below reconciled with the architect's §4 at the **Phase-2 fold** (2026-07-12).

---

## 0. BLUF

- **6 ATs, 14 TCs** (TC-332…TC-345 after the Phase-2 fold; TC-344/TC-345 cover the two A-01 data-loss guards, M4). Every story's deliverable is observed through the **shipped TUI surface** (Textual `App.run_test()` pilot / rendered widget text / issues panel / on-screen change-set), never only through the service API.
- **Every AT has a stated RED counterfactual** — a concrete pre-implementation condition under which the assertion fails, so no AT can pass vacuously against `main`.
- **C-16 real-interaction** honored for the two interactive stories (US-067 info modal, US-068b per-entry popup) via real `pilot.click` (precedent: `tests/test_tui_entropy_viewer.py:797`), **not** `.focus()` / direct setters. **AT-068b clicks the NEW `#patch_entry_edit_json_button`** (Phase-2 fold B2), not the existing field-based `#patch_entry_edit_button`.
- **C-17 hostile-input** carried by the dedicated **AT-066b** (bracket/ANSI/link payload in a file-derived A2L tag name; ANSI asserted neutralized/stripped, not verbatim — Phase-2 fold F-m2).
- **C-18** realized: each AT maps to **exactly one distinct on-disk test-function node** in a named, already-existing file (no new files required).
- **Phase-2 fold discharged:** AT-065a copy pinned verbatim (M3), AT-068b re-pointed to the new per-entry JSON control (B2), US-066 producer sink corrected to `validation_service` (M1), issue code ratified `A2L_ADDRESS_EXCEEDS_32BIT` (B1).

---

## 1. Validation-method table (per requirement)

Default method is `test`. Justification required for anything non-`test`.

| Story | Deliverable (WHAT, black-box) | Method | Justification |
|-------|-------------------------------|--------|---------------|
| US-065 (B-16) | Rendered free-path placeholder + section copy read as *alternative to the dropdown for the same change-set*, not a "v2 file". | **test** | Rendered widget text is queryable via pilot; deterministic string assertion. |
| US-066 (B-17) — warning | A **WARNING** `ValidationIssue` (code `A2L_ADDRESS_EXCEEDS_32BIT`) naming the tag appears on the issues surface when a tag address > `0xFFFFFFFF`. Producer is `validation_service.build_validation_report` (Phase-2 fold M1), which reaches `GroupedIssuesPanel`. | **test** | Issue object + issues panel both observable through the load handler. |
| US-066 (B-17) — safety | A hostile/oversized address & tag name render **literally** (no crash, no markup/style leak). | **test** | Adversarial input → observable rendered `Text`; deterministic. C-17. |
| US-067 (B-18) — behavior | Activating the info affordance opens a modal containing the variant-selector help text. | **test** | Real click → modal push + content, observable via pilot. |
| US-067 (B-18) — geometry | Info button + modal fit at 80×24 and 120×30 without clipping/below-fold. | **inspection** (pilot-measured, Phase 3) | C-23: geometry is *pilot-measured* on the running app, not asserted by fr-math; recorded as a Phase-3 measurement, not a CI TC. **Not** a substitute for AT-067a. |
| US-068a (B-19a) | After an edit, **undo** restores the prior change-set; **redo** re-applies it; history is bounded. | **test** | Change-set state read back through the rendered surface; deterministic. |
| US-068b (B-19b) | The **per-entry** JSON popup opens for the selected entry; confirming edits **only** that entry. | **test** | Real click → scoped popup + post-confirm table state, observable via pilot. |

No requirement is validated by `demo` or `analysis` alone. The single non-`test` item (US-067 geometry) is an **additive** Phase-3 inspection that does not replace the functional AT-067a.

---

## 2. Layer A — functional white-box `TC-NNN` (TC-332 … TC-345)

Each TC targets one LLR at the mechanism level (service / method / compose), asserting a specific value. LLR ids reconciled with §4 at the Phase-2 fold.

| TC | LLR | Target unit | Asserts |
|----|-----|-------------|---------|
| **TC-332** | LLR-065.1 / .2 | `screens_directionb` compose (`#patch_doc_path_input`, section title `Label`) | Section-title `Label` equals `"Change document (JSON)"` and `#patch_doc_path_input` placeholder equals `"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"` — both **verbatim**; the placeholder contains the alternative-to-dropdown tokens and neither string contains `v2`. |
| **TC-333** | LLR-066.1 | `services/validation_service` producer (`supplemental_a2l_oversized_address_issues`, sibling of `supplemental_a2l_row_issues` `:20`) | Given a tag with `address = 0x1_0000_0000`, the producer emits a `ValidationIssue(severity=WARNING, code="A2L_ADDRESS_EXCEEDS_32BIT")` whose `message` contains the **tag name**. |
| **TC-334** | LLR-066.2 | `validation_service.build_validation_report` (both branches, `:166-169` / `:191-194`) | The WARNING merges into `ValidationReport.issues` in **both** the MAC-only and primary-backed branches before `dedupe_issues`; severity round-trips through `css_class_for_severity` → the WARNING `sev-*` class (colour contract intact); the constructed issue text is markup-safe (explicit `Text` via `safe_text`). |
| **TC-335** | LLR-066.3 (boundary) | Same producer | Boundary pair: `address = 0xFFFFFFFF` (32-bit max) yields **no** oversize warning; `address = 0x1_0000_0000` yields exactly one; non-int/`None` address yields none. |
| **TC-336** | LLR-067.1 | app info-button handler + new `ModalScreen` | Pressing the variant-selector info affordance pushes the help `ModalScreen`. |
| **TC-337** | LLR-067.2 / .3 | New help `ModalScreen` content | The modal body contains the variant-selector help text (names *which firmware image it picks* and *when it appears*). |
| **TC-338** | LLR-068a.1 | undo/redo history stack (ChangeService/screen) | After one edit, `undo` restores the prior change-set object (deep-equal to pre-edit snapshot); each snapshot is a true deep copy (no alias). |
| **TC-339** | LLR-068a.2 | Same | `redo` after `undo` re-applies the edit (deep-equal to post-edit snapshot). |
| **TC-340** | LLR-068a.3 (bound) | Same | History is bounded: at the configured depth the oldest snapshot is dropped; `undo` at the base and `redo` at the head are no-ops (no crash, no index error). |
| **TC-341** | LLR-068b.1 | per-entry popup open path | Opening the per-entry editor (`#patch_entry_edit_json_button`) for selected index *i* seeds the popup with entry *i*'s JSON only. |
| **TC-342** | LLR-068b.2 | per-entry popup confirm path | Confirming an edited entry *i* mutates only entry *i*; all other entries are byte-identical. |
| **TC-343** | LLR-068b.3 (route) | per-entry confirm → load/parse route | The confirmed JSON is routed through the validated parse/load path (mirrors batch-37 `ChangeSetJsonScreen`; no direct-bypass write), so malformed input is rejected and markup-safe. |
| **TC-344** | LLR-068a.4 (A-01) | undo/redo enable-state | Undo/Redo controls are DISABLED iff `ChangeService.document.source_path is not None` (file-backed); enabled when `source_path is None` (paste-authored). |
| **TC-345** | LLR-068b.4 (A-01) | per-entry control enable-state | `#patch_entry_edit_json_button` is DISABLED iff `source_path is not None`; enabled when `source_path is None`. |

**TC id range: TC-332 … TC-345 (14 TCs).** Mapping is 1 story-mechanism → ≥1 TC; boundary (TC-335, TC-340), negative/route (TC-343), colour-contract (TC-334), and A-01 data-loss guard (TC-344/TC-345) cases are explicit, not folded. TC-332 covers the copy pair; TC-337 covers routing + content.

---

## 3. Layer B — behavioral black-box `AT-NNN`

Each AT drives the **shipped surface** and observes the **deliverable**. Format: mechanism · inputs (representative / boundary / negative) · deliverable observed · **RED counterfactual**.

### AT-065a — Change-set free-path label reads as alternative-to-dropdown
- **Story / deliverable:** US-065 · the **rendered** placeholder text of `#patch_doc_path_input` + the patch-doc section-title `Label`.
- **Mechanism:** `App.run_test()` pilot → open the Patch Editor (Direction-B) → `query_one("#patch_doc_path_input", ...).placeholder` and the section-title `Label` renderable text.
- **Inputs:** single rendered state (label copy is input-independent). Representative = default patch-editor open.
- **Deliverable observed:** the two literal strings.
- **Assertion (C-10 content, pinned Phase-2 M3):** section-title `Label.renderable` equals **`"Change document (JSON)"`** verbatim; `#patch_doc_path_input` placeholder equals **`"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`** verbatim; the positive tokens (`alternative to`, `same change-set`, `patches/ dropdown`) are present in the placeholder; the substring `v2` is absent from BOTH strings.
- **RED counterfactual:** at `main`, the placeholder is literally `"path to v2 change-set .json"` (screens_directionb.py:1904) and the title `"Change document (v2 JSON)"` (screens_directionb.py:1854) → the verbatim-equality + "no v2" assertions fail RED.
- **Node:** `tests/test_tui_directionb.py` (patch-editor compose home) — one new test function.

### AT-066a — WARNING surfaces for a >32-bit A2L tag address, naming the tag
- **Story / deliverable:** US-066 · a **WARNING** row on the issues surface (`GroupedIssuesPanel #validation_issues_groups`) naming the offending tag.
- **Mechanism:** `App.run_test()` pilot → load an on-disk A2L fixture **through the app load handler** (not by calling `enrich_tags_and_render` directly) → read the grouped issues surface.
- **Inputs:**
  - *Boundary/representative:* a tag whose `address = 0x1_0000_0000` (one past 32-bit max).
  - *Negative control:* a sibling in-range tag (`address ≤ 0xFFFFFFFF`) that must **not** produce this warning.
- **Deliverable observed:** a `ValidationIssue` of severity WARNING whose message names the oversized tag is present on the issues panel; the in-range tag produces no such warning.
- **Assertion (C-10 content):** assert the WARNING **names the specific tag** and carries the new oversize code — not merely "issues list non-empty".
- **RED counterfactual:** at `main`, 0 hits for `0xFFFFFFFF`/>32-bit handling in `a2l.py`/`validation/` (PLAN §RC-1) → no such WARNING is produced → assertion fails RED.
- **Node:** `tests/test_tui_a2l.py` (TUI-level A2L, handler-driven) — one new test function.

### AT-066b — Hostile address + tag name render literally (C-17)
- **Story / deliverable:** US-066 safety · the constructed WARNING message renders the **file-derived tag name literally**.
- **Mechanism:** `App.run_test()` pilot → load an A2L fixture whose oversized tag's **name** carries a hostile payload → read the WARNING message renderable on the issues surface.
- **Inputs (C-17 payloads in the tag name):** e.g. `[red]PWN[/]`, `[/]`, an ANSI escape sequence, and a Textual `[link=…]` markup, combined with `address > 0xFFFFFFFF`.
- **Deliverable observed:** the WARNING message text as rendered.
- **Assertion (C-17, split by payload — Phase-2 F-m2):** for the **bracket/link** payload the literal characters appear **verbatim** (`[red]` renders as literal chars via explicit `Text`); for the **ANSI-escape** payload assert only **no style leak / no crash / neutralized-or-stripped** — NOT "verbatim" — because `ValidationIssue.__post_init__` strips ANSI CSI from `message` (`model.py:71`, `_ANSI_CSI_RE.sub`) and `safe_text` neutralizes any that reach `symbol`. In all cases: **no** markup parse, **no** style leak into adjacent cells, **no** exception during load or render.
- **RED counterfactual:** if the tag name is interpolated into a markup-enabled string, the `[red]…[/]` is consumed as styling (bracket chars absent from the rendered text) or a `MarkupError` is raised → assertion fails RED.
- **Node:** `tests/test_tui_a2l_issue_recolor.py` (A2L-issue-through-TUI home; distinct file from AT-066a's node) — one new test function.

### AT-067a — Variant-selector info affordance opens a help modal (C-16)
- **Story / deliverable:** US-067 · a modal containing the variant-selector help text.
- **Mechanism (C-16 real pointer):** `App.run_test()` pilot → **`await pilot.click("#<variant_info_button_id>")`** (real pointer, precedent `test_tui_entropy_viewer.py:797`) — **not** `.focus()` / `.press()` proxy / direct `push_screen`.
- **Inputs (render rule pinned, F-m3):** the info button is **always rendered** whenever the variant selector renders; the selector itself requires **≥2 images** in the project dir, so the fixture MUST create a ≥2-image project state to make the selector + info button live click targets. The click is the driver.
- **Deliverable observed:** `app.screen` is the new help `ModalScreen`, and its rendered content contains the help text (what the selector does / when it appears).
- **Assertion (C-10 content):** assert the modal **type** AND that its body text names the variant behavior — not merely "a screen was pushed".
- **RED counterfactual:** at `main`, no info affordance is wired to `#patch_variant_select` (PLAN §RC-1: 0 info/help popup) → the click target does not exist / no modal opens → assertion fails RED.
- **Node:** `tests/test_tui_variants.py` — one new test function.

### AT-068a — Undo restores the prior change-set; redo re-applies it
- **Story / deliverable:** US-068a · the restored change-set state, read back through the shipped surface.
- **Mechanism:** `App.run_test()` pilot → drive a real change-set edit through the patch-editor entry controls (add/edit an entry) → activate **undo** (real key/click on the undo affordance) → read the change-set back from the rendered entries table/document → activate **redo** → read again.
- **Inputs:** representative = one entry edit (e.g. change entry 0's bytes) on a **paste-authored** doc (`source_path is None`); also exercise **redo-after-undo**; boundary = undo at base / redo at head are no-ops; **A-01 branch (M4)** = a **file-loaded** doc (`source_path is not None`) has Undo/Redo DISABLED (mirrors batch-37 AT-064c).
- **Deliverable observed:** the change-set after undo == the pre-edit change-set; after redo == the post-edit change-set; controls disabled iff `source_path is not None`.
- **Assertion (C-10 content):** assert the **specific restored entry content** (the exact address/bytes/value of the affected entry) before and after — **not** merely "the change-set object differs"; assert **no-alias** (mutating the live document after undo does not alter a stored snapshot — deep-copy).
- **RED counterfactual:** at `main`, 0 hits for `undo`/`redo` (PLAN §RC-1) → no undo affordance exists / edit is irreversible → assertion fails RED.
- **Node:** `tests/test_tui_patch_editor_v2.py` — one new test function (distinct node from AT-068b).

### AT-068b — Per-entry JSON popup opens for the selected entry; confirm edits that entry only (C-16)
- **Story / deliverable:** US-068b · the per-entry popup + the post-confirm change-set (only the selected entry changed).
- **Mechanism (C-16 real pointer, B2):** `App.run_test()` pilot → select entry *i* in `#patch_doc_entries_table` → **`await pilot.click("#patch_entry_edit_json_button")`** (real pointer — the **NEW** per-entry JSON control, distinct from the existing field-based `#patch_entry_edit_button` at `:1886` → `edit_entry` action `:2230`, and from the whole-set `#patch_edit_json_button` at `:2033`) to open the **per-entry** JSON popup → edit the popup JSON → confirm → read the entries table back.
- **Inputs:** representative = a 2+ entry change-set on a **paste-authored** doc (`source_path is None`), edit entry *i* (i ≠ 0 to prove scoping); negative/route = malformed JSON in the popup is rejected (mirrors TC-343); **A-01 branch (M4)** = a **file-loaded** doc (`source_path is not None`) has the per-entry JSON control DISABLED (mirrors batch-37 AT-064c).
- **Deliverable observed:** (a) a per-entry popup opens seeded with entry *i*'s JSON only — a **single** entry, distinct from batch-37's whole-set `ChangeSetJsonScreen`; (b) after confirm, entry *i* is updated and **every other entry is byte-identical**; (c) control disabled iff `source_path is not None`.
- **Assertion (C-10 content):** assert the popup seed is a single entry (entry *i*'s JSON, not the whole set); assert the edited entry's new content AND the unchanged content of at least one sibling entry — proves scoping, not "popup appeared".
- **RED counterfactual (B2, sound):** at `main`, no per-entry JSON control exists (`#patch_entry_edit_json_button` absent; PLAN §RC-1: per-entry edit opens no popup) → the new click target is not found → no scoped popup / no confirm-path → assertion fails RED. (The existing `#patch_entry_edit_button` performs the field-populate `edit_entry` action and is NOT the target — clicking it would never turn GREEN on this feature.)
- **Node:** `tests/test_tui_patch_editor_v2.py` — one new test function (distinct node from AT-068a).

---

## 4. Control-compliance checklist (per AT)

| AT | C-10 (non-default value / content, per-branch) | C-16 (real interaction) | C-17 (markup safety) | C-18 (one distinct node) | Bidirectional reachability |
|----|-----------------------------------------------|-------------------------|----------------------|--------------------------|----------------------------|
| **AT-065a** | ✓ asserts corrected copy CONTENT (alt-to-dropdown present + v2 absent), not "non-empty" | n/a (static render) | n/a | ✓ `test_tui_directionb.py` | ✓ observed through composed widget, not the source string constant |
| **AT-066a** | ✓ asserts WARNING names the specific tag + code; in-range negative control | n/a (load event) | (covered by AT-066b) | ✓ `test_tui_a2l.py` | ✓ input = A2L via **load handler**; output = **issues panel** |
| **AT-066b** | ✓ asserts literal bracket/escape chars present | n/a | ✓ **owns** hostile bracket/ANSI/link payload | ✓ `test_tui_a2l_issue_recolor.py` | ✓ hostile name enters via load handler; rendered via issues surface |
| **AT-067a** | ✓ asserts modal body CONTENT, not "a screen pushed" | ✓ **real `pilot.click`** on info button | n/a | ✓ `test_tui_variants.py` | ✓ click drives the app; modal read from `app.screen` |
| **AT-068a** | ✓ asserts specific restored entry content (undo AND redo branches) | ✓ real key/click on undo/redo affordance | n/a | ✓ `test_tui_patch_editor_v2.py` | ✓ edit + undo driven through controls; state read from rendered table |
| **AT-068b** | ✓ asserts single-entry seed + edited entry content + sibling unchanged (scoping) | ✓ **real `pilot.click`** on the NEW `#patch_entry_edit_json_button` (B2) | (route rejects malformed → markup-safe, TC-343) | ✓ `test_tui_patch_editor_v2.py` (distinct fn) | ✓ input via new per-entry JSON button + popup; output via entries table |

**Default-value-reliant / "output non-empty" scan:** none of the six ATs pass by asserting non-emptiness or a default value. US-065 asserts changed copy content; US-066 asserts a named WARNING against an in-range negative control; US-067/068b assert modal/entry CONTENT after a real drive; US-068a asserts specific restored content.

---

## 5. C-18 node inventory (AT → exactly one existing file)

All target files already exist (verified on disk); no new file is required.

| AT | File | Exists? |
|----|------|---------|
| AT-065a | `tests/test_tui_directionb.py` | ✓ |
| AT-066a | `tests/test_tui_a2l.py` | ✓ |
| AT-066b | `tests/test_tui_a2l_issue_recolor.py` | ✓ |
| AT-067a | `tests/test_tui_variants.py` | ✓ |
| AT-068a | `tests/test_tui_patch_editor_v2.py` | ✓ |
| AT-068b | `tests/test_tui_patch_editor_v2.py` (distinct test function from AT-068a) | ✓ |

Two ATs share `test_tui_patch_editor_v2.py` but occupy **distinct test-function nodes** — C-18 is satisfied at the node granularity ("each AT → exactly one on-disk node"), not the file granularity.

---

## 6. Bidirectional surface-reachability ledger

Every named input dimension is fed through the handler, and every deliverable is observed through the handler — not only via the service API.

| Story | Input dimension → handler path | Deliverable → observed surface |
|-------|--------------------------------|--------------------------------|
| US-065 | patch-editor open (compose) | placeholder/section text via `query_one` on the live widget |
| US-066 | A2L file `address` field → **app load handler** → `validation_service.build_validation_report` (M1) | WARNING `ValidationIssue` (`A2L_ADDRESS_EXCEEDS_32BIT`) on **`GroupedIssuesPanel`** |
| US-066 safety | hostile **tag name** → load handler | rendered WARNING message text |
| US-067 | real click on info button → app | help `ModalScreen` in `app.screen` |
| US-068a | entry edit via patch-editor controls → app | restored change-set via rendered entries table; Undo/Redo disabled when file-backed (A-01) |
| US-068b | entry select + `pilot.click` on **`#patch_entry_edit_json_button`** (B2) → app | single-entry popup seed + post-confirm entries table; control disabled when file-backed (A-01) |

White-box TCs (§2) may call the service/method directly; the black-box ATs (§3) are the reachability guarantee.

---

## 7. Flags / testability concerns to raise at Phase 2

1. **AT-065a hardening — RESOLVED (Phase-2 M3).** Copy pinned verbatim: title `:1854` → `"Change document (JSON)"`, placeholder `:1904` → `"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`. AT-065a now asserts both verbatim + positive tokens + `v2` absent. (Per F-m4: the *alternative-to-dropdown* framing is bound to the free-path placeholder `:1904`, not the entries-pane title `:1854`.)
2. **AT-068a hardening — RESOLVED.** Snapshot granularity is change-set-level (LLR-068a.1); AT-068a asserts specific restored entry content on both branches + a deep-copy no-alias assertion.
3. **US-066 producer location — RESOLVED (Phase-2 M1).** Producer is `validation_service.build_validation_report` (sibling `supplemental_a2l_oversized_address_issues`), verified sink-reaching (`build_validation_report` → `update_validation_issues_view` → `GroupedIssuesPanel`). `enrich_tags_and_render` returns tag rows, not issues (`a2l_service.py:14`) — NOT the producer. TC-333/334/335 re-pointed accordingly. AT-066a surface `#validation_issues_groups` is correct.
4. **US-066 issue code — RESOLVED (Phase-2 B1).** Canonical code is **`A2L_ADDRESS_EXCEEDS_32BIT`** (the §4 value); the earlier `A2L_ADDRESS_OVER_32BIT` candidate is retired. TC-333/335 + AT-066a bind to `A2L_ADDRESS_EXCEEDS_32BIT` verbatim. Grep-clean in `tests/` (no back-compat break); do not rename post-lock.
5. **US-067 geometry (C-23):** the modal geometry is **pilot-measured at Phase 3** at 80×24 and 120×30, recorded as an inspection result — it is **not** a gating CI TC and must not be conflated with the functional AT-067a. Snapshot drift on the new button/modal is **predicted `xfail(strict=False)` per-cell (C-22)**, canonical-CI regen only.
6. **US-068b vs batch-37 distinctness — RESOLVED (Phase-2 B2).** AT-068b clicks the NEW `#patch_entry_edit_json_button` (distinct from `#patch_entry_edit_button` field-edit and the whole-set `#patch_edit_json_button`) and asserts the popup seed is a **single** entry (entry *i*'s JSON only), explicitly distinct from batch-37's whole-set `ChangeSetJsonScreen` (screens.py:171).
7. **C-26 reverse census (Phase 4 carry):** US-065/067/068 touch shared ids/classes (`patch-section-title` at `:1854` **only** — `:1918`/`:1936` untouched; `#patch_doc_path_input`, `#patch_variant_select`). New ids added: `#patch_variant_info_button`, `#patch_undo_button`/`#patch_redo_button`, `#patch_entry_edit_json_button`. The existing `#patch_entry_edit_button` (`:1886` → `edit_entry` `:2230`) is **unchanged** (no hijack). Each touched/new id/class must be reverse-grepped across `tests/` before increment close; no existing test asserts the literal `"v2"` copy (grep clean → 0 breakages expected, not the over-cautious prediction). **Flag for the increment gate.**

---

## 8. Phase-1 gate evidence checklist

| # | Item | ✓/✗ | Evidence |
|---|------|-----|----------|
| 1 | Acceptance expressed as testable deliverables (WHAT), one AC per story | ✓ | §1 method table + §3 ATs; AC text from `01-requirements.md` §2.6 |
| 2 | Validation method set per requirement; non-`test` justified | ✓ | §1 — only US-067 geometry is `inspection`, justified (C-23), additive to AT-067a |
| 3 | Layer-A TCs enumerated, mapped to LLRs, with explicit assertions | ✓ | §2, TC-332…TC-345, 14 TCs (incl. TC-344/345 A-01 guards) |
| 4 | Layer-B ATs drive the **shipped surface** with mechanism + inputs + deliverable | ✓ | §3, all six ATs use `App.run_test()` pilot / rendered widget / issues panel |
| 5 | Every AT has a RED counterfactual (cannot pass vacuously) | ✓ | §3, each AT's "RED counterfactual" line, each tied to a PLAN §RC-1 already-shipped=0 fact |
| 6 | Edge coverage: empty/boundary/invalid/error present | ✓ | boundary TC-335 (0xFFFFFFFF vs +1), TC-340 (undo/redo ends), negative controls AT-066a/AT-068b; hostile-input AT-066b |
| 7 | C-10 discipline: no default-value-reliant / "output non-empty" AT | ✓ | §4 scan row; §7 items 1–2 harden the two at-risk ATs |
| 8 | C-16: interactive-story ATs use real click/press, not `.focus()`/setter | ✓ | AT-067a + AT-068b use `pilot.click` (precedent test_tui_entropy_viewer.py:797) |
| 9 | C-17: hostile-input AT feeds bracket/ANSI/link payload, asserts literal render | ✓ | AT-066b, §3 |
| 10 | C-18: each AT → exactly one distinct on-disk node; files verified to exist | ✓ | §5 inventory; all 5 files present on disk (Glob-verified) |
| 11 | Bidirectional reachability: every input dim + deliverable through the handler | ✓ | §6 ledger |
| 12 | No real PII / secrets in fixtures | ✓ | fixtures are synthetic A2L/change-set data; hostile payloads are inert markup strings |
| 13 | Test-results columns left blank (human/CI to fill) | ✓ | no TC/AT marked passed; this is an authoring artifact |
| 14 | No unfilled template placeholders | ✓ | all `TC-`/`AT-`/LLR ids concrete; provisional LLR reconciliation flagged for Phase 2 (§7) |
| 15 | Frozen-module respect: no TC/AT requires editing `validation/` or other frozen files | ✓ | US-066 producer is TUI-side service; §7 item 3 |

**Gate verdict (qa authoring):** Phase-1 QA strategy is **complete and internally consistent**. **Phase-2 fold discharged (2026-07-12):** §7 items 1–4 and 6 are RESOLVED — AT-065a copy pinned (M3), AT-068a content + deep-copy asserted, US-066 producer corrected to `validation_service` (M1), issue code ratified `A2L_ADDRESS_EXCEEDS_32BIT` (B1), AT-068b re-pointed to the new per-entry JSON control (B2). Item 5 (US-067 geometry) remains a Phase-3 pilot-measurement; item 7 (C-26 census) remains an increment-gate carry. The A-01 data-loss guards (TC-344/TC-345, M4) are added.
