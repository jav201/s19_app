# 01 — Requirements — 2026-07-12-batch-38

> Phase-0 intake recorded below (§2.6). §3 Acceptance / §4 HLR-LLR are derived in **Phase 1** after operator plan approval.

## §2.6 Story intake & Definition of Ready (Phase 0)

**RC-1 base-currency:** PASS @ `origin/main` tip `5a6c45b` (HEAD == merge-base == tip; fetch clean). Already-shipped per-story check: 0 source hits for all four outcomes.

### US-065 (B-16) — Change-set free-path label clarity
- **User / outcome / why:** A patch-editor user reading the free-path field understands it is an **alternate way to point at the SAME primary change-set** (instead of the `patches/` dropdown), not a second or "v2" file. Removes a recurring misread.
- **Out of scope:** the dropdown behavior, the underlying load path (unchanged), any file-format change.
- **Feasibility:** trivial — copy on `screens_directionb.py:1854` (section title) + `:1904` (placeholder). No deps.
- **Evaluability (black-box AC):** *When the Patch Editor renders, the free-path field's placeholder + its section copy no longer contain the misleading "v2 file" framing and state it is an alternative to the dropdown* → `AT-065a` reads the rendered widget text.
- **Independent:** yes. **Classify: READY.**

### US-066 (B-17) — Defensive WARNING for A2L addresses > 0xFFFFFFFF
- **User / outcome / why:** When an A2L tag's address exceeds 32 bits, the user sees a **WARNING-severity issue naming that tag**, making the previously-unreproducible "two extra characters" a diagnosable condition; a hostile/oversized address never crashes or leaks markup.
- **Out of scope:** changing how in-range addresses render; editing the frozen `validation/` engine.
- **Feasibility:** the WARNING is constructed **TUI-side** in `services/validation_service.build_validation_report` (a supplemental producer sibling of `supplemental_a2l_row_issues`, `validation_service.py:20`; services/ is not frozen), so it reaches `ValidationReport.issues` → `update_validation_issues_view` → `GroupedIssuesPanel`. **Sink correction (Phase-2 M1):** `a2l_service.enrich_tags_and_render` returns tag rows + summary lines (`a2l_service.py:14`), NOT issues, so a WARNING built there is dropped and never reaches the issues surface — it is the wrong sink. `ValidationSeverity.WARNING` exists (`model.py:13`); colour via existing `css_class_for_severity`. C-17 markup-safety applies (file-derived tag name).
- **Evaluability (black-box AC):** *When an A2L with a tag address > 0xFFFFFFFF is loaded, the issues surface shows a WARNING naming the tag* → `AT-066a`; *a hostile address string renders literally, no parse error / style leak* → `AT-066b` (C-17 hostile-input).
- **Independent:** yes. **Classify: READY.**

### US-067 (B-18) — Variant-selector info/help popup
- **User / outcome / why:** A user unsure what the variant selector does can open an **info/help modal** explaining it picks which firmware image loads and when it appears (≥2 images in the project dir).
- **Out of scope:** other info buttons (deferred); changing variant selection behavior.
- **Feasibility:** new info button beside `Select#patch_variant_select`; new help `ModalScreen`. Geometry pilot-measured (C-23).
- **Evaluability (black-box AC):** *When the info affordance is activated, a modal appears containing the variant-selector help text* → `AT-067a` drives the real click/press and asserts the modal + its content.
- **Independent:** yes. **Classify: READY.**

### US-068 (B-19) — Patch-editor undo/redo + per-entry JSON popup
- **User / outcome / why:** A patch-editor user can **undo/redo** change-set edits and **edit a single entry's JSON** in a popup (distinct from batch-37's whole-set popup), reducing edit risk.
- **Out of scope:** keystroke-level undo (change-set-level only); the whole-set popup (already shipped batch-37).
- **Feasibility:** undo/redo = bounded history stack (new capability); per-entry popup mirrors `ChangeSetJsonScreen` scoped to one entry. Per-entry `Add/Edit/Remove` buttons exist (`1885-87`). **Likely SPLIT** → US-068a (undo/redo) + US-068b (per-entry popup) at Phase 1/2.
- **Evaluability (black-box AC):** *After an edit, undo restores the prior change-set and redo re-applies it* → `AT-068a`; *the per-entry popup opens for a selected entry, and confirming edits that entry only* → `AT-068b`.
- **Independent:** yes (within-story split ordered a→b). **Classify: READY (split-likely).**

### Definition-of-Ready gate summary
| US | Valuable | Estimable/Small | Testable (black-box) | Classify |
|----|----------|-----------------|----------------------|----------|
| US-065 | ✓ | ✓ (trivial) | ✓ AT-065a | READY |
| US-066 | ✓ | ✓ (service-side) | ✓ AT-066a/b | READY |
| US-067 | ✓ | ✓ (modal) | ✓ AT-067a | READY |
| US-068 | ✓ | ✓ (split a/b) | ✓ AT-068a/b | READY (split-likely) |

All four **READY** → proceed to Phase 1 on operator plan approval. None `REFINE`/`SPIKE`/`OUT`.

> **Phase-1 split confirmed.** US-068 (B-19) is split into **US-068a** (change-set-level undo/redo) + **US-068b** (per-entry JSON popup) — two separable capabilities with distinct ATs (precedent: batch-37 US-064). Story count for Phase 1 onward is **5**: US-065, US-066, US-067, US-068a, US-068b. Split rationale + reconciliation audit in §6.4.

> **Draft-time verification (dominant control) — legend.** Every code symbol / file / line cited below was read against the working tree at commit `5a6c45b` (batch-38 base). Citations use `path:line`. Symbols to be created by an increment are flagged **`NEW — Phase 3`**. Rendered-size / magic-number constants with no measured source are flagged **`assumed — pilot-measure in Phase 3`** (C-23) or **`assumed — verify in Phase 3`**. The source tree lives in the primary checkout `s19_app/…` (the `.dev-flow` worktree carries docs only); all citations are repo-relative.

---

## 3. Acceptance (black-box, the WHAT) — one block per story

> Each block is independent of the §4 LLR decomposition. It names the observable outcome, the shipped surface that produces it, the concrete deliverable + how it is observed, and the `AT-NNN`. Every AT drives the SHIPPED surface via Textual Pilot and asserts the outcome; it references NO internal symbol. Boundary catalog (QC-3) authored here.

### §3.1 — US-065 (B-16) — Change-set free-path label clarity
- **Observable outcome:** The Patch Editor's change-set section title and the free-path field placeholder read as an **alternative way to point at the same primary change-set** (instead of the `patches/` dropdown) — neither implies a second / "v2" file.
- **Shipped surface:** `PatchEditorPanel` compose in `s19_app/tui/screens_directionb.py`. **Scope (qa F-m4):** the change-document section-title `Label` at `:1854` (currently `"Change document (v2 JSON)"`) is the *entries-pane* header (`id="patch_pane_entries"`) — its edit only drops the misleading `v2`. The *alternative-to-dropdown* framing is bound to the free-path field itself: the `#patch_doc_path_input` `OsClipboardInput` placeholder at `:1904` (currently `"path to v2 change-set .json"`), which sits directly under the `patches/` dropdown `#patch_doc_file_select`. Only the `:1854` instance of `patch-section-title` is touched — the class also appears at `:1918`/`:1936` and stays unchanged (C-26).
- **Pinned copy (Phase-2 fold, M3):** title `:1854` → **`"Change document (JSON)"`**; placeholder `:1904` → **`"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`**.
- **Deliverable + observation:** the two rendered strings. Observed via Pilot: `query_one("#patch_doc_path_input", Input).placeholder` and the section-title `Label.renderable` text.
- **Acceptance test(s):** **`AT-065a`** — mount the panel; assert the section-title `Label.renderable` text equals **`"Change document (JSON)"`** verbatim and `query_one("#patch_doc_path_input", Input).placeholder` equals **`"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`** verbatim; assert the positive tokens (`alternative to`, `same change-set`, `patches/ dropdown`) are present in the placeholder and the substring `v2` is absent from BOTH strings (C-10 content assertion, not merely non-empty).
- **Boundary catalog (QC-3):** ☐ empty — N/A (static copy, no input) · ☐ boundary — N/A · ☐ invalid — N/A · ☐ error — N/A. Copy-only story: the sole class is the rendered-text assertion (`AT-065a`).

### §3.2 — US-066 (B-17) — Defensive WARNING for A2L address > 0xFFFFFFFF
- **Observable outcome:** Loading an A2L whose tag address exceeds `0xFFFFFFFF` surfaces a **WARNING-severity issue that names the offending tag** in the validation issues surface; a hostile / oversized tag renders literally (no crash, no markup/style leak).
- **Shipped surface:** the validation issues surface `GroupedIssuesPanel` (`s19_app/tui/issues_view.py:215`), fed from `S19TuiApp.update_validation_issues_view` ← `ValidationReport.issues` ← `validation_service.build_validation_report` (`s19_app/tui/services/validation_service.py:111`). The WARNING is a `ValidationIssue(severity=WARNING)` and its row is coloured through the existing `css_class_for_severity` → `sev-warning` class.
- **Deliverable + observation:** a `ValidationIssue` (code `A2L_ADDRESS_EXCEEDS_32BIT`, severity `WARNING`, `symbol=<tag name>`) rendered as an `IssueRow` under the WARNING group. Observed via Pilot: the mounted `GroupedIssuesPanel` contains a warning-group row whose literal detail text includes the tag name.
- **Acceptance test(s):**
  - **`AT-066a`** (present + names tag): load an A2L containing a tag at address `0x100000000` (> 32-bit); assert the issues surface shows exactly one WARNING row (code `A2L_ADDRESS_EXCEEDS_32BIT`) naming that tag; assert a sibling tag at `0xFFFFFFFF` (the 32-bit max, boundary) produces NO oversized WARNING. **(A-1, confirm Phase 3):** the positive branch fires only if the tag `address` is a parsed `int` in the report branches (LLR-066.1 guards `isinstance(address, int)`); the fixture's oversized tag MUST carry a genuine int address (not a hex string) so the AT is not a vacuous pass — confirm in Phase 3.
  - **`AT-066b`** (C-17 hostile-input): load an A2L whose oversized tag's **name** carries a hostile payload with an address > `0xFFFFFFFF`. Split the assertion by payload class: (i) for **Rich-markup bracket/link** metacharacters (e.g. `[red]evil[/red]`, `[link=…]`) assert the literal bracket characters render **verbatim** (`[red]` appears as literal chars), no style applied; (ii) for an **ANSI escape** payload assert only **no leak / no crash / neutralized** — NOT verbatim — because `ValidationIssue.__post_init__` strips ANSI CSI from `message` (`validation/model.py:71`, `_ANSI_CSI_RE.sub`). In both cases assert no `MarkupError` is raised and no style leaks into adjacent cells. Drives the real load + render surface.
- **Boundary catalog (QC-3):** ☑ boundary — `0xFFFFFFFF` (no warn) vs `0x100000000` (warn) covered by `AT-066a` / `TC`. ☑ invalid/hostile — markup-bearing tag name covered by `AT-066b`. ☐ empty — N/A (no oversized tag ⇒ no WARNING; covered as the negative half of `AT-066a`). ☐ error — N/A (collect-don't-abort; an oversized address is a WARNING, never an abort).

### §3.3 — US-067 (B-18) — Variant-selector info/help popup
- **Observable outcome:** Activating an info/help affordance next to the variant selector opens a **modal explaining what the selector does** — that it picks which firmware image loads, and that it appears when ≥2 images exist in the project directory.
- **Shipped surface:** a **`NEW — Phase 3`** info `Button` beside `Select#patch_variant_select` in the `PatchEditorPanel` compose (`s19_app/tui/screens_directionb.py:1988` is the current `#patch_variant_select` site), and a **`NEW — Phase 3`** help `ModalScreen` pushed by `S19TuiApp`.
- **Deliverable + observation:** the pushed modal and its help-text content. Observed via Pilot: after a real `pilot.click` on the info button, `app.screen` is the help modal and its body text contains the explanation tokens (picks which firmware image loads; appears with ≥2 images).
- **Acceptance test(s):** **`AT-067a`** — mount the panel, `pilot.click` the real info button (C-16: no `.focus()` / no direct `push_screen` proxy), assert the help modal is now the active screen and its rendered text contains the required explanation tokens (content assertion, not non-empty). A second assertion dismisses it and confirms return to the prior screen. **Render rule (pin, F-m3):** the info button is **always rendered** whenever the variant selector renders (the selector itself requires ≥2 images in the project dir); the AT fixture MUST provide a ≥2-image project state so the selector + info button exist as live click targets.
- **Boundary catalog (QC-3):** ☑ boundary — modal open vs dismissed (both asserted in `AT-067a`). ☐ empty — N/A (static help text). ☐ invalid — N/A (no input). ☐ error — N/A. **Geometry note:** the modal's rendered dimensions are **`assumed — pilot-measure in Phase 3`** (C-23) at 80×24 and 120×30; no fr-math size is asserted at Phase 1.

### §3.4 — US-068a (B-19a) — Patch-editor change-set undo/redo
- **Observable outcome:** After a change-set edit (add / edit / remove / paste-load), **undo restores the prior change-set** and **redo re-applies** it, up to a bounded history depth.
- **Shipped surface:** **`NEW — Phase 3`** Undo / Redo `Button`s in the `PatchEditorPanel` (`s19_app/tui/screens_directionb.py`), routed to **`NEW — Phase 3`** `ChangeService.undo()` / `redo()` (`s19_app/tui/services/change_service.py:285`), with the entries table (`#patch_doc_entries_table`) re-rendered via the existing `PatchEditorPanel.refresh_entries` (`app.py:1737,3260`).
- **Deliverable + observation:** the `#patch_doc_entries_table` row set. Observed via Pilot: add an entry (table has N+1 rows) → click Undo → table returns to the N-row prior state → click Redo → table returns to N+1.
- **Acceptance test(s):** **`AT-068a`** — mount the panel with a known change-set, perform a real entry mutation through the surface, `pilot.click` Undo (C-16) and assert the rendered entries match the pre-mutation set byte-for-byte (addresses + values), then `pilot.click` Redo and assert the mutation is restored. Boundary: with an empty history, clicking Undo is a no-op (asserted). **A-01 data-loss branch (M4):** with a paste-authored document (`source_path is None`) the Undo/Redo controls are enabled and the round-trip holds; with a file-loaded document (`source_path is not None`) the controls are **DISABLED** (no clobber of the file-backed doc) — mirrors batch-37 `AT-064c`. **Deep-copy (R-B):** assert the restored document is a true deep copy — mutating `document.entries` after undo must NOT alias any stored snapshot.
- **Boundary catalog (QC-3):** ☑ empty — Undo/Redo on empty history = no-op (asserted). ☑ boundary — history depth cap (oldest snapshot evicted past the bound); file-loaded vs paste-authored A-01 branch (controls disabled vs enabled). ☐ invalid — N/A. ☑ error — undo after a load-replace restores the prior document, not a crash (asserted via the mutation→undo path).

### §3.5 — US-068b (B-19b) — Per-entry JSON edit popup
- **Observable outcome:** For a **selected** change-set entry, a per-entry JSON popup opens showing that one entry's JSON; confirming an edit changes **only that entry**, leaving all other entries unchanged.
- **Shipped surface:** a **`NEW — Phase 3`** per-entry JSON control in `PatchEditorPanel` (distinct from the whole-set `#patch_edit_json_button` at `screens_directionb.py:2033` and from the field-based `#patch_entry_edit_button` at `:1886`) targeting the row selected in `#patch_doc_entries_table` (`cursor_type="row"`, `:1859`), and a **`NEW — Phase 3`** per-entry JSON `ModalScreen` mirroring `ChangeSetJsonScreen` (`screens.py:171`) scoped to one entry.
- **Deliverable + observation:** the edited entry in `ChangeService.document.entries` and the re-rendered `#patch_doc_entries_table`. Observed via Pilot: select entry *i*, open the popup, edit its JSON, Confirm; assert entry *i*'s rendered row reflects the edit and every other row is byte-identical to before.
- **Acceptance test(s):** **`AT-068b`** — mount the panel with ≥2 entries, select entry *i*, `pilot.click` the **new** per-entry JSON control `#patch_entry_edit_json_button` (C-16: real click, not a direct setter; distinct from the field-based `#patch_entry_edit_button` at `:1886` and the whole-set `#patch_edit_json_button` at `:2033`), assert the popup is the active screen and seeded with entry *i*'s JSON only — a **single** entry, distinguishable from batch-37's whole-set `ChangeSetJsonScreen`; edit + Confirm; assert entry *i* changed and entries *≠ i* are byte-identical (content assertion on both branches). **A-01 data-loss branch (M4):** paste-authored doc (`source_path is None`) → control enabled; file-loaded doc (`source_path is not None`) → control **DISABLED** (no silent mutate/replace of the file-backed doc) — mirrors batch-37 `AT-064c`.
- **Boundary catalog (QC-3):** ☑ boundary — first vs middle vs last selected row scoping (assert only the selected index changes); file-loaded vs paste-authored A-01 branch (control disabled vs enabled). ☑ invalid — malformed JSON on Confirm surfaces a collect-don't-abort issue, no crash, other entries untouched. ☐ empty — N/A (control requires a selected entry; with no selection it is a no-op). ☑ error — Confirm with invalid JSON asserted non-crashing.

---

## 4. Requirements — HLR + LLR

> Normative regime: `shall` only. R-TUI ids: **R-TUI-054 … R-TUI-058** (batch-37 ended at R-TUI-053). Every LLR names its **target file** (all NON-frozen — the engine-frozen set `core.py` / `hexfile.py` / `range_index.py` / `validation/` / `tui/a2l.py` / `tui/mac.py` / `tui/color_policy.py` is untouched) and **declares touched shared symbols** (C-26) for Phase-2/3 reverse-grep across `tests/`.

### HLR-065 (R-TUI-054) — Change-set free-path label clarity
- **Traceability:** US-065
- **Statement:** When the Patch Editor is rendered, the system shall present the change-set section title and free-path placeholder as an alternative to the `patches/` dropdown for the same primary change-set, and shall not describe the free-path field as a distinct or "v2" file.
- **Rationale (informative):** the current `"Change document (v2 JSON)"` title + `"path to v2 change-set .json"` placeholder are misread as a second file; this is a copy-only clarification.
- **Validation:** `test (pilot)` · **Executed verification:** `pytest tests/test_tui_directionb.py -k patch_label_clarity` (node id provisional-until-Phase-3, V-5) · **Numeric pass threshold:** `AT-065a` passes; 0 occurrences of `v2` in the two rendered strings.
- **Priority:** low
- **Acceptance (black-box):** §3.1 — `AT-065a`.

#### LLR-065.1 — Section-title copy
- **Traceability:** HLR-065
- **Target file (non-frozen):** `s19_app/tui/screens_directionb.py`
- **Statement:** The `PatchEditorPanel` compose shall render the change-document section-title `Label` at `screens_directionb.py:1854` as the pinned string **`"Change document (JSON)"`** (was `"Change document (v2 JSON)"`) — dropping the `v2` token only. This `Label` is the entries-pane header (`id="patch_pane_entries"`), so the alternative-to-dropdown framing is carried by the free-path placeholder (LLR-065.2), not here.
- **Touched symbols (C-26):** the string literal at `screens_directionb.py:1854` only; the `patch-section-title` CSS class (also at `:1918`/`:1936`) and all widget ids are **unchanged** — the edit is scoped to the `:1854` instance and must not perturb the class or the other two labels' copy (reverse-grep `patch-section-title` must show no class rename).
- **Validation:** `test (pilot)` · **Executed verification:** `AT-065a` reads the section-title `Label` text · **Numeric pass threshold:** text equals `"Change document (JSON)"` verbatim; substring `v2` absent.
- **Acceptance criteria:** the rendered title equals the pinned string; no widget id/class churn.

#### LLR-065.2 — Free-path placeholder copy
- **Traceability:** HLR-065
- **Target file (non-frozen):** `s19_app/tui/screens_directionb.py`
- **Statement:** The `#patch_doc_path_input` placeholder at `screens_directionb.py:1904` (id at `:1905`) shall be the pinned string **`"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`** (was `"path to v2 change-set .json"`) — stating it is an alternative to the `patches/` dropdown for the SAME change-set, without the `v2` token.
- **Touched symbols (C-26):** the placeholder string literal at `screens_directionb.py:1904`; the id `#patch_doc_path_input` is **unchanged** (reverse-grep must show the id survives — every existing selector/test that queries `#patch_doc_path_input` stays valid).
- **Validation:** `test (pilot)` · **Executed verification:** `AT-065a` reads `query_one("#patch_doc_path_input", Input).placeholder` · **Numeric pass threshold:** placeholder equals the pinned string verbatim; tokens `alternative to` / `same change-set` / `patches/ dropdown` present; substring `v2` absent.
- **Acceptance criteria:** the rendered placeholder equals the pinned string; the id is preserved.

### HLR-066 (R-TUI-055) — Defensive WARNING for A2L address > 0xFFFFFFFF
- **Traceability:** US-066
- **Statement:** When an A2L tag's parsed integer address exceeds `0xFFFFFFFF`, the system shall emit a WARNING-severity validation issue naming that tag into the validation issues surface; and if such a tag's name carries markup metacharacters, then the system shall render it literally without a parse error or style leak.
- **Rationale (informative):** turns the previously-unreproducible "two extra characters" into a diagnosable warning. The WARNING is built TUI-side (services layer) so the engine-frozen `validation/` package is not edited.
- **Validation:** `test (unit)` + `test (pilot)` · **Executed verification:** `pytest tests/test_validation_service.py -k oversized_address` and `pytest tests/test_tui_directionb.py -k a2l_oversized_warning` (nodes provisional-until-Phase-3) · **Numeric pass threshold:** `AT-066a` + `AT-066b` pass; oversized-tag count → WARNING count 1:1; 0 `MarkupError`.
- **Priority:** medium
- **Acceptance (black-box):** §3.2 — `AT-066a`, `AT-066b`.

#### LLR-066.1 — Oversized-address WARNING producer (TUI-side)
- **Traceability:** HLR-066
- **Target file (non-frozen):** `s19_app/tui/services/validation_service.py`
- **Statement:** A new supplemental producer (sibling of `supplemental_a2l_row_issues`, `validation_service.py:20`) shall, for each effective A2L tag whose `address` is an `int` strictly greater than `0xFFFFFFFF`, construct one `ValidationIssue(code="A2L_ADDRESS_EXCEEDS_32BIT", severity=ValidationSeverity.WARNING, artifact="a2l", symbol=<tag name or None>, address=<addr>)`; a tag whose address is `<= 0xFFFFFFFF`, `None`, or non-int shall produce no issue.
- **Touched symbols (C-26):** **`NEW — Phase 3`** function (e.g. `supplemental_a2l_oversized_address_issues`) and **`NEW — Phase 3`** public issue code string `"A2L_ADDRESS_EXCEEDS_32BIT"` (issue codes are public contract — Phase-2/3 reverse-greps this code across `tests/`). Imports `ValidationIssue` / `ValidationSeverity` already present (`validation_service.py:6-13`; `ValidationSeverity.WARNING` at `validation/model.py:13`; `ValidationIssue` fields at `validation/model.py:121-129`). Reads the tag `address` key already consumed at `validation_service.py:86`.
- **Validation:** `test (unit)` · **Executed verification:** `pytest tests/test_validation_service.py -k oversized_address` · **Numeric pass threshold:** boundary table — `0xFFFFFFFF`→0 issues, `0x100000000`→1 issue, `None`/str→0 issues.
- **Acceptance criteria:** exactly one WARNING per oversized tag; boundary at `0xFFFFFFFF` exclusive.

#### LLR-066.2 — Merge into both report branches
- **Traceability:** HLR-066
- **Target file (non-frozen):** `s19_app/tui/services/validation_service.py`
- **Statement:** `build_validation_report` (`validation_service.py:111`) shall merge the LLR-066.1 supplemental WARNINGs into the collected issue list in BOTH the MAC-only branch (near `:166-169`) and the primary-backed cross branch (near `:191-194`), before the `dedupe_issues` call, mirroring the existing `supplemental_a2l_row_issues` merge — so the WARNING reaches `ValidationReport.issues` regardless of session kind.
- **Touched symbols (C-26):** `build_validation_report` (existing, extended — `validation_service.py:111`); its return contract (`tuple[Optional[ValidationReport], list[ValidationIssue], Optional[str]]`) is **unchanged**. Reverse-grep `build_validation_report` callers (`_compute_mac_view_payload`, service tests) to confirm no signature drift.
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_validation_service.py -k oversized_address_both_branches` · **Numeric pass threshold:** WARNING present in `report.issues` for both a MAC-only and a primary-backed session.
- **Acceptance criteria:** issue appears in both branches; no change to existing issue codes/counts for non-oversized fixtures.

#### LLR-066.3 — Markup-safe rendering of the file-derived tag name (C-17)
- **Traceability:** HLR-066
- **Target file (non-frozen):** `s19_app/tui/services/validation_service.py` (producer) — render surface is the existing `s19_app/tui/issues_view.py`
- **Statement:** The WARNING message shall carry the file-derived tag name only via the `ValidationIssue.symbol` field and/or a message that is NOT pre-formatted with Rich markup, so that the existing markup-safe issues render (`IssueRow` composes `symbol`/`address`/`message` through `safe_text` as a literal `rich.text.Text` — `issues_view.py:187,201`; `safe_text` imported `:38`) displays a hostile tag name literally; the system shall not interpolate raw tag text into a markup-parsed string.
- **Touched symbols (C-26):** relies on existing `safe_text` / `IssueRow` (`issues_view.py:38,115,187,201`) — **no render code added**; the message-scrub in `ValidationIssue.__post_init__` (`validation/model.py:131-137`, strips control/ANSI but NOT `[...]`) is consumed, not edited. Declares dependency on `safe_text` for the reverse census.
- **Validation:** `test (pilot)` · **Executed verification:** `AT-066b` — load a tag named `[red]evil[/red]` at `0x100000000`, assert literal brackets in the rendered row, 0 `MarkupError` · **Numeric pass threshold:** `AT-066b` passes.
- **Acceptance criteria:** hostile tag name renders verbatim; oversized address formats as hex digits (inherently markup-safe).

### HLR-067 (R-TUI-056) — Variant-selector info/help popup
- **Traceability:** US-067
- **Statement:** When the operator activates the info affordance beside the variant selector, the system shall display a modal whose text explains that the selector picks which firmware image loads and that it appears when at least two images exist in the project directory.
- **Rationale (informative):** the variant `Select` (`#patch_variant_select`) is unexplained; the info modal is discovery help. Scope is this one selector's info button (other info buttons deferred).
- **Validation:** `test (pilot)` · **Executed verification:** `pytest tests/test_tui_directionb.py -k variant_info_modal` (node provisional-until-Phase-3) · **Numeric pass threshold:** `AT-067a` passes; modal text contains the required explanation tokens.
- **Priority:** medium
- **Acceptance (black-box):** §3.3 — `AT-067a`.

#### LLR-067.1 — Info button beside the variant selector
- **Traceability:** HLR-067
- **Target file (non-frozen):** `s19_app/tui/screens_directionb.py`
- **Statement:** The `PatchEditorPanel` compose shall place an info `Button` adjacent to `Select#patch_variant_select` (current site `screens_directionb.py:1988`), enabled whenever the variant selector is present.
- **Touched symbols (C-26):** **`NEW — Phase 3`** button id (e.g. `#patch_variant_info_button`); `#patch_variant_select` and its `set_variants` / `VariantSelected` wiring (`screens_directionb.py:1681,1761,1801`) are **unchanged** (reverse-grep confirms no variant-select selector churn).
- **Validation:** `test (pilot)` · **Executed verification:** `AT-067a` locates the button · **Numeric pass threshold:** button present and enabled.
- **Acceptance criteria:** the info button renders beside the variant selector.

#### LLR-067.2 — Real-interaction routing to the help modal (C-16)
- **Traceability:** HLR-067
- **Target files (non-frozen):** `s19_app/tui/screens_directionb.py` (panel message) + `s19_app/tui/app.py` (handler + push)
- **Statement:** When the info button is pressed, the panel shall post a new message that `S19TuiApp` handles by pushing the help `ModalScreen`; the acceptance shall exercise the real `pilot.click` path (no `.focus()` / no direct `push_screen` proxy).
- **Touched symbols (C-26):** **`NEW — Phase 3`** `Message` class (e.g. `PatchEditorPanel.VariantHelpRequested`) and **`NEW — Phase 3`** handler (e.g. `S19TuiApp.on_patch_editor_panel_variant_help_requested`), mirroring the batch-37 `EditJsonRequested` → `on_patch_editor_panel_edit_json_requested` pattern (`screens_directionb.py:1626`, `app.py:1873`).
- **Validation:** `test (pilot)` · **Executed verification:** `AT-067a` real click → assert modal is active screen · **Numeric pass threshold:** `app.screen` is the help modal post-click.
- **Acceptance criteria:** a real click opens the modal; dismiss returns to prior screen.

#### LLR-067.3 — Help modal content
- **Traceability:** HLR-067
- **Target file (non-frozen):** `s19_app/tui/screens.py` (where the modal `ChangeSetJsonScreen` and siblings live)
- **Statement:** A new help `ModalScreen` shall render static text stating that the variant selector chooses which firmware image loads and that it appears when ≥2 images are present in the project directory, plus a dismiss control; the text shall render markup-safe (`markup=False` or literal `Text`).
- **Touched symbols (C-26):** **`NEW — Phase 3`** class (e.g. `VariantHelpScreen(ModalScreen)`) and its content constant; reuses the shared `.modal-dialog` CSS class (no new CSS class required — declared for reverse census).
- **Geometry (C-23):** modal/dialog rendered dimensions are **`assumed — pilot-measure in Phase 3`** at 80×24 and 120×30; no CSS-fr-derived size is asserted here.
- **Validation:** `test (pilot)` · **Executed verification:** `AT-067a` asserts the modal body text contains the explanation tokens · **Numeric pass threshold:** required tokens present (content assertion, not non-empty).
- **Acceptance criteria:** modal shows the help text; dismissable.

### HLR-068a (R-TUI-057) — Patch-editor change-set undo/redo
- **Traceability:** US-068a
- **Statement:** When the operator has performed one or more change-set edits, the system shall, on undo, restore the immediately-prior change-set, and on redo, re-apply the undone change-set, up to a bounded history depth; and if the history stack is empty, then undo (respectively redo) shall be a no-op.
- **Rationale (informative):** reduces edit risk. History is change-set-level (whole-document snapshots), NOT keystroke-level; depth is bounded to cap memory.
- **Validation:** `test (unit)` + `test (pilot)` · **Executed verification:** `pytest tests/test_change_service.py -k undo_redo` and `pytest tests/test_tui_directionb.py -k patch_undo_redo` (nodes provisional-until-Phase-3) · **Numeric pass threshold:** `AT-068a` passes; document round-trips through undo→redo; empty-stack no-op holds.
- **Priority:** medium
- **Acceptance (black-box):** §3.4 — `AT-068a`.

#### LLR-068a.1 — Bounded history snapshotting in ChangeService
- **Traceability:** HLR-068a
- **Target file (non-frozen):** `s19_app/tui/services/change_service.py`
- **Statement:** `ChangeService` (`change_service.py:285`) shall capture a deep snapshot of its `document` (`change_service.py:331`) immediately before each document-mutating operation (`add_entry:478`, `edit_entry:523`, `remove_entry:555`, `load:581`, `load_text:633`), pushing it onto an undo stack bounded to a fixed depth, evicting the oldest snapshot past the bound, and clearing the redo stack on a fresh mutation.
- **Touched symbols (C-26):** **`NEW — Phase 3`** attributes (e.g. `_undo_stack`, `_redo_stack`), **`NEW — Phase 3`** helper (e.g. `_snapshot_document` / `_push_history`), and **`NEW — Phase 3`** depth constant (e.g. `_HISTORY_MAX`, value **`assumed — verify in Phase 3`**, default 20). Existing mutators keep their signatures/return types (reverse-grep their app.py action routing at `add_entry`/`edit_entry`/`remove_entry` call-sites to confirm no behavioral change on the forward path).
- **Validation:** `test (unit)` · **Executed verification:** `pytest tests/test_change_service.py -k undo_redo_history` · **Numeric pass threshold:** stack depth never exceeds the bound; snapshot equals pre-mutation document.
- **Acceptance criteria:** each mutation pushes exactly one snapshot; redo cleared on new mutation; bound enforced; each snapshot is a true `ChangeDocument` deep copy (no aliasing — mutating the live document must not alter a stored snapshot; no-alias asserted in Phase 3, per risk R-B). `_HISTORY_MAX` default 20 is **`assumed — verify Phase 3`**.

#### LLR-068a.2 — undo() / redo() restore semantics
- **Traceability:** HLR-068a
- **Target file (non-frozen):** `s19_app/tui/services/change_service.py`
- **Statement:** `ChangeService.undo()` shall replace `document` with the top undo snapshot (pushing the current document onto the redo stack) and `redo()` shall replace `document` with the top redo snapshot (pushing the current onto the undo stack); each shall be a no-op returning an unchanged document when its source stack is empty.
- **Touched symbols (C-26):** **`NEW — Phase 3`** methods `ChangeService.undo` / `ChangeService.redo`.
- **Validation:** `test (unit)` · **Executed verification:** `pytest tests/test_change_service.py -k undo_redo_roundtrip` · **Numeric pass threshold:** mutate→undo yields the pre-mutation document; undo→redo yields the post-mutation document; empty-stack undo/redo leaves `document` identical.
- **Acceptance criteria:** round-trip equality; empty-stack no-op.

#### LLR-068a.3 — Undo/Redo controls wired to the surface (C-16)
- **Traceability:** HLR-068a
- **Target files (non-frozen):** `s19_app/tui/screens_directionb.py` (buttons + messages) + `s19_app/tui/app.py` (handlers)
- **Statement:** The `PatchEditorPanel` shall expose Undo and Redo `Button`s that, when pressed, post messages `S19TuiApp` handles by calling `ChangeService.undo()` / `redo()` and re-rendering the entries table via the existing `PatchEditorPanel.refresh_entries` (`app.py:1737,3260`); the acceptance shall use real `pilot.click`.
- **Touched symbols (C-26):** **`NEW — Phase 3`** button ids (e.g. `#patch_undo_button`, `#patch_redo_button`), **`NEW — Phase 3`** `Message` classes and handlers. `refresh_entries` / `#patch_doc_entries_table` (`screens_directionb.py:1857`) are reused unchanged.
- **Validation:** `test (pilot)` · **Executed verification:** `AT-068a` clicks Undo/Redo and asserts the rendered entries table · **Numeric pass threshold:** `AT-068a` passes.
- **Acceptance criteria:** clicking Undo/Redo re-renders the table to the expected prior/next state.

#### LLR-068a.4 — A-01 data-loss guard on Undo/Redo (file-backed document)
- **Traceability:** HLR-068a
- **Target files (non-frozen):** `s19_app/tui/screens_directionb.py` (control enable state) + `s19_app/tui/app.py` (refresh path)
- **Statement:** When `ChangeService.document.source_path is not None` (a file-loaded change document), the Undo and Redo controls shall be **DISABLED** so undo/redo cannot silently mutate or replace a file-backed document; when `source_path is None` (paste-authored) the controls shall be enabled. This mirrors the batch-37 A-01 disable-guard (`panel.set_edit_json_enabled(service.document.source_path is None)`, `app.py:1743,3264`; whole-set refusal at `app.py:1907`). **Stance:** DISABLE (not silent in-memory divergence) — the batch-37 precedent, so a file-backed doc is never clobbered by an undo/redo path.
- **Touched symbols (C-26):** **`NEW — Phase 3`** enable-state helper (e.g. `set_undo_redo_enabled`) mirroring the existing `set_edit_json_enabled` pattern; reuses the `source_path` attribute already read across `app.py` (`app.py:1682,1743,1907,3264`). No existing id renamed.
- **Validation:** `test (pilot)` · **Executed verification:** `AT-068a` A-01 branch — file-loaded doc → controls disabled; paste-authored → enabled · **Numeric pass threshold:** controls disabled iff `source_path is not None`.
- **Acceptance criteria:** file-backed doc cannot be clobbered by undo/redo; paste-authored doc round-trips.

### HLR-068b (R-TUI-058) — Per-entry JSON edit popup
- **Traceability:** US-068b
- **Statement:** When the operator activates the per-entry JSON control for a selected change-set entry, the system shall open a modal seeded with that entry's JSON, and on confirm shall apply the edit to only that entry, leaving all other entries unchanged; and if the confirmed JSON is malformed, then the system shall record a collect-don't-abort issue without crashing and without mutating other entries.
- **Rationale (informative):** finer-grained editing than the batch-37 whole-set popup. The per-entry control is distinct from the whole-set `#patch_edit_json_button` and the field-based `#patch_entry_edit_button`.
- **Validation:** `test (pilot)` · **Executed verification:** `pytest tests/test_tui_directionb.py -k patch_entry_json_popup` (node provisional-until-Phase-3) · **Numeric pass threshold:** `AT-068b` passes; only the selected entry changes.
- **Priority:** medium
- **Acceptance (black-box):** §3.5 — `AT-068b`.

#### LLR-068b.1 — Per-entry JSON control scoped to the selected row
- **Traceability:** HLR-068b
- **Target file (non-frozen):** `s19_app/tui/screens_directionb.py`
- **Statement:** The `PatchEditorPanel` shall expose a per-entry JSON control that targets the row selected in `#patch_doc_entries_table` (`cursor_type="row"`, `screens_directionb.py:1859`), distinct from the whole-set `#patch_edit_json_button` (`:2033`) and the field-based `#patch_entry_edit_button` (`:1886`); with no selected entry the control shall be a no-op.
- **Touched symbols (C-26):** **`NEW — Phase 3`** control id (e.g. `#patch_entry_edit_json_button`); existing ids `#patch_edit_json_button`, `#patch_entry_edit_button`, `#patch_doc_entries_table` are **unchanged** (reverse-grep must show all three survive — no hijack of the existing per-entry Edit action `edit_entry` at `screens_directionb.py:2230`).
- **Validation:** `test (pilot)` · **Executed verification:** `AT-068b` locates the control and opens it for a selected row · **Numeric pass threshold:** control present; opens only with a selection.
- **Acceptance criteria:** the per-entry control is distinct and selection-scoped.

#### LLR-068b.2 — Per-entry JSON modal (mirror of ChangeSetJsonScreen)
- **Traceability:** HLR-068b
- **Target file (non-frozen):** `s19_app/tui/screens.py`
- **Statement:** A new per-entry JSON `ModalScreen[Optional[str]]` shall mirror `ChangeSetJsonScreen` (`screens.py:171`; `__init__(seed_text)` `:225`; `TextArea#changeset_json_text` `:232`; Confirm dismisses with the TextArea text) but be seeded with a single entry's JSON, returning the edited JSON on Confirm and `None` on Cancel.
- **Touched symbols (C-26):** **`NEW — Phase 3`** class (e.g. `EntryJsonScreen`) with its own TextArea id (e.g. `#entry_json_text` — new, to avoid colliding with `#changeset_json_text`); reuses the shared `.modal-dialog` CSS class.
- **Geometry (C-23):** modal dimensions **`assumed — pilot-measure in Phase 3`** at 80×24 and 120×30.
- **Validation:** `test (pilot)` · **Executed verification:** `AT-068b` asserts the modal is seeded with the selected entry's JSON · **Numeric pass threshold:** seed text equals the selected entry's JSON.
- **Acceptance criteria:** modal opens seeded with one entry's JSON; Confirm returns edited text.

#### LLR-068b.3 — Apply confirmed JSON to only the selected entry (C-16)
- **Traceability:** HLR-068b
- **Target files (non-frozen):** `s19_app/tui/app.py` (handler) + `s19_app/tui/services/change_service.py` (apply method)
- **Statement:** On modal Confirm, `S19TuiApp` shall route the edited JSON to a new `ChangeService` method that replaces only the selected entry at its index (leaving all other `document.entries` unchanged) and then re-render via `refresh_entries`; malformed JSON shall be collected as an issue without aborting or mutating other entries; the acceptance shall use real `pilot.click`.
- **Touched symbols (C-26):** **`NEW — Phase 3`** `Message` class, **`NEW — Phase 3`** handler (mirroring `on_patch_editor_panel_edit_json_requested` / `_apply_changeset_json_edit`, `app.py:1873,1918`), and **`NEW — Phase 3`** `ChangeService` method (e.g. `edit_entry_json(index, text)`). Integrates with LLR-068a snapshotting (a per-entry edit is a history-eligible mutation).
- **Validation:** `test (pilot)` · **Executed verification:** `AT-068b` edits entry *i*, Confirm, asserts entry *i* changed and entries *≠ i* byte-identical; invalid-JSON branch asserts non-crash · **Numeric pass threshold:** `AT-068b` passes both branches.
- **Acceptance criteria:** only the selected entry changes; malformed JSON is non-crashing.

#### LLR-068b.4 — A-01 data-loss guard on the per-entry JSON edit (file-backed document)
- **Traceability:** HLR-068b
- **Target files (non-frozen):** `s19_app/tui/screens_directionb.py` (control enable state) + `s19_app/tui/app.py` (handler)
- **Statement:** When `ChangeService.document.source_path is not None`, the per-entry JSON edit control (`#patch_entry_edit_json_button`, LLR-068b.1) shall be **DISABLED** so a per-entry edit cannot silently mutate/replace a file-backed document; when `source_path is None` it shall be enabled. This mirrors the batch-37 whole-set Edit-JSON A-01 guard (`app.py:1743,1907,3264`; disable pattern documented at `screens_directionb.py:2449-2450`). **Stance:** DISABLE (batch-37 precedent) — file-backed docs are protected, edited only via the on-disk source, never through the in-memory popup.
- **Touched symbols (C-26):** reuses the batch-37 enable/refuse pattern; **`NEW — Phase 3`** enable-state wiring for `#patch_entry_edit_json_button`. The `source_path` read is existing. No existing id renamed.
- **Validation:** `test (pilot)` · **Executed verification:** `AT-068b` A-01 branch — file-loaded → control disabled; paste-authored → enabled · **Numeric pass threshold:** control disabled iff `source_path is not None`.
- **Acceptance criteria:** file-backed doc protected; paste-authored doc editable per-entry.

---

## 5. Validation strategy

### 5.1 Methods
- **Layer A — white-box / functional (`TC-NNN`):** `test (unit)` / `test (integration)` / `test (pilot)` validating the LLR mechanism. Every `test` LLR names its executed verification + numeric pass threshold above. Test-file paths, `-k` selectors, and node ids are **provisional-until-Phase-3** (V-5), reconciled at Phase 4.
- **Layer B — black-box / behavioral acceptance (`AT-NNN`):** Textual Pilot e2e exercising the shipped surface as the user; asserts the story outcome with boundary + negative evidence. `AT` ids: `AT-065a`, `AT-066a`, `AT-066b`, `AT-067a`, `AT-068a`, `AT-068b`.
- **Testing-strategy cross-check:** all `test (pilot)` labels run under the repo's ratified `pytest` + Textual `App.run_test()` Pilot harness (the batch-21..37 idiom); no new test runtime introduced — no ADR conflict.

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test (`AT-NNN`) | Observed? |
|----|--------------------|-----------------|----------------------------|-----------|
| US-065 | Change-set label/placeholder read as an alternative to the dropdown, no `v2` framing | `PatchEditorPanel` section title + `#patch_doc_path_input` placeholder | `AT-065a` | Phase 4 |
| US-066 | WARNING naming the tag for address > 0xFFFFFFFF; hostile name renders literally | `GroupedIssuesPanel` (warning group row) | `AT-066a`, `AT-066b` | Phase 4 |
| US-067 | Info affordance opens a modal explaining the variant selector | info button + help `ModalScreen` | `AT-067a` | Phase 4 |
| US-068a | Undo restores prior change-set; redo re-applies | Undo/Redo buttons → `#patch_doc_entries_table` | `AT-068a` | Phase 4 |
| US-068b | Per-entry popup edits only the selected entry | per-entry JSON control + modal → entries table | `AT-068b` | Phase 4 |

**Functional chain (white-box) — per requirement.** TC ids reconciled (Phase-2 M2) onto the qa-owned **TC-332.. scheme** (batch-37 ended at TC-331); the old TC-001..019 numbering is **DELETED** (namespace collision + count double-book). HLRs are validated through their black-box `AT` surface; every LLR maps to a TC in the 332+ range. TC-332..343 mirror `01b` §2; TC-344/TC-345 extend contiguously for the two new A-01 guard LLRs (M4).

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-065 (R-TUI-054) | test (pilot) | via `AT-065a` | issues through §3.1 surface |
| LLR-065.1 | test (pilot) | TC-332 | section-title copy (verbatim `"Change document (JSON)"`) |
| LLR-065.2 | test (pilot) | TC-332 | placeholder copy (verbatim), id preserved |
| HLR-066 (R-TUI-055) | test (pilot) | via `AT-066a`/`AT-066b` | issues surface WARNING |
| LLR-066.1 | test (unit) | TC-333 | producer emits WARNING `A2L_ADDRESS_EXCEEDS_32BIT` naming tag |
| LLR-066.2 | test (integration) | TC-334 | merge into both report branches; colour round-trips `css_class_for_severity` |
| LLR-066.3 | test (pilot) | TC-335 | boundary `0xFFFFFFFF`/`0x100000000`; markup-safe hostile name |
| HLR-067 (R-TUI-056) | test (pilot) | via `AT-067a` | modal content |
| LLR-067.1 | test (pilot) | TC-336 | info button present (always rendered w/ selector) |
| LLR-067.2 | test (pilot) | TC-337 | real-click routing → push modal |
| LLR-067.3 | test (pilot) | TC-337 | help-text tokens (content) |
| HLR-068a (R-TUI-057) | test (pilot) | via `AT-068a` | undo/redo round-trip |
| LLR-068a.1 | test (unit) | TC-338 | bounded deep-copy snapshotting (no-alias) |
| LLR-068a.2 | test (unit) | TC-339 | restore semantics + empty no-op |
| LLR-068a.3 | test (pilot) | TC-340 | button wiring, real click |
| LLR-068a.4 (A-01) | test (pilot) | TC-344 | undo/redo disabled iff `source_path is not None` |
| HLR-068b (R-TUI-058) | test (pilot) | via `AT-068b` | per-entry edit isolation |
| LLR-068b.1 | test (pilot) | TC-341 | control distinct (`#patch_entry_edit_json_button`) + selection-scoped |
| LLR-068b.2 | test (pilot) | TC-342 | modal seeded with one entry |
| LLR-068b.3 | test (pilot) | TC-343 | only selected entry changes; malformed non-crash (validated route) |
| LLR-068b.4 (A-01) | test (pilot) | TC-345 | per-entry control disabled iff `source_path is not None` |

> **TC id range: TC-332 … TC-345 (14 distinct TCs).** TC-332 covers the copy pair (LLR-065.1/.2); TC-337 covers routing + content (LLR-067.2/.3); the remaining LLRs are 1:1. `TC-NNN` ids are provisional-until-Phase-3 (V-5); Phase-4 reconciles them to the implemented node ids. Each `AT` maps to exactly one on-disk node (C-18).

### 5.3 Batch acceptance criteria
- Every LLR covered by ≥1 passing `TC`; every US covered by ≥1 passing `AT` observing its outcome through the shipped surface with boundary + negative evidence.
- 0 blocker fails in validation; 0 engine-frozen diffs vs `main` (`_ENGINE_PATHS` guards green).
- C-26 reverse-grep clean: every declared touched/new symbol accounted for across `tests/`; no undeclared shared-symbol edit.
- No requirement without an assigned validation method.

---

## 6. Appendices

### 6.3 Open risks
- **R-A (US-066 issue-code contract):** `A2L_ADDRESS_EXCEEDS_32BIT` is a new public issue code — Phase 2/3 must confirm no existing test asserts on the pre-change A2L issue-count for oversized fixtures (there are none today; the condition was unhandled).
- **R-B (US-068a memory/semantics):** deep-snapshot history can grow — bounded by `_HISTORY_MAX` (value assumed, verify Phase 3). Snapshot must be a true deep copy (mutating `document.entries` must not alias a stored snapshot).
- **R-C (US-067 / US-068b geometry):** modal dimensions assumed — pilot-measure at Phase 3 (C-23); no fr-math.
- **R-D (snapshot drift):** new buttons/modals may drift Textual SVG cells → predicted per-cell `xfail(strict=False)` (C-22); canonical-CI regen only.

### 6.4 Phase-1 reconciliation log

**Event R1 — US-068 split (B-19 → US-068a + US-068b).**

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| R1-split | US-068 split into US-068a (undo/redo) + US-068b (per-entry JSON popup); two HLRs (R-TUI-057, R-TUI-058) instead of one | No prior HLR existed (Phase-1 first derivation); §2.6 already flagged split-likely; the two capabilities are separable with distinct ATs (AT-068a vs AT-068b) and distinct surfaces (Undo/Redo buttons vs per-entry modal) | §3.4/§3.5 acceptance blocks + HLR-068a/HLR-068b + LLR-068a.1-3 / LLR-068b.1-3 now exist as separate bodies |

**Event R2 — US-066 routed TUI-side (engine-freeze compliance).**

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| R2-freeze | The >32-bit WARNING is produced in `services/validation_service.py` (non-frozen), not in `validation/` (frozen) | HLR-066 statement + LLR-066.1/.2 target `validation_service.py`; `validation/model.py` is imported (ValidationIssue/Severity) but not edited | LLR-066.1 target file = `services/validation_service.py`; §2.5-consistent; frozen set untouched |

### 6.5 Requirement amendments

**Phase-1 derivation:** first derivation — no amendments.

**Phase-2 fold (2026-07-12) — reconciliation of the three sub-reviews (architect + qa).** No requirement re-derivation, no story change; cross-artifact contradictions collapsed to a single value and two data-loss guard LLRs added. Before → After (New/Deleted tokens marked):

| ID | Fold | Before | After |
|----|------|--------|-------|
| **B1** | Canonical A2L oversize issue code (public contract) | Two live strings: §4 `A2L_ADDRESS_EXCEEDS_32BIT` vs `01b` `A2L_ADDRESS_OVER_32BIT` / unbound `<new code>` | **`A2L_ADDRESS_EXCEEDS_32BIT`** ratified as THE code everywhere; `A2L_ADDRESS_OVER_32BIT` **[Deleted]**; bound in §3.2 AT-066a, §4 LLR-066.1, and `01b` TC-333/334/335 + AT-066a |
| **M1** | US-066 WARNING producer sink | §2.6 feasibility named `services/a2l_service.enrich_tags_and_render` | **`services/validation_service.build_validation_report`** (sibling of `supplemental_a2l_row_issues`); §2.6 corrected; §4 LLR-066.1/.2 were already correct — left unchanged. `enrich_tags_and_render` returns tag rows, not issues (`a2l_service.py:14`) — wrong sink noted |
| **M2** | TC numbering | §5.2 functional chain used **TC-001…TC-019** (19 rows) | **TC-001…TC-019 [Deleted]**; replaced with **TC-332…TC-345** (14 TCs) on the qa scheme; every LLR maps to a 332+ TC; HLRs via AT surface. TC-344/TC-345 **[New]** for the A-01 guards |
| **M3** | US-065 pinned copy | Abstract "new wording tokens"; title `"Change document (v2 JSON)"`, placeholder `"path to v2 change-set .json"` | **Title `:1854` → `"Change document (JSON)"`** (drops `v2` only; entries-pane header per F-m4); **Placeholder `:1904` → `"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`** (carries the alternative-to-dropdown framing). AT-065a asserts both verbatim + `v2` absent. Edit scoped to the `:1854` `patch-section-title` instance only (C-26; `:1918`/`:1936` untouched) |
| **M4** | A-01 data-loss guard (file-backed doc) | No stance for US-068a/US-068b when `source_path is not None` | **[New] LLR-068a.4** + **[New] LLR-068b.4**: Undo/Redo and the per-entry JSON edit controls are **DISABLED** when `source_path is not None` (batch-37 precedent `set_edit_json_enabled`, `app.py:1743,1907,3264`). Boundary AT branch added to §3.4 AT-068a and §3.5 AT-068b (file-loaded → disabled; paste-authored → enabled), mirroring batch-37 AT-064c |

**Minors folded (same pass):** AT-066b split by payload class (brackets verbatim; ANSI neutralized/stripped — `model.py:71`); AT-067a pinned always-rendered info button + ≥2-image fixture (F-m3); LLR-068a.1 + AT-068a require a deep-copy / no-alias assertion, `_HISTORY_MAX` default 20 flagged `assumed — verify Phase 3`; AT-066a flagged A-1 (positive branch needs a parsed-int address — `confirm Phase 3`).

**B2** (AT-068b re-pointed from `#patch_entry_edit_button` to the new `#patch_entry_edit_json_button`) is a `01b`/§3.5 acceptance-wording fix, not a locked-requirement amendment (LLR-068b.1 already mandated the new id); recorded in the `01b` change set and §3.5 above. No increment-cut change (C-21): AT-068b was re-pointed, not added.
